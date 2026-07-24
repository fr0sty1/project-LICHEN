//! CoAP blockwise transfer (RFC 7959).
//!
//! Block options enable chunked transfer of large payloads over the constrained
//! CoAP MTU. Block1 is for request payloads (uploads), Block2 for response
//! payloads (downloads).

use crate::codec::{CoapBuilder, CoapError, CoapOption};
use crate::option::OptionNumber;
use lichen_core::error::BufferTooSmall;

/// Block option value (Block1 or Block2).
///
/// Wire format: 1-3 bytes encoding NUM (4-20 bits), M flag (1 bit), SZX (3 bits).
/// - SZX: size exponent (block size = 2^(SZX+4), valid 0-6 = 16-1024 bytes)
/// - M: more blocks follow
/// - NUM: block number (0-based)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOption {
    /// Block number (0-based).
    pub num: u32,
    /// More blocks follow.
    pub more: bool,
    /// Size exponent (0-6). Block size = 2^(szx+4).
    pub szx: u8,
}

impl BlockOption {
    /// Minimum block size (16 bytes, SZX=0).
    pub const MIN_SIZE: usize = 16;
    /// Maximum block size (1024 bytes, SZX=6).
    pub const MAX_SIZE: usize = 1024;

    /// Create a new block option.
    ///
    /// Returns `Err(CoapError::InvalidBlockOption)` if `szx > 6` or `num > 0xFFFFF` (20-bit max).
    pub fn new(num: u32, more: bool, szx: u8) -> Result<Self, CoapError> {
        if szx > 6 {
            return Err(CoapError::InvalidBlockOption);
        }
        if num > 0xFFFFF {
            return Err(CoapError::InvalidBlockOption);
        }
        Ok(Self { num, more, szx })
    }

    /// Parse from option value bytes (1-3 bytes).
    pub fn from_bytes(data: &[u8]) -> Result<Self, CoapError> {
        if data.is_empty() || data.len() > 3 {
            return Err(CoapError::InvalidBlockOption);
        }
        // Decode as big-endian integer
        let mut val = 0u32;
        for &b in data {
            val = (val << 8) | b as u32;
        }
        let szx = (val & 0x07) as u8;
        let more = (val & 0x08) != 0;
        let num = val >> 4;
        if szx > 6 {
            return Err(CoapError::InvalidBlockOption);
        }
        Ok(Self { num, more, szx })
    }

    /// Write to output buffer (1-3 bytes, minimal encoding).
    ///
    /// Returns the number of bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, CoapError> {
        let val = (self.num << 4) | ((self.more as u32) << 3) | (self.szx as u32);
        if val <= 0xFF {
            if out.is_empty() {
                return Err(BufferTooSmall::new(1, 0).into());
            }
            out[0] = val as u8;
            Ok(1)
        } else if val <= 0xFFFF {
            if out.len() < 2 {
                return Err(BufferTooSmall::new(2, out.len()).into());
            }
            out[0] = (val >> 8) as u8;
            out[1] = val as u8;
            Ok(2)
        } else {
            if out.len() < 3 {
                return Err(BufferTooSmall::new(3, out.len()).into());
            }
            out[0] = (val >> 16) as u8;
            out[1] = (val >> 8) as u8;
            out[2] = val as u8;
            Ok(3)
        }
    }

    /// Block size in bytes.
    pub fn size(&self) -> usize {
        1 << (self.szx + 4)
    }

    /// Byte offset of this block in the complete payload.
    pub fn offset(&self) -> usize {
        self.num as usize * self.size()
    }

    /// Create from block size (rounds down to valid SZX).
    ///
    /// Returns `Err(CoapError::InvalidBlockOption)` if `num > 0xFFFFF` (20-bit max).
    pub fn from_size(num: u32, more: bool, size: usize) -> Result<Self, CoapError> {
        let szx = size_to_szx(size);
        Self::new(num, more, szx)
    }
}

/// Convert block size to SZX exponent (rounds down).
pub fn size_to_szx(size: usize) -> u8 {
    if size < 16 {
        return 0;
    }
    ((size.ilog2() as u8).saturating_sub(4)).min(6)
}

/// Convert SZX exponent to block size.
pub fn szx_to_size(szx: u8) -> usize {
    1 << (szx.min(6) + 4)
}

impl<'a> CoapOption<'a> {
    /// True if this is a Block1 option.
    pub fn is_block1(&self) -> bool {
        self.number == OptionNumber::Block1 as u16
    }

    /// True if this is a Block2 option.
    pub fn is_block2(&self) -> bool {
        self.number == OptionNumber::Block2 as u16
    }

    /// True if this is a Size1 option.
    pub fn is_size1(&self) -> bool {
        self.number == OptionNumber::Size1 as u16
    }

    /// True if this is a Size2 option.
    pub fn is_size2(&self) -> bool {
        self.number == OptionNumber::Size2 as u16
    }

    /// Parse as Block1 or Block2 option.
    pub fn as_block(&self) -> Result<BlockOption, CoapError> {
        if self.is_block1() || self.is_block2() {
            BlockOption::from_bytes(self.value)
        } else {
            Err(CoapError::InvalidBlockOption)
        }
    }
}

impl<'a> CoapBuilder<'a> {
    /// Add a Block1 option (for request payload chunking).
    pub fn block1(&mut self, block: BlockOption) -> Result<&mut Self, CoapError> {
        let mut buf = [0u8; 3];
        let len = block.write_to(&mut buf)?;
        self.option(OptionNumber::Block1 as u16, &buf[..len])
    }

    /// Add a Block2 option (for response payload chunking).
    pub fn block2(&mut self, block: BlockOption) -> Result<&mut Self, CoapError> {
        let mut buf = [0u8; 3];
        let len = block.write_to(&mut buf)?;
        self.option(OptionNumber::Block2 as u16, &buf[..len])
    }

    /// Add a Size1 option (total request body size).
    pub fn size1(&mut self, size: u32) -> Result<&mut Self, CoapError> {
        let bytes = uint_to_bytes(size);
        let len = uint_len(size);
        self.option(OptionNumber::Size1 as u16, &bytes[4 - len..])
    }

    /// Add a Size2 option (total response body size).
    pub fn size2(&mut self, size: u32) -> Result<&mut Self, CoapError> {
        let bytes = uint_to_bytes(size);
        let len = uint_len(size);
        self.option(OptionNumber::Size2 as u16, &bytes[4 - len..])
    }
}

/// Encode u32 as minimal big-endian bytes.
fn uint_to_bytes(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Minimal encoding length for u32.
fn uint_len(val: u32) -> usize {
    if val == 0 {
        0
    } else if val <= 0xFF {
        1
    } else if val <= 0xFFFF {
        2
    } else if val <= 0xFFFFFF {
        3
    } else {
        4
    }
}

/// Blockwise transfer sender state.
#[derive(Debug)]
pub struct BlockSender {
    /// Full payload to send.
    data: [u8; 4096],
    data_len: usize,
    /// Block size (negotiated).
    block_size: usize,
    /// Current block number.
    current_block: u32,
    /// True when all blocks acknowledged.
    complete: bool,
}

impl BlockSender {
    /// Maximum payload size for blockwise transfer.
    pub const MAX_PAYLOAD: usize = 4096;

    /// Create a new sender for the given payload.
    ///
    /// Returns `Err(CoapError::PayloadTooLarge)` if the payload exceeds `MAX_PAYLOAD`.
    pub fn new(payload: &[u8], block_size: usize) -> Result<Self, CoapError> {
        if payload.len() > Self::MAX_PAYLOAD {
            return Err(CoapError::PayloadTooLarge);
        }
        let mut data = [0u8; Self::MAX_PAYLOAD];
        data[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            data,
            data_len: payload.len(),
            block_size: block_size.clamp(BlockOption::MIN_SIZE, BlockOption::MAX_SIZE),
            current_block: 0,
            complete: false,
        })
    }

    /// Total payload size.
    pub fn total_size(&self) -> usize {
        self.data_len
    }

    /// Number of blocks needed.
    pub fn block_count(&self) -> u32 {
        self.data_len.div_ceil(self.block_size) as u32
    }

    /// Get the next block to send. Returns (block_option, block_data).
    ///
    /// Returns `None` if the transfer is complete or no more blocks.
    /// Block number is always valid because MAX_PAYLOAD / MIN_SIZE < 0xFFFFF.
    pub fn next_block(&self) -> Option<(BlockOption, &[u8])> {
        if self.complete {
            return None;
        }
        let offset = self.current_block as usize * self.block_size;
        if offset >= self.data_len {
            return None;
        }
        let end = (offset + self.block_size).min(self.data_len);
        let more = end < self.data_len;
        // Block number is bounded: MAX_PAYLOAD / MIN_SIZE = 256, well under 0xFFFFF
        let block = BlockOption::from_size(self.current_block, more, self.block_size)
            .expect("block number within bounds");
        Some((block, &self.data[offset..end]))
    }

    /// Acknowledge current block and advance. Returns true if transfer complete.
    pub fn ack_block(&mut self, block_num: u32) -> bool {
        if block_num == self.current_block {
            self.current_block += 1;
            if self.current_block >= self.block_count() {
                self.complete = true;
            }
        }
        self.complete
    }

    /// Handle server requesting smaller block size.
    pub fn resize(&mut self, new_szx: u8) {
        let new_size = szx_to_size(new_szx);
        if new_size < self.block_size {
            // Server wants smaller blocks - recalculate current position
            let current_offset = self.current_block as usize * self.block_size;
            self.block_size = new_size;
            self.current_block = (current_offset / new_size) as u32;
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Blockwise transfer receiver state.
#[derive(Debug)]
pub struct BlockReceiver {
    /// Accumulated payload.
    data: [u8; 4096],
    data_len: usize,
    /// Block number to use for the next request.
    expected_block: u32,
    /// Negotiated block size.
    block_size: usize,
    /// Expected total size (from Size2 option).
    expected_size: Option<usize>,
    /// True when final block received.
    complete: bool,
}

impl BlockReceiver {
    /// Maximum payload size.
    pub const MAX_PAYLOAD: usize = 4096;

    /// Create a new receiver.
    pub fn new(block_size: usize) -> Self {
        Self {
            data: [0u8; Self::MAX_PAYLOAD],
            data_len: 0,
            expected_block: 0,
            block_size: block_size.clamp(BlockOption::MIN_SIZE, BlockOption::MAX_SIZE),
            expected_size: None,
            complete: false,
        }
    }

    /// Set expected total size (from Size2 option).
    pub fn set_expected_size(&mut self, size: usize) {
        self.expected_size = Some(size);
    }

    /// Receive a block. Returns true if this completes the transfer.
    pub fn receive_block(&mut self, block: BlockOption, data: &[u8]) -> Result<bool, CoapError> {
        if self.complete {
            return Err(CoapError::BlockOutOfOrder);
        }

        let block_size = block.size();
        if (self.data_len > 0 && block_size > self.block_size)
            || data.len() > block_size
            || (block.more && data.len() != block_size)
        {
            return Err(CoapError::InvalidBlockOption);
        }

        let offset = block.offset();
        if offset != self.data_len {
            return Err(CoapError::BlockOutOfOrder);
        }
        let offset = self.data_len;
        let needed = offset + data.len();
        if needed > Self::MAX_PAYLOAD {
            return Err(BufferTooSmall::new(needed, Self::MAX_PAYLOAD).into());
        }

        self.data[offset..offset + data.len()].copy_from_slice(data);
        self.data_len = needed;
        self.block_size = block_size;
        self.expected_block = block.num + 1;

        if !block.more {
            self.complete = true;
        }
        Ok(self.complete)
    }

    /// Get the assembled payload (only valid after complete).
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Next block number to request.
    ///
    /// Block number is always valid because MAX_PAYLOAD / MIN_SIZE < 0xFFFFF.
    pub fn next_request_block(&self) -> BlockOption {
        // Block number is bounded: MAX_PAYLOAD / MIN_SIZE = 256, well under 0xFFFFF
        BlockOption::from_size(self.expected_block, false, self.block_size)
            .expect("block number within bounds")
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_option_roundtrip() {
        let cases = [
            BlockOption::new(0, false, 2).unwrap(), // num=0, m=0, szx=2 (64 bytes)
            BlockOption::new(0, true, 2).unwrap(),  // num=0, m=1, szx=2
            BlockOption::new(15, false, 6).unwrap(), // num=15, m=0, szx=6 (1024 bytes)
            BlockOption::new(255, true, 4).unwrap(), // num=255, m=1, szx=4
            BlockOption::new(4095, true, 0).unwrap(), // large block number
        ];
        for original in cases {
            let mut buf = [0u8; 3];
            let len = original.write_to(&mut buf).unwrap();
            let parsed = BlockOption::from_bytes(&buf[..len]).unwrap();
            assert_eq!(parsed, original, "roundtrip failed for {:?}", original);
        }
    }

    #[test]
    fn block_option_size() {
        assert_eq!(BlockOption::new(0, false, 0).unwrap().size(), 16);
        assert_eq!(BlockOption::new(0, false, 1).unwrap().size(), 32);
        assert_eq!(BlockOption::new(0, false, 2).unwrap().size(), 64);
        assert_eq!(BlockOption::new(0, false, 3).unwrap().size(), 128);
        assert_eq!(BlockOption::new(0, false, 4).unwrap().size(), 256);
        assert_eq!(BlockOption::new(0, false, 5).unwrap().size(), 512);
        assert_eq!(BlockOption::new(0, false, 6).unwrap().size(), 1024);
    }

    #[test]
    fn block_option_offset() {
        let block = BlockOption::new(3, false, 4).unwrap(); // block 3, 256 bytes
        assert_eq!(block.offset(), 768);
    }

    #[test]
    fn size_to_szx_values() {
        assert_eq!(size_to_szx(16), 0);
        assert_eq!(size_to_szx(32), 1);
        assert_eq!(size_to_szx(64), 2);
        assert_eq!(size_to_szx(128), 3);
        assert_eq!(size_to_szx(256), 4);
        assert_eq!(size_to_szx(512), 5);
        assert_eq!(size_to_szx(1024), 6);
        assert_eq!(size_to_szx(2048), 6); // capped
    }

    #[test]
    fn sender_single_block() {
        let payload = b"hello";
        let sender = BlockSender::new(payload, 64).unwrap();
        assert_eq!(sender.block_count(), 1);
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 0);
        assert!(!block.more);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn sender_multiple_blocks() {
        let payload = [0u8; 200];
        let mut sender = BlockSender::new(&payload, 64).unwrap();
        assert_eq!(sender.block_count(), 4); // 200/64 = 3.125 → 4 blocks

        // Block 0
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 0);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(0);

        // Block 1
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 1);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(1);

        // Block 2
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 2);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(2);

        // Block 3 (final)
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 3);
        assert!(!block.more);
        assert_eq!(data.len(), 8); // 200 - 192 = 8

        assert!(sender.ack_block(3));
        assert!(sender.is_complete());
    }

    #[test]
    fn receiver_single_block() {
        let mut receiver = BlockReceiver::new(64);
        let block = BlockOption::new(0, false, 2).unwrap();
        let done = receiver.receive_block(block, b"hello").unwrap();
        assert!(done);
        assert_eq!(receiver.payload(), b"hello");
    }

    #[test]
    fn receiver_multiple_blocks() {
        let mut receiver = BlockReceiver::new(64);

        // Block 0
        let block0 = BlockOption::new(0, true, 2).unwrap();
        assert!(!receiver.receive_block(block0, &[1u8; 64]).unwrap());

        // Block 1
        let block1 = BlockOption::new(1, true, 2).unwrap();
        assert!(!receiver.receive_block(block1, &[2u8; 64]).unwrap());

        // Block 2 (final)
        let block2 = BlockOption::new(2, false, 2).unwrap();
        assert!(receiver.receive_block(block2, &[3u8; 32]).unwrap());

        let payload = receiver.payload();
        assert_eq!(payload.len(), 160);
        assert!(payload[..64].iter().all(|&b| b == 1));
        assert!(payload[64..128].iter().all(|&b| b == 2));
        assert!(payload[128..160].iter().all(|&b| b == 3));
    }

    #[test]
    fn block_option_invalid_szx() {
        assert_eq!(
            BlockOption::new(0, false, 7),
            Err(CoapError::InvalidBlockOption)
        );
    }

    #[test]
    fn block_option_invalid_num() {
        assert_eq!(
            BlockOption::new(0x100000, false, 2),
            Err(CoapError::InvalidBlockOption)
        );
    }

    #[test]
    fn block_sender_payload_too_large() {
        let payload = [0u8; BlockSender::MAX_PAYLOAD + 1];
        assert!(matches!(
            BlockSender::new(&payload, 64),
            Err(CoapError::PayloadTooLarge)
        ));
    }

    #[test]
    fn receiver_out_of_order_block() {
        let mut receiver = BlockReceiver::new(64);

        // Sending block 1 before block 0 should fail
        let block1 = BlockOption::new(1, true, 2).unwrap();
        assert_eq!(
            receiver.receive_block(block1, &[1u8; 64]),
            Err(CoapError::BlockOutOfOrder)
        );
    }

    #[test]
    fn receiver_handles_mid_transfer_szx_reduction() {
        // RFC 7959: server may reduce SZX mid-transfer (NUM rescales).
        // Receiver tracks cumulative bytes, not block_num * block_size.
        let mut receiver = BlockReceiver::new(128); // szx=3

        let block0 = BlockOption::new(0, true, 3).unwrap(); // szx=3 (128 bytes)
        assert!(!receiver.receive_block(block0, &[1u8; 128]).unwrap());

        // RFC 7959 Figure 4: reducing 128-byte blocks to 64 bytes rescales NUM.
        let block2 = BlockOption::new(2, true, 2).unwrap(); // szx=2 (64 bytes)
        assert!(!receiver.receive_block(block2, &[2u8; 64]).unwrap());

        let block3 = BlockOption::new(3, false, 2).unwrap();
        assert!(receiver.receive_block(block3, &[3u8; 32]).unwrap());

        let payload = receiver.payload();
        assert_eq!(payload.len(), 224);
        assert!(payload[..128].iter().all(|&b| b == 1));
        assert!(payload[128..192].iter().all(|&b| b == 2));
        assert!(payload[192..].iter().all(|&b| b == 3));
    }

    #[test]
    fn receiver_rejects_gap_without_mutating_state() {
        let mut receiver = BlockReceiver::new(64);
        let block0 = BlockOption::new(0, true, 2).unwrap();
        receiver.receive_block(block0, &[1u8; 64]).unwrap();

        let block2 = BlockOption::new(2, false, 2).unwrap();
        assert_eq!(
            receiver.receive_block(block2, &[2u8; 64]),
            Err(CoapError::BlockOutOfOrder)
        );
        assert_eq!(receiver.payload(), &[1u8; 64]);
        assert_eq!(receiver.next_request_block().num, 1);

        let block1 = BlockOption::new(1, false, 2).unwrap();
        assert!(receiver.receive_block(block1, &[3u8; 64]).unwrap());
        assert_eq!(&receiver.payload()[64..], &[3u8; 64]);
    }

    #[test]
    fn receiver_rejects_overlap_without_mutating_state() {
        let mut receiver = BlockReceiver::new(128);
        let block0 = BlockOption::new(0, true, 3).unwrap();
        receiver.receive_block(block0, &[1u8; 128]).unwrap();

        let overlapping = BlockOption::new(1, false, 2).unwrap();
        assert_eq!(
            receiver.receive_block(overlapping, &[2u8; 64]),
            Err(CoapError::BlockOutOfOrder)
        );
        assert_eq!(receiver.payload(), &[1u8; 128]);

        let block2 = BlockOption::new(2, false, 2).unwrap();
        assert!(receiver.receive_block(block2, &[3u8; 64]).unwrap());
        assert_eq!(&receiver.payload()[128..], &[3u8; 64]);
    }

    #[test]
    fn receiver_rejects_short_non_final_block() {
        let mut receiver = BlockReceiver::new(64);
        let short = BlockOption::new(0, true, 2).unwrap();
        assert_eq!(
            receiver.receive_block(short, &[1u8; 63]),
            Err(CoapError::InvalidBlockOption)
        );
        assert!(receiver.payload().is_empty());

        let valid = BlockOption::new(0, false, 2).unwrap();
        assert!(receiver.receive_block(valid, &[2u8; 32]).unwrap());
    }

    #[test]
    fn receiver_accepts_initial_szx_larger_than_preferred() {
        // Server may choose any SZX for the first block (RFC 7959 §4).
        let mut receiver = BlockReceiver::new(64);
        let larger = BlockOption::new(0, false, 3).unwrap();

        assert!(receiver.receive_block(larger, &[1u8; 128]).unwrap());
        assert_eq!(receiver.payload(), &[1u8; 128]);
    }

    #[test]
    fn receiver_rejects_mid_transfer_szx_increase() {
        let mut receiver = BlockReceiver::new(128);
        let block0 = BlockOption::new(0, true, 2).unwrap();
        let block1 = BlockOption::new(1, true, 2).unwrap();
        receiver.receive_block(block0, &[1u8; 64]).unwrap();
        receiver.receive_block(block1, &[2u8; 64]).unwrap();

        let larger = BlockOption::new(1, false, 3).unwrap();
        assert_eq!(
            receiver.receive_block(larger, &[3u8; 128]),
            Err(CoapError::InvalidBlockOption)
        );
        assert_eq!(receiver.payload().len(), 128);
        assert_eq!(receiver.next_request_block().num, 2);
        assert_eq!(receiver.next_request_block().size(), 64);
    }

    #[test]
    fn receiver_rejects_blocks_after_completion() {
        let mut receiver = BlockReceiver::new(64);
        let final_block = BlockOption::new(0, false, 2).unwrap();
        receiver.receive_block(final_block, &[1u8; 32]).unwrap();

        let extra = BlockOption::new(2, false, 0).unwrap();
        assert_eq!(
            receiver.receive_block(extra, &[2u8; 16]),
            Err(CoapError::BlockOutOfOrder)
        );
        assert_eq!(receiver.payload(), &[1u8; 32]);
        assert!(receiver.is_complete());
    }

    #[test]
    fn receiver_handles_larger_blocks_than_expected() {
        // Server sends 128-byte blocks when receiver expects 64-byte blocks.
        // Without fix: block 1 at offset 64 would overwrite block 0's data at 64..128.
        let mut receiver = BlockReceiver::new(64); // expects 64-byte blocks

        // Block 0: server sends 128 bytes
        let block0 = BlockOption::new(0, true, 3).unwrap(); // szx=3 (128 bytes)
        assert!(!receiver.receive_block(block0, &[1u8; 128]).unwrap());

        // Block 1: server sends 128 bytes
        let block1 = BlockOption::new(1, false, 3).unwrap();
        assert!(receiver.receive_block(block1, &[2u8; 128]).unwrap());

        let payload = receiver.payload();
        assert_eq!(payload.len(), 256);
        // All of block 0's data should be intact
        assert!(payload[..128].iter().all(|&b| b == 1));
        // All of block 1's data should be intact
        assert!(payload[128..256].iter().all(|&b| b == 2));
    }

    #[test]
    fn receiver_handles_smaller_blocks_than_expected() {
        // Server sends 64-byte blocks when receiver expects 128-byte blocks.
        // Without fix: block 1 at offset 128 would leave a gap at 64..128.
        let mut receiver = BlockReceiver::new(128); // expects 128-byte blocks

        // Block 0: server sends 64 bytes
        let block0 = BlockOption::new(0, true, 2).unwrap(); // szx=2 (64 bytes)
        assert!(!receiver.receive_block(block0, &[1u8; 64]).unwrap());

        // Block 1: server sends 64 bytes
        let block1 = BlockOption::new(1, false, 2).unwrap();
        assert!(receiver.receive_block(block1, &[2u8; 64]).unwrap());

        let payload = receiver.payload();
        assert_eq!(payload.len(), 128);
        // No gaps - data is contiguous
        assert!(payload[..64].iter().all(|&b| b == 1));
        assert!(payload[64..128].iter().all(|&b| b == 2));
    }

    #[test]
    fn uint_encoding_takes_last_bytes() {
        // Verify uint_to_bytes + slice gives correct big-endian encoding
        // Bug fix: was taking first N bytes instead of last N bytes
        let cases: &[(u32, &[u8])] = &[
            (0, &[]),
            (1, &[0x01]),
            (255, &[0xFF]),
            (256, &[0x01, 0x00]),
            (65535, &[0xFF, 0xFF]),
            (65536, &[0x01, 0x00, 0x00]),
            (0xFFFFFF, &[0xFF, 0xFF, 0xFF]),
            (0x1000000, &[0x01, 0x00, 0x00, 0x00]),
        ];
        for &(val, expected) in cases {
            let bytes = uint_to_bytes(val);
            let len = uint_len(val);
            let slice = &bytes[4 - len..];
            assert_eq!(slice, expected, "encoding of {:#x}", val);
        }
    }
}
