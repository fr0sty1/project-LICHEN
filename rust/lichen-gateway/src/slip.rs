//! SLIP framing (RFC 1055).
//!
//! SLIP is a trivial byte-stuffing framing protocol.  Each packet is bounded
//! by FEND (0xC0) bytes; FEND and FESC bytes in the payload are replaced by
//! two-byte escape sequences.
//!
//! Provides both async functions (`send_packet`/`recv_packet`) and a stateful
//! `SlipFramer` for non-blocking queue-based I/O.

use std::collections::VecDeque;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::warn;

// Use shared framing constants from lichen-kiss (KISS and SLIP use the same byte values).
use lichen_kiss::framing::{FEND, FESC, TFEND, TFESC};

/// Escape a single byte for SLIP transmission.
///
/// Returns `(bytes, len)` where `bytes[..len]` contains the escaped output.
/// For FEND/FESC, returns a 2-byte escape sequence; otherwise the byte unchanged.
#[inline]
const fn slip_escape(byte: u8) -> ([u8; 2], usize) {
    match byte {
        FEND => ([FESC, TFEND], 2),
        FESC => ([FESC, TFESC], 2),
        b => ([b, 0], 1),
    }
}

/// SLIP-encode a packet into a Vec, including leading and trailing FEND.
fn slip_encode(packet: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(packet.len() * 2 + 2);
    buf.push(FEND);
    for &byte in packet {
        let (escaped, len) = slip_escape(byte);
        buf.extend_from_slice(&escaped[..len]);
    }
    buf.push(FEND);
    buf
}

/// Result of processing one byte during SLIP unescaping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlipDecodeResult {
    /// No output byte yet (start of escape sequence or inter-packet FEND).
    None,
    /// Decoded byte to append to buffer.
    Byte(u8),
    /// End of packet (FEND received with data in buffer).
    End,
}

/// Process one byte during SLIP reception.
///
/// `in_escape` tracks whether the previous byte was FESC.
/// Returns the decode result and the updated escape state.
#[inline]
fn slip_decode_byte(byte: u8, in_escape: bool) -> (SlipDecodeResult, bool) {
    match byte {
        FEND => (SlipDecodeResult::End, false),
        FESC => (SlipDecodeResult::None, true),
        TFEND if in_escape => (SlipDecodeResult::Byte(FEND), false),
        TFESC if in_escape => (SlipDecodeResult::Byte(FESC), false),
        b if in_escape => {
            tracing::warn!(byte = b, "invalid SLIP escape sequence");
            (SlipDecodeResult::Byte(b), false)
        }
        b => (SlipDecodeResult::Byte(b), false),
    }
}

/// SLIP framing error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlipError {
    /// Packet too large for buffer.
    PacketTooLarge,
    /// TX queue is full.
    QueueFull,
    /// Output buffer too small for worst-case SLIP encoding of queued packet.
    BufferTooSmall { needed: usize },
}

impl std::fmt::Display for SlipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooLarge => write!(f, "packet too large"),
            Self::QueueFull => write!(f, "TX queue full"),
            Self::BufferTooSmall { needed } => {
                write!(f, "buffer too small (need {} bytes)", needed)
            }
        }
    }
}

impl core::error::Error for SlipError {}

/// Maximum size of raw packet data (before SLIP encoding).
const TX_BUFFER_SIZE: usize = 4096;
/// Buffer size required for a worst-case encoded TX packet.
pub const SLIP_TX_BUF_SIZE: usize = 2 + TX_BUFFER_SIZE * 2;
/// Maximum number of packets in TX queue.
const TX_QUEUE_CAPACITY: usize = 8;
/// Maximum size of RX buffer before discarding the frame.
/// SECURITY: Prevents DoS via memory exhaustion from malicious/faulty senders.
const RX_BUFFER_MAX: usize = 4096;

/// Minimum buffer size for `try_get_tx()` to handle worst-case SLIP encoding.
///
/// SLIP worst-case: 2 FEND bytes + each data byte escaped (2x expansion).
/// This must cover the largest packet that can be queued (TX_BUFFER_SIZE).
pub const SLIP_TX_BUF_SIZE: usize = 2 + TX_BUFFER_SIZE * 2;

/// Stateful SLIP framer with RX accumulation and TX queue.
///
/// Feed incoming bytes with `feed()`, retrieve complete packets from the
/// returned iterator. Queue outgoing packets with `queue_send()`, drain
/// encoded bytes with `try_get_tx()`.
///
/// TX packets are stored in a pre-allocated ring buffer and SLIP-encoded
/// on-the-fly when retrieved, avoiding per-packet allocation. The ring buffer
/// wraps around, so consumed space at the front can be reused even while
/// packets are still pending.
///
/// # Example
///
/// ```
/// use lichen_gateway::slip::SlipFramer;
///
/// let mut framer = SlipFramer::new();
///
/// framer.queue_send(b"hello").unwrap();
///
/// let mut tx_buf = [0u8; 64];
/// if let Ok(Some(len)) = framer.try_get_tx(&mut tx_buf) {
///     // use tx_buf[..len]
/// }
///
/// let wire_data = [0xC0, 0x48, 0x69, 0xC0];
/// let packets: Vec<_> = framer.feed(&wire_data).collect();
/// assert_eq!(packets.len(), 1);
/// assert_eq!(packets[0], b"Hi");
/// ```
pub struct SlipFramer {
    rx_buffer: Vec<u8>,
    rx_in_escape: bool,
    /// Pre-allocated ring buffer for TX packet data (raw, not yet SLIP-encoded).
    tx_buffer: Box<[u8; TX_BUFFER_SIZE]>,
    /// Start of first pending packet's data in ring buffer.
    tx_head: usize,
    /// Next write position in ring buffer (wraps around).
    tx_tail: usize,
    /// Queue of (offset, length) for pending packets in tx_buffer.
    tx_packets: VecDeque<(usize, usize)>,
}

impl Default for SlipFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl SlipFramer {
    /// Create a new framer.
    pub fn new() -> Self {
        Self {
            rx_buffer: Vec::with_capacity(2048),
            rx_in_escape: false,
            tx_buffer: Box::new([0u8; TX_BUFFER_SIZE]),
            tx_head: 0,
            tx_tail: 0,
            tx_packets: VecDeque::with_capacity(TX_QUEUE_CAPACITY),
        }
    }

    /// Feed incoming bytes and return an iterator of complete packets.
    ///
    /// Each call processes the input and yields any complete packets found.
    /// Partial packets are accumulated internally until complete.
    pub fn feed<'a>(&'a mut self, data: &'a [u8]) -> impl Iterator<Item = Vec<u8>> + 'a {
        SlipFeedIter {
            framer: self,
            data,
            pos: 0,
        }
    }

    /// Queue a packet for transmission.
    ///
    /// The packet data is copied to a pre-allocated ring buffer and SLIP-encoded
    /// on retrieval. Returns error if queue is full (max 8 pending packets)
    /// or if buffer space is exhausted. The ring buffer wraps around, so
    /// consumed space can be reused even while packets are pending.
    pub fn queue_send(&mut self, packet: &[u8]) -> Result<(), SlipError> {
        if self.tx_packets.len() >= TX_QUEUE_CAPACITY {
            return Err(SlipError::QueueFull);
        }

        // Reset both pointers when queue is empty
        if self.tx_packets.is_empty() {
            self.tx_head = 0;
            self.tx_tail = 0;
        }

        // Ring buffer space calculation:
        // - If tail >= head: data spans [head..tail), free is [tail..end) + [0..head)
        // - If tail < head: data spans [head..end) + [0..tail), free is [tail..head)
        if self.tx_tail >= self.tx_head {
            // Normal case: try to fit at end first
            let space_at_end = TX_BUFFER_SIZE - self.tx_tail;
            if packet.len() <= space_at_end {
                let offset = self.tx_tail;
                self.tx_buffer[offset..offset + packet.len()].copy_from_slice(packet);
                self.tx_tail += packet.len();
                self.tx_packets.push_back((offset, packet.len()));
                return Ok(());
            }
            // Doesn't fit at end, try wrapping to start (before head)
            if packet.len() <= self.tx_head {
                self.tx_buffer[..packet.len()].copy_from_slice(packet);
                self.tx_tail = packet.len();
                self.tx_packets.push_back((0, packet.len()));
                return Ok(());
            }
        } else {
            // Wrapped case: free space is [tail..head)
            let space = self.tx_head - self.tx_tail;
            if packet.len() <= space {
                let offset = self.tx_tail;
                self.tx_buffer[offset..offset + packet.len()].copy_from_slice(packet);
                self.tx_tail += packet.len();
                self.tx_packets.push_back((offset, packet.len()));
                return Ok(());
            }
        }

        Err(SlipError::PacketTooLarge)
    }
    /// Try to get the next SLIP-encoded TX frame.
    ///
    /// Encodes the packet on-the-fly into `out`. Returns `Ok(Some(n))` with bytes written
    /// or `Ok(None)` if queue empty. Returns `Err(BufferTooSmall)` if `out` is too small.
    pub fn try_get_tx(&mut self, out: &mut [u8]) -> Result<Option<usize>, SlipError> {
        let Some(&(offset, len)) = self.tx_packets.front() else {
            return Ok(None);
        };
        let packet = &self.tx_buffer[offset..offset + len];

        let worst_case = 2 + len * 2;
        if out.len() < worst_case {
            return Err(SlipError::BufferTooSmall { needed: worst_case });
        }

        self.tx_packets.pop_front();

        self.tx_head = self
            .tx_packets
            .front()
            .map(|&(next_offset, _)| next_offset)
            .unwrap_or(self.tx_tail);

        let mut pos = 0;

        out[pos] = FEND;
        pos += 1;

        for &byte in packet {
            let (escaped, esc_len) = slip_escape(byte);
            out[pos..pos + esc_len].copy_from_slice(&escaped[..esc_len]);
            pos += esc_len;
        }

        out[pos] = FEND;
        pos += 1;

        Ok(Some(pos))
    }

    /// Number of packets waiting in TX queue.
    pub fn tx_pending(&self) -> usize {
        self.tx_packets.len()
    }

    /// Check if TX queue is empty.
    pub fn tx_empty(&self) -> bool {
        self.tx_packets.is_empty()
    }

    /// Clear RX state and TX queue.
    pub fn clear(&mut self) {
        self.rx_buffer.clear();
        self.rx_in_escape = false;
        self.tx_head = 0;
        self.tx_tail = 0;
        self.tx_packets.clear();
    }

    /// Returns the current size of the RX buffer (for testing/diagnostics).
    #[cfg(test)]
    pub fn rx_buffer_len(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Process one byte, returning a complete packet if FEND delimiter received.
    fn process_byte(&mut self, byte: u8) -> Option<Vec<u8>> {
        let (result, new_escape) = slip_decode_byte(byte, self.rx_in_escape);
        self.rx_in_escape = new_escape;

        match result {
            SlipDecodeResult::End => {
                if self.rx_buffer.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.rx_buffer))
                }
            }
            SlipDecodeResult::Byte(b) => {
                // SECURITY: Prevent DoS via memory exhaustion by discarding
                // oversized frames. A malicious sender could transmit continuous
                // data without FEND delimiters to grow the buffer indefinitely.
                if self.rx_buffer.len() >= RX_BUFFER_MAX {
                    self.rx_buffer.clear();
                    self.rx_in_escape = false;
                    None
                } else {
                    self.rx_buffer.push(b);
                    None
                }
            }
            SlipDecodeResult::None => None,
        }
    }
}

/// Iterator over complete packets from a feed() call.
struct SlipFeedIter<'a> {
    framer: &'a mut SlipFramer,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for SlipFeedIter<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.data.len() {
            let byte = self.data[self.pos];
            self.pos += 1;
            if let Some(packet) = self.framer.process_byte(byte) {
                return Some(packet);
            }
        }
        None
    }
}

/// Send `packet` as a single SLIP frame on `writer`.
///
/// Surrounds the packet with FEND bytes and escapes any FEND/FESC bytes in the
/// payload per RFC 1055 S2.
pub async fn send_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    // slip_encode includes leading FEND (flushes garbage) and trailing FEND.
    let buf = slip_encode(packet);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Read one SLIP packet from `reader` into `buf`.
///
/// Blocks until a complete packet is received (terminated by FEND).
/// Returns the number of bytes written into `buf`, or an error if `buf`
/// is too small.
pub async fn recv_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut out = 0usize;
    let mut in_escape = false;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;

        let (result, new_escape) = slip_decode_byte(byte[0], in_escape);
        in_escape = new_escape;

        match result {
            SlipDecodeResult::End => {
                if out > 0 {
                    return Ok(out);
                }
                // Empty FEND: inter-packet separator, keep reading.
            }
            SlipDecodeResult::Byte(b) => {
                if out >= buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SLIP packet too large",
                    ));
                }
                buf[out] = b;
                out += 1;
            }
            SlipDecodeResult::None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(packet: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        send_packet(&mut wire, packet).await.unwrap();

        let mut decoded = vec![0u8; packet.len() + 4];
        let n = recv_packet(&mut wire.as_slice(), &mut decoded)
            .await
            .unwrap();
        decoded.truncate(n);
        decoded
    }

    #[tokio::test]
    async fn plain_packet() {
        let data = b"hello SLIP";
        assert_eq!(roundtrip(data).await, data);
    }

    #[tokio::test]
    async fn packet_with_fend_byte() {
        let data = [0x01, FEND, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_fesc_byte() {
        let data = [0x01, FESC, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_both_special_bytes() {
        let data = [FEND, FESC, FEND, 0x42, FESC];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[test]
    fn framer_simple_rx() {
        let mut framer = SlipFramer::new();
        let packets: Vec<_> = framer.feed(&[FEND, b'H', b'i', FEND]).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"Hi");
    }

    #[test]
    fn framer_partial_rx() {
        let mut framer = SlipFramer::new();

        // Feed partial packet
        let packets1: Vec<_> = framer.feed(&[FEND, b'H']).collect();
        assert!(packets1.is_empty());

        // Complete it
        let packets2: Vec<_> = framer.feed(&[b'i', FEND]).collect();
        assert_eq!(packets2.len(), 1);
        assert_eq!(packets2[0], b"Hi");
    }

    #[test]
    fn framer_multiple_rx() {
        let mut framer = SlipFramer::new();
        let packets: Vec<_> = framer.feed(&[FEND, b'A', FEND, FEND, b'B', FEND]).collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], b"A");
        assert_eq!(packets[1], b"B");
    }

    #[test]
    fn framer_rx_with_escapes() {
        let mut framer = SlipFramer::new();
        // "A" + FEND (escaped) + "B"
        let packets: Vec<_> = framer
            .feed(&[FEND, b'A', FESC, TFEND, b'B', FEND])
            .collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], &[b'A', FEND, b'B']);
    }

    #[test]
    fn framer_tx_queue() {
        let mut framer = SlipFramer::new();
        let mut out = [0u8; 64];

        framer.queue_send(b"Hi").unwrap();
        assert_eq!(framer.tx_pending(), 1);

        let len = framer.try_get_tx(&mut out).unwrap().unwrap();
        assert_eq!(&out[..len], &[FEND, b'H', b'i', FEND]);
        assert!(framer.tx_empty());
    }

    #[test]
    fn framer_tx_with_escapes() {
        let mut framer = SlipFramer::new();
        let mut out = [0u8; 64];

        framer.queue_send(&[b'A', FEND, b'B']).unwrap();
        let len = framer.try_get_tx(&mut out).unwrap().unwrap();
        assert_eq!(&out[..len], &[FEND, b'A', FESC, TFEND, b'B', FEND]);
    }

    #[test]
    fn framer_tx_worst_case_fits_public_buffer_size() {
        let mut framer = SlipFramer::new();
        let packet = [FEND; TX_BUFFER_SIZE];
        let mut out = [0u8; SLIP_TX_BUF_SIZE];

        framer.queue_send(&packet).unwrap();
        let len = framer.try_get_tx(&mut out).unwrap();

        assert_eq!(len, 8194);
        assert_eq!(out[0], FEND);
        assert_eq!(out[len - 1], FEND);
        assert!(out[1..len - 1]
            .chunks_exact(2)
            .all(|pair| pair == [FESC, TFEND]));
    }

    #[test]
    fn framer_retains_packet_when_tx_buffer_is_too_small() {
        let mut framer = SlipFramer::new();
        let packet = [FEND; TX_BUFFER_SIZE];
        let mut small = [0u8; SLIP_TX_BUF_SIZE - 1];
        let mut full = [0u8; SLIP_TX_BUF_SIZE];

        framer.queue_send(&packet).unwrap();
        assert_eq!(framer.try_get_tx(&mut small), None);
        assert_eq!(framer.tx_pending(), 1);
        assert_eq!(framer.try_get_tx(&mut full), Some(8194));
        assert!(framer.tx_empty());
    }

    #[test]
    fn framer_roundtrip() {
        let mut tx_framer = SlipFramer::new();
        let mut rx_framer = SlipFramer::new();
        let mut wire = [0u8; 64];

        // Encode with TX framer
        tx_framer.queue_send(b"Hello").unwrap();
        let len = tx_framer.try_get_tx(&mut wire).unwrap().unwrap();

        // Decode with RX framer
        let packets: Vec<_> = rx_framer.feed(&wire[..len]).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"Hello");
    }

    #[test]
    fn framer_rx_buffer_bounded() {
        // SECURITY: Verify RX buffer cannot grow beyond RX_BUFFER_MAX.
        // A malicious sender could transmit continuous data without FEND
        // delimiters to exhaust memory. The framer must discard such data.
        use super::RX_BUFFER_MAX;

        let mut framer = SlipFramer::new();

        // Feed data much larger than RX_BUFFER_MAX without any FEND delimiter.
        // Without the fix, this would allocate unbounded memory.
        // With the fix, buffer resets at RX_BUFFER_MAX, then bytes continue
        // accumulating until the next reset or FEND.
        let oversized = vec![0x42; RX_BUFFER_MAX * 3];
        let packets: Vec<_> = framer.feed(&oversized).collect();

        // No complete packet (no FEND received)
        assert!(packets.is_empty());

        // The key assertion: internal buffer length is bounded.
        // After processing 3*RX_BUFFER_MAX bytes, buffer would be ~12KB without fix.
        // With fix, it's at most RX_BUFFER_MAX bytes.
        assert!(framer.rx_buffer_len() <= RX_BUFFER_MAX);
    }

    #[test]
    fn framer_rx_buffer_recovers_after_discard() {
        // Verify that after discarding an oversized frame, normal operation resumes.
        use super::RX_BUFFER_MAX;

        let mut framer = SlipFramer::new();

        // Start a normal frame
        let _: Vec<_> = framer.feed(&[FEND, b'A', b'B']).collect();

        // Feed enough data to exceed the limit multiple times
        let attack_data = vec![0x99; RX_BUFFER_MAX * 2];
        let packets: Vec<_> = framer.feed(&attack_data).collect();
        assert!(packets.is_empty());

        // Buffer should be bounded
        assert!(framer.rx_buffer_len() <= RX_BUFFER_MAX);

        // Send a FEND to flush any garbage, then a clean frame
        let packets: Vec<_> = framer.feed(&[FEND, FEND, b'X', b'Y', b'Z', FEND]).collect();

        // Should get the clean XYZ frame (maybe preceded by garbage packet)
        let last_packet = packets.last().unwrap();
        assert_eq!(last_packet, b"XYZ");
    }

    #[test]
    fn framer_tx_ring_wraps() {
        // Test that TX ring buffer properly wraps around and reuses space
        // from consumed packets, even while other packets are pending.
        use super::TX_BUFFER_SIZE;

        let mut framer = SlipFramer::new();
        let mut out = [0u8; 8192];

        // Fill most of the buffer with a large packet
        let large = vec![0xAA; TX_BUFFER_SIZE - 100];
        framer.queue_send(&large).unwrap();
        assert_eq!(framer.tx_pending(), 1);

        // Consume the large packet - frees space at the front
        let len = framer.try_get_tx(&mut out).unwrap().unwrap();
        assert!(len > 0);
        assert!(framer.tx_empty());

        // Queue another large packet that uses the freed space
        framer.queue_send(&large).unwrap();
        assert_eq!(framer.tx_pending(), 1);

        // Now the real test: queue + consume in a loop to force wrap
        // With proper ring buffer, this should work indefinitely.
        // With the old broken impl, it would fail after the buffer fills.
        for i in 0..20 {
            // Queue a small packet while another is pending
            let small = [i as u8; 50];
            framer.queue_send(&small).unwrap();
            assert_eq!(framer.tx_pending(), 2);

            let _ = framer.try_get_tx(&mut out).unwrap().unwrap();
            assert_eq!(framer.tx_pending(), 1);

            // Replace consumed large packet with new one
            // This should wrap around to use space freed by consumed packets
            framer.queue_send(&large).unwrap();
            assert_eq!(framer.tx_pending(), 2);

            let len = framer.try_get_tx(&mut out).unwrap().unwrap();
            assert_eq!(len, 52);
            assert_eq!(framer.tx_pending(), 1);
        }
    }
}
