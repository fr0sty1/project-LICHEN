//! LICHEN frame format (spec section 4).

/// Destination addressing mode (LLSec bits 0-1, spec 4.3).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrMode {
    /// Broadcast — zero address bytes.
    None = 0,
    /// 16-bit short address — 2 bytes.
    Short = 1,
    /// EUI-64 extended address — 8 bytes.
    Extended = 2,
    /// Elided — derived from IPv6 destination — 0 bytes.
    Elided = 3,
}

impl AddrMode {
    pub fn addr_len(self) -> usize {
        match self {
            AddrMode::None | AddrMode::Elided => 0,
            AddrMode::Short => 2,
            AddrMode::Extended => 8,
        }
    }
}

/// MIC length setting (LLSec bits 2-4, spec 4.2).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MicLength {
    /// 4-byte (32-bit) MIC.
    Bits32 = 0,
    /// 8-byte (64-bit) MIC.
    Bits64 = 1,
}

impl MicLength {
    pub fn mic_len(self) -> usize {
        match self {
            MicLength::Bits32 => 4,
            MicLength::Bits64 => 8,
        }
    }
}

// LLSec bitmasks
const ADDR_MODE_MASK: u8 = 0b0000_0011;
const MIC_LEN_SHIFT: u8 = 2;
const MIC_LEN_MASK: u8 = 0b0000_0111;
const SIGNATURE_BIT: u8 = 1 << 5;
const ENCRYPTED_BIT: u8 = 1 << 6;
const RESERVED_BIT: u8 = 1 << 7;

/// Maximum body length in bytes (the Length field is a single byte).
pub const MAX_FRAME_BODY: usize = 255;

/// Error type for link-layer frame parsing and serialisation.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Empty,
    TruncatedBody,
    BodyTooShort,
    ReservedBitSet,
    ReservedMicLength(u8),
    AddrLenMismatch,
    MicLenMismatch,
    FrameTooLarge,
}

/// A parsed LICHEN link-layer frame.
///
/// Payload is stored as a reference to avoid heap allocation in `no_std`
/// contexts. Use [`LichenFrameBuf`] for an owned variant (future work).
#[derive(Debug)]
pub struct LichenFrame<'a> {
    pub epoch: u8,
    pub seqnum: u16,
    pub dst_addr: &'a [u8],
    pub payload: &'a [u8],
    pub mic: &'a [u8],
    pub addr_mode: AddrMode,
    pub mic_length: MicLength,
    pub signature_present: bool,
    pub encrypted: bool,
}

impl<'a> LichenFrame<'a> {
    /// Compute the LLSec flags byte from this frame's fields.
    pub fn llsec_byte(&self) -> u8 {
        let mut v = (self.addr_mode as u8) & ADDR_MODE_MASK;
        v |= ((self.mic_length as u8) & MIC_LEN_MASK) << MIC_LEN_SHIFT;
        if self.signature_present { v |= SIGNATURE_BIT; }
        if self.encrypted { v |= ENCRYPTED_BIT; }
        v
    }

    /// Serialize the frame into `buf`, returning the number of bytes written.
    ///
    /// Returns `FrameError::FrameTooLarge` if the body exceeds 255 bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, FrameError> {
        let body_len = 1 + 1 + 2 + self.dst_addr.len() + self.payload.len() + self.mic.len();
        if body_len > MAX_FRAME_BODY {
            return Err(FrameError::FrameTooLarge);
        }
        let total = 1 + body_len;
        if buf.len() < total {
            return Err(FrameError::FrameTooLarge);
        }
        buf[0] = body_len as u8;
        buf[1] = self.llsec_byte();
        buf[2] = self.epoch;
        buf[3] = (self.seqnum >> 8) as u8;
        buf[4] = self.seqnum as u8;
        let mut off = 5;
        buf[off..off + self.dst_addr.len()].copy_from_slice(self.dst_addr);
        off += self.dst_addr.len();
        buf[off..off + self.payload.len()].copy_from_slice(self.payload);
        off += self.payload.len();
        buf[off..off + self.mic.len()].copy_from_slice(self.mic);
        off += self.mic.len();
        Ok(off)
    }

    /// Parse a frame from a byte slice.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FrameError> {
        if data.is_empty() {
            return Err(FrameError::Empty);
        }
        let length = data[0] as usize;
        let body = data.get(1..1 + length).ok_or(FrameError::TruncatedBody)?;
        if length < 4 {
            return Err(FrameError::BodyTooShort);
        }
        let llsec = body[0];
        if llsec & RESERVED_BIT != 0 {
            return Err(FrameError::ReservedBitSet);
        }
        let addr_mode = match llsec & ADDR_MODE_MASK {
            0 => AddrMode::None,
            1 => AddrMode::Short,
            2 => AddrMode::Extended,
            3 => AddrMode::Elided,
            _ => unreachable!(),
        };
        let mic_field = (llsec >> MIC_LEN_SHIFT) & MIC_LEN_MASK;
        let mic_length = match mic_field {
            0 => MicLength::Bits32,
            1 => MicLength::Bits64,
            v => return Err(FrameError::ReservedMicLength(v)),
        };
        let epoch = body[1];
        let seqnum = u16::from_be_bytes([body[2], body[3]]);
        let addr_len = addr_mode.addr_len();
        let mic_len = mic_length.mic_len();
        if body.len() < 4 + addr_len + mic_len {
            return Err(FrameError::BodyTooShort);
        }
        let dst_addr = &body[4..4 + addr_len];
        let payload_end = body.len() - mic_len;
        let payload = &body[4 + addr_len..payload_end];
        let mic = &body[payload_end..];
        Ok(LichenFrame {
            epoch,
            seqnum,
            dst_addr,
            payload,
            mic,
            addr_mode,
            mic_length,
            signature_present: llsec & SIGNATURE_BIT != 0,
            encrypted: llsec & ENCRYPTED_BIT != 0,
        })
    }
}
