//! LICHEN frame format (spec section 4).

use crate::seqnum::LinkSeqNum;
use lichen_core::error::TooShort;

/// Coarse states in zero-copy link-frame parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameProcessingState {
    Start,
    LengthRead,
    HeaderRead,
    Parsed,
    Failed,
}

impl FrameProcessingState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Start, Self::LengthRead)
                | (Self::Start, Self::Failed)
                | (Self::LengthRead, Self::HeaderRead)
                | (Self::LengthRead, Self::Failed)
                | (Self::HeaderRead, Self::Parsed)
                | (Self::HeaderRead, Self::Failed)
                | (Self::Parsed, Self::Parsed)
                | (Self::Failed, Self::Failed)
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvalidFrameProcessingTransition {
    pub from: FrameProcessingState,
    pub to: FrameProcessingState,
}

fn transition_frame_state(
    state: &mut FrameProcessingState,
    next: FrameProcessingState,
) -> Result<(), InvalidFrameProcessingTransition> {
    if state.can_transition_to(next) {
        *state = next;
        Ok(())
    } else {
        Err(InvalidFrameProcessingTransition {
            from: *state,
            to: next,
        })
    }
}

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
    /// Try to convert a u8 to an AddrMode.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Short),
            2 => Some(Self::Extended),
            3 => Some(Self::Elided),
            _ => None,
        }
    }

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
    /// Try to convert a u8 to a MicLength.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Bits32),
            1 => Some(Self::Bits64),
            _ => None,
        }
    }

    pub fn mic_len(self) -> usize {
        match self {
            MicLength::Bits32 => 4,
            MicLength::Bits64 => 8,
        }
    }
}

/// Whether the frame includes a Schnorr signature (LLSec bit 5, spec 4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Signature {
    /// No signature appended.
    #[default]
    Absent,
    /// 48-byte Schnorr signature present.
    Present,
}

impl Signature {
    /// Returns true if a signature is present.
    pub fn is_present(self) -> bool {
        matches!(self, Signature::Present)
    }
}

/// Whether the frame payload is encrypted (LLSec bit 6, spec 4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Encryption {
    /// Payload is plaintext.
    #[default]
    Plaintext,
    /// Payload is AES-CCM encrypted.
    Encrypted,
}

impl Encryption {
    /// Returns true if payload is encrypted.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Encryption::Encrypted)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    Empty,
    TooShort(TooShort),
    ReservedBitSet,
    ReservedMicLength(u8),
    AddrLenMismatch,
    MicLenMismatch,
    FrameTooLarge,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame"),
            Self::TooShort(e) => write!(f, "frame {}", e),
            Self::ReservedBitSet => write!(f, "reserved bit set"),
            Self::ReservedMicLength(v) => write!(f, "reserved MIC length: {}", v),
            Self::AddrLenMismatch => write!(f, "address length mismatch"),
            Self::MicLenMismatch => write!(f, "MIC length mismatch"),
            Self::FrameTooLarge => write!(f, "frame too large"),
        }
    }
}

impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for FrameError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

/// A parsed LICHEN link-layer frame.
///
/// # Security: Unverified Structure
///
/// **This struct represents a *parsed* frame, not a *verified* one.**
///
/// The `signature` field indicates whether a signature is *present* in the wire
/// format, NOT whether it has been cryptographically verified. Similarly, the
/// `mic` field contains the raw MIC bytes but does not imply authentication.
///
/// Callers must use `LinkLayer::verify()` or equivalent to cryptographically
/// validate frames before trusting their contents. A `LichenFrame` obtained
/// from `from_bytes()` should be treated as untrusted input.
///
/// Payload is stored as a reference to avoid heap allocation in `no_std`
/// contexts. Use [`LichenFrameBuf`] for an owned variant (future work).
#[derive(Debug, PartialEq, Eq)]
pub struct LichenFrame<'a> {
    pub epoch: u8,
    pub seqnum: LinkSeqNum,
    pub dst_addr: &'a [u8],
    pub payload: &'a [u8],
    pub mic: &'a [u8],
    pub addr_mode: AddrMode,
    pub mic_length: MicLength,
    pub signature: Signature,
    pub encryption: Encryption,
}

impl<'a> LichenFrame<'a> {
    /// Compute the LLSec flags byte from this frame's fields.
    pub fn llsec_byte(&self) -> u8 {
        let mut v = (self.addr_mode as u8) & ADDR_MODE_MASK;
        v |= ((self.mic_length as u8) & MIC_LEN_MASK) << MIC_LEN_SHIFT;
        if self.signature.is_present() {
            v |= SIGNATURE_BIT;
        }
        if self.encryption.is_encrypted() {
            v |= ENCRYPTED_BIT;
        }
        v
    }

    /// Serialize the frame into `buf`, returning the number of bytes written.
    ///
    /// Returns `FrameError::FrameTooLarge` if the body exceeds 255 bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, FrameError> {
        // body = LLSec(1) + epoch(1) + seqnum(2) + dst_addr + payload + MIC
        let body_len = 4 + self.dst_addr.len() + self.payload.len() + self.mic.len();
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
        let seqnum_bytes = self.seqnum.to_be_bytes();
        buf[3] = seqnum_bytes[0];
        buf[4] = seqnum_bytes[1];
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
    ///
    /// # Panics
    ///
    /// This function does not panic. Internal `.expect()` calls guard state
    /// machine transitions that are provably valid by control flow. Malformed
    /// input returns `Err(FrameError)`, never a panic.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FrameError> {
        let mut state = FrameProcessingState::Start;
        if data.is_empty() {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("empty input can fail before length read");
            return Err(FrameError::Empty);
        }
        let length = data[0] as usize;
        transition_frame_state(&mut state, FrameProcessingState::LengthRead)
            .expect("non-empty frame can read length");
        let expected_total = 1 + length;
        let Some(body) = data.get(1..expected_total) else {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail bounds check");
            return Err(TooShort::new(expected_total, data.len()).into());
        };
        if length < 4 {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail minimum body length check");
            return Err(TooShort::new(4, length).into());
        }
        let llsec = body[0];
        if llsec & RESERVED_BIT != 0 {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail LLSec reserved bit check");
            return Err(FrameError::ReservedBitSet);
        }
        // ADDR_MODE_MASK is 0b11, so value is always 0-3; from_u8 covers all cases
        let addr_mode = AddrMode::from_u8(llsec & ADDR_MODE_MASK).unwrap();
        let mic_field = (llsec >> MIC_LEN_SHIFT) & MIC_LEN_MASK;
        let Some(mic_length) = MicLength::from_u8(mic_field) else {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail MIC length decoding");
            return Err(FrameError::ReservedMicLength(mic_field));
        };
        let epoch = body[1];
        let seqnum = LinkSeqNum::from_be_bytes([body[2], body[3]]);
        transition_frame_state(&mut state, FrameProcessingState::HeaderRead)
            .expect("valid fixed header can advance to header-read");
        let addr_len = addr_mode.addr_len();
        let mic_len = mic_length.mic_len();
        let min_body = 4 + addr_len + mic_len;
        if body.len() < min_body {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("header-read frame can fail variable length check");
            return Err(TooShort::new(min_body, body.len()).into());
        }
        let dst_addr = &body[4..4 + addr_len];
        let payload_end = body.len() - mic_len;
        let payload = &body[4 + addr_len..payload_end];
        let mic = &body[payload_end..];
        transition_frame_state(&mut state, FrameProcessingState::Parsed)
            .expect("header-read frame can parse successfully");
        Ok(LichenFrame {
            epoch,
            seqnum,
            dst_addr,
            payload,
            mic,
            addr_mode,
            mic_length,
            signature: if llsec & SIGNATURE_BIT != 0 {
                Signature::Present
            } else {
                Signature::Absent
            },
            encryption: if llsec & ENCRYPTED_BIT != 0 {
                Encryption::Encrypted
            } else {
                Encryption::Plaintext
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::from_hex;

    #[test]
    fn frame_processing_transition_table_rejects_recovery_from_failure() {
        assert!(FrameProcessingState::Start.can_transition_to(FrameProcessingState::LengthRead));
        assert!(
            FrameProcessingState::LengthRead.can_transition_to(FrameProcessingState::HeaderRead)
        );
        assert!(FrameProcessingState::HeaderRead.can_transition_to(FrameProcessingState::Parsed));
        assert!(!FrameProcessingState::Failed.can_transition_to(FrameProcessingState::Parsed));
        assert!(!FrameProcessingState::Parsed.can_transition_to(FrameProcessingState::HeaderRead));
    }

    #[test]
    fn broadcast_min_roundtrip() {
        let wire = from_hex("0b0001000261626301020304");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 1);
        assert_eq!(frame.seqnum.get(), 2);
        assert_eq!(frame.dst_addr, &[] as &[u8]);
        assert_eq!(frame.payload, b"abc");
        assert_eq!(frame.mic, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(frame.addr_mode, AddrMode::None);
        assert_eq!(frame.mic_length, MicLength::Bits32);
        assert_eq!(frame.signature, Signature::Absent);
        assert_eq!(frame.encryption, Encryption::Plaintext);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn short_addr_roundtrip() {
        let wire = from_hex("0c01102030abcd686900000000");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 16);
        assert_eq!(frame.seqnum.get(), 0x2030);
        assert_eq!(frame.dst_addr, &[0xab, 0xcd]);
        assert_eq!(frame.payload, b"hi");
        assert_eq!(frame.mic, &[0u8; 4]);
        assert_eq!(frame.addr_mode, AddrMode::Short);
        assert_eq!(frame.mic_length, MicLength::Bits32);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn extended_addr_mic64_roundtrip() {
        let wire = from_hex("1806ffffff0001020304050607646174610001020304050607");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 255);
        assert_eq!(frame.seqnum.get(), 0xffff);
        assert_eq!(frame.dst_addr, &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(frame.payload, b"data");
        assert_eq!(frame.mic, &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(frame.addr_mode, AddrMode::Extended);
        assert_eq!(frame.mic_length, MicLength::Bits64);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn signed_encrypted_roundtrip() {
        let wire = from_hex("09600300047800000000");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 3);
        assert_eq!(frame.seqnum.get(), 4);
        assert_eq!(frame.dst_addr, &[] as &[u8]);
        assert_eq!(frame.payload, &[0x78]);
        assert_eq!(frame.mic, &[0u8; 4]);
        assert_eq!(frame.signature, Signature::Present);
        assert_eq!(frame.encryption, Encryption::Encrypted);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn empty_input_error() {
        assert_eq!(LichenFrame::from_bytes(&[]), Err(FrameError::Empty));
    }

    #[test]
    fn too_short_error() {
        assert!(matches!(
            LichenFrame::from_bytes(&[0x0f, 0x00]),
            Err(FrameError::TooShort(_))
        ));
    }

    #[test]
    fn reserved_bit_error() {
        let wire = from_hex("0b8001000261626301020304");
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::ReservedBitSet)
        );
    }
}
