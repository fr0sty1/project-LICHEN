//! LICHEN frame format (spec section 4).

use crate::seqnum::LinkSeqNum;
use lichen_core::error::{BufferTooSmall, TooShort};

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

    /// Try to determine AddrMode from address byte length.
    pub fn from_addr_len(len: usize) -> Option<Self> {
        match len {
            0 => Some(Self::None),
            2 => Some(Self::Short),
            8 => Some(Self::Extended),
            _ => None,
        }
    }
}

/// MIC length setting (LLSec bits 2-4, spec 4.2).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MicLength {
    /// Compatibility selector; unsigned frames have no MIC.
    Bits32 = 0,
    /// Compatibility selector; unsigned frames have no MIC.
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
}

/// Whether the frame includes a Schnorr signature (LLSec bit 5, spec 4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Signature {
    /// No signature present in the MIC field.
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
    /// Encrypted payload flag; encrypted link frames are unsupported.
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

/// Maximum serialized LoRa frame length, including the Length field.
pub const MAX_FRAME_LEN: usize = 255;

/// Maximum body length represented by the Length field.
pub const MAX_FRAME_BODY: usize = MAX_FRAME_LEN - 1;

/// Error type for link-layer frame parsing and serialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    Empty,
    TooShort(TooShort),
    BufferTooSmall(BufferTooSmall),
    ReservedBitSet,
    ReservedMicLength(u8),
    AddrLenMismatch,
    MicLenMismatch,
    SignatureMicMismatch,
    SignedEncryptedUnsupported,
    TrailingBytes,
    FrameTooLarge,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame"),
            Self::TooShort(e) => write!(f, "frame {}", e),
            Self::BufferTooSmall(e) => write!(f, "frame {}", e),
            Self::ReservedBitSet => write!(f, "reserved bit set"),
            Self::ReservedMicLength(v) => write!(f, "reserved MIC length: {}", v),
            Self::AddrLenMismatch => write!(f, "address length mismatch"),
            Self::MicLenMismatch => write!(f, "MIC length mismatch"),
            Self::SignatureMicMismatch => write!(f, "signature MIC must be 48 bytes"),
            Self::SignedEncryptedUnsupported => {
                write!(f, "signed and encrypted frames are unsupported")
            }
            Self::TrailingBytes => write!(f, "trailing bytes after frame"),
            Self::FrameTooLarge => write!(f, "frame too large"),
        }
    }
}

impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for FrameError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for FrameError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
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
/// contexts. Use `LichenFrameBuf` (future work) for an owned variant.
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

    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, FrameError> {
        if self.signature.is_present() && self.encryption.is_encrypted() {
            return Err(FrameError::SignedEncryptedUnsupported);
        }
        if self.addr_mode.addr_len() != self.dst_addr.len() {
            return Err(FrameError::AddrLenMismatch);
        }
        let expected_mic_len = if self.signature.is_present() { 48 } else { 0 };
        if self.mic.len() != expected_mic_len {
            return Err(if self.signature.is_present() {
                FrameError::SignatureMicMismatch
            } else {
                FrameError::MicLenMismatch
            });
        }
        let body_len = 4 + self.dst_addr.len() + self.payload.len() + self.mic.len();
        if body_len > MAX_FRAME_BODY {
            return Err(FrameError::FrameTooLarge);
        }
        let total = 1 + body_len;
        if buf.len() < total {
            return Err(BufferTooSmall::new(total, buf.len()).into());
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
        if data.len() > MAX_FRAME_LEN {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("oversized input can fail before length read");
            return Err(FrameError::FrameTooLarge);
        }
        let length = data[0] as usize;
        transition_frame_state(&mut state, FrameProcessingState::LengthRead)
            .expect("non-empty frame can read length");
        if length > MAX_FRAME_BODY {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail size check");
            return Err(FrameError::FrameTooLarge);
        }
        let expected_total = 1 + length;
        if data.len() > expected_total {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("length-read frame can fail trailing-bytes check");
            return Err(FrameError::TrailingBytes);
        }
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
        let signature = llsec & SIGNATURE_BIT != 0;
        if signature && llsec & ENCRYPTED_BIT != 0 {
            transition_frame_state(&mut state, FrameProcessingState::Failed)
                .expect("header-read frame can reject signed encrypted combination");
            return Err(FrameError::SignedEncryptedUnsupported);
        }
        let mic_len = if signature { 48 } else { 0 };
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
            signature: if signature {
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
    use std::vec;

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
        let wire = from_hex("0700010002616263");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 1);
        assert_eq!(frame.seqnum.get(), 2);
        assert_eq!(frame.dst_addr, &[] as &[u8]);
        assert_eq!(frame.payload, b"abc");
        assert_eq!(frame.mic, &[] as &[u8]);
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
        let wire = from_hex("0801102030abcd6869");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 16);
        assert_eq!(frame.seqnum.get(), 0x2030);
        assert_eq!(frame.dst_addr, &[0xab, 0xcd]);
        assert_eq!(frame.payload, b"hi");
        assert_eq!(frame.mic, &[] as &[u8]);
        assert_eq!(frame.addr_mode, AddrMode::Short);
        assert_eq!(frame.mic_length, MicLength::Bits32);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn extended_addr_mic64_roundtrip() {
        let wire = from_hex("1006ffffff000102030405060764617461");
        let frame = LichenFrame::from_bytes(&wire).unwrap();
        assert_eq!(frame.epoch, 255);
        assert_eq!(frame.seqnum.get(), 0xffff);
        assert_eq!(frame.dst_addr, &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(frame.payload, b"data");
        assert_eq!(frame.mic, &[] as &[u8]);
        assert_eq!(frame.addr_mode, AddrMode::Extended);
        assert_eq!(frame.mic_length, MicLength::Bits64);
        let mut buf = [0u8; 64];
        let n = frame.write_to(&mut buf).unwrap();
        assert_eq!(&buf[..n], &wire[..]);
    }

    #[test]
    fn signed_encrypted_is_rejected() {
        let mut wire = vec![0x35, 0x60, 0x03, 0x00, 0x04, 0x78];
        wire.extend([0u8; 48]);
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::SignedEncryptedUnsupported)
        );
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

    #[test]
    fn trailing_bytes_error() {
        let mut wire = from_hex("0700010002616263");
        wire.push(0xff);
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::TrailingBytes)
        );
    }

    #[test]
    fn signed_short_mic_error() {
        let wire = [9, 0x20, 1, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::TooShort(_))
        ));
    }

    #[test]
    fn serializer_rejects_inconsistent_lengths() {
        let frame = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[0xaa],
            payload: &[],
            mic: &[],
            addr_mode: AddrMode::Short,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        assert_eq!(
            frame.write_to(&mut [0; 32]),
            Err(FrameError::AddrLenMismatch)
        );

        let frame = LichenFrame {
            dst_addr: &[],
            mic: &[],
            addr_mode: AddrMode::None,
            signature: Signature::Present,
            ..frame
        };
        assert_eq!(
            frame.write_to(&mut [0; 64]),
            Err(FrameError::SignatureMicMismatch)
        );

        let frame = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[],
            payload: &[0; 252],
            mic: &[],
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        assert_eq!(
            frame.write_to(&mut [0; 300]),
            Err(FrameError::FrameTooLarge)
        );

        let frame = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[],
            payload: &[],
            mic: &[],
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        assert!(matches!(
            frame.write_to(&mut [0; 4]),
            Err(FrameError::BufferTooSmall(_))
        ));
    }

    #[test]
    fn write_to_distinguishes_buffer_too_small_from_body_too_large() {
        let frame = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[],
            payload: b"test",
            mic: &[],
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        let mut small_buf = [0u8; 5];
        assert_eq!(
            frame.write_to(&mut small_buf),
            Err(FrameError::BufferTooSmall(BufferTooSmall::new(9, 5)))
        );

        let large_payload = vec![0u8; 260];
        let large_frame = LichenFrame {
            payload: &large_payload,
            ..frame
        };
        let mut buf = [0u8; 300];
        assert_eq!(
            large_frame.write_to(&mut buf),
            Err(FrameError::FrameTooLarge)
        );
    }

    // ─── Cross-validation tests from spec/test-vectors/frame.json ───────────────

    mod spec_vectors {
        use super::*;
        use serde::Deserialize;
        use std::string::String;
        use std::vec::Vec;

        const FRAME_VECTORS_JSON: &str = include_str!("../../../spec/test-vectors/frame.json");

        #[derive(Deserialize)]
        struct VectorFile {
            vectors: Vec<TestVector>,
        }

        #[derive(Deserialize)]
        struct TestVector {
            name: String,
            input_hex: String,
            expected: Expected,
        }

        #[derive(Deserialize)]
        struct Expected {
            #[serde(default)]
            error: bool,
            #[serde(default)]
            error_type: String,
            #[serde(default)]
            addr_mode: u8,
            #[serde(default)]
            mic_length: u8,
            #[serde(default)]
            signature_present: bool,
            #[serde(default)]
            encrypted: bool,
            #[serde(default)]
            epoch: u8,
            #[serde(default)]
            seqnum: u16,
            #[serde(default)]
            dst_addr_hex: String,
            #[serde(default)]
            payload_hex: String,
            #[serde(default)]
            payload_len: Option<usize>,
            #[serde(default)]
            payload_fill_hex: String,
            #[serde(default)]
            payload_fill_len: Option<usize>,
            #[serde(default)]
            payload_suffix_hex: String,
            #[serde(default)]
            mic_hex: String,
        }

        fn hex_decode(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        #[test]
        fn cross_validate_parse() {
            let file: VectorFile =
                serde_json::from_str(FRAME_VECTORS_JSON).expect("failed to parse frame.json");

            for vector in &file.vectors {
                let name = &vector.name;

                let data = hex_decode(&vector.input_hex);

                // Error cases
                if vector.expected.error {
                    let error = LichenFrame::from_bytes(&data)
                        .expect_err("invalid vector unexpectedly parsed");
                    let matches_type = match vector.expected.error_type.as_str() {
                        "empty_frame" => error == FrameError::Empty,
                        "length_mismatch" | "frame_too_short" => {
                            matches!(error, FrameError::TooShort(_))
                        }
                        "reserved_bit_set" => error == FrameError::ReservedBitSet,
                        "reserved_mic_length" => error == FrameError::ReservedMicLength(2),
                        "signed_encrypted_unsupported" => error == FrameError::SignedEncryptedUnsupported,
                        "frame_too_large" => error == FrameError::FrameTooLarge,
                        _ => false,
                    };
                    assert!(
                        matches_type,
                        "{}: expected {}, got {:?}",
                        name, vector.expected.error_type, error
                    );
                    continue;
                }

                // Valid frame - parse and verify
                let frame = LichenFrame::from_bytes(&data)
                    .unwrap_or_else(|e| panic!("{}: parse failed: {:?}", name, e));

                assert_eq!(
                    frame.addr_mode as u8, vector.expected.addr_mode,
                    "{}: addr_mode",
                    name
                );
                assert_eq!(
                    frame.mic_length as u8, vector.expected.mic_length,
                    "{}: mic_length",
                    name
                );
                assert_eq!(
                    frame.signature.is_present(),
                    vector.expected.signature_present,
                    "{}: signature_present",
                    name
                );
                assert_eq!(
                    frame.encryption.is_encrypted(),
                    vector.expected.encrypted,
                    "{}: encrypted",
                    name
                );
                assert_eq!(frame.epoch, vector.expected.epoch, "{}: epoch", name);
                assert_eq!(
                    frame.seqnum.get(),
                    vector.expected.seqnum,
                    "{}: seqnum",
                    name
                );
                assert_eq!(
                    frame.dst_addr,
                    hex_decode(&vector.expected.dst_addr_hex).as_slice(),
                    "{}: dst_addr",
                    name
                );
                assert_eq!(
                    frame.mic,
                    hex_decode(&vector.expected.mic_hex).as_slice(),
                    "{}: mic",
                    name
                );

                // Payload - check by length if specified
                if let Some(expected_len) = vector.expected.payload_len {
                    assert_eq!(frame.payload.len(), expected_len, "{}: payload_len", name);
                    if let Some(fill_len) = vector.expected.payload_fill_len {
                        let fill = hex_decode(&vector.expected.payload_fill_hex);
                        assert_eq!(fill.len(), 1, "{}: payload fill byte", name);
                        assert!(
                            frame.payload[..fill_len]
                                .iter()
                                .all(|byte| *byte == fill[0]),
                            "{}: payload fill",
                            name
                        );
                        assert_eq!(
                            &frame.payload[fill_len..],
                            hex_decode(&vector.expected.payload_suffix_hex).as_slice(),
                            "{}: payload suffix",
                            name
                        );
                    }
                } else {
                    assert_eq!(
                        frame.payload,
                        hex_decode(&vector.expected.payload_hex).as_slice(),
                        "{}: payload",
                        name
                    );
                }
            }
        }

        #[test]
        fn cross_validate_roundtrip() {
            let file: VectorFile =
                serde_json::from_str(FRAME_VECTORS_JSON).expect("failed to parse frame.json");

            for vector in &file.vectors {
                // Skip error/empty cases
                if vector.expected.error || vector.input_hex.is_empty() {
                    continue;
                }

                let name = &vector.name;
                let data = hex_decode(&vector.input_hex);
                let frame = LichenFrame::from_bytes(&data).unwrap();

                let mut buf = [0u8; 300];
                let n = frame
                    .write_to(&mut buf)
                    .unwrap_or_else(|e| panic!("{}: write failed: {:?}", name, e));
                assert_eq!(&buf[..n], &data[..], "{}: roundtrip", name);
            }
        }
    }
}
