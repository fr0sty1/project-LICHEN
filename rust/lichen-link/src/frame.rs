//! LICHEN frame format (spec section 4).

use crate::seqnum::LinkSeqNum;
use lichen_core::error::{BufferTooSmall, TooShort};

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
///
/// Wire values 0 and 1 select the compatibility encodings below. Values 2
/// through 7 are reserved and are rejected by [`LichenFrame::from_bytes`]
/// with [`FrameError::ReservedMicLength`].
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
const SIGNER_EUI64_BIT: u8 = 1 << 7;

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
    SignatureSignerMismatch,
    EncryptedUnsupported,
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
            Self::SignatureSignerMismatch => write!(
                f,
                "signer EUI-64 must be 8 bytes when signed, empty when unsigned"
            ),
            Self::EncryptedUnsupported => {
                write!(f, "encrypted frames are unsupported")
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
/// Production receivers must pass wire bytes to
/// `LinkLayer::receive_frame` (or `LinkLayer::receive_frame_at`) and trust only
/// the returned `AuthenticatedFrame`. A `LichenFrame` obtained from
/// `from_bytes()` is untrusted input; successful parsing and
/// [`Signature::Present`] are not proof of authenticity.
///
/// Payload is stored as a reference to avoid heap allocation in `no_std`
/// contexts. Use `LichenFrameBuf` (future work) for an owned variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LichenFrame<'a> {
    pub epoch: u8,
    pub seqnum: LinkSeqNum,
    pub dst_addr: &'a [u8],
    /// Canonical signer EUI-64, present exactly when `signature` is present.
    pub signer_eui64: &'a [u8],
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
            v |= SIGNER_EUI64_BIT;
        }
        if self.encryption.is_encrypted() {
            v |= ENCRYPTED_BIT;
        }
        v
    }

    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, FrameError> {
        if self.encryption.is_encrypted() {
            return Err(FrameError::EncryptedUnsupported);
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
        let signer_len_ok = if self.signature.is_present() {
            self.signer_eui64.len() == 8
        } else {
            self.signer_eui64.is_empty()
        };
        if !signer_len_ok {
            return Err(FrameError::SignatureSignerMismatch);
        }
        let body_len =
            4 + self.dst_addr.len() + self.signer_eui64.len() + self.payload.len() + self.mic.len();
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
        buf[off..off + self.signer_eui64.len()].copy_from_slice(self.signer_eui64);
        off += self.signer_eui64.len();
        buf[off..off + self.payload.len()].copy_from_slice(self.payload);
        off += self.payload.len();
        buf[off..off + self.mic.len()].copy_from_slice(self.mic);
        off += self.mic.len();
        Ok(off)
    }

    /// Parse a frame from a byte slice.
    ///
    /// Malformed input returns `Err(FrameError)`.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FrameError> {
        if data.is_empty() {
            return Err(FrameError::Empty);
        }
        if data.len() > MAX_FRAME_LEN {
            return Err(FrameError::FrameTooLarge);
        }
        let length = data[0] as usize;
        if length > MAX_FRAME_BODY {
            return Err(FrameError::FrameTooLarge);
        }
        let expected_total = 1 + length;
        if data.len() > expected_total {
            return Err(FrameError::TrailingBytes);
        }
        let Some(body) = data.get(1..expected_total) else {
            return Err(TooShort::new(expected_total, data.len()).into());
        };
        if length < 4 {
            return Err(TooShort::new(4, length).into());
        }
        let llsec = body[0];
        // SECURITY: Encrypted frames are unsupported; receivers MUST reject
        // them before signature or reserved-bit processing so E=1 always
        // reports as `EncryptedUnsupported` (spec 4.2, link_frame.json
        // `signed_encrypted_unsupported`).
        if llsec & ENCRYPTED_BIT != 0 {
            return Err(FrameError::EncryptedUnsupported);
        }
        let addr_mode = match llsec & ADDR_MODE_MASK {
            0 => AddrMode::None,
            1 => AddrMode::Short,
            2 => AddrMode::Extended,
            _ => AddrMode::Elided,
        };
        let mic_field = (llsec >> MIC_LEN_SHIFT) & MIC_LEN_MASK;
        let Some(mic_length) = MicLength::from_u8(mic_field) else {
            return Err(FrameError::ReservedMicLength(mic_field));
        };
        let epoch = body[1];
        let seqnum = LinkSeqNum::from_be_bytes([body[2], body[3]]);
        let addr_len = addr_mode.addr_len();
        let signature = llsec & SIGNATURE_BIT != 0;
        let signer_present = llsec & SIGNER_EUI64_BIT != 0;
        if signature != signer_present {
            return Err(FrameError::SignatureSignerMismatch);
        }
        let signer_len = if signer_present { 8 } else { 0 };
        let mic_len = if signature { 48 } else { 0 };
        let min_body = 4 + addr_len + signer_len + mic_len;
        if body.len() < min_body {
            return Err(TooShort::new(min_body, body.len()).into());
        }
        let dst_addr = &body[4..4 + addr_len];
        let payload_end = body.len() - mic_len;
        let signer_start = 4 + addr_len;
        let signer_eui64 = &body[signer_start..signer_start + signer_len];
        let payload = &body[signer_start + signer_len..payload_end];
        let mic = &body[payload_end..];
        Ok(LichenFrame {
            epoch,
            seqnum,
            dst_addr,
            signer_eui64,
            payload,
            mic,
            addr_mode,
            mic_length,
            signature: if signature {
                Signature::Present
            } else {
                Signature::Absent
            },
            encryption: Encryption::Plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::from_hex;
    use std::vec;

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
    fn extended_addr_compat1_roundtrip() {
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
    fn encrypted_is_rejected() {
        // Encrypted frame without signature: LLSec=0x40 (bit 6 set)
        let wire = vec![0x04, 0x40, 0x00, 0x00, 0x00];
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::EncryptedUnsupported)
        );
    }

    #[test]
    fn all_reserved_mic_lengths_are_rejected() {
        for mic_length in 2..=7 {
            let wire = [4, mic_length << MIC_LEN_SHIFT, 0, 0, 0];
            assert_eq!(
                LichenFrame::from_bytes(&wire),
                Err(FrameError::ReservedMicLength(mic_length))
            );
        }
    }

    #[test]
    fn signed_encrypted_is_rejected() {
        // Signed + encrypted: signature bit (0x20) + encrypted bit (0x40) = 0x60
        let mut wire = vec![0x35, 0x60, 0x03, 0x00, 0x04, 0x78];
        wire.extend([0u8; 48]);
        // Encrypted check fires first, before the signature check
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::EncryptedUnsupported)
        );
    }

    #[test]
    fn empty_input_error() {
        assert_eq!(LichenFrame::from_bytes(&[]), Err(FrameError::Empty));
    }

    #[test]
    fn every_prefix_below_minimum_frame_reports_precise_size() {
        // A complete minimum frame is LENGTH(4) plus the four-byte body.
        // Every non-empty proper prefix retains that declared length, so the
        // error reports total wire bytes: expected 5, actual 1..=4.
        let minimum = [4, 0, 0, 0, 0];
        assert_eq!(
            LichenFrame::from_bytes(&minimum[..0]),
            Err(FrameError::Empty)
        );
        for actual in 1..minimum.len() {
            assert_eq!(
                LichenFrame::from_bytes(&minimum[..actual]),
                Err(FrameError::TooShort(TooShort::new(minimum.len(), actual)))
            );
        }
    }

    #[test]
    fn every_declared_body_length_below_fixed_header_reports_precise_size() {
        // These are complete wires whose own LENGTH is invalid. The size
        // category is therefore the four-byte body minimum, not total wire
        // truncation (which the prefix test above covers independently).
        for body_len in 0..4 {
            let mut wire = vec![0; body_len + 1];
            wire[0] = body_len as u8;
            assert_eq!(
                LichenFrame::from_bytes(&wire),
                Err(FrameError::TooShort(TooShort::new(4, body_len)))
            );
        }
    }

    #[test]
    fn address_and_signed_minimum_bodies_are_exact_boundaries() {
        for mode in [
            AddrMode::None,
            AddrMode::Short,
            AddrMode::Extended,
            AddrMode::Elided,
        ] {
            for signed in [false, true] {
                let security_bytes = if signed { 8 + 48 } else { 0 };
                let minimum_body = 4 + mode.addr_len() + security_bytes;
                let llsec = mode as u8
                    | if signed {
                        SIGNATURE_BIT | SIGNER_EUI64_BIT
                    } else {
                        0
                    };

                let mut exact = vec![0; minimum_body + 1];
                exact[0] = minimum_body as u8;
                exact[1] = llsec;
                let parsed = LichenFrame::from_bytes(&exact)
                    .unwrap_or_else(|error| panic!("{mode:?}/{signed} minimum: {error:?}"));
                assert_eq!(parsed.addr_mode, mode);
                assert_eq!(parsed.signature.is_present(), signed);
                assert!(parsed.payload.is_empty());

                let short_body = minimum_body - 1;
                let mut truncated = vec![0; short_body + 1];
                truncated[0] = short_body as u8;
                truncated[1] = llsec;
                assert_eq!(
                    LichenFrame::from_bytes(&truncated),
                    Err(FrameError::TooShort(TooShort::new(
                        minimum_body,
                        short_body
                    ))),
                    "{mode:?}/{signed} one-byte-short boundary"
                );
            }
        }
    }

    #[test]
    fn too_short_error() {
        assert!(matches!(
            LichenFrame::from_bytes(&[0x0f, 0x00]),
            Err(FrameError::TooShort(_))
        ));
    }

    #[test]
    fn signer_bit_without_signature_is_rejected() {
        let wire = from_hex("0b8001000261626301020304");
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::SignatureSignerMismatch)
        );
    }

    #[test]
    fn signature_bit_without_signer_bit_is_rejected() {
        // Mirror of the SI-only case above: signed frames MUST set both
        // the S and SI bits (spec 4.2), so S alone is the same mismatch.
        let wire = [4, SIGNATURE_BIT, 0, 0, 0];
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::SignatureSignerMismatch)
        );
    }

    #[test]
    fn parser_rejects_256_byte_wire() {
        // LENGTH declares a legal 254-byte body, but 256 bytes are present.
        let mut wire = vec![0u8; 256];
        wire[0] = MAX_FRAME_BODY as u8;
        assert_eq!(
            LichenFrame::from_bytes(&wire),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn write_body_length_boundaries_254_255() {
        let base = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[],
            signer_eui64: &[],
            payload: &[],
            mic: &[],
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        let mut buf = [0u8; 300];

        // 254-byte body (250-byte unsigned payload) is the exact maximum.
        let max_unsigned = LichenFrame {
            payload: &[0xaa; 250][..],
            ..base
        };
        let n = max_unsigned.write_to(&mut buf).unwrap();
        assert_eq!(n, 255);
        assert_eq!(buf[0], 254);
        let parsed = LichenFrame::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.payload.len(), 250);

        // 255-byte body (251-byte unsigned payload) is one byte over.
        let over_unsigned = LichenFrame {
            payload: &[0xaa; 251][..],
            ..base
        };
        assert_eq!(
            over_unsigned.write_to(&mut buf),
            Err(FrameError::FrameTooLarge)
        );

        // Signed broadcast: 8-byte SIID + 48-byte signature, so the exact
        // maximum payload is 194 bytes (body 254).
        let max_signed = LichenFrame {
            payload: &[0xaa; 194][..],
            signer_eui64: &[0u8; 8][..],
            mic: &[0u8; 48][..],
            signature: Signature::Present,
            ..base
        };
        let n = max_signed.write_to(&mut buf).unwrap();
        assert_eq!(n, 255);
        assert_eq!(buf[0], 254);
        assert_eq!(
            buf[1] & (SIGNATURE_BIT | SIGNER_EUI64_BIT),
            SIGNATURE_BIT | SIGNER_EUI64_BIT
        );

        // 195-byte signed payload pushes the body to 255: reject.
        let over_signed = LichenFrame {
            payload: &[0xaa; 195][..],
            ..max_signed
        };
        assert_eq!(
            over_signed.write_to(&mut buf),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn serializer_rejects_signature_signer_mismatch_atomically() {
        let si_only = LichenFrame {
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            dst_addr: &[],
            signer_eui64: &[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            payload: b"abc",
            mic: &[],
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };
        let mut output = [0x5au8; 64];
        let original = output;
        assert_eq!(
            si_only.write_to(&mut output),
            Err(FrameError::SignatureSignerMismatch)
        );
        assert_eq!(output, original, "SI-only rejection changed output");

        let s_only = LichenFrame {
            signer_eui64: &[],
            mic: &[0u8; 48],
            signature: Signature::Present,
            ..si_only
        };
        assert_eq!(
            s_only.write_to(&mut output),
            Err(FrameError::SignatureSignerMismatch)
        );
        assert_eq!(output, original, "S-only rejection changed output");
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
        let wire = [9, 0xa0, 1, 0, 0, 0, 0, 0, 0, 0];
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
            signer_eui64: &[],
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
            signer_eui64: &[],
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
            signer_eui64: &[],
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
            signer_eui64: &[],
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
            signer_eui64: &[],
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
            signer_eui64_hex: String,
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
                        "signer_presence_mismatch" => error == FrameError::SignatureSignerMismatch,
                        "reserved_mic_length" => error == FrameError::ReservedMicLength(2),
                        "encrypted_unsupported" => error == FrameError::EncryptedUnsupported,
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
                    frame.signer_eui64,
                    hex_decode(&vector.expected.signer_eui64_hex).as_slice(),
                    "{}: signer_eui64",
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
