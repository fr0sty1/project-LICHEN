//! SOS origin signature (spec 18.4.1).
//!
//! Hop-by-hop link signatures are replaced on relay. The origin signature
//! persists so receivers can still authenticate who started the SOS.
//!
//! Wire format (`test/vectors/sos_signature.json`):
//! `8-byte big-endian origin sequence || 48-byte Schnorr48`.
//!
//! Transcript (hashed with SHA-512, then signed):
//! `LICHEN-SOS-ORIGIN-v1` || origin IPv6 (16) || sequence (u64 BE) ||
//! canonical CBOR payload.

/// Domain separator; 20 ASCII octets, no terminating NUL.
pub const SOS_ORIGIN_DOMAIN: &[u8; 20] = b"LICHEN-SOS-ORIGIN-v1";

/// Wire length: 8-byte sequence + 48-byte Schnorr48.
pub const SOS_ORIGIN_SIGNATURE_LENGTH: usize = 8 + 48;

/// Parsed SOS origin signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SosOriginSignature {
    origin_sequence: u64,
    signature: [u8; 48],
}

/// Origin-signature wire parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosOriginSignatureError {
    /// Input was not exactly [`SOS_ORIGIN_SIGNATURE_LENGTH`] bytes.
    WrongLength,
}

impl SosOriginSignature {
    /// Construct from a sequence and 48-byte Schnorr48 signature.
    pub const fn new(origin_sequence: u64, signature: [u8; 48]) -> Self {
        Self {
            origin_sequence,
            signature,
        }
    }

    pub const fn origin_sequence(&self) -> u64 {
        self.origin_sequence
    }

    pub const fn signature(&self) -> &[u8; 48] {
        &self.signature
    }

    /// Serialize: 8-byte big-endian sequence + 48-byte signature.
    pub fn to_bytes(&self) -> [u8; SOS_ORIGIN_SIGNATURE_LENGTH] {
        let mut out = [0u8; SOS_ORIGIN_SIGNATURE_LENGTH];
        out[..8].copy_from_slice(&self.origin_sequence.to_be_bytes());
        out[8..].copy_from_slice(&self.signature);
        out
    }

    /// Parse the 56-byte wire encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SosOriginSignatureError> {
        if data.len() != SOS_ORIGIN_SIGNATURE_LENGTH {
            return Err(SosOriginSignatureError::WrongLength);
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&data[..8]);
        let mut signature = [0u8; 48];
        signature.copy_from_slice(&data[8..]);
        Ok(Self {
            origin_sequence: u64::from_be_bytes(seq),
            signature,
        })
    }
}

/// SHA-512(domain || origin IPv6 || seq BE || canonical CBOR).
#[cfg(feature = "schnorr")]
pub fn compute_sos_transcript(
    origin_addr: &[u8; 16],
    origin_sequence: u64,
    payload_cbor: &[u8],
) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(SOS_ORIGIN_DOMAIN);
    hasher.update(origin_addr);
    hasher.update(origin_sequence.to_be_bytes());
    hasher.update(payload_cbor);
    hasher.finalize().into()
}

/// Sign canonical SOS payload bytes with the origin key.
#[cfg(feature = "schnorr")]
pub fn sign_sos_origin(
    privkey: &crate::keys::PrivateKey,
    pubkey: &crate::keys::PublicKey,
    origin_addr: &[u8; 16],
    origin_sequence: u64,
    payload_cbor: &[u8],
) -> SosOriginSignature {
    use crate::schnorr::sign;
    let digest = compute_sos_transcript(origin_addr, origin_sequence, payload_cbor);
    let signature = sign(privkey, pubkey, &digest);
    let mut bytes = [0u8; 48];
    bytes.copy_from_slice(signature.as_ref());
    SosOriginSignature::new(origin_sequence, bytes)
}

/// Verify an origin signature over canonical SOS payload bytes.
#[cfg(feature = "schnorr")]
pub fn verify_sos_origin(
    pubkey: &crate::keys::PublicKey,
    origin_addr: &[u8; 16],
    payload_cbor: &[u8],
    signature: &SosOriginSignature,
) -> bool {
    use crate::schnorr::verify;
    let digest = compute_sos_transcript(origin_addr, signature.origin_sequence, payload_cbor);
    verify(pubkey, &digest, &signature.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matches_vector() {
        assert_eq!(SOS_ORIGIN_DOMAIN.len(), 20);
        assert_eq!(SOS_ORIGIN_DOMAIN.as_slice(), b"LICHEN-SOS-ORIGIN-v1");
        let hex = "4c494348454e2d534f532d4f524947494e2d7631";
        let expected: std::vec::Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(SOS_ORIGIN_DOMAIN.as_slice(), expected.as_slice());
    }

    #[test]
    fn wire_format_sequence_42() {
        let sig = SosOriginSignature::new(42, [0xab; 48]);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 56);
        assert_eq!(&bytes[..8], &[0, 0, 0, 0, 0, 0, 0, 0x2a]);
        assert_eq!(&bytes[8..], &[0xab; 48]);
        let parsed = SosOriginSignature::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        assert_eq!(
            SosOriginSignature::from_bytes(&[0u8; 8]),
            Err(SosOriginSignatureError::WrongLength)
        );
        assert_eq!(
            SosOriginSignature::from_bytes(&[0u8; 57]),
            Err(SosOriginSignatureError::WrongLength)
        );
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn transcript_matches_python_oracle() {
        // Independent SHA-512 of domain || ipv6 || seq || canonical CBOR
        // for origin_transcript_format in sos_signature.json.
        let addr = decode_hex16("0200123456789abcdef0123456789abc");
        let cbor = decode_hex_vec(
            "a36274731a66536a90646e6f646573303230303a313233343a353637383a39616263647479706563736f73",
        );
        let got = compute_sos_transcript(&addr, 1, &cbor);
        let expected = decode_hex64(
            "27c558161598913e67951404055694a91a85d8448bb71d17d38da5d537f36955539b49f132895e02a524adf9423ca0379567b9dc2c9923ad6a9d42876663dd18",
        );
        assert_eq!(got, expected);
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn sign_verify_roundtrip() {
        use crate::keys::Seed;
        use crate::schnorr::derive_keypair;
        let (privkey, pubkey) = derive_keypair(&Seed::new([0x11; 32]));
        let addr = [0x02u8; 16];
        let cbor = b"\xa0";
        let signed = sign_sos_origin(&privkey, &pubkey, &addr, 7, cbor);
        assert!(verify_sos_origin(&pubkey, &addr, cbor, &signed));
        let mut bad_addr = addr;
        bad_addr[0] ^= 1;
        assert!(!verify_sos_origin(&pubkey, &bad_addr, cbor, &signed));
        let tampered = SosOriginSignature::new(8, *signed.signature());
        assert!(!verify_sos_origin(&pubkey, &addr, cbor, &tampered));
    }

    #[cfg(feature = "schnorr")]
    #[test]
    fn wrong_domain_does_not_verify() {
        use crate::keys::Seed;
        use crate::schnorr::{derive_keypair, sign, verify};
        use sha2::{Digest, Sha512};
        let (privkey, pubkey) = derive_keypair(&Seed::new([0x22; 32]));
        let addr = [0x02u8; 16];
        let cbor = b"\xa0";
        let seq = 1u64;
        let mut hasher = Sha512::new();
        hasher.update(b"LICHEN-DAO-ORIGIN-v1");
        hasher.update(addr);
        hasher.update(seq.to_be_bytes());
        hasher.update(cbor);
        let wrong: [u8; 64] = hasher.finalize().into();
        let signature = sign(&privkey, &pubkey, &wrong);
        let mut bytes = [0u8; 48];
        bytes.copy_from_slice(signature.as_ref());
        let wrapped = SosOriginSignature::new(seq, bytes);
        assert!(!verify_sos_origin(&pubkey, &addr, cbor, &wrapped));
        assert!(verify(&pubkey, &wrong, &bytes));
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex16(hex: &str) -> [u8; 16] {
        let v = decode_hex_vec(hex);
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        out
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex64(hex: &str) -> [u8; 64] {
        let v = decode_hex_vec(hex);
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[cfg(feature = "schnorr")]
    fn decode_hex_vec(hex: &str) -> std::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
