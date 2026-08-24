//! Schnorr48 link signatures (draft-lichen-schnorr-00).
//!
//! 48-byte deterministic Schnorr signatures over Ed25519:
//!   16-byte truncated challenge (e) || 32-byte response (s)
//!
//! Core signature operations are provided by the `schnorr48` crate.
//! This module re-exports those and adds frame-specific signing helpers.

extern crate alloc;

#[cfg(any(test, feature = "std"))]
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::seqnum::LinkSeqNum;
use alloc::vec::Vec;

// Re-export core schnorr48 API
pub use schnorr48::{derive_keypair, sign, verify};

/// Length of a Schnorr48 signature in bytes.
pub const SIGNATURE_LENGTH: usize = schnorr48::SIGNATURE_LEN;

/// Versioned application-domain prefix for every link-frame signature.
///
/// The terminating NUL is part of the domain. It prevents a valid Schnorr48
/// signature made for another LICHEN profile (or the legacy unprefixed link
/// transcript) from being accepted as a link MIC.
pub const LINK_SIGNATURE_DOMAIN: &[u8; 15] = b"LICHEN-LINK-v1\0";

/// LLSec Signer-Identifier-present bit (draft-lichen-link-01 §3.2).
///
/// When set in `llsec`, the signed data (draft-lichen-link-01 §4.1) covers
/// the canonical 8-byte signer EUI-64 placed between DST and PLD; when clear,
/// no signer identifier bytes are covered.
pub const LLSEC_SI_BIT: u8 = 1 << 7;

/// Verify a Schnorr48 signature over a caller-domain-separated profile message.
///
/// Protocols using this helper MUST include their own fixed, versioned domain
/// prefix. Link frames use [`LINK_SIGNATURE_DOMAIN`] through [`verify_frame`].
pub fn verify_profile_message(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = <&[u8; SIGNATURE_LENGTH]>::try_from(signature) else {
        return false;
    };
    verify(public_key, message, signature)
}

/// Sign a link-layer frame. The returned 48 bytes occupy the MIC field.
///
/// Signed data layout (draft-lichen-link-01 §4.1): `LICHEN-LINK-v1\0` ||
/// LENGTH || LLSec ||
/// epoch || seqnum || dst_addr_len(1) || dst_addr || [signer_eui64 (8) iff
/// `llsec` has [`LLSEC_SI_BIT`] set] || payload.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "std"))]
pub(crate) fn sign_frame(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_eui64: &[u8],
    inner_payload: &[u8],
    privkey: &PrivateKey,
    pubkey: &PublicKey,
) -> [u8; 48] {
    assert!(
        dst_addr.len() <= u8::MAX as usize,
        "link destination too long"
    );
    assert!(
        llsec & LLSEC_SI_BIT == 0 || signer_eui64.len() == 8,
        "SI-set link signature requires an 8-byte signer EUI-64"
    );
    let msg = build_signable(
        length,
        llsec,
        epoch,
        seqnum,
        dst_addr,
        signer_eui64,
        inner_payload,
    );
    sign(privkey, pubkey, &msg)
}

/// Verify a signed link-layer frame.
///
/// `signature` is the 48-byte MIC and `payload` is the inner payload. The
/// `llsec`/`signer_eui64` pair MUST match the values used at signing time:
/// with [`LLSEC_SI_BIT`] set, a different EUI-64 fails verification; with it
/// clear, the signer identifier argument is ignored entirely.
#[allow(clippy::too_many_arguments)]
pub fn verify_frame(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_eui64: &[u8],
    payload: &[u8],
    signature: &[u8],
    sender_pubkey: &PublicKey,
) -> bool {
    if signature.len() != SIGNATURE_LENGTH
        || dst_addr.len() > u8::MAX as usize
        || (llsec & LLSEC_SI_BIT != 0 && signer_eui64.len() != 8)
    {
        return false;
    }
    let sig: [u8; 48] = signature.try_into().unwrap();
    let msg = build_signable(
        length,
        llsec,
        epoch,
        seqnum,
        dst_addr,
        signer_eui64,
        payload,
    );
    verify(sender_pubkey, &msg, &sig)
}

fn build_signable(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_eui64: &[u8],
    inner_payload: &[u8],
) -> Vec<u8> {
    let signer_eui64_len = if llsec & LLSEC_SI_BIT != 0 { 8usize } else { 0 };
    let mut buf = Vec::with_capacity(
        LINK_SIGNATURE_DOMAIN.len() + 6 + dst_addr.len() + signer_eui64_len + inner_payload.len(),
    );
    buf.extend_from_slice(LINK_SIGNATURE_DOMAIN);
    buf.push(length);
    buf.push(llsec);
    buf.push(epoch);
    buf.extend_from_slice(&seqnum.to_be_bytes());
    buf.push(u8::try_from(dst_addr.len()).expect("validated link destination length"));
    buf.extend_from_slice(dst_addr);
    if signer_eui64_len > 0 {
        buf.extend_from_slice(signer_eui64);
    }
    buf.extend_from_slice(inner_payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seed;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().expect("expected 32 bytes")
    }

    fn arr48(v: &[u8]) -> [u8; 48] {
        v.try_into().expect("expected 48 bytes")
    }

    // ── keypair derivation ────────────────────────────────────────────────

    #[test]
    fn derive_vector1() {
        let seed = Seed::new(arr32(&hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )));
        let (priv_got, pub_got) = derive_keypair(&seed);
        assert_eq!(
            *priv_got.as_bytes(),
            arr32(&hex(
                "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156"
            ))
        );
        assert_eq!(
            *pub_got.as_bytes(),
            arr32(&hex(
                "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
            ))
        );
    }

    #[test]
    fn derive_vector2() {
        let seed = Seed::new(arr32(&hex(
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
        )));
        let (priv_got, pub_got) = derive_keypair(&seed);
        assert_eq!(
            *priv_got.as_bytes(),
            arr32(&hex(
                "50b8c29238a8403e0ac69e23d47b9184c371a92460d518351b099944bbdfa867"
            ))
        );
        assert_eq!(
            *pub_got.as_bytes(),
            arr32(&hex(
                "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d"
            ))
        );
    }

    // ── sign: output must match test-vector signatures exactly ───────────

    struct Vector {
        privkey: &'static str,
        pubkey: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    const VALID: &[Vector] = &[
        Vector {
            privkey:   "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156",
            pubkey:    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            message:   "",
            signature: "26f70691bbde0c1e8becc00e7e7663cb6b72364b6ea208fdabef226c5b0d07cec9c661fd69671981ca40277598ea9c01",
        },
        Vector {
            privkey:   "50b8c29238a8403e0ac69e23d47b9184c371a92460d518351b099944bbdfa867",
            pubkey:    "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
            message:   "74657374",
            signature: "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
        },
        Vector {
            privkey:   "b0829ce3ccf1d8edd5da1132d46271b0169f58b6414fd263d3c98da627170f5e",
            pubkey:    "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
            message:   "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
            signature: "e15b69ed5bd6fccc6c624431eb1bb08341ba571158da31249ac72a28af7f77ea0534b94cc1f8650dead98ccae16ec803",
        },
        Vector {
            privkey:   "20cd6935864716a79d74dd5fabbd8964304051ca41a31c4659158ebb7c3d0b57",
            pubkey:    "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
            message:   "000102030000fffe",
            signature: "5f305af4656afd6278b1f2be87853e67e952b1449f17380a24ff98ee90fbcec193b82bd58f33291658b452b610febe0a",
        },
        Vector {
            privkey:   "68ae63a46076e4e250dd1cf4b15c5f645827bb55af53e23b76d8f3ffd1b8dd55",
            pubkey:    "9474957069b71153ee776274d7d7b842fe9ddf33df44dc61b851f73c885af800",
            message:   "0100000100000000000000000000000000000000436f4150207061796c6f6164",
            signature: "9d76e7510ffc2bad6e5d45b3b6db1ebe2586389ec18b4fb8297c4e366e912f5a0a6ac2f2e52769009e006e92ba864403",
        },
    ];

    #[test]
    fn sign_matches_vectors() {
        for (i, v) in VALID.iter().enumerate() {
            let privkey = PrivateKey::new(arr32(&hex(v.privkey)));
            let pubkey = PublicKey::new(arr32(&hex(v.pubkey)));
            let msg = hex(v.message);
            let expected = hex(v.signature);
            let got = sign(&privkey, &pubkey, &msg);
            assert_eq!(
                got.as_ref(),
                expected.as_slice(),
                "vector {i} sign mismatch"
            );
        }
    }

    #[test]
    fn verify_valid_vectors() {
        for (i, v) in VALID.iter().enumerate() {
            let pubkey = PublicKey::new(arr32(&hex(v.pubkey)));
            let msg = hex(v.message);
            let sig = arr48(&hex(v.signature));
            assert!(verify(&pubkey, &msg, &sig), "vector {i} verify rejected");
        }
    }

    // ── verify: invalid cases ────────────────────────────────────────────

    #[test]
    fn invalid_wrong_message() {
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("77726f6e67"); // "wrong"
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_tampered_challenge() {
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578953fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_tampered_response() {
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609c98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_wrong_pubkey() {
        let pubkey = PublicKey::new(arr32(&hex(
            "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
        )));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_all_zeros() {
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("74657374");
        let sig = [0u8; 48];
        assert!(!verify(&pubkey, &msg, &sig));
    }

    // ── point validation tests ───────────────────────────────────────────
    // Defense-in-depth: verify rejects identity points, low-order points,
    // non-canonical scalars, and zero scalars.

    #[test]
    fn invalid_identity_point_pubkey() {
        // Identity point: y=1, x=0 encoded as 0x01 || 0x00*31
        let pubkey = PublicKey::new(arr32(&hex(
            "0100000000000000000000000000000000000000000000000000000000000000",
        )));
        let msg = hex("74657374");
        let sig = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(
            !verify(&pubkey, &msg, &sig),
            "identity point must be rejected"
        );
    }

    #[test]
    fn invalid_low_order_pubkey() {
        // 8-torsion point (not in prime-order subgroup)
        let pubkey = PublicKey::new(arr32(&hex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        )));
        let msg = hex("74657374");
        let sig = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(
            !verify(&pubkey, &msg, &sig),
            "low-order point must be rejected"
        );
    }

    #[test]
    fn invalid_non_canonical_s() {
        // s = L (curve order), which is non-canonical (must be < L)
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("74657374");
        let sig = arr48(&hex("c9bec10578943fc8d453252fb262fa03edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        assert!(
            !verify(&pubkey, &msg, &sig),
            "non-canonical s must be rejected"
        );
    }

    #[test]
    fn invalid_zero_s() {
        // s = 0 is invalid
        let pubkey = PublicKey::new(arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        )));
        let msg = hex("74657374");
        let sig = arr48(&hex("c9bec10578943fc8d453252fb262fa030000000000000000000000000000000000000000000000000000000000000000"));
        assert!(!verify(&pubkey, &msg, &sig), "zero s must be rejected");
    }

    // ── two-node authenticated frame exchange ────────────────────────────

    #[test]
    fn two_node_frame_exchange() {
        use crate::frame::{AddrMode, Encryption, LichenFrame, MicLength, Signature};
        use crate::replay::ReplayWindow;

        let seed_a = Seed::new([0x01u8; 32]);
        let (priv_a, pub_a) = derive_keypair(&seed_a);
        let seed_b = Seed::new([0x02u8; 32]);
        let (_, pub_b) = derive_keypair(&seed_b);

        let mut replay = ReplayWindow::new();

        let epoch: u8 = 1;
        let seqnum = LinkSeqNum::new(42);
        let dst_addr = [0x00u8, 0x01u8];
        let inner_payload = b"hello";

        // llsec: Short addr, signature present, signer EUI-64 present.
        let llsec: u8 = 0xa1;
        let signer_eui64 = [0x42; 8];
        let frame_length =
            4 + dst_addr.len() + signer_eui64.len() + inner_payload.len() + SIGNATURE_LENGTH;
        let sig = sign_frame(
            frame_length as u8,
            llsec,
            epoch,
            seqnum,
            &dst_addr,
            &signer_eui64,
            inner_payload,
            &priv_a,
            &pub_a,
        );

        // Node A: serialise frame
        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr: &dst_addr,
            signer_eui64: &signer_eui64,
            payload: inner_payload,
            mic: &sig,
            addr_mode: AddrMode::Short,
            mic_length: MicLength::Bits32,
            signature: Signature::Present,
            encryption: Encryption::Plaintext,
        };
        let mut wire = [0u8; 128];
        let n = frame.write_to(&mut wire).unwrap();
        assert_eq!(usize::from(wire[0]), n - 1);

        // Node B: parse and verify
        let rx = LichenFrame::from_bytes(&wire[..n]).unwrap();
        assert_eq!(rx.signature, Signature::Present);
        assert!(
            replay.accept(rx.seqnum),
            "first delivery should pass replay window"
        );
        assert!(
            verify_frame(
                wire[0],
                llsec,
                rx.epoch,
                rx.seqnum,
                rx.dst_addr,
                rx.signer_eui64,
                rx.payload,
                rx.mic,
                &pub_a
            ),
            "valid frame should verify"
        );

        // Replay: same sequence number rejected by ReplayWindow
        assert!(!replay.accept(rx.seqnum), "replay must be rejected");

        // Tampered inner payload: signature check fails
        let mut tampered = *inner_payload;
        tampered[0] ^= 0xFF;
        assert!(
            !verify_frame(
                frame_length as u8,
                llsec,
                epoch,
                seqnum,
                &dst_addr,
                &[],
                &tampered,
                &sig,
                &pub_a
            ),
            "tampered payload must not verify"
        );

        // Wrong public key: signature check fails
        assert!(
            !verify_frame(
                frame_length as u8,
                llsec,
                epoch,
                seqnum,
                &dst_addr,
                &[],
                inner_payload,
                &sig,
                &pub_b
            ),
            "wrong pubkey must not verify"
        );

        // Signature must be exactly 48 bytes.
        assert!(
            !verify_frame(
                frame_length as u8,
                llsec,
                epoch,
                seqnum,
                &dst_addr,
                &[],
                inner_payload,
                &sig[..47],
                &pub_a
            ),
            "truncated signature must not verify"
        );
    }

    // ── signer EUI-64 coverage (LLSEC_SI_BIT, draft-lichen-link-01 §3.2/§4.1) ──

    const SI_TEST_LLSEC: u8 = 0x21; // Short addr + S=1, SI clear

    fn si_test_keypair() -> (PrivateKey, PublicKey) {
        derive_keypair(&Seed::new([0x07u8; 32]))
    }

    #[test]
    fn public_verifier_rejects_non_frame_address_and_signer_eui64_lengths() {
        let (_, pubkey) = si_test_keypair();
        let signature = [0u8; SIGNATURE_LENGTH];
        assert!(!verify_frame(
            0,
            SI_TEST_LLSEC,
            0,
            LinkSeqNum::new(0),
            &[0u8; 256],
            &[],
            &[],
            &signature,
            &pubkey,
        ));
        assert!(!verify_frame(
            0,
            SI_TEST_LLSEC | LLSEC_SI_BIT,
            0,
            LinkSeqNum::new(0),
            &[],
            &[0u8; 7],
            &[],
            &signature,
            &pubkey,
        ));
    }

    #[test]
    fn si_bit_set_covers_signer_eui64() {
        let (priv_a, pub_a) = si_test_keypair();
        let llsec_si = SI_TEST_LLSEC | LLSEC_SI_BIT;
        let sig = sign_frame(
            60,
            llsec_si,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xAAu8; 8],
            b"payload",
            &priv_a,
            &pub_a,
        );

        // Correct signer EUI-64 verifies.
        assert!(verify_frame(
            60,
            llsec_si,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xAAu8; 8],
            b"payload",
            &sig,
            &pub_a
        ));
        // A different signer EUI-64 must fail: the identifier is signed.
        assert!(!verify_frame(
            60,
            llsec_si,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xBBu8; 8],
            b"payload",
            &sig,
            &pub_a
        ));
        // Clearing the SI bit changes the signed message, so the signature no
        // longer verifies against it.
        assert!(!verify_frame(
            60,
            SI_TEST_LLSEC,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xAAu8; 8],
            b"payload",
            &sig,
            &pub_a
        ));
    }

    #[test]
    fn si_bit_clear_excludes_signer_eui64() {
        let (priv_a, pub_a) = si_test_keypair();
        let sig_a = sign_frame(
            60,
            SI_TEST_LLSEC,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xAAu8; 8],
            b"payload",
            &priv_a,
            &pub_a,
        );
        let sig_b = sign_frame(
            60,
            SI_TEST_LLSEC,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xBBu8; 8],
            b"payload",
            &priv_a,
            &pub_a,
        );

        // Signing is deterministic: identical signed data means identical
        // signatures regardless of which signer EUI-64 bytes were passed in.
        assert_eq!(sig_a.as_ref(), sig_b.as_ref());
        // Verification likewise ignores the signer EUI-64 when the bit is clear.
        assert!(verify_frame(
            60,
            SI_TEST_LLSEC,
            1,
            LinkSeqNum::new(9),
            &[0x00, 0x01],
            &[0xCCu8; 8],
            b"payload",
            &sig_a,
            &pub_a
        ));
    }

    #[test]
    fn link_domain_rejects_legacy_and_other_profile_signatures() {
        let (private_key, public_key) = si_test_keypair();
        let llsec = SI_TEST_LLSEC | LLSEC_SI_BIT;
        let signer_eui64 = [0xAA; 8];
        let payload = b"profile-separated";
        let length = 4 + 2 + signer_eui64.len() as u8 + payload.len() as u8 + 48;

        let canonical = build_signable(
            length,
            llsec,
            1,
            LinkSeqNum::new(9),
            &[0, 1],
            &signer_eui64,
            payload,
        );
        let legacy = &canonical[LINK_SIGNATURE_DOMAIN.len()..];
        let legacy_signature = sign(&private_key, &public_key, legacy);
        assert!(!verify_frame(
            length,
            llsec,
            1,
            LinkSeqNum::new(9),
            &[0, 1],
            &signer_eui64,
            payload,
            &legacy_signature,
            &public_key,
        ));

        let mut other_profile = b"LICHEN-SOS-v1\0".to_vec();
        other_profile.extend_from_slice(legacy);
        let other_signature = sign(&private_key, &public_key, &other_profile);
        assert!(!verify_frame(
            length,
            llsec,
            1,
            LinkSeqNum::new(9),
            &[0, 1],
            &signer_eui64,
            payload,
            &other_signature,
            &public_key,
        ));
    }

    #[test]
    fn si_frame_serialises_and_verifies() {
        use crate::frame::{AddrMode, Encryption, LichenFrame, MicLength, Signature};

        let (priv_a, pub_a) = si_test_keypair();
        let dst_addr = [0x00u8, 0x01];
        let payload = b"si-frame";
        // draft-lichen-link-01 §3.4: S=1 frames MUST set SI=1.
        let llsec = SI_TEST_LLSEC | LLSEC_SI_BIT;
        let iid = [0x42u8; 8];
        let frame_length: u8 =
            4 + dst_addr.len() as u8 + iid.len() as u8 + payload.len() as u8 + 48;
        let seqnum = LinkSeqNum::new(77);

        let sig = sign_frame(
            frame_length,
            llsec,
            1,
            seqnum,
            &dst_addr,
            &iid,
            payload,
            &priv_a,
            &pub_a,
        );
        let frame = LichenFrame {
            epoch: 1,
            seqnum,
            dst_addr: &dst_addr,
            signer_eui64: &iid,
            payload,
            mic: &sig,
            addr_mode: AddrMode::Short,
            mic_length: MicLength::Bits32,
            signature: Signature::Present,
            encryption: Encryption::Plaintext,
        };
        let mut wire = [0u8; 128];
        let wire_len = frame.write_to(&mut wire).unwrap();
        assert_eq!(wire[0], frame_length);
        assert_eq!(wire[1], llsec);
        let parsed = LichenFrame::from_bytes(&wire[..wire_len]).unwrap();

        // Verify the exact parsed transcript, including the serialized LENGTH.
        assert!(verify_frame(
            wire[0],
            parsed.llsec_byte(),
            parsed.epoch,
            parsed.seqnum,
            parsed.dst_addr,
            parsed.signer_eui64,
            parsed.payload,
            parsed.mic,
            &pub_a
        ));
    }
}
