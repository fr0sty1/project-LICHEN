//! Schnorr48 link signatures (draft-lichen-schnorr-00).
//!
//! 48-byte deterministic Schnorr signatures over Ed25519:
//!   16-byte truncated challenge (e) || 32-byte response (s)
//!
//! Core signature operations are provided by the `schnorr48` crate.
//! This module re-exports those and adds frame-specific signing helpers.

extern crate alloc;

use crate::keys::{PrivateKey, PublicKey};
use crate::seqnum::LinkSeqNum;
use alloc::vec::Vec;

// Re-export core schnorr48 API
pub use schnorr48::{derive_keypair, sign, verify};

/// Length of a Schnorr48 signature in bytes.
pub const SIGNATURE_LENGTH: usize = schnorr48::SIGNATURE_LEN;

/// Sign a link-layer frame. The returned 48 bytes occupy the MIC field.
///
/// Signed data layout: length || LLSec || epoch || seqnum || dst_addr_len(1)
/// || dst_addr || [signer_iid (8) if SI=1] || payload (domain separation per j7rk).
#[allow(clippy::too_many_arguments)]
pub fn sign_frame(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_iid: &[u8],
    inner_payload: &[u8],
    privkey: &PrivateKey,
    pubkey: &PublicKey,
) -> [u8; 48] {
    let msg = build_signable(
        length,
        llsec,
        epoch,
        seqnum,
        dst_addr,
        signer_iid,
        inner_payload,
    );
    sign(privkey, pubkey, &msg)
}

/// Verify a signed link-layer frame.
///
/// `signature` is the 48-byte MIC and `payload` is the inner payload.
#[allow(clippy::too_many_arguments)]
pub fn verify_frame(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_iid: &[u8],
    payload: &[u8],
    signature: &[u8],
    sender_pubkey: &PublicKey,
) -> bool {
    if signature.len() != SIGNATURE_LENGTH {
        return false;
    }
    let sig: [u8; 48] = signature.try_into().unwrap();
    let msg = build_signable(length, llsec, epoch, seqnum, dst_addr, signer_iid, payload);
    verify(sender_pubkey, &msg, &sig)
}

fn build_signable(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    signer_iid: &[u8],
    inner_payload: &[u8],
) -> Vec<u8> {
    let signer_iid_len = if llsec & 0x80 != 0 { 8usize } else { 0 };
    let mut buf = Vec::with_capacity(6 + dst_addr.len() + signer_iid_len + inner_payload.len());
    buf.push(length);
    buf.push(llsec);
    buf.push(epoch);
    buf.extend_from_slice(&seqnum.to_be_bytes());
    buf.push(dst_addr.len() as u8);
    buf.extend_from_slice(dst_addr);
    if signer_iid_len > 0 {
        buf.extend_from_slice(signer_iid);
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

        // llsec: Short addr (0x01), signature present (0x20)
        let llsec: u8 = 0x21;
        let frame_length = 4 + dst_addr.len() + inner_payload.len() + SIGNATURE_LENGTH;
        let sig = sign_frame(
            frame_length as u8,
            llsec,
            epoch,
            seqnum,
            &dst_addr,
            &[], // signer_iid not used in current frame format
            inner_payload,
            &priv_a,
            &pub_a,
        );

        // Node A: serialise frame
        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr: &dst_addr,
            payload: inner_payload,
            mic: &sig,
            addr_mode: AddrMode::Short,
            mic_length: MicLength::Bits32,
            signature: Signature::Present,
            encryption: Encryption::Plaintext,
        };
        let mut wire = [0u8; 128];
        let n = frame.write_to(&mut wire).unwrap();

        // Node B: parse and verify
        let rx = LichenFrame::from_bytes(&wire[..n]).unwrap();
        assert_eq!(rx.signature, Signature::Present);
        assert!(
            replay.accept(rx.seqnum),
            "first delivery should pass replay window"
        );
        assert!(
            verify_frame(
                frame_length as u8,
                llsec,
                rx.epoch,
                rx.seqnum,
                rx.dst_addr,
                &[],
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
}
