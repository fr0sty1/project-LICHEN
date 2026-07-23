//! Schnorr48 link signatures (draft-lichen-schnorr-00).
//!
//! 48-byte deterministic Schnorr signatures over Ed25519:
//!   16-byte truncated challenge (e) || 32-byte response (s)
//!
//! Curve25519-dalek provides timing-safe scalar multiplication.
//! Nonce is deterministic (RFC 6979 style) to prevent nonce reuse.

extern crate alloc;

use crate::keys::{PrivateKey, PublicKey, Seed};
use crate::seqnum::LinkSeqNum;
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// Derive an Ed25519 keypair from a seed.
///
/// Returns `(privkey, pubkey)`:
/// - `privkey` — clamped Ed25519 scalar (little-endian)
/// - `pubkey`  — compressed Ed25519 point
///
/// # Panics
///
/// This function does not panic. Internal `.unwrap()` calls operate on
/// fixed-size SHA-512 output slices that are provably the correct length.
pub fn derive_keypair(seed: &Seed) -> (PrivateKey, PublicKey) {
    let hash = Sha512::digest(seed.as_bytes());
    // SAFETY: hash is 64 bytes, so hash[..32] is exactly 32 bytes
    let privkey_bytes = clamp(hash[..32].try_into().unwrap());
    let priv_scalar = Scalar::from_bytes_mod_order(privkey_bytes);
    let pubkey_bytes = (priv_scalar * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    (PrivateKey::new(privkey_bytes), PublicKey::new(pubkey_bytes))
}

/// Sign `msg`. Returns 48-byte signature `e[16] || s[32]`.
///
/// `privkey` and `pubkey` must come from [`derive_keypair`]. Nonce uses
/// H(privkey || msg) per draft-lichen-schnorr-00 (intentional deviation
/// from RFC 8032 prefix = H(seed)[32:64] to avoid storing 64-byte expanded
/// key; only 32-byte clamped scalar is used). Matches Python reference and
/// all test vectors.
///
/// # Panics
///
/// This function does not panic. Internal `.unwrap()` calls operate on
/// fixed-size SHA-512 output slices that are provably the correct length.
pub fn sign(privkey: &PrivateKey, pubkey: &PublicKey, msg: &[u8]) -> [u8; 48] {
    // 1. Deterministic nonce: r = SHA-512(privkey || msg) mod L per spec
    let nonce_hash = Sha512::new()
        .chain_update(privkey.as_bytes())
        .chain_update(msg)
        .finalize();
    let r = Scalar::from_bytes_mod_order_wide(&nonce_hash.into());

    // 2. Commitment: R = r * B
    let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

    // 3. Challenge: e = SHA-512(R || pubkey || msg)[..16]
    let e_hash = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(pubkey.as_bytes())
        .chain_update(msg)
        .finalize();
    // SAFETY: e_hash is 64 bytes (SHA-512 output), so [..16] is exactly 16 bytes
    let e: [u8; 16] = e_hash[..16].try_into().unwrap();

    // 4. Extend 16-byte challenge to 32-byte scalar. Zero-padding the high
    //    bytes is correct because Scalar uses little-endian representation.
    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(&e);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    // 5. s = (r + e_scalar * priv_scalar) mod L
    let priv_scalar = Scalar::from_bytes_mod_order(*privkey.as_bytes());
    let s = r + e_scalar * priv_scalar;

    let mut sig = [0u8; 48];
    sig[..16].copy_from_slice(&e);
    sig[16..].copy_from_slice(s.as_bytes());
    sig
}

/// Verify a 48-byte signature. Returns `true` if valid.
///
/// Defense-in-depth checks (beyond what minimal Schnorr requires):
/// - Rejects non-canonical scalars (s >= L, the curve order)
/// - Rejects zero scalars (s == 0)
/// - Rejects identity point as pubkey
/// - Rejects low-order/torsion points as pubkey (not in prime-order subgroup)
///
/// These checks prevent attacks on cofactor-sensitive operations and ensure
/// the pubkey represents a legitimate Ed25519 public key.
///
/// # Panics
///
/// This function does not panic. Internal `.unwrap()` calls operate on the
/// fixed-size 48-byte signature array, which is provably the correct length.
pub fn verify(pubkey: &PublicKey, msg: &[u8], sig: &[u8; 48]) -> bool {
    // 1. Parse: e_received (16 bytes) || s (32 bytes)
    // SAFETY: sig is exactly 48 bytes, so [..16] = 16 bytes and [16..] = 32 bytes
    let e_received: [u8; 16] = sig[..16].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[16..].try_into().unwrap();

    // 2. s must be canonical (< L) and non-zero
    let s: Scalar = match Scalar::from_canonical_bytes(s_bytes).into() {
        Some(s) => s,
        None => return false,
    };
    if s == Scalar::ZERO {
        return false;
    }

    // 3. Decompress public key and reject identity/low-order points
    let pubkey_point = match CompressedEdwardsY(*pubkey.as_bytes()).decompress() {
        Some(p) if !p.is_identity() && p.is_torsion_free() => p,
        _ => return false,
    };

    // 4. Extend 16-byte challenge to 32-byte scalar. Zero-padding the high
    //    bytes is correct because Scalar uses little-endian representation.
    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(&e_received);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    // 5. R' = s*B - e*pubkey
    let sb = s * ED25519_BASEPOINT_POINT;
    let epk = e_scalar * pubkey_point;
    let r_prime = (sb - epk).compress();

    // 6. Recompute challenge and compare (constant-time)
    let e_check = Sha512::new()
        .chain_update(r_prime.as_bytes())
        .chain_update(pubkey.as_bytes())
        .chain_update(msg)
        .finalize();

    e_check[..16].ct_eq(&e_received).into()
}

/// Length of a Schnorr48 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 48;

/// Sign a link-layer frame. The returned 48 bytes occupy the MIC field.
///
/// Signed data layout: length || LLSec || epoch || seqnum || dst_addr_len(1)
/// || dst_addr || payload (domain separation per j7rk).
#[allow(clippy::too_many_arguments)]
pub fn sign_frame(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    inner_payload: &[u8],
    privkey: &PrivateKey,
    pubkey: &PublicKey,
) -> [u8; 48] {
    let msg = build_signable(length, llsec, epoch, seqnum, dst_addr, inner_payload);
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
    payload: &[u8],
    signature: &[u8],
    sender_pubkey: &PublicKey,
) -> bool {
    if signature.len() != SIGNATURE_LENGTH {
        return false;
    }
    let sig: [u8; 48] = signature.try_into().unwrap();
    let msg = build_signable(length, llsec, epoch, seqnum, dst_addr, payload);
    verify(sender_pubkey, &msg, &sig)
}

    // LENGTH || LLSec || epoch || seqnum || dst_addr_len(1) || dst_addr || inner_payload
fn build_signable(
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: LinkSeqNum,
    dst_addr: &[u8],
    inner_payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + dst_addr.len() + inner_payload.len());
    buf.push(length);
    buf.push(llsec);
    buf.push(epoch);
    buf.extend_from_slice(&seqnum.to_be_bytes());
    buf.push(dst_addr.len() as u8);
    buf.extend_from_slice(dst_addr);
    buf.extend_from_slice(inner_payload);
    buf
}

fn clamp(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let sig = sign_frame(
            59,
            0x21,
            epoch,
            seqnum,
            &dst_addr,
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
                59,
                0x21,
                rx.epoch,
                rx.seqnum,
                rx.dst_addr,
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
            !verify_frame(59, 0x21, epoch, seqnum, &dst_addr, &tampered, &sig, &pub_a),
            "tampered payload must not verify"
        );

        // Wrong public key: signature check fails
        assert!(
            !verify_frame(
                59,
                0x21,
                epoch,
                seqnum,
                &dst_addr,
                inner_payload,
                &sig,
                &pub_b
            ),
            "wrong pubkey must not verify"
        );

        // Signature must be exactly 48 bytes.
        assert!(
            !verify_frame(
                59,
                0x21,
                epoch,
                seqnum,
                &dst_addr,
                inner_payload,
                &sig[..47],
                &pub_a
            ),
            "truncated signature must not verify"
        );
    }
}
