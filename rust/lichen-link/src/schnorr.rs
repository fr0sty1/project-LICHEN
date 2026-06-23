//! Schnorr48 link signatures (draft-lichen-schnorr-00).
//!
//! 48-byte deterministic Schnorr signatures over Ed25519:
//!   16-byte truncated challenge (e) || 32-byte response (s)
//!
//! Curve25519-dalek provides timing-safe scalar multiplication.
//! Nonce is deterministic (RFC 6979 style) to prevent nonce reuse.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use sha2::{Digest, Sha512};

/// Derive an Ed25519 keypair from a 32-byte seed.
///
/// Returns `(privkey, pubkey)`:
/// - `privkey` — 32-byte clamped scalar (little-endian)
/// - `pubkey`  — 32-byte compressed Ed25519 point
pub fn derive_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hash = Sha512::digest(seed);
    let mut h = [0u8; 64];
    h.copy_from_slice(&hash[..]);

    let privkey = clamp(h[..32].try_into().unwrap());
    let priv_scalar = Scalar::from_bytes_mod_order(privkey);
    let pubkey = (priv_scalar * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    (privkey, pubkey)
}

/// Sign `msg`. Returns 48-byte signature `e[16] || s[32]`.
///
/// `privkey` and `pubkey` must come from [`derive_keypair`].
pub fn sign(privkey: &[u8; 32], pubkey: &[u8; 32], msg: &[u8]) -> [u8; 48] {
    // 1. Deterministic nonce: r = SHA-512(privkey || msg) mod L
    let nonce_hash = Sha512::new()
        .chain_update(privkey)
        .chain_update(msg)
        .finalize();
    let mut nh = [0u8; 64];
    nh.copy_from_slice(&nonce_hash[..]);
    let r = Scalar::from_bytes_mod_order_wide(&nh);

    // 2. Commitment: R = r * B
    let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

    // 3. Challenge: e = SHA-512(R || pubkey || msg)[..16]
    let e_hash = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(pubkey)
        .chain_update(msg)
        .finalize();
    let e: [u8; 16] = e_hash[..16].try_into().unwrap();

    // 4. e_scalar = e || 0x00*16 (32-byte little-endian scalar)
    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(&e);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    // 5. s = (r + e_scalar * priv_scalar) mod L
    let priv_scalar = Scalar::from_bytes_mod_order(*privkey);
    let s = r + e_scalar * priv_scalar;

    let mut sig = [0u8; 48];
    sig[..16].copy_from_slice(&e);
    sig[16..].copy_from_slice(s.as_bytes());
    sig
}

/// Verify a 48-byte signature. Returns `true` if valid.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 48]) -> bool {
    // 1. Parse: e_received (16 bytes) || s (32 bytes)
    let e_received: [u8; 16] = sig[..16].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[16..].try_into().unwrap();

    // 2. s must be canonical (< L) and non-zero
    let s_opt: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
    let s = match s_opt {
        Some(s) => s,
        None => return false,
    };
    if s == Scalar::ZERO {
        return false;
    }

    // 3. Decompress public key — rejects invalid/low-order points
    let pubkey_point = match CompressedEdwardsY(*pubkey).decompress() {
        Some(p) => p,
        None => return false,
    };

    // 4. e_scalar = e_received || 0x00*16
    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(&e_received);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    // 5. R' = s*B - e*pubkey
    let sb = s * ED25519_BASEPOINT_POINT;
    let epk = e_scalar * pubkey_point;
    let r_prime = (sb - epk).compress();

    // 6. Recompute challenge and compare
    let e_check = Sha512::new()
        .chain_update(r_prime.as_bytes())
        .chain_update(pubkey)
        .chain_update(msg)
        .finalize();

    e_check[..16] == e_received
}

/// Length of a Schnorr48 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 48;

/// Sign a link-layer frame. Append the returned 48 bytes to the inner payload.
///
/// Signed data layout: epoch(1B) || seqnum(2B, BE) || dst_addr || inner_payload.
/// This matches the Python reference: `_build_signable_data`.
pub fn sign_frame(
    epoch: u8,
    seqnum: u16,
    dst_addr: &[u8],
    inner_payload: &[u8],
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
) -> [u8; 48] {
    let mut buf = [0u8; 256];
    let msg = build_signable(&mut buf, epoch, seqnum, dst_addr, inner_payload);
    sign(privkey, pubkey, msg)
}

/// Verify a signed link-layer frame.
///
/// `payload_with_sig` is the full frame payload: inner_payload || sig(48B).
/// Returns `false` if the payload is shorter than 48 bytes or the signature
/// does not verify.
pub fn verify_frame(
    epoch: u8,
    seqnum: u16,
    dst_addr: &[u8],
    payload_with_sig: &[u8],
    sender_pubkey: &[u8; 32],
) -> bool {
    if payload_with_sig.len() < SIGNATURE_LENGTH {
        return false;
    }
    let split = payload_with_sig.len() - SIGNATURE_LENGTH;
    let inner_payload = &payload_with_sig[..split];
    let sig: [u8; 48] = payload_with_sig[split..].try_into().unwrap();
    let mut buf = [0u8; 256];
    let msg = build_signable(&mut buf, epoch, seqnum, dst_addr, inner_payload);
    verify(sender_pubkey, msg, &sig)
}

// epoch(1) || seqnum(2, BE) || dst_addr || inner_payload — max 202 bytes for LoRa.
fn build_signable<'a>(
    buf: &'a mut [u8; 256],
    epoch: u8,
    seqnum: u16,
    dst_addr: &[u8],
    inner_payload: &[u8],
) -> &'a [u8] {
    buf[0] = epoch;
    buf[1..3].copy_from_slice(&seqnum.to_be_bytes());
    let mut off = 3;
    buf[off..off + dst_addr.len()].copy_from_slice(dst_addr);
    off += dst_addr.len();
    buf[off..off + inner_payload.len()].copy_from_slice(inner_payload);
    off += inner_payload.len();
    &buf[..off]
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
        let seed = arr32(&hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ));
        let (priv_got, pub_got) = derive_keypair(&seed);
        assert_eq!(
            priv_got,
            arr32(&hex(
                "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156"
            ))
        );
        assert_eq!(
            pub_got,
            arr32(&hex(
                "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
            ))
        );
    }

    #[test]
    fn derive_vector2() {
        let seed = arr32(&hex(
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
        ));
        let (priv_got, pub_got) = derive_keypair(&seed);
        assert_eq!(
            priv_got,
            arr32(&hex(
                "50b8c29238a8403e0ac69e23d47b9184c371a92460d518351b099944bbdfa867"
            ))
        );
        assert_eq!(
            pub_got,
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
            let privkey = arr32(&hex(v.privkey));
            let pubkey = arr32(&hex(v.pubkey));
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
            let pubkey = arr32(&hex(v.pubkey));
            let msg = hex(v.message);
            let sig = arr48(&hex(v.signature));
            assert!(verify(&pubkey, &msg, &sig), "vector {i} verify rejected");
        }
    }

    // ── verify: invalid cases ────────────────────────────────────────────

    #[test]
    fn invalid_wrong_message() {
        let pubkey = arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        ));
        let msg = hex("77726f6e67"); // "wrong"
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_tampered_challenge() {
        let pubkey = arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        ));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578953fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_tampered_response() {
        let pubkey = arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        ));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609c98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_wrong_pubkey() {
        let pubkey = arr32(&hex(
            "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
        ));
        let msg = hex("74657374");
        let sig    = arr48(&hex("c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009"));
        assert!(!verify(&pubkey, &msg, &sig));
    }

    #[test]
    fn invalid_all_zeros() {
        let pubkey = arr32(&hex(
            "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
        ));
        let msg = hex("74657374");
        let sig = [0u8; 48];
        assert!(!verify(&pubkey, &msg, &sig));
    }

    // ── two-node authenticated frame exchange ────────────────────────────

    #[test]
    fn two_node_frame_exchange() {
        use crate::frame::{AddrMode, LichenFrame, MicLength};
        use crate::replay::ReplayWindow;

        let seed_a = [0x01u8; 32];
        let (priv_a, pub_a) = derive_keypair(&seed_a);
        let seed_b = [0x02u8; 32];
        let (_, pub_b) = derive_keypair(&seed_b);

        let mut replay = ReplayWindow::new();

        let epoch: u8 = 1;
        let seqnum: u16 = 42;
        let dst_addr = [0x00u8, 0x01u8];
        let inner_payload = b"hello";

        // Node A: sign and assemble payload = inner_payload || sig
        let sig = sign_frame(epoch, seqnum, &dst_addr, inner_payload, &priv_a, &pub_a);
        let mut signed_payload = [0u8; 53]; // 5 + 48
        signed_payload[..5].copy_from_slice(inner_payload);
        signed_payload[5..].copy_from_slice(&sig);

        // Node A: serialise frame
        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr: &dst_addr,
            payload: &signed_payload,
            mic: &[0u8; 4],
            addr_mode: AddrMode::Short,
            mic_length: MicLength::Bits32,
            signature_present: true,
            encrypted: false,
        };
        let mut wire = [0u8; 128];
        let n = frame.write_to(&mut wire).unwrap();

        // Node B: parse and verify
        let rx = LichenFrame::from_bytes(&wire[..n]).unwrap();
        assert!(rx.signature_present);
        assert!(
            replay.accept(rx.seqnum),
            "first delivery should pass replay window"
        );
        assert!(
            verify_frame(rx.epoch, rx.seqnum, rx.dst_addr, rx.payload, &pub_a),
            "valid frame should verify"
        );

        // Replay: same sequence number rejected by ReplayWindow
        assert!(!replay.accept(rx.seqnum), "replay must be rejected");

        // Tampered inner payload: signature check fails
        let mut tampered = signed_payload;
        tampered[0] ^= 0xFF;
        assert!(
            !verify_frame(epoch, seqnum, &dst_addr, &tampered, &pub_a),
            "tampered payload must not verify"
        );

        // Wrong public key: signature check fails
        assert!(
            !verify_frame(epoch, seqnum, &dst_addr, &signed_payload, &pub_b),
            "wrong pubkey must not verify"
        );

        // Payload too short to contain a signature
        assert!(
            !verify_frame(epoch, seqnum, &dst_addr, &signed_payload[..47], &pub_a),
            "truncated payload must not verify"
        );
    }
}
