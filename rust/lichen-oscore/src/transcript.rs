// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! EDHOC transcript hash helpers (RFC 9528).
//!
//! The transcript hashes bind each handshake message into the session key
//! material. TH_2 = H(CBOR(G_Y) || CBOR(H(message_1))) per RFC 9528
//! Section 5.3.2, where both values are encoded as CBOR byte strings.

use super::EdhocError;
use heapless::Vec as HeaplessVec;
use sha2::{Digest, Sha256};

/// Compute transcript hash: H(input) with SHA-256 (RFC 9528 Suite 0).
pub(crate) fn compute_th(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// TH_2 = H(CBOR(G_Y) || CBOR(H(message_1))) (RFC 9528 Section 5.3.2).
///
/// `g_y` is the responder's ephemeral X25519 public key and `msg1` is the
/// raw message_1 bytes. Both are encoded as CBOR byte strings before
/// hashing, bit-for-bit identical to the Python reference
/// `cbor2.dumps(g_y) + cbor2.dumps(h_msg1)`.
pub fn transcript_2(g_y: &[u8; 32], msg1: &[u8]) -> Result<[u8; 32], EdhocError> {
    let h_msg1 = compute_th(msg1);
    let mut buf = HeaplessVec::<u8, 68>::new();
    encode_bstr32(&mut buf, g_y)?;
    encode_bstr32(&mut buf, &h_msg1)?;
    Ok(compute_th(&buf))
}

/// Append a 32-byte value as a definite-length CBOR byte string (0x58 0x20).
fn encode_bstr32(buf: &mut HeaplessVec<u8, 68>, value: &[u8; 32]) -> Result<(), EdhocError> {
    buf.extend_from_slice(&[0x58, 0x20])
        .map_err(|_| EdhocError::BufferTooSmall)?;
    buf.extend_from_slice(value)
        .map_err(|_| EdhocError::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 9529 Section 2.2 TH_2 vector, transcribed identically in
    /// python/tests/crypto/test_edhoc.py::TestRfc9528KdfStructure.
    #[test]
    fn th2_matches_rfc_9529_section_2_2() {
        let msg1 =
            hex!("0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
        let g_y = hex!("dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");

        let h_msg1 = compute_th(&msg1);
        assert_eq!(
            h_msg1,
            hex!("c165d6a99d1bcafaac8dbf2b352a6f7d71a30b439c9d64d349a23848038ed16b")
        );

        let th_2 = transcript_2(&g_y, &msg1).expect("transcript_2 failed");
        assert_eq!(
            th_2,
            hex!("c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d")
        );
    }
}
