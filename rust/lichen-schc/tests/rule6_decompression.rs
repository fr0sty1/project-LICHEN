// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Strict inverse coverage for current-spec SCHC Rule 6 (global OSCORE).

use lichen_schc::{compress, decompress, SchcError};
use serde::Deserialize;

const MAX_DECOMPRESSED_COAP: usize = 1_500;
const FIXED_COMPRESSED_LEN: usize = 37;
const CANONICAL_COMPRESSED: &[u8] = &[
    0x06, 0x40, 0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63, 0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63,
    0x42, 0xf7, 0x7a, 0x7b, 0xaa, 0x12, 0x26, 0xb5, 0xf5, 0x7a, 0x7b, 0xaa, 0x12, 0x26, 0xb5, 0x0c,
    0x33, 0x08, 0x04, 0x48, 0xd0, 0, 1, 0x92, 9, 0, 0xff, 0xde, 0xad, 0xbe, 0xef,
];

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    packet: Option<String>,
    compressed: Option<String>,
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn fixed_residue() -> Vec<u8> {
    CANONICAL_COMPRESSED[..FIXED_COMPRESSED_LEN].to_vec()
}

#[test]
fn canonical_shared_vector_decompresses_to_python_oracle() {
    let document: VectorFile =
        serde_json::from_str(include_str!("../../../test/vectors/schc_compression.json")).unwrap();
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.name == "oscore_global")
        .unwrap();
    let expected = hex(vector.packet.as_deref().unwrap());
    let compressed = hex(vector.compressed.as_deref().unwrap());
    assert_eq!(compressed, CANONICAL_COMPRESSED);

    let mut output = vec![0u8; expected.len()];
    let length = decompress(&compressed, &mut output).unwrap();
    assert_eq!(&output[..length], expected);
}

#[test]
fn independently_encoded_residue_reconstructs_global_fields_and_tail() {
    let mut encoded = hex("0601");
    encoded.extend_from_slice(&[0xff; 15]);
    encoded.extend_from_slice(&[0; 14]);
    encoded.push(1);
    encoded.extend_from_slice(&hex("0fc916fbbcaa55920901ff010203"));

    let mut output = [0u8; 128];
    let length = decompress(&encoded, &mut output).unwrap();
    assert_eq!(length, 61);
    assert_eq!(&output[0..8], &hex("6000000000151101"));
    assert_eq!(
        &output[8..40],
        &hex("02ffffffffffffffffffffffffffffff02000000000000000000000000000001")
    );
    assert_eq!(&output[40..46], &hex("1630163f0015"));
    assert_ne!(&output[46..48], &[0, 0]);
    assert_eq!(&output[48..length], &hex("7245beefaa55920901ff010203"));

    let mut recompressed = [0u8; 128];
    let compressed_length = compress(&output[..length], &mut recompressed).unwrap();
    assert_eq!(&recompressed[..compressed_length], encoded);
}

#[test]
fn every_truncated_rule6_residue_is_rejected() {
    for length in 1..FIXED_COMPRESSED_LEN {
        let mut output = [0u8; 128];
        assert!(matches!(
            decompress(&CANONICAL_COMPRESSED[..length], &mut output),
            Err(SchcError::TooShort(_))
        ));
    }
}

#[test]
fn both_nonzero_padding_bits_are_rejected() {
    for bit in [1, 2] {
        let mut malformed = CANONICAL_COMPRESSED.to_vec();
        malformed[FIXED_COMPRESSED_LEN - 1] |= bit;
        let mut output = [0u8; 128];
        assert!(matches!(
            decompress(&malformed, &mut output),
            Err(SchcError::NonCanonicalResidue(_))
        ));
    }
}

#[test]
fn rule6_rejects_plaintext_malformed_and_duplicate_oscore_tails_atomically() {
    for tail in [
        &[0, 1][..],
        &[0, 1, 0x9f][..],
        &[0, 1, 0x9d][..],
        &[0, 1, 0x91, 1][..],
        &[0, 1, 0x90, 0][..],
        &[0, 1, 0x90, 0xff][..],
    ] {
        let mut encoded = fixed_residue();
        encoded.extend_from_slice(tail);
        let mut output = [0xa5; 128];
        assert!(matches!(
            decompress(&encoded, &mut output),
            Err(SchcError::NonCanonicalResidue(_))
        ));
        assert_eq!(output, [0xa5; 128], "tail {tail:02x?}");
    }
}

#[test]
fn rule6_rejects_reserved_or_unavailable_token_length() {
    let mut reserved_tkl = fixed_residue();
    reserved_tkl[33] = (reserved_tkl[33] & 0xc3) | (9 << 2);
    reserved_tkl.extend_from_slice(&[0; 9]);
    let missing_token = fixed_residue();

    let mut output = [0xa5; 128];
    for encoded in [&reserved_tkl, &missing_token] {
        assert!(matches!(
            decompress(encoded, &mut output),
            Err(SchcError::NonCanonicalResidue(_))
        ));
        assert_eq!(output, [0xa5; 128]);
        output.fill(0xa5);
    }
}

#[test]
fn exact_embedded_coap_boundary_round_trips_and_one_over_fails_atomically() {
    let mut encoded = fixed_residue();
    encoded.extend_from_slice(&[0, 1, 0x90, 0xff]);
    encoded.resize(FIXED_COMPRESSED_LEN + MAX_DECOMPRESSED_COAP - 4, 0xaa);

    let mut output = vec![0u8; 48 + MAX_DECOMPRESSED_COAP];
    let length = decompress(&encoded, &mut output).unwrap();
    assert_eq!(length, output.len());
    let mut recompressed = vec![0u8; encoded.len()];
    let compressed_length = compress(&output, &mut recompressed).unwrap();
    assert_eq!(compressed_length, encoded.len());
    assert_eq!(recompressed, encoded);

    encoded.push(0xaa);
    let mut oversized_output = vec![0xa5; output.len() + 1];
    assert!(matches!(
        decompress(&encoded, &mut oversized_output),
        Err(SchcError::BufferTooSmall(_))
    ));
    assert!(oversized_output.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn undersized_output_fails_without_mutation() {
    let mut output = vec![0xa5; 61];
    assert!(matches!(
        decompress(CANONICAL_COMPRESSED, &mut output),
        Err(SchcError::BufferTooSmall(_))
    ));
    assert!(output.iter().all(|byte| *byte == 0xa5));
}
