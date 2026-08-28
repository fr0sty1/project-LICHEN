// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Focused decompression coverage for SCHC Rule 5 (link-local OSCORE).

use lichen_schc::{compress, decompress, SchcError};
use serde::Deserialize;

const MAX_DECOMPRESSED_COAP: usize = 1_500;
const FIXED_COMPRESSED_LEN: usize = 23;
const CANONICAL_COMPRESSED: &[u8] = &[
    0x05, 0x40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0x33, 0x08, 0x04, 0x48, 0xd0, 0, 1,
    0x92, 9, 0, 0xff, 0xde, 0xad, 0xbe, 0xef,
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

fn canonical_fixed_residue() -> Vec<u8> {
    CANONICAL_COMPRESSED[..FIXED_COMPRESSED_LEN].to_vec()
}

#[test]
fn canonical_shared_vector_decompresses_to_python_oracle() {
    let document: VectorFile =
        serde_json::from_str(include_str!("../../../test/vectors/schc_compression.json")).unwrap();
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.name == "oscore_linklocal")
        .unwrap();
    let expected = hex(vector.packet.as_deref().unwrap());
    let compressed = hex(vector.compressed.as_deref().unwrap());
    assert_eq!(compressed, CANONICAL_COMPRESSED);

    let mut output = vec![0u8; expected.len()];
    let length = decompress(&compressed, &mut output).unwrap();
    assert_eq!(&output[..length], expected);
}

#[test]
fn independently_encoded_residue_reconstructs_fields_and_oscore_tail() {
    // Hop=1, IIDs=ffff:ffff:ffff:ffff and 0102:0304:0506:0708,
    // ports=5680/5695, CoAP CON/TKL=2/code=0x45/MID=0xbeef.
    let mut encoded = hex("0501ffffffffffffffff01020304050607080fc916fbbc");
    encoded.extend_from_slice(&hex("aa55920901ff010203"));

    let mut output = [0u8; 128];
    let length = decompress(&encoded, &mut output).unwrap();
    assert_eq!(length, 61);
    assert_eq!(&output[0..8], &hex("6000000000151101"));
    assert_eq!(
        &output[8..40],
        &hex("fe80000000000000fffffffffffffffffe800000000000000102030405060708")
    );
    assert_eq!(&output[40..46], &hex("1630163f0015"));
    assert_ne!(&output[46..48], &[0, 0]);
    assert_eq!(&output[48..length], &hex("7245beefaa55920901ff010203"));

    let mut recompressed = [0u8; 128];
    let compressed_length = compress(&output[..length], &mut recompressed).unwrap();
    assert_eq!(&recompressed[..compressed_length], encoded);
}

#[test]
fn every_truncated_rule5_residue_is_rejected() {
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
fn rule5_rejects_plaintext_malformed_and_duplicate_oscore_tails() {
    for tail in [
        &[0, 1][..],
        &[0, 1, 0x9f][..],
        &[0, 1, 0x9d][..],
        &[0, 1, 0x91, 1][..],
        &[0, 1, 0x90, 0][..],
        &[0, 1, 0x90, 0xff][..],
    ] {
        let mut encoded = canonical_fixed_residue();
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
fn rule5_rejects_reserved_or_unavailable_token_length() {
    let mut reserved_tkl = canonical_fixed_residue();
    reserved_tkl[19] = (reserved_tkl[19] & 0xc3) | (9 << 2);
    reserved_tkl.extend_from_slice(&[0; 9]);

    let missing_token = canonical_fixed_residue();
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
    let mut encoded = canonical_fixed_residue();
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
