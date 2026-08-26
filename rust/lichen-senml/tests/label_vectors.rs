// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_senml::wire::{decode, SenmlLabel};
use lichen_senml::{CborError, Record};
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../test/vectors/senml_labels.json");

#[derive(Deserialize)]
struct Document {
    format_version: u8,
    vectors: Vec<LabelVector>,
}

#[derive(Deserialize)]
struct LabelVector {
    field: String,
    label: i64,
    cbor_key_hex: String,
}

fn one_byte_hex(value: &str) -> u8 {
    assert_eq!(value.len(), 2);
    u8::from_str_radix(value, 16).unwrap()
}

#[test]
fn complete_rfc8428_numeric_label_mapping_matches_shared_vectors() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document.format_version, 2);
    assert_eq!(document.vectors.len(), SenmlLabel::ALL.len());

    let mut seen = [false; 15];
    for vector in document.vectors {
        let label = SenmlLabel::from_i64(vector.label).expect("known RFC 8428 label");
        assert_eq!(label.field_name(), vector.field);
        let index = SenmlLabel::ALL
            .iter()
            .position(|candidate| *candidate == label)
            .unwrap();
        assert!(!seen[index], "duplicate label {}", vector.label);
        seen[index] = true;

        let mut encoded = [0xff; 2];
        let length = label.write_cbor_key(&mut encoded).unwrap();
        assert_eq!(length, 1);
        assert_eq!(encoded[0], one_byte_hex(&vector.cbor_key_hex));
        assert_eq!(
            SenmlLabel::from_cbor_key(&encoded[..length]),
            Ok((label, 1))
        );
    }
    assert!(seen.into_iter().all(|present| present));
}

#[test]
fn unknown_and_non_integer_keys_fail_safely() {
    assert_eq!(SenmlLabel::from_i64(-7), None);
    assert_eq!(SenmlLabel::from_i64(9), None);
    assert_eq!(
        SenmlLabel::from_cbor_key(&[0x26]),
        Err(CborError::InvalidInput)
    );
    assert_eq!(
        SenmlLabel::from_cbor_key(&[0x09]),
        Err(CborError::InvalidInput)
    );
    assert_eq!(
        SenmlLabel::from_cbor_key(&[0x61, b'n']),
        Err(CborError::InvalidInput)
    );
    assert!(SenmlLabel::Name.write_cbor_key(&mut []).is_err());
}

#[test]
fn decoder_rejects_duplicate_standard_labels_even_when_record_lacks_field() {
    // [{bs: 0, bs: 1}]. `senml-cbor::Record` does not expose Base Sum yet,
    // but the full RFC mapping still makes duplicate -6 labels invalid.
    let wire = [0x81, 0xa2, 0x25, 0x00, 0x25, 0x01];
    let mut records = [const { Record::empty() }; 1];
    assert_eq!(decode(&wire, &mut records), Err(CborError::InvalidInput));
}
