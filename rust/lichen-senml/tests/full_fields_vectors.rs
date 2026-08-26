// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_senml::wire::{decode, encode};
use lichen_senml::{CborError, Record};
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../test/vectors/senml_full_fields.json");

#[derive(Deserialize)]
struct Document {
    format_version: u8,
    records: Vec<VectorRecord>,
    cbor_hex: String,
}

#[derive(Deserialize)]
struct VectorRecord {
    bn: Option<String>,
    bt: Option<f64>,
    bu: Option<String>,
    bv: Option<f64>,
    bs: Option<f64>,
    bver: Option<u8>,
    n: Option<String>,
    u: Option<String>,
    v: Option<f64>,
    vs: Option<String>,
    vb: Option<bool>,
    vd_hex: Option<String>,
    s: Option<f64>,
    t: Option<f64>,
    ut: Option<f64>,
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn complete_pack_encodes_and_decodes_byte_exactly() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document.format_version, 2);
    let data_values: Vec<Option<Vec<u8>>> = document
        .records
        .iter()
        .map(|record| record.vd_hex.as_deref().map(hex))
        .collect();
    let records: Vec<Record<'_>> = document
        .records
        .iter()
        .zip(&data_values)
        .map(|(record, data)| Record {
            base_name: record.bn.as_deref(),
            base_time: record.bt,
            base_unit: record.bu.as_deref(),
            base_value: record.bv,
            base_sum: record.bs,
            base_version: record.bver,
            name: record.n.as_deref(),
            unit: record.u.as_deref(),
            value: record.v,
            string_value: record.vs.as_deref(),
            bool_value: record.vb,
            data_value: data.as_deref(),
            sum: record.s,
            time: record.t,
            update_time: record.ut,
        })
        .collect();
    let expected = hex(&document.cbor_hex);
    let mut wire = vec![0xa5; expected.len()];
    assert_eq!(encode(&records, &mut wire), Ok(expected.len()));
    assert_eq!(wire, expected);

    let mut decoded = [const { Record::empty() }; 5];
    assert_eq!(decode(&wire, &mut decoded), Ok(5));
    assert_eq!(decoded.as_slice(), records.as_slice());

    let mut reencoded = vec![0; wire.len()];
    assert_eq!(encode(&decoded, &mut reencoded), Ok(wire.len()));
    assert_eq!(reencoded, wire);
}

#[test]
fn data_value_participates_in_one_value_rule() {
    let record = Record {
        value: Some(1.0),
        data_value: Some(&[1, 2]),
        ..Record::empty()
    };
    let mut out = [0x5a; 32];
    assert_eq!(encode(&[record], &mut out), Err(CborError::MultipleValues));
    assert!(out.iter().all(|byte| *byte == 0x5a));

    // [{v: 1, vd: h'0102'}]
    let wire = [0x81, 0xa2, 0x02, 0x01, 0x08, 0x42, 0x01, 0x02];
    let mut decoded = [const { Record::empty() }; 1];
    assert_eq!(decode(&wire, &mut decoded), Err(CborError::MultipleValues));
}

#[test]
fn base_version_range_is_enforced_without_partial_writes() {
    for version in [0, 11] {
        let record = Record {
            base_version: Some(version),
            ..Record::empty()
        };
        let mut out = [0x5a; 16];
        assert_eq!(encode(&[record], &mut out), Err(CborError::InvalidInput));
        assert!(out.iter().all(|byte| *byte == 0x5a));
    }
    for wire in [[0x81, 0xa1, 0x20, 0x00], [0x81, 0xa1, 0x20, 0x0b]] {
        let mut decoded = [const { Record::empty() }; 1];
        assert_eq!(decode(&wire, &mut decoded), Err(CborError::InvalidInput));
    }
}

#[test]
fn text_extensions_follow_rfc8428_mandatory_suffix_rule() {
    // [{n: "x", "foo": 1}] — optional unknown extension is ignored.
    let optional = [0x81, 0xa2, 0x00, 0x61, b'x', 0x63, b'f', b'o', b'o', 0x01];
    let mut decoded = [const { Record::empty() }; 1];
    assert_eq!(decode(&optional, &mut decoded), Ok(1));
    assert_eq!(decoded[0].name, Some("x"));

    // [{"foo_": 1}] — trailing underscore marks an unknown mandatory field.
    let mandatory = [0x81, 0xa1, 0x64, b'f', b'o', b'o', b'_', 0x01];
    assert_eq!(
        decode(&mandatory, &mut decoded),
        Err(CborError::InvalidInput)
    );
}
