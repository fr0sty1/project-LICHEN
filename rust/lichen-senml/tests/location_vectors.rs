// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-language SenML location vectors (spec appendix-senml F.3).
//!
//! Consumes `test/vectors/senml_location.json`, the same oracle file the
//! Python reference (`lichen.senml`) validates against byte-for-byte in
//! `python/tests/coap/test_senml_location_vectors.py`. Positive vectors must
//! encode to identical bytes through `lichen_senml::wire`, decode back into
//! identical records, and re-encode stably; decoder-reject vectors must be
//! refused.
//!
//! The four encoder range/finite rejects (latitude bounds, longitude bounds)
//! pin profile-level policy (spec F.3) rather than codec policy; only the NaN
//! case is observable at this layer (as `CborError::NonFiniteValue`). The
//! remaining range checks belong to the field-validation work item.

use std::fs;
use std::path::Path as FsPath;

use lichen_senml::wire;
use lichen_senml::Record;
use senml_cbor::cbor::CborError;
use serde::Deserialize;

/// Field order used by the Python `profiles.location()` helper; vector
/// "fields" follow it after bn/bt.
const LOCATION_FIELD_ORDER: [(&str, &str); 7] = [
    ("lat", "lat"),
    ("lon", "lon"),
    ("alt", "m"),
    ("speed", "m/s"),
    ("heading", "deg"),
    ("hacc", "m"),
    ("vacc", "m"),
];

#[derive(Debug, Deserialize)]
struct VectorDocument {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    #[serde(default)]
    fields: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    cbor_hex: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn load_vectors() -> VectorDocument {
    let path =
        FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/senml_location.json");
    let contents = fs::read_to_string(path).expect("read SenML location vectors");
    serde_json::from_str(&contents).expect("parse SenML location vectors")
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("hex digit");
            (hi * 16 + lo) as u8
        })
        .collect()
}

/// Resolve the documented string sentinels to the float values they stand in
/// for (the JSON oracle cannot carry a literal NaN).
fn resolve_f64(value: &serde_json::Value) -> f64 {
    match value {
        serde_json::Value::String(s) if s == "NaN" => f64::NAN,
        other => other
            .as_f64()
            .unwrap_or_else(|| panic!("field {other} is not a number")),
    }
}

/// Assemble the pack exactly as the Python test does: base fields ride on a
/// leading base-only record, every remaining field becomes one record via
/// the location profile shape.
fn records_from_fields(fields: &serde_json::Map<String, serde_json::Value>) -> Vec<Record<'_>> {
    let mut records: Vec<Record> = Vec::new();
    let base_name = fields.get("bn").and_then(|v| v.as_str());
    let base_time = fields.get("bt").map(resolve_f64);
    if base_name.is_some() || base_time.is_some() {
        records.push(Record {
            base_name,
            base_time,
            ..Record::empty()
        });
    }
    for (name, unit) in LOCATION_FIELD_ORDER {
        if let Some(value) = fields.get(name) {
            records.push(Record {
                name: Some(name),
                unit: Some(unit),
                value: Some(resolve_f64(value)),
                ..Record::empty()
            });
        }
    }
    records
}

#[test]
fn positive_vectors_encode_decode_and_reencode_byte_exactly() {
    let document = load_vectors();
    let positives: Vec<&Vector> = document
        .vectors
        .iter()
        .filter(|v| v.error.is_none())
        .collect();
    assert_eq!(positives.len(), 5, "oracle file changed: revisit counts");

    for vector in positives {
        let expected_hex = vector.cbor_hex.as_deref().expect("positive vector hex");
        let fields = vector.fields.as_ref().expect("positive vector fields");
        let records = records_from_fields(fields);

        // Encode parity with the committed oracle bytes.
        let mut buf = [0u8; 256];
        let n = wire::encode(&records, &mut buf).expect("encode positive vector");
        assert_eq!(
            &buf[..n],
            unhex(expected_hex).as_slice(),
            "{}: encoded bytes differ from oracle",
            vector.id
        );

        // Decode parity: the oracle bytes yield the same record sequence.
        let mut decoded = [const { Record::empty() }; 12];
        let count = wire::decode(&buf[..n], &mut decoded).expect("decode own encoding");
        assert_eq!(count, records.len(), "{}", vector.id);
        for (want, got) in records.iter().zip(decoded.iter().take(count)) {
            assert_eq!(want.base_name, got.base_name, "{}", vector.id);
            assert_eq!(want.base_time, got.base_time, "{}", vector.id);
            assert_eq!(want.name, got.name, "{}", vector.id);
            assert_eq!(want.unit, got.unit, "{}", vector.id);
            assert_eq!(want.value, got.value, "{}", vector.id);
        }

        // Re-encoding decoded records is byte-stable.
        let mut again = [0u8; 256];
        let n2 = wire::encode(&decoded[..count], &mut again).expect("re-encode decoded");
        assert_eq!(
            &again[..n2],
            &buf[..n],
            "{}: round trip not stable",
            vector.id
        );

        // The oracle bytes also decode directly and re-encode identically,
        // even where they carry integer-form timestamps.
        let oracle = unhex(expected_hex);
        let count = wire::decode(&oracle, &mut decoded).expect("decode oracle bytes");
        let n3 = wire::encode(&decoded[..count], &mut again).expect("re-encode decoded oracle");
        assert_eq!(&again[..n3], oracle.as_slice(), "{}", vector.id);
    }
}

#[test]
fn full_vector_carries_expected_semantics() {
    let document = load_vectors();
    let vector = document
        .vectors
        .iter()
        .find(|v| v.id == "senml-location-full")
        .expect("senml-location-full vector");
    let oracle = unhex(vector.cbor_hex.as_deref().expect("cbor hex"));
    let mut decoded = [const { Record::empty() }; 12];
    let count = wire::decode(&oracle, &mut decoded).expect("decode full vector");

    assert_eq!(decoded[0].base_name, Some("urn:dev:mac:0011223344556677:"));
    assert_eq!(decoded[0].base_time, Some(1_716_742_800.0));
    let names_units: Vec<(&str, &str)> = decoded[1..count]
        .iter()
        .map(|r| (r.name.expect("name"), r.unit.expect("unit")))
        .collect();
    assert_eq!(
        names_units,
        vec![
            ("lat", "lat"),
            ("lon", "lon"),
            ("alt", "m"),
            ("speed", "m/s"),
            ("heading", "deg"),
            ("hacc", "m"),
            ("vacc", "m")
        ]
    );
    assert_eq!(decoded[1].value, Some(37.774_929));
    assert_eq!(decoded[2].value, Some(-122.419_416));
}

#[test]
fn minimal_vector_has_no_base_record() {
    let document = load_vectors();
    let vector = document
        .vectors
        .iter()
        .find(|v| v.id == "senml-location-minimal")
        .expect("minimal vector");
    let oracle = unhex(vector.cbor_hex.as_deref().expect("cbor hex"));
    let mut decoded = [const { Record::empty() }; 12];
    let count = wire::decode(&oracle, &mut decoded).expect("decode minimal vector");
    assert_eq!(count, 2);
    assert!(decoded[..count]
        .iter()
        .all(|r| r.base_name.is_none() && r.base_time.is_none()));
}

#[test]
fn nan_coordinate_rejects_at_the_codec_layer() {
    let document = load_vectors();
    let vector = document
        .vectors
        .iter()
        .find(|v| v.id == "senml-location-err-lat-nan")
        .expect("NaN vector");
    let fields = vector.fields.as_ref().expect("fields");
    let records = records_from_fields(fields);
    assert!(records.iter().any(|r| r.value.is_some_and(|v| v.is_nan())));
    let mut buf = [0u8; 64];
    assert_eq!(
        wire::encode(&records, &mut buf),
        Err(CborError::NonFiniteValue)
    );
}

#[test]
fn decode_reject_vectors_are_refused() {
    let document = load_vectors();
    let rejects: Vec<&Vector> = document
        .vectors
        .iter()
        .filter(|v| v.error.is_some() && v.cbor_hex.is_some())
        .collect();
    assert_eq!(rejects.len(), 3, "oracle file changed: revisit counts");

    for vector in rejects {
        let wire_bytes = unhex(vector.cbor_hex.as_deref().expect("reject vector hex"));
        let mut buf = [const { Record::empty() }; 4];
        let result = wire::decode(&wire_bytes, &mut buf);
        assert!(result.is_err(), "{}: malformed pack accepted", vector.id);
        if vector.id.ends_with("multiple-value-fields") {
            assert_eq!(result, Err(CborError::MultipleValues), "{}", vector.id);
        }
    }
}

#[test]
fn vector_partition_is_exhaustive() {
    let document = load_vectors();
    let total = document.vectors.len();
    let positives = document
        .vectors
        .iter()
        .filter(|v| v.error.is_none())
        .count();
    let encode_rejects = document
        .vectors
        .iter()
        .filter(|v| v.error.is_some() && v.cbor_hex.is_none())
        .count();
    let decode_rejects = document
        .vectors
        .iter()
        .filter(|v| v.error.is_some() && v.cbor_hex.is_some())
        .count();
    assert_eq!(positives + encode_rejects + decode_rejects, total);
    assert_eq!(total, 12);
}
