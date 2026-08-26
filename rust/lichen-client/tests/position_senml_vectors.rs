// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-implementation byte-parity tests for position SenML encoding.
//!
//! Oracle: `test/vectors/senml_location.json` — CBOR hex produced
//! independently of any implementation (per the file's own description) and
//! already matched byte-for-byte by the Python codec
//! (`python/tests/coap/test_senml_location_vectors.py`). Proving this crate
//! reproduces the same bytes proves Python/Rust parity with neither side
//! acting as the other's oracle. All tests are offline.

use lichen_client::pos::Position;
use serde_json::Value;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test/vectors/senml_location.json"
);

/// Field order used by `Position::to_senml_cbor` after bn/bt; matches the
/// spec F.3 record order and the Python `profiles.location()` signature.
const LOCATION_FIELDS: [&str; 7] = ["lat", "lon", "alt", "speed", "heading", "hacc", "vacc"];

fn load_vectors() -> Vec<Value> {
    let raw = std::fs::read_to_string(VECTORS_PATH).expect("read senml_location.json");
    let doc: Value = serde_json::from_str(&raw).expect("parse senml_location.json");
    doc["vectors"].as_array().expect("vectors array").clone()
}

fn resolve(value: &Value) -> f64 {
    match value.as_str() {
        Some("NaN") => f64::NAN,
        _ => value
            .as_f64()
            .unwrap_or_else(|| panic!("numeric or \"NaN\" sentinel, got {value}")),
    }
}

fn position_from_fields(fields: &Value) -> Position {
    let mut position = Position {
        device: fields["bn"].as_str().map(str::to_string),
        time: fields["bt"].as_u64(),
        lat: resolve(&fields["lat"]),
        lon: resolve(&fields["lon"]),
        alt: None,
        speed: None,
        heading: None,
        hacc: None,
        vacc: None,
    };
    for name in LOCATION_FIELDS.iter().skip(2) {
        if let Some(value) = fields.get(*name) {
            let resolved = resolve(value);
            match *name {
                "alt" => position.alt = Some(resolved),
                "speed" => position.speed = Some(resolved),
                "heading" => position.heading = Some(resolved),
                "hacc" => position.hacc = Some(resolved),
                "vacc" => position.vacc = Some(resolved),
                other => panic!("unexpected location field {other}"),
            }
        }
    }
    position
}

#[test]
fn positive_vectors_encode_byte_identically() {
    let vectors = load_vectors();
    for vector in vectors.iter().filter(|v| v.get("error").is_none()) {
        let id = vector["id"].as_str().expect("vector id");
        let expected = vector["cbor_hex"].as_str().expect("cbor_hex");

        let position = position_from_fields(&vector["fields"]);
        let encoded = position
            .to_senml_cbor()
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(hex::encode(&encoded), expected, "{id}");

        // Decode -> re-encode is stable, mirroring the Python round-trip test.
        let decoded = Position::from_senml_cbor(&encoded).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            hex::encode(decoded.to_senml_cbor().unwrap()),
            expected,
            "{id}"
        );
    }
}

#[test]
fn decoded_positive_vectors_match_field_values() {
    let vector = load_vectors()
        .iter()
        .find(|v| v["id"] == "senml-location-full")
        .expect("full vector")
        .clone();
    let wire = hex::decode(vector["cbor_hex"].as_str().unwrap()).unwrap();
    let position = Position::from_senml_cbor(&wire).unwrap();

    assert_eq!(
        position.device.as_deref(),
        Some("urn:dev:mac:0011223344556677:")
    );
    assert_eq!(position.time, Some(1_716_742_800));
    assert_eq!(position.lat, 37.774929);
    assert_eq!(position.lon, -122.419416);
    assert_eq!(position.alt, Some(10.5));
    assert_eq!(position.speed, Some(1.2));
    assert_eq!(position.heading, Some(45.0));
    assert_eq!(position.hacc, Some(5.0));
    assert_eq!(position.vacc, Some(10.0));
}

#[test]
fn encoder_reject_vectors_are_refused() {
    let vectors = load_vectors();
    let rejects: Vec<&Value> = vectors
        .iter()
        .filter(|v| v.get("error").is_some() && v.get("cbor_hex").is_none())
        .collect();
    assert!(rejects.len() >= 3, "range/finite reject vectors present");

    for vector in rejects {
        let id = vector["id"].as_str().expect("vector id");
        let fields = &vector["fields"];
        let mut position = position_from_fields(fields);
        // Reject vectors may omit lon; keep it in range so the intended
        // violation (lat range/finite) is what trips validation.
        if fields.get("lon").is_none() {
            position.lon = 0.0;
        }
        assert!(position.to_senml_cbor().is_err(), "{id} must be rejected");
    }
}

#[test]
fn decoder_reject_vectors_are_refused() {
    let vectors = load_vectors();
    let rejects: Vec<&Value> = vectors
        .iter()
        .filter(|v| v.get("error").is_some() && v.get("cbor_hex").is_some())
        .collect();
    assert_eq!(rejects.len(), 3, "all decoder reject vectors exercised");

    for vector in rejects {
        let id = vector["id"].as_str().expect("vector id");
        let wire = hex::decode(vector["cbor_hex"].as_str().expect("cbor_hex")).unwrap();
        assert!(
            Position::from_senml_cbor(&wire).is_err(),
            "{id} must be rejected"
        );
    }
}
