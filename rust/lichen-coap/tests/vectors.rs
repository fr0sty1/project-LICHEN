// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Tests for /deaddrop and /confessions vectors from test/vectors/deaddrop.json
//! and test/vectors/confessions.json. Validates CoAP wire format parseability.

use std::fs;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<serde_json::Value>,
}

fn load_vectors(path_rel: &str) -> VectorFile {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let path = format!("{}/{}", base, path_rel);
    let content = fs::read_to_string(&path).expect("Failed to read vector file");
    serde_json::from_str(&content).expect("Failed to parse vector file")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_deaddrop_vector_wire_format() {
    let doc = load_vectors("test/vectors/deaddrop.json");
    assert_eq!(doc.vectors.len(), 4, "expected 4 deaddrop vectors");

    for v in &doc.vectors {
        let name = v["name"].as_str().unwrap();
        let encoded = hex_to_bytes(v["encoded"].as_str().unwrap());
        assert!(encoded.len() >= 4, "{}: CoAP frame too short", name);
        assert_eq!(
            encoded[0] & 0xC0,
            0x40,
            "{}: not CoAP version 1",
            name
        );
        let code = encoded[1];
        let vector_type = v["type"].as_str().unwrap();
        match vector_type {
            "post_submission" | "oscore_wrapped" => {
                assert_eq!(code, 0x02, "{}: expected POST code", name);
            }
            "pickup" => {
                assert_eq!(code, 0x01, "{}: expected GET code", name);
            }
            "rejection" => {
                assert_eq!(code, 0x02, "{}: expected POST code for rejection", name);
            }
            _ => panic!("{}: unknown type {}", name, vector_type),
        }
        if let Some(senml) = v["senml_payload"].as_str() {
            if !senml.is_empty() {
                let senml_bytes = hex_to_bytes(senml);
                assert!(senml_bytes.len() >= 2, "{}: SenML too short", name);
            }
        }
        if let Some(ct) = v["ciphertext"].as_str() {
            if !ct.is_empty() {
                let ct_bytes = hex_to_bytes(ct);
                assert!(ct_bytes.len() >= 2, "{}: ciphertext too short", name);
            }
        }
        if let Some(expected) = v["expected"].as_object() {
            if let Some(rc) = expected.get("response_code").and_then(|c| c.as_u64()) {
                assert!(rc <= 255, "{}: response code out of range", name);
            }
        }
    }
}

#[test]
fn test_confessions_vector_wire_format() {
    let doc = load_vectors("test/vectors/confessions.json");
    assert_eq!(doc.vectors.len(), 4, "expected 4 confessions vectors");

    for v in &doc.vectors {
        let name = v["name"].as_str().unwrap();
        let encoded = hex_to_bytes(v["encoded"].as_str().unwrap());
        assert!(encoded.len() >= 4, "{}: CoAP frame too short", name);
        assert_eq!(
            encoded[0] & 0xC0,
            0x40,
            "{}: not CoAP version 1",
            name
        );
        let code = encoded[1];
        let vector_type = v["type"].as_str().unwrap();
        match vector_type {
            "post_submission" => {
                assert_eq!(code, 0x02, "{}: expected POST code", name);
            }
            "get" => {
                assert_eq!(code, 0x01, "{}: expected GET code", name);
            }
            "rejection" => {
                assert_eq!(code, 0x02, "{}: expected POST code for rejection", name);
            }
            _ => panic!("{}: unknown type {}", name, vector_type),
        }
        if let Some(senml) = v["senml_payload"].as_str() {
            if !senml.is_empty() {
                let senml_bytes = hex_to_bytes(senml);
                assert!(senml_bytes.len() >= 2, "{}: SenML too short", name);
            }
        }
        if let Some(payload) = v["payload"].as_str() {
            if !payload.is_empty() {
                let payload_bytes = hex_to_bytes(payload);
                assert!(payload_bytes.len() >= 1, "{}: payload too short", name);
            }
        }
        if let Some(expected) = v["expected"].as_object() {
            if let Some(rc) = expected.get("response_code").and_then(|c| c.as_u64()) {
                assert!(rc <= 255, "{}: response code out of range", name);
            }
        }
    }
}
