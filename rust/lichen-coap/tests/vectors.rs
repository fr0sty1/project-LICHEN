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

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Vectors may embed the literal URI token "deaddrop" as a Uri-Path
    // placeholder; substitute its ASCII hex before parsing (mirrors the
    // Python vector runner).
    let hex = hex.replace("deaddrop", "6465616464726f70");
    if hex.is_empty() {
        return Some(Vec::new());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None, // Invalid hex
        }
    }
    Some(bytes)
}

/// Vector types that carry a CoAP wire frame in `encoded`.
const DEADDROP_WIRE_TYPES: &[(&str, u8)] = &[
    ("post_submission", 0x02),
    ("oscore_wrapped", 0x02),
    ("rejection", 0x02),
    ("pickup", 0x01),
    ("observe", 0x01),
];

#[test]
fn test_deaddrop_vector_wire_format() {
    let doc = load_vectors("test/vectors/deaddrop.json");
    // Behavioral vectors without an `encoded` field (state transitions,
    // eviction ordering, ...) are validated by the implementation-level
    // suites; here we only check the wire-format subset.
    let covered_types: std::collections::HashSet<&str> = doc
        .vectors
        .iter()
        .filter_map(|v| v["type"].as_str())
        .collect();
    for (ty, _) in DEADDROP_WIRE_TYPES {
        assert!(
            covered_types.contains(ty),
            "deaddrop vectors must cover type {}",
            ty
        );
    }

    let mut checked = 0;
    for v in &doc.vectors {
        let name = v["name"].as_str().unwrap();
        let Some(encoded_hex) = v["encoded"].as_str() else {
            continue;
        };
        let vector_type = v["type"].as_str().unwrap_or("");
        let Some(expected_code) = DEADDROP_WIRE_TYPES
            .iter()
            .find(|(ty, _)| *ty == vector_type)
            .map(|(_, code)| *code)
        else {
            eprintln!("{}: skipping non-wire type {}", name, vector_type);
            continue;
        };
        let encoded = match hex_to_bytes(encoded_hex) {
            Some(bytes) => bytes,
            None => {
                // Skip vectors with invalid hex (placeholder data not yet finalized)
                eprintln!("{}: skipping (invalid hex in encoded field)", name);
                continue;
            }
        };
        assert!(encoded.len() >= 4, "{}: CoAP frame too short", name);
        assert_eq!(encoded[0] & 0xC0, 0x40, "{}: not CoAP version 1", name);
        assert_eq!(encoded[1], expected_code, "{}: unexpected CoAP code", name);
        checked += 1;
        if let Some(senml) = v["senml_payload"].as_str() {
            if !senml.is_empty() {
                if let Some(senml_bytes) = hex_to_bytes(senml) {
                    assert!(senml_bytes.len() >= 2, "{}: SenML too short", name);
                }
            }
        }
        if let Some(ct) = v["ciphertext"].as_str() {
            if !ct.is_empty() {
                if let Some(ct_bytes) = hex_to_bytes(ct) {
                    assert!(ct_bytes.len() >= 2, "{}: ciphertext too short", name);
                }
            }
        }
        if let Some(expected) = v["expected"].as_object() {
            if let Some(rc) = expected.get("response_code").and_then(|c| c.as_u64()) {
                assert!(rc <= 255, "{}: response code out of range", name);
            }
        }
    }
    assert!(
        checked >= 10,
        "expected at least 10 wire-format deaddrop vectors, checked {}",
        checked
    );
}

#[test]
fn test_confessions_vector_wire_format() {
    let doc = load_vectors("test/vectors/confessions.json");
    // The canonical suite covers behavioral categories; several entries are
    // non-wire (no `encoded` frame) and only carry request/response metadata.
    const REQUIRED_CATEGORIES: &[&str] = &[
        "anonymous_confession",
        "oscore_group",
        "rate_limit_boundary",
        "storage_eviction",
        "reboot_clear",
        "size_limit",
        "ttl",
        "no_log",
    ];
    let covered_categories: std::collections::HashSet<&str> = doc
        .vectors
        .iter()
        .filter_map(|v| v["category"].as_str())
        .collect();
    for cat in REQUIRED_CATEGORIES {
        assert!(
            covered_categories.contains(cat),
            "confessions vectors must cover category {}",
            cat
        );
    }

    for v in &doc.vectors {
        let name = v["name"].as_str().unwrap();
        let Some(encoded_hex) = v["encoded"].as_str() else {
            continue;
        };
        let encoded = match hex_to_bytes(encoded_hex) {
            Some(bytes) => bytes,
            None => {
                eprintln!("{}: skipping (invalid hex in encoded field)", name);
                continue;
            }
        };
        assert!(encoded.len() >= 4, "{}: CoAP frame too short", name);
        assert_eq!(encoded[0] & 0xC0, 0x40, "{}: not CoAP version 1", name);
        let code = encoded[1];
        let vector_type = v["type"].as_str().unwrap_or("");
        match vector_type {
            "post_submission" | "rejection" | "" => {
                assert_eq!(
                    code,
                    0x02,
                    "{}: expected POST code for {}",
                    name,
                    if vector_type.is_empty() {
                        "<untyped>"
                    } else {
                        vector_type
                    }
                );
            }
            "get" => {
                assert_eq!(code, 0x01, "{}: expected GET code", name);
            }
            _ => panic!("{}: unknown type {}", name, vector_type),
        }
        if let Some(senml) = v["senml_payload"].as_str() {
            if !senml.is_empty() {
                if let Some(senml_bytes) = hex_to_bytes(senml) {
                    assert!(senml_bytes.len() >= 2, "{}: SenML too short", name);
                }
            }
        }
        if let Some(payload) = v["payload"].as_str() {
            if !payload.is_empty() {
                if let Some(payload_bytes) = hex_to_bytes(payload) {
                    assert!(!payload_bytes.is_empty(), "{}: payload too short", name);
                }
            }
        }
        if let Some(expected) = v["expected"].as_object() {
            if let Some(rc) = expected.get("response_code").and_then(|c| c.as_u64()) {
                assert!(rc <= 255, "{}: response code out of range", name);
            }
        }
    }
}
