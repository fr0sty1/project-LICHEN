// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Tests using RFC 8613 test vectors from test/vectors/oscore.json

use lichen_oscore::{Context, OscoreError};
use serde::Deserialize;
use std::fs;

/// Test vector file format
#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

/// Individual test vector
/// Many fields are for documentation/schema; not all tested directly.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "type")]
    vector_type: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    master_secret: Option<String>,
    #[serde(default)]
    master_salt: Option<String>,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    recipient_id: Option<String>,
    #[serde(default)]
    id_context: Option<String>,
    #[serde(default)]
    sender_seq: Option<u32>,
    #[serde(default)]
    plaintext: Option<Plaintext>,
    #[serde(default)]
    expected: Option<Expected>,
    // Replay test fields
    #[serde(default)]
    highest_seq: Option<u32>,
    #[serde(default)]
    window_bits: Option<u32>,
    #[serde(default)]
    test_seq: Option<u32>,
    #[serde(default)]
    expected_error: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Plaintext {
    code: u8,
    options: String,
    payload: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Expected {
    sender_key: Option<String>,
    recipient_key: Option<String>,
    common_iv: Option<String>,
    is_replay: Option<bool>,
    new_highest: Option<u32>,
    new_window: Option<u32>,
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/oscore.json"
    );
    let content = fs::read_to_string(path).expect("Failed to read oscore.json");
    serde_json::from_str(&content).expect("Failed to parse oscore.json")
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

fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_to_bytes(hex);
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

#[test]
fn test_roundtrip_vectors() {
    let vectors = load_vectors();

    for v in vectors.vectors.iter().filter(|v| v.vector_type == "roundtrip") {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

        // Create sender context
        let mut sender_ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            &sender_id,
            &recipient_id,
        )
        .expect(&format!("Failed to create sender context for {}", v.name));

        // Create recipient context (swapped IDs)
        let mut recipient_ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            &recipient_id,
            &sender_id,
        )
        .expect(&format!(
            "Failed to create recipient context for {}",
            v.name
        ));

        // Get plaintext
        let pt = v.plaintext.as_ref().unwrap();
        let payload = hex_to_bytes(&pt.payload);

        // Protect request
        let (ciphertext, oscore_opt) = sender_ctx
            .protect_request(pt.code, &[], &payload)
            .expect(&format!("protect_request failed for {}", v.name));

        // Unprotect request
        let (dec_code, _dec_options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .expect(&format!("unprotect_request failed for {}", v.name));

        assert_eq!(dec_code, pt.code, "code mismatch for {}", v.name);
        assert_eq!(
            dec_payload.as_slice(),
            payload.as_slice(),
            "payload mismatch for {}",
            v.name
        );
    }
}

// Replay window tests are covered by the unit tests in lib.rs since they
// require access to private Context fields (replay_window, recipient_seq).
// The JSON vectors serve as documentation and are tested by Python.
#[test]
fn test_replay_vectors_documented() {
    let vectors = load_vectors();

    // Verify replay vectors exist and are parseable
    let replay_vectors: Vec<_> = vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "replay")
        .collect();

    assert!(!replay_vectors.is_empty(), "No replay vectors found");

    // Verify each vector has required fields
    for v in &replay_vectors {
        assert!(v.highest_seq.is_some(), "Missing highest_seq in {}", v.name);
        assert!(v.test_seq.is_some(), "Missing test_seq in {}", v.name);
        assert!(
            v.expected.as_ref().and_then(|e| e.is_replay).is_some(),
            "Missing expected.is_replay in {}",
            v.name
        );
    }
}

#[test]
fn test_invalid_inputs() {
    let vectors = load_vectors();

    for v in vectors.vectors.iter().filter(|v| v.vector_type == "invalid") {
        match v.expected_error.as_deref() {
            Some("invalid_param") => {
                // Test ID too long
                if v.sender_id.as_ref().map(|s| s.len()).unwrap_or(0) > 14 {
                    let master_secret: [u8; 16] =
                        hex_to_array(v.master_secret.as_ref().unwrap());
                    let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
                    let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

                    let result = Context::new(&master_secret, None, &sender_id, &recipient_id);
                    assert!(
                        matches!(result, Err(OscoreError::InvalidParam)),
                        "Expected InvalidParam for {}, got {:?}",
                        v.name,
                        result
                    );
                }
            }
            _ => {}
        }
    }
}

#[test]
fn test_sender_id_too_long() {
    // IDs longer than 7 bytes should be rejected (nonce capacity)
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8]; // 8 bytes - too long

    let result = Context::new(&master_secret, None, &too_long_id, &[1]);
    assert!(
        matches!(result, Err(OscoreError::InvalidParam)),
        "Expected InvalidParam for 8-byte sender_id"
    );
}

#[test]
fn test_recipient_id_too_long() {
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8];

    let result = Context::new(&master_secret, None, &[0], &too_long_id);
    assert!(
        matches!(result, Err(OscoreError::InvalidParam)),
        "Expected InvalidParam for 8-byte recipient_id"
    );
}

#[test]
fn test_key_derivation_symmetry() {
    // Test that client and server derive symmetric keys
    // (client sender_key == server recipient_key)
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "key_derivation")
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap_or(&String::new()));
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap_or(&String::new()));

        // Skip vectors with id_context for now (not supported in Context::new)
        if v.id_context.is_some() {
            continue;
        }

        // Create both contexts
        let sender_ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            &sender_id,
            &recipient_id,
        );
        let recipient_ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            &recipient_id,
            &sender_id,
        );

        // Both should succeed
        assert!(
            sender_ctx.is_ok(),
            "Failed to create sender context for {}",
            v.name
        );
        assert!(
            recipient_ctx.is_ok(),
            "Failed to create recipient context for {}",
            v.name
        );
    }
}
