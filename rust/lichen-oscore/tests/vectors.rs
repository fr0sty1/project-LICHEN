// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Tests using RFC 8613 test vectors from test/vectors/oscore.json

use lichen_oscore::{
    validate_option, Context, ContextId, ContextStoreError, OscoreError, SenderSequenceState,
    SenderStateStore,
};

struct TestStore(SenderSequenceState);

impl TestStore {
    fn existing(sequence: u64) -> Self {
        Self(SenderSequenceState {
            next_sequence: sequence,
            exhausted: false,
        })
    }
}

impl SenderStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load(
        &mut self,
        _context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(Some(self.0))
    }

    fn compare_exchange(
        &mut self,
        _context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if Some(self.0) != expected {
            return Ok(false);
        }
        self.0 = next;
        Ok(true)
    }
}
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
    request_piv: Option<String>,
    #[serde(default)]
    request_kid: Option<String>,
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
    oscore_option: Option<String>,
    ciphertext: Option<String>,
    is_replay: Option<bool>,
    new_highest: Option<u32>,
    new_window: Option<u32>,
}

fn context_at(
    master_secret: &[u8; 16],
    master_salt: Option<&[u8]>,
    id_context: Option<&[u8]>,
    sender_id: &[u8],
    recipient_id: &[u8],
    sequence: u64,
) -> (Context, TestStore) {
    let mut store = TestStore::existing(sequence);
    let context = Context::load_existing(
        master_secret,
        master_salt,
        id_context,
        sender_id,
        recipient_id,
        &mut store,
    )
    .unwrap();
    (context, store)
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

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "roundtrip")
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

        // Create sender context
        let (mut sender_ctx, mut store) = context_at(
            &master_secret,
            master_salt.as_deref(),
            None,
            &sender_id,
            &recipient_id,
            u64::from(v.sender_seq.unwrap_or(0)),
        );

        // Create recipient context (swapped IDs)
        let (mut recipient_ctx, _) = context_at(
            &master_secret,
            master_salt.as_deref(),
            None,
            &recipient_id,
            &sender_id,
            0,
        );

        // Get plaintext
        let pt = v.plaintext.as_ref().unwrap();
        let payload = hex_to_bytes(&pt.payload);

        // Protect request
        let (ciphertext, oscore_opt) = sender_ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(pt.code, &[], &payload)
            .unwrap_or_else(|_| panic!("protect_request failed for {}", v.name));

        // Unprotect request
        let (dec_code, _dec_options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .unwrap_or_else(|_| panic!("unprotect_request failed for {}", v.name));

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

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "invalid")
    {
        if v.expected_error.as_deref() == Some("invalid_param")
            && v.sender_id.as_ref().map(|s| s.len()).unwrap_or(0) > 14
        {
            let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
            let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
            let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

            let result = Context::load_existing(
                &master_secret,
                None,
                None,
                &sender_id,
                &recipient_id,
                &mut TestStore::existing(0),
            );
            assert!(
                matches!(
                    result,
                    Err(ContextStoreError::Oscore(OscoreError::InvalidParam))
                ),
                "Expected InvalidParam for {}, got {:?}",
                v.name,
                result
            );
        }
    }
}

#[test]
fn test_sender_id_too_long() {
    // IDs longer than 7 bytes should be rejected (nonce capacity)
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8]; // 8 bytes - too long

    let result = Context::load_existing(
        &master_secret,
        None,
        None,
        &too_long_id,
        &[1],
        &mut TestStore::existing(0),
    );
    assert!(
        matches!(
            result,
            Err(ContextStoreError::Oscore(OscoreError::InvalidParam))
        ),
        "Expected InvalidParam for 8-byte sender_id"
    );
}

#[test]
fn test_recipient_id_too_long() {
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8];

    let result = Context::load_existing(
        &master_secret,
        None,
        None,
        &[0],
        &too_long_id,
        &mut TestStore::existing(0),
    );
    assert!(
        matches!(
            result,
            Err(ContextStoreError::Oscore(OscoreError::InvalidParam))
        ),
        "Expected InvalidParam for 8-byte recipient_id"
    );
}

#[test]
fn present_empty_id_context_is_distinct_and_encoded() {
    let secret = [0u8; 16];
    let (absent, _) = context_at(&secret, None, None, &[0], &[1], 0);
    let (mut present, mut store) = context_at(&secret, None, Some(&[]), &[0], &[1], 0);

    assert_ne!(absent.context_id(), present.context_id());
    let (_, option) = present
        .reserve_sender(&mut store)
        .unwrap()
        .protect_request(0x01, &[], &[])
        .unwrap();
    assert_eq!(option.as_slice(), &[0x19, 0x00, 0x00, 0x00]);
}

#[test]
fn id_context_over_implementation_capacity_is_rejected() {
    let result = Context::load_existing(
        &[0u8; 16],
        None,
        Some(&[0; 9]),
        &[0],
        &[1],
        &mut TestStore::existing(0),
    );
    assert!(matches!(
        result,
        Err(ContextStoreError::Oscore(OscoreError::InvalidParam))
    ));
}

#[test]
fn malformed_oscore_options_are_rejected_without_keys() {
    for option in [
        &b"\x20"[..],
        &b"\x02\x01"[..],
        &b"\x02\x00\x01"[..],
        &b"\x10"[..],
        &b"\x19\x01\x09\x00"[..],
        &b"\x09\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08"[..],
    ] {
        assert_eq!(validate_option(option), Err(OscoreError::InvalidParam));
    }

    assert_eq!(validate_option(b"\x09\x01\x00"), Ok(()));
}

#[test]
fn test_request_protection_vectors() {
    for vector in load_vectors()
        .vectors
        .into_iter()
        .filter(|vector| vector.vector_type == "request_protection")
    {
        let master_secret = hex_to_array(vector.master_secret.as_ref().unwrap());
        let master_salt = vector.master_salt.as_ref().map(|value| hex_to_bytes(value));
        let id_context = vector.id_context.as_ref().map(|value| hex_to_bytes(value));
        let sender_id = hex_to_bytes(vector.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(vector.recipient_id.as_ref().unwrap());
        let plaintext = vector.plaintext.as_ref().unwrap();
        let (expected_option, expected_ciphertext) = match vector.name.as_str() {
            "rfc8613_c4_request_protection" => (
                hex_to_bytes("0914"),
                hex_to_bytes("612f1092f1776f1c1668b3825e"),
            ),
            "rfc8613_c5_request_protection_no_salt" => (
                hex_to_bytes("091400"),
                hex_to_bytes("4ed339a5a379b0b8bc731fffb0"),
            ),
            "rfc8613_c6_request_protection_with_id_context" => (
                hex_to_bytes("19140837cbf3210017a2d3"),
                hex_to_bytes("72cd7273fd331ac45cffbe55c3"),
            ),
            _ => panic!("missing independent expected values for {}", vector.name),
        };
        let (mut context, mut store) = context_at(
            &master_secret,
            master_salt.as_deref(),
            id_context.as_deref(),
            &sender_id,
            &recipient_id,
            u64::from(vector.sender_seq.unwrap()),
        );

        let (ciphertext, option) = context
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(
                plaintext.code,
                &hex_to_bytes("b3747631"),
                &hex_to_bytes(&plaintext.payload),
            )
            .unwrap();

        assert_eq!(
            option.as_slice(),
            expected_option,
            "OSCORE option mismatch for {}",
            vector.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            expected_ciphertext,
            "ciphertext mismatch for {}",
            vector.name
        );
    }
}

#[test]
fn test_response_protection_vectors() {
    for vector in load_vectors()
        .vectors
        .into_iter()
        .filter(|vector| vector.vector_type == "response_protection")
    {
        let master_secret = hex_to_array(vector.master_secret.as_ref().unwrap());
        let master_salt = vector.master_salt.as_ref().map(|value| hex_to_bytes(value));
        let responder_id = hex_to_bytes(vector.sender_id.as_ref().unwrap());
        let requester_id = hex_to_bytes(vector.request_kid.as_ref().unwrap());
        let request_piv = hex_to_bytes(vector.request_piv.as_ref().unwrap());
        let plaintext = vector.plaintext.as_ref().unwrap();
        let (expected_option, expected_ciphertext) = match vector.name.as_str() {
            "rfc8613_c7_response_protection" => (
                hex_to_bytes(""),
                hex_to_bytes("dbaad1e9a7e7b2a813d3c31524378303cdafae119106"),
            ),
            "rfc8613_c8_response_with_partial_iv" => (
                hex_to_bytes("0100"),
                hex_to_bytes("4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"),
            ),
            _ => panic!("missing independent expected values for {}", vector.name),
        };
        let (mut requester, _) = context_at(
            &master_secret,
            master_salt.as_deref(),
            None,
            &requester_id,
            &responder_id,
            0,
        );

        let (code, options, payload) = requester
            .unprotect_response(&expected_option, &expected_ciphertext, &request_piv)
            .unwrap_or_else(|_| panic!("unprotect_response failed for {}", vector.name));

        assert_eq!(code, plaintext.code, "code mismatch for {}", vector.name);
        assert_eq!(
            options.as_slice(),
            hex_to_bytes(&plaintext.options),
            "options mismatch for {}",
            vector.name
        );
        assert_eq!(
            payload.as_slice(),
            hex_to_bytes(&plaintext.payload),
            "payload mismatch for {}",
            vector.name
        );
    }
}
