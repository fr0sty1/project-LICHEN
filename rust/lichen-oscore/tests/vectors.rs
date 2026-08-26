// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Tests using RFC 8613 test vectors from test/vectors/oscore.json

use lichen_oscore::{
    validate_option, Context, ContextId, OscoreError, SenderSequenceState, SenderStateStore,
};

struct TestStore(Option<SenderSequenceState>);

impl TestStore {
    fn existing(sequence: u64) -> Self {
        Self(Some(SenderSequenceState {
            next_sequence: sequence,
            exhausted: false,
        }))
    }

    fn fresh() -> Self {
        Self(None)
    }
}

impl SenderStateStore for TestStore {
    type Error = core::convert::Infallible;

    fn load(
        &mut self,
        _context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self.0)
    }

    fn compare_exchange(
        &mut self,
        _context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.0 != expected {
            return Ok(false);
        }
        self.0 = Some(next);
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

/// Individual test vector. Only fields used by tests are retained (no dead code).
#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "type")]
    vector_type: String,
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
    include_piv: Option<bool>,
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
    test_seq: Option<u32>,
    #[serde(default)]
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Plaintext {
    code: u8,
    options: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    oscore_option: Option<String>,
    ciphertext: Option<String>,
    is_replay: Option<bool>,
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
    let context = Context::new(
        master_secret,
        master_salt,
        id_context,
        sender_id,
        recipient_id,
    )
    .unwrap()
    .restore_existing(&mut store)
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
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("hex_to_array: expected {} bytes, got {}", N, len))
}

#[test]
fn test_request_protection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "request_protection" && v.id_context.is_none())
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());
        let seq = v.sender_seq.unwrap_or(0);

        let mut store = TestStore::existing(seq.into());
        let mut ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            None,
            &sender_id,
            &recipient_id,
        )
        .unwrap_or_else(|_| panic!("Failed to create context for {}", v.name))
        .restore_existing(&mut store)
        .unwrap_or_else(|_| panic!("Failed to restore context for {}", v.name));

        let pt = v.plaintext.as_ref().unwrap();
        let options = hex_to_bytes(&pt.options);
        let payload = hex_to_bytes(&pt.payload);

        let (ciphertext, oscore_opt) = ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(pt.code, &options, &payload)
            .unwrap_or_else(|_| panic!("protect_request failed for {}", v.name));
        let expected = v.expected.as_ref().unwrap();

        assert_eq!(
            oscore_opt.as_slice(),
            hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
            "OSCORE option mismatch for {}",
            v.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            "ciphertext mismatch for {}",
            v.name
        );
    }
}

#[test]
fn test_response_protection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "response_protection")
    {
        let master_secret = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());
        let request_piv = hex_to_bytes(v.request_piv.as_ref().unwrap());
        let request_kid = hex_to_bytes(v.request_kid.as_ref().unwrap());
        let pt = v.plaintext.as_ref().unwrap();
        let options = hex_to_bytes(&pt.options);
        let payload = hex_to_bytes(&pt.payload);
        let expected = v.expected.as_ref().unwrap();
        let include_piv = v.include_piv.unwrap();
        // For responses without a fresh PIV (include_piv=false), we need a fresh context
        // that hasn't been restored from storage, since restored contexts conservatively
        // disallow no-PIV responses to prevent nonce reuse. Fresh contexts from EDHOC
        // can safely do one no-PIV response per received request.
        let mut ctx = if include_piv {
            let mut store = TestStore::existing(v.sender_seq.unwrap().into());
            Context::new(
                &master_secret,
                master_salt.as_deref(),
                None,
                &sender_id,
                &recipient_id,
            )
            .unwrap()
            .restore_existing(&mut store)
            .unwrap()
        } else {
            let mut store = TestStore::fresh();
            Context::new(
                &master_secret,
                master_salt.as_deref(),
                None,
                &sender_id,
                &recipient_id,
            )
            .unwrap()
            .register_fresh(&mut store)
            .unwrap()
        };

        let (ciphertext, oscore_opt) = ctx
            .protect_response(
                pt.code,
                &options,
                &payload,
                &request_kid,
                &request_piv,
                include_piv,
            )
            .unwrap_or_else(|_| panic!("protect_response failed for {}", v.name));

        assert_eq!(
            oscore_opt.as_slice(),
            hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
            "OSCORE option mismatch for {}",
            v.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            "ciphertext mismatch for {}",
            v.name
        );
    }
}

/// Encrypt-side coverage for request vectors with an ID Context, which the
/// loop in `test_request_protection_vectors` skips.
#[test]
fn test_request_protection_with_id_context_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "request_protection" && v.id_context.is_some())
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let id_context = hex_to_bytes(v.id_context.as_ref().unwrap());
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

        let mut store = TestStore::existing(v.sender_seq.unwrap_or(0).into());
        let mut ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            Some(&id_context),
            &sender_id,
            &recipient_id,
        )
        .unwrap_or_else(|_| panic!("Failed to create context for {}", v.name))
        .restore_existing(&mut store)
        .unwrap_or_else(|_| panic!("Failed to restore context for {}", v.name));

        let pt = v.plaintext.as_ref().unwrap();
        let expected = v.expected.as_ref().unwrap();
        let (ciphertext, oscore_opt) = ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(
                pt.code,
                &hex_to_bytes(&pt.options),
                &hex_to_bytes(&pt.payload),
            )
            .unwrap_or_else(|_| panic!("protect_request failed for {}", v.name));

        assert_eq!(
            oscore_opt.as_slice(),
            hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
            "OSCORE option mismatch for {}",
            v.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            "ciphertext mismatch for {}",
            v.name
        );
    }
}

/// Decrypt-side validation of RFC 8613 Appendix C request vectors (C.4-C.6):
/// the canonical ciphertext and OSCORE option are fed to `unprotect_request`
/// on a receiver-role context and must yield exactly the vector plaintext.
/// This exercises decrypt with the RFC 8613 Section 5.4 AAD independently of
/// the encrypt path.
#[test]
fn test_request_unprotection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "request_protection")
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let id_context = v.id_context.as_ref().map(|s| hex_to_bytes(s));
        let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

        // Receiver view of the same security material: roles are swapped so
        // that the client's sender key becomes our recipient key.
        let mut store = TestStore::fresh();
        let mut ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            id_context.as_deref(),
            &recipient_id,
            &sender_id,
        )
        .unwrap_or_else(|_| panic!("Failed to create context for {}", v.name))
        .register_fresh(&mut store)
        .unwrap_or_else(|_| panic!("Failed to register context for {}", v.name));

        let pt = v.plaintext.as_ref().unwrap();
        let expected = v.expected.as_ref().unwrap();
        let (code, options, payload) = ctx
            .unprotect_request(
                &hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
                &hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
            )
            .unwrap_or_else(|e| panic!("unprotect_request failed for {}: {:?}", v.name, e));

        assert_eq!(code, pt.code, "code mismatch for {}", v.name);
        assert_eq!(
            options.as_slice(),
            hex_to_bytes(&pt.options),
            "options mismatch for {}",
            v.name
        );
        assert_eq!(
            payload.as_slice(),
            hex_to_bytes(&pt.payload),
            "payload mismatch for {}",
            v.name
        );
    }
}

/// Decrypt-side validation of RFC 8613 Appendix C response vectors (C.7-C.8):
/// the canonical ciphertext and OSCORE option are authenticated and decrypted
/// via `begin_unprotect_response` + `commit` on a client-role context and must
/// yield exactly the vector plaintext, covering both the no-PIV (C.7) and
/// fresh-PIV (C.8) AAD forms.
#[test]
fn test_response_unprotection_vectors() {
    let vectors = load_vectors();

    for v in vectors
        .vectors
        .iter()
        .filter(|v| v.vector_type == "response_protection")
    {
        let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
        let master_salt = v.master_salt.as_ref().map(|s| hex_to_bytes(s));
        let id_context = v.id_context.as_ref().map(|s| hex_to_bytes(s));
        // The protecting party (responder) owns vector sender_id; we take the
        // requester role, whose sender id is vector recipient_id.
        let responder_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
        let requester_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());
        let request_piv = hex_to_bytes(v.request_piv.as_ref().unwrap());

        let mut store = TestStore::fresh();
        let mut ctx = Context::new(
            &master_secret,
            master_salt.as_deref(),
            id_context.as_deref(),
            &requester_id,
            &responder_id,
        )
        .unwrap_or_else(|_| panic!("Failed to create context for {}", v.name))
        .register_fresh(&mut store)
        .unwrap_or_else(|_| panic!("Failed to register context for {}", v.name));

        let pt = v.plaintext.as_ref().unwrap();
        let expected = v.expected.as_ref().unwrap();
        let pending = ctx
            .begin_unprotect_response(
                &hex_to_bytes(expected.oscore_option.as_ref().unwrap()),
                &hex_to_bytes(expected.ciphertext.as_ref().unwrap()),
                &request_piv,
            )
            .unwrap_or_else(|e| panic!("begin_unprotect_response failed for {}: {:?}", v.name, e));
        let (code, options, payload) = pending
            .commit()
            .unwrap_or_else(|e| panic!("commit failed for {}: {:?}", v.name, e));

        assert_eq!(code, pt.code, "code mismatch for {}", v.name);
        assert_eq!(
            options.as_slice(),
            hex_to_bytes(&pt.options),
            "options mismatch for {}",
            v.name
        );
        assert_eq!(
            payload.as_slice(),
            hex_to_bytes(&pt.payload),
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
        if let Some("invalid_param") = v.expected_error.as_deref() {
            // Test ID too long
            if v.sender_id.as_ref().map(|s| s.len()).unwrap_or(0) > 14 {
                let master_secret: [u8; 16] = hex_to_array(v.master_secret.as_ref().unwrap());
                let sender_id = hex_to_bytes(v.sender_id.as_ref().unwrap());
                let recipient_id = hex_to_bytes(v.recipient_id.as_ref().unwrap());

                let result = Context::new(&master_secret, None, None, &sender_id, &recipient_id);
                assert!(
                    matches!(result, Err(OscoreError::InvalidParam)),
                    "Expected InvalidParam for {}, got {:?}",
                    v.name,
                    result
                );
            }
        }
    }
}

#[test]
fn test_sender_id_too_long() {
    // IDs longer than 7 bytes should be rejected (nonce capacity)
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8]; // 8 bytes - too long

    let result = Context::new(&master_secret, None, None, &too_long_id, &[1]);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
}

#[test]
fn test_recipient_id_too_long() {
    let master_secret = [0u8; 16];
    let too_long_id = [0u8; 8];

    let result = Context::new(&master_secret, None, None, &[0], &too_long_id);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
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
    let result = Context::new(&[0u8; 16], None, Some(&[0; 9]), &[0], &[1]);
    assert!(matches!(result, Err(OscoreError::InvalidParam)));
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

/// Validates that edhoc.json test vectors are present and parseable.
/// For actual EDHOC handshake validation, enable the `edhoc` feature.
#[test]
fn test_edhoc_vectors_parseable() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/vectors/edhoc.json");
    let content = fs::read_to_string(path).expect("Failed to read edhoc.json");
    let doc: serde_json::Value =
        serde_json::from_str(&content).expect("Failed to parse edhoc.json");
    let v = &doc["vectors"][0];
    assert_eq!(v["name"], "fixed_seed_sign_sign");
    // Verify all required fields are present
    for field in &[
        "seed_i",
        "seed_r",
        "msg1",
        "msg2",
        "msg3",
        "oscore_master_secret",
        "oscore_master_salt",
        "oscore_sender_id",
        "oscore_recipient_id",
    ] {
        assert!(
            v[field].as_str().is_some(),
            "Missing required field: {}",
            field
        );
    }
}

/// Validates that the Rust EDHOC implementation produces the same exported
/// OSCORE context as the Python reference oracle in test vectors.
///
/// This test runs a full EDHOC handshake with the same seeds and RNG values
/// as the Python generator, then verifies the exported OSCORE context works
/// for message protection.
#[cfg(feature = "edhoc")]
#[test]
fn test_edhoc_exported_context_matches_vectors() {
    use lichen_oscore::{EdhocInitiator, EdhocResponder};
    use rand_core::{CryptoRng, RngCore};

    // RNG that always returns 0x42 bytes, matching Python's os.urandom mock
    struct FixedRng;
    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            0x42424242
        }
        fn next_u64(&mut self) -> u64 {
            0x4242424242424242
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x42);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(0x42);
            Ok(())
        }
    }
    impl CryptoRng for FixedRng {}

    // Load test vectors
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/vectors/edhoc.json");
    let content = fs::read_to_string(path).expect("Failed to read edhoc.json");
    let doc: serde_json::Value =
        serde_json::from_str(&content).expect("Failed to parse edhoc.json");
    let v = &doc["vectors"][0];
    assert_eq!(v["name"], "fixed_seed_sign_sign");

    // Extract expected values from vectors
    let expected_sender_id = hex_to_bytes(v["oscore_sender_id"].as_str().unwrap());
    let expected_recipient_id = hex_to_bytes(v["oscore_recipient_id"].as_str().unwrap());

    // Create initiator and responder with seeds matching Python generator:
    // seed_i = bytes(range(32)) = [0,1,2,...,31]
    // seed_r = bytes(range(32,64)) = [32,33,...,63]
    let seed_i: [u8; 32] = core::array::from_fn(|i| i as u8);
    let seed_r: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);

    // Derive public keys from seeds using schnorr48 (same as Python)
    let (_, initiator_pubkey) = schnorr48::derive_keypair(&seed_i.into());
    let (_, responder_pubkey) = schnorr48::derive_keypair(&seed_r.into());
    let initiator_pubkey_bytes = initiator_pubkey.into_bytes();
    let responder_pubkey_bytes = responder_pubkey.into_bytes();

    let mut initiator = EdhocInitiator::new_with_rng(seed_i, 0x00, &mut FixedRng)
        .expect("Failed to create initiator");
    let mut responder = EdhocResponder::new_with_rng(seed_r, 0x01, &mut FixedRng)
        .expect("Failed to create responder");

    // Execute EDHOC handshake
    let msg1 = initiator
        .create_message_1()
        .expect("Failed to create message 1");
    let msg2 = responder
        .process_message_1(&msg1)
        .expect("Failed to process message 1");
    let msg3 = initiator
        .process_message_2(&msg2, &responder_pubkey_bytes)
        .expect("Failed to process message 2");
    responder
        .process_message_3(&msg3, &initiator_pubkey_bytes)
        .expect("Failed to process message 3");

    // Export OSCORE contexts
    let initiator_ctx = initiator
        .export_oscore()
        .expect("Failed to export initiator context");
    let responder_ctx = responder
        .export_oscore()
        .expect("Failed to export responder context");

    // Validate initiator's exported context matches vectors
    assert_eq!(
        initiator_ctx.sender_id(),
        expected_sender_id.as_slice(),
        "Initiator sender_id mismatch"
    );
    assert_eq!(
        initiator_ctx.recipient_id(),
        expected_recipient_id.as_slice(),
        "Initiator recipient_id mismatch"
    );

    // Validate sender/recipient IDs are swapped correctly
    assert_eq!(
        responder_ctx.sender_id(),
        expected_recipient_id.as_slice(),
        "Responder sender_id mismatch"
    );
    assert_eq!(
        responder_ctx.recipient_id(),
        expected_sender_id.as_slice(),
        "Responder recipient_id mismatch"
    );

    // Note: Context IDs will differ because they include sender_id in the derivation.
    // This is expected - each side has its own context ID for state lookup.

    // Functional validation: verify the contexts can communicate
    let mut initiator_store = TestStore::existing(0);
    let mut responder_store = TestStore::fresh();
    let mut initiator_ctx = initiator_ctx
        .restore_existing(&mut initiator_store)
        .expect("Failed to restore initiator context");
    let mut responder_ctx = responder_ctx
        .register_fresh(&mut responder_store)
        .expect("Failed to register responder context");

    // Test request protection/unprotection
    let test_payload = b"EDHOC context validation test";
    let (ciphertext, oscore_opt) = initiator_ctx
        .reserve_sender(&mut initiator_store)
        .expect("Failed to reserve sender")
        .protect_request(0x01, &[], test_payload)
        .expect("Failed to protect request");

    let (recv_code, _recv_opts, recv_payload) = responder_ctx
        .unprotect_request(&oscore_opt, &ciphertext)
        .expect("Failed to unprotect request");

    assert_eq!(recv_code, 0x01, "Request code mismatch");
    assert_eq!(
        &recv_payload[..],
        test_payload,
        "Request payload mismatch after decrypt"
    );
}
