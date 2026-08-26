// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-implementation ciphertext parity tests (Python <-> Rust).
//!
//! The committed fixture `test/vectors/oscore_cross_exchange.json` holds, for
//! every exchange derived deterministically from `test/vectors/oscore.json`
//! (roundtrip vectors plus synthesized responses over the same contexts),
//! the protected output produced by each implementation independently:
//!
//! - `python_protected`: output of python/src/lichen/crypto/oscore.py
//! - `rust_protected`:   output of this crate
//!
//! Regenerate the fixture with `test/vectors/generate_oscore_cross.py`.
//! The RFC 8613 Appendix C vectors remain the external correctness oracle;
//! this file proves the two implementations agree BYTE FOR BYTE with each
//! other and can decrypt each other's output (both directions).

use lichen_oscore::{Context, ContextId, OscoreError, SenderSequenceState, SenderStateStore};
use serde::Deserialize;
use std::fs;

struct TestStore(Option<SenderSequenceState>);

impl TestStore {
    fn existing(sequence: u64) -> Self {
        Self(Some(SenderSequenceState {
            next_sequence: sequence,
            exhausted: false,
        }))
    }

    fn default_empty() -> Self {
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

fn fixture_path() -> String {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/oscore_cross_exchange.json"
    )
    .to_string()
}

fn load_fixture() -> ExchangeFile {
    let content = fs::read_to_string(fixture_path())
        .expect("missing test/vectors/oscore_cross_exchange.json; run test/vectors/generate_oscore_cross.py");
    serde_json::from_str(&content).expect("failed to parse oscore_cross_exchange.json")
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

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02X}", b);
    }
    out
}

fn hex_to_array16(hex: &str) -> [u8; 16] {
    hex_to_bytes(hex)
        .try_into()
        .expect("master_secret must be 16 bytes")
}

/// Optional salt/id-context as the Context API expects.
fn opt_hex(hex: &Option<String>) -> Option<Vec<u8>> {
    hex.as_ref()
        .filter(|h| !h.is_empty())
        .map(|h| hex_to_bytes(h))
}

/// Minimal big-endian Partial IV encoding (>= 1 byte), shared by both
/// implementations per RFC 8613 Section 5.2.
fn minimal_piv(seq: u64) -> Vec<u8> {
    if seq == 0 {
        return vec![0x00];
    }
    let len = (u64::BITS - seq.leading_zeros()).div_ceil(8);
    seq.to_be_bytes()[((8 - len) as usize)..].to_vec()
}

#[derive(Debug, Deserialize)]
struct Protected {
    oscore_option: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct Plaintext {
    code: u8,
    options: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct RequestExchange {
    name: String,
    master_secret: String,
    master_salt: Option<String>,
    sender_id: String,
    recipient_id: String,
    id_context: Option<String>,
    sender_seq: u64,
    plaintext: Plaintext,
    python_protected: Protected,
    rust_protected: Protected,
}

#[derive(Debug, Deserialize)]
struct ResponseExchange {
    name: String,
    master_secret: String,
    master_salt: Option<String>,
    sender_id: String,
    recipient_id: String,
    id_context: Option<String>,
    request_kid: String,
    request_piv: String,
    include_piv: bool,
    responder_sender_seq: u64,
    plaintext: Plaintext,
    python_protected: Protected,
    rust_protected: Protected,
}

#[derive(Debug, Deserialize)]
struct ExchangeFile {
    requests: Vec<RequestExchange>,
    responses: Vec<ResponseExchange>,
}

/// Build a context with explicit roles.
///
/// `fresh=true` registers a never-sent context in an empty store (required
/// for no-PIV responses, and its sender sequence starts at 0); otherwise the
/// context is restored at `sender_seq`.
fn build_context(
    master_secret: &str,
    master_salt: &Option<String>,
    id_context: &Option<String>,
    sender_id: &str,
    recipient_id: &str,
    sender_seq: u64,
    fresh: bool,
) -> Context {
    let secret = hex_to_array16(master_secret);
    let salt = opt_hex(master_salt);
    let idc = opt_hex(id_context);
    let built = Context::new(
        &secret,
        salt.as_deref(),
        idc.as_deref(),
        &hex_to_bytes(sender_id),
        &hex_to_bytes(recipient_id),
    )
    .expect("context creation failed");
    if fresh {
        built
            .register_fresh(&mut TestStore::default_empty())
            .expect("register_fresh failed")
    } else {
        built
            .restore_existing(&mut TestStore::existing(sender_seq))
            .expect("restore failed")
    }
}

#[test]
fn rust_request_output_is_byte_identical_to_python() {
    let fixture = load_fixture();
    assert!(
        !fixture.requests.is_empty(),
        "fixture has no request exchanges"
    );

    for ex in &fixture.requests {
        // Sender role protects the request.
        let mut ctx = build_context(
            &ex.master_secret,
            &ex.master_salt,
            &ex.id_context,
            &ex.sender_id,
            &ex.recipient_id,
            ex.sender_seq,
            false,
        );
        let mut store = TestStore::existing(ex.sender_seq);
        let (ct, opt) = ctx
            .reserve_sender(&mut store)
            .unwrap_or_else(|e| panic!("{}: reserve_sender failed: {:?}", ex.name, e))
            .protect_request(
                ex.plaintext.code,
                &hex_to_bytes(&ex.plaintext.options),
                &hex_to_bytes(&ex.plaintext.payload),
            )
            .unwrap_or_else(|e| panic!("{}: protect_request failed: {:?}", ex.name, e));

        assert_eq!(
            opt.as_slice(),
            hex_to_bytes(&ex.python_protected.oscore_option),
            "{}: OSCORE option diverges from Python",
            ex.name
        );
        assert_eq!(
            ct.as_slice(),
            hex_to_bytes(&ex.python_protected.ciphertext),
            "{}: ciphertext diverges from Python",
            ex.name
        );
        assert_eq!(
            ct.as_slice(),
            hex_to_bytes(&ex.rust_protected.ciphertext),
            "{}: ciphertext drifted from committed rust_protected",
            ex.name
        );
    }
}

#[test]
fn rust_decrypts_python_protected_requests() {
    let fixture = load_fixture();

    for ex in &fixture.requests {
        // Receiver role: IDs swapped.
        let mut ctx = build_context(
            &ex.master_secret,
            &ex.master_salt,
            &ex.id_context,
            &ex.recipient_id,
            &ex.sender_id,
            0,
            false,
        );
        let (code, options, payload) = ctx
            .unprotect_request(
                &hex_to_bytes(&ex.python_protected.oscore_option),
                &hex_to_bytes(&ex.python_protected.ciphertext),
            )
            .unwrap_or_else(|e| panic!("{}: unprotect_request failed: {:?}", ex.name, e));

        assert_eq!(code, ex.plaintext.code, "{}: code mismatch", ex.name);
        assert_eq!(
            options.as_slice(),
            hex_to_bytes(&ex.plaintext.options),
            "{}: options mismatch",
            ex.name
        );
        assert_eq!(
            payload.as_slice(),
            hex_to_bytes(&ex.plaintext.payload),
            "{}: payload mismatch",
            ex.name
        );

        // Replaying the identical request MUST be rejected.
        let replay = ctx.unprotect_request(
            &hex_to_bytes(&ex.python_protected.oscore_option),
            &hex_to_bytes(&ex.python_protected.ciphertext),
        );
        assert!(
            matches!(replay, Err(OscoreError::Replay)),
            "{}: duplicate request was not rejected as replay",
            ex.name
        );
    }
}

#[test]
fn rust_response_output_is_byte_identical_to_python() {
    let fixture = load_fixture();
    assert!(
        !fixture.responses.is_empty(),
        "fixture has no response exchanges"
    );

    for ex in &fixture.responses {
        // Responder role protects the response. Restored contexts conservatively
        // refuse no-PIV responses; those need a fresh registration, exactly
        // like test_response_protection_vectors.
        let mut ctx = build_context(
            &ex.master_secret,
            &ex.master_salt,
            &ex.id_context,
            &ex.recipient_id,
            &ex.sender_id,
            ex.responder_sender_seq,
            !ex.include_piv,
        );
        let (ct, opt) = ctx
            .protect_response(
                ex.plaintext.code,
                &hex_to_bytes(&ex.plaintext.options),
                &hex_to_bytes(&ex.plaintext.payload),
                &hex_to_bytes(&ex.request_kid),
                &hex_to_bytes(&ex.request_piv),
                ex.include_piv,
            )
            .unwrap_or_else(|e| panic!("{}: protect_response failed: {:?}", ex.name, e));

        assert_eq!(
            opt.as_slice(),
            hex_to_bytes(&ex.python_protected.oscore_option),
            "{}: OSCORE option diverges from Python",
            ex.name
        );
        assert_eq!(
            ct.as_slice(),
            hex_to_bytes(&ex.python_protected.ciphertext),
            "{}: ciphertext diverges from Python",
            ex.name
        );
        assert_eq!(
            ct.as_slice(),
            hex_to_bytes(&ex.rust_protected.ciphertext),
            "{}: ciphertext drifted from committed rust_protected",
            ex.name
        );
    }
}

#[test]
fn rust_decrypts_python_protected_responses() {
    let fixture = load_fixture();

    for ex in &fixture.responses {
        // Client role receives the response.
        let mut ctx = build_context(
            &ex.master_secret,
            &ex.master_salt,
            &ex.id_context,
            &ex.sender_id,
            &ex.recipient_id,
            0,
            false,
        );

        let (code, options, payload) = ctx
            .begin_unprotect_response(
                &hex_to_bytes(&ex.python_protected.oscore_option),
                &hex_to_bytes(&ex.python_protected.ciphertext),
                &hex_to_bytes(&ex.request_piv),
            )
            .unwrap_or_else(|e| panic!("{}: begin_unprotect_response failed: {:?}", ex.name, e))
            .commit()
            .unwrap_or_else(|e| panic!("{}: response commit failed: {:?}", ex.name, e));

        assert_eq!(code, ex.plaintext.code, "{}: code mismatch", ex.name);
        assert_eq!(
            options.as_slice(),
            hex_to_bytes(&ex.plaintext.options),
            "{}: options mismatch",
            ex.name
        );
        assert_eq!(
            payload.as_slice(),
            hex_to_bytes(&ex.plaintext.payload),
            "{}: payload mismatch",
            ex.name
        );
    }
}

/// Dump this implementation's protected output for every exchange so
/// `generate_oscore_cross.py` can merge it into the committed fixture.
///
/// Run: cargo test -p lichen-oscore --test cross_parity dump_rust_protected -- --ignored --nocapture
#[ignore = "generator helper: invoked by test/vectors/generate_oscore_cross.py"]
#[test]
fn dump_rust_protected() {
    // Exchanges are derived straight from the canonical source of truth so
    // generation never depends on the fixture already existing.
    let vectors_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/oscore.json"
    );
    let content = fs::read_to_string(vectors_path).expect("failed to read oscore.json");
    let doc: serde_json::Value =
        serde_json::from_str(&content).expect("failed to parse oscore.json");

    const RESPONSE_PAYLOAD_HEX: &str = "4c494348454e2063726f737320726573706f6e7365"; // b"LICHEN cross response"

    let mut requests: Vec<serde_json::Value> = Vec::new();
    let mut responses: Vec<serde_json::Value> = Vec::new();

    for v in doc["vectors"].as_array().expect("vectors array") {
        if v["type"].as_str() != Some("roundtrip") {
            continue;
        }
        let name = v["name"].as_str().expect("vector name").to_string();
        let master_secret = v["master_secret"].as_str().unwrap().to_string();
        let master_salt: Option<String> = v["master_salt"].as_str().map(str::to_string);
        let sender_id = v["sender_id"].as_str().unwrap().to_string();
        let recipient_id = v["recipient_id"].as_str().unwrap().to_string();
        let sender_seq = v["sender_seq"].as_u64().unwrap_or(0);

        // --- request protection ---
        let pt_code = v["plaintext"]["code"].as_u64().unwrap() as u8;
        let pt_options = v["plaintext"]["options"].as_str().unwrap().to_string();
        let pt_payload = v["plaintext"]["payload"].as_str().unwrap().to_string();

        let mut ctx = build_context(
            &master_secret,
            &master_salt,
            &None,
            &sender_id,
            &recipient_id,
            sender_seq,
            false,
        );
        let mut store = TestStore::existing(sender_seq);
        let (ct, opt) = ctx
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(
                pt_code,
                &hex_to_bytes(&pt_options),
                &hex_to_bytes(&pt_payload),
            )
            .unwrap();
        requests.push(serde_json::json!({
            "name": name,
            "oscore_option": to_hex(&opt),
            "ciphertext": to_hex(&ct),
        }));

        // --- synthesized responses over the same context material ---
        let request_piv = to_hex(&minimal_piv(sender_seq));

        for (suffix, include_piv) in [("response_nopiv", false), ("response_piv", true)] {
            let resp_name = format!("{name}#{suffix}");
            let resp_code: u8 = 69; // 2.05 Content

            let mut ctx = build_context(
                &master_secret,
                &master_salt,
                &None,
                &recipient_id,
                &sender_id,
                0,
                !include_piv,
            );
            let (ct, opt) = ctx
                .protect_response(
                    resp_code,
                    &[],
                    &hex_to_bytes(RESPONSE_PAYLOAD_HEX),
                    &hex_to_bytes(&sender_id),
                    &hex_to_bytes(&request_piv),
                    include_piv,
                )
                .unwrap();
            responses.push(serde_json::json!({
                "name": resp_name,
                "oscore_option": to_hex(&opt),
                "ciphertext": to_hex(&ct),
            }));
        }
    }

    println!("---BEGIN-RUST-CROSS-JSON---");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "requests": requests,
            "responses": responses,
        }))
        .unwrap()
    );
    println!("---END-RUST-CROSS-JSON---");
}
