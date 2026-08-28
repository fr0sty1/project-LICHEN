// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-validation of the Dead Drop domain model against shared vectors.
//!
//! Vectors in `test/vectors/deaddrop.json` are derived independently of both
//! implementations (RFC 7252 / RFC 8613 / RFC 8428). Two vector pins are
//! known-divergent from spec 18.9 and the Python oracle; see beads
//! project-LICHEN-worker6-44m9 (human decision pending):
//!
//! * `rate_limit_rejection` pins 163 (5.03); spec 18.9 mandates 4.29 with
//!   `Retry-After` for rate limits (the Python oracle returns 157). The
//!   implementation follows the spec.
//! * post-success vectors pin 69 (2.05); spec 18.9/LCI 17.5.8 mandate
//!   2.01 Created (65) with `Location-Path` (the Python oracle returns
//!   CREATED). The implementation follows spec + Python.
//!
//! Several `senml_payload` hex strings are malformed CBOR (short length
//! headers); where so, the `senml_payload_decoded` / `recipient` / `ttl`
//! fields are the normative form (the Python oracle does the same).

use std::sync::Arc;

use lichen_client::deaddrop::{
    code, is_drop_id, AddDropParams, DeadDropStore, DropFilter, GetResponse, PickupOutcome,
    PostOutcome, PostRequest, SenmlRecord, DEFAULT_TTL, MAX_DROP_SIZE, MAX_TTL, POSTS_PER_HOUR,
    STORAGE_BR, STORAGE_LEAF,
};
use serde_json::Value;
use std::fs;

fn load_vectors() -> Vec<Value> {
    let json_str = fs::read_to_string("../../test/vectors/deaddrop.json")
        .expect("failed to read deaddrop.json");
    let data: Value = serde_json::from_str(&json_str).expect("failed to parse JSON");
    data["vectors"].as_array().cloned().expect("vectors array")
}

fn vec_by_name<'a>(vectors: &'a [Value], name: &str) -> &'a Value {
    let matches: Vec<&Value> = vectors.iter().filter(|v| v["name"] == *name).collect();
    assert_eq!(matches.len(), 1, "unique vector {name}");
    matches[0]
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.replace("deaddrop", "6465616464726f70");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Deterministic test clock (Unix seconds).
#[derive(Clone)]
struct TestClock {
    t: Arc<std::sync::Mutex<f64>>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            t: Arc::new(std::sync::Mutex::new(1_700_000_000.0)),
        }
    }

    fn clock(&self) -> lichen_client::deaddrop::Clock {
        let t = self.t.clone();
        Arc::new(move || *t.lock().unwrap())
    }

    fn advance(&self, seconds: f64) {
        *self.t.lock().unwrap() += seconds;
    }
}

fn store(limit: usize, clock: &TestClock) -> DeadDropStore {
    DeadDropStore::with_clock(limit, clock.clock()).expect("valid storage limit")
}

fn post(
    s: &mut DeadDropStore,
    identity: Option<&str>,
    oscore_option: Option<&[u8]>,
    body: Vec<u8>,
) -> PostOutcome {
    s.post(&PostRequest {
        body,
        identity: identity.map(str::to_owned),
        oscore_option: oscore_option.map(<[u8]>::to_vec),
    })
}

fn senml_body(records: &[SenmlRecord]) -> Vec<u8> {
    lichen_client::deaddrop::encode_senml_pack(records).expect("encode")
}

fn pending_for(s: &mut DeadDropStore, node: &str) -> usize {
    s.drops(
        None,
        &DropFilter {
            node: Some(node),
            ..Default::default()
        },
    )
    .len()
}

// ---------------------------------------------------------------------------
// Spec 18.9 constants (pinned by the Python oracle's TestSpecConstants)
// ---------------------------------------------------------------------------

#[test]
fn spec_limits_match_python_reference() {
    assert_eq!(POSTS_PER_HOUR, 6);
    assert_eq!(MAX_DROP_SIZE, 1536);
    assert_eq!(STORAGE_LEAF, 8 * 1024);
    assert_eq!(STORAGE_BR, 32 * 1024);
    assert_eq!(DEFAULT_TTL, 24 * 3600);
    assert_eq!(MAX_TTL, 7 * 24 * 3600);
}

#[test]
fn drop_ids_are_canonical_six_hex() {
    assert!(is_drop_id("7f3a9c"));
    assert!(is_drop_id("ffffff"));
    assert!(!is_drop_id("7F3A9C")); // uppercase rejected
    assert!(!is_drop_id("7f3a9"));
    assert!(!is_drop_id("7f3a9cc"));
    assert!(!is_drop_id("+fffff"));
}

// ---------------------------------------------------------------------------
// Wire-format pre-check: every vector's `encoded` frame is CoAP v1 with the
// expected request code for its type (same check as lichen-coap/tests).
// ---------------------------------------------------------------------------

#[test]
fn encoded_frames_are_coap_v1_with_expected_request_code() {
    const TYPES: &[(&str, u8)] = &[
        ("post_submission", 0x02),
        ("oscore_wrapped", 0x02),
        ("rejection", 0x02),
        ("pickup", 0x01),
        ("observe", 0x01),
        ("state_transition", 0x02),
    ];
    let vectors = load_vectors();
    let mut checked = 0;
    for v in &vectors {
        let Some(encoded_hex) = v["encoded"].as_str() else {
            continue;
        };
        let name = v["name"].as_str().unwrap();
        let vtype = v["type"].as_str().unwrap_or("");
        let Some(&want) = TYPES.iter().find(|(ty, _)| *ty == vtype).map(|(_, c)| c) else {
            panic!("{name}: unclassified wire type {vtype:?}");
        };
        let encoded = hex_to_bytes(encoded_hex);
        assert!(encoded.len() >= 4, "{name}: frame too short");
        assert_eq!(encoded[0] & 0xC0, 0x40, "{name}: not CoAP version 1");
        assert_eq!(encoded[1], want, "{name}: unexpected request code");
        checked += 1;
    }
    assert!(
        checked >= 15,
        "expected >=15 wire vectors, checked {checked}"
    );
}

// ---------------------------------------------------------------------------
// Per-vector behavioral validation
// ---------------------------------------------------------------------------

#[test]
fn post_submission_basic_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "post_submission_basic");

    // The vector's SenML payload hex decodes to [{n:"temp", u:"Cel", v:23.5}]
    // (independently verified with an external CBOR decoder).
    let records = lichen_client::deaddrop::decode_senml_pack(&hex_to_bytes(
        v["senml_payload"].as_str().unwrap(),
    ))
    .expect("vector senml_payload is valid CBOR");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name.as_deref(), Some("temp"));
    assert_eq!(records[0].unit.as_deref(), Some("Cel"));
    assert_eq!(records[0].value, Some(23.5));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut submitted = records.clone();
    submitted.push(SenmlRecord::text(
        "recipient",
        v["recipient"].as_str().unwrap(),
    ));
    let option = hex_to_bytes(v["expected"]["oscore_option"].as_str().unwrap());
    let outcome = post(
        &mut s,
        Some("ctx-poster"),
        Some(&option),
        senml_body(&submitted),
    );
    // Divergence: vector pins 69 (2.05); spec 18.9 says 2.01 Created (65).
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(69));
    let PostOutcome::Created {
        drop_id,
        location_path,
        max_age,
    } = &outcome
    else {
        panic!(
            "Created expected (spec 2.01; vector 69 divergence, bead \
                project-LICHEN-worker6-44m9): {outcome:?}"
        );
    };
    assert!(is_drop_id(drop_id));
    assert!(location_path.starts_with("/deaddrop/"));
    assert_eq!(*max_age, 86400);
    // num_pending 0: nothing is addressed to the poster's own identity.
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
    assert_eq!(pending_for(&mut s, "ctx-poster"), 0);
    assert_eq!(pending_for(&mut s, "node1234"), 1);
}

#[test]
fn post_submission_string_payload_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "post_submission_string_payload");

    // JSON-style string-name SenML decodes (RFC 8428 extension tolerance).
    let records = lichen_client::deaddrop::decode_senml_pack(&hex_to_bytes(
        v["senml_payload"].as_str().unwrap(),
    ))
    .expect("string-keyed pack decodes");
    assert_eq!(records[0].name.as_deref(), Some("content"));
    assert_eq!(records[0].string_value.as_deref(), Some("alert"));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut submitted = records.clone();
    submitted.push(SenmlRecord::text(
        "recipient",
        v["recipient"].as_str().unwrap(),
    ));
    let option = hex_to_bytes(v["expected"]["oscore_option"].as_str().unwrap());
    let outcome = post(&mut s, Some("ctx-b"), Some(&option), senml_body(&submitted));
    assert!(
        matches!(outcome, PostOutcome::Created { .. }),
        "Created (spec 2.01; vector pins 69, divergence bead \
         project-LICHEN-worker6-44m9): {outcome:?}"
    );
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
    assert_eq!(pending_for(&mut s, "ctx-b"), 0);
    assert_eq!(pending_for(&mut s, "msg-node"), 1);
}

#[test]
fn pickup_with_pending_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "pickup_with_pending");
    assert_eq!(
        v["encoded"].as_str().unwrap(),
        "4101000301b86465616464726f704b6e6f64653d616263313233",
        "GET /deaddrop?node=abc123"
    );

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    for i in 0..v["expected"]["num_pending"].as_u64().unwrap() {
        let drop_id = format!("aa000{i}");
        assert!(s
            .add_drop(
                &[SenmlRecord::text("content", &format!("pending-{i}"))],
                "sender",
                &AddDropParams {
                    drop_id: Some(drop_id),
                    recipient: Some("abc123".into()),
                    ..Default::default()
                },
            )
            .is_some());
    }
    let response = s
        .render_get(
            None,
            &DropFilter {
                node: Some("abc123"),
                ..Default::default()
            },
            false,
        )
        .expect("listing encodes");
    assert_eq!(response.content_format, 112);
    assert_eq!(pending_for(&mut s, "abc123"), 2);
    assert_eq!(code::CONTENT, 69);
    let listing =
        lichen_client::deaddrop::decode_senml_pack(&response.payload).expect("listing decodes");
    assert!(listing
        .iter()
        .any(|r| r.name.as_deref() == Some("content")
            && r.string_value.as_deref() == Some("pending-0")));
}

#[test]
fn oscore_wrapped_dead_drop_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "oscore_wrapped_dead_drop");

    let records = lichen_client::deaddrop::decode_senml_pack(&hex_to_bytes(
        v["senml_payload"].as_str().unwrap(),
    ))
    .expect("vector senml_payload decodes");
    assert_eq!(records[0].name.as_deref(), Some("deaddrop"));
    assert_eq!(records[0].value, Some(1.0));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut submitted = records.clone();
    submitted.push(SenmlRecord::text(
        "recipient",
        v["recipient"].as_str().unwrap(),
    ));
    let option = hex_to_bytes(v["expected"]["oscore_option"].as_str().unwrap());
    let outcome = post(
        &mut s,
        Some("ctx-0910"),
        Some(&option),
        senml_body(&submitted),
    );
    assert!(
        matches!(outcome, PostOutcome::Created { .. }),
        "{outcome:?}"
    );
    assert_eq!(v["expected"]["oscore_option"].as_str(), Some("0910"));
}

#[test]
fn rate_limit_rejection_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "rate_limit_rejection");
    // Divergence: vector pins 163 (5.03); spec 18.9 mandates 4.29 (157) with
    // Retry-After for rate limits, which is what the Python oracle emits and
    // what this implementation returns. Bead project-LICHEN-worker6-44m9.
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(163));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let body = senml_body(&[SenmlRecord::text("content", "flood")]);
    for i in 0..POSTS_PER_HOUR {
        clock.advance(1.0);
        let outcome = post(&mut s, Some("flooder123"), None, body.clone());
        assert!(
            matches!(outcome, PostOutcome::Created { .. }),
            "post {i} should succeed: {outcome:?}"
        );
    }
    clock.advance(1.0);
    let outcome = post(&mut s, Some("flooder123"), None, body.clone());
    match &outcome {
        PostOutcome::TooManyRequests { retry_after } => {
            assert!(*retry_after >= 1);
            assert_eq!(outcome.response_code(), 157); // 4.29 per spec 18.9
        }
        other => panic!("expected rate limit rejection, got {other:?}"),
    }
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
    assert_eq!(pending_for(&mut s, "flooder123"), 0);

    // A different OSCORE context is not limited by the first.
    let other = post(&mut s, Some("ctx-b"), None, body);
    assert!(matches!(other, PostOutcome::Created { .. }));
}

#[test]
fn oscore_e2e_roundtrip_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "oscore_e2e_post_pickup_roundtrip");
    assert_eq!(
        v["expected"]["oscore_option"].as_str(),
        Some("091400"),
        "RFC 8613 C.5 context (sender 0x00, recipient 0x01, seq 20)"
    );

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut records = vec![SenmlRecord::text("content", "for-bob")];
    records.push(SenmlRecord {
        name: Some("ttl".into()),
        value: Some(v["ttl"].as_f64().unwrap()),
        ..Default::default()
    });
    records.push(SenmlRecord::text(
        "recipient",
        v["recipient"].as_str().unwrap(),
    ));
    let option = hex_to_bytes(v["oscore_option"].as_str().unwrap());
    let outcome = post(&mut s, Some("alice"), Some(&option), senml_body(&records));
    let PostOutcome::Created { max_age, .. } = &outcome else {
        panic!("alice's post should be Created: {outcome:?}");
    };
    assert_eq!(*max_age, 7200, "effective ttl from the vector");

    // Bob picks up: num_pending 1 for his address.
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(1));
    let bob_view = s.drops(
        None,
        &DropFilter {
            node: Some(v["recipient"].as_str().unwrap()),
            ..Default::default()
        },
    );
    assert_eq!(bob_view.len(), 1);
    assert_eq!(
        bob_view[0].recipient.as_deref(),
        Some("eui-0102030405060708")
    );
}

#[test]
fn oscore_recipient_mismatch_is_unauthorized() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "oscore_e2e_recipient_mismatch");
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(129)); // 4.01

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    // OSCORE option present but no context matches -> no post-unprotect
    // identity -> 4.01 (option presence is not authentication).
    let option = hex_to_bytes(v["oscore_option"].as_str().unwrap());
    let outcome = post(&mut s, None, Some(&option), vec![1, 2, 3]);
    assert_eq!(outcome, PostOutcome::Unauthorized);
    assert_eq!(outcome.response_code(), 129);
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
    assert_eq!(pending_for(&mut s, "eui-0000000000000000"), 0);
}

#[test]
fn empty_ciphertext_with_context_is_bad_request() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "oscore_e2e_post_empty_ciphertext");
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(128)); // 4.00

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let outcome = post(
        &mut s,
        Some("eui-0102030405060708"),
        Some(&hex_to_bytes(v["oscore_option"].as_str().unwrap())),
        Vec::new(),
    );
    assert_eq!(outcome, PostOutcome::BadRequest);
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
}

#[test]
fn ttl_expired_pickup_returns_empty_content() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "deaddrop_ttl_expired_pickup");

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    // ttl: 0 in the vector -> immediate expiry, zero retention.
    assert_eq!(v["ttl"].as_u64(), Some(0));
    assert!(s
        .add_drop(
            &[SenmlRecord::text("content", "stale")],
            "ctx-a",
            &AddDropParams {
                ttl: Some(0),
                drop_id: Some("010203".into()),
                recipient: Some(v["recipient"].as_str().unwrap().to_owned()),
                ..Default::default()
            },
        )
        .is_some());

    let response = s
        .render_get(
            None,
            &DropFilter {
                node: Some(v["recipient"].as_str().unwrap()),
                ..Default::default()
            },
            false,
        )
        .expect("listing encodes");
    // GET still succeeds (2.05) with an empty listing; 0 pending.
    assert_eq!(response.content_format, 112);
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(69));
    assert_eq!(code::CONTENT, 69);
    assert_eq!(v["expected"]["num_pending"].as_u64(), Some(0));
    assert_eq!(pending_for(&mut s, "eui-0102030405060708"), 0);
    let listing =
        lichen_client::deaddrop::decode_senml_pack(&response.payload).expect("empty pack decodes");
    assert!(listing.is_empty(), "expired drop omitted: {listing:?}");
}

#[test]
fn request_entity_too_large_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "request_entity_too_large");
    assert_eq!(v["payload_size"].as_u64(), Some(2048));
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(141)); // 4.13
    assert_eq!(
        v["expected"]["error_type"].as_str(),
        Some("request_entity_too_large")
    );

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    // Size gate fires before decode (mirrors the Python reference order).
    let outcome = post(
        &mut s,
        Some("node-large"),
        None,
        vec![0u8; v["payload_size"].as_u64().unwrap() as usize],
    );
    assert_eq!(outcome, PostOutcome::EntityTooLarge);
    assert_eq!(outcome.response_code(), 141);
}

#[test]
fn storage_full_rejection_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "storage_full_rejection");
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(163)); // 5.03
    assert_eq!(
        v["expected"]["cbor_payload"]["reason"].as_str(),
        Some("storage_full")
    );
    assert_eq!(
        v["expected"]["cbor_payload"]["retry_after"].as_u64(),
        Some(3600)
    );

    let small = [SenmlRecord::text("content", "block")];
    let size = senml_body(&small).len();
    let clock = TestClock::new();
    let mut s = store(size, &clock);
    let first = s.add_drop(&small, "ctx-a", &AddDropParams::default());
    assert!(first.is_some(), "first drop fills the budget");

    let bigger = [SenmlRecord::text(
        "content",
        &format!("block{}", "!".repeat(16)),
    )];
    assert!(senml_body(&bigger).len() > size, "bigger than the budget");
    let outcome = post(&mut s, Some("ctx-b"), None, senml_body(&bigger));
    match &outcome {
        PostOutcome::ServiceUnavailable {
            retry_after,
            available_kb,
        } => {
            assert_eq!(*retry_after, 3600);
            assert_eq!(outcome.response_code(), 163);
            assert!(*available_kb >= 0.0);
        }
        other => panic!("expected storage full 5.03, got {other:?}"),
    }
    // The in-flight drop never wiped the store.
    assert_eq!(s.storage_info().drop_count, 1);
}

#[test]
fn ttl_clamped_to_max_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "ttl_clamped_to_max");
    assert_eq!(v["ttl"].as_u64(), Some(1_209_600));
    assert_eq!(v["expected"]["effective_ttl"].as_u64(), Some(604_800));
    assert_eq!(v["expected"]["max_age"].as_u64(), Some(604_800));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let records = vec![
        SenmlRecord {
            name: Some("ttl".into()),
            value: Some(v["ttl"].as_f64().unwrap()),
            ..Default::default()
        },
        SenmlRecord::text("content", "long"),
    ];
    let outcome = post(&mut s, Some("ctx-ttl"), None, senml_body(&records));
    let PostOutcome::Created { max_age, .. } = &outcome else {
        panic!("Created expected: {outcome:?}");
    };
    assert_eq!(*max_age, 604_800);
    assert_eq!(*max_age, MAX_TTL);
    assert_eq!(*max_age, v["expected"]["effective_ttl"].as_u64().unwrap());
}

#[test]
fn canonical_senml_payload_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "canonical_senml_payload");
    assert_eq!(
        v["expected"]["location_path_prefix"].as_str(),
        Some("/deaddrop/")
    );

    // Build the pack from the normative `senml_payload_decoded` list.
    let mut records = Vec::new();
    for item in v["senml_payload_decoded"].as_array().unwrap() {
        let mut record = SenmlRecord::default();
        if let Some(bn) = item["bn"].as_str() {
            record.base_name = Some(bn.to_owned());
        }
        if let Some(bt) = item["bt"].as_f64() {
            record.base_time = Some(bt);
        }
        if let Some(n) = item["n"].as_str() {
            record.name = Some(n.to_owned());
        }
        if let Some(u) = item["u"].as_str() {
            record.unit = Some(u.to_owned());
        }
        if let Some(v) = item["v"].as_f64() {
            record.value = Some(v);
        }
        if let Some(vs) = item["vs"].as_str() {
            record.string_value = Some(vs.to_owned());
        }
        records.push(record);
    }
    assert_eq!(records.len(), 7);
    assert_eq!(
        records[0].base_name.as_deref(),
        Some("urn:dev:mac:0011223344556677:")
    );
    assert_eq!(records[0].base_time, Some(1_721_654_321.0));

    // Round-trip: my encoder output decodes back to the same records.
    let encoded = senml_body(&records);
    assert_eq!(
        lichen_client::deaddrop::decode_senml_pack(&encoded).unwrap(),
        records,
        "encode/decode round-trip preserves the canonical pack"
    );

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let outcome = post(&mut s, Some("eui-0011223344556677"), None, encoded);
    let PostOutcome::Created {
        location_path,
        max_age,
        ..
    } = &outcome
    else {
        panic!("Created expected: {outcome:?}");
    };
    assert!(location_path.starts_with(v["expected"]["location_path_prefix"].as_str().unwrap()));
    assert_eq!(*max_age, 86400, "ttl record 86400 honored");

    // The pickup listing carries the canonical content.
    let listing = s.drops(None, &DropFilter::default());
    assert_eq!(listing.len(), 1);
    assert_eq!(
        listing[0]
            .records
            .iter()
            .find(|r| r.name.as_deref() == Some("content"))
            .and_then(|r| r.string_value.as_deref()),
        Some("Supply cache at these coords - do not broadcast")
    );
    assert_eq!(
        listing[0]
            .records
            .iter()
            .find(|r| r.name.as_deref() == Some("lat"))
            .and_then(|r| r.value),
        Some(37.7749)
    );

    // The vector's own senml_payload hex is malformed CBOR (short text
    // length headers); it must not decode to the intended pack.
    let raw = lichen_client::deaddrop::decode_senml_pack(&hex_to_bytes(
        v["senml_payload"].as_str().unwrap(),
    ));
    assert!(
        raw.is_err() || raw.unwrap() != records,
        "malformed vector hex must not round-trip to the canonical pack"
    );
}

#[test]
fn oscore_group_context_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "oscore_group_context");
    assert_eq!(v["expected"]["oscore_option"].as_str(), Some("19100001"));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut records = vec![SenmlRecord::text("group-msg", "test-123")];
    records.push(SenmlRecord::text(
        "recipient",
        v["recipient"].as_str().unwrap(),
    ));
    let option = hex_to_bytes(v["oscore_option"].as_str().unwrap());
    let outcome = post(
        &mut s,
        Some(v["group_context_id"].as_str().unwrap()),
        Some(&option),
        senml_body(&records),
    );
    assert!(
        matches!(outcome, PostOutcome::Created { .. }),
        "group context post created (spec 2.01; vector pins 69, divergence \
         bead project-LICHEN-worker6-44m9): {outcome:?}"
    );
    assert_eq!(v["ttl"].as_u64(), Some(43_200));
}

#[test]
fn get_single_drop_by_id_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "get_single_drop_by_id");
    assert_eq!(v["drop_id"].as_str(), Some("7f3a9c"));
    assert_eq!(v["expected"]["content_format"].as_u64(), Some(112));
    assert_eq!(v["expected"]["has_max_age"].as_bool(), Some(true));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let drop_id = s
        .add_drop(
            &[SenmlRecord::text("content", "single")],
            "ctx-a",
            &AddDropParams {
                drop_id: Some(v["drop_id"].as_str().unwrap().to_owned()),
                recipient: Some(v["recipient"].as_str().unwrap().to_owned()),
                ..Default::default()
            },
        )
        .expect("drop created");
    assert_eq!(drop_id, "7f3a9c");

    let outcome = s.get_by_id("7f3a9c", None);
    match &outcome {
        PickupOutcome::Content {
            payload,
            content_format,
            max_age,
        } => {
            assert_eq!(*content_format, 112);
            assert!(max_age.is_some(), "remaining TTL reported");
            let got = lichen_client::deaddrop::decode_senml_pack(payload).unwrap();
            assert_eq!(got, vec![SenmlRecord::text("content", "single")]);
        }
        other => panic!("expected Content, got {other:?}"),
    }
    assert_eq!(outcome.response_code(), 69); // 2.05 Content
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(69));
}

#[test]
fn get_nonexistent_drop_id_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "get_nonexistent_drop_id");
    assert_eq!(v["drop_id"].as_str(), Some("ffffff"));
    assert_eq!(v["expected"]["response_code"].as_u64(), Some(132)); // 4.04

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let outcome = s.get_by_id("ffffff", None);
    assert_eq!(outcome, PickupOutcome::NotFound);
    assert_eq!(outcome.response_code(), 132);
}

#[test]
fn eviction_fifo_order_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "eviction_fifo_order");
    assert_eq!(v["expected"]["evicted"].as_str(), Some("drop-001"));
    assert_eq!(
        v["expected"]["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["drop-002", "drop-003"]
    );
    let storage_limit = v["storage_limit"].as_u64().unwrap() as usize; // 256
    let new_drop_size = v["new_drop_size"].as_u64().unwrap() as usize; // 128

    // Craft deterministic drop sizes: a packed {n:"content", vs:"x"*N} with
    // 24 <= N <= 255 is 14 + N bytes (array + 2-entry map + 7-char name +
    // 2-byte vs header), so N=50 -> 64 B for each initial drop and N=114 ->
    // 128 B for the incoming drop.
    let drop_record =
        |n: usize| -> Vec<SenmlRecord> { vec![SenmlRecord::text("content", &"x".repeat(n - 14))] };
    assert_eq!(senml_body(&drop_record(64)).len(), 64);
    assert_eq!(senml_body(&drop_record(128)).len(), 128);
    assert!(new_drop_size == 128 && storage_limit == 256);

    let clock = TestClock::new();
    let mut s = store(storage_limit, &clock);
    // ids 647261..647263 stand in for the vector's drop-001..drop-003.
    for id in ["647261", "647262", "647263"] {
        clock.advance(1.0);
        assert_eq!(
            s.add_drop(
                &drop_record(64),
                "ctx-a",
                &AddDropParams {
                    drop_id: Some(id.into()),
                    ..Default::default()
                }
            ),
            Some(id.to_owned())
        );
    }
    clock.advance(1.0);
    let outcome = post(
        &mut s,
        Some("ctx-a"),
        None,
        senml_body(&drop_record(new_drop_size)),
    );
    assert!(
        matches!(outcome, PostOutcome::Created { .. }),
        "new drop accepted after FIFO eviction: {outcome:?}"
    );
    let ids: Vec<String> = s
        .drops(None, &DropFilter::default())
        .into_iter()
        .map(|d| d.id)
        .collect();
    // Vector "remaining" maps to the surviving initial drops; the incoming
    // drop is also present (mirrors the Python oracle's aa0004 outcome).
    let PostOutcome::Created {
        drop_id: new_id, ..
    } = &outcome
    else {
        panic!();
    };
    assert_eq!(
        ids,
        vec!["647262", "647263", new_id],
        "oldest evicted first"
    );
    assert_eq!(s.storage_info().drop_count, 3);
}

#[test]
fn observe_notification_matches_vector() {
    let vectors = load_vectors();
    let v = vec_by_name(&vectors, "observe_notification");
    assert_eq!(v["observe_option"].as_u64(), Some(0));
    assert_eq!(v["expected"]["has_observe_option"].as_bool(), Some(true));
    assert_eq!(v["expected"]["content_format"].as_u64(), Some(112));

    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let before = s.observe_version();
    let initial: GetResponse = s
        .render_get(None, &DropFilter::default(), true)
        .expect("listing encodes");
    assert_eq!(initial.content_format, 112);
    assert_eq!(initial.observe, Some(before));

    // A new drop bumps the Observe state version -> notification fires.
    assert!(s
        .add_drop(
            &[SenmlRecord::text("content", "hello")],
            "ctx-a",
            &AddDropParams {
                drop_id: Some("aa0001".into()),
                recipient: Some(v["recipient"].as_str().unwrap().to_owned()),
                ..Default::default()
            },
        )
        .is_some());
    let notification = s
        .render_get(None, &DropFilter::default(), true)
        .expect("listing encodes");
    assert_eq!(notification.content_format, 112, "vector ct=112");
    assert_eq!(notification.observe, Some(before + 1), "Observe option set");
    let listing = lichen_client::deaddrop::decode_senml_pack(&notification.payload).unwrap();
    assert!(listing.iter().any(
        |r| r.name.as_deref() == Some("content") && r.string_value.as_deref() == Some("hello")
    ));
}

// ---------------------------------------------------------------------------
// Privacy ACL (spec 18.9), exercised through the vector resource semantics
// ---------------------------------------------------------------------------

#[test]
fn private_and_group_acl_fail_closed() {
    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let private_id = s
        .add_drop(
            &[SenmlRecord::text("content", "alice-only")],
            "alice",
            &AddDropParams {
                drop_id: Some("aa0001".into()),
                privacy: lichen_client::Privacy::Private,
                ..Default::default()
            },
        )
        .unwrap();
    let group_id = s
        .add_drop(
            &[SenmlRecord::text("content", "group-msg")],
            "group-a",
            &AddDropParams {
                drop_id: Some("aa0002".into()),
                privacy: lichen_client::Privacy::Group,
                recipient: Some("bob".into()),
                ..Default::default()
            },
        )
        .unwrap();

    // Anonymous listing sees nothing private.
    assert!(s.drops(None, &DropFilter::default()).is_empty());
    // Creator sees their private drop; stranger gets 4.04 (hidden existence).
    assert!(matches!(
        s.get_by_id(&private_id, Some("alice")),
        PickupOutcome::Content { .. }
    ));
    assert_eq!(
        s.get_by_id(&private_id, Some("eve")),
        PickupOutcome::NotFound
    );
    assert_eq!(s.get_by_id(&private_id, None), PickupOutcome::NotFound);
    // Group: creator or designated recipient allowed; others 4.03.
    assert!(matches!(
        s.get_by_id(&group_id, Some("group-a")),
        PickupOutcome::Content { .. }
    ));
    assert!(matches!(
        s.get_by_id(&group_id, Some("bob")),
        PickupOutcome::Content { .. }
    ));
    assert_eq!(
        s.get_by_id(&group_id, Some("eve")),
        PickupOutcome::Forbidden
    );
}

#[test]
fn generated_drop_ids_are_canonical_and_unique() {
    let clock = TestClock::new();
    let mut s = store(STORAGE_LEAF, &clock);
    let mut ids = Vec::new();
    for i in 0..16 {
        let drop_id = s
            .add_drop(
                &[SenmlRecord::text("content", &format!("m-{i}"))],
                "ctx-a",
                &AddDropParams::default(),
            )
            .expect("generated ID accepted");
        assert!(is_drop_id(&drop_id), "canonical 6-hex: {drop_id}");
        ids.push(drop_id);
    }
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "store rejects duplicate IDs, so minted IDs are unique: {ids:?}"
    );
}

#[test]
fn internal_error_outcome_maps_to_500() {
    let outcome = PickupOutcome::InternalError;
    assert_eq!(outcome.response_code(), code::INTERNAL_SERVER_ERROR);
    assert_eq!(code::INTERNAL_SERVER_ERROR, 160); // 5.00
}

#[test]
fn add_drop_doomed_explicit_id_preserves_live_drops() {
    let small = [SenmlRecord::text("content", "live")];
    let size = senml_body(&small).len();
    let clock = TestClock::new();
    // Budget fits exactly one drop: any admission requires eviction.
    let mut s = store(size, &clock);
    assert_eq!(
        s.add_drop(
            &small,
            "ctx-a",
            &AddDropParams {
                drop_id: Some("aa0001".into()),
                ..Default::default()
            },
        ),
        Some("aa0001".to_owned()),
        "store filled to capacity"
    );

    // A rejected create (invalid hex / duplicate ID) must not evict the
    // live drop to make room it will never use.
    assert_eq!(
        s.add_drop(
            &small,
            "ctx-b",
            &AddDropParams {
                drop_id: Some("nothex".into()),
                ..Default::default()
            },
        ),
        None,
        "non-canonical explicit ID rejected"
    );
    assert_eq!(
        s.add_drop(
            &small,
            "ctx-b",
            &AddDropParams {
                drop_id: Some("AA0001".into()),
                ..Default::default()
            },
        ),
        None,
        "uppercase explicit ID rejected"
    );
    assert_eq!(
        s.add_drop(
            &small,
            "ctx-b",
            &AddDropParams {
                drop_id: Some("aa0001".into()),
                ..Default::default()
            },
        ),
        None,
        "duplicate explicit ID rejected"
    );
    assert_eq!(
        s.storage_info().drop_count,
        1,
        "doomed requests destroyed no live drops"
    );
    assert!(matches!(
        s.get_by_id("aa0001", None),
        PickupOutcome::Content { .. }
    ));

    // Eviction itself still works for an admissible request.
    clock.advance(1.0);
    assert_eq!(
        s.add_drop(
            &small,
            "ctx-b",
            &AddDropParams {
                drop_id: Some("aa0002".into()),
                ..Default::default()
            },
        ),
        Some("aa0002".to_owned())
    );
    assert_eq!(s.storage_info().drop_count, 1, "FIFO evicted the oldest");
    assert!(matches!(
        s.get_by_id("aa0002", None),
        PickupOutcome::Content { .. }
    ));
}
