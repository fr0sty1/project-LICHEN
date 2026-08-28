// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Conformance tests for `/confessions` driven by the committed oracle
//! `test/vectors/confessions.json` (spec 18.10).
//!
//! Only `anonymous_confession_default` carries wire bytes
//! (`senml_cbor_hex`, the repaired oracle from bead 2yps); it is pinned
//! byte-exact in both decode and re-encode directions. Every other
//! vector drives the Python-reference semantics
//! (`lichen.coap.resources.confessions`) through the same sequences its
//! `expected` block describes: payloads are built from `senml_json`,
//! posted through [`ConfessionStore`], and outcomes asserted against the
//! vector expectations.

use std::sync::{Arc, Mutex};

use ciborium::value::Value as Cbor;
use lichen_client::confessions::{
    code, is_confession_id, AddConfessionParams, ConfessionPayload, ConfessionQuery,
    ConfessionStore, RateDecision, CONFESSION_COOLDOWN_S, CONFESSION_HOURLY_MAX,
    CONFESSION_MAX_SIZE, CONFESSION_MAX_TTL, CONFESSION_STORAGE_BR, CONFESSION_STORAGE_LEAF,
    CONTENT_FORMAT_CBOR, CONTENT_FORMAT_SENML_CBOR, TTL_EXPIRED,
};
use serde_json::Value;

fn load_vectors() -> Vec<Value> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/confessions.json"
    ))
    .expect("confessions.json readable");
    let doc: Value = serde_json::from_str(&raw).expect("confessions.json is valid JSON");
    match &doc {
        Value::Array(v) => v.clone(),
        Value::Object(o) => o
            .get("vectors")
            .and_then(|v| v.as_array())
            .cloned()
            .expect("vectors array"),
        _ => panic!("unexpected confessions.json shape"),
    }
}

fn find_vector(name: &str) -> Value {
    load_vectors()
        .into_iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"))
}

fn oracle_hex(v: &Value) -> Vec<u8> {
    let hex = v["senml_cbor_hex"].as_str().expect("senml_cbor_hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
        .collect()
}

/// Thread-safe fake uptime clock (f64 seconds behind a mutex).
type FakeClock = Arc<Mutex<f64>>;

fn clock_from(cell: &FakeClock) -> Arc<dyn Fn() -> f64 + Send + Sync> {
    let cell = Arc::clone(cell);
    Arc::new(move || *cell.lock().expect("fake clock"))
}

fn clock_at(secs: f64) -> FakeClock {
    Arc::new(Mutex::new(secs))
}

const IID: &str = "0011223344556677";

// ---------------------------------------------------------------------------
// POST payload vectors.
// ---------------------------------------------------------------------------

#[test]
fn anonymous_confession_default_decodes_and_reencodes() {
    let vec = find_vector("anonymous_confession_default");
    let wire = oracle_hex(&vec);
    assert!(wire.len() <= CONFESSION_MAX_SIZE);

    let payload = ConfessionPayload::from_senml(&wire).expect("default confession decodes");
    assert_eq!(payload.claimed_iid.as_deref(), Some("0011223344556677"));
    assert_eq!(payload.base_time, Some(1721654321.0));
    assert_eq!(payload.confession_type.as_deref(), Some("confession"));
    assert!(payload
        .content
        .as_deref()
        .unwrap_or_default()
        .contains("unlocked"));
    assert_eq!(payload.lat, Some(37.7749));
    assert_eq!(payload.lon, Some(-122.4194));
    assert!(payload.anonymous, "anonymous=1 decodes true (18.10.1)");
    assert!(payload.anonymous_record_present);
    assert_eq!(payload.ttl, Some(43200.0));

    // Canonical SenML packing is byte-parity with the committed hex.
    let reencoded = payload.to_senml().expect("re-encode");
    assert_eq!(reencoded, wire, "to_senml must reproduce the oracle bytes");
}

#[test]
fn anonymous_confession_minimal_defaults() {
    let vec = find_vector("anonymous_confession_minimal");
    // No wire oracle for this vector: build from senml_json and assert
    // field-level round-trip stability.
    let payload = payload_from_senml_json(&vec["senml_json"]);
    assert_eq!(payload.claimed_iid.as_deref(), Some("aabbccddeeff0011"));
    assert_eq!(payload.base_time, Some(1721654400.0));
    assert!(payload.anonymous, "anonymous defaults true when absent");
    assert!(!payload.anonymous_record_present, "no record was carried");
    assert_eq!(payload.lat, None);
    assert_eq!(payload.lon, None);
    assert_eq!(payload.ttl, None);
    assert_eq!(payload.content.as_deref(), Some("I ate the last MRE."));
    assert_eq!(
        vec["expected"]["anonymous_default"], true,
        "vector pins the anonymous default"
    );
    let wire = payload.to_senml().expect("encode");
    let round = ConfessionPayload::from_senml(&wire).expect("re-decode own encoding");
    assert_eq!(round, payload, "encode/decode round-trip is stable");
}

#[test]
fn non_anonymous_confession_carries_sender_policy() {
    let vec = find_vector("non_anonymous_confession");
    // 18.10.1: implementations MAY accept (2.01) or reject (4.03); this
    // implementation accepts (the vector lists both as valid outcomes).
    let payload = payload_from_senml_json(&vec["senml_json"]);
    assert!(!payload.anonymous);
    assert_eq!(payload.sender.as_deref(), Some("0011223344556677"));
    let wire = payload.to_senml().expect("encode");
    let round = ConfessionPayload::from_senml(&wire).expect("re-decode");
    assert_eq!(round, payload, "non-anonymous pack round-trips");

    // Matching authenticated source: sender preserved on the entry.
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(100.0)))
            .expect("store");
    let out = store.post(&wire, Some("0011223344556677"));
    assert!(out.is_created(), "{out:?}");
    let detail = store.entry(out.id.as_deref().expect("id")).expect("entry");
    assert!(!detail.anonymous);
    assert_eq!(detail.sender.as_deref(), Some("0011223344556677"));

    // Spoofed bn (different from authenticated source) is never stored.
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(100.0)))
            .expect("store");
    let out = store.post(&wire, Some("9999999999999999"));
    assert!(out.is_created(), "{out:?}");
    let detail = store.entry(out.id.as_deref().expect("id")).expect("entry");
    assert_eq!(
        detail.sender, None,
        "spoofed bn must not become the stored sender"
    );
}

// ---------------------------------------------------------------------------
// Rate-limit vectors (18.10.3): cooldown then rolling-hour ceiling.
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_30s_window_rejects_with_retry_after() {
    let vec = find_vector("rate_limit_30s_window");
    assert_eq!(vec["last_post_uptime_ms"], 10_000);
    assert_eq!(vec["current_uptime_ms"], 25_000);
    assert_eq!(vec["expected"]["reason"], "30s_limit");
    assert_eq!(vec["expected"]["retry_after_s"], 15);

    let now = clock_at(10.0);
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&now)).expect("store");
    let wire = build_post_body("0011223344556677", "first post");
    let out = store.post(&wire, Some("0011223344556677"));
    assert!(out.is_created(), "first post accepted");

    *now.lock().unwrap() = 25.0;
    let out = store.post(&wire, Some("0011223344556677"));
    assert_eq!(out.code, code::TOO_MANY_REQUESTS, "{out:?}");
    assert_eq!(out.reason, Some("30s_limit"));
    // 30 - (25 - 10) = 15 s retry, per the vector's retry_after_s.
    assert_eq!(out.retry_after_s, Some(15));
    assert_eq!(CONFESSION_COOLDOWN_S, 30);
}

#[test]
fn rate_limit_12th_post_accepted_13th_rejected() {
    let vec12 = find_vector("rate_limit_12th_post_accepted");
    let vec13 = find_vector("rate_limit_13th_post_rejected");
    assert_eq!(vec12["history_count_in_rolling_hour"], 11);
    assert_eq!(vec13["history_count_in_rolling_hour"], 12);

    let now = clock_at(0.0);
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&now)).expect("store");
    // Seed 11 recorded posts inside the rolling hour (each seed >30 s
    // after the previous on the fake clock, so no cooldown interference).
    for i in 0..11_u64 {
        *now.lock().unwrap() = i as f64 * 60.0;
        store.record_request(IID);
    }
    // 12th post (the first actual POST): accepted, hour is then full.
    *now.lock().unwrap() = 700.0;
    let wire12 = build_post_body(IID, "This is my twelfth confession this hour.");
    let out = store.post(&wire12, Some(IID));
    assert!(
        out.is_created(),
        "12th post within the hour accepted: {out:?}"
    );
    let (remaining, _reset) = store.rate_info(IID);
    assert_eq!(remaining, 0, "rate_remaining 0 after the 12th post");

    // 13th post: 4.29 with hourly_limit_exceeded and a Retry-After. It
    // must be past the 30 s cooldown (so the cooldown does not fire
    // first) but still inside the rolling hour (window started at 60 s).
    *now.lock().unwrap() = 735.0;
    let wire13 = build_post_body(IID, "This should be rejected.");
    let out = store.post(&wire13, Some(IID));
    assert_eq!(out.code, code::TOO_MANY_REQUESTS, "{out:?}");
    assert_eq!(out.reason, Some("hourly_limit_exceeded"));
    assert!(out.retry_after_s.is_some(), "Retry-After present");
    assert_eq!(CONFESSION_HOURLY_MAX, 12);
}

// ---------------------------------------------------------------------------
// Storage vectors: FIFO eviction, no back-pressure.
// ---------------------------------------------------------------------------

#[test]
fn storage_full_fifo_eviction_oldest_first() {
    let vec = find_vector("storage_full_fifo_eviction");
    assert_eq!(vec["node_type"], "leaf");
    assert_eq!(vec["storage_max_kb"], 2);
    assert_eq!(vec["incoming_confession_size_bytes"], 600);
    let existing = vec["existing_confessions"].as_array().expect("existing");
    assert_eq!(existing.len(), 4, "4x512B fills the 2KB leaf budget");

    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    let ids = ["0000aa", "0000ab", "0000ac", "0000ad"];
    for (i, id) in ids.iter().enumerate() {
        store
            .add_confession(AddConfessionParams {
                content: format!("confession {i}"),
                id: Some((*id).to_owned()),
                size: Some(512),
                anonymous: true,
                ..Default::default()
            })
            .expect("seed");
    }
    // Incoming 600 B against a full 2 KiB store: the two oldest vanish
    // (FIFO, silently, no back-pressure) and the post is created. The
    // wire body is padded to exactly the vector's incoming size.
    let mut pad = String::new();
    let mut body = build_post_body(IID, "");
    while body.len() < 600 {
        pad.push('x');
        body = build_post_body(IID, &pad);
    }
    assert_eq!(body.len(), 600, "incoming body sized to the vector");
    let out = store.post(&body, Some(IID));
    assert_eq!(out.code, code::CREATED, "{out:?}");
    let listing = store.listing(ConfessionQuery::default(), None);
    assert!(!listing.confessions.iter().any(|e| e.id == "0000aa"));
    assert!(!listing.confessions.iter().any(|e| e.id == "0000ab"));
    assert!(listing.confessions.iter().any(|e| e.id == "0000ac"));
    assert!(listing.confessions.iter().any(|e| e.id == "0000ad"));
    assert_eq!(listing.count, 3, "oldest two evicted, newest three remain");
}

#[test]
fn storage_full_br_larger_budget() {
    let vec = find_vector("storage_full_br_larger_budget");
    assert_eq!(vec["node_type"], "border_router");
    assert_eq!(vec["storage_max_kb"], 8);
    assert_eq!(vec["incoming_confession_size_bytes"], 768);

    let mut store = ConfessionStore::with_clock(CONFESSION_STORAGE_BR, clock_from(&clock_at(0.0)))
        .expect("store");
    // 12 entries x 640 B = 7.5 KB used (vector storage_used_kb 7.5).
    for i in 0..12_u32 {
        store
            .add_confession(AddConfessionParams {
                content: format!("br {i}"),
                id: Some(format!("0000{:02x}", i)),
                size: Some(640),
                anonymous: true,
                ..Default::default()
            })
            .expect("seed");
    }
    let body = build_post_body(IID, &"y".repeat(600));
    let out = store.post(&body, Some(IID));
    assert_eq!(
        out.code,
        code::CREATED,
        "BR budget admits after FIFO eviction"
    );
    // Eviction was needed: the oldest 640 B entry made room for 768 B.
    let listing = store.listing(ConfessionQuery::default(), None);
    assert_eq!(listing.count, 12, "one evicted, one added");
    assert!(!listing.confessions.iter().any(|e| e.id == "000000"));
    let (used, max) = store.storage_info();
    assert!(used <= max, "{used} <= {max}");
}

// ---------------------------------------------------------------------------
// Reboot vectors: RAM-only storage cleared on any reboot (18.10.4).
// ---------------------------------------------------------------------------

#[test]
fn reboot_clear_empty_get() {
    let vec = find_vector("reboot_clear_empty_get");
    assert_eq!(vec["pre_reboot_confession_count"], 5);
    assert_eq!(vec["reboot_type"], "warm");
    assert_eq!(vec["expected"]["confession_count"], 0);

    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    for i in 0..5 {
        store
            .add_confession(AddConfessionParams {
                content: format!("pre-reboot {i}"),
                anonymous: true,
                ..Default::default()
            })
            .expect("seed");
    }
    assert_eq!(store.len(), 5);
    store.clear(); // warm reboot
    assert!(store.is_empty(), "RAM-only storage cleared on warm reboot");
    // Empty SenML feed (Content-Format 112 per the vector): just 0x80.
    let feed = store.feed_senml().expect("feed");
    assert_eq!(feed, vec![0x80], "empty SenML feed is an empty CBOR array");
    let listing = store.listing(ConfessionQuery::default(), None);
    assert_eq!(listing.count, 0);
    assert!(listing.confessions.is_empty());
}

#[test]
fn reboot_clear_crash() {
    let vec = find_vector("reboot_clear_crash");
    assert_eq!(vec["pre_reboot_confession_count"], 10);
    assert_eq!(vec["reboot_type"], "crash");

    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    for i in 0..10 {
        store
            .add_confession(AddConfessionParams {
                content: format!("crash survivor? no {i}"),
                anonymous: true,
                ..Default::default()
            })
            .expect("seed");
    }
    store.clear(); // crash reboot is a clear too
    assert!(store.is_empty());
    // Rate state is RAM-only as well: a fresh bucket allows posting again.
    let wire = build_post_body(IID, "posted right after the crash");
    let out = store.post(&wire, Some(IID));
    assert!(out.is_created(), "{out:?}");
}

// ---------------------------------------------------------------------------
// OSCORE vectors: privacy semantics (18.10.5), no wire decryption here.
// ---------------------------------------------------------------------------

#[test]
fn oscore_group_confession_sender_unlinked() {
    let vec = find_vector("oscore_group_confession");
    assert_eq!(vec["expected"]["sender_identity_revealed"], false);
    let payload = payload_from_senml_json(&vec["plaintext_senml_json"]);
    assert!(
        payload.anonymous,
        "group confession is anonymous on the wire"
    );
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    let wire = payload.to_senml().expect("encode plaintext");
    let out = store.post(&wire, None);
    assert!(out.is_created(), "{out:?}");
    let detail = store.entry(out.id.as_deref().expect("id")).expect("entry");
    assert_eq!(
        detail.sender, None,
        "group context never reveals the sender"
    );
}

#[test]
fn oscore_pairwise_confession_privacy_warning() {
    let vec = find_vector("oscore_pairwise_confession_privacy_warning");
    assert_eq!(vec["expected"]["sender_identity_revealed"], true);
    assert!(vec["expected"]["privacy_warning"]
        .as_str()
        .unwrap_or_default()
        .contains("reveals"));
    // Policy behavior under pairwise OSCORE: the sender IS revealed when
    // the post is non-anonymous and the claimed bn matches the source.
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    let payload = ConfessionPayload {
        claimed_iid: Some(IID.to_owned()),
        base_time: Some(1_721_654_600.0),
        content: Some("pairwise post".to_owned()),
        anonymous: false,
        sender: Some(IID.to_owned()),
        anonymous_record_present: true,
        ..ConfessionPayload::default()
    };
    let wire = payload.to_senml().expect("encode");
    let out = store.post(&wire, Some(IID));
    assert!(out.is_created(), "{out:?}");
    let detail = store.entry(out.id.as_deref().expect("id")).expect("detail");
    assert!(!detail.anonymous);
    assert_eq!(detail.sender.as_deref(), Some(IID));
}

// ---------------------------------------------------------------------------
// Size-limit vectors: exactly 768 B accepted, 769 B rejected 4.13.
// ---------------------------------------------------------------------------

#[test]
fn max_confession_size_accepted_and_exceeded() {
    let acc = find_vector("max_confession_size_accepted");
    let exc = find_vector("max_confession_size_exceeded");
    assert_eq!(acc["payload_size_bytes"], 768);
    assert_eq!(exc["payload_size_bytes"], 769);
    assert_eq!(acc["expected"]["response_code"], "2.01 Created");
    assert_eq!(
        exc["expected"]["response_code"],
        "4.13 Request Entity Too Large"
    );

    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    // A post whose wire size is exactly the max (768 B): pad content so
    // the canonical SenML pack lands on the boundary.
    let mut pad = String::new();
    let mut body = build_post_body(IID, "");
    while body.len() < 768 {
        pad.push('x');
        body = build_post_body(IID, &pad);
    }
    assert_eq!(body.len(), 768, "scaffold hits the exact boundary");
    let out = store.post(&body, Some(IID));
    assert_eq!(out.code, code::CREATED, "at-max post accepted: {out:?}");

    // One byte over: 4.13.
    let over = build_post_body(IID, &format!("{pad}x"));
    assert_eq!(over.len(), 769);
    let out = store.post(&over, Some(IID));
    assert_eq!(out.code, code::ENTITY_TOO_LARGE, "{out:?}");
    assert_eq!(CONFESSION_MAX_SIZE, 768);
}

// ---------------------------------------------------------------------------
// TTL vector: expired entries are not returned (ttl_expired).
// ---------------------------------------------------------------------------

#[test]
fn ttl_expiry_drops_returned_entries() {
    let vec = find_vector("ttl_expiry");
    assert_eq!(vec["confession"]["ttl"], 43200);
    assert_eq!(vec["current_time"], 1_721_700_000.0);
    assert_eq!(vec["expected"]["confession_returned"], false);
    assert_eq!(vec["expected"]["reason"], "ttl_expired");
    assert_eq!(vec["expected"]["elapsed_s"], 100_000);
    assert_eq!(TTL_EXPIRED, "ttl_expired");
    assert_eq!(CONFESSION_MAX_TTL, 48 * 3600);

    // Receive at uptime 0 with the vector's 12 h TTL; the confession must
    // be gone once the elapsed uptime exceeds the TTL.
    let now = clock_at(0.0);
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&now)).expect("store");
    let id = store
        .add_confession(AddConfessionParams {
            content: "temporary honesty".to_owned(),
            ts: Some(1_721_600_000.0),
            ttl: Some(43_200),
            anonymous: true,
            ..Default::default()
        })
        .expect("seed");
    assert!(store.entry(&id).is_some(), "live at elapsed 0");
    *now.lock().unwrap() = 100_000.0; // vector elapsed_s
    assert!(
        store.entry(&id).is_none(),
        "expired once elapsed > ttl ({TTL_EXPIRED})"
    );
}

// ---------------------------------------------------------------------------
// GET metadata vector (18.10.7 query/display map, Content-Format 60).
// ---------------------------------------------------------------------------

#[test]
fn get_confessions_with_metadata() {
    let vec = find_vector("get_confessions_with_metadata");
    let query_params = &vec["query_params"];
    assert_eq!(query_params["count"], 5);
    assert_eq!(query_params["since"], 1_721_650_000.0);
    let fields = &vec["expected"]["response_fields"];
    assert_eq!(vec["expected"]["content_format"], CONTENT_FORMAT_CBOR);
    assert_eq!(vec["expected"]["response_code"], "2.05 Content");

    let now = clock_at(0.0);
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&now)).expect("store");
    // Seed the vector's two surviving confessions with the vector's ages:
    // 3c1d9e received first (age 1200 at GET time), 8a4f2b 300 s later
    // (age 900), plus two below the `since` cut. GET happens at 1200.
    store
        .add_confession(AddConfessionParams {
            content: "second".to_owned(),
            id: Some("3c1d9e".to_owned()),
            ts: Some(1_721_654_000.0),
            size: Some(300),
            anonymous: true,
            ..Default::default()
        })
        .expect("seed");
    *now.lock().unwrap() = 300.0;
    let id_a = store
        .add_confession(AddConfessionParams {
            content: "first".to_owned(),
            id: Some("8a4f2b".to_owned()),
            ts: Some(1_721_654_321.0),
            size: Some(300),
            anonymous: true,
            ..Default::default()
        })
        .expect("seed");
    let id_b = "3c1d9e".to_owned();
    store
        .add_confession(AddConfessionParams {
            content: "old".to_owned(),
            id: Some("0000aa".to_owned()),
            ts: Some(1_721_649_999.0),
            size: Some(300),
            anonymous: true,
            ..Default::default()
        })
        .expect("seed below since");
    store
        .add_confession(AddConfessionParams {
            content: "older".to_owned(),
            id: Some("0000ab".to_owned()),
            ts: Some(1_721_600_000.0),
            size: Some(300),
            anonymous: true,
            ..Default::default()
        })
        .expect("seed below since");
    *now.lock().unwrap() = 1200.0;

    let query = ConfessionQuery {
        count: Some(5),
        since: Some(1_721_650_000.0),
        ..ConfessionQuery::default()
    };
    // Authenticated requester sees rate metadata (reference rule).
    store.record_request(IID);
    let listing = store.listing(query, Some(IID));
    assert_eq!(listing.count, 2, "only entries at/after `since` survive");
    assert_eq!(listing.confessions[0].id, id_a, "newest first");
    assert_eq!(listing.confessions[1].id, id_b);
    assert_eq!(listing.confessions[0].age_s, 900, "vector age_s 900");
    assert_eq!(listing.confessions[1].age_s, 1200, "vector age_s 1200");
    assert!(listing.rate_remaining.is_some(), "rate metadata present");
    assert!(listing.rate_reset_s.is_some());
    assert_eq!(listing.storage_max_kb, 2.0, "vector storage_max_kb 2");
    assert!(listing.storage_used_kb > 0.0);
    let _ = fields["count"]; // shape documented above

    // Unauthenticated requesters get no rate metadata (reference rule).
    let listing = store.listing(ConfessionQuery::default(), None);
    assert!(listing.rate_remaining.is_none());
    assert!(listing.rate_reset_s.is_none());
}

// ---------------------------------------------------------------------------
// No-log compliance vector (18.10.4).
// ---------------------------------------------------------------------------

#[test]
fn no_log_guarantee_checks() {
    let vec = find_vector("no_log_guarantee_checks");
    assert_eq!(vec["expected"]["all_prohibited"], true);
    assert_eq!(vec["expected"]["storage_type"], "ram_only");
    assert_eq!(vec["expected"]["cleared_on_reboot"], true);
    // The store holds everything in process memory: it exposes no
    // persistence API at all, and `logging` is surfaced (not defaulted)
    // only via the explicit operator override.
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    let listing = store.listing(ConfessionQuery::default(), None);
    assert!(!listing.logging, "no-log is the default surface");
    store.set_persist(true); // operator override voids the guarantee
    let listing = store.listing(ConfessionQuery::default(), None);
    assert!(listing.logging, "override must be surfaced per 18.10.4");
    // Reboot still clears everything (cleared_on_reboot).
    store
        .add_confession(AddConfessionParams {
            content: "gone on reboot".to_owned(),
            ..Default::default()
        })
        .expect("seed");
    store.clear();
    assert!(store.is_empty());
    // Feed content format is SenML+CBOR 112 per spec 18.10.2.
    assert_eq!(CONTENT_FORMAT_SENML_CBOR, 112);
}

// ---------------------------------------------------------------------------
// Domain-contract behaviors referenced by the spec but not vector-pinned.
// ---------------------------------------------------------------------------

#[test]
fn invalid_posts_rejected_400() {
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    // Empty payload.
    assert_eq!(store.post(&[], Some(IID)).code, code::BAD_REQUEST);
    // Undecodable bytes.
    assert_eq!(
        store.post(&[0x00, 0x01, 0x02], Some(IID)).code,
        code::BAD_REQUEST
    );
    // No bn base name.
    let mut pack = Vec::new();
    ciborium::into_writer(
        &Cbor::Array(vec![Cbor::Map(vec![(
            Cbor::Text("n".into()),
            Cbor::Text("content".into()),
        )])]),
        &mut pack,
    )
    .unwrap();
    assert_eq!(store.post(&pack, Some(IID)).code, code::BAD_REQUEST);
    // Wrong type.
    let wrong_type = build_post_body_typed(IID, "content here", "not-a-confession");
    assert_eq!(store.post(&wrong_type, Some(IID)).code, code::BAD_REQUEST);
}

#[test]
fn check_rate_limit_fresh_bucket_allows() {
    let mut store =
        ConfessionStore::with_clock(CONFESSION_STORAGE_LEAF, clock_from(&clock_at(0.0)))
            .expect("store");
    assert_eq!(
        store.check_rate_limit("0000000000000001"),
        RateDecision::Allow
    );
    // Canonical IDs validate like the reference _is_confession_id.
    assert!(is_confession_id("8a4f2b"));
    assert!(!is_confession_id("8A4F2B"));
    assert!(!is_confession_id("8a4f2"));
    assert!(!is_confession_id("8a4f2bb"));
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Build a canonical SenML+CBOR POST body from bn/type/content records
/// (scaffolding only — outcome assertions never treat these bytes as
/// golden data).
fn build_post_body(iid: &str, content: &str) -> Vec<u8> {
    let payload = ConfessionPayload {
        claimed_iid: Some(iid.to_owned()),
        base_time: Some(1_721_654_700.0),
        confession_type: Some("confession".to_owned()),
        content: Some(content.to_owned()),
        ..ConfessionPayload::default()
    };
    payload.to_senml().expect("encode")
}

/// Body with a non-confession `type` (rejection path).
fn build_post_body_typed(iid: &str, content: &str, type_: &str) -> Vec<u8> {
    let payload = ConfessionPayload {
        claimed_iid: Some(iid.to_owned()),
        base_time: Some(1_721_654_700.0),
        confession_type: Some(type_.to_owned()),
        content: Some(content.to_owned()),
        ..ConfessionPayload::default()
    };
    payload.to_senml().expect("encode")
}

/// Build a payload from a vector's `senml_json` shape (bn/bt base record
/// plus named `vs`/`v` records; scaffolding only).
fn payload_from_senml_json(records: &Value) -> ConfessionPayload {
    // Spec 18.10.1: anonymous defaults true when no record is carried
    // (the derived Default is false, so set the spec default explicitly).
    let mut payload = ConfessionPayload {
        anonymous: true,
        ..ConfessionPayload::default()
    };
    for r in records.as_array().expect("records array") {
        if let Some(bn) = r["bn"].as_str() {
            let rest = bn.strip_prefix("urn:dev:mac:").unwrap_or(bn);
            let iid = rest.split(':').next().unwrap_or_default();
            if !iid.is_empty() {
                payload.claimed_iid = Some(iid.to_ascii_lowercase());
            }
        }
        if let Some(bt) = r["bt"].as_f64() {
            payload.base_time = Some(bt);
        }
        match r["n"].as_str() {
            Some("type") => payload.confession_type = r["vs"].as_str().map(str::to_owned),
            Some("content") => payload.content = r["vs"].as_str().map(str::to_owned),
            Some("anonymous") => {
                payload.anonymous_record_present = true;
                payload.anonymous = r["v"].as_f64().map(|v| v != 0.0).unwrap_or(true);
            }
            Some("ttl") => payload.ttl = r["v"].as_f64(),
            Some("lat") => payload.lat = r["v"].as_f64(),
            Some("lon") => payload.lon = r["v"].as_f64(),
            Some("sender") => payload.sender = r["vs"].as_str().map(str::to_owned),
            _ => {}
        }
    }
    payload
}
