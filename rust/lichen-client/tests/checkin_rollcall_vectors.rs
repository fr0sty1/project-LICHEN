// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-validation of check-in / roll call wire codecs against shared
//! vectors.
//!
//! Vectors in `test/vectors/checkin_rollcall.json` are the only oracle;
//! expected bytes and fields come from the JSON, never from this
//! implementation. Re-encodes MUST reproduce the oracle bytes exactly,
//! except for `rollcall_integer_id`, whose oracle carries the integer id
//! form that the reference resource (and this codec) coerces to text on
//! decode — mirroring the Python oracle, whose re-dump would also emit text.

use ciborium::value::Value as Cbor;
use lichen_client::checkin::{
    CheckIn, RollcallRequest, RollcallStatus, CHECKIN_CBOR_MAX, CHECKIN_STATUS_VALUES,
    DEFAULT_TIMEOUT_S, MAX_CHECKINS, MAX_ROLLCALLS, MAX_TIMEOUT_S, ROLLCALL_REQ_CBOR_MAX,
    ROLLCALL_STATUS_CBOR_MAX, ROLLCALL_TRACK_MAX,
};
use serde_json::Value;
use std::fs;

fn load_vectors() -> Vec<Value> {
    let json_str = fs::read_to_string("../../test/vectors/checkin_rollcall.json")
        .expect("failed to read checkin_rollcall.json");
    let data: Value = serde_json::from_str(&json_str).expect("failed to parse JSON");
    data["vectors"].as_array().cloned().expect("vectors array")
}

fn hex_decode(v: &Value) -> Vec<u8> {
    hex::decode(v["cbor_hex"].as_str().expect("cbor_hex")).expect("valid hex")
}

fn expect_error(v: &Value, err: lichen_client::Error) {
    let want = v["expected"]["error"].as_str().unwrap_or_else(|| {
        panic!(
            "{}: failure vector without pinned error code",
            v["name"].as_str().unwrap()
        )
    });
    assert!(
        err.to_string().contains(want),
        "{}: error {:?} does not pin {want}",
        v["name"].as_str().unwrap(),
        err
    );
}

#[test]
fn spec_constants_match_vectors() {
    let vectors = load_vectors();
    let find = |name: &str| {
        vectors
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("vector {name} missing"))
            .clone()
    };

    let rollcall = find("rollcall_constants");
    assert_eq!(
        rollcall["max_rollcalls"].as_u64(),
        Some(MAX_ROLLCALLS as u64)
    );
    assert_eq!(rollcall["max_timeout_s"].as_u64(), Some(MAX_TIMEOUT_S));
    assert_eq!(
        rollcall["default_timeout_s"].as_u64(),
        Some(DEFAULT_TIMEOUT_S)
    );

    let checkin = find("checkin_constants");
    assert_eq!(checkin["max_checkins"].as_u64(), Some(MAX_CHECKINS as u64));

    let statuses = find("checkin_status_values")["valid_status_values"]
        .as_array()
        .expect("valid_status_values")
        .iter()
        .map(|v| v.as_str().expect("status text").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(statuses, CHECKIN_STATUS_VALUES);
}

#[test]
fn checkin_vectors_decode_and_reencode() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        if !name.starts_with("checkin") || v.get("cbor_hex").is_none() {
            continue;
        }
        let bytes = hex_decode(&v);

        match v["expected"]["decode_success"].as_bool().unwrap() {
            true => {
                let p = &v["cbor_payload"];
                let c = CheckIn::from_cbor(&bytes)
                    .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

                assert_eq!(c.node, p["node"].as_str().unwrap(), "{name}: node");
                assert_eq!(c.ts, p["ts"].as_u64().unwrap(), "{name}: ts");
                assert_eq!(
                    c.status.as_str(),
                    p["status"].as_str().unwrap(),
                    "{name}: status"
                );
                assert_eq!(c.lat, p.get("lat").and_then(Value::as_f64), "{name}: lat");
                assert_eq!(c.lon, p.get("lon").and_then(Value::as_f64), "{name}: lon");
                assert_eq!(
                    c.msg.as_deref(),
                    p.get("msg").and_then(Value::as_str),
                    "{name}: msg"
                );

                // Re-encode must reproduce the oracle bytes exactly.
                assert_eq!(
                    c.to_cbor().unwrap(),
                    bytes,
                    "{name}: re-encode differs from oracle bytes"
                );
            }
            false => {
                if let Err(e) = CheckIn::from_cbor(&bytes) {
                    expect_error(&v, e);
                } else {
                    panic!("{name}: should not decode");
                }
            }
        }
    }
}

#[test]
fn rollcall_request_vectors_decode_and_reencode() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        if !name.starts_with("rollcall")
            || name == "rollcall_status_response"
            || v.get("cbor_hex").is_none()
        {
            continue;
        }
        let bytes = hex_decode(&v);

        match v["expected"]["decode_success"].as_bool().unwrap() {
            true => {
                let p = &v["cbor_payload"];
                let r = RollcallRequest::from_cbor(&bytes)
                    .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

                // Integer ids are coerced to decimal text (reference behavior).
                let want_id = match &p["id"] {
                    Value::Number(n) => n.to_string(),
                    Value::String(s) => s.clone(),
                    other => panic!("{name}: unexpected id {other:?}"),
                };
                assert_eq!(r.id, want_id, "{name}: id");
                assert_eq!(
                    r.from.as_deref(),
                    p.get("from").and_then(Value::as_str),
                    "{name}: from"
                );
                assert_eq!(r.ts, p.get("ts").and_then(Value::as_u64), "{name}: ts");
                assert_eq!(
                    r.timeout_s,
                    p.get("timeout_s").and_then(Value::as_u64),
                    "{name}: timeout_s"
                );

                // The integer-id oracle carries the pre-coercion wire form;
                // every text-id vector must re-encode byte-exactly.
                if p["id"].is_string() {
                    assert_eq!(
                        r.to_cbor().unwrap(),
                        bytes,
                        "{name}: re-encode differs from oracle bytes"
                    );
                }
            }
            false => {
                if let Err(e) = RollcallRequest::from_cbor(&bytes) {
                    expect_error(&v, e);
                } else {
                    panic!("{name}: should not decode");
                }
            }
        }
    }
}

#[test]
fn rollcall_status_response_vector() {
    let vectors = load_vectors();
    let v = vectors
        .iter()
        .find(|v| v["name"] == "rollcall_status_response")
        .expect("rollcall_status_response vector");
    let bytes = hex_decode(v);
    let p = &v["cbor_payload"];

    let s = RollcallStatus::from_cbor(&bytes)
        .unwrap_or_else(|e| panic!("rollcall_status_response: decode failed: {e:?}"));

    assert_eq!(s.id, p["id"].as_str().unwrap());
    assert_eq!(s.started, p["started"].as_u64().unwrap());
    assert_eq!(s.timeout_s, p["timeout_s"].as_u64().unwrap());

    for (got, want) in s
        .responded
        .iter()
        .zip(p["responded"].as_array().expect("responded list").iter())
    {
        assert_eq!(got.node, want["node"].as_str().unwrap(), "responded node");
        assert_eq!(got.ts, want["ts"].as_u64().unwrap(), "responded ts");
        assert_eq!(
            got.status.as_str(),
            want["status"].as_str().unwrap(),
            "responded status"
        );
    }
    assert_eq!(s.responded.len(), p["responded"].as_array().unwrap().len());

    for (got, want) in s
        .missing
        .iter()
        .zip(p["missing"].as_array().expect("missing list").iter())
    {
        assert_eq!(got.node, want["node"].as_str().unwrap(), "missing node");
        assert_eq!(
            got.last_seen,
            want["last_seen"].as_u64().unwrap(),
            "missing last_seen"
        );
    }
    assert_eq!(s.missing.len(), p["missing"].as_array().unwrap().len());

    // Re-encode must reproduce the oracle bytes exactly.
    assert_eq!(
        s.to_cbor().unwrap(),
        bytes,
        "re-encode differs from oracle bytes"
    );
}

#[test]
fn checkin_rejects_negative_ts() {
    // checkin_ts_semantics pins ts_type=uint with reject on negatives.
    // Hand-derived oracle bytes: the checkin_minimal payload with ts
    // replaced by CBOR -1 (0x20).
    let bytes = hex::decode(
        "a3646e6f64657827303230303a303030303a303030303a303030303a303031313a\
         323233333a343435353a363637376274732066737461747573626f6b",
    )
    .unwrap();
    let err = CheckIn::from_cbor(&bytes).expect_err("negative ts must be rejected");
    assert!(err.to_string().contains("invalid_ts_value"), "{err:?}");
}

#[test]
fn rollcall_request_builder_rejects_out_of_range_timeout() {
    let base = RollcallRequest {
        id: "roll-001".into(),
        from: None,
        ts: None,
        timeout_s: None,
    };
    let mut zero = base.clone();
    zero.timeout_s = Some(0);
    assert!(zero.to_cbor().is_err(), "timeout 0 must fail encode");
    let mut over = base;
    over.timeout_s = Some(MAX_TIMEOUT_S + 1);
    assert!(over.to_cbor().is_err(), "timeout > max must fail encode");
}

// ── Decoder conformance pins (C codec parity) ────────────────────────────

/// Encode a hand-built CBOR value; used to construct hostile inputs the
/// oracle JSON does not carry. Encoding is scaffolding only — assertions
/// are on rejection codes, never on these bytes as golden data.
fn cbor_bytes(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR encode to Vec cannot fail");
    out
}

fn text(s: &str) -> Cbor {
    Cbor::Text(s.into())
}

fn uint(n: u64) -> Cbor {
    Cbor::Integer(n.into())
}

fn vector_wire(name: &str) -> Vec<u8> {
    let vectors = load_vectors();
    let v = vectors
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"));
    hex_decode(v)
}

fn find_vector(name: &str) -> Value {
    load_vectors()
        .into_iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"))
}

#[test]
fn decoders_reject_trailing_bytes() {
    // C returns LICHEN_CHECKIN_ERR_TRAILING_DATA for bytes after the
    // top-level item; all three Rust decoders must agree.
    for (name, path) in [
        ("checkin_minimal", "checkin"),
        ("rollcall_minimal", "request"),
        ("rollcall_status_response", "status"),
    ] {
        let mut bytes = vector_wire(name);
        bytes.push(0xff);
        let err = match path {
            "checkin" => CheckIn::from_cbor(&bytes).expect_err(name),
            "request" => RollcallRequest::from_cbor(&bytes).expect_err(name),
            _ => RollcallStatus::from_cbor(&bytes).expect_err(name),
        };
        assert!(
            err.to_string().contains("trailing_data"),
            "{name}: trailing byte accepted: {err:?}"
        );
    }
}

#[test]
fn decoders_reject_duplicate_map_keys() {
    // RFC 8949 §5.6: duplicate keys are not valid; C rejects with
    // LICHEN_CHECKIN_ERR_DUPLICATE_KEY (first-wins would hide them).
    let node = "0200:0000:0000:0000:0011:2233:4455:6677";

    let checkin_dup = Cbor::Map(vec![
        (text("node"), text(node)),
        (text("ts"), uint(1716742800)),
        (text("ts"), uint(1716742801)),
        (text("status"), text("ok")),
    ]);
    let err = CheckIn::from_cbor(&cbor_bytes(&checkin_dup)).expect_err("duplicate ts");
    assert!(err.to_string().contains("duplicate_key"), "{err:?}");

    let request_dup = Cbor::Map(vec![
        (text("id"), text("roll-001")),
        (text("id"), text("roll-002")),
    ]);
    let err = RollcallRequest::from_cbor(&cbor_bytes(&request_dup)).expect_err("duplicate id");
    assert!(err.to_string().contains("duplicate_key"), "{err:?}");

    let status_dup = Cbor::Map(vec![
        (text("id"), text("roll-001")),
        (text("id"), text("roll-001")),
    ]);
    let err = RollcallStatus::from_cbor(&cbor_bytes(&status_dup)).expect_err("duplicate id");
    assert!(err.to_string().contains("duplicate_key"), "{err:?}");

    // Duplicate keys inside a track entry are rejected too.
    let track_dup = Cbor::Map(vec![
        (text("id"), text("roll-001")),
        (text("started"), uint(1716742800)),
        (text("timeout_s"), uint(60)),
        (
            text("responded"),
            Cbor::Array(vec![Cbor::Map(vec![
                (text("node"), text(node)),
                (text("node"), text(node)),
                (text("ts"), uint(1716742810)),
                (text("status"), text("ok")),
            ])]),
        ),
        (text("missing"), Cbor::Array(vec![])),
    ]);
    let err = RollcallStatus::from_cbor(&cbor_bytes(&track_dup)).expect_err("duplicate node");
    assert!(err.to_string().contains("duplicate_key"), "{err:?}");
}

#[test]
fn checkin_node_format_pinned_by_vector() {
    let v = find_vector("checkin_node_format");
    let valid = v["valid_node_examples"].as_array().expect("valid examples");
    let invalid = v["invalid_node_examples"]
        .as_array()
        .expect("invalid examples");

    let make = |node: &str| CheckIn {
        node: node.into(),
        ts: 1716742800,
        status: lichen_client::checkin::CheckInStatus::Ok,
        lat: None,
        lon: None,
        msg: None,
    };

    for example in valid {
        let node = example.as_str().expect("node text");
        let wire = make(node)
            .to_cbor()
            .unwrap_or_else(|e| panic!("valid node example {node} rejected on encode: {e:?}"));
        CheckIn::from_cbor(&wire)
            .unwrap_or_else(|e| panic!("valid node example {node} rejected on decode: {e:?}"));
    }

    for example in invalid {
        let node = example.as_str().expect("node text");
        let err = make(node)
            .to_cbor()
            .expect_err("invalid node example must fail encode");
        assert!(
            err.to_string().contains("invalid_node_format"),
            "encode({node}): {err:?}"
        );

        let wire = cbor_bytes(&Cbor::Map(vec![
            (text("node"), text(node)),
            (text("ts"), uint(1716742800)),
            (text("status"), text("ok")),
        ]));
        let err = CheckIn::from_cbor(&wire).expect_err("invalid node example must fail decode");
        assert!(
            err.to_string().contains("invalid_node_format"),
            "decode({node}): {err:?}"
        );
    }
}

#[test]
fn decoders_enforce_input_size_caps() {
    // Raw input beyond the per-payload bound is rejected before parsing
    // (C buffer bounds LICHEN_CHECKIN_CBOR_MAX / LICHEN_ROLLCALL_REQ_CBOR_MAX
    // / LICHEN_ROLLCALL_STATUS_CBOR_MAX).
    type DecodeCheck = fn(&[u8]) -> lichen_client::Error;
    let decoders: [(&str, usize, DecodeCheck); 3] = [
        ("checkin", CHECKIN_CBOR_MAX, |b: &[u8]| {
            CheckIn::from_cbor(b).expect_err("over-cap must fail")
        }),
        ("rollcall request", ROLLCALL_REQ_CBOR_MAX, |b: &[u8]| {
            RollcallRequest::from_cbor(b).expect_err("over-cap must fail")
        }),
        ("rollcall status", ROLLCALL_STATUS_CBOR_MAX, |b: &[u8]| {
            RollcallStatus::from_cbor(b).expect_err("over-cap must fail")
        }),
    ];
    for (label, max_len, decode) in decoders {
        let err = decode(&vec![0xa0; max_len + 1]);
        assert!(
            err.to_string().contains("payload_exceeds_maximum"),
            "{label}: over-cap input accepted: {err:?}"
        );
        // Exactly at the bound the size gate passes (failure is then
        // ordinary CBOR handling of the filler bytes, not the cap).
        let err = decode(&vec![0xa0; max_len]);
        assert!(
            !err.to_string().contains("payload_exceeds_maximum"),
            "{label}: at-cap input hit the size gate: {err:?}"
        );
    }
}

#[test]
fn rollcall_status_caps_track_arrays() {
    let node = "0200:0000:0000:0000:0011:2233:4455:6677";
    let responder = || {
        Cbor::Map(vec![
            (text("node"), text(node)),
            (text("ts"), uint(1716742810)),
            (text("status"), text("ok")),
        ])
    };
    let missing = || {
        Cbor::Map(vec![
            (text("node"), text(node)),
            (text("last_seen"), uint(1716740000)),
        ])
    };
    let status = |responded: Vec<Cbor>, missing_list: Vec<Cbor>| {
        cbor_bytes(&Cbor::Map(vec![
            (text("id"), text("roll-001")),
            (text("started"), uint(1716742800)),
            (text("timeout_s"), uint(60)),
            (text("responded"), Cbor::Array(responded)),
            (text("missing"), Cbor::Array(missing_list)),
        ]))
    };

    // At the cap the document decodes.
    let at_cap = status(vec![responder(); ROLLCALL_TRACK_MAX], vec![]);
    let decoded = RollcallStatus::from_cbor(&at_cap).expect("cap-sized track array must decode");
    assert_eq!(decoded.responded.len(), ROLLCALL_TRACK_MAX);
    assert_eq!(decoded.missing.len(), 0);

    // One past the cap is rejected (C LICHEN_CHECKIN_ERR_OUT_OF_RANGE).
    let over = status(
        (0..ROLLCALL_TRACK_MAX + 1).map(|_| responder()).collect(),
        vec![],
    );
    let err = RollcallStatus::from_cbor(&over).expect_err("over-cap responded must fail");
    assert!(err.to_string().contains("out_of_range"), "{err:?}");

    let over_missing = status(
        vec![],
        (0..ROLLCALL_TRACK_MAX + 1).map(|_| missing()).collect(),
    );
    let err = RollcallStatus::from_cbor(&over_missing).expect_err("over-cap missing must fail");
    assert!(err.to_string().contains("out_of_range"), "{err:?}");
}

/// C coerces any CBOR uint id (full u64) to its decimal form
/// (checkin.c lichen_rollcall_request_decode); Rust must not constrain
/// ids to i64 (conformance bead zow8).
#[test]
fn rollcall_request_u64_max_id_coerced() {
    let body = Cbor::Map(vec![
        (text("id"), uint(u64::MAX)),
        (text("timeout_s"), uint(60)),
    ]);
    let req = RollcallRequest::from_cbor(&cbor_bytes(&body))
        .expect("u64::MAX uint id must decode like C");
    assert_eq!(req.id, "18446744073709551615");
}

/// A huge uint timeout_s exceeds the maximum in C
/// (LICHEN_CHECKIN_ERR_TIMEOUT_MAX -> timeout_exceeds_maximum); it must
/// not surface as invalid_timeout_value (conformance bead zow8).
#[test]
fn rollcall_request_huge_uint_timeout_exceeds_maximum() {
    let body = Cbor::Map(vec![
        (text("id"), text("roll-001")),
        (text("timeout_s"), uint(u64::MAX)),
    ]);
    let err = RollcallRequest::from_cbor(&cbor_bytes(&body))
        .expect_err("u64::MAX timeout_s must exceed the maximum");
    assert!(
        err.to_string().contains("timeout_exceeds_maximum"),
        "{err:?}"
    );
}
