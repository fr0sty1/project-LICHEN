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

use lichen_client::checkin::{
    CheckIn, RollcallRequest, RollcallStatus, CHECKIN_STATUS_VALUES, DEFAULT_TIMEOUT_S,
    MAX_CHECKINS, MAX_ROLLCALLS, MAX_TIMEOUT_S,
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
