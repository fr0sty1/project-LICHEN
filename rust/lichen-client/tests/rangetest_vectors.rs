// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-validation of range-testing wire codecs against shared vectors.
//!
//! Vectors in `test/vectors/rangetest.json` are hand-derived from RFC 8428
//! independently of both the Python and Rust implementations; these tests
//! MUST reproduce their bytes exactly.

use lichen_client::rangetest::{
    interval_body, RangeTestReading, RangeTestRequest, TracerouteResult, DEFAULT_INTERVAL_MS,
    MAX_COUNT, MAX_PAYLOAD_LEN,
};
use serde_json::Value;
use std::fs;

fn load_vectors() -> Vec<Value> {
    let json_str = fs::read_to_string("../../test/vectors/rangetest.json")
        .expect("failed to read rangetest.json");
    let data: Value = serde_json::from_str(&json_str).expect("failed to parse JSON");
    data["vectors"].as_array().cloned().expect("vectors array")
}

fn hex_decode(v: &Value, key: &str) -> Option<Vec<u8>> {
    v[key].as_str().map(|h| hex::decode(h).expect("valid hex"))
}

#[test]
fn spec_limits_match_python_reference() {
    // Spec 18.7 bounds pinned by the Python reference resource.
    assert_eq!(MAX_PAYLOAD_LEN, 255);
    assert_eq!(MAX_COUNT, 100);
    assert_eq!(DEFAULT_INTERVAL_MS, 5_000);
}

#[test]
fn successful_rangetest_responses_match_vectors() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        let vtype = v["type"].as_str().unwrap();
        let code = v["expected"]["code"].as_str().unwrap();
        if vtype == "traceroute" || code != "2.05" {
            continue;
        }

        let payload = hex_decode(&v["expected"], "payload_hex")
            .unwrap_or_else(|| panic!("{name}: missing payload_hex"));

        let reading = RangeTestReading::from_senml_cbor(&payload)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

        let provider = &v["provider"];
        let eui = provider["node_eui64"].as_str().unwrap();
        assert_eq!(
            reading.base_name.as_deref(),
            Some(format!("urn:dev:mac:{eui}:").as_str()),
            "{name}: base name mismatch"
        );
        let now = v["now"].as_i64().unwrap();
        assert_eq!(
            reading.base_time,
            Some(now as f64),
            "{name}: base time mismatch"
        );

        // Sequence number comes straight from the vector's record list.
        let want_seq = v["expected"]["records"][1]["2"]
            .as_i64()
            .expect("seq value in records");
        assert_eq!(reading.seq, want_seq, "{name}: seq mismatch");

        let metrics = &reading.metrics;
        assert_eq!(
            metrics.rssi,
            provider["rssi"].as_f64().unwrap(),
            "{name}: rssi"
        );
        assert_eq!(
            metrics.snr,
            provider["snr"].as_f64().unwrap(),
            "{name}: snr"
        );
        assert_eq!(
            metrics.freq,
            provider["freq"].as_f64().unwrap(),
            "{name}: freq"
        );
        assert_eq!(
            i64::from(metrics.sf),
            provider["sf"].as_i64().unwrap(),
            "{name}: sf"
        );
    }
}

#[test]
fn traceroute_responses_match_vectors() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        if v["type"].as_str().unwrap() != "traceroute"
            || v["expected"]["code"].as_str().unwrap() != "2.05"
        {
            continue;
        }

        let payload = hex_decode(&v["expected"], "payload_hex").unwrap();
        let result = TracerouteResult::from_cbor(&payload)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));

        let want_hops = v["expected"]["records"]["hops"]
            .as_array()
            .expect("hops records");
        assert_eq!(result.hops.len(), want_hops.len(), "{name}: hop count");
        for (got, want) in result.hops.iter().zip(want_hops) {
            assert_eq!(got.addr, want["addr"].as_str().unwrap(), "{name}");
            assert_eq!(got.rssi, want["rssi"].as_f64().unwrap(), "{name}");
            assert_eq!(got.rtt_ms, want["rtt_ms"].as_f64().unwrap(), "{name}");
        }
        assert_eq!(
            result.total_hops,
            v["expected"]["records"]["total_hops"].as_u64().unwrap() as usize,
            "{name}: total_hops"
        );
        assert_eq!(
            result.total_rtt_ms,
            v["expected"]["records"]["total_rtt_ms"].as_f64().unwrap(),
            "{name}: total_rtt_ms"
        );

        // Round-trip must reproduce the oracle bytes exactly.
        assert_eq!(
            result.to_cbor().unwrap(),
            payload,
            "{name}: re-encode differs from oracle bytes"
        );
    }
}

#[test]
fn valid_request_bodies_roundtrip_through_vectors() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        let vtype = v["type"].as_str().unwrap();
        if vtype == "traceroute" || v["expected"]["code"].as_str().unwrap() != "2.05" {
            continue;
        }
        let Some(body) = hex_decode(&v["request"], "body_hex") else {
            continue;
        };

        // Parse externally-authored bytes, then reproduce them exactly.
        // (POST bodies only: the GET interval body has its own builder.)
        if vtype == "rangetest_post" {
            let req = RangeTestRequest::from_cbor(&body)
                .unwrap_or_else(|e| panic!("{name}: request parse failed: {e:?}"));
            assert_eq!(
                req.to_cbor().unwrap(),
                body,
                "{name}: request re-encode differs from oracle bytes"
            );
        }

        // Interval bodies are rebuilt through the validated builder.
        if vtype == "rangetest_get" {
            let val: ciborium::value::Value = ciborium::from_reader(&body[..])
                .unwrap_or_else(|e| panic!("{name}: body parse failed: {e}"));
            if let ciborium::value::Value::Map(entries) = &val {
                for (k, val) in entries {
                    if matches!(k, ciborium::value::Value::Text(t) if t == "interval_ms") {
                        let i = val.as_integer().expect("integer interval");
                        let ms = u64::try_from(i64::try_from(i).expect("interval fits i64"))
                            .expect("interval positive");
                        assert_eq!(
                            interval_body(ms).unwrap(),
                            body,
                            "{name}: interval body mismatch"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_request_bodies_are_rejected_client_side() {
    for v in load_vectors() {
        let name = v["name"].as_str().unwrap();
        let vtype = v["type"].as_str().unwrap();
        if vtype == "traceroute" || v["expected"]["code"].as_str().unwrap() != "4.00" {
            continue;
        }
        let body = hex_decode(&v["request"], "body_hex");

        match name {
            // Structurally invalid CBOR or wrong top-level type must fail parse.
            "rangetest_err_post_malformed_cbor"
            | "rangetest_err_get_malformed_cbor"
            | "rangetest_err_post_non_dict_body"
            | "rangetest_err_get_non_dict_payload" => {
                let bytes = body.expect("{name} carries body_hex");
                assert!(
                    RangeTestRequest::from_cbor(&bytes).is_err(),
                    "{name}: should not parse"
                );
            }
            // Out-of-range values parse but MUST fail validation on encode.
            "rangetest_err_post_seq_bool"
            | "rangetest_err_post_seq_negative"
            | "rangetest_err_post_seq_string"
            | "rangetest_err_post_payload_len_negative" => {
                let bytes = body.expect("{name} carries body_hex");
                assert!(
                    RangeTestRequest::from_cbor(&bytes).is_err(),
                    "{name}: typed parse should reject"
                );
            }
            "rangetest_err_post_payload_len_over"
            | "rangetest_err_post_count_zero"
            | "rangetest_err_post_count_over" => {
                let bytes = body.expect("{name} carries body_hex");
                let req = RangeTestRequest::from_cbor(&bytes)
                    .unwrap_or_else(|e| panic!("{name}: unexpected parse failure: {e:?}"));
                assert!(req.to_cbor().is_err(), "{name}: should fail validation");
            }
            // GET-only option bodies have no POST-side client type; interval
            // positivity is covered by the dedicated unit test below.
            _ => {}
        }
    }
}

#[test]
fn interval_builder_enforces_positive_interval() {
    assert!(interval_body(0).is_err());
    assert!(interval_body(1000).is_ok());
}
