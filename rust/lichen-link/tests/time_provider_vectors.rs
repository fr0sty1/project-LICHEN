// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Shared `packets-timing.json` consumers for epoch floor and monotonic uptime.

use lichen_link::{
    evaluate_epoch_floor, DioTimeOption, DioTimeStratum, MonotonicUptime, DIO_TIME_OPTION_TYPE,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/packets-timing.json");

fn vectors() -> Vec<Value> {
    let document: Value =
        serde_json::from_str(VECTORS_JSON).expect("packets-timing vectors must parse");
    document["vectors"]
        .as_array()
        .expect("vectors array")
        .clone()
}

fn named(name: &str) -> Value {
    vectors()
        .into_iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("missing vector {name}"))
}

#[test]
fn epoch_floor_matches_canonical_timing_vector() {
    let vector = named("time_sync_epoch_floor");
    for case in vector["cases"].as_array().expect("cases") {
        let build = case["build_epoch"].as_u64().unwrap() as u32;
        let action = case["action"].as_str().unwrap();
        let expected_floor = case["expected_floor"].as_u64().unwrap() as u32;
        let expected_status = case["status"].as_str().unwrap();
        let result = match action {
            "firmware_only" => evaluate_epoch_floor(build, None, false, 0).expect("build"),
            "raw_integer" => {
                let provision = case["provision_epoch"].as_u64().unwrap() as u32;
                evaluate_epoch_floor(build, Some(provision), false, 0).expect("build")
            }
            "authenticated_provision" => {
                let provision = case["provision_epoch"].as_u64().unwrap() as u32;
                let lead = case["max_provision_lead_s"].as_u64().unwrap() as u32;
                evaluate_epoch_floor(build, Some(provision), true, lead).expect("build")
            }
            other => panic!("unknown epoch-floor action {other}"),
        };
        assert_eq!(result.floor(), expected_floor, "{action}");
        assert_eq!(
            result.provision_status().as_str(),
            expected_status,
            "{action}"
        );
        assert!(result.accepts(expected_floor), "{action}");
        if expected_floor > 0 {
            assert!(!result.accepts(expected_floor - 1), "{action}");
        }
    }
}

#[test]
fn dio_time_option_matches_canonical_timing_vector() {
    let vector = named("dio_time_option");
    assert_eq!(
        vector["option_type"].as_u64().unwrap(),
        u64::from(DIO_TIME_OPTION_TYPE)
    );
    let encoded = hex_decode(vector["encoded_hex"].as_str().unwrap());
    let opt = DioTimeOption::decode(&encoded).expect("encoded option");
    assert_eq!(
        opt.stratum().wire(),
        vector["decoded_stratum"].as_u64().unwrap() as u8
    );
    assert_eq!(
        opt.timestamp(),
        vector["decoded_timestamp"].as_u64().unwrap() as u32
    );
    assert_eq!(opt.encode().as_slice(), encoded.as_slice());
    assert_eq!(opt.stratum(), DioTimeStratum::Nts);

    let no_sync = hex_decode(vector["no_sync_encoded_hex"].as_str().unwrap());
    let opt = DioTimeOption::decode(&no_sync).expect("no-sync option");
    assert_eq!(opt.stratum(), DioTimeStratum::NoSync);
    assert_eq!(opt.timestamp(), 0);
    assert_eq!(opt.encode().as_slice(), no_sync.as_slice());
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn monotonic_uptime_matches_canonical_timing_vector() {
    let vector = named("monotonic_uptime_sequences");
    for case in vector["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().unwrap();
        let observations = case["observations"].as_array().unwrap();
        let expected = case["expected_acceptance"].as_array().unwrap();
        let mut clock = MonotonicUptime::new();
        for (obs, accept) in observations.iter().zip(expected.iter()) {
            let ticks = obs.as_u64().unwrap();
            let ok = clock.observe(ticks).is_ok();
            assert_eq!(ok, accept.as_bool().unwrap(), "{name} ticks={ticks}");
        }
    }
}
