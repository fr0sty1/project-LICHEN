// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Shared TDMA clock vectors (`ccp_tdma.json`, `ccp7_holdover.json`).

use lichen_link::{
    beacon_delta_ms, correction_ms, drift_bound, drift_ppm, guard_sufficient, holdover_expired,
    in_guard, tx_allowed,
};
use serde_json::Value;

fn load(path: &str) -> Value {
    serde_json::from_str(path).expect("vectors must parse")
}

#[test]
fn ccp_tdma_guard_and_drift_vectors() {
    let document: Value = load(include_str!("../../../test/vectors/ccp_tdma.json"));
    for vector in document["vectors"].as_array().unwrap() {
        match vector["name"].as_str().unwrap() {
            "data_window_last_millisecond" | "guard_boundary_start" => {
                let start = vector["slot_start_ms"].as_u64().unwrap();
                let current = vector["current_ms"].as_u64().unwrap();
                let duration = vector["slot_duration_ms"].as_u64().unwrap();
                let guard = vector["guard_ms"].as_u64().unwrap();
                assert_eq!(
                    in_guard(start, current, duration, guard),
                    vector["expected_in_guard"].as_bool().unwrap(),
                    "{}",
                    vector["name"]
                );
                assert_eq!(
                    tx_allowed(start, current, duration, guard),
                    vector["expected_tx_allowed"].as_bool().unwrap(),
                    "{}",
                    vector["name"]
                );
            }
            "drift_compensation" => {
                let local = vector["local_beacon_rx_ms"].as_i64().unwrap();
                let expected = vector["expected_beacon_ms"].as_i64().unwrap();
                let correction = vector["expected_correction_ms"].as_i64().unwrap();
                assert_eq!(beacon_delta_ms(local, expected), correction);
                assert_eq!(vector["drift_ppm"].as_i64().unwrap(), 10);
            }
            _ => {}
        }
    }
}

#[test]
fn ccp7_holdover_vectors() {
    let document: Value = load(include_str!("../../../test/vectors/ccp7_holdover.json"));
    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        match vector["category"].as_str().unwrap() {
            "drift_bound" => {
                let bound = drift_bound(
                    vector["b0"].as_u64().unwrap(),
                    vector["rho"].as_u64().unwrap(),
                    vector["h"].as_u64().unwrap(),
                );
                assert_eq!(bound, vector["expected_bound"].as_u64().unwrap(), "{name}");
            }
            "guard_budget" => {
                let need = vector["b_i"].as_u64().unwrap()
                    + vector["b_j"].as_u64().unwrap()
                    + vector["j_i"].as_u64().unwrap()
                    + vector["j_j"].as_u64().unwrap()
                    + vector["p"].as_u64().unwrap()
                    + vector["m"].as_u64().unwrap();
                assert_eq!(need, vector["need"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    guard_sufficient(
                        vector["guard"].as_u64().unwrap(),
                        vector["b_i"].as_u64().unwrap(),
                        vector["b_j"].as_u64().unwrap(),
                        vector["j_i"].as_u64().unwrap(),
                        vector["j_j"].as_u64().unwrap(),
                        vector["p"].as_u64().unwrap(),
                        vector["m"].as_u64().unwrap(),
                    ),
                    vector["expected_sufficient"].as_bool().unwrap(),
                    "{name}"
                );
            }
            "holdover" => {
                assert_eq!(
                    holdover_expired(
                        vector["measured_drift_ppm"].as_i64().unwrap(),
                        vector["guard_ppm"].as_u64().unwrap(),
                    ),
                    vector["expected_expired"].as_bool().unwrap(),
                    "{name}"
                );
            }
            "drift_ppm" => {
                let ppm = drift_ppm(
                    vector["delta_ms"].as_i64().unwrap(),
                    vector["beacon_interval_ms"].as_u64().unwrap(),
                )
                .expect("interval");
                assert_eq!(ppm, vector["expected_ppm"].as_i64().unwrap(), "{name}");
                assert_eq!(
                    correction_ms(ppm, vector["future_delta_ms"].as_i64().unwrap()),
                    vector["expected_correction_ms"].as_i64().unwrap(),
                    "{name}"
                );
            }
            other => panic!("unknown category {other} in {name}"),
        }
    }
}
