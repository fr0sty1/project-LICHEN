// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Constrained-node time vectors (spec 09 14.6).

use lichen_link::{consumer_timestamp, ConsumerTimestamp, TimeSourceClass, WallClockValidity};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/constrained_node_time.json");

#[test]
fn constrained_node_time_vectors() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    for case in document["vectors"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut clock = WallClockValidity::new();
        if case["wall_clock_valid"].as_bool().unwrap() {
            let source =
                TimeSourceClass::from_str(case["source"].as_str().unwrap()).expect("source class");
            clock = clock.establish(source).expect("establish");
        }
        let unix = case["unix"].as_u64().unwrap() as u32;
        let ticks = case["uptime_ticks"].as_u64().unwrap();
        let stamp = consumer_timestamp(clock, unix, ticks);
        match case["expected_kind"].as_str().unwrap() {
            "monotonic" => {
                assert_eq!(
                    stamp,
                    ConsumerTimestamp::MonotonicFallback {
                        ticks: case["expected_ticks"].as_u64().unwrap()
                    },
                    "{name}"
                );
                assert!(!stamp.wall_clock_valid(), "{name}");
            }
            "unix" => {
                let source = TimeSourceClass::from_str(case["expected_source"].as_str().unwrap())
                    .expect("expected source");
                assert_eq!(
                    stamp,
                    ConsumerTimestamp::UnixSeconds {
                        unix: case["expected_unix"].as_u64().unwrap() as u32,
                        source,
                    },
                    "{name}"
                );
                assert!(stamp.wall_clock_valid(), "{name}");
            }
            other => panic!("unknown kind {other} in {name}"),
        }
    }
}
