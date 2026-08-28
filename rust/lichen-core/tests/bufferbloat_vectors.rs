// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! B.2 Design Principles vs shared bufferbloat vectors.
//!
//! Independent oracle: `test/vectors/tx_queue_{bounded,expiry,priority}.json`
//! and `test/vectors/forwarding_buffer.json` (spec/appendix-bufferbloat.md).
//! Does not derive expected values from lichen-core.

use lichen_core::tx_queue::{
    TxPriority, DEADLINE_ACK_MS, DEADLINE_BULK_MS, DEADLINE_NORMAL_MS, DEADLINE_ROUTING_MS,
    DEADLINE_SOS_MS, DEADLINE_URGENT_MS, TX_QUEUE_CAPACITY,
};
use serde_json::Value;

const BOUNDED_JSON: &str = include_str!("../../../test/vectors/tx_queue_bounded.json");
const EXPIRY_JSON: &str = include_str!("../../../test/vectors/tx_queue_expiry.json");
const PRIORITY_JSON: &str = include_str!("../../../test/vectors/tx_queue_priority.json");
const FORWARD_JSON: &str = include_str!("../../../test/vectors/forwarding_buffer.json");

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("vector json")
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing {key}"))
}

#[test]
fn tx_queue_capacity_matches_bounded_vector() {
    let document = parse(BOUNDED_JSON);
    let case = document["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"] == "capacity_default_4")
        .expect("capacity_default_4");
    assert_eq!(
        TX_QUEUE_CAPACITY as u64,
        u64_field(&case["expected"], "capacity")
    );
}

#[test]
fn deadline_constants_match_expiry_vector() {
    let constants = &parse(EXPIRY_JSON)["constants"];
    assert_eq!(DEADLINE_SOS_MS, u64_field(constants, "DEADLINE_SOS_MS"));
    assert_eq!(
        DEADLINE_ROUTING_MS,
        u64_field(constants, "DEADLINE_ROUTING_MS")
    );
    assert_eq!(DEADLINE_ACK_MS, u64_field(constants, "DEADLINE_ACK_MS"));
    assert_eq!(
        DEADLINE_URGENT_MS,
        u64_field(constants, "DEADLINE_URGENT_MS")
    );
    assert_eq!(
        DEADLINE_NORMAL_MS,
        u64_field(constants, "DEADLINE_NORMAL_MS")
    );
    assert_eq!(DEADLINE_BULK_MS, u64_field(constants, "DEADLINE_BULK_MS"));
    assert_eq!(TX_QUEUE_CAPACITY as u64, u64_field(constants, "CAPACITY"));
}

#[test]
fn priority_discriminants_match_priority_vector() {
    let constants = &parse(PRIORITY_JSON)["constants"];
    assert_eq!(TxPriority::Sos as u64, u64_field(constants, "PRIORITY_SOS"));
    assert_eq!(
        TxPriority::Routing as u64,
        u64_field(constants, "PRIORITY_ROUTING")
    );
    assert_eq!(
        TxPriority::Routing as u64,
        u64_field(constants, "PRIORITY_ACK")
    );
    assert_eq!(
        TxPriority::Urgent as u64,
        u64_field(constants, "PRIORITY_URGENT")
    );
    assert_eq!(
        TxPriority::Normal as u64,
        u64_field(constants, "PRIORITY_NORMAL")
    );
    assert_eq!(
        TxPriority::Bulk as u64,
        u64_field(constants, "PRIORITY_BULK")
    );
    assert_eq!(TX_QUEUE_CAPACITY as u64, u64_field(constants, "CAPACITY"));
}

#[test]
fn forwarding_buffer_oracle_matches_spec_b2() {
    let oracle = &parse(FORWARD_JSON)["oracle"];
    assert_eq!(u64_field(oracle, "max_forwarding_sources"), 8);
    assert_eq!(u64_field(oracle, "max_packets_per_source"), 2);
    assert_eq!(u64_field(oracle, "total_capacity"), 16);
}

const CONGESTION_JSON: &str = include_str!("../../../test/vectors/bufferbloat_congestion.json");

#[test]
fn b5_congestion_vectors_match_spec_testing_table() {
    let document = parse(CONGESTION_JSON);
    let mut names = Vec::new();
    for case in document["vectors"].as_array().expect("vectors") {
        let name = case["name"].as_str().unwrap();
        names.push(name);
        match name {
            "queue_full" => {
                assert_eq!(u64_field(case, "tx_capacity"), TX_QUEUE_CAPACITY as u64);
                assert_eq!(case["expected"], "ENOBUFS");
            }
            "deadline_expiry" => {
                assert_eq!(u64_field(case, "routing_deadline_ms"), DEADLINE_ROUTING_MS);
                assert_eq!(u64_field(case, "ack_deadline_ms"), DEADLINE_ACK_MS);
                assert_eq!(u64_field(case, "app_deadline_ms"), DEADLINE_NORMAL_MS);
                assert_eq!(case["expected"], "drop_before_tx");
            }
            "priority_preemption" => {
                assert_eq!(case["expected"], "higher_preempts_lower");
            }
            "multihop_latency" => {
                assert_eq!(case["expected"], "bounded_e2e_delay");
            }
            "fairness" => {
                assert_eq!(u64_field(case, "max_packets_per_source"), 2);
                assert_eq!(u64_field(case, "max_forwarding_sources"), 8);
                assert_eq!(case["expected"], "nack_when_source_full");
            }
            other => panic!("unexpected congestion vector {other}"),
        }
    }
    assert_eq!(
        names,
        [
            "queue_full",
            "deadline_expiry",
            "priority_preemption",
            "multihop_latency",
            "fairness"
        ]
    );
}
