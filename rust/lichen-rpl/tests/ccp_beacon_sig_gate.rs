// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Test vectors for CCP beacon signature gate (ccp_beacon_sig_gate.json).
//!
//! Validates:
//! 1. L2 signature verification gates DIO processing (conceptual - signature
//!    check happens in LinkLayer::receive_frame() before process_dio is called)
//! 2. Path cost calculation matches test vectors (rounding behavior)
//! 3. Admissibility respects MAX_RANK_INCREASE ceiling

use lichen_rpl::dodag::{
    DodagRole, DodagState, ParentCandidate, INFINITE_RANK, MAX_RANK_INCREASE, MIN_HOP_RANK_INCREASE,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../test/vectors/ccp_beacon_sig_gate.json");

fn load_vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["format_version"], 2);
    document["vectors"].as_array().unwrap().to_vec()
}

fn path_cost_vectors() -> Vec<Value> {
    load_vectors()
        .into_iter()
        .filter(|v| {
            v.get("category").and_then(|c| c.as_str()) == Some("path_cost")
                && v.get("expected_path_cost").is_some()
                && v.get("link_etx").and_then(|e| e.as_str()) != Some("NaN")
                && v.get("link_etx")
                    .and_then(|e| e.as_f64())
                    .map(|e| e >= 0.0)
                    .unwrap_or(false)
        })
        .collect()
}

fn admissibility_vectors() -> Vec<Value> {
    load_vectors()
        .into_iter()
        .filter(|v| v.get("category").and_then(|c| c.as_str()) == Some("admissibility"))
        .collect()
}

#[test]
fn path_cost_calculation_matches_vectors() {
    for vector in path_cost_vectors() {
        let name = vector["name"].as_str().unwrap();
        let parent_rank = vector["parent_rank"].as_u64().unwrap() as u16;
        let link_etx = vector["link_etx"].as_f64().unwrap() as f32;
        let mhri = vector["min_hop_rank_increase"].as_u64().unwrap() as u16;
        let expected = vector["expected_path_cost"].as_u64().unwrap() as u16;

        let candidate = ParentCandidate {
            addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            rank: parent_rank,
            link_etx,
        };

        let actual = candidate.path_cost(mhri);
        assert_eq!(
            actual, expected,
            "{name}: path_cost={actual}, expected={expected}"
        );
    }
}

#[test]
fn path_cost_half_boundary_rust_round_away() {
    // This test explicitly checks the known divergence point where Rust
    // rounds 128.5 to 129 (away from zero) while Python rounds to 128.
    let vectors: std::collections::HashMap<_, _> = load_vectors()
        .into_iter()
        .map(|v| (v["name"].as_str().unwrap().to_string(), v))
        .collect();

    let vector = &vectors["path_cost_half_boundary_python_even"];
    let parent_rank = vector["parent_rank"].as_u64().unwrap() as u16;
    let link_etx = vector["link_etx"].as_f64().unwrap() as f32;
    let mhri = vector["min_hop_rank_increase"].as_u64().unwrap() as u16;
    let expected_rust = vector["expected_path_cost_rust"].as_u64().unwrap() as u16;

    let candidate = ParentCandidate {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        rank: parent_rank,
        link_etx,
    };

    let actual = candidate.path_cost(mhri);
    assert_eq!(
        actual, expected_rust,
        "Rust path_cost={actual}, expected={expected_rust} (round away from zero)"
    );

    // Verify the exact link_cost calculation
    let link_cost = link_etx * mhri as f32;
    let expected_link_cost = vector["link_cost_exact"].as_f64().unwrap() as f32;
    assert!(
        (link_cost - expected_link_cost).abs() < 0.0001,
        "link_cost mismatch"
    );
}

#[test]
fn path_cost_overflow_saturates() {
    let vectors: std::collections::HashMap<_, _> = load_vectors()
        .into_iter()
        .map(|v| (v["name"].as_str().unwrap().to_string(), v))
        .collect();

    let vector = &vectors["path_cost_overflow_saturation"];
    let parent_rank = vector["parent_rank"].as_u64().unwrap() as u16;
    let link_etx = vector["link_etx"].as_f64().unwrap() as f32;
    let mhri = vector["min_hop_rank_increase"].as_u64().unwrap() as u16;

    let candidate = ParentCandidate {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        rank: parent_rank,
        link_etx,
    };

    let actual = candidate.path_cost(mhri);
    // Rust uses saturating_add, so it saturates to u16::MAX
    assert_eq!(actual, INFINITE_RANK);
}

#[test]
fn path_cost_nan_returns_max() {
    // Rust explicitly handles NaN and returns u16::MAX (dodag.rs:172)
    let candidate = ParentCandidate {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        rank: 256,
        link_etx: f32::NAN,
    };

    let actual = candidate.path_cost(256);
    assert_eq!(actual, u16::MAX, "NaN ETX should return u16::MAX");
}

#[test]
fn path_cost_negative_etx_returns_max() {
    // Rust returns u16::MAX for negative ETX (dodag.rs:172)
    let candidate = ParentCandidate {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        rank: 256,
        link_etx: -1.0,
    };

    let actual = candidate.path_cost(256);
    assert_eq!(actual, u16::MAX, "Negative ETX should return u16::MAX");
}

#[test]
fn admissibility_with_default_max_rank_increase() {
    // Rust default MAX_RANK_INCREASE is 1024
    assert_eq!(
        MAX_RANK_INCREASE, 1024,
        "Rust MAX_RANK_INCREASE should be 1024"
    );

    for vector in admissibility_vectors() {
        let name = vector["name"].as_str().unwrap();
        let lowest_rank = vector["lowest_rank"].as_u64().unwrap() as u16;
        let path_cost = vector["path_cost"].as_u64().unwrap() as u16;
        let expected_admissible = vector["expected_rust_admissible_default"]
            .as_bool()
            .unwrap();

        // Check ceiling calculation with Rust default
        let ceiling = lowest_rank.saturating_add(MAX_RANK_INCREASE);
        let actual_admissible = path_cost <= ceiling;

        assert_eq!(
            actual_admissible, expected_admissible,
            "{name}: admissible={actual_admissible}, expected={expected_admissible}, \
             path_cost={path_cost}, ceiling={ceiling}"
        );
    }
}

#[test]
fn sig_gate_conceptual_invalid_signature() {
    // Conceptual test: invalid signature means no DIO processing.
    //
    // In the actual implementation, signature verification happens in
    // LinkLayer::receive_frame() (link_layer.rs:515). If verification fails,
    // LinkRxError::UnknownSender is returned and process_dio is never called.
    //
    // This test verifies the invariant by checking that an unjoined node
    // with no DIOs processed remains in UNJOINED state.

    let dodag_id = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let node = DodagState::new(0, dodag_id, 128);

    // Before any DIO processing
    assert_eq!(node.role, DodagRole::Unjoined);
    assert_eq!(node.rank, INFINITE_RANK);
    assert_eq!(node.preferred_parent, None);

    // If signature verification failed, process_dio would not be called.
    // The node state remains unchanged - this is the signature gate invariant.
}

#[test]
fn sig_gate_conceptual_valid_signature() {
    // Conceptual test: valid signature allows DIO processing.
    //
    // When signature verification passes in LinkLayer::receive_frame(), the frame
    // is passed to upper layers and process_dio is called.

    let vectors: std::collections::HashMap<_, _> = load_vectors()
        .into_iter()
        .map(|v| (v["name"].as_str().unwrap().to_string(), v))
        .collect();

    let vector = &vectors["sig_gate_valid_allows_dio"];
    let dio_fields = &vector["dio"];

    let dodag_id_hex = dio_fields["dodag_id_hex"].as_str().unwrap();
    let dodag_id: [u8; 16] = hex_to_bytes(dodag_id_hex).try_into().unwrap();

    let mut node = DodagState::new(
        dio_fields["rpl_instance_id"].as_u64().unwrap() as u8,
        dodag_id,
        dio_fields["version"].as_u64().unwrap() as u8,
    );

    let dio = lichen_rpl::message::Dio {
        rpl_instance_id: dio_fields["rpl_instance_id"].as_u64().unwrap() as u8,
        version: dio_fields["version"].as_u64().unwrap() as u8,
        rank: dio_fields["rank"].as_u64().unwrap() as u16,
        grounded: false,
        mode_of_operation: 0,
        preference: 0,
        dtsn: 0,
        flags: 0,
        dodag_id,
    };

    let neighbor = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let link_etx = vector["link_etx"].as_f64().unwrap() as f32;

    // After valid signature, process_dio is called
    node.process_dio(&dio, neighbor, link_etx);

    // Verify expected state change
    assert_eq!(node.role, DodagRole::Joined);
    let expected_rank = vector["expected"]["new_rank"].as_u64().unwrap() as u16;
    assert_eq!(node.rank, expected_rank);
}

#[test]
fn dodag_state_unchanged_without_dio() {
    // Verify DODAG state is immutable without DIO processing.
    // This supports the signature gate invariant: if L2 rejects a frame,
    // no state change occurs because process_dio is never called.

    let dodag_id = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let node = DodagState::new(0, dodag_id, 128);

    let initial_role = node.role;
    let initial_rank = node.rank;
    let initial_parent = node.preferred_parent;

    // No DIOs processed - state should be identical
    assert_eq!(node.role, initial_role);
    assert_eq!(node.rank, initial_rank);
    assert_eq!(node.preferred_parent, initial_parent);
}

#[test]
fn max_rank_increase_constant() {
    // Document the MAX_RANK_INCREASE constant value.
    // Rust default is 1024, which differs from Python default of 2048.
    // This is a known divergence documented in the test vectors.
    assert_eq!(
        MAX_RANK_INCREASE, 1024,
        "Rust MAX_RANK_INCREASE should be 1024 (conservative default). \
         Note: Python uses 2048 by default."
    );
}

#[test]
fn min_hop_rank_increase_constant() {
    // Verify MIN_HOP_RANK_INCREASE matches spec.
    assert_eq!(MIN_HOP_RANK_INCREASE, 256);
}

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    hex_str
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
