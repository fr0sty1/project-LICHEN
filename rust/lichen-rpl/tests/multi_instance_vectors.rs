//! Test vectors for RPL Multi-Instance Coordination (GCP-5).
//!
//! Validates the Rust implementation against `test/vectors/rpl_multi_instance.json`
//! for cross-validation with the Python oracle.

use lichen_rpl::message::Dio;
use lichen_rpl::multi_instance::{
    iid_compare_int, resolve_slot_conflict, validate_rpl_instance_id, DaoBackboneBridge, DaoTarget,
    DaoTransit, GatewayInfo, MultiRootCoordinator,
};
use serde_json::Value;
use std::net::Ipv6Addr;
use std::str::FromStr;

const VECTORS: &str = include_str!("../../../test/vectors/rpl_multi_instance.json");

/// Parse IPv6 address string to byte array.
fn ipv6(s: &str) -> [u8; 16] {
    Ipv6Addr::from_str(s).expect("valid IPv6").octets()
}

/// Get a vector by name from the loaded JSON.
fn get_vector(name: &str) -> Value {
    let root: Value = serde_json::from_str(VECTORS).expect("valid JSON");
    root["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("vector '{}' not found", name))
}

#[test]
fn vector_multi_root_basic() {
    let vec = get_vector("multi_root_basic");

    let coord = MultiRootCoordinator::new(vec["rpl_instance_id"].as_u64().unwrap() as u8);

    // Add gateways
    for gw in vec["gateways"].as_array().unwrap() {
        let iid = ipv6(gw["iid"].as_str().unwrap());
        let has_gps = gw["has_gps"].as_bool().unwrap_or(false);
        coord.add_peer(GatewayInfo::new(iid).with_gps(has_gps));
    }

    // Verify time master election
    let master = coord.elect_time_master().expect("should have master");
    let expected = ipv6(vec["expected_time_master"].as_str().unwrap());
    assert_eq!(master.iid, expected);
}

#[test]
fn vector_slot_conflict_iid_resolution() {
    let vec = get_vector("slot_conflict_iid_resolution");

    let claimant_a = ipv6(vec["claimant_a"].as_str().unwrap());
    let claimant_b = ipv6(vec["claimant_b"].as_str().unwrap());
    let expected_winner = ipv6(vec["expected_winner"].as_str().unwrap());

    let winner = resolve_slot_conflict(&claimant_a, &claimant_b);
    assert_eq!(winner, expected_winner);
}

#[test]
fn vector_dio_validation_same_instance() {
    let vec = get_vector("dio_validation_same_instance");

    let rpl_instance_id = vec["rpl_instance_id"].as_u64().unwrap() as u8;
    let dio_instance_id = vec["dio_instance_id"].as_u64().unwrap() as u8;
    let dio_rank = vec["dio_rank"].as_u64().unwrap() as u16;
    let expected_valid = vec["expected_valid"].as_bool().unwrap();

    let coord = MultiRootCoordinator::new(rpl_instance_id);
    let dio = Dio {
        rpl_instance_id: dio_instance_id,
        version: 1,
        rank: dio_rank,
        grounded: true,
        mode_of_operation: 1,
        preference: 0,
        dtsn: 0,
        flags: 0,
        dodag_id: [0; 16],
    };

    let result = coord.validate_dio(&dio);
    assert_eq!(result.is_valid, expected_valid);
}

#[test]
fn vector_dio_validation_different_instance() {
    let vec = get_vector("dio_validation_different_instance");

    let rpl_instance_id = vec["rpl_instance_id"].as_u64().unwrap() as u8;
    let dio_instance_id = vec["dio_instance_id"].as_u64().unwrap() as u8;
    let dio_rank = vec["dio_rank"].as_u64().unwrap() as u16;
    let expected_valid = vec["expected_valid"].as_bool().unwrap();

    let coord = MultiRootCoordinator::new(rpl_instance_id);
    let dio = Dio {
        rpl_instance_id: dio_instance_id,
        version: 1,
        rank: dio_rank,
        grounded: true,
        mode_of_operation: 1,
        preference: 0,
        dtsn: 0,
        flags: 0,
        dodag_id: [0; 16],
    };

    let result = coord.validate_dio(&dio);
    assert_eq!(result.is_valid, expected_valid);
    assert!(result.reason.contains("mismatch"));
}

#[test]
fn vector_dodag_version_lollipop() {
    let vec = get_vector("dodag_version_lollipop");

    let initial_version = vec["initial_version"].as_u64().unwrap() as u8;
    let expected_versions: Vec<u8> = vec["expected_versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let coord = MultiRootCoordinator::new(0);
    coord.set_dodag_version(initial_version);

    for expected in expected_versions {
        let actual = coord.increment_dodag_version();
        assert_eq!(actual, expected);
    }
}

#[test]
fn vector_three_gateway_federation() {
    let vec = get_vector("three_gateway_federation");

    let coord = MultiRootCoordinator::new(vec["rpl_instance_id"].as_u64().unwrap() as u8);

    for gw in vec["gateways"].as_array().unwrap() {
        let iid = ipv6(gw["iid"].as_str().unwrap());
        let routes = gw["routes_learned"].as_u64().unwrap() as u32;
        coord.add_peer(GatewayInfo::new(iid).with_routes_learned(routes));
    }

    let master = coord.elect_time_master().expect("should have master");
    let expected_master = ipv6(vec["expected_time_master"].as_str().unwrap());
    assert_eq!(master.iid, expected_master);

    let total = vec["total_aggregated_routes"].as_u64().unwrap() as u32;
    assert_eq!(coord.total_aggregated_routes(), total);
}

#[test]
fn vector_gateway_role_determination() {
    let vec = get_vector("gateway_role_determination");

    for case in vec["test_cases"].as_array().unwrap() {
        let scenario = case["scenario"].as_str().unwrap();
        let local_iid = ipv6(case["local_gateway"].as_str().unwrap());
        let peers: Vec<[u8; 16]> = case["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| ipv6(p.as_str().unwrap()))
            .collect();
        let expected_role = case["expected_role"].as_str().unwrap();

        let mut coord = MultiRootCoordinator::new(0);
        coord.set_local_gateway(GatewayInfo::new(local_iid));
        for peer_iid in peers {
            coord.add_peer(GatewayInfo::new(peer_iid));
        }

        let role = coord.get_role();
        let role_str = role.as_str();
        assert_eq!(role_str, expected_role, "scenario: {}", scenario);
    }
}

#[test]
fn vector_rpl_instance_id_validation() {
    let vec = get_vector("rpl_instance_id_validation");

    // Valid IDs
    for id in vec["valid_ids"].as_array().unwrap() {
        let id = id.as_i64().unwrap() as i32;
        assert!(
            validate_rpl_instance_id(id).is_ok(),
            "id {} should be valid",
            id
        );
    }

    // Invalid IDs
    for id in vec["invalid_ids"].as_array().unwrap() {
        let id = id.as_i64().unwrap() as i32;
        assert!(
            validate_rpl_instance_id(id).is_err(),
            "id {} should be invalid",
            id
        );
    }
}

#[test]
fn vector_dao_backbone_propagation() {
    let vec = get_vector("dao_backbone_propagation");

    let origin = ipv6(vec["origin_gateway"].as_str().unwrap());
    let rpl_instance_id = vec["rpl_instance_id"].as_u64().unwrap() as u8;
    let dao_sequence = vec["dao_sequence"].as_u64().unwrap() as u8;

    let mut bridge = DaoBackboneBridge::new(rpl_instance_id);
    bridge.set_local_gateway_iid(origin);

    let targets: Vec<DaoTarget> = vec["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| DaoTarget {
            target: ipv6(t["target"].as_str().unwrap()),
            prefix_length: t["prefix_length"].as_u64().unwrap() as u8,
        })
        .collect();

    let transit: Vec<DaoTransit> = vec["transit"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| DaoTransit {
            path_sequence: t["path_sequence"].as_u64().unwrap() as u8,
            path_lifetime: t["path_lifetime"].as_u64().unwrap() as u8,
            path_control: t["path_control"].as_u64().unwrap() as u8,
            parent: t["parent"].as_str().map(ipv6),
        })
        .collect();

    let message = bridge
        .create_backbone_message(dao_sequence, targets, transit, 0.0)
        .expect("should create message");

    assert_eq!(message.origin_gateway, origin);
    assert_eq!(message.rpl_instance_id, rpl_instance_id);
    assert_eq!(message.dao_sequence, dao_sequence);
}

#[test]
fn vector_dao_target_aggregation() {
    let vec = get_vector("dao_target_aggregation");

    let origin = ipv6(vec["origin_gateway"].as_str().unwrap());
    let dao_sequence = vec["dao_sequence"].as_u64().unwrap() as u8;
    let target_count = vec["target_count"].as_u64().unwrap() as usize;

    let mut bridge = DaoBackboneBridge::new(0);
    bridge.set_local_gateway_iid(origin);

    let targets: Vec<DaoTarget> = vec["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| DaoTarget {
            target: ipv6(t["target"].as_str().unwrap()),
            prefix_length: t["prefix_length"].as_u64().unwrap() as u8,
        })
        .collect();

    let message = bridge
        .create_backbone_message(dao_sequence, targets, vec![], 0.0)
        .expect("should create message");

    assert_eq!(message.targets.len(), target_count);
}

#[test]
fn vector_iid_comparison_bytes() {
    let vec = get_vector("iid_comparison_bytes");

    for cmp in vec["comparisons"].as_array().unwrap() {
        let a = ipv6(cmp["a"].as_str().unwrap());
        let b = ipv6(cmp["b"].as_str().unwrap());
        let expected_result = cmp["result"].as_i64().unwrap() as i32;
        let expected_winner = cmp["winner"].as_str().unwrap();

        let result = iid_compare_int(&a, &b);
        assert_eq!(result, expected_result, "comparing {:?} vs {:?}", a, b);

        if expected_winner != "either" {
            let winner = resolve_slot_conflict(&a, &b);
            assert_eq!(winner, ipv6(expected_winner));
        }
    }
}
