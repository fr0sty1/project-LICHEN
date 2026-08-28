// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Test vector consumer for node_handoff.json (GCP-7).
//!
//! Validates handoff protocol messages against spec test vectors.

use lichen_gateway::handoff::{
    FreshnessState, HandoffError, HandoffRejectReason, HandoffRequest, HandoffResponse, OscoreState,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/node_handoff.json");

fn parse_ipv6_bytes(hex: &str) -> [u8; 16] {
    let bytes = hex::decode(hex).expect("valid hex");
    bytes.try_into().expect("16 bytes for IPv6")
}

#[test]
fn handoff_request_minimal_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_minimal")
        .expect("vector exists");

    let addr = parse_ipv6_bytes(case["node_address_bytes"].as_str().unwrap());
    let timestamp = case["timestamp"].as_i64().unwrap();
    let request = HandoffRequest::new(addr, timestamp);

    // Verify roundtrip
    let encoded = request.encode();
    let decoded = HandoffRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.node_address, addr);
    assert_eq!(decoded.timestamp, timestamp);
    assert!(decoded.rssi.is_none());
}

#[test]
fn handoff_request_with_rssi_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_with_rssi")
        .expect("vector exists");

    let addr = parse_ipv6_bytes(case["node_address_bytes"].as_str().unwrap());
    let timestamp = case["timestamp"].as_i64().unwrap();
    let rssi = case["rssi"].as_i64().unwrap() as i32;
    let request = HandoffRequest::with_rssi(addr, timestamp, rssi);

    let encoded = request.encode();
    let decoded = HandoffRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.node_address, addr);
    assert_eq!(decoded.timestamp, timestamp);
    assert_eq!(decoded.rssi, Some(rssi));
}

#[test]
fn handoff_request_roundtrip_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_roundtrip")
        .expect("vector exists");

    let input = &case["input"];
    let expected = &case["expected_decoded"];

    // Parse address from the string format (e.g., "200::dead:beef:cafe:babe")
    let addr_str = input["node_address"].as_str().unwrap();
    let addr: std::net::Ipv6Addr = addr_str.parse().unwrap();
    let addr_bytes: [u8; 16] = addr.octets();

    let timestamp = input["timestamp"].as_i64().unwrap();
    let rssi = input["rssi"].as_i64().unwrap() as i32;
    let request = HandoffRequest::with_rssi(addr_bytes, timestamp, rssi);

    let encoded = request.encode();
    let decoded = HandoffRequest::decode(&encoded).unwrap();

    // Verify matches expected_decoded
    let expected_addr: std::net::Ipv6Addr =
        expected["node_address"].as_str().unwrap().parse().unwrap();
    assert_eq!(decoded.node_address, expected_addr.octets());
    assert_eq!(decoded.timestamp, expected["timestamp"].as_i64().unwrap());
    assert_eq!(
        decoded.rssi,
        Some(expected["rssi"].as_i64().unwrap() as i32)
    );
}

#[test]
fn handoff_response_error_vectors() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    // Test all error response vectors
    let error_cases = [
        (
            "handoff_response_error_not_found",
            HandoffRejectReason::NodeNotFound,
        ),
        ("handoff_response_error_busy", HandoffRejectReason::NodeBusy),
        (
            "handoff_response_error_auth_failed",
            HandoffRejectReason::AuthFailed,
        ),
        (
            "handoff_response_error_malformed",
            HandoffRejectReason::MalformedRequest,
        ),
        (
            "handoff_response_error_rate_limited",
            HandoffRejectReason::RateLimited,
        ),
    ];

    for (name, expected_status) in error_cases {
        let case = vectors
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("vector {name} exists"));

        let status = case["status"].as_u64().unwrap() as u8;
        let message = case["message"].as_str().unwrap();

        // Create error response and verify roundtrip
        let response = HandoffResponse::error(expected_status, message);
        assert_eq!(response.status as u8, status);

        let encoded = response.encode();
        let decoded = HandoffResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.status, expected_status);
        assert_eq!(decoded.message, message);
    }
}

#[test]
fn handoff_response_success_minimal_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_response_success_minimal")
        .expect("vector exists");

    let addr_str = case["node_address"].as_str().unwrap();
    let addr: std::net::Ipv6Addr = addr_str.parse().unwrap();
    let dao_seq = case["dao_sequence"].as_u64().unwrap() as u32;
    let path_seq = case["path_sequence"].as_u64().unwrap() as u32;

    let response = HandoffResponse::success(addr.octets(), dao_seq, path_seq);

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    assert_eq!(decoded.status, HandoffRejectReason::Success);
    assert_eq!(decoded.node_address, Some(addr.octets()));
    assert_eq!(decoded.dao_sequence, Some(dao_seq));
    assert_eq!(decoded.path_sequence, Some(path_seq));
}

#[test]
fn handoff_response_success_full_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_response_success_full")
        .expect("vector exists");

    let addr_str = case["node_address"].as_str().unwrap();
    let addr: std::net::Ipv6Addr = addr_str.parse().unwrap();
    let dao_seq = case["dao_sequence"].as_u64().unwrap() as u32;
    let path_seq = case["path_sequence"].as_u64().unwrap() as u32;

    // Parse OSCORE state from vector
    let oscore_json = &case["oscore_state"];
    let oscore = OscoreState {
        master_secret: hex::decode(oscore_json["master_secret"].as_str().unwrap()).unwrap(),
        master_salt: Vec::new(), // Not in this vector's structure
        sender_id: Vec::new(),
        recipient_id: Vec::new(),
        algorithm: 10,
        hashfun: "SHA-256".into(),
        window_size: 32,
        id_context: None,
        sender_sequence: oscore_json["sender_sequence"].as_u64().unwrap(),
        replay_index: oscore_json["replay_index"].as_u64().unwrap(),
        replay_bitfield: oscore_json["replay_bitfield"].as_u64().unwrap(),
    };

    // Parse freshness state from vector
    let fresh_json = &case["freshness"];
    let freshness = FreshnessState {
        sequence: fresh_json["sequence"].as_u64().unwrap() as u32,
        active_until: fresh_json["active_until"].as_f64(),
        retain_until: fresh_json["retain_until"].as_f64().unwrap(),
        updated_at: 0.0, // Not in this vector
    };

    // Parse parents
    let parents: Vec<[u8; 16]> = case["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let addr: std::net::Ipv6Addr = p.as_str().unwrap().parse().unwrap();
            addr.octets()
        })
        .collect();

    let response = HandoffResponse::success(addr.octets(), dao_seq, path_seq)
        .with_oscore(oscore)
        .with_freshness(freshness)
        .with_parents(parents.clone());

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    assert_eq!(decoded.status, HandoffRejectReason::Success);
    assert_eq!(decoded.dao_sequence, Some(dao_seq));
    assert_eq!(decoded.path_sequence, Some(path_seq));
    assert!(decoded.oscore_state.is_some());
    assert!(decoded.freshness.is_some());
    assert_eq!(decoded.parents.len(), parents.len());
}

#[test]
fn oscore_state_transfer_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "oscore_state_transfer")
        .expect("vector exists");

    // Verify the vector has the expected structure for OSCORE state
    let master_secret = hex::decode(case["master_secret"].as_str().unwrap()).unwrap();
    let master_salt = hex::decode(case["master_salt"].as_str().unwrap()).unwrap();
    let sender_id = hex::decode(case["sender_id"].as_str().unwrap()).unwrap();
    let recipient_id = hex::decode(case["recipient_id"].as_str().unwrap()).unwrap();
    let algorithm = case["algorithm"].as_i64().unwrap();
    let hashfun = case["hashfun"].as_str().unwrap();
    let window_size = case["window_size"].as_u64().unwrap() as u32;
    let sender_sequence = case["sender_sequence"].as_u64().unwrap();
    let replay_index = case["replay_index"].as_u64().unwrap();
    let replay_bitfield = case["replay_bitfield"].as_u64().unwrap();

    let oscore = OscoreState {
        master_secret,
        master_salt,
        sender_id,
        recipient_id,
        algorithm,
        hashfun: hashfun.to_string(),
        window_size,
        id_context: None,
        sender_sequence,
        replay_index,
        replay_bitfield,
    };

    // Verify the state can be embedded in a handoff response and roundtripped
    let addr = [
        0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let response = HandoffResponse::success(addr, 100, 50).with_oscore(oscore);

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    let dec_oscore = decoded.oscore_state.unwrap();
    assert_eq!(dec_oscore.sender_sequence, sender_sequence);
    assert_eq!(dec_oscore.replay_index, replay_index);
    assert_eq!(dec_oscore.replay_bitfield, replay_bitfield);
    assert_eq!(dec_oscore.algorithm, algorithm);
    assert_eq!(dec_oscore.hashfun, hashfun);
    assert_eq!(dec_oscore.window_size, window_size);
}

#[test]
fn oscore_state_with_id_context_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "oscore_state_with_id_context")
        .expect("vector exists");

    let id_context = hex::decode(case["id_context"].as_str().unwrap()).unwrap();

    let oscore = OscoreState {
        master_secret: hex::decode(case["master_secret"].as_str().unwrap()).unwrap(),
        master_salt: hex::decode(case["master_salt"].as_str().unwrap()).unwrap(),
        sender_id: hex::decode(case["sender_id"].as_str().unwrap()).unwrap(),
        recipient_id: hex::decode(case["recipient_id"].as_str().unwrap()).unwrap(),
        algorithm: case["algorithm"].as_i64().unwrap(),
        hashfun: case["hashfun"].as_str().unwrap().to_string(),
        window_size: case["window_size"].as_u64().unwrap() as u32,
        id_context: Some(id_context.clone()),
        sender_sequence: case["sender_sequence"].as_u64().unwrap(),
        replay_index: case["replay_index"].as_u64().unwrap(),
        replay_bitfield: case["replay_bitfield"].as_u64().unwrap(),
    };

    let addr = [
        0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let response = HandoffResponse::success(addr, 100, 50).with_oscore(oscore);

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    let dec_oscore = decoded.oscore_state.unwrap();
    assert_eq!(dec_oscore.id_context, Some(id_context));
}

#[test]
fn freshness_state_transfer_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "freshness_state_transfer")
        .expect("vector exists");

    let freshness = FreshnessState {
        sequence: case["sequence"].as_u64().unwrap() as u32,
        active_until: case["active_until"].as_f64(),
        retain_until: case["retain_until"].as_f64().unwrap(),
        updated_at: case["updated_at"].as_f64().unwrap(),
    };

    let addr = [
        0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let response = HandoffResponse::success(addr, 100, 50).with_freshness(freshness.clone());

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    let dec_fresh = decoded.freshness.unwrap();
    assert_eq!(dec_fresh.sequence, freshness.sequence);
    assert!((dec_fresh.retain_until - freshness.retain_until).abs() < 0.001);
    assert!(dec_fresh.active_until.is_some());
}

#[test]
fn freshness_state_inactive_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "freshness_state_inactive")
        .expect("vector exists");

    let freshness = FreshnessState {
        sequence: case["sequence"].as_u64().unwrap() as u32,
        active_until: case["active_until"].as_f64(), // null -> None
        retain_until: case["retain_until"].as_f64().unwrap(),
        updated_at: case["updated_at"].as_f64().unwrap(),
    };

    assert!(freshness.active_until.is_none());

    let addr = [
        0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let response = HandoffResponse::success(addr, 100, 50).with_freshness(freshness);

    let encoded = response.encode();
    let decoded = HandoffResponse::decode(&encoded).unwrap();

    let dec_fresh = decoded.freshness.unwrap();
    assert!(dec_fresh.active_until.is_none());
}

#[test]
fn handoff_sequence_increment_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_sequence_increment")
        .expect("vector exists");

    // GCP-7 SECURITY: After handoff, new gateway MUST increment sequence numbers
    let transferred_dao = case["transferred_dao_sequence"].as_u64().unwrap() as u32;
    let transferred_path = case["transferred_path_sequence"].as_u64().unwrap() as u32;
    let transferred_oscore_seq = case["transferred_oscore_sender_seq"].as_u64().unwrap();
    let expected_dao = case["expected_dao_sequence"].as_u64().unwrap() as u32;
    let expected_path = case["expected_path_sequence"].as_u64().unwrap() as u32;
    let expected_oscore_seq = case["expected_oscore_sender_seq"].as_u64().unwrap();

    // Verify the expected increments match +1
    assert_eq!(expected_dao, transferred_dao + 1);
    assert_eq!(expected_path, transferred_path + 1);
    assert_eq!(expected_oscore_seq, transferred_oscore_seq + 1);

    // Test with NodeRegistry.accept_handoff
    use lichen_gateway::handoff::NodeRegistry;

    let oscore = OscoreState {
        master_secret: vec![0; 16],
        master_salt: vec![0; 8],
        sender_id: vec![0],
        recipient_id: vec![1],
        algorithm: 10,
        hashfun: "SHA-256".into(),
        window_size: 32,
        id_context: None,
        sender_sequence: transferred_oscore_seq,
        replay_index: 100,
        replay_bitfield: 0,
    };

    let addr = [
        0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    let response =
        HandoffResponse::success(addr, transferred_dao, transferred_path).with_oscore(oscore);

    let mut registry = NodeRegistry::new();
    registry.accept_handoff(&response).unwrap();

    let entry = registry.get(&addr).unwrap();
    assert_eq!(entry.dao_sequence, expected_dao);
    assert_eq!(entry.path_sequence, expected_path);
    assert_eq!(
        entry.oscore_state.as_ref().unwrap().sender_sequence,
        expected_oscore_seq
    );
}

#[test]
fn handoff_request_invalid_not_map_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_invalid_not_map")
        .expect("vector exists");

    let cbor_input = hex::decode(case["cbor_input"].as_str().unwrap()).unwrap();
    let result = HandoffRequest::decode(&cbor_input);

    assert!(matches!(result, Err(HandoffError::ExpectedMap)));
}

#[test]
fn handoff_request_invalid_missing_timestamp_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_invalid_missing_timestamp")
        .expect("vector exists");

    let cbor_input = hex::decode(case["cbor_input"].as_str().unwrap()).unwrap();
    let result = HandoffRequest::decode(&cbor_input);

    // Should fail with missing field error
    assert!(matches!(result, Err(HandoffError::MissingField(_))));
}

#[test]
fn handoff_request_invalid_truncated_vector() {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_request_invalid_truncated")
        .expect("vector exists");

    let cbor_input = hex::decode(case["cbor_input"].as_str().unwrap()).unwrap();
    let result = HandoffRequest::decode(&cbor_input);

    assert!(matches!(result, Err(HandoffError::InvalidCbor)));
}

#[test]
fn handoff_protocol_flow_vector() {
    // This vector describes the complete handoff flow - verify the structure is documented
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let vectors = doc["vectors"].as_array().unwrap();

    let case = vectors
        .iter()
        .find(|v| v["name"] == "handoff_protocol_flow_complete")
        .expect("vector exists");

    // Verify the protocol flow has expected structure
    let actors = &case["actors"];
    assert!(actors["node"].is_string());
    assert!(actors["gateway_a"].is_string());
    assert!(actors["gateway_b"].is_string());

    let initial = &case["initial_state"];
    assert_eq!(initial["node_registered_at"], "gateway_a");
    assert!(initial["dao_sequence"].is_u64());

    let messages = case["messages"].as_array().unwrap();
    assert!(!messages.is_empty());

    let final_state = &case["final_state"];
    assert_eq!(final_state["node_registered_at"], "gateway_b");
    // Verify sequence incremented
    let initial_dao = initial["dao_sequence"].as_u64().unwrap();
    let final_dao = final_state["dao_sequence"].as_u64().unwrap();
    assert_eq!(final_dao, initial_dao + 1);
}
