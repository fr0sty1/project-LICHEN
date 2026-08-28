// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-implementation waypoint CBOR parity against the shared oracle.

use lichen_client::waypoint::{Waypoint, WaypointList, WaypointShare};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(
        &std::fs::read_to_string("../../test/vectors/waypoint.json").expect("read waypoint.json"),
    )
    .expect("parse waypoint.json");
    document["vectors"]
        .as_array()
        .cloned()
        .expect("vectors array")
}

fn collection_wire(waypoint_wire: &[u8]) -> Vec<u8> {
    let mut wire = b"\xa1\x69waypoints\x81".to_vec();
    wire.extend_from_slice(waypoint_wire);
    wire
}

#[test]
fn detail_share_and_collection_forms_are_byte_exact() {
    for vector in vectors()
        .into_iter()
        .filter(|vector| vector.get("reject").is_none())
    {
        let name = vector["name"].as_str().expect("name");
        let expected = hex::decode(vector["encoded_hex"].as_str().expect("encoded_hex"))
            .expect("valid encoded_hex");
        let waypoint: Waypoint =
            serde_json::from_value(vector["input"].clone()).expect("waypoint input");
        let share: WaypointShare =
            serde_json::from_value(vector["input"].clone()).expect("share input");

        assert_eq!(
            waypoint.to_cbor().expect("detail encode"),
            expected,
            "{name}"
        );
        assert_eq!(share.to_cbor().expect("share encode"), expected, "{name}");
        assert_eq!(
            Waypoint::from_cbor(&expected).expect("detail decode"),
            waypoint,
            "{name}"
        );
        assert_eq!(
            WaypointList {
                waypoints: vec![waypoint]
            }
            .to_cbor()
            .expect("collection encode"),
            collection_wire(&expected),
            "{name}"
        );
    }
}

#[test]
fn shared_reject_vectors_fail_closed() {
    for vector in vectors()
        .into_iter()
        .filter(|vector| vector.get("reject").is_some())
    {
        let name = vector["name"].as_str().expect("name");
        let wire = hex::decode(vector["encoded_hex"].as_str().expect("encoded_hex"))
            .expect("valid encoded_hex");

        assert!(Waypoint::from_cbor(&wire).is_err(), "{name}: detail");
        assert!(
            ciborium::from_reader::<WaypointShare, _>(wire.as_slice()).is_err(),
            "{name}: share"
        );
    }
}
