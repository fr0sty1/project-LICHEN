// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-language CCP beacon and TDMA slot vectors.

use lichen_core::{lichen_hash_32, tdma_beacon::TdmaBeaconHeader};
use lichen_node::TdmaScheduler;
use serde_json::Value;

const JSON: &str = include_str!("../../../test/vectors/ccp_beacon_format.json");

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(JSON).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn canonical_slot_vectors_drive_production_scheduler() {
    let mut consumed = 0;
    for vector in vectors()
        .into_iter()
        .filter(|vector| vector["type"] == "slot_selection")
    {
        let input = &vector["input"];
        let bytes = hex::decode(input["eui64"].as_str().unwrap()).unwrap();
        let eui: [u8; 8] = bytes.try_into().unwrap();
        let sfn = input["sfn"].as_u64().unwrap() as u32;
        let slots = u16::try_from(input["num_slots"].as_u64().unwrap()).unwrap();
        let expected = u16::try_from(vector["output"]["slot"].as_u64().unwrap()).unwrap();
        assert_eq!(
            TdmaScheduler::slot_for(&eui, sfn, slots).unwrap(),
            expected,
            "{}",
            vector["name"].as_str().unwrap()
        );
        if let Some(expected_hash) = vector["output"]["hash_32"].as_u64() {
            assert_eq!(lichen_hash_32(&eui), expected_hash as u32);
        }
        consumed += 1;
    }
    assert!(consumed > 0, "vector set contains no slot-selection cases");
}

#[test]
fn canonical_beacon_wire_drives_production_codec() {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector["name"] == "beacon_wire_example")
        .unwrap();
    let input = &vector["input"];
    let header = TdmaBeaconHeader {
        epoch: input["epoch"].as_u64().unwrap() as u32,
        num_slots: input["num_slots"].as_u64().unwrap() as u8,
        sfn: input["sfn"].as_u64().unwrap() as u32,
        timestamp: input["timestamp"].as_u64().unwrap() as u32,
        flags: input["flags"].as_u64().unwrap() as u8,
        rx_chains: input["rx_chains"].as_u64().unwrap() as u8,
        setup_window: input["setup_window"].as_u64().unwrap() as u16,
        occupied_time: input["occupied_time"].as_u64().unwrap() as u16,
        guard: input["guard"].as_u64().unwrap() as u8,
        channel_mask: input["channel_mask"].as_u64().unwrap() as u32,
    };
    let mut encoded = [0u8; 24];
    header.serialize(&mut encoded).unwrap();
    assert_eq!(hex::encode(encoded), vector["output"]["header_hex"]);
    assert_eq!(TdmaBeaconHeader::parse(&encoded).unwrap(), header);
}

#[test]
fn zero_slot_schedule_is_rejected() {
    assert!(TdmaScheduler::slot_for(&[0; 8], 0, 0).is_err());
}
