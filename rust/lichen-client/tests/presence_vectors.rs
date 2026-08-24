//! Cross-validation tests for presence CBOR encoding against shared vectors.

use lichen_client::presence::{
    Activity, Presence, PresenceCache, PresenceCacheEntry, PresenceStatus,
};
use serde_json::Value;
use std::fs;

#[test]
fn test_presence_vectors() {
    let json_str = fs::read_to_string("../../test/vectors/presence_cbor.json")
        .expect("Failed to read presence_cbor.json");
    let data: Value = serde_json::from_str(&json_str).expect("Failed to parse JSON");

    let vectors = data["vectors"].as_array().expect("vectors should be array");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let expected_hex = v["encoded_hex"].as_str().unwrap();
        let input = &v["input"];

        // Skip cache vectors for now (different type)
        if name.contains("cache") {
            continue;
        }

        // Parse input to Presence
        let status = match input["status"].as_str().unwrap() {
            "available" => PresenceStatus::Available,
            "busy" => PresenceStatus::Busy,
            "away" => PresenceStatus::Away,
            "offline" => PresenceStatus::Offline,
            "emergency" => PresenceStatus::Emergency,
            s => panic!("Unknown status: {}", s),
        };

        let activity = input
            .get("activity")
            .and_then(|a| a.as_str())
            .map(|s| match s {
                "stationary" => Activity::Stationary,
                "moving" => Activity::Moving,
                "resting" => Activity::Resting,
                "working" => Activity::Working,
                s => panic!("Unknown activity: {}", s),
            });

        let msg = input.get("msg").and_then(|m| m.as_str()).map(String::from);
        let battery = input
            .get("battery")
            .and_then(|b| b.as_u64())
            .map(|b| b as u32);
        let ts = input["ts"].as_u64().unwrap();

        let presence = Presence {
            status,
            activity,
            msg,
            battery,
            ts,
        };

        let cbor = presence.to_cbor().expect("Failed to encode");
        let actual_hex = hex::encode(&cbor);

        assert_eq!(actual_hex, expected_hex, "Vector '{}' mismatch", name);
    }
}
