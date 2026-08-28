//! Cross-validation tests for presence CBOR encoding against shared vectors.
//!
//! Oracle: committed hex in `test/vectors/presence_cbor.json` (spec 18.5.1).

use lichen_client::presence::{
    Activity, Presence, PresenceCache, PresenceCacheEntry, PresenceStatus,
};
use serde_json::Value;
use std::fs;

fn load_vectors() -> Vec<Value> {
    let json_str = fs::read_to_string("../../test/vectors/presence_cbor.json")
        .expect("failed to read presence_cbor.json");
    let data: Value = serde_json::from_str(&json_str).expect("failed to parse JSON");
    data["vectors"]
        .as_array()
        .cloned()
        .expect("vectors should be array")
}

fn parse_presence(input: &Value) -> Presence {
    Presence {
        status: input["status"]
            .as_str()
            .expect("status")
            .parse()
            .expect("known status"),
        activity: input
            .get("activity")
            .and_then(|a| a.as_str())
            .map(|s| s.parse::<Activity>().expect("known activity")),
        msg: input.get("msg").and_then(|m| m.as_str()).map(String::from),
        battery: input
            .get("battery")
            .and_then(|b| b.as_u64())
            .map(|b| b as u32),
        low_battery: input.get("low_battery").and_then(|b| b.as_bool()),
        ts: input["ts"].as_u64().expect("ts"),
    }
}

fn parse_cache_entry(entry: &Value) -> PresenceCacheEntry {
    PresenceCacheEntry {
        addr: entry["addr"].as_str().expect("addr").to_string(),
        status: entry["status"]
            .as_str()
            .expect("status")
            .parse()
            .expect("known status"),
        battery: entry
            .get("battery")
            .and_then(|b| b.as_u64())
            .map(|b| b as u32),
        age_s: entry["age_s"].as_u64().expect("age_s"),
    }
}

fn parse_cache(input: &Value) -> PresenceCache {
    PresenceCache {
        nodes: input["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .map(parse_cache_entry)
            .collect(),
    }
}

fn is_cache(name: &str) -> bool {
    name.contains("cache")
}

#[test]
fn all_vectors_encode_to_committed_hex() {
    for vector in load_vectors() {
        let name = vector["name"].as_str().expect("name");
        let expected = hex::decode(vector["encoded_hex"].as_str().expect("encoded_hex"))
            .expect("valid encoded_hex");
        let actual = if is_cache(name) {
            parse_cache(&vector["input"])
                .to_cbor()
                .unwrap_or_else(|e| panic!("{name}: encode failed: {e}"))
        } else {
            parse_presence(&vector["input"])
                .to_cbor()
                .unwrap_or_else(|e| panic!("{name}: encode failed: {e}"))
        };
        assert_eq!(actual, expected, "{name}: encode mismatch");
    }
}

#[test]
fn all_vectors_decode_and_reencode() {
    for vector in load_vectors() {
        let name = vector["name"].as_str().expect("name");
        let expected = hex::decode(vector["encoded_hex"].as_str().expect("encoded_hex"))
            .expect("valid encoded_hex");
        if is_cache(name) {
            let decoded = PresenceCache::from_cbor(&expected)
                .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
            let want = parse_cache(&vector["input"]);
            assert_eq!(decoded, want, "{name}: decode fields mismatch");
            assert_eq!(
                decoded.to_cbor().expect("re-encode"),
                expected,
                "{name}: re-encode mismatch"
            );
        } else {
            let decoded = Presence::from_cbor(&expected)
                .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
            let want = parse_presence(&vector["input"]);
            assert_eq!(decoded, want, "{name}: decode fields mismatch");
            assert_eq!(
                decoded.to_cbor().expect("re-encode"),
                expected,
                "{name}: re-encode mismatch"
            );
        }
    }
}

#[test]
fn vectors_cover_all_status_and_activity_values() {
    let mut statuses = std::collections::BTreeSet::new();
    let mut activities = std::collections::BTreeSet::new();
    for vector in load_vectors() {
        if is_cache(vector["name"].as_str().unwrap()) {
            continue;
        }
        statuses.insert(vector["input"]["status"].as_str().unwrap().to_string());
        if let Some(activity) = vector["input"].get("activity").and_then(|a| a.as_str()) {
            activities.insert(activity.to_string());
        }
    }
    for status in [
        PresenceStatus::Available,
        PresenceStatus::Busy,
        PresenceStatus::Away,
        PresenceStatus::Offline,
        PresenceStatus::Emergency,
    ] {
        assert!(
            statuses.contains(status.as_str()),
            "missing status vector {}",
            status.as_str()
        );
    }
    for activity in [
        Activity::Stationary,
        Activity::Moving,
        Activity::Resting,
        Activity::Working,
    ] {
        assert!(
            activities.contains(activity.as_str()),
            "missing activity vector {}",
            activity.as_str()
        );
    }
}
