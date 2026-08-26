// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-validation tests for the `/pos/cache` CBOR response types.

use lichen_client::pos::PositionCache;

#[test]
fn decodes_shared_position_cache_vectors() {
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("../../test/vectors/position_cache.json")
            .expect("read position_cache.json"),
    )
    .expect("parse position_cache.json");

    for vector in document["vectors"].as_array().expect("vectors array") {
        if vector.get("kind").and_then(|kind| kind.as_str()) == Some("reject") {
            continue;
        }

        let name = vector["name"].as_str().expect("vector name");
        let encoded = hex::decode(vector["encoded_hex"].as_str().expect("encoded_hex"))
            .expect("valid encoded_hex");
        let cache = PositionCache::from_cbor(&encoded)
            .unwrap_or_else(|error| panic!("{name}: decode failed: {error}"));
        let expected = vector["input"]["record"].as_array().expect("record array");

        assert_eq!(cache.positions.len(), expected.len(), "{name}");
        for (entry, record) in cache.positions.iter().zip(expected) {
            assert_eq!(entry.node, record["node"].as_str().expect("node"), "{name}");
            assert_eq!(entry.lat, record["lat"].as_f64().expect("lat"), "{name}");
            assert_eq!(entry.lon, record["lon"].as_f64().expect("lon"), "{name}");
            assert_eq!(entry.ts, record["ts"].as_f64().expect("ts"), "{name}");
            assert_eq!(
                entry.alt,
                record.get("alt").and_then(|alt| alt.as_f64()),
                "{name}"
            );

            let now = vector["input"]["now"].as_f64().expect("now");
            assert_eq!(entry.age_s, (now - entry.ts) as i64, "{name}");
        }
    }
}

#[test]
fn rejects_cache_entries_missing_required_fields() {
    // {"positions": [{"node": "0200::1"}]} lacks coordinates,
    // timestamp, and age.
    let malformed = hex::decode("a169706f736974696f6e7381a1646e6f6467303230303a3a31").unwrap();
    assert!(PositionCache::from_cbor(&malformed).is_err());
}
