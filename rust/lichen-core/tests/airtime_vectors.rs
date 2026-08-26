// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical LICHEN packet-timing vector consumer for LoRa airtime.

use lichen_core::airtime::{airtime_us_with_config, AirtimeConfig};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    category: String,
    #[serde(default)]
    payload_len: Option<u16>,
    #[serde(default)]
    sf: Option<u8>,
    #[serde(default)]
    bw_hz: Option<u32>,
    #[serde(default)]
    airtime_us: Option<u64>,
    #[serde(default)]
    max_phy_payload_bytes: Option<u16>,
    #[serde(default)]
    max_payload_airtime_us: Option<u64>,
}

fn canonical_vectors() -> VectorFile {
    serde_json::from_str(include_str!("../../../test/vectors/packets-timing.json"))
        .expect("packets-timing vectors must be valid JSON")
}

#[test]
fn consumes_normative_sf9_airtime_vector() {
    let vectors = canonical_vectors();
    let vector = vectors
        .vectors
        .iter()
        .find(|vector| vector.category == "airtime_sf9")
        .expect("canonical SF9 airtime vector");
    let config = AirtimeConfig {
        spreading_factor: vector.sf.expect("sf"),
        bandwidth_hz: vector.bw_hz.expect("bandwidth"),
        ..AirtimeConfig::default()
    };

    assert_eq!(
        airtime_us_with_config(vector.payload_len.expect("payload length"), &config),
        Ok(vector.airtime_us.expect("airtime")),
        "{}",
        vector.name
    );
}

#[test]
fn consumes_canonical_maximum_payload_airtime_vector() {
    let vectors = canonical_vectors();
    let vector = vectors
        .vectors
        .iter()
        .find(|vector| vector.category == "tdma_constants")
        .expect("canonical maximum-payload airtime vector");
    let config = AirtimeConfig {
        spreading_factor: vector.sf.expect("sf"),
        bandwidth_hz: vector.bw_hz.expect("bandwidth"),
        // CCP profile 0x01 fixes DE off even though other profiles may select
        // it automatically from the symbol-duration threshold.
        low_data_rate_optimization: Some(false),
        ..AirtimeConfig::default()
    };

    assert_eq!(
        airtime_us_with_config(
            vector.max_phy_payload_bytes.expect("payload length"),
            &config
        ),
        Ok(vector.max_payload_airtime_us.expect("airtime")),
        "{}",
        vector.name
    );
}
