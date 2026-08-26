// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::airtime::{airtime_us_with_config, AirtimeConfig};
use lichen_core::duty_cycle::{DutyCycleRegion, DutyCycleTracker};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/duty_cycle_calculation.json");

#[derive(Debug, Deserialize)]
struct Document {
    format_version: u8,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    category: String,
    radio: Option<Radio>,
    profile: Option<Profile>,
    #[serde(default)]
    transmissions: Vec<Transmission>,
    query_ms: Option<u64>,
    proposed_duration_ms: Option<u32>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Radio {
    payload_len: u16,
    spreading_factor: u8,
    bandwidth_hz: u32,
    coding_rate: u8,
    preamble_symbols: u16,
    crc_enabled: bool,
    implicit_header: bool,
}

#[derive(Debug, Deserialize)]
struct Profile {
    region: String,
    duty_permille: u16,
    window_ms: u64,
    max_dwell_time_ms: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Transmission {
    start_ms: u64,
    duration_ms: u32,
}

#[derive(Debug, Deserialize)]
struct Expected {
    airtime_us: Option<u64>,
    eu_1_percent_packets_per_hour: Option<u64>,
    spec_10_percent_packets_per_hour: Option<u64>,
    used_ms: Option<u32>,
    remaining_ms: Option<u32>,
    usage_permille: Option<u16>,
    can_transmit: Option<bool>,
}

fn vectors() -> Document {
    serde_json::from_str(VECTORS_JSON).expect("valid duty-cycle calculation vectors")
}

#[test]
fn exact_airtime_and_packet_budgets_match_vector() {
    let document = vectors();
    assert_eq!(document.format_version, 2);
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.category == "exact_airtime")
        .expect("exact-airtime vector");
    let radio = vector.radio.as_ref().expect("radio configuration");
    let config = AirtimeConfig {
        spreading_factor: radio.spreading_factor,
        bandwidth_hz: radio.bandwidth_hz,
        coding_rate: radio.coding_rate,
        preamble_symbols: radio.preamble_symbols,
        crc_enabled: radio.crc_enabled,
        implicit_header: radio.implicit_header,
        low_data_rate_optimization: None,
    };
    let airtime_us =
        airtime_us_with_config(radio.payload_len, &config).expect("valid radio profile");
    assert_eq!(
        Some(airtime_us),
        vector.expected.airtime_us,
        "{}",
        vector.name
    );
    assert_eq!(
        Some(36_000_000 / airtime_us),
        vector.expected.eu_1_percent_packets_per_hour,
        "{}",
        vector.name
    );
    assert_eq!(
        Some(360_000_000 / airtime_us),
        vector.expected.spec_10_percent_packets_per_hour,
        "{}",
        vector.name
    );
}

#[test]
fn regional_tracking_matches_vectors() {
    let document = vectors();
    let tracking: Vec<_> = document
        .vectors
        .iter()
        .filter(|vector| vector.category == "tracking")
        .collect();
    assert_eq!(tracking.len(), 8, "all regional edge vectors are consumed");

    for vector in tracking {
        let profile = vector.profile.as_ref().expect("regional profile");
        assert_eq!(profile.window_ms, 3_600_000, "{}", vector.name);
        let region = match profile.region.as_str() {
            "EU868" => DutyCycleRegion::Eu868,
            "US915" => DutyCycleRegion::Us915,
            other => panic!("unknown vector region {other}"),
        };
        let mut tracker: DutyCycleTracker<128> = DutyCycleTracker::with_region(region);
        let configured = tracker.regional_limit();
        assert_eq!(
            configured.duty_permille(),
            profile.duty_permille,
            "{}",
            vector.name
        );
        assert_eq!(
            configured.max_dwell_time_ms(),
            profile.max_dwell_time_ms,
            "{}",
            vector.name
        );

        for transmission in &vector.transmissions {
            assert!(
                tracker.try_record_tx(transmission.start_ms, transmission.duration_ms),
                "history record rejected for {}",
                vector.name
            );
        }

        let now_ms = vector.query_ms.expect("query timestamp");
        let expected_remaining = vector.expected.remaining_ms.expect("remaining budget");
        let expected_used = vector.expected.used_ms.expect("used airtime");
        assert_eq!(
            tracker.remaining_ms(now_ms),
            expected_remaining,
            "{}",
            vector.name
        );
        assert_eq!(
            tracker.max_tx_ms() - expected_remaining,
            expected_used,
            "{}",
            vector.name
        );
        assert_eq!(
            tracker.usage_permille(now_ms),
            vector.expected.usage_permille.expect("usage permille"),
            "{}",
            vector.name
        );

        let proposed = vector.proposed_duration_ms.expect("proposed duration");
        let expected_allowed = vector.expected.can_transmit.expect("transmit decision");
        assert_eq!(
            tracker.can_transmit(now_ms, proposed),
            expected_allowed,
            "{}",
            vector.name
        );
        let records_before = tracker.record_count();
        assert_eq!(
            tracker.try_record_tx(now_ms, proposed),
            expected_allowed,
            "{}",
            vector.name
        );
        if !expected_allowed {
            assert_eq!(tracker.record_count(), records_before, "{}", vector.name);
        }
    }
}
