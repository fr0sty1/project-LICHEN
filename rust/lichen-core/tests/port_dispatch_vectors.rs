// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Spec 07 UDP port table vs lichen-core constants.

use lichen_core::constants::{
    PORT_APRS_IS, PORT_CAYENNE_LPP, PORT_COAP, PORT_COAP_DTLS, PORT_COMPACT_COT, PORT_MQTT_SN,
    PORT_NMEA, PORT_SENML,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/port_dispatch.json");

fn well_known(app: &str) -> Option<u16> {
    Some(match app {
        "compact_cot" => PORT_COMPACT_COT,
        "senml" => PORT_SENML,
        "coap" => PORT_COAP,
        "reserved_dtls" => PORT_COAP_DTLS,
        "cayenne_lpp" => PORT_CAYENNE_LPP,
        "aprs_is" => PORT_APRS_IS,
        "nmea" => PORT_NMEA,
        "mqtt_sn" => PORT_MQTT_SN,
        _ => return None,
    })
}

#[test]
fn port_dispatch_vectors_match_constants() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let mut known = 0u8;
    for case in document["vectors"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let port = case["port"].as_u64().unwrap() as u16;
        let app = case["app"].as_str().unwrap();
        match well_known(app) {
            Some(expected) => {
                assert_eq!(expected, port, "{name}");
                known += 1;
            }
            None => {
                assert_eq!(app, "unknown", "{name}");
                assert!(well_known("coap") != Some(port));
                assert!(well_known("mqtt_sn") != Some(port));
            }
        }
    }
    assert!(known >= 8, "expected all spec well-known ports");
}
