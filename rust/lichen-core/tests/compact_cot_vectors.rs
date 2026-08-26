// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-language Compact CoT parity against the canonical JSON corpus.

use lichen_core::compact_cot::{
    decode, decode_pli, encode, ChatDest, CompactCot, CompactCotType, DecodeError, DestType,
    PliPayload, PliValidationError, PLI_TOTAL_SIZE,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/compact_cot.json");

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have complete octets");
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid hex"))
        .collect()
}

fn pli_payload(message: &CompactCot) -> &PliPayload {
    match message {
        CompactCot::FriendlyPli(payload)
        | CompactCot::HostilePli(payload)
        | CompactCot::NeutralPli(payload)
        | CompactCot::UnknownPli(payload) => payload,
        _ => panic!("expected PLI message"),
    }
}

fn expected_subtype(value: u64) -> CompactCotType {
    CompactCotType::from_byte(value as u8).expect("canonical subtype")
}

fn chat_payload(message: &CompactCot) -> (&ChatDest, &[u8]) {
    match message {
        CompactCot::Chat(payload) => (&payload.dest, payload.message()),
        _ => panic!("expected chat message"),
    }
}

#[test]
fn canonical_pli_vectors_have_exact_python_rust_parity() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("vector JSON parses");
    let vectors = document["vectors"].as_array().expect("vectors array");
    let mut valid_count = 0;
    let mut invalid_count = 0;

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        if !name.starts_with("pli_") {
            continue;
        }
        let wire = decode_hex(vector["binary_hex"].as_str().expect("binary_hex"));
        let fields = &vector["decoded_fields"];
        if fields.get("expect_error").is_some() {
            let error = decode_pli(&wire).expect_err(name);
            match name {
                "pli_invalid_truncated" => assert!(matches!(error, DecodeError::TooShort(_))),
                "pli_invalid_trailing_byte" => {
                    assert!(matches!(error, DecodeError::InvalidPliLength { .. }))
                }
                "pli_invalid_latitude" | "pli_invalid_latitude_below_minimum" => assert!(matches!(
                    error,
                    DecodeError::InvalidPli(PliValidationError::Latitude(_))
                )),
                "pli_invalid_longitude" | "pli_invalid_longitude_below_minimum" => {
                    assert!(matches!(
                        error,
                        DecodeError::InvalidPli(PliValidationError::Longitude(_))
                    ))
                }
                "pli_invalid_course" => assert!(matches!(
                    error,
                    DecodeError::InvalidPli(PliValidationError::Course(_))
                )),
                "pli_invalid_unknown_subtype" => {
                    assert!(matches!(error, DecodeError::UnknownSubtype(0x06)))
                }
                "pli_invalid_non_pli_subtype" => {
                    assert!(matches!(error, DecodeError::NotPliSubtype(0x01)))
                }
                _ => panic!("unhandled negative vector: {name}"),
            }
            invalid_count += 1;
            continue;
        }

        assert_eq!(wire.len(), PLI_TOTAL_SIZE, "{name}: exact PLI size");
        let decoded = decode_pli(&wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            decoded.subtype(),
            expected_subtype(fields["subtype"].as_u64().expect("subtype")),
            "{name}: subtype"
        );
        let payload = pli_payload(&decoded);
        assert_eq!(
            i64::from(payload.lat_microdeg),
            fields["latitude_microdegrees"].as_i64().expect("latitude"),
            "{name}: latitude"
        );
        assert_eq!(
            i64::from(payload.lon_microdeg),
            fields["longitude_microdegrees"]
                .as_i64()
                .expect("longitude"),
            "{name}: longitude"
        );
        assert_eq!(
            i64::from(payload.alt_dm),
            fields["altitude_decimeters"].as_i64().expect("altitude"),
            "{name}: altitude"
        );
        assert_eq!(
            u64::from(payload.course_cdeg),
            fields["course_centidegrees"].as_u64().expect("course"),
            "{name}: course"
        );
        assert_eq!(
            u64::from(payload.speed_cm_s),
            fields["speed_cm_s"].as_u64().expect("speed"),
            "{name}: speed"
        );
        assert_eq!(
            u64::from(payload.team),
            fields["team"].as_u64().expect("team")
        );
        assert_eq!(
            u64::from(payload.role),
            fields["role"].as_u64().expect("role")
        );

        let mut encoded = [0u8; PLI_TOTAL_SIZE];
        let length =
            encode(&decoded, &mut encoded).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(length, PLI_TOTAL_SIZE, "{name}: encoded length");
        assert_eq!(&encoded[..], &wire[..], "{name}: byte-exact re-encoding");
        valid_count += 1;
    }

    assert_eq!(
        valid_count, 8,
        "all canonical positive PLI vectors consumed"
    );
    assert_eq!(
        invalid_count, 9,
        "all canonical negative PLI vectors consumed"
    );
}

#[test]
fn encoder_rejects_noncanonical_pli_fields() {
    let invalid = [
        PliPayload {
            lat_microdeg: 90_000_001,
            lon_microdeg: 0,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 0,
            role: 0,
        },
        PliPayload {
            lat_microdeg: 0,
            lon_microdeg: -180_000_001,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 0,
            role: 0,
        },
        PliPayload {
            lat_microdeg: 0,
            lon_microdeg: 0,
            alt_dm: 0,
            course_cdeg: 36_000,
            speed_cm_s: 0,
            team: 0,
            role: 0,
        },
    ];

    for payload in invalid {
        let mut output = [0u8; PLI_TOTAL_SIZE];
        assert!(encode(&CompactCot::FriendlyPli(payload), &mut output).is_err());
    }
}

#[test]
fn canonical_chat_destination_vectors_have_python_rust_parity() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("vector JSON parses");
    let vectors = document["vectors"].as_array().expect("vectors array");
    let mut valid_count = 0;
    let mut invalid_count = 0;

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        if !name.starts_with("chat_") {
            continue;
        }
        let wire = decode_hex(vector["binary_hex"].as_str().expect("binary_hex"));
        let fields = &vector["decoded_fields"];
        if fields.get("expect_error").is_some() {
            let error = decode(&wire).expect_err(name);
            match name {
                "chat_invalid_dest_type" => {
                    assert!(matches!(error, DecodeError::InvalidDestType(0x03)))
                }
                "chat_invalid_team_zero" => {
                    assert!(matches!(error, DecodeError::InvalidTeam(0x00)))
                }
                "chat_invalid_team_above_range" => {
                    assert!(matches!(error, DecodeError::InvalidTeam(0x0b)))
                }
                "chat_invalid_direct_truncated" | "chat_invalid_message_truncated" => {
                    assert!(matches!(error, DecodeError::TooShort(_)))
                }
                "chat_invalid_trailing_byte" => {
                    assert!(matches!(error, DecodeError::InvalidChatLength { .. }))
                }
                "chat_invalid_utf8" => assert!(matches!(error, DecodeError::InvalidUtf8)),
                _ => panic!("unhandled negative vector: {name}"),
            }
            invalid_count += 1;
            continue;
        }

        let decoded = decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        let (destination, message) = chat_payload(&decoded);
        assert_eq!(
            destination.dest_type() as u8,
            fields["dest_type"].as_u64().expect("dest_type") as u8,
            "{name}: destination type"
        );
        match destination {
            ChatDest::Broadcast => assert_eq!(DestType::Broadcast as u8, 0x00),
            ChatDest::Team(team) => assert_eq!(
                *team as u8,
                fields["dest_team"].as_u64().expect("dest_team") as u8,
                "{name}: team"
            ),
            ChatDest::Direct(address) => assert_eq!(
                address.as_slice(),
                decode_hex(
                    fields["dest_address_hex"]
                        .as_str()
                        .expect("dest_address_hex")
                ),
                "{name}: address"
            ),
        }
        assert_eq!(
            message,
            fields["message_utf8"]
                .as_str()
                .expect("message_utf8")
                .as_bytes(),
            "{name}: message"
        );

        let mut encoded = [0u8; 512];
        let length =
            encode(&decoded, &mut encoded).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(&encoded[..length], &wire[..], "{name}: byte-exact encoding");
        valid_count += 1;
    }

    assert_eq!(valid_count, 9, "all positive chat vectors consumed");
    assert_eq!(invalid_count, 7, "all negative chat vectors consumed");
}

#[test]
fn canonical_xml_vectors_have_rust_binary_parity() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("vector JSON parses");
    let vectors = document["vectors"].as_array().expect("vectors array");
    let mut positive_count = 0;
    let mut invalid_count = 0;

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        if !name.starts_with("xml_") {
            continue;
        }
        let fields = &vector["decoded_fields"];
        if fields.get("xml_expect_error").is_some() {
            assert_eq!(
                vector["binary_hex"].as_str(),
                Some(""),
                "{name}: invalid XML has no canonical wire encoding"
            );
            invalid_count += 1;
            continue;
        }

        assert!(
            fields.get("xml_input").is_some(),
            "{name}: positive XML input is present"
        );
        let wire = decode_hex(vector["binary_hex"].as_str().expect("binary_hex"));
        let decoded = decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        let mut encoded = [0u8; 512];
        let length =
            encode(&decoded, &mut encoded).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(&encoded[..length], &wire[..], "{name}: byte-exact encoding");
        positive_count += 1;
    }

    assert_eq!(positive_count, 4, "all positive XML vectors consumed");
    assert_eq!(invalid_count, 8, "all invalid XML vectors accounted for");
}
