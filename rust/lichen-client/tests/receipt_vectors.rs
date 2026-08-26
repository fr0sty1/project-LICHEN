// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-implementation delivery-receipt tests using the shared wire vectors.

use lichen_client::msg::{DeliveryReceipt, ReceiptStatus};
use serde_json::Value;

const MESSAGING_VECTORS: &str = include_str!("../../../test/vectors/messaging.json");

fn status(value: &str) -> ReceiptStatus {
    match value {
        "delivered" => ReceiptStatus::Delivered,
        "read" => ReceiptStatus::Read,
        "failed" => ReceiptStatus::Failed,
        other => panic!("unexpected valid receipt status {other:?}"),
    }
}

fn encode_json(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("vector payload must encode as CBOR");
    bytes
}

#[test]
fn receipt_vectors_accept_and_reject_as_specified() {
    let document: Value = serde_json::from_str(MESSAGING_VECTORS).expect("valid messaging vectors");
    let vectors = document["vectors"].as_array().expect("vectors array");
    let mut accepted = 0;
    let mut rejected = 0;

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        if !name.starts_with("receipt_post_") {
            continue;
        }

        let expected_code = vector["expected"]["response_code"]
            .as_str()
            .expect("expected response code");
        let result = match vector.get("cbor_payload") {
            Some(payload) => DeliveryReceipt::from_cbor(&encode_json(payload)),
            None => DeliveryReceipt::from_cbor(&[]),
        };

        if expected_code.starts_with("2.") {
            let receipt = result.unwrap_or_else(|error| panic!("{name} was rejected: {error}"));
            let payload = &vector["cbor_payload"];
            assert_eq!(
                receipt.message_id,
                payload["id"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                receipt.status,
                status(payload["status"].as_str().unwrap()),
                "{name}"
            );
            assert_eq!(receipt.ts, payload["ts"].as_u64().unwrap(), "{name}");
            accepted += 1;
        } else {
            assert!(result.is_err(), "{name} unexpectedly decoded");
            rejected += 1;
        }
    }

    assert_eq!(accepted, 5, "all valid receipt vectors must be exercised");
    assert_eq!(rejected, 9, "all invalid receipt vectors must be exercised");
}

#[test]
fn delivered_receipt_matches_canonical_wire_bytes() {
    let document: Value = serde_json::from_str(MESSAGING_VECTORS).expect("valid messaging vectors");
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "receipt_post_delivered")
        .expect("delivered receipt vector");
    let expected = hex::decode(vector["cbor_hex"].as_str().unwrap()).unwrap();

    let receipt = DeliveryReceipt::new(12_345, ReceiptStatus::Delivered, 1_716_742_900);
    assert_eq!(receipt.to_cbor().unwrap(), expected);
}

#[test]
fn receipt_status_enum_matches_shared_vectors() {
    let document: Value = serde_json::from_str(MESSAGING_VECTORS).expect("valid messaging vectors");
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "receipt_post_invalid_status")
        .expect("invalid status vector");
    let statuses: Vec<&str> = vector["expected"]["valid_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();

    assert_eq!(
        statuses,
        [
            ReceiptStatus::Delivered.as_str(),
            ReceiptStatus::Read.as_str(),
            ReceiptStatus::Failed.as_str(),
        ]
    );
}
