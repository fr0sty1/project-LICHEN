// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Drive the Rust messaging resources against `test/vectors/messaging.json`.
//!
//! The vectors are the independent oracle (spec §17.5.7 / §18.1). This test
//! consumes every vector through [`lichen_client::msg::MessagingResources`],
//! matching the Python `MessagesResource` consumer.

use ciborium::value::Value;
use lichen_client::msg::{InboxPost, MessagingResources, MsgCode, DEFAULT_CANNED_MESSAGES};
use serde_json::Value as Json;

const MESSAGING_VECTORS: &str = include_str!("../../../test/vectors/messaging.json");

fn load_vectors() -> Vec<Json> {
    let document: Json = serde_json::from_str(MESSAGING_VECTORS).expect("valid messaging vectors");
    assert_eq!(document["format_version"], 2);
    document["vectors"]
        .as_array()
        .expect("vectors array")
        .clone()
}

fn encode_payload(vector: &Json) -> Vec<u8> {
    if let Some(hex) = vector.get("payload_hex").and_then(Json::as_str) {
        return hex::decode(hex).expect("payload_hex");
    }
    if vector.get("payload").and_then(Json::as_str) == Some("") {
        return Vec::new();
    }
    if let Some(payload) = vector.get("cbor_payload") {
        let mut bytes = Vec::new();
        ciborium::into_writer(payload, &mut bytes).expect("vector payload must encode as CBOR");
        return bytes;
    }
    Vec::new()
}

fn seed_message(resources: &mut MessagingResources, id: u64) {
    let post = InboxPost {
        id: Some(id),
        body: Some("seed".into()),
        ..InboxPost::default()
    };
    let resp = resources
        .messages
        .post_inbox(&post.to_cbor().expect("seed encode"));
    assert_eq!(resp.code, MsgCode::Created, "seed id {id}");
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k.as_text() {
        Some(text) if text == key => Some(v),
        _ => None,
    })
}

fn expected_class(expected_code: &str) -> &str {
    expected_code
        .split_whitespace()
        .next()
        .expect("response code class")
}

#[test]
fn messaging_resources_match_shared_vectors() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 30,
        "expected at least 30 messaging vectors, got {}",
        vectors.len()
    );

    for vector in &vectors {
        let name = vector["name"].as_str().expect("vector name");
        let resource = vector["resource"].as_str().expect("resource");
        let method = vector["method"].as_str().expect("method");
        let expected = &vector["expected"];
        let expected_code = expected["response_code"]
            .as_str()
            .expect("expected response_code");

        let mut resources = MessagingResources::new();
        if let Some(precondition) = vector.get("precondition") {
            let exists = &precondition["message_id_exists"];
            if exists.as_bool() == Some(true) {
                seed_message(&mut resources, 42);
            } else if let Some(id) = exists.as_u64() {
                seed_message(&mut resources, id);
            }
        }

        let payload = encode_payload(vector);
        let resp = resources.handle(method, resource, &payload);
        assert_eq!(
            resp.code.class(),
            expected_class(expected_code),
            "{name}: got {}, expected {expected_code}",
            resp.code.as_str()
        );

        if expected.get("message_stored") == Some(&Json::Bool(true)) {
            assert!(
                !resources.messages.sent_messages().is_empty(),
                "{name}: expected a stored sent message"
            );
        }
        if expected.get("receipt_stored") == Some(&Json::Bool(true)) {
            assert!(
                !resources.receipts.receipts().is_empty(),
                "{name}: expected a stored receipt"
            );
        }
        if let Some(assigned) = expected.get("assigned_id").and_then(Json::as_u64) {
            assert_eq!(
                resp.location_path,
                ["msg".to_string(), "sent".to_string(), assigned.to_string()],
                "{name}: Location-Path"
            );
        }
        if let Some(location) = expected.get("location_path").and_then(Json::as_str) {
            let actual = resp
                .location_uri()
                .unwrap_or_else(|| panic!("{name}: missing Location-Path"));
            if location.contains("{id}") {
                assert!(
                    actual.starts_with("/msg/sent/"),
                    "{name}: location {actual}"
                );
                let id = actual.rsplit('/').next().unwrap();
                assert!(
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
                    "{name}: non-decimal Location-Path id {id}"
                );
            } else {
                assert_eq!(actual, location, "{name}: Location-Path");
            }
        }

        if method == "POST" && resource == "/msg/inbox" && expected_code.starts_with("2.") {
            if let Some(cbor_payload) = vector.get("cbor_payload") {
                if let Some(canned_id) = cbor_payload.get("canned").and_then(Json::as_u64) {
                    let text = DEFAULT_CANNED_MESSAGES
                        .iter()
                        .find(|(id, _)| *id == canned_id)
                        .map(|(_, text)| *text)
                        .expect("canned catalog id");
                    let stored = resources.messages.sent_messages().last().copied().unwrap();
                    let Value::Map(map) = stored else {
                        panic!("{name}: stored sent record is not a map");
                    };
                    assert_eq!(
                        map_get(map, "body").and_then(Value::as_text),
                        Some(text),
                        "{name}: canned expansion"
                    );
                }
            }
        }

        if method == "GET" && expected_code.starts_with("2.") {
            assert_eq!(
                resp.content_format,
                Some(60),
                "{name}: Content-Format application/cbor"
            );
            let decoded: Value = ciborium::from_reader(resp.payload.as_slice())
                .unwrap_or_else(|error| panic!("{name}: GET payload CBOR: {error}"));
            if resource == "/msg/inbox" {
                let Value::Map(map) = &decoded else {
                    panic!("{name}: inbox GET is not a map");
                };
                assert!(
                    matches!(map_get(map, "messages"), Some(Value::Array(_))),
                    "{name}: messages array"
                );
                let unread = map_get(map, "unread")
                    .and_then(|v| match v {
                        Value::Integer(i) => u64::try_from(*i).ok(),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("{name}: unread uint"));
                assert_eq!(unread, resources.messages.unread_count(), "{name}: unread");
                assert!(resp.observable, "{name}: inbox is Observe-capable");
            } else if resource == "/msg/sent" {
                let Value::Map(map) = &decoded else {
                    panic!("{name}: sent GET is not a map");
                };
                assert!(
                    matches!(map_get(map, "messages"), Some(Value::Array(_))),
                    "{name}: sent messages array"
                );
            } else if let Some(fields) = expected.get("fields_present").and_then(Json::as_array) {
                let Value::Map(map) = &decoded else {
                    panic!("{name}: sent detail is not a map");
                };
                for field in fields {
                    let key = field.as_str().expect("field name");
                    assert!(map_get(map, key).is_some(), "{name}: missing field {key}");
                }
            }
        }

        if expected.get("error").is_some() && expected_code.starts_with("4.") {
            let seeded = vector
                .get("precondition")
                .and_then(|p| p.get("message_id_exists"))
                .map(|v| v.as_bool() == Some(true) || v.as_u64().is_some())
                .unwrap_or(false);
            if resource.starts_with("/msg/inbox") && !seeded {
                assert!(
                    resources.messages.inbox_messages().is_empty(),
                    "{name}: rejected inbox POST must not store"
                );
            }
            if resource == "/msg/ack" {
                assert!(
                    resources.receipts.receipts().is_empty(),
                    "{name}: rejected receipt must not store"
                );
            }
        }
    }
}

#[test]
fn inbox_post_full_message_encodes_spec_fields() {
    let vector = load_vectors()
        .into_iter()
        .find(|v| v["name"] == "inbox_post_full_message")
        .expect("full message vector");
    let payload = &vector["cbor_payload"];
    let draft = InboxPost {
        id: payload["id"].as_u64(),
        to: payload["to"].as_str().map(str::to_owned),
        body: payload["body"].as_str().map(str::to_owned),
        ack: payload["ack"].as_bool(),
        priority: payload["priority"].as_u64(),
        reply_to: payload["reply_to"].as_u64(),
        ttl: payload["ttl"].as_u64(),
        ..InboxPost::default()
    };
    let encoded = draft.to_cbor().expect("encode");
    let decoded: Value = ciborium::from_reader(encoded.as_slice()).unwrap();
    let Value::Map(map) = decoded else {
        panic!("map")
    };
    assert_eq!(
        map_get(&map, "to").and_then(Value::as_text),
        payload["to"].as_str()
    );
    assert_eq!(
        map_get(&map, "body").and_then(Value::as_text),
        payload["body"].as_str()
    );
    assert_eq!(map_get(&map, "ack"), Some(&Value::Bool(true)));
}

#[test]
fn canned_catalog_matches_spec_18_1_3() {
    assert_eq!(
        DEFAULT_CANNED_MESSAGES,
        &[
            (0, "I'm OK"),
            (1, "Need assistance"),
            (2, "At checkpoint"),
            (3, "Returning to base"),
            (4, "Emergency - send help"),
        ]
    );
}
