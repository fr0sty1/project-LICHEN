// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Messaging domain types and CBOR wire codecs.
//!
//! Wire contract (firmware `lichen/subsys/lichen/coap/coap_msg.c`, spec §18.1):
//!
//! - `POST /msg/inbox` request : `{to: tstr, body: tstr, ack: bool}`
//!   (`to` and `body` required; unknown keys ignored by the firmware).
//! - `POST /msg/inbox` response: `{id, to, body, timestamp, status}`.
//! - `GET  /msg/inbox` response: `{messages: [{id, from, body, received}]}`.

use serde::{Deserialize, Serialize};

use crate::Error;

/// A message to send to a peer — the body of a `POST /msg/inbox` request.
///
/// Field names match the firmware CBOR keys exactly. In particular the text
/// key is `body` (not `text`, which the firmware silently ignores).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingMessage {
    /// Recipient IPv6 address string, or `ff02::1` for link-local broadcast.
    pub to: String,
    /// Message text.
    pub body: String,
    /// Request a delivery receipt.
    pub ack: bool,
}

impl OutgoingMessage {
    /// Build a message with no delivery-receipt request.
    pub fn new(to: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            body: body.into(),
            ack: false,
        }
    }

    /// Encode as the CBOR body the firmware `POST /msg/inbox` handler expects.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Serializing a struct into a `Vec` writer is infallible.
        ciborium::into_writer(self, &mut buf).expect("CBOR encode to Vec cannot fail");
        buf
    }
}

/// A received message — an element of the `GET /msg/inbox` response array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxMessage {
    /// Firmware-assigned message id.
    pub id: u64,
    /// Sender IPv6 address string.
    pub from: String,
    /// Message text.
    pub body: String,
    /// Receive time (Unix seconds; 0 = time unknown).
    pub received: u64,
}

/// The `GET /msg/inbox` response envelope: `{messages: [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbox {
    pub messages: Vec<InboxMessage>,
}

impl Inbox {
    /// Decode a `GET /msg/inbox` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// A sent-message record — the `POST /msg/inbox` response and each element of
/// `GET /msg/sent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentMessage {
    /// Firmware-assigned message id.
    pub id: u64,
    /// Recipient IPv6 address string.
    pub to: String,
    /// Message text.
    pub body: String,
    /// Send time (Unix seconds; 0 = time unknown).
    pub timestamp: u64,
    /// Delivery status: `queued`, `sent`, `delivered`, `failed`, ...
    pub status: String,
}

impl SentMessage {
    /// Decode a `POST /msg/inbox` (or `GET /msg/sent/{id}`) CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    /// Oracle: hand-derived CBOR bytes (per RFC 8949) for the exact map the
    /// firmware `POST /msg/inbox` handler decodes. Independent of the encoder
    /// under test. This is the regression guard for the historical bug where
    /// the CLI sent `{to, text}` — the firmware keys are `to`, `body`, `ack`.
    #[test]
    fn outgoing_encodes_firmware_wire_bytes() {
        let msg = OutgoingMessage {
            to: "fd00::1".into(),
            body: "hi".into(),
            ack: true,
        };
        let expected: &[u8] = &[
            0xA3, // map(3)
            0x62, b't', b'o', // "to"
            0x67, b'f', b'd', b'0', b'0', b':', b':', b'1', // "fd00::1"
            0x64, b'b', b'o', b'd', b'y', // "body"
            0x62, b'h', b'i', // "hi"
            0x63, b'a', b'c', b'k', // "ack"
            0xF5, // true
        ];
        assert_eq!(msg.to_cbor(), expected);
    }

    /// The encoded body must carry the `body` key, never `text`.
    #[test]
    fn outgoing_uses_body_key_not_text() {
        let bytes = OutgoingMessage::new("ff02::1", "hello").to_cbor();
        let v: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = match v {
            Value::Map(m) => m,
            other => panic!("expected map, got {other:?}"),
        };
        let keys: Vec<&str> = map.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert!(keys.contains(&"body"), "keys were {keys:?}");
        assert!(!keys.contains(&"text"), "must not emit legacy `text` key");
    }

    /// Oracle: an explicitly built CBOR map using the firmware's exact keys
    /// (`messages`/`id`/`from`/`body`/`received`), independent of the struct's
    /// serde mapping. Proves [`Inbox`] decodes the real inbox response shape.
    #[test]
    fn inbox_decodes_firmware_envelope() {
        let wire = Value::Map(vec![(
            Value::Text("messages".into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("id".into()), Value::Integer(7u64.into())),
                (Value::Text("from".into()), Value::Text("fd00::2".into())),
                (Value::Text("body".into()), Value::Text("hello".into())),
                (
                    Value::Text("received".into()),
                    Value::Integer(1_716_742_800u64.into()),
                ),
            ])]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        let inbox = Inbox::from_cbor(&bytes).unwrap();
        assert_eq!(
            inbox.messages,
            vec![InboxMessage {
                id: 7,
                from: "fd00::2".into(),
                body: "hello".into(),
                received: 1_716_742_800,
            }]
        );
    }

    /// A bare CBOR array (the shape an early client wrongly assumed) is not a
    /// valid inbox response and must be rejected, not silently mis-parsed.
    #[test]
    fn inbox_rejects_bare_array() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Array(vec![]), &mut bytes).unwrap();
        assert!(Inbox::from_cbor(&bytes).is_err());
    }

    /// Oracle: firmware `POST /msg/inbox` response keys
    /// (`id`/`to`/`body`/`timestamp`/`status`).
    #[test]
    fn sent_decodes_firmware_response() {
        let wire = Value::Map(vec![
            (Value::Text("id".into()), Value::Integer(42u64.into())),
            (Value::Text("to".into()), Value::Text("fd00::9".into())),
            (Value::Text("body".into()), Value::Text("ping".into())),
            (
                Value::Text("timestamp".into()),
                Value::Integer(1_716_742_801u64.into()),
            ),
            (Value::Text("status".into()), Value::Text("queued".into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        let sent = SentMessage::from_cbor(&bytes).unwrap();
        assert_eq!(
            sent,
            SentMessage {
                id: 42,
                to: "fd00::9".into(),
                body: "ping".into(),
                timestamp: 1_716_742_801,
                status: "queued".into(),
            }
        );
    }
}
