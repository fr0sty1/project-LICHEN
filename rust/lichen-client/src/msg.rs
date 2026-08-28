// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Messaging domain types, CBOR codecs, and resource logic.
//!
//! Spec contract (`spec/12-apps.md` §18.1, `spec/11-lci.md` §17.5.7):
//!
//! - `POST /msg/inbox`: send. The map MUST include `body`, legacy `text`, or
//!   `canned`. `to`, `ack`, `id`, `priority`, `reply_to`, and `ttl` are optional.
//! - `GET  /msg/inbox`: observable `{messages, unread}`.
//! - `GET  /msg/sent` and `GET /msg/sent/{id}`: sent archive. Path ids are
//!   canonical decimal with no leading zeros, in uint64 range.
//! - `GET  /msg/canned`: pre-defined catalog (§18.1.3).
//! - `POST /msg/ack`: `{id, status, ts}` with status `delivered`/`read`/`failed`.
//!
//! Firmware (`coap_msg.c`) also accepts a local-admin `POST /msg/sent` with
//! `{to, body, ack}` and returns `{id, to, body, timestamp, status}`.
//! [`OutgoingMessage`] / [`SentMessage`] match that firmware shape.

use std::collections::HashMap;
use std::io::Cursor;

use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use crate::Error;

// Conservative mutation limits matching Python oracle (_decode_single_cbor).
// Keep hostile CBOR work bounded for LoRa/CoAP nodes while remaining well
// above every currently defined endpoint payload.
const CBOR_MAX_ENCODED_BYTES: usize = 4096;
const CBOR_MAX_DEPTH: usize = 16;
const CBOR_MAX_MAP_ENTRIES: usize = 64;
const CBOR_MAX_ARRAY_ENTRIES: usize = 256;
const CBOR_MAX_ITEMS: usize = 1024;

/// Maximum retained inbox, sent, and receipt entries (Python oracle default).
pub const MAX_MESSAGES: usize = 100;

/// CoAP Content-Format for `application/cbor` (RFC 7252 §12.3).
pub const CBOR_CONTENT_FORMAT: u16 = 60;

/// Spec §18.1.3 default canned catalog: `(id, text)`.
pub const DEFAULT_CANNED_MESSAGES: &[(u64, &str)] = &[
    (0, "I'm OK"),
    (1, "Need assistance"),
    (2, "At checkpoint"),
    (3, "Returning to base"),
    (4, "Emergency - send help"),
];

/// A message to send to a peer - the body of a firmware `POST /msg/sent` request.
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

    /// Encode as the CBOR body the firmware `POST /msg/sent` handler expects.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Serializing a struct into a `Vec` writer is infallible.
        ciborium::into_writer(self, &mut buf).expect("CBOR encode to Vec cannot fail");
        buf
    }
}

/// Spec §18.1.1 / §17.5.7 `POST /msg/inbox` request map.
///
/// Optional fields are omitted on the wire. Legacy `text` is accepted by the
/// resource as an alias for `body` but is not emitted by [`InboxPost::new`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InboxPost {
    /// Explicit message id (uint). Assigned by the resource when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Recipient IPv6 address string, or `ff02::1` for broadcast.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Sender IPv6 address string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Unix timestamp in seconds; omit or 0 when wall-clock is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    /// Message text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Legacy alias for `body`. Implementations MUST accept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Canned catalog id (§18.1.3). Expanded to `body` when no text is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canned: Option<u64>,
    /// Request a delivery receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<bool>,
    /// 0=normal, 1=high, 2=emergency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u64>,
    /// Previous message id this post replies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<u64>,
    /// Relative expiry in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

impl InboxPost {
    /// Build a minimal post with a `body` field and no optional keys.
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: Some(body.into()),
            ..Self::default()
        }
    }

    /// Encode as the CBOR map for `POST /msg/inbox`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|error| Error::Encode(error.to_string()))?;
        Ok(buf)
    }
}

/// A received message — an element of the firmware `GET /msg/inbox` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxMessage {
    /// Firmware-assigned message id.
    pub id: u64,
    /// Sender IPv6 address string.
    #[serde(default)]
    pub from: String,
    /// Message text.
    #[serde(default)]
    pub body: String,
    /// Receive time (Unix seconds; 0 = time unknown).
    #[serde(default)]
    pub received: u64,
}

/// The `GET /msg/inbox` response envelope: `{messages: [...], unread}`.
///
/// `unread` is required by spec §18.1.2. Firmware that omits it deserializes
/// as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbox {
    pub messages: Vec<InboxMessage>,
    /// Count of inbox entries not marked `read`.
    #[serde(default)]
    pub unread: u64,
}

impl Inbox {
    /// Decode a `GET /msg/inbox` CBOR response.
    ///
    /// SECURITY: Uses strict CBOR decoding matching Python oracle. Rejects
    /// trailing bytes, duplicate keys, tags, and payloads exceeding limits.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let _ = decode_single_cbor(bytes)?;
        let mut reader = Cursor::new(bytes);
        ciborium::from_reader(&mut reader).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// A sent-message record - the firmware `POST /msg/sent` response and each
/// element of firmware `GET /msg/sent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentMessage {
    /// Firmware-assigned message id.
    pub id: u64,
    /// Recipient IPv6 address string.
    #[serde(default)]
    pub to: String,
    /// Message text.
    #[serde(default)]
    pub body: String,
    /// Send time (Unix seconds; 0 = time unknown).
    #[serde(default)]
    pub timestamp: u64,
    /// Delivery status: `queued`, `sent`, `delivered`, `failed`, ...
    #[serde(default)]
    pub status: String,
}

impl SentMessage {
    /// Decode a `POST /msg/sent` (or `GET /msg/sent/{id}`) CBOR response.
    ///
    /// SECURITY: Uses strict CBOR decoding matching Python oracle. Rejects
    /// trailing bytes, duplicate keys, tags, and payloads exceeding limits.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let _ = decode_single_cbor(bytes)?;
        let mut reader = Cursor::new(bytes);
        ciborium::from_reader(&mut reader).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// The `GET /msg/sent` response envelope: `{messages: [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    pub messages: Vec<SentMessage>,
}

impl Sent {
    /// Decode a `GET /msg/sent` CBOR response.
    ///
    /// SECURITY: Uses strict CBOR decoding matching Python oracle. Rejects
    /// trailing bytes, duplicate keys, tags, and payloads exceeding limits.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let _ = decode_single_cbor(bytes)?;
        let mut reader = Cursor::new(bytes);
        ciborium::from_reader(&mut reader).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// One canned catalog entry (`GET /msg/canned`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CannedMessage {
    /// Catalog identifier.
    pub id: u64,
    /// Expanded message text.
    pub text: String,
}

/// Delivery receipt states accepted by `POST /msg/ack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    /// The original message reached its recipient.
    Delivered,
    /// The recipient displayed or otherwise marked the message as read.
    Read,
    /// Delivery of the original message failed.
    Failed,
}

impl ReceiptStatus {
    /// Return the status text used on the CBOR wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Read => "read",
            Self::Failed => "failed",
        }
    }
}

impl core::fmt::Display for ReceiptStatus {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A delivery, read, or failure receipt sent to `POST /msg/ack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// Identifier of the original message.
    #[serde(rename = "id")]
    pub message_id: u64,
    /// Current delivery state.
    pub status: ReceiptStatus,
    /// Receipt creation time in Unix seconds; zero means time is unknown.
    pub ts: u64,
}

impl DeliveryReceipt {
    /// Construct a receipt for an original message.
    pub const fn new(message_id: u64, status: ReceiptStatus, ts: u64) -> Self {
        Self {
            message_id,
            status,
            ts,
        }
    }

    /// Encode the receipt as the CBOR body expected by `POST /msg/ack`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|error| Error::Encode(error.to_string()))?;
        Ok(buf)
    }

    /// Decode and validate a `POST /msg/ack` CBOR body.
    ///
    /// Missing fields, non-unsigned integer identifiers or timestamps, and
    /// status strings outside the three values defined by the specification
    /// are rejected during deserialization.
    ///
    /// SECURITY: Uses strict CBOR decoding matching Python oracle. Rejects
    /// trailing bytes, duplicate keys, tags, and payloads exceeding limits.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        // Validate payload structure before serde deserialization
        let _ = decode_single_cbor(bytes)?;
        // Re-decode with serde for typed deserialization
        let mut reader = Cursor::new(bytes);
        ciborium::from_reader(&mut reader).map_err(|error| Error::Decode(error.to_string()))
    }
}

/// CoAP response codes produced by the messaging resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgCode {
    /// 2.01 Created.
    Created,
    /// 2.04 Changed.
    Changed,
    /// 2.05 Content.
    Content,
    /// 4.00 Bad Request.
    BadRequest,
    /// 4.04 Not Found.
    NotFound,
    /// 5.03 Service Unavailable (message-id space exhausted).
    ServiceUnavailable,
}

impl MsgCode {
    /// Full CoAP reason-phrase string, e.g. `2.01 Created`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "2.01 Created",
            Self::Changed => "2.04 Changed",
            Self::Content => "2.05 Content",
            Self::BadRequest => "4.00 Bad Request",
            Self::NotFound => "4.04 Not Found",
            Self::ServiceUnavailable => "5.03 Service Unavailable",
        }
    }

    /// Numeric class only, e.g. `2.01`.
    pub const fn class(self) -> &'static str {
        match self {
            Self::Created => "2.01",
            Self::Changed => "2.04",
            Self::Content => "2.05",
            Self::BadRequest => "4.00",
            Self::NotFound => "4.04",
            Self::ServiceUnavailable => "5.03",
        }
    }
}

/// Result of handling one messaging CoAP request.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgResponse {
    /// CoAP response code.
    pub code: MsgCode,
    /// Location-Path option segments (`msg`, `sent`, `{id}`) on Created.
    pub location_path: Vec<String>,
    /// CBOR body; empty when the code has no representation.
    pub payload: Vec<u8>,
    /// Content-Format option; `Some(60)` on CBOR success bodies.
    pub content_format: Option<u16>,
    /// True when the resource is Observe-capable (GET `/msg/inbox`).
    pub observable: bool,
}

impl MsgResponse {
    fn created(id: u64) -> Self {
        Self {
            code: MsgCode::Created,
            location_path: vec!["msg".into(), "sent".into(), id.to_string()],
            payload: Vec::new(),
            content_format: None,
            observable: false,
        }
    }

    fn content(payload: Vec<u8>, observable: bool) -> Self {
        Self {
            code: MsgCode::Content,
            location_path: Vec::new(),
            payload,
            content_format: Some(CBOR_CONTENT_FORMAT),
            observable,
        }
    }

    fn changed() -> Self {
        Self {
            code: MsgCode::Changed,
            location_path: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            observable: false,
        }
    }

    fn bad_request() -> Self {
        Self {
            code: MsgCode::BadRequest,
            location_path: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            observable: false,
        }
    }

    fn not_found() -> Self {
        Self {
            code: MsgCode::NotFound,
            location_path: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            observable: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            code: MsgCode::ServiceUnavailable,
            location_path: Vec::new(),
            payload: Vec::new(),
            content_format: None,
            observable: false,
        }
    }

    /// Join Location-Path segments into a URI path (`/msg/sent/42`).
    pub fn location_uri(&self) -> Option<String> {
        if self.location_path.is_empty() {
            None
        } else {
            Some(format!("/{}", self.location_path.join("/")))
        }
    }
}

/// Parse a `/msg/sent/{id}` path segment.
///
/// IDs MUST be canonical ASCII decimal with no leading zeros (except `0`)
/// and MUST fit in uint64. Anything else is not found (vectors: `abc`,
/// `0042`, overflow).
pub fn parse_sent_id(segment: &str) -> Option<u64> {
    if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value = segment.parse::<u64>().ok()?;
    if value.to_string() != segment {
        return None;
    }
    Some(value)
}

/// In-memory `/msg/inbox`, `/msg/sent`, and `/msg/canned` resource.
///
/// Mirrors the Python `MessagesResource` oracle so both implementations
/// consume `test/vectors/messaging.json`.
#[derive(Debug, Clone)]
pub struct MessagesStore {
    max_messages: usize,
    inbox: Vec<Value>,
    sent: HashMap<u64, Value>,
    sent_order: Vec<u64>,
    next_id: u128,
    canned: Vec<(u64, String)>,
}

impl Default for MessagesStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagesStore {
    /// Create a store with the default capacity and canned catalog.
    pub fn new() -> Self {
        Self {
            max_messages: MAX_MESSAGES,
            inbox: Vec::new(),
            sent: HashMap::new(),
            sent_order: Vec::new(),
            next_id: 1,
            canned: DEFAULT_CANNED_MESSAGES
                .iter()
                .map(|(id, text)| (*id, (*text).to_owned()))
                .collect(),
        }
    }

    /// Sent records in creation order.
    pub fn sent_messages(&self) -> Vec<&Value> {
        self.sent_order
            .iter()
            .filter_map(|id| self.sent.get(id))
            .collect()
    }

    /// Inbox records in delivery order.
    pub fn inbox_messages(&self) -> &[Value] {
        &self.inbox
    }

    /// Count of inbox entries whose `read` field is missing or falsy.
    pub fn unread_count(&self) -> u64 {
        self.inbox
            .iter()
            .filter(|msg| !message_is_read(msg))
            .count() as u64
    }

    /// Canned catalog as `(id, text)` pairs.
    pub fn canned_messages(&self) -> &[(u64, String)] {
        &self.canned
    }

    /// Look up one sent record by id.
    pub fn sent_message(&self, id: u64) -> Option<&Value> {
        self.sent.get(&id)
    }

    /// True when `id` already names a sent or inbox row (spec 18.1.1 unique).
    fn id_in_use(&self, id: u64) -> bool {
        self.sent.contains_key(&id) || self.inbox.iter().any(|msg| message_id(msg) == Some(id))
    }

    /// Next unused auto-assigned id, or `None` when the uint64 space is exhausted.
    ///
    /// SECURITY: only this path advances `next_id`. Caller-supplied ids must
    /// not latch the allocator (a single `id = u64::MAX` POST would otherwise
    /// make every later auto-assign return 5.03).
    fn allocate_id(&mut self) -> Option<u64> {
        while self.next_id <= u128::from(u64::MAX) {
            let id = u64::try_from(self.next_id).expect("next_id bounded by u64::MAX");
            self.next_id += 1;
            if !self.id_in_use(id) {
                return Some(id);
            }
        }
        None
    }

    /// `POST /msg/inbox` with no transport identity (payload `from` is stripped).
    pub fn post_inbox(&mut self, payload: &[u8]) -> MsgResponse {
        self.post_inbox_from(payload, None)
    }

    /// `POST /msg/inbox`, binding sender identity to the CoAP peer.
    ///
    /// SECURITY: payload `from` is discarded. The inbox `from` field is the
    /// transport peer, matching the Python `MessagesResource.render_post`
    /// `body.pop("from")` / `request.remote.hostinfo` rebind. Inbox records
    /// persist only spec 18.1.2 receive fields `{id, from, ts, body}`.
    pub fn post_inbox_from(&mut self, payload: &[u8], from: Option<&str>) -> MsgResponse {
        if payload.is_empty() {
            return MsgResponse::bad_request();
        }
        // SECURITY: Use strict CBOR decoding matching Python oracle. Rejects
        // trailing bytes, duplicate keys, tags, and payloads exceeding limits.
        let decoded: Value = match decode_single_cbor(payload) {
            Ok(value) => value,
            Err(_) => return MsgResponse::bad_request(),
        };
        let Value::Map(mut map) = decoded else {
            return MsgResponse::bad_request();
        };

        // SECURITY: never trust client-supplied sender identity.
        remove_key(&mut map, "from");
        if let Some(from) = from {
            set_key(&mut map, "from", Value::Text(from.to_owned()));
        }

        if let Some(canned) = map_get(&map, "canned") {
            match value_as_u64(canned) {
                Some(id) if self.canned_text(id).is_some() => {}
                _ => return MsgResponse::bad_request(),
            }
        }
        if let Some(body) = map_get(&map, "body") {
            if body.as_text().is_none() {
                return MsgResponse::bad_request();
            }
        }
        if let Some(text) = map_get(&map, "text") {
            if text.as_text().is_none() {
                return MsgResponse::bad_request();
            }
        }
        // Spec 18.1.1 optional field type validation. Reject mismatches before
        // mutation to match Python oracle _accept_outbound.
        if let Some(to) = map_get(&map, "to") {
            if to.as_text().is_none() {
                return MsgResponse::bad_request();
            }
        }
        if let Some(ack) = map_get(&map, "ack") {
            if !matches!(ack, Value::Bool(_)) {
                return MsgResponse::bad_request();
            }
        }
        if let Some(priority) = map_get(&map, "priority") {
            match value_as_u64(priority) {
                Some(p) if p <= 2 => {}
                _ => return MsgResponse::bad_request(),
            }
        }
        if let Some(ts) = map_get(&map, "ts") {
            if value_as_u64(ts).is_none() {
                return MsgResponse::bad_request();
            }
        }
        if let Some(ttl) = map_get(&map, "ttl") {
            if value_as_u64(ttl).is_none() {
                return MsgResponse::bad_request();
            }
        }
        if let Some(reply_to) = map_get(&map, "reply_to") {
            if value_as_u64(reply_to).is_none() {
                return MsgResponse::bad_request();
            }
        }

        let has_body = map_get(&map, "body").and_then(Value::as_text).is_some();
        let has_text = map_get(&map, "text").and_then(Value::as_text).is_some();
        if !has_body && !has_text {
            let Some(canned_id) = map_get(&map, "canned").and_then(value_as_u64) else {
                return MsgResponse::bad_request();
            };
            let Some(text) = self.canned_text(canned_id) else {
                return MsgResponse::bad_request();
            };
            set_key(&mut map, "body", Value::Text(text));
        }

        let assigned_id = if let Some(id_val) = map_get(&map, "id") {
            let Some(id) = value_as_u64(id_val) else {
                return MsgResponse::bad_request();
            };
            // SECURITY: caller ids are untrusted. A duplicate would overwrite
            // the sent HashMap row while appending a second inbox document.
            // Do not bump next_id to id+1: id == u64::MAX would exhaust
            // auto-assign. 5.03 is for legitimate space exhaustion only.
            if self.id_in_use(id) {
                return MsgResponse::bad_request();
            }
            id
        } else {
            let Some(id) = self.allocate_id() else {
                return MsgResponse::unavailable();
            };
            set_key(&mut map, "id", Value::Integer(id.into()));
            id
        };

        if map_get(&map, "body").is_none() {
            let text = map_get(&map, "text")
                .and_then(Value::as_text)
                .map(str::to_owned);
            if let Some(text) = text {
                set_key(&mut map, "body", Value::Text(text));
            }
        }

        let body_text = map_get(&map, "body")
            .and_then(Value::as_text)
            .unwrap_or("")
            .to_owned();

        // Spec 18.1.1: preserve sender ts when present and valid; default to 0
        // (time unknown) when absent. Receivers MAY accept omitted ts or ts=0
        // as time unknown; they are not required to wipe a valid sender ts.
        let sender_ts = map_get(&map, "ts").and_then(value_as_u64).unwrap_or(0);

        // SECURITY: Filter to spec 18.1.1 keys only. Drop client-supplied 'read'
        // and other non-spec keys. Matches Python _accept_outbound allowed_keys.
        const ALLOWED_KEYS: &[&str] = &[
            "from", "to", "body", "text", "ts", "ack", "priority", "reply_to", "ttl", "canned",
            "id",
        ];
        let filtered_map: Vec<(Value, Value)> = map
            .into_iter()
            .filter(|(k, _)| k.as_text().map_or(false, |key| ALLOWED_KEYS.contains(&key)))
            .collect();
        let stored = Value::Map(filtered_map);
        self.sent.insert(assigned_id, stored);
        if !self.sent_order.contains(&assigned_id) {
            self.sent_order.push(assigned_id);
        }
        if self.sent_order.len() > self.max_messages {
            let drop_count = self.sent_order.len() - self.max_messages;
            let dropped: Vec<u64> = self.sent_order.drain(..drop_count).collect();
            for id in dropped {
                self.sent.remove(&id);
            }
        }
        // Inbox is a server-authoritative receive document, not the caller map.
        // Preserve sender ts when valid; default to 0 (time unknown).
        self.inbox.push(inbox_receive_document(
            assigned_id,
            from,
            sender_ts,
            &body_text,
        ));
        if self.inbox.len() > self.max_messages {
            let drop_count = self.inbox.len() - self.max_messages;
            self.inbox.drain(..drop_count);
        }
        MsgResponse::created(assigned_id)
    }

    /// `GET /msg/inbox`.
    pub fn get_inbox(&self) -> MsgResponse {
        let unread = self.unread_count();
        let payload = Value::Map(vec![
            (
                Value::Text("messages".into()),
                Value::Array(self.inbox.clone()),
            ),
            (Value::Text("unread".into()), Value::Integer(unread.into())),
        ]);
        MsgResponse::content(encode_cbor(&payload), true)
    }

    /// `GET /msg/sent`.
    pub fn get_sent(&self) -> MsgResponse {
        let messages: Vec<Value> = self
            .sent_order
            .iter()
            .filter_map(|id| self.sent.get(id).cloned())
            .collect();
        let payload = Value::Map(vec![(
            Value::Text("messages".into()),
            Value::Array(messages),
        )]);
        MsgResponse::content(encode_cbor(&payload), false)
    }

    /// `GET /msg/sent/{id}`.
    pub fn get_sent_id(&self, segment: &str) -> MsgResponse {
        let Some(id) = parse_sent_id(segment) else {
            return MsgResponse::not_found();
        };
        match self.sent.get(&id) {
            Some(message) => MsgResponse::content(encode_cbor(message), false),
            None => MsgResponse::not_found(),
        }
    }

    /// `GET /msg/canned`.
    pub fn get_canned(&self) -> MsgResponse {
        let messages: Vec<Value> = self
            .canned
            .iter()
            .map(|(id, text)| {
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Integer((*id).into())),
                    (Value::Text("text".into()), Value::Text(text.clone())),
                ])
            })
            .collect();
        let payload = Value::Map(vec![(
            Value::Text("messages".into()),
            Value::Array(messages),
        )]);
        MsgResponse::content(encode_cbor(&payload), false)
    }

    fn canned_text(&self, id: u64) -> Option<String> {
        self.canned
            .iter()
            .find(|(canned_id, _)| *canned_id == id)
            .map(|(_, text)| text.clone())
    }
}

/// In-memory `/msg/ack` resource.
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    max_receipts: usize,
    receipts: Vec<DeliveryReceipt>,
}

impl Default for ReceiptStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptStore {
    /// Create a store with the default receipt depth.
    pub fn new() -> Self {
        Self {
            max_receipts: MAX_MESSAGES,
            receipts: Vec::new(),
        }
    }

    /// Stored receipts in POST order.
    pub fn receipts(&self) -> &[DeliveryReceipt] {
        &self.receipts
    }

    /// `POST /msg/ack`.
    pub fn post(&mut self, payload: &[u8]) -> MsgResponse {
        if payload.is_empty() {
            return MsgResponse::bad_request();
        }
        match DeliveryReceipt::from_cbor(payload) {
            Ok(receipt) => {
                self.receipts.push(receipt);
                if self.receipts.len() > self.max_receipts {
                    let drop_count = self.receipts.len() - self.max_receipts;
                    self.receipts.drain(..drop_count);
                }
                MsgResponse::changed()
            }
            Err(_) => MsgResponse::bad_request(),
        }
    }
}

/// Combined messaging resources used to consume `messaging.json`.
#[derive(Debug, Clone, Default)]
pub struct MessagingResources {
    /// Inbox / sent / canned store.
    pub messages: MessagesStore,
    /// Delivery-receipt store.
    pub receipts: ReceiptStore,
}

impl MessagingResources {
    /// Create empty inbox, sent, canned, and receipt resources.
    pub fn new() -> Self {
        Self::default()
    }

    /// Dispatch one CoAP method/path against the messaging resources.
    pub fn handle(&mut self, method: &str, resource: &str, payload: &[u8]) -> MsgResponse {
        self.handle_from(method, resource, payload, None)
    }

    /// Like [`Self::handle`], binding POST `/msg/inbox` sender to `from`.
    pub fn handle_from(
        &mut self,
        method: &str,
        resource: &str,
        payload: &[u8],
        from: Option<&str>,
    ) -> MsgResponse {
        match (method, resource) {
            ("POST", "/msg/inbox") => self.messages.post_inbox_from(payload, from),
            ("GET", "/msg/inbox") => self.messages.get_inbox(),
            ("GET", "/msg/sent") => self.messages.get_sent(),
            ("POST", "/msg/ack") => self.receipts.post(payload),
            ("GET", "/msg/canned") => self.messages.get_canned(),
            ("GET", path) => match path.strip_prefix("/msg/sent/") {
                Some(segment) => self.messages.get_sent_id(segment),
                None => MsgResponse::not_found(),
            },
            _ => MsgResponse::not_found(),
        }
    }
}

/// Decode one CBOR item with strict validation matching the Python oracle.
///
/// Rejects:
/// - Payloads exceeding `CBOR_MAX_ENCODED_BYTES` (4096)
/// - Trailing bytes after the first CBOR item
/// - CBOR tags anywhere in the value
/// - Duplicate map keys
/// - Maps exceeding `CBOR_MAX_MAP_ENTRIES` (64)
/// - Arrays exceeding `CBOR_MAX_ARRAY_ENTRIES` (256)
/// - Nesting depth exceeding `CBOR_MAX_DEPTH` (16)
/// - Total item count exceeding `CBOR_MAX_ITEMS` (1024)
fn decode_single_cbor(payload: &[u8]) -> Result<Value, Error> {
    if payload.len() > CBOR_MAX_ENCODED_BYTES {
        return Err(Error::Decode(
            "CBOR payload exceeds mutation byte limit".into(),
        ));
    }
    let mut reader = Cursor::new(payload);
    let value: Value =
        ciborium::from_reader(&mut reader).map_err(|e| Error::Decode(e.to_string()))?;
    if reader.position() != payload.len() as u64 {
        return Err(Error::Decode("trailing data after CBOR item".into()));
    }
    validate_cbor_value(&value, 0, &mut 0)?;
    Ok(value)
}

/// Recursively validate a decoded CBOR value against mutation limits.
fn validate_cbor_value(value: &Value, depth: usize, items: &mut usize) -> Result<(), Error> {
    if depth > CBOR_MAX_DEPTH {
        return Err(Error::Decode(
            "CBOR nesting depth exceeds mutation limit".into(),
        ));
    }
    *items += 1;
    if *items > CBOR_MAX_ITEMS {
        return Err(Error::Decode(
            "CBOR item count exceeds mutation limit".into(),
        ));
    }
    match value {
        Value::Tag(_, _) => Err(Error::Decode(
            "CBOR tags are not allowed in mutation payloads".into(),
        )),
        Value::Array(entries) => {
            if entries.len() > CBOR_MAX_ARRAY_ENTRIES {
                return Err(Error::Decode("CBOR array exceeds mutation limit".into()));
            }
            for entry in entries {
                validate_cbor_value(entry, depth + 1, items)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            if entries.len() > CBOR_MAX_MAP_ENTRIES {
                return Err(Error::Decode("CBOR map exceeds mutation limit".into()));
            }
            // Check for duplicate keys
            for (index, (key, _)) in entries.iter().enumerate() {
                if entries[..index].iter().any(|(prev_key, _)| prev_key == key) {
                    return Err(Error::Decode("duplicate CBOR map key".into()));
                }
                validate_cbor_value(key, depth + 1, items)?;
            }
            for (_, val) in entries {
                validate_cbor_value(val, depth + 1, items)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn encode_cbor(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR encode to Vec cannot fail");
    buf
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k.as_text() {
        Some(text) if text == key => Some(v),
        _ => None,
    })
}

fn set_key(map: &mut Vec<(Value, Value)>, key: &str, val: Value) {
    if let Some((_, slot)) = map.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
        *slot = val;
    } else {
        map.push((Value::Text(key.to_owned()), val));
    }
}

fn remove_key(map: &mut Vec<(Value, Value)>, key: &str) {
    map.retain(|(k, _)| k.as_text() != Some(key));
}

/// Spec 18.1.2 inbox item. Drops send-only and client-controlled keys.
/// Preserves sender `ts` when present and valid; defaults to 0 (time unknown).
fn inbox_receive_document(id: u64, from: Option<&str>, ts: u64, body: &str) -> Value {
    let mut map = vec![
        (Value::Text("id".into()), Value::Integer(id.into())),
        (Value::Text("ts".into()), Value::Integer(ts.into())),
        (Value::Text("body".into()), Value::Text(body.to_owned())),
    ];
    if let Some(from) = from {
        map.insert(
            1,
            (Value::Text("from".into()), Value::Text(from.to_owned())),
        );
    }
    Value::Map(map)
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(integer) => u64::try_from(*integer).ok(),
        _ => None,
    }
}

fn message_id(value: &Value) -> Option<u64> {
    let Value::Map(map) = value else {
        return None;
    };
    map_get(map, "id").and_then(value_as_u64)
}

fn message_is_read(value: &Value) -> bool {
    let Value::Map(map) = value else {
        return false;
    };
    match map_get(map, "read") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Integer(integer)) => i128::from(*integer) != 0,
        Some(Value::Text(text)) if text.is_empty() => false,
        Some(Value::Array(items)) if items.is_empty() => false,
        Some(Value::Map(entries)) if entries.is_empty() => false,
        Some(Value::Bytes(bytes)) if bytes.is_empty() => false,
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: hand-derived CBOR bytes (per RFC 8949) for the exact map the
    /// firmware `POST /msg/sent` handler decodes. Independent of the encoder
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
        assert_eq!(inbox.unread, 0);
    }

    /// A bare CBOR array (the shape an early client wrongly assumed) is not a
    /// valid inbox response and must be rejected, not silently mis-parsed.
    #[test]
    fn inbox_rejects_bare_array() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Array(vec![]), &mut bytes).unwrap();
        assert!(Inbox::from_cbor(&bytes).is_err());
    }

    /// Oracle: firmware `POST /msg/sent` response keys
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

    /// Oracle: firmware `GET /msg/sent` response envelope
    /// (`messages: [{id, to, body, timestamp, status}]`).
    #[test]
    fn sent_list_decodes_firmware_envelope() {
        let wire = Value::Map(vec![(
            Value::Text("messages".into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("id".into()), Value::Integer(42u64.into())),
                (Value::Text("to".into()), Value::Text("fd00::9".into())),
                (Value::Text("body".into()), Value::Text("ping".into())),
                (
                    Value::Text("timestamp".into()),
                    Value::Integer(1_716_742_801u64.into()),
                ),
                (
                    Value::Text("status".into()),
                    Value::Text("delivered".into()),
                ),
            ])]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        let sent = Sent::from_cbor(&bytes).unwrap();
        assert_eq!(
            sent.messages,
            vec![SentMessage {
                id: 42,
                to: "fd00::9".into(),
                body: "ping".into(),
                timestamp: 1_716_742_801,
                status: "delivered".into(),
            }]
        );
    }

    #[test]
    fn receipt_status_wire_names() {
        assert_eq!(ReceiptStatus::Delivered.as_str(), "delivered");
        assert_eq!(ReceiptStatus::Read.as_str(), "read");
        assert_eq!(ReceiptStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn receipt_round_trip() {
        let receipt = DeliveryReceipt::new(12_345, ReceiptStatus::Read, 1_716_742_901);
        let encoded = receipt.to_cbor().unwrap();
        assert_eq!(DeliveryReceipt::from_cbor(&encoded).unwrap(), receipt);
    }

    #[test]
    fn receipt_rejects_unknown_status() {
        let wire = Value::Map(vec![
            (Value::Text("id".into()), Value::Integer(12_345u64.into())),
            (Value::Text("status".into()), Value::Text("unknown".into())),
            (
                Value::Text("ts".into()),
                Value::Integer(1_716_742_900u64.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        assert!(DeliveryReceipt::from_cbor(&bytes).is_err());
    }

    #[test]
    fn parse_sent_id_canonical_decimal() {
        assert_eq!(parse_sent_id("0"), Some(0));
        assert_eq!(parse_sent_id("42"), Some(42));
        assert_eq!(parse_sent_id("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_sent_id("abc"), None);
        assert_eq!(parse_sent_id("0042"), None);
        assert_eq!(parse_sent_id("00"), None);
        assert_eq!(parse_sent_id(""), None);
        assert_eq!(parse_sent_id("18446744073709551616"), None);
        assert_eq!(parse_sent_id("-1"), None);
    }

    #[test]
    fn inbox_post_accepts_legacy_text_and_assigns_id() {
        let mut store = MessagesStore::new();
        let post = InboxPost {
            text: Some("Legacy text field".into()),
            to: Some("0200:1234:5678:9abc::1111:2222:3333:4444".into()),
            ..InboxPost::default()
        };
        let resp = store.post_inbox(&post.to_cbor().unwrap());
        assert_eq!(resp.code, MsgCode::Created);
        assert_eq!(resp.location_uri().as_deref(), Some("/msg/sent/1"));
        let stored = store.sent_message(1).unwrap();
        let Value::Map(map) = stored else {
            panic!("map")
        };
        assert_eq!(
            map_get(map, "body").and_then(Value::as_text),
            Some("Legacy text field")
        );
    }

    #[test]
    fn inbox_post_expands_canned_catalog() {
        let mut store = MessagesStore::new();
        let post = InboxPost {
            canned: Some(4),
            ack: Some(true),
            ..InboxPost::default()
        };
        let resp = store.post_inbox(&post.to_cbor().unwrap());
        assert_eq!(resp.code, MsgCode::Created);
        let stored = store.sent_messages().last().copied().unwrap();
        let Value::Map(map) = stored else {
            panic!("map")
        };
        assert_eq!(
            map_get(map, "body").and_then(Value::as_text),
            Some("Emergency - send help")
        );
    }

    #[test]
    fn inbox_get_includes_unread() {
        let mut store = MessagesStore::new();
        let resp = store.post_inbox(&InboxPost::new("hi").to_cbor().unwrap());
        assert_eq!(resp.code, MsgCode::Created);
        let get = store.get_inbox();
        assert_eq!(get.code, MsgCode::Content);
        assert!(get.observable);
        assert_eq!(get.content_format, Some(CBOR_CONTENT_FORMAT));
        assert_eq!(store.unread_count(), 1);
        let inbox = Inbox::from_cbor(&get.payload).unwrap();
        assert_eq!(inbox.unread, 1);
        assert_eq!(inbox.messages.len(), 1);
        assert_eq!(inbox.messages[0].id, 1);
        assert_eq!(inbox.messages[0].body, "hi");
    }

    #[test]
    fn inbox_post_strips_spoofed_from_without_peer() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (
                Value::Text("from".into()),
                Value::Text("fe80::spoof".into()),
            ),
            (Value::Text("body".into()), Value::Text("hi".into())),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::Created);

        let Value::Map(sent) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        assert!(map_get(sent, "from").is_none());

        let Value::Map(inbox) = &store.inbox_messages()[0] else {
            panic!("inbox map")
        };
        assert!(map_get(inbox, "from").is_none());
        assert_eq!(map_get(inbox, "body").and_then(Value::as_text), Some("hi"));
    }

    #[test]
    fn inbox_post_rebinds_from_to_transport_peer() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (
                Value::Text("from".into()),
                Value::Text("fe80::spoof".into()),
            ),
            (Value::Text("body".into()), Value::Text("hi".into())),
        ]);
        let resp = store.post_inbox_from(&encode_cbor(&wire), Some("fe80::1"));
        assert_eq!(resp.code, MsgCode::Created);

        let Value::Map(sent) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(sent, "from").and_then(Value::as_text),
            Some("fe80::1")
        );

        let Value::Map(inbox) = &store.inbox_messages()[0] else {
            panic!("inbox map")
        };
        assert_eq!(
            map_get(inbox, "from").and_then(Value::as_text),
            Some("fe80::1")
        );
    }

    /// SECURITY: Payloads with duplicate map keys are rejected per Python oracle.
    /// RFC 8949 SS5.6 forbids duplicate keys; the first-vs-last ambiguity is a
    /// classic security split. Strict rejection prevents parser differentials.
    #[test]
    fn inbox_post_rejects_duplicate_map_keys() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("from".into()), Value::Text("spoof-a".into())),
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("from".into()), Value::Text("spoof-b".into())),
        ]);
        let resp = store.post_inbox_from(&encode_cbor(&wire), Some("fe80::peer"));
        // Duplicate keys must be rejected, not silently processed
        assert_eq!(resp.code, MsgCode::BadRequest);
    }

    #[test]
    fn inbox_post_ignores_client_read_for_unread() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("read".into()), Value::Bool(true)),
        ]);
        assert_eq!(store.post_inbox(&encode_cbor(&wire)).code, MsgCode::Created);
        assert_eq!(store.unread_count(), 1);

        let Value::Map(inbox) = &store.inbox_messages()[0] else {
            panic!("inbox map")
        };
        assert!(map_get(inbox, "read").is_none());
    }

    #[test]
    fn inbox_post_persists_only_receive_fields() {
        let mut store = MessagesStore::new();
        let post = InboxPost {
            to: Some("ff02::1".into()),
            from: Some("fe80::spoof".into()),
            ts: Some(1_716_742_800),
            body: Some("hello".into()),
            text: Some("legacy".into()),
            canned: Some(0),
            ack: Some(true),
            priority: Some(2),
            ..InboxPost::default()
        };
        let resp = store.post_inbox_from(&post.to_cbor().unwrap(), Some("fe80::abcd"));
        assert_eq!(resp.code, MsgCode::Created);

        let Value::Map(inbox) = &store.inbox_messages()[0] else {
            panic!("inbox map")
        };
        let keys: Vec<&str> = inbox.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert_eq!(keys, ["id", "from", "ts", "body"]);
        assert_eq!(
            map_get(inbox, "from").and_then(Value::as_text),
            Some("fe80::abcd")
        );
        assert_eq!(
            map_get(inbox, "body").and_then(Value::as_text),
            Some("hello")
        );
        // Spec 18.1.1: sender ts is preserved, not wiped to 0.
        assert_eq!(
            map_get(inbox, "ts").and_then(value_as_u64),
            Some(1_716_742_800)
        );
        assert!(map_get(inbox, "to").is_none());
        assert!(map_get(inbox, "canned").is_none());
        assert!(map_get(inbox, "ack").is_none());
        assert!(map_get(inbox, "priority").is_none());
        assert!(map_get(inbox, "text").is_none());

        let Value::Map(sent) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(sent, "to").and_then(Value::as_text),
            Some("ff02::1")
        );
        assert_eq!(map_get(sent, "ack"), Some(&Value::Bool(true)));
        assert_eq!(
            map_get(sent, "from").and_then(Value::as_text),
            Some("fe80::abcd")
        );
        assert_ne!(
            map_get(sent, "from").and_then(Value::as_text),
            Some("fe80::spoof")
        );
    }

    #[test]
    fn handle_from_rebinds_inbox_sender() {
        let mut resources = MessagingResources::new();
        let post = InboxPost::new("via handle");
        let resp = resources.handle_from(
            "POST",
            "/msg/inbox",
            &post.to_cbor().unwrap(),
            Some("fe80::cafe"),
        );
        assert_eq!(resp.code, MsgCode::Created);
        let get = resources.handle("GET", "/msg/inbox", &[]);
        let decoded: Value = ciborium::from_reader(get.payload.as_slice()).unwrap();
        let Value::Map(envelope) = decoded else {
            panic!("envelope")
        };
        let Value::Array(messages) = map_get(&envelope, "messages").unwrap() else {
            panic!("messages")
        };
        let Value::Map(item) = &messages[0] else {
            panic!("item")
        };
        assert_eq!(
            map_get(item, "from").and_then(Value::as_text),
            Some("fe80::cafe")
        );
        assert_eq!(
            map_get(item, "body").and_then(Value::as_text),
            Some("via handle")
        );
    }

    /// Spec 18.1.1: `id` is a unique message ID. A second POST with the same
    /// caller id is 4.00 and must not overwrite the sent row or append inbox.
    #[test]
    fn inbox_post_rejects_duplicate_id_without_overwrite() {
        let mut store = MessagesStore::new();
        let first = InboxPost {
            id: Some(7),
            body: Some("original".into()),
            ..InboxPost::default()
        };
        let second = InboxPost {
            id: Some(7),
            body: Some("overwrite-me".into()),
            ..InboxPost::default()
        };

        assert_eq!(
            store.post_inbox(&first.to_cbor().unwrap()).code,
            MsgCode::Created
        );
        let dup = store.post_inbox(&second.to_cbor().unwrap());
        assert_eq!(dup.code, MsgCode::BadRequest);
        assert!(dup.location_path.is_empty());

        assert_eq!(store.sent_messages().len(), 1);
        assert_eq!(store.inbox_messages().len(), 1);
        let Value::Map(sent) = store.sent_message(7).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(sent, "body").and_then(Value::as_text),
            Some("original")
        );
        let Value::Map(inbox) = &store.inbox_messages()[0] else {
            panic!("inbox map")
        };
        assert_eq!(map_get(inbox, "id").and_then(value_as_u64), Some(7));
        assert_eq!(
            map_get(inbox, "body").and_then(Value::as_text),
            Some("original")
        );

        // Duplicate reject must not latch or skip the auto-assign sequence.
        let auto = store.post_inbox(&InboxPost::new("auto").to_cbor().unwrap());
        assert_eq!(auto.code, MsgCode::Created);
        assert_eq!(auto.location_uri().as_deref(), Some("/msg/sent/1"));
        assert_eq!(store.sent_messages().len(), 2);
        assert_eq!(store.inbox_messages().len(), 2);
    }

    /// Caller `id = u64::MAX` is a valid explicit id (vectors) but must not
    /// set next_id to MAX+1. Later omitted-id POSTs still auto-assign from 1.
    #[test]
    fn inbox_post_max_id_does_not_latch_allocator() {
        let mut store = MessagesStore::new();
        let max_post = InboxPost {
            id: Some(u64::MAX),
            body: Some("max".into()),
            ..InboxPost::default()
        };
        let max_resp = store.post_inbox(&max_post.to_cbor().unwrap());
        assert_eq!(max_resp.code, MsgCode::Created);
        assert_eq!(
            max_resp.location_uri().as_deref(),
            Some("/msg/sent/18446744073709551615")
        );

        let auto = store.post_inbox(&InboxPost::new("auto").to_cbor().unwrap());
        assert_eq!(auto.code, MsgCode::Created);
        assert_eq!(auto.location_uri().as_deref(), Some("/msg/sent/1"));
        assert_ne!(auto.code, MsgCode::ServiceUnavailable);

        assert_eq!(store.sent_messages().len(), 2);
        assert!(store.sent_message(u64::MAX).is_some());
        assert!(store.sent_message(1).is_some());
        let Value::Map(auto_sent) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(auto_sent, "body").and_then(Value::as_text),
            Some("auto")
        );
        let Value::Map(max_sent) = store.sent_message(u64::MAX).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(max_sent, "body").and_then(Value::as_text),
            Some("max")
        );
    }

    /// Occupying the next auto-assign id with an explicit POST must not
    /// overwrite on the following omitted-id POST; the allocator skips it.
    #[test]
    fn inbox_post_auto_assign_skips_occupied_id() {
        let mut store = MessagesStore::new();
        let explicit = InboxPost {
            id: Some(1),
            body: Some("taken".into()),
            ..InboxPost::default()
        };
        assert_eq!(
            store.post_inbox(&explicit.to_cbor().unwrap()).code,
            MsgCode::Created
        );

        let auto = store.post_inbox(&InboxPost::new("auto").to_cbor().unwrap());
        assert_eq!(auto.code, MsgCode::Created);
        assert_eq!(auto.location_uri().as_deref(), Some("/msg/sent/2"));

        let Value::Map(first) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(first, "body").and_then(Value::as_text),
            Some("taken")
        );
        let Value::Map(second) = store.sent_message(2).unwrap() else {
            panic!("sent map")
        };
        assert_eq!(
            map_get(second, "body").and_then(Value::as_text),
            Some("auto")
        );
        assert_eq!(store.inbox_messages().len(), 2);
    }

    /// SECURITY: Spec 18.1.1 sent records must not echo arbitrary extra keys.
    /// Verify that non-spec keys are filtered from sent rows.
    #[test]
    fn inbox_post_filters_extra_keys_from_sent() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (
                Value::Text("extra_key".into()),
                Value::Text("should drop".into()),
            ),
            (
                Value::Text("arbitrary".into()),
                Value::Integer(12345.into()),
            ),
            (Value::Text("read".into()), Value::Bool(true)),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::Created);

        let Value::Map(sent) = store.sent_message(1).unwrap() else {
            panic!("sent map")
        };
        let keys: Vec<&str> = sent.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert!(keys.contains(&"body"));
        assert!(keys.contains(&"id"));
        assert!(!keys.contains(&"extra_key"));
        assert!(!keys.contains(&"arbitrary"));
        assert!(!keys.contains(&"read"));
    }

    /// Spec 18.1.1: to must be tstr. Nested map is rejected.
    #[test]
    fn inbox_post_rejects_invalid_to_type() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("to".into()), Value::Map(vec![])),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }

    /// Spec 18.1.1: ack must be bool. Integer is rejected.
    #[test]
    fn inbox_post_rejects_invalid_ack_type() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("ack".into()), Value::Integer(1.into())),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }

    /// Spec 18.1.1: priority must be uint 0..2. Value outside range is rejected.
    #[test]
    fn inbox_post_rejects_invalid_priority_value() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("priority".into()), Value::Integer(99.into())),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }

    /// Spec 18.1.1: ttl must be uint. Negative is rejected.
    #[test]
    fn inbox_post_rejects_negative_ttl() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("ttl".into()), Value::Integer((-1).into())),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }

    /// Spec 18.1.1: reply_to must be uint. String is rejected.
    #[test]
    fn inbox_post_rejects_invalid_reply_to_type() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (
                Value::Text("reply_to".into()),
                Value::Text("not-an-id".into()),
            ),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }

    /// Spec 18.1.1: ts must be uint. Negative is rejected.
    #[test]
    fn inbox_post_rejects_negative_ts() {
        let mut store = MessagesStore::new();
        let wire = Value::Map(vec![
            (Value::Text("body".into()), Value::Text("hi".into())),
            (Value::Text("ts".into()), Value::Integer((-100).into())),
        ]);
        let resp = store.post_inbox(&encode_cbor(&wire));
        assert_eq!(resp.code, MsgCode::BadRequest);
        assert!(store.sent_messages().is_empty());
    }
}
