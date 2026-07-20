// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Peer link-key (TOFU) domain types and CBOR wire codecs.
//!
//! Wire contract (firmware `lichen/subsys/lichen/coap/coap_keys.c`):
//!
//! - `GET /keys` : `{keys: [{iid, pubkey_fp, trust, first_seen, last_seen}]}`.
//!
//! SECURITY: `trust` reflects the node's link-key trust state for a peer
//! interface identifier (`none`, `tofu`, `dane`, `verified`). The node pins
//! the first pubkey seen for an IID (trust-on-first-use) and rejects later
//! pubkey changes for that IID; this list is the client's view of those
//! anchors. The write side (`PUT`/`DELETE /keys/{iid}`) is intentionally not
//! modeled here yet — pinning UX is a separate, security-sensitive change.

use serde::{Deserialize, Serialize};

use crate::Error;

/// One entry of the `GET /keys` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyListEntry {
    /// Peer interface identifier (hex).
    pub iid: String,
    /// Short fingerprint of the peer's pinned public key.
    pub pubkey_fp: String,
    /// Trust state: `none`, `tofu`, `dane`, `verified`.
    pub trust: String,
    /// When the key was first seen (ISO 8601).
    pub first_seen: String,
    /// When the key was last seen (ISO 8601).
    pub last_seen: String,
}

/// The `GET /keys` response envelope: `{keys: [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyList {
    pub keys: Vec<KeyListEntry>,
}

impl KeyList {
    /// Decode a `GET /keys` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// The `GET /keys/{iid}` single-key detail (full base64 public key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Peer interface identifier (hex, `xxxx:xxxx:xxxx:xxxx`).
    pub iid: String,
    /// Base64-encoded public key.
    pub pubkey: String,
    /// Trust state: `none`, `tofu`, `dane`, `verified`.
    pub trust: String,
    /// When the key was first seen (ISO 8601).
    pub first_seen: String,
    /// When the key was last seen (ISO 8601).
    pub last_seen: String,
}

impl KeyEntry {
    /// Decode a `GET /keys/{iid}` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// The `PUT /keys/{iid}` body used to pin/set a peer's key.
///
/// SECURITY: the node TOFU-rejects any request whose `pubkey` differs from the
/// one already pinned for the IID (4.09 Conflict). A client therefore confirms
/// a trust level by re-sending the *same* pubkey it already observed; it cannot
/// inject a new key for an existing IID this way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPin {
    /// Base64-encoded public key (must match the pinned key for existing IIDs).
    pub pubkey: String,
    /// Target trust level: `none`, `tofu`, `dane`, `verified`.
    pub trust: String,
}

impl KeyPin {
    /// Encode as the CBOR body the firmware `PUT /keys/{iid}` handler expects.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR encode to Vec cannot fail");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn txt(s: &str) -> Value {
        Value::Text(s.into())
    }

    /// Oracle: the firmware `/keys` envelope with the exact per-entry keys
    /// (`iid`/`pubkey_fp`/`trust`/`first_seen`/`last_seen`).
    #[test]
    fn key_list_decodes_firmware_envelope() {
        let wire = Value::Map(vec![(
            txt("keys"),
            Value::Array(vec![Value::Map(vec![
                (txt("iid"), txt("7a7ff09dc86c2c10")),
                (txt("pubkey_fp"), txt("SHA256:abcd1234")),
                (txt("trust"), txt("tofu")),
                (txt("first_seen"), txt("2026-07-01T00:00:00Z")),
                (txt("last_seen"), txt("2026-07-18T12:00:00Z")),
            ])]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        let list = KeyList::from_cbor(&bytes).unwrap();
        assert_eq!(
            list.keys,
            vec![KeyListEntry {
                iid: "7a7ff09dc86c2c10".into(),
                pubkey_fp: "SHA256:abcd1234".into(),
                trust: "tofu".into(),
                first_seen: "2026-07-01T00:00:00Z".into(),
                last_seen: "2026-07-18T12:00:00Z".into(),
            }]
        );
    }

    /// An empty key table is valid and yields an empty list.
    #[test]
    fn key_list_empty() {
        let wire = Value::Map(vec![(txt("keys"), Value::Array(vec![]))]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();
        assert!(KeyList::from_cbor(&bytes).unwrap().keys.is_empty());
    }

    /// Oracle: the firmware `GET /keys/{iid}` map keys
    /// (`iid`/`pubkey`/`trust`/`first_seen`/`last_seen`).
    #[test]
    fn key_entry_decodes_firmware_map() {
        let wire = Value::Map(vec![
            (txt("iid"), txt("7a7f:f09d:c86c:2c10")),
            (txt("pubkey"), txt("YWJjZGVmZ2g=")),
            (txt("trust"), txt("tofu")),
            (txt("first_seen"), txt("2026-07-01T00:00:00Z")),
            (txt("last_seen"), txt("2026-07-18T12:00:00Z")),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).unwrap();

        let e = KeyEntry::from_cbor(&bytes).unwrap();
        assert_eq!(e.iid, "7a7f:f09d:c86c:2c10");
        assert_eq!(e.pubkey, "YWJjZGVmZ2g=");
        assert_eq!(e.trust, "tofu");
    }

    /// The PUT body must carry exactly the firmware keys `pubkey` and `trust`.
    #[test]
    fn key_pin_encodes_pubkey_and_trust() {
        let pin = KeyPin {
            pubkey: "YWJjZGVmZ2g=".into(),
            trust: "verified".into(),
        };
        let v: Value = ciborium::from_reader(pin.to_cbor().as_slice()).unwrap();
        let map = match v {
            Value::Map(m) => m,
            other => panic!("expected map, got {other:?}"),
        };
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .and_then(|(_, val)| val.as_text())
                .map(str::to_owned)
        };
        assert_eq!(get("pubkey").as_deref(), Some("YWJjZGVmZ2g="));
        assert_eq!(get("trust").as_deref(), Some("verified"));
        assert_eq!(map.len(), 2);
    }
}
