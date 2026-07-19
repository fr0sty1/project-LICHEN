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
}
