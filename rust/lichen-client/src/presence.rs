// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Presence and status domain types with CBOR wire codecs.
//!
//! Wire contract (firmware `/presence` resource, spec Section 18.5.1):
//!
//! ```cbor
//! {
//!   "status": "available",      ; presence status (tstr)
//!   "activity": "moving",       ; activity hint (tstr, optional)
//!   "msg": "On patrol",         ; custom status message (tstr, optional)
//!   "battery": 87,              ; battery percentage (uint, optional)
//!   "ts": 1716742800            ; last update (uint)
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::Error;

/// Presence status values (based on RFC 3863 simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceStatus {
    /// Online and reachable.
    Available,
    /// Online but occupied.
    Busy,
    /// Temporarily unavailable.
    Away,
    /// Not reachable.
    Offline,
    /// In emergency state.
    Emergency,
}

impl PresenceStatus {
    /// Returns the status as a string slice matching the wire format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Busy => "busy",
            Self::Away => "away",
            Self::Offline => "offline",
            Self::Emergency => "emergency",
        }
    }
}

impl core::fmt::Display for PresenceStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Activity hint values (optional refinement of presence status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Activity {
    /// Not moving.
    Stationary,
    /// In motion.
    Moving,
    /// Taking break.
    Resting,
    /// Performing task.
    Working,
}

impl Activity {
    /// Returns the activity as a string slice matching the wire format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stationary => "stationary",
            Self::Moving => "moving",
            Self::Resting => "resting",
            Self::Working => "working",
        }
    }
}

impl core::fmt::Display for Activity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A node's presence state from `GET /presence`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Presence {
    /// Presence status (required).
    pub status: PresenceStatus,
    /// Activity hint (optional refinement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<Activity>,
    /// Custom status message (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// Battery percentage (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<u32>,
    /// Last update timestamp (Unix seconds).
    pub ts: u64,
}

impl Presence {
    /// Create a new presence with required fields only.
    pub fn new(status: PresenceStatus, ts: u64) -> Self {
        Self {
            status,
            activity: None,
            msg: None,
            battery: None,
            ts,
        }
    }

    /// Decode a `GET /presence` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }

    /// Encode to CBOR for `PUT /presence`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(buf)
    }
}

/// One entry of the `GET /presence/cache` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceCacheEntry {
    /// Node IPv6 address string.
    pub addr: String,
    /// Presence status.
    pub status: PresenceStatus,
    /// Battery percentage (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<u32>,
    /// Seconds since the presence was last updated.
    pub age_s: u64,
}

/// The `GET /presence/cache` response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceCache {
    pub nodes: Vec<PresenceCacheEntry>,
}

impl PresenceCache {
    /// Decode a `GET /presence/cache` CBOR response.
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

    fn encode(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    /// Oracle: a CBOR map built with the exact /presence keys from the spec,
    /// independent of the struct's serde mapping.
    #[test]
    fn presence_decodes_firmware_map() {
        let wire = Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("activity"), txt("moving")),
            (txt("msg"), txt("On patrol")),
            (txt("battery"), Value::Integer(87u64.into())),
            (txt("ts"), Value::Integer(1_716_742_800u64.into())),
        ]);

        let p = Presence::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(p.status, PresenceStatus::Available);
        assert_eq!(p.activity, Some(Activity::Moving));
        assert_eq!(p.msg.as_deref(), Some("On patrol"));
        assert_eq!(p.battery, Some(87));
        assert_eq!(p.ts, 1_716_742_800);
    }

    /// Minimal presence with only required fields.
    #[test]
    fn presence_minimal() {
        let wire = Value::Map(vec![
            (txt("status"), txt("busy")),
            (txt("ts"), Value::Integer(100u64.into())),
        ]);

        let p = Presence::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(p.status, PresenceStatus::Busy);
        assert_eq!(p.activity, None);
        assert_eq!(p.msg, None);
        assert_eq!(p.battery, None);
        assert_eq!(p.ts, 100);
    }

    /// All status values decode correctly.
    #[test]
    fn presence_status_variants() {
        for (s, expected) in [
            ("available", PresenceStatus::Available),
            ("busy", PresenceStatus::Busy),
            ("away", PresenceStatus::Away),
            ("offline", PresenceStatus::Offline),
            ("emergency", PresenceStatus::Emergency),
        ] {
            let wire = Value::Map(vec![
                (txt("status"), txt(s)),
                (txt("ts"), Value::Integer(0u64.into())),
            ]);
            let p = Presence::from_cbor(&encode(&wire)).unwrap();
            assert_eq!(p.status, expected);
        }
    }

    /// All activity values decode correctly.
    #[test]
    fn presence_activity_variants() {
        for (a, expected) in [
            ("stationary", Activity::Stationary),
            ("moving", Activity::Moving),
            ("resting", Activity::Resting),
            ("working", Activity::Working),
        ] {
            let wire = Value::Map(vec![
                (txt("status"), txt("available")),
                (txt("activity"), txt(a)),
                (txt("ts"), Value::Integer(0u64.into())),
            ]);
            let p = Presence::from_cbor(&encode(&wire)).unwrap();
            assert_eq!(p.activity, Some(expected));
        }
    }

    /// Round-trip encode/decode.
    #[test]
    fn presence_roundtrip() {
        let original = Presence {
            status: PresenceStatus::Emergency,
            activity: Some(Activity::Moving),
            msg: Some("SOS".into()),
            battery: Some(15),
            ts: 1_716_742_800,
        };

        let cbor = original.to_cbor().unwrap();
        let decoded = Presence::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, original);
    }

    /// Encode omits None fields (skip_serializing_if).
    #[test]
    fn presence_encode_omits_none() {
        let p = Presence::new(PresenceStatus::Available, 123);
        let cbor = p.to_cbor().unwrap();

        // Decode as raw Value to inspect keys
        let v: Value = ciborium::from_reader(&cbor[..]).unwrap();
        let map = match v {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };

        // Should only have "status" and "ts"
        assert_eq!(map.len(), 2);
        assert!(map.iter().any(|(k, _)| k == &txt("status")));
        assert!(map.iter().any(|(k, _)| k == &txt("ts")));
    }

    /// Presence cache decodes correctly.
    #[test]
    fn presence_cache_decodes() {
        let wire = Value::Map(vec![(
            txt("nodes"),
            Value::Array(vec![
                Value::Map(vec![
                    (txt("addr"), txt("0200::1111")),
                    (txt("status"), txt("available")),
                    (txt("battery"), Value::Integer(87u64.into())),
                    (txt("age_s"), Value::Integer(30u64.into())),
                ]),
                Value::Map(vec![
                    (txt("addr"), txt("0200::2222")),
                    (txt("status"), txt("away")),
                    (txt("age_s"), Value::Integer(120u64.into())),
                ]),
            ]),
        )]);

        let cache = PresenceCache::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(cache.nodes.len(), 2);

        assert_eq!(cache.nodes[0].addr, "0200::1111");
        assert_eq!(cache.nodes[0].status, PresenceStatus::Available);
        assert_eq!(cache.nodes[0].battery, Some(87));
        assert_eq!(cache.nodes[0].age_s, 30);

        assert_eq!(cache.nodes[1].addr, "0200::2222");
        assert_eq!(cache.nodes[1].status, PresenceStatus::Away);
        assert_eq!(cache.nodes[1].battery, None);
        assert_eq!(cache.nodes[1].age_s, 120);
    }

    /// Empty cache is valid.
    #[test]
    fn presence_cache_empty() {
        let wire = Value::Map(vec![(txt("nodes"), Value::Array(vec![]))]);
        let cache = PresenceCache::from_cbor(&encode(&wire)).unwrap();
        assert!(cache.nodes.is_empty());
    }

    /// Status Display trait.
    #[test]
    fn presence_status_display() {
        assert_eq!(PresenceStatus::Available.to_string(), "available");
        assert_eq!(PresenceStatus::Emergency.to_string(), "emergency");
    }

    /// Activity Display trait.
    #[test]
    fn activity_display() {
        assert_eq!(Activity::Moving.to_string(), "moving");
        assert_eq!(Activity::Stationary.to_string(), "stationary");
    }
}
