// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Waypoint domain type with CBOR wire codec.
//!
//! Wire contract (firmware `/waypoints` resource, spec Section 18.3):
//!
//! ```cbor
//! {
//!   "id": "wpt-001",              ; unique ID (tstr)
//!   "name": "Rally Point Alpha",  ; human-readable name (tstr)
//!   "lat": 37.774929,             ; WGS84 latitude (float)
//!   "lon": -122.419416,           ; WGS84 longitude (float)
//!   "alt": 10.5,                  ; altitude meters (float, optional)
//!   "icon": "flag",               ; icon hint (tstr, optional)
//!   "color": "#FF0000",           ; color hint (tstr, optional)
//!   "notes": "Meet here at 1400", ; description (tstr, optional)
//!   "created": 1716742800,        ; creation time (uint)
//!   "creator": "0200:...:1111",   ; creator node (tstr)
//!   "expires": 1716829200         ; expiration time (uint, optional)
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::Error;

/// Waypoint icon hints (spec Section 18.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WaypointIcon {
    Flag,
    Marker,
    Camp,
    Water,
    Danger,
    Medical,
    Vehicle,
    Poi,
    Start,
    Finish,
    Checkpoint,
}

impl WaypointIcon {
    /// Returns the icon as a string slice matching the wire format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Marker => "marker",
            Self::Camp => "camp",
            Self::Water => "water",
            Self::Danger => "danger",
            Self::Medical => "medical",
            Self::Vehicle => "vehicle",
            Self::Poi => "poi",
            Self::Start => "start",
            Self::Finish => "finish",
            Self::Checkpoint => "checkpoint",
        }
    }
}

impl core::fmt::Display for WaypointIcon {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A shareable point of interest with metadata (spec Section 18.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Waypoint {
    /// Unique waypoint ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// WGS84 latitude in decimal degrees.
    pub lat: f64,
    /// WGS84 longitude in decimal degrees.
    pub lon: f64,
    /// Altitude in meters (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<f64>,
    /// Icon hint (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<WaypointIcon>,
    /// Color hint as hex string, e.g. "#FF0000" (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Description/notes (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Creation timestamp (Unix seconds).
    pub created: u64,
    /// Creator node address string.
    pub creator: String,
    /// Expiration timestamp (Unix seconds, optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

impl Waypoint {
    /// Create a new waypoint with required fields only.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        lat: f64,
        lon: f64,
        created: u64,
        creator: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            lat,
            lon,
            alt: None,
            icon: None,
            color: None,
            notes: None,
            created,
            creator: creator.into(),
            expires: None,
        }
    }

    /// Decode a waypoint from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }

    /// Encode to CBOR for `POST /waypoints` or sharing.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(buf)
    }
}

/// The `GET /waypoints` response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaypointList {
    pub waypoints: Vec<Waypoint>,
}

impl WaypointList {
    /// Decode a `GET /waypoints` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }

    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(buf)
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

    /// Oracle: a CBOR map built with the exact /waypoints keys from the spec,
    /// independent of the struct's serde mapping.
    #[test]
    fn waypoint_decodes_firmware_map() {
        let wire = Value::Map(vec![
            (txt("id"), txt("wpt-001")),
            (txt("name"), txt("Rally Point Alpha")),
            (txt("lat"), Value::Float(37.774929)),
            (txt("lon"), Value::Float(-122.419416)),
            (txt("alt"), Value::Float(10.5)),
            (txt("icon"), txt("flag")),
            (txt("color"), txt("#FF0000")),
            (txt("notes"), txt("Meet here at 1400")),
            (txt("created"), Value::Integer(1_716_742_800u64.into())),
            (txt("creator"), txt("0200::1111")),
            (txt("expires"), Value::Integer(1_716_829_200u64.into())),
        ]);

        let w = Waypoint::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(w.id, "wpt-001");
        assert_eq!(w.name, "Rally Point Alpha");
        assert_eq!(w.lat, 37.774929);
        assert_eq!(w.lon, -122.419416);
        assert_eq!(w.alt, Some(10.5));
        assert_eq!(w.icon, Some(WaypointIcon::Flag));
        assert_eq!(w.color.as_deref(), Some("#FF0000"));
        assert_eq!(w.notes.as_deref(), Some("Meet here at 1400"));
        assert_eq!(w.created, 1_716_742_800);
        assert_eq!(w.creator, "0200::1111");
        assert_eq!(w.expires, Some(1_716_829_200));
    }

    /// Minimal waypoint with only required fields.
    #[test]
    fn waypoint_minimal() {
        let wire = Value::Map(vec![
            (txt("id"), txt("wpt-002")),
            (txt("name"), txt("Water Source")),
            (txt("lat"), Value::Float(37.78)),
            (txt("lon"), Value::Float(-122.42)),
            (txt("created"), Value::Integer(100u64.into())),
            (txt("creator"), txt("0200::2222")),
        ]);

        let w = Waypoint::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(w.id, "wpt-002");
        assert_eq!(w.name, "Water Source");
        assert_eq!(w.lat, 37.78);
        assert_eq!(w.lon, -122.42);
        assert_eq!(w.alt, None);
        assert_eq!(w.icon, None);
        assert_eq!(w.color, None);
        assert_eq!(w.notes, None);
        assert_eq!(w.created, 100);
        assert_eq!(w.creator, "0200::2222");
        assert_eq!(w.expires, None);
    }

    /// All icon values decode correctly.
    #[test]
    fn waypoint_icon_variants() {
        for (s, expected) in [
            ("flag", WaypointIcon::Flag),
            ("marker", WaypointIcon::Marker),
            ("camp", WaypointIcon::Camp),
            ("water", WaypointIcon::Water),
            ("danger", WaypointIcon::Danger),
            ("medical", WaypointIcon::Medical),
            ("vehicle", WaypointIcon::Vehicle),
            ("poi", WaypointIcon::Poi),
            ("start", WaypointIcon::Start),
            ("finish", WaypointIcon::Finish),
            ("checkpoint", WaypointIcon::Checkpoint),
        ] {
            let wire = Value::Map(vec![
                (txt("id"), txt("test")),
                (txt("name"), txt("Test")),
                (txt("lat"), Value::Float(0.0)),
                (txt("lon"), Value::Float(0.0)),
                (txt("icon"), txt(s)),
                (txt("created"), Value::Integer(0u64.into())),
                (txt("creator"), txt("0200::0")),
            ]);
            let w = Waypoint::from_cbor(&encode(&wire)).unwrap();
            assert_eq!(w.icon, Some(expected));
        }
    }

    /// Round-trip encode/decode.
    #[test]
    fn waypoint_roundtrip() {
        let original = Waypoint {
            id: "wpt-003".into(),
            name: "Checkpoint 3".into(),
            lat: 37.78,
            lon: -122.42,
            alt: Some(15.0),
            icon: Some(WaypointIcon::Checkpoint),
            color: Some("#00FF00".into()),
            notes: Some("Third checkpoint".into()),
            created: 1_716_742_800,
            creator: "0200::3333".into(),
            expires: Some(1_716_829_200),
        };

        let cbor = original.to_cbor().unwrap();
        let decoded = Waypoint::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, original);
    }

    /// Encode omits None fields (skip_serializing_if).
    #[test]
    fn waypoint_encode_omits_none() {
        let w = Waypoint::new("wpt-min", "Minimal", 37.0, -122.0, 123, "0200::min");
        let cbor = w.to_cbor().unwrap();

        // Decode as raw Value to inspect keys
        let v: Value = ciborium::from_reader(&cbor[..]).unwrap();
        let map = match v {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };

        // Should only have required fields
        assert_eq!(map.len(), 6);
        assert!(map.iter().any(|(k, _)| k == &txt("id")));
        assert!(map.iter().any(|(k, _)| k == &txt("name")));
        assert!(map.iter().any(|(k, _)| k == &txt("lat")));
        assert!(map.iter().any(|(k, _)| k == &txt("lon")));
        assert!(map.iter().any(|(k, _)| k == &txt("created")));
        assert!(map.iter().any(|(k, _)| k == &txt("creator")));
        // Optional fields should not be present
        assert!(!map.iter().any(|(k, _)| k == &txt("alt")));
        assert!(!map.iter().any(|(k, _)| k == &txt("icon")));
        assert!(!map.iter().any(|(k, _)| k == &txt("color")));
        assert!(!map.iter().any(|(k, _)| k == &txt("notes")));
        assert!(!map.iter().any(|(k, _)| k == &txt("expires")));
    }

    /// Waypoint list decodes correctly.
    #[test]
    fn waypoint_list_decodes() {
        let wire = Value::Map(vec![(
            txt("waypoints"),
            Value::Array(vec![
                Value::Map(vec![
                    (txt("id"), txt("wpt-001")),
                    (txt("name"), txt("Rally Point Alpha")),
                    (txt("lat"), Value::Float(37.774929)),
                    (txt("lon"), Value::Float(-122.419416)),
                    (txt("created"), Value::Integer(1_716_742_800u64.into())),
                    (txt("creator"), txt("0200::1111")),
                ]),
                Value::Map(vec![
                    (txt("id"), txt("wpt-002")),
                    (txt("name"), txt("Water Source")),
                    (txt("lat"), Value::Float(37.78)),
                    (txt("lon"), Value::Float(-122.42)),
                    (txt("icon"), txt("water")),
                    (txt("created"), Value::Integer(1_716_742_900u64.into())),
                    (txt("creator"), txt("0200::2222")),
                ]),
            ]),
        )]);

        let list = WaypointList::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(list.waypoints.len(), 2);

        assert_eq!(list.waypoints[0].id, "wpt-001");
        assert_eq!(list.waypoints[0].name, "Rally Point Alpha");
        assert_eq!(list.waypoints[0].icon, None);

        assert_eq!(list.waypoints[1].id, "wpt-002");
        assert_eq!(list.waypoints[1].name, "Water Source");
        assert_eq!(list.waypoints[1].icon, Some(WaypointIcon::Water));
    }

    /// Empty waypoint list is valid.
    #[test]
    fn waypoint_list_empty() {
        let wire = Value::Map(vec![(txt("waypoints"), Value::Array(vec![]))]);
        let list = WaypointList::from_cbor(&encode(&wire)).unwrap();
        assert!(list.waypoints.is_empty());
    }

    /// Waypoint list round-trip.
    #[test]
    fn waypoint_list_roundtrip() {
        let original = WaypointList {
            waypoints: vec![
                Waypoint::new("wpt-a", "Point A", 37.0, -122.0, 100, "0200::a"),
                Waypoint::new("wpt-b", "Point B", 38.0, -123.0, 200, "0200::b"),
            ],
        };

        let cbor = original.to_cbor().unwrap();
        let decoded = WaypointList::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, original);
    }

    /// Icon Display trait.
    #[test]
    fn waypoint_icon_display() {
        assert_eq!(WaypointIcon::Flag.to_string(), "flag");
        assert_eq!(WaypointIcon::Checkpoint.to_string(), "checkpoint");
        assert_eq!(WaypointIcon::Medical.to_string(), "medical");
    }

    /// Constructor helper works correctly.
    #[test]
    fn waypoint_new_constructor() {
        let w = Waypoint::new("id1", "Name", 1.0, 2.0, 12345, "0200::creator");
        assert_eq!(w.id, "id1");
        assert_eq!(w.name, "Name");
        assert_eq!(w.lat, 1.0);
        assert_eq!(w.lon, 2.0);
        assert_eq!(w.created, 12345);
        assert_eq!(w.creator, "0200::creator");
        assert!(w.alt.is_none());
        assert!(w.icon.is_none());
        assert!(w.color.is_none());
        assert!(w.notes.is_none());
        assert!(w.expires.is_none());
    }
}
