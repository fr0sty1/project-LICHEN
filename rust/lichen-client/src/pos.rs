// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Position / location domain type and SenML wire codec.
//!
//! Wire contract (spec `12-apps.md` §18.2): position is carried as a SenML
//! pack (`application/senml+cbor`, RFC 8428). The pack is a base record
//! carrying the source device (`bn = urn:dev:mac:<eui>:`) and optional fix
//! time (`bt`), followed by one record per measurement:
//!
//! ```text
//! [ {bn: "urn:dev:mac:0011223344556677:", bt: 1716742800},
//!   {n: "lat",     u: "lat", v: 37.774929},
//!   {n: "lon",     u: "lon", v: -122.419416},
//!   {n: "alt",     u: "m",   v: 10.5},
//!   {n: "speed",   u: "m/s", v: 1.2},
//!   {n: "heading", u: "deg", v: 45} ]
//! ```
//!
//! NOTE: the firmware does not yet serve the §18.2 position resources
//! (`/sensors/location`, `/pos`, `/pos/cache`); this type implements the
//! spec contract so clients are ready once the node side lands.

use lichen_senml::cbor;
use lichen_senml::Record;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Maximum SenML pack size for a position: 6 records, each well under 64 B.
const ENC_BUF_LEN: usize = 512;
/// Upper bound on records decoded from a position pack (base + 5 fields, with
/// headroom for unexpected extras).
const DEC_MAX_RECORDS: usize = 12;

/// A geographic position, encoded on the wire as a SenML pack (spec §18.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Position {
    /// SenML base name identifying the source device, e.g.
    /// `urn:dev:mac:0011223344556677:`. See [`Position::from_eui64`].
    pub device: String,
    /// Fix time (SenML base time `bt`, Unix seconds); `None` when unknown.
    pub time: Option<u64>,
    /// Latitude in decimal degrees.
    pub lat: f64,
    /// Longitude in decimal degrees.
    pub lon: f64,
    /// Altitude in meters.
    pub alt: Option<f64>,
    /// Ground speed in m/s.
    pub speed: Option<f64>,
    /// Heading in degrees (0..360, 0 = north).
    pub heading: Option<f64>,
}

impl Position {
    /// Build a position whose SenML base name is `urn:dev:mac:<eui_hex>:`.
    pub fn from_eui64(eui_hex: &str, lat: f64, lon: f64) -> Self {
        Self {
            device: format!("urn:dev:mac:{eui_hex}:"),
            time: None,
            lat,
            lon,
            alt: None,
            speed: None,
            heading: None,
        }
    }

    /// Encode as a SenML-CBOR pack (spec §18.2 `application/senml+cbor`).
    pub fn to_senml_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut recs: [Record; 6] = [Record::empty(); 6];
        let mut n = 0;

        // Base record: device (bn) and optional fix time (bt).
        recs[n] = Record {
            base_name: Some(self.device.as_str()),
            base_time: self.time.map(|t| t as f64),
            ..Record::empty()
        };
        n += 1;
        recs[n] = value_record("lat", "lat", self.lat);
        n += 1;
        recs[n] = value_record("lon", "lon", self.lon);
        n += 1;
        if let Some(alt) = self.alt {
            recs[n] = value_record("alt", "m", alt);
            n += 1;
        }
        if let Some(speed) = self.speed {
            recs[n] = value_record("speed", "m/s", speed);
            n += 1;
        }
        if let Some(heading) = self.heading {
            recs[n] = value_record("heading", "deg", heading);
            n += 1;
        }

        let mut buf = [0u8; ENC_BUF_LEN];
        let written = cbor::encode(&recs[..n], &mut buf)
            .map_err(|e| Error::Decode(format!("SenML encode: {e:?}")))?;
        Ok(buf[..written].to_vec())
    }

    /// Decode a SenML-CBOR position pack (spec §18.2).
    ///
    /// `bn` (device) plus `lat` and `lon` are required; other fields are
    /// filled when present. Base fields may appear on any record per RFC 8428.
    pub fn from_senml_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut recs = [Record::empty(); DEC_MAX_RECORDS];
        let count = cbor::decode(bytes, &mut recs)
            .map_err(|e| Error::Decode(format!("SenML decode: {e:?}")))?;

        let mut device = None;
        let mut time = None;
        let mut lat = None;
        let mut lon = None;
        let mut alt = None;
        let mut speed = None;
        let mut heading = None;

        for rec in &recs[..count] {
            if let Some(bn) = rec.base_name {
                device = Some(bn.to_owned());
            }
            if let Some(bt) = rec.base_time {
                time = Some(bt as u64);
            }
            match (rec.name, rec.value) {
                (Some("lat"), Some(v)) => lat = Some(v),
                (Some("lon"), Some(v)) => lon = Some(v),
                (Some("alt"), Some(v)) => alt = Some(v),
                (Some("speed"), Some(v)) => speed = Some(v),
                (Some("heading"), Some(v)) => heading = Some(v),
                _ => {}
            }
        }

        Ok(Self {
            device: device.ok_or_else(|| Error::Decode("SenML position missing bn".into()))?,
            time,
            lat: lat.ok_or_else(|| Error::Decode("SenML position missing lat".into()))?,
            lon: lon.ok_or_else(|| Error::Decode("SenML position missing lon".into()))?,
            alt,
            speed,
            heading,
        })
    }
}

fn value_record<'a>(name: &'a str, unit: &'a str, value: f64) -> Record<'a> {
    Record {
        name: Some(name),
        unit: Some(unit),
        value: Some(value),
        ..Record::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the SenML field names and units mandated by spec §18.2
    /// (`bn`/`bt` base record, then `lat`/`lon`/`alt`/`speed`/`heading` with
    /// units `lat`/`lon`/`m`/`m/s`/`deg`). Decoded with the raw `lichen-senml`
    /// codec, independent of this module's mapping.
    #[test]
    fn encodes_spec_senml_shape() {
        let p = Position {
            device: "urn:dev:mac:0011223344556677:".into(),
            time: Some(1_716_742_800),
            lat: 37.774929,
            lon: -122.419416,
            alt: Some(10.5),
            speed: Some(1.2),
            heading: Some(45.0),
        };
        let bytes = p.to_senml_cbor().unwrap();

        let mut recs = [Record::empty(); DEC_MAX_RECORDS];
        let n = cbor::decode(&bytes, &mut recs).unwrap();

        assert_eq!(recs[0].base_name, Some("urn:dev:mac:0011223344556677:"));
        assert_eq!(recs[0].base_time, Some(1_716_742_800.0));

        let find = |name: &str| recs[..n].iter().find(|r| r.name == Some(name)).copied();
        let lat = find("lat").expect("lat record");
        assert_eq!((lat.unit, lat.value), (Some("lat"), Some(37.774929)));
        let lon = find("lon").expect("lon record");
        assert_eq!((lon.unit, lon.value), (Some("lon"), Some(-122.419416)));
        let alt = find("alt").expect("alt record");
        assert_eq!((alt.unit, alt.value), (Some("m"), Some(10.5)));
        let speed = find("speed").expect("speed record");
        assert_eq!((speed.unit, speed.value), (Some("m/s"), Some(1.2)));
        let heading = find("heading").expect("heading record");
        assert_eq!((heading.unit, heading.value), (Some("deg"), Some(45.0)));
    }

    /// Oracle: an explicitly built spec-shaped SenML pack (independent of the
    /// encoder under test) decodes into the expected [`Position`] fields.
    #[test]
    fn decodes_spec_senml() {
        let recs = [
            Record {
                base_name: Some("urn:dev:mac:aabb:"),
                base_time: Some(1_716_742_800.0),
                ..Record::empty()
            },
            value_record("lat", "lat", 37.0),
            value_record("lon", "lon", -122.0),
            value_record("alt", "m", 5.0),
        ];
        let mut buf = [0u8; ENC_BUF_LEN];
        let n = cbor::encode(&recs, &mut buf).unwrap();

        let p = Position::from_senml_cbor(&buf[..n]).unwrap();
        assert_eq!(p.device, "urn:dev:mac:aabb:");
        assert_eq!(p.time, Some(1_716_742_800));
        assert_eq!(p.lat, 37.0);
        assert_eq!(p.lon, -122.0);
        assert_eq!(p.alt, Some(5.0));
        assert_eq!(p.speed, None);
        assert_eq!(p.heading, None);
    }

    /// A full position survives an encode/decode round trip unchanged.
    #[test]
    fn round_trips() {
        let p = Position {
            device: "urn:dev:mac:dead:".into(),
            time: Some(42),
            lat: 1.5,
            lon: -2.5,
            alt: Some(3.5),
            speed: Some(0.0),
            heading: Some(359.0),
        };
        let bytes = p.to_senml_cbor().unwrap();
        assert_eq!(Position::from_senml_cbor(&bytes).unwrap(), p);
    }

    /// A pack without `lat` is not a valid position and must be rejected.
    #[test]
    fn decode_missing_lat_errors() {
        let recs = [
            Record {
                base_name: Some("urn:dev:mac:x:"),
                ..Record::empty()
            },
            value_record("lon", "lon", 1.0),
        ];
        let mut buf = [0u8; ENC_BUF_LEN];
        let n = cbor::encode(&recs, &mut buf).unwrap();
        assert!(Position::from_senml_cbor(&buf[..n]).is_err());
    }
}
