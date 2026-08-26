//! Gateway `/status` time object (spec 11, firmware time provider).
//!
//! When `wall_clock_valid` is false, `unix_time` is omitted so clients do
//! not treat uptime as Unix seconds.

use lichen_link::{DioTimeStratum, TimeSourceClass};
use serde::{Deserialize, Serialize};

/// Time-provider snapshot returned by the border-router status resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeProviderStatus {
    /// True only after an accepted wall-clock sample.
    pub wall_clock_valid: bool,
    /// Unix seconds; omitted when the clock is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_time: Option<u32>,
    /// Canonical source-class string (e.g. "GNSS").
    pub source_class: String,
    /// Optional source instance name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Seconds since the last accepted sample.
    pub age_s: u32,
    /// DIO Time Option stratum 0..=4.
    pub stratum: u8,
}

impl TimeProviderStatus {
    /// Build from lichen-link time types.
    pub fn new(
        wall_clock_valid: bool,
        unix_time: Option<u32>,
        source: TimeSourceClass,
        source_name: Option<String>,
        age_s: u32,
        stratum: DioTimeStratum,
    ) -> Self {
        Self {
            wall_clock_valid,
            unix_time: if wall_clock_valid { unix_time } else { None },
            source_class: source.as_str().to_string(),
            source_name,
            age_s,
            stratum: stratum.wire(),
        }
    }

    /// Encode as CBOR (text-key map, spec 11 GET /status `time` object).
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Decode a CBOR time object.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_gnss_roundtrip() {
        let status = TimeProviderStatus::new(
            true,
            Some(1_716_742_800),
            TimeSourceClass::Gnss,
            Some("onboard-gnss".into()),
            120,
            DioTimeStratum::GnssGpsd,
        );
        let cbor = status.to_cbor().expect("encode");
        let decoded = TimeProviderStatus::from_cbor(&cbor).expect("decode");
        assert_eq!(decoded, status);
        assert_eq!(decoded.source_class, "GNSS");
        assert_eq!(decoded.stratum, 4);
        assert_eq!(decoded.unix_time, Some(1_716_742_800));
    }

    #[test]
    fn invalid_omits_unix_time() {
        let status = TimeProviderStatus::new(
            false,
            Some(1_716_742_800),
            TimeSourceClass::Monotonic,
            None,
            0,
            DioTimeStratum::NoSync,
        );
        assert!(status.unix_time.is_none());
        let cbor = status.to_cbor().expect("encode");
        let decoded = TimeProviderStatus::from_cbor(&cbor).expect("decode");
        assert!(!decoded.wall_clock_valid);
        assert_eq!(decoded.unix_time, None);
        assert_eq!(decoded.stratum, 0);
    }
}
