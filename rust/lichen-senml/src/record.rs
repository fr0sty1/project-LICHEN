//! SenML record type (RFC 8428 §4).

use crate::cbor::{self, CborError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A single SenML record.
///
/// Fields mirror RFC 8428 §4.3. All string fields are `&str` slices to avoid
/// heap allocation; owned variants can be built with `alloc` (future work).
///
/// # Encoding/Decoding
///
/// Single records can use the method API for consistency with other crates:
/// ```ignore
/// let n = record.encode(&mut buf)?;
/// let record = Record::parse(&data)?;
/// ```
///
/// For batch operations on multiple records, use [`cbor::encode`] and
/// [`cbor::decode`] directly, which avoid repeated array framing overhead.
/// JSON support (via `serde` feature) produces RFC 8428 SenML-JSON.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Record<'a> {
    /// Base name, e.g. `"urn:dev:mac:0123456789abcdef:"`.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "bn", skip_serializing_if = "Option::is_none", default)
    )]
    pub base_name: Option<&'a str>,
    /// Base time (Unix seconds since 1970-01-01T00:00:00Z, absolute or relative)
    /// and relative time offset. Both are `f64` (IEEE 754 binary64, 53-bit
    /// mantissa). This exactly represents all integer Unix timestamps up to ~2^53
    /// (~year 285,000,000); near present-day values (~1.7e9) the unit in the last
    /// place is ~0.0002 s, providing ample sub-second precision for sensors.
    /// Prefer a shared `base_time` + small relative `time` offsets for time
    /// series to avoid precision loss on large absolutes. See RFC 8428 §4.3/§4.5.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "bt", skip_serializing_if = "Option::is_none", default)
    )]
    pub base_time: Option<f64>,
    /// Relative name appended to base_name, e.g. `"temp"`.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "n", skip_serializing_if = "Option::is_none", default)
    )]
    pub name: Option<&'a str>,
    /// (see `base_time` documentation above)
    #[cfg_attr(
        feature = "serde",
        serde(rename = "t", skip_serializing_if = "Option::is_none", default)
    )]
    pub time: Option<f64>,
    /// Numeric value.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "v", skip_serializing_if = "Option::is_none", default)
    )]
    pub value: Option<f64>,
    /// String value.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "vs", skip_serializing_if = "Option::is_none", default)
    )]
    pub string_value: Option<&'a str>,
    /// Boolean value.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "vb", skip_serializing_if = "Option::is_none", default)
    )]
    pub bool_value: Option<bool>,
    /// Unit, e.g. `"Cel"` for Celsius.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "u", skip_serializing_if = "Option::is_none", default)
    )]
    pub unit: Option<&'a str>,
}

impl<'a> Record<'a> {
    pub const fn empty() -> Self {
        Self {
            base_name: None,
            base_time: None,
            name: None,
            time: None,
            value: None,
            string_value: None,
            bool_value: None,
            unit: None,
        }
    }

    /// Encode this record as a SenML-CBOR pack (single-element array).
    ///
    /// Returns the number of bytes written. For encoding multiple records,
    /// use [`cbor::encode`] to avoid repeated array framing.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CborError> {
        cbor::encode(core::slice::from_ref(self), out)
    }

    /// Parse a single record from a SenML-CBOR pack.
    ///
    /// Returns the parsed record. The input must be a CBOR array containing
    /// exactly one record map. For decoding multiple records, use
    /// [`cbor::decode`].
    ///
    /// Alias: [`from_bytes`](Self::from_bytes) for consistency with other crates.
    pub fn parse(data: &'a [u8]) -> Result<Self, CborError> {
        let mut buf = [Record::empty()];
        let count = cbor::decode(data, &mut buf)?;
        if count != 1 {
            return Err(CborError::InvalidInput);
        }
        Ok(buf[0])
    }

    /// Parse a single record from a SenML-CBOR pack.
    ///
    /// Alias for [`parse`](Self::parse), provided for API consistency with
    /// other codec types in the workspace (CoapPacket, LichenFrame, etc.).
    #[inline]
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CborError> {
        Self::parse(data)
    }
}
