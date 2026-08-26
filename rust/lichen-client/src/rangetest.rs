// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Range testing domain types and CBOR wire codecs (spec 18.7).
//!
//! Wire contract (firmware `/diag/rangetest` and `/diag/traceroute`
//! resources):
//!
//! * Extended/continuous range test responses are SenML+CBOR packs
//!   (RFC 8428, Content-Format 112) with numeric labels: `bn` = -2,
//!   `bt` = -3, `n` = 0, `u` = 1, `v` = 2. Records carry `seq`, `rssi`
//!   (dBm), `snr` (dB), `sf`, and `freq` (MHz).
//! * Traceroute responses are a CBOR map with text keys
//!   `hops` / `total_hops` / `total_rtt_ms`.
//! * Request bodies are CBOR maps with text keys: `seq`, `payload_len`,
//!   `count` for POST; `interval_ms` for GET.
//!
//! Conformance vectors: `test/vectors/rangetest.json`.

use ciborium::value::Value;

use crate::Error;

/// Maximum test payload size per spec 18.7.2.
pub const MAX_PAYLOAD_LEN: u32 = 255;
/// Maximum response count per spec 18.7.2.
pub const MAX_COUNT: u32 = 100;
/// Default continuous-test interval in milliseconds.
pub const DEFAULT_INTERVAL_MS: u64 = 5000;

/// Radio link quality metrics reported by a range test.
#[derive(Debug, Clone, PartialEq)]
pub struct RadioMetrics {
    /// Received signal strength in dBm (negative).
    pub rssi: f64,
    /// Signal-to-noise ratio in dB.
    pub snr: f64,
    /// LoRa spreading factor.
    pub sf: u8,
    /// Center frequency in MHz.
    pub freq: f64,
}

/// One decoded range-test reading (SenML pack).
#[derive(Debug, Clone, PartialEq)]
pub struct RangeTestReading {
    /// Base name (`bn`), e.g. `urn:dev:mac:<eui64>:`.
    pub base_name: Option<String>,
    /// Base time (`bt`) in Unix seconds.
    pub base_time: Option<f64>,
    /// Test sequence number echoed by the responder.
    pub seq: i64,
    /// Current radio metrics.
    pub metrics: RadioMetrics,
}

/// A single hop in a mesh traceroute.
#[derive(Debug, Clone, PartialEq)]
pub struct TracerouteHop {
    /// Next-hop IPv6 address.
    pub addr: String,
    /// Link RSSI toward that hop in dBm.
    pub rssi: f64,
    /// Round-trip time to that hop in milliseconds.
    pub rtt_ms: f64,
}

/// Decoded `/diag/traceroute` response.
#[derive(Debug, Clone, PartialEq)]
pub struct TracerouteResult {
    /// Hop-by-hop path.
    pub hops: Vec<TracerouteHop>,
    /// Number of hops (equal to `hops.len()`).
    pub total_hops: usize,
    /// End-to-end round trip in milliseconds (last hop's RTT).
    pub total_rtt_ms: f64,
}

/// Extended range-test request body (`POST /diag/rangetest`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeTestRequest {
    /// Sequence number to echo (>= 0).
    pub seq: Option<u32>,
    /// Padding payload size in bytes (0..=[MAX_PAYLOAD_LEN]).
    pub payload_len: Option<u32>,
    /// Number of exchanges (1..=[MAX_COUNT]).
    pub count: Option<u32>,
}

fn value_label(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i64::try_from(*i).is_ok_and(|v| v == key)))
        .map(|(_, v)| v)
}

fn text_key<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn as_i64(v: &Value) -> Result<i64, Error> {
    match v {
        Value::Integer(i) => {
            i64::try_from(*i).map_err(|_| Error::Decode("integer out of range".into()))
        }
        _ => Err(Error::Decode(format!("expected integer, got {v:?}"))),
    }
}

fn as_f64(v: &Value) -> Result<f64, Error> {
    match v {
        Value::Integer(i) => match i64::try_from(*i) {
            Ok(v) => Ok(v as f64),
            Err(_) => Err(Error::Decode("integer too large for float".into())),
        },
        Value::Float(f) => Ok(*f),
        _ => Err(Error::Decode(format!("expected number, got {v:?}"))),
    }
}

fn as_map(v: &Value) -> Result<&Vec<(Value, Value)>, Error> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(Error::Decode(format!("expected map, got {v:?}"))),
    }
}

fn as_array(v: &Value) -> Result<&Vec<Value>, Error> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(Error::Decode(format!("expected array, got {v:?}"))),
    }
}

impl RangeTestReading {
    /// Decode a SenML+CBOR range-test response pack.
    pub fn from_senml_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
        let records = as_array(&value)?;

        let mut base_name = None;
        let mut base_time = None;
        let mut seq = None;
        let mut rssi = None;
        let mut snr = None;
        let mut sf = None;
        let mut freq = None;

        for record in records {
            let map = as_map(record)?;
            let name = value_label(map, 0)
                .and_then(Value::as_text)
                .map(str::to_owned);
            match name.as_deref() {
                Some("seq") => {
                    seq = Some(as_i64(value_label(map, 2).ok_or_else(|| {
                        Error::Decode("seq record missing value".into())
                    })?)?)
                }
                Some("rssi") | Some("snr") | Some("freq") => {
                    let v = as_f64(
                        value_label(map, 2)
                            .ok_or_else(|| Error::Decode("metric record missing value".into()))?,
                    )?;
                    match name.as_deref() {
                        Some("rssi") => rssi = Some(v),
                        Some("snr") => snr = Some(v),
                        _ => freq = Some(v),
                    }
                }
                Some("sf") => {
                    sf = Some(
                        u8::try_from(as_i64(
                            value_label(map, 2)
                                .ok_or_else(|| Error::Decode("sf record missing value".into()))?,
                        )?)
                        .map_err(|_| Error::Decode("sf out of u8 range".into()))?,
                    );
                }
                _ => {
                    // Base record and unknown records: harvest base fields only.
                    if let Some(v) = value_label(map, -2) {
                        base_name = Some(
                            v.as_text()
                                .ok_or_else(|| Error::Decode("bn must be text".into()))?
                                .to_owned(),
                        );
                    }
                    if let Some(v) = value_label(map, -3) {
                        base_time = Some(as_f64(v)?);
                    }
                }
            }
        }

        Ok(Self {
            base_name,
            base_time,
            seq: seq.ok_or_else(|| Error::Decode("missing seq record".into()))?,
            metrics: RadioMetrics {
                rssi: rssi.ok_or_else(|| Error::Decode("missing rssi record".into()))?,
                snr: snr.ok_or_else(|| Error::Decode("missing snr record".into()))?,
                sf: sf.ok_or_else(|| Error::Decode("missing sf record".into()))?,
                freq: freq.ok_or_else(|| Error::Decode("missing freq record".into()))?,
            },
        })
    }
}

impl RangeTestRequest {
    fn validate(&self) -> Result<(), Error> {
        if let Some(plen) = self.payload_len {
            if plen > MAX_PAYLOAD_LEN {
                return Err(Error::Encode(format!(
                    "payload_len {plen} exceeds MAX_PAYLOAD_LEN ({MAX_PAYLOAD_LEN})"
                )));
            }
        }
        if let Some(count) = self.count {
            if !(1..=MAX_COUNT).contains(&count) {
                return Err(Error::Encode(format!(
                    "count {count} outside 1..={MAX_COUNT}"
                )));
            }
        }
        Ok(())
    }

    /// Encode the request body as a CBOR map with text keys.
    ///
    /// Only set fields are emitted; bounds per spec 18.7.2 are enforced.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut entries = Vec::new();
        if let Some(seq) = self.seq {
            entries.push((Value::Text("seq".into()), Value::Integer(seq.into())));
        }
        if let Some(plen) = self.payload_len {
            entries.push((
                Value::Text("payload_len".into()),
                Value::Integer(plen.into()),
            ));
        }
        if let Some(count) = self.count {
            entries.push((Value::Text("count".into()), Value::Integer(count.into())));
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut bytes)
            .map_err(|e| Error::Encode(e.to_string()))?;
        Ok(bytes)
    }

    /// Decode a request body (used when echoing or inspecting requests).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
        let map = as_map(&value)?;
        let get_u32 = |key: &str| -> Result<Option<u32>, Error> {
            match text_key(map, key) {
                Some(v) => {
                    Ok(Some(u32::try_from(as_i64(v)?).map_err(|_| {
                        Error::Decode(format!("{key} out of u32 range"))
                    })?))
                }
                None => Ok(None),
            }
        };
        Ok(Self {
            seq: get_u32("seq")?,
            payload_len: get_u32("payload_len")?,
            count: get_u32("count")?,
        })
    }
}

/// Encode a continuous-test interval body (`GET /diag/rangetest`).
///
/// The interval must be positive; the server rejects anything else with 4.00.
pub fn interval_body(interval_ms: u64) -> Result<Vec<u8>, Error> {
    if interval_ms == 0 {
        return Err(Error::Encode("interval_ms must be positive".into()));
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Value::Map(vec![(
            Value::Text("interval_ms".into()),
            Value::Integer(interval_ms.into()),
        )]),
        &mut bytes,
    )
    .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(bytes)
}

/// Minimal deterministic CBOR writers matching the reference codec's output
/// (Python `cbor2.dumps` emits 64-bit floats, never half/single precision).
mod wire {
    pub(super) fn uint(out: &mut Vec<u8>, v: u64) {
        if v < 24 {
            out.push(v as u8);
        } else if v <= u64::from(u8::MAX) {
            out.push(24);
            out.push(v as u8);
        } else if v <= u64::from(u16::MAX) {
            out.push(25);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= u64::from(u32::MAX) {
            out.push(26);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            out.push(27);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub(super) fn text(out: &mut Vec<u8>, s: &str) {
        let len = s.len();
        if len < 24 {
            out.push(0x60 | len as u8);
        } else if len <= usize::from(u8::MAX) {
            out.push(0x78);
            out.push(len as u8);
        } else if len <= usize::from(u16::MAX) {
            out.push(0x79);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x7A);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        out.extend_from_slice(s.as_bytes());
    }

    pub(super) fn array(out: &mut Vec<u8>, len: usize) {
        debug_assert!(len <= u32::MAX as usize);
        if len < 24 {
            out.push(0x80 | len as u8);
        } else if len <= usize::from(u8::MAX) {
            out.push(0x98);
            out.push(len as u8);
        } else {
            out.push(0x99);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }

    pub(super) fn map(out: &mut Vec<u8>, len: usize) {
        debug_assert!(len <= 23, "traceroute maps are fixed-shape");
        out.push(0xA0 | len as u8);
    }

    pub(super) fn float64(out: &mut Vec<u8>, v: f64) {
        out.push(0xFB);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

impl TracerouteResult {
    /// Decode a `/diag/traceroute` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
        let map = as_map(&value)?;

        let hops_value =
            as_array(text_key(map, "hops").ok_or_else(|| Error::Decode("missing hops".into()))?)?;
        let mut hops = Vec::with_capacity(hops_value.len());
        for hop in hops_value {
            let hop_map = as_map(hop)?;
            let addr = text_key(hop_map, "addr")
                .ok_or_else(|| Error::Decode("hop missing addr".into()))?
                .as_text()
                .ok_or_else(|| Error::Decode("addr must be text".into()))?
                .to_owned();
            let rssi = as_f64(
                text_key(hop_map, "rssi")
                    .ok_or_else(|| Error::Decode("hop missing rssi".into()))?,
            )?;
            let rtt_ms = as_f64(
                text_key(hop_map, "rtt_ms")
                    .ok_or_else(|| Error::Decode("hop missing rtt_ms".into()))?,
            )?;
            hops.push(TracerouteHop { addr, rssi, rtt_ms });
        }

        let total_hops = usize::try_from(as_i64(
            text_key(map, "total_hops")
                .ok_or_else(|| Error::Decode("missing total_hops".into()))?,
        )?)
        .map_err(|_| Error::Decode("total_hops out of range".into()))?;

        let total_rtt_ms = as_f64(
            text_key(map, "total_rtt_ms")
                .ok_or_else(|| Error::Decode("missing total_rtt_ms".into()))?,
        )?;

        Ok(Self {
            hops,
            total_hops,
            total_rtt_ms,
        })
    }

    /// Encode a traceroute response body (text-keyed map, field order
    /// `hops`, `total_hops`, `total_rtt_ms` matching the reference codec).
    ///
    /// Floats are emitted as 64-bit to match the Python reference bytes
    /// (ciborium's minimal-width float output would break byte-exact
    /// conformance).
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        wire::map(&mut out, 3);
        wire::text(&mut out, "hops");
        wire::array(&mut out, self.hops.len());
        for h in &self.hops {
            wire::map(&mut out, 3);
            wire::text(&mut out, "addr");
            wire::text(&mut out, &h.addr);
            wire::text(&mut out, "rssi");
            wire::float64(&mut out, h.rssi);
            wire::text(&mut out, "rtt_ms");
            wire::float64(&mut out, h.rtt_ms);
        }
        wire::text(&mut out, "total_hops");
        wire::uint(
            &mut out,
            u64::try_from(self.total_hops)
                .map_err(|_| Error::Encode("total_hops out of range".into()))?,
        );
        wire::text(&mut out, "total_rtt_ms");
        wire::float64(&mut out, self.total_rtt_ms);
        Ok(out)
    }
}
