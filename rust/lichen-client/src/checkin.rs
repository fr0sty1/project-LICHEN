// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Check-In / Roll Call domain types and CBOR wire codecs (spec 18.6).
//!
//! Wire contract (firmware `/checkin` and `/rollcall` resources):
//!
//! * Check-in bodies (`POST /checkin`, spec 18.6.1) are CBOR maps with
//!   text keys: required `node` (full IPv6 colon-hex text), `ts` (Unix
//!   epoch seconds), `status` (`"ok"`, `"help"`, or `"delayed"`); optional
//!   paired `lat`/`lon` (f64, inclusive ranges ±90/±180) and `msg` (text).
//!   Success answer is 2.04 Changed; violations answer 4.00.
//! * Roll Call initiation bodies (`POST /rollcall`, spec 18.6.2) are CBOR
//!   maps with text keys: required `id` (text or integer; integers are
//!   coerced to their decimal text form); optional `from`, `ts`, and
//!   `timeout_s` (1..=[MAX_TIMEOUT_S], default [DEFAULT_TIMEOUT_S]).
//! * Roll Call status bodies (spec 18.6.3) are CBOR maps with text keys
//!   `id` / `started` / `timeout_s` / `responded` / `missing`, where the
//!   two lists carry `node`/`ts`/`status` and `node`/`last_seen` records.
//!
//! Conformance vectors: `test/vectors/checkin_rollcall.json`. Decode
//! rejections use the vector error codes verbatim (e.g.
//! `missing_required_field_node`) so cross-implementation tests can pin
//! them exactly.
//!
//! Decoder strictness (matching the C codec in
//! `lichen/subsys/lichen/coap/checkin.c`): inputs larger than the
//! per-payload bounds below are rejected (`payload_exceeds_maximum`),
//! bytes after the top-level item are rejected (`trailing_data`),
//! duplicate map keys are rejected (`duplicate_key`, RFC 8949 §5.6), and
//! the check-in `node` must be a full-notation IPv6 address, exactly 8
//! colon-separated groups of 4 hex digits (`invalid_node_format`). Codes
//! `payload_exceeds_maximum` and `out_of_range` (over-length roll-call
//! track arrays) are not pinned by current vectors; they mirror the C
//! `LICHEN_CHECKIN_ERR_*` names in vector style.

use std::io::Cursor;

use ciborium::value::Value;

use crate::Error;

/// Maximum stored check-ins per the reference resource (spec 18.6.1).
pub const MAX_CHECKINS: usize = 256;
/// Maximum concurrently tracked roll calls (spec 18.6.2).
pub const MAX_ROLLCALLS: usize = 256;
/// Default roll call timeout in seconds (spec 18.6.2).
pub const DEFAULT_TIMEOUT_S: u64 = 60;
/// Maximum roll call timeout in seconds: 7 days (spec 18.6.2).
pub const MAX_TIMEOUT_S: u64 = 7 * 86_400;
/// Conservative CBOR size bound for a check-in payload
/// (`LICHEN_CHECKIN_CBOR_MAX` in `lichen/checkin.h`).
pub const CHECKIN_CBOR_MAX: usize = 512;
/// Conservative CBOR size bound for a roll-call request
/// (`LICHEN_ROLLCALL_REQ_CBOR_MAX`).
pub const ROLLCALL_REQ_CBOR_MAX: usize = 160;
/// Conservative CBOR size bound for a roll-call status document
/// (`LICHEN_ROLLCALL_STATUS_CBOR_MAX`).
pub const ROLLCALL_STATUS_CBOR_MAX: usize = 5120;
/// Tracked responders/missing entries per roll call
/// (`LICHEN_ROLLCALL_TRACK_MAX`).
pub const ROLLCALL_TRACK_MAX: usize = 32;

/// Valid check-in `status` values in wire order (spec 18.6.1).
pub const CHECKIN_STATUS_VALUES: [&str; 3] = ["ok", "help", "delayed"];

/// Check-in presence status (spec 18.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckInStatus {
    /// All is well.
    Ok,
    /// Assistance is needed.
    Help,
    /// Schedule slip.
    Delayed,
}

impl CheckInStatus {
    /// Wire text for this status.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckInStatus::Ok => "ok",
            CheckInStatus::Help => "help",
            CheckInStatus::Delayed => "delayed",
        }
    }

    fn from_wire(s: &str) -> Result<Self, Error> {
        match s {
            "ok" => Ok(CheckInStatus::Ok),
            "help" => Ok(CheckInStatus::Help),
            "delayed" => Ok(CheckInStatus::Delayed),
            _ => Err(Error::Decode("invalid_status_value".into())),
        }
    }
}

/// One check-in record (`POST /checkin`, spec 18.6.1).
#[derive(Debug, Clone, PartialEq)]
pub struct CheckIn {
    /// Checking-in node's full IPv6 address (colon-hex text).
    pub node: String,
    /// Check-in timestamp in Unix epoch seconds.
    pub ts: u64,
    /// Presence status.
    pub status: CheckInStatus,
    /// Latitude in degrees (-90..=90); always paired with [Self::lon].
    pub lat: Option<f64>,
    /// Longitude in degrees (-180..=180); always paired with [Self::lat].
    pub lon: Option<f64>,
    /// Optional free-form note.
    pub msg: Option<String>,
}

/// Roll Call initiation request (`POST /rollcall`, spec 18.6.2).
#[derive(Debug, Clone, PartialEq)]
pub struct RollcallRequest {
    /// Roll call identifier; integer ids are coerced to decimal text.
    pub id: String,
    /// Initiating node address, if carried on the wire.
    pub from: Option<String>,
    /// Start timestamp in Unix seconds; server defaults to current time.
    pub ts: Option<u64>,
    /// Response window in seconds (1..=[MAX_TIMEOUT_S]).
    pub timeout_s: Option<u64>,
}

/// A node that answered a roll call (spec 18.6.3).
#[derive(Debug, Clone, PartialEq)]
pub struct RollcallResponder {
    /// Responding node's full IPv6 address (colon-hex text).
    pub node: String,
    /// Response timestamp in Unix epoch seconds.
    pub ts: u64,
    /// Reported status.
    pub status: CheckInStatus,
}

/// A node that has not answered a roll call (spec 18.6.3).
#[derive(Debug, Clone, PartialEq)]
pub struct RollcallMissing {
    /// Missing node's full IPv6 address (colon-hex text).
    pub node: String,
    /// Last time this node was seen, in Unix epoch seconds.
    pub last_seen: u64,
}

/// Roll Call status document (`GET /rollcall/{id}`, spec 18.6.3).
#[derive(Debug, Clone, PartialEq)]
pub struct RollcallStatus {
    /// Roll call identifier.
    pub id: String,
    /// Start timestamp in Unix epoch seconds.
    pub started: u64,
    /// Response window in seconds.
    pub timeout_s: u64,
    /// Nodes that responded within the window.
    pub responded: Vec<RollcallResponder>,
    /// Nodes that have not responded.
    pub missing: Vec<RollcallMissing>,
}

fn text_key<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
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

fn as_i64(v: &Value) -> Result<i64, Error> {
    match v {
        Value::Integer(i) => {
            i64::try_from(*i).map_err(|_| Error::Decode("integer out of range".into()))
        }
        _ => Err(Error::Decode(format!("expected integer, got {v:?}"))),
    }
}

fn wire_u64(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Integer(i) => {
            u64::try_from(*i).map_err(|_| Error::Decode("integer out of range".into()))
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

/// Gate raw input at the per-payload size bound before parsing.
fn check_input_len(bytes: &[u8], max_len: usize) -> Result<(), Error> {
    if bytes.len() > max_len {
        return Err(Error::Decode("payload_exceeds_maximum".into()));
    }
    Ok(())
}

/// Decode exactly one CBOR item, rejecting bytes after it (C
/// `LICHEN_CHECKIN_ERR_TRAILING_DATA`; same pattern as `deaddrop.rs`).
fn decode_item(bytes: &[u8]) -> Result<Value, Error> {
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|e| Error::Decode(e.to_string()))?;
    if cursor.position() as usize != bytes.len() {
        return Err(Error::Decode("trailing_data".into()));
    }
    Ok(value)
}

/// RFC 8949 §5.6: keys within a map must be unique; first-wins lookup
/// would silently accept duplicates the reference codec rejects (C
/// `LICHEN_CHECKIN_ERR_DUPLICATE_KEY`). Same discipline as msg.rs.
fn reject_duplicate_keys(map: &[(Value, Value)]) -> Result<(), Error> {
    for (index, (key, _)) in map.iter().enumerate() {
        if map[..index].iter().any(|(prev, _)| prev == key) {
            return Err(Error::Decode("duplicate_key".into()));
        }
    }
    Ok(())
}

/// Full-notation IPv6 check: exactly 8 groups of 4 hex digits separated
/// by colons (39 characters). Port of C `lichen_checkin_addr_valid`;
/// case-insensitive on hex digits, per the `checkin_node_format` vector.
fn is_valid_node_format(addr: &str) -> bool {
    let bytes = addr.as_bytes();
    if bytes.len() != 39 {
        return false;
    }
    let (groups, last) = bytes.split_at(35);
    groups
        .chunks_exact(5)
        .all(|g| g[4] == b':' && g[..4].iter().all(u8::is_ascii_hexdigit))
        && last.iter().all(u8::is_ascii_hexdigit)
}

/// Shared `from_cbor` prologue: size gate, single-item parse with
/// trailing-byte rejection, map shape, and duplicate-key rejection.
fn decode_map(bytes: &[u8], max_len: usize) -> Result<Vec<(Value, Value)>, Error> {
    check_input_len(bytes, max_len)?;
    let value = decode_item(bytes)?;
    let map = as_map(&value)?.clone();
    reject_duplicate_keys(&map)?;
    Ok(map)
}

/// Decode an optional coordinate, enforcing inclusive bounds and finiteness.
fn opt_coord(map: &[(Value, Value)], key: &str, limit: f64) -> Result<Option<f64>, Error> {
    match text_key(map, key) {
        None => Ok(None),
        Some(v) => {
            let c = as_f64(v)?;
            if !c.is_finite() || !(-limit..=limit).contains(&c) {
                return Err(Error::Decode("coordinate_out_of_range".into()));
            }
            Ok(Some(c))
        }
    }
}

/// Minimal deterministic CBOR writers matching the reference codec's output
/// (Python `cbor2.dumps` emits unsigned ints minimally and 64-bit floats).
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
        debug_assert!(len <= 23, "check-in maps are fixed-shape");
        out.push(0xA0 | len as u8);
    }

    pub(super) fn float64(out: &mut Vec<u8>, v: f64) {
        out.push(0xFB);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

impl CheckIn {
    fn validate(&self) -> Result<(), Error> {
        if !is_valid_node_format(&self.node) {
            return Err(Error::Encode("invalid_node_format".into()));
        }
        for (c, limit) in [(self.lat, 90.0_f64), (self.lon, 180.0_f64)] {
            if let Some(c) = c {
                if !c.is_finite() || !(-limit..=limit).contains(&c) {
                    return Err(Error::Encode("coordinate_out_of_range".into()));
                }
            }
        }
        if self.lat.is_none() != self.lon.is_none() {
            return Err(Error::Encode("incomplete_coordinate_pair".into()));
        }
        Ok(())
    }

    /// Encode the check-in body as a CBOR map with text keys.
    ///
    /// Field order matches the reference codec: `node`, `ts`, `lat`,
    /// `lon`, `status`, `msg`; only set optional fields are emitted.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut fields = 3_usize;
        if self.lat.is_some() {
            fields += 1;
        }
        if self.lon.is_some() {
            fields += 1;
        }
        if self.msg.is_some() {
            fields += 1;
        }

        let mut out = Vec::new();
        wire::map(&mut out, fields);
        wire::text(&mut out, "node");
        wire::text(&mut out, &self.node);
        wire::text(&mut out, "ts");
        wire::uint(&mut out, self.ts);
        if let Some(lat) = self.lat {
            wire::text(&mut out, "lat");
            wire::float64(&mut out, lat);
        }
        if let Some(lon) = self.lon {
            wire::text(&mut out, "lon");
            wire::float64(&mut out, lon);
        }
        wire::text(&mut out, "status");
        wire::text(&mut out, self.status.as_str());
        if let Some(msg) = &self.msg {
            wire::text(&mut out, "msg");
            wire::text(&mut out, msg);
        }
        Ok(out)
    }

    /// Decode and validate a check-in body.
    ///
    /// Unknown fields are ignored (matching the reference resource);
    /// required-field and range violations carry the vector error codes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let map = decode_map(bytes, CHECKIN_CBOR_MAX)?;

        let node = match text_key(&map, "node") {
            None => return Err(Error::Decode("missing_required_field_node".into())),
            Some(v) => match v.as_text() {
                Some(s) if is_valid_node_format(s) => s.to_owned(),
                _ => return Err(Error::Decode("invalid_node_format".into())),
            },
        };
        let ts = match text_key(&map, "ts") {
            None => return Err(Error::Decode("missing_required_field_ts".into())),
            Some(v) => wire_u64(v).map_err(|_| Error::Decode("invalid_ts_value".into()))?,
        };
        let status = match text_key(&map, "status") {
            None => return Err(Error::Decode("missing_required_field_status".into())),
            Some(v) => match v.as_text() {
                Some(s) => CheckInStatus::from_wire(s)?,
                None => return Err(Error::Decode("invalid_status_value".into())),
            },
        };
        let lat = opt_coord(&map, "lat", 90.0)?;
        let lon = opt_coord(&map, "lon", 180.0)?;
        if lat.is_none() != lon.is_none() {
            return Err(Error::Decode("incomplete_coordinate_pair".into()));
        }
        let msg = match text_key(&map, "msg") {
            None => None,
            Some(v) => match v.as_text() {
                Some(s) => Some(s.to_owned()),
                None => return Err(Error::Decode("invalid_msg_type".into())),
            },
        };

        Ok(Self {
            node,
            ts,
            status,
            lat,
            lon,
            msg,
        })
    }
}

impl RollcallRequest {
    fn timeout_from_wire(v: &Value) -> Result<u64, Error> {
        let t = as_i64(v).map_err(|_| Error::Decode("invalid_timeout_value".into()))?;
        if t <= 0 {
            return Err(Error::Decode("invalid_timeout_value".into()));
        }
        if t > i64::try_from(MAX_TIMEOUT_S).expect("MAX_TIMEOUT_S fits i64") {
            return Err(Error::Decode("timeout_exceeds_maximum".into()));
        }
        u64::try_from(t).map_err(|_| Error::Decode("invalid_timeout_value".into()))
    }

    /// Encode the roll call initiation body as a CBOR map with text keys.
    ///
    /// Field order matches the reference codec: `id`, `from`, `ts`,
    /// `timeout_s`; only set optional fields are emitted. The `id` is
    /// always emitted as text (integer ids were coerced at decode time).
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        if let Some(t) = self.timeout_s {
            if t == 0 {
                return Err(Error::Encode("invalid_timeout_value".into()));
            }
            if t > MAX_TIMEOUT_S {
                return Err(Error::Encode("timeout_exceeds_maximum".into()));
            }
        }
        let mut fields = 1_usize;
        if self.from.is_some() {
            fields += 1;
        }
        if self.ts.is_some() {
            fields += 1;
        }
        if self.timeout_s.is_some() {
            fields += 1;
        }

        let mut out = Vec::new();
        wire::map(&mut out, fields);
        wire::text(&mut out, "id");
        wire::text(&mut out, &self.id);
        if let Some(from) = &self.from {
            wire::text(&mut out, "from");
            wire::text(&mut out, from);
        }
        if let Some(ts) = self.ts {
            wire::text(&mut out, "ts");
            wire::uint(&mut out, ts);
        }
        if let Some(timeout_s) = self.timeout_s {
            wire::text(&mut out, "timeout_s");
            wire::uint(&mut out, timeout_s);
        }
        Ok(out)
    }

    /// Decode and validate a roll call initiation body.
    ///
    /// Integer `id` values are coerced to their decimal text form (the
    /// reference resource does the same); missing `timeout_s` means
    /// [DEFAULT_TIMEOUT_S] server-side and is left as [None] here.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let map = decode_map(bytes, ROLLCALL_REQ_CBOR_MAX)?;

        let id = match text_key(&map, "id") {
            None => return Err(Error::Decode("missing_required_field_id".into())),
            Some(v) => match v {
                Value::Text(s) => s.clone(),
                Value::Integer(_) => as_i64(v)?.to_string(),
                _ => return Err(Error::Decode("invalid_id_type".into())),
            },
        };
        let from = match text_key(&map, "from") {
            None => None,
            Some(v) => match v.as_text() {
                Some(s) => Some(s.to_owned()),
                None => return Err(Error::Decode("invalid_from_type".into())),
            },
        };
        let ts = match text_key(&map, "ts") {
            None => None,
            Some(v) => Some(wire_u64(v).map_err(|_| Error::Decode("invalid_ts_value".into()))?),
        };
        let timeout_s = match text_key(&map, "timeout_s") {
            None => None,
            Some(v) => Some(Self::timeout_from_wire(v)?),
        };

        Ok(Self {
            id,
            from,
            ts,
            timeout_s,
        })
    }
}

impl RollcallStatus {
    fn responder_from_wire(v: &Value) -> Result<RollcallResponder, Error> {
        let map = as_map(v)?;
        reject_duplicate_keys(map)?;
        let node = text_key(map, "node")
            .and_then(Value::as_text)
            .ok_or_else(|| Error::Decode("invalid_responder_node".into()))?
            .to_owned();
        let ts = wire_u64(
            text_key(map, "ts").ok_or_else(|| Error::Decode("invalid_responder_ts".into()))?,
        )
        .map_err(|_| Error::Decode("invalid_responder_ts".into()))?;
        let status = text_key(map, "status")
            .and_then(Value::as_text)
            .ok_or_else(|| Error::Decode("invalid_status_value".into()))
            .and_then(CheckInStatus::from_wire)?;
        Ok(RollcallResponder { node, ts, status })
    }

    fn missing_from_wire(v: &Value) -> Result<RollcallMissing, Error> {
        let map = as_map(v)?;
        reject_duplicate_keys(map)?;
        let node = text_key(map, "node")
            .and_then(Value::as_text)
            .ok_or_else(|| Error::Decode("invalid_missing_node".into()))?
            .to_owned();
        let last_seen = wire_u64(
            text_key(map, "last_seen")
                .ok_or_else(|| Error::Decode("invalid_missing_last_seen".into()))?,
        )
        .map_err(|_| Error::Decode("invalid_missing_last_seen".into()))?;
        Ok(RollcallMissing { node, last_seen })
    }

    /// Encode the roll call status document (text-keyed map, field order
    /// `id`, `started`, `timeout_s`, `responded`, `missing` matching the
    /// reference codec).
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        wire::map(&mut out, 5);
        wire::text(&mut out, "id");
        wire::text(&mut out, &self.id);
        wire::text(&mut out, "started");
        wire::uint(&mut out, self.started);
        wire::text(&mut out, "timeout_s");
        wire::uint(&mut out, self.timeout_s);
        wire::text(&mut out, "responded");
        wire::array(&mut out, self.responded.len());
        for r in &self.responded {
            wire::map(&mut out, 3);
            wire::text(&mut out, "node");
            wire::text(&mut out, &r.node);
            wire::text(&mut out, "ts");
            wire::uint(&mut out, r.ts);
            wire::text(&mut out, "status");
            wire::text(&mut out, r.status.as_str());
        }
        wire::text(&mut out, "missing");
        wire::array(&mut out, self.missing.len());
        for m in &self.missing {
            wire::map(&mut out, 2);
            wire::text(&mut out, "node");
            wire::text(&mut out, &m.node);
            wire::text(&mut out, "last_seen");
            wire::uint(&mut out, m.last_seen);
        }
        Ok(out)
    }

    /// Decode a roll call status document.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let map = decode_map(bytes, ROLLCALL_STATUS_CBOR_MAX)?;

        let id = text_key(&map, "id")
            .and_then(Value::as_text)
            .ok_or_else(|| Error::Decode("missing_required_field_id".into()))?
            .to_owned();
        let started = wire_u64(
            text_key(&map, "started")
                .ok_or_else(|| Error::Decode("invalid_started_value".into()))?,
        )
        .map_err(|_| Error::Decode("invalid_started_value".into()))?;
        let timeout_s = wire_u64(
            text_key(&map, "timeout_s")
                .ok_or_else(|| Error::Decode("invalid_timeout_value".into()))?,
        )
        .map_err(|_| Error::Decode("invalid_timeout_value".into()))?;
        let responded = Self::tracks_from_wire(&map, "responded", Self::responder_from_wire)?;
        let missing = Self::tracks_from_wire(&map, "missing", Self::missing_from_wire)?;

        Ok(Self {
            id,
            started,
            timeout_s,
            responded,
            missing,
        })
    }

    /// Decode a responded/missing array, capped at [ROLLCALL_TRACK_MAX]
    /// entries (C `LICHEN_ROLLCALL_TRACK_MAX`; over-cap arrays are C's
    /// `LICHEN_CHECKIN_ERR_OUT_OF_RANGE`).
    fn tracks_from_wire<T>(
        map: &[(Value, Value)],
        key: &str,
        decode_entry: fn(&Value) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let items = as_array(
            text_key(map, key).ok_or_else(|| Error::Decode(format!("invalid_{key}_type")))?,
        )?;
        if items.len() > ROLLCALL_TRACK_MAX {
            return Err(Error::Decode("out_of_range".into()));
        }
        items.iter().map(decode_entry).collect()
    }
}
