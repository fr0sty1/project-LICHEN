// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Dead Drop domain model and SenML wire codecs (spec 18.9, LCI 17.5.8).
//!
//! `/deaddrop` is a rate-limited, OSCORE-protected store-and-forward service:
//! clients POST SenML+CBOR packs for later pickup by others, optionally with
//! CoAP Observe (RFC 7641) for live notifications.
//!
//! Wire contract (firmware `/deaddrop` and `/deaddrop/{id}` resources):
//!
//! * Payloads are SenML+CBOR packs (RFC 8428, Content-Format 112) with RFC
//!   8428 Table 1 integer labels; JSON-style string names are also accepted
//!   on decode, mirroring the Python reference resource.
//! * `POST` requires a post-unprotect OSCORE identity
//!   ([`PostRequest::identity`]); the raw CoAP `oscore` option (9) bytes are
//!   carried alongside but never constitute authentication (spec 18.9:
//!   unprotected POST -> 4.01 `{"error": "oscore_required"}`).
//! * Responses are modeled by [`PostOutcome`] / [`PickupOutcome`] /
//!   [`GetResponse`] with raw CoAP code bytes ([`code`]).
//!
//! Rate limits and budgets (spec 18.9): 6 POSTs/hour/context, max drop size
//! 1536 B, storage 8 KB (leaf) / 32 KB (BR), default retention 24 h (max
//! 7 d). Eviction is expired-first, then oldest (FIFO). Packs are capped at
//! [`MAX_RECORDS_PER_PACK`] records: storage is charged by wire size, so an
//! unbounded record count would let tiny wire packs pin large decoded heap
//! (a deliberate, documented divergence from the Python reference, which has
//! no such cap).
//!
//! Conformance vectors: `test/vectors/deaddrop.json`.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value;
use getrandom::getrandom as fill_random;

use crate::Error;

/// POSTs per hour per OSCORE context (spec 18.9).
pub const POSTS_PER_HOUR: u32 = 6;
/// Maximum drop size in bytes (spec 18.9).
pub const MAX_DROP_SIZE: usize = 1536;
/// Maximum SenML records accepted in one submitted pack.
///
/// Spec 18.9 charges storage by wire size, but each decoded record carries
/// a fixed owned-struct overhead, so a pack of minimal records amplifies
/// tens of times on decode while charged only its wire length. Capping at
/// 32 records bounds the amplification of any stored drop to roughly an
/// order of magnitude of its 1536 B wire charge. Insert-time only: listing
/// packs assembled by [`DeadDropStore::render_get`] may legitimately hold
/// more records.
pub const MAX_RECORDS_PER_PACK: usize = 32;
/// Total storage budget for leaf nodes in bytes (spec 18.9).
pub const STORAGE_LEAF: usize = 8 * 1024;
/// Total storage budget for border routers in bytes (spec 18.9).
pub const STORAGE_BR: usize = 32 * 1024;
/// Default retention in seconds: 24 h (spec 18.9).
pub const DEFAULT_TTL: u64 = 24 * 3600;
/// Maximum retention in seconds: 7 days (spec 18.9).
pub const MAX_TTL: u64 = 7 * 24 * 3600;

/// Length of a drop ID in hex chars (e.g. `7f3a9c`; 3 random bytes).
const DROP_ID_HEX_LEN: usize = 6;

/// Bounded CSPRNG draws when minting a drop ID (spec 18.9 IDs are 24-bit).
///
/// Collisions are negligible until the space is nearly full; giving up with
/// a store-full outcome keeps a saturated store from spinning forever.
const MAX_ID_ATTEMPTS: usize = 32;

/// Raw CoAP response code bytes used by the Dead Drop outcomes.
pub mod code {
    /// 2.01 Created (POST success, `Location-Path: /deaddrop/{id}`).
    pub const CREATED: u8 = 65;
    /// 2.05 Content (GET success).
    pub const CONTENT: u8 = 69;
    /// 4.00 Bad Request.
    pub const BAD_REQUEST: u8 = 128;
    /// 4.01 Unauthorized (`{"error": "oscore_required"}`).
    pub const UNAUTHORIZED: u8 = 129;
    /// 4.03 Forbidden (group drop, non-recipient).
    pub const FORBIDDEN: u8 = 131;
    /// 4.04 Not Found.
    pub const NOT_FOUND: u8 = 132;
    /// 4.13 Request Entity Too Large (spec 18.9: max drop size 1536 B).
    pub const ENTITY_TOO_LARGE: u8 = 141;
    /// 5.00 Internal Server Error (invariant-violation outcome; never
    /// emitted while the store invariants hold).
    pub const INTERNAL_SERVER_ERROR: u8 = 160;
    /// 4.29 Too Many Requests with `Retry-After` (spec 18.9).
    pub const TOO_MANY_REQUESTS: u8 = 157;
    /// 5.03 Service Unavailable with CBOR details (spec 18.9).
    pub const SERVICE_UNAVAILABLE: u8 = 163;
}

/// Wall clock returning Unix seconds (spec 18.9 drop timestamps).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn system_clock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Return `true` if *value* is a canonical 6-char lowercase hex drop ID.
pub fn is_drop_id(value: &str) -> bool {
    value.len() == DROP_ID_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Drop visibility policy (spec 18.9 "Privacy toggles").
///
/// Unknown policy strings are rejected at creation time (fail-closed per
/// spec 18.9); only canonical tokens are ever stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Privacy {
    /// Visible to every reader.
    #[default]
    Public,
    /// Visible to the creating OSCORE context only.
    Private,
    /// Visible to the creating context or the designated recipient.
    Group,
}

impl Privacy {
    /// Parse a canonical privacy token; `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            "group" => Some(Self::Group),
            _ => None,
        }
    }

    /// The canonical token (SenML `privacy` record value).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Group => "group",
        }
    }
}

/// One RFC 8428 SenML record (owned form of `lichen_senml::wire::Record`).
///
/// The store keeps decoded records for drops, so the owned representation is
/// required; field names follow the RFC 8428 short names.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SenmlRecord {
    pub base_name: Option<String>,
    pub base_time: Option<f64>,
    pub base_unit: Option<String>,
    pub base_value: Option<f64>,
    pub base_sum: Option<f64>,
    pub base_version: Option<u8>,
    pub name: Option<String>,
    pub unit: Option<String>,
    pub value: Option<f64>,
    pub string_value: Option<String>,
    pub bool_value: Option<bool>,
    pub data_value: Option<Vec<u8>>,
    pub sum: Option<f64>,
    pub time: Option<f64>,
    pub update_time: Option<f64>,
}

impl SenmlRecord {
    /// A named string-value record (`n` / `vs`).
    pub fn text(name: &str, value: &str) -> Self {
        Self {
            name: Some(name.to_owned()),
            string_value: Some(value.to_owned()),
            ..Self::default()
        }
    }

    /// A named unit-carrying numeric-value record (`n` / `u` / `v`).
    pub fn number(name: &str, unit: &str, value: f64) -> Self {
        Self {
            name: Some(name.to_owned()),
            unit: Some(unit.to_owned()),
            value: Some(value),
            ..Self::default()
        }
    }
}

/// Resolve an RFC 8428 CBOR integer label (`field_for_label`).
fn field_for_label(label: i64) -> Option<&'static str> {
    Some(match label {
        -2 => "bn",
        -3 => "bt",
        -4 => "bu",
        -5 => "bv",
        -6 => "bs",
        -1 => "bver",
        0 => "n",
        1 => "u",
        2 => "v",
        3 => "vs",
        4 => "vb",
        5 => "s",
        6 => "t",
        7 => "ut",
        8 => "vd",
        _ => return None,
    })
}

/// Resolve an RFC 8428 short field name (`label_for_field`).
fn label_for_field(field: &str) -> Option<i64> {
    Some(match field {
        "bn" => -2,
        "bt" => -3,
        "bu" => -4,
        "bv" => -5,
        "bs" => -6,
        "bver" => -1,
        "n" => 0,
        "u" => 1,
        "v" => 2,
        "vs" => 3,
        "vb" => 4,
        "s" => 5,
        "t" => 6,
        "ut" => 7,
        "vd" => 8,
        _ => return None,
    })
}

/// Decode one numeric SenML field value (any integer width or float;
/// booleans are not numbers, mirroring the Python codec's type gate).
fn numeric_field(value: &Value) -> Result<f64, Error> {
    let out = match value {
        Value::Integer(i) => {
            // ciborium's Integer is i128-backed; convert infallibly.
            let raw: i128 = From::from(*i);
            raw as f64
        }
        Value::Float(f) => *f,
        _ => {
            return Err(Error::Decode(format!(
                "SenML field must be number, got {value:?}"
            )))
        }
    };
    if !out.is_finite() {
        return Err(Error::Decode("SenML number must be finite".into()));
    }
    Ok(out)
}

fn text_field(value: &Value) -> Result<String, Error> {
    value
        .as_text()
        .map(str::to_owned)
        .ok_or_else(|| Error::Decode(format!("SenML field must be text, got {value:?}")))
}

/// Assign one record map entry to *record* by RFC 8428 label.
fn assign_field(record: &mut SenmlRecord, label: i64, value: &Value) -> Result<(), Error> {
    match label {
        -2 => record.base_name = Some(text_field(value)?),
        -3 => record.base_time = Some(numeric_field(value)?),
        -4 => record.base_unit = Some(text_field(value)?),
        -5 => record.base_value = Some(numeric_field(value)?),
        -6 => record.base_sum = Some(numeric_field(value)?),
        -1 => {
            let raw = match value {
                Value::Integer(i) => u8::try_from(i128::from(*i))
                    .map_err(|_| Error::Decode("bver out of u8 range".into()))?,
                _ => return Err(Error::Decode("bver must be an integer".into())),
            };
            if !(1..=10).contains(&raw) {
                return Err(Error::Decode("bver must be in [1,10]".into()));
            }
            record.base_version = Some(raw);
        }
        0 => record.name = Some(text_field(value)?),
        1 => record.unit = Some(text_field(value)?),
        2 => record.value = Some(numeric_field(value)?),
        3 => record.string_value = Some(text_field(value)?),
        4 => match value {
            Value::Bool(b) => record.bool_value = Some(*b),
            _ => return Err(Error::Decode("vb must be a boolean".into())),
        },
        5 => record.sum = Some(numeric_field(value)?),
        6 => record.time = Some(numeric_field(value)?),
        7 => record.update_time = Some(numeric_field(value)?),
        8 => match value {
            Value::Bytes(b) => record.data_value = Some(b.clone()),
            _ => return Err(Error::Decode("vd must be a byte string".into())),
        },
        _ => return Err(Error::Decode(format!("unknown SenML label {label}"))),
    }
    Ok(())
}

fn value_field_count(record: &SenmlRecord) -> usize {
    usize::from(record.value.is_some())
        + usize::from(record.string_value.is_some())
        + usize::from(record.bool_value.is_some())
        + usize::from(record.data_value.is_some())
}

fn record_from_map(map: &[(Value, Value)]) -> Result<SenmlRecord, Error> {
    let mut out = SenmlRecord::default();
    for (key, value) in map {
        match key {
            Value::Integer(i) => {
                let label = i64::try_from(*i)
                    .map_err(|_| Error::Decode("SenML label out of range".into()))?;
                if field_for_label(label).is_some() {
                    assign_field(&mut out, label, value)?;
                }
                // Unknown integer labels are ignored (RFC 8428 extension rule).
            }
            Value::Text(name) => {
                if name.ends_with('_') {
                    return Err(Error::Decode(format!(
                        "unknown mandatory SenML label '{name}'"
                    )));
                }
                if let Some(label) = label_for_field(name) {
                    assign_field(&mut out, label, value)?;
                }
                // Unknown string names are ignored.
            }
            other => {
                return Err(Error::Decode(format!(
                    "SenML label must be integer or string, got {other:?}"
                )))
            }
        }
    }
    if value_field_count(&out) > 1 {
        return Err(Error::Decode(
            "SenML record must have at most one value field".into(),
        ));
    }
    Ok(out)
}

/// Decode a SenML+CBOR pack (RFC 8428, Content-Format 112).
///
/// Accepts integer labels and JSON-style string names; rejects trailing
/// bytes, non-array packs, wrong-typed fields, records carrying more than
/// one value field, non-finite numbers, and `bver` outside [1,10].
pub fn decode_senml_pack(bytes: &[u8]) -> Result<Vec<SenmlRecord>, Error> {
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|e| Error::Decode(e.to_string()))?;
    if cursor.position() as usize != bytes.len() {
        return Err(Error::Decode("trailing bytes after SenML pack".into()));
    }
    let items = match &value {
        Value::Array(items) => items,
        _ => return Err(Error::Decode("SenML pack must be an array".into())),
    };
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Map(map) => records.push(record_from_map(map)?),
            _ => return Err(Error::Decode("SenML records must be maps".into())),
        }
    }
    Ok(records)
}

/// Minimal deterministic CBOR writers matching the Python reference codec
/// (`cbor2.dumps`: shortest-form integers, 64-bit floats).
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

    pub(super) fn int(out: &mut Vec<u8>, v: i64) {
        if v < 0 {
            // Negative ints use major type 1: value -1 - magnitude.
            nint(out, u64::MAX - (v as u64));
        } else {
            uint(out, v as u64);
        }
    }

    pub(super) fn nint(out: &mut Vec<u8>, magnitude: u64) {
        if magnitude < 24 {
            out.push(0x20 | magnitude as u8);
        } else if magnitude <= u64::from(u8::MAX) {
            out.push(0x38);
            out.push(magnitude as u8);
        } else if magnitude <= u64::from(u16::MAX) {
            out.push(0x39);
            out.extend_from_slice(&(magnitude as u16).to_be_bytes());
        } else if magnitude <= u64::from(u32::MAX) {
            out.push(0x3A);
            out.extend_from_slice(&(magnitude as u32).to_be_bytes());
        } else {
            out.push(0x3B);
            out.extend_from_slice(&magnitude.to_be_bytes());
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

    pub(super) fn bytes(out: &mut Vec<u8>, data: &[u8]) {
        let len = data.len();
        if len < 24 {
            out.push(0x40 | len as u8);
        } else if len <= usize::from(u8::MAX) {
            out.push(0x58);
            out.push(len as u8);
        } else if len <= usize::from(u16::MAX) {
            out.push(0x59);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x5A);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        out.extend_from_slice(data);
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
        debug_assert!(len <= 23, "SenML records carry at most 15 fields");
        out.push(0xA0 | len as u8);
    }

    /// Numeric value: shortest-form integer when integral within the exact
    /// `i64` window (matching `cbor2` on int inputs), otherwise 64-bit float.
    pub(super) fn number(out: &mut Vec<u8>, v: f64) {
        if v.is_finite()
            && v.fract() == 0.0
            && v >= i64::MIN as f64
            && v < 9_223_372_036_854_775_808.0
        {
            int(out, v as i64);
        } else {
            out.push(0xFB);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

fn field_count(record: &SenmlRecord) -> usize {
    usize::from(record.base_name.is_some())
        + usize::from(record.base_time.is_some())
        + usize::from(record.base_unit.is_some())
        + usize::from(record.base_value.is_some())
        + usize::from(record.base_sum.is_some())
        + usize::from(record.base_version.is_some())
        + usize::from(record.name.is_some())
        + usize::from(record.unit.is_some())
        + usize::from(record.value.is_some())
        + usize::from(record.string_value.is_some())
        + usize::from(record.bool_value.is_some())
        + usize::from(record.data_value.is_some())
        + usize::from(record.sum.is_some())
        + usize::from(record.time.is_some())
        + usize::from(record.update_time.is_some())
}

/// Encode a SenML pack deterministically (RFC 8428 integer labels, field
/// order matching the Python reference codec's dataclass field order:
/// bn, bt, bu, bv, bs, bver, n, u, v, vs, vb, vd, s, t, ut).
pub fn encode_senml_pack(records: &[SenmlRecord]) -> Result<Vec<u8>, Error> {
    for record in records {
        if value_field_count(record) > 1 {
            return Err(Error::Encode(
                "SenML record must have at most one value field".into(),
            ));
        }
    }
    let mut out = Vec::new();
    wire::array(&mut out, records.len());
    for record in records {
        wire::map(&mut out, field_count(record));
        emit_record_fields(record, &mut out);
    }
    Ok(out)
}

fn emit_record_fields(record: &SenmlRecord, out: &mut Vec<u8>) {
    if let Some(v) = record.base_name.as_deref() {
        wire::int(out, -2);
        wire::text(out, v);
    }
    if let Some(v) = record.base_time {
        wire::int(out, -3);
        wire::number(out, v);
    }
    if let Some(v) = record.base_unit.as_deref() {
        wire::int(out, -4);
        wire::text(out, v);
    }
    if let Some(v) = record.base_value {
        wire::int(out, -5);
        wire::number(out, v);
    }
    if let Some(v) = record.base_sum {
        wire::int(out, -6);
        wire::number(out, v);
    }
    if let Some(v) = record.base_version {
        wire::int(out, -1);
        wire::uint(out, u64::from(v));
    }
    if let Some(v) = record.name.as_deref() {
        wire::uint(out, 0);
        wire::text(out, v);
    }
    if let Some(v) = record.unit.as_deref() {
        wire::uint(out, 1);
        wire::text(out, v);
    }
    if let Some(v) = record.value {
        wire::uint(out, 2);
        wire::number(out, v);
    }
    if let Some(v) = record.string_value.as_deref() {
        wire::uint(out, 3);
        wire::text(out, v);
    }
    if let Some(v) = record.bool_value {
        wire::uint(out, 4);
        out.push(u8::from(v));
    }
    if let Some(v) = record.data_value.as_deref() {
        wire::uint(out, 8);
        wire::bytes(out, v);
    }
    if let Some(v) = record.sum {
        wire::uint(out, 5);
        wire::number(out, v);
    }
    if let Some(v) = record.time {
        wire::uint(out, 6);
        wire::number(out, v);
    }
    if let Some(v) = record.update_time {
        wire::uint(out, 7);
        wire::number(out, v);
    }
}

/// Text value of the first record named *name* (`vs` form).
fn senml_text<'a>(records: &'a [SenmlRecord], name: &str) -> Option<&'a str> {
    records
        .iter()
        .find(|r| r.name.as_deref() == Some(name))
        .and_then(|r| r.string_value.as_deref())
}

/// Retention seconds from SenML `ttl` / `expires` records, clamped to spec
/// 18.9 limits.
///
/// A `ttl` of zero or less is honored as immediate expiry; an `expires` in
/// the past likewise yields zero retention. Only packs carrying neither
/// field fall back to [`DEFAULT_TTL`]. Non-finite values clamp fail-closed:
/// `+inf` to [`MAX_TTL`], `-inf`/NaN to zero.
pub fn extract_ttl(records: &[SenmlRecord], now: f64) -> u64 {
    let mut ttl: Option<f64> = None;
    let mut expires: Option<f64> = None;
    for record in records {
        let Some(value) = record.value else {
            continue;
        };
        match record.name.as_deref() {
            Some("ttl") => ttl = Some(value),
            Some("expires") => expires = Some(value),
            _ => {}
        }
    }
    if let Some(ttl) = ttl {
        if ttl.is_finite() {
            return (ttl as i64).clamp(0, MAX_TTL as i64) as u64;
        }
        return if ttl > 0.0 { MAX_TTL } else { 0 };
    }
    if let Some(expires) = expires {
        let remaining = expires - now;
        if remaining > 0.0 {
            return (remaining as i64).clamp(0, MAX_TTL as i64) as u64;
        }
        return 0;
    }
    DEFAULT_TTL
}

/// Clamp a caller-supplied retention to `[0, MAX_TTL]` seconds.
pub fn clamp_ttl(ttl: u64) -> u64 {
    ttl.min(MAX_TTL)
}

/// A stored dead drop's public view.
#[derive(Debug, Clone, PartialEq)]
pub struct DropView {
    /// Drop ID (`/deaddrop/{id}` suffix).
    pub id: String,
    /// Wrapped SenML payload records.
    pub records: Vec<SenmlRecord>,
    /// Creation time (Unix seconds).
    pub created: f64,
    /// Retention seconds assigned at creation (clamped).
    pub ttl: u64,
    /// Age in seconds at read time.
    pub age_s: u64,
    /// Encoded size in bytes charged against the storage budget.
    pub size: usize,
    /// Visibility policy.
    pub privacy: Privacy,
    /// Designated recipient, if addressed.
    pub recipient: Option<String>,
    /// Creating OSCORE context identity.
    pub context: String,
}

/// Visibility of one stored drop.
fn drop_visible(
    privacy: Privacy,
    context: &str,
    recipient: Option<&str>,
    viewer: Option<&str>,
) -> bool {
    match privacy {
        Privacy::Public => true,
        Privacy::Private => viewer == Some(context),
        Privacy::Group => viewer == Some(context) || viewer == recipient,
    }
}

struct StoredDrop {
    id: String,
    records: Vec<SenmlRecord>,
    created: f64,
    ttl: u64,
    context: String,
    size: usize,
    privacy: Privacy,
    recipient: Option<String>,
}

impl StoredDrop {
    fn visible_to(&self, viewer: Option<&str>) -> bool {
        drop_visible(
            self.privacy,
            &self.context,
            self.recipient.as_deref(),
            viewer,
        )
    }

    fn view(&self, now: f64) -> DropView {
        DropView {
            id: self.id.clone(),
            records: self.records.clone(),
            created: self.created,
            ttl: self.ttl,
            age_s: (now - self.created).max(0.0) as u64,
            size: self.size,
            privacy: self.privacy,
            recipient: self.recipient.clone(),
            context: self.context.clone(),
        }
    }
}

/// Outcome of `POST /deaddrop` (raw codes in [`code`]).
#[derive(Debug, Clone, PartialEq)]
pub enum PostOutcome {
    /// 2.01 Created; `location_path` is `/deaddrop/{id}`, `max_age` the
    /// effective (clamped) retention.
    Created {
        drop_id: String,
        location_path: String,
        max_age: u64,
    },
    /// 4.00 Bad Request (malformed body or privacy policy).
    BadRequest,
    /// 4.01 Unauthorized: no post-unprotect OSCORE identity.
    Unauthorized,
    /// 4.13 Request Entity Too Large.
    EntityTooLarge,
    /// 4.29 Too Many Requests; `retry_after` seconds for `Retry-After`.
    TooManyRequests { retry_after: u64 },
    /// 5.03 Service Unavailable with CBOR details
    /// `{reason: "storage_full", retry_after, available_kb}`. Also returned
    /// when the 24-bit drop-ID space is exhausted (a storage-full form: the
    /// store cannot admit another drop). Live drops are never evicted for a
    /// request that ends in this outcome.
    ServiceUnavailable { retry_after: u64, available_kb: f64 },
}

impl PostOutcome {
    /// The raw CoAP response code byte for this outcome.
    pub fn response_code(&self) -> u8 {
        match self {
            Self::Created { .. } => code::CREATED,
            Self::BadRequest => code::BAD_REQUEST,
            Self::Unauthorized => code::UNAUTHORIZED,
            Self::EntityTooLarge => code::ENTITY_TOO_LARGE,
            Self::TooManyRequests { .. } => code::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable { .. } => code::SERVICE_UNAVAILABLE,
        }
    }
}

/// Outcome of `GET /deaddrop/{id}` (raw codes in [`code`]).
#[derive(Debug, Clone, PartialEq)]
pub enum PickupOutcome {
    /// 2.05 Content with the drop's SenML pack and remaining `max_age`.
    Content {
        payload: Vec<u8>,
        content_format: u16,
        max_age: Option<u64>,
    },
    /// 4.03 Forbidden (group drop, requester is not creator or recipient).
    Forbidden,
    /// 4.04 Not Found (unknown/expired ID, or a private drop of another
    /// context — hidden to conceal existence).
    NotFound,
    /// 5.00 Internal Server Error. Unreachable while the store invariants
    /// hold (stored records are decode-validated, so re-encoding cannot
    /// fail); returned instead of masking a violated invariant as an empty
    /// 2.05.
    InternalError,
}

impl PickupOutcome {
    /// The raw CoAP response code byte for this outcome.
    pub fn response_code(&self) -> u8 {
        match self {
            Self::Content { .. } => code::CONTENT,
            Self::Forbidden => code::FORBIDDEN,
            Self::NotFound => code::NOT_FOUND,
            Self::InternalError => code::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Response to `GET /deaddrop` (collection listing).
#[derive(Debug, Clone, PartialEq)]
pub struct GetResponse {
    /// SenML+CBOR pack of wrapped drops.
    pub payload: Vec<u8>,
    /// Content-Format (112, `application/senml+cbor`).
    pub content_format: u16,
    /// Observe sequence value when the request registered Observe.
    pub observe: Option<u64>,
}

/// Collection listing filters (spec 18.9 query parameters).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DropFilter<'a> {
    /// `?type=` filter on the SenML `type` record.
    pub drop_type: Option<&'a str>,
    /// `?after=` Unix seconds; only drops created strictly after.
    pub after: Option<f64>,
    /// `?node=` recipient filter (drop recipient or SenML
    /// `recipient`/`node` records).
    pub node: Option<&'a str>,
}

/// Storage accounting snapshot ([`DeadDropStore::storage_info`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageInfo {
    pub used_bytes: usize,
    pub limit_bytes: usize,
    pub available_bytes: usize,
    pub drop_count: usize,
}

/// Parameters for a direct drop creation (mesh delivery, tests).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddDropParams {
    /// Explicit retention override; clamped. `None` derives from the pack.
    pub ttl: Option<u64>,
    /// Requested drop ID (canonical 6-hex, unused); generated when `None`.
    pub drop_id: Option<String>,
    /// Visibility when the pack carries no `privacy` record.
    pub privacy: Privacy,
    /// Recipient when the pack carries no `recipient`/`node` record.
    pub recipient: Option<String>,
}

/// A `POST /deaddrop` request as seen by the resource after transport.
#[derive(Debug, Clone, Default)]
pub struct PostRequest {
    /// Raw request payload (the OSCORE-protected plaintext).
    pub body: Vec<u8>,
    /// Post-unprotect OSCORE identity. `None` -> 4.01 (spec 18.9); the raw
    /// `oscore` option bytes are never authentication on their own.
    pub identity: Option<String>,
    /// Raw CoAP OSCORE option (9) bytes from the request, carried for
    /// context binding and echo; see `identity` for the security stance.
    pub oscore_option: Option<Vec<u8>>,
}

/// Rate-limited store-and-forward dead drop (spec 18.9).
///
/// Mirrors the Python reference resource: per-context rate limiting
/// (6/hour, 1-hour sliding window with global reaping), drop size cap,
/// storage budget with expired-then-oldest FIFO eviction, privacy ACL, TTL
/// clamping (`ttl` record, then `expires`, else default), and Observe state
/// versioning.
pub struct DeadDropStore {
    storage_limit: usize,
    clock: Clock,
    drops: Vec<StoredDrop>,
    request_times: HashMap<String, Vec<f64>>,
    current_storage: usize,
    version: u64,
}

impl DeadDropStore {
    /// Create a store with *storage_limit* bytes and the system clock.
    pub fn new(storage_limit: usize) -> Result<Self, Error> {
        Self::with_clock(storage_limit, Arc::new(system_clock))
    }

    /// Create a store with an injected clock (Unix seconds).
    ///
    /// Rejects a zero *storage_limit* with [`Error::Config`] — a
    /// configuration-validation failure, not a wire encode failure.
    pub fn with_clock(storage_limit: usize, clock: Clock) -> Result<Self, Error> {
        if storage_limit == 0 {
            return Err(Error::Config(
                "storage_limit must be a positive integer".into(),
            ));
        }
        Ok(Self {
            storage_limit,
            clock,
            drops: Vec::new(),
            request_times: HashMap::new(),
            current_storage: 0,
            version: 0,
        })
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Remove expired drops; `true` when anything was pruned.
    fn prune_expired(&mut self) -> bool {
        let now = self.now();
        let before = self.drops.len();
        self.drops.retain(|d| now - d.created < d.ttl as f64);
        if self.drops.len() != before {
            self.current_storage = self.drops.iter().map(|d| d.size).sum();
            true
        } else {
            false
        }
    }

    /// Evict expired, then oldest, drops until *needed* bytes fit.
    /// `false` when even an empty store could not hold the drop.
    fn evict_for_space(&mut self, needed: usize) -> bool {
        if needed > self.storage_limit {
            return false;
        }
        self.prune_expired();
        while self.current_storage + needed > self.storage_limit && !self.drops.is_empty() {
            if let Some(oldest) = self.drops.first() {
                let size = oldest.size;
                self.drops.remove(0);
                self.current_storage -= size;
            }
        }
        self.current_storage + needed <= self.storage_limit
    }

    fn find_index(&self, drop_id: &str) -> Option<usize> {
        self.drops.iter().position(|d| d.id == drop_id)
    }

    /// Generate an unused canonical drop ID.
    ///
    /// Three bytes are drawn from the OS CSPRNG (`getrandom`), mirroring the
    /// Python reference's `secrets.token_hex(3)`: the 6-hex format is fixed
    /// by spec 18.9, so unpredictability against enumeration is the
    /// achievable property. Collisions are retried, but only up to
    /// [`MAX_ID_ATTEMPTS`] draws; `None` means the 2^24 ID space is
    /// effectively exhausted (or the CSPRNG failed) and the store cannot
    /// admit the drop.
    fn generate_drop_id(&mut self) -> Option<String> {
        for _ in 0..MAX_ID_ATTEMPTS {
            let mut bytes = [0u8; DROP_ID_HEX_LEN / 2];
            fill_random(&mut bytes).ok()?;
            let id = format!(
                "{:0width$x}",
                u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
                width = DROP_ID_HEX_LEN
            );
            if self.find_index(&id).is_none() {
                return Some(id);
            }
        }
        None
    }

    /// Remove timestamps older than the 1-hour window from every bucket.
    ///
    /// Reaping is global so abandoned identities cannot grow the map.
    fn reap_stale_buckets(&mut self) {
        let cutoff = self.now() - 3600.0;
        self.request_times.retain(|_, ts| {
            ts.retain(|t| *t > cutoff);
            !ts.is_empty()
        });
    }

    /// Check the per-context POST budget; returns `(allowed, retry_after)`.
    pub fn check_rate_limit(&mut self, context_id: &str) -> (bool, u64) {
        self.reap_stale_buckets();
        let now = self.now();
        let Some(timestamps) = self.request_times.get(context_id) else {
            return (true, 0);
        };
        if timestamps.len() < POSTS_PER_HOUR as usize {
            return (true, 0);
        }
        let oldest = timestamps.iter().copied().fold(f64::INFINITY, f64::min);
        let retry_after = (3600.0 - (now - oldest)).ceil();
        (false, (retry_after as i64).max(1) as u64)
    }

    fn record_request(&mut self, context_id: &str) {
        self.reap_stale_buckets();
        let now = self.now();
        self.request_times
            .entry(context_id.to_owned())
            .or_default()
            .push(now);
    }

    /// The Observe state version (RFC 7641); bumped on each new drop.
    pub fn observe_version(&self) -> u64 {
        self.version
    }

    /// Current storage accounting (expired drops pruned first).
    pub fn storage_info(&mut self) -> StorageInfo {
        self.prune_expired();
        StorageInfo {
            used_bytes: self.current_storage,
            limit_bytes: self.storage_limit,
            available_bytes: self.storage_limit - self.current_storage,
            drop_count: self.drops.len(),
        }
    }

    fn available_kb(&self) -> f64 {
        let available = self.storage_limit.saturating_sub(self.current_storage);
        available as f64 / 1024.0
    }

    /// Add a drop directly (mesh delivery or tests).
    ///
    /// Returns the drop ID, or `None` when the pack is invalid, exceeds
    /// [`MAX_DROP_SIZE`], the budget or the drop-ID space is exhausted, or
    /// the requested ID or privacy policy is invalid. No live drop is
    /// evicted for a request that returns `None`. An explicit `ttl` of zero
    /// is honored as immediate expiry.
    pub fn add_drop(
        &mut self,
        payload: &[SenmlRecord],
        context_id: &str,
        params: &AddDropParams,
    ) -> Option<String> {
        let encoded = encode_senml_pack(payload).ok()?;
        let size = encoded.len();
        if size > MAX_DROP_SIZE || payload.len() > MAX_RECORDS_PER_PACK {
            return None;
        }
        let ttl = match params.ttl {
            Some(ttl) => clamp_ttl(ttl),
            None => extract_ttl(payload, self.now()),
        };
        let privacy = match privacy_from_records(payload) {
            Ok(privacy) => privacy.unwrap_or(params.privacy),
            Err(()) => return None,
        };
        let recipient = params
            .recipient
            .clone()
            .or_else(|| senml_text(payload, "recipient").map(str::to_owned))
            .or_else(|| senml_text(payload, "node").map(str::to_owned));
        // Validate an explicit ID before eviction (spec 18.9: eviction admits
        // a stored drop; it must not fire on a doomed request). A generated
        // ID is likewise minted first so a saturated ID space cannot evict.
        let generated = match &params.drop_id {
            Some(id) => {
                if !is_drop_id(id) || self.find_index(id).is_some() {
                    return None;
                }
                None
            }
            None => Some(self.generate_drop_id()?),
        };
        if !self.evict_for_space(size) {
            return None;
        }
        let drop_id = match (&params.drop_id, generated) {
            (Some(id), _) => id.clone(),
            (None, Some(id)) => id,
            (None, None) => return None,
        };
        let now = self.now();
        self.drops.push(StoredDrop {
            id: drop_id.clone(),
            records: payload.to_vec(),
            created: now,
            ttl,
            context: context_id.to_owned(),
            size,
            privacy,
            recipient,
        });
        self.current_storage += size;
        self.version += 1;
        Some(drop_id)
    }

    /// Handle `POST /deaddrop` (spec 18.9 gate order).
    pub fn post(&mut self, request: &PostRequest) -> PostOutcome {
        // Writes MUST be OSCORE-protected; identity is bound post-unprotect.
        let Some(context_id) = request.identity.clone() else {
            return PostOutcome::Unauthorized;
        };
        if request.body.is_empty() {
            return PostOutcome::BadRequest;
        }
        if request.body.len() > MAX_DROP_SIZE {
            return PostOutcome::EntityTooLarge;
        }
        let records = match decode_senml_pack(&request.body) {
            Ok(records) => records,
            Err(_) => return PostOutcome::BadRequest,
        };
        if records.len() > MAX_RECORDS_PER_PACK {
            return PostOutcome::BadRequest;
        }
        let (allowed, retry_after) = self.check_rate_limit(&context_id);
        if !allowed {
            return PostOutcome::TooManyRequests { retry_after };
        }
        let now = self.now();
        let ttl = extract_ttl(&records, now);
        let privacy = match privacy_from_records(&records) {
            Ok(privacy) => privacy.unwrap_or(Privacy::Public),
            Err(()) => return PostOutcome::BadRequest,
        };
        let size = request.body.len();
        // Mint the ID before eviction: a store that cannot admit another
        // drop (ID space exhausted) must not evict live drops first.
        let Some(drop_id) = self.generate_drop_id() else {
            return PostOutcome::ServiceUnavailable {
                retry_after: 3600,
                available_kb: self.available_kb(),
            };
        };
        if !self.evict_for_space(size) {
            return PostOutcome::ServiceUnavailable {
                retry_after: 3600,
                available_kb: self.available_kb(),
            };
        }
        let recipient = senml_text(&records, "recipient")
            .map(str::to_owned)
            .or_else(|| senml_text(&records, "node").map(str::to_owned));
        self.drops.push(StoredDrop {
            id: drop_id.clone(),
            records,
            created: now,
            ttl,
            context: context_id.clone(),
            size,
            privacy,
            recipient,
        });
        self.current_storage += size;
        self.record_request(&context_id);
        self.version += 1;
        PostOutcome::Created {
            location_path: format!("/deaddrop/{drop_id}"),
            drop_id,
            max_age: ttl,
        }
    }

    /// Drops visible to *context_id*, oldest first, after pruning.
    pub fn drops(&mut self, context_id: Option<&str>, filter: &DropFilter<'_>) -> Vec<DropView> {
        self.prune_expired();
        let now = self.now();
        let mut views = Vec::new();
        for drop in &self.drops {
            if !drop.visible_to(context_id) {
                continue;
            }
            if let Some(after) = filter.after {
                if drop.created <= after {
                    continue;
                }
            }
            if let Some(want) = filter.drop_type {
                if senml_text(&drop.records, "type") != Some(want) {
                    continue;
                }
            }
            if let Some(node) = filter.node {
                let recipient = drop
                    .recipient
                    .as_deref()
                    .or_else(|| senml_text(&drop.records, "recipient"));
                let node_field = senml_text(&drop.records, "node");
                if recipient != Some(node) && node_field != Some(node) {
                    continue;
                }
            }
            views.push(drop.view(now));
        }
        views
    }

    /// Handle `GET /deaddrop`: wrapped listing as SenML+CBOR (Content-Format
    /// 112), each drop prefixed with `id` / `age_s` / `ttl` / `size`
    /// metadata records followed by its own payload records.
    ///
    /// `Err` is unreachable while the store invariants hold (every stored
    /// record was decode-validated, so the wrapped pack always re-encodes);
    /// a failure is surfaced instead of masked as an empty listing.
    pub fn render_get(
        &mut self,
        context_id: Option<&str>,
        filter: &DropFilter<'_>,
        observe: bool,
    ) -> Result<GetResponse, Error> {
        let views = self.drops(context_id, filter);
        let mut records = Vec::new();
        for view in &views {
            records.push(SenmlRecord::text("id", &view.id));
            records.push(SenmlRecord::number("age_s", "s", view.age_s as f64));
            records.push(SenmlRecord::number("ttl", "s", view.ttl as f64));
            records.push(SenmlRecord::number("size", "B", view.size as f64));
            records.extend(view.records.iter().cloned());
        }
        let payload = encode_senml_pack(&records)?;
        Ok(GetResponse {
            payload,
            content_format: 112,
            observe: observe.then_some(self.version),
        })
    }

    /// Handle `GET /deaddrop/{id}`: a single drop's SenML payload with
    /// `max_age` set to the remaining retention.
    pub fn get_by_id(&mut self, drop_id: &str, context_id: Option<&str>) -> PickupOutcome {
        if !is_drop_id(drop_id) {
            return PickupOutcome::NotFound;
        }
        self.prune_expired();
        let Some(index) = self.find_index(drop_id) else {
            return PickupOutcome::NotFound;
        };
        let now = self.now();
        let drop = &self.drops[index];
        if !drop.visible_to(context_id) {
            // Private drops return 4.04 to hide existence; group drops 4.03
            // to signal the recipient should authenticate (Python reference).
            return match drop.privacy {
                Privacy::Private => PickupOutcome::NotFound,
                _ => PickupOutcome::Forbidden,
            };
        }
        // Unreachable while the store invariants hold (records are
        // decode-validated at insert); surface the violation instead of
        // masking it as an empty 2.05.
        let payload = match encode_senml_pack(&drop.records) {
            Ok(payload) => payload,
            Err(_) => return PickupOutcome::InternalError,
        };
        let remaining = drop
            .ttl
            .saturating_sub((now - drop.created).max(0.0) as u64);
        PickupOutcome::Content {
            payload,
            content_format: 112,
            max_age: (remaining > 0).then_some(remaining),
        }
    }
}

/// Extract the privacy policy from SenML `privacy` records.
///
/// `Err(())` marks an invalid (non-canonical) token; `Ok(None)` means the
/// pack carries no policy and the caller's default applies.
fn privacy_from_records(records: &[SenmlRecord]) -> Result<Option<Privacy>, ()> {
    match senml_text(records, "privacy") {
        None => Ok(None),
        Some(token) => Privacy::parse(token).map(Some).ok_or(()),
    }
}
