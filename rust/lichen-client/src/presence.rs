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
//!   "low_battery": true,        ; set when battery < 10 (bool, optional)
//!   "ts": 1716742800            ; last update (uint)
//! }
//! ```
//!
//! Optional fields are omitted when unset. Map key order is status, activity,
//! msg, battery, low_battery, ts so encoding matches
//! `test/vectors/presence_cbor.json`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Error;

// SECURITY: Mutation limits matching Python _decode_single_cbor to bound
// hostile CBOR work for LoRa/CoAP nodes.
const MAX_PAYLOAD_BYTES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_MAP_ENTRIES: usize = 64;
const MAX_ARRAY_ENTRIES: usize = 256;
const MAX_ITEMS: usize = 1024;

/// CBOR scanner budget for item counting.
struct ScanBudget {
    items: usize,
}

impl ScanBudget {
    fn new() -> Self {
        Self { items: 0 }
    }

    fn count(&mut self) -> Result<(), Error> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(Error::Decode(
                "CBOR item count exceeds mutation limit".into(),
            ));
        }
        Ok(())
    }
}

/// Read CBOR argument value from additional info.
fn cbor_argument(payload: &[u8], offset: usize, additional: u8) -> Result<(u64, usize), Error> {
    if additional < 24 {
        return Ok((additional as u64, offset));
    }
    let width = match additional {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(Error::Decode("invalid CBOR argument encoding".into())),
    };
    if offset + width > payload.len() {
        return Err(Error::Decode("truncated CBOR argument".into()));
    }
    let mut value = 0u64;
    for byte in &payload[offset..offset + width] {
        value = (value << 8) | (*byte as u64);
    }
    Ok((value, offset + width))
}

/// Scan one CBOR item, rejecting tags, duplicate keys, and enforcing limits.
fn scan_cbor_item(
    payload: &[u8],
    offset: usize,
    depth: usize,
    budget: &mut ScanBudget,
) -> Result<usize, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Decode(
            "CBOR nesting depth exceeds mutation limit".into(),
        ));
    }
    budget.count()?;

    if offset >= payload.len() {
        return Err(Error::Decode("truncated CBOR item".into()));
    }
    let initial = payload[offset];
    if initial == 0xFF {
        return Err(Error::Decode("unexpected CBOR break".into()));
    }
    let mut pos = offset + 1;
    let major = initial >> 5;
    let additional = initial & 0x1F;
    let indefinite = additional == 31;

    match major {
        // unsigned int, negative int, simple/float
        0 | 1 | 7 => {
            if indefinite {
                return Err(Error::Decode("invalid indefinite scalar".into()));
            }
            let (_value, new_pos) = cbor_argument(payload, pos, additional)?;
            Ok(new_pos)
        }
        // byte string, text string
        2 | 3 => {
            if !indefinite {
                let (length, new_pos) = cbor_argument(payload, pos, additional)?;
                // SECURITY: Reject lengths that exceed usize::MAX to avoid truncation
                // on 32-bit systems (e.g., 0x1_0000_0010 -> 0x10 bypassing bounds check).
                if length > usize::MAX as u64 {
                    return Err(Error::Decode(
                        "CBOR string length exceeds platform limit".into(),
                    ));
                }
                // SECURITY: Use checked_add to prevent integer overflow. A malicious
                // CBOR payload claiming length near usize::MAX could wrap the sum,
                // bypassing the bounds check (e.g., new_pos=10 + length=usize::MAX-5 = 4).
                let end = new_pos
                    .checked_add(length as usize)
                    .ok_or_else(|| Error::Decode("CBOR string length overflow".into()))?;
                if end > payload.len() {
                    return Err(Error::Decode("truncated CBOR string".into()));
                }
                return Ok(end);
            }
            // indefinite string
            loop {
                if pos >= payload.len() {
                    return Err(Error::Decode("unterminated indefinite CBOR string".into()));
                }
                if payload[pos] == 0xFF {
                    return Ok(pos + 1);
                }
                let chunk = payload[pos];
                if chunk >> 5 != major || chunk & 0x1F == 31 {
                    return Err(Error::Decode("invalid indefinite CBOR string chunk".into()));
                }
                pos = scan_cbor_item(payload, pos, depth + 1, budget)?;
            }
        }
        // array
        4 => {
            if indefinite {
                let mut count = 0usize;
                loop {
                    if pos >= payload.len() {
                        return Err(Error::Decode("unterminated indefinite CBOR array".into()));
                    }
                    if payload[pos] == 0xFF {
                        return Ok(pos + 1);
                    }
                    count += 1;
                    if count > MAX_ARRAY_ENTRIES {
                        return Err(Error::Decode("CBOR array exceeds mutation limit".into()));
                    }
                    pos = scan_cbor_item(payload, pos, depth + 1, budget)?;
                }
            }
            let (length, new_pos) = cbor_argument(payload, pos, additional)?;
            // SECURITY: Compare u64 directly to avoid truncation on 32-bit systems
            if length > MAX_ARRAY_ENTRIES as u64 {
                return Err(Error::Decode("CBOR array exceeds mutation limit".into()));
            }
            pos = new_pos;
            for _ in 0..length {
                pos = scan_cbor_item(payload, pos, depth + 1, budget)?;
            }
            Ok(pos)
        }
        // map
        5 => {
            let map_length: Option<u64>;
            if indefinite {
                map_length = None;
            } else {
                let (len, new_pos) = cbor_argument(payload, pos, additional)?;
                // SECURITY: Compare u64 directly to avoid truncation on 32-bit systems
                if len > MAX_MAP_ENTRIES as u64 {
                    return Err(Error::Decode("CBOR map exceeds mutation limit".into()));
                }
                map_length = Some(len);
                pos = new_pos;
            }

            let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
            let mut count = 0usize;

            loop {
                if let Some(len) = map_length {
                    if count >= len as usize {
                        break;
                    }
                }
                if pos >= payload.len() {
                    return Err(Error::Decode("unterminated CBOR map".into()));
                }
                if map_length.is_none() && payload[pos] == 0xFF {
                    return Ok(pos + 1);
                }
                count += 1;
                if count > MAX_MAP_ENTRIES {
                    return Err(Error::Decode("CBOR map exceeds mutation limit".into()));
                }

                let key_start = pos;
                pos = scan_cbor_item(payload, pos, depth + 1, budget)?;
                let key_bytes = payload[key_start..pos].to_vec();

                // SECURITY: Reject duplicate keys. serde last-wins behavior could flip
                // status (e.g., status:available then status:emergency).
                if !keys.insert(key_bytes) {
                    return Err(Error::Decode("duplicate CBOR map key".into()));
                }

                pos = scan_cbor_item(payload, pos, depth + 1, budget)?;
            }
            Ok(pos)
        }
        // tag
        6 => {
            // SECURITY: Tags may trigger semantic type decoding or shared/cyclic
            // objects (RFC 8746 tags 28 and 29). Reject in mutation payloads.
            Err(Error::Decode(
                "CBOR tags are not allowed in mutation payloads".into(),
            ))
        }
        _ => Err(Error::Decode("invalid CBOR major type".into())),
    }
}

/// Validate a CBOR payload before deserializing.
fn validate_cbor_payload(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Decode(
            "CBOR payload exceeds mutation byte limit".into(),
        ));
    }
    let mut budget = ScanBudget::new();
    let end = scan_cbor_item(payload, 0, 0, &mut budget)?;
    if end != payload.len() {
        return Err(Error::Decode("trailing bytes after CBOR item".into()));
    }
    Ok(())
}

/// GPS stationary threshold in seconds (spec 18.5.3).
pub const STATIONARY_AFTER_S: u64 = 5 * 60;
/// Inactivity-away threshold in seconds (spec 18.5.3).
pub const AWAY_AFTER_S: u64 = 30 * 60;
/// Battery percentage below which `low_battery` is set (spec 18.5.3).
pub const LOW_BATTERY_PCT: u32 = 10;

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

impl core::str::FromStr for PresenceStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "available" => Ok(Self::Available),
            "busy" => Ok(Self::Busy),
            "away" => Ok(Self::Away),
            "offline" => Ok(Self::Offline),
            "emergency" => Ok(Self::Emergency),
            _ => Err(Error::Decode(
                "status must be a known presence status".into(),
            )),
        }
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

impl core::str::FromStr for Activity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stationary" => Ok(Self::Stationary),
            "moving" => Ok(Self::Moving),
            "resting" => Ok(Self::Resting),
            "working" => Ok(Self::Working),
            _ => Err(Error::Decode(
                "activity must be a known activity hint".into(),
            )),
        }
    }
}

/// A node's presence state from `GET /presence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    /// Presence status (required).
    pub status: PresenceStatus,
    /// Activity hint (optional refinement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<Activity>,
    /// Custom status message (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// Battery percentage (optional, 0..=100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<u32>,
    /// Set when battery is below [`LOW_BATTERY_PCT`] (spec 18.5.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_battery: Option<bool>,
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
            low_battery: None,
            ts,
        }
    }

    fn check(&self) -> Result<(), &'static str> {
        if self.battery.is_some_and(|battery| battery > 100) {
            return Err("battery must be an integer 0..100");
        }
        Ok(())
    }

    /// Decode a `GET /presence` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        // SECURITY: Validate structure before deserializing to reject tags,
        // duplicate keys, and oversized payloads.
        validate_cbor_payload(bytes)?;
        let presence: Self =
            ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
        presence.check().map_err(|m| Error::Decode(m.into()))?;
        Ok(presence)
    }

    /// Encode to CBOR for `PUT /presence`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.check().map_err(|m| Error::Encode(m.into()))?;
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(buf)
    }
}

/// One entry of the `GET /presence/cache` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceCacheEntry {
    /// Node IPv6 address string.
    pub addr: String,
    /// Presence status.
    pub status: PresenceStatus,
    /// Battery percentage (optional, 0..=100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<u32>,
    /// Seconds since the presence was last updated.
    pub age_s: u64,
}

impl PresenceCacheEntry {
    fn check(&self) -> Result<(), &'static str> {
        if self.addr.is_empty() {
            return Err("addr must be a non-empty string");
        }
        if self.battery.is_some_and(|battery| battery > 100) {
            return Err("battery must be an integer 0..100");
        }
        Ok(())
    }
}

/// The `GET /presence/cache` response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceCache {
    /// Cached presence records for known nodes.
    pub nodes: Vec<PresenceCacheEntry>,
}

impl PresenceCache {
    fn check(&self) -> Result<(), &'static str> {
        for entry in &self.nodes {
            entry.check()?;
        }
        Ok(())
    }

    /// Decode a `GET /presence/cache` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        // SECURITY: Validate structure before deserializing to reject tags,
        // duplicate keys, and oversized payloads.
        validate_cbor_payload(bytes)?;
        let cache: Self = ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
        cache.check().map_err(|m| Error::Decode(m.into()))?;
        Ok(cache)
    }

    /// Encode the cache envelope as CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        self.check().map_err(|m| Error::Encode(m.into()))?;
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
        Ok(buf)
    }
}

fn finite_non_negative(value: f64, name: &'static str) -> Result<f64, Error> {
    if !value.is_finite() || value < 0.0 {
        return Err(Error::Decode(format!(
            "{name} must be a non-negative finite number"
        )));
    }
    Ok(value)
}

/// Seconds since `ts`, clamped to 0 when the clock went backwards.
pub fn age_s_at(now: f64, ts: f64) -> Result<u64, Error> {
    let now_f = finite_non_negative(now, "now")?;
    let ts_f = finite_non_negative(ts, "ts")?;
    Ok((now_f - ts_f).max(0.0) as u64)
}

/// Return presence updated from spec 18.5.3 conditions.
///
/// Priority: SOS, GPS motion, inactivity, GPS stationary. `low_battery` is
/// set when `battery < 10` and omitted otherwise. `ts` is refreshed only
/// when the resulting document differs from `current`.
pub fn apply_automatic_status(
    current: &Presence,
    now: f64,
    moving: Option<bool>,
    last_motion_at: Option<f64>,
    last_interaction_at: Option<f64>,
    sos_active: bool,
) -> Result<Presence, Error> {
    let now_f = finite_non_negative(now, "now")?;
    let last_motion_at = match last_motion_at {
        Some(value) => Some(finite_non_negative(value, "last_motion_at")?),
        None => None,
    };
    let last_interaction_at = match last_interaction_at {
        Some(value) => Some(finite_non_negative(value, "last_interaction_at")?),
        None => None,
    };

    let mut status = current.status;
    let mut activity = current.activity;

    if sos_active {
        status = PresenceStatus::Emergency;
    } else if moving == Some(true) {
        status = PresenceStatus::Available;
        activity = Some(Activity::Moving);
    } else if last_interaction_at.is_some_and(|stamp| (now_f - stamp) > AWAY_AFTER_S as f64) {
        status = PresenceStatus::Away;
    } else if moving == Some(false)
        && last_motion_at.is_some_and(|stamp| (now_f - stamp) > STATIONARY_AFTER_S as f64)
    {
        status = PresenceStatus::Available;
        activity = Some(Activity::Stationary);
    }

    let low_battery = match current.battery {
        Some(battery) if battery < LOW_BATTERY_PCT => Some(true),
        _ => None,
    };

    let candidate = Presence {
        status,
        activity,
        msg: current.msg.clone(),
        battery: current.battery,
        low_battery,
        ts: current.ts,
    };
    if &candidate == current {
        return Ok(current.clone());
    }
    Ok(Presence {
        ts: now_f as u64,
        ..candidate
    })
}

/// Error returned by [`PresenceClient`] operations.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum PresenceClientError {
    /// CBOR encoding failed or the document failed validation.
    Encode(Error),
    /// The response payload was not a valid presence document.
    Decode(Error),
    /// CoAP transport failed.
    Transport(lichen_coap::client::ClientError),
    /// The node returned a non-success CoAP response.
    CoapResponse {
        /// CoAP response code, such as `4.04`.
        code: String,
    },
}

#[cfg(feature = "tokio")]
impl core::fmt::Display for PresenceClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(error) => write!(f, "encode error: {error}"),
            Self::Decode(error) => write!(f, "decode error: {error}"),
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::CoapResponse { code } => write!(f, "presence request failed: CoAP {code}"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for PresenceClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::CoapResponse { .. } => None,
        }
    }
}

#[cfg(feature = "tokio")]
impl From<lichen_coap::client::ClientError> for PresenceClientError {
    fn from(error: lichen_coap::client::ClientError) -> Self {
        Self::Transport(error)
    }
}

/// High-level client for `/presence` and `/presence/cache`.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct PresenceClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl PresenceClient {
    /// Create a client with no active peer backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch and decode `GET /presence`.
    pub async fn get(
        &mut self,
        node: std::net::SocketAddr,
    ) -> Result<Presence, PresenceClientError> {
        let response = self.coap.get(node, crate::paths::PRESENCE).await?;
        if !response.is_success() {
            return Err(PresenceClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Presence::from_cbor(&response.payload).map_err(PresenceClientError::Decode)
    }

    /// Encode and `PUT /presence`. Expects 2.04 Changed.
    pub async fn put(
        &mut self,
        node: std::net::SocketAddr,
        presence: &Presence,
    ) -> Result<(), PresenceClientError> {
        let payload = presence.to_cbor().map_err(PresenceClientError::Encode)?;
        let response = self
            .coap
            .put(node, crate::paths::PRESENCE, &payload)
            .await?;
        if response.code != lichen_coap::MessageCode::CHANGED.0 {
            return Err(PresenceClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(())
    }

    /// Fetch and decode `GET /presence/cache`.
    pub async fn get_cache(
        &mut self,
        node: std::net::SocketAddr,
    ) -> Result<PresenceCache, PresenceClientError> {
        let response = self.coap.get(node, crate::paths::PRESENCE_CACHE).await?;
        if !response.is_success() {
            return Err(PresenceClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        PresenceCache::from_cbor(&response.payload).map_err(PresenceClientError::Decode)
    }

    /// Clear all remembered 5.03 backoff state.
    pub fn clear_all_backoffs(&mut self) {
        self.coap.clear_all_backoffs();
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
        assert_eq!(p.low_battery, None);
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
        assert_eq!(p.low_battery, None);
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
            low_battery: None,
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

        let v: Value = ciborium::from_reader(&cbor[..]).unwrap();
        let map = match v {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };

        assert_eq!(map.len(), 2);
        assert!(map.iter().any(|(k, _)| k == &txt("status")));
        assert!(map.iter().any(|(k, _)| k == &txt("ts")));
    }

    /// Hand-derived CBOR for the spec 18.5.3 low_battery flag.
    #[test]
    fn presence_encodes_low_battery_before_ts() {
        let p = Presence {
            status: PresenceStatus::Available,
            activity: None,
            msg: None,
            battery: None,
            low_battery: Some(true),
            ts: 1_716_742_800,
        };
        let cbor = p.to_cbor().unwrap();
        assert_eq!(
            hex_encode(&cbor),
            "a36673746174757369617661696c61626c656b6c6f775f62617474657279f56274731a66536a90"
        );
        let decoded = Presence::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.low_battery, Some(true));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        assert_eq!(hex_encode(&cache.to_cbor().unwrap()), "a1656e6f64657380");
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

    #[test]
    fn rejects_unknown_status_and_activity() {
        assert!("invisible".parse::<PresenceStatus>().is_err());
        assert!("running".parse::<Activity>().is_err());
        let wire = Value::Map(vec![
            (txt("status"), txt("invisible")),
            (txt("ts"), Value::Integer(0u64.into())),
        ]);
        assert!(Presence::from_cbor(&encode(&wire)).is_err());
    }

    #[test]
    fn rejects_battery_out_of_range() {
        let wire = Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("battery"), Value::Integer(101u64.into())),
            (txt("ts"), Value::Integer(0u64.into())),
        ]);
        assert!(Presence::from_cbor(&encode(&wire)).is_err());
        let mut p = Presence::new(PresenceStatus::Available, 0);
        p.battery = Some(101);
        assert!(p.to_cbor().is_err());
    }

    #[test]
    fn rejects_unknown_presence_field() {
        let wire = Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("ts"), Value::Integer(0u64.into())),
            (txt("rank"), Value::Integer(1u64.into())),
        ]);
        assert!(Presence::from_cbor(&encode(&wire)).is_err());
    }

    #[test]
    fn rejects_truncated_and_trailing_presence_payloads() {
        let valid = encode(&Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("ts"), Value::Integer(0u64.into())),
        ]));
        assert!(Presence::from_cbor(&valid[..valid.len() - 1]).is_err());

        let mut trailing = valid;
        trailing.push(0);
        let error = Presence::from_cbor(&trailing).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn rejects_truncated_and_trailing_presence_cache_payloads() {
        let valid = encode(&Value::Map(vec![(txt("nodes"), Value::Array(vec![]))]));
        assert!(PresenceCache::from_cbor(&valid[..valid.len() - 1]).is_err());

        let mut trailing = valid;
        trailing.push(0);
        let error = PresenceCache::from_cbor(&trailing).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        // CBOR map with duplicate "status" key: first "available", then "emergency"
        // a3 = map(3), 66 "status", 69 "available", 66 "status", 69 "emergency", 62 "ts", 00
        let duplicate = hex::decode(
            "a36673746174757369617661696c61626c656673746174757369656d657267656e637962747300",
        )
        .unwrap();
        let error = Presence::from_cbor(&duplicate).unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_tagged_cbor() {
        // CBOR tag(29) wrapping a valid presence map - tests RFC 8746 shared ref rejection
        // D8 1D = tag(29), followed by valid presence map
        let valid = encode(&Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("ts"), Value::Integer(0u64.into())),
        ]));
        let mut tagged = vec![0xD8, 0x1D]; // tag(29)
        tagged.extend_from_slice(&valid);
        let error = Presence::from_cbor(&tagged).unwrap_err();
        assert!(error.to_string().contains("tag"));
    }

    #[test]
    fn rejects_oversized_payload() {
        // Payload exceeding 4096 bytes
        let large_msg = "x".repeat(5000);
        let wire = Value::Map(vec![
            (txt("status"), txt("available")),
            (txt("msg"), Value::Text(large_msg)),
            (txt("ts"), Value::Integer(0u64.into())),
        ]);
        let error = Presence::from_cbor(&encode(&wire)).unwrap_err();
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn rejects_empty_cache_addr() {
        let mut cache = PresenceCache {
            nodes: vec![PresenceCacheEntry {
                addr: String::new(),
                status: PresenceStatus::Available,
                battery: None,
                age_s: 1,
            }],
        };
        assert!(cache.to_cbor().is_err());
        cache.nodes[0].addr = "0200::1".into();
        cache.to_cbor().unwrap();
    }

    #[test]
    fn age_s_clamps_backwards_clock() {
        assert_eq!(age_s_at(1_716_742_845.0, 1_716_742_800.0).unwrap(), 45);
        assert_eq!(age_s_at(1_716_742_750.0, 1_716_742_800.0).unwrap(), 0);
        assert!(age_s_at(f64::NAN, 1.0).is_err());
    }

    fn auto_base() -> Presence {
        Presence {
            status: PresenceStatus::Busy,
            activity: Some(Activity::Working),
            msg: Some("In meeting".into()),
            battery: Some(50),
            low_battery: None,
            ts: 1_716_742_800,
        }
    }

    #[test]
    fn automatic_gps_motion_sets_available_moving() {
        let updated =
            apply_automatic_status(&auto_base(), 1_716_742_801.0, Some(true), None, None, false)
                .unwrap();
        assert_eq!(updated.status, PresenceStatus::Available);
        assert_eq!(updated.activity, Some(Activity::Moving));
        assert_eq!(updated.ts, 1_716_742_801);
    }

    #[test]
    fn automatic_stationary_after_five_minutes() {
        let t0 = 1_716_742_800.0;
        let updated = apply_automatic_status(
            &auto_base(),
            t0 + STATIONARY_AFTER_S as f64 + 1.0,
            Some(false),
            Some(t0),
            None,
            false,
        )
        .unwrap();
        assert_eq!(updated.status, PresenceStatus::Available);
        assert_eq!(updated.activity, Some(Activity::Stationary));
    }

    #[test]
    fn automatic_stationary_at_exactly_five_minutes_does_not_fire() {
        let t0 = 1_716_742_800.0;
        let updated = apply_automatic_status(
            &auto_base(),
            t0 + STATIONARY_AFTER_S as f64,
            Some(false),
            Some(t0),
            None,
            false,
        )
        .unwrap();
        assert_eq!(updated.status, PresenceStatus::Busy);
        assert_eq!(updated.activity, Some(Activity::Working));
    }

    #[test]
    fn automatic_inactivity_sets_away() {
        let t0 = 1_716_742_800.0;
        let updated = apply_automatic_status(
            &auto_base(),
            t0 + AWAY_AFTER_S as f64 + 1.0,
            None,
            None,
            Some(t0),
            false,
        )
        .unwrap();
        assert_eq!(updated.status, PresenceStatus::Away);
        assert_eq!(updated.activity, Some(Activity::Working));
    }

    #[test]
    fn automatic_motion_overrides_inactivity() {
        let t0 = 1_716_742_800.0;
        let updated = apply_automatic_status(
            &auto_base(),
            t0 + AWAY_AFTER_S as f64 + 1.0,
            Some(true),
            None,
            Some(t0),
            false,
        )
        .unwrap();
        assert_eq!(updated.status, PresenceStatus::Available);
        assert_eq!(updated.activity, Some(Activity::Moving));
    }

    #[test]
    fn automatic_sos_wins_over_gps() {
        let updated =
            apply_automatic_status(&auto_base(), 1_716_742_801.0, Some(true), None, None, true)
                .unwrap();
        assert_eq!(updated.status, PresenceStatus::Emergency);
        assert_eq!(updated.activity, Some(Activity::Working));
    }

    #[test]
    fn automatic_low_battery_flag_below_ten() {
        let current = Presence {
            battery: Some(LOW_BATTERY_PCT - 1),
            ..Presence::new(PresenceStatus::Available, 1_716_742_800)
        };
        let updated =
            apply_automatic_status(&current, 1_716_742_800.0, None, None, None, false).unwrap();
        assert_eq!(updated.battery, Some(9));
        assert_eq!(updated.low_battery, Some(true));
    }

    #[test]
    fn automatic_no_low_battery_at_ten_percent() {
        let current = Presence {
            battery: Some(LOW_BATTERY_PCT),
            ..Presence::new(PresenceStatus::Available, 1_716_742_800)
        };
        let updated =
            apply_automatic_status(&current, 1_716_742_800.0, None, None, None, false).unwrap();
        assert_eq!(updated.low_battery, None);
        assert_eq!(updated, current);
    }

    #[test]
    fn automatic_unchanged_keeps_ts() {
        let current = Presence {
            battery: Some(50),
            ..Presence::new(PresenceStatus::Available, 1_716_742_800)
        };
        let updated =
            apply_automatic_status(&current, 1_716_742_810.0, None, None, None, false).unwrap();
        assert_eq!(updated.ts, 1_716_742_800);
        assert_eq!(updated, current);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_gets_presence_from_presence_path() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let payload = hex_decode("a26673746174757369617661696c61626c656274731a66536a90");
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::GET);
            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["presence"]);

            let mut response_bytes = [0u8; 256];
            let mut response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CONTENT,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            response.payload(&payload).unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        let presence = PresenceClient::new().get(address).await.unwrap();
        assert_eq!(presence.status, PresenceStatus::Available);
        assert_eq!(presence.ts, 1_716_742_800);
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_puts_presence_and_requires_changed() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let presence = Presence {
            status: PresenceStatus::Busy,
            activity: None,
            msg: Some("In meeting".into()),
            battery: None,
            low_battery: None,
            ts: 1_716_742_800,
        };
        let expected = presence.to_cbor().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::PUT);
            assert_eq!(request.payload(), expected);
            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["presence"]);

            let mut response_bytes = [0u8; 64];
            let response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CHANGED,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        PresenceClient::new().put(address, &presence).await.unwrap();
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_gets_presence_cache() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let payload = hex_decode("a1656e6f64657380");
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::GET);
            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["presence", "cache"]);

            let mut response_bytes = [0u8; 256];
            let mut response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CONTENT,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            response.payload(&payload).unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        let cache = PresenceClient::new().get_cache(address).await.unwrap();
        assert!(cache.nodes.is_empty());
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_put_rejects_content_instead_of_changed() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let presence = Presence::new(PresenceStatus::Available, 1);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            let mut response_bytes = [0u8; 64];
            let response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CONTENT,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        let error = PresenceClient::new()
            .put(address, &presence)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PresenceClientError::CoapResponse { ref code } if code == "2.05"
        ));
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    fn hex_decode(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("valid hex")
    }
}
