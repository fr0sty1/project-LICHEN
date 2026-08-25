//! SOS signature domain types (spec 18.4).
//!
//! Domain types for SOS authentication per spec section 18.4.1:
//! - [`SosAlertType`]: Alert category (sos, medical, security, fire, cancel).
//! - [`SosAlert`]: Signed SOS payload structure.
//! - [`SosRateLimitState`]: Per-source rate limit tracking.
//! - [`SosRateLimitConfig`]: Rate limit parameters.
//!
//! SOS frames use Schnorr48 signatures (see [`crate::schnorr`]) for
//! authentication. This module provides the typed payload that gets signed.
//!
//! Wire format (spec 18.4.1):
//! ```text
//! SOS frame = [LLSec header] [SOS payload] [Schnorr signature (48B)]
//! ```
//!
//! Rate limiting (spec 18.4.3):
//! - 10-minute cooldown between alerts from the same source
//! - Maximum 3 alerts per hour per source
//! - Burst allowance of 2 for rapid successive alerts
//! - Cancel messages bypass rate limits

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// SOS alert type per spec 18.4.2.
///
/// Alert categories for emergency messages. The `Cancel` type terminates
/// a previously-active SOS from the same node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SosAlertType {
    /// General emergency (default).
    Sos = 0,
    /// Medical emergency.
    Medical = 1,
    /// Security threat.
    Security = 2,
    /// Fire emergency.
    Fire = 3,
    /// Cancel previous alert from this node.
    Cancel = 4,
}

impl SosAlertType {
    /// Wire representation for CBOR encoding.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sos => "sos",
            Self::Medical => "medical",
            Self::Security => "security",
            Self::Fire => "fire",
            Self::Cancel => "cancel",
        }
    }

    /// Parse from wire string.
    ///
    /// This intentionally returns `Option` for the existing no-allocation wire
    /// API rather than the `Result` required by `core::str::FromStr`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sos" => Some(Self::Sos),
            "medical" => Some(Self::Medical),
            "security" => Some(Self::Security),
            "fire" => Some(Self::Fire),
            "cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

impl fmt::Display for SosAlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SOS alert payload per spec 18.4.2.
///
/// CBOR structure:
/// ```text
/// {
///   "type": "sos",               ; alert type (tstr)
///   "node": "0200:...:1111",     ; originating node IID (tstr)
///   "ts": 1716742800,            ; timestamp (uint)
///   "lat": 37.774929,            ; latitude (float, optional)
///   "lon": -122.419416,          ; longitude (float, optional)
///   "msg": "Injured, need evac", ; details (tstr, optional)
///   "seq": 1                     ; sequence for updates (uint)
/// }
/// ```
///
/// The payload is signed with Schnorr48 for authentication. Unsigned or
/// invalid SOS messages are silently dropped (spec 18.4.1).
#[derive(Debug, Clone, PartialEq)]
pub struct SosAlert {
    /// Alert type.
    pub alert_type: SosAlertType,
    /// Originating node IID (hex string, e.g., "0200:...:1111").
    pub node: String,
    /// Timestamp (Unix epoch seconds).
    pub ts: u64,
    /// Latitude (optional).
    pub lat: Option<f64>,
    /// Longitude (optional).
    pub lon: Option<f64>,
    /// Message details (optional).
    pub msg: Option<String>,
    /// Sequence number for updates to the same alert.
    pub seq: u32,
}

impl SosAlert {
    /// Create a new SOS alert.
    pub fn new(alert_type: SosAlertType, node: String, ts: u64, seq: u32) -> Self {
        Self {
            alert_type,
            node,
            ts,
            lat: None,
            lon: None,
            msg: None,
            seq,
        }
    }

    /// Add location to the alert.
    pub fn with_location(mut self, lat: f64, lon: f64) -> Self {
        self.lat = Some(lat);
        self.lon = Some(lon);
        self
    }

    /// Add message to the alert.
    pub fn with_message(mut self, msg: String) -> Self {
        self.msg = Some(msg);
        self
    }

    /// Decode a spec 18.4.2 SOS payload map from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SosCborError> {
        decode_alert(bytes)
    }

    /// Encode as CoAP-wire CBOR matching `test/vectors/sos_cbor.json`.
    ///
    /// Key order is the spec example order (`type`, `node`, `ts`, `lat`,
    /// `lon`, `msg`, `seq`) with absent optionals omitted. Lat/lon use
    /// IEEE-754 binary64. This matches `cbor2.dumps(payload)` without
    /// `canonical=True`.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_alert(self, CborKeyOrder::Wire)
    }

    /// RFC 8949 deterministic CBOR for origin signatures.
    ///
    /// Keys are sorted by encoded form (length-first). Integers use shortest
    /// form. Floats use the shortest encoding that round-trips (Python
    /// `cbor2.dumps(..., canonical=True)`).
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        encode_alert(self, CborKeyOrder::Canonical)
    }
}

/// SOS CBOR decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosCborError {
    /// Input ended before a complete map.
    Truncated,
    /// Top-level item is not a definite CBOR map.
    NotAMap,
    /// Extra bytes after the map.
    TrailingData,
    /// Duplicate map key.
    DuplicateKey,
    /// Unknown map key.
    UnknownKey,
    /// Required field `type`, `node`, `ts`, or `seq` missing.
    MissingField,
    /// Field had the wrong CBOR type.
    UnexpectedType,
    /// Text was not UTF-8, or `type` was not a spec 18.4.2 token.
    InvalidValue,
    /// Integer did not fit the field width.
    OutOfRange,
}

#[derive(Clone, Copy)]
enum CborKeyOrder {
    Wire,
    Canonical,
}

const KEY_TYPE: &str = "type";
const KEY_NODE: &str = "node";
const KEY_TS: &str = "ts";
const KEY_LAT: &str = "lat";
const KEY_LON: &str = "lon";
const KEY_MSG: &str = "msg";
const KEY_SEQ: &str = "seq";

fn encode_alert(alert: &SosAlert, order: CborKeyOrder) -> Vec<u8> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    push_text_pair(&mut pairs, KEY_TYPE, alert.alert_type.as_str());
    push_text_pair(&mut pairs, KEY_NODE, &alert.node);
    push_uint_pair(&mut pairs, KEY_TS, alert.ts);
    if let Some(lat) = alert.lat {
        push_float_pair(&mut pairs, KEY_LAT, lat, order);
    }
    if let Some(lon) = alert.lon {
        push_float_pair(&mut pairs, KEY_LON, lon, order);
    }
    if let Some(ref msg) = alert.msg {
        push_text_pair(&mut pairs, KEY_MSG, msg);
    }
    push_uint_pair(&mut pairs, KEY_SEQ, u64::from(alert.seq));

    if matches!(order, CborKeyOrder::Canonical) {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
    }

    let mut out = Vec::new();
    push_type_len(&mut out, 5, pairs.len() as u64);
    for (key, value) in pairs {
        out.extend_from_slice(&key);
        out.extend_from_slice(&value);
    }
    out
}

fn push_text_pair(pairs: &mut Vec<(Vec<u8>, Vec<u8>)>, key: &str, value: &str) {
    let mut k = Vec::new();
    push_text(&mut k, key);
    let mut v = Vec::new();
    push_text(&mut v, value);
    pairs.push((k, v));
}

fn push_uint_pair(pairs: &mut Vec<(Vec<u8>, Vec<u8>)>, key: &str, value: u64) {
    let mut k = Vec::new();
    push_text(&mut k, key);
    let mut v = Vec::new();
    push_type_len(&mut v, 0, value);
    pairs.push((k, v));
}

fn push_float_pair(
    pairs: &mut Vec<(Vec<u8>, Vec<u8>)>,
    key: &str,
    value: f64,
    order: CborKeyOrder,
) {
    let mut k = Vec::new();
    push_text(&mut k, key);
    let mut v = Vec::new();
    push_float(&mut v, value, matches!(order, CborKeyOrder::Canonical));
    pairs.push((k, v));
}

fn push_text(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    push_type_len(buf, 3, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn push_type_len(buf: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        buf.push(mt | (n as u8));
    } else if n <= 0xff {
        buf.push(mt | 24);
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(mt | 25);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(mt | 26);
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        buf.push(mt | 27);
        buf.extend_from_slice(&n.to_be_bytes());
    }
}

fn push_float(buf: &mut Vec<u8>, value: f64, preferred: bool) {
    if preferred {
        if let Some(half) = f64_to_f16_exact(value) {
            buf.push(0xf9);
            buf.extend_from_slice(&half.to_be_bytes());
            return;
        }
        let single = value as f32;
        if (single as f64).to_bits() == value.to_bits() {
            buf.push(0xfa);
            buf.extend_from_slice(&single.to_bits().to_be_bytes());
            return;
        }
    }
    buf.push(0xfb);
    buf.extend_from_slice(&value.to_bits().to_be_bytes());
}

fn f64_to_f16_exact(value: f64) -> Option<u16> {
    let bits = value.to_bits();
    let sign = ((bits >> 63) as u16) & 1;
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if exp == 0 && frac == 0 {
        return Some(sign << 15);
    }
    if exp == 0x7ff {
        return None;
    }
    let unbiased = exp - 1023;
    if !(-14..=15).contains(&unbiased) {
        return None;
    }
    if frac & ((1u64 << 42) - 1) != 0 {
        return None;
    }
    let half_exp = (unbiased + 15) as u16;
    let half_frac = (frac >> 42) as u16;
    let half = (sign << 15) | (half_exp << 10) | half_frac;
    if f16_to_f64(half).to_bits() == bits {
        Some(half)
    } else {
        None
    }
}

fn f16_to_f64(bits: u16) -> f64 {
    let sign = u64::from((bits >> 15) & 1);
    let exp = (bits >> 10) & 0x1f;
    let frac = u64::from(bits & 0x3ff);
    let out = if exp == 0 {
        if frac == 0 {
            sign << 63
        } else {
            let mut m = frac;
            let mut e: i32 = -14;
            while m & 0x400 == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x3ff;
            let exp_bits = (e + 1023) as u64;
            (sign << 63) | (exp_bits << 52) | (m << 42)
        }
    } else if exp == 31 {
        (sign << 63) | (0x7ffu64 << 52) | (frac << 42)
    } else {
        let exp_bits = u64::from(exp) - 15 + 1023;
        (sign << 63) | (exp_bits << 52) | (frac << 42)
    };
    f64::from_bits(out)
}

struct CborReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn rest(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SosCborError> {
        if self.rest() < n {
            return Err(SosCborError::Truncated);
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..self.pos])
    }

    fn take_u8(&mut self) -> Result<u8, SosCborError> {
        Ok(self.take(1)?[0])
    }

    fn header(&mut self) -> Result<(u8, u64), SosCborError> {
        let first = self.take_u8()?;
        let major = first >> 5;
        let ai = first & 0x1f;
        let n = match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.take_u8()?),
            25 => {
                let b = self.take(2)?;
                u64::from(u16::from_be_bytes([b[0], b[1]]))
            }
            26 => {
                let b = self.take(4)?;
                u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            }
            27 => {
                let b = self.take(8)?;
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
            _ => return Err(SosCborError::UnexpectedType),
        };
        Ok((major, n))
    }

    fn text(&mut self) -> Result<&'a str, SosCborError> {
        let (major, n) = self.header()?;
        if major != 3 {
            return Err(SosCborError::UnexpectedType);
        }
        let n = usize::try_from(n).map_err(|_| SosCborError::OutOfRange)?;
        let bytes = self.take(n)?;
        core::str::from_utf8(bytes).map_err(|_| SosCborError::InvalidValue)
    }

    fn uint(&mut self) -> Result<u64, SosCborError> {
        let (major, n) = self.header()?;
        if major != 0 {
            return Err(SosCborError::UnexpectedType);
        }
        Ok(n)
    }

    fn float(&mut self) -> Result<f64, SosCborError> {
        let first = self.take_u8()?;
        match first {
            0xf9 => {
                let b = self.take(2)?;
                Ok(f16_to_f64(u16::from_be_bytes([b[0], b[1]])))
            }
            0xfa => {
                let b = self.take(4)?;
                Ok(f32::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) as f64)
            }
            0xfb => {
                let b = self.take(8)?;
                Ok(f64::from_bits(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ])))
            }
            _ => Err(SosCborError::UnexpectedType),
        }
    }
}

fn valid_node_id(node: &str) -> bool {
    // Vector sos_node_format: IPv6 full notation, 8 colon-separated groups.
    let mut groups = 0usize;
    for group in node.split(':') {
        groups += 1;
        if group.is_empty() || group.len() > 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    groups == 8
}

fn decode_alert(bytes: &[u8]) -> Result<SosAlert, SosCborError> {
    let mut r = CborReader::new(bytes);
    let (major, count) = r.header()?;
    if major != 5 {
        return Err(SosCborError::NotAMap);
    }
    // Spec 18.4.2 has at most 7 keys. Reject huge declared counts before looping.
    if count > 16 {
        return Err(SosCborError::OutOfRange);
    }
    let mut alert_type = None;
    let mut node = None;
    let mut ts = None;
    let mut lat = None;
    let mut lon = None;
    let mut msg = None;
    let mut seq = None;
    for _ in 0..count {
        let key = r.text()?;
        match key {
            KEY_TYPE => {
                if alert_type.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                let raw = r.text()?;
                alert_type = Some(SosAlertType::from_str(raw).ok_or(SosCborError::InvalidValue)?);
            }
            KEY_NODE => {
                if node.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                let value = r.text()?;
                if !valid_node_id(value) {
                    return Err(SosCborError::InvalidValue);
                }
                node = Some(String::from(value));
            }
            KEY_TS => {
                if ts.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                ts = Some(r.uint()?);
            }
            KEY_LAT => {
                if lat.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                let value = r.float()?;
                if !value.is_finite() {
                    return Err(SosCborError::InvalidValue);
                }
                lat = Some(value);
            }
            KEY_LON => {
                if lon.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                let value = r.float()?;
                if !value.is_finite() {
                    return Err(SosCborError::InvalidValue);
                }
                lon = Some(value);
            }
            KEY_MSG => {
                if msg.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                msg = Some(String::from(r.text()?));
            }
            KEY_SEQ => {
                if seq.is_some() {
                    return Err(SosCborError::DuplicateKey);
                }
                let n = r.uint()?;
                seq = Some(u32::try_from(n).map_err(|_| SosCborError::OutOfRange)?);
            }
            _ => return Err(SosCborError::UnknownKey),
        }
    }
    if r.pos != r.buf.len() {
        return Err(SosCborError::TrailingData);
    }
    Ok(SosAlert {
        alert_type: alert_type.ok_or(SosCborError::MissingField)?,
        node: node.ok_or(SosCborError::MissingField)?,
        ts: ts.ok_or(SosCborError::MissingField)?,
        lat,
        lon,
        msg,
        seq: seq.ok_or(SosCborError::MissingField)?,
    })
}

/// Rate limit configuration for SOS alerts (spec 18.4.3).
///
/// Default values per spec:
/// - `cooldown_secs`: 600 (10 minutes)
/// - `max_per_hour`: 3
/// - `burst_allowance`: 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SosRateLimitConfig {
    /// Minimum seconds between alerts from the same source.
    cooldown_secs: u32,
    /// Maximum alerts per hour per source.
    max_per_hour: u8,
    /// Initial burst allowance before cooldown applies.
    burst_allowance: u8,
}

/// Invalid SOS rate-limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosRateLimitConfigError {
    /// Cooldown must advance time.
    ZeroCooldown,
    /// The bounded state stores exactly the normative maximum of three alerts.
    InvalidHourlyLimit,
    /// The protocol permits at most two immediate alerts.
    InvalidBurstAllowance,
}

impl Default for SosRateLimitConfig {
    fn default() -> Self {
        Self {
            cooldown_secs: 600, // 10 minutes
            max_per_hour: 3,
            burst_allowance: 2,
        }
    }
}

impl SosRateLimitConfig {
    /// Create a validated rate limit configuration.
    pub const fn new(
        cooldown_secs: u32,
        max_per_hour: u8,
        burst_allowance: u8,
    ) -> Result<Self, SosRateLimitConfigError> {
        if cooldown_secs == 0 {
            return Err(SosRateLimitConfigError::ZeroCooldown);
        }
        if max_per_hour == 0 || max_per_hour > 3 {
            return Err(SosRateLimitConfigError::InvalidHourlyLimit);
        }
        if burst_allowance == 0 || burst_allowance > 2 || burst_allowance > max_per_hour {
            return Err(SosRateLimitConfigError::InvalidBurstAllowance);
        }
        Ok(Self {
            cooldown_secs,
            max_per_hour,
            burst_allowance,
        })
    }

    pub const fn cooldown_secs(&self) -> u32 {
        self.cooldown_secs
    }

    pub const fn max_per_hour(&self) -> u8 {
        self.max_per_hour
    }

    pub const fn burst_allowance(&self) -> u8 {
        self.burst_allowance
    }
}

/// Per-source rate limit state for SOS alerts.
///
/// Tracks the rate limit state for a single source node. The state includes:
/// - Timestamps of recent alerts within the hour window
/// - Remaining burst allowance
///
/// Use [`SosRateLimitState::check`] to determine if an alert should be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SosRateLimitState {
    /// Timestamps of alerts within the current hour window (Unix epoch secs).
    /// Ordered oldest to newest, pruned on check.
    alert_times: [u64; 3],
    /// Number of valid entries in `alert_times`.
    alert_count: u8,
    /// Remaining burst allowance.
    burst_remaining: u8,
}

/// Result of rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosRateLimitResult {
    /// Alert is allowed.
    Allowed,
    /// Alert is denied due to cooldown period.
    CooldownActive {
        /// Seconds until cooldown expires.
        remaining_secs: u32,
    },
    /// Alert is denied due to hourly limit.
    HourlyLimitExceeded {
        /// Seconds until oldest alert expires from window.
        window_reset_secs: u32,
    },
}

impl SosRateLimitState {
    /// Create a new rate limit state for a source.
    pub fn new(config: &SosRateLimitConfig) -> Self {
        Self {
            alert_times: [0; 3],
            alert_count: 0,
            burst_remaining: config.burst_allowance,
        }
    }

    /// Check if an alert should be allowed at the given timestamp.
    ///
    /// Returns [`SosRateLimitResult::Allowed`] if the alert passes rate limits.
    /// Does not modify state; call [`record`](Self::record) after accepting.
    pub fn check(&self, now: u64, config: &SosRateLimitConfig) -> SosRateLimitResult {
        // Prune alerts older than 1 hour for counting
        let hour_ago = now.saturating_sub(3600);
        let valid_count = self.count_in_window(hour_ago);

        // Check hourly limit
        if valid_count >= config.max_per_hour as usize {
            let oldest_in_window = self.oldest_in_window(hour_ago);
            if let Some(oldest) = oldest_in_window {
                let window_reset = (oldest + 3600).saturating_sub(now) as u32;
                return SosRateLimitResult::HourlyLimitExceeded {
                    window_reset_secs: window_reset,
                };
            }
        }

        // Burst allowance bypasses cooldown
        if self.burst_remaining > 0 {
            return SosRateLimitResult::Allowed;
        }

        // Check cooldown from most recent alert
        if let Some(last) = self.most_recent() {
            let elapsed = now.saturating_sub(last);
            if elapsed < config.cooldown_secs as u64 {
                return SosRateLimitResult::CooldownActive {
                    remaining_secs: (config.cooldown_secs as u64 - elapsed) as u32,
                };
            }
        }

        SosRateLimitResult::Allowed
    }

    /// Record an accepted alert at the given timestamp.
    ///
    /// Call this after accepting an alert to update rate limit state.
    pub fn record(&mut self, now: u64, config: &SosRateLimitConfig) {
        // Consume burst if available
        if self.burst_remaining > 0 {
            self.burst_remaining -= 1;
        }

        // Prune old entries and add new one
        let hour_ago = now.saturating_sub(3600);
        self.prune_old(hour_ago);

        if (self.alert_count as usize) < self.alert_times.len() {
            self.alert_times[self.alert_count as usize] = now;
            self.alert_count += 1;
        } else {
            // Shift out oldest, add new
            for i in 0..self.alert_times.len() - 1 {
                self.alert_times[i] = self.alert_times[i + 1];
            }
            self.alert_times[self.alert_times.len() - 1] = now;
        }

        // Reset burst if enough time has passed (full cooldown cycle)
        let _ = config; // Future: could use config for burst reset logic
    }

    /// Reset burst allowance (e.g., after extended quiet period).
    pub fn reset_burst(&mut self, config: &SosRateLimitConfig) {
        self.burst_remaining = config.burst_allowance;
    }

    fn count_in_window(&self, cutoff: u64) -> usize {
        self.alert_times[..self.alert_count as usize]
            .iter()
            .filter(|&&t| t >= cutoff)
            .count()
    }

    fn oldest_in_window(&self, cutoff: u64) -> Option<u64> {
        self.alert_times[..self.alert_count as usize]
            .iter()
            .copied()
            .filter(|&t| t >= cutoff)
            .min()
    }

    fn most_recent(&self) -> Option<u64> {
        if self.alert_count == 0 {
            None
        } else {
            Some(self.alert_times[self.alert_count as usize - 1])
        }
    }

    fn prune_old(&mut self, cutoff: u64) {
        let mut write_idx = 0;
        for read_idx in 0..self.alert_count as usize {
            if self.alert_times[read_idx] >= cutoff {
                self.alert_times[write_idx] = self.alert_times[read_idx];
                write_idx += 1;
            }
        }
        self.alert_count = write_idx as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_type_roundtrip() {
        for t in [
            SosAlertType::Sos,
            SosAlertType::Medical,
            SosAlertType::Security,
            SosAlertType::Fire,
            SosAlertType::Cancel,
        ] {
            let s = t.as_str();
            let parsed = SosAlertType::from_str(s).expect("parse failed");
            assert_eq!(t, parsed);
        }
    }

    #[test]
    fn alert_type_unknown() {
        assert_eq!(SosAlertType::from_str("unknown"), None);
        assert_eq!(SosAlertType::from_str(""), None);
    }

    #[test]
    fn alert_builder() {
        let alert = SosAlert::new(
            SosAlertType::Medical,
            "0200:1234:5678:9abc".into(),
            1716742800,
            1,
        )
        .with_location(37.774929, -122.419416)
        .with_message("Injured, need evac".into());

        assert_eq!(alert.alert_type, SosAlertType::Medical);
        assert_eq!(alert.node, "0200:1234:5678:9abc");
        assert_eq!(alert.ts, 1716742800);
        assert_eq!(alert.lat, Some(37.774929));
        assert_eq!(alert.lon, Some(-122.419416));
        assert_eq!(alert.msg, Some("Injured, need evac".into()));
        assert_eq!(alert.seq, 1);
    }

    #[test]
    fn alert_minimal() {
        let alert = SosAlert::new(
            SosAlertType::Sos,
            "0200:dead:beef:cafe".into(),
            1700000000,
            0,
        );

        assert_eq!(alert.alert_type, SosAlertType::Sos);
        assert_eq!(alert.lat, None);
        assert_eq!(alert.lon, None);
        assert_eq!(alert.msg, None);
    }

    #[test]
    fn cbor_roundtrip_minimal() {
        let alert = SosAlert::new(
            SosAlertType::Medical,
            "0200:0000:0000:0000:aabb:ccdd:eeff:0011".into(),
            1716742900,
            2,
        );
        let wire = alert.to_cbor();
        let decoded = SosAlert::from_cbor(&wire).expect("decode");
        assert_eq!(decoded, alert);
    }

    #[test]
    fn cbor_rejects_invalid_node_ids() {
        for node in ["", "192.168.1.1", "0011:2233:4455:6677"] {
            let mut payload = Vec::new();
            push_type_len(&mut payload, 5, 4);
            push_text(&mut payload, "type");
            push_text(&mut payload, "sos");
            push_text(&mut payload, "node");
            push_text(&mut payload, node);
            push_text(&mut payload, "ts");
            push_type_len(&mut payload, 0, 0);
            push_text(&mut payload, "seq");
            push_type_len(&mut payload, 0, 1);
            assert_eq!(
                SosAlert::from_cbor(&payload),
                Err(SosCborError::InvalidValue),
                "{node:?}"
            );
        }
        let ok = SosAlert::from_cbor(
            &SosAlert::new(
                SosAlertType::Sos,
                "0200:0000:0000:0000:0011:2233:4455:6677".into(),
                0,
                1,
            )
            .to_cbor(),
        )
        .expect("full notation");
        assert_eq!(ok.node, "0200:0000:0000:0000:0011:2233:4455:6677");
    }

    #[test]
    fn cbor_rejects_unknown_type() {
        // {"type":"nope","node":"n","ts":0,"seq":1}
        let wire = [
            0xa4, 0x64, b't', b'y', b'p', b'e', 0x64, b'n', b'o', b'p', b'e', 0x64, b'n', b'o',
            b'd', b'e', 0x61, b'n', 0x62, b't', b's', 0x00, 0x63, b's', b'e', b'q', 0x01,
        ];
        assert_eq!(SosAlert::from_cbor(&wire), Err(SosCborError::InvalidValue));
    }

    #[test]
    fn cbor_rejects_trailing_bytes() {
        let alert = SosAlert::new(
            SosAlertType::Sos,
            "0200:0000:0000:0000:0000:0000:0000:0001".into(),
            0,
            1,
        );
        let mut wire = alert.to_cbor();
        wire.push(0x00);
        assert_eq!(SosAlert::from_cbor(&wire), Err(SosCborError::TrailingData));
    }

    #[test]
    fn cbor_rejects_non_finite_lat() {
        let mut wire = SosAlert::new(
            SosAlertType::Sos,
            "0200:0000:0000:0000:0000:0000:0000:0001".into(),
            0,
            1,
        )
        .to_cbor();
        wire[0] = 0xa5;
        wire.extend_from_slice(&[
            0x63, b'l', b'a', b't', 0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(SosAlert::from_cbor(&wire), Err(SosCborError::InvalidValue));
    }

    #[test]
    fn cbor_decodes_f16_zero_lat() {
        let alert = SosAlert::new(
            SosAlertType::Sos,
            "0200:0000:0000:0000:0000:0000:0000:0001".into(),
            0,
            1,
        )
        .with_location(0.0, 0.0);
        let canonical = alert.to_canonical_cbor();
        let decoded = SosAlert::from_cbor(&canonical).expect("canonical decode");
        assert_eq!(decoded.lat, Some(0.0));
        assert_eq!(decoded.lon, Some(0.0));
        assert_eq!(decoded.to_canonical_cbor(), canonical);
    }

    #[test]
    fn rate_limit_config_default() {
        let config = SosRateLimitConfig::default();
        assert_eq!(config.cooldown_secs(), 600);
        assert_eq!(config.max_per_hour(), 3);
        assert_eq!(config.burst_allowance(), 2);
    }

    #[test]
    fn rate_limit_config_rejects_fail_open_values() {
        assert_eq!(
            SosRateLimitConfig::new(0, 3, 2),
            Err(SosRateLimitConfigError::ZeroCooldown)
        );
        assert_eq!(
            SosRateLimitConfig::new(600, 0, 0),
            Err(SosRateLimitConfigError::InvalidHourlyLimit)
        );
        assert_eq!(
            SosRateLimitConfig::new(600, 4, 2),
            Err(SosRateLimitConfigError::InvalidHourlyLimit)
        );
        assert_eq!(
            SosRateLimitConfig::new(600, 3, 3),
            Err(SosRateLimitConfigError::InvalidBurstAllowance)
        );
        assert!(SosRateLimitConfig::new(600, 3, 2).is_ok());
    }

    #[test]
    fn rate_limit_burst_allows_rapid_alerts() {
        let config = SosRateLimitConfig::default();
        let mut state = SosRateLimitState::new(&config);
        let now = 1700000000u64;

        // First two alerts should use burst allowance
        assert_eq!(state.check(now, &config), SosRateLimitResult::Allowed);
        state.record(now, &config);

        assert_eq!(state.check(now + 1, &config), SosRateLimitResult::Allowed);
        state.record(now + 1, &config);

        // Third alert should be blocked by cooldown (burst exhausted)
        match state.check(now + 2, &config) {
            SosRateLimitResult::CooldownActive { remaining_secs } => {
                assert!(remaining_secs > 500); // ~10 min remaining
            }
            other => panic!("expected CooldownActive, got {:?}", other),
        }
    }

    #[test]
    fn rate_limit_cooldown_expires() {
        let config = SosRateLimitConfig::default();
        let mut state = SosRateLimitState::new(&config);
        let now = 1700000000u64;

        // Exhaust burst
        state.record(now, &config);
        state.record(now + 1, &config);

        // After cooldown (10 min), should be allowed again
        let after_cooldown = now + 601;
        assert_eq!(
            state.check(after_cooldown, &config),
            SosRateLimitResult::Allowed
        );
    }

    #[test]
    fn rate_limit_hourly_max() {
        let config = SosRateLimitConfig::default();
        let mut state = SosRateLimitState::new(&config);
        let now = 1700000000u64;

        // Send 3 alerts spaced by cooldown (allowed)
        state.record(now, &config);
        state.record(now + 700, &config);
        state.record(now + 1400, &config);

        // 4th alert after cooldown should hit hourly limit
        let after_cooldown = now + 2100;
        match state.check(after_cooldown, &config) {
            SosRateLimitResult::HourlyLimitExceeded { window_reset_secs } => {
                // Should reset when first alert exits window
                assert!(window_reset_secs > 0);
                assert!(window_reset_secs < 3600);
            }
            other => panic!("expected HourlyLimitExceeded, got {:?}", other),
        }
    }

    #[test]
    fn rate_limit_window_expires() {
        let config = SosRateLimitConfig::default();
        let mut state = SosRateLimitState::new(&config);
        let now = 1700000000u64;

        // Send 3 alerts
        state.record(now, &config);
        state.record(now + 700, &config);
        state.record(now + 1400, &config);

        // After 1 hour from first alert, window resets
        let after_window = now + 3601;
        assert_eq!(
            state.check(after_window, &config),
            SosRateLimitResult::Allowed
        );
    }

    #[test]
    fn rate_limit_reset_burst() {
        let config = SosRateLimitConfig::default();
        let mut state = SosRateLimitState::new(&config);
        let now = 1700000000u64;

        // Exhaust burst
        state.record(now, &config);
        state.record(now + 1, &config);

        // Reset burst
        state.reset_burst(&config);

        // Should be allowed again with burst
        assert_eq!(state.check(now + 2, &config), SosRateLimitResult::Allowed);
    }
}
