// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Confessions domain model and SenML wire codecs (spec 18.10, LCI 17.5.9).
//!
//! `/confessions` is an anonymous, ephemeral messaging board with a no-log
//! guarantee: RAM-only storage, cleared on any reboot, never persisted to
//! flash/NVS/filesystem and never included in beacons (spec 18.10.4).
//!
//! Wire contract (firmware `/confessions` resource, Python reference
//! `lichen.coap.resources.confessions`):
//!
//! * POST bodies are SenML+CBOR packs (RFC 8428, Content-Format 112):
//!   a base record (`bn` = `urn:dev:mac:<iid>:`, `bt` = Unix seconds),
//!   `type` (`vs`, must be `"confession"` when present), `content` (`vs`,
//!   required non-empty), optional `lat`/`lon` (`u`+`v`), `anonymous`
//!   (`v` != 0 or `vb`, default true), `ttl` (`v` seconds), optional
//!   `sender` (`vs`), `signature` (`vs`, carried but not verified here).
//! * Packing is canonical SenML: measurement values always 64-bit floats,
//!   integral base times shortest-form integers (byte-parity with
//!   `lichen_senml::wire` and the committed
//!   `test/vectors/confessions.json` hex oracle).
//! * Decoding is strict: trailing bytes, duplicate map keys, records with
//!   more than one value field, and non-finite numbers are rejected —
//!   `lichen_senml::wire::decode` enforces all of these natively (the same
//!   trailing-bytes / duplicate-key precedents as `deaddrop::decode_senml_pack`
//!   and `msg` mutation payloads).
//! * Collection GET has two representations: the 18.10.2 SenML feed
//!   (Content-Format 112) and the 18.10.7 query/display map with `count`,
//!   `confessions`, storage and rate metadata (the Python reference
//!   serializes that map as Content-Format 60).
//!
//! Rate limits (spec 18.10.3, the tightest in LICHEN): 1 POST per 30 s and
//! 12 per rolling hour per source IID, on monotonic uptime. Oversize posts
//! (> [`CONFESSION_MAX_SIZE`]) answer 4.13; rate violations answer 4.29
//! with a retry delay and the vector error code (`30s_limit` or
//! `hourly_limit_exceeded`). Storage overrun evicts oldest-first (FIFO)
//! with no back-pressure. TTL defaults to 12 h, clamped to 48 h; expired
//! entries vanish (`ttl_expired`).
//!
//! SECURITY: rate buckets are keyed on the authenticated source IID (or a
//! single shared bucket when unauthenticated) — never on the client-supplied
//! SenML `bn`. A non-anonymous confession stores a sender only when the
//! claimed `bn` IID equals the authenticated source IID.
//!
//! Conformance vectors: `test/vectors/confessions.json`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use lichen_senml::wire::{self, Record};

use crate::Error;

/// Cooldown between POSTs per source IID, in seconds (spec 18.10.3).
pub const CONFESSION_COOLDOWN_S: u64 = 30;
/// Maximum POSTs per rolling hour per source IID (spec 18.10.3).
pub const CONFESSION_HOURLY_MAX: u32 = 12;
/// Maximum confession payload size in bytes (spec 18.10.3).
pub const CONFESSION_MAX_SIZE: usize = 768;
/// Total storage budget for leaf nodes, in bytes (spec 18.10.3).
pub const CONFESSION_STORAGE_LEAF: usize = 2 * 1024;
/// Total storage budget for border routers, in bytes (spec 18.10.3).
pub const CONFESSION_STORAGE_BR: usize = 8 * 1024;
/// Default retention in seconds: 12 h (spec 18.10.3).
pub const CONFESSION_DEFAULT_TTL: u64 = 12 * 3600;
/// Maximum retention in seconds: 48 h (spec 18.10.3).
pub const CONFESSION_MAX_TTL: u64 = 48 * 3600;
/// Rolling rate window in seconds (spec 18.10.3 hourly ceiling).
pub const CONFESSION_WINDOW_S: u64 = 3600;
/// Vector error code for an entry past its retention (spec 18.10.3).
pub const TTL_EXPIRED: &str = "ttl_expired";

/// Length of a confession ID in hex chars (e.g. `8a4f2b`; 3 random bytes).
const ID_HEX_LEN: usize = 6;
/// Bounded CSPRNG retries when a generated ID collides (2^24 space).
const MAX_ID_ATTEMPTS: usize = 8;

/// Default number of entries returned by a collection query (reference
/// `_DEFAULT_GET_COUNT`).
const DEFAULT_GET_COUNT: usize = 100;

/// Raw CoAP response code bytes used by the confessions outcomes.
pub mod code {
    /// 2.01 Created (POST success, `Location-Path: /confessions/{id}`).
    pub const CREATED: u8 = 65;
    /// 2.05 Content (GET success).
    pub const CONTENT: u8 = 69;
    /// 4.00 Bad Request.
    pub const BAD_REQUEST: u8 = 128;
    /// 4.13 Request Entity Too Large (spec 18.10.3: max size 768 B).
    pub const ENTITY_TOO_LARGE: u8 = 141;
    /// 4.29 Too Many Requests with `Retry-After` (spec 18.10.3).
    pub const TOO_MANY_REQUESTS: u8 = 157;
    /// 5.03 Service Unavailable (ID space exhausted after bounded retries).
    pub const SERVICE_UNAVAILABLE: u8 = 173;
}

/// Content-Format for SenML+CBOR payloads and the 18.10.2 feed.
pub const CONTENT_FORMAT_SENML_CBOR: u16 = 112;
/// Content-Format for the 18.10.7 query/display CBOR map.
pub const CONTENT_FORMAT_CBOR: u16 = 60;

/// Rate bucket key for requests with no authenticated identity.
///
/// SECURITY: never key a bucket on the client-supplied SenML `bn`.
const UNAUTHENTICATED_RATE_KEY: &str = "unauthenticated";

/// Monotonic uptime clock in seconds (spec 18.10.3 mandates uptime, not
/// wall clock, so limits cannot be bypassed by clock spoofing).
pub type UptimeClock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn default_uptime() -> f64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// Fill *buf* from the operating system CSPRNG.
fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buf).map_err(|e| Error::Encode(e.to_string()))
}

/// Return `true` if *value* is a canonical 6-char lowercase hex confession ID.
pub fn is_confession_id(value: &str) -> bool {
    value.len() == ID_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why a POST was rate limited (vector error codes verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// Fewer than [`CONFESSION_COOLDOWN_S`] since this source's last POST.
    Cooldown,
    /// [`CONFESSION_HOURLY_MAX`] POSTs already recorded in the rolling hour.
    HourlyLimit,
}

impl RateLimitReason {
    /// Vector error code for this reason (`30s_limit`,
    /// `hourly_limit_exceeded`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cooldown => "30s_limit",
            Self::HourlyLimit => "hourly_limit_exceeded",
        }
    }
}

/// A decoded `POST /confessions` SenML payload (spec 18.10.1).
///
/// Field order matches the reference payload: base record first, then
/// `type`, `content`, `lat`, `lon`, `anonymous`, `ttl`, `sender`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfessionPayload {
    /// IID claimed by the SenML `bn` (`urn:dev:mac:<iid>:`, lowercased).
    ///
    /// SECURITY: attacker-controlled; the store only trusts it when it
    /// equals the authenticated source IID.
    pub claimed_iid: Option<String>,
    /// Base time (`bt`) in Unix seconds, when carried.
    pub base_time: Option<f64>,
    /// `type` record (`vs`); must be `"confession"` when present.
    pub confession_type: Option<String>,
    /// `content` record (`vs`); required non-empty by the store.
    pub content: Option<String>,
    /// `anonymous` flag (`v` != 0 or `vb`); default true (spec 18.10.1).
    pub anonymous: bool,
    /// Requested retention in seconds, when carried.
    pub ttl: Option<f64>,
    /// Optional latitude (`lat` record `v`).
    pub lat: Option<f64>,
    /// Optional longitude (`lon` record `v`).
    pub lon: Option<f64>,
    /// `sender` record (`vs`) on non-anonymous posts.
    pub sender: Option<String>,
    /// Whether the SenML payload carried an explicit `anonymous` record;
    /// controls whether [`ConfessionPayload::to_senml`] re-emits it so a
    /// decoded vector payload re-encodes to the committed oracle bytes.
    pub anonymous_record_present: bool,
}

/// Extract the IID from a `urn:dev:mac:<hex>:` base name (reference
/// `_extract_claimed_iid`).
fn claimed_iid_from_base_name(base_name: &str) -> Option<String> {
    let rest = base_name.strip_prefix("urn:dev:mac:")?;
    let iid = rest.split(':').next()?;
    if iid.is_empty() {
        return None;
    }
    Some(iid.to_ascii_lowercase())
}

/// Canonical `urn:dev:mac:<iid>:` base name rebuilt from an IID.
fn owned_base_name(iid: &str) -> String {
    format!("urn:dev:mac:{iid}:")
}

/// Text value of the first record named *name* (`vs` form).
fn senml_text<'a>(records: &'a [Record<'_>], name: &str) -> Option<&'a str> {
    records
        .iter()
        .find(|r| r.name == Some(name))
        .and_then(|r| r.string_value)
}

/// Numeric value of the first record named *name* (`v` form).
fn senml_value(records: &[Record<'_>], name: &str) -> Option<f64> {
    records
        .iter()
        .find(|r| r.name == Some(name))
        .and_then(|r| r.value)
}

fn text_record<'a>(name: &'a str, value: &'a str) -> Record<'a> {
    Record {
        name: Some(name),
        string_value: Some(value),
        ..Record::empty()
    }
}

fn number_record<'a>(name: &'a str, unit: &'a str, value: f64) -> Record<'a> {
    Record {
        name: Some(name),
        unit: if unit.is_empty() { None } else { Some(unit) },
        value: Some(value),
        ..Record::empty()
    }
}

impl ConfessionPayload {
    /// Decode and validate a SenML+CBOR POST body (spec 18.10.1).
    ///
    /// Strict per the canonical codec: trailing bytes, duplicate map keys,
    /// multi-value records, and non-finite numbers are rejected. Domain
    /// validation uses pinned error codes: `invalid_confession_type`,
    /// `missing_content`, `invalid_ttl_value`, `invalid_coordinate`,
    /// `invalid_anonymous_value`.
    pub fn from_senml(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = [const { Record::empty() }; 16];
        let count = wire::decode(bytes, &mut buf).map_err(|e| Error::Decode(e.to_string()))?;
        let records = &buf[..count];

        let mut payload = Self {
            anonymous: true,
            ..Self::default()
        };
        for record in records {
            if let Some(base_name) = record.base_name {
                payload.claimed_iid = claimed_iid_from_base_name(base_name);
            }
            if let Some(base_time) = record.base_time {
                payload.base_time = Some(base_time);
            }
        }

        if let Some(text) = senml_text(records, "type") {
            if text != "confession" {
                return Err(Error::Decode("invalid_confession_type".into()));
            }
            payload.confession_type = Some(text.to_owned());
        }
        if let Some(text) = senml_text(records, "content") {
            if text.is_empty() {
                return Err(Error::Decode("missing_content".into()));
            }
            payload.content = Some(text.to_owned());
        }
        for record in records {
            if record.name != Some("anonymous") {
                continue;
            }
            payload.anonymous_record_present = true;
            if let Some(flag) = record.bool_value {
                payload.anonymous = flag;
            } else if let Some(value) = record.value {
                payload.anonymous = value != 0.0;
            } else {
                return Err(Error::Decode("invalid_anonymous_value".into()));
            }
        }
        if let Some(ttl) = senml_value(records, "ttl") {
            if !ttl.is_finite() || ttl <= 0.0 {
                return Err(Error::Decode("invalid_ttl_value".into()));
            }
            payload.ttl = Some(ttl);
        }
        for (name, slot) in [("lat", &mut payload.lat), ("lon", &mut payload.lon)] {
            if let Some(value) = senml_value(records, name) {
                if !value.is_finite() {
                    return Err(Error::Decode("invalid_coordinate".into()));
                }
                *slot = Some(value);
            }
        }
        if let Some(text) = senml_text(records, "sender") {
            payload.sender = Some(text.to_owned());
        }
        Ok(payload)
    }

    /// Encode as a canonical SenML+CBOR pack (RFC 8428 integer labels).
    ///
    /// Field order matches the reference payload (base, `type`, `content`,
    /// `lat`, `lon`, `anonymous`, `ttl`, `sender`); values are always
    /// 64-bit floats and integral base times shortest-form integers, so a
    /// decoded vector payload re-encodes to the committed oracle bytes.
    pub fn to_senml(&self) -> Result<Vec<u8>, Error> {
        let base_name = self
            .claimed_iid
            .as_deref()
            .map(owned_base_name)
            .map(String::into_boxed_str);
        let type_owned = self.confession_type.clone().unwrap_or_default();
        let content_owned = self.content.clone().unwrap_or_default();
        let sender_owned = self.sender.clone().unwrap_or_default();

        let mut records: Vec<Record<'_>> = Vec::new();
        if base_name.is_some() || self.base_time.is_some() {
            records.push(Record {
                base_name: base_name.as_deref(),
                base_time: self.base_time,
                ..Record::empty()
            });
        }
        if self.confession_type.is_some() {
            records.push(text_record("type", &type_owned));
        }
        if self.content.is_some() {
            records.push(text_record("content", &content_owned));
        }
        if let Some(lat) = self.lat {
            records.push(number_record("lat", "lat", lat));
        }
        if let Some(lon) = self.lon {
            records.push(number_record("lon", "lon", lon));
        }
        if self.anonymous_record_present {
            records.push(number_record("anonymous", "", self.anonymous as i64 as f64));
        }
        if let Some(ttl) = self.ttl {
            records.push(number_record("ttl", "", ttl));
        }
        if self.sender.is_some() {
            records.push(text_record("sender", &sender_owned));
        }

        let mut out = vec![0u8; 2048];
        let n = wire::encode(&records, &mut out).map_err(|e| Error::Encode(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }
}

/// A confession stored in RAM (spec 18.10.3/18.10.4 fields).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfessionEntry {
    /// Canonical 6-char lowercase hex ID (Location-Path suffix).
    pub id: String,
    /// Confession text (`content` record).
    pub content: String,
    /// `type` record value (defaults to `"confession"`).
    pub confession_type: String,
    /// Sender-declared timestamp: SenML `bt` in Unix seconds, or the
    /// receive uptime when the post carried no `bt` (reference stores
    /// `base_time or now`).
    pub ts: f64,
    /// Monotonic receive time (uptime seconds).
    pub received_at: f64,
    /// Monotonic expiry (uptime seconds; `received_at` + clamped TTL).
    pub expire_time: f64,
    /// Charged storage size in bytes (wire payload length, reference
    /// `len(request.payload)`).
    pub size: usize,
    /// `anonymous` flag (spec 18.10.1, default true).
    pub anonymous: bool,
    /// Authenticated source IID, stored only for non-anonymous posts whose
    /// claimed `bn` IID matches the authenticated source. Never persisted
    /// with OSCORE context (spec 18.10.5).
    pub source: Option<String>,
    /// Optional latitude (`lat` record `v`).
    pub lat: Option<f64>,
    /// Optional longitude (`lon` record `v`).
    pub lon: Option<f64>,
}

/// Direct-insert parameters for [`ConfessionStore::add_confession`]
/// (mirrors the reference `add_confession` keyword arguments).
#[derive(Debug, Clone, Default)]
pub struct AddConfessionParams {
    /// Confession text (`content` record); required non-empty.
    pub content: String,
    /// Explicit canonical 6-char lowercase hex ID, or None for CSPRNG.
    pub id: Option<String>,
    /// Sender-declared timestamp (Unix seconds), or None for uptime.
    pub ts: Option<f64>,
    /// Retention in seconds (clamped to [`CONFESSION_MAX_TTL`]).
    pub ttl: Option<u64>,
    /// Charged storage size, or None for `content.len() + 64`.
    pub size: Option<usize>,
    /// `anonymous` flag (default true via [`Default`]).
    pub anonymous: bool,
    /// Authenticated source IID for non-anonymous entries.
    pub source: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

/// Outcome of a `POST /confessions` submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostOutcome {
    /// Raw CoAP response code (see [`code`]).
    pub code: u8,
    /// Generated confession ID on `2.01 Created`.
    pub id: Option<String>,
    /// `Retry-After` seconds on `4.29 Too Many Requests`.
    pub retry_after_s: Option<u64>,
    /// Vector error code for rejections (`30s_limit`,
    /// `hourly_limit_exceeded`).
    pub reason: Option<&'static str>,
}

impl PostOutcome {
    fn created(id: String) -> Self {
        Self {
            code: code::CREATED,
            id: Some(id),
            retry_after_s: None,
            reason: None,
        }
    }

    fn bad_request() -> Self {
        Self {
            code: code::BAD_REQUEST,
            id: None,
            retry_after_s: None,
            reason: None,
        }
    }

    fn too_large() -> Self {
        Self {
            code: code::ENTITY_TOO_LARGE,
            id: None,
            retry_after_s: None,
            reason: None,
        }
    }

    fn too_many_requests(retry_after_s: u64, reason: RateLimitReason) -> Self {
        Self {
            code: code::TOO_MANY_REQUESTS,
            id: None,
            retry_after_s: Some(retry_after_s),
            reason: Some(reason.as_str()),
        }
    }

    fn unavailable() -> Self {
        Self {
            code: code::SERVICE_UNAVAILABLE,
            id: None,
            retry_after_s: None,
            reason: None,
        }
    }

    /// True when the post was created.
    pub const fn is_created(&self) -> bool {
        self.code == code::CREATED
    }
}

/// Collection query parameters (spec 18.10.2/18.10.7: `count`, `since`,
/// `after`, `type`).
#[derive(Debug, Clone, Default)]
pub struct ConfessionQuery {
    /// Maximum entries returned (default 100).
    pub count: Option<usize>,
    /// Only confessions with `ts >= since`.
    pub since: Option<f64>,
    /// Only confessions with `ts > after`.
    pub after: Option<f64>,
    /// Only confessions whose `type` matches exactly.
    pub type_filter: Option<String>,
}

/// One public entry of a collection listing (spec 18.10.7 entry shape).
#[derive(Debug, Clone, PartialEq)]
pub struct ListingEntry {
    pub id: String,
    pub content: String,
    pub ts: f64,
    /// Seconds since receive, floored at zero.
    pub age_s: u64,
}

/// Collection listing body fields (spec 18.10.7; the Python reference
/// serializes this map as Content-Format 60).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfessionListing {
    pub count: usize,
    pub confessions: Vec<ListingEntry>,
    pub storage_used_kb: f64,
    pub storage_max_kb: f64,
    /// Present only for authenticated requesters (never the shared
    /// unauthenticated bucket).
    pub rate_remaining: Option<u32>,
    pub rate_reset_s: Option<u64>,
    /// Operator persistence override (spec 18.10.4).
    pub logging: bool,
}

/// Detail body for `GET /confessions/{id}` (adds `anonymous`/`sender`).
#[derive(Debug, Clone, PartialEq)]
pub struct EntryDetail {
    pub id: String,
    pub content: String,
    pub ts: f64,
    pub age_s: u64,
    pub anonymous: bool,
    pub sender: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

/// Rate-limit decision for a POST (spec 18.10.3: cooldown first, then the
/// rolling-hour ceiling; both on monotonic uptime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Deny {
        retry_after_s: u64,
        reason: RateLimitReason,
    },
}

/// RAM-only anonymous confession board (spec 18.10).
///
/// Mirrors the Python reference `ConfessionsResource`: FIFO eviction with
/// no back-pressure, per-identity rate buckets on monotonic uptime, TTL
/// clamped to [`CONFESSION_MAX_TTL`], and a `clear()` that models any
/// reboot (warm, cold, or crash) by wiping confessions and rate state.
///
/// SECURITY: buckets are keyed on the authenticated source IID only;
/// the client-supplied SenML `bn` never keys a bucket and never becomes a
/// stored sender unless it matches the authenticated IID.
pub struct ConfessionStore {
    storage_limit: usize,
    clock: UptimeClock,
    persist: bool,
    confessions: Vec<ConfessionEntry>,
    total_size: usize,
    request_times: HashMap<String, Vec<f64>>,
}

impl ConfessionStore {
    /// Create a store with *storage_limit* bytes and the system uptime.
    pub fn new(storage_limit: usize) -> Result<Self, Error> {
        Self::with_clock(storage_limit, Arc::new(default_uptime))
    }

    /// Create a store with an explicit monotonic uptime clock.
    ///
    /// Rejects a zero *storage_limit* with [`Error::Config`] — a
    /// configuration problem, not an encoding problem.
    pub fn with_clock(storage_limit: usize, clock: UptimeClock) -> Result<Self, Error> {
        if storage_limit == 0 {
            return Err(Error::Config(
                "storage_limit must be a positive integer".into(),
            ));
        }
        Ok(Self {
            storage_limit,
            clock,
            persist: false,
            confessions: Vec::new(),
            total_size: 0,
            request_times: HashMap::new(),
        })
    }

    /// Operator persistence override (spec 18.10.4): surfaces `logging`
    /// in listings; storage stays RAM-only in this model.
    pub fn set_persist(&mut self, persist: bool) {
        self.persist = persist;
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Remove expired confessions (TTL measured from receive time).
    pub fn prune_expired(&mut self) {
        let now = self.now();
        self.confessions.retain(|c| c.expire_time > now);
        self.total_size = self.confessions.iter().map(|c| c.size).sum();
    }

    /// Drop timestamps older than the 1-hour window from every bucket.
    ///
    /// SECURITY: reaping is global; abandoned keys must not wait for that
    /// key to return.
    pub fn reap_stale_rate_buckets(&mut self) {
        let cutoff = self.now() - CONFESSION_WINDOW_S as f64;
        self.request_times.retain(|_, ts| {
            ts.retain(|t| *t > cutoff);
            !ts.is_empty()
        });
    }

    /// Check whether *source* may POST right now (spec 18.10.3).
    ///
    /// The 30 s cooldown is the tighter limit and is checked first.
    pub fn check_rate_limit(&mut self, source: &str) -> RateDecision {
        self.reap_stale_rate_buckets();
        let now = self.now();
        let Some(timestamps) = self.request_times.get(source) else {
            return RateDecision::Allow;
        };
        if let Some(last) = timestamps.last() {
            let since = now - last;
            if since < CONFESSION_COOLDOWN_S as f64 {
                let retry = (CONFESSION_COOLDOWN_S as f64 - since).ceil();
                return RateDecision::Deny {
                    retry_after_s: retry.max(0.0) as u64,
                    reason: RateLimitReason::Cooldown,
                };
            }
        }
        if timestamps.len() >= CONFESSION_HOURLY_MAX as usize {
            let oldest = timestamps[0];
            let retry = (CONFESSION_WINDOW_S as f64 - (now - oldest)).ceil();
            return RateDecision::Deny {
                retry_after_s: retry.max(0.0) as u64,
                reason: RateLimitReason::HourlyLimit,
            };
        }
        RateDecision::Allow
    }

    /// Record a successful POST timestamp for *source*.
    pub fn record_request(&mut self, source: &str) {
        self.reap_stale_rate_buckets();
        let now = self.now();
        self.request_times
            .entry(source.to_owned())
            .or_default()
            .push(now);
    }

    /// Rate info for an authenticated source (reference `rate_info`).
    pub fn rate_info(&mut self, source: &str) -> (u32, u64) {
        self.reap_stale_rate_buckets();
        let now = self.now();
        match self.request_times.get(source) {
            None => (CONFESSION_HOURLY_MAX, CONFESSION_WINDOW_S),
            Some(timestamps) => {
                let remaining = CONFESSION_HOURLY_MAX - timestamps.len() as u32;
                let oldest = timestamps[0];
                let reset = ((CONFESSION_WINDOW_S as f64 - (now - oldest)).max(0.0)) as u64;
                (remaining, reset)
            }
        }
    }

    /// Storage usage in KiB (spec 18.10.7 metadata).
    pub fn storage_info(&self) -> (f64, f64) {
        (
            self.total_size as f64 / 1024.0,
            self.storage_limit as f64 / 1024.0,
        )
    }

    fn evict_oldest(&mut self, needed_space: usize) {
        while !self.confessions.is_empty() && self.total_size + needed_space > self.storage_limit {
            let oldest = self.confessions.remove(0);
            self.total_size -= oldest.size;
        }
    }

    fn unique_id(&self) -> Option<String> {
        for _ in 0..MAX_ID_ATTEMPTS {
            let mut bytes = [0u8; ID_HEX_LEN / 2];
            fill_random(&mut bytes).ok()?;
            let id = format!(
                "{:0width$x}",
                u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
                width = ID_HEX_LEN
            );
            if self.confessions.iter().all(|c| c.id != id) {
                return Some(id);
            }
        }
        None
    }

    /// Insert a confession directly (tests, mesh delivery, reboot seeds).
    ///
    /// Does not consume the POST rate budget. Evicts oldest entries if
    /// needed. Mirrors the reference `add_confession`: explicit IDs must
    /// be unique canonical 6-char lowercase hex.
    pub fn add_confession(&mut self, params: AddConfessionParams) -> Result<String, Error> {
        let now = self.now();
        let ttl = match params.ttl {
            None => CONFESSION_DEFAULT_TTL,
            Some(t) => {
                let t = t.min(CONFESSION_MAX_TTL);
                if t == 0 {
                    CONFESSION_DEFAULT_TTL
                } else {
                    t
                }
            }
        };
        let size = params.size.unwrap_or(params.content.len() + 64);
        self.prune_expired();
        self.evict_oldest(size);
        let id = match params.id {
            None => self
                .unique_id()
                .ok_or_else(|| Error::Encode("confession id space exhausted".into()))?,
            Some(explicit) => {
                if !is_confession_id(&explicit) || self.confessions.iter().any(|c| c.id == explicit)
                {
                    return Err(Error::Config(
                        "confession_id must be a unique 6-char lowercase hex id".into(),
                    ));
                }
                explicit.to_owned()
            }
        };
        let entry = ConfessionEntry {
            id: id.clone(),
            content: params.content,
            confession_type: "confession".to_owned(),
            ts: params.ts.unwrap_or(now),
            received_at: now,
            expire_time: now + ttl as f64,
            size,
            anonymous: params.anonymous,
            source: if params.anonymous {
                None
            } else {
                params.source
            },
            lat: params.lat,
            lon: params.lon,
        };
        self.total_size += entry.size;
        self.confessions.push(entry);
        Ok(id)
    }

    /// POST /confessions (spec 18.10.1-18.10.3).
    ///
    /// *source_iid* is the authenticated IPv6 source IID when available;
    /// without it all requests share the single unauthenticated bucket.
    /// Gate order matches the reference: 4.00 empty/undecodable, 4.13
    /// oversize, 4.29 rate limits (with `Retry-After` and the vector
    /// reason), then payload validation, then FIFO eviction, then create.
    pub fn post(&mut self, bytes: &[u8], source_iid: Option<&str>) -> PostOutcome {
        if bytes.is_empty() {
            return PostOutcome::bad_request();
        }
        if bytes.len() > CONFESSION_MAX_SIZE {
            return PostOutcome::too_large();
        }
        let payload = match ConfessionPayload::from_senml(bytes) {
            Ok(p) => p,
            Err(_) => return PostOutcome::bad_request(),
        };
        let Some(claimed_iid) = payload.claimed_iid else {
            return PostOutcome::bad_request();
        };
        let content = match &payload.content {
            Some(c) if !c.is_empty() => c.clone(),
            _ => return PostOutcome::bad_request(),
        };

        let rate_key = source_iid.unwrap_or(UNAUTHENTICATED_RATE_KEY);
        match self.check_rate_limit(rate_key) {
            RateDecision::Deny {
                retry_after_s,
                reason,
            } => return PostOutcome::too_many_requests(retry_after_s, reason),
            RateDecision::Allow => {}
        }

        let ttl = match payload.ttl {
            Some(t) => (t as u64).min(CONFESSION_MAX_TTL),
            None => CONFESSION_DEFAULT_TTL,
        };
        let size = bytes.len();
        self.prune_expired();
        self.evict_oldest(size);

        let Some(id) = self.unique_id() else {
            return PostOutcome::unavailable();
        };
        // SECURITY: the claimed bn is displayed only when it equals the
        // authenticated IPv6 source IID (reference `_displayed_sender`).
        let stored_source = if payload.anonymous {
            None
        } else {
            source_iid
                .filter(|auth| auth == &claimed_iid)
                .map(str::to_owned)
        };
        let now = self.now();
        let entry = ConfessionEntry {
            id: id.clone(),
            content,
            confession_type: payload
                .confession_type
                .unwrap_or_else(|| "confession".to_owned()),
            ts: payload.base_time.unwrap_or(now),
            received_at: now,
            expire_time: now + ttl as f64,
            size,
            anonymous: payload.anonymous,
            source: stored_source,
            lat: payload.lat,
            lon: payload.lon,
        };
        self.total_size += entry.size;
        self.confessions.push(entry);
        self.record_request(rate_key);
        PostOutcome::created(id)
    }

    /// Collection listing (spec 18.10.7): filtered, newest first, with
    /// storage and per-requester rate metadata.
    pub fn listing(&mut self, query: ConfessionQuery, rate_key: Option<&str>) -> ConfessionListing {
        self.prune_expired();
        self.reap_stale_rate_buckets();
        let now = self.now();
        let count_limit = query.count.unwrap_or(DEFAULT_GET_COUNT);
        let mut selected: Vec<&ConfessionEntry> = self
            .confessions
            .iter()
            .filter(|c| {
                if let Some(since) = query.since {
                    if c.ts < since {
                        return false;
                    }
                }
                if let Some(after) = query.after {
                    if c.ts <= after {
                        return false;
                    }
                }
                if let Some(t) = &query.type_filter {
                    if &c.confession_type != t {
                        return false;
                    }
                }
                true
            })
            .collect();
        // 18.10.7: newest first, ordered by sender ts (descending). The
        // vector pins 8a4f2b (ts ...321) ahead of 3c1d9e (ts ...000)
        // regardless of arrival order.
        selected.sort_by(|a, b| {
            b.ts.partial_cmp(&a.ts)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(
                    b.received_at
                        .partial_cmp(&a.received_at)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
        });
        selected.truncate(count_limit);
        let entries: Vec<ListingEntry> = selected
            .iter()
            .map(|c| ListingEntry {
                id: c.id.clone(),
                content: c.content.clone(),
                ts: c.ts,
                age_s: (now - c.received_at).max(0.0) as u64,
            })
            .collect();
        let (storage_used_kb, storage_max_kb) = self.storage_info();
        let (rate_remaining, rate_reset_s) = match rate_key {
            // Rate info is for the requesting client, not the host; omit
            // for unauthenticated requesters (reference acceptance rule).
            Some(key) if key != UNAUTHENTICATED_RATE_KEY => {
                let (remaining, reset) = self.rate_info(key);
                (Some(remaining), Some(reset))
            }
            _ => (None, None),
        };
        ConfessionListing {
            count: entries.len(),
            confessions: entries,
            storage_used_kb,
            storage_max_kb,
            rate_remaining,
            rate_reset_s,
            logging: self.persist,
        }
    }

    /// Number of live confessions (after expiry pruning).
    pub fn len(&mut self) -> usize {
        self.prune_expired();
        self.confessions.len()
    }

    /// True when no live confessions are stored.
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    /// Detail body for `GET /confessions/{id}` (spec 18.10.2), or None
    /// when the id is not canonical / not found / expired.
    pub fn entry(&mut self, id: &str) -> Option<EntryDetail> {
        self.prune_expired();
        if !is_confession_id(id) {
            return None;
        }
        let now = self.now();
        self.confessions
            .iter()
            .find(|c| c.id == id)
            .map(|c| EntryDetail {
                id: c.id.clone(),
                content: c.content.clone(),
                ts: c.ts,
                age_s: (now - c.received_at).max(0.0) as u64,
                anonymous: c.anonymous,
                sender: if c.anonymous { None } else { c.source.clone() },
                lat: c.lat,
                lon: c.lon,
            })
    }

    /// 18.10.2 SenML feed (Content-Format 112): a CBOR array holding each
    /// live confession's SenML pack. Only the empty-board form (`0x80`)
    /// is vector-pinned; the non-empty entry pack shape is
    /// implementation-defined pending a committed vector.
    pub fn feed_senml(&mut self) -> Result<Vec<u8>, Error> {
        use ciborium::value::Value;
        self.prune_expired();
        let mut packs = Vec::new();
        for c in &self.confessions {
            let payload = ConfessionPayload {
                base_time: Some(c.ts),
                content: Some(c.content.clone()),
                anonymous: c.anonymous,
                anonymous_record_present: false,
                lat: c.lat,
                lon: c.lon,
                ..ConfessionPayload::default()
            };
            let bytes = payload.to_senml()?;
            let value: Value =
                ciborium::from_reader(&bytes[..]).map_err(|e| Error::Encode(e.to_string()))?;
            packs.push(value);
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Array(packs), &mut out)
            .map_err(|e| Error::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Clear all state — models any reboot (spec 18.10.4: RAM-only
    /// storage, cleared warm/cold/crash; rate table is RAM-only too).
    pub fn clear(&mut self) {
        self.confessions.clear();
        self.total_size = 0;
        self.request_times.clear();
    }
}
