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
