//! Data-traffic timing (spec 09 section 14.3).
//!
//! Telemetry is 5-60 minutes. Heartbeat/keepalive is 30 minutes if no data
//! has been sent. Comparisons use wrapping unsigned elapsed time.

/// 5 minutes in milliseconds.
pub const TELEMETRY_MIN_MS: u64 = 5 * 60 * 1000;
/// 60 minutes in milliseconds.
pub const TELEMETRY_MAX_MS: u64 = 60 * 60 * 1000;
/// Heartbeat/keepalive interval (30 minutes).
pub const HEARTBEAT_MS: u64 = 30 * 60 * 1000;

/// Wrap-safe elapsed ticks: `now.wrapping_sub(then)`.
pub const fn elapsed(now: u64, then: u64) -> u64 {
    now.wrapping_sub(then)
}

/// Configured telemetry period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryInterval {
    interval_ms: u64,
}

/// Invalid telemetry configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryIntervalError {
    /// Below 5 minutes or above 60 minutes.
    OutOfRange,
}

impl TelemetryInterval {
    /// Construct a period in `[5 min, 60 min]`.
    pub const fn new(interval_ms: u64) -> Result<Self, TelemetryIntervalError> {
        if interval_ms < TELEMETRY_MIN_MS || interval_ms > TELEMETRY_MAX_MS {
            return Err(TelemetryIntervalError::OutOfRange);
        }
        Ok(Self { interval_ms })
    }

    /// Configured period in milliseconds.
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms
    }

    /// True if no sample has been sent, or `interval_ms` has elapsed.
    pub const fn due(self, now_ms: u64, last_tx_ms: Option<u64>) -> bool {
        match last_tx_ms {
            None => true,
            Some(last) => elapsed(now_ms, last) >= self.interval_ms,
        }
    }
}

/// 30-minute heartbeat if no data has been sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    interval_ms: u64,
}

impl Heartbeat {
    /// Spec 14.3 keepalive interval.
    pub const fn new() -> Self {
        Self {
            interval_ms: HEARTBEAT_MS,
        }
    }

    /// True if no data has gone out, or 30 minutes have elapsed since last TX.
    pub const fn due(self, now_ms: u64, last_data_tx_ms: Option<u64>) -> bool {
        match last_data_tx_ms {
            None => true,
            Some(last) => elapsed(now_ms, last) >= self.interval_ms,
        }
    }
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_rejects_out_of_range() {
        assert_eq!(
            TelemetryInterval::new(TELEMETRY_MIN_MS - 1),
            Err(TelemetryIntervalError::OutOfRange)
        );
        assert_eq!(
            TelemetryInterval::new(TELEMETRY_MAX_MS + 1),
            Err(TelemetryIntervalError::OutOfRange)
        );
        assert!(TelemetryInterval::new(TELEMETRY_MIN_MS).is_ok());
        assert!(TelemetryInterval::new(TELEMETRY_MAX_MS).is_ok());
    }

    #[test]
    fn telemetry_due_after_interval() {
        let period = TelemetryInterval::new(TELEMETRY_MIN_MS).unwrap();
        assert!(period.due(0, None));
        assert!(!period.due(TELEMETRY_MIN_MS - 1, Some(0)));
        assert!(period.due(TELEMETRY_MIN_MS, Some(0)));
    }

    #[test]
    fn heartbeat_due_after_30_min() {
        let hb = Heartbeat::new();
        assert!(hb.due(0, None));
        assert!(!hb.due(HEARTBEAT_MS - 1, Some(0)));
        assert!(hb.due(HEARTBEAT_MS, Some(0)));
    }

    #[test]
    fn wrap_safe_elapsed() {
        assert_eq!(elapsed(5, 1), 4);
        assert_eq!(elapsed(0, u64::MAX), 1);
        let period = TelemetryInterval::new(TELEMETRY_MIN_MS).unwrap();
        assert!(period.due(TELEMETRY_MIN_MS - 1, Some(u64::MAX)));
    }
}
