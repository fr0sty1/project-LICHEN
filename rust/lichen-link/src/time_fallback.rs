//! Constrained-node time when `wall_clock_valid` is false (spec 09 14.6).
//!
//! Consumers MUST fall back to monotonic uptime and mark data so it is not
//! treated as Unix wall-clock time.

use crate::time_source::TimeSourceClass;
use crate::wall_clock::WallClockValidity;

/// Timestamp a consumer should attach to outbound data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerTimestamp {
    /// Established wall-clock Unix seconds plus provenance.
    UnixSeconds {
        /// Accepted Unix time.
        unix: u32,
        /// Source that established the clock.
        source: TimeSourceClass,
    },
    /// Wall clock is invalid; use monotonic ticks instead.
    MonotonicFallback {
        /// Uptime ticks since boot.
        ticks: u64,
    },
}

impl ConsumerTimestamp {
    /// True only for an established Unix timestamp.
    pub const fn wall_clock_valid(self) -> bool {
        matches!(self, Self::UnixSeconds { .. })
    }
}

/// Choose a consumer timestamp from current validity and local clocks.
///
/// When `clock` is invalid, `unix` is ignored and the monotonic sample is
/// returned so SenML / diagnostics cannot be stamped with unsynchronized Unix
/// time.
pub const fn consumer_timestamp(
    clock: WallClockValidity,
    unix: u32,
    uptime_ticks: u64,
) -> ConsumerTimestamp {
    match clock.source() {
        Some(source) if clock.is_valid() => ConsumerTimestamp::UnixSeconds { unix, source },
        _ => ConsumerTimestamp::MonotonicFallback {
            ticks: uptime_ticks,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time_source::TimeSourceClass;
    use crate::wall_clock::WallClockValidity;

    #[test]
    fn invalid_clock_falls_back_to_monotonic() {
        let stamp = consumer_timestamp(WallClockValidity::new(), 1_700_000_000, 42);
        assert_eq!(stamp, ConsumerTimestamp::MonotonicFallback { ticks: 42 });
        assert!(!stamp.wall_clock_valid());
    }

    #[test]
    fn established_clock_uses_unix() {
        let clock = WallClockValidity::new()
            .establish(TimeSourceClass::Gnss)
            .expect("gnss");
        let stamp = consumer_timestamp(clock, 1_700_000_000, 99);
        assert_eq!(
            stamp,
            ConsumerTimestamp::UnixSeconds {
                unix: 1_700_000_000,
                source: TimeSourceClass::Gnss,
            }
        );
        assert!(stamp.wall_clock_valid());
        let stamp = consumer_timestamp(clock.invalidate(), 1_700_000_000, 99);
        assert_eq!(stamp, ConsumerTimestamp::MonotonicFallback { ticks: 99 });
        assert!(!stamp.wall_clock_valid());
    }
}
