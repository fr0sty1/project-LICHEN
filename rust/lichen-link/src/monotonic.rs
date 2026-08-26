//! Monotonic uptime tracking (spec 09 section 14.6).
//!
//! Observations are implementation-defined ticks since boot. Equal values are
//! valid; a decrease or wrap within one power cycle is not.

/// Non-decreasing tick counter for one power cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MonotonicUptime {
    last: Option<u64>,
}

/// Rejected monotonic observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonotonicError {
    /// Sample is earlier than a previously accepted tick in this power cycle.
    Regression,
}

impl MonotonicUptime {
    /// Start with no observations (boot).
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Last accepted tick, if any.
    pub const fn now(self) -> Option<u64> {
        self.last
    }

    /// Accept `ticks` when it does not go backwards.
    pub fn observe(&mut self, ticks: u64) -> Result<u64, MonotonicError> {
        if let Some(prev) = self.last {
            if ticks < prev {
                return Err(MonotonicError::Regression);
            }
        }
        self.last = Some(ticks);
        Ok(ticks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_decreases() {
        let mut clock = MonotonicUptime::new();
        assert_eq!(clock.now(), None);
        assert_eq!(clock.observe(0), Ok(0));
        assert_eq!(clock.observe(0), Ok(0));
        assert_eq!(clock.observe(7), Ok(7));
        assert_eq!(clock.observe(6), Err(MonotonicError::Regression));
        assert_eq!(clock.now(), Some(7));
    }

    #[test]
    fn wrap_to_zero_is_regression() {
        let mut clock = MonotonicUptime::new();
        assert_eq!(clock.observe(u64::MAX), Ok(u64::MAX));
        assert_eq!(clock.observe(0), Err(MonotonicError::Regression));
        assert_eq!(clock.now(), Some(u64::MAX));
    }
}
