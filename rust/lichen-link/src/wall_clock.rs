//! Wall-clock validity flag (spec 09 section 14.6).

use crate::time_source::TimeSourceClass;

/// Tracks whether a node currently has an established wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WallClockValidity {
    valid: bool,
    source: Option<TimeSourceClass>,
}

/// Failed wall-clock establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallClockError {
    /// Monotonic uptime cannot establish wall-clock time.
    SourceCannotEstablish,
}

impl WallClockValidity {
    /// Start unsynchronized (`wall_clock_valid = false`).
    pub const fn new() -> Self {
        Self {
            valid: false,
            source: None,
        }
    }

    /// Current `wall_clock_valid` flag.
    pub const fn is_valid(self) -> bool {
        self.valid
    }

    /// Source that established the clock, if valid.
    pub const fn source(self) -> Option<TimeSourceClass> {
        self.source
    }

    /// Transition to valid after an accepted wall-clock sample.
    pub const fn establish(mut self, source: TimeSourceClass) -> Result<Self, WallClockError> {
        if !source.can_establish_wall_clock() {
            return Err(WallClockError::SourceCannotEstablish);
        }
        self.valid = true;
        self.source = Some(source);
        Ok(self)
    }

    /// Drop wall-clock validity (holdover expiry, desync).
    pub const fn invalidate(self) -> Self {
        Self {
            valid: false,
            source: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_invalid_then_establishes() {
        let clock = WallClockValidity::new();
        assert!(!clock.is_valid());
        assert_eq!(clock.source(), None);
        let clock = clock
            .establish(TimeSourceClass::Gnss)
            .expect("gnss can establish");
        assert!(clock.is_valid());
        assert_eq!(clock.source(), Some(TimeSourceClass::Gnss));
        let clock = clock.invalidate();
        assert!(!clock.is_valid());
        assert_eq!(clock.source(), None);
    }

    #[test]
    fn monotonic_cannot_establish() {
        assert_eq!(
            WallClockValidity::new().establish(TimeSourceClass::Monotonic),
            Err(WallClockError::SourceCannotEstablish)
        );
        assert!(!WallClockValidity::new().is_valid());
    }
}
