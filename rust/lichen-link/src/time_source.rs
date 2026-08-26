//! Time source class (spec 09 section 14.6).
//!
//! Wire strings match Python `lichen.timing.time_sync.SourceClass`.

/// Provenance class of a wall-clock or monotonic sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeSourceClass {
    /// GNSS receiver (GPS/Galileo/etc.).
    Gnss,
    /// Authenticated network time (NTS, Roughtime, SNTP).
    Network,
    /// Local-client / phone / gpsd.
    LocalClient,
    /// Operator-provisioned static time.
    Manual,
    /// On-board real-time clock.
    InternalRtc,
    /// Monotonic uptime; cannot establish wall clock.
    Monotonic,
}

impl TimeSourceClass {
    /// Canonical wire / JSON string (Python `SourceClass` values).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gnss => "GNSS",
            Self::Network => "Network",
            Self::LocalClient => "Local-client",
            Self::Manual => "Manual/static",
            Self::InternalRtc => "Internal RTC",
            Self::Monotonic => "Monotonic",
        }
    }

    /// Parse a canonical source-class string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "GNSS" => Some(Self::Gnss),
            "Network" => Some(Self::Network),
            "Local-client" => Some(Self::LocalClient),
            "Manual/static" => Some(Self::Manual),
            "Internal RTC" => Some(Self::InternalRtc),
            "Monotonic" => Some(Self::Monotonic),
            _ => None,
        }
    }

    /// True if this class can originate a wall-clock sample.
    pub const fn can_establish_wall_clock(self) -> bool {
        !matches!(self, Self::Monotonic)
    }

    /// All classes in spec order.
    pub const ALL: [Self; 6] = [
        Self::Gnss,
        Self::Network,
        Self::LocalClient,
        Self::Manual,
        Self::InternalRtc,
        Self::Monotonic,
    ];
}

impl core::fmt::Display for TimeSourceClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_python_wire_strings() {
        let expected = [
            (TimeSourceClass::Gnss, "GNSS"),
            (TimeSourceClass::Network, "Network"),
            (TimeSourceClass::LocalClient, "Local-client"),
            (TimeSourceClass::Manual, "Manual/static"),
            (TimeSourceClass::InternalRtc, "Internal RTC"),
            (TimeSourceClass::Monotonic, "Monotonic"),
        ];
        assert_eq!(TimeSourceClass::ALL.len(), expected.len());
        for (class, wire) in expected {
            assert_eq!(class.as_str(), wire);
            assert_eq!(TimeSourceClass::from_str(wire), Some(class));
        }
        assert_eq!(TimeSourceClass::from_str("gps"), None);
        assert_eq!(TimeSourceClass::from_str(""), None);
    }

    #[test]
    fn monotonic_cannot_establish_wall_clock() {
        assert!(!TimeSourceClass::Monotonic.can_establish_wall_clock());
        for class in TimeSourceClass::ALL {
            if class != TimeSourceClass::Monotonic {
                assert!(class.can_establish_wall_clock());
            }
        }
    }
}
