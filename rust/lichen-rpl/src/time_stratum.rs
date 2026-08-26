//! Time-stratum and relay-hop tracking for the DIO Time Option.
//!
//! LICHEN's wire stratum is a source-quality value: zero means unsynchronized,
//! and values one through four represent increasing quality. It is not an NTP
//! hop count and does not authenticate or identify a source. Relay distance is
//! therefore tracked separately and never changes the advertised quality.

/// Time quality advertised in a LICHEN DIO Time Option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TimeStratum {
    /// No valid wall-clock source. A corresponding DIO timestamp must be zero.
    NoSync = 0,
    /// Conservative synchronized time.
    ConservativeSync = 1,
    /// Roughtime-backed network time.
    Roughtime = 2,
    /// NTS-backed network time.
    Nts = 3,
    /// GNSS or verified gpsd time.
    GnssGpsd = 4,
}

impl TimeStratum {
    /// Return the canonical one-octet wire value.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    /// Whether this value represents usable synchronized time.
    #[must_use]
    pub const fn is_synchronized(self) -> bool {
        !matches!(self, Self::NoSync)
    }
}

impl TryFrom<u8> for TimeStratum {
    type Error = StratumError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoSync),
            1 => Ok(Self::ConservativeSync),
            2 => Ok(Self::Roughtime),
            3 => Ok(Self::Nts),
            4 => Ok(Self::GnssGpsd),
            value => Err(StratumError::InvalidWireValue(value)),
        }
    }
}

/// Failure to construct valid time-stratum tracking state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StratumError {
    /// The encoded stratum is outside the canonical range 0 through 4.
    InvalidWireValue(u8),
    /// Unsynchronized time cannot be treated as an authoritative source.
    UnsynchronizedAuthority,
    /// The separately tracked relay-hop counter cannot be represented.
    RelayHopOverflow,
}

/// Stratum state propagated from an already authenticated time authority.
///
/// This type deliberately does not decide whether a DIO signer is authorized
/// to control the clock. Callers must perform link authentication, signer
/// authorization, source/provenance validation, replay checks, and epoch-floor
/// validation before constructing or replacing authoritative state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StratumTracker {
    stratum: TimeStratum,
    hops_from_authority: u8,
}

impl StratumTracker {
    /// Construct unsynchronized initial state.
    #[must_use]
    pub const fn unsynchronized() -> Self {
        Self {
            stratum: TimeStratum::NoSync,
            hops_from_authority: 0,
        }
    }

    /// Start tracking an already validated authoritative time source.
    pub const fn authoritative(stratum: TimeStratum) -> Result<Self, StratumError> {
        if !stratum.is_synchronized() {
            return Err(StratumError::UnsynchronizedAuthority);
        }
        Ok(Self {
            stratum,
            hops_from_authority: 0,
        })
    }

    /// Derive state for the next authenticated relay hop.
    ///
    /// Relay distance increases by one. The source-quality stratum is retained:
    /// changing it would incorrectly relabel GNSS, NTS, or Roughtime provenance.
    pub const fn relayed_from(parent: Self) -> Result<Self, StratumError> {
        if !parent.stratum.is_synchronized() {
            return Err(StratumError::UnsynchronizedAuthority);
        }
        let Some(hops_from_authority) = parent.hops_from_authority.checked_add(1) else {
            return Err(StratumError::RelayHopOverflow);
        };
        Ok(Self {
            stratum: parent.stratum,
            hops_from_authority,
        })
    }

    /// Current advertised source-quality stratum.
    #[must_use]
    pub const fn stratum(self) -> TimeStratum {
        self.stratum
    }

    /// Number of authenticated relay hops from the original authority.
    #[must_use]
    pub const fn hops_from_authority(self) -> u8 {
        self.hops_from_authority
    }

    /// Clear all synchronized state.
    pub fn clear(&mut self) {
        *self = Self::unsynchronized();
    }
}

impl Default for StratumTracker {
    fn default() -> Self {
        Self::unsynchronized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_wire_values_round_trip() {
        let strata = [
            TimeStratum::NoSync,
            TimeStratum::ConservativeSync,
            TimeStratum::Roughtime,
            TimeStratum::Nts,
            TimeStratum::GnssGpsd,
        ];
        for (wire, stratum) in (0_u8..=4).zip(strata) {
            assert_eq!(TimeStratum::try_from(wire), Ok(stratum));
            assert_eq!(stratum.wire_value(), wire);
        }
        assert_eq!(
            TimeStratum::try_from(5),
            Err(StratumError::InvalidWireValue(5))
        );
        assert_eq!(
            TimeStratum::try_from(u8::MAX),
            Err(StratumError::InvalidWireValue(u8::MAX))
        );
    }

    #[test]
    fn authoritative_source_starts_at_zero_hops() {
        let tracker = StratumTracker::authoritative(TimeStratum::GnssGpsd).unwrap();
        assert_eq!(tracker.stratum(), TimeStratum::GnssGpsd);
        assert_eq!(tracker.hops_from_authority(), 0);
    }

    #[test]
    fn each_relay_increments_hops_without_relabeling_quality() {
        let mut tracker = StratumTracker::authoritative(TimeStratum::Nts).unwrap();
        for expected_hops in 1..=4 {
            tracker = StratumTracker::relayed_from(tracker).unwrap();
            assert_eq!(tracker.stratum(), TimeStratum::Nts);
            assert_eq!(tracker.hops_from_authority(), expected_hops);
        }
    }

    #[test]
    fn unsynchronized_state_cannot_be_an_authority_or_relay() {
        assert_eq!(
            StratumTracker::authoritative(TimeStratum::NoSync),
            Err(StratumError::UnsynchronizedAuthority)
        );
        assert_eq!(
            StratumTracker::relayed_from(StratumTracker::unsynchronized()),
            Err(StratumError::UnsynchronizedAuthority)
        );
    }

    #[test]
    fn relay_hop_overflow_fails_closed() {
        let tracker = StratumTracker {
            stratum: TimeStratum::ConservativeSync,
            hops_from_authority: u8::MAX,
        };
        assert_eq!(
            StratumTracker::relayed_from(tracker),
            Err(StratumError::RelayHopOverflow)
        );
    }

    #[test]
    fn clear_returns_to_canonical_unsynchronized_state() {
        let mut tracker = StratumTracker::authoritative(TimeStratum::Roughtime).unwrap();
        tracker = StratumTracker::relayed_from(tracker).unwrap();
        tracker.clear();
        assert_eq!(tracker, StratumTracker::default());
        assert_eq!(tracker.stratum(), TimeStratum::NoSync);
        assert_eq!(tracker.hops_from_authority(), 0);
    }
}
