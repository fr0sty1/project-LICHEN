// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! GNSS pulse-per-second edge capture and wall-clock association.
//!
//! Hardware or an operating-system PPS source supplies monotonic timestamps
//! for rising edges. A GNSS decoder later associates the most recently
//! captured edge with the UTC second named by a time-valid GNSS message. This
//! module performs no I/O and allocates no memory, so the same state machine is
//! usable by embedded and gateway integrations.

/// Number of microseconds in one UTC second.
pub const MICROS_PER_SECOND: u64 = 1_000_000;

/// Result of capturing a monotonic PPS edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeCapture {
    /// No unassociated edge was pending.
    Captured,
    /// A newer edge replaced an edge for which no GNSS second was associated.
    ///
    /// The caller should expose this as a missed-association diagnostic. Only
    /// the newer edge remains eligible for association.
    ReplacedUnassociated { previous_edge_ns: u64 },
}

/// A validated mapping between a monotonic PPS edge and one UTC second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PpsAssociation {
    /// Monotonic timestamp captured at the PPS rising edge, in nanoseconds.
    pub edge_monotonic_ns: u64,
    /// Monotonic timestamp at which the corresponding GNSS message arrived.
    pub message_monotonic_ns: u64,
    /// UTC second named by the time-valid GNSS message.
    pub unix_second: u64,
    /// UTC timestamp at the PPS edge, in microseconds.
    pub unix_time_us: u64,
    /// Delay from PPS capture to receipt of the GNSS message.
    pub message_delay_ns: u64,
}

/// PPS configuration or association failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PpsError {
    /// Production clock state requires a non-zero firmware build epoch.
    ZeroBuildEpoch,
    /// The firmware build epoch cannot be represented in microseconds.
    BuildEpochOverflow,
    /// A zero-width association window cannot accept a delayed GNSS message.
    ZeroAssociationWindow,
    /// A captured edge did not advance the monotonic clock.
    EdgeOutOfOrder { previous_ns: u64, received_ns: u64 },
    /// No captured edge is waiting for a GNSS second.
    NoPendingEdge,
    /// A GNSS message receipt did not advance the monotonic receipt timestamp.
    MessageOutOfOrder { previous_ns: u64, received_ns: u64 },
    /// The GNSS message was timestamped before its candidate PPS edge.
    MessageBeforeEdge { edge_ns: u64, received_ns: u64 },
    /// The candidate edge is older than the configured association window.
    StaleEdge { age_ns: u64, maximum_age_ns: u64 },
    /// The GNSS second predates the immutable firmware build epoch.
    GnssSecondBelowBuildEpoch {
        unix_second: u64,
        build_epoch_second: u64,
    },
    /// The GNSS seconds did not advance between successful associations.
    GnssSecondOutOfOrder {
        previous_second: u64,
        received_second: u64,
    },
    /// Conversion of the GNSS second to microseconds overflowed.
    UnixTimeOverflow { unix_second: u64 },
}

/// Stateful PPS edge capture and GNSS-second association.
///
/// All monotonic values use a single caller-defined clock domain and are
/// expressed in nanoseconds, preserving sub-microsecond capture precision. The
/// caller must only submit GNSS messages whose
/// time-valid indication has already been checked. Position validity is
/// intentionally irrelevant to time association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PpsAssociator {
    firmware_build_epoch_s: u64,
    maximum_message_delay_ns: u64,
    last_edge_ns: Option<u64>,
    pending_edge_ns: Option<u64>,
    last_message_ns: Option<u64>,
    last_gnss_second: Option<u64>,
    last_association: Option<PpsAssociation>,
}

impl PpsAssociator {
    /// Construct empty association state.
    ///
    /// `firmware_build_epoch_s` is the immutable epoch-floor baseline from the
    /// time-provider policy. Integrations with authenticated board-provision
    /// metadata should pass the already evaluated effective floor instead.
    /// `maximum_message_delay_ns` is the inclusive stale-edge threshold.
    pub const fn new(
        firmware_build_epoch_s: u64,
        maximum_message_delay_ns: u64,
    ) -> Result<Self, PpsError> {
        if firmware_build_epoch_s == 0 {
            return Err(PpsError::ZeroBuildEpoch);
        }
        if firmware_build_epoch_s
            .checked_mul(MICROS_PER_SECOND)
            .is_none()
        {
            return Err(PpsError::BuildEpochOverflow);
        }
        if maximum_message_delay_ns == 0 {
            return Err(PpsError::ZeroAssociationWindow);
        }

        Ok(Self {
            firmware_build_epoch_s,
            maximum_message_delay_ns,
            last_edge_ns: None,
            pending_edge_ns: None,
            last_message_ns: None,
            last_gnss_second: None,
            last_association: None,
        })
    }

    /// Capture a PPS rising edge from the bound monotonic clock.
    ///
    /// Edge timestamps must increase strictly. A new edge replaces an older
    /// unassociated edge and reports that loss to the caller; this keeps the
    /// state bounded while ensuring a stale edge is never silently reused.
    pub fn capture_edge(&mut self, edge_monotonic_ns: u64) -> Result<EdgeCapture, PpsError> {
        if let Some(previous_ns) = self.last_edge_ns {
            if edge_monotonic_ns <= previous_ns {
                return Err(PpsError::EdgeOutOfOrder {
                    previous_ns,
                    received_ns: edge_monotonic_ns,
                });
            }
        }

        let outcome = match self.pending_edge_ns {
            Some(previous_edge_ns) => EdgeCapture::ReplacedUnassociated { previous_edge_ns },
            None => EdgeCapture::Captured,
        };
        self.last_edge_ns = Some(edge_monotonic_ns);
        self.pending_edge_ns = Some(edge_monotonic_ns);
        Ok(outcome)
    }

    /// Associate the pending PPS edge with a time-valid GNSS UTC second.
    ///
    /// The operation is transactional: every rejection leaves the pending
    /// edge and the last successful association unchanged. The configured
    /// maximum delay is inclusive.
    pub fn associate_gnss_second(
        &mut self,
        unix_second: u64,
        message_monotonic_ns: u64,
    ) -> Result<PpsAssociation, PpsError> {
        let edge_monotonic_ns = self.pending_edge_ns.ok_or(PpsError::NoPendingEdge)?;

        if let Some(previous_ns) = self.last_message_ns {
            if message_monotonic_ns <= previous_ns {
                return Err(PpsError::MessageOutOfOrder {
                    previous_ns,
                    received_ns: message_monotonic_ns,
                });
            }
        }
        let Some(message_delay_ns) = message_monotonic_ns.checked_sub(edge_monotonic_ns) else {
            return Err(PpsError::MessageBeforeEdge {
                edge_ns: edge_monotonic_ns,
                received_ns: message_monotonic_ns,
            });
        };
        if message_delay_ns > self.maximum_message_delay_ns {
            return Err(PpsError::StaleEdge {
                age_ns: message_delay_ns,
                maximum_age_ns: self.maximum_message_delay_ns,
            });
        }
        if unix_second < self.firmware_build_epoch_s {
            return Err(PpsError::GnssSecondBelowBuildEpoch {
                unix_second,
                build_epoch_second: self.firmware_build_epoch_s,
            });
        }
        if let Some(previous_second) = self.last_gnss_second {
            if unix_second <= previous_second {
                return Err(PpsError::GnssSecondOutOfOrder {
                    previous_second,
                    received_second: unix_second,
                });
            }
        }
        let unix_time_us = unix_second
            .checked_mul(MICROS_PER_SECOND)
            .ok_or(PpsError::UnixTimeOverflow { unix_second })?;

        let association = PpsAssociation {
            edge_monotonic_ns,
            message_monotonic_ns,
            unix_second,
            unix_time_us,
            message_delay_ns,
        };
        self.pending_edge_ns = None;
        self.last_message_ns = Some(message_monotonic_ns);
        self.last_gnss_second = Some(unix_second);
        self.last_association = Some(association);
        Ok(association)
    }

    /// Return the edge currently awaiting GNSS association.
    #[must_use]
    pub const fn pending_edge_ns(&self) -> Option<u64> {
        self.pending_edge_ns
    }

    /// Return the most recent successful association.
    #[must_use]
    pub const fn last_association(&self) -> Option<PpsAssociation> {
        self.last_association
    }

    /// Discard a pending edge and return its monotonic timestamp.
    ///
    /// This is useful after a stale or invalid GNSS message. Ordering history
    /// is retained, so a later capture must still advance the clock.
    pub fn discard_pending_edge(&mut self) -> Option<u64> {
        self.pending_edge_ns.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD_EPOCH_S: u64 = 1_704_067_200;

    fn associator() -> PpsAssociator {
        PpsAssociator::new(BUILD_EPOCH_S, 500_000).unwrap()
    }

    #[test]
    fn associates_edge_with_valid_gnss_second() {
        let mut state = associator();
        assert_eq!(state.capture_edge(10_000_000), Ok(EdgeCapture::Captured));

        let association = state
            .associate_gnss_second(BUILD_EPOCH_S + 4, 10_125_123)
            .unwrap();
        assert_eq!(association.edge_monotonic_ns, 10_000_000);
        assert_eq!(association.message_delay_ns, 125_123);
        assert_eq!(association.unix_time_us, 1_704_067_204_000_000);
        assert_eq!(state.pending_edge_ns(), None);
        assert_eq!(state.last_association(), Some(association));
    }

    #[test]
    fn configuration_rejects_invalid_epoch_and_window() {
        assert_eq!(PpsAssociator::new(0, 1), Err(PpsError::ZeroBuildEpoch));
        assert_eq!(
            PpsAssociator::new(u64::MAX, 1),
            Err(PpsError::BuildEpochOverflow)
        );
        assert_eq!(
            PpsAssociator::new(BUILD_EPOCH_S, 0),
            Err(PpsError::ZeroAssociationWindow)
        );
    }

    #[test]
    fn edge_capture_is_strictly_monotonic_and_preserves_state_on_error() {
        let mut state = associator();
        state.capture_edge(20).unwrap();
        assert_eq!(
            state.capture_edge(20),
            Err(PpsError::EdgeOutOfOrder {
                previous_ns: 20,
                received_ns: 20,
            })
        );
        assert_eq!(
            state.capture_edge(19),
            Err(PpsError::EdgeOutOfOrder {
                previous_ns: 20,
                received_ns: 19,
            })
        );
        assert_eq!(state.pending_edge_ns(), Some(20));
    }

    #[test]
    fn replacing_unassociated_edge_is_observable_and_uses_newest_edge() {
        let mut state = associator();
        state.capture_edge(1_000_000).unwrap();
        assert_eq!(
            state.capture_edge(2_000_000),
            Ok(EdgeCapture::ReplacedUnassociated {
                previous_edge_ns: 1_000_000,
            })
        );
        let association = state
            .associate_gnss_second(BUILD_EPOCH_S, 2_100_000)
            .unwrap();
        assert_eq!(association.edge_monotonic_ns, 2_000_000);
    }

    #[test]
    fn missing_early_and_stale_edges_are_rejected_without_consumption() {
        let mut state = associator();
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S, 1),
            Err(PpsError::NoPendingEdge)
        );

        state.capture_edge(1_000_000).unwrap();
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S, 999_999),
            Err(PpsError::MessageBeforeEdge {
                edge_ns: 1_000_000,
                received_ns: 999_999,
            })
        );
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S, 1_500_001),
            Err(PpsError::StaleEdge {
                age_ns: 500_001,
                maximum_age_ns: 500_000,
            })
        );
        assert_eq!(state.pending_edge_ns(), Some(1_000_000));

        let boundary = state
            .associate_gnss_second(BUILD_EPOCH_S, 1_500_000)
            .unwrap();
        assert_eq!(boundary.message_delay_ns, 500_000);
    }

    #[test]
    fn build_epoch_and_unix_microsecond_overflow_fail_closed() {
        let mut state = associator();
        state.capture_edge(100).unwrap();
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S - 1, 101),
            Err(PpsError::GnssSecondBelowBuildEpoch {
                unix_second: BUILD_EPOCH_S - 1,
                build_epoch_second: BUILD_EPOCH_S,
            })
        );
        assert_eq!(state.pending_edge_ns(), Some(100));

        let maximum_second = u64::MAX / MICROS_PER_SECOND;
        let mut large_epoch = PpsAssociator::new(maximum_second, 10).unwrap();
        large_epoch.capture_edge(200).unwrap();
        assert_eq!(
            large_epoch.associate_gnss_second(maximum_second + 1, 201),
            Err(PpsError::UnixTimeOverflow {
                unix_second: maximum_second + 1,
            })
        );
        assert_eq!(large_epoch.pending_edge_ns(), Some(200));
    }

    #[test]
    fn successful_associations_require_increasing_messages_and_seconds() {
        let mut state = associator();
        state.capture_edge(1_000).unwrap();
        state
            .associate_gnss_second(BUILD_EPOCH_S + 1, 1_100)
            .unwrap();

        state.capture_edge(2_000).unwrap();
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S + 2, 1_100),
            Err(PpsError::MessageOutOfOrder {
                previous_ns: 1_100,
                received_ns: 1_100,
            })
        );
        assert_eq!(
            state.associate_gnss_second(BUILD_EPOCH_S + 1, 2_100),
            Err(PpsError::GnssSecondOutOfOrder {
                previous_second: BUILD_EPOCH_S + 1,
                received_second: BUILD_EPOCH_S + 1,
            })
        );
        assert_eq!(state.pending_edge_ns(), Some(2_000));

        let next = state
            .associate_gnss_second(BUILD_EPOCH_S + 2, 2_100)
            .unwrap();
        assert_eq!(next.unix_second, BUILD_EPOCH_S + 2);
    }

    #[test]
    fn association_projects_deterministically_to_sfn() {
        let mut state = associator();
        state.capture_edge(9_000_000).unwrap();
        let association = state
            .associate_gnss_second(BUILD_EPOCH_S + 4, 9_100_000)
            .unwrap();

        assert_eq!(
            lichen_core::sfn_from_unix_time(
                association.unix_time_us,
                lichen_core::SUPERFRAME_DURATION_US,
                lichen_core::GNSS_EPOCH_BASE_US,
            ),
            2
        );
    }

    #[test]
    fn pending_edge_can_be_explicitly_discarded() {
        let mut state = associator();
        state.capture_edge(42).unwrap();
        assert_eq!(state.discard_pending_edge(), Some(42));
        assert_eq!(state.discard_pending_edge(), None);
        assert_eq!(state.pending_edge_ns(), None);
    }
}
