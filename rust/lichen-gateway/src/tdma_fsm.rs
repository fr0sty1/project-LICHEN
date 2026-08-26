//! TDMA CCP desync/rejoin FSM (spec 09 section 14.8).
//!
//! States and transitions follow the normative table in 14.8. Missed-beacon
//! desync uses strictly greater than three misses.

/// Coordinated-capacity node state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdmaState {
    /// Power-on / reset.
    Unjoined,
    /// Listening for an authenticated beacon.
    Acquiring,
    /// Assigned slot, transmitting.
    Synced,
    /// Missed beacons or RPL version increment.
    Drifting,
    /// Waiting for DAO-ACK and slot assignment.
    Rejoining,
}

/// Input that can change [`TdmaState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdmaEvent {
    /// Finish platform init (`lichen_node_init` equivalent).
    Init,
    /// Signature-verified beacon with acceptable stratum/version.
    ValidBeacon,
    /// Beacon received in the assigned slot while synced.
    BeaconInSlot,
    /// Count of consecutive missed beacons.
    MissedBeacons(u8),
    /// RPL DODAG version incremented.
    RplVersionIncrement,
    /// DAO-ACK carrying a slot assignment.
    DaoAckWithSlot,
    /// Beacon failed signature or stratum too low; MUST discard.
    InvalidBeacon,
}

impl TdmaState {
    /// Apply `event` and return the next state. Unknown pairs stay put.
    pub const fn on_event(self, event: TdmaEvent) -> Self {
        match (self, event) {
            (Self::Unjoined, TdmaEvent::Init) => Self::Acquiring,
            (Self::Acquiring, TdmaEvent::ValidBeacon) => Self::Synced,
            (Self::Synced, TdmaEvent::BeaconInSlot) => Self::Synced,
            (Self::Synced, TdmaEvent::MissedBeacons(n)) if n > 3 => Self::Drifting,
            (Self::Synced, TdmaEvent::RplVersionIncrement) => Self::Drifting,
            (Self::Drifting, TdmaEvent::ValidBeacon) => Self::Acquiring,
            (Self::Drifting, TdmaEvent::InvalidBeacon) => Self::Drifting,
            (Self::Drifting, TdmaEvent::DaoAckWithSlot) => Self::Synced,
            (Self::Rejoining, TdmaEvent::DaoAckWithSlot) => Self::Synced,
            (state, _) => state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_14_8_table_transitions() {
        assert_eq!(
            TdmaState::Unjoined.on_event(TdmaEvent::Init),
            TdmaState::Acquiring
        );
        assert_eq!(
            TdmaState::Acquiring.on_event(TdmaEvent::ValidBeacon),
            TdmaState::Synced
        );
        assert_eq!(
            TdmaState::Synced.on_event(TdmaEvent::BeaconInSlot),
            TdmaState::Synced
        );
        assert_eq!(
            TdmaState::Synced.on_event(TdmaEvent::MissedBeacons(3)),
            TdmaState::Synced
        );
        assert_eq!(
            TdmaState::Synced.on_event(TdmaEvent::MissedBeacons(4)),
            TdmaState::Drifting
        );
        assert_eq!(
            TdmaState::Synced.on_event(TdmaEvent::RplVersionIncrement),
            TdmaState::Drifting
        );
        assert_eq!(
            TdmaState::Drifting.on_event(TdmaEvent::ValidBeacon),
            TdmaState::Acquiring
        );
        assert_eq!(
            TdmaState::Drifting.on_event(TdmaEvent::InvalidBeacon),
            TdmaState::Drifting
        );
        assert_eq!(
            TdmaState::Rejoining.on_event(TdmaEvent::DaoAckWithSlot),
            TdmaState::Synced
        );
    }
}
