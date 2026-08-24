//! Desynchronization Recovery State Machines (spec §14.7-14.8, CCP-13a).
//!
//! Provides FSMs for handling sync loss and recovery in LICHEN TDMA networks.
//!
//! # FSMs
//!
//! - [`DesyncFSM`]: Simple 3-state FSM for §14.7 sync recovery
//! - [`CcpFSM`]: 4-state FSM for CCP-13a desync/rejoin robustness (§14.8)

/// Desync recovery constants matching Python DESYNC_CONSTANTS.
pub mod constants {
    /// Minimum listen period in seconds.
    pub const LISTEN_PERIOD_MIN_S: u32 = 30;
    /// Maximum listen period in seconds.
    pub const LISTEN_PERIOD_MAX_S: u32 = 60;
    /// Delay per node heard in seconds.
    pub const DELAY_PER_NODE_S: u32 = 5;
    /// Maximum startup delay in seconds.
    pub const MAX_STARTUP_DELAY_S: u32 = 300;
}

/// Compute initial startup delay based on nodes heard.
///
/// Formula: min(MAX_STARTUP_DELAY, nodes_heard * DELAY_PER_NODE)
///
/// # Example
///
/// ```
/// use lichen_core::desync::initial_startup_delay;
///
/// assert_eq!(initial_startup_delay(0), 0);
/// assert_eq!(initial_startup_delay(10), 50);
/// assert_eq!(initial_startup_delay(100), 300); // Capped at MAX_STARTUP_DELAY
/// ```
pub fn initial_startup_delay(nodes_heard: u32) -> u32 {
    let computed = nodes_heard.saturating_mul(constants::DELAY_PER_NODE_S);
    computed.min(constants::MAX_STARTUP_DELAY_S)
}

/// Desync recovery states (§14.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DesyncState {
    /// Node is synchronized with the network.
    #[default]
    Synced,
    /// Node has lost sync (detected via SFN wrap or timeout).
    Desynced,
    /// Node is attempting to recover sync by listening for beacons.
    Recovering,
}

/// Desynchronization Recovery FSM (§14.7 table).
///
/// State transitions:
/// - SYNCED -> DESYNCED: on SFN wrap with invalid time
/// - DESYNCED -> RECOVERING: on first valid beacon
/// - RECOVERING -> SYNCED: after 3 consecutive valid beacons
/// - RECOVERING -> DESYNCED: on invalid beacon
///
/// # Example
///
/// ```
/// use lichen_core::desync::{DesyncFSM, DesyncState};
///
/// let mut fsm = DesyncFSM::new();
/// assert_eq!(fsm.state(), DesyncState::Synced);
///
/// // Lose sync on SFN wrap
/// fsm.on_sfn_wrap(false);
/// assert_eq!(fsm.state(), DesyncState::Desynced);
///
/// // Start recovery on valid beacon
/// fsm.on_beacon(true);
/// assert_eq!(fsm.state(), DesyncState::Recovering);
///
/// // Need 3 consecutive valid beacons to sync
/// fsm.on_beacon(true);
/// fsm.on_beacon(true);
/// assert_eq!(fsm.state(), DesyncState::Synced);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DesyncFSM {
    state: DesyncState,
    consecutive_valid: u8,
}

impl Default for DesyncFSM {
    fn default() -> Self {
        Self::new()
    }
}

impl DesyncFSM {
    /// Create a new FSM in the Synced state.
    pub const fn new() -> Self {
        Self {
            state: DesyncState::Synced,
            consecutive_valid: 0,
        }
    }

    /// Get the current state.
    pub const fn state(&self) -> DesyncState {
        self.state
    }

    /// Get the current consecutive valid beacon count.
    pub const fn consecutive_valid(&self) -> u8 {
        self.consecutive_valid
    }

    /// Handle SFN wrap event.
    ///
    /// If time is invalid and currently synced, transitions to Desynced.
    pub fn on_sfn_wrap(&mut self, time_valid: bool) -> DesyncState {
        if !time_valid && self.state == DesyncState::Synced {
            self.state = DesyncState::Desynced;
            self.consecutive_valid = 0;
        }
        self.state
    }

    /// Handle beacon reception.
    ///
    /// - DESYNCED + valid beacon -> RECOVERING (start counting)
    /// - RECOVERING + valid beacon -> count++; if count >= 3 -> SYNCED
    /// - RECOVERING + invalid beacon -> DESYNCED (reset)
    pub fn on_beacon(&mut self, valid: bool) -> DesyncState {
        match self.state {
            DesyncState::Desynced if valid => {
                self.state = DesyncState::Recovering;
                self.consecutive_valid = 1;
            }
            DesyncState::Recovering => {
                if valid {
                    self.consecutive_valid += 1;
                    if self.consecutive_valid >= 3 {
                        self.state = DesyncState::Synced;
                        self.consecutive_valid = 0;
                    }
                } else {
                    self.state = DesyncState::Desynced;
                    self.consecutive_valid = 0;
                }
            }
            _ => {}
        }
        self.state
    }
}

/// CCP desync recovery states (spec §14.8, 2a.6, CCP-13a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcpState {
    /// Not synchronized to any DODAG.
    #[default]
    Unjoined,
    /// Synchronized and can transmit.
    Joined,
    /// Sync stale, approaching desync threshold.
    Drift,
    /// Actively attempting to regain sync.
    Recover,
}

/// CCP desync recovery FSM (spec 2a.6, CCP-13a).
///
/// State transitions:
/// - UNJOINED -> JOINED: on valid beacon reception and DODAG join
/// - JOINED -> DRIFT: on sync timeout (T_DRIFT_WARN elapsed)
/// - DRIFT -> JOINED: on valid beacon received within window
/// - DRIFT -> RECOVER: on T_DRIFT_MAX timeout
/// - RECOVER -> JOINED: on successful resync (valid beacon)
/// - RECOVER -> UNJOINED: on T_GIVE_UP timeout
///
/// # Example
///
/// ```
/// use lichen_core::desync::{CcpFSM, CcpState};
///
/// let mut fsm = CcpFSM::new();
/// assert_eq!(fsm.state(), CcpState::Unjoined);
///
/// // Join network
/// fsm.on_join();
/// assert_eq!(fsm.state(), CcpState::Joined);
///
/// // Sync becomes stale
/// fsm.on_drift_warn();
/// assert_eq!(fsm.state(), CcpState::Drift);
///
/// // Valid beacon recovers sync
/// fsm.on_beacon(true);
/// assert_eq!(fsm.state(), CcpState::Joined);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CcpFSM {
    state: CcpState,
}

impl Default for CcpFSM {
    fn default() -> Self {
        Self::new()
    }
}

impl CcpFSM {
    /// Create a new FSM in the Unjoined state.
    pub const fn new() -> Self {
        Self {
            state: CcpState::Unjoined,
        }
    }

    /// Get the current state.
    pub const fn state(&self) -> CcpState {
        self.state
    }

    /// Node joined DODAG with valid beacon.
    ///
    /// Transitions: UNJOINED -> JOINED
    pub fn on_join(&mut self) -> CcpState {
        if self.state == CcpState::Unjoined {
            self.state = CcpState::Joined;
        }
        self.state
    }

    /// Beacon received; valid indicates MIC and timing check passed.
    ///
    /// Transitions: DRIFT/RECOVER + valid -> JOINED
    pub fn on_beacon(&mut self, valid: bool) -> CcpState {
        if valid && matches!(self.state, CcpState::Drift | CcpState::Recover) {
            self.state = CcpState::Joined;
        }
        self.state
    }

    /// T_DRIFT_WARN timer expired (sync becoming stale).
    ///
    /// Transitions: JOINED -> DRIFT
    pub fn on_drift_warn(&mut self) -> CcpState {
        if self.state == CcpState::Joined {
            self.state = CcpState::Drift;
        }
        self.state
    }

    /// T_DRIFT_MAX timer expired (must attempt recovery).
    ///
    /// Transitions: DRIFT -> RECOVER
    pub fn on_drift_max(&mut self) -> CcpState {
        if self.state == CcpState::Drift {
            self.state = CcpState::Recover;
        }
        self.state
    }

    /// T_GIVE_UP timer expired (recovery failed).
    ///
    /// Transitions: RECOVER -> UNJOINED
    pub fn on_give_up(&mut self) -> CcpState {
        if self.state == CcpState::Recover {
            self.state = CcpState::Unjoined;
        }
        self.state
    }

    /// Explicit leave or disconnect.
    ///
    /// Transitions: any -> UNJOINED
    pub fn on_leave(&mut self) -> CcpState {
        self.state = CcpState::Unjoined;
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DesyncFSM tests ---

    #[test]
    fn test_desync_fsm_initial_state() {
        let fsm = DesyncFSM::new();
        assert_eq!(fsm.state(), DesyncState::Synced);
        assert_eq!(fsm.consecutive_valid(), 0);
    }

    #[test]
    fn test_desync_fsm_sfn_wrap_invalid_time() {
        let mut fsm = DesyncFSM::new();
        let state = fsm.on_sfn_wrap(false);
        assert_eq!(state, DesyncState::Desynced);
    }

    #[test]
    fn test_desync_fsm_sfn_wrap_valid_time() {
        let mut fsm = DesyncFSM::new();
        let state = fsm.on_sfn_wrap(true);
        assert_eq!(state, DesyncState::Synced);
    }

    #[test]
    fn test_desync_fsm_recovery_flow() {
        let mut fsm = DesyncFSM::new();

        // Lose sync
        fsm.on_sfn_wrap(false);
        assert_eq!(fsm.state(), DesyncState::Desynced);

        // First valid beacon -> Recovering
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), DesyncState::Recovering);
        assert_eq!(fsm.consecutive_valid(), 1);

        // Second valid beacon
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), DesyncState::Recovering);
        assert_eq!(fsm.consecutive_valid(), 2);

        // Third valid beacon -> Synced
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), DesyncState::Synced);
        assert_eq!(fsm.consecutive_valid(), 0);
    }

    #[test]
    fn test_desync_fsm_invalid_beacon_resets_recovery() {
        let mut fsm = DesyncFSM::new();

        fsm.on_sfn_wrap(false);
        fsm.on_beacon(true); // -> Recovering
        fsm.on_beacon(true); // count = 2
        fsm.on_beacon(false); // -> Desynced

        assert_eq!(fsm.state(), DesyncState::Desynced);
        assert_eq!(fsm.consecutive_valid(), 0);
    }

    #[test]
    fn test_desync_fsm_beacon_ignored_when_synced() {
        let mut fsm = DesyncFSM::new();
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), DesyncState::Synced);
        fsm.on_beacon(false);
        assert_eq!(fsm.state(), DesyncState::Synced);
    }

    #[test]
    fn test_desync_fsm_invalid_beacon_ignored_when_desynced() {
        let mut fsm = DesyncFSM::new();
        fsm.on_sfn_wrap(false);
        fsm.on_beacon(false);
        assert_eq!(fsm.state(), DesyncState::Desynced);
    }

    // --- CcpFSM tests ---

    #[test]
    fn test_ccp_fsm_initial_state() {
        let fsm = CcpFSM::new();
        assert_eq!(fsm.state(), CcpState::Unjoined);
    }

    #[test]
    fn test_ccp_fsm_on_join() {
        let mut fsm = CcpFSM::new();
        let state = fsm.on_join();
        assert_eq!(state, CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_on_join_idempotent() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_join();
        assert_eq!(fsm.state(), CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_drift_flow() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();

        fsm.on_drift_warn();
        assert_eq!(fsm.state(), CcpState::Drift);

        // Valid beacon recovers
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_recovery_flow() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_drift_warn();
        fsm.on_drift_max();
        assert_eq!(fsm.state(), CcpState::Recover);

        // Valid beacon recovers
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_give_up_flow() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_drift_warn();
        fsm.on_drift_max();
        fsm.on_give_up();
        assert_eq!(fsm.state(), CcpState::Unjoined);
    }

    #[test]
    fn test_ccp_fsm_on_leave() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_leave();
        assert_eq!(fsm.state(), CcpState::Unjoined);
    }

    #[test]
    fn test_ccp_fsm_invalid_beacon_no_transition() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_drift_warn();

        fsm.on_beacon(false);
        assert_eq!(fsm.state(), CcpState::Drift);
    }

    #[test]
    fn test_ccp_fsm_beacon_no_effect_when_joined() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), CcpState::Joined);
        fsm.on_beacon(false);
        assert_eq!(fsm.state(), CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_beacon_no_effect_when_unjoined() {
        let mut fsm = CcpFSM::new();
        fsm.on_beacon(true);
        assert_eq!(fsm.state(), CcpState::Unjoined);
    }

    #[test]
    fn test_ccp_fsm_drift_warn_only_from_joined() {
        let mut fsm = CcpFSM::new();
        fsm.on_drift_warn();
        assert_eq!(fsm.state(), CcpState::Unjoined);

        fsm.on_join();
        fsm.on_drift_warn();
        fsm.on_drift_warn(); // No effect in Drift
        assert_eq!(fsm.state(), CcpState::Drift);
    }

    #[test]
    fn test_ccp_fsm_drift_max_only_from_drift() {
        let mut fsm = CcpFSM::new();
        fsm.on_drift_max();
        assert_eq!(fsm.state(), CcpState::Unjoined);

        fsm.on_join();
        fsm.on_drift_max(); // No effect in Joined
        assert_eq!(fsm.state(), CcpState::Joined);
    }

    #[test]
    fn test_ccp_fsm_give_up_only_from_recover() {
        let mut fsm = CcpFSM::new();
        fsm.on_join();
        fsm.on_give_up(); // No effect in Joined
        assert_eq!(fsm.state(), CcpState::Joined);

        fsm.on_drift_warn();
        fsm.on_give_up(); // No effect in Drift
        assert_eq!(fsm.state(), CcpState::Drift);
    }

    // --- initial_startup_delay tests ---

    #[test]
    fn test_initial_startup_delay_zero() {
        assert_eq!(initial_startup_delay(0), 0);
    }

    #[test]
    fn test_initial_startup_delay_normal() {
        assert_eq!(initial_startup_delay(10), 50);
        assert_eq!(initial_startup_delay(20), 100);
    }

    #[test]
    fn test_initial_startup_delay_capped() {
        assert_eq!(initial_startup_delay(60), 300);
        assert_eq!(initial_startup_delay(100), 300);
        assert_eq!(initial_startup_delay(1000), 300);
    }
}
