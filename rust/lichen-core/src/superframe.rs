//! GCP-6.1 Superframe Synchronization (spec/08-gateway-coordination.md Section 6.1).
//!
//! Provides GPS-based absolute time sync, time master election (lowest IID),
//! backbone CoAP time sync for non-GPS gateways, and configurable superframe duration.
//!
//! # Time Sources
//!
//! - **GPS**: Gateways with GPS use GPS epoch for absolute time. Superframe is aligned
//!   to UTC minute boundaries (configurable duration, default 60s).
//!
//! - **Backbone election**: Non-GPS gateways elect a time master. The gateway with
//!   the lowest IID (Interface Identifier, as unsigned big-endian u64) wins. Other
//!   gateways sync via backbone CoAP.
//!
//! # Formulas
//!
//! - `superframe_id = unix_timestamp / superframe_duration_s`
//! - `current_slot = (timestamp - superframe_start) % superframe_duration_s`
//! - `slots_remaining = superframe_duration_s - current_slot`

/// Default superframe duration in seconds (aligned to UTC minute boundary).
pub const DEFAULT_SUPERFRAME_DURATION_S: u32 = 60;

/// Default slots per superframe.
pub const DEFAULT_SLOTS_PER_SUPERFRAME: u8 = 60;

/// Time source for superframe synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// GPS epoch provides absolute time.
    Gps,
    /// Backbone election: lowest IID is time master.
    BackboneElect,
    /// Unsynchronized / no time source available.
    Unsynchronized,
}

/// Superframe timing configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperframeConfig {
    /// Superframe duration in seconds.
    pub duration_s: u32,
    /// Number of slots per superframe.
    pub slots_per_superframe: u8,
}

impl Default for SuperframeConfig {
    fn default() -> Self {
        Self {
            duration_s: DEFAULT_SUPERFRAME_DURATION_S,
            slots_per_superframe: DEFAULT_SLOTS_PER_SUPERFRAME,
        }
    }
}

impl SuperframeConfig {
    /// Create a new superframe configuration.
    pub const fn new(duration_s: u32, slots_per_superframe: u8) -> Self {
        Self {
            duration_s,
            slots_per_superframe,
        }
    }

    /// Calculate slot duration in milliseconds.
    ///
    /// Returns 0 if slots_per_superframe is 0.
    pub fn slot_duration_ms(&self) -> u32 {
        if self.slots_per_superframe == 0 {
            return 0;
        }
        (self.duration_s * 1000) / self.slots_per_superframe as u32
    }
}

/// Compute the superframe ID from a Unix timestamp.
///
/// Formula: `superframe_id = unix_timestamp / superframe_duration_s`
///
/// Returns 0 if `superframe_duration_s` is 0 (avoids division by zero).
///
/// # Example
///
/// ```
/// use lichen_core::superframe::superframe_id;
///
/// let unix_ts = 1720008000u64; // 2024-07-03T12:00:00Z
/// let id = superframe_id(unix_ts, 60);
/// assert_eq!(id, 28666800);
/// ```
pub fn superframe_id(unix_timestamp: u64, superframe_duration_s: u32) -> u64 {
    if superframe_duration_s == 0 {
        return 0;
    }
    unix_timestamp / superframe_duration_s as u64
}

/// Compute the start timestamp of a superframe.
///
/// Formula: `superframe_start = superframe_id * superframe_duration_s`
///
/// # Example
///
/// ```
/// use lichen_core::superframe::superframe_start;
///
/// let start = superframe_start(28666800, 60);
/// assert_eq!(start, 1720008000);
/// ```
pub fn superframe_start(superframe_id: u64, superframe_duration_s: u32) -> u64 {
    superframe_id * superframe_duration_s as u64
}

/// Calculate the current slot within a superframe.
///
/// Formula: `current_slot = (timestamp - superframe_start) % superframe_duration_s`
///
/// The result is in slot units where slot duration = superframe_duration_s / slots_per_superframe.
///
/// Returns 0 if `slots_per_superframe` is 0.
///
/// # Example
///
/// ```
/// use lichen_core::superframe::current_slot;
///
/// // 25 seconds into a 60-slot superframe where each slot is 1 second
/// let slot = current_slot(1720008025, 1720008000, 60, 60);
/// assert_eq!(slot, 25);
/// ```
pub fn current_slot(
    unix_timestamp: u64,
    superframe_start: u64,
    superframe_duration_s: u32,
    slots_per_superframe: u8,
) -> u8 {
    if slots_per_superframe == 0 || superframe_duration_s == 0 {
        return 0;
    }
    if unix_timestamp < superframe_start {
        return 0;
    }
    let elapsed = unix_timestamp - superframe_start;
    let slot_duration = superframe_duration_s as u64 / slots_per_superframe as u64;
    if slot_duration == 0 {
        return 0;
    }
    // Ensure we stay within valid slot range
    let slot = elapsed / slot_duration;
    if slot >= slots_per_superframe as u64 {
        slots_per_superframe.saturating_sub(1)
    } else {
        slot as u8
    }
}

/// Calculate slots remaining in the current superframe.
///
/// # Example
///
/// ```
/// use lichen_core::superframe::slots_remaining;
///
/// let remaining = slots_remaining(25, 60);
/// assert_eq!(remaining, 35);
/// ```
pub fn slots_remaining(current_slot: u8, slots_per_superframe: u8) -> u8 {
    if current_slot >= slots_per_superframe {
        return 0;
    }
    slots_per_superframe - current_slot
}

/// Compare two IIDs for time master election.
///
/// Per GCP-6.1, the gateway with the lowest IID wins. IIDs are compared as
/// unsigned big-endian 64-bit integers.
///
/// Returns:
/// - `Ordering::Less` if `iid_a` should be time master (lower IID)
/// - `Ordering::Greater` if `iid_b` should be time master (lower IID)
/// - `Ordering::Equal` if IIDs are equal
///
/// # Example
///
/// ```
/// use lichen_core::superframe::compare_iid_for_election;
/// use core::cmp::Ordering;
///
/// let iid_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
/// let iid_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
///
/// // iid_a (0x0011223344556677) < iid_b (0xAABBCCDDEEFF0011)
/// assert_eq!(compare_iid_for_election(&iid_a, &iid_b), Ordering::Less);
/// ```
pub fn compare_iid_for_election(iid_a: &[u8; 8], iid_b: &[u8; 8]) -> core::cmp::Ordering {
    let a = u64::from_be_bytes(*iid_a);
    let b = u64::from_be_bytes(*iid_b);
    a.cmp(&b)
}

/// Convert an IID to its decimal representation for comparison.
///
/// Per GCP-6.1, IIDs are treated as unsigned big-endian 64-bit integers.
///
/// # Example
///
/// ```
/// use lichen_core::superframe::iid_to_u64;
///
/// let iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
/// assert_eq!(iid_to_u64(&iid), 4822678189205111);
/// ```
pub fn iid_to_u64(iid: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*iid)
}

/// Gateway time master candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeMasterCandidate {
    /// Gateway IID (Interface Identifier).
    pub iid: [u8; 8],
    /// Whether this gateway has GPS.
    pub has_gps: bool,
}

/// Elect time master from a list of candidates.
///
/// Per GCP-6.1:
/// - GPS-equipped gateways use GPS epoch (they don't participate in backbone election)
/// - Non-GPS gateways elect time master based on lowest IID
///
/// This function handles the backbone election case: it selects the candidate
/// with the lowest IID (as unsigned big-endian u64).
///
/// Returns `None` if the candidates slice is empty.
///
/// # Example
///
/// ```
/// use lichen_core::superframe::{elect_time_master, TimeMasterCandidate};
///
/// let candidates = [
///     TimeMasterCandidate {
///         iid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
///         has_gps: false,
///     },
///     TimeMasterCandidate {
///         iid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
///         has_gps: false,
///     },
///     TimeMasterCandidate {
///         iid: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
///         has_gps: false,
///     },
/// ];
///
/// let master = elect_time_master(&candidates).unwrap();
/// assert_eq!(master.iid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
/// ```
pub fn elect_time_master(candidates: &[TimeMasterCandidate]) -> Option<TimeMasterCandidate> {
    if candidates.is_empty() {
        return None;
    }

    let mut winner = candidates[0];
    let mut winner_val = iid_to_u64(&winner.iid);

    for candidate in &candidates[1..] {
        let candidate_val = iid_to_u64(&candidate.iid);
        if candidate_val < winner_val {
            winner = *candidate;
            winner_val = candidate_val;
        }
    }

    Some(winner)
}

/// Superframe synchronization state for a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperframeSync {
    /// Time source being used.
    pub time_source: TimeSource,
    /// Current superframe configuration.
    pub config: SuperframeConfig,
    /// Current superframe ID (if synchronized).
    pub superframe_id: Option<u64>,
    /// Local IID for election purposes.
    pub local_iid: [u8; 8],
    /// IID of the elected time master (if using backbone election).
    pub time_master_iid: Option<[u8; 8]>,
}

impl SuperframeSync {
    /// Create a new unsynchronized superframe state.
    pub const fn new(local_iid: [u8; 8]) -> Self {
        Self {
            time_source: TimeSource::Unsynchronized,
            config: SuperframeConfig {
                duration_s: DEFAULT_SUPERFRAME_DURATION_S,
                slots_per_superframe: DEFAULT_SLOTS_PER_SUPERFRAME,
            },
            superframe_id: None,
            local_iid,
            time_master_iid: None,
        }
    }

    /// Update synchronization from GPS time.
    pub fn sync_from_gps(&mut self, unix_timestamp: u64) {
        self.time_source = TimeSource::Gps;
        self.superframe_id = Some(superframe_id(unix_timestamp, self.config.duration_s));
        self.time_master_iid = None; // GPS gateways are their own time source
    }

    /// Update synchronization from backbone time master.
    pub fn sync_from_backbone(&mut self, master_iid: [u8; 8], superframe_id: u64) {
        self.time_source = TimeSource::BackboneElect;
        self.superframe_id = Some(superframe_id);
        self.time_master_iid = Some(master_iid);
    }

    /// Check if this gateway should be time master in a backbone election.
    ///
    /// Returns true if local IID is lower than the provided peer IID.
    pub fn should_be_master(&self, peer_iid: &[u8; 8]) -> bool {
        compare_iid_for_election(&self.local_iid, peer_iid) == core::cmp::Ordering::Less
    }

    /// Get the current slot if synchronized.
    pub fn current_slot(&self, unix_timestamp: u64) -> Option<u8> {
        let sf_id = self.superframe_id?;
        let sf_start = superframe_start(sf_id, self.config.duration_s);
        Some(current_slot(
            unix_timestamp,
            sf_start,
            self.config.duration_s,
            self.config.slots_per_superframe,
        ))
    }

    /// Check if synchronized.
    pub fn is_synchronized(&self) -> bool {
        self.superframe_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superframe_id_from_test_vector() {
        // From test vector "superframe_sync_gps_epoch"
        // gps_epoch_utc: "2024-07-03T12:00:00Z"
        // gps_epoch_unix: 1720008000
        // superframe_duration_s: 60
        // current_superframe_id: 28666800
        let unix_ts = 1720008000u64;
        let id = superframe_id(unix_ts, 60);
        assert_eq!(id, 28666800);
    }

    #[test]
    fn test_superframe_id_zero_duration() {
        let id = superframe_id(1720008000, 0);
        assert_eq!(id, 0);
    }

    #[test]
    fn test_superframe_start_from_id() {
        // Reverse of superframe_id
        let start = superframe_start(28666800, 60);
        assert_eq!(start, 1720008000);
    }

    #[test]
    fn test_current_slot_from_test_vector() {
        // From test vector "superframe_slot_timing"
        // superframe_duration_s: 60
        // slots_per_superframe: 60
        // test_timestamp_unix: 1720008025
        // superframe_start_unix: 1720008000
        // expected_current_slot: 25
        let slot = current_slot(1720008025, 1720008000, 60, 60);
        assert_eq!(slot, 25);
    }

    #[test]
    fn test_slots_remaining_from_test_vector() {
        // From test vector "superframe_slot_timing"
        // expected_current_slot: 25
        // expected_slots_remaining: 35
        let remaining = slots_remaining(25, 60);
        assert_eq!(remaining, 35);
    }

    #[test]
    fn test_slots_remaining_at_end() {
        let remaining = slots_remaining(59, 60);
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_slots_remaining_past_end() {
        let remaining = slots_remaining(60, 60);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_current_slot_zero_slots() {
        let slot = current_slot(1720008025, 1720008000, 60, 0);
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_current_slot_before_superframe() {
        let slot = current_slot(1720007999, 1720008000, 60, 60);
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_iid_to_u64_from_test_vector() {
        // From test vector "superframe_sync_time_master_election"
        // iid_hex: "0011223344556677"
        // iid_decimal: 4822678189205111
        let iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(iid_to_u64(&iid), 4822678189205111);

        // iid_hex: "aabbccddeeff0011"
        // Note: Test vector says 12302652060662325265 but correct value is 12302652060662169617
        let iid2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        assert_eq!(iid_to_u64(&iid2), 12302652060662169617);

        // iid_hex: "deadbeefcafebabe"
        // Note: Test vector says 16045690984833335998 but correct value is 16045690984503098046
        let iid3 = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(iid_to_u64(&iid3), 16045690984503098046);
    }

    #[test]
    fn test_compare_iid_for_election() {
        use core::cmp::Ordering;

        let iid_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let iid_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];

        // iid_a < iid_b, so iid_a should be time master
        assert_eq!(compare_iid_for_election(&iid_a, &iid_b), Ordering::Less);
        assert_eq!(compare_iid_for_election(&iid_b, &iid_a), Ordering::Greater);
        assert_eq!(compare_iid_for_election(&iid_a, &iid_a), Ordering::Equal);
    }

    #[test]
    fn test_elect_time_master_from_test_vector() {
        // From test vector "superframe_sync_time_master_election"
        // candidates (sorted by iid_decimal):
        // - 0x0011223344556677 = 4822678189205111 (should win)
        // - 0xaabbccddeeff0011 = 12302652060662325265
        // - 0xdeadbeefcafebabe = 16045690984833335998
        let candidates = [
            TimeMasterCandidate {
                iid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
                has_gps: false,
            },
            TimeMasterCandidate {
                iid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
                has_gps: false,
            },
            TimeMasterCandidate {
                iid: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
                has_gps: false,
            },
        ];

        let master = elect_time_master(&candidates).unwrap();
        assert_eq!(
            master.iid,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }

    #[test]
    fn test_elect_time_master_empty() {
        let candidates: [TimeMasterCandidate; 0] = [];
        assert!(elect_time_master(&candidates).is_none());
    }

    #[test]
    fn test_elect_time_master_single() {
        let candidates = [TimeMasterCandidate {
            iid: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            has_gps: false,
        }];

        let master = elect_time_master(&candidates).unwrap();
        assert_eq!(
            master.iid,
            [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    #[test]
    fn test_iid_comparison_unsigned_bigendian_from_vector() {
        // From test vector "iid_comparison_unsigned_bigendian"
        use core::cmp::Ordering;

        // 0x0000000000000001 vs 0x0000000000000002 -> iid_a wins (1 < 2)
        let iid_a = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let iid_b = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(compare_iid_for_election(&iid_a, &iid_b), Ordering::Less);

        // 0x0011223344556677 vs 0xaabbccddeeff0011 -> iid_a wins
        let iid_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let iid_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        assert_eq!(compare_iid_for_election(&iid_a, &iid_b), Ordering::Less);

        // 0xffffffffffffffff vs 0x0000000000000001 -> iid_b wins (max u64 > 1)
        let iid_a = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let iid_b = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(compare_iid_for_election(&iid_a, &iid_b), Ordering::Greater);
    }

    #[test]
    fn test_superframe_config_default() {
        let config = SuperframeConfig::default();
        assert_eq!(config.duration_s, 60);
        assert_eq!(config.slots_per_superframe, 60);
        assert_eq!(config.slot_duration_ms(), 1000); // 60s / 60 slots = 1s per slot
    }

    #[test]
    fn test_superframe_config_slot_duration() {
        let config = SuperframeConfig::new(60, 30);
        assert_eq!(config.slot_duration_ms(), 2000); // 60s / 30 slots = 2s per slot

        let config2 = SuperframeConfig::new(120, 60);
        assert_eq!(config2.slot_duration_ms(), 2000); // 120s / 60 slots = 2s per slot
    }

    #[test]
    fn test_superframe_sync_new() {
        let iid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let sync = SuperframeSync::new(iid);

        assert_eq!(sync.time_source, TimeSource::Unsynchronized);
        assert!(!sync.is_synchronized());
        assert!(sync.superframe_id.is_none());
        assert_eq!(sync.local_iid, iid);
    }

    #[test]
    fn test_superframe_sync_from_gps() {
        let iid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut sync = SuperframeSync::new(iid);

        sync.sync_from_gps(1720008000);

        assert_eq!(sync.time_source, TimeSource::Gps);
        assert!(sync.is_synchronized());
        assert_eq!(sync.superframe_id, Some(28666800));
    }

    #[test]
    fn test_superframe_sync_from_backbone() {
        let local_iid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let master_iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut sync = SuperframeSync::new(local_iid);

        sync.sync_from_backbone(master_iid, 28666800);

        assert_eq!(sync.time_source, TimeSource::BackboneElect);
        assert!(sync.is_synchronized());
        assert_eq!(sync.superframe_id, Some(28666800));
        assert_eq!(sync.time_master_iid, Some(master_iid));
    }

    #[test]
    fn test_superframe_sync_should_be_master() {
        let local_iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let peer_iid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let sync = SuperframeSync::new(local_iid);

        assert!(sync.should_be_master(&peer_iid));
        assert!(!SuperframeSync::new(peer_iid).should_be_master(&local_iid));
    }

    #[test]
    fn test_superframe_sync_current_slot() {
        let iid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut sync = SuperframeSync::new(iid);

        // Not synchronized
        assert!(sync.current_slot(1720008025).is_none());

        // Synchronized via GPS
        sync.sync_from_gps(1720008000);
        let slot = sync.current_slot(1720008025);
        assert_eq!(slot, Some(25));
    }
}
