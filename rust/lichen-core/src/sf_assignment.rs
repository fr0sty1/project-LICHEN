//! Spreading Factor assignment oracle (spec 02-physical-link.md 3.4).
//!
//! Implements:
//! - Stateless hash-based fallback: `assigned_sf = 7 + (hash_32(IID) % 6)`
//! - Gateway-assigned SF via DIO option (type 0x14)
//! - Per-SF node tracking for gateway load balancing
//!
//! Hash uses FNV-1a32 (basis 0x811c9dc5) per CCP-15.8.3. Gateway- and node-side
//! MUST receive on all SF7-SF12 regardless of TX SF.

use crate::constants::DIO_OPTION_ASSIGNED_SF;
use crate::lichen_hash_32;

/// Invalid spreading-factor assignment supplied by a caller or DIO producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSpreadingFactor(pub u8);

impl core::fmt::Display for InvalidSpreadingFactor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "spreading factor must be 7-12, got {}", self.0)
    }
}

/// Stateless hash-based SF assignment.
///
/// Returns SF in 7..=12 based on FNV-1a32 hash of the IID.
///
/// # Arguments
/// * `iid` - 8-byte IID/EUI-64
#[inline]
pub fn assigned_sf_hash_based(iid: &[u8; 8]) -> u8 {
    let h = lichen_hash_32(iid);
    7 + (h % 6) as u8
}

/// Per-node SF assignment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SfAssignmentState {
    /// Gateway-assigned SF via DIO (None if not assigned).
    assigned_sf_dio: Option<u8>,
    /// Whether the node has joined the network.
    joined: bool,
}

impl Default for SfAssignmentState {
    fn default() -> Self {
        Self::new()
    }
}

impl SfAssignmentState {
    /// Create new state with no assignment.
    #[inline]
    pub const fn new() -> Self {
        Self {
            assigned_sf_dio: None,
            joined: false,
        }
    }

    /// Resolve effective TX SF per spec 3.4 priority:
    /// 1. Gateway-assigned ASSIGNED_SF via DIO (if present, 7..=12) -> MUST use
    /// 2. Stateless hash-based fallback -> 7 + (hash(IID) % 6)
    /// 3. No assignment -> SF10 (backwards compat, join-based initial)
    ///
    /// # Arguments
    /// * `iid` - 8-byte IID/EUI-64 for hash-based fallback
    #[inline]
    pub fn effective_sf(&self, iid: &[u8; 8]) -> u8 {
        if let Some(sf) = self.assigned_sf_dio {
            if (7..=12).contains(&sf) {
                return sf;
            }
        }
        if !self.joined {
            return 10;
        }
        assigned_sf_hash_based(iid)
    }

    /// Set gateway-assigned SF from DIO.
    #[inline]
    pub fn set_assigned_sf(&mut self, sf: u8) -> Result<(), InvalidSpreadingFactor> {
        if !is_valid_sf(sf) {
            return Err(InvalidSpreadingFactor(sf));
        }
        self.assigned_sf_dio = Some(sf);
        Ok(())
    }

    /// Return the current validated gateway assignment, if any.
    pub const fn assigned_sf(&self) -> Option<u8> {
        self.assigned_sf_dio
    }

    /// Return whether the node has joined the network.
    pub const fn is_joined(&self) -> bool {
        self.joined
    }

    /// Mark node as joined.
    #[inline]
    pub fn set_joined(&mut self) {
        self.joined = true;
    }
}

/// Gateway load-balancing: pick least-loaded SF (7..=12, tie -> lowest SF).
///
/// # Arguments
/// * `load_by_sf` - Array of 6 elements representing node counts for SF7-SF12
///
/// # Returns
/// Assigned SF (7-12)
#[inline]
pub fn gateway_assigned_sf(load_by_sf: &[u32; 6]) -> u8 {
    let mut best_sf = 7u8;
    let mut best_load = load_by_sf[0];
    for (i, &load) in load_by_sf.iter().enumerate().skip(1) {
        if load < best_load {
            best_load = load;
            best_sf = 7 + i as u8;
        }
    }
    best_sf
}

/// Check if an SF is valid (7-12).
#[inline]
pub const fn is_valid_sf(sf: u8) -> bool {
    sf >= 7 && sf <= 12
}

/// Nodes and gateways MUST receive on all SF7-SF12 regardless of TX SF.
#[inline]
pub const fn must_receive_all_sf(sf: u8) -> bool {
    is_valid_sf(sf)
}

/// Build an ASSIGNED_SF DIO option payload.
///
/// # Arguments
/// * `sf` - Spreading factor to assign (must be 7-12)
///
/// # Returns
/// 3-byte TLV: [type, length, sf]
///
#[inline]
pub fn make_assigned_sf_option(sf: u8) -> Result<[u8; 3], InvalidSpreadingFactor> {
    if !is_valid_sf(sf) {
        return Err(InvalidSpreadingFactor(sf));
    }
    Ok([DIO_OPTION_ASSIGNED_SF, 1, sf])
}

/// Parse an ASSIGNED_SF DIO option from a TLV buffer.
///
/// # Arguments
/// * `data` - At least 3 bytes: [type, length, sf]
///
/// # Returns
/// `Some(sf)` if valid, `None` if wrong type, length, or invalid SF value.
#[inline]
pub fn parse_assigned_sf_option(data: &[u8]) -> Option<u8> {
    if data.len() < 3 {
        return None;
    }
    if data[0] != DIO_OPTION_ASSIGNED_SF {
        return None;
    }
    if data[1] != 1 {
        return None;
    }
    let sf = data[2];
    if is_valid_sf(sf) {
        Some(sf)
    } else {
        None
    }
}

/// Gateway-side per-SF node tracking for load balancing.
///
/// Tracks node count per SF (7-12) and assigns least-loaded SF to new nodes.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct GatewaySfTracker {
    /// Nodes tracked by SF (SF 7-12 indexed as 0-5).
    nodes_by_sf: [std::collections::HashSet<[u8; 8]>; 6],
}

#[cfg(feature = "std")]
impl GatewaySfTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a node at a given SF.
    ///
    /// # Panics
    /// Panics if sf is not in 7..=12.
    pub fn register_node(&mut self, iid: [u8; 8], sf: u8) {
        assert!(is_valid_sf(sf), "sf must be 7-12, got {}", sf);
        self.remove_node(&iid);
        self.nodes_by_sf[(sf - 7) as usize].insert(iid);
    }

    /// Remove a node from tracking.
    pub fn unregister_node(&mut self, iid: &[u8; 8]) {
        self.remove_node(iid);
    }

    fn remove_node(&mut self, iid: &[u8; 8]) {
        for set in &mut self.nodes_by_sf {
            set.remove(iid);
        }
    }

    /// Return node count per SF as array [SF7, SF8, ..., SF12].
    pub fn load_by_sf(&self) -> [u32; 6] {
        let mut result = [0u32; 6];
        for (i, set) in self.nodes_by_sf.iter().enumerate() {
            result[i] = set.len() as u32;
        }
        result
    }

    /// Assign least-loaded SF for a new node and register it.
    ///
    /// # Arguments
    /// * `iid` - Node's IID (8-byte EUI-64)
    ///
    /// # Returns
    /// Assigned SF (7-12)
    pub fn assign_sf(&mut self, iid: [u8; 8]) -> u8 {
        let load = self.load_by_sf();
        let sf = gateway_assigned_sf(&load);
        self.register_node(iid, sf);
        sf
    }

    /// Total number of tracked nodes.
    pub fn node_count(&self) -> usize {
        self.nodes_by_sf.iter().map(|s| s.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assigned_sf_hash_based_range() {
        // All results should be in 7..=12
        for i in 0..=255u8 {
            let iid = [i, 0, 0, 0, 0, 0, 0, 0];
            let sf = assigned_sf_hash_based(&iid);
            assert!(
                (7..=12).contains(&sf),
                "SF {} out of range for iid {:?}",
                sf,
                iid
            );
        }
    }

    #[test]
    fn test_assigned_sf_hash_based_vectors() {
        // Test vectors from sf_assignment.json
        assert_eq!(assigned_sf_hash_based(&[0; 8]), 10); // zero_iid -> SF10
        assert_eq!(
            assigned_sf_hash_based(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            12
        ); // example_iid -> SF12
        assert_eq!(assigned_sf_hash_based(&[0xff; 8]), 8); // max_iid -> SF8
        assert_eq!(
            assigned_sf_hash_based(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            10
        ); // incremental -> SF10
    }

    #[test]
    fn test_sf_assignment_state_effective_sf() {
        let iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        // Not joined, no DIO -> SF10
        let state = SfAssignmentState::new();
        assert_eq!(state.effective_sf(&iid), 10);

        // Joined, no DIO -> hash-based (SF12 for this IID)
        let mut state = SfAssignmentState::new();
        state.set_joined();
        assert_eq!(state.effective_sf(&iid), 12);

        // DIO assigned SF9 overrides hash-based
        let mut state = SfAssignmentState::new();
        state.set_joined();
        assert_eq!(state.set_assigned_sf(9), Ok(()));
        assert_eq!(state.assigned_sf(), Some(9));
        assert!(state.is_joined());
        assert_eq!(state.effective_sf(&iid), 9);

        assert_eq!(state.set_assigned_sf(6), Err(InvalidSpreadingFactor(6)));
        assert_eq!(state.set_assigned_sf(13), Err(InvalidSpreadingFactor(13)));
        assert_eq!(state.assigned_sf(), Some(9));
    }

    #[test]
    fn test_gateway_assigned_sf_least_loaded() {
        // All empty -> SF7 (lowest)
        assert_eq!(gateway_assigned_sf(&[0; 6]), 7);

        // SF7 has 5, others 0 -> SF8
        assert_eq!(gateway_assigned_sf(&[5, 0, 0, 0, 0, 0]), 8);

        // SF7-SF10 have 3, SF11-SF12 have 0 -> SF11
        assert_eq!(gateway_assigned_sf(&[3, 3, 3, 3, 0, 0]), 11);

        // Tie at minimum -> lowest SF wins
        assert_eq!(gateway_assigned_sf(&[1, 1, 1, 1, 1, 1]), 7);
    }

    #[test]
    fn test_make_parse_assigned_sf_option() {
        assert_eq!(DIO_OPTION_ASSIGNED_SF, 0x14);
        for sf in 7..=12 {
            let opt = make_assigned_sf_option(sf).unwrap();
            assert_eq!(opt[0], DIO_OPTION_ASSIGNED_SF);
            assert_eq!(opt[1], 1);
            assert_eq!(opt[2], sf);

            let parsed = parse_assigned_sf_option(&opt);
            assert_eq!(parsed, Some(sf));
        }
        assert_eq!(make_assigned_sf_option(6), Err(InvalidSpreadingFactor(6)));
        assert_eq!(make_assigned_sf_option(13), Err(InvalidSpreadingFactor(13)));
    }

    #[test]
    fn test_parse_assigned_sf_option_invalid() {
        // Wrong type
        assert_eq!(parse_assigned_sf_option(&[0x00, 1, 10]), None);
        // Wrong length
        assert_eq!(
            parse_assigned_sf_option(&[DIO_OPTION_ASSIGNED_SF, 2, 10]),
            None
        );
        // Invalid SF
        assert_eq!(
            parse_assigned_sf_option(&[DIO_OPTION_ASSIGNED_SF, 1, 6]),
            None
        );
        assert_eq!(
            parse_assigned_sf_option(&[DIO_OPTION_ASSIGNED_SF, 1, 13]),
            None
        );
        // Too short
        assert_eq!(parse_assigned_sf_option(&[DIO_OPTION_ASSIGNED_SF, 1]), None);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_gateway_sf_tracker() {
        let mut tracker = GatewaySfTracker::new();
        assert_eq!(tracker.node_count(), 0);

        let iid1 = [1u8; 8];
        let iid2 = [2u8; 8];
        let iid3 = [3u8; 8];

        // First node -> SF7 (all empty)
        let sf1 = tracker.assign_sf(iid1);
        assert_eq!(sf1, 7);
        assert_eq!(tracker.node_count(), 1);
        assert_eq!(tracker.load_by_sf()[0], 1);

        // Second node -> SF8 (SF7 has 1)
        let sf2 = tracker.assign_sf(iid2);
        assert_eq!(sf2, 8);
        assert_eq!(tracker.node_count(), 2);

        // Third node -> SF9 (SF7, SF8 have 1 each)
        let sf3 = tracker.assign_sf(iid3);
        assert_eq!(sf3, 9);
        assert_eq!(tracker.node_count(), 3);

        // Unregister and verify
        tracker.unregister_node(&iid2);
        assert_eq!(tracker.node_count(), 2);
        assert_eq!(tracker.load_by_sf()[1], 0); // SF8 now empty
    }
}
