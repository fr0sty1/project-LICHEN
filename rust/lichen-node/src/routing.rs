//! Routing integration: wraps lichen-rpl with neighbor tracking and node-level API.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. The `Router`
//! type owns DODAG state, trickle timer, and neighbor table, providing a
//! unified interface for the node's receive/transmit paths.
//!
//! Requires `std` feature for full RPL integration.

#[cfg(feature = "std")]
use lichen_core::constants::RPL_INSTANCE_ID;
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
pub use lichen_rpl::dodag::{DodagRole, DodagState, ParentCandidate, ROOT_RANK};
#[cfg(feature = "std")]
pub use lichen_rpl::message::{Dao, Dio, DodagConfig, RplError};
#[cfg(feature = "std")]
pub use lichen_rpl::routing::{DaoManager, RoutingTable, SourceRoutingHeader};
#[cfg(feature = "std")]
pub use lichen_rpl::trickle::{TrickleEvent, TrickleTimer};

/// Maximum neighbors tracked.
pub const MAX_NEIGHBORS: usize = 16;

/// Link quality estimate (ETX as f32: 1.0 = perfect link).
pub type LinkEtx = f32;

/// Neighbor entry with link quality tracking.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub addr: [u8; 16],
    pub etx: LinkEtx,
    pub last_seen_ms: u32,
    pub rssi: i8,
}

/// Neighbor table for link quality tracking.
#[derive(Debug)]
pub struct NeighborTable {
    entries: [Option<Neighbor>; MAX_NEIGHBORS],
}

impl NeighborTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_NEIGHBORS],
        }
    }

    /// Update or insert a neighbor. Returns the slot index.
    pub fn update(&mut self, addr: &[u8; 16], etx: LinkEtx, rssi: i8, now_ms: u32) -> usize {
        // Find existing or empty slot
        let mut empty_slot = None;
        for (i, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(n) if n.addr == *addr => {
                    n.etx = etx;
                    n.rssi = rssi;
                    n.last_seen_ms = now_ms;
                    return i;
                }
                None if empty_slot.is_none() => empty_slot = Some(i),
                _ => {}
            }
        }
        // Insert new
        if let Some(i) = empty_slot {
            self.entries[i] = Some(Neighbor {
                addr: *addr,
                etx,
                rssi,
                last_seen_ms: now_ms,
            });
            return i;
        }
        // Table full - evict oldest
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|n| (i, n.last_seen_ms)))
            .min_by_key(|(_, t)| *t)
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.entries[oldest] = Some(Neighbor {
            addr: *addr,
            etx,
            rssi,
            last_seen_ms: now_ms,
        });
        oldest
    }

    /// Get neighbor ETX, or None if unknown.
    pub fn get_etx(&self, addr: &[u8; 16]) -> Option<LinkEtx> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .map(|n| n.etx)
    }

    /// Remove stale entries older than `max_age_ms`.
    pub fn prune(&mut self, now_ms: u32, max_age_ms: u32) {
        for slot in self.entries.iter_mut() {
            if let Some(n) = slot {
                // Handles u32 overflow after ~49 days
                if now_ms.wrapping_sub(n.last_seen_ms) > max_age_ms {
                    *slot = None;
                }
            }
        }
    }

    /// Iterate over valid neighbors.
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.iter().flatten()
    }

    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Unified routing state combining DODAG, trickle, DAO manager, and neighbor table.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct Router {
    pub dodag: DodagState,
    pub trickle: TrickleTimer,
    pub dao_manager: DaoManager,
    pub neighbors: NeighborTable,
    #[allow(dead_code)] // stored at construction; not yet consulted
    node_addr: [u8; 16],
    dodag_id: [u8; 16],
}

#[cfg(feature = "std")]
impl Router {
    /// Create a new router for a non-root node.
    pub fn new(node_addr: [u8; 16], dodag_id: [u8; 16]) -> Self {
        Self {
            dodag: DodagState::new(RPL_INSTANCE_ID, dodag_id, 0),
            trickle: TrickleTimer::new(256, 8, 10), // Imin=256ms, doublings=8, k=10
            dao_manager: DaoManager::new(node_addr, RPL_INSTANCE_ID, dodag_id),
            neighbors: NeighborTable::new(),
            node_addr,
            dodag_id,
        }
    }

    /// Create a new router as DODAG root.
    pub fn new_root(node_addr: [u8; 16]) -> Self {
        let dodag_id = node_addr; // Root's address is DODAG ID
        Self {
            dodag: DodagState::as_root(RPL_INSTANCE_ID, dodag_id, 0),
            trickle: TrickleTimer::new(256, 8, 10),
            dao_manager: DaoManager::as_root(node_addr, RPL_INSTANCE_ID, dodag_id),
            neighbors: NeighborTable::new(),
            node_addr,
            dodag_id,
        }
    }

    /// Process a received DIO message from a neighbor.
    ///
    /// Updates neighbor table, feeds DODAG state machine, and returns whether
    /// the trickle timer should be reset (inconsistent DIO heard).
    pub fn process_dio(&mut self, dio: &Dio, sender_addr: [u8; 16], rssi: i8, now_ms: u32) -> bool {
        // Update neighbor table with default ETX (1.0 = perfect link)
        let etx = self.neighbors.get_etx(&sender_addr).unwrap_or(1.0);
        self.neighbors.update(&sender_addr, etx, rssi, now_ms);

        // Check consistency before processing
        let was_joined = self.dodag.is_joined();
        let old_parent = self.dodag.preferred_parent;

        // Feed to DODAG state machine
        self.dodag.process_dio(dio, sender_addr, etx);

        // Detect inconsistency: joined state changed, or parent changed
        let now_joined = self.dodag.is_joined();
        let new_parent = self.dodag.preferred_parent;
        was_joined != now_joined || old_parent != new_parent
    }

    /// Process a received DAO message (root only).
    ///
    /// Returns true if a route was updated.
    pub fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
        if !self.dodag.is_root() {
            return false;
        }
        self.dao_manager.process_dao(dao_bytes)
    }

    /// Build a DAO message to send to parent.
    ///
    /// Returns the DAO bytes, or empty vec if not joined.
    pub fn build_dao(&mut self) -> Vec<u8> {
        if let Some(parent) = self.dodag.preferred_parent {
            self.dao_manager.build_dao(parent)
        } else {
            Vec::new()
        }
    }

    /// Build a DIO message to advertise.
    ///
    /// Returns the number of bytes written.
    pub fn build_dio(&self, out: &mut [u8]) -> usize {
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: self.dodag.version,
            rank: self.dodag.rank,
            grounded: true,
            mode_of_operation: 1, // Non-Storing
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: self.dodag_id,
        };
        dio.write_to(out).unwrap_or(0)
    }

    /// Get the route path for a destination (root only).
    pub fn lookup_route(&self, dst: &[u8; 16]) -> Option<&[[u8; 16]]> {
        self.dao_manager.routing_table.lookup(dst)
    }

    /// Check trickle timer and return pending event.
    pub fn poll_trickle(&self) -> TrickleEvent {
        self.trickle.next_event()
    }

    /// Handle trickle transmit event. Returns true if DIO should be sent.
    pub fn trickle_transmit(&mut self) -> bool {
        self.trickle.fire_transmit()
    }

    /// Handle trickle expire event. Doubles interval.
    pub fn trickle_expire(&mut self, now_ms: u32, rand_offset: u32) {
        self.trickle.expire(now_ms, rand_offset);
    }

    /// Reset trickle on inconsistency.
    pub fn trickle_reset(&mut self, now_ms: u32, rand_offset: u32) {
        self.trickle.reset(now_ms, rand_offset);
    }

    /// Start trickle timer.
    pub fn trickle_start(&mut self, now_ms: u32, rand_offset: u32) {
        self.trickle.start(now_ms, rand_offset);
    }

    /// Heard consistent DIO - increment counter.
    pub fn trickle_consistent(&mut self) {
        self.trickle.heard_consistent();
    }

    pub fn is_root(&self) -> bool {
        self.dodag.is_root()
    }

    pub fn is_joined(&self) -> bool {
        self.dodag.is_joined()
    }

    pub fn rank(&self) -> u16 {
        self.dodag.rank
    }

    pub fn preferred_parent(&self) -> Option<[u8; 16]> {
        self.dodag.preferred_parent
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn link_local(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = iid;
        addr
    }

    #[test]
    fn neighbor_table_update_and_lookup() {
        let mut table = NeighborTable::new();
        let addr1 = link_local(1);
        let addr2 = link_local(2);

        table.update(&addr1, 1.0, -50, 1000);
        table.update(&addr2, 2.0, -70, 2000);

        assert_eq!(table.get_etx(&addr1), Some(1.0));
        assert_eq!(table.get_etx(&addr2), Some(2.0));
        assert_eq!(table.count(), 2);
    }

    #[test]
    fn neighbor_table_prune_stale() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);
        table.update(&addr, 1.0, -50, 1000);

        table.prune(5000, 3000); // 4 seconds elapsed, 3 second max age
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn router_non_root_starts_unjoined() {
        let router = Router::new(link_local(1), link_local(0));
        assert!(!router.is_joined());
        assert!(!router.is_root());
        assert_eq!(router.rank(), u16::MAX);
    }

    #[test]
    fn router_root_starts_joined() {
        let router = Router::new_root(link_local(0));
        assert!(router.is_joined());
        assert!(router.is_root());
        assert_eq!(router.rank(), ROOT_RANK);
    }

    #[test]
    fn router_joins_on_dio() {
        let mut router = Router::new(link_local(2), link_local(0));
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: link_local(0),
        };
        let root_addr = link_local(0);
        let inconsistent = router.process_dio(&dio, root_addr, -40, 1000);
        assert!(inconsistent, "should detect inconsistency on join");
        assert!(router.is_joined());
        assert_eq!(router.preferred_parent(), Some(root_addr));
    }
}
