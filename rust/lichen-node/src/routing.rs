//! Routing integration: wraps lichen-rpl with neighbor tracking and node-level API.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. The `Router`
//! type owns DODAG state, trickle timer, and neighbor table, providing a
//! unified interface for the node's receive/transmit paths.
//!
//! Also provides GPSR geographic forwarding fallback (spec 9.7) when gradient
//! routes are unavailable and LOADng discovery times out.
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

/// Geographic coordinates (latitude, longitude) in decimal degrees.
pub type GeoCoords = (f64, f64);

/// Neighbor entry with link quality tracking and optional coordinates.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub addr: [u8; 16],
    pub etx: LinkEtx,
    pub last_seen_ms: u32,
    pub rssi: i8,
    /// Geographic coordinates from announce app_data (spec 9.7).
    /// None if neighbor hasn't advertised coords.
    pub coords: Option<GeoCoords>,
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
        self.update_with_coords(addr, etx, rssi, now_ms, None)
    }

    /// Update or insert a neighbor with optional coordinates.
    pub fn update_with_coords(
        &mut self,
        addr: &[u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u32,
        coords: Option<GeoCoords>,
    ) -> usize {
        // Find existing or empty slot
        let mut empty_slot = None;
        for (i, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(n) if n.addr == *addr => {
                    n.etx = etx;
                    n.rssi = rssi;
                    n.last_seen_ms = now_ms;
                    if coords.is_some() {
                        n.coords = coords;
                    }
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
                coords,
            });
            return i;
        }
        // Table full - evict oldest (wraparound-safe, tie-break by index for stability)
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|n| (i, n.last_seen_ms)))
            .max_by_key(|(i, t)| (now_ms.wrapping_sub(*t), *i))
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.entries[oldest] = Some(Neighbor {
            addr: *addr,
            etx,
            rssi,
            last_seen_ms: now_ms,
            coords,
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

    /// Get neighbor coordinates, or None if unknown or not advertised.
    pub fn get_coords(&self, addr: &[u8; 16]) -> Option<GeoCoords> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .and_then(|n| n.coords)
    }

    /// Update coordinates for an existing neighbor. Does nothing if neighbor not found.
    pub fn set_coords(&mut self, addr: &[u8; 16], coords: GeoCoords) {
        for n in self.entries.iter_mut().flatten() {
            if n.addr == *addr {
                n.coords = Some(coords);
                return;
            }
        }
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
    /// This node's geographic coordinates for GPSR (spec 9.7).
    /// None if GPS unavailable or privacy mode enabled.
    pub node_coords: Option<GeoCoords>,
}

#[cfg(feature = "std")]
impl Router {
    /// Create a new router for a non-root node.
    pub fn new(node_addr: [u8; 16], dodag_id: [u8; 16]) -> Self {
        Self {
            dodag: DodagState::new(RPL_INSTANCE_ID, dodag_id, 0),
            trickle: TrickleTimer::new(4096, 8, 10), // Imin=4096ms (2^12), doublings=8, k=10
            dao_manager: DaoManager::new(node_addr, RPL_INSTANCE_ID, dodag_id),
            neighbors: NeighborTable::new(),
            node_addr,
            dodag_id,
            node_coords: None,
        }
    }

    /// Create a new router as DODAG root.
    pub fn new_root(node_addr: [u8; 16]) -> Self {
        let dodag_id = node_addr; // Root's address is DODAG ID
        Self {
            dodag: DodagState::as_root(RPL_INSTANCE_ID, dodag_id, 0),
            trickle: TrickleTimer::new(4096, 8, 10),
            dao_manager: DaoManager::as_root(node_addr, RPL_INSTANCE_ID, dodag_id),
            neighbors: NeighborTable::new(),
            node_addr,
            dodag_id,
            node_coords: None,
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

    /// Look up route for a destination (root only).
    ///
    /// Non-root nodes always return `None`.
    pub fn lookup_route(&self, dst: &[u8; 16]) -> Option<&[[u8; 16]]> {
        if !self.dodag.is_root() {
            return None;
        }
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

    /// Set this node's geographic coordinates (from GPS or config).
    pub fn set_node_coords(&mut self, coords: GeoCoords) {
        self.node_coords = Some(coords);
    }

    /// Clear this node's coordinates (privacy mode or GPS unavailable).
    pub fn clear_node_coords(&mut self) {
        self.node_coords = None;
    }

    /// Update a neighbor's coordinates (from their announce app_data).
    pub fn update_neighbor_coords(&mut self, addr: &[u8; 16], coords: GeoCoords) {
        self.neighbors.set_coords(addr, coords);
    }

    /// GPSR greedy forwarding: find neighbor closest to destination (spec 9.7).
    ///
    /// Returns the address of the neighbor that makes the most progress toward
    /// the destination, or None if:
    /// - This node has no coordinates
    /// - No neighbors have coordinates
    /// - No neighbor is closer to the destination than this node (local minimum)
    /// - Destination coordinates are invalid (NaN, inf, out of range, null island)
    ///
    /// # Arguments
    /// * `dst_coords` - Geographic coordinates of the destination node
    ///
    /// # Returns
    /// Next-hop address if forwarding is possible, None otherwise
    pub fn gpsr_forward(&self, dst_coords: GeoCoords) -> Option<[u8; 16]> {
        // Validate destination coordinates
        if !is_valid_coords(dst_coords) {
            return None;
        }

        // Need our own coordinates to calculate progress
        let my_coords = self.node_coords?;
        if !is_valid_coords(my_coords) {
            return None;
        }

        let my_dist = haversine(my_coords, dst_coords);
        let mut best_neighbor: Option<[u8; 16]> = None;
        let mut best_dist = my_dist; // Must make progress

        for neighbor in self.neighbors.iter() {
            if let Some(n_coords) = neighbor.coords {
                // Skip neighbors with invalid coordinates
                if !is_valid_coords(n_coords) {
                    continue;
                }
                let d = haversine(n_coords, dst_coords);
                if d < best_dist {
                    best_dist = d;
                    best_neighbor = Some(neighbor.addr);
                }
            }
        }

        best_neighbor
    }
}

#[cfg(feature = "std")]
/// Haversine distance in meters between two (lat, lon) points.
fn haversine(c1: GeoCoords, c2: GeoCoords) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;

    let (lat1, lon1) = c1;
    let (lat2, lon2) = c2;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    // Clamp a to [0, 1] before sqrt to handle floating-point errors
    let c = 2.0 * a.min(1.0).sqrt().asin();

    EARTH_RADIUS_M * c
}

#[cfg(feature = "std")]
/// Validate geographic coordinates.
/// Returns false for NaN, inf, out-of-range, or null island (0,0).
fn is_valid_coords(coords: GeoCoords) -> bool {
    let (lat, lon) = coords;

    // Check for NaN/inf
    if !lat.is_finite() || !lon.is_finite() {
        return false;
    }

    // Reject null island sentinel (almost always invalid GPS data)
    if lat == 0.0 && lon == 0.0 {
        return false;
    }

    // Check valid geographic ranges
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

// --- DTN Store-and-Forward (spec 9.8) ---
//
// Border routers MAY buffer messages for unreachable destinations,
// delivering when a path appears. Uses absolute TTL (Unix timestamp)
// and oldest-first eviction when buffer is full.

#[cfg(feature = "std")]
use std::collections::VecDeque;

/// Default DTN buffer size: 64KB per spec 9.8
#[cfg(feature = "std")]
pub const DTN_BUFFER_MAX_BYTES: usize = 65536;

/// A message buffered for DTN store-and-forward (spec 9.8).
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct DtnMessage {
    /// Raw IPv6 packet data.
    pub packet: Vec<u8>,
    /// 8-byte IID of destination.
    pub destination_iid: [u8; 8],
    /// Unix timestamp when message expires.
    pub expiry_unix: u32,
    /// When message was buffered (monotonic ms for eviction ordering).
    pub buffered_at_ms: u32,
}

#[cfg(feature = "std")]
impl DtnMessage {
    /// Approximate size in bytes for buffer accounting.
    pub fn size(&self) -> usize {
        self.packet.len() + std::mem::size_of::<Self>()
    }
}

/// DTN store-and-forward buffer (spec 9.8).
///
/// Buffers messages for unreachable destinations until a path appears.
/// Uses oldest-first eviction when the buffer exceeds max_bytes.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DtnBuffer {
    buffer: VecDeque<DtnMessage>,
    max_bytes: usize,
    current_bytes: usize,
}

#[cfg(feature = "std")]
impl DtnBuffer {
    /// Create a new DTN buffer with default capacity (64KB).
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes: DTN_BUFFER_MAX_BYTES,
            current_bytes: 0,
        }
    }

    /// Create a new DTN buffer with custom capacity.
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Buffer a message for DTN store-and-forward.
    ///
    /// Returns `true` if buffered, `false` if rejected (expired or oversized).
    pub fn buffer_message(
        &mut self,
        packet: Vec<u8>,
        destination_iid: [u8; 8],
        expiry_unix: u32,
        now_unix: u32,
        now_ms: u32,
    ) -> bool {
        // Reject already-expired messages
        if expiry_unix <= now_unix {
            return false;
        }

        let msg = DtnMessage {
            packet,
            destination_iid,
            expiry_unix,
            buffered_at_ms: now_ms,
        };

        // Reject messages that exceed the maximum buffer size
        let msg_size = msg.size();
        if msg_size > self.max_bytes {
            return false;
        }

        // Evict oldest messages until we have space
        self.evict_if_needed(msg_size);

        self.current_bytes += msg_size;
        self.buffer.push_back(msg);
        true
    }

    /// Get list of destination IIDs with buffered messages.
    pub fn get_pending_iids(&self) -> Vec<[u8; 8]> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for msg in &self.buffer {
            if seen.insert(msg.destination_iid) {
                result.push(msg.destination_iid);
            }
        }
        result
    }

    /// Retrieve and remove all messages for a destination IID.
    pub fn retrieve_for(&mut self, destination_iid: &[u8; 8]) -> Vec<DtnMessage> {
        let mut matching = Vec::new();
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.destination_iid == *destination_iid {
                self.current_bytes -= msg.size();
                matching.push(msg);
            } else {
                remaining.push_back(msg);
            }
        }
        self.buffer = remaining;
        matching
    }

    /// Remove expired messages from buffer. Returns count removed.
    pub fn expire_old(&mut self, now_unix: u32) -> usize {
        let mut expired = 0;
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.expiry_unix > now_unix {
                remaining.push_back(msg);
            } else {
                self.current_bytes -= msg.size();
                expired += 1;
            }
        }
        self.buffer = remaining;
        expired
    }

    /// Current buffer size in bytes.
    pub fn current_size(&self) -> usize {
        self.current_bytes
    }

    /// Number of messages in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Evict oldest messages to make room for new_msg_size bytes.
    fn evict_if_needed(&mut self, new_msg_size: usize) -> usize {
        let mut evicted = 0;
        while self.current_bytes + new_msg_size > self.max_bytes {
            if let Some(oldest) = self.buffer.pop_front() {
                self.current_bytes -= oldest.size();
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }
}

#[cfg(feature = "std")]
impl Default for DtnBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::vec;

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

    #[test]
    fn neighbor_table_eviction_wraparound() {
        // Test that eviction is correct after u32 timestamp wraparound (~49 days)
        let mut table = NeighborTable::new();

        // Fill the table
        for i in 0..MAX_NEIGHBORS {
            let addr = link_local(i as u8);
            // All entries have timestamps just before wraparound
            table.update(&addr, 1.0, -50, 0xFFFF_FF00 + i as u32);
        }
        assert_eq!(table.count(), MAX_NEIGHBORS);

        // Now time has wrapped around to a small value
        let now_ms = 0x0000_1000_u32; // After wraparound

        // Insert a new neighbor - should evict the oldest (lowest slot index)
        let new_addr = link_local(0xFF);
        let evicted_slot = table.update(&new_addr, 1.0, -50, now_ms);

        // The oldest entry is slot 0 (timestamp 0xFFFF_FF00, largest age from now_ms)
        assert_eq!(evicted_slot, 0);
        assert_eq!(table.get_etx(&new_addr), Some(1.0));

        // Verify slot 0 was evicted (original addr link_local(0) is gone)
        let original_addr0 = link_local(0);
        assert_eq!(table.get_etx(&original_addr0), None);
    }

    // --- DTN Buffer Tests ---

    fn make_iid(v: u8) -> [u8; 8] {
        [0, 0, 0, 0, 0, 0, 0, v]
    }

    #[test]
    fn dtn_buffer_message_and_retrieve() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);
        let packet = vec![0u8; 100];

        // Buffer a message
        let buffered = buf.buffer_message(packet.clone(), iid, 1000, 500, 100);
        assert!(buffered);
        assert_eq!(buf.len(), 1);

        // Retrieve it
        let retrieved = buf.retrieve_for(&iid);
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].packet, packet);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_rejects_expired() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);
        let packet = vec![0u8; 100];

        // Try to buffer an expired message (expiry <= now)
        let buffered = buf.buffer_message(packet, iid, 500, 600, 100);
        assert!(!buffered);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_rejects_oversized() {
        let mut buf = DtnBuffer::with_max_bytes(1000);
        let iid = make_iid(1);
        let packet = vec![0u8; 2000]; // Larger than buffer

        let buffered = buf.buffer_message(packet, iid, 1000, 500, 100);
        assert!(!buffered);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_expire_old() {
        let mut buf = DtnBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Buffer two messages with different expiry times
        buf.buffer_message(vec![0u8; 100], iid1, 500, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 20);
        assert_eq!(buf.len(), 2);

        // Expire at time 600 - first message should be removed
        let expired = buf.expire_old(600);
        assert_eq!(expired, 1);
        assert_eq!(buf.len(), 1);

        // The remaining message should be for iid2
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid2);
    }

    #[test]
    fn dtn_buffer_eviction_on_full() {
        let mut buf = DtnBuffer::with_max_bytes(350);
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);
        let iid3 = make_iid(3);

        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 20);
        assert_eq!(buf.len(), 2);

        buf.buffer_message(vec![0u8; 100], iid3, 1000, 100, 30);
        assert_eq!(buf.len(), 2);

        let pending = buf.get_pending_iids();
        assert!(!pending.contains(&iid1));
        assert!(pending.contains(&iid2));
        assert!(pending.contains(&iid3));
    }

    #[test]
    fn dtn_buffer_get_pending_iids_deduplicates() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);

        // Buffer multiple messages for the same destination
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 20);
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 30);
        assert_eq!(buf.len(), 3);

        // get_pending_iids should return only one IID
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid);
    }

    #[test]
    fn dtn_buffer_retrieve_removes_all_for_iid() {
        let mut buf = DtnBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Buffer multiple messages for different destinations
        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 20);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 30);
        assert_eq!(buf.len(), 3);

        // Retrieve all for iid1
        let retrieved = buf.retrieve_for(&iid1);
        assert_eq!(retrieved.len(), 2);
        assert_eq!(buf.len(), 1);

        // Only iid2 should remain
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid2);
    }

    // --- GPSR Tests (spec 9.7) ---

    #[test]
    fn neighbor_coords_update_and_lookup() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);

        // Insert neighbor without coords
        table.update(&addr, 1.0, -50, 1000);
        assert_eq!(table.get_coords(&addr), None);

        // Update with coords
        let coords = (47.6062, -122.3321);
        table.set_coords(&addr, coords);
        assert_eq!(table.get_coords(&addr), Some(coords));
    }

    #[test]
    fn neighbor_update_with_coords() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);
        let coords = (45.5152, -122.6784);

        table.update_with_coords(&addr, 1.0, -50, 1000, Some(coords));
        assert_eq!(table.get_coords(&addr), Some(coords));
    }

    #[test]
    fn gpsr_forward_selects_closest_neighbor() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0)); // Avoid null island

        // Add two neighbors with coords
        let neighbor_a = link_local(0xa);
        let neighbor_b = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&neighbor_a, 1.0, -50, 1000, Some((1.0, 1.0)));
        router
            .neighbors
            .update_with_coords(&neighbor_b, 1.0, -50, 1000, Some((0.5, 1.0)));

        // Destination is 2 degrees north - neighbor_a (1.0) is closer than neighbor_b (0.5)
        let dst_coords = (2.0, 1.0);
        let next_hop = router.gpsr_forward(dst_coords);

        assert_eq!(next_hop, Some(neighbor_a));
    }

    #[test]
    fn gpsr_forward_requires_progress() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((1.0, 1.0));

        // Neighbors are further from destination than we are
        let neighbor_a = link_local(0xa);
        let neighbor_b = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&neighbor_a, 1.0, -50, 1000, Some((0.5, 1.0)));
        router
            .neighbors
            .update_with_coords(&neighbor_b, 1.0, -50, 1000, Some((0.0, 1.0)));

        // Destination is 2.0 north - we're at 1.0, neighbors are at 0.5 and 0.0
        let dst_coords = (2.0, 1.0);
        let next_hop = router.gpsr_forward(dst_coords);

        // No progress possible - local minimum
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_no_node_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = None; // No GPS

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_no_neighbor_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        // Neighbor without coords
        let neighbor = link_local(0xa);
        router.neighbors.update(&neighbor, 1.0, -50, 1000);

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_nan_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((f64::NAN, 1.0)), None);
        assert_eq!(router.gpsr_forward((1.0, f64::NAN)), None);
    }

    #[test]
    fn gpsr_forward_inf_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((f64::INFINITY, 1.0)), None);
        assert_eq!(router.gpsr_forward((f64::NEG_INFINITY, 1.0)), None);
    }

    #[test]
    fn gpsr_forward_invalid_latitude() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((91.0, 0.0)), None);
        assert_eq!(router.gpsr_forward((-91.0, 0.0)), None);
    }

    #[test]
    fn gpsr_forward_invalid_longitude() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((0.0, 181.0)), None);
        assert_eq!(router.gpsr_forward((0.0, -181.0)), None);
    }

    #[test]
    fn gpsr_forward_null_island() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((1.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((0.5, 0.5)));

        // Null island (0, 0) is rejected as invalid sentinel
        assert_eq!(router.gpsr_forward((0.0, 0.0)), None);
    }

    #[test]
    fn gpsr_forward_skips_invalid_neighbor_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        // Neighbor with NaN coords should be skipped
        let bad_neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&bad_neighbor, 1.0, -50, 1000, Some((f64::NAN, 1.0)));

        // Good neighbor should still be selected
        let good_neighbor = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&good_neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, Some(good_neighbor));
    }

    #[test]
    fn haversine_distance_same_point() {
        let p = (47.6062, -122.3321);
        assert!(super::haversine(p, p) < 0.01);
    }

    #[test]
    fn haversine_distance_known() {
        // Seattle to Portland ~= 233km
        let seattle = (47.6062, -122.3321);
        let portland = (45.5152, -122.6784);
        let d = super::haversine(seattle, portland);
        assert!((d - 233_000.0).abs() < 5000.0);
    }

    #[test]
    fn is_valid_coords_rejects_nan() {
        assert!(!super::is_valid_coords((f64::NAN, 0.0)));
        assert!(!super::is_valid_coords((0.0, f64::NAN)));
    }

    #[test]
    fn is_valid_coords_rejects_inf() {
        assert!(!super::is_valid_coords((f64::INFINITY, 0.0)));
        assert!(!super::is_valid_coords((f64::NEG_INFINITY, 0.0)));
    }

    #[test]
    fn is_valid_coords_rejects_null_island() {
        assert!(!super::is_valid_coords((0.0, 0.0)));
    }

    #[test]
    fn is_valid_coords_accepts_valid() {
        assert!(super::is_valid_coords((47.6062, -122.3321)));
        assert!(super::is_valid_coords((-33.8688, 151.2093))); // Sydney
        assert!(super::is_valid_coords((90.0, 0.0))); // North pole
        assert!(super::is_valid_coords((-90.0, 180.0))); // South pole
    }
}
