//! Hybrid routing decision engine (spec section 7.2).
//!
//! The HybridRouter decides how to forward each packet based on destination address:
//! 1. Link-local (fe80::/10): Direct neighbor delivery
//! 2. Mesh-local (ULA or mesh GUA): Gradient lookup -> LOADng discovery
//! 3. External: Forward to RPL parent toward border router
//!
//! Each protocol has its own state machine; the HybridRouter orchestrates them
//! based on address classification and route availability.

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::{collections::VecDeque, vec::Vec};

#[cfg(feature = "std")]
use crate::gradient::{
    GeoCoords, GradientEntry, GradientSource, GradientTable, GRADIENT_TIMEOUT_MS,
};
#[cfg(feature = "std")]
use lichen_core::loadng::{Idle, RouteDiscovery, Rreq, Searching};

/// Classification of IPv6 destination address (spec 7.2 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// fe80::/10 - direct neighbor, one hop away.
    LinkLocal,
    /// ULA (fd00::/8) or configured mesh GUA - peer in mesh.
    MeshLocal,
    /// Other GUA or unknown - route via border router.
    External,
}

/// What to do with a packet after routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// Forward to the provided next_hop immediately.
    Forward,
    /// Queue pending LOADng discovery.
    Queue,
    /// No route, cannot discover (unjoined, etc.).
    Drop,
    /// Packet is for this node (deliver to upper layer).
    DeliverLocal,
}

/// Routing outcome with next-hop information.
#[derive(Debug, Clone)]
pub struct RouteResult {
    pub decision: RouteDecision,
    /// Next-hop address (Some for Forward, None otherwise).
    pub next_hop: Option<[u8; 16]>,
}

impl RouteResult {
    pub const fn forward(next_hop: [u8; 16]) -> Self {
        Self {
            decision: RouteDecision::Forward,
            next_hop: Some(next_hop),
        }
    }

    pub const fn queue() -> Self {
        Self {
            decision: RouteDecision::Queue,
            next_hop: None,
        }
    }

    pub const fn drop() -> Self {
        Self {
            decision: RouteDecision::Drop,
            next_hop: None,
        }
    }

    pub const fn deliver_local() -> Self {
        Self {
            decision: RouteDecision::DeliverLocal,
            next_hop: None,
        }
    }
}

/// A packet queued pending route discovery.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PendingPacket {
    /// Serialized IPv6 packet data.
    pub data: Vec<u8>,
    /// Destination address being discovered.
    pub destination: [u8; 16],
    /// Timestamp when queued (for timeout).
    pub queued_at_ms: u32,
    /// Priority (0=highest, 3=lowest per ForwardEntry/TxPriority spec).
    pub priority: u8,
}

/// Active LOADng route discovery state.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ActiveDiscovery {
    /// Destination being discovered.
    pub destination: [u8; 16],
    /// Discovery state machine.
    pub discovery: RouteDiscovery<Searching>,
    /// Time when current RREQ was sent.
    pub sent_at_ms: u32,
}

/// Mesh prefix configuration.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct MeshPrefix {
    /// Network prefix bytes.
    pub prefix: [u8; 16],
    /// Prefix length in bits.
    pub prefix_len: u8,
}

#[cfg(feature = "std")]
impl MeshPrefix {
    pub fn new(prefix: [u8; 16], prefix_len: u8) -> Self {
        Self { prefix, prefix_len }
    }

    /// Check if an address is within this prefix.
    pub fn contains(&self, addr: &[u8; 16]) -> bool {
        let full_bytes = (self.prefix_len / 8) as usize;
        let remaining_bits = self.prefix_len % 8;

        // Check full bytes
        if addr[..full_bytes] != self.prefix[..full_bytes] {
            return false;
        }

        // Check remaining bits
        if remaining_bits > 0 && full_bytes < 16 {
            let mask = 0xFF << (8 - remaining_bits);
            if (addr[full_bytes] & mask) != (self.prefix[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

/// Hybrid routing decision engine (spec 7.2).
///
/// Orchestrates RPL (border router traffic), Announce gradients (peer-to-peer),
/// and LOADng (fallback discovery). Owns the gradient table, pending packet queue,
/// and active discoveries.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct HybridRouter {
    /// This node's IPv6 address.
    node_address: [u8; 16],
    /// Unified gradient/routing table (spec 11).
    pub gradient_table: GradientTable,
    /// RPL preferred parent (if joined).
    rpl_parent: Option<[u8; 16]>,
    /// Whether this node is joined to an RPL DODAG.
    rpl_joined: bool,
    /// Mesh-local prefixes (ULA or configured GUA).
    mesh_prefixes: Vec<MeshPrefix>,
    /// Packets waiting for route discovery.
    pending_queue: std::collections::HashMap<[u8; 16], VecDeque<PendingPacket>>,
    /// Maximum packets to queue per destination.
    max_pending_per_dest: usize,
    /// Active LOADng discoveries.
    active_discoveries: Vec<ActiveDiscovery>,
    /// Next LOADng sequence number.
    loadng_seq: u16,
    /// This node's geographic coordinates (for GPSR).
    node_coords: Option<GeoCoords>,
    /// Neighbor coordinates (link-local -> coords).
    neighbor_coords: std::collections::HashMap<[u8; 16], GeoCoords>,
}

#[cfg(feature = "std")]
impl HybridRouter {
    /// Create a new hybrid router.
    pub fn new(node_address: [u8; 16]) -> Self {
        Self {
            node_address,
            gradient_table: GradientTable::default(),
            rpl_parent: None,
            rpl_joined: false,
            mesh_prefixes: Vec::new(),
            pending_queue: std::collections::HashMap::new(),
            max_pending_per_dest: 3,
            active_discoveries: Vec::new(),
            loadng_seq: 0,
            node_coords: None,
            neighbor_coords: std::collections::HashMap::new(),
        }
    }

    /// Classify an IPv6 destination address (spec 7.2 table).
    pub fn classify_address(&self, addr: &[u8; 16]) -> AddressClass {
        // Link-local: fe80::/10 (first 10 bits = 1111111010)
        // Check bytes: fe80:: through febf::
        if addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80 {
            return AddressClass::LinkLocal;
        }

        // ULA: fd00::/8
        if addr[0] == 0xfd {
            return AddressClass::MeshLocal;
        }

        // Check configured mesh prefixes
        for prefix in &self.mesh_prefixes {
            if prefix.contains(addr) {
                return AddressClass::MeshLocal;
            }
        }

        AddressClass::External
    }

    /// Make a routing decision for a packet (spec 7.2 pseudocode).
    ///
    /// Returns the decision and optional next-hop. For Queue decisions,
    /// the packet should be passed to `queue_pending`.
    pub fn route(&self, dst: &[u8; 16], now_ms: u32) -> RouteResult {
        // Check for local delivery first
        if *dst == self.node_address {
            return RouteResult::deliver_local();
        }

        let addr_class = self.classify_address(dst);

        match addr_class {
            AddressClass::LinkLocal => {
                // Link-local: destination IS the next hop
                RouteResult::forward(*dst)
            }
            AddressClass::MeshLocal => self.route_mesh_local(dst, now_ms),
            AddressClass::External => self.route_external(),
        }
    }

    /// Route to a mesh-local address (ULA or mesh GUA).
    fn route_mesh_local(&self, dst: &[u8; 16], now_ms: u32) -> RouteResult {
        // Check gradient table for existing route
        if let Some(entry) = self.gradient_table.lookup(dst, now_ms) {
            return RouteResult::forward(entry.next_hop);
        }

        // No gradient found - need LOADng discovery
        // Try GPSR fallback if we have coords (spec 9.7)
        if let Some(next_hop) = self.gpsr_forward(dst, now_ms) {
            return RouteResult::forward(next_hop);
        }

        // Queue for LOADng discovery
        RouteResult::queue()
    }

    /// Route to an external address (via RPL border router).
    fn route_external(&self) -> RouteResult {
        if !self.rpl_joined {
            return RouteResult::drop();
        }

        match self.rpl_parent {
            Some(parent) => RouteResult::forward(parent),
            None => RouteResult::drop(),
        }
    }

    /// GPSR greedy forwarding: find neighbor closest to destination (spec 9.7).
    fn gpsr_forward(&self, dst: &[u8; 16], _now_ms: u32) -> Option<[u8; 16]> {
        // Need our own coords
        let my_coords = self.node_coords?;

        // Need destination coords (from gradient table entry, even if expired)
        let dst_coords = self
            .gradient_table
            .iter()
            .find(|e| e.destination == *dst)
            .and_then(|e| e.coords)?;

        // Validate coords
        if !is_valid_coords(&dst_coords) || !is_valid_coords(&my_coords) {
            return None;
        }

        let my_dist = haversine(&my_coords, &dst_coords);
        let mut best_neighbor: Option<[u8; 16]> = None;
        let mut best_dist = my_dist; // Must make progress

        for (neighbor, coords) in &self.neighbor_coords {
            if !is_valid_coords(coords) {
                continue;
            }
            let d = haversine(coords, &dst_coords);
            if d < best_dist {
                best_dist = d;
                best_neighbor = Some(*neighbor);
            }
        }

        best_neighbor
    }

    /// Queue a packet pending route discovery.
    pub fn queue_pending(&mut self, data: Vec<u8>, dst: [u8; 16], priority: u8, now_ms: u32) {
        let pending = PendingPacket {
            data,
            destination: dst,
            queued_at_ms: now_ms,
            priority,
        };

        let queue = self.pending_queue.entry(dst).or_default();

        queue.push_back(pending);

        // If over limit, evict lowest-priority packet (highest `priority` u8 value,
        // tie broken by oldest `queued_at_ms`). Prevents high-prio packets being
        // evicted by later low-prio ones.
        if queue.len() > self.max_pending_per_dest {
            if let Some((idx, _)) = queue
                .iter()
                .enumerate()
                .max_by_key(|(_, p)| (p.priority, std::cmp::Reverse(p.queued_at_ms)))
            {
                queue.remove(idx);
            }
        }
    }

    /// Get pending packets for a destination (after route discovery succeeds).
    pub fn get_pending(&mut self, dst: &[u8; 16]) -> Vec<PendingPacket> {
        self.pending_queue
            .remove(dst)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Clear pending packets for a destination. Returns count cleared.
    pub fn clear_pending(&mut self, dst: &[u8; 16]) -> usize {
        self.pending_queue.remove(dst).map(|q| q.len()).unwrap_or(0)
    }

    /// Expire pending packets older than timeout_ms. Returns count expired.
    pub fn expire_pending(&mut self, now_ms: u32, timeout_ms: u32) -> usize {
        let mut expired = 0;

        self.pending_queue.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|p| now_ms.wrapping_sub(p.queued_at_ms) < timeout_ms);
            expired += before - queue.len();
            !queue.is_empty()
        });

        expired
    }

    /// Start a LOADng route discovery for a destination.
    /// Returns the RREQ to broadcast.
    pub fn start_discovery(&mut self, dst: [u8; 16], now_ms: u32) -> Rreq {
        if let Some(discovery) = self
            .active_discoveries
            .iter_mut()
            .find(|d| d.destination == dst)
        {
            discovery.sent_at_ms = now_ms;
            return discovery.discovery.rreq();
        }

        let seq = self.loadng_seq;
        self.loadng_seq = self.loadng_seq.wrapping_add(1);

        let idle = RouteDiscovery::<Idle>::new(
            lichen_core::addr::Ipv6Addr(self.node_address),
            lichen_core::addr::Ipv6Addr(dst),
            seq,
        );
        let (searching, rreq) = idle.start();

        self.active_discoveries.push(ActiveDiscovery {
            destination: dst,
            discovery: searching,
            sent_at_ms: now_ms,
        });

        rreq
    }

    /// Handle LOADng RREP received. Installs gradient and returns pending packets.
    pub fn on_rrep_received(
        &mut self,
        dst: [u8; 16],
        next_hop: [u8; 16],
        hop_count: u8,
        seq_num: u16,
        now_ms: u32,
    ) -> Vec<PendingPacket> {
        // Install gradient entry
        let entry = GradientEntry {
            destination: dst,
            next_hop,
            hop_count,
            seq_num,
            source: GradientSource::Rrep,
            expires_ms: now_ms.wrapping_add(GRADIENT_TIMEOUT_MS),
            coords: None,
        };
        self.gradient_table.update(entry, now_ms);

        // Remove active discovery
        self.active_discoveries.retain(|d| d.destination != dst);

        // Return pending packets
        self.get_pending(&dst)
    }

    /// Called when route discovery times out. Advances expanding ring or fails.
    /// Returns Some(Rreq) to retry, or None if all rings exhausted.
    pub fn on_discovery_timeout(&mut self, dst: &[u8; 16], now_ms: u32) -> Option<Rreq> {
        let idx = self
            .active_discoveries
            .iter()
            .position(|d| &d.destination == dst)?;
        let discovery = self.active_discoveries.remove(idx);

        match discovery.discovery.advance_ring() {
            Ok((searching, rreq)) => {
                self.active_discoveries.push(ActiveDiscovery {
                    destination: discovery.destination,
                    discovery: searching,
                    sent_at_ms: now_ms,
                });
                Some(rreq)
            }
            Err(_failed) => {
                // All rings exhausted - drop pending packets
                self.clear_pending(&discovery.destination);
                None
            }
        }
    }

    /// Process received announce and update gradient table.
    pub fn process_announce(
        &mut self,
        originator_iid: &[u8; 8],
        from_neighbor: [u8; 16],
        hop_count: u8,
        seq_num: u16,
        coords: Option<GeoCoords>,
        now_ms: u32,
    ) -> bool {
        // Construct full destination address (link-local with IID)
        let mut dst = [0u8; 16];
        dst[0] = 0xfe;
        dst[1] = 0x80;
        dst[8..].copy_from_slice(originator_iid);

        let entry = GradientEntry {
            destination: dst,
            next_hop: from_neighbor,
            hop_count,
            seq_num,
            source: GradientSource::Announce,
            expires_ms: now_ms.wrapping_add(GRADIENT_TIMEOUT_MS),
            coords,
        };

        self.gradient_table.update(entry, now_ms)
    }

    /// Install a gradient from passive learning (forwarded data).
    pub fn learn_from_data(&mut self, src: [u8; 16], from_neighbor: [u8; 16], now_ms: u32) {
        let entry = GradientEntry {
            destination: src,
            next_hop: from_neighbor,
            hop_count: 1, // Assume 1 hop for passive learning
            seq_num: 0,   // No sequence for data-learned
            source: GradientSource::Data,
            expires_ms: now_ms.wrapping_add(crate::gradient::DATA_GRADIENT_TIMEOUT_MS),
            coords: None,
        };
        self.gradient_table.update(entry, now_ms);
    }

    /// Add a mesh-local prefix.
    pub fn add_mesh_prefix(&mut self, prefix: [u8; 16], prefix_len: u8) {
        self.mesh_prefixes.push(MeshPrefix::new(prefix, prefix_len));
    }

    /// Remove a mesh-local prefix.
    pub fn remove_mesh_prefix(&mut self, prefix: &[u8; 16]) {
        self.mesh_prefixes.retain(|p| &p.prefix != prefix);
    }

    /// Update RPL parent and join state.
    pub fn set_rpl_state(&mut self, joined: bool, parent: Option<[u8; 16]>) {
        self.rpl_joined = joined;
        self.rpl_parent = parent;
    }

    /// Set this node's geographic coordinates.
    pub fn set_node_coords(&mut self, coords: GeoCoords) {
        self.node_coords = Some(coords);
    }

    /// Update neighbor coordinates (from their announce).
    pub fn update_neighbor_coords(&mut self, neighbor: [u8; 16], coords: GeoCoords) {
        self.neighbor_coords.insert(neighbor, coords);
    }

    /// Get this node's address.
    pub fn node_address(&self) -> [u8; 16] {
        self.node_address
    }

    /// Whether any LOADng discovery is active.
    pub fn has_active_discoveries(&self) -> bool {
        !self.active_discoveries.is_empty()
    }

    /// Get active discovery destinations.
    pub fn active_discovery_destinations(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.active_discoveries.iter().map(|d| &d.destination)
    }
}

#[cfg(feature = "std")]
/// Validate geographic coordinates.
#[cfg(feature = "std")]
fn is_valid_coords(coords: &GeoCoords) -> bool {
    if coords.lat.is_nan()
        || coords.lat.is_infinite()
        || coords.lon.is_nan()
        || coords.lon.is_infinite()
    {
        return false;
    }
    // Reject null island (0, 0) as likely invalid GPS data
    if coords.lat == 0.0 && coords.lon == 0.0 {
        return false;
    }
    // Valid range
    coords.lat >= -90.0 && coords.lat <= 90.0 && coords.lon >= -180.0 && coords.lon <= 180.0
}

#[cfg(feature = "std")]
/// Haversine distance in meters between two (lat, lon) points.
#[cfg(feature = "std")]
fn haversine(c1: &GeoCoords, c2: &GeoCoords) -> f32 {
    const EARTH_RADIUS_M: f32 = 6_371_000.0;

    let lat1 = c1.lat.to_radians();
    let lon1 = c1.lon.to_radians();
    let lat2 = c2.lat.to_radians();
    let lon2 = c2.lon.to_radians();

    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;

    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    // Clamp for floating point errors
    let c = 2.0 * libm::asinf(libm::sqrtf(a.min(1.0)));

    EARTH_RADIUS_M * c
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

    fn ula(suffix: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[15] = suffix;
        addr
    }

    fn gua(suffix: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = suffix;
        addr
    }

    #[test]
    fn classify_link_local() {
        let router = HybridRouter::new(link_local(1));
        assert_eq!(
            router.classify_address(&link_local(2)),
            AddressClass::LinkLocal
        );

        // Test full fe80::/10 range (fe80:: through febf::)
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0xbf;
        assert_eq!(router.classify_address(&addr), AddressClass::LinkLocal);

        // fec0:: is NOT link-local
        addr[1] = 0xc0;
        assert_ne!(router.classify_address(&addr), AddressClass::LinkLocal);
    }

    #[test]
    fn classify_ula() {
        let router = HybridRouter::new(link_local(1));
        assert_eq!(router.classify_address(&ula(2)), AddressClass::MeshLocal);
    }

    #[test]
    fn classify_external() {
        let router = HybridRouter::new(link_local(1));
        assert_eq!(router.classify_address(&gua(2)), AddressClass::External);
    }

    #[test]
    fn classify_mesh_prefix() {
        let mut router = HybridRouter::new(link_local(1));

        // GUA not in any prefix - external
        assert_eq!(router.classify_address(&gua(2)), AddressClass::External);

        // Add mesh prefix
        let mut prefix = gua(0);
        prefix[15] = 0; // Prefix base
        router.add_mesh_prefix(prefix, 64);

        // Now GUA with matching prefix is mesh-local
        assert_eq!(router.classify_address(&gua(2)), AddressClass::MeshLocal);
    }

    #[test]
    fn route_link_local_is_forward() {
        let router = HybridRouter::new(link_local(1));
        let result = router.route(&link_local(2), 1000);
        assert_eq!(result.decision, RouteDecision::Forward);
        assert_eq!(result.next_hop, Some(link_local(2)));
    }

    #[test]
    fn route_self_is_deliver_local() {
        let router = HybridRouter::new(link_local(1));
        let result = router.route(&link_local(1), 1000);
        assert_eq!(result.decision, RouteDecision::DeliverLocal);
    }

    #[test]
    fn route_mesh_local_no_gradient_is_queue() {
        let router = HybridRouter::new(link_local(1));
        let result = router.route(&ula(2), 1000);
        assert_eq!(result.decision, RouteDecision::Queue);
    }

    #[test]
    fn route_mesh_local_with_gradient_is_forward() {
        let mut router = HybridRouter::new(link_local(1));

        // Install gradient
        let entry = GradientEntry {
            destination: ula(2),
            next_hop: link_local(10),
            hop_count: 3,
            seq_num: 100,
            source: GradientSource::Announce,
            expires_ms: 1000 + GRADIENT_TIMEOUT_MS,
            coords: None,
        };
        router.gradient_table.update(entry, 1000);

        let result = router.route(&ula(2), 1000);
        assert_eq!(result.decision, RouteDecision::Forward);
        assert_eq!(result.next_hop, Some(link_local(10)));
    }

    #[test]
    fn route_external_unjoined_is_drop() {
        let router = HybridRouter::new(link_local(1));
        let result = router.route(&gua(2), 1000);
        assert_eq!(result.decision, RouteDecision::Drop);
    }

    #[test]
    fn route_external_joined_is_forward_to_parent() {
        let mut router = HybridRouter::new(link_local(1));
        router.set_rpl_state(true, Some(link_local(0)));

        let result = router.route(&gua(2), 1000);
        assert_eq!(result.decision, RouteDecision::Forward);
        assert_eq!(result.next_hop, Some(link_local(0)));
    }

    #[test]
    fn pending_queue_fifo() {
        let mut router = HybridRouter::new(link_local(1));
        let dst = ula(2);

        router.queue_pending(vec![1, 2, 3], dst, 2, 1000);
        router.queue_pending(vec![4, 5, 6], dst, 2, 2000);

        let pending = router.get_pending(&dst);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].data, vec![1, 2, 3]);
        assert_eq!(pending[1].data, vec![4, 5, 6]);
    }

    #[test]
    fn pending_queue_limit() {
        let mut router = HybridRouter::new(link_local(1));
        router.max_pending_per_dest = 2;
        let dst = ula(2);

        router.queue_pending(vec![1], dst, 2, 1000);
        router.queue_pending(vec![2], dst, 2, 2000);
        router.queue_pending(vec![3], dst, 2, 3000); // Should evict [1]

        let pending = router.get_pending(&dst);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].data, vec![2]);
        assert_eq!(pending[1].data, vec![3]);
    }

    #[test]
    fn expire_pending_removes_old() {
        let mut router = HybridRouter::new(link_local(1));
        let dst = ula(2);

        router.queue_pending(vec![1], dst, 2, 1000);
        router.queue_pending(vec![2], dst, 2, 5000);

        let expired = router.expire_pending(6000, 4000);
        assert_eq!(expired, 1);

        let pending = router.get_pending(&dst);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].data, vec![2]);
    }

    #[test]
    fn process_announce_installs_gradient() {
        let mut router = HybridRouter::new(link_local(1));
        let iid = [0x02, 0, 0, 0, 0, 0, 0, 5];
        let from = link_local(10);

        let updated = router.process_announce(&iid, from, 3, 100, None, 1000);
        assert!(updated);

        // Lookup by full address
        let mut dst = [0u8; 16];
        dst[0] = 0xfe;
        dst[1] = 0x80;
        dst[8..].copy_from_slice(&iid);

        let entry = router.gradient_table.lookup(&dst, 1000).unwrap();
        assert_eq!(entry.hop_count, 3);
        assert_eq!(entry.next_hop, from);
    }

    #[test]
    fn haversine_distance() {
        // Seattle (47.6, -122.3) to Portland (45.5, -122.7)
        let seattle = GeoCoords {
            lat: 47.6,
            lon: -122.3,
        };
        let portland = GeoCoords {
            lat: 45.5,
            lon: -122.7,
        };

        let dist = haversine(&seattle, &portland);
        // Should be ~233 km
        assert!(dist > 230_000.0 && dist < 240_000.0);
    }

    #[test]
    fn gpsr_forwards_to_closer_neighbor() {
        let mut router = HybridRouter::new(link_local(1));

        // Set our coords (Seattle)
        router.set_node_coords(GeoCoords {
            lat: 47.6,
            lon: -122.3,
        });

        // Add destination with coords (San Francisco)
        let dst = ula(99);
        let entry = GradientEntry {
            destination: dst,
            next_hop: [0; 16], // Doesn't matter
            hop_count: 10,
            seq_num: 1,
            source: GradientSource::Announce,
            expires_ms: 0, // Expired, but coords still used
            coords: Some(GeoCoords {
                lat: 37.8,
                lon: -122.4,
            }),
        };
        router.gradient_table.update(entry, 0);

        // Add neighbors
        // Neighbor A (Portland) - closer to SF
        router.update_neighbor_coords(
            link_local(10),
            GeoCoords {
                lat: 45.5,
                lon: -122.7,
            },
        );
        // Neighbor B (Vancouver) - farther from SF
        router.update_neighbor_coords(
            link_local(20),
            GeoCoords {
                lat: 49.3,
                lon: -123.1,
            },
        );

        let result = router.gpsr_forward(&dst, 1000);
        assert_eq!(result, Some(link_local(10))); // Portland is closer
    }

    #[test]
    fn mesh_prefix_contains() {
        let mut prefix_bytes = [0u8; 16];
        prefix_bytes[0] = 0x20;
        prefix_bytes[1] = 0x01;
        prefix_bytes[2] = 0x0d;
        prefix_bytes[3] = 0xb8;

        let prefix = MeshPrefix::new(prefix_bytes, 32);

        // Address within prefix
        let mut addr1 = prefix_bytes;
        addr1[15] = 1;
        assert!(prefix.contains(&addr1));

        // Address outside prefix
        let mut addr2 = [0u8; 16];
        addr2[0] = 0x20;
        addr2[1] = 0x01;
        addr2[2] = 0x0d;
        addr2[3] = 0xb9; // Different
        assert!(!prefix.contains(&addr2));
    }
}
