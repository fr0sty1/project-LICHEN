//! RPL routing table, DAO management, and source-routing header (RFC 6550 §6.7, RFC 6554).
//!
//! Ports `python/src/lichen/rpl/routing.py` and `python/src/lichen/rpl/dao.py`.
//!
//! - `RoutingTable` maps a /128 target to the ordered hop path from root to target.
//! - `DaoManager` builds DAOs (non-root) and assembles routes from incoming DAOs (root).
//! - `SourceRoutingHeader` encodes/decodes the RFC 6554 SRH wire format.

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    vec::Vec,
};

#[cfg(feature = "std")]
use crate::message::{
    Dao, OptionIter, RplError, RplTarget, TransitInfo, OPT_RPL_TARGET, OPT_TRANSIT_INFO,
};

#[cfg(feature = "std")]
const LOLLIPOP_CIRCULAR_BIT: u8 = 128;
#[cfg(feature = "std")]
const LOLLIPOP_SEQUENCE_WINDOW: u8 = 16;

#[cfg(feature = "std")]
fn seq_is_newer(new_seq: u8, old_seq: u8) -> bool {
    match (
        new_seq < LOLLIPOP_CIRCULAR_BIT,
        old_seq < LOLLIPOP_CIRCULAR_BIT,
    ) {
        (true, true) => new_seq > old_seq,
        (false, false) => {
            let diff = new_seq.wrapping_sub(old_seq) & 0x7F;
            diff > 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW
        }
        (true, false) => true,
        (false, true) => false,
    }
}
#[cfg(feature = "std")]
use lichen_core::error::{BufferTooSmall, TooShort};

#[cfg(feature = "std")]
const MAX_CHAIN: usize = 64;

// ── Source Routing Header (RFC 6554) ─────────────────────────────────────────

/// RFC 6554 Source Routing Header, routing type 3 (uncompressed).
///
/// `addresses` are the hops still to visit; `segments_left` counts how many remain.
#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct SourceRoutingHeader {
    pub segments_left: u8,
    pub addresses: Vec<[u8; 16]>,
}

#[cfg(feature = "std")]
impl SourceRoutingHeader {
    /// Encode to the SRH wire format: 6 fixed bytes + 16 bytes per address.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 6 + self.addresses.len() * 16;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = 3; // routing type
        out[1] = self.segments_left;
        out[2] = 0; // CmprI
        out[3] = 0; // CmprE
        out[4] = 0; // reserved
        out[5] = 0;
        for (i, addr) in self.addresses.iter().enumerate() {
            out[6 + i * 16..6 + (i + 1) * 16].copy_from_slice(addr);
        }
        Ok(needed)
    }

    /// Parse from SRH wire bytes (starting at the routing-type byte).
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 6 {
            return Err(TooShort::new(6, data.len()).into());
        }
        if data[0] != 3 {
            return Err(RplError::BadRoutingType(data[0]));
        }
        // SECURITY: Reject compressed SRHs (CmprI/CmprE > 0 per RFC 6554 Section 3).
        // We only support uncompressed addresses (16 bytes each). Compressed SRHs
        // would be parsed incorrectly, leading to misrouted packets.
        if data[2] != 0 || data[3] != 0 {
            return Err(RplError::InvalidOption);
        }
        let addr_bytes = &data[6..];
        if !addr_bytes.len().is_multiple_of(16) {
            return Err(RplError::InvalidOption);
        }
        let addresses: Vec<[u8; 16]> = addr_bytes
            .chunks_exact(16)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        let segments_left = data[1];
        if (segments_left as usize) > addresses.len() {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            segments_left,
            addresses,
        })
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteEntryState {
    Fresh,
    Stale,
    Expired,
}

#[cfg(feature = "std")]
impl RouteEntryState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Fresh, Self::Fresh)
                | (Self::Fresh, Self::Stale)
                | (Self::Fresh, Self::Expired)
                | (Self::Stale, Self::Fresh)
                | (Self::Stale, Self::Stale)
                | (Self::Stale, Self::Expired)
                | (Self::Expired, Self::Expired)
        )
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRouteEntryTransition {
    pub from: RouteEntryState,
    pub to: RouteEntryState,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub path: Vec<[u8; 16]>,
    pub state: RouteEntryState,
}

#[cfg(feature = "std")]
impl RouteEntry {
    pub fn fresh(path: &[[u8; 16]]) -> Self {
        Self {
            path: path.to_vec(),
            state: RouteEntryState::Fresh,
        }
    }

    fn transition_to(&mut self, next: RouteEntryState) -> Result<(), InvalidRouteEntryTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidRouteEntryTransition {
                from: self.state,
                to: next,
            })
        }
    }

    pub fn mark_stale(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Stale)
    }

    pub fn mark_expired(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Expired)
    }

    pub fn refresh(&mut self, path: &[[u8; 16]]) -> Result<(), InvalidRouteEntryTransition> {
        if self.state == RouteEntryState::Expired {
            return Err(InvalidRouteEntryTransition {
                from: self.state,
                to: RouteEntryState::Fresh,
            });
        }
        self.path = path.to_vec();
        self.transition_to(RouteEntryState::Fresh)
    }

    pub fn is_usable(&self) -> bool {
        self.state != RouteEntryState::Expired
    }
}

/// Root-side map from target address to the ordered hop list `[h1, ..., target]`.
///
/// The first element is the root's direct neighbour; the last is the target.
/// A single-hop target has a one-element path containing only itself.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct RoutingTable {
    routes: HashMap<[u8; 16], RouteEntry>,
}

#[cfg(feature = "std")]
impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) {
        match self.routes.get_mut(&target) {
            Some(entry) if entry.state != RouteEntryState::Expired => {
                entry
                    .refresh(path)
                    .expect("fresh or stale route entry can refresh");
            }
            _ => {
                self.routes.insert(target, RouteEntry::fresh(path));
            }
        }
    }

    pub fn remove_route(&mut self, target: &[u8; 16]) {
        self.routes.remove(target);
    }

    pub fn mark_stale(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes.get_mut(target).map(RouteEntry::mark_stale)
    }

    pub fn mark_expired(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes.get_mut(target).map(RouteEntry::mark_expired)
    }

    pub fn entry_state(&self, target: &[u8; 16]) -> Option<RouteEntryState> {
        self.routes.get(target).map(|entry| entry.state)
    }

    /// Return the path for `target`, or `None` if no route is known.
    pub fn lookup(&self, target: &[u8; 16]) -> Option<&[[u8; 16]]> {
        self.routes
            .get(target)
            .filter(|entry| entry.is_usable())
            .map(|entry| entry.path.as_slice())
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

// ── DAO manager ───────────────────────────────────────────────────────────────

/// Builds DAOs (non-root nodes) and assembles source routes from incoming DAOs (root).
///
/// On the root, `routing_table` is updated in place as DAOs arrive.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DaoManager {
    pub node_address: [u8; 16],
    pub is_root: bool,
    pub rpl_instance_id: u8,
    pub dodag_id: [u8; 16],
    pub routing_table: RoutingTable,
    dao_sequence: u8,
    parent_map: HashMap<[u8; 16], [u8; 16]>,
    /// Last accepted DAO sequence per target (replay protection).
    dao_seq_map: HashMap<[u8; 16], u8>,
}

#[cfg(feature = "std")]
impl DaoManager {
    pub fn new(node_address: [u8; 16], rpl_instance_id: u8, dodag_id: [u8; 16]) -> Self {
        Self {
            node_address,
            is_root: false,
            rpl_instance_id,
            dodag_id,
            routing_table: RoutingTable::new(),
            dao_sequence: 0,
            parent_map: HashMap::new(),
            dao_seq_map: HashMap::new(),
        }
    }

    pub fn as_root(node_address: [u8; 16], rpl_instance_id: u8, dodag_id: [u8; 16]) -> Self {
        let mut m = Self::new(node_address, rpl_instance_id, dodag_id);
        m.is_root = true;
        m
    }

    /// Build a DAO advertising this node with `parent_addr` as transit.
    ///
    /// Returns the encoded bytes: DAO base + RPL Target option + Transit Info option.
    pub fn build_dao(&mut self, parent_addr: [u8; 16]) -> Vec<u8> {
        self.dao_sequence = self.dao_sequence.wrapping_add(1);
        let dao = Dao {
            rpl_instance_id: self.rpl_instance_id,
            ack_requested: false,
            flags: 0,
            dao_sequence: self.dao_sequence,
            dodag_id: self.dodag_id,
        };

        let mut buf = [0u8; 64]; // DAO(20) + Target(20) + TransitInfo(22) = 62
        let mut pos = dao
            .write_to(&mut buf)
            .expect("DAO base (20 bytes) fits in 64-byte buffer");

        let target = RplTarget {
            prefix_len: 128,
            prefix: self.node_address,
        };
        let mut tmp = [0u8; 24];
        let n = target
            .write_to(&mut tmp)
            .expect("RPL Target option (19 bytes) fits in 24-byte buffer");
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;

        let transit = TransitInfo {
            path_control: 0,
            path_sequence: 0,
            path_lifetime: 255,
            parent_address: parent_addr,
        };
        pos += transit
            .write_to(&mut buf[pos..])
            .expect("TransitInfo option (22 bytes) fits in remaining buffer");

        buf[..pos].to_vec()
    }

    /// Process a received DAO on the root. Returns `true` if a route was installed.
    ///
    /// `dao_bytes` is the raw DAO wire bytes (base object + options).
    /// SECURITY: Validates DAO sequence to prevent replay attacks with stale routes.
    pub fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
        if !self.is_root {
            return false;
        }
        // Parse DAO to get sequence number
        let Ok(dao) = Dao::from_bytes(dao_bytes) else {
            return false;
        };
        let Some((target, parent)) = self.extract_edge(dao_bytes) else {
            return false;
        };
        // SECURITY: Reject stale DAO sequences to prevent replay attacks
        if let Some(&last_seq) = self.dao_seq_map.get(&target) {
            if !seq_is_newer(dao.dao_sequence, last_seq) {
                return false;
            }
        }
        self.dao_seq_map.insert(target, dao.dao_sequence);
        self.parent_map.insert(target, parent);
        self.rebuild_routes();
        true
    }

    fn extract_edge(&self, dao_bytes: &[u8]) -> Option<([u8; 16], [u8; 16])> {
        let options = Dao::options_tail(dao_bytes);
        let mut target: Option<[u8; 16]> = None;
        let mut parent: Option<[u8; 16]> = None;
        for opt in OptionIter::new(options) {
            let opt = opt.ok()?;
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    target = RplTarget::from_bytes(opt.data).ok().map(|t| t.prefix);
                }
                OPT_TRANSIT_INFO => {
                    parent = TransitInfo::from_bytes(opt.data)
                        .ok()
                        .map(|ti| ti.parent_address);
                }
                _ => {}
            }
        }
        Some((target?, parent?))
    }

    fn rebuild_routes(&mut self) {
        let targets: Vec<[u8; 16]> = self.parent_map.keys().copied().collect();
        for target in targets {
            if let Some(path) = self.assemble_path(target) {
                self.routing_table.add_route(target, &path);
            }
        }
    }

    /// Walk target → parent → … → root and return the reversed downward path.
    ///
    /// Returns `None` if the chain is incomplete or contains a loop.
    fn assemble_path(&self, target: [u8; 16]) -> Option<Vec<[u8; 16]>> {
        let mut chain: Vec<[u8; 16]> = Vec::new();
        let mut node = target;
        let mut visited: HashSet<[u8; 16]> = HashSet::new();

        loop {
            if node == self.node_address {
                break;
            }
            if visited.contains(&node) || chain.len() > MAX_CHAIN {
                return None;
            }
            visited.insert(node);
            chain.push(node);
            let parent = self.parent_map.get(&node)?;
            node = *parent;
        }

        chain.reverse();
        Some(chain)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn ll(iid: u8) -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid]
    }

    fn dodag_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xfd;
        id[15] = 1;
        id
    }

    #[test]
    fn routing_table_add_lookup_remove() {
        let mut table = RoutingTable::new();
        let target = ll(3);
        let path = [ll(2), ll(3)];
        table.add_route(target, &path);

        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(&target), Some(path.as_slice()));

        table.remove_route(&target);
        assert!(table.lookup(&target).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn route_entry_state_machine_allows_stale_refresh_and_rejects_expired_refresh() {
        let mut entry = RouteEntry::fresh(&[ll(2), ll(3)]);
        assert_eq!(entry.state, RouteEntryState::Fresh);

        entry.mark_stale().unwrap();
        assert_eq!(entry.state, RouteEntryState::Stale);

        entry.refresh(&[ll(4), ll(3)]).unwrap();
        assert_eq!(entry.state, RouteEntryState::Fresh);
        assert_eq!(entry.path, [ll(4), ll(3)]);

        entry.mark_expired().unwrap();
        assert_eq!(
            entry.refresh(&[ll(2), ll(3)]),
            Err(InvalidRouteEntryTransition {
                from: RouteEntryState::Expired,
                to: RouteEntryState::Fresh,
            })
        );
    }

    #[test]
    fn routing_table_hides_expired_routes_but_keeps_state_visible() {
        let mut table = RoutingTable::new();
        let target = ll(3);
        table.add_route(target, &[ll(2), ll(3)]);

        table.mark_stale(&target).unwrap().unwrap();
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Stale));
        assert!(table.lookup(&target).is_some());

        table.mark_expired(&target).unwrap().unwrap();
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Expired));
        assert!(table.lookup(&target).is_none());

        table.add_route(target, &[ll(4), ll(3)]);
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Fresh));
        assert_eq!(table.lookup(&target).unwrap(), &[ll(4), ll(3)]);
    }

    #[test]
    fn srh_encode_decode_roundtrip() {
        let addresses: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        let srh = SourceRoutingHeader {
            segments_left: 2,
            addresses: addresses.clone(),
        };
        let mut buf = [0u8; 38]; // 6 + 2*16
        let n = srh.write_to(&mut buf).unwrap();
        assert_eq!(n, 38);
        assert_eq!(buf[0], 3); // routing type
        assert_eq!(buf[1], 2); // segments_left

        let decoded = SourceRoutingHeader::from_bytes(&buf[..n]).unwrap();
        assert_eq!(decoded.segments_left, 2);
        assert_eq!(decoded.addresses, addresses);
    }

    #[test]
    fn srh_encode_buffer_too_small() {
        let addresses: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        let srh = SourceRoutingHeader {
            segments_left: 2,
            addresses,
        };
        let mut buf = [0u8; 37]; // one byte short of needed 38
        assert!(matches!(
            srh.write_to(&mut buf),
            Err(RplError::BufferTooSmall(_))
        ));
    }

    #[test]
    fn srh_wrong_type_returns_error() {
        let mut buf = [0u8; 6];
        buf[0] = 0; // routing type 0, not 3
        assert_eq!(
            SourceRoutingHeader::from_bytes(&buf),
            Err(RplError::BadRoutingType(0))
        );
    }

    #[test]
    fn build_dao_produces_valid_options() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let dao_bytes = mgr.build_dao(ll(1));

        // Parse the DAO base
        let dao = Dao::from_bytes(&dao_bytes).unwrap();
        assert_eq!(dao.dao_sequence, 1);
        assert_eq!(dao.dodag_id, dodag_id());

        // Parse options
        let options_data = Dao::options_tail(&dao_bytes);
        let mut found_target = false;
        let mut found_transit = false;
        for opt in OptionIter::new(options_data) {
            let opt = opt.unwrap();
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    found_target = true;
                    let t = RplTarget::from_bytes(opt.data).unwrap();
                    assert_eq!(t.prefix, ll(2)); // advertises itself
                }
                OPT_TRANSIT_INFO => {
                    found_transit = true;
                    let ti = TransitInfo::from_bytes(opt.data).unwrap();
                    assert_eq!(ti.parent_address, ll(1)); // via parent 1
                }
                _ => {}
            }
        }
        assert!(found_target);
        assert!(found_transit);
    }

    #[test]
    fn root_process_single_hop_dao_installs_route() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // Node ll(2) sends DAO: target=ll(2), parent=root
        let mut node2 = DaoManager::new(ll(2), 0, dodag_id());
        let dao = node2.build_dao(root_addr);

        assert!(root.process_dao(&dao));
        // Single-hop path: [ll(2)]
        let path = root.routing_table.lookup(&ll(2)).unwrap();
        assert_eq!(path, &[ll(2)]);
    }

    #[test]
    fn root_process_two_hop_dao_assembles_full_path() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // Node ll(2) sends DAO: target=ll(2), parent=root
        let mut node2 = DaoManager::new(ll(2), 0, dodag_id());
        root.process_dao(&node2.build_dao(root_addr));

        // Node ll(3) sends DAO: target=ll(3), parent=ll(2)
        let mut node3 = DaoManager::new(ll(3), 0, dodag_id());
        root.process_dao(&node3.build_dao(ll(2)));

        // Two-hop path: root → ll(2) → ll(3)
        let path = root.routing_table.lookup(&ll(3)).unwrap();
        assert_eq!(path, &[ll(2), ll(3)]);
    }

    #[test]
    fn incomplete_chain_does_not_install_route() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // ll(3) sends DAO pointing to ll(2), but ll(2) hasn't sent a DAO yet.
        let mut node3 = DaoManager::new(ll(3), 0, dodag_id());
        root.process_dao(&node3.build_dao(ll(2)));

        assert!(root.routing_table.lookup(&ll(3)).is_none());
    }

    #[test]
    fn dao_sequence_increments() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let d1 = Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap();
        let d2 = Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap();
        assert_eq!(d2.dao_sequence, d1.dao_sequence + 1);
    }

    #[test]
    fn replayed_dao_with_stale_sequence_rejected() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // Node ll(2) sends DAO with sequence 1
        let mut node2 = DaoManager::new(ll(2), 0, dodag_id());
        let dao1 = node2.build_dao(root_addr);
        assert!(root.process_dao(&dao1));
        assert!(root.routing_table.lookup(&ll(2)).is_some());

        // Node ll(2) sends DAO with sequence 2 (newer, should be accepted)
        let dao2 = node2.build_dao(root_addr);
        assert!(root.process_dao(&dao2));

        // Replay attack: attacker replays dao1 (sequence 1, now stale)
        assert!(!root.process_dao(&dao1), "stale DAO should be rejected");

        // Same sequence should also be rejected
        let dao2_copy = dao2.clone();
        assert!(
            !root.process_dao(&dao2_copy),
            "same sequence should be rejected"
        );
    }

    #[test]
    fn dao_sequence_comparison_handles_lollipop() {
        // RFC 6550 Section 9.1: DAOSequence is a lollipop counter
        // Linear region: 0-127, Circular region: 128-255

        // Linear region: simple comparison
        assert!(super::seq_is_newer(1, 0));
        assert!(super::seq_is_newer(127, 0));
        assert!(!super::seq_is_newer(0, 1));

        // Circular region: modular comparison with sequence window
        assert!(super::seq_is_newer(129, 128));
        assert!(super::seq_is_newer(144, 128)); // diff=16, within window
        assert!(!super::seq_is_newer(145, 128)); // diff=17, outside window
        assert!(super::seq_is_newer(255, 254));
        assert!(super::seq_is_newer(128, 255)); // wraps around within circular

        // Mixed: linear (restart) is always newer than circular
        assert!(super::seq_is_newer(0, 255));
        assert!(super::seq_is_newer(0, 128));
        assert!(super::seq_is_newer(127, 200));
        assert!(super::seq_is_newer(127, 128)); // key bug case from bead
        assert!(!super::seq_is_newer(200, 127)); // circular not newer than linear
        assert!(!super::seq_is_newer(128, 127)); // circular not newer than linear

        // Same sequence is not newer
        assert!(!super::seq_is_newer(100, 100));
        assert!(!super::seq_is_newer(200, 200));
    }
}
