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

use crate::messages::{Dao, OptionIter, RplTarget, TransitInfo, OPT_RPL_TARGET, OPT_TRANSIT_INFO};

const MAX_CHAIN: usize = 64;

// ── Source Routing Header (RFC 6554) ─────────────────────────────────────────

/// RFC 6554 Source Routing Header, routing type 3 (uncompressed).
///
/// `addresses` are the hops still to visit; `segments_left` counts how many remain.
#[cfg(feature = "std")]
pub struct SourceRoutingHeader {
    pub segments_left: u8,
    pub addresses: Vec<[u8; 16]>,
}

#[cfg(feature = "std")]
impl SourceRoutingHeader {
    /// Encode to the SRH wire format: 6 fixed bytes + 16 bytes per address.
    pub fn encode(&self, out: &mut [u8]) -> usize {
        let needed = 6 + self.addresses.len() * 16;
        if out.len() < needed {
            return 0;
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
        needed
    }

    /// Parse from SRH wire bytes (starting at the routing-type byte).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 || data[0] != 3 {
            return None;
        }
        let addr_bytes = &data[6..];
        if !addr_bytes.len().is_multiple_of(16) {
            return None;
        }
        let mut addresses = Vec::with_capacity(addr_bytes.len() / 16);
        for chunk in addr_bytes.chunks_exact(16) {
            let mut a = [0u8; 16];
            a.copy_from_slice(chunk);
            addresses.push(a);
        }
        Some(Self {
            segments_left: data[1],
            addresses,
        })
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

/// Root-side map from target address to the ordered hop list `[h1, ..., target]`.
///
/// The first element is the root's direct neighbour; the last is the target.
/// A single-hop target has a one-element path containing only itself.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct RoutingTable {
    routes: HashMap<[u8; 16], Vec<[u8; 16]>>,
}

#[cfg(feature = "std")]
impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(&mut self, target: [u8; 16], path: Vec<[u8; 16]>) {
        self.routes.insert(target, path);
    }

    pub fn remove_route(&mut self, target: &[u8; 16]) {
        self.routes.remove(target);
    }

    /// Return the path for `target`, or `None` if no route is known.
    pub fn lookup(&self, target: &[u8; 16]) -> Option<&[[u8; 16]]> {
        self.routes.get(target).map(|v| v.as_slice())
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
pub struct DaoManager {
    pub node_address: [u8; 16],
    pub is_root: bool,
    pub rpl_instance_id: u8,
    pub dodag_id: [u8; 16],
    pub routing_table: RoutingTable,
    dao_sequence: u8,
    parent_map: HashMap<[u8; 16], [u8; 16]>,
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
        let mut pos = dao.encode(&mut buf).unwrap_or(0);

        let target = RplTarget {
            prefix_len: 128,
            prefix: self.node_address,
        };
        let mut tmp = [0u8; 24];
        let n = target.encode_option(&mut tmp).unwrap_or(0);
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;

        let transit = TransitInfo {
            path_control: 0,
            path_sequence: 0,
            path_lifetime: 255,
            parent_address: parent_addr,
        };
        pos += transit.encode_option(&mut buf[pos..]).unwrap_or(0);

        buf[..pos].to_vec()
    }

    /// Process a received DAO on the root. Returns `true` if a route was installed.
    ///
    /// `dao_bytes` is the raw DAO wire bytes (base object + options).
    pub fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
        if !self.is_root {
            return false;
        }
        let (target, parent) = match self.extract_edge(dao_bytes) {
            Some(pair) => pair,
            None => return false,
        };
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
                    if let Ok(t) = RplTarget::parse(opt.data) {
                        target = Some(t.prefix);
                    }
                }
                OPT_TRANSIT_INFO => {
                    if let Ok(ti) = TransitInfo::parse(opt.data) {
                        parent = Some(ti.parent_address);
                    }
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
                self.routing_table.add_route(target, path);
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
        let path: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        table.add_route(target, path.clone());

        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(&target), Some(path.as_slice()));

        table.remove_route(&target);
        assert!(table.lookup(&target).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn srh_encode_decode_roundtrip() {
        let addresses: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        let srh = SourceRoutingHeader {
            segments_left: 2,
            addresses: addresses.clone(),
        };
        let mut buf = [0u8; 38]; // 6 + 2*16
        let n = srh.encode(&mut buf);
        assert_eq!(n, 38);
        assert_eq!(buf[0], 3); // routing type
        assert_eq!(buf[1], 2); // segments_left

        let decoded = SourceRoutingHeader::parse(&buf[..n]).unwrap();
        assert_eq!(decoded.segments_left, 2);
        assert_eq!(decoded.addresses, addresses);
    }

    #[test]
    fn srh_wrong_type_returns_none() {
        let mut buf = [0u8; 6];
        buf[0] = 0; // routing type 0, not 3
        assert!(SourceRoutingHeader::parse(&buf).is_none());
    }

    #[test]
    fn build_dao_produces_valid_options() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let dao_bytes = mgr.build_dao(ll(1));

        // Parse the DAO base
        let dao = Dao::parse(&dao_bytes).unwrap();
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
                    let t = RplTarget::parse(opt.data).unwrap();
                    assert_eq!(t.prefix, ll(2)); // advertises itself
                }
                OPT_TRANSIT_INFO => {
                    found_transit = true;
                    let ti = TransitInfo::parse(opt.data).unwrap();
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
        let d1 = Dao::parse(&mgr.build_dao(ll(1))).unwrap();
        let d2 = Dao::parse(&mgr.build_dao(ll(1))).unwrap();
        assert_eq!(d2.dao_sequence, d1.dao_sequence + 1);
    }
}
