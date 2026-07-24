//! Meshtastic node ID to LICHEN IPv6 address mapping.
//!
//! Meshtastic uses 32-bit node IDs while LICHEN uses 128-bit IPv6 addresses
//! derived from Ed25519 public keys. This module provides bidirectional
//! mapping between the two address spaces.

#[cfg(any(feature = "alloc", test))]
use alloc::vec::Vec;
use core::fmt;
use hashbrown::HashMap;
use lichen_link::{iid_from_pubkey, PublicKey};

// Re-export Ipv6Addr from lichen-core
pub use lichen_core::addr::Ipv6Addr;

/// Link-local prefix (fe80::/64).
const LINK_LOCAL_PREFIX: [u8; 8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0];

/// Marker for synthetic IIDs: first 4 bytes are 0x4d_45_53_48 ("MESH").
const SYNTHETIC_MARKER: [u8; 4] = [0x4d, 0x45, 0x53, 0x48];

/// Meshtastic 32-bit node identifier.
///
/// This newtype wrapper provides type safety for Meshtastic node IDs,
/// preventing accidental confusion with other `u32` values like port numbers,
/// sequence numbers, or channel indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MeshtasticNodeId(u32);

impl MeshtasticNodeId {
    /// Create a new node ID from a raw `u32`.
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw `u32` value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Convert to big-endian bytes.
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Create from big-endian bytes.
    #[inline]
    pub const fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

impl From<u32> for MeshtasticNodeId {
    #[inline]
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<MeshtasticNodeId> for u32 {
    #[inline]
    fn from(id: MeshtasticNodeId) -> Self {
        id.0
    }
}

impl fmt::Display for MeshtasticNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "!{:08x}", self.0)
    }
}

/// Extension trait for Meshtastic-specific IPv6 address operations.
pub trait Ipv6AddrMeshtasticExt {
    /// Returns true if this address has a synthetic IID (unknown Meshtastic node).
    fn is_synthetic(&self) -> bool;

    /// Extract the Meshtastic node ID from a synthetic address.
    fn synthetic_node_id(&self) -> Option<MeshtasticNodeId>;

    /// Get the interface identifier (IID) portion of the address.
    fn iid(&self) -> [u8; 8];
}

impl Ipv6AddrMeshtasticExt for Ipv6Addr {
    fn is_synthetic(&self) -> bool {
        self.0[8..12] == SYNTHETIC_MARKER
    }

    fn synthetic_node_id(&self) -> Option<MeshtasticNodeId> {
        if self.is_synthetic() {
            Some(MeshtasticNodeId::from_be_bytes([
                self.0[12], self.0[13], self.0[14], self.0[15],
            ]))
        } else {
            None
        }
    }

    fn iid(&self) -> [u8; 8] {
        let mut iid = [0u8; 8];
        iid.copy_from_slice(&self.0[8..16]);
        iid
    }
}

/// Entry storing a node's public key and derived IID.
#[derive(Clone, Debug)]
struct NodeEntry {
    pubkey: PublicKey,
    iid: [u8; 8],
}

/// Maps between Meshtastic node IDs and LICHEN IPv6 addresses.
#[derive(Debug, Default)]
pub struct AddressMapper {
    by_node_id: HashMap<MeshtasticNodeId, NodeEntry>,
    by_iid: HashMap<[u8; 8], MeshtasticNodeId>,
}

impl AddressMapper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Learn (or update) the mapping from a Meshtastic node ID to a LICHEN
    /// public key (and its derived IID).
    ///
    /// Implements TOFU key pinning per IID: the first pubkey seen for a given
    /// IID is pinned; subsequent different pubkeys for the same IID are
    /// rejected. This fixes the collision/stale mapping issue (see bead
    /// project-LICHEN-fmjo). Node key rotation (different IID) is allowed
    /// and cleans up the old mapping.
    ///
    /// Returns `true` if the mapping was accepted/updated, `false` if
    /// rejected due to TOFU violation (collision on IID with different key).
    pub fn learn_mapping(&mut self, node_id: MeshtasticNodeId, pubkey: &PublicKey) -> bool {
        let iid = iid_from_pubkey(pubkey);

        // TOFU/collision check: reject if IID already pinned to a different pubkey.
        // This prevents the by_iid map from pointing to the wrong node_id and
        // avoids stale entries when pubkeys collide on the first 8 bytes of hash.
        if let Some(&existing_node) = self.by_iid.get(&iid) {
            if let Some(existing_entry) = self.by_node_id.get(&existing_node) {
                if existing_entry.pubkey != *pubkey {
                    return false; // TOFU violation or IID collision; keep pinned mapping
                }
            }
            if existing_node != node_id {
                return false; // different node claiming same IID
            }
        }

        // Handle update for this node_id (e.g. rekeying changes IID)
        if let Some(old) = self.by_node_id.get(&node_id) {
            if old.pubkey == *pubkey && old.iid == iid {
                return true; // no change
            }
            if old.iid != iid {
                let _ = self.by_iid.remove(&old.iid);
            }
        } else if let Some(&existing_node) = self.by_iid.get(&iid) {
            if existing_node != node_id {
                let _ = self.by_node_id.remove(&existing_node);
            }
        }

        self.by_iid.insert(iid, node_id);
        self.by_node_id.insert(
            node_id,
            NodeEntry {
                pubkey: *pubkey,
                iid,
            },
        );
        true
    }

    pub fn meshtastic_to_ipv6(&self, node_id: MeshtasticNodeId) -> Ipv6Addr {
        if let Some(entry) = self.by_node_id.get(&node_id) {
            iid_to_link_local(&entry.iid)
        } else {
            synthetic_addr(node_id)
        }
    }

    pub fn ipv6_to_meshtastic(&self, addr: Ipv6Addr) -> Option<MeshtasticNodeId> {
        if let Some(node_id) = addr.synthetic_node_id() {
            return Some(node_id);
        }

        let mut iid = addr.iid();
        iid[0] ^= 0x02;

        self.by_iid.get(&iid).copied()
    }

    pub fn get_pubkey(&self, node_id: MeshtasticNodeId) -> Option<&PublicKey> {
        self.by_node_id.get(&node_id).map(|e| &e.pubkey)
    }

    #[cfg(any(feature = "alloc", test))]
    pub fn known_nodes(&self) -> Vec<MeshtasticNodeId> {
        self.by_node_id.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.by_node_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_node_id.is_empty()
    }
}

fn iid_to_link_local(iid: &[u8; 8]) -> Ipv6Addr {
    let mut addr = [0u8; 16];
    addr[..8].copy_from_slice(&LINK_LOCAL_PREFIX);
    addr[8..16].copy_from_slice(iid);
    addr[8] ^= 0x02;
    Ipv6Addr(addr)
}

fn synthetic_addr(node_id: MeshtasticNodeId) -> Ipv6Addr {
    let id_bytes = node_id.to_be_bytes();
    Ipv6Addr([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        SYNTHETIC_MARKER[0],
        SYNTHETIC_MARKER[1],
        SYNTHETIC_MARKER[2],
        SYNTHETIC_MARKER[3],
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meshtastic_node_id_conversions() {
        let raw: u32 = 0x12345678;
        let node_id = MeshtasticNodeId::from(raw);
        assert_eq!(node_id.as_u32(), raw);
        assert_eq!(u32::from(node_id), raw);

        let bytes = node_id.to_be_bytes();
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(MeshtasticNodeId::from_be_bytes(bytes), node_id);
    }

    #[test]
    fn test_iid_from_pubkey_clears_ul_bit() {
        let pubkey = PublicKey::new([0u8; 32]);
        let iid = iid_from_pubkey(&pubkey);
        assert_eq!(iid[0] & 0x02, 0, "U/L bit must be cleared");
    }

    #[test]
    fn test_synthetic_addr_format() {
        let addr = synthetic_addr(MeshtasticNodeId::new(0x12345678));
        assert_eq!(&addr.0[0..8], &LINK_LOCAL_PREFIX);
        assert_eq!(&addr.0[8..12], &SYNTHETIC_MARKER);
        assert_eq!(&addr.0[12..16], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_synthetic_addr_roundtrip() {
        let node_id = MeshtasticNodeId::new(0xDEADBEEF);
        let addr = synthetic_addr(node_id);
        assert!(addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), Some(node_id));
    }

    #[test]
    fn test_learn_mapping_and_lookup() {
        let mut mapper = AddressMapper::new();
        let node_id = MeshtasticNodeId::new(0x12345678);
        let pubkey = PublicKey::new([0xAB; 32]);

        assert!(mapper.learn_mapping(node_id, &pubkey));
        let addr = mapper.meshtastic_to_ipv6(node_id);
        assert!(!addr.is_synthetic());
        let result = mapper.ipv6_to_meshtastic(addr);
        assert_eq!(result, Some(node_id));
    }

    #[test]
    fn test_tofu_collision_rejected() {
        let mut mapper = AddressMapper::new();
        let node1 = MeshtasticNodeId::new(0x11111111);
        let node2 = MeshtasticNodeId::new(0x22222222);
        let pubkey1 = PublicKey::new([0x11; 32]);
        let pubkey2 = PublicKey::new([0x22; 32]);
        let pubkey3 = PublicKey::new([0x33; 32]);

        // First learn succeeds
        assert!(mapper.learn_mapping(node1, &pubkey1));

        // Same IID (via same pubkey) but different node_id: rejected (prevents hijack)
        assert!(!mapper.learn_mapping(node2, &pubkey1));

        // Verify lookup still points to first node
        let addr1 = mapper.meshtastic_to_ipv6(node1);
        assert_eq!(mapper.ipv6_to_meshtastic(addr1), Some(node1));

        // Rekey same node (new pubkey -> new IID): allowed, updates mapping
        assert!(mapper.learn_mapping(node1, &pubkey3));
        let addr3 = mapper.meshtastic_to_ipv6(node1);
        assert_eq!(mapper.ipv6_to_meshtastic(addr3), Some(node1));
        assert_eq!(mapper.get_pubkey(node1), Some(&pubkey3));
    }

    #[test]
    fn test_unknown_node_gets_synthetic() {
        let mapper = AddressMapper::new();
        let node_id = MeshtasticNodeId::new(0x87654321);

        let addr = mapper.meshtastic_to_ipv6(node_id);
        assert!(addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), Some(node_id));
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut mapper = AddressMapper::new();
        assert!(mapper.is_empty());
        assert_eq!(mapper.len(), 0);

        assert!(mapper.learn_mapping(MeshtasticNodeId::new(1), &PublicKey::new([0x11; 32])));
        assert!(!mapper.is_empty());
        assert_eq!(mapper.len(), 1);
    }

    #[test]
    fn test_ipv6_addr_iid() {
        let addr = Ipv6Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(addr.iid(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_non_synthetic_has_no_node_id() {
        let mut mapper = AddressMapper::new();
        let node_id = MeshtasticNodeId::new(123);
        assert!(mapper.learn_mapping(node_id, &PublicKey::new([0xAA; 32])));
        let addr = mapper.meshtastic_to_ipv6(node_id);
        assert!(!addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), None);
    }

    // Tests requiring alloc feature
    #[cfg(feature = "alloc")]
    mod alloc_tests {
        use super::*;
        use alloc::format;
        use alloc::vec;

        #[test]
        fn test_meshtastic_node_id_display() {
            let node = MeshtasticNodeId::new(0xDEADBEEF);
            assert_eq!(format!("{}", node), "!deadbeef");

            let node_small = MeshtasticNodeId::new(0x123);
            assert_eq!(format!("{}", node_small), "!00000123");
        }

        #[test]
        fn test_known_nodes() {
            let mut mapper = AddressMapper::new();
            assert!(mapper.learn_mapping(MeshtasticNodeId::new(1), &PublicKey::new([0x11; 32])));
            assert!(mapper.learn_mapping(MeshtasticNodeId::new(2), &PublicKey::new([0x22; 32])));
            assert!(mapper.learn_mapping(MeshtasticNodeId::new(3), &PublicKey::new([0x33; 32])));

            let mut nodes = mapper.known_nodes();
            nodes.sort();
            assert_eq!(
                nodes,
                vec![
                    MeshtasticNodeId::new(1),
                    MeshtasticNodeId::new(2),
                    MeshtasticNodeId::new(3)
                ]
            );
        }
    }
}
