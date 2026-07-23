//! Address types: Ipv6Addr (re-exported from lichen-ipv6) and NodeId (EUI-64).

// Re-export Addr from lichen-ipv6 as Ipv6Addr for backward compatibility.
// This eliminates the duplicate type definition while preserving the API.
pub use lichen_ipv6::Addr as Ipv6Addr;
use sha2::{Digest, Sha256, Sha512};

/// A 64-bit node identifier (EUI-64 derived from the radio hardware address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 8]);

impl NodeId {
    /// Derive the link-local IPv6 address from this EUI-64 (spec §6.2).
    ///
    /// Flips the U/L bit (bit 6 of octet 0) and prefixes with `fe80::/64`.
    /// NodeId is already EUI-64 — no `ff:fe` insertion (that is the separate
    /// MAC-48 → EUI-64 step, not needed here).
    pub fn link_local_addr(&self) -> Ipv6Addr {
        self.addr_with_prefix([0xfe, 0x80, 0, 0, 0, 0, 0, 0])
    }

    /// Derive a ULA or GUA address from this EUI-64 and a `/64` prefix.
    ///
    /// `prefix` is the high 8 bytes of the target address; the low 8 bytes
    /// are the EUI-64 interface identifier (U/L bit flipped per RFC 4291).
    /// Equivalent to `link_local_addr` but with a caller-supplied prefix.
    pub fn ula_addr(&self, prefix: [u8; 8]) -> Ipv6Addr {
        self.addr_with_prefix(prefix)
    }

    /// Reconstruct a NodeId from the interface identifier in an IPv6 address.
    ///
    /// Reverses the U/L bit flip (XOR 0x02 on first IID byte) performed by
    /// `link_local_addr` and `ula_addr`. Works for both link-local and ULA/GUA
    /// addresses per spec §6.1. Independent roundtrip oracle used in tests.
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        let mut iid = addr.iid();
        iid[0] ^= 0x02;
        NodeId(iid)
    }

    fn addr_with_prefix(&self, prefix: [u8; 8]) -> Ipv6Addr {
        let e = self.0;
        Ipv6Addr([
            prefix[0],
            prefix[1],
            prefix[2],
            prefix[3],
            prefix[4],
            prefix[5],
            prefix[6],
            prefix[7],
            e[0] ^ 0x02,
            e[1],
            e[2],
            e[3],
            e[4],
            e[5],
            e[6],
            e[7],
        ])
    }
}

/// Derive 16-byte Yggdrasil 02xx::/7 address from Ed25519 pubkey per spec/06-security.md §8.5
/// and test/vectors/yggdrasil-derivation.json. Uses SHA-512(pubkey)[0:7] for bytes 1-7
/// and IID = SHA-256(pubkey)[0:8] with U/L bit cleared (`iid[0] &= 0b1111_1101`) for bytes 8-15.
/// Lower 64 bits bind key to address. Must match C `lichen_identity_ygg_addr_from_ed25519`
/// and previous `yggdrasil_addr_from_pubkey`.
pub fn ygg_addr_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    let hash512 = Sha512::digest(pubkey);
    let digest256 = Sha256::digest(pubkey);
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&digest256[0..8]);
    iid[0] &= 0b1111_1101;
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1..8].copy_from_slice(&hash512[0..7]);
    addr[8..16].copy_from_slice(&iid);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_flips_ul_bit() {
        let node = NodeId([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let ll = node.link_local_addr();
        assert_eq!(ll.0[0], 0xfe);
        assert_eq!(ll.0[1], 0x80);
        assert_eq!(ll.0[8], 0x00); // 0x02 ^ 0x02 = 0x00
    }

    #[test]
    fn ula_addr_uses_supplied_prefix() {
        let node = NodeId([0x02, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x01]);
        let prefix = [0xfd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00];
        let ula = node.ula_addr(prefix);
        assert_eq!(&ula.0[..8], &prefix);
        assert_eq!(ula.0[8], 0x00); // 0x02 ^ 0x02
        assert_eq!(&ula.0[9..], &[0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn is_link_local() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        assert!(node.link_local_addr().is_link_local());
    }

    #[test]
    fn ula_addr_is_not_link_local() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(!node.ula_addr(prefix).is_link_local());
    }

    #[test]
    fn is_ula_fd00() {
        // fd00::/8 is a common ULA prefix
        let addr = Ipv6Addr([0xfd, 0x00, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_ula());
        assert!(!addr.is_link_local());
        assert!(!addr.is_gua());
    }

    #[test]
    fn is_ula_fc00() {
        // fc00::/8 is also technically ULA (but L=0, rarely used)
        let addr = Ipv6Addr([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_ula());
    }

    #[test]
    fn is_gua() {
        // 2001:db8::/32 is documentation prefix (a GUA)
        let addr = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_gua());
        assert!(!addr.is_ula());
        assert!(!addr.is_link_local());
    }

    #[test]
    fn is_gua_range() {
        // 2000::/3 means 2000:: through 3fff::
        let addr_2000 = Ipv6Addr([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let addr_3fff = Ipv6Addr([
            0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        assert!(addr_2000.is_gua());
        assert!(addr_3fff.is_gua());

        // 4000:: is NOT a GUA
        let addr_4000 = Ipv6Addr([0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!addr_4000.is_gua());
    }

    #[test]
    fn is_multicast() {
        let addr = Ipv6Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_multicast());
        assert!(!addr.is_ula());
        assert!(!addr.is_gua());
    }

    #[test]
    fn is_loopback() {
        let addr = Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_loopback());
        assert!(!addr.is_ula());
        assert!(!addr.is_gua());
        assert!(!addr.is_multicast());
    }

    #[test]
    fn from_ipv6_roundtrip_link_local_and_ula() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let ll = node.link_local_addr();
        assert_eq!(NodeId::from_ipv6(ll), node);

        let prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0];
        let ula = node.ula_addr(prefix);
        assert_eq!(NodeId::from_ipv6(ula), node);
    }

    #[test]
    fn from_ipv6_roundtrip_ula() {
        let node = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let prefix = [0xfd, 0x00, 0x12, 0x34, 0, 0, 0, 0];
        let ula = node.ula_addr(prefix);
        assert_eq!(NodeId::from_ipv6(ula), node);
    }

    #[test]
    fn from_ipv6_independent_roundtrip() {
        // Independent test (no dependency on link_local_addr/ula_addr for input construction)
        // Verifies from_ipv6 correctly reverses the U/L bit flip on IID per spec.
        let node = NodeId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let addr = Ipv6Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, // U/L bit flipped in IID
        ]);
        assert_eq!(NodeId::from_ipv6(addr), node);
        assert_eq!(node.link_local_addr(), addr); // full roundtrip
    }
}
