//! Address types: IPv6Addr and NodeId (EUI-64).

/// A 128-bit IPv6 address, stored in network (big-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Self([0u8; 16]);

    /// True if this is a link-local address (fe80::/10).
    pub fn is_link_local(&self) -> bool {
        self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0x80
    }
}

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
        let e = self.0;
        Ipv6Addr([
            0xfe,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
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
