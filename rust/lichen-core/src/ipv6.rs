//! IPv6 header parsing (no_std, no allocation).
//!
//! Provides zero-copy parsing of IPv6 fixed headers for routing decisions.

use crate::addr::Ipv6Addr;

/// IPv6 header length (fixed portion, no extension headers).
pub const IPV6_HEADER_LEN: usize = 40;

/// Common next header values.
pub mod next_header {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT: u8 = 59;
}

/// IPv6 header parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Error {
    TooShort,
    WrongVersion(u8),
    PayloadTruncated,
}

/// A parsed IPv6 header (zero-copy reference to buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header<'a> {
    data: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    /// Parse IPv6 header from packet start.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, Ipv6Error> {
        if data.len() < IPV6_HEADER_LEN {
            return Err(Ipv6Error::TooShort);
        }
        let version = data[0] >> 4;
        if version != 6 {
            return Err(Ipv6Error::WrongVersion(version));
        }
        Ok(Self { data })
    }

    /// Traffic class (6 bits from byte 0, 2 bits from byte 1).
    pub fn traffic_class(&self) -> u8 {
        ((self.data[0] & 0x0F) << 4) | (self.data[1] >> 4)
    }

    /// Flow label (20 bits).
    pub fn flow_label(&self) -> u32 {
        let b1 = (self.data[1] & 0x0F) as u32;
        let b2 = self.data[2] as u32;
        let b3 = self.data[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    /// Payload length (does not include 40-byte header).
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Next header protocol number.
    pub fn next_header(&self) -> u8 {
        self.data[6]
    }

    /// Hop limit (TTL equivalent).
    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    /// Source address.
    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr(self.data[8..24].try_into().unwrap())
    }

    /// Destination address.
    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr(self.data[24..40].try_into().unwrap())
    }

    /// Payload slice (after fixed header).
    pub fn payload(&self) -> Result<&'a [u8], Ipv6Error> {
        let plen = self.payload_length() as usize;
        let total = IPV6_HEADER_LEN + plen;
        if self.data.len() < total {
            return Err(Ipv6Error::PayloadTruncated);
        }
        Ok(&self.data[IPV6_HEADER_LEN..total])
    }

    /// Total packet length (header + payload).
    pub fn total_length(&self) -> usize {
        IPV6_HEADER_LEN + self.payload_length() as usize
    }

    /// Raw header bytes (40 bytes).
    pub fn header_bytes(&self) -> &'a [u8] {
        &self.data[..IPV6_HEADER_LEN]
    }
}

/// Build an IPv6 header into a buffer.
///
/// Returns header length (always 40) on success.
pub fn write_header(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload_len: u16,
    out: &mut [u8],
) -> Result<usize, Ipv6Error> {
    if out.len() < IPV6_HEADER_LEN {
        return Err(Ipv6Error::TooShort);
    }
    out[0] = 0x60; // version=6, TC=0, flow=0
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&payload_len.to_be_bytes());
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src.0);
    out[24..40].copy_from_slice(&dst.0);
    Ok(IPV6_HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    #[test]
    fn parse_header() {
        let mut pkt = [0u8; 48];
        write_header(&ll(1), &ll(2), next_header::ICMPV6, 64, 8, &mut pkt).unwrap();
        pkt[40..48].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0]); // echo request

        let hdr = Ipv6Header::from_bytes(&pkt).unwrap();
        assert_eq!(hdr.src(), ll(1));
        assert_eq!(hdr.dst(), ll(2));
        assert_eq!(hdr.next_header(), next_header::ICMPV6);
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.payload_length(), 8);
        assert_eq!(hdr.payload().unwrap().len(), 8);
    }

    #[test]
    fn wrong_version() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x40; // version 4
        assert_eq!(Ipv6Header::from_bytes(&pkt), Err(Ipv6Error::WrongVersion(4)));
    }

    #[test]
    fn too_short() {
        assert_eq!(Ipv6Header::from_bytes(&[0u8; 39]), Err(Ipv6Error::TooShort));
    }

    #[test]
    fn payload_truncated() {
        let mut pkt = [0u8; 44];
        write_header(&ll(1), &ll(2), 0, 64, 10, &mut pkt).unwrap();
        // Says payload is 10 bytes but buffer only has 4 after header
        let hdr = Ipv6Header::from_bytes(&pkt).unwrap();
        assert_eq!(hdr.payload(), Err(Ipv6Error::PayloadTruncated));
    }

    #[test]
    fn traffic_class_and_flow() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x6F; // version=6, TC high nibble=0xF
        pkt[1] = 0xAB; // TC low nibble=0xA, flow high=0xB
        pkt[2] = 0xCD;
        pkt[3] = 0xEF;
        let hdr = Ipv6Header::from_bytes(&pkt).unwrap();
        assert_eq!(hdr.traffic_class(), 0xFA);
        assert_eq!(hdr.flow_label(), 0xBCDEF);
    }
}
