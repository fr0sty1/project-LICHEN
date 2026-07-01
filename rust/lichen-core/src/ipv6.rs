//! IPv6 header parsing (no_std, no allocation).
//!
//! Provides zero-copy parsing of IPv6 fixed headers for routing decisions.

use crate::addr::Ipv6Addr;
use crate::error::{BufferTooSmall, TooShort};

/// IPv6 header length (fixed portion, no extension headers).
pub const IPV6_HEADER_LEN: usize = 40;

/// IPv6 header field offsets.
pub mod field {
    /// Byte offset of source address (16 bytes).
    pub const SRC_OFFSET: usize = 8;
    /// Byte offset of destination address (16 bytes).
    pub const DST_OFFSET: usize = 24;
}

/// Common next header values.
pub mod next_header {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT: u8 = 59;
    pub const DEST_OPTIONS: u8 = 60;

    /// Returns true if this next-header value is a TLV-style extension header
    /// (Hop-by-Hop, Routing, or Destination Options).
    pub const fn is_tlv_extension(nh: u8) -> bool {
        matches!(nh, HOP_BY_HOP | ROUTING | DEST_OPTIONS)
    }
}

/// IPv6 header parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Error {
    /// Buffer too short for the expected data.
    TooShort(TooShort),
    /// Wrong IP version (expected 6).
    WrongVersion(u8),
    /// Extension header length is not a multiple of 8 bytes.
    InvalidExtensionLength,
    /// Fragment headers are not supported (LICHEN uses SCHC fragmentation).
    FragmentNotSupported,
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
}

impl core::fmt::Display for Ipv6Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "IPv6 {}", e),
            Self::WrongVersion(v) => write!(f, "wrong IP version: {}", v),
            Self::InvalidExtensionLength => {
                write!(f, "extension header length must be a multiple of 8")
            }
            Self::FragmentNotSupported => {
                write!(f, "IPv6 Fragment headers not supported (use SCHC)")
            }
            Self::BufferTooSmall(e) => write!(f, "IPv6 {}", e),
        }
    }
}

impl core::error::Error for Ipv6Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for Ipv6Error {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for Ipv6Error {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
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
            return Err(TooShort::new(IPV6_HEADER_LEN, data.len()).into());
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
            return Err(TooShort::new(total, self.data.len()).into());
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
        return Err(BufferTooSmall::new(IPV6_HEADER_LEN, out.len()).into());
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

// ── Extension Headers (RFC 8200 §4) ─────────────────────────────────────────

/// A parsed TLV-style IPv6 extension header (zero-copy).
///
/// Supports Hop-by-Hop Options (0), Routing (43), and Destination Options (60).
/// The total length is always `(hdr_ext_len + 1) * 8` octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHeader<'a> {
    /// This header's type (Hop-by-Hop, Routing, or Destination Options).
    pub header_type: u8,
    /// Raw data slice: next_header (1) + hdr_ext_len (1) + data (N).
    data: &'a [u8],
}

impl<'a> ExtensionHeader<'a> {
    /// Parse an extension header from the start of `data`.
    ///
    /// Returns the parsed header and the number of bytes consumed.
    /// `header_type` is the Next Header value that led us here.
    pub fn from_bytes(header_type: u8, data: &'a [u8]) -> Result<(Self, usize), Ipv6Error> {
        if !next_header::is_tlv_extension(header_type) {
            // Not a TLV extension header we handle
            return Err(TooShort::new(2, data.len()).into());
        }
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let hdr_ext_len = data[1] as usize;
        let total_len = (hdr_ext_len + 1) * 8;
        if data.len() < total_len {
            return Err(TooShort::new(total_len, data.len()).into());
        }
        Ok((
            Self {
                header_type,
                data: &data[..total_len],
            },
            total_len,
        ))
    }

    /// The Next Header field (protocol of what follows this header).
    pub fn next_header(&self) -> u8 {
        self.data[0]
    }

    /// Header extension length field (units of 8 octets, minus 1).
    pub fn hdr_ext_len(&self) -> u8 {
        self.data[1]
    }

    /// Total length of this extension header in bytes.
    pub fn total_len(&self) -> usize {
        (self.data[1] as usize + 1) * 8
    }

    /// The data portion (after the 2-byte prefix).
    pub fn options_data(&self) -> &'a [u8] {
        &self.data[2..]
    }

    /// Raw extension header bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// Write a TLV-style extension header into `out`.
///
/// `header_type` is the type of this extension header.
/// `next_header` is the protocol that follows.
/// `options_data` is the TLV content (must be `total_len - 2` bytes where
/// `total_len` is a multiple of 8).
///
/// Returns the number of bytes written.
pub fn write_extension_header(
    header_type: u8,
    next_header: u8,
    options_data: &[u8],
    out: &mut [u8],
) -> Result<usize, Ipv6Error> {
    let total_len = options_data.len() + 2;
    if !total_len.is_multiple_of(8) {
        return Err(Ipv6Error::InvalidExtensionLength);
    }
    if out.len() < total_len {
        return Err(BufferTooSmall::new(total_len, out.len()).into());
    }
    let _ = header_type; // used for documentation/validation only
    let hdr_ext_len = (total_len / 8 - 1) as u8;
    out[0] = next_header;
    out[1] = hdr_ext_len;
    out[2..total_len].copy_from_slice(options_data);
    Ok(total_len)
}

/// Result of walking the extension header chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionChainInfo {
    /// The upper-layer protocol (after all extension headers).
    pub upper_protocol: u8,
    /// Offset from the start of the payload where the upper-layer data begins.
    pub upper_offset: usize,
}

/// Walk the extension header chain and return the upper-layer protocol info.
///
/// `payload` is the bytes after the 40-byte IPv6 header.
/// `first_next_header` is the Next Header field from the IPv6 base header.
///
/// Returns the upper-layer protocol number and the offset into `payload`
/// where the upper-layer data begins.
///
/// Returns `FragmentNotSupported` if a Fragment header (44) is encountered.
pub fn walk_extension_chain(
    payload: &[u8],
    first_next_header: u8,
) -> Result<ExtensionChainInfo, Ipv6Error> {
    let mut offset = 0;
    let mut nh = first_next_header;

    while next_header::is_tlv_extension(nh) {
        if offset + 2 > payload.len() {
            return Err(TooShort::new(offset + 2, payload.len()).into());
        }
        let following = payload[offset];
        let hdr_ext_len = payload[offset + 1] as usize;
        let total = (hdr_ext_len + 1) * 8;
        if offset + total > payload.len() {
            return Err(TooShort::new(offset + total, payload.len()).into());
        }
        offset += total;
        nh = following;
    }

    if nh == next_header::FRAGMENT {
        return Err(Ipv6Error::FragmentNotSupported);
    }

    Ok(ExtensionChainInfo {
        upper_protocol: nh,
        upper_offset: offset,
    })
}

/// Build padding options (PadN) to fill `len` bytes.
///
/// PadN option: Type=1, Length=N-2, then N-2 zero bytes.
/// For 1 byte, use Pad1 (Type=0, no length/value).
///
/// `out` must have at least `len` bytes available.
pub fn write_padding(len: usize, out: &mut [u8]) -> Result<(), Ipv6Error> {
    if out.len() < len {
        return Err(BufferTooSmall::new(len, out.len()).into());
    }
    match len {
        0 => {}
        1 => out[0] = 0, // Pad1
        n => {
            out[0] = 1; // PadN type
            out[1] = (n - 2) as u8;
            out[2..n].fill(0);
        }
    }
    Ok(())
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
        assert_eq!(
            Ipv6Header::from_bytes(&[0u8; 39]),
            Err(Ipv6Error::TooShort(TooShort::new(IPV6_HEADER_LEN, 39)))
        );
    }

    #[test]
    fn payload_too_short() {
        let mut pkt = [0u8; 44];
        write_header(&ll(1), &ll(2), 0, 64, 10, &mut pkt).unwrap();
        // Says payload is 10 bytes but buffer only has 4 after header
        let hdr = Ipv6Header::from_bytes(&pkt).unwrap();
        assert!(matches!(hdr.payload(), Err(Ipv6Error::TooShort(_))));
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

    #[test]
    fn extension_header_parse() {
        // Build a Hop-by-Hop extension header (8 bytes minimum)
        // next_header=17 (UDP), hdr_ext_len=0 (meaning 8 bytes total), 6 bytes padding
        let mut ext = [0u8; 8];
        ext[0] = next_header::UDP; // next header
        ext[1] = 0; // hdr_ext_len = 0 means 8 bytes total
        // bytes 2-7 are padding (already zero)

        let (hdr, consumed) = ExtensionHeader::from_bytes(next_header::HOP_BY_HOP, &ext).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(hdr.header_type, next_header::HOP_BY_HOP);
        assert_eq!(hdr.next_header(), next_header::UDP);
        assert_eq!(hdr.hdr_ext_len(), 0);
        assert_eq!(hdr.total_len(), 8);
        assert_eq!(hdr.options_data().len(), 6);
    }

    #[test]
    fn extension_header_16_bytes() {
        // 16-byte extension header: hdr_ext_len=1 means (1+1)*8 = 16 bytes
        let mut ext = [0u8; 16];
        ext[0] = next_header::ICMPV6;
        ext[1] = 1; // 16 bytes total
        write_padding(14, &mut ext[2..]).unwrap();

        let (hdr, consumed) = ExtensionHeader::from_bytes(next_header::ROUTING, &ext).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(hdr.total_len(), 16);
        assert_eq!(hdr.options_data().len(), 14);
    }

    #[test]
    fn write_extension_header_roundtrip() {
        let mut buf = [0u8; 8];
        // 6 bytes of options data (+ 2 byte prefix = 8 bytes total)
        let opts = [0x01, 0x04, 0x00, 0x00, 0x00, 0x00]; // PadN(4)
        let n = write_extension_header(
            next_header::HOP_BY_HOP,
            next_header::UDP,
            &opts,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf[0], next_header::UDP);
        assert_eq!(buf[1], 0); // hdr_ext_len

        let (parsed, _) = ExtensionHeader::from_bytes(next_header::HOP_BY_HOP, &buf).unwrap();
        assert_eq!(parsed.next_header(), next_header::UDP);
        assert_eq!(parsed.options_data(), &opts);
    }

    #[test]
    fn write_extension_invalid_length() {
        let mut buf = [0u8; 16];
        // 5 bytes of options (+ 2 = 7, not multiple of 8)
        let opts = [0u8; 5];
        assert_eq!(
            write_extension_header(next_header::HOP_BY_HOP, next_header::UDP, &opts, &mut buf),
            Err(Ipv6Error::InvalidExtensionLength)
        );
    }

    #[test]
    fn walk_extension_chain_no_extensions() {
        // UDP directly after IPv6 header
        let payload = [0u8; 8]; // UDP header
        let info = walk_extension_chain(&payload, next_header::UDP).unwrap();
        assert_eq!(info.upper_protocol, next_header::UDP);
        assert_eq!(info.upper_offset, 0);
    }

    #[test]
    fn walk_extension_chain_one_hop_by_hop() {
        // Hop-by-Hop (8 bytes) then UDP
        let mut payload = [0u8; 16];
        payload[0] = next_header::UDP; // next header after hop-by-hop
        payload[1] = 0; // hdr_ext_len=0 (8 bytes)
        // UDP header would start at offset 8

        let info = walk_extension_chain(&payload, next_header::HOP_BY_HOP).unwrap();
        assert_eq!(info.upper_protocol, next_header::UDP);
        assert_eq!(info.upper_offset, 8);
    }

    #[test]
    fn walk_extension_chain_two_extensions() {
        // Hop-by-Hop (8 bytes) -> Routing (16 bytes) -> ICMPv6
        let mut payload = [0u8; 32];
        // Hop-by-Hop header
        payload[0] = next_header::ROUTING;
        payload[1] = 0; // 8 bytes
        // Routing header at offset 8
        payload[8] = next_header::ICMPV6;
        payload[9] = 1; // 16 bytes

        let info = walk_extension_chain(&payload, next_header::HOP_BY_HOP).unwrap();
        assert_eq!(info.upper_protocol, next_header::ICMPV6);
        assert_eq!(info.upper_offset, 24); // 8 + 16
    }

    #[test]
    fn walk_extension_chain_fragment_rejected() {
        // Fragment header should be rejected
        let payload = [0u8; 8];
        assert_eq!(
            walk_extension_chain(&payload, next_header::FRAGMENT),
            Err(Ipv6Error::FragmentNotSupported)
        );
    }

    #[test]
    fn walk_extension_chain_truncated() {
        // Hop-by-Hop says 16 bytes but only 8 present
        let mut payload = [0u8; 8];
        payload[0] = next_header::UDP;
        payload[1] = 1; // 16 bytes

        assert!(matches!(
            walk_extension_chain(&payload, next_header::HOP_BY_HOP),
            Err(Ipv6Error::TooShort(_))
        ));
    }

    #[test]
    fn write_padding_various() {
        let mut buf = [0xFFu8; 8];

        // Pad1 (1 byte)
        write_padding(1, &mut buf[..1]).unwrap();
        assert_eq!(buf[0], 0);

        // PadN (3 bytes): type=1, length=1, one zero
        buf.fill(0xFF);
        write_padding(3, &mut buf[..3]).unwrap();
        assert_eq!(&buf[..3], &[1, 1, 0]);

        // PadN (6 bytes): type=1, length=4, four zeros
        buf.fill(0xFF);
        write_padding(6, &mut buf[..6]).unwrap();
        assert_eq!(&buf[..6], &[1, 4, 0, 0, 0, 0]);

        // Zero padding (no-op)
        buf.fill(0xFF);
        write_padding(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0xFF); // unchanged
    }
}
