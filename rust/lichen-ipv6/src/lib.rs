// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Minimal IPv6/ICMPv6/UDP for LICHEN mesh nodes.
//!
//! # ponytail: not a full IP stack
//!
//! This is NOT smoltcp. No TCP, no DHCP, no DNS, no reassembly, no routing
//! tables. Just the bytes that go over LoRa:
//!
//! - IPv6 header construction/parsing (40 bytes)
//! - ICMPv6 Echo Request/Reply (ping)
//! - ICMPv6 Neighbor Solicitation/Advertisement
//! - UDP header (8 bytes, for CoAP)
//!
//! Standalone pucks can originate/terminate traffic. Border router handles
//! the real IP stack for internet connectivity.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use heapless::Vec;

/// Error indicating input data was shorter than expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooShort {
    /// Minimum number of bytes expected.
    pub expected: usize,
    /// Actual number of bytes present.
    pub actual: usize,
}

impl TooShort {
    /// Create a new TooShort error.
    #[inline]
    pub const fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }
}

impl core::fmt::Display for TooShort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "buffer too short: expected {} bytes, got {}",
            self.expected, self.actual
        )
    }
}

impl core::error::Error for TooShort {}

/// Error indicating an output buffer is too small to hold the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Minimum buffer size required.
    pub required: usize,
    /// Actual buffer size provided.
    pub provided: usize,
}

impl BufferTooSmall {
    /// Create a new BufferTooSmall error.
    #[inline]
    pub const fn new(required: usize, provided: usize) -> Self {
        Self { required, provided }
    }
}

impl core::fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "output buffer too small: need {} bytes, have {}",
            self.required, self.provided
        )
    }
}

impl core::error::Error for BufferTooSmall {}

/// IPv6 parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ipv6Error {
    /// Buffer too short for the expected data.
    TooShort(TooShort),
    /// Wrong IP version (expected 6).
    WrongVersion(u8),
    /// Output buffer too small for serialization.
    BufferTooSmall(BufferTooSmall),
    /// Flow label exceeds 20-bit limit (RFC 6437).
    InvalidFlowLabel(u32),
    /// Payload exceeds the maximum size for a UDP datagram (65527 bytes).
    PayloadTooLarge(usize),
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

impl core::fmt::Display for Ipv6Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "IPv6 {}", e),
            Self::WrongVersion(v) => write!(f, "wrong IP version: {} (expected 6)", v),
            Self::BufferTooSmall(e) => write!(f, "IPv6 {}", e),
            Self::InvalidFlowLabel(v) => {
                write!(f, "flow label 0x{:x} exceeds 20-bit limit (max 0xfffff)", v)
            }
            Self::PayloadTooLarge(size) => {
                write!(f, "UDP payload too large: {} bytes (max 65527)", size)
            }
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

/// IPv6 header length (fixed, no extension headers for LICHEN).
pub const IPV6_HEADER_LEN: usize = 40;

/// UDP header length.
pub const UDP_HEADER_LEN: usize = 8;

/// ICMPv6 header length (type + code + checksum).
pub const ICMPV6_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6ChecksumError {
    MessageTooLong,
}

impl core::fmt::Display for Icmpv6ChecksumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageTooLong => write!(f, "ICMPv6 message exceeds the 32-bit length field"),
        }
    }
}

impl core::error::Error for Icmpv6ChecksumError {}

/// Next Header values.
pub mod next_header {
    pub const ICMPV6: u8 = 58;
    pub const UDP: u8 = 17;
}

/// ICMPv6 message types.
pub mod icmpv6_type {
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
}

/// IPv6 address (128 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Addr(pub [u8; 16]);

impl Addr {
    /// All-zeros (unspecified) address.
    pub const UNSPECIFIED: Self = Self([0; 16]);

    /// Loopback address (::1).
    pub const LOOPBACK: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// All-nodes multicast (ff02::1).
    pub const ALL_NODES: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);

    /// All-routers multicast (ff02::2).
    pub const ALL_ROUTERS: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);

    /// Create link-local address from 8-byte node ID (EUI-64).
    ///
    /// Input is treated as EUI-64 per RFC 4291. U/L bit (LSB of first octet)
    /// is flipped. No IEEE validation performed (no OUI check, no reserved
    /// patterns rejected like all-zero or broadcast). Caller responsible for
    /// valid input. Synthetic node IDs permitted for LICHEN mesh.
    ///
    /// See also: link_local_from_mac for 48-bit MACs.
    pub fn link_local_from_eui64(eui64: &[u8; 8]) -> Self {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[8] = eui64[0] ^ 0x02;
        addr[9] = eui64[1];
        addr[10] = eui64[2];
        addr[11] = eui64[3];
        addr[12] = eui64[4];
        addr[13] = eui64[5];
        addr[14] = eui64[6];
        addr[15] = eui64[7];
        Self(addr)
    }

    /// Create link-local address from 6-byte MAC by inserting 0xfffe
    /// to form modified EUI-64 (RFC 4291), then calling link_local_from_eui64.
    /// No validation on resulting EUI-64 (e.g. all-zero MAC produces
    /// fe80::ff:fe00:0 which is technically invalid per some strict impls).
    pub fn link_local_from_mac(mac: &[u8; 6]) -> Self {
        let mut eui64 = [0u8; 8];
        eui64[0] = mac[0];
        eui64[1] = mac[1];
        eui64[2] = mac[2];
        eui64[3] = 0xff;
        eui64[4] = 0xfe;
        eui64[5] = mac[3];
        eui64[6] = mac[4];
        eui64[7] = mac[5];
        Self::link_local_from_eui64(&eui64)
    }

    /// Create solicited-node multicast address for this unicast address.
    ///
    /// Format: ff02::1:ffXX:XXXX (last 24 bits of unicast).
    pub fn solicited_node(&self) -> Self {
        let mut addr = [0u8; 16];
        addr[0] = 0xff;
        addr[1] = 0x02;
        addr[11] = 0x01;
        addr[12] = 0xff;
        addr[13] = self.0[13];
        addr[14] = self.0[14];
        addr[15] = self.0[15];
        Self(addr)
    }

    /// Check if this is a link-local address (fe80::/10).
    pub fn is_link_local(&self) -> bool {
        self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0x80
    }

    /// Check if this is a multicast address (ff00::/8).
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Check if this is a Unique Local Address (fc00::/7, typically fd00::/8).
    ///
    /// Per RFC 4193, ULAs have the prefix fc00::/7. In practice, the L bit
    /// (bit 8) is set to 1 for locally-assigned addresses, giving fd00::/8.
    pub fn is_ula(&self) -> bool {
        // fc00::/7 means first byte has top 7 bits = 1111110x (0xfc or 0xfd)
        (self.0[0] & 0xfe) == 0xfc
    }

    /// Check if this is a Global Unicast Address (2000::/3).
    ///
    /// Per RFC 4291, GUAs have the prefix 2000::/3, meaning the first 3 bits
    /// are 001 (addresses 2000:: through 3fff::).
    pub fn is_gua(&self) -> bool {
        // 2000::/3 means first byte has top 3 bits = 001 (0x20..0x3f)
        (self.0[0] & 0xe0) == 0x20
    }

    /// Check if this is the loopback address (::1).
    pub fn is_loopback(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    }

    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Extract the Interface Identifier (IID) - the low 64 bits.
    pub fn iid(&self) -> [u8; 8] {
        let mut iid = [0u8; 8];
        iid.copy_from_slice(&self.0[8..16]);
        iid
    }
}

/// IPv6 header (40 bytes, no extension headers).
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32, // 20 bits
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Addr,
    pub dst: Addr,
}

impl Ipv6Header {
    /// Create a new IPv6 header with sensible defaults.
    pub fn new(next_header: u8, src: Addr, dst: Addr) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_len: 0, // Set when encoding
            next_header,
            hop_limit: 64,
            src,
            dst,
        }
    }

    /// Maximum valid flow label value (20 bits, per RFC 6437).
    pub const MAX_FLOW_LABEL: u32 = 0xfffff;

    /// Write header to output buffer.
    ///
    /// Returns the number of bytes written (always `IPV6_HEADER_LEN`).
    /// Returns `InvalidFlowLabel` if `flow_label` exceeds 20 bits.
    pub fn write_to(&self, payload_len: u16, out: &mut [u8]) -> Result<usize, Ipv6Error> {
        if out.len() < IPV6_HEADER_LEN {
            return Err(BufferTooSmall::new(IPV6_HEADER_LEN, out.len()).into());
        }
        if self.flow_label > Self::MAX_FLOW_LABEL {
            return Err(Ipv6Error::InvalidFlowLabel(self.flow_label));
        }

        // Version (4) | Traffic Class (8) | Flow Label (20)
        out[0] = 0x60 | (self.traffic_class >> 4);
        out[1] = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8 & 0x0f);
        out[2] = (self.flow_label >> 8) as u8;
        out[3] = self.flow_label as u8;

        // Payload length
        out[4] = (payload_len >> 8) as u8;
        out[5] = payload_len as u8;

        // Next header, hop limit
        out[6] = self.next_header;
        out[7] = self.hop_limit;

        // Addresses
        out[8..24].copy_from_slice(&self.src.0);
        out[24..40].copy_from_slice(&self.dst.0);

        Ok(IPV6_HEADER_LEN)
    }

    /// Parse header from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Ipv6Error> {
        if buf.len() < IPV6_HEADER_LEN {
            return Err(TooShort::new(IPV6_HEADER_LEN, buf.len()).into());
        }

        // Check version
        let version = buf[0] >> 4;
        if version != 6 {
            return Err(Ipv6Error::WrongVersion(version));
        }

        let traffic_class = ((buf[0] & 0x0f) << 4) | (buf[1] >> 4);
        let flow_label = ((buf[1] as u32 & 0x0f) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        let payload_len = ((buf[4] as u16) << 8) | (buf[5] as u16);
        let next_header = buf[6];
        let hop_limit = buf[7];

        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        dst.copy_from_slice(&buf[24..40]);

        Ok(Self {
            traffic_class,
            flow_label,
            payload_len,
            next_header,
            hop_limit,
            src: Addr(src),
            dst: Addr(dst),
        })
    }

    /// Decrement hop limit per RFC 8200 §3 for forwarding. Returns `None`
    /// if decrement would reach zero (caller must generate ICMPv6 Time
    /// Exceeded type 3/code 0). Test uses independent values per spec.
    pub fn with_decremented_hop_limit(&self) -> Option<Self> {
        let new_hop_limit = self.hop_limit.saturating_sub(1);
        if new_hop_limit == 0 {
            None
        } else {
            let mut hdr = *self;
            hdr.hop_limit = new_hop_limit;
            Some(hdr)
        }
    }
}

/// UDP header (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Create new UDP header.
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 0,   // Set when encoding
            checksum: 0, // Set when encoding
        }
    }

    /// Write **only the 8-byte UDP header** to `out`.
    ///
    /// The `payload` slice is used *only* for IPv6 pseudo-header checksum
    /// computation. Caller **MUST** copy `payload` to the output buffer
    /// immediately after these 8 bytes. Checksum will be invalid for the
    /// transmitted packet if payload is forgotten or differs.
    ///
    /// Returns `UDP_HEADER_LEN`.
    pub fn write_header_to(
        &self,
        src: &Addr,
        dst: &Addr,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Ipv6Error> {
        if out.len() < UDP_HEADER_LEN {
            return Err(BufferTooSmall::new(UDP_HEADER_LEN, out.len()).into());
        }

        let total = UDP_HEADER_LEN + payload.len();
        if total > u16::MAX as usize {
            return Err(Ipv6Error::PayloadTooLarge(payload.len()));
        }
        let length = total as u16;

        out[0] = (self.src_port >> 8) as u8;
        out[1] = self.src_port as u8;
        out[2] = (self.dst_port >> 8) as u8;
        out[3] = self.dst_port as u8;
        out[4] = (length >> 8) as u8;
        out[5] = length as u8;
        out[6] = 0; // checksum placeholder
        out[7] = 0;

        // Compute checksum over pseudo-header + UDP header (zeroed) + payload
        let checksum = udp_checksum(src, dst, &out[..UDP_HEADER_LEN], payload);
        out[6] = (checksum >> 8) as u8;
        out[7] = checksum as u8;

        Ok(UDP_HEADER_LEN)
    }

    /// Write complete UDP datagram (header + payload) to `out`.
    ///
    /// Preferred API: places payload in buffer then computes checksum over
    /// the actual transmitted bytes. Eliminates the header-only footgun.
    ///
    /// Returns total bytes written (`UDP_HEADER_LEN + payload.len()`).
    pub fn write_packet_to(
        &self,
        src: &Addr,
        dst: &Addr,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Ipv6Error> {
        let total = UDP_HEADER_LEN + payload.len();
        if out.len() < total {
            return Err(BufferTooSmall::new(total, out.len()).into());
        }

        let _ = self.write_header_to(src, dst, payload, &mut out[0..UDP_HEADER_LEN])?;
        out[UDP_HEADER_LEN..total].copy_from_slice(payload);

        Ok(total)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, Ipv6Error> {
        if buf.len() < UDP_HEADER_LEN {
            return Err(TooShort::new(UDP_HEADER_LEN, buf.len()).into());
        }
        let length = ((buf[4] as u16) << 8) | (buf[5] as u16);
        if length < UDP_HEADER_LEN as u16 || length as usize > buf.len() {
            return Err(TooShort::new(length as usize, buf.len()).into());
        }

        Ok(Self {
            src_port: ((buf[0] as u16) << 8) | (buf[1] as u16),
            dst_port: ((buf[2] as u16) << 8) | (buf[3] as u16),
            length,
            checksum: ((buf[6] as u16) << 8) | (buf[7] as u16),
        })
    }
}

/// ICMPv6 Echo message (request or reply).
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6Echo {
    pub id: u16,
    pub seq: u16,
}

/// Maximum echo data that fits in build buffer (128-byte buffer minus 8-byte header).
pub const MAX_ECHO_DATA: usize = 120;

impl Icmpv6Echo {
    /// Build Echo Request packet (header + data).
    ///
    /// Returns `Err(BufferTooSmall)` if data exceeds [`MAX_ECHO_DATA`] (120 bytes).
    pub fn build_request(
        &self,
        src: &Addr,
        dst: &Addr,
        data: &[u8],
    ) -> Result<Vec<u8, 128>, BufferTooSmall> {
        self.build(icmpv6_type::ECHO_REQUEST, src, dst, data)
    }

    /// Build Echo Reply packet.
    ///
    /// Returns `Err(BufferTooSmall)` if data exceeds [`MAX_ECHO_DATA`] (120 bytes).
    pub fn build_reply(
        &self,
        src: &Addr,
        dst: &Addr,
        data: &[u8],
    ) -> Result<Vec<u8, 128>, BufferTooSmall> {
        self.build(icmpv6_type::ECHO_REPLY, src, dst, data)
    }

    fn build(
        &self,
        msg_type: u8,
        src: &Addr,
        dst: &Addr,
        data: &[u8],
    ) -> Result<Vec<u8, 128>, BufferTooSmall> {
        const HEADER_LEN: usize = 8; // ICMPv6 header (4) + Echo header (4)
        const CAPACITY: usize = 128;

        let required = HEADER_LEN + data.len();
        if required > CAPACITY {
            return Err(BufferTooSmall::new(required, CAPACITY));
        }

        let mut pkt = Vec::new();

        // ICMPv6 header: type, code, checksum (placeholder)
        // These pushes cannot fail - we checked capacity above
        pkt.push(msg_type).expect("capacity pre-checked");
        pkt.push(0).expect("capacity pre-checked"); // code
        pkt.push(0).expect("capacity pre-checked"); // checksum high (placeholder)
        pkt.push(0).expect("capacity pre-checked"); // checksum low

        // Echo header: id, seq
        pkt.push((self.id >> 8) as u8)
            .expect("capacity pre-checked");
        pkt.push(self.id as u8).expect("capacity pre-checked");
        pkt.push((self.seq >> 8) as u8)
            .expect("capacity pre-checked");
        pkt.push(self.seq as u8).expect("capacity pre-checked");

        // Data
        pkt.extend_from_slice(data).expect("capacity pre-checked");

        // Compute checksum
        let checksum = icmpv6_checksum(src, dst, &pkt).expect("bounded echo request");
        pkt[2] = (checksum >> 8) as u8;
        pkt[3] = checksum as u8;

        Ok(pkt)
    }

    /// Parse Echo message from ICMPv6 payload (after type/code/checksum).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Ipv6Error> {
        if buf.len() < 4 {
            return Err(TooShort::new(4, buf.len()).into());
        }

        Ok(Self {
            id: ((buf[0] as u16) << 8) | (buf[1] as u16),
            seq: ((buf[2] as u16) << 8) | (buf[3] as u16),
        })
    }
}

/// ICMPv6 Neighbor Solicitation.
#[derive(Debug, Clone, Copy)]
pub struct NeighborSolicitation {
    pub target: Addr,
}

impl NeighborSolicitation {
    /// Build NS packet.
    ///
    /// NS is fixed-size (24 bytes), so this cannot fail with the 64-byte buffer.
    pub fn build(&self, src: &Addr, dst: &Addr) -> Vec<u8, 64> {
        let mut pkt = Vec::new();

        // ICMPv6 header
        pkt.push(icmpv6_type::NEIGHBOR_SOLICITATION)
            .expect("capacity pre-checked");
        pkt.push(0).expect("capacity pre-checked"); // code
        pkt.push(0).expect("capacity pre-checked"); // checksum
        pkt.push(0).expect("capacity pre-checked");

        // Reserved (4 bytes)
        pkt.extend_from_slice(&[0u8; 4])
            .expect("capacity pre-checked");

        // Target address (16 bytes)
        pkt.extend_from_slice(&self.target.0)
            .expect("capacity pre-checked");

        // Compute checksum
        let checksum = icmpv6_checksum(src, dst, &pkt).expect("fixed-size solicitation");
        pkt[2] = (checksum >> 8) as u8;
        pkt[3] = checksum as u8;

        pkt
    }

    /// Parse NS from ICMPv6 payload.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Ipv6Error> {
        // After type/code/checksum: 4 reserved + 16 target
        if buf.len() < 20 {
            return Err(TooShort::new(20, buf.len()).into());
        }

        let mut target = [0u8; 16];
        target.copy_from_slice(&buf[4..20]);

        Ok(Self {
            target: Addr(target),
        })
    }
}

/// ICMPv6 Neighbor Advertisement.
#[derive(Debug, Clone, Copy)]
pub struct NeighborAdvertisement {
    pub target: Addr,
    pub router: bool,
    pub solicited: bool,
    pub override_flag: bool,
}

impl NeighborAdvertisement {
    /// Build NA packet.
    ///
    /// NA is fixed-size (24 bytes), so this cannot fail with the 64-byte buffer.
    pub fn build(&self, src: &Addr, dst: &Addr) -> Vec<u8, 64> {
        let mut pkt = Vec::new();

        // ICMPv6 header
        pkt.push(icmpv6_type::NEIGHBOR_ADVERTISEMENT)
            .expect("capacity pre-checked");
        pkt.push(0).expect("capacity pre-checked"); // code
        pkt.push(0).expect("capacity pre-checked"); // checksum
        pkt.push(0).expect("capacity pre-checked");

        // Flags + reserved (4 bytes)
        let mut flags = 0u8;
        if self.router {
            flags |= 0x80;
        }
        if self.solicited {
            flags |= 0x40;
        }
        if self.override_flag {
            flags |= 0x20;
        }
        pkt.push(flags).expect("capacity pre-checked");
        pkt.extend_from_slice(&[0u8; 3])
            .expect("capacity pre-checked");

        // Target address
        pkt.extend_from_slice(&self.target.0)
            .expect("capacity pre-checked");

        // Compute checksum
        let checksum = icmpv6_checksum(src, dst, &pkt).expect("fixed-size advertisement");
        pkt[2] = (checksum >> 8) as u8;
        pkt[3] = checksum as u8;

        pkt
    }
}

/// Compute an ICMPv6 checksum over the IPv6 pseudo-header and complete message.
///
/// The message checksum bytes are ignored, so callers may use this both to fill
/// a zeroed checksum field and to independently recompute an existing packet.
pub fn icmpv6_checksum(
    src: &Addr,
    dst: &Addr,
    icmpv6_msg: &[u8],
) -> Result<u16, Icmpv6ChecksumError> {
    let length =
        u32::try_from(icmpv6_msg.len()).map_err(|_| Icmpv6ChecksumError::MessageTooLong)?;
    let mut sum = 0u64;

    // Pseudo-header: src, dst, length, next header
    for chunk in src.0.chunks(2) {
        add_checksum_word(&mut sum, u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    for chunk in dst.0.chunks(2) {
        add_checksum_word(&mut sum, u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    sum += u64::from(length);
    sum += u64::from(next_header::ICMPV6);

    for i in (0..icmpv6_msg.len()).step_by(2) {
        if i == 2 {
            continue;
        }
        let high = icmpv6_msg.get(i).copied().unwrap_or(0);
        let low = icmpv6_msg.get(i + 1).copied().unwrap_or(0);
        let word = ((high as u16) << 8) | (low as u16);
        sum += u64::from(word);
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    Ok(!sum as u16)
}

fn add_checksum_word(sum: &mut u64, word: u16) {
    *sum += u64::from(word);
    *sum = (*sum & 0xffff) + (*sum >> 16);
}

/// Verify ICMPv6 checksum.
///
/// Returns true if the checksum in the message is valid.
fn verify_icmpv6_checksum(src: &Addr, dst: &Addr, icmpv6_msg: &[u8]) -> bool {
    if icmpv6_msg.len() < ICMPV6_HEADER_LEN {
        return false;
    }
    let received = ((icmpv6_msg[2] as u16) << 8) | (icmpv6_msg[3] as u16);
    icmpv6_checksum(src, dst, icmpv6_msg).is_ok_and(|computed| received == computed)
}

/// Compute UDP checksum over pseudo-header + UDP header + payload.
fn udp_checksum(src: &Addr, dst: &Addr, udp_header: &[u8], payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let length = udp_header.len() + payload.len();

    // Pseudo-header
    for chunk in src.0.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    for chunk in dst.0.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    sum += length as u32;
    sum += next_header::UDP as u32;

    // UDP header (skip checksum field at bytes 6-7)
    let mut i = 0;
    while i + 1 < udp_header.len() {
        if i == 6 {
            i += 2;
            continue;
        }
        sum += ((udp_header[i] as u32) << 8) | (udp_header[i + 1] as u32);
        i += 2;
    }
    if i < udp_header.len() {
        sum += (udp_header[i] as u32) << 8;
    }

    // Payload
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += ((payload[i] as u32) << 8) | (payload[i + 1] as u32);
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let result = !sum as u16;
    // UDP checksum of 0 is transmitted as 0xFFFF
    if result == 0 {
        0xffff
    } else {
        result
    }
}

/// Parse an incoming IPv6 packet.
///
/// Returns (header, payload).
pub fn parse_packet(buf: &[u8]) -> Result<(Ipv6Header, &[u8]), Ipv6Error> {
    let header = Ipv6Header::from_bytes(buf)?;
    let payload_start = IPV6_HEADER_LEN;
    let payload_end = payload_start + header.payload_len as usize;

    if buf.len() != payload_end {
        return Err(TooShort::new(payload_end, buf.len()).into());
    }

    Ok((header, &buf[payload_start..payload_end]))
}

/// Dispatch incoming ICMPv6 message.
///
/// Returns `Ok(Some(packet))` if a response should be sent, `Ok(None)` if no response
/// is needed, or `Err` if parsing/building fails.
pub fn handle_icmpv6(
    local_addr: &Addr,
    ip_header: &Ipv6Header,
    icmpv6_payload: &[u8],
) -> Result<Option<Vec<u8, 256>>, Ipv6Error> {
    if icmpv6_payload.len() < ICMPV6_HEADER_LEN {
        return Ok(None);
    }

    // SECURITY: Verify checksum before processing to prevent amplification attacks.
    // Without this, an attacker could send spoofed packets with invalid checksums
    // and we would still generate responses, amplifying traffic to the victim.
    // Use ip_header.dst (not local_addr) because multicast packets (e.g., solicited-node
    // multicast for Neighbor Solicitation) have checksum computed over the multicast dst.
    if !verify_icmpv6_checksum(&ip_header.src, &ip_header.dst, icmpv6_payload) {
        return Ok(None);
    }

    let msg_type = icmpv6_payload[0];
    let code = icmpv6_payload[1];
    // checksum at [2..4]
    let body = &icmpv6_payload[ICMPV6_HEADER_LEN..];

    match msg_type {
        icmpv6_type::ECHO_REQUEST => {
            // RFC 4443: code MUST be 0 for Echo Request
            if code != 0 {
                return Ok(None);
            }
            if ip_header.dst.is_multicast() || ip_header.src.is_multicast() {
                return Ok(None);
            }
            // Reply to ping
            let echo = Icmpv6Echo::from_bytes(body)?;
            let data = &body[4..]; // After id+seq

            // RFC 4443 Section 4.2: reply source SHOULD be the destination of the request.
            // This ensures nodes with multiple addresses reply from the address that was pinged.
            let reply_icmp = echo.build_reply(&ip_header.dst, &ip_header.src, data)?;
            let mut reply_ip = Ipv6Header::new(next_header::ICMPV6, ip_header.dst, ip_header.src);
            reply_ip.hop_limit = 255;

            let mut pkt = Vec::new();
            let mut ip_buf = [0u8; IPV6_HEADER_LEN];
            reply_ip.write_to(reply_icmp.len() as u16, &mut ip_buf)?;
            // IPv6 header (40) + max ICMPv6 echo reply (128) = 168 bytes, fits in 256
            pkt.extend_from_slice(&ip_buf)
                .map_err(|()| BufferTooSmall::new(pkt.len() + ip_buf.len(), pkt.capacity()))?;
            pkt.extend_from_slice(&reply_icmp)
                .map_err(|()| BufferTooSmall::new(pkt.len() + reply_icmp.len(), pkt.capacity()))?;

            Ok(Some(pkt))
        }

        icmpv6_type::NEIGHBOR_SOLICITATION => {
            // RFC 4861: code MUST be 0 for Neighbor Solicitation
            if code != 0 {
                return Ok(None);
            }
            let ns = NeighborSolicitation::from_bytes(body)?;

            // SECURITY: RFC 4861 Section 7.1.1 - Target address MUST NOT be multicast
            if ns.target.is_multicast() {
                return Ok(None);
            }

            // Only respond if target is us
            if ns.target != *local_addr {
                return Ok(None);
            }

            // RFC 4861: DAD probe has unspecified source (::)
            // Response to DAD must use dst=all-nodes multicast, solicited=false
            let is_dad = ip_header.src == Addr::UNSPECIFIED;

            // SECURITY: RFC 4861 Section 7.1.1 - If source is unspecified (DAD),
            // the NS MUST be sent to the solicited-node multicast address of the target.
            // This prevents attackers from using unspecified source with arbitrary destinations.
            if is_dad && ip_header.dst != ns.target.solicited_node() {
                return Ok(None);
            }

            // SECURITY: RFC 4861 Section 7.1.1 - Source address must be unicast or unspecified.
            // Multicast source addresses are invalid for NS messages.
            if ip_header.src.is_multicast() {
                return Ok(None);
            }
            let (reply_dst, solicited) = if is_dad {
                (Addr::ALL_NODES, false)
            } else {
                (ip_header.src, true)
            };

            let na = NeighborAdvertisement {
                target: *local_addr,
                router: false,
                solicited,
                override_flag: true,
            };

            let reply_icmp = na.build(local_addr, &reply_dst);
            let mut reply_ip = Ipv6Header::new(next_header::ICMPV6, *local_addr, reply_dst);
            reply_ip.hop_limit = 255;

            let mut pkt = Vec::new();
            let mut ip_buf = [0u8; IPV6_HEADER_LEN];
            reply_ip.write_to(reply_icmp.len() as u16, &mut ip_buf)?;
            // IPv6 header (40) + NA (24) = 64 bytes, fits easily in 256
            pkt.extend_from_slice(&ip_buf)
                .map_err(|()| BufferTooSmall::new(pkt.len() + ip_buf.len(), pkt.capacity()))?;
            pkt.extend_from_slice(&reply_icmp)
                .map_err(|()| BufferTooSmall::new(pkt.len() + reply_icmp.len(), pkt.capacity()))?;

            Ok(Some(pkt))
        }

        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_link_local_from_mac() {
        let mac = hex!("00 11 22 33 44 55");
        let addr = Addr::link_local_from_mac(&mac);

        // fe80::0211:22ff:fe33:4455
        assert!(addr.is_link_local());
        assert_eq!(addr.0, hex!("fe80 0000 0000 0000 0211 22ff fe33 4455"));
    }

    #[test]
    fn test_solicited_node() {
        let addr = Addr(hex!("fe80 0000 0000 0000 0211 22ff fe33 4455"));
        let sn = addr.solicited_node();

        // ff02::1:ff33:4455
        assert_eq!(sn.0, hex!("ff02 0000 0000 0000 0000 0001 ff33 4455"));
    }

    #[test]
    fn test_ipv6_header_roundtrip() {
        let src = Addr::link_local_from_mac(&hex!("001122334455"));
        let dst = Addr::link_local_from_mac(&hex!("665544332211"));

        let hdr = Ipv6Header::new(next_header::ICMPV6, src, dst);
        let mut buf = [0u8; IPV6_HEADER_LEN];
        let n = hdr.write_to(24, &mut buf).unwrap();
        assert_eq!(n, IPV6_HEADER_LEN);

        let expected = hex!(
            "60 00 00 00 00 18 3a 40 fe 80 00 00 00 00 00 00
             02 11 22 ff fe 33 44 55 fe 80 00 00 00 00 00 00
             64 55 44 ff fe 33 22 11"
        );
        assert_eq!(&buf[..], &expected[..]);

        let parsed = Ipv6Header::from_bytes(&buf).unwrap();

        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.next_header, next_header::ICMPV6);
        assert_eq!(parsed.payload_len, 24);
        assert_eq!(parsed.hop_limit, 64);
        assert_eq!(parsed.traffic_class, 0);
        assert_eq!(parsed.flow_label, 0);
    }

    #[test]
    fn test_echo_request_response() {
        let src = Addr::link_local_from_mac(&hex!("001122334455"));
        let dst = Addr::link_local_from_mac(&hex!("665544332211"));

        let echo = Icmpv6Echo { id: 1, seq: 1 };
        let request = echo.build_request(&src, &dst, b"ping").unwrap();

        assert_eq!(request[0], icmpv6_type::ECHO_REQUEST);
        assert_eq!(request.len(), 8 + 4); // header + "ping"

        let reply = echo.build_reply(&dst, &src, b"ping").unwrap();
        assert_eq!(reply[0], icmpv6_type::ECHO_REPLY);
    }

    #[test]
    fn test_handle_ping() {
        let local = Addr::link_local_from_mac(&hex!("001122334455"));
        let remote = Addr::link_local_from_mac(&hex!("665544332211"));

        // Build a ping request
        let echo = Icmpv6Echo { id: 42, seq: 1 };
        let icmp_req = echo.build_request(&remote, &local, b"test").unwrap();

        let ip_hdr = Ipv6Header::new(next_header::ICMPV6, remote, local);

        // Handle it
        let response = handle_icmpv6(&local, &ip_hdr, &icmp_req).unwrap();
        assert!(response.is_some());

        let pkt = response.unwrap();
        // Should be IPv6 header + ICMPv6 reply
        assert!(pkt.len() > IPV6_HEADER_LEN);

        let (resp_ip, resp_payload) = parse_packet(&pkt).unwrap();
        assert_eq!(resp_ip.src, local);
        assert_eq!(resp_ip.dst, remote);
        assert_eq!(resp_ip.hop_limit, 255);
        assert_eq!(resp_payload[0], icmpv6_type::ECHO_REPLY);
    }

    #[test]
    fn test_reject_bad_checksum() {
        let local = Addr::link_local_from_mac(&hex!("001122334455"));
        let remote = Addr::link_local_from_mac(&hex!("665544332211"));

        // Build a valid ping request
        let echo = Icmpv6Echo { id: 42, seq: 1 };
        let mut icmp_req = echo.build_request(&remote, &local, b"test").unwrap();

        // Corrupt the checksum (bytes 2-3)
        icmp_req[2] ^= 0xFF;

        let ip_hdr = Ipv6Header::new(next_header::ICMPV6, remote, local);

        // Should reject due to bad checksum (returns Ok(None), not an error)
        let response = handle_icmpv6(&local, &ip_hdr, &icmp_req).unwrap();
        assert!(response.is_none(), "should reject packet with bad checksum");
    }

    #[test]
    fn test_echo_data_too_large() {
        let src = Addr::link_local_from_mac(&hex!("001122334455"));
        let dst = Addr::link_local_from_mac(&hex!("665544332211"));

        let echo = Icmpv6Echo { id: 1, seq: 1 };
        // MAX_ECHO_DATA is 120 bytes (128 buffer - 8 header)
        let large_data = [0u8; 121];

        let result = echo.build_request(&src, &dst, &large_data);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.required, 129); // 8 header + 121 data
        assert_eq!(err.provided, 128);

        // Exactly at the limit should succeed
        let max_data = [0u8; MAX_ECHO_DATA];
        let result = echo.build_request(&src, &dst, &max_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 128);
    }

    #[test]
    fn test_is_ula() {
        // fd00::/8 is a common ULA prefix
        let addr = Addr(hex!("fd00 1234 0000 0000 0000 0000 0000 0001"));
        assert!(addr.is_ula());
        assert!(!addr.is_link_local());
        assert!(!addr.is_gua());

        // fc00::/8 is also technically ULA (but L=0, rarely used)
        let addr2 = Addr(hex!("fc00 0000 0000 0000 0000 0000 0000 0001"));
        assert!(addr2.is_ula());
    }

    #[test]
    fn test_is_gua() {
        // 2001:db8::/32 is documentation prefix (a GUA)
        let addr = Addr(hex!("2001 0db8 0000 0000 0000 0000 0000 0001"));
        assert!(addr.is_gua());
        assert!(!addr.is_ula());
        assert!(!addr.is_link_local());

        // 2000::/3 means 2000:: through 3fff::
        let addr_2000 = Addr(hex!("2000 0000 0000 0000 0000 0000 0000 0001"));
        let addr_3fff = Addr(hex!("3fff ffff ffff ffff 0000 0000 0000 0001"));
        assert!(addr_2000.is_gua());
        assert!(addr_3fff.is_gua());

        // 4000:: is NOT a GUA
        let addr_4000 = Addr(hex!("4000 0000 0000 0000 0000 0000 0000 0001"));
        assert!(!addr_4000.is_gua());
    }

    #[test]
    fn test_is_loopback() {
        assert!(Addr::LOOPBACK.is_loopback());
        let addr = Addr(hex!("0000 0000 0000 0000 0000 0000 0000 0001"));
        assert!(addr.is_loopback());
        assert!(!Addr::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_iid() {
        let addr = Addr(hex!("fe80 0000 0000 0000 0211 22ff fe33 4455"));
        let iid = addr.iid();
        assert_eq!(iid, hex!("0211 22ff fe33 4455"));
    }

    #[test]
    fn test_flow_label_validation() {
        let src = Addr::link_local_from_mac(&hex!("001122334455"));
        let dst = Addr::link_local_from_mac(&hex!("665544332211"));
        let mut buf = [0u8; IPV6_HEADER_LEN];

        // Valid flow_label at maximum (20 bits = 0xfffff)
        let mut hdr = Ipv6Header::new(next_header::ICMPV6, src, dst);
        hdr.flow_label = 0xfffff;
        assert!(hdr.write_to(0, &mut buf).is_ok());

        // Invalid flow_label exceeds 20 bits
        hdr.flow_label = 0x100000;
        let result = hdr.write_to(0, &mut buf);
        assert!(matches!(result, Err(Ipv6Error::InvalidFlowLabel(0x100000))));

        // Also test a larger invalid value
        hdr.flow_label = 0xffffffff;
        let result = hdr.write_to(0, &mut buf);
        assert!(matches!(
            result,
            Err(Ipv6Error::InvalidFlowLabel(0xffffffff))
        ));
    }

    #[test]
    fn test_with_decremented_hop_limit() {
        let src = Addr::link_local_from_mac(&hex!("001122334455"));
        let dst = Addr::link_local_from_mac(&hex!("665544332211"));
        let mut hdr = Ipv6Header::new(next_header::ICMPV6, src, dst);
        hdr.hop_limit = 5;
        hdr.flow_label = 0x12345;

        // independent test vector per RFC 8200: 5->4, fields preserved
        let dec = hdr.with_decremented_hop_limit().unwrap();
        assert_eq!(dec.hop_limit, 4);
        assert_eq!(dec.flow_label, 0x12345);
        assert_eq!(dec.src, src);
        assert_eq!(dec.dst, dst);
        assert_eq!(dec.next_header, next_header::ICMPV6);

        // hop_limit=1 or 0 reaches zero after decrement -> None (drop + ICMP)
        let mut one = hdr;
        one.hop_limit = 1;
        assert!(one.with_decremented_hop_limit().is_none());

        let mut zero = hdr;
        zero.hop_limit = 0;
        assert!(zero.with_decremented_hop_limit().is_none());
    }
}
