//! Whole-packet SCHC compression: packet bytes <-> field dicts (RFC 8724).
//!
//! Bridges parsed protocol headers and the field-dict the SCHC codec consumes. A
//! [`PacketProfile`] flattens a raw packet of a particular shape into field-value
//! pairs (plus a variable tail the rule does not model) and rebuilds the bytes
//! from decompressed fields.
//!
//! This mirrors the Python `lichen.schc.headers` module.
//!
//! Profiles implemented (spec appendix A.1):
//! - rule 0: link-local IPv6 + UDP + CoAP
//! - rule 1: global IPv6 + UDP + CoAP
//! - rule 2: ICMPv6 Echo Request/Reply over link-local IPv6
//! - rule 3: RPL DIO over link-local ICMPv6
//! - rule 4: RPL DAO over link-local ICMPv6
//! - rule 5: link-local IPv6 + UDP + OSCORE CoAP
//! - rule 6: global IPv6 + UDP + OSCORE CoAP
//!
//! The variable trailer (CoAP token/options/payload, or RPL options) travels
//! verbatim after the byte-aligned residue.

use crate::context::FieldId;
use crate::rules::Rule;

// IPv6 constants
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const COAP_FIXED_HEADER: usize = 4;
const COAP_BUF_SIZE: usize = 256;
const COAP_MAX_TAIL: usize = COAP_BUF_SIZE - COAP_FIXED_HEADER;
const ICMPV6_HEADER: usize = 4;
const ICMPV6_ECHO_BASE: usize = 8;
const DIO_BASE: usize = 24;
const DAO_BASE_WITH_DODAGID: usize = 20;

// Next header values
const NEXT_HEADER_UDP: u8 = 17;
const NEXT_HEADER_ICMPV6: u8 = 58;

// ICMPv6 types
const ICMPV6_RPL_TYPE: u8 = 155;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Maximum number of fields in a parsed packet.
pub const MAX_FIELDS: usize = 24;

/// A parsed packet as field-value pairs plus trailing bytes.
pub struct ParsedPacket<'a> {
    /// Field ID to value mapping.
    pub fields: [(FieldId, u128); MAX_FIELDS],
    /// Number of valid entries in fields.
    pub field_count: usize,
    /// Trailing bytes not covered by field descriptors.
    pub tail: &'a [u8],
}

impl<'a> ParsedPacket<'a> {
    /// Create an empty parsed packet.
    pub fn new(tail: &'a [u8]) -> Self {
        Self {
            fields: [("", 0); MAX_FIELDS],
            field_count: 0,
            tail,
        }
    }

    /// Add a field to the parsed packet.
    ///
    /// Returns false if the field array is full.
    pub fn add_field(&mut self, id: FieldId, value: u128) -> bool {
        if self.field_count >= MAX_FIELDS {
            return false;
        }
        self.fields[self.field_count] = (id, value);
        self.field_count += 1;
        true
    }

    /// Get a field value by ID.
    pub fn get(&self, id: &str) -> Option<u128> {
        for i in 0..self.field_count {
            if self.fields[i].0 == id {
                return Some(self.fields[i].1);
            }
        }
        None
    }

    /// Get field slice for rule matching.
    pub fn as_slice(&self) -> &[(FieldId, u128)] {
        &self.fields[..self.field_count]
    }
}

/// Error type for packet parsing/building.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    /// Packet is too short.
    TooShort { expected: usize, actual: usize },
    /// Invalid packet structure.
    InvalidPacket(&'static str),
    /// Buffer too small for output.
    BufferTooSmall { needed: usize, available: usize },
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(
                    f,
                    "packet too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidPacket(msg) => write!(f, "invalid packet: {}", msg),
            Self::BufferTooSmall { needed, available } => {
                write!(
                    f,
                    "buffer too small: need {} bytes, have {}",
                    needed, available
                )
            }
        }
    }
}

impl core::error::Error for PacketError {}

// ============================================================================
// Address helpers
// ============================================================================

fn is_link_local(addr: &[u8]) -> bool {
    addr.len() == 16 && addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
}

fn is_global(addr: &[u8]) -> bool {
    addr.len() == 16 && (addr[0] >> 5) == 0b001
}

fn is_ula(addr: &[u8]) -> bool {
    addr.len() == 16 && (addr[0] & 0xfe) == 0xfc
}

fn is_routable(addr: &[u8]) -> bool {
    is_link_local(addr) || is_ula(addr) || is_global(addr)
}

fn addr_to_u128(addr: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(addr);
    u128::from_be_bytes(bytes)
}

fn u128_to_addr(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

// ============================================================================
// Checksum helpers
// ============================================================================

fn oc_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >> 16 != 0 {
        (s & 0xFFFF) + (s >> 16)
    } else {
        s
    }
}

fn checksum_bytes(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let chunks = data.chunks_exact(2);
    let remainder = chunks.remainder();
    for pair in chunks {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    if let Some(&last) = remainder.first() {
        sum = oc_add(sum, (last as u32) << 8);
    }
    sum
}

fn pseudo_sum(src: &[u8; 16], dst: &[u8; 16], next_header: u8, length: u16) -> u32 {
    let mut sum: u32 = 0;
    for pair in src.chunks_exact(2) {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    for pair in dst.chunks_exact(2) {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    sum = oc_add(sum, length as u32);
    oc_add(sum, next_header as u32)
}

fn finalize(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

fn udp_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> u16 {
    let udp_len = (8 + payload.len()) as u16;
    let mut sum = pseudo_sum(src, dst, NEXT_HEADER_UDP, udp_len);
    sum = oc_add(sum, src_port as u32);
    sum = oc_add(sum, dst_port as u32);
    sum = oc_add(sum, udp_len as u32);
    sum = oc_add(sum, checksum_bytes(payload));
    finalize(sum)
}

fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmpv6_payload: &[u8]) -> u16 {
    let length = icmpv6_payload.len() as u16;
    let mut sum = pseudo_sum(src, dst, NEXT_HEADER_ICMPV6, length);
    sum = oc_add(sum, checksum_bytes(icmpv6_payload));
    finalize(sum)
}

// ============================================================================
// IPv6 field extraction
// ============================================================================

fn parse_ipv6_fields<'a>(raw: &'a [u8], parsed: &mut ParsedPacket<'a>) -> Result<(), PacketError> {
    if raw.len() < IPV6_HEADER_LEN {
        return Err(PacketError::TooShort {
            expected: IPV6_HEADER_LEN,
            actual: raw.len(),
        });
    }

    let version = raw[0] >> 4;
    if version != 6 {
        return Err(PacketError::InvalidPacket("not IPv6"));
    }

    let traffic_class = ((raw[0] & 0x0F) << 4) | (raw[1] >> 4);
    let flow_label = ((raw[1] as u32 & 0x0F) << 16) | ((raw[2] as u32) << 8) | (raw[3] as u32);
    let payload_length = u16::from_be_bytes([raw[4], raw[5]]);
    let next_header = raw[6];
    let hop_limit = raw[7];
    let src = addr_to_u128(&raw[8..24]);
    let dst = addr_to_u128(&raw[24..40]);

    parsed.add_field("IPv6.version", 6);
    parsed.add_field("IPv6.traffic_class", traffic_class as u128);
    parsed.add_field("IPv6.flow_label", flow_label as u128);
    parsed.add_field("IPv6.payload_length", payload_length as u128);
    parsed.add_field("IPv6.next_header", next_header as u128);
    parsed.add_field("IPv6.hop_limit", hop_limit as u128);
    parsed.add_field("IPv6.src", src);
    parsed.add_field("IPv6.dst", dst);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_ipv6_header(
    out: &mut [u8],
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    flow: (u8, u32),
    src: &[u8; 16],
    dst: &[u8; 16],
) {
    let (traffic_class, flow_label) = flow;
    out[0] = 0x60 | ((traffic_class >> 4) & 0x0F);
    out[1] = ((traffic_class & 0x0F) << 4) | ((flow_label >> 16) as u8 & 0x0F);
    out[2] = (flow_label >> 8) as u8;
    out[3] = flow_label as u8;
    out[4] = (payload_len >> 8) as u8;
    out[5] = payload_len as u8;
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(src);
    out[24..40].copy_from_slice(dst);
}

// ============================================================================
// PacketProfile trait
// ============================================================================

/// Maps a class of packets to/from a SCHC rule's field dict.
pub trait PacketProfile {
    /// The SCHC rule associated with this profile.
    fn rule(&self) -> &'static Rule;

    /// Check if a raw packet matches this profile.
    fn matches(&self, raw: &[u8]) -> bool;

    /// Parse a raw packet into fields and a tail.
    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError>;

    /// Build a packet from fields and a tail.
    ///
    /// Returns the number of bytes written to `out`.
    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError>;
}

// ============================================================================
// CoAP over UDP profiles
// ============================================================================

/// Link-local IPv6 + UDP + CoAP (SCHC rule 0).
pub struct CoapUdpLinkLocalProfile;

/// Global IPv6 + UDP + CoAP (SCHC rule 1).
pub struct CoapUdpGlobalProfile;

impl CoapUdpLinkLocalProfile {
    fn addr_ok(addr: &[u8]) -> bool {
        is_link_local(addr)
    }
}

impl CoapUdpGlobalProfile {
    fn addr_ok(addr: &[u8]) -> bool {
        is_global(addr)
    }
}

fn coap_profile_matches<F: Fn(&[u8]) -> bool>(raw: &[u8], addr_check: F) -> bool {
    let min_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + COAP_FIXED_HEADER;
    if raw.len() < min_len {
        return false;
    }
    if raw[0] >> 4 != 6 {
        return false;
    }
    if raw[6] != NEXT_HEADER_UDP {
        return false;
    }
    let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    if raw.len() < IPV6_HEADER_LEN + payload_length {
        return false;
    }
    if payload_length < UDP_HEADER_LEN + COAP_FIXED_HEADER {
        return false;
    }
    addr_check(&raw[8..24]) && addr_check(&raw[24..40])
}

fn parse_coap_udp<'a>(raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
    let min_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + COAP_FIXED_HEADER;
    if raw.len() < min_len {
        return Err(PacketError::TooShort {
            expected: min_len,
            actual: raw.len(),
        });
    }

    let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    if IPV6_HEADER_LEN + payload_length > raw.len() {
        return Err(PacketError::TooShort {
            expected: IPV6_HEADER_LEN + payload_length,
            actual: raw.len(),
        });
    }
    let udp = &raw[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_length];
    let coap = &udp[UDP_HEADER_LEN..];
    let tail = &coap[COAP_FIXED_HEADER..];

    let mut parsed = ParsedPacket::new(tail);
    parse_ipv6_fields(raw, &mut parsed)?;

    // UDP fields
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_length = u16::from_be_bytes([udp[4], udp[5]]);
    let udp_checksum = u16::from_be_bytes([udp[6], udp[7]]);

    parsed.add_field("UDP.src_port", src_port as u128);
    parsed.add_field("UDP.dst_port", dst_port as u128);
    parsed.add_field("UDP.length", udp_length as u128);
    parsed.add_field("UDP.checksum", udp_checksum as u128);

    // CoAP fixed header fields
    let coap_b0 = coap[0];
    parsed.add_field("CoAP.version", (coap_b0 >> 6) as u128);
    parsed.add_field("CoAP.type", ((coap_b0 >> 4) & 0x3) as u128);
    parsed.add_field("CoAP.tkl", (coap_b0 & 0x0F) as u128);
    parsed.add_field("CoAP.code", coap[1] as u128);
    parsed.add_field("CoAP.mid", u16::from_be_bytes([coap[2], coap[3]]) as u128);

    Ok(parsed)
}

fn build_coap_udp(
    fields: &[(FieldId, u128)],
    tail: &[u8],
    out: &mut [u8],
) -> Result<usize, PacketError> {
    // Helper to get required field
    let get = |id: &str| -> Result<u128, PacketError> {
        for (fid, val) in fields {
            if *fid == id {
                return Ok(*val);
            }
        }
        Err(PacketError::InvalidPacket("missing required field"))
    };

    let src = u128_to_addr(get("IPv6.src")?);
    let dst = u128_to_addr(get("IPv6.dst")?);
    let hop_limit = get("IPv6.hop_limit")? as u8;
    let traffic_class = get("IPv6.traffic_class").unwrap_or(0) as u8;
    let flow_label = get("IPv6.flow_label").unwrap_or(0) as u32;

    let src_port = get("UDP.src_port")? as u16;
    let dst_port = get("UDP.dst_port")? as u16;

    let coap_type = get("CoAP.type")? as u8;
    let coap_tkl = get("CoAP.tkl")? as u8;
    let coap_code = get("CoAP.code")? as u8;
    let coap_mid = get("CoAP.mid")? as u16;

    // Build CoAP
    let coap_len = COAP_FIXED_HEADER + tail.len();
    let udp_len = (UDP_HEADER_LEN + coap_len) as u16;
    let total = IPV6_HEADER_LEN + UDP_HEADER_LEN + coap_len;

    if out.len() < total {
        return Err(PacketError::BufferTooSmall {
            needed: total,
            available: out.len(),
        });
    }

    // Build CoAP header
    // SECURITY: Validate tail fits in buffer to prevent panic on oversized payloads
    if tail.len() > COAP_MAX_TAIL {
        return Err(PacketError::BufferTooSmall {
            needed: COAP_FIXED_HEADER + tail.len(),
            available: COAP_BUF_SIZE,
        });
    }
    let coap_b0 = (1u8 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F);
    let mut coap_buf = [0u8; COAP_BUF_SIZE];
    coap_buf[0] = coap_b0;
    coap_buf[1] = coap_code;
    coap_buf[2] = (coap_mid >> 8) as u8;
    coap_buf[3] = coap_mid as u8;
    coap_buf[COAP_FIXED_HEADER..COAP_FIXED_HEADER + tail.len()].copy_from_slice(tail);

    // Calculate UDP checksum
    let cksum = udp_checksum(&src, &dst, src_port, dst_port, &coap_buf[..coap_len]);

    // Write IPv6 header
    write_ipv6_header(
        out,
        udp_len,
        NEXT_HEADER_UDP,
        hop_limit,
        traffic_class,
        flow_label,
        &src,
        &dst,
    );

    // Write UDP header
    out[40..42].copy_from_slice(&src_port.to_be_bytes());
    out[42..44].copy_from_slice(&dst_port.to_be_bytes());
    out[44..46].copy_from_slice(&udp_len.to_be_bytes());
    out[46..48].copy_from_slice(&cksum.to_be_bytes());

    // Write CoAP
    out[48..48 + coap_len].copy_from_slice(&coap_buf[..coap_len]);

    Ok(total)
}

impl PacketProfile for CoapUdpLinkLocalProfile {
    fn rule(&self) -> &'static Rule {
        &crate::rules::LINK_LOCAL_COAP_RULE
    }

    fn matches(&self, raw: &[u8]) -> bool {
        coap_profile_matches(raw, Self::addr_ok)
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
        parse_coap_udp(raw)
    }

    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        build_coap_udp(fields, tail, out)
    }
}

impl PacketProfile for CoapUdpGlobalProfile {
    fn rule(&self) -> &'static Rule {
        &crate::rules::GLOBAL_COAP_RULE
    }

    fn matches(&self, raw: &[u8]) -> bool {
        coap_profile_matches(raw, Self::addr_ok)
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
        parse_coap_udp(raw)
    }

    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        build_coap_udp(fields, tail, out)
    }
}

// ============================================================================
// ICMPv6 Echo profile
// ============================================================================

/// Link-local IPv6 + ICMPv6 Echo Request/Reply (SCHC rule 2).
pub struct Icmpv6EchoProfile;

impl PacketProfile for Icmpv6EchoProfile {
    fn rule(&self) -> &'static Rule {
        &crate::rules::ICMPV6_ECHO_RULE
    }

    fn matches(&self, raw: &[u8]) -> bool {
        let min_len = IPV6_HEADER_LEN + ICMPV6_ECHO_BASE;
        if raw.len() < min_len {
            return false;
        }
        if raw[0] >> 4 != 6 {
            return false;
        }
        if raw[6] != NEXT_HEADER_ICMPV6 {
            return false;
        }
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if raw.len() < IPV6_HEADER_LEN + payload_length {
            return false;
        }
        if payload_length < ICMPV6_ECHO_BASE {
            return false;
        }
        if !is_link_local(&raw[8..24]) || !is_link_local(&raw[24..40]) {
            return false;
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..];
        (icmpv6[0] == ICMPV6_ECHO_REQUEST || icmpv6[0] == ICMPV6_ECHO_REPLY) && icmpv6[1] == 0
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
        let min_len = IPV6_HEADER_LEN + ICMPV6_ECHO_BASE;
        if raw.len() < min_len {
            return Err(PacketError::TooShort {
                expected: min_len,
                actual: raw.len(),
            });
        }

        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if IPV6_HEADER_LEN + payload_length > raw.len() {
            return Err(PacketError::TooShort {
                expected: IPV6_HEADER_LEN + payload_length,
                actual: raw.len(),
            });
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_length];
        let tail = &icmpv6[ICMPV6_ECHO_BASE..];

        let mut parsed = ParsedPacket::new(tail);
        parse_ipv6_fields(raw, &mut parsed)?;

        parsed.add_field("ICMPv6.type", icmpv6[0] as u128);
        parsed.add_field("ICMPv6.code", icmpv6[1] as u128);
        parsed.add_field(
            "ICMPv6.checksum",
            u16::from_be_bytes([icmpv6[2], icmpv6[3]]) as u128,
        );
        parsed.add_field(
            "ICMPv6.identifier",
            u16::from_be_bytes([icmpv6[4], icmpv6[5]]) as u128,
        );
        parsed.add_field(
            "ICMPv6.sequence",
            u16::from_be_bytes([icmpv6[6], icmpv6[7]]) as u128,
        );

        Ok(parsed)
    }

    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        let get = |id: &str| -> Result<u128, PacketError> {
            for (fid, val) in fields {
                if *fid == id {
                    return Ok(*val);
                }
            }
            Err(PacketError::InvalidPacket("missing required field"))
        };

        let src = u128_to_addr(get("IPv6.src")?);
        let dst = u128_to_addr(get("IPv6.dst")?);
        let hop_limit = get("IPv6.hop_limit")? as u8;
        let traffic_class = get("IPv6.traffic_class").unwrap_or(0) as u8;
        let flow_label = get("IPv6.flow_label").unwrap_or(0) as u32;

        let icmp_type = get("ICMPv6.type")? as u8;
        let icmp_code = get("ICMPv6.code").unwrap_or(0) as u8;
        let icmp_id = get("ICMPv6.identifier")? as u16;
        let icmp_seq = get("ICMPv6.sequence")? as u16;

        let icmp_len = ICMPV6_ECHO_BASE + tail.len();
        let total = IPV6_HEADER_LEN + icmp_len;

        if out.len() < total {
            return Err(PacketError::BufferTooSmall {
                needed: total,
                available: out.len(),
            });
        }
        if tail.len() > 248 {
            return Err(PacketError::BufferTooSmall {
                needed: ICMPV6_ECHO_BASE + tail.len(),
                available: 248,
            });
        }

        let mut icmp_buf = [0u8; 256];
        icmp_buf[0] = icmp_type;
        icmp_buf[1] = icmp_code;
        icmp_buf[2] = 0;
        icmp_buf[3] = 0;
        icmp_buf[4] = (icmp_id >> 8) as u8;
        icmp_buf[5] = icmp_id as u8;
        icmp_buf[6] = (icmp_seq >> 8) as u8;
        icmp_buf[7] = icmp_seq as u8;
        icmp_buf[ICMPV6_ECHO_BASE..ICMPV6_ECHO_BASE + tail.len()].copy_from_slice(tail);

        let cksum = icmpv6_checksum(&src, &dst, &icmp_buf[..icmp_len]);

        write_ipv6_header(
            out,
            icmp_len as u16,
            NEXT_HEADER_ICMPV6,
            hop_limit,
            traffic_class,
            flow_label,
            &src,
            &dst,
        );

        out[40] = icmp_type;
        out[41] = icmp_code;
        out[42] = (cksum >> 8) as u8;
        out[43] = cksum as u8;
        out[44] = (icmp_id >> 8) as u8;
        out[45] = icmp_id as u8;
        out[46] = (icmp_seq >> 8) as u8;
        out[47] = icmp_seq as u8;
        out[48..48 + tail.len()].copy_from_slice(tail);

        Ok(total)
    }
}

// ============================================================================
// RPL profiles
// ============================================================================

/// RPL DIO over link-local ICMPv6 (SCHC rule 3).
pub struct RplDioProfile;

/// RPL DAO with DODAGID over routable IPv6 (SCHC rule 4, multi-hop source model).
pub struct RplDaoProfile;

impl PacketProfile for RplDioProfile {
    fn rule(&self) -> &'static Rule {
        &crate::rules::RPL_DIO_RULE
    }

    fn matches(&self, raw: &[u8]) -> bool {
        let min_len = IPV6_HEADER_LEN + ICMPV6_HEADER + DIO_BASE;
        if raw.len() < min_len {
            return false;
        }
        if raw[0] >> 4 != 6 {
            return false;
        }
        if raw[6] != NEXT_HEADER_ICMPV6 {
            return false;
        }
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if raw.len() < IPV6_HEADER_LEN + payload_length {
            return false;
        }
        if payload_length < ICMPV6_HEADER + DIO_BASE {
            return false;
        }
        if !is_routable(&raw[8..24]) || !is_routable(&raw[24..40]) {
            return false;
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..];
        icmpv6[0] == ICMPV6_RPL_TYPE && icmpv6[1] == 1 // DIO code
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
        let min_len = IPV6_HEADER_LEN + ICMPV6_HEADER + DIO_BASE;
        if raw.len() < min_len {
            return Err(PacketError::TooShort {
                expected: min_len,
                actual: raw.len(),
            });
        }

        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if IPV6_HEADER_LEN + payload_length > raw.len() {
            return Err(PacketError::TooShort {
                expected: IPV6_HEADER_LEN + payload_length,
                actual: raw.len(),
            });
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_length];
        let rpl = &icmpv6[ICMPV6_HEADER..];
        let tail = &rpl[DIO_BASE..];

        let mut parsed = ParsedPacket::new(tail);
        parse_ipv6_fields(raw, &mut parsed)?;

        parsed.add_field("ICMPv6.type", icmpv6[0] as u128);
        parsed.add_field("ICMPv6.code", icmpv6[1] as u128);
        parsed.add_field(
            "ICMPv6.checksum",
            u16::from_be_bytes([icmpv6[2], icmpv6[3]]) as u128,
        );

        parsed.add_field("RPL.instance", rpl[0] as u128);
        parsed.add_field("RPL.version", rpl[1] as u128);
        parsed.add_field("RPL.rank", u16::from_be_bytes([rpl[2], rpl[3]]) as u128);
        parsed.add_field("RPL.gmop", rpl[4] as u128);
        parsed.add_field("RPL.dtsn", rpl[5] as u128);
        parsed.add_field("RPL.flags", rpl[6] as u128);
        parsed.add_field("RPL.reserved", rpl[7] as u128);

        let dodagid = u128::from_be_bytes(rpl[8..24].try_into().unwrap());
        parsed.add_field("RPL.dodagid", dodagid);

        Ok(parsed)
    }

    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        let get = |id: &str| -> Result<u128, PacketError> {
            for (fid, val) in fields {
                if *fid == id {
                    return Ok(*val);
                }
            }
            Err(PacketError::InvalidPacket("missing required field"))
        };

        let src = u128_to_addr(get("IPv6.src")?);
        let dst = u128_to_addr(get("IPv6.dst")?);
        let hop_limit = get("IPv6.hop_limit")? as u8;
        let traffic_class = get("IPv6.traffic_class").unwrap_or(0) as u8;
        let flow_label = get("IPv6.flow_label").unwrap_or(0) as u32;

        let instance = get("RPL.instance")? as u8;
        let version = get("RPL.version")? as u8;
        let rank = get("RPL.rank")? as u16;
        let gmop = get("RPL.gmop")? as u8;
        let dtsn = get("RPL.dtsn")? as u8;
        let flags = get("RPL.flags").unwrap_or(0) as u8;
        let reserved = get("RPL.reserved").unwrap_or(0) as u8;
        let dodagid = get("RPL.dodagid")?;

        let rpl_body_len = DIO_BASE + tail.len();
        let icmp_len = ICMPV6_HEADER + rpl_body_len;
        let total = IPV6_HEADER_LEN + icmp_len;

        if out.len() < total {
            return Err(PacketError::BufferTooSmall {
                needed: total,
                available: out.len(),
            });
        }
        if rpl_body_len > 256 {
            return Err(PacketError::BufferTooSmall {
                needed: rpl_body_len,
                available: 256,
            });
        }

        let mut icmp_buf = [0u8; 256];
        icmp_buf[0] = ICMPV6_RPL_TYPE;
        icmp_buf[1] = 1;
        icmp_buf[2] = 0;
        icmp_buf[3] = 0;
        icmp_buf[4] = instance;
        icmp_buf[5] = version;
        icmp_buf[6] = (rank >> 8) as u8;
        icmp_buf[7] = rank as u8;
        icmp_buf[8] = gmop;
        icmp_buf[9] = dtsn;
        icmp_buf[10] = flags;
        icmp_buf[11] = reserved;
        icmp_buf[12..28].copy_from_slice(&dodagid.to_be_bytes());
        icmp_buf[28..28 + tail.len()].copy_from_slice(tail);

        let cksum = icmpv6_checksum(&src, &dst, &icmp_buf[..icmp_len]);

        write_ipv6_header(
            out,
            icmp_len as u16,
            NEXT_HEADER_ICMPV6,
            hop_limit,
            traffic_class,
            flow_label,
            &src,
            &dst,
        );

        out[40..40 + icmp_len].copy_from_slice(&icmp_buf[..icmp_len]);
        out[42] = (cksum >> 8) as u8;
        out[43] = cksum as u8;

        Ok(total)
    }
}

impl PacketProfile for RplDaoProfile {
    fn rule(&self) -> &'static Rule {
        &crate::rules::RPL_DAO_RULE
    }

    fn matches(&self, raw: &[u8]) -> bool {
        let min_len = IPV6_HEADER_LEN + ICMPV6_HEADER + DAO_BASE_WITH_DODAGID;
        if raw.len() < min_len {
            return false;
        }
        if raw[0] >> 4 != 6 {
            return false;
        }
        if raw[6] != NEXT_HEADER_ICMPV6 {
            return false;
        }
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if raw.len() < IPV6_HEADER_LEN + payload_length {
            return false;
        }
        if payload_length < ICMPV6_HEADER + DAO_BASE_WITH_DODAGID {
            return false;
        }
        if !is_routable(&raw[8..24]) || !is_routable(&raw[24..40]) {
            return false;
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..];
        if icmpv6[0] != ICMPV6_RPL_TYPE || icmpv6[1] != 2 {
            return false;
        }
        let flags = icmpv6[ICMPV6_HEADER + 1];
        (flags & 0x40) != 0
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedPacket<'a>, PacketError> {
        let min_len = IPV6_HEADER_LEN + ICMPV6_HEADER + DAO_BASE_WITH_DODAGID;
        if raw.len() < min_len {
            return Err(PacketError::TooShort {
                expected: min_len,
                actual: raw.len(),
            });
        }

        let payload_length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if IPV6_HEADER_LEN + payload_length > raw.len() {
            return Err(PacketError::TooShort {
                expected: IPV6_HEADER_LEN + payload_length,
                actual: raw.len(),
            });
        }
        let icmpv6 = &raw[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_length];
        let rpl = &icmpv6[ICMPV6_HEADER..];
        let tail = &rpl[DAO_BASE_WITH_DODAGID..];

        let mut parsed = ParsedPacket::new(tail);
        parse_ipv6_fields(raw, &mut parsed)?;

        parsed.add_field("ICMPv6.type", icmpv6[0] as u128);
        parsed.add_field("ICMPv6.code", icmpv6[1] as u128);
        parsed.add_field(
            "ICMPv6.checksum",
            u16::from_be_bytes([icmpv6[2], icmpv6[3]]) as u128,
        );

        parsed.add_field("RPL.instance", rpl[0] as u128);
        parsed.add_field("RPL.flags", rpl[1] as u128);
        parsed.add_field("RPL.reserved", rpl[2] as u128);
        parsed.add_field("RPL.seq", rpl[3] as u128);

        let dodagid = u128::from_be_bytes(rpl[4..20].try_into().unwrap());
        parsed.add_field("RPL.dodagid", dodagid);

        Ok(parsed)
    }

    fn build(
        &self,
        fields: &[(FieldId, u128)],
        tail: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        let get = |id: &str| -> Result<u128, PacketError> {
            for (fid, val) in fields {
                if *fid == id {
                    return Ok(*val);
                }
            }
            Err(PacketError::InvalidPacket("missing required field"))
        };

        let src = u128_to_addr(get("IPv6.src")?);
        let dst = u128_to_addr(get("IPv6.dst")?);
        let hop_limit = get("IPv6.hop_limit")? as u8;
        let traffic_class = get("IPv6.traffic_class").unwrap_or(0) as u8;
        let flow_label = get("IPv6.flow_label").unwrap_or(0) as u32;

        let instance = get("RPL.instance")? as u8;
        let flags = get("RPL.flags")? as u8;
        let reserved = get("RPL.reserved").unwrap_or(0) as u8;
        let seq = get("RPL.seq")? as u8;
        let dodagid = get("RPL.dodagid")?;

        let rpl_body_len = DAO_BASE_WITH_DODAGID + tail.len();
        let icmp_len = ICMPV6_HEADER + rpl_body_len;
        let total = IPV6_HEADER_LEN + icmp_len;

        if out.len() < total {
            return Err(PacketError::BufferTooSmall {
                needed: total,
                available: out.len(),
            });
        }
        if rpl_body_len > 256 {
            return Err(PacketError::BufferTooSmall {
                needed: rpl_body_len,
                available: 256,
            });
        }

        let mut icmp_buf = [0u8; 256];
        icmp_buf[0] = ICMPV6_RPL_TYPE;
        icmp_buf[1] = 2;
        icmp_buf[2] = 0;
        icmp_buf[3] = 0;
        icmp_buf[4] = instance;
        icmp_buf[5] = flags;
        icmp_buf[6] = reserved;
        icmp_buf[7] = seq;
        icmp_buf[8..24].copy_from_slice(&dodagid.to_be_bytes());
        icmp_buf[24..24 + tail.len()].copy_from_slice(tail);

        let cksum = icmpv6_checksum(&src, &dst, &icmp_buf[..icmp_len]);

        write_ipv6_header(
            out,
            icmp_len as u16,
            NEXT_HEADER_ICMPV6,
            hop_limit,
            traffic_class,
            flow_label,
            &src,
            &dst,
        );

        out[40..40 + icmp_len].copy_from_slice(&icmp_buf[..icmp_len]);
        out[42] = (cksum >> 8) as u8;
        out[43] = cksum as u8;

        Ok(total)
    }
}

// ============================================================================
// Default profiles list
// ============================================================================

/// Default packet profiles, ordered by matching priority.
///
/// OSCORE profiles should be inserted before CoAP profiles if supported.
pub const DEFAULT_PROFILES: &[&dyn PacketProfile] = &[
    &CoapUdpLinkLocalProfile,
    &CoapUdpGlobalProfile,
    &Icmpv6EchoProfile,
    &RplDioProfile,
    &RplDaoProfile,
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn coap_linklocal_matches() {
        let packet = hex("6000000000131140fe800000000000000000000000000001\
             fe80000000000000000000000000000216331633001328dd\
             40011234ff737461747573");
        let profile = CoapUdpLinkLocalProfile;
        assert!(profile.matches(&packet));
    }

    #[test]
    fn coap_linklocal_parse_build_round_trip() {
        let packet = hex("6000000000131140fe800000000000000000000000000001\
             fe80000000000000000000000000000216331633001328dd\
             40011234ff737461747573");
        let profile = CoapUdpLinkLocalProfile;

        let parsed = profile.parse(&packet).unwrap();
        assert_eq!(parsed.get("IPv6.version"), Some(6));
        assert_eq!(parsed.get("IPv6.hop_limit"), Some(64));
        assert_eq!(parsed.get("UDP.src_port"), Some(5683));
        assert_eq!(parsed.get("UDP.dst_port"), Some(5683));
        assert_eq!(parsed.get("CoAP.version"), Some(1));
        assert_eq!(parsed.get("CoAP.code"), Some(1)); // GET
        assert_eq!(parsed.get("CoAP.mid"), Some(0x1234));

        let mut out = [0u8; 256];
        let n = profile
            .build(parsed.as_slice(), parsed.tail, &mut out)
            .unwrap();
        assert_eq!(&out[..n], packet.as_slice());
    }

    #[test]
    fn coap_global_matches() {
        let packet = hex("600000000013114020010db8000000000000000000000001\
             20010db800000000000000000000000216331633001\
             3ca6c40011234ff737461747573");
        let profile = CoapUdpGlobalProfile;
        assert!(profile.matches(&packet));
        assert!(!CoapUdpLinkLocalProfile.matches(&packet));
    }

    #[test]
    fn icmpv6_echo_matches_and_parses() {
        let packet = hex("60000000000c3a40fe800000000000000000000000000001\
             fe8000000000000000000000000000028000f80eabcd0007\
             70696e67");
        let profile = Icmpv6EchoProfile;
        assert!(profile.matches(&packet));

        let parsed = profile.parse(&packet).unwrap();
        assert_eq!(parsed.get("ICMPv6.type"), Some(128)); // Echo Request
        assert_eq!(parsed.get("ICMPv6.identifier"), Some(0xabcd));
        assert_eq!(parsed.get("ICMPv6.sequence"), Some(7));
        assert_eq!(parsed.tail, b"ping");
    }

    #[test]
    fn rpl_dio_matches_and_parses() {
        let packet = hex("60000000001c3a40fe800000000000000000000000000001\
             fe8000000000000000000000000000029b01e01f00010100\
             88000000fe800000000000000000000000000001");
        let profile = RplDioProfile;
        assert!(profile.matches(&packet));

        let parsed = profile.parse(&packet).unwrap();
        assert_eq!(parsed.get("ICMPv6.type"), Some(155)); // RPL
        assert_eq!(parsed.get("ICMPv6.code"), Some(1)); // DIO
        assert_eq!(parsed.get("RPL.instance"), Some(0));
        assert_eq!(parsed.get("RPL.version"), Some(1));
    }

    #[test]
    fn rpl_dao_matches_and_parses() {
        let packet = hex("6000000000183a40fe800000000000000000000000000001\
             fe8000000000000000000000000000029b0268df00400005\
             fe800000000000000000000000000001");
        let profile = RplDaoProfile;
        assert!(profile.matches(&packet));

        let parsed = profile.parse(&packet).unwrap();
        assert_eq!(parsed.get("ICMPv6.type"), Some(155));
        assert_eq!(parsed.get("ICMPv6.code"), Some(2));
        assert_eq!(parsed.get("RPL.flags"), Some(0x40));
        assert_eq!(parsed.get("RPL.seq"), Some(5));
    }

    #[test]
    fn dao_without_d_flag_does_not_match() {
        let packet = hex("6000000000083a40fe800000000000000000000000000001\
             fe8000000000000000000000000000029b0200000005");
        let profile = RplDaoProfile;
        assert!(!profile.matches(&packet));
    }

    #[test]
    fn build_coap_oversized_tail_returns_error() {
        // Build a CoAP packet with a tail larger than COAP_MAX_TAIL (252 bytes)
        let oversized_tail = [0u8; 300];
        let fields: &[(FieldId, u128)] = &[
            ("IPv6.version", 6),
            ("IPv6.traffic_class", 0),
            ("IPv6.flow_label", 0),
            ("IPv6.hop_limit", 64),
            ("IPv6.src", 0xfe80_0000_0000_0000_0000_0000_0000_0001),
            ("IPv6.dst", 0xfe80_0000_0000_0000_0000_0000_0000_0002),
            ("UDP.src_port", 5683),
            ("UDP.dst_port", 5683),
            ("CoAP.version", 1),
            ("CoAP.type", 0),
            ("CoAP.tkl", 0),
            ("CoAP.code", 1),
            ("CoAP.mid", 0x1234),
        ];

        let mut out = [0u8; 512];
        let profile = CoapUdpLinkLocalProfile;
        let result = profile.build(fields, &oversized_tail, &mut out);

        assert!(result.is_err());
        if let Err(PacketError::BufferTooSmall { needed, available }) = result {
            assert_eq!(needed, COAP_FIXED_HEADER + 300);
            assert_eq!(available, COAP_BUF_SIZE);
        } else {
            panic!("expected BufferTooSmall error");
        }
    }
}
