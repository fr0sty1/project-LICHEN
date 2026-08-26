//! SCHC compress/decompress (RFC 8724) — rules 0-6 + uncompressed fallback.
//!
//! `compress(packet, out)` → residue bytes written into `out`.
//! `decompress(data, out)` → reconstructed IPv6 packet written into `out`.
//!
//! Bit order: MSB-first (network bit order). The residue is zero-padded to
//! a byte boundary. All computation is no_std.
//!
//! # Naming Convention
//!
//! This module uses `compress`/`decompress` rather than the `encode`/`decode`
//! or `from_bytes`/`write_to` verbs used elsewhere in the workspace. This
//! follows RFC 8724 terminology and reflects a semantic distinction: SCHC is
//! true compression — it elides header fields entirely when they can be
//! reconstructed from shared context, reducing a 40-byte IPv6 header to as
//! little as 1-2 bytes. By contrast, SLIP and message serialization are
//! *encodings* — bijective transformations with no information reduction.
//! The verb choice signals that SCHC requires matching rules on both ends.

use crate::context::RuleVersionFailureTracker;
use crate::rules::{versions_compatible, RULE_SET_VERSION};
use core::sync::atomic::{AtomicU32, Ordering};
use lichen_core::constants::{
    PORT_MQTT_SN, RULE_GLOBAL_COAP, RULE_GLOBAL_OSCORE, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP,
    RULE_LINK_LOCAL_OSCORE, RULE_MQTT_SN, RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED,
    SCHC_FRAG_MAX_PACKET_SIZE, SCHC_MAX_DECOMPRESSED,
};
use lichen_core::error::{BufferTooSmall, TooShort};
use lichen_core::ipv6::IPV6_HEADER_LEN;

/// IPv6 link-local prefix (fe80::/64) as a u128 with the prefix in the high 64 bits.
/// To reconstruct a full link-local address, OR this with a 64-bit Interface Identifier (IID).
/// See RFC 4291 Section 2.5.6: Link-Local addresses have the format fe80::<IID>/10.
const LINK_LOCAL_PREFIX: u128 = 0xFE80_0000_0000_0000_u128 << 64;

/// Stable authenticated-DIO rejection categories used by interop vectors and
/// operator diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DioAdmissionError {
    MissingRuleVersion,
    MalformedRuleVersionLength0,
    MalformedRuleVersionLength2,
    MalformedRuleVersion,
    DuplicateRuleVersion,
    DodagScopeMismatch,
    RoleScopeMismatch,
    SourceSignerMismatch,
    RootKeyDodagMismatch,
}

impl DioAdmissionError {
    pub const fn token(self) -> &'static str {
        match self {
            Self::MissingRuleVersion => "missing_rule_version",
            Self::MalformedRuleVersionLength0 => "malformed_rule_version_length_0",
            Self::MalformedRuleVersionLength2 => "malformed_rule_version_length_2",
            Self::MalformedRuleVersion => "malformed_rule_version",
            Self::DuplicateRuleVersion => "duplicate_rule_version",
            Self::DodagScopeMismatch => "dodag_scope_mismatch",
            Self::RoleScopeMismatch => "role_scope_mismatch",
            Self::SourceSignerMismatch => "source_signer_mismatch",
            Self::RootKeyDodagMismatch => "root_key_dodag_mismatch",
        }
    }
}

/// Error returned by compression/decompression.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchcError {
    /// No rule matched the packet headers.
    NoMatchingRule,
    /// The output buffer is too small.
    BufferTooSmall(BufferTooSmall),
    /// The rule ID in the compressed data is unknown.
    UnknownRuleId(u8),
    /// The compressed data is too short.
    TooShort(TooShort),
    /// The input packet is structurally invalid and must be dropped.
    InvalidPacket(&'static str),
    /// The compressed residue has a non-canonical representation.
    NonCanonicalResidue(&'static str),
    /// A new authenticated signer cannot be tracked without unsafe eviction.
    FailureTrackerFull,
    /// Authenticated peer capability is stale, foreign, or retired.
    InvalidPeerEvidence,
    /// A bounded no-std peer-evidence authority has no free entry.
    PeerAuthorityFull,
    /// Authenticated DIO failed one stable admission guard.
    DioAdmission(DioAdmissionError),
}

impl core::fmt::Display for SchcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMatchingRule => write!(f, "no matching rule"),
            Self::BufferTooSmall(e) => write!(f, "SCHC {}", e),
            Self::UnknownRuleId(id) => write!(f, "unknown rule ID: {}", id),
            Self::TooShort(e) => write!(f, "SCHC {}", e),
            Self::InvalidPacket(reason) => write!(f, "invalid packet: {}", reason),
            Self::NonCanonicalResidue(reason) => {
                write!(f, "non-canonical SCHC residue: {}", reason)
            }
            Self::FailureTrackerFull => write!(f, "SCHC failure tracker source capacity is full"),
            Self::InvalidPeerEvidence => write!(f, "stale or foreign authenticated peer evidence"),
            Self::PeerAuthorityFull => write!(f, "authenticated peer authority capacity is full"),
            Self::DioAdmission(error) => write!(f, "authenticated DIO rejected: {}", error.token()),
        }
    }
}

impl core::error::Error for SchcError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for SchcError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for SchcError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

// ─── bit-packing ─────────────────────────────────────────────────────────────

struct BitWriter<'a> {
    buf: &'a mut [u8],
    nbits: usize,
}

impl<'a> BitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        buf.fill(0);
        Self { buf, nbits: 0 }
    }

    /// Write the low `nbits` of `value`, MSB first.
    fn write(&mut self, value: u128, nbits: usize) -> Result<(), SchcError> {
        // Iterate from the most significant bit down to the least significant.
        // The reversed range (0..nbits).rev() processes bit positions MSB-first,
        // which is the correct network bit order per RFC 8724.
        for i in (0..nbits).rev() {
            let bit = ((value >> i) & 1) as u8;
            let byte_pos = self.nbits / 8;
            let bit_pos = 7 - (self.nbits % 8);
            if byte_pos >= self.buf.len() {
                return Err(BufferTooSmall::new(byte_pos + 1, self.buf.len()).into());
            }
            self.buf[byte_pos] |= bit << bit_pos;
            self.nbits += 1;
        }
        Ok(())
    }

    fn byte_len(&self) -> usize {
        self.nbits.div_ceil(8)
    }
}

struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read(&mut self, nbits: usize) -> Result<u128, SchcError> {
        if nbits > 128 {
            return Err(TooShort::new(17, 16).into());
        }
        let required_bits = self.pos + nbits;
        let available_bits = self.buf.len() * 8;
        if required_bits > available_bits {
            let required_bytes = required_bits.div_ceil(8);
            return Err(TooShort::new(required_bytes, self.buf.len()).into());
        }
        let mut value: u128 = 0;
        for _ in 0..nbits {
            let byte = self.buf[self.pos / 8];
            let bit = (byte >> (7 - (self.pos % 8))) & 1;
            value = (value << 1) | bit as u128;
            self.pos += 1;
        }
        Ok(value)
    }

    /// Byte offset at which the padded residue ends (i.e. where a tail starts).
    fn residue_byte_end(&self) -> usize {
        self.pos.div_ceil(8)
    }

    fn padding_is_zero(&self) -> bool {
        let used_in_last_byte = self.pos % 8;
        if used_in_last_byte == 0 {
            return true;
        }
        let padding_bits = 8 - used_in_last_byte;
        self.buf[self.pos / 8] & ((1u8 << padding_bits) - 1) == 0
    }
}

// ─── address helpers ─────────────────────────────────────────────────────────

#[cfg(test)]
fn is_link_local(addr: &[u8]) -> bool {
    addr.len() == 16 && addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
}

/// Rule-profile canonical link-local prefix: exactly fe80::/64, not fe80::/10.
fn is_link_local_64(addr: &[u8]) -> bool {
    addr.len() == 16 && addr[..8] == [0xFE, 0x80, 0, 0, 0, 0, 0, 0]
}

fn is_unspecified_address(address: &[u8]) -> bool {
    address.len() == 16 && address.iter().all(|&byte| byte == 0)
}

fn is_loopback_address(address: &[u8]) -> bool {
    address.len() == 16 && address[..15].iter().all(|&byte| byte == 0) && address[15] == 1
}

fn is_ipv4_mapped_address(address: &[u8]) -> bool {
    address.len() == 16
        && address[..10].iter().all(|&byte| byte == 0)
        && address[10..12] == [0xff, 0xff]
}

fn validate_address_policy(src: &[u8], dst: &[u8]) -> Result<(), SchcError> {
    if src.len() != 16
        || is_unspecified_address(src)
        || is_loopback_address(src)
        || src.first() == Some(&0xff)
        || is_ipv4_mapped_address(src)
    {
        return Err(SchcError::InvalidPacket("invalid IPv6 source address"));
    }
    if dst.len() != 16
        || is_unspecified_address(dst)
        || is_loopback_address(dst)
        || is_ipv4_mapped_address(dst)
    {
        return Err(SchcError::InvalidPacket("invalid IPv6 destination address"));
    }
    if dst.first() == Some(&0xff) && !(2..=14).contains(&(dst[1] & 0x0f)) {
        return Err(SchcError::InvalidPacket(
            "invalid IPv6 destination multicast scope",
        ));
    }
    Ok(())
}

/// Validate the complete IPv6 packet accepted by the LICHEN SCHC profile.
pub fn validate_full_ipv6(packet: &[u8]) -> Result<(), SchcError> {
    if packet.len() < 40 {
        return Err(SchcError::InvalidPacket("truncated IPv6 header"));
    }
    if packet[0] >> 4 != 6 {
        return Err(SchcError::InvalidPacket("IPv6 version is not 6"));
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if packet.len() != 40usize.saturating_add(payload_len) {
        return Err(SchcError::InvalidPacket("IPv6 payload length mismatch"));
    }
    let src = &packet[8..24];
    let dst = &packet[24..40];
    validate_address_policy(src, dst)?;

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let mut upper_layer_destination = dst;
    loop {
        match next_header {
            0 | 43 | 60 => {
                if offset.saturating_add(2) > packet.len() {
                    return Err(SchcError::InvalidPacket("truncated IPv6 extension header"));
                }
                let ext_len = (packet[offset + 1] as usize + 1).saturating_mul(8);
                let end = offset.saturating_add(ext_len);
                if end > packet.len() {
                    return Err(SchcError::InvalidPacket(
                        "IPv6 extension header exceeds packet",
                    ));
                }
                if next_header == 43 {
                    if ext_len < 24
                        || packet[offset + 2] != 3
                        || packet[offset + 4] != 0
                        || packet[offset + 5] != 0
                    {
                        return Err(SchcError::InvalidPacket(
                            "unsupported RPL source-routing header",
                        ));
                    }
                    let address_count = (ext_len - 8) / 16;
                    let segments_left = usize::from(packet[offset + 3]);
                    if segments_left > address_count {
                        return Err(SchcError::InvalidPacket(
                            "invalid RPL source-routing segments-left",
                        ));
                    }
                    if segments_left != 0 {
                        upper_layer_destination = &packet[end - 16..end];
                    }
                }
                next_header = packet[offset];
                offset = end;
            }
            44 => {
                return Err(SchcError::InvalidPacket(
                    "IPv6 Fragment header is unsupported",
                ))
            }
            _ => break,
        }
    }

    if next_header == 17 {
        let udp = &packet[offset..];
        if udp.len() < 8 {
            return Err(SchcError::InvalidPacket("truncated IPv6/UDP datagram"));
        }
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if udp_len < 8 || udp_len != udp.len() {
            return Err(SchcError::InvalidPacket("UDP length mismatch"));
        }
        let checksum = u16::from_be_bytes([udp[6], udp[7]]);
        if checksum == 0 {
            return Err(SchcError::InvalidPacket("IPv6 UDP checksum is zero"));
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        if checksum != udp_checksum(src, upper_layer_destination, src_port, dst_port, &udp[8..])? {
            return Err(SchcError::InvalidPacket("IPv6 UDP checksum is invalid"));
        }
    }
    Ok(())
}

/// Check if CoAP payload contains OSCORE option (option number 9).
/// CoAP options are encoded as delta+length nibbles after the 4-byte header + token.
fn has_oscore_option(coap: &[u8]) -> bool {
    if coap.len() < 4 {
        return false;
    }
    let tkl = (coap[0] & 0x0F) as usize;
    let mut pos = 4 + tkl;
    let mut opt_num: u16 = 0;

    while pos < coap.len() {
        let b = coap[pos];
        if b == 0xFF {
            break; // payload marker
        }
        let delta_nibble = (b >> 4) & 0x0F;
        let len_nibble = b & 0x0F;
        pos += 1;

        let delta = match delta_nibble {
            0..=12 => delta_nibble as u16,
            13 => {
                if pos >= coap.len() {
                    return false;
                }
                let ext = coap[pos] as u16;
                pos += 1;
                ext + 13
            }
            14 => {
                if pos + 1 >= coap.len() {
                    return false;
                }
                let ext = u16::from_be_bytes([coap[pos], coap[pos + 1]]);
                pos += 2;
                ext.saturating_add(269)
            }
            _ => return false, // 15 is reserved
        };

        let len = match len_nibble {
            0..=12 => len_nibble as usize,
            13 => {
                if pos >= coap.len() {
                    return false;
                }
                let ext = coap[pos] as usize;
                pos += 1;
                ext + 13
            }
            14 => {
                if pos + 1 >= coap.len() {
                    return false;
                }
                let ext = u16::from_be_bytes([coap[pos], coap[pos + 1]]) as usize;
                pos += 2;
                ext + 269
            }
            _ => return false,
        };

        opt_num = opt_num.saturating_add(delta);
        if opt_num == 9 {
            return true; // OSCORE option found
        }
        if opt_num > 9 {
            return false; // past option 9, won't find it
        }
        pos += len;
    }
    false
}

// ─── checksum helpers (no_std) ───────────────────────────────────────────────

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

fn pseudo_sum(src: &[u8], dst: &[u8], next_header: u8, length: u16) -> u32 {
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

fn ones_complement_sum(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    let c = !(s as u16);
    if c == 0 {
        0xFFFF
    } else {
        c
    }
}

fn udp_checksum(
    src: &[u8],
    dst: &[u8],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<u16, SchcError> {
    let total_len = 8usize.saturating_add(payload.len());
    if total_len > u16::MAX as usize {
        return Err(BufferTooSmall::new(total_len, u16::MAX as usize).into());
    }
    let udp_len = total_len as u16;
    let mut sum = pseudo_sum(src, dst, 17, udp_len);
    sum = oc_add(sum, src_port as u32);
    sum = oc_add(sum, dst_port as u32);
    sum = oc_add(sum, udp_len as u32);
    sum = oc_add(sum, checksum_bytes(payload));
    Ok(ones_complement_sum(sum))
}

fn icmpv6_checksum(src: &[u8], dst: &[u8], icmpv6_payload: &[u8]) -> u16 {
    let length = icmpv6_payload.len() as u16;
    let mut sum = pseudo_sum(src, dst, 58, length);
    sum = oc_add(sum, checksum_bytes(icmpv6_payload));
    ones_complement_sum(sum)
}

/// Verify ICMPv6 checksum by computing the one's complement sum over the full
/// ICMPv6 data (including the existing checksum field). Returns true if valid.
fn icmpv6_checksum_valid(src: &[u8], dst: &[u8], icmpv6: &[u8]) -> bool {
    if icmpv6.len() < 4 {
        return false;
    }
    let length = icmpv6.len() as u16;
    let mut sum = pseudo_sum(src, dst, 58, length);
    sum = oc_add(sum, checksum_bytes(icmpv6));
    // Fold to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // If checksum is valid, the folded sum should be 0xFFFF
    sum as u16 == 0xFFFF
}

/// Write a 40-byte IPv6 header into `out`.
///
/// This helper extracts the common IPv6 header construction pattern used by
/// all decompress functions. The header layout is:
/// - `[0..4]`: Version (6), Traffic Class (0), Flow Label (0)
/// - `[4..6]`: Payload Length (bytes following the 40-byte header)
/// - `[6]`: Next Header (17=UDP, 58=ICMPv6)
/// - `[7]`: Hop Limit
/// - `[8..24]`: Source Address (16 bytes)
/// - `[24..40]`: Destination Address (16 bytes)
#[inline]
fn write_ipv6_header(
    out: &mut [u8],
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: &[u8; 16],
    dst: &[u8; 16],
) {
    out[0] = 0x60; // Version 6
    out[1] = 0; // Traffic Class (low 4 bits) + Flow Label (high 4 bits)
    out[2] = 0; // Flow Label (middle 8 bits)
    out[3] = 0; // Flow Label (low 8 bits)
    out[4] = (payload_len >> 8) as u8;
    out[5] = payload_len as u8;
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(src);
    out[24..40].copy_from_slice(dst);
}

// ─── per-rule compress ────────────────────────────────────────────────────────
//
// IPv6 header layout (40 bytes):
//   [0..4]   - Version/TC/Flow Label
//   [4..6]   - Payload Length
//   [6]      - Next Header (17=UDP, 58=ICMPv6)
//   [7]      - Hop Limit
//   [8..24]  - Source Address (16 bytes)
//   [24..40] - Destination Address (16 bytes)
//
// ICMPv6 header (4 bytes, at offset 40):
//   [40]     - Type (128=Echo Request, 129=Echo Reply, 155=RPL)
//   [41]     - Code (1=DIO, 2=DAO for RPL)
//   [42..44] - Checksum
//
// RPL body starts at offset 44 (after IPv6 + ICMPv6 header).

fn ensure_ipv6(packet: &[u8]) -> Result<(), SchcError> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Err(SchcError::NoMatchingRule);
    }
    Ok(())
}

/// Rules 0/5 (link-local) and 1/6 (global): IPv6 + UDP + CoAP/OSCORE.
/// Link-local uses exact fe80::/64; global uses canonical Yggdrasil 0200::/8.
fn compress_coap(packet: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    if packet.len() < 40 + 8 + 4 {
        return Err(SchcError::NoMatchingRule);
    }
    if packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields (see layout comment above)
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    // UDP header starts immediately after IPv6
    let udp = &packet[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let coap = &udp[8..];
    let coap_type = (coap[0] >> 4) & 0x3;
    let coap_tkl = coap[0] & 0x0F;
    if coap[0] >> 6 != 1 || coap_tkl > 8 || 4usize.saturating_add(coap_tkl as usize) > coap.len() {
        return Err(SchcError::NoMatchingRule);
    }
    let coap_code = coap[1];
    let coap_mid = u16::from_be_bytes([coap[2], coap[3]]);
    let tail = &coap[4..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = rule_id;

    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;

    // Address compression is rule-specific:
    // - Rules 0/5 (link-local): require both fe80::/64, send 64-bit IID
    // - Rules 1/6 (Yggdrasil): require both 0200::/8, send 120 bits
    let both_link_local = is_link_local_64(src) && is_link_local_64(dst);
    let both_yggdrasil = src[0] == 0x02 && dst[0] == 0x02;

    match rule_id {
        RULE_LINK_LOCAL_COAP | RULE_LINK_LOCAL_OSCORE => {
            if !both_link_local {
                return Err(SchcError::NoMatchingRule);
            }
            let src_iid = u64::from_be_bytes(src[8..16].try_into().expect("IID is 8 bytes"));
            let dst_iid = u64::from_be_bytes(dst[8..16].try_into().expect("IID is 8 bytes"));
            w.write(src_iid as u128, 64)?;
            w.write(dst_iid as u128, 64)?;
        }
        RULE_GLOBAL_COAP | RULE_GLOBAL_OSCORE => {
            if !both_yggdrasil {
                return Err(SchcError::NoMatchingRule);
            }
            // Yggdrasil: MSB-match 8 bits (0x02), send low 120 bits
            let src_int = u128::from_be_bytes(src.try_into().expect("IPv6 addr is 16 bytes"));
            let dst_int = u128::from_be_bytes(dst.try_into().expect("IPv6 addr is 16 bytes"));
            w.write(src_int & ((1u128 << 120) - 1), 120)?;
            w.write(dst_int & ((1u128 << 120) - 1), 120)?;
        }
        _ => return Err(SchcError::NoMatchingRule),
    }

    // UDP ports use LSB compression: MSB-match 12 bits against CoAP default 5683,
    // send only the low 4 bits.
    const COAP_PORT: u16 = 5683;
    const PORT_LSB_BITS: usize = 4;
    let src_msb = src_port >> PORT_LSB_BITS;
    let dst_msb = dst_port >> PORT_LSB_BITS;
    let expected_msb = COAP_PORT >> PORT_LSB_BITS;
    if src_msb != expected_msb || dst_msb != expected_msb {
        return Err(SchcError::NoMatchingRule);
    }
    w.write((src_port & 0xF) as u128, PORT_LSB_BITS)?;
    w.write((dst_port & 0xF) as u128, PORT_LSB_BITS)?;
    w.write(coap_type as u128, 2)?;
    w.write(coap_tkl as u128, 4)?;
    w.write(coap_code as u128, 8)?;
    w.write(coap_mid as u128, 16)?;

    let residue_len = w.byte_len();
    let tail_start = 1 + residue_len;
    let needed = tail_start + tail.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 2: link-local IPv6 + ICMPv6 Echo.
fn compress_icmpv6_echo(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    // 40 (IPv6) + 8 (ICMPv6 Echo: type + code + checksum + id + seq)
    if packet.len() < 40 + 8 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields (see layout comment above)
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    // ICMPv6 header starts at offset 40
    let icmp = &packet[40..];
    let icmp_type = icmp[0];
    let icmp_id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let icmp_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let tail = &icmp[8..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_ICMPV6_ECHO;
    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    let src_iid = u64::from_be_bytes(src[8..16].try_into().expect("IID is 8 bytes"));
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().expect("IID is 8 bytes"));
    w.write(src_iid as u128, 64)?;
    w.write(dst_iid as u128, 64)?;
    w.write(icmp_type as u128, 8)?;
    w.write(icmp_id as u128, 16)?;
    w.write(icmp_seq as u128, 16)?;

    let residue_len = w.byte_len();
    let tail_start = 1 + residue_len;
    let needed = tail_start + tail.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 3: link-local IPv6 + ICMPv6 RPL DIO.
fn compress_rpl_dio(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    // 40 (IPv6) + 4 (ICMPv6 header) + 24 (DIO base: instance + version + rank + G/MOP/Prf + DTSN + flags + reserved + DODAGID)
    if packet.len() < 40 + 4 + 24 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields (see layout comment above)
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    // RPL body starts at offset 44: skip 40-byte IPv6 + 4-byte ICMPv6 header (type/code/checksum)
    let rpl = &packet[44..];
    let instance = rpl[0];
    let version = rpl[1];
    let rank = u16::from_be_bytes([rpl[2], rpl[3]]);
    let gmop = rpl[4];
    let dtsn = rpl[5];
    // flags (rpl[6]) and reserved (rpl[7]) are NOT_SENT (both expected to be 0)
    if rpl[6] != 0 || rpl[7] != 0 {
        return Err(SchcError::NoMatchingRule);
    }
    let dodagid = u128::from_be_bytes(rpl[8..24].try_into().expect("DODAGID is 16 bytes"));
    let tail = &rpl[24..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_RPL_DIO;
    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    let src_iid = u64::from_be_bytes(src[8..16].try_into().expect("IID is 8 bytes"));
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().expect("IID is 8 bytes"));
    w.write(src_iid as u128, 64)?;
    w.write(dst_iid as u128, 64)?;
    w.write(instance as u128, 8)?;
    w.write(version as u128, 8)?;
    w.write(rank as u128, 16)?;
    w.write(gmop as u128, 8)?;
    w.write(dtsn as u128, 8)?;
    w.write(dodagid, 128)?;

    let residue_len = w.byte_len();
    let tail_start = 1 + residue_len;
    let needed = tail_start + tail.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 4: link-local IPv6 + ICMPv6 RPL DAO with DODAGID.
fn compress_rpl_dao(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    // 40 (IPv6) + 4 (ICMPv6 header) + 20 (DAO base with D=1: instance + K/D/flags + reserved + seq + DODAGID)
    if packet.len() < 40 + 4 + 20 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields (see layout comment above)
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    // RPL body starts at offset 44: skip 40-byte IPv6 + 4-byte ICMPv6 header (type/code/checksum)
    let rpl = &packet[44..];
    let instance = rpl[0];
    let kd_flags = rpl[1];
    // reserved (rpl[2]) is NOT_SENT
    if kd_flags & 0x40 == 0 || rpl[2] != 0 {
        return Err(SchcError::NoMatchingRule);
    }
    let seq = rpl[3];
    let dodagid = u128::from_be_bytes(rpl[4..20].try_into().expect("DODAGID is 16 bytes"));
    let tail = &rpl[20..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_RPL_DAO;
    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    let src_iid = u64::from_be_bytes(src[8..16].try_into().expect("IID is 8 bytes"));
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().expect("IID is 8 bytes"));
    w.write(src_iid as u128, 64)?;
    w.write(dst_iid as u128, 64)?;
    w.write(instance as u128, 8)?;
    w.write(kd_flags as u128, 8)?;
    w.write(seq as u128, 8)?;
    w.write(dodagid, 128)?;

    let residue_len = w.byte_len();
    let tail_start = 1 + residue_len;
    let needed = tail_start + tail.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 7: IPv6 + UDP with port 10883 (MQTT-SN).
///
/// Matches when either source or destination port is 10883. IPv6 addresses
/// are compressed the same as Rule 0/1 (link-local IID only vs full global).
/// The port that is NOT 10883 is sent as 16-bit residue; port 10883 is NOT_SENT.
fn compress_mqtt_sn(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    // 40 (IPv6) + 8 (UDP header) minimum
    if packet.len() < 40 + 8 {
        return Err(SchcError::InvalidPacket("truncated IPv6/UDP datagram"));
    }
    if packet[6] != 17 {
        return Err(SchcError::InvalidPacket("Rule 7 requires UDP next header"));
    }
    let available_udp_len = packet.len() - 40;
    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if ipv6_payload_len != available_udp_len {
        return Err(SchcError::InvalidPacket("IPv6 payload length mismatch"));
    }
    // IPv6 header fields
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    validate_address_policy(src, dst)?;
    // UDP header starts immediately after IPv6
    let udp = &packet[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len != available_udp_len {
        return Err(SchcError::InvalidPacket("UDP length mismatch"));
    }

    // Must match port 10883 on at least one side
    if src_port != PORT_MQTT_SN && dst_port != PORT_MQTT_SN {
        return Err(SchcError::NoMatchingRule);
    }

    let wire_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if wire_checksum == 0 {
        return Err(SchcError::InvalidPacket("IPv6 UDP checksum is zero"));
    }
    let expected_checksum = udp_checksum(src, dst, src_port, dst_port, &udp[8..])?;
    if wire_checksum != expected_checksum {
        return Err(SchcError::InvalidPacket("IPv6 UDP checksum is invalid"));
    }
    if packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
        return Err(SchcError::NoMatchingRule);
    }

    // Determine which port is the "other" port (the one that's not 10883)
    let other_port = if src_port == PORT_MQTT_SN {
        dst_port
    } else {
        src_port
    };
    // Direction bit: 0 = src is 10883, 1 = dst is 10883
    let direction = if src_port == PORT_MQTT_SN { 0u8 } else { 1u8 };

    let tail = &udp[8..]; // MQTT-SN payload after UDP header

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_MQTT_SN;

    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;

    // Address compression: same logic as CoAP rules
    if is_link_local_64(src) && is_link_local_64(dst) {
        let src_iid = u64::from_be_bytes(src[8..16].try_into().expect("IID is 8 bytes"));
        let dst_iid = u64::from_be_bytes(dst[8..16].try_into().expect("IID is 8 bytes"));
        w.write(0, 1)?; // Address mode: 0 = link-local
        w.write(src_iid as u128, 64)?;
        w.write(dst_iid as u128, 64)?;
    } else {
        let src_int = u128::from_be_bytes(src.try_into().expect("IPv6 addr is 16 bytes"));
        let dst_int = u128::from_be_bytes(dst.try_into().expect("IPv6 addr is 16 bytes"));
        w.write(1, 1)?; // Address mode: 1 = full
        w.write(src_int, 128)?;
        w.write(dst_int, 128)?;
    }

    // Direction bit and other port
    w.write(direction as u128, 1)?;
    w.write(other_port as u128, 16)?;

    let residue_len = w.byte_len();
    let tail_start = 1 + residue_len;
    let needed = tail_start + tail.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

// ─── per-rule decompress ──────────────────────────────────────────────────────

fn decompress_coap(data: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;

    // Yggdrasil prefix (0200::/8) as a 128-bit value with only top 8 bits set
    const YGGDRASIL_PREFIX: u128 = 0x02_u128 << 120;

    let (src_int, dst_int) = match rule_id {
        RULE_LINK_LOCAL_COAP | RULE_LINK_LOCAL_OSCORE => {
            // Link-local: fe80::/64 prefix + 64-bit IID
            let src_iid = r.read(64)?;
            let dst_iid = r.read(64)?;
            (LINK_LOCAL_PREFIX | src_iid, LINK_LOCAL_PREFIX | dst_iid)
        }
        RULE_GLOBAL_COAP | RULE_GLOBAL_OSCORE => {
            // Yggdrasil (0200::/8): read 120 bits, add 0x02 prefix
            let src_lsb = r.read(120)?;
            let dst_lsb = r.read(120)?;
            (YGGDRASIL_PREFIX | src_lsb, YGGDRASIL_PREFIX | dst_lsb)
        }
        _ => (r.read(128)?, r.read(128)?),
    };

    // UDP ports use LSB compression: read 4 bits and add CoAP default port MSB
    const COAP_PORT_MSB: u16 = 5683 & 0xFFF0; // High 12 bits of 5683
    let src_port = COAP_PORT_MSB | (r.read(4)? as u16);
    let dst_port = COAP_PORT_MSB | (r.read(4)? as u16);
    let coap_type = r.read(2)? as u8;
    let coap_tkl = r.read(4)? as u8;
    let coap_code = r.read(8)? as u8;
    let coap_mid = r.read(16)? as u16;

    if !r.padding_is_zero() {
        return Err(SchcError::NonCanonicalResidue(
            "nonzero generic rule residue padding",
        ));
    }

    let tail = &data[1 + r.residue_byte_end()..];

    let src = src_int.to_be_bytes();
    let dst = dst_int.to_be_bytes();
    let coap_b0 = (1u8 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F);
    let coap_len = 4 + tail.len();
    let total_udp = 8usize.saturating_add(coap_len);
    if total_udp > u16::MAX as usize {
        return Err(BufferTooSmall::new(total_udp, u16::MAX as usize).into());
    }
    let udp_len = total_udp as u16;

    if coap_len > SCHC_MAX_DECOMPRESSED {
        return Err(BufferTooSmall::new(coap_len, SCHC_MAX_DECOMPRESSED).into());
    }
    let mut coap_buf = [0u8; SCHC_MAX_DECOMPRESSED];
    coap_buf[0] = coap_b0;
    coap_buf[1] = coap_code;
    coap_buf[2] = (coap_mid >> 8) as u8;
    coap_buf[3] = coap_mid as u8;
    coap_buf[4..4 + tail.len()].copy_from_slice(tail);
    let coap_slice = &coap_buf[..coap_len];

    let udp_cksum = udp_checksum(&src, &dst, src_port, dst_port, coap_slice)?;
    let total = 40 + 8 + coap_len;
    if total > out.len() {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }

    write_ipv6_header(out, udp_len, 17, hop_limit, &src, &dst);

    // UDP header
    out[40..42].copy_from_slice(&src_port.to_be_bytes());
    out[42..44].copy_from_slice(&dst_port.to_be_bytes());
    out[44..46].copy_from_slice(&udp_len.to_be_bytes());
    out[46..48].copy_from_slice(&udp_cksum.to_be_bytes());

    // CoAP
    out[48..48 + coap_len].copy_from_slice(coap_slice);
    Ok(total)
}

fn decompress_icmpv6_echo(data: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;
    let src_iid = r.read(64)?;
    let dst_iid = r.read(64)?;
    let icmp_type = r.read(8)? as u8;
    let icmp_id = r.read(16)? as u16;
    let icmp_seq = r.read(16)? as u16;

    // SECURITY: Revalidate that the decompressed type matches the Rule 2 profile.
    // Rule 2 compresses only ICMPv6 Echo Request (128) or Echo Reply (129).
    // A crafted residue with a different type would produce a packet whose
    // inner protocol contradicts the SCHC rule ID.
    if icmp_type != 128 && icmp_type != 129 {
        return Err(SchcError::NonCanonicalResidue(
            "rule 2 residue contains non-Echo ICMPv6 type",
        ));
    }

    if !r.padding_is_zero() {
        return Err(SchcError::NonCanonicalResidue(
            "nonzero generic rule residue padding",
        ));
    }

    let tail = &data[1 + r.residue_byte_end()..];

    let src = (LINK_LOCAL_PREFIX | src_iid).to_be_bytes();
    let dst = (LINK_LOCAL_PREFIX | dst_iid).to_be_bytes();

    // ICMPv6 payload: type(1) code(1) cksum(2) id(2) seq(2) + tail
    let icmp_len = 8 + tail.len();
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }

    // Build ICMPv6 with zero checksum for computation.
    if icmp_len > SCHC_MAX_DECOMPRESSED {
        return Err(BufferTooSmall::new(icmp_len, SCHC_MAX_DECOMPRESSED).into());
    }
    let mut icmp_buf = [0u8; SCHC_MAX_DECOMPRESSED];
    icmp_buf[0] = icmp_type;
    icmp_buf[1] = 0; // code NOT_SENT = 0
    icmp_buf[2] = 0; // checksum placeholder hi
    icmp_buf[3] = 0; // checksum placeholder lo
    icmp_buf[4] = (icmp_id >> 8) as u8;
    icmp_buf[5] = icmp_id as u8;
    icmp_buf[6] = (icmp_seq >> 8) as u8;
    icmp_buf[7] = icmp_seq as u8;
    icmp_buf[8..8 + tail.len()].copy_from_slice(tail);
    let icmp_slice = &icmp_buf[..icmp_len];

    let cksum = icmpv6_checksum(&src, &dst, icmp_slice);

    write_ipv6_header(out, icmp_len as u16, 58, hop_limit, &src, &dst);

    // ICMPv6
    out[40] = icmp_type;
    out[41] = 0;
    out[42] = (cksum >> 8) as u8;
    out[43] = cksum as u8;
    out[44] = (icmp_id >> 8) as u8;
    out[45] = icmp_id as u8;
    out[46] = (icmp_seq >> 8) as u8;
    out[47] = icmp_seq as u8;
    out[48..48 + tail.len()].copy_from_slice(tail);

    Ok(total)
}

fn decompress_rpl_dio(data: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;
    let src_iid = r.read(64)?;
    let dst_iid = r.read(64)?;
    let instance = r.read(8)? as u8;
    let version = r.read(8)? as u8;
    let rank = r.read(16)? as u16;
    let gmop = r.read(8)? as u8;
    let dtsn = r.read(8)? as u8;
    let dodagid = r.read(128)?;

    if !r.padding_is_zero() {
        return Err(SchcError::NonCanonicalResidue(
            "nonzero generic rule residue padding",
        ));
    }

    let tail = &data[1 + r.residue_byte_end()..];

    let src = (LINK_LOCAL_PREFIX | src_iid).to_be_bytes();
    let dst = (LINK_LOCAL_PREFIX | dst_iid).to_be_bytes();

    // RPL DIO base (24 bytes) + tail
    let rpl_body_len = 24 + tail.len();
    let icmp_len = 4 + rpl_body_len; // type+code+cksum + body
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }
    if icmp_len > SCHC_MAX_DECOMPRESSED {
        return Err(BufferTooSmall::new(icmp_len, SCHC_MAX_DECOMPRESSED).into());
    }

    let mut icmp_buf = [0u8; SCHC_MAX_DECOMPRESSED];
    icmp_buf[0] = 155; // RPL
    icmp_buf[1] = 1; // DIO code
    icmp_buf[2] = 0; // checksum placeholder
    icmp_buf[3] = 0;
    icmp_buf[4] = instance;
    icmp_buf[5] = version;
    icmp_buf[6] = (rank >> 8) as u8;
    icmp_buf[7] = rank as u8;
    icmp_buf[8] = gmop;
    icmp_buf[9] = dtsn;
    icmp_buf[10] = 0; // flags (NOT_SENT = 0)
    icmp_buf[11] = 0; // reserved (NOT_SENT = 0)
    let dodagid_bytes = dodagid.to_be_bytes();
    icmp_buf[12..28].copy_from_slice(&dodagid_bytes);
    icmp_buf[28..28 + tail.len()].copy_from_slice(tail);
    let icmp_slice = &icmp_buf[..icmp_len];

    let cksum = icmpv6_checksum(&src, &dst, icmp_slice);

    write_ipv6_header(out, icmp_len as u16, 58, hop_limit, &src, &dst);
    out[40..40 + icmp_len].copy_from_slice(icmp_slice);
    out[42] = (cksum >> 8) as u8;
    out[43] = cksum as u8;

    Ok(total)
}

fn decompress_rpl_dao(data: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;
    let src_iid = r.read(64)?;
    let dst_iid = r.read(64)?;
    let instance = r.read(8)? as u8;
    let kd_flags = r.read(8)? as u8;
    let seq = r.read(8)? as u8;
    let dodagid = r.read(128)?;

    // SECURITY: Revalidate that the decompressed kd_flags matches the Rule 4 profile.
    // Rule 4 compresses only DAO messages with the D flag set (DODAGID present).
    // A crafted residue without the D flag would produce a no-DODAGID DAO under
    // the with-DODAGID rule.
    if kd_flags & 0x40 == 0 {
        return Err(SchcError::NonCanonicalResidue(
            "rule 4 residue lacks required D flag in kd_flags",
        ));
    }

    if !r.padding_is_zero() {
        return Err(SchcError::NonCanonicalResidue(
            "nonzero generic rule residue padding",
        ));
    }

    let tail = &data[1 + r.residue_byte_end()..];

    let src = (LINK_LOCAL_PREFIX | src_iid).to_be_bytes();
    let dst = (LINK_LOCAL_PREFIX | dst_iid).to_be_bytes();

    let rpl_body_len = 20 + tail.len();
    let icmp_len = 4 + rpl_body_len;
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }
    if icmp_len > SCHC_MAX_DECOMPRESSED {
        return Err(BufferTooSmall::new(icmp_len, SCHC_MAX_DECOMPRESSED).into());
    }

    let mut icmp_buf = [0u8; SCHC_MAX_DECOMPRESSED];
    icmp_buf[0] = 155; // RPL
    icmp_buf[1] = 2; // DAO code
    icmp_buf[2] = 0; // checksum placeholder
    icmp_buf[3] = 0;
    icmp_buf[4] = instance;
    icmp_buf[5] = kd_flags;
    icmp_buf[6] = 0; // reserved (NOT_SENT = 0)
    icmp_buf[7] = seq;
    let dodagid_bytes = dodagid.to_be_bytes();
    icmp_buf[8..24].copy_from_slice(&dodagid_bytes);
    icmp_buf[24..24 + tail.len()].copy_from_slice(tail);
    let icmp_slice = &icmp_buf[..icmp_len];

    let cksum = icmpv6_checksum(&src, &dst, icmp_slice);

    write_ipv6_header(out, icmp_len as u16, 58, hop_limit, &src, &dst);
    out[40..40 + icmp_len].copy_from_slice(icmp_slice);
    out[42] = (cksum >> 8) as u8;
    out[43] = cksum as u8;

    Ok(total)
}

fn decompress_mqtt_sn(data: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    if data.is_empty() || data[0] != rule_id {
        return Err(SchcError::NoMatchingRule);
    }
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;
    let addr_mode = r.read(1)? as u8;

    let (src, dst) = if addr_mode == 0 {
        let src_iid = r.read(64)?;
        let dst_iid = r.read(64)?;
        (
            (LINK_LOCAL_PREFIX | src_iid).to_be_bytes(),
            (LINK_LOCAL_PREFIX | dst_iid).to_be_bytes(),
        )
    } else {
        let src_int = r.read(128)?;
        let dst_int = r.read(128)?;
        (src_int.to_be_bytes(), dst_int.to_be_bytes())
    };

    validate_address_policy(&src, &dst)?;

    if addr_mode == 1 && is_link_local_64(&src) && is_link_local_64(&dst) {
        return Err(SchcError::NonCanonicalResidue(
            "full-address mode used for two fe80::/64 addresses",
        ));
    }

    let direction = r.read(1)? as u8;
    let other_port = r.read(16)? as u16;
    if direction == 1 && other_port == PORT_MQTT_SN {
        return Err(SchcError::NonCanonicalResidue(
            "both MQTT-SN ports require direction zero",
        ));
    }
    if !r.padding_is_zero() {
        return Err(SchcError::NonCanonicalResidue(
            "nonzero Rule 7 residue padding",
        ));
    }

    let (src_port, dst_port) = if direction == 0 {
        (PORT_MQTT_SN, other_port)
    } else {
        (other_port, PORT_MQTT_SN)
    };

    let tail = &data[1 + r.residue_byte_end()..];

    let total_len = 8usize.saturating_add(tail.len());
    if total_len > u16::MAX as usize {
        return Err(BufferTooSmall::new(total_len, u16::MAX as usize).into());
    }
    let udp_len = total_len as u16;
    let udp_cksum = udp_checksum(&src, &dst, src_port, dst_port, tail)?;
    let total = 40 + 8 + tail.len();
    if total > out.len() {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }

    write_ipv6_header(out, udp_len, 17, hop_limit, &src, &dst);

    // UDP header
    out[40..42].copy_from_slice(&src_port.to_be_bytes());
    out[42..44].copy_from_slice(&dst_port.to_be_bytes());
    out[44..46].copy_from_slice(&udp_len.to_be_bytes());
    out[46..48].copy_from_slice(&udp_cksum.to_be_bytes());

    // MQTT-SN payload
    out[48..48 + tail.len()].copy_from_slice(tail);

    Ok(total)
}

// ─── public API ──────────────────────────────────────────────────────────────

/// Encode sender-selected Rule 255 after validating the complete IPv6 packet.
pub fn encode_rule255(
    packet: &[u8],
    out: &mut [u8],
    single_frame_limit: usize,
) -> Result<usize, SchcError> {
    validate_full_ipv6(packet)?;
    let needed = packet.len().saturating_add(1);
    let profile_limit = single_frame_limit.min(SCHC_FRAG_MAX_PACKET_SIZE);
    if needed > profile_limit {
        return Err(BufferTooSmall::new(needed, profile_limit).into());
    }
    if out.len() < needed {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[0] = RULE_UNCOMPRESSED;
    out[1..needed].copy_from_slice(packet);
    Ok(needed)
}

/// Decode Rule 255 without accepting arbitrary or fragmented IPv6 bytes.
pub fn decode_rule255(
    data: &[u8],
    out: &mut [u8],
    single_frame_limit: usize,
) -> Result<usize, SchcError> {
    if data.first() != Some(&RULE_UNCOMPRESSED) {
        return Err(SchcError::InvalidPacket(
            "version mismatch accepts Rule 255 only",
        ));
    }
    let profile_limit = single_frame_limit.min(SCHC_FRAG_MAX_PACKET_SIZE);
    if data.len() > profile_limit {
        return Err(BufferTooSmall::new(data.len(), profile_limit).into());
    }
    let packet = &data[1..];
    validate_full_ipv6(packet)?;
    if out.len() < packet.len() {
        return Err(BufferTooSmall::new(packet.len(), out.len()).into());
    }
    out[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}

/// Decompress one live authenticated link frame with bounded signer tracking.
#[cfg(feature = "std")]
pub fn decompress_authenticated_frame_tracked<const MAX_SOURCES: usize>(
    link: &lichen_link::link_layer::LinkLayer,
    frame: &lichen_link::link_layer::AuthenticatedFrame,
    out: &mut [u8],
    tracker: &mut RuleVersionFailureTracker<MAX_SOURCES>,
    mut notify_operator: impl FnMut(&[u8; 32]),
) -> Result<usize, SchcError> {
    if !link.accepts_authenticated_frame(frame) {
        return Err(SchcError::InvalidPacket(
            "stale or foreign authenticated link evidence",
        ));
    }
    if frame.payload().first().copied() != Some(lichen_core::constants::L2_DISPATCH_SCHC) {
        return Err(SchcError::InvalidPacket("missing SCHC L2 dispatch"));
    }
    let source = *frame.sender().pubkey.as_bytes();
    match decompress(&frame.payload()[1..], out) {
        Ok(length) => {
            tracker.record_success(&source);
            Ok(length)
        }
        Err(error @ SchcError::BufferTooSmall(_)) => Err(error),
        Err(error) => {
            let notify = tracker.record_failure(source).unwrap_or(false);
            if notify {
                notify_operator(&source);
            }
            Err(error)
        }
    }
}

/// Immutable peer policy issued after an authenticated DIO is parsed.
#[derive(Debug)]
pub struct AuthenticatedPeerSchcContext {
    remote_version: u8,
    signer_identity: [u8; 32],
    authenticated_counter: u32,
    key_generation: lichen_link::PeerKeyGeneration,
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    authority_owner: u32,
    authority_slot: u16,
    authority_generation: u32,
    receipt_clock_domain: u64,
    receipt_ticks: u64,
    #[cfg(feature = "std")]
    evidence: Option<lichen_link::link_layer::AuthenticatedFrame>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerAuthorityEntry {
    signer: [u8; 32],
    counter: u32,
    key_generation: lichen_link::PeerKeyGeneration,
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    generation: u32,
    receipt_clock_domain: u64,
    receipt_ticks: u64,
}

static NEXT_PEER_AUTHORITY_OWNER: AtomicU32 = AtomicU32::new(1);

/// Bounded no-std owner of link-verified peer capabilities.
///
/// The link integration owns this object and calls
/// [`Self::issue_from_authenticated_dio`]
/// only after signature, replay, DIO-structure, and local-role validation.
/// Contexts are opaque and every operation revalidates their generation.
pub struct PeerContextAuthority<const MAX_PEERS: usize> {
    owner: u32,
    local_signer: [u8; 32],
    local_eui64: [u8; 8],
    entries: [Option<PeerAuthorityEntry>; MAX_PEERS],
}

impl<const MAX_PEERS: usize> PeerContextAuthority<MAX_PEERS> {
    pub fn new(local_signer: [u8; 32]) -> Result<Self, SchcError> {
        if MAX_PEERS == 0 || MAX_PEERS > u16::MAX as usize {
            return Err(SchcError::PeerAuthorityFull);
        }
        let owner = NEXT_PEER_AUTHORITY_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| SchcError::PeerAuthorityFull)?;
        let mut local_eui64 = lichen_core::addr::iid_from_pubkey_bytes(&local_signer);
        local_eui64[0] ^= 0x02;
        Ok(Self {
            owner,
            local_signer,
            local_eui64,
            entries: [None; MAX_PEERS],
        })
    }

    /// Issue a capability from opaque evidence produced by the link TCB.
    pub fn issue_from_authenticated_dio(
        &mut self,
        evidence: lichen_link::AuthenticatedLinkFrame<'_>,
        expected_rpl_instance_id: u8,
        expected_dodag_id: &[u8; 16],
        expected_mop: u8,
        expected_role: ExpectedDioRole,
    ) -> Result<AuthenticatedPeerSchcContext, SchcError> {
        if !evidence.is_current()
            || evidence.receipt().monotonic_millis().is_none()
            || !authenticated_dio_destination_is_local(evidence, &self.local_eui64)
        {
            return Err(SchcError::InvalidPeerEvidence);
        }
        let mut context = AuthenticatedPeerSchcContext::parse_authenticated_dio_evidence(
            evidence,
            expected_rpl_instance_id,
            expected_dodag_id,
            expected_mop,
            expected_role,
        )?;
        let signer = context.signer_identity;
        let authenticated_counter = context.authenticated_counter;
        let receipt_clock_domain = context.receipt_clock_domain;
        let receipt_ticks = context.receipt_ticks;
        let existing = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.signer == signer));
        let slot = existing
            .or_else(|| self.entries.iter().position(Option::is_none))
            .ok_or(SchcError::PeerAuthorityFull)?;
        let key_generation = evidence.peer_key_generation();
        let durable_key_generation = evidence.durable_peer_key_generation();
        if self.entries[slot].is_some_and(|entry| {
            entry.key_generation == key_generation
                && entry.durable_key_generation == durable_key_generation
                && authenticated_counter <= entry.counter
        }) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        if self.entries[slot].is_some_and(|entry| {
            entry.receipt_clock_domain != receipt_clock_domain
                || receipt_ticks < entry.receipt_ticks
        }) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        let generation =
            self.entries[slot].map_or(1, |entry| entry.generation.checked_add(1).unwrap_or(0));
        if generation == 0 {
            self.entries[slot] = None;
            return Err(SchcError::InvalidPeerEvidence);
        }
        self.entries[slot] = Some(PeerAuthorityEntry {
            signer,
            counter: authenticated_counter,
            key_generation,
            durable_key_generation,
            generation,
            receipt_clock_domain,
            receipt_ticks,
        });
        context.authority_owner = self.owner;
        context.authority_slot = slot as u16;
        context.authority_generation = generation;
        context.key_generation = key_generation;
        context.durable_key_generation = durable_key_generation;
        Ok(context)
    }

    #[cfg(test)]
    pub(crate) fn issue_test_peer(
        &mut self,
        signer: [u8; 32],
        authenticated_counter: u32,
        remote_version: u8,
        receipt_clock_domain: u64,
        receipt_ticks: u64,
    ) -> Result<AuthenticatedPeerSchcContext, SchcError> {
        self.issue_test_peer_for_generation(
            signer,
            authenticated_counter,
            remote_version,
            receipt_clock_domain,
            receipt_ticks,
            lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
            lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_test_peer_for_generation(
        &mut self,
        signer: [u8; 32],
        authenticated_counter: u32,
        remote_version: u8,
        receipt_clock_domain: u64,
        receipt_ticks: u64,
        key_generation: lichen_link::PeerKeyGeneration,
        durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    ) -> Result<AuthenticatedPeerSchcContext, SchcError> {
        let slot = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.signer == signer))
            .or_else(|| self.entries.iter().position(Option::is_none))
            .ok_or(SchcError::PeerAuthorityFull)?;
        if self.entries[slot].is_some_and(|entry| {
            entry.key_generation == key_generation
                && entry.durable_key_generation == durable_key_generation
                && authenticated_counter <= entry.counter
        }) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        let generation =
            self.entries[slot].map_or(1, |entry| entry.generation.checked_add(1).unwrap_or(0));
        if generation == 0 {
            return Err(SchcError::InvalidPeerEvidence);
        }
        self.entries[slot] = Some(PeerAuthorityEntry {
            signer,
            counter: authenticated_counter,
            key_generation,
            durable_key_generation,
            generation,
            receipt_clock_domain,
            receipt_ticks,
        });
        Ok(AuthenticatedPeerSchcContext {
            remote_version,
            signer_identity: signer,
            authenticated_counter,
            key_generation,
            durable_key_generation,
            authority_owner: self.owner,
            authority_slot: slot as u16,
            authority_generation: generation,
            receipt_clock_domain,
            receipt_ticks,
            #[cfg(feature = "std")]
            evidence: None,
        })
    }

    /// Retire every capability issued for `signer`.
    pub fn retire(&mut self, signer: &[u8; 32]) {
        for entry in &mut self.entries {
            if entry.is_some_and(|entry| &entry.signer == signer) {
                *entry = None;
            }
        }
    }

    pub fn is_current(&self, peer: &AuthenticatedPeerSchcContext) -> bool {
        peer.authority_owner == self.owner
            && self
                .entries
                .get(peer.authority_slot as usize)
                .is_some_and(|entry| {
                    entry.is_some_and(|entry| {
                        entry.signer == peer.signer_identity
                            && entry.counter == peer.authenticated_counter
                            && entry.key_generation == peer.key_generation
                            && entry.durable_key_generation == peer.durable_key_generation
                            && entry.generation == peer.authority_generation
                    })
                })
    }

    pub(crate) const fn local_eui64(&self) -> &[u8; 8] {
        &self.local_eui64
    }

    pub(crate) const fn local_signer(&self) -> &[u8; 32] {
        &self.local_signer
    }
}

/// Expected sender role bound during authenticated DIO admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedDioRole {
    Root,
    Peer,
}

impl AuthenticatedPeerSchcContext {
    /// Bind exactly one canonical version option to a link-authenticated,
    /// replay-accepted DIO frame. The DIO body begins with its 24-byte base.
    fn parse_authenticated_dio_evidence(
        frame: lichen_link::AuthenticatedLinkFrame<'_>,
        expected_rpl_instance_id: u8,
        expected_dodag_id: &[u8; 16],
        expected_mop: u8,
        expected_role: ExpectedDioRole,
    ) -> Result<Self, SchcError> {
        if !frame.is_current()
            || frame.payload().first().copied() != Some(lichen_core::constants::L2_DISPATCH_SCHC)
        {
            return Err(SchcError::InvalidPacket("DIO missing SCHC L2 dispatch"));
        }
        let mut ipv6 = [0u8; 512];
        let ipv6_len = decompress(&frame.payload()[1..], &mut ipv6)?;
        let ipv6 = &ipv6[..ipv6_len];
        if ipv6.len() < IPV6_HEADER_LEN + 4 + 24 || ipv6[6] != 58 {
            return Err(SchcError::InvalidPacket(
                "authenticated SCHC payload is not a valid RPL DIO",
            ));
        }
        let src: &[u8; 16] = ipv6[8..24]
            .try_into()
            .map_err(|_| SchcError::InvalidPacket("invalid DIO IPv6 source"))?;
        let dst: &[u8; 16] = ipv6[24..40]
            .try_into()
            .map_err(|_| SchcError::InvalidPacket("invalid DIO IPv6 destination"))?;
        let mut signer_iid = frame.signer_eui64();
        signer_iid[0] ^= 0x02;
        if src[..8] != [0xfe, 0x80, 0, 0, 0, 0, 0, 0] || src[8..] != signer_iid {
            return Err(SchcError::DioAdmission(
                DioAdmissionError::SourceSignerMismatch,
            ));
        }
        if ipv6[40] != 155
            || ipv6[41] != 1
            || lichen_core::checksum::upper_layer_checksum(src, dst, 58, &ipv6[40..]) != 0
        {
            return Err(SchcError::InvalidPacket(
                "authenticated SCHC payload is not a valid RPL DIO",
            ));
        }
        let payload = &ipv6[44..];
        if payload[7] != 0 {
            return Err(SchcError::InvalidPacket("malformed authenticated DIO"));
        }
        if payload[0] != expected_rpl_instance_id {
            return Err(SchcError::InvalidPacket(
                "authenticated DIO instance mismatch",
            ));
        }
        if &payload[8..24] != expected_dodag_id {
            return Err(SchcError::DioAdmission(
                DioAdmissionError::DodagScopeMismatch,
            ));
        }
        if (payload[4] >> 3) & 0x07 != expected_mop {
            return Err(SchcError::InvalidPacket("authenticated DIO MOP mismatch"));
        }
        let is_root = u16::from_be_bytes([payload[2], payload[3]]) == 256;
        if is_root != matches!(expected_role, ExpectedDioRole::Root) {
            return Err(SchcError::DioAdmission(
                DioAdmissionError::RoleScopeMismatch,
            ));
        }
        if is_root && lichen_core::addr::ygg_addr_from_pubkey(&frame.signer()) != *expected_dodag_id
        {
            return Err(SchcError::DioAdmission(
                DioAdmissionError::RootKeyDodagMismatch,
            ));
        }
        let mut cursor = 24usize;
        let mut version = None;
        while cursor < payload.len() {
            if payload[cursor] == 0 {
                cursor += 1;
                continue;
            }
            if cursor + 2 > payload.len() {
                return Err(SchcError::InvalidPacket(
                    "truncated authenticated DIO option",
                ));
            }
            let option_type = payload[cursor];
            let option_len = payload[cursor + 1] as usize;
            let end = cursor
                .checked_add(2 + option_len)
                .ok_or(SchcError::InvalidPacket("DIO option length overflow"))?;
            if end > payload.len() {
                return Err(SchcError::InvalidPacket(
                    "truncated authenticated DIO option",
                ));
            }
            if option_type == crate::rules::SCHC_RULE_VERSION_TYPE {
                if option_len != 1 {
                    return Err(SchcError::DioAdmission(match option_len {
                        0 => DioAdmissionError::MalformedRuleVersionLength0,
                        2 => DioAdmissionError::MalformedRuleVersionLength2,
                        _ => DioAdmissionError::MalformedRuleVersion,
                    }));
                }
                if version.replace(payload[cursor + 2]).is_some() {
                    return Err(SchcError::DioAdmission(
                        DioAdmissionError::DuplicateRuleVersion,
                    ));
                }
            }
            cursor = end;
        }
        let remote_version = version.ok_or(SchcError::DioAdmission(
            DioAdmissionError::MissingRuleVersion,
        ))?;
        let signer_identity = frame.signer();
        Ok(Self {
            remote_version,
            signer_identity,
            authenticated_counter: frame.authenticated_counter(),
            key_generation: frame.peer_key_generation(),
            durable_key_generation: frame.durable_peer_key_generation(),
            authority_owner: 0,
            authority_slot: 0,
            authority_generation: 0,
            receipt_clock_domain: frame.receipt().clock_domain(),
            receipt_ticks: frame.receipt().monotonic_ticks(),
            #[cfg(feature = "std")]
            evidence: None,
        })
    }

    /// Consume authenticated frame evidence into a current owner-bound peer context.
    #[cfg(feature = "std")]
    pub fn from_authenticated_dio_frame(
        frame: lichen_link::link_layer::AuthenticatedFrame,
        expected_rpl_instance_id: u8,
        expected_dodag_id: &[u8; 16],
        expected_mop: u8,
        expected_role: ExpectedDioRole,
    ) -> Result<Self, SchcError> {
        if !authenticated_dio_destination_is_local(frame.link_evidence(), &frame.receiving_eui64())
        {
            return Err(SchcError::InvalidPeerEvidence);
        }
        let mut context = Self::parse_authenticated_dio_evidence(
            frame.link_evidence(),
            expected_rpl_instance_id,
            expected_dodag_id,
            expected_mop,
            expected_role,
        )?;
        context.evidence = Some(frame);
        Ok(context)
    }

    #[cfg(feature = "std")]
    pub(crate) fn is_current_for(&self, link: &lichen_link::link_layer::LinkLayer) -> bool {
        self.evidence
            .as_ref()
            .is_some_and(|frame| link.accepts_authenticated_frame(frame))
    }

    #[cfg(feature = "std")]
    fn retained_evidence_is_current(&self) -> bool {
        self.evidence
            .as_ref()
            .is_some_and(|frame| frame.is_current())
    }

    #[cfg(not(feature = "std"))]
    const fn retained_evidence_is_current(&self) -> bool {
        false
    }

    pub(crate) const fn authenticated_counter(&self) -> u32 {
        self.authenticated_counter
    }

    /// Borrow the immutable authenticated frame retained by this capability.
    #[cfg(feature = "std")]
    pub fn authenticated_frame(&self) -> Option<&lichen_link::link_layer::AuthenticatedFrame> {
        self.evidence.as_ref()
    }

    pub const fn remote_version(&self) -> u8 {
        self.remote_version
    }

    pub const fn signer_identity(&self) -> &[u8; 32] {
        &self.signer_identity
    }

    /// Opaque identity of the exact installed remote key generation.
    pub const fn key_generation(&self) -> lichen_link::PeerKeyGeneration {
        self.key_generation
    }

    /// Stable trust-store identity of the installed remote key generation.
    pub const fn durable_key_generation(&self) -> lichen_link::DurablePeerKeyGeneration {
        self.durable_key_generation
    }

    pub const fn receipt_clock_domain(&self) -> u64 {
        self.receipt_clock_domain
    }

    pub const fn receipt_ticks(&self) -> u64 {
        self.receipt_ticks
    }

    /// A DODAG is admissible only for the sole implemented v3 registry.
    pub const fn allows_dodag_join(&self) -> bool {
        versions_compatible(RULE_SET_VERSION, self.remote_version)
    }

    pub fn compress(
        &self,
        packet: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
    ) -> Result<usize, SchcError> {
        if !self.retained_evidence_is_current() {
            return Err(SchcError::InvalidPeerEvidence);
        }
        if self.allows_dodag_join() {
            compress(packet, out)
        } else {
            encode_rule255(packet, out, single_frame_limit)
        }
    }

    pub fn decompress(
        &self,
        data: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
    ) -> Result<usize, SchcError> {
        if !self.retained_evidence_is_current() {
            return Err(SchcError::InvalidPeerEvidence);
        }
        if self.allows_dodag_join() {
            decompress(data, out)
        } else {
            decode_rule255(data, out, single_frame_limit)
        }
    }

    /// no-std operation gated by the current authority generation.
    pub fn compress_with_authority<const MAX_PEERS: usize>(
        &self,
        authority: &PeerContextAuthority<MAX_PEERS>,
        packet: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
    ) -> Result<usize, SchcError> {
        if !authority.is_current(self) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        if self.allows_dodag_join() {
            compress(packet, out)
        } else {
            encode_rule255(packet, out, single_frame_limit)
        }
    }

    /// no-std ingress gated by the current authority generation.
    pub fn decompress_with_authority<const MAX_PEERS: usize>(
        &self,
        authority: &PeerContextAuthority<MAX_PEERS>,
        data: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
    ) -> Result<usize, SchcError> {
        if !authority.is_current(self) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        if self.allows_dodag_join() {
            decompress(data, out)
        } else {
            decode_rule255(data, out, single_frame_limit)
        }
    }

    /// no-std tracked ingress gated by the current authority generation.
    pub fn decompress_tracked_with_authority<const MAX_PEERS: usize, const MAX_SOURCES: usize>(
        &self,
        authority: &PeerContextAuthority<MAX_PEERS>,
        data: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
        tracker: &mut RuleVersionFailureTracker<MAX_SOURCES>,
        mut notify_operator: impl FnMut(&[u8; 32]),
    ) -> Result<usize, SchcError> {
        match self.decompress_with_authority(authority, data, out, single_frame_limit) {
            Ok(length) => {
                tracker.record_success(&self.signer_identity);
                Ok(length)
            }
            Err(error @ SchcError::BufferTooSmall(_)) => Err(error),
            Err(error @ SchcError::InvalidPeerEvidence) => Err(error),
            Err(error) => {
                let notify = tracker
                    .record_failure(self.signer_identity)
                    .unwrap_or(false);
                if notify {
                    notify_operator(&self.signer_identity);
                }
                Err(error)
            }
        }
    }

    /// Production ingress with bounded per-signer failure tracking.
    ///
    /// Malformed SCHC input records one consecutive failure; output-capacity
    /// errors do not. A validated decompression clears the signer run. The
    /// callback fires exactly once when the configured threshold is crossed.
    pub fn decompress_tracked<const MAX_SOURCES: usize>(
        &self,
        data: &[u8],
        out: &mut [u8],
        single_frame_limit: usize,
        tracker: &mut RuleVersionFailureTracker<MAX_SOURCES>,
        mut notify_operator: impl FnMut(&[u8; 32]),
    ) -> Result<usize, SchcError> {
        match self.decompress(data, out, single_frame_limit) {
            Ok(length) => {
                tracker.record_success(&self.signer_identity);
                Ok(length)
            }
            Err(error @ SchcError::BufferTooSmall(_)) => Err(error),
            Err(error @ SchcError::InvalidPeerEvidence) => Err(error),
            Err(error) => {
                let notify = tracker
                    .record_failure(self.signer_identity)
                    .unwrap_or(false);
                if notify {
                    notify_operator(&self.signer_identity);
                }
                Err(error)
            }
        }
    }
}

fn authenticated_dio_destination_is_local(
    frame: lichen_link::AuthenticatedLinkFrame<'_>,
    local_eui64: &[u8; 8],
) -> bool {
    const ALL_RPL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];

    let mut ipv6 = [0u8; 512];
    let Ok(length) = decompress(frame.payload().get(1..).unwrap_or_default(), &mut ipv6) else {
        return false;
    };
    if length < IPV6_HEADER_LEN {
        return false;
    }
    let destination = &ipv6[24..40];
    let mut local_iid = *local_eui64;
    local_iid[0] ^= 0x02;
    let local_link = [
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        local_iid[0],
        local_iid[1],
        local_iid[2],
        local_iid[3],
        local_iid[4],
        local_iid[5],
        local_iid[6],
        local_iid[7],
    ];

    if destination == ALL_RPL_NODES {
        return frame.payload().get(1).copied() == Some(RULE_UNCOMPRESSED)
            && matches!(
                frame.destination_mode(),
                lichen_link::frame::AddrMode::None | lichen_link::frame::AddrMode::Elided
            );
    }
    destination == local_link
        && frame.destination_mode() == lichen_link::frame::AddrMode::Extended
        && frame.destination() == local_eui64
}

/// Compress a full IPv6 `packet` into `out` using the best matching SCHC rule.
///
/// Falls back to rule 255 (uncompressed: rule byte + raw packet) if no rule
/// matches. Returns the number of bytes written to `out`.
pub fn compress(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    validate_full_ipv6(packet)?;

    // Every v3 compressed rule elides Traffic Class and Flow Label as zero.
    // A structurally valid packet with different values is a non-match, not a
    // malformed packet: preserve it byte-for-byte with Rule 255.
    if packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
        return encode_rule255(packet, out, usize::MAX);
    }

    let nh = packet[6];
    let src = &packet[8..24];
    let dst = &packet[24..40];

    if nh == 17 && packet.len() >= 48 {
        // UDP — need at least 48 bytes (40 IPv6 + 8 UDP) for port/CoAP access
        let src_port = u16::from_be_bytes([packet[40], packet[41]]);
        let dst_port = u16::from_be_bytes([packet[42], packet[43]]);

        // Try MQTT-SN (rule 7) first if port matches
        if src_port == PORT_MQTT_SN || dst_port == PORT_MQTT_SN {
            match compress_mqtt_sn(packet, out) {
                Ok(n) => return enforce_encoded_profile_limit(n),
                Err(SchcError::NoMatchingRule) => {}
                Err(error) => return Err(error),
            }
        }

        // Check for OSCORE (CoAP option 9) to select rules 5/6 vs 0/1
        let coap = &packet[48..]; // UDP header is 8 bytes after IPv6
        let is_oscore = packet.len() >= 52 && has_oscore_option(coap);

        if is_link_local_64(src) && is_link_local_64(dst) {
            let rule = if is_oscore {
                RULE_LINK_LOCAL_OSCORE
            } else {
                RULE_LINK_LOCAL_COAP
            };
            if let Ok(n) = compress_coap(packet, out, rule) {
                return enforce_encoded_profile_limit(n);
            }
        }
        // Yggdrasil (02xx::/8) addresses use rules 1/6 (120-bit compression)
        // OSCORE -> rule 6, plaintext CoAP -> rule 1
        // ULA and other global addresses fall through to uncompressed.
        let rule = if is_oscore {
            RULE_GLOBAL_OSCORE
        } else {
            RULE_GLOBAL_COAP
        };
        if let Ok(n) = compress_coap(packet, out, rule) {
            return enforce_encoded_profile_limit(n);
        }
    } else if nh == 58 && packet.len() >= 40 + 4 {
        // ICMPv6 — verify checksum before selecting rules 2/3/4.
        // Invalid checksums fall through to Rule 255, matching Python behavior.
        let icmpv6 = &packet[40..];
        if !icmpv6_checksum_valid(src, dst, icmpv6) {
            return encode_rule255(packet, out, usize::MAX);
        }

        let icmp_type = packet[40];
        let icmp_code = packet[41];

        if (icmp_type == 128 || icmp_type == 129)
            && icmp_code == 0
            && is_link_local_64(src)
            && is_link_local_64(dst)
            && packet.len() >= 40 + 8
        {
            if let Ok(n) = compress_icmpv6_echo(packet, out) {
                return enforce_encoded_profile_limit(n);
            }
        } else if icmp_type == 155 && is_link_local_64(src) && is_link_local_64(dst) {
            if icmp_code == 1 && packet.len() >= 40 + 4 + 24 {
                // DIO
                if let Ok(n) = compress_rpl_dio(packet, out) {
                    return enforce_encoded_profile_limit(n);
                }
            } else if icmp_code == 2 && packet.len() >= 40 + 4 + 20 {
                // DAO — only rule 4 if D flag set
                // packet[45] = offset 40 (IPv6) + 4 (ICMPv6 header) + 1 (instance) = K/D/flags byte
                let kd_flags = packet[45];
                if kd_flags & 0x40 != 0 {
                    if let Ok(n) = compress_rpl_dao(packet, out) {
                        return enforce_encoded_profile_limit(n);
                    }
                }
            }
        }
    }

    encode_rule255(packet, out, usize::MAX)
}

/// Decompress a SCHC packet back into a full IPv6 datagram.
///
/// Returns the number of bytes written to `out`.
pub fn decompress(data: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if data.is_empty() {
        return Err(TooShort::new(1, 0).into());
    }
    if data.len() > SCHC_FRAG_MAX_PACKET_SIZE {
        return Err(SchcError::InvalidPacket(
            "SCHC packet exceeds profile limit",
        ));
    }
    match data[0] {
        RULE_LINK_LOCAL_COAP => decompress_coap(data, out, RULE_LINK_LOCAL_COAP),
        RULE_GLOBAL_COAP => decompress_coap(data, out, RULE_GLOBAL_COAP),
        RULE_ICMPV6_ECHO => decompress_icmpv6_echo(data, out),
        RULE_RPL_DIO => decompress_rpl_dio(data, out),
        RULE_RPL_DAO => decompress_rpl_dao(data, out),
        RULE_LINK_LOCAL_OSCORE => decompress_coap(data, out, RULE_LINK_LOCAL_OSCORE),
        RULE_GLOBAL_OSCORE => decompress_coap(data, out, RULE_GLOBAL_OSCORE),
        RULE_MQTT_SN => decompress_mqtt_sn(data, out, RULE_MQTT_SN),
        RULE_UNCOMPRESSED => decode_rule255(data, out, usize::MAX),
        id => Err(SchcError::UnknownRuleId(id)),
    }
}

fn enforce_encoded_profile_limit(length: usize) -> Result<usize, SchcError> {
    if length > SCHC_FRAG_MAX_PACKET_SIZE {
        Err(SchcError::InvalidPacket(
            "SCHC packet exceeds profile limit",
        ))
    } else {
        Ok(length)
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{vec, vec::Vec};

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn mqtt_packet(
        src: &[u8],
        dst: &[u8],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = vec![0u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(src);
        packet[24..40].copy_from_slice(dst);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let checksum = udp_checksum(src, dst, src_port, dst_port, payload).unwrap();
        packet[46..48].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn round_trip(packet_hex: &str, compressed_hex: &str, rule_id: u8) {
        let packet = hex(packet_hex);
        let expected = hex(compressed_hex);

        let mut comp_buf = [0u8; 1500];
        let n = compress(&packet, &mut comp_buf).unwrap();
        assert_eq!(
            &comp_buf[..n],
            expected.as_slice(),
            "compress mismatch rule {rule_id}"
        );
        assert_eq!(comp_buf[0], rule_id, "rule_id mismatch");

        let mut decomp_buf = [0u8; 1500];
        let m = decompress(&expected, &mut decomp_buf).unwrap();
        assert_eq!(
            &decomp_buf[..m],
            packet.as_slice(),
            "decompress mismatch rule {rule_id}"
        );
    }

    #[test]
    fn vector_coap_linklocal() {
        // From shared test vectors: link-local with 4-bit LSB port compression
        round_trip(
            "6000000000131140fe800000000000000000000000000001\
             fe80000000000000000000000000000216331633001328dd\
             40011234ff737461747573",
            "00400000000000000001000000000000000233000448d0\
             ff737461747573",
            0,
        );
    }

    #[test]
    fn vector_coap_global() {
        // From shared test vectors: Yggdrasil (02xx) with 120-bit address compression
        round_trip(
            "6000000000131140027dd5cfc679ab637dd5cfc679ab6342\
             02f77a7baa1226b5f57a7baa1226b50c1633163300132a9b\
             40011234ff737461747573",
            "01407dd5cfc679ab637dd5cfc679ab6342f77a7baa1226b5\
             f57a7baa1226b50c33000448d0ff737461747573",
            1,
        );
    }

    #[test]
    fn vector_icmpv6_echo() {
        round_trip(
            "60000000000c3a40fe800000000000000000000000000001\
             fe8000000000000000000000000000028000f80eabcd0007\
             70696e67",
            "02400000000000000001000000000000000280abcd0007\
             70696e67",
            2,
        );
    }

    #[test]
    fn vector_rpl_dio() {
        round_trip(
            "60000000001c3a40fe800000000000000000000000000001\
             fe8000000000000000000000000000029b01e01f00010100\
             88000000fe800000000000000000000000000001",
            "034000000000000000010000000000000002000101008800\
             fe800000000000000000000000000001",
            3,
        );
    }

    #[test]
    fn vector_rpl_dao() {
        round_trip(
            "6000000000183a40fe800000000000000000000000000001\
             fe8000000000000000000000000000029b0268df00400005\
             fe800000000000000000000000000001",
            "044000000000000000010000000000000002004005\
             fe800000000000000000000000000001",
            4,
        );
    }

    #[test]
    fn mqtt_sn_round_trip_linklocal() {
        // Test round-trip for link-local MQTT-SN (src=10883)
        // Build packet manually and verify compression/decompression
        let src_addr = hex("fe800000000000000000000000000001");
        let dst_addr = hex("fe800000000000000000000000000002");
        let src_port: u16 = PORT_MQTT_SN; // 10883
        let dst_port: u16 = 5000;
        let payload = b"test";

        // Build UDP segment for checksum
        let udp_len: u16 = 8 + payload.len() as u16;

        // Compute UDP checksum
        let cksum = udp_checksum(&src_addr, &dst_addr, src_port, dst_port, payload).unwrap();

        // Build full IPv6 packet
        let mut packet = [0u8; 60];
        packet[0] = 0x60; // Version 6
        packet[4] = (udp_len >> 8) as u8;
        packet[5] = udp_len as u8;
        packet[6] = 17; // UDP
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&src_addr);
        packet[24..40].copy_from_slice(&dst_addr);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[44..46].copy_from_slice(&udp_len.to_be_bytes());
        packet[46..48].copy_from_slice(&cksum.to_be_bytes());
        packet[48..52].copy_from_slice(payload);

        let packet_len = 52;
        let packet = &packet[..packet_len];

        // Compress
        let mut comp_buf = [0u8; 256];
        let n = compress(packet, &mut comp_buf).unwrap();
        assert_eq!(comp_buf[0], RULE_MQTT_SN, "should use Rule 7 for MQTT-SN");

        // Decompress
        let mut decomp_buf = [0u8; 256];
        let m = decompress(&comp_buf[..n], &mut decomp_buf).unwrap();
        assert_eq!(&decomp_buf[..m], packet, "round-trip should match");
    }

    #[test]
    fn mqtt_sn_shared_vectors_are_byte_exact() {
        for (packet, compressed) in [
            (
                "60000000000c1140fe800000000000000000000000000001fe8000000000000000000000000000022a831388000cdcec74657374",
                "07400000000000000000800000000000000104e20074657374",
            ),
            (
                "60000000000f1140fe800000000000000000000000000001fe80000000000000000000000000000213882a83000f197f636f6e6e656374",
                "07400000000000000000800000000000000144e200636f6e6e656374",
            ),
            (
                "6000000000091140fe800000000000000000000000000001fe8000000000000000000000000000022a832a83000935d178",
                "0740000000000000000080000000000000010aa0c078",
            ),
            (
                "60000000000b114020010db800000000000000000000000120010db80000000000000000000000022a8322b8000b84b2707562",
                "0740900086dc000000000000000000000000900086dc00000000000000000000000108ae00707562",
            ),
            (
                "6000000000091140fe80000000000000000000000000000120010db80000000000000000000000022a831388000928946d",
                "0740ff400000000000000000000000000000900086dc00000000000000000000000104e2006d",
            ),
        ] {
            round_trip(packet, compressed, RULE_MQTT_SN);
        }
    }

    #[test]
    fn mqtt_sn_round_trip_dst_10883() {
        // Test round-trip for MQTT-SN with dst=10883 (client -> server)
        let src_addr = hex("fe800000000000000000000000000001");
        let dst_addr = hex("fe800000000000000000000000000002");
        let src_port: u16 = 12345;
        let dst_port: u16 = PORT_MQTT_SN; // 10883
        let payload = b"connect";

        let udp_len: u16 = 8 + payload.len() as u16;
        let cksum = udp_checksum(&src_addr, &dst_addr, src_port, dst_port, payload).unwrap();

        let mut packet = [0u8; 64];
        packet[0] = 0x60;
        packet[4] = (udp_len >> 8) as u8;
        packet[5] = udp_len as u8;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src_addr);
        packet[24..40].copy_from_slice(&dst_addr);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[44..46].copy_from_slice(&udp_len.to_be_bytes());
        packet[46..48].copy_from_slice(&cksum.to_be_bytes());
        packet[48..55].copy_from_slice(payload);

        let packet_len = 55;
        let packet = &packet[..packet_len];

        let mut comp_buf = [0u8; 256];
        let n = compress(packet, &mut comp_buf).unwrap();
        assert_eq!(comp_buf[0], RULE_MQTT_SN);

        let mut decomp_buf = [0u8; 256];
        let m = decompress(&comp_buf[..n], &mut decomp_buf).unwrap();
        assert_eq!(&decomp_buf[..m], packet);
    }

    #[test]
    fn mqtt_sn_profile_size_boundary() {
        let src = hex("fe800000000000000000000000000001");
        let dst = hex("fe800000000000000000000000000002");
        // Link-local Rule 7 has a canonical 21-byte encoded prefix, so the
        // largest SCHC packet carries 22,533 payload bytes and reconstructs a
        // 22,581-byte IPv6 packet.
        let payload = vec![0u8; SCHC_FRAG_MAX_PACKET_SIZE - 21];
        let packet = mqtt_packet(&src, &dst, PORT_MQTT_SN, 5000, &payload);
        assert_eq!(packet.len(), SCHC_FRAG_MAX_PACKET_SIZE + 27);

        let mut compressed = vec![0u8; SCHC_FRAG_MAX_PACKET_SIZE];
        let compressed_len = compress(&packet, &mut compressed).unwrap();
        assert_eq!(compressed_len, SCHC_FRAG_MAX_PACKET_SIZE);
        compressed.truncate(compressed_len);
        let mut restored = vec![0u8; packet.len()];
        let restored_len = decompress(&compressed, &mut restored).unwrap();
        assert_eq!(&restored[..restored_len], packet.as_slice());

        compressed.push(0);
        assert!(matches!(
            decompress(&compressed, &mut restored),
            Err(SchcError::InvalidPacket(
                "SCHC packet exceeds profile limit"
            ))
        ));
    }

    #[test]
    fn mqtt_sn_global_addresses() {
        // Test MQTT-SN with global addresses (uses full 128-bit addresses)
        let src_addr = hex("20010db8000000000000000000000001");
        let dst_addr = hex("20010db8000000000000000000000002");
        let src_port: u16 = PORT_MQTT_SN;
        let dst_port: u16 = 8888;
        let payload = b"pub";

        let udp_len: u16 = 8 + payload.len() as u16;
        let cksum = udp_checksum(&src_addr, &dst_addr, src_port, dst_port, payload).unwrap();

        let mut packet = [0u8; 64];
        packet[0] = 0x60;
        packet[4] = (udp_len >> 8) as u8;
        packet[5] = udp_len as u8;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src_addr);
        packet[24..40].copy_from_slice(&dst_addr);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[44..46].copy_from_slice(&udp_len.to_be_bytes());
        packet[46..48].copy_from_slice(&cksum.to_be_bytes());
        packet[48..51].copy_from_slice(payload);

        let packet_len = 51;
        let packet = &packet[..packet_len];

        let mut comp_buf = [0u8; 256];
        let n = compress(packet, &mut comp_buf).unwrap();
        assert_eq!(comp_buf[0], RULE_MQTT_SN);

        let mut decomp_buf = [0u8; 256];
        let m = decompress(&comp_buf[..n], &mut decomp_buf).unwrap();
        assert_eq!(&decomp_buf[..m], packet);
    }

    #[test]
    fn mqtt_sn_fe80_slash10_outside_slash64_uses_full_addresses() {
        let src = hex("fe800000000000010000000000000001");
        let dst = hex("fe800000000000020000000000000002");
        assert!(is_link_local(&src) && is_link_local(&dst));
        assert!(!is_link_local_64(&src) && !is_link_local_64(&dst));
        let packet = mqtt_packet(&src, &dst, PORT_MQTT_SN, 5000, b"test");

        let mut compressed = [0u8; 512];
        let n = compress(&packet, &mut compressed).unwrap();
        assert_eq!(compressed[0], RULE_MQTT_SN);
        assert_eq!(compressed[2] & 0x80, 0x80, "AddressMode must be full");

        let mut decompressed = [0u8; 512];
        let m = decompress(&compressed[..n], &mut decompressed).unwrap();
        assert_eq!(&decompressed[..m], packet);
    }

    #[test]
    fn mqtt_sn_rejects_invalid_elided_ipv6_udp_fields() {
        let src = hex("fe800000000000000000000000000001");
        let dst = hex("fe800000000000000000000000000002");
        let valid = mqtt_packet(&src, &dst, PORT_MQTT_SN, 5000, b"test");
        let mut out = [0u8; 256];

        for mutation in 0..6 {
            let mut packet = valid.clone();
            match mutation {
                0 => packet[0] |= 0x01,
                1 => packet[2] = 1,
                2 => packet[5] = packet[5].wrapping_add(1),
                3 => packet[45] = packet[45].wrapping_add(1),
                4 => packet[46..48].fill(0),
                5 => packet[47] ^= 1,
                _ => unreachable!(),
            }
            let result = compress(&packet, &mut out);
            if mutation < 2 {
                let length = result.expect("valid descriptor non-match must fall back");
                assert_eq!(out[0], RULE_UNCOMPRESSED);
                assert_eq!(&out[1..length], packet.as_slice());
            } else {
                assert!(
                    matches!(result, Err(SchcError::InvalidPacket(_))),
                    "mutation {mutation} must be dropped"
                );
            }
        }
    }

    #[test]
    fn mqtt_sn_non_udp_does_not_match_rule_7() {
        let src = hex("fe800000000000000000000000000001");
        let dst = hex("fe800000000000000000000000000002");
        let mut packet = mqtt_packet(&src, &dst, PORT_MQTT_SN, 5000, b"test");
        packet[6] = 59;
        let mut out = [0u8; 256];
        let n = compress(&packet, &mut out).unwrap();
        assert_eq!(out[0], RULE_UNCOMPRESSED);
        assert_eq!(&out[1..n], packet);
    }

    #[test]
    fn mqtt_sn_rejects_noncanonical_residues() {
        let src = hex("fe800000000000000000000000000001");
        let dst = hex("fe800000000000000000000000000002");
        let packet = mqtt_packet(&src, &dst, PORT_MQTT_SN, PORT_MQTT_SN, b"x");
        let mut compressed = [0u8; 512];
        let n = compress(&packet, &mut compressed).unwrap();

        let mut nonzero_padding = compressed[..n].to_vec();
        nonzero_padding[20] |= 1;
        let mut out = [0u8; 512];
        assert!(matches!(
            decompress(&nonzero_padding, &mut out),
            Err(SchcError::NonCanonicalResidue(_))
        ));

        let mut noncanonical_direction = compressed[..n].to_vec();
        noncanonical_direction[18] |= 0x40;
        assert!(matches!(
            decompress(&noncanonical_direction, &mut out),
            Err(SchcError::NonCanonicalResidue(_))
        ));

        let mut full = [0u8; 512];
        full[0] = RULE_MQTT_SN;
        let residue_end = {
            let mut writer = BitWriter::new(&mut full[1..]);
            writer.write(64, 8).unwrap();
            writer.write(1, 1).unwrap();
            writer
                .write(u128::from_be_bytes(src.as_slice().try_into().unwrap()), 128)
                .unwrap();
            writer
                .write(u128::from_be_bytes(dst.as_slice().try_into().unwrap()), 128)
                .unwrap();
            writer.write(0, 1).unwrap();
            writer.write(PORT_MQTT_SN as u128, 16).unwrap();
            1 + writer.byte_len()
        };
        full[residue_end] = b'x';
        assert!(matches!(
            decompress(&full[..residue_end + 1], &mut out),
            Err(SchcError::NonCanonicalResidue(_))
        ));
    }

    #[test]
    fn mqtt_sn_checksum_zero_is_serialized_as_ffff() {
        let src = hex("fe800000000000000000000000000001");
        let dst = hex("fe800000000000000000000000000002");
        let payload = (0u16..=u16::MAX)
            .map(u16::to_be_bytes)
            .find(|candidate| {
                udp_checksum(&src, &dst, PORT_MQTT_SN, 5000, candidate).unwrap() == 0xFFFF
            })
            .expect("a two-byte checksum-zero payload exists");
        let packet = mqtt_packet(&src, &dst, PORT_MQTT_SN, 5000, &payload);
        assert_eq!(&packet[46..48], &[0xFF, 0xFF]);

        let mut compressed = [0u8; 512];
        let n = compress(&packet, &mut compressed).unwrap();
        let mut decompressed = [0u8; 512];
        let m = decompress(&compressed[..n], &mut decompressed).unwrap();
        assert_eq!(&decompressed[..m], packet);
        assert_eq!(&decompressed[46..48], &[0xFF, 0xFF]);
    }

    #[test]
    fn uncompressed_fallback_requires_full_ipv6() {
        let packet = hex("deadbeef");
        let mut buf = [0u8; 8];
        assert!(matches!(
            compress(&packet, &mut buf),
            Err(SchcError::InvalidPacket(_))
        ));
    }

    #[test]
    fn non_ipv6_is_rejected_before_rule_255() {
        let raw = hex("deadbeef");
        let mut buf = [0u8; 8];
        assert!(matches!(
            compress(&raw, &mut buf),
            Err(SchcError::InvalidPacket(_))
        ));
    }

    #[test]
    fn unknown_rule_id_errors() {
        let data = hex("7edeadbeef");
        let mut out = [0u8; 64];
        assert_eq!(
            decompress(&data, &mut out),
            Err(SchcError::UnknownRuleId(0x7e))
        );
    }

    #[test]
    fn authenticated_peer_version_mismatch_allows_only_single_frame_rule255() {
        let packet =
            hex("6000000000003a40fe800000000000000000000000000001fe800000000000000000000000000002");
        let mut authority = PeerContextAuthority::<1>::new([0x24; 32]).unwrap();
        let peer = authority.issue_test_peer([0x42; 32], 1, 2, 7, 1).unwrap();
        assert!(!peer.allows_dodag_join());
        let mut encoded = [0u8; 64];
        let length = peer
            .compress_with_authority(&authority, &packet, &mut encoded, 64)
            .unwrap();
        assert_eq!(encoded[0], RULE_UNCOMPRESSED);
        let mut decoded = [0u8; 64];
        assert_eq!(
            peer.decompress_with_authority(&authority, &encoded[..length], &mut decoded, 64)
                .unwrap(),
            packet.len()
        );
        assert!(peer
            .compress_with_authority(&authority, &packet, &mut encoded, 40)
            .is_err());
        assert!(peer
            .decompress_with_authority(&authority, &[RULE_MQTT_SN; 21], &mut decoded, 64)
            .is_err());
    }
}
