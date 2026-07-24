//! SCHC compress/decompress (RFC 8724) — rules 0-4 + uncompressed fallback.
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

use lichen_core::constants::{
    PORT_MQTT_SN, RULE_GLOBAL_COAP, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP, RULE_MQTT_SN,
    RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED, SCHC_MAX_DECOMPRESSED,
};
use lichen_core::error::{BufferTooSmall, TooShort};

/// IPv6 link-local prefix (fe80::/64) as a u128 with the prefix in the high 64 bits.
/// To reconstruct a full link-local address, OR this with a 64-bit Interface Identifier (IID).
/// See RFC 4291 Section 2.5.6: Link-Local addresses have the format fe80::<IID>/10.
const LINK_LOCAL_PREFIX: u128 = 0xFE80_0000_0000_0000_u128 << 64;

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
}

impl core::fmt::Display for SchcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMatchingRule => write!(f, "no matching rule"),
            Self::BufferTooSmall(e) => write!(f, "SCHC {}", e),
            Self::UnknownRuleId(id) => write!(f, "unknown rule ID: {}", id),
            Self::TooShort(e) => write!(f, "SCHC {}", e),
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
        for b in buf.iter_mut() {
            *b = 0;
        }
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
}

// ─── address helpers ─────────────────────────────────────────────────────────

fn is_link_local(addr: &[u8]) -> bool {
    addr.len() == 16 && addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
}

fn is_global(addr: &[u8]) -> bool {
    addr.len() == 16 && (addr[0] >> 5) == 0b001
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

fn finalize(sum: u32) -> u16 {
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
    Ok(finalize(sum))
}

fn icmpv6_checksum(src: &[u8], dst: &[u8], icmpv6_payload: &[u8]) -> u16 {
    let length = icmpv6_payload.len() as u16;
    let mut sum = pseudo_sum(src, dst, 58, length);
    sum = oc_add(sum, checksum_bytes(icmpv6_payload));
    finalize(sum)
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

/// Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
/// Write SCHC-compressed address fields into `w`.
///
/// Encodes one bit of address mode (0 = link-local IID, 1 = full 128-bit),
/// then the address(es). Rule 0 (link-local CoAP) is implicitly link-local;
/// Rule 1 (global CoAP) uses a mode bit to cover both cases.
fn write_compressed_addrs(
    w: &mut BitWriter,
    rule_id: u8,
    src: &[u8; 16],
    dst: &[u8; 16],
) -> Result<(), SchcError> {
    if rule_id == RULE_LINK_LOCAL_COAP {
        let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
        let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
        w.write(src_iid as u128, 64)?;
        w.write(dst_iid as u128, 64)?;
    } else {
        let src_int = u128::from_be_bytes(*src);
        let dst_int = u128::from_be_bytes(*dst);
        w.write(src_int, 128)?;
        w.write(dst_int, 128)?;
    }
    Ok(())
}

/// Write SCHC-compressed address fields with a leading address-mode bit.
///
/// Writes 1-bit mode (0 = link-local IID, 1 = full 128-bit), then the addresses.
fn write_compressed_addrs_with_mode(
    w: &mut BitWriter,
    src: &[u8; 16],
    dst: &[u8; 16],
) -> Result<(), SchcError> {
    if is_link_local(src) && is_link_local(dst) {
        let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
        let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
        w.write(0, 1)?;
        w.write(src_iid as u128, 64)?;
        w.write(dst_iid as u128, 64)?;
    } else {
        let src_int = u128::from_be_bytes(*src);
        let dst_int = u128::from_be_bytes(*dst);
        w.write(1, 1)?;
        w.write(src_int, 128)?;
        w.write(dst_int, 128)?;
    }
    Ok(())
}

/// Read SCHC-compressed address fields, returning `(src, dst)` as 16-byte arrays.
///
/// `rule_id` determines whether addresses are link-local (IID only) or full 128-bit.
fn read_compressed_addrs(r: &mut BitReader, rule_id: u8) -> Result<([u8; 16], [u8; 16]), SchcError> {
    if rule_id == RULE_LINK_LOCAL_COAP {
        let src_iid = r.read(64)?;
        let dst_iid = r.read(64)?;
        Ok((
            (LINK_LOCAL_PREFIX | src_iid).to_be_bytes(),
            (LINK_LOCAL_PREFIX | dst_iid).to_be_bytes(),
        ))
    } else {
        let src_int = r.read(128)?;
        let dst_int = r.read(128)?;
        Ok((src_int.to_be_bytes(), dst_int.to_be_bytes()))
    }
}

/// Read SCHC-compressed address fields prefixed by a 1-bit address-mode, returning
/// `(src, dst)` as 16-byte arrays.
fn read_compressed_addrs_with_mode(r: &mut BitReader) -> Result<([u8; 16], [u8; 16]), SchcError> {
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
    if (addr_mode == 0) != (is_link_local(&src) && is_link_local(&dst)) {
        return Err(SchcError::NoMatchingRule);
    }
    Ok((src, dst))
}

fn compress_coap(packet: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    if packet.len() < 40 + 8 + 4 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields (see layout comment above)
    let hop_limit = packet[7];
    let src: &[u8; 16] = packet[8..24].try_into().unwrap();
    let dst: &[u8; 16] = packet[24..40].try_into().unwrap();
    // UDP header starts immediately after IPv6
    let udp = &packet[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let coap = &udp[8..];
    let coap_type = (coap[0] >> 4) & 0x3;
    let coap_tkl = coap[0] & 0x0F;
    let coap_code = coap[1];
    let coap_mid = u16::from_be_bytes([coap[2], coap[3]]);
    let tail = &coap[4..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = rule_id;

    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    write_compressed_addrs(&mut w, rule_id, src, dst)?;

    w.write(src_port as u128, 16)?;
    w.write(dst_port as u128, 16)?;
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
    let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
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
    let dodagid = u128::from_be_bytes(rpl[8..24].try_into().unwrap());
    let tail = &rpl[24..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_RPL_DIO;
    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
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
    let seq = rpl[3];
    let dodagid = u128::from_be_bytes(rpl[4..20].try_into().unwrap());
    let tail = &rpl[20..];

    if out.is_empty() {
        return Err(BufferTooSmall::new(1, 0).into());
    }
    out[0] = RULE_RPL_DAO;
    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;
    let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
    let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
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

/// Rule 5: IPv6 + UDP with port 10883 (MQTT-SN).
///
/// Matches when either source or destination port is 10883. IPv6 addresses
/// are compressed the same as Rule 0/1 (link-local IID only vs full global).
/// The port that is NOT 10883 is sent as 16-bit residue; port 10883 is NOT_SENT.
fn compress_mqtt_sn(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    ensure_ipv6(packet)?;
    // 40 (IPv6) + 8 (UDP header) minimum
    if packet.len() < 40 + 8 {
        return Err(SchcError::NoMatchingRule);
    }
    // IPv6 header fields
    let hop_limit = packet[7];
    let src: &[u8; 16] = packet[8..24].try_into().unwrap();
    let dst: &[u8; 16] = packet[24..40].try_into().unwrap();
    // UDP header starts immediately after IPv6
    let udp = &packet[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

    // Must match port 10883 on at least one side
    if src_port != PORT_MQTT_SN && dst_port != PORT_MQTT_SN {
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
    write_compressed_addrs_with_mode(&mut w, src, dst)?;

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
    let (src, dst) = read_compressed_addrs(&mut r, rule_id)?;

    let src_port = r.read(16)? as u16;
    let dst_port = r.read(16)? as u16;
    let coap_type = r.read(2)? as u8;
    let coap_tkl = r.read(4)? as u8;
    let coap_code = r.read(8)? as u8;
    let coap_mid = r.read(16)? as u16;

    let tail = &data[1 + r.residue_byte_end()..];

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
    let (src, dst) = read_compressed_addrs_with_mode(&mut r)?;

    let direction = r.read(1)? as u8;
    let other_port = r.read(16)? as u16;

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

/// Compress a full IPv6 `packet` into `out` using the best matching SCHC rule.
///
/// Falls back to rule 255 (uncompressed: rule byte + raw packet) if no rule
/// matches. Returns the number of bytes written to `out`.
pub fn compress(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        // Not IPv6 — uncompressed fallback (saturating_add prevents usize overflow)
        let needed = packet.len().saturating_add(1);
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = RULE_UNCOMPRESSED;
        out[1..needed].copy_from_slice(packet);
        return Ok(needed);
    }

    let nh = packet[6];
    let src = &packet[8..24];
    let dst = &packet[24..40];

    if nh == 17 {
        // UDP — try MQTT-SN (rule 5) first if port matches, then CoAP (rules 0/1)
        if packet.len() >= 40 + 8 {
            let src_port = u16::from_be_bytes([packet[40], packet[41]]);
            let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
            if src_port == PORT_MQTT_SN || dst_port == PORT_MQTT_SN {
                if let Ok(n) = compress_mqtt_sn(packet, out) {
                    return Ok(n);
                }
            }
        }
        if is_link_local(src) && is_link_local(dst) {
            if let Ok(n) = compress_coap(packet, out, RULE_LINK_LOCAL_COAP) {
                return Ok(n);
            }
        }
        if let Ok(n) = compress_coap(packet, out, RULE_GLOBAL_COAP) {
            return Ok(n);
        }
    } else if nh == 58 && packet.len() >= 40 + 4 {
        // ICMPv6
        let icmp_type = packet[40];
        let icmp_code = packet[41];

        if (icmp_type == 128 || icmp_type == 129)
            && icmp_code == 0
            && is_link_local(src)
            && is_link_local(dst)
            && packet.len() >= 40 + 8
        {
            if let Ok(n) = compress_icmpv6_echo(packet, out) {
                return Ok(n);
            }
        } else if icmp_type == 155 && is_link_local(src) && is_link_local(dst) {
            if icmp_code == 1 && packet.len() >= 40 + 4 + 24 {
                // DIO
                if let Ok(n) = compress_rpl_dio(packet, out) {
                    return Ok(n);
                }
            } else if icmp_code == 2 && packet.len() >= 40 + 4 + 20 {
                // DAO — only rule 4 if D flag set
                // packet[45] = offset 40 (IPv6) + 4 (ICMPv6 header) + 1 (instance) = K/D/flags byte
                let kd_flags = packet[45];
                if kd_flags & 0x40 != 0 {
                    if let Ok(n) = compress_rpl_dao(packet, out) {
                        return Ok(n);
                    }
                }
            }
        }
    }

    // Uncompressed fallback (saturating_add prevents usize overflow)
    let needed = packet.len().saturating_add(1);
    if out.len() < needed {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[0] = RULE_UNCOMPRESSED;
    out[1..needed].copy_from_slice(packet);
    Ok(needed)
}

/// Decompress a SCHC packet back into a full IPv6 datagram.
///
/// Returns the number of bytes written to `out`.
pub fn decompress(data: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if data.is_empty() {
        return Err(TooShort::new(1, 0).into());
    }
    match data[0] {
        RULE_LINK_LOCAL_COAP => decompress_coap(data, out, RULE_LINK_LOCAL_COAP),
        RULE_GLOBAL_COAP => decompress_coap(data, out, RULE_GLOBAL_COAP),
        RULE_ICMPV6_ECHO => decompress_icmpv6_echo(data, out),
        RULE_RPL_DIO => decompress_rpl_dio(data, out),
        RULE_RPL_DAO => decompress_rpl_dao(data, out),
        RULE_MQTT_SN => decompress_mqtt_sn(data, out, RULE_MQTT_SN),
        RULE_UNCOMPRESSED => {
            let payload = &data[1..];
            if out.len() < payload.len() {
                return Err(BufferTooSmall::new(payload.len(), out.len()).into());
            }
            out[..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }
        id => Err(SchcError::UnknownRuleId(id)),
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

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
        round_trip(
            "6000000000131140fe800000000000000000000000000001\
             fe80000000000000000000000000000216331633001328dd\
             40011234ff737461747573",
            "00400000000000000001000000000000000216331633000448d0\
             ff737461747573",
            0,
        );
    }

    #[test]
    fn vector_coap_global() {
        round_trip(
            "600000000013114020010db8000000000000000000000001\
             20010db800000000000000000000000216331633001\
             3ca6c40011234ff737461747573",
            "014020010db800000000000000000000000120010db8000000\
             00000000000000000216331633000448d0ff737461747573",
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
        assert_eq!(comp_buf[0], RULE_MQTT_SN, "should use rule 5 for MQTT-SN");

        // Decompress
        let mut decomp_buf = [0u8; 256];
        let m = decompress(&comp_buf[..n], &mut decomp_buf).unwrap();
        assert_eq!(&decomp_buf[..m], packet, "round-trip should match");
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
    fn uncompressed_fallback() {
        let packet = hex("deadbeef");
        let mut buf = [0u8; 8];
        let n = compress(&packet, &mut buf).unwrap();
        assert_eq!(buf[0], 255);
        assert_eq!(&buf[1..n], packet.as_slice());

        let mut out = [0u8; 8];
        let m = decompress(&buf[..n], &mut out).unwrap();
        assert_eq!(&out[..m], packet.as_slice());
    }

    #[test]
    fn non_ipv6_falls_back_to_rule_255() {
        let raw = hex("deadbeef");
        let mut buf = [0u8; 8];
        compress(&raw, &mut buf).unwrap();
        assert_eq!(buf[0], RULE_UNCOMPRESSED);
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
}
