//! SCHC compress/decompress (RFC 8724) — rules 0-4 + uncompressed fallback.
//!
//! `compress(packet, out)` → residue bytes written into `out`.
//! `decompress(data, out)` → reconstructed IPv6 packet written into `out`.
//!
//! Bit order: MSB-first (network bit order). The residue is zero-padded to
//! a byte boundary. All computation is no_std.

use lichen_core::constants::{
    RULE_GLOBAL_COAP, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP, RULE_RPL_DAO, RULE_RPL_DIO,
    RULE_UNCOMPRESSED,
};

/// Error returned by compression/decompression.
#[derive(Debug, PartialEq, Eq)]
pub enum SchcError {
    /// No rule matched the packet headers.
    NoMatchingRule,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The rule ID in the compressed data is unknown.
    UnknownRuleId(u8),
    /// The compressed data is truncated.
    Truncated,
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
        for i in (0..nbits).rev() {
            let bit = ((value >> i) & 1) as u8;
            let byte_pos = self.nbits / 8;
            let bit_pos = 7 - (self.nbits % 8);
            if byte_pos >= self.buf.len() {
                return Err(SchcError::BufferTooSmall);
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
        if self.pos + nbits > self.buf.len() * 8 {
            return Err(SchcError::Truncated);
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
    let mut i = 0;
    while i + 1 < data.len() {
        sum = oc_add(sum, u16::from_be_bytes([data[i], data[i + 1]]) as u32);
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum = oc_add(sum, (data[data.len() - 1] as u32) << 8);
    }
    sum
}

fn pseudo_sum(src: &[u8], dst: &[u8], next_header: u8, length: u16) -> u32 {
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([src[i], src[i + 1]]) as u32);
    }
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([dst[i], dst[i + 1]]) as u32);
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

fn udp_checksum(src: &[u8], dst: &[u8], src_port: u16, dst_port: u16, payload: &[u8]) -> u16 {
    let udp_len = (8 + payload.len()) as u16;
    let mut sum = pseudo_sum(src, dst, 17, udp_len);
    sum = oc_add(sum, src_port as u32);
    sum = oc_add(sum, dst_port as u32);
    sum = oc_add(sum, udp_len as u32);
    // checksum field (0 during computation)
    sum = oc_add(sum, checksum_bytes(payload));
    finalize(sum)
}

fn icmpv6_checksum(src: &[u8], dst: &[u8], icmpv6_payload: &[u8]) -> u16 {
    let length = icmpv6_payload.len() as u16;
    let mut sum = pseudo_sum(src, dst, 58, length);
    sum = oc_add(sum, checksum_bytes(icmpv6_payload));
    finalize(sum)
}

// ─── per-rule compress ────────────────────────────────────────────────────────

/// Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
fn compress_coap(packet: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    if packet.len() < 40 + 8 + 4 {
        return Err(SchcError::NoMatchingRule);
    }
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
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
        return Err(SchcError::BufferTooSmall);
    }
    out[0] = rule_id;

    let mut w = BitWriter::new(&mut out[1..]);
    w.write(hop_limit as u128, 8)?;

    if rule_id == RULE_LINK_LOCAL_COAP {
        let src_iid = u64::from_be_bytes(src[8..16].try_into().unwrap());
        let dst_iid = u64::from_be_bytes(dst[8..16].try_into().unwrap());
        w.write(src_iid as u128, 64)?;
        w.write(dst_iid as u128, 64)?;
    } else {
        let src_int = u128::from_be_bytes(src.try_into().unwrap());
        let dst_int = u128::from_be_bytes(dst.try_into().unwrap());
        w.write(src_int, 128)?;
        w.write(dst_int, 128)?;
    }

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
        return Err(SchcError::BufferTooSmall);
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 2: link-local IPv6 + ICMPv6 Echo.
fn compress_icmpv6_echo(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if packet.len() < 40 + 8 {
        return Err(SchcError::NoMatchingRule);
    }
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    let icmp = &packet[40..];
    let icmp_type = icmp[0];
    let icmp_id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let icmp_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let tail = &icmp[8..];

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
        return Err(SchcError::BufferTooSmall);
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 3: link-local IPv6 + ICMPv6 RPL DIO.
fn compress_rpl_dio(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if packet.len() < 40 + 4 + 24 {
        return Err(SchcError::NoMatchingRule);
    }
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    let rpl = &packet[44..]; // skip ICMPv6 type/code/checksum (4 bytes)
    let instance = rpl[0];
    let version = rpl[1];
    let rank = u16::from_be_bytes([rpl[2], rpl[3]]);
    let gmop = rpl[4];
    let dtsn = rpl[5];
    // flags (rpl[6]) and reserved (rpl[7]) are NOT_SENT (both expected to be 0)
    let dodagid = u128::from_be_bytes(rpl[8..24].try_into().unwrap());
    let tail = &rpl[24..];

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
        return Err(SchcError::BufferTooSmall);
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

/// Rule 4: link-local IPv6 + ICMPv6 RPL DAO with DODAGID.
fn compress_rpl_dao(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if packet.len() < 40 + 4 + 20 {
        return Err(SchcError::NoMatchingRule);
    }
    let hop_limit = packet[7];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    let rpl = &packet[44..];
    let instance = rpl[0];
    let kd_flags = rpl[1];
    // reserved (rpl[2]) is NOT_SENT
    let seq = rpl[3];
    let dodagid = u128::from_be_bytes(rpl[4..20].try_into().unwrap());
    let tail = &rpl[20..];

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
        return Err(SchcError::BufferTooSmall);
    }
    out[tail_start..needed].copy_from_slice(tail);
    Ok(needed)
}

// ─── per-rule decompress ──────────────────────────────────────────────────────

fn decompress_coap(data: &[u8], out: &mut [u8], rule_id: u8) -> Result<usize, SchcError> {
    let mut r = BitReader::new(&data[1..]);

    let hop_limit = r.read(8)? as u8;

    let (src_int, dst_int) = if rule_id == RULE_LINK_LOCAL_COAP {
        let src_iid = r.read(64)?;
        let dst_iid = r.read(64)?;
        (
            (0xFE80_0000_0000_0000_u128 << 64) | src_iid,
            (0xFE80_0000_0000_0000_u128 << 64) | dst_iid,
        )
    } else {
        (r.read(128)?, r.read(128)?)
    };

    let src_port = r.read(16)? as u16;
    let dst_port = r.read(16)? as u16;
    let coap_type = r.read(2)? as u8;
    let coap_tkl = r.read(4)? as u8;
    let coap_code = r.read(8)? as u8;
    let coap_mid = r.read(16)? as u16;

    let tail = &data[1 + r.residue_byte_end()..];

    let src = src_int.to_be_bytes();
    let dst = dst_int.to_be_bytes();
    let coap_b0 = (1u8 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F);
    let coap_len = 4 + tail.len();
    let udp_len = (8 + coap_len) as u16;

    // Build CoAP bytes for checksum
    let mut coap_buf = [0u8; 1500];
    coap_buf[0] = coap_b0;
    coap_buf[1] = coap_code;
    coap_buf[2] = (coap_mid >> 8) as u8;
    coap_buf[3] = coap_mid as u8;
    coap_buf[4..4 + tail.len()].copy_from_slice(tail);
    let coap_slice = &coap_buf[..coap_len];

    let udp_cksum = udp_checksum(&src, &dst, src_port, dst_port, coap_slice);
    let ipv6_payload_len = udp_len;
    let total = 40 + 8 + coap_len;
    if total > out.len() {
        return Err(SchcError::BufferTooSmall);
    }

    // IPv6 header
    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (ipv6_payload_len >> 8) as u8;
    out[5] = ipv6_payload_len as u8;
    out[6] = 17; // UDP
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src);
    out[24..40].copy_from_slice(&dst);

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

    let src = ((0xFE80_0000_0000_0000_u128 << 64) | src_iid).to_be_bytes();
    let dst = ((0xFE80_0000_0000_0000_u128 << 64) | dst_iid).to_be_bytes();

    // ICMPv6 payload: type(1) code(1) cksum(2) id(2) seq(2) + tail
    let icmp_body_len = 4 + tail.len(); // after checksum, reuse buf
    let icmp_len = 8 + tail.len();
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(SchcError::BufferTooSmall);
    }

    // Build ICMPv6 with zero checksum for computation
    let mut icmp_buf = [0u8; 1500];
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

    // IPv6 header
    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (icmp_len >> 8) as u8;
    out[5] = icmp_len as u8;
    out[6] = 58; // ICMPv6
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src);
    out[24..40].copy_from_slice(&dst);

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

    let _ = icmp_body_len; // suppress unused warning
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

    let src = ((0xFE80_0000_0000_0000_u128 << 64) | src_iid).to_be_bytes();
    let dst = ((0xFE80_0000_0000_0000_u128 << 64) | dst_iid).to_be_bytes();

    // RPL DIO base (24 bytes) + tail
    let rpl_body_len = 24 + tail.len();
    let icmp_len = 4 + rpl_body_len; // type+code+cksum + body
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(SchcError::BufferTooSmall);
    }

    let mut icmp_buf = [0u8; 512];
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

    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (icmp_len >> 8) as u8;
    out[5] = icmp_len as u8;
    out[6] = 58;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src);
    out[24..40].copy_from_slice(&dst);
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

    let src = ((0xFE80_0000_0000_0000_u128 << 64) | src_iid).to_be_bytes();
    let dst = ((0xFE80_0000_0000_0000_u128 << 64) | dst_iid).to_be_bytes();

    let rpl_body_len = 20 + tail.len();
    let icmp_len = 4 + rpl_body_len;
    let total = 40 + icmp_len;
    if total > out.len() {
        return Err(SchcError::BufferTooSmall);
    }

    let mut icmp_buf = [0u8; 512];
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

    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (icmp_len >> 8) as u8;
    out[5] = icmp_len as u8;
    out[6] = 58;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src);
    out[24..40].copy_from_slice(&dst);
    out[40..40 + icmp_len].copy_from_slice(icmp_slice);
    out[42] = (cksum >> 8) as u8;
    out[43] = cksum as u8;

    Ok(total)
}

// ─── public API ──────────────────────────────────────────────────────────────

/// Compress a full IPv6 `packet` into `out` using the best matching SCHC rule.
///
/// Falls back to rule 255 (uncompressed: rule byte + raw packet) if no rule
/// matches. Returns the number of bytes written to `out`.
pub fn compress(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        // Not IPv6 — uncompressed fallback
        let needed = 1 + packet.len();
        if out.len() < needed {
            return Err(SchcError::BufferTooSmall);
        }
        out[0] = RULE_UNCOMPRESSED;
        out[1..needed].copy_from_slice(packet);
        return Ok(needed);
    }

    let nh = packet[6];
    let src = &packet[8..24];
    let dst = &packet[24..40];

    if nh == 17 {
        // UDP — rules 0 or 1
        if is_link_local(src) && is_link_local(dst) {
            if let Ok(n) = compress_coap(packet, out, RULE_LINK_LOCAL_COAP) {
                return Ok(n);
            }
        } else if is_global(src) && is_global(dst) {
            if let Ok(n) = compress_coap(packet, out, RULE_GLOBAL_COAP) {
                return Ok(n);
            }
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
                let kd_flags = packet[45]; // rpl[1] in DAO base
                if kd_flags & 0x40 != 0 {
                    if let Ok(n) = compress_rpl_dao(packet, out) {
                        return Ok(n);
                    }
                }
            }
        }
    }

    // Uncompressed fallback
    let needed = 1 + packet.len();
    if out.len() < needed {
        return Err(SchcError::BufferTooSmall);
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
        return Err(SchcError::Truncated);
    }
    match data[0] {
        RULE_LINK_LOCAL_COAP => decompress_coap(data, out, RULE_LINK_LOCAL_COAP),
        RULE_GLOBAL_COAP => decompress_coap(data, out, RULE_GLOBAL_COAP),
        RULE_ICMPV6_ECHO => decompress_icmpv6_echo(data, out),
        RULE_RPL_DIO => decompress_rpl_dio(data, out),
        RULE_RPL_DAO => decompress_rpl_dao(data, out),
        RULE_UNCOMPRESSED => {
            let payload = &data[1..];
            if out.len() < payload.len() {
                return Err(SchcError::BufferTooSmall);
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
