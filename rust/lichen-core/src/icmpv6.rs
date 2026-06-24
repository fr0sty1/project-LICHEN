//! ICMPv6 Echo packet builder (no_std, no allocation).
//!
//! Builds full IPv6 + ICMPv6 Echo Request / Reply packets in a caller-supplied
//! buffer. The IPv6 pseudo-header checksum is computed automatically.

use crate::addr::Ipv6Addr;

/// ICMPv6 Echo Request type byte.
pub const ECHO_REQUEST: u8 = 128;
/// ICMPv6 Echo Reply type byte.
pub const ECHO_REPLY: u8 = 129;

/// Build an ICMPv6 Echo Request packet into `out`.
///
/// `out` must be at least `48 + data.len()` bytes. Returns bytes written.
pub fn echo_request(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    id: u16,
    seq: u16,
    data: &[u8],
    out: &mut [u8],
) -> usize {
    build(ECHO_REQUEST, src, dst, id, seq, data, out)
}

/// Build an ICMPv6 Echo Reply packet into `out`.
///
/// `out` must be at least `48 + data.len()` bytes. Returns bytes written.
pub fn echo_reply(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    id: u16,
    seq: u16,
    data: &[u8],
    out: &mut [u8],
) -> usize {
    build(ECHO_REPLY, src, dst, id, seq, data, out)
}

fn build(
    icmp_type: u8,
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    id: u16,
    seq: u16,
    data: &[u8],
    out: &mut [u8],
) -> usize {
    let icmpv6_len = 8 + data.len();
    let total = 40 + icmpv6_len;

    // IPv6 fixed header (40 bytes)
    out[0] = 0x60; // version=6, TC=0, flow=0
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
    out[6] = 58; // next header = ICMPv6
    out[7] = 64; // hop limit
    out[8..24].copy_from_slice(&src.0);
    out[24..40].copy_from_slice(&dst.0);

    // ICMPv6 header — checksum zero for now
    out[40] = icmp_type;
    out[41] = 0; // code
    out[42] = 0; // checksum (placeholder)
    out[43] = 0;
    out[44..46].copy_from_slice(&id.to_be_bytes());
    out[46..48].copy_from_slice(&seq.to_be_bytes());
    out[48..total].copy_from_slice(data);

    // Compute and fill in checksum
    let csum = icmpv6_checksum(&src.0, &dst.0, &out[40..total]);
    out[42..44].copy_from_slice(&csum.to_be_bytes());

    total
}

// ── One's-complement checksum (RFC 1071) ────────────────────────────────────

fn oc_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >> 16 != 0 {
        (s & 0xFFFF) + (s >> 16)
    } else {
        s
    }
}

fn sum_words(data: &[u8]) -> u32 {
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

/// ICMPv6 checksum over IPv6 pseudo-header + ICMPv6 payload.
///
/// `icmpv6_payload` must include the ICMPv6 header with checksum field
/// already zeroed. `src` and `dst` are 16-byte IPv6 addresses.
fn icmpv6_checksum(src: &[u8], dst: &[u8], icmpv6_payload: &[u8]) -> u16 {
    // Pseudo-header: src + dst + upper-layer length + zeros + next-header=58
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([src[i], src[i + 1]]) as u32);
    }
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([dst[i], dst[i + 1]]) as u32);
    }
    sum = oc_add(sum, icmpv6_payload.len() as u32);
    sum = oc_add(sum, 58u32); // next header

    sum = oc_add(sum, sum_words(icmpv6_payload));

    // Fold 32-bit sum to 16 bits and invert
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Ipv6Addr;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid,
        ])
    }

    #[test]
    fn echo_request_has_correct_headers() {
        let mut buf = [0u8; 52];
        let n = echo_request(&ll(1), &ll(2), 0x1234, 7, b"ping", &mut buf);
        assert_eq!(n, 52);
        assert_eq!(buf[0] >> 4, 6); // version = 6
        assert_eq!(buf[6], 58); // NH = ICMPv6
        assert_eq!(buf[7], 64); // hop limit
        assert_eq!(&buf[8..24], &ll(1).0); // src
        assert_eq!(&buf[24..40], &ll(2).0); // dst
        assert_eq!(buf[40], ECHO_REQUEST);
        assert_eq!(buf[41], 0); // code
        assert_eq!(&buf[44..46], &[0x12, 0x34]); // id
        assert_eq!(&buf[46..48], &[0x00, 0x07]); // seq
        assert_eq!(&buf[48..52], b"ping"); // data
    }

    #[test]
    fn echo_reply_type_byte() {
        let mut buf = [0u8; 48];
        echo_reply(&ll(2), &ll(1), 0x1234, 7, &[], &mut buf);
        assert_eq!(buf[40], ECHO_REPLY);
    }

    #[test]
    fn checksum_is_nonzero_and_stable() {
        let mut buf = [0u8; 52];
        echo_request(&ll(1), &ll(2), 1, 1, b"test", &mut buf);
        let csum = u16::from_be_bytes([buf[42], buf[43]]);
        assert_ne!(csum, 0);
        // Rebuild — same checksum
        let mut buf2 = [0u8; 52];
        echo_request(&ll(1), &ll(2), 1, 1, b"test", &mut buf2);
        assert_eq!(buf, buf2);
    }
}
