//! ICMPv6 Echo packet builder (no_std, no allocation).
//!
//! Builds full IPv6 + ICMPv6 Echo Request / Reply packets in a caller-supplied
//! buffer. The IPv6 pseudo-header checksum is computed automatically.

use crate::addr::Ipv6Addr;
use crate::checksum::upper_layer_checksum;
use crate::ipv6::{next_header, IPV6_HEADER_LEN};

/// ICMPv6 fixed header length (type, code, checksum, message body).
pub const ICMPV6_HEADER_LEN: usize = 8;

/// ICMPv6 header field offsets (relative to ICMPv6 header start).
pub mod hdr_field {
    /// Offset of ICMPv6 type byte.
    pub const TYPE_OFFSET: usize = 0;
    /// Offset of ICMPv6 code byte.
    pub const CODE_OFFSET: usize = 1;
    /// Offset of ICMPv6 message body (after type, code, checksum).
    pub const BODY_OFFSET: usize = 4;
}

/// ICMPv6 Echo message field offsets (relative to ICMPv6 header start).
pub mod echo_field {
    /// Offset of echo identifier (2 bytes, relative to ICMPv6 header).
    pub const ID_OFFSET: usize = 4;
    /// Offset of echo sequence number (2 bytes, relative to ICMPv6 header).
    pub const SEQ_OFFSET: usize = 6;
    /// Offset of echo data (relative to ICMPv6 header).
    pub const DATA_OFFSET: usize = 8;
}

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
    let icmpv6_len = ICMPV6_HEADER_LEN + data.len();
    let total = IPV6_HEADER_LEN + icmpv6_len;

    // IPv6 fixed header (40 bytes)
    out[0] = 0x60; // version=6, TC=0, flow=0
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
    out[6] = next_header::ICMPV6;
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
    let csum = upper_layer_checksum(&src.0, &dst.0, next_header::ICMPV6, &out[40..total]);
    out[42..44].copy_from_slice(&csum.to_be_bytes());

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Ipv6Addr;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
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
