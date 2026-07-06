//! IPv6 upper-layer checksum (RFC 1071, RFC 8200).
//!
//! Provides the one's-complement checksum used by UDP, ICMPv6, and other
//! IPv6 upper-layer protocols. The checksum covers the IPv6 pseudo-header
//! (source, destination, length, next-header) plus the upper-layer payload.

/// One's-complement addition with carry.
#[inline]
fn oc_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >> 16 != 0 {
        (s & 0xFFFF) + (s >> 16)
    } else {
        s
    }
}

/// Sum 16-bit words from a byte slice (with carry folding).
#[inline]
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

/// Compute the IPv6 upper-layer checksum.
///
/// This implements RFC 1071 one's-complement checksum over the IPv6
/// pseudo-header (RFC 8200 section 8.1) plus the upper-layer payload.
///
/// # Arguments
/// * `src` - Source IPv6 address (16 bytes)
/// * `dst` - Destination IPv6 address (16 bytes)
/// * `next_header` - IPv6 next header value (e.g., 17 for UDP, 58 for ICMPv6)
/// * `payload` - Upper-layer payload (header + data, with checksum field zeroed)
///
/// # Returns
/// The 16-bit one's-complement checksum (inverted).
pub fn upper_layer_checksum(src: &[u8; 16], dst: &[u8; 16], next_header: u8, payload: &[u8]) -> u16 {
    // IPv6 pseudo-header: src + dst + upper-layer-length + zeros + next-header
    let mut sum: u32 = 0;

    // Add source address (8 words)
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([src[i], src[i + 1]]) as u32);
    }
    // Add destination address (8 words)
    for i in (0..16).step_by(2) {
        sum = oc_add(sum, u16::from_be_bytes([dst[i], dst[i + 1]]) as u32);
    }
    // Upper-layer length (32 bits, only low 16 bits nonzero for normal packets)
    sum = oc_add(sum, payload.len() as u32);
    // Next header
    sum = oc_add(sum, next_header as u32);

    // Add payload
    sum = oc_add(sum, sum_words(payload));

    // Fold to 16 bits and invert
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Link-local address helper for tests.
    fn ll(iid: u8) -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid]
    }

    #[test]
    fn checksum_is_nonzero() {
        let src = ll(1);
        let dst = ll(2);
        // Minimal payload: just some bytes
        let payload = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]; // ICMPv6 echo request header
        let csum = upper_layer_checksum(&src, &dst, 58, &payload);
        assert_ne!(csum, 0);
    }

    #[test]
    fn checksum_is_deterministic() {
        let src = ll(1);
        let dst = ll(2);
        let payload = b"test payload data";
        let csum1 = upper_layer_checksum(&src, &dst, 17, payload);
        let csum2 = upper_layer_checksum(&src, &dst, 17, payload);
        assert_eq!(csum1, csum2);
    }

    #[test]
    fn different_next_header_gives_different_checksum() {
        let src = ll(1);
        let dst = ll(2);
        let payload = b"same payload";
        let csum_udp = upper_layer_checksum(&src, &dst, 17, payload);
        let csum_icmp = upper_layer_checksum(&src, &dst, 58, payload);
        assert_ne!(csum_udp, csum_icmp);
    }

    #[test]
    fn empty_payload() {
        let src = ll(1);
        let dst = ll(2);
        let csum = upper_layer_checksum(&src, &dst, 17, &[]);
        // Should compute checksum over just the pseudo-header
        assert_ne!(csum, 0);
    }

    #[test]
    fn odd_length_payload() {
        let src = ll(1);
        let dst = ll(2);
        // Odd-length payload to test padding logic
        let payload = [0x01, 0x02, 0x03];
        let csum = upper_layer_checksum(&src, &dst, 17, &payload);
        assert_ne!(csum, 0);
    }
}
