// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Deterministic 16-bit short-address derivation.
//!
//! Short addresses use CRC32-IEEE/ISO-HDLC with the low 32 bits of ASCII
//! `"LICHEN"` as the initial value. This is intentionally different from the
//! FNV-1a hash used for channel, slot, and spreading-factor selection.

/// Fixed high-order bytes of an RFC 4944 short-address IID.
pub const SHORT_ADDR_IID_PREFIX: [u8; 6] = [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00];

/// Null/unspecified short address, which cannot identify a unicast peer.
pub const SHORT_ADDR_RESERVED_NULL: u16 = 0x0000;

/// IEEE 802.15.4 unspecified short address.
pub const SHORT_ADDR_RESERVED_UNSPECIFIED: u16 = 0xfffe;

/// IEEE 802.15.4 broadcast short address.
pub const SHORT_ADDR_RESERVED_BROADCAST: u16 = 0xffff;

/// Low 32 bits of the historical ASCII `"LICHEN"` initializer.
pub const LICHEN_CRC32_INITIAL: u32 = 0x4348_454e;

/// Return whether a short address is reserved rather than peer-addressable.
pub const fn is_reserved_short_addr(short_addr: u16) -> bool {
    matches!(
        short_addr,
        SHORT_ADDR_RESERVED_NULL | SHORT_ADDR_RESERVED_UNSPECIFIED | SHORT_ADDR_RESERVED_BROADCAST
    )
}

/// Map a 16-bit short address to its RFC 4944 interface identifier.
///
/// The returned bytes are exactly `0000:00ff:fe00:XXXX`, with `short_addr`
/// encoded big-endian in the final two bytes. This mechanical mapping is
/// defined for every `u16`; protocol callers must reject values identified by
/// [`is_reserved_short_addr`] when resolving a unicast peer.
pub const fn short_addr_to_iid(short_addr: u16) -> [u8; 8] {
    let [high, low] = short_addr.to_be_bytes();
    [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, high, low]
}

/// Parse an RFC 4944 short-address IID back into its 16-bit address.
///
/// Returns `None` for a wrong length or non-canonical prefix. Reserved values
/// are returned intact so callers can distinguish malformed input from a
/// well-formed but non-unicast short address.
pub fn short_addr_from_iid(iid: &[u8]) -> Option<u16> {
    if iid.len() != 8 || !iid.starts_with(&SHORT_ADDR_IID_PREFIX) {
        return None;
    }
    Some(u16::from_be_bytes([iid[6], iid[7]]))
}

/// Compute reflected CRC32-IEEE/ISO-HDLC with a caller-provided initial value.
///
/// This matches `binascii.crc32(data, initial)`: the register is complemented
/// before and after processing, and each input octet is processed least-
/// significant bit first with reflected polynomial `0xedb88320`.
pub fn crc32_ieee(data: &[u8], initial: u32) -> u32 {
    let mut crc = initial ^ u32::MAX;

    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }

    crc ^ u32::MAX
}

/// Derive the mesh-local 16-bit short address for an EUI-64.
///
/// The low 16 bits are returned exactly as derived. Reserved-address handling
/// belongs to Duplicate Address Detection (DAD), which can retry with a seed.
pub fn derive_short_addr(eui64: &[u8; 8]) -> u16 {
    crc32_ieee(eui64, LICHEN_CRC32_INITIAL) as u16
}

/// Derive a deterministic DAD retry candidate by mixing `seed` into the EUI-64.
///
/// The little-endian seed bytes are XORed into EUI-64 bytes 4 through 7 before
/// applying the same CRC32 derivation as [`derive_short_addr`].
pub fn derive_short_addr_with_seed(eui64: &[u8; 8], seed: u32) -> u16 {
    let mut mixed = *eui64;
    let seed_bytes = seed.to_le_bytes();
    for (byte, seed_byte) in mixed[4..].iter_mut().zip(seed_bytes) {
        *byte ^= seed_byte;
    }
    derive_short_addr(&mixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_iso_hdlc_check_value() {
        assert_eq!(crc32_ieee(b"123456789", 0), 0xcbf4_3926);
    }

    #[test]
    fn derives_canonical_short_address() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(derive_short_addr(&eui64), 0x056e);
    }

    #[test]
    fn seed_is_mixed_little_endian() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(derive_short_addr_with_seed(&eui64, 1), 0x620b);
        assert_eq!(
            derive_short_addr_with_seed(&eui64, 0),
            derive_short_addr(&eui64)
        );
    }

    #[test]
    fn short_address_iid_mapping_is_big_endian() {
        assert_eq!(short_addr_to_iid(0x0001), [0, 0, 0, 0xff, 0xfe, 0, 0, 1]);
        assert_eq!(
            short_addr_to_iid(0xabcd),
            [0, 0, 0, 0xff, 0xfe, 0, 0xab, 0xcd]
        );
    }

    #[test]
    fn short_address_iid_parser_roundtrips_boundaries() {
        for short_addr in [0x0000, 0x0001, 0xabcd, 0xfffd, 0xfffe, 0xffff] {
            let iid = short_addr_to_iid(short_addr);
            assert_eq!(short_addr_from_iid(&iid), Some(short_addr));
        }

        assert_eq!(short_addr_from_iid(&[0; 7]), None);
        assert_eq!(short_addr_from_iid(&[0; 9]), None);
        assert_eq!(short_addr_from_iid(&[0, 0, 0, 0xff, 0xff, 0, 0, 1]), None);
    }

    #[test]
    fn reserved_short_addresses_are_explicit() {
        assert!(is_reserved_short_addr(SHORT_ADDR_RESERVED_NULL));
        assert!(is_reserved_short_addr(SHORT_ADDR_RESERVED_UNSPECIFIED));
        assert!(is_reserved_short_addr(SHORT_ADDR_RESERVED_BROADCAST));
        assert!(!is_reserved_short_addr(0x0001));
        assert!(!is_reserved_short_addr(0xfffd));
    }
}
