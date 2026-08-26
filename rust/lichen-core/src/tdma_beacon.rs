//! TDMA beacon header parsing and serialization (spec 02a-coordinated-capacity.md).
//!
//! Wire format:
//! ```text
//! Offset  Field           Size    Encoding
//! 0       epoch           4       u32 BE
//! 4       num_slots       1       u8
//! 5       sfn             4       u32 BE
//! 9       timestamp       4       u32 BE
//! 13      flags           1       u8
//! 14      rx_chains       1       u8
//! 15      setup_window    2       u16 BE
//! 17      occupied_time   2       u16 BE
//! 19      guard           1       u8
//! 20      channel_mask    4       u32 BE
//! 24      cbor_options    var     (skipped for now)
//! E-48    schnorr_sig     48      Schnorr48 signature
//! ```

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 24;
/// Schnorr48 signature size.
pub const SIG_SIZE: usize = 48;
/// Minimum beacon size (header + signature, no CBOR options).
pub const MIN_BEACON_SIZE: usize = HEADER_SIZE + SIG_SIZE;

/// Derive the node's TDMA slot for one superframe.
///
/// The hash addition wraps in `u32` before the positive slot modulus, as
/// required by CCP-15 and the SFN-wrap vectors.
pub fn slot_for(eui64: &[u8; 8], sfn: u32, num_slots: u8) -> Option<u8> {
    if num_slots == 0 {
        return None;
    }
    let hash = crate::lichen_hash_32(eui64);
    Some((hash.wrapping_add(sfn) % u32::from(num_slots)) as u8)
}

/// TDMA beacon header (24 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdmaBeaconHeader {
    pub epoch: u32,
    pub num_slots: u8,
    pub sfn: u32,
    pub timestamp: u32,
    pub flags: u8,
    pub rx_chains: u8,
    pub setup_window: u16,
    pub occupied_time: u16,
    pub guard: u8,
    pub channel_mask: u32,
}

/// Beacon flags (offset 13, bits 0-3 defined, 4-7 reserved).
pub mod flags {
    pub const SCHEDULED: u8 = 0x01;
    pub const CSMA: u8 = 0x02;
    pub const CH0_RX: u8 = 0x04;
    pub const GNSS_PPS: u8 = 0x08;
    pub const RESERVED_MASK: u8 = 0xF0;
}

/// Errors from beacon header parsing/serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer too short for header.
    TooShort,
    /// Reserved flag bits (4-7) are set.
    ReservedFlagSet,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short for TDMA beacon header"),
            Self::ReservedFlagSet => write!(f, "reserved flag bits (4-7) must be zero"),
        }
    }
}

impl TdmaBeaconHeader {
    /// Parse header from bytes. Requires at least HEADER_SIZE bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < HEADER_SIZE {
            return Err(ParseError::TooShort);
        }
        let flags = data[13];
        if flags & flags::RESERVED_MASK != 0 {
            return Err(ParseError::ReservedFlagSet);
        }
        Ok(Self {
            epoch: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            num_slots: data[4],
            sfn: u32::from_be_bytes([data[5], data[6], data[7], data[8]]),
            timestamp: u32::from_be_bytes([data[9], data[10], data[11], data[12]]),
            flags,
            rx_chains: data[14],
            setup_window: u16::from_be_bytes([data[15], data[16]]),
            occupied_time: u16::from_be_bytes([data[17], data[18]]),
            guard: data[19],
            channel_mask: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }

    /// Serialize header to bytes.
    ///
    /// Returns `Err(ReservedFlagSet)` if reserved flag bits (4-7) are set.
    pub fn serialize(&self, out: &mut [u8]) -> Result<(), ParseError> {
        if out.len() < HEADER_SIZE {
            return Err(ParseError::TooShort);
        }
        if self.flags & flags::RESERVED_MASK != 0 {
            return Err(ParseError::ReservedFlagSet);
        }
        out[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        out[4] = self.num_slots;
        out[5..9].copy_from_slice(&self.sfn.to_be_bytes());
        out[9..13].copy_from_slice(&self.timestamp.to_be_bytes());
        out[13] = self.flags;
        out[14] = self.rx_chains;
        out[15..17].copy_from_slice(&self.setup_window.to_be_bytes());
        out[17..19].copy_from_slice(&self.occupied_time.to_be_bytes());
        out[19] = self.guard;
        out[20..24].copy_from_slice(&self.channel_mask.to_be_bytes());
        Ok(())
    }

    /// Check if SCHEDULED flag is set.
    pub fn is_scheduled(&self) -> bool {
        self.flags & flags::SCHEDULED != 0
    }

    /// Check if CSMA flag is set.
    pub fn is_csma(&self) -> bool {
        self.flags & flags::CSMA != 0
    }

    /// Check if GNSS PPS flag is set.
    pub fn has_gnss_pps(&self) -> bool {
        self.flags & flags::GNSS_PPS != 0
    }

    /// Check if CH0 RX flag is set.
    pub fn is_ch0_rx(&self) -> bool {
        self.flags & flags::CH0_RX != 0
    }
}

/// Extract signature bytes from a complete beacon.
/// Returns None if beacon is too short.
pub fn signature_bytes(beacon: &[u8]) -> Option<&[u8]> {
    if beacon.len() < MIN_BEACON_SIZE {
        return None;
    }
    Some(&beacon[beacon.len() - SIG_SIZE..])
}

/// Extract signed data (everything except signature) from a complete beacon.
/// Returns None if beacon is too short.
pub fn signed_data(beacon: &[u8]) -> Option<&[u8]> {
    if beacon.len() < MIN_BEACON_SIZE {
        return None;
    }
    Some(&beacon[..beacon.len() - SIG_SIZE])
}

/// Extract CBOR options bytes from a complete beacon.
/// Returns the bytes between header and signature, or None if beacon is minimal.
pub fn cbor_options(beacon: &[u8]) -> Option<&[u8]> {
    if beacon.len() <= MIN_BEACON_SIZE {
        return None;
    }
    Some(&beacon[HEADER_SIZE..beacon.len() - SIG_SIZE])
}

/// Maximum slot_map entries we'll parse (DoS prevention).
pub const MAX_SLOT_MAP_ENTRIES: usize = 64;

/// Parse slot_map from CBOR options bytes.
///
/// The slot_map is a CBOR array of u8 slot indices. This is a minimal inline
/// parser for the specific format, not a general CBOR decoder.
///
/// Returns Ok(slots) if valid, Err if malformed or validation fails.
/// Validation: each slot < num_slots, array is sorted ascending.
pub fn parse_slot_map(
    cbor: &[u8],
    num_slots: u8,
) -> Result<heapless::Vec<u8, MAX_SLOT_MAP_ENTRIES>, SlotMapError> {
    if cbor.is_empty() {
        return Ok(heapless::Vec::new());
    }

    let mut pos = 0;

    // Parse CBOR array header
    let first = cbor[pos];
    pos += 1;

    let len = if (0x80..=0x97).contains(&first) {
        // Short array: length 0-23 encoded in low 5 bits
        (first - 0x80) as usize
    } else if first == 0x98 {
        // Array with 1-byte length
        if pos >= cbor.len() {
            return Err(SlotMapError::Truncated);
        }
        let len = cbor[pos] as usize;
        pos += 1;
        len
    } else {
        // Not an array or unsupported length encoding
        return Err(SlotMapError::NotAnArray);
    };

    if len > MAX_SLOT_MAP_ENTRIES {
        return Err(SlotMapError::TooManySlots);
    }

    let mut slots = heapless::Vec::new();
    let mut prev: Option<u8> = None;

    for _ in 0..len {
        if pos >= cbor.len() {
            return Err(SlotMapError::Truncated);
        }

        let byte = cbor[pos];
        pos += 1;

        let slot = if byte <= 0x17 {
            // Immediate value 0-23
            byte
        } else if byte == 0x18 {
            // 1-byte value follows
            if pos >= cbor.len() {
                return Err(SlotMapError::Truncated);
            }
            let v = cbor[pos];
            pos += 1;
            v
        } else {
            return Err(SlotMapError::InvalidSlotEncoding);
        };

        // Validate: slot < num_slots
        if slot >= num_slots {
            return Err(SlotMapError::SlotOutOfBounds { slot, num_slots });
        }

        // Validate: sorted ascending (no duplicates)
        if let Some(p) = prev {
            if slot <= p {
                return Err(SlotMapError::NotSorted);
            }
        }
        prev = Some(slot);

        slots.push(slot).map_err(|_| SlotMapError::TooManySlots)?;
    }

    // Reject trailing garbage bytes
    if pos != cbor.len() {
        return Err(SlotMapError::TrailingBytes);
    }

    Ok(slots)
}

/// Errors from slot_map parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotMapError {
    /// CBOR data truncated.
    Truncated,
    /// First byte is not a CBOR array marker.
    NotAnArray,
    /// Array has more than MAX_SLOT_MAP_ENTRIES elements.
    TooManySlots,
    /// Slot value encoding is invalid (not u8).
    InvalidSlotEncoding,
    /// Trailing bytes after CBOR array.
    TrailingBytes,
    /// Slot index >= num_slots.
    SlotOutOfBounds { slot: u8, num_slots: u8 },
    /// Array is not sorted ascending.
    NotSorted,
}

impl core::fmt::Display for SlotMapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "CBOR data truncated"),
            Self::NotAnArray => write!(f, "expected CBOR array"),
            Self::TooManySlots => write!(f, "slot_map exceeds maximum entries"),
            Self::InvalidSlotEncoding => write!(f, "invalid CBOR encoding for slot value"),
            Self::TrailingBytes => write!(f, "trailing bytes after CBOR array"),
            Self::SlotOutOfBounds { slot, num_slots } => {
                write!(f, "slot {} >= num_slots {}", slot, num_slots)
            }
            Self::NotSorted => write!(f, "slot_map not sorted ascending"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let hdr = TdmaBeaconHeader {
            epoch: 0x12345678,
            num_slots: 16,
            sfn: 0xAABBCCDD,
            timestamp: 0x11223344,
            flags: flags::SCHEDULED | flags::GNSS_PPS,
            rx_chains: 2,
            setup_window: 100,
            occupied_time: 200,
            guard: 50,
            channel_mask: 0x0000001F,
        };
        let mut buf = [0u8; HEADER_SIZE];
        hdr.serialize(&mut buf).unwrap();
        let parsed = TdmaBeaconHeader::parse(&buf).unwrap();
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn test_parse_too_short() {
        let buf = [0u8; HEADER_SIZE - 1];
        assert_eq!(TdmaBeaconHeader::parse(&buf), Err(ParseError::TooShort));
    }

    #[test]
    fn test_reserved_flag_rejected() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[13] = 0x10; // reserved bit 4 set
        assert_eq!(
            TdmaBeaconHeader::parse(&buf),
            Err(ParseError::ReservedFlagSet)
        );
    }

    #[test]
    fn test_signature_bytes() {
        let beacon = [0u8; MIN_BEACON_SIZE];
        let sig = signature_bytes(&beacon).unwrap();
        assert_eq!(sig.len(), SIG_SIZE);
    }

    #[test]
    fn test_signed_data() {
        let beacon = [0u8; MIN_BEACON_SIZE];
        let data = signed_data(&beacon).unwrap();
        assert_eq!(data.len(), HEADER_SIZE);
    }

    #[test]
    fn test_flag_helpers() {
        let hdr = TdmaBeaconHeader {
            epoch: 0,
            num_slots: 8,
            sfn: 0,
            timestamp: 0,
            flags: flags::SCHEDULED | flags::CSMA | flags::CH0_RX,
            rx_chains: 1,
            setup_window: 0,
            occupied_time: 0,
            guard: 0,
            channel_mask: 0,
        };
        assert!(hdr.is_scheduled());
        assert!(hdr.is_csma());
        assert!(hdr.is_ch0_rx());
        assert!(!hdr.has_gnss_pps());
    }

    #[test]
    fn test_serialize_rejects_reserved_flags() {
        let hdr = TdmaBeaconHeader {
            epoch: 0,
            num_slots: 8,
            sfn: 0,
            timestamp: 0,
            flags: 0x10, // reserved bit 4
            rx_chains: 1,
            setup_window: 0,
            occupied_time: 0,
            guard: 0,
            channel_mask: 0,
        };
        let mut buf = [0u8; HEADER_SIZE];
        assert_eq!(hdr.serialize(&mut buf), Err(ParseError::ReservedFlagSet));
    }

    #[test]
    fn test_slot_map_empty() {
        // CBOR empty array: 0x80
        let cbor = [0x80];
        let slots = parse_slot_map(&cbor, 16).unwrap();
        assert!(slots.is_empty());
    }

    #[test]
    fn test_slot_map_simple() {
        // CBOR array [1, 3, 5]: 0x83 0x01 0x03 0x05
        let cbor = [0x83, 0x01, 0x03, 0x05];
        let slots = parse_slot_map(&cbor, 16).unwrap();
        assert_eq!(&slots[..], &[1, 3, 5]);
    }

    #[test]
    fn test_slot_map_value_over_23() {
        // CBOR array [24, 30]: 0x82 0x18 0x18 0x18 0x1e
        let cbor = [0x82, 0x18, 0x18, 0x18, 0x1e];
        let slots = parse_slot_map(&cbor, 64).unwrap();
        assert_eq!(&slots[..], &[24, 30]);
    }

    #[test]
    fn test_slot_map_out_of_bounds() {
        // slot 10 with num_slots=8
        let cbor = [0x81, 0x0a];
        let err = parse_slot_map(&cbor, 8).unwrap_err();
        assert_eq!(
            err,
            SlotMapError::SlotOutOfBounds {
                slot: 10,
                num_slots: 8
            }
        );
    }

    #[test]
    fn test_slot_map_not_sorted() {
        // [5, 3] not sorted
        let cbor = [0x82, 0x05, 0x03];
        let err = parse_slot_map(&cbor, 16).unwrap_err();
        assert_eq!(err, SlotMapError::NotSorted);
    }

    #[test]
    fn test_slot_map_duplicates() {
        // [3, 3] has duplicates
        let cbor = [0x82, 0x03, 0x03];
        let err = parse_slot_map(&cbor, 16).unwrap_err();
        assert_eq!(err, SlotMapError::NotSorted);
    }

    #[test]
    fn test_slot_map_truncated() {
        // Array claims 3 elements but only 2 present
        let cbor = [0x83, 0x01, 0x02];
        let err = parse_slot_map(&cbor, 16).unwrap_err();
        assert_eq!(err, SlotMapError::Truncated);
    }

    #[test]
    fn test_slot_map_not_an_array() {
        // 0x00 is CBOR uint 0, not an array
        let cbor = [0x00];
        let err = parse_slot_map(&cbor, 16).unwrap_err();
        assert_eq!(err, SlotMapError::NotAnArray);
    }

    #[test]
    fn test_slot_map_trailing_bytes() {
        // [1] followed by garbage byte 0xFF
        let cbor = [0x81, 0x01, 0xFF];
        let err = parse_slot_map(&cbor, 16).unwrap_err();
        assert_eq!(err, SlotMapError::TrailingBytes);
    }
}
