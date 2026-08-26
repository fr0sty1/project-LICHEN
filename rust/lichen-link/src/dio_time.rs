//! DIO Time Option wire codec (spec 09 section 14.6).
//!
//! Project-local provisional type 0x15; 8 bytes:
//! Type(1) + Len(1) + Stratum(1) + Reserved(1) + Timestamp(4, Unix seconds BE).

/// Provisional DIO option type (not IANA-assigned).
pub const DIO_TIME_OPTION_TYPE: u8 = 0x15;
/// Option length excluding type/len (stratum + reserved + timestamp).
pub const DIO_TIME_OPTION_LEN: u8 = 6;
/// Encoded option size.
pub const DIO_TIME_OPTION_TOTAL: usize = 8;

/// Time quality advertised in a DIO Time Option (0 = unsynchronized).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DioTimeStratum {
    /// No valid wall-clock source; timestamp MUST be zero.
    NoSync = 0,
    /// Conservative synchronized time.
    ConservativeSync = 1,
    /// Roughtime-backed network time.
    Roughtime = 2,
    /// NTS-backed network time.
    Nts = 3,
    /// GNSS or verified gpsd time.
    GnssGpsd = 4,
}

/// Failed DIO Time Option encode/decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DioTimeError {
    /// Buffer is not exactly 8 bytes.
    Truncated,
    /// Type or length byte is not 0x15 / 6.
    BadTypeOrLength,
    /// Reserved octet is not zero.
    ReservedNonzero,
    /// Stratum is outside 0..=4.
    InvalidStratum,
    /// NO_SYNC carried a non-zero timestamp.
    NoSyncTimestamp,
}

impl DioTimeError {
    /// Canonical vector token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::BadTypeOrLength => "bad-type-or-length",
            Self::ReservedNonzero => "reserved-nonzero",
            Self::InvalidStratum => "invalid-stratum",
            Self::NoSyncTimestamp => "no-sync-timestamp",
        }
    }
}

/// Encoded DIO Time Option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DioTimeOption {
    stratum: DioTimeStratum,
    timestamp: u32,
}

impl DioTimeStratum {
    /// Wire value 0..=4.
    pub const fn wire(self) -> u8 {
        self as u8
    }

    /// Parse a wire stratum.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoSync),
            1 => Some(Self::ConservativeSync),
            2 => Some(Self::Roughtime),
            3 => Some(Self::Nts),
            4 => Some(Self::GnssGpsd),
            _ => None,
        }
    }
}

impl DioTimeOption {
    /// Construct an option. NO_SYNC requires timestamp 0.
    pub const fn new(stratum: DioTimeStratum, timestamp: u32) -> Result<Self, DioTimeError> {
        if matches!(stratum, DioTimeStratum::NoSync) && timestamp != 0 {
            return Err(DioTimeError::NoSyncTimestamp);
        }
        Ok(Self { stratum, timestamp })
    }

    /// Advertised stratum.
    pub const fn stratum(self) -> DioTimeStratum {
        self.stratum
    }

    /// Unix timestamp seconds (zero when unsynchronized).
    pub const fn timestamp(self) -> u32 {
        self.timestamp
    }

    /// Encode the 8-byte option.
    pub const fn encode(self) -> [u8; DIO_TIME_OPTION_TOTAL] {
        let ts = self.timestamp.to_be_bytes();
        [
            DIO_TIME_OPTION_TYPE,
            DIO_TIME_OPTION_LEN,
            self.stratum.wire(),
            0,
            ts[0],
            ts[1],
            ts[2],
            ts[3],
        ]
    }

    /// Decode an 8-byte option.
    pub fn decode(data: &[u8]) -> Result<Self, DioTimeError> {
        if data.len() != DIO_TIME_OPTION_TOTAL {
            return Err(DioTimeError::Truncated);
        }
        if data[0] != DIO_TIME_OPTION_TYPE || data[1] != DIO_TIME_OPTION_LEN {
            return Err(DioTimeError::BadTypeOrLength);
        }
        if data[3] != 0 {
            return Err(DioTimeError::ReservedNonzero);
        }
        let stratum = DioTimeStratum::from_wire(data[2]).ok_or(DioTimeError::InvalidStratum)?;
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Self::new(stratum, timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sync_roundtrip() {
        let opt = DioTimeOption::new(DioTimeStratum::NoSync, 0).unwrap();
        let bytes = opt.encode();
        assert_eq!(bytes, [0x15, 0x06, 0, 0, 0, 0, 0, 0]);
        assert_eq!(DioTimeOption::decode(&bytes).unwrap(), opt);
        assert_eq!(
            DioTimeOption::new(DioTimeStratum::NoSync, 1),
            Err(DioTimeError::NoSyncTimestamp)
        );
    }

    #[test]
    fn rejects_bad_headers() {
        assert_eq!(DioTimeOption::decode(&[0; 7]), Err(DioTimeError::Truncated));
        assert_eq!(
            DioTimeOption::decode(&[0x14, 6, 0, 0, 0, 0, 0, 0]),
            Err(DioTimeError::BadTypeOrLength)
        );
        assert_eq!(
            DioTimeOption::decode(&[0x15, 6, 0, 1, 0, 0, 0, 0]),
            Err(DioTimeError::ReservedNonzero)
        );
        assert_eq!(
            DioTimeOption::decode(&[0x15, 6, 5, 0, 0, 0, 0, 0]),
            Err(DioTimeError::InvalidStratum)
        );
    }
}
