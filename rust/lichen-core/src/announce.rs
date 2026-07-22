//! Announce message codec (spec section 9.2).
//!
//! Wire format:
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Type=0x01 | Flags     | Hop Count   | Seq Num               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Originator IID (8 bytes)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Public Key (32 bytes)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Signature (48 bytes)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Optional: App Data (variable)              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total: 93 bytes minimum (1+1+1+2+8+32+48).

/// Announce message type identifier.
pub const ANNOUNCE_TYPE: u8 = 0x01;

/// Schnorr48 signature length.
pub const SIGNATURE_LENGTH: usize = 48;

/// Maximum hop count (spec 9.4).
pub const MAX_ANNOUNCE_HOPS: u8 = 15;

/// Fixed portion length before app_data.
const FIXED_LENGTH: usize = 1 + 1 + 1 + 2 + 8 + 32 + 48;

use crate::error::{BufferTooSmall, TooShort};

/// Announce message parse/serialize error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceError {
    TooShort(TooShort),
    WrongType(u8),
    BufferTooSmall(BufferTooSmall),
    NotSigned,
    HopCountExceeded,
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "announce {}", e),
            Self::WrongType(t) => write!(f, "wrong announce type: {}", t),
            Self::BufferTooSmall(e) => write!(f, "announce {}", e),
            Self::NotSigned => write!(f, "announce not signed"),
            Self::HopCountExceeded => write!(f, "hop count exceeded"),
        }
    }
}

impl core::error::Error for AnnounceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for AnnounceError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for AnnounceError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

/// A parsed announce message.
///
/// References slices from the original buffer to avoid allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce<'a> {
    pub originator_iid: &'a [u8; 8],
    pub pubkey: &'a [u8; 32],
    pub seq_num: u16,
    pub hop_count: u8,
    pub signature: &'a [u8; 48],
    pub app_data: &'a [u8],
    pub flags: u8,
}

impl<'a> Announce<'a> {
    /// Parse from wire format.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, AnnounceError> {
        if data.len() < FIXED_LENGTH {
            return Err(TooShort::new(FIXED_LENGTH, data.len()).into());
        }
        if data[0] != ANNOUNCE_TYPE {
            return Err(AnnounceError::WrongType(data[0]));
        }

        // ponytail: unwrap safe, bounds checked above
        let originator_iid = data[5..13].try_into().unwrap();
        let pubkey = data[13..45].try_into().unwrap();
        let signature = data[45..93].try_into().unwrap();

        Ok(Self {
            flags: data[1],
            hop_count: data[2],
            seq_num: u16::from_be_bytes([data[3], data[4]]),
            originator_iid,
            pubkey,
            signature,
            app_data: &data[93..],
        })
    }

    /// Data covered by signature (IID + pubkey + seq_num + app_data).
    ///
    /// Hop count is NOT signed because relays must increment it.
    pub fn signed_data_len(&self) -> usize {
        8 + 32 + 2 + self.app_data.len()
    }

    /// Write signed data to buffer. Returns bytes written.
    pub fn write_signed_data(&self, out: &mut [u8]) -> Result<usize, AnnounceError> {
        let len = self.signed_data_len();
        if out.len() < len {
            return Err(BufferTooSmall::new(len, out.len()).into());
        }
        out[..8].copy_from_slice(self.originator_iid);
        out[8..40].copy_from_slice(self.pubkey);
        out[40..42].copy_from_slice(&self.seq_num.to_be_bytes());
        out[42..len].copy_from_slice(self.app_data);
        Ok(len)
    }

    /// Whether this announce should be relayed (hop_count < MAX).
    pub fn should_relay(&self) -> bool {
        self.hop_count < MAX_ANNOUNCE_HOPS
    }
}

/// Builder for creating announce messages.
#[derive(Debug)]
pub struct AnnounceBuilder<'a> {
    pub originator_iid: &'a [u8; 8],
    pub pubkey: &'a [u8; 32],
    pub seq_num: u16,
    pub hop_count: u8,
    pub signature: &'a [u8; 48],
    pub app_data: &'a [u8],
    pub flags: u8,
}

impl<'a> AnnounceBuilder<'a> {
    /// Serialize to wire format. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, AnnounceError> {
        let total = FIXED_LENGTH + self.app_data.len();
        if out.len() < total {
            return Err(BufferTooSmall::new(total, out.len()).into());
        }

        out[0] = ANNOUNCE_TYPE;
        out[1] = self.flags;
        out[2] = self.hop_count;
        out[3..5].copy_from_slice(&self.seq_num.to_be_bytes());
        out[5..13].copy_from_slice(self.originator_iid);
        out[13..45].copy_from_slice(self.pubkey);
        out[45..93].copy_from_slice(self.signature);
        out[93..total].copy_from_slice(self.app_data);

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_announce() -> [u8; 93] {
        let mut buf = [0u8; 93];
        buf[0] = ANNOUNCE_TYPE;
        buf[1] = 0; // flags
        buf[2] = 3; // hop_count
        buf[3] = 0x12; // seq_num high
        buf[4] = 0x34; // seq_num low
                       // iid at 5..13
        buf[5] = 0x02;
        buf[12] = 0x01;
        // pubkey at 13..45 (all zeros ok for test)
        // signature at 45..93 (all zeros ok for test)
        buf
    }

    #[test]
    fn roundtrip() {
        let wire = make_announce();
        let ann = Announce::from_bytes(&wire).unwrap();
        assert_eq!(ann.hop_count, 3);
        assert_eq!(ann.seq_num, 0x1234);
        assert_eq!(ann.originator_iid[0], 0x02);
        assert!(ann.app_data.is_empty());

        let builder = AnnounceBuilder {
            originator_iid: ann.originator_iid,
            pubkey: ann.pubkey,
            seq_num: ann.seq_num,
            hop_count: ann.hop_count,
            signature: ann.signature,
            app_data: ann.app_data,
            flags: ann.flags,
        };
        let mut out = [0u8; 93];
        let n = builder.write_to(&mut out).unwrap();
        assert_eq!(n, 93);
        assert_eq!(&out[..], &wire[..]);
    }

    #[test]
    fn too_short() {
        assert_eq!(
            Announce::from_bytes(&[0u8; 92]),
            Err(AnnounceError::TooShort(TooShort::new(FIXED_LENGTH, 92)))
        );
    }

    #[test]
    fn wrong_type() {
        let mut wire = make_announce();
        wire[0] = 0xFF;
        assert_eq!(
            Announce::from_bytes(&wire),
            Err(AnnounceError::WrongType(0xFF))
        );
    }

    #[test]
    fn invalid_channel() {
        let mut wire = make_announce();
        wire[1] = 0x10; // channel = 16 invalid
        assert_eq!(
            Announce::from_bytes(&wire),
            Err(AnnounceError::InvalidChannel(16))
        );
    }

    #[test]
    fn should_relay() {
        let mut wire = make_announce();
        wire[2] = 14;
        let ann = Announce::from_bytes(&wire).unwrap();
        assert!(ann.should_relay());

        wire[2] = 15;
        let ann = Announce::from_bytes(&wire).unwrap();
        assert!(!ann.should_relay());
    }
}
