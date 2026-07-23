//! Announce message codec (spec section 9.2 + CCP-9).
//!
//! Wire format (updated for CCP-9 rendezvous):
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Type=0x01 | Flags | Hop Cnt | Cur Ch | Seq Num               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Originator IID (8 bytes)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Public Key (32 bytes)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Signature (48 bytes)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | rx_channel (u8) | Optional: App Data (variable)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total: 94 bytes minimum (1+1+1+2+8+32+48+1). rx_channel signed per CCP-9 to prevent rendezvous tampering.

/// Announce message type identifier.
pub const ANNOUNCE_TYPE: u8 = 0x01;

/// Schnorr48 signature length.
pub const SIGNATURE_LENGTH: usize = 48;

/// Maximum hop count (spec 9.4).
pub const MAX_ANNOUNCE_HOPS: u8 = 15;

/// Fixed portion length before app_data (includes rx_channel per CCP-9).
const FIXED_LENGTH: usize = 1 + 1 + 1 + 2 + 8 + 32 + 48 + 1;

use crate::error::{BufferTooSmall, TooShort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceError {
    TooShort(TooShort),
    WrongType(u8),
    BufferTooSmall(BufferTooSmall),
    InvalidChannel(u8),
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "announce {}", e),
            Self::WrongType(t) => write!(f, "wrong announce type: {}", t),
            Self::BufferTooSmall(e) => write!(f, "announce {}", e),
            Self::InvalidChannel(c) => {
                write!(f, "invalid rx_channel: {} (must be 0-7 per CCP-9)", c)
            }
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

/// A parsed announce message (CCP-9 updated).
///
/// References slices from the original buffer to avoid allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce<'a> {
    pub originator_iid: &'a [u8; 8],
    pub pubkey: &'a [u8; 32],
    pub seq_num: u16,
    pub hop_count: u8,
    pub rx_channel: u8,
    pub signature: &'a [u8; 48],
    pub app_data: &'a [u8],
    pub flags: u8,
}

impl<'a> Announce<'a> {
    /// Parse from wire format (CCP-9: rx_channel at offset 93).
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, AnnounceError> {
        if data.len() < FIXED_LENGTH {
            return Err(TooShort::new(FIXED_LENGTH, data.len()).into());
        }
        if data[0] != ANNOUNCE_TYPE {
            return Err(AnnounceError::WrongType(data[0]));
        }
        let rx_channel = data[5];
        if rx_channel > 15 {
            return Err(AnnounceError::InvalidChannel(rx_channel));
        }

        // ponytail: unwrap safe, bounds checked above
        let originator_iid = data[5..13].try_into().unwrap();
        let pubkey = data[13..45].try_into().unwrap();
        let signature = data[45..93].try_into().unwrap();
        let rx_channel = data[93];
        if rx_channel >= 8 {
            return Err(AnnounceError::InvalidChannel(rx_channel));
        }

        Ok(Self {
            flags: data[1],
            hop_count: data[2],
            seq_num: u16::from_be_bytes([data[3], data[4]]),
            rx_channel,
            originator_iid,
            pubkey,
            signature,
            app_data: &data[94..],
        })
    }

    /// Data covered by signature (IID + pubkey + seq_num + rx_channel + app_data).
    ///
    /// Hop count is NOT signed because relays must increment it.
    /// rx_channel IS signed (CCP-9) to prevent rendezvous tampering.
    pub fn signed_data_len(&self) -> usize {
        8 + 32 + 2 + 1 + self.app_data.len()
    }

    pub fn write_signed_data(&self, out: &mut [u8]) -> Result<usize, AnnounceError> {
        let len = self.signed_data_len();
        if out.len() < len {
            return Err(BufferTooSmall::new(len, out.len()).into());
        }
        out[..8].copy_from_slice(self.originator_iid);
        out[8..40].copy_from_slice(self.pubkey);
        out[40..42].copy_from_slice(&self.seq_num.to_be_bytes());
        out[42] = self.rx_channel;
        out[43..len].copy_from_slice(self.app_data);
        Ok(len)
    }

    pub fn should_relay(&self) -> bool {
        self.hop_count < MAX_ANNOUNCE_HOPS
    }
}

/// Builder for creating announce messages (CCP-9 updated).
#[derive(Debug)]
pub struct AnnounceBuilder<'a> {
    pub originator_iid: &'a [u8; 8],
    pub pubkey: &'a [u8; 32],
    pub seq_num: u16,
    pub hop_count: u8,
    pub rx_channel: u8,
    pub signature: &'a [u8; 48],
    pub app_data: &'a [u8],
    pub flags: u8,
}

impl<'a> AnnounceBuilder<'a> {
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, AnnounceError> {
        if self.rx_channel >= 8 {
            return Err(AnnounceError::InvalidChannel(self.rx_channel));
        }
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
        out[93] = self.rx_channel;
        out[94..total].copy_from_slice(self.app_data);

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_announce() -> [u8; 94] {
        let mut buf = [0u8; 94];
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
        buf[93] = 2; // rx_channel per CCP-9 test vectors
        buf
    }

    #[test]
    fn roundtrip() {
        let wire = make_announce();
        let ann = Announce::from_bytes(&wire).unwrap();
        assert_eq!(ann.hop_count, 3);
        assert_eq!(ann.seq_num, 0x1234);
        assert_eq!(ann.rx_channel, 5);
        assert_eq!(ann.originator_iid[0], 0x02);
        assert_eq!(ann.rx_channel, 2);
        assert!(ann.app_data.is_empty());

        let builder = AnnounceBuilder {
            originator_iid: ann.originator_iid,
            pubkey: ann.pubkey,
            seq_num: ann.seq_num,
            hop_count: ann.hop_count,
            rx_channel: ann.rx_channel,
            signature: ann.signature,
            app_data: ann.app_data,
            flags: ann.flags,
        };
        let mut out = [0u8; 94];
        let n = builder.write_to(&mut out).unwrap();
        assert_eq!(n, 94);
        assert_eq!(&out[..], &wire[..]);
    }

    #[test]
    fn too_short() {
        assert_eq!(
            Announce::from_bytes(&[0u8; 93]),
            Err(AnnounceError::TooShort(TooShort::new(FIXED_LENGTH, 93)))
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
        wire[93] = 8;
        assert_eq!(
            Announce::from_bytes(&wire),
            Err(AnnounceError::InvalidChannel(8))
        );

        let builder = AnnounceBuilder {
            originator_iid: &[0; 8],
            pubkey: &[0; 32],
            seq_num: 0,
            hop_count: 0,
            rx_channel: 9,
            signature: &[0; 48],
            app_data: &[],
            flags: 0,
        };
        let mut out = [0u8; 100];
        assert_eq!(
            builder.write_to(&mut out),
            Err(AnnounceError::InvalidChannel(9))
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
