//! Announce message codec (spec section 9.2 + CCP-9).
//!
//! Wire format (L2 dispatch 0x15 || announce):
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | 0x15 | Type=0x01 | rx_channel (0-7) | Hop Cnt | Seq Num (BE) |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Originator IID (8 bytes)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Public Key (32 bytes)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Signature (48 bytes)                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Optional: App Data (variable)                                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Fixed announce payload = 93 bytes (type to end of sig). rx_channel at
//! announce byte 1 (reuses old Flags position), included in signed_data
//! per CCP-9 to bind rendezvous channel (prevents tampering). Matches
//! test/vectors/ccp9.json roundtrip vector with expected_flags=channel.

/// Announce message type identifier.
pub const ANNOUNCE_TYPE: u8 = 0x01;
pub const SIGNATURE_LENGTH: usize = 48;
pub const MAX_ANNOUNCE_HOPS: u8 = 15;
const FIXED_LENGTH: usize = 93;
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
            Self::InvalidChannel(c) => write!(f, "invalid rx_channel: {}", c),
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
    fn from(e: TooShort) -> Self { Self::TooShort(e) }
}
impl From<BufferTooSmall> for AnnounceError {
    fn from(e: BufferTooSmall) -> Self { Self::BufferTooSmall(e) }
}
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
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, AnnounceError> {
        if data.len() < FIXED_LENGTH {
            return Err(TooShort::new(FIXED_LENGTH, data.len()).into());
        }
        if data[0] != ANNOUNCE_TYPE {
            return Err(AnnounceError::WrongType(data[0]));
        }
        let rx_channel = data[1];
        if rx_channel >= 8 {
            return Err(AnnounceError::InvalidChannel(rx_channel));
        }
        let originator_iid = data[5..13].try_into().unwrap();
        let pubkey = data[13..45].try_into().unwrap();
        let signature = data[45..93].try_into().unwrap();
        Ok(Self {
            flags: 0,
            hop_count: data[2],
            seq_num: u16::from_be_bytes([data[3], data[4]]),
            rx_channel,
            originator_iid,
            pubkey,
            signature,
            app_data: &data[93..],
        })
    }
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
        out[1] = self.rx_channel;
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
        buf[1] = 2;
        buf[2] = 3;
        buf[3] = 0x12;
        buf[4] = 0x34;
        buf[5] = 0x02;
        buf[12] = 0x01;
        buf
    }
    #[test]
    fn roundtrip() {
        let wire = make_announce();
        let ann = Announce::from_bytes(&wire).unwrap();
        assert_eq!(ann.hop_count, 3);
        assert_eq!(ann.seq_num, 0x1234);
        assert_eq!(ann.rx_channel, 2);
        assert_eq!(ann.originator_iid[0], 0x02);
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
        wire[1] = 16;
        assert_eq!(
            Announce::from_bytes(&wire),
            Err(AnnounceError::InvalidChannel(16))
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
