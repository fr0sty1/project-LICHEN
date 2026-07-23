use crate::constants::L2_DISPATCH_ROUTING;
use crate::error::{BufferTooSmall, TooShort};

pub const ANNOUNCE_TYPE: u8 = 0x01;
pub const SIGNATURE_LENGTH: usize = 48;
pub const MAX_ANNOUNCE_HOPS: u8 = 15;
const FIXED_LENGTH: usize = 93;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceError {
    TooShort(TooShort),
    WrongType(u8),
    BufferTooSmall(BufferTooSmall),
    InvalidChannel(u8),
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => core::fmt::Display::fmt(e, f),
            Self::WrongType(t) => write!(f, "wrong type: {}", t),
            Self::BufferTooSmall(e) => core::fmt::Display::fmt(e, f),
            Self::InvalidChannel(c) => write!(f, "invalid rx_channel: {} (must be 0-7)", c),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce<'a> {
    pub originator_iid: &'a [u8; 8],
    pub pubkey: &'a [u8; 32],
    pub seq_num: u16,
    pub hop_count: u8,
    pub rx_channel: u8,
    pub signature: &'a [u8; 48],
    pub app_data: &'a [u8],
}

impl<'a> Announce<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, AnnounceError> {
        let data = if !data.is_empty() && data[0] == L2_DISPATCH_ROUTING {
            if data.len() < FIXED_LENGTH + 1 {
                return Err(TooShort::new(FIXED_LENGTH + 1, data.len()).into());
            }
            &data[1..]
        } else {
            data
        };
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
            originator_iid,
            pubkey,
            seq_num: u16::from_be_bytes([data[3], data[4]]),
            hop_count: data[2],
            rx_channel,
            signature,
            app_data: &data[93..],
        })
    }
    pub fn signed_data_len(&self) -> usize {
        43 + self.app_data.len()
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
    use crate::error::TooShort;
    #[test]
    fn roundtrip() {
        let wire = [
            1, 2, 3, 0x12, 0x34, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let ann = Announce::from_bytes(&wire[..93]).unwrap();
        let mut out = [0; 93];
        let b = AnnounceBuilder {
            originator_iid: ann.originator_iid,
            pubkey: ann.pubkey,
            seq_num: ann.seq_num,
            hop_count: ann.hop_count,
            rx_channel: ann.rx_channel,
            signature: ann.signature,
            app_data: ann.app_data,
        };
        let n = b.write_to(&mut out).unwrap();
        assert_eq!(n, 93);
    }
    #[test]
    fn too_short() {
        assert_eq!(
            Announce::from_bytes(&[0; 92]),
            Err(AnnounceError::TooShort(TooShort::new(FIXED_LENGTH, 92)))
        );
    }
    #[test]
    fn wrong_type() {
        let mut w = [1u8; 93];
        w[0] = 0xff;
        assert_eq!(
            Announce::from_bytes(&w),
            Err(AnnounceError::WrongType(0xff))
        );
    }
    #[test]
    fn invalid_channel() {
        let mut w = [1u8; 93];
        w[1] = 16;
        assert_eq!(
            Announce::from_bytes(&w),
            Err(AnnounceError::InvalidChannel(16))
        );
    }
    #[test]
    fn should_relay() {
        let mut w = [
            1, 2, 14, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let a = Announce::from_bytes(&w[..93]).unwrap();
        assert!(a.should_relay());
    }
}
