use crate::constants::L2_DISPATCH_ROUTING;
use crate::error::{BufferTooSmall, TooShort};

pub const ANNOUNCE_TYPE: u8 = 0x01;
pub const SIGNATURE_LENGTH: usize = 48;
pub const MAX_ANNOUNCE_HOPS: u8 = 15;
/// Domain separator for the canonical Announce signature transcript.
pub const ANNOUNCE_SIGNING_DOMAIN: &[u8; 19] = b"LICHEN-ANNOUNCE-v1\0";
/// Bytes before application data in the canonical signature transcript.
pub const ANNOUNCE_SIGNED_FIXED_LENGTH: usize = 64;
const FIXED_LENGTH: usize = 93;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceError {
    TooShort(TooShort),
    WrongType(u8),
    BufferTooSmall(BufferTooSmall),
    InvalidChannel(u8),
    AppDataTooLong(usize),
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => core::fmt::Display::fmt(e, f),
            Self::WrongType(t) => write!(f, "wrong type: {}", t),
            Self::BufferTooSmall(e) => core::fmt::Display::fmt(e, f),
            Self::InvalidChannel(c) => write!(f, "invalid rx_channel: {} (must be 0-7)", c),
            Self::AppDataTooLong(len) => {
                write!(f, "Announce application data length {len} exceeds u16")
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
        ANNOUNCE_SIGNED_FIXED_LENGTH + self.app_data.len()
    }
    pub fn write_signed_data(&self, out: &mut [u8]) -> Result<usize, AnnounceError> {
        write_announce_signed_data(
            self.originator_iid,
            self.pubkey,
            self.seq_num,
            self.rx_channel,
            self.app_data,
            out,
        )
    }
    pub fn should_relay(&self) -> bool {
        self.hop_count < MAX_ANNOUNCE_HOPS
    }

    /// Convert to builder with hop_count incremented for relay.
    /// Returns `None` if hop_count >= MAX_ANNOUNCE_HOPS (relay not allowed).
    /// Per spec 9.3: relay decision + hop increment in one ergonomic call.
    pub fn for_relay(&self) -> Option<AnnounceBuilder<'a>> {
        if self.hop_count >= MAX_ANNOUNCE_HOPS {
            return None;
        }
        Some(AnnounceBuilder {
            originator_iid: self.originator_iid,
            pubkey: self.pubkey,
            seq_num: self.seq_num,
            hop_count: self.hop_count + 1,
            rx_channel: self.rx_channel,
            signature: self.signature,
            app_data: self.app_data,
        })
    }
}

/// Write the canonical, domain-separated transcript signed by an Announce.
pub fn write_announce_signed_data(
    originator_iid: &[u8; 8],
    pubkey: &[u8; 32],
    seq_num: u16,
    rx_channel: u8,
    app_data: &[u8],
    out: &mut [u8],
) -> Result<usize, AnnounceError> {
    if rx_channel >= 8 {
        return Err(AnnounceError::InvalidChannel(rx_channel));
    }
    let app_len =
        u16::try_from(app_data.len()).map_err(|_| AnnounceError::AppDataTooLong(app_data.len()))?;
    let len = ANNOUNCE_SIGNED_FIXED_LENGTH + app_data.len();
    if out.len() < len {
        return Err(BufferTooSmall::new(len, out.len()).into());
    }

    out[..19].copy_from_slice(ANNOUNCE_SIGNING_DOMAIN);
    out[19..27].copy_from_slice(originator_iid);
    out[27..59].copy_from_slice(pubkey);
    out[59..61].copy_from_slice(&seq_num.to_be_bytes());
    out[61] = rx_channel;
    out[62..64].copy_from_slice(&app_len.to_be_bytes());
    out[64..len].copy_from_slice(app_data);
    Ok(len)
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
            1, 2, 3, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    fn rx_channel_nonzero_vector_cases() {
        for &ch in &[0u8, 2, 3, 5, 7] {
            let mut w = [0u8; 93];
            w[0] = 1;
            w[1] = ch;
            let ann = Announce::from_bytes(&w).unwrap();
            assert_eq!(ann.rx_channel, ch);
            let mut signed = [0u8; ANNOUNCE_SIGNED_FIXED_LENGTH];
            let _ = ann.write_signed_data(&mut signed).unwrap();
            assert_eq!(signed[61], ch);
            assert_eq!(&signed[62..64], &[0, 0]);
            let mut out = [0u8; 100];
            let b = AnnounceBuilder {
                originator_iid: &[0; 8],
                pubkey: &[0; 32],
                seq_num: 0,
                hop_count: 0,
                rx_channel: ch,
                signature: &[0; 48],
                app_data: &[],
            };
            let n = b.write_to(&mut out).unwrap();
            assert_eq!(out[1], ch);
            assert_eq!(n, 93);
        }
    }
    #[test]
    fn should_relay() {
        let w = [
            1, 2, 14, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let a = Announce::from_bytes(&w[..93]).unwrap();
        assert!(a.should_relay());
    }

    #[test]
    fn for_relay_increments_hop_count() {
        // hop_count = 5, should relay with hop_count = 6
        let mut w = [0u8; 93];
        w[0] = 1; // type
        w[1] = 2; // rx_channel
        w[2] = 5; // hop_count
        let a = Announce::from_bytes(&w).unwrap();
        assert_eq!(a.hop_count, 5);
        let builder = a.for_relay().expect("should relay at hop_count 5");
        assert_eq!(builder.hop_count, 6);
    }

    #[test]
    fn for_relay_at_boundary() {
        // hop_count = 14 (MAX - 1), should relay with hop_count = 15
        let mut w = [0u8; 93];
        w[0] = 1;
        w[1] = 2;
        w[2] = 14; // MAX_ANNOUNCE_HOPS - 1
        let a = Announce::from_bytes(&w).unwrap();
        assert!(a.should_relay());
        let builder = a.for_relay().expect("should relay at hop_count 14");
        assert_eq!(builder.hop_count, 15);
    }

    #[test]
    fn for_relay_at_max_returns_none() {
        // hop_count = 15 (MAX), should NOT relay
        let mut w = [0u8; 93];
        w[0] = 1;
        w[1] = 2;
        w[2] = 15; // MAX_ANNOUNCE_HOPS
        let a = Announce::from_bytes(&w).unwrap();
        assert!(!a.should_relay());
        assert!(a.for_relay().is_none());
    }

    #[test]
    fn for_relay_preserves_fields() {
        let mut w = [0u8; 93];
        w[0] = 1;
        w[1] = 3; // rx_channel
        w[2] = 2; // hop_count
        w[3] = 0x12;
        w[4] = 0x34; // seq_num = 0x1234
        for (i, byte) in w.iter_mut().enumerate().take(13).skip(5) {
            *byte = i as u8; // originator_iid
        }
        for (i, byte) in w.iter_mut().enumerate().take(45).skip(13) {
            *byte = (i * 2) as u8; // pubkey
        }
        for (i, byte) in w.iter_mut().enumerate().skip(45) {
            *byte = (i + 100) as u8; // signature
        }
        let a = Announce::from_bytes(&w).unwrap();
        let builder = a.for_relay().unwrap();

        assert_eq!(builder.hop_count, 3); // incremented
        assert_eq!(builder.rx_channel, 3);
        assert_eq!(builder.seq_num, 0x1234);
        assert_eq!(builder.originator_iid, a.originator_iid);
        assert_eq!(builder.pubkey, a.pubkey);
        assert_eq!(builder.signature, a.signature);
    }
}
