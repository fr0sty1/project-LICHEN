//! LOADng control message codecs (spec section 10, appendix B2).
//!
//! LOADng provides reactive peer-to-peer route discovery. Messages are ICMPv6
//! type 158, with code selecting RREQ (0), RREP (1), RERR (2).

use crate::addr::Ipv6Addr;

/// ICMPv6 type for LOADng messages.
pub const LOADNG_ICMPV6_TYPE: u8 = 158;

/// Initial hop limit for expanding ring search.
pub const INITIAL_HOP_LIMIT: u8 = 4;

/// Maximum hop limit.
pub const MAX_HOP_LIMIT: u8 = 15;

/// Expanding ring hop limits: [4, 8, 15].
pub const EXPANDING_RING: [u8; 3] = [4, 8, 15];

/// LOADng ICMPv6 codes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadngCode {
    Rreq = 0,
    Rrep = 1,
    Rerr = 2,
}

impl LoadngCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Rreq),
            1 => Some(Self::Rrep),
            2 => Some(Self::Rerr),
            _ => None,
        }
    }
}

/// LOADng message parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadngError {
    TooShort,
    BufferTooSmall,
    UnknownCode(u8),
}

// RREQ/RREP fixed length: flags(1) + hop(1) + seq(2) + orig(16) + dest(16) = 36
const RREQ_RREP_LEN: usize = 36;
// RERR fixed length: flags(1) + error_code(1) + unreachable(16) = 18
const RERR_LEN: usize = 18;

/// Route Request, flooded toward a destination (spec 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rreq {
    pub originator: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub seq_num: u16,
    pub hop_limit: u8,
    pub flags: u8,
}

impl Rreq {
    /// Parse RREQ from ICMPv6 body (after type/code/checksum).
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RREQ_RREP_LEN {
            return Err(LoadngError::TooShort);
        }
        Ok(Self {
            flags: data[0],
            hop_limit: data[1],
            seq_num: u16::from_be_bytes([data[2], data[3]]),
            originator: Ipv6Addr(data[4..20].try_into().unwrap()),
            destination: Ipv6Addr(data[20..36].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RREQ_RREP_LEN {
            return Err(LoadngError::BufferTooSmall);
        }
        out[0] = self.flags;
        out[1] = self.hop_limit;
        out[2..4].copy_from_slice(&self.seq_num.to_be_bytes());
        out[4..20].copy_from_slice(&self.originator.0);
        out[20..36].copy_from_slice(&self.destination.0);
        Ok(RREQ_RREP_LEN)
    }

    /// Decrement hop limit. Returns None if already zero.
    pub fn with_decremented_hop_limit(self) -> Option<Self> {
        if self.hop_limit == 0 {
            None
        } else {
            Some(Self {
                hop_limit: self.hop_limit - 1,
                ..self
            })
        }
    }
}

/// Route Reply, unicast back along reverse path (spec 10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rrep {
    pub originator: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub seq_num: u16,
    pub hop_count: u8,
    pub flags: u8,
}

impl Rrep {
    /// Parse RREP from ICMPv6 body.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RREQ_RREP_LEN {
            return Err(LoadngError::TooShort);
        }
        Ok(Self {
            flags: data[0],
            hop_count: data[1],
            seq_num: u16::from_be_bytes([data[2], data[3]]),
            originator: Ipv6Addr(data[4..20].try_into().unwrap()),
            destination: Ipv6Addr(data[20..36].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RREQ_RREP_LEN {
            return Err(LoadngError::BufferTooSmall);
        }
        out[0] = self.flags;
        out[1] = self.hop_count;
        out[2..4].copy_from_slice(&self.seq_num.to_be_bytes());
        out[4..20].copy_from_slice(&self.originator.0);
        out[20..36].copy_from_slice(&self.destination.0);
        Ok(RREQ_RREP_LEN)
    }

    /// Increment hop count.
    pub fn with_incremented_hop_count(self) -> Self {
        Self {
            hop_count: self.hop_count.saturating_add(1),
            ..self
        }
    }
}

/// Route Error, sent when a link fails (spec 10.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rerr {
    pub unreachable: Ipv6Addr,
    pub error_code: u8,
    pub flags: u8,
}

impl Rerr {
    /// Parse RERR from ICMPv6 body.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RERR_LEN {
            return Err(LoadngError::TooShort);
        }
        Ok(Self {
            flags: data[0],
            error_code: data[1],
            unreachable: Ipv6Addr(data[2..18].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RERR_LEN {
            return Err(LoadngError::BufferTooSmall);
        }
        out[0] = self.flags;
        out[1] = self.error_code;
        out[2..18].copy_from_slice(&self.unreachable.0);
        Ok(RERR_LEN)
    }
}

/// Unified LOADng message enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadngMessage {
    Rreq(Rreq),
    Rrep(Rrep),
    Rerr(Rerr),
}

impl LoadngMessage {
    /// Parse from ICMPv6 code and body.
    pub fn from_icmpv6(code: u8, body: &[u8]) -> Result<Self, LoadngError> {
        match LoadngCode::from_u8(code) {
            Some(LoadngCode::Rreq) => Ok(Self::Rreq(Rreq::from_bytes(body)?)),
            Some(LoadngCode::Rrep) => Ok(Self::Rrep(Rrep::from_bytes(body)?)),
            Some(LoadngCode::Rerr) => Ok(Self::Rerr(Rerr::from_bytes(body)?)),
            None => Err(LoadngError::UnknownCode(code)),
        }
    }

    /// ICMPv6 code for this message.
    pub fn code(&self) -> u8 {
        match self {
            Self::Rreq(_) => LoadngCode::Rreq as u8,
            Self::Rrep(_) => LoadngCode::Rrep as u8,
            Self::Rerr(_) => LoadngCode::Rerr as u8,
        }
    }

    /// Serialize body to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        match self {
            Self::Rreq(m) => m.write_to(out),
            Self::Rrep(m) => m.write_to(out),
            Self::Rerr(m) => m.write_to(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    #[test]
    fn rreq_roundtrip() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 0x1234,
            hop_limit: 8,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        let n = rreq.write_to(&mut buf).unwrap();
        assert_eq!(n, 36);

        let parsed = Rreq::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.originator, ll(1));
        assert_eq!(parsed.destination, ll(2));
        assert_eq!(parsed.seq_num, 0x1234);
        assert_eq!(parsed.hop_limit, 8);
    }

    #[test]
    fn rrep_roundtrip() {
        let rrep = Rrep {
            originator: ll(2),
            destination: ll(1),
            seq_num: 0x5678,
            hop_count: 3,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        let n = rrep.write_to(&mut buf).unwrap();
        assert_eq!(n, 36);

        let parsed = Rrep::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.originator, ll(2));
        assert_eq!(parsed.destination, ll(1));
        assert_eq!(parsed.seq_num, 0x5678);
        assert_eq!(parsed.hop_count, 3);
    }

    #[test]
    fn rerr_roundtrip() {
        let rerr = Rerr {
            unreachable: ll(3),
            error_code: 1,
            flags: 0,
        };
        let mut buf = [0u8; 32];
        let n = rerr.write_to(&mut buf).unwrap();
        assert_eq!(n, 18);

        let parsed = Rerr::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.unreachable, ll(3));
        assert_eq!(parsed.error_code, 1);
    }

    #[test]
    fn loadng_message_dispatch() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 100,
            hop_limit: 4,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        rreq.write_to(&mut buf).unwrap();

        let msg = LoadngMessage::from_icmpv6(0, &buf).unwrap();
        assert!(matches!(msg, LoadngMessage::Rreq(_)));
        assert_eq!(msg.code(), 0);
    }

    #[test]
    fn hop_limit_decrement() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 1,
            hop_limit: 2,
            flags: 0,
        };
        let dec = rreq.with_decremented_hop_limit().unwrap();
        assert_eq!(dec.hop_limit, 1);

        let dec2 = dec.with_decremented_hop_limit().unwrap();
        assert_eq!(dec2.hop_limit, 0);

        assert!(dec2.with_decremented_hop_limit().is_none());
    }
}
