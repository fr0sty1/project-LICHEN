//! RPL control message codecs — DIO / DAO / DIS / DAO-ACK (RFC 6550).
//!
//! Wire layout matches the Python reference and test vectors in
//! test/vectors/. Aligns with CCP-9/15 vectors, FNV-1a32, and core style
//! from epic l3j5. #![forbid(unsafe_code)], no dead consts, perfect roundtrip.

#![forbid(unsafe_code)]

use lichen_core::error::{BufferTooSmall, TooShort};

/// Error returned when a message or option is malformed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplError {
    /// Buffer too short for the expected data.
    TooShort(TooShort),
    /// Option data overruns the buffer.
    OptionOverrun,
    /// Unrecognized option type.
    BadOptionType(u8),
    /// Unrecognized routing type.
    BadRoutingType(u8),
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
    /// Invalid option value.
    InvalidOption,
}

impl From<TooShort> for RplError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for RplError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

impl core::fmt::Display for RplError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "RPL {}", e),
            Self::OptionOverrun => write!(f, "option overruns buffer"),
            Self::BadOptionType(t) => write!(f, "bad option type: {}", t),
            Self::BadRoutingType(t) => write!(f, "bad routing type: {}", t),
            Self::BufferTooSmall(e) => write!(f, "RPL {}", e),
            Self::InvalidOption => write!(f, "invalid option value"),
        }
    }
}

impl core::error::Error for RplError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

// ── Option type bytes ─────────────────────────────────────────────────────────

pub const OPT_PAD1: u8 = 0;
pub const OPT_DODAG_CONFIG: u8 = 4;
pub const OPT_RPL_TARGET: u8 = 5;
pub const OPT_TRANSIT_INFO: u8 = 6;
pub const OPT_PREFIX_INFO: u8 = 8;
pub const OPT_RPL_TARGET_DESCRIPTOR: u8 = 9;
/// Provisional LICHEN DAO origin-authentication option.
pub const OPT_DAO_ORIGIN_SIGNATURE: u8 = 0x12;
pub const DAO_ORIGIN_SIGNATURE_DATA_LEN: usize = 56;
pub const DAO_ORIGIN_SIGNATURE_LEN: usize = 58;

// ── ICMPv6 code for each RPL message ─────────────────────────────────────────

pub const CODE_DIS: u8 = 0;
pub const CODE_DIO: u8 = 1;
pub const CODE_DAO: u8 = 2;
pub const CODE_DAO_ACK: u8 = 3;

// ── DIO ──────────────────────────────────────────────────────────────────────

/// DIO base object (24 bytes), decoded from the ICMPv6 body after the 4-byte
/// ICMPv6 type/code/checksum header.
///
/// In a full IPv6 packet produced by the SCHC decompressor, the DIO base
/// starts at offset 44 (= 40 IPv6 header + 4 ICMPv6 header bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dio {
    pub rpl_instance_id: u8,
    pub version: u8,
    pub rank: u16,
    pub grounded: bool,
    pub mode_of_operation: u8,
    pub preference: u8,
    pub dtsn: u8,
    pub flags: u8,
    pub dodag_id: [u8; 16],
}

impl Dio {
    pub const BASE_LEN: usize = 24;

    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < Self::BASE_LEN {
            return Err(TooShort::new(Self::BASE_LEN, data.len()).into());
        }
        let gmop = data[4];
        if data[7] != 0 {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            rpl_instance_id: data[0],
            version: data[1],
            rank: u16::from_be_bytes([data[2], data[3]]),
            grounded: (gmop >> 7) & 1 == 1,
            mode_of_operation: (gmop >> 3) & 0x7,
            preference: gmop & 0x7,
            dtsn: data[5],
            flags: data[6],
            // SAFETY: length check above ensures data.len() >= BASE_LEN (24),
            // so 8..24 is within bounds and exactly 16 bytes
            dodag_id: data[8..24].try_into().unwrap(),
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if out.len() < Self::BASE_LEN {
            return Err(BufferTooSmall::new(Self::BASE_LEN, out.len()).into());
        }
        let gmop = ((self.grounded as u8) << 7)
            | ((self.mode_of_operation & 0x7) << 3)
            | (self.preference & 0x7);
        out[0] = self.rpl_instance_id;
        out[1] = self.version;
        out[2] = (self.rank >> 8) as u8;
        out[3] = self.rank as u8;
        out[4] = gmop;
        out[5] = self.dtsn;
        out[6] = self.flags;
        out[7] = 0; // reserved
        out[8..24].copy_from_slice(&self.dodag_id);
        Ok(Self::BASE_LEN)
    }

    /// Options slice (everything after the 24-byte base).
    pub fn options_tail(data: &[u8]) -> &[u8] {
        if data.len() > Self::BASE_LEN {
            &data[Self::BASE_LEN..]
        } else {
            &[]
        }
    }
}

// ── DAO ──────────────────────────────────────────────────────────────────────

/// DAO base object (RFC 6550 §6.4). D-flag (bit 6 of byte 1) determines length:
/// D=1 includes 16-byte DODAGID (20 bytes total); D=0 elides it (4 bytes total).
/// LICHEN/SCHC rule 4 uses D=1; parser supports both (D=0 zeros dodag_id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dao {
    pub rpl_instance_id: u8,
    pub ack_requested: bool,
    pub flags: u8,
    pub dao_sequence: u8,
    pub dodag_id: Option<[u8; 16]>,
}

impl Dao {
    pub const BASE_LEN: usize = 20; // for D=1 (common case)

    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 4 {
            return Err(TooShort::new(4, data.len()).into());
        }
        let kd = data[1];
        let d_flag = (kd >> 6) & 1;
        let base_len = if d_flag == 1 { 20 } else { 4 };
        if data.len() < base_len {
            return Err(TooShort::new(base_len, data.len()).into());
        }
        let dodag_id = if d_flag == 1 {
            // SAFETY: length check ensures data.len() >= 20; 4..20 is 16 bytes
            Some(data[4..20].try_into().unwrap())
        } else {
            None // D=0 elides DODAGID per RFC 6550 §6.4.2
        };
        Ok(Self {
            rpl_instance_id: data[0],
            ack_requested: (kd >> 7) & 1 == 1,
            flags: kd & 0x3F,
            dao_sequence: data[3],
            dodag_id,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if self.rpl_instance_id & 0x80 != 0 && self.dodag_id.is_none() {
            return Err(RplError::InvalidOption);
        }
        let base_len = if self.dodag_id.is_some() {
            Self::BASE_LEN
        } else {
            Self::BASE_LEN
        };
        if out.len() < base_len {
            return Err(BufferTooSmall::new(base_len, out.len()).into());
        }
        let kd = ((self.ack_requested as u8) << 7)
            | (1u8 << 6) // D-flag always set (LICHEN/SCHC rule 4)
            | (self.flags & 0x3F);
        out[0] = self.rpl_instance_id;
        out[1] = kd;
        out[2] = 0; // reserved
        out[3] = self.dao_sequence;
        if let Some(dodag_id) = self.dodag_id {
            out[4..20].copy_from_slice(&dodag_id);
        }
        Ok(base_len)
    }

    pub fn options_tail(data: &[u8]) -> &[u8] {
        if data.len() < 4 {
            return &[];
        }
        let kd = data[1];
        let d_flag = (kd >> 6) & 1;
        let base_len = if d_flag == 1 { 20 } else { 4 };
        data.get(base_len..).unwrap_or_default()
    }
}

/// Parsed terminal DAO origin-authentication option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaoOriginSignature<'a> {
    pub origin_sequence: u64,
    pub signature: &'a [u8; 48],
}

impl<'a> DaoOriginSignature<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, RplError> {
        if data.len() != DAO_ORIGIN_SIGNATURE_DATA_LEN {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            origin_sequence: u64::from_be_bytes(data[..8].try_into().unwrap()),
            signature: data[8..].try_into().unwrap(),
        })
    }

    pub fn write_to(
        origin_sequence: u64,
        signature: &[u8; 48],
        out: &mut [u8],
    ) -> Result<usize, RplError> {
        if origin_sequence == 0 {
            return Err(RplError::InvalidOption);
        }
        if out.len() < DAO_ORIGIN_SIGNATURE_LEN {
            return Err(BufferTooSmall::new(DAO_ORIGIN_SIGNATURE_LEN, out.len()).into());
        }
        out[0] = OPT_DAO_ORIGIN_SIGNATURE;
        out[1] = DAO_ORIGIN_SIGNATURE_DATA_LEN as u8;
        out[2..10].copy_from_slice(&origin_sequence.to_be_bytes());
        out[10..DAO_ORIGIN_SIGNATURE_LEN].copy_from_slice(signature);
        Ok(DAO_ORIGIN_SIGNATURE_LEN)
    }
}

/// Structurally valid signed DAO borrowing the exact signed wire prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDaoEnvelope<'a> {
    pub dao: Dao,
    pub signed_bytes: &'a [u8],
    pub unsigned_bytes: &'a [u8],
    pub origin: DaoOriginSignature<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DaoEnvelopeError {
    Rpl(RplError),
    MissingSignature,
    DuplicateSignature,
    NonTerminalSignature,
    InvalidOptionLength,
    UnknownOption(u8),
}

impl From<RplError> for DaoEnvelopeError {
    fn from(error: RplError) -> Self {
        Self::Rpl(error)
    }
}

impl<'a> SignedDaoEnvelope<'a> {
    /// Require one origin signature option, with exact length, as the final option.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, DaoEnvelopeError> {
        let dao = Dao::from_bytes(data)?;
        if dao.flags != 0 || data[2] != 0 {
            return Err(DaoEnvelopeError::Rpl(RplError::InvalidOption));
        }
        let base_len = data.len() - Dao::options_tail(data).len();
        let mut pos = base_len;
        let mut found = None;
        while pos < data.len() {
            if data[pos] == OPT_PAD1 {
                if found.is_some() {
                    return Err(DaoEnvelopeError::NonTerminalSignature);
                }
                pos += 1;
                continue;
            }
            if pos + 2 > data.len() {
                return Err(DaoEnvelopeError::InvalidOptionLength);
            }
            let end = pos + 2 + usize::from(data[pos + 1]);
            if end > data.len() {
                return Err(DaoEnvelopeError::InvalidOptionLength);
            }
            if data[pos] == OPT_DAO_ORIGIN_SIGNATURE {
                if found.is_some() {
                    return Err(DaoEnvelopeError::DuplicateSignature);
                }
                let origin = DaoOriginSignature::from_bytes(&data[pos + 2..end])
                    .map_err(|_| DaoEnvelopeError::InvalidOptionLength)?;
                if origin.origin_sequence == 0 {
                    return Err(DaoEnvelopeError::InvalidOptionLength);
                }
                found = Some((pos, origin));
            } else {
                if found.is_some() {
                    return Err(DaoEnvelopeError::NonTerminalSignature);
                }
                match data[pos] {
                    OPT_PADN => {}
                    OPT_RPL_TARGET if data[pos + 1] as usize == 18 => {}
                    OPT_TRANSIT_INFO if data[pos + 1] as usize == TransitInfo::DATA_LEN => {}
                    OPT_RPL_TARGET_DESCRIPTOR if data[pos + 1] as usize == 4 => {}
                    OPT_RPL_TARGET | OPT_TRANSIT_INFO | OPT_RPL_TARGET_DESCRIPTOR => {
                        return Err(DaoEnvelopeError::InvalidOptionLength)
                    }
                    option => return Err(DaoEnvelopeError::UnknownOption(option)),
                }
            }
            pos = end;
        }
        let (unsigned_len, origin) = found.ok_or(DaoEnvelopeError::MissingSignature)?;
        Ok(Self {
            dao,
            signed_bytes: data,
            unsigned_bytes: &data[..unsigned_len],
            origin,
        })
    }
}

// ── DODAG Configuration option (type 4) ──────────────────────────────────────

pub const DODAG_CONFIG_DATA_LEN: usize = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DodagConfig {
    pub pcs: u8,
    pub a_flag: bool,
    pub min_hop_rank_increase: u16,
    pub max_rank_increase: u16,
    pub ocp: u16,
    pub def_lifetime: u8,
    pub lifetime_unit: u16,
    pub dio_int_min: u8,
    pub dio_int_doublings: u8,
    pub dio_redundancy_const: u8,
}

impl Default for DodagConfig {
    fn default() -> Self {
        Self {
            pcs: 0,
            a_flag: false,
            min_hop_rank_increase: 256,
            max_rank_increase: 2048,
            ocp: 1,
            def_lifetime: 0xFF,
            lifetime_unit: 60,
            dio_int_min: 12,
            dio_int_doublings: 8,
            dio_redundancy_const: 10,
        }
    }
}

impl DodagConfig {
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < DODAG_CONFIG_DATA_LEN {
            return Err(TooShort::new(DODAG_CONFIG_DATA_LEN, data.len()).into());
        }
        let flags = data[0];
        let pcs = flags & 0x07;
        let a_flag = (flags & 0x10) != 0;
        if data[10] != 0 {
            return Err(RplError::InvalidOption); // reserved field per RFC 6550 §6.7.6
        }
        Ok(Self {
            pcs,
            a_flag,
            dio_int_doublings: data[1],
            dio_int_min: data[2],
            dio_redundancy_const: data[3],
            max_rank_increase: u16::from_be_bytes([data[4], data[5]]),
            min_hop_rank_increase: u16::from_be_bytes([data[6], data[7]]),
            ocp: u16::from_be_bytes([data[8], data[9]]),
            // data[10] is reserved (checked above); def_lifetime follows
            def_lifetime: data[11],
            lifetime_unit: u16::from_be_bytes([data[12], data[13]]),
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 2 + DODAG_CONFIG_DATA_LEN;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = OPT_DODAG_CONFIG;
        out[1] = DODAG_CONFIG_DATA_LEN as u8;
        let flags = ((self.a_flag as u8) << 4) | (self.pcs & 0x07);
        out[2] = flags;
        out[3] = self.dio_int_doublings;
        out[4] = self.dio_int_min;
        out[5] = self.dio_redundancy_const;
        out[6] = (self.max_rank_increase >> 8) as u8;
        out[7] = self.max_rank_increase as u8;
        out[8] = (self.min_hop_rank_increase >> 8) as u8;
        out[9] = self.min_hop_rank_increase as u8;
        out[10] = (self.ocp >> 8) as u8;
        out[11] = self.ocp as u8;
        out[12] = 0;
        out[13] = self.def_lifetime;
        out[14] = (self.lifetime_unit >> 8) as u8;
        out[15] = self.lifetime_unit as u8;
        Ok(needed)
    }
}

// ── RPL Target option (type 5) ────────────────────────────────────────────────

/// RPL Target — advertises a /128 target address in a DAO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RplTarget {
    pub prefix_len: u8,
    pub prefix: [u8; 16],
}

impl RplTarget {
    /// Parse from the option data bytes (after type/length).
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let prefix_len = data[1];
        // IPv6 prefix cannot exceed 128 bits (16 bytes)
        if prefix_len > 128 {
            return Err(RplError::InvalidOption);
        }
        let nbytes = (prefix_len as usize).div_ceil(8);
        if data.len() < 2 + nbytes {
            return Err(TooShort::new(2 + nbytes, data.len()).into());
        }
        let mut prefix = [0u8; 16];
        prefix[..nbytes].copy_from_slice(&data[2..2 + nbytes]);
        Ok(Self { prefix_len, prefix })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        // Always encode full /128 for simplicity
        let nbytes = (self.prefix_len as usize).div_ceil(8);
        let data_len = 2 + nbytes;
        let needed = 2 + data_len;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = OPT_RPL_TARGET;
        out[1] = data_len as u8;
        out[2] = 0; // flags
        out[3] = self.prefix_len;
        out[4..4 + nbytes].copy_from_slice(&self.prefix[..nbytes]);
        Ok(needed)
    }
}

// ── Transit Information option (type 6) ──────────────────────────────────────

/// Transit Information option (RFC 6550 6.7.8). E flag (bit 7 of first data
/// byte) indicates whether Parent Address is present; LICHEN always uses E=1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitInfo {
    pub path_control: u8,
    pub path_sequence: u8,
    pub path_lifetime: u8,
    pub parent_address: [u8; 16],
}

impl TransitInfo {
    pub const DATA_LEN: usize = 20; // flags(1)+path_ctl(1)+path_seq(1)+path_life(1)+addr(16)

    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < Self::DATA_LEN {
            return Err(TooShort::new(Self::DATA_LEN, data.len()).into());
        }
        // SAFETY: length check above ensures data.len() >= DATA_LEN (20),
        // so 4..20 is within bounds and exactly 16 bytes. E flag (data[0] bit 7)
        // is asserted by caller tests per aligned E/Parent contract.
        Ok(Self {
            path_control: data[1],
            path_sequence: data[2],
            path_lifetime: data[3],
            parent_address: data[4..20].try_into().unwrap(),
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 2 + Self::DATA_LEN;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = OPT_TRANSIT_INFO;
        out[1] = Self::DATA_LEN as u8;
        out[2] = 0x80; // E=1 (parent address present) per RFC 6550 6.7.8, aligned with Python
        out[3] = self.path_control;
        out[4] = self.path_sequence;
        out[5] = self.path_lifetime;
        out[6..22].copy_from_slice(&self.parent_address);
        Ok(needed)
    }
}

// ── TLV option iterator ───────────────────────────────────────────────────────

/// An iterator over RPL TLV options in a byte slice.
#[derive(Debug)]
pub struct OptionIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OptionIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

/// A single parsed option reference (data slice excludes type/length bytes).
#[derive(Clone, Debug)]
pub struct RawOption<'a> {
    pub opt_type: u8,
    pub data: &'a [u8],
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = Result<RawOption<'a>, RplError>;

    fn next(&mut self) -> Option<Self::Item> {
        // SECURITY: Skip PAD1 bytes iteratively to prevent stack overflow
        // from malicious packets with many consecutive PAD1 bytes
        while self.pos < self.data.len() && self.data[self.pos] == OPT_PAD1 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return None;
        }
        let opt_type = self.data[self.pos];
        if self.pos + 2 > self.data.len() {
            return Some(Err(TooShort::new(self.pos + 2, self.data.len()).into()));
        }
        let length = self.data[self.pos + 1] as usize;
        if self.pos + 2 + length > self.data.len() {
            return Some(Err(RplError::OptionOverrun));
        }
        let data = &self.data[self.pos + 2..self.pos + 2 + length];
        self.pos += 2 + length;
        Some(Ok(RawOption { opt_type, data }))
    }
}

// ── Helper: append raw option bytes to a buffer ───────────────────────────────

/// Append a pre-encoded option to `buf[pos..]`. Returns the new position.
pub fn append_option(buf: &mut [u8], pos: usize, option_bytes: &[u8]) -> Result<usize, RplError> {
    let end = pos + option_bytes.len();
    if end > buf.len() {
        return Err(BufferTooSmall::new(end, buf.len()).into());
    }
    buf[pos..end].copy_from_slice(option_bytes);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DIO round-trip ────────────────────────────────────────────────────────

    #[test]
    fn dio_encode_decode_roundtrip() {
        let mut dodag_id = [0u8; 16];
        dodag_id[0] = 0xfd;
        dodag_id[15] = 1;

        let orig = Dio {
            rpl_instance_id: 0,
            version: 1,
            rank: 256,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 42,
            flags: 0,
            dodag_id,
        };

        let mut buf = [0u8; 24];
        orig.write_to(&mut buf).unwrap();

        // gmop = (1<<7) | (1<<3) | 0 = 0x88
        assert_eq!(buf[0], 0); // instance id
        assert_eq!(buf[1], 1); // version
        assert_eq!(&buf[2..4], &[0x01, 0x00]); // rank 256 BE
        assert_eq!(buf[4], 0x88); // gmop
        assert_eq!(buf[5], 42); // dtsn
        assert_eq!(&buf[8..24], &dodag_id);

        let decoded = Dio::from_bytes(&buf).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn dio_too_short() {
        assert_eq!(
            Dio::from_bytes(&[0u8; 23]),
            Err(TooShort::new(24, 23).into())
        );
    }

    // ── DAO round-trip ────────────────────────────────────────────────────────

    #[test]
    fn dao_encode_decode_roundtrip() {
        let mut dodag_id = [0u8; 16];
        dodag_id[0] = 0xfd;

        let orig = Dao {
            rpl_instance_id: 0,
            ack_requested: false,
            flags: 0,
            dao_sequence: 7,
            dodag_id: Some(dodag_id),
        };

        let mut buf = [0u8; 20];
        orig.write_to(&mut buf).unwrap();

        // kd: K=0, D=1 → 0x40
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 0x40);
        assert_eq!(buf[2], 0); // reserved
        assert_eq!(buf[3], 7); // sequence
        assert_eq!(&buf[4..20], &dodag_id);

        let decoded = Dao::from_bytes(&buf).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn dao_ack_requested_sets_k_flag() {
        let mut dodag_id = [0u8; 16];
        dodag_id[0] = 0xfd;
        let dao = Dao {
            rpl_instance_id: 0,
            ack_requested: true,
            flags: 0,
            dao_sequence: 1,
            dodag_id: Some(dodag_id),
        };
        let mut buf = [0u8; 20];
        dao.write_to(&mut buf).unwrap();
        assert_eq!(buf[1], 0xC0); // K=1, D=1
    }

    #[test]
    fn dao_supports_d_flag_zero() {
        // Per RFC 6550 both D=0 and D=1 valid; LICHEN prefers D=1 but
        // accepts D=0 with zeroed DODAGID for interop (use DIO DODAGID).
        let mut buf = [0u8; 20];
        buf[0] = 0; // rpl_instance_id
        buf[1] = 0x00; // K=0, D=0, flags=0
        buf[2] = 0; // reserved
        buf[3] = 1; // dao_sequence
        let dao = Dao::from_bytes(&buf).unwrap();
        assert_eq!(dao.rpl_instance_id, 0);
        assert!(!dao.ack_requested);
        assert_eq!(dao.flags, 0);
        assert_eq!(dao.dao_sequence, 1);
        assert_eq!(dao.dodag_id, [0u8; 16]);
    }

    #[test]
    fn dao_accepts_d_flag_one() {
        // DAO with D=1 (LICHEN/SCHC preferred case)
        let mut buf = [0u8; 20];
        buf[0] = 0; // rpl_instance_id
        buf[1] = 0x40; // K=0, D=1, flags=0
        buf[2] = 0; // reserved
        buf[3] = 5; // dao_sequence
        buf[4] = 0xfd; // DODAGID starts here
        let dao = Dao::from_bytes(&buf).unwrap();
        assert_eq!(dao.rpl_instance_id, 0);
        assert!(!dao.ack_requested);
        assert_eq!(dao.dao_sequence, 5);
        assert_eq!(dao.dodag_id[0], 0xfd);
    }

    #[test]
    fn dao_origin_signature_codec_and_envelope_are_exact() {
        let signature = [0x5a; 48];
        let mut option = [0u8; DAO_ORIGIN_SIGNATURE_LEN];
        assert_eq!(
            DaoOriginSignature::write_to(0x0102_0304_0506_0708, &signature, &mut option).unwrap(),
            58
        );
        assert_eq!(&option[..10], &[0x12, 56, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut wire = [0u8; 62];
        wire[..4].copy_from_slice(&[0, 0, 0, 7]);
        wire[4..].copy_from_slice(&option);
        let envelope = SignedDaoEnvelope::from_bytes(&wire).unwrap();
        assert_eq!(envelope.unsigned_bytes, &[0, 0, 0, 7]);
        assert_eq!(envelope.origin.origin_sequence, 0x0102_0304_0506_0708);
        assert_eq!(envelope.origin.signature, &signature);
    }

    #[test]
    fn dao_origin_signature_must_be_unique_terminal_and_complete() {
        let mut valid = [0u8; 62];
        valid[..4].copy_from_slice(&[0, 0, 0, 1]);
        DaoOriginSignature::write_to(1, &[7; 48], &mut valid[4..]).unwrap();
        assert!(SignedDaoEnvelope::from_bytes(&valid[..4]).is_err());
        assert!(SignedDaoEnvelope::from_bytes(&valid[..61]).is_err());

        let mut trailing = [0u8; 63];
        trailing[..62].copy_from_slice(&valid);
        assert!(SignedDaoEnvelope::from_bytes(&trailing).is_err());

        let mut duplicate = [0u8; 120];
        duplicate[..62].copy_from_slice(&valid);
        duplicate[62..].copy_from_slice(&valid[4..]);
        assert!(SignedDaoEnvelope::from_bytes(&duplicate).is_err());

        let mut zero = valid;
        zero[6..14].fill(0);
        assert!(SignedDaoEnvelope::from_bytes(&zero).is_err());
    }

    #[test]
    fn signed_dao_checks_base_and_frames_supported_option_kinds() {
        let target = RplTarget {
            prefix_len: 128,
            prefix: [0x44; 16],
        };
        let mut wire = [0u8; 82];
        wire[..4].copy_from_slice(&[0, 0, 0, 1]);
        target.write_to(&mut wire[4..24]).unwrap();
        DaoOriginSignature::write_to(1, &[7; 48], &mut wire[24..]).unwrap();
        assert!(SignedDaoEnvelope::from_bytes(&wire).is_ok());

        let mut flags = wire;
        flags[1] = 1;
        assert!(matches!(
            SignedDaoEnvelope::from_bytes(&flags),
            Err(DaoEnvelopeError::Rpl(RplError::InvalidOption))
        ));
        let mut reserved = wire;
        reserved[2] = 1;
        assert!(matches!(
            SignedDaoEnvelope::from_bytes(&reserved),
            Err(DaoEnvelopeError::Rpl(RplError::InvalidOption))
        ));
        let mut prefix = wire;
        prefix[7] = 64;
        assert!(SignedDaoEnvelope::from_bytes(&prefix).is_ok());

        let mut descriptor = [0u8; 68];
        descriptor[..4].copy_from_slice(&[0, 0, 0, 1]);
        descriptor[4..10].copy_from_slice(&[OPT_RPL_TARGET_DESCRIPTOR, 4, 0, 0, 0, 1]);
        DaoOriginSignature::write_to(1, &[7; 48], &mut descriptor[10..]).unwrap();
        assert!(SignedDaoEnvelope::from_bytes(&descriptor).is_ok());
    }

    // ── RPL Target option ─────────────────────────────────────────────────────

    #[test]
    fn rpl_target_encode_decode() {
        let mut prefix = [0u8; 16];
        prefix[0] = 0xfe;
        prefix[1] = 0x80;
        prefix[15] = 1;

        let target = RplTarget {
            prefix_len: 128,
            prefix,
        };
        let mut buf = [0u8; 22];
        let n = target.write_to(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_RPL_TARGET);
        assert_eq!(buf[1], 18); // 2 + 16 bytes for /128
        assert_eq!(buf[2], 0); // flags
        assert_eq!(buf[3], 128); // prefix_len
        assert_eq!(&buf[4..20], &prefix);
        assert_eq!(n, 20);

        let decoded = RplTarget::from_bytes(&buf[2..n]).unwrap();
        assert_eq!(decoded, target);
    }

    // ── Transit Information option ────────────────────────────────────────────

    #[test]
    fn transit_info_encode_decode() {
        let mut parent = [0u8; 16];
        parent[0] = 0xfe;
        parent[1] = 0x80;
        parent[15] = 0x02;

        let ti = TransitInfo {
            path_control: 0,
            path_sequence: 3,
            path_lifetime: 255,
            parent_address: parent,
        };
        let mut buf = [0u8; 24];
        let n = ti.write_to(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_TRANSIT_INFO);
        assert_eq!(buf[1], 20);
        assert_eq!(buf[2], 0x80); // E=1 parent present
        assert_eq!(buf[3], 0); // path_control
        assert_eq!(buf[4], 3); // path_sequence
        assert_eq!(buf[5], 255); // path_lifetime
        assert_eq!(&buf[6..22], &parent);

        let decoded = TransitInfo::from_bytes(&buf[2..n]).unwrap();
        assert_eq!(decoded, ti);
    }

    // ── DODAG Configuration option ────────────────────────────────────────────

    #[test]
    fn dodag_config_encode_decode() {
        let cfg = DodagConfig::default();
        let mut buf = [0u8; 20];
        let n = cfg.write_to(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_DODAG_CONFIG);
        assert_eq!(buf[1], 14);

        let decoded = DodagConfig::from_bytes(&buf[2..n]).unwrap();
        assert_eq!(decoded.pcs, 0);
        assert!(!decoded.a_flag);
        assert_eq!(decoded.min_hop_rank_increase, 256);
        assert_eq!(decoded.max_rank_increase, 2048);
        assert_eq!(decoded.ocp, 1);
    }

    #[test]
    fn dodag_config_rejects_nonzero_reserved() {
        let mut data = [0u8; DODAG_CONFIG_DATA_LEN];
        data[10] = 1; // nonzero reserved
        assert!(matches!(
            DodagConfig::from_bytes(&data),
            Err(RplError::InvalidOption)
        ));
    }

    // ── Option iterator ───────────────────────────────────────────────────────

    #[test]
    fn option_iter_parses_target_and_transit() {
        let mut target_addr = [0u8; 16];
        target_addr[15] = 3;
        let mut parent_addr = [0u8; 16];
        parent_addr[15] = 2;

        let target = RplTarget {
            prefix_len: 128,
            prefix: target_addr,
        };
        let transit = TransitInfo {
            path_control: 0,
            path_sequence: 0,
            path_lifetime: 255,
            parent_address: parent_addr,
        };

        let mut buf = [0u8; 50];
        let mut pos = 0;
        let mut tmp = [0u8; 25];
        let n = target.write_to(&mut tmp).unwrap();
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;
        let n = transit.write_to(&mut tmp).unwrap();
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;

        let mut found_target = false;
        let mut found_transit = false;
        for opt in OptionIter::new(&buf[..pos]) {
            let opt = opt.unwrap();
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    found_target = true;
                    let t = RplTarget::from_bytes(opt.data).unwrap();
                    assert_eq!(t.prefix, target_addr);
                }
                OPT_TRANSIT_INFO => {
                    found_transit = true;
                    let ti = TransitInfo::from_bytes(opt.data).unwrap();
                    assert_eq!(ti.parent_address, parent_addr);
                }
                _ => {}
            }
        }
        assert!(found_target);
        assert!(found_transit);
    }

    #[test]
    fn option_iter_handles_many_pad1_bytes() {
        // Regression test: many PAD1 bytes must not cause stack overflow
        // (fixed by using iterative loop instead of recursion)
        let mut buf = [0u8; 300];
        // 200 PAD1 bytes followed by a valid target option
        let pad1_count = 200;
        for byte in buf.iter_mut().take(pad1_count) {
            *byte = OPT_PAD1;
        }
        // Add a minimal RPL Target after the PAD1 bytes
        let mut target_addr = [0u8; 16];
        target_addr[15] = 0x42;
        let target = RplTarget {
            prefix_len: 128,
            prefix: target_addr,
        };
        let mut tmp = [0u8; 25];
        let n = target.write_to(&mut tmp).unwrap();
        buf[pad1_count..pad1_count + n].copy_from_slice(&tmp[..n]);
        let total_len = pad1_count + n;

        // Verify iterator skips PAD1 bytes and finds the target
        let mut iter = OptionIter::new(&buf[..total_len]);
        let opt = iter.next().unwrap().unwrap();
        assert_eq!(opt.opt_type, OPT_RPL_TARGET);
        let decoded = RplTarget::from_bytes(opt.data).unwrap();
        assert_eq!(decoded.prefix, target_addr);
        assert!(iter.next().is_none());
    }

    #[test]
    fn option_iter_all_pad1_returns_none() {
        // Buffer with only PAD1 bytes should return None (no options)
        let buf = [OPT_PAD1; 100];
        let mut iter = OptionIter::new(&buf);
        assert!(iter.next().is_none());
    }
}
