//! RPL control message codecs — DIO / DAO / DIS / DAO-ACK (RFC 6550).
//!
//! Wire layout matches the Python reference in
//! `python/src/lichen/rpl/messages.py` and `dao.py`.
//!
//! All integer fields are big-endian. The module is no_std; no allocation.

/// Error returned when a message or option is malformed.
#[derive(Debug, PartialEq, Eq)]
pub enum RplError {
    TooShort,
    OptionOverrun,
    BadOptionType(u8),
    BufferTooSmall,
}

// ── Option type bytes ─────────────────────────────────────────────────────────

pub const OPT_PAD1: u8 = 0;
pub const OPT_PADN: u8 = 1;
pub const OPT_DAG_METRIC: u8 = 2;
pub const OPT_DODAG_CONFIG: u8 = 4;
pub const OPT_RPL_TARGET: u8 = 5;
pub const OPT_TRANSIT_INFO: u8 = 6;
pub const OPT_PREFIX_INFO: u8 = 8;

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

    pub fn parse(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < Self::BASE_LEN {
            return Err(RplError::TooShort);
        }
        let gmop = data[4];
        Ok(Self {
            rpl_instance_id: data[0],
            version: data[1],
            rank: u16::from_be_bytes([data[2], data[3]]),
            grounded: (gmop >> 7) & 1 == 1,
            mode_of_operation: (gmop >> 3) & 0x7,
            preference: gmop & 0x7,
            dtsn: data[5],
            flags: data[6],
            dodag_id: data[8..24].try_into().unwrap(),
        })
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if out.len() < Self::BASE_LEN {
            return Err(RplError::BufferTooSmall);
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

/// DAO base object with DODAGID always present (D-flag = 1), as required by
/// SCHC rule 4. The base is 20 bytes.
///
/// In a full decompressed packet the DAO base starts at offset 44; options
/// start at offset 64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dao {
    pub rpl_instance_id: u8,
    pub ack_requested: bool,
    pub flags: u8,
    pub dao_sequence: u8,
    pub dodag_id: [u8; 16],
}

impl Dao {
    pub const BASE_LEN: usize = 20;

    pub fn parse(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < Self::BASE_LEN {
            return Err(RplError::TooShort);
        }
        let kd = data[1];
        Ok(Self {
            rpl_instance_id: data[0],
            ack_requested: (kd >> 7) & 1 == 1,
            flags: kd & 0x3F,
            dao_sequence: data[3],
            dodag_id: data[4..20].try_into().unwrap(),
        })
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if out.len() < Self::BASE_LEN {
            return Err(RplError::BufferTooSmall);
        }
        let kd = ((self.ack_requested as u8) << 7)
            | (1u8 << 6) // D-flag always set
            | (self.flags & 0x3F);
        out[0] = self.rpl_instance_id;
        out[1] = kd;
        out[2] = 0; // reserved
        out[3] = self.dao_sequence;
        out[4..20].copy_from_slice(&self.dodag_id);
        Ok(Self::BASE_LEN)
    }

    pub fn options_tail(data: &[u8]) -> &[u8] {
        if data.len() > Self::BASE_LEN {
            &data[Self::BASE_LEN..]
        } else {
            &[]
        }
    }
}

// ── DODAG Configuration option (type 4) ──────────────────────────────────────

pub const DODAG_CONFIG_DATA_LEN: usize = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DodagConfig {
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
            min_hop_rank_increase: 256,
            max_rank_increase: 2048,
            ocp: 1, // MRHOF
            def_lifetime: 0xFF,
            lifetime_unit: 60,
            dio_int_min: 3,
            dio_int_doublings: 8,
            dio_redundancy_const: 10,
        }
    }
}

impl DodagConfig {
    pub fn parse(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < DODAG_CONFIG_DATA_LEN {
            return Err(RplError::TooShort);
        }
        Ok(Self {
            dio_int_doublings: data[1],
            dio_int_min: data[2],
            dio_redundancy_const: data[3],
            max_rank_increase: u16::from_be_bytes([data[4], data[5]]),
            min_hop_rank_increase: u16::from_be_bytes([data[6], data[7]]),
            ocp: u16::from_be_bytes([data[8], data[9]]),
            def_lifetime: data[11],
            lifetime_unit: u16::from_be_bytes([data[12], data[13]]),
        })
    }

    pub fn encode_option(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 2 + DODAG_CONFIG_DATA_LEN;
        if out.len() < needed {
            return Err(RplError::BufferTooSmall);
        }
        out[0] = OPT_DODAG_CONFIG;
        out[1] = DODAG_CONFIG_DATA_LEN as u8;
        out[2] = 0; // A/PCS flags
        out[3] = self.dio_int_doublings;
        out[4] = self.dio_int_min;
        out[5] = self.dio_redundancy_const;
        out[6] = (self.max_rank_increase >> 8) as u8;
        out[7] = self.max_rank_increase as u8;
        out[8] = (self.min_hop_rank_increase >> 8) as u8;
        out[9] = self.min_hop_rank_increase as u8;
        out[10] = (self.ocp >> 8) as u8;
        out[11] = self.ocp as u8;
        out[12] = 0; // reserved
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
    pub fn parse(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 2 {
            return Err(RplError::TooShort);
        }
        let prefix_len = data[1];
        let nbytes = (prefix_len as usize).div_ceil(8);
        if data.len() < 2 + nbytes {
            return Err(RplError::TooShort);
        }
        let mut prefix = [0u8; 16];
        prefix[..nbytes].copy_from_slice(&data[2..2 + nbytes]);
        Ok(Self { prefix_len, prefix })
    }

    pub fn encode_option(&self, out: &mut [u8]) -> Result<usize, RplError> {
        // Always encode full /128 for simplicity
        let nbytes = (self.prefix_len as usize).div_ceil(8);
        let data_len = 2 + nbytes;
        let needed = 2 + data_len;
        if out.len() < needed {
            return Err(RplError::BufferTooSmall);
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

/// Transit Information — carries the parent address in a DAO.
///
/// LICHEN always includes the parent address (20-byte data field).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitInfo {
    pub path_control: u8,
    pub path_sequence: u8,
    pub path_lifetime: u8,
    pub parent_address: [u8; 16],
}

impl TransitInfo {
    pub const DATA_LEN: usize = 20; // flags(1)+path_ctl(1)+path_seq(1)+path_life(1)+addr(16)

    pub fn parse(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < Self::DATA_LEN {
            return Err(RplError::TooShort);
        }
        Ok(Self {
            path_control: data[1],
            path_sequence: data[2],
            path_lifetime: data[3],
            parent_address: data[4..20].try_into().unwrap(),
        })
    }

    pub fn encode_option(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 2 + Self::DATA_LEN;
        if out.len() < needed {
            return Err(RplError::BufferTooSmall);
        }
        out[0] = OPT_TRANSIT_INFO;
        out[1] = Self::DATA_LEN as u8;
        out[2] = 0; // flags (E=0 for internal target)
        out[3] = self.path_control;
        out[4] = self.path_sequence;
        out[5] = self.path_lifetime;
        out[6..22].copy_from_slice(&self.parent_address);
        Ok(needed)
    }
}

// ── TLV option iterator ───────────────────────────────────────────────────────

/// An iterator over RPL TLV options in a byte slice.
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
        if self.pos >= self.data.len() {
            return None;
        }
        let opt_type = self.data[self.pos];
        if opt_type == OPT_PAD1 {
            self.pos += 1;
            return self.next();
        }
        if self.pos + 2 > self.data.len() {
            return Some(Err(RplError::TooShort));
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
        return Err(RplError::BufferTooSmall);
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
        orig.encode(&mut buf).unwrap();

        // gmop = (1<<7) | (1<<3) | 0 = 0x88
        assert_eq!(buf[0], 0); // instance id
        assert_eq!(buf[1], 1); // version
        assert_eq!(&buf[2..4], &[0x01, 0x00]); // rank 256 BE
        assert_eq!(buf[4], 0x88); // gmop
        assert_eq!(buf[5], 42); // dtsn
        assert_eq!(&buf[8..24], &dodag_id);

        let decoded = Dio::parse(&buf).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn dio_too_short() {
        assert_eq!(Dio::parse(&[0u8; 23]), Err(RplError::TooShort));
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
            dodag_id,
        };

        let mut buf = [0u8; 20];
        orig.encode(&mut buf).unwrap();

        // kd: K=0, D=1 → 0x40
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 0x40);
        assert_eq!(buf[2], 0); // reserved
        assert_eq!(buf[3], 7); // sequence
        assert_eq!(&buf[4..20], &dodag_id);

        let decoded = Dao::parse(&buf).unwrap();
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
            dodag_id,
        };
        let mut buf = [0u8; 20];
        dao.encode(&mut buf).unwrap();
        assert_eq!(buf[1], 0xC0); // K=1, D=1
    }

    // ── RPL Target option ─────────────────────────────────────────────────────

    #[test]
    fn rpl_target_encode_decode() {
        let mut prefix = [0u8; 16];
        prefix[0] = 0xfe;
        prefix[1] = 0x80;
        prefix[15] = 1;

        let target = RplTarget { prefix_len: 128, prefix };
        let mut buf = [0u8; 22];
        let n = target.encode_option(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_RPL_TARGET);
        assert_eq!(buf[1], 18); // 2 + 16 bytes for /128
        assert_eq!(buf[2], 0);  // flags
        assert_eq!(buf[3], 128); // prefix_len
        assert_eq!(&buf[4..20], &prefix);
        assert_eq!(n, 20);

        let decoded = RplTarget::parse(&buf[2..n]).unwrap();
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
        let n = ti.encode_option(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_TRANSIT_INFO);
        assert_eq!(buf[1], 20);
        assert_eq!(buf[4], 3);   // path_sequence
        assert_eq!(buf[5], 255); // path_lifetime
        assert_eq!(&buf[6..22], &parent);

        let decoded = TransitInfo::parse(&buf[2..n]).unwrap();
        assert_eq!(decoded, ti);
    }

    // ── DODAG Configuration option ────────────────────────────────────────────

    #[test]
    fn dodag_config_encode_decode() {
        let cfg = DodagConfig::default();
        let mut buf = [0u8; 20];
        let n = cfg.encode_option(&mut buf).unwrap();
        assert_eq!(buf[0], OPT_DODAG_CONFIG);
        assert_eq!(buf[1], 14);

        let decoded = DodagConfig::parse(&buf[2..n]).unwrap();
        assert_eq!(decoded.min_hop_rank_increase, 256);
        assert_eq!(decoded.max_rank_increase, 2048);
        assert_eq!(decoded.ocp, 1);
    }

    // ── Option iterator ───────────────────────────────────────────────────────

    #[test]
    fn option_iter_parses_target_and_transit() {
        let mut target_addr = [0u8; 16];
        target_addr[15] = 3;
        let mut parent_addr = [0u8; 16];
        parent_addr[15] = 2;

        let target = RplTarget { prefix_len: 128, prefix: target_addr };
        let transit = TransitInfo {
            path_control: 0,
            path_sequence: 0,
            path_lifetime: 255,
            parent_address: parent_addr,
        };

        let mut buf = [0u8; 50];
        let mut pos = 0;
        let mut tmp = [0u8; 25];
        let n = target.encode_option(&mut tmp).unwrap();
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;
        let n = transit.encode_option(&mut tmp).unwrap();
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;

        let mut found_target = false;
        let mut found_transit = false;
        for opt in OptionIter::new(&buf[..pos]) {
            let opt = opt.unwrap();
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    found_target = true;
                    let t = RplTarget::parse(opt.data).unwrap();
                    assert_eq!(t.prefix, target_addr);
                }
                OPT_TRANSIT_INFO => {
                    found_transit = true;
                    let ti = TransitInfo::parse(opt.data).unwrap();
                    assert_eq!(ti.parent_address, parent_addr);
                }
                _ => {}
            }
        }
        assert!(found_target);
        assert!(found_transit);
    }
}
