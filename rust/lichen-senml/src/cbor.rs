//! SenML-CBOR encode/decode (RFC 8428 §6, Content-Format 112).
//!
//! Encodes/decodes SenML packs as CBOR arrays-of-maps with integer labels.
//! Supports the `Record` fields: n(0), u(1), v(2), vs(3), vb(4), t(6),
//! bn(-2), bt(-3). Unknown keys on decode are silently skipped.
//!
//! No heap allocation — all I/O through caller-supplied byte slices.

use crate::record::Record;

/// Error type for CBOR encode/decode.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborError {
    BufferTooSmall,
    InvalidInput,
    NotImplemented,
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidInput => write!(f, "invalid CBOR input"),
            Self::NotImplemented => write!(f, "CBOR feature not implemented"),
        }
    }
}

impl core::error::Error for CborError {}

// RFC 8428 §6 Table 4 integer labels
const L_BN: i8 = -2; // base name
const L_BT: i8 = -3; // base time
const L_N: u8 = 0; // name
const L_U: u8 = 1; // unit
const L_V: u8 = 2; // value (numeric)
const L_VS: u8 = 3; // value (string)
const L_VB: u8 = 4; // value (bool)
const L_T: u8 = 6; // time

// ── Encoder ──────────────────────────────────────────────────────────────────

fn enc_head(out: &mut [u8], pos: usize, major: u8, n: u64) -> Result<usize, CborError> {
    match n {
        0..=23 => {
            if pos >= out.len() {
                return Err(CborError::BufferTooSmall);
            }
            out[pos] = major | n as u8;
            Ok(1)
        }
        24..=0xff => {
            if pos + 2 > out.len() {
                return Err(CborError::BufferTooSmall);
            }
            out[pos] = major | 24;
            out[pos + 1] = n as u8;
            Ok(2)
        }
        _ => Err(CborError::BufferTooSmall),
    }
}

fn enc_key_pos(out: &mut [u8], pos: usize, k: u8) -> Result<usize, CborError> {
    enc_head(out, pos, 0x00, k as u64)
}

fn enc_key_neg(out: &mut [u8], pos: usize, k: i8) -> Result<usize, CborError> {
    // CBOR major type 1 (0x20): stored value = -(k) - 1
    let v = (-(k as i16) - 1) as u64;
    enc_head(out, pos, 0x20, v)
}

fn enc_text(out: &mut [u8], pos: usize, s: &str) -> Result<usize, CborError> {
    let bytes = s.as_bytes();
    let h = enc_head(out, pos, 0x60, bytes.len() as u64)?;
    if pos + h + bytes.len() > out.len() {
        return Err(CborError::BufferTooSmall);
    }
    out[pos + h..pos + h + bytes.len()].copy_from_slice(bytes);
    Ok(h + bytes.len())
}

fn enc_f64(out: &mut [u8], pos: usize, f: f64) -> Result<usize, CborError> {
    if pos + 9 > out.len() {
        return Err(CborError::BufferTooSmall);
    }
    out[pos] = 0xfb; // major 7, additional 27 (8-byte float)
    out[pos + 1..pos + 9].copy_from_slice(&f.to_bits().to_be_bytes());
    Ok(9)
}

fn enc_bool(out: &mut [u8], pos: usize, b: bool) -> Result<usize, CborError> {
    if pos >= out.len() {
        return Err(CborError::BufferTooSmall);
    }
    out[pos] = if b { 0xf5 } else { 0xf4 };
    Ok(1)
}

fn field_count(r: &Record<'_>) -> u64 {
    [
        r.base_name.is_some(),
        r.base_time.is_some(),
        r.name.is_some(),
        r.unit.is_some(),
        r.value.is_some(),
        r.string_value.is_some(),
        r.bool_value.is_some(),
        r.time.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u64
}

/// Encode a slice of records into `out` as SenML-CBOR.
///
/// Returns the number of bytes written, or an error if `out` is too small.
pub fn encode<'a>(records: &[Record<'a>], out: &mut [u8]) -> Result<usize, CborError> {
    let mut p = 0;
    p += enc_head(out, p, 0x80, records.len() as u64)?;
    for r in records {
        p += enc_head(out, p, 0xa0, field_count(r))?;
        if let Some(s) = r.base_name {
            p += enc_key_neg(out, p, L_BN)?;
            p += enc_text(out, p, s)?;
        }
        if let Some(f) = r.base_time {
            p += enc_key_neg(out, p, L_BT)?;
            p += enc_f64(out, p, f)?;
        }
        if let Some(s) = r.name {
            p += enc_key_pos(out, p, L_N)?;
            p += enc_text(out, p, s)?;
        }
        if let Some(s) = r.unit {
            p += enc_key_pos(out, p, L_U)?;
            p += enc_text(out, p, s)?;
        }
        if let Some(f) = r.value {
            p += enc_key_pos(out, p, L_V)?;
            p += enc_f64(out, p, f)?;
        }
        if let Some(s) = r.string_value {
            p += enc_key_pos(out, p, L_VS)?;
            p += enc_text(out, p, s)?;
        }
        if let Some(b) = r.bool_value {
            p += enc_key_pos(out, p, L_VB)?;
            p += enc_bool(out, p, b)?;
        }
        if let Some(f) = r.time {
            p += enc_key_pos(out, p, L_T)?;
            p += enc_f64(out, p, f)?;
        }
    }
    Ok(p)
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Returns `(major_type, additional_value, header_byte_count)`.
fn dec_head(data: &[u8], pos: usize) -> Result<(u8, u64, usize), CborError> {
    if pos >= data.len() {
        return Err(CborError::InvalidInput);
    }
    let b = data[pos];
    let major = b >> 5;
    let info = b & 0x1f;
    match info {
        0..=23 => Ok((major, info as u64, 1)),
        24 => {
            if pos + 2 > data.len() {
                return Err(CborError::InvalidInput);
            }
            Ok((major, data[pos + 1] as u64, 2))
        }
        25 => {
            if pos + 3 > data.len() {
                return Err(CborError::InvalidInput);
            }
            let v = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
            Ok((major, v as u64, 3))
        }
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_int(data: &[u8], pos: usize) -> Result<(i64, usize), CborError> {
    let (major, val, adv) = dec_head(data, pos)?;
    match major {
        0 => Ok((val as i64, adv)),
        1 => Ok(((-(val as i64)).wrapping_sub(1), adv)),
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_text<'a>(data: &'a [u8], pos: usize) -> Result<(&'a str, usize), CborError> {
    let (major, len, adv) = dec_head(data, pos)?;
    if major != 3 {
        return Err(CborError::InvalidInput);
    }
    let start = pos + adv;
    let end = start + len as usize;
    if end > data.len() {
        return Err(CborError::InvalidInput);
    }
    let s = core::str::from_utf8(&data[start..end]).map_err(|_| CborError::InvalidInput)?;
    Ok((s, adv + len as usize))
}

fn dec_f64(data: &[u8], pos: usize) -> Result<(f64, usize), CborError> {
    if pos >= data.len() {
        return Err(CborError::InvalidInput);
    }
    match data[pos] {
        0xfb => {
            if pos + 9 > data.len() {
                return Err(CborError::InvalidInput);
            }
            let b = [
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
                data[pos + 8],
            ];
            Ok((f64::from_bits(u64::from_be_bytes(b)), 9))
        }
        0xfa => {
            if pos + 5 > data.len() {
                return Err(CborError::InvalidInput);
            }
            let b = [data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]];
            Ok((f32::from_bits(u32::from_be_bytes(b)) as f64, 5))
        }
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_bool(data: &[u8], pos: usize) -> Result<(bool, usize), CborError> {
    if pos >= data.len() {
        return Err(CborError::InvalidInput);
    }
    match data[pos] {
        0xf5 => Ok((true, 1)),
        0xf4 => Ok((false, 1)),
        _ => Err(CborError::InvalidInput),
    }
}

/// Skip one CBOR item starting at `pos`; returns byte count consumed.
fn skip_one(data: &[u8], pos: usize) -> Result<usize, CborError> {
    if pos >= data.len() {
        return Err(CborError::InvalidInput);
    }
    let b = data[pos];
    let major = b >> 5;
    let info = b & 0x1f;
    let (val, adv): (u64, usize) = match info {
        0..=23 => (info as u64, 1),
        24 => {
            if pos + 2 > data.len() {
                return Err(CborError::InvalidInput);
            }
            (data[pos + 1] as u64, 2)
        }
        25 => {
            if pos + 3 > data.len() {
                return Err(CborError::InvalidInput);
            }
            (u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as u64, 3)
        }
        _ => return Err(CborError::InvalidInput),
    };
    match major {
        0 | 1 => Ok(adv),
        2 | 3 => {
            let end = pos + adv + val as usize;
            if end > data.len() {
                return Err(CborError::InvalidInput);
            }
            Ok(adv + val as usize)
        }
        4 => {
            let mut cur = pos + adv;
            for _ in 0..val {
                cur += skip_one(data, cur)?;
            }
            Ok(cur - pos)
        }
        5 => {
            let mut cur = pos + adv;
            for _ in 0..val {
                cur += skip_one(data, cur)?;
                cur += skip_one(data, cur)?;
            }
            Ok(cur - pos)
        }
        7 => match info {
            20 | 21 | 22 | 23 => Ok(1),
            25 => {
                if pos + 3 > data.len() {
                    return Err(CborError::InvalidInput);
                }
                Ok(3)
            }
            26 => {
                if pos + 5 > data.len() {
                    return Err(CborError::InvalidInput);
                }
                Ok(5)
            }
            27 => {
                if pos + 9 > data.len() {
                    return Err(CborError::InvalidInput);
                }
                Ok(9)
            }
            _ => Err(CborError::InvalidInput),
        },
        _ => Err(CborError::InvalidInput),
    }
}

/// Decode SenML-CBOR bytes into a fixed-size array of records.
///
/// Returns the number of records decoded. Unknown map keys are skipped.
/// Returns an error if the data is not a valid CBOR array-of-maps or if
/// the number of records exceeds `buf.len()`.
pub fn decode<'a>(data: &'a [u8], buf: &mut [Record<'a>]) -> Result<usize, CborError> {
    let (major, n_recs, mut pos) = dec_head(data, 0)?;
    if major != 4 {
        return Err(CborError::InvalidInput);
    }
    let n_recs = n_recs as usize;
    if n_recs > buf.len() {
        return Err(CborError::InvalidInput);
    }
    for i in 0..n_recs {
        let (major, n_kv, adv) = dec_head(data, pos)?;
        if major != 5 {
            return Err(CborError::InvalidInput);
        }
        pos += adv;
        buf[i] = Record::empty();
        for _ in 0..n_kv {
            let (key, adv) = dec_int(data, pos)?;
            pos += adv;
            match key {
                -2 => {
                    let (s, adv) = dec_text(data, pos)?;
                    buf[i].base_name = Some(s);
                    pos += adv;
                }
                -3 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    buf[i].base_time = Some(f);
                    pos += adv;
                }
                0 => {
                    let (s, adv) = dec_text(data, pos)?;
                    buf[i].name = Some(s);
                    pos += adv;
                }
                1 => {
                    let (s, adv) = dec_text(data, pos)?;
                    buf[i].unit = Some(s);
                    pos += adv;
                }
                2 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    buf[i].value = Some(f);
                    pos += adv;
                }
                3 => {
                    let (s, adv) = dec_text(data, pos)?;
                    buf[i].string_value = Some(s);
                    pos += adv;
                }
                4 => {
                    let (b, adv) = dec_bool(data, pos)?;
                    buf[i].bool_value = Some(b);
                    pos += adv;
                }
                6 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    buf[i].time = Some(f);
                    pos += adv;
                }
                _ => {
                    pos += skip_one(data, pos)?;
                }
            }
        }
    }
    Ok(n_recs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Record;

    #[test]
    fn roundtrip_numeric_record() {
        let records = [Record {
            name: Some("temp"),
            value: Some(23.5),
            unit: Some("Cel"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 64];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(decoded[0].name, Some("temp"));
        assert_eq!(decoded[0].value, Some(23.5));
        assert_eq!(decoded[0].unit, Some("Cel"));
    }

    #[test]
    fn roundtrip_bool_record() {
        let records = [Record {
            name: Some("alarm"),
            bool_value: Some(true),
            ..Record::empty()
        }];
        let mut buf = [0u8; 32];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(decoded[0].name, Some("alarm"));
        assert_eq!(decoded[0].bool_value, Some(true));
    }

    #[test]
    fn roundtrip_string_value() {
        let records = [Record {
            name: Some("status"),
            string_value: Some("ok"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 32];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(decoded[0].string_value, Some("ok"));
    }

    #[test]
    fn roundtrip_base_name_and_time() {
        let records = [Record {
            base_name: Some("urn:dev:mac:0123456789abcdef:"),
            base_time: Some(1_700_000_000.0),
            name: Some("temp"),
            value: Some(22.0),
            time: Some(0.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 128];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            decoded[0].base_name,
            Some("urn:dev:mac:0123456789abcdef:")
        );
        assert_eq!(decoded[0].base_time, Some(1_700_000_000.0));
        assert_eq!(decoded[0].time, Some(0.0));
    }

    #[test]
    fn roundtrip_empty_pack() {
        let records: [Record; 0] = [];
        let mut buf = [0u8; 16];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty(), Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn roundtrip_multiple_records() {
        let records = [
            Record {
                name: Some("temp"),
                value: Some(21.0),
                unit: Some("Cel"),
                ..Record::empty()
            },
            Record {
                name: Some("hum"),
                value: Some(65.0),
                unit: Some("%RH"),
                ..Record::empty()
            },
        ];
        let mut buf = [0u8; 128];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty(), Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 2);
        assert_eq!(decoded[0].name, Some("temp"));
        assert_eq!(decoded[1].name, Some("hum"));
        assert_eq!(decoded[1].unit, Some("%RH"));
    }

    #[test]
    fn buffer_too_small_returns_error() {
        let records = [Record {
            name: Some("a-long-name"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 2];
        assert_eq!(encode(&records, &mut buf), Err(CborError::BufferTooSmall));
    }

    #[test]
    fn decode_invalid_data_returns_error() {
        let data = [0xffu8; 3]; // not a valid CBOR array
        let mut buf = [Record::empty()];
        assert!(decode(&data, &mut buf).is_err());
    }

    #[test]
    fn decode_skips_unknown_keys() {
        // Hand-crafted: array(1) map(2) [key=99 val="x"] [key=0 val="temp"]
        // 0x81 = array(1), 0xa2 = map(2), 0x18 0x63 = uint(99), 0x61 0x78 = text("x")
        // 0x00 = uint(0), 0x64 0x74 0x65 0x6d 0x70 = text("temp")
        let data = [
            0x81, // array(1)
            0xa2, // map(2)
            0x18, 0x63, // key=99
            0x61, 0x78, // text("x")
            0x00, // key=0 (n)
            0x64, b't', b'e', b'm', b'p', // text("temp")
        ];
        let mut buf = [Record::empty()];
        let count = decode(&data, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].name, Some("temp"));
    }

    #[test]
    fn record_method_encode_parse_roundtrip() {
        let record = Record {
            name: Some("temp"),
            value: Some(23.5),
            unit: Some("Cel"),
            ..Record::empty()
        };
        let mut buf = [0u8; 64];
        let n = record.encode(&mut buf).unwrap();
        let decoded = Record::parse(&buf[..n]).unwrap();
        assert_eq!(decoded.name, Some("temp"));
        assert_eq!(decoded.value, Some(23.5));
        assert_eq!(decoded.unit, Some("Cel"));
    }

    #[test]
    fn record_parse_rejects_multi_record_pack() {
        // Create a pack with 2 records, then try to parse as single
        let records = [
            Record {
                name: Some("a"),
                ..Record::empty()
            },
            Record {
                name: Some("b"),
                ..Record::empty()
            },
        ];
        let mut buf = [0u8; 64];
        let n = encode(&records, &mut buf).unwrap();
        assert_eq!(Record::parse(&buf[..n]), Err(CborError::InvalidInput));
    }
}
