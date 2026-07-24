//! SenML-CBOR encode/decode (RFC 8428 §6, Content-Format 112).
//!
//! Encodes/decodes SenML packs as CBOR arrays-of-maps with integer labels.
//! Supports the `Record` fields: n(0), u(1), v(2), vs(3), vb(4), t(6),
//! bn(-2), bt(-3). Unknown keys on decode are silently skipped; duplicate
//! known keys within a record return InvalidInput.
//!
//! No heap allocation — all I/O through caller-supplied byte slices.

use crate::record::Record;
use lichen_core::error::BufferTooSmall;

/// Error type for CBOR encode/decode.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborError {
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
    /// Invalid CBOR input.
    InvalidInput,
    /// CBOR feature not implemented.
    NotImplemented,
    /// Multiple value fields set in a single record (RFC 8428 violation).
    MultipleValues,
    /// Resolved name too long (RFC 8428 §4.2).
    NameTooLong,
}

impl From<BufferTooSmall> for CborError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall(e) => write!(f, "SenML-CBOR {}", e),
            Self::InvalidInput => write!(f, "invalid CBOR input"),
            Self::NotImplemented => write!(f, "CBOR feature not implemented"),
            Self::MultipleValues => write!(f, "multiple value fields set (RFC 8428 violation)"),
            Self::NameTooLong => write!(f, "resolved name too long (RFC 8428 §4.2)"),
        }
    }
}

impl core::error::Error for CborError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

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
            // Consistent pos + N > len() prevents underflow (project-LICHEN-dkji)
            if pos + 1 > out.len() {
                return Err(BufferTooSmall::new(pos + 1, out.len()).into());
            }
            out[pos] = major | n as u8;
            Ok(1)
        }
        24..=0xff => {
            if pos + 2 > out.len() {
                return Err(BufferTooSmall::new(pos + 2, out.len()).into());
            }
            out[pos] = major | 24;
            out[pos + 1] = n as u8;
            Ok(2)
        }
        0x100..=0xffff => {
            if pos + 3 > out.len() {
                return Err(BufferTooSmall::new(pos + 3, out.len()).into());
            }
            out[pos] = major | 25;
            out[pos + 1] = (n >> 8) as u8;
            out[pos + 2] = n as u8;
            Ok(3)
        }
        _ => Err(CborError::NotImplemented), // Values > 65535 not supported
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
    let needed = pos + h + bytes.len();
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[pos + h..pos + h + bytes.len()].copy_from_slice(bytes);
    Ok(h + bytes.len())
}

fn enc_f64(out: &mut [u8], pos: usize, f: f64) -> Result<usize, CborError> {
    let needed = pos + 9;
    if needed > out.len() {
        return Err(BufferTooSmall::new(needed, out.len()).into());
    }
    out[pos] = 0xfb; // major 7, additional 27 (8-byte float)
    out[pos + 1..pos + 9].copy_from_slice(&f.to_bits().to_be_bytes());
    Ok(9)
}

fn enc_bool(out: &mut [u8], pos: usize, b: bool) -> Result<usize, CborError> {
    if pos + 1 > out.len() {
        return Err(BufferTooSmall::new(pos + 1, out.len()).into());
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

/// Count how many value fields are set in a record.
/// RFC 8428 Section 4.2 requires at most one of: value, string_value, bool_value.
fn value_field_count(r: &Record<'_>) -> usize {
    [
        r.value.is_some(),
        r.string_value.is_some(),
        r.bool_value.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count()
}

/// Encode a slice of records into `out` as SenML-CBOR.
///
/// Returns the number of bytes written, or an error if `out` is too small.
/// Returns `CborError::MultipleValues` if multiple value fields or
/// `CborError::NameTooLong` if resolved name exceeds 128 bytes (RFC 8428 §4.2).
pub fn encode<'a>(records: &[Record<'a>], out: &mut [u8]) -> Result<usize, CborError> {
    for r in records {
        if value_field_count(r) > 1 {
            return Err(CborError::MultipleValues);
        }
        let bn_len = r.base_name.map_or(0, |s| s.len());
        let n_len = r.name.map_or(0, |s| s.len());
        if bn_len.checked_add(n_len).map_or(true, |l| l > 128) || bn_len > 128 || n_len > 128 {
            return Err(CborError::NameTooLong);
        }
    }

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
        26 | 27 => Err(CborError::NotImplemented),
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_int(data: &[u8], pos: usize) -> Result<(i64, usize), CborError> {
    let (major, val, adv) = dec_head(data, pos)?;
    match major {
        0 => Ok((val as i64, adv)),
        1 => {
            // CBOR major type 1 encodes -(n+1), so we compute -1 - val.
            // Validate that val fits in i64 before casting to avoid wrapping.
            if val > i64::MAX as u64 {
                return Err(CborError::InvalidInput);
            }
            Ok((-(val as i64) - 1, adv))
        }
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_text(data: &[u8], pos: usize) -> Result<(&str, usize), CborError> {
    let (major, len, adv) = dec_head(data, pos)?;
    if major != 3 {
        return Err(CborError::InvalidInput);
    }
    // Use checked arithmetic to prevent overflow on 16-bit platforms.
    // len can be up to 65535 from 2-byte length encoding, which would
    // wrap on 16-bit usize if added carelessly.
    let len_usize = usize::try_from(len).map_err(|_| CborError::InvalidInput)?;
    let start = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
    let end = start
        .checked_add(len_usize)
        .ok_or(CborError::InvalidInput)?;
    if end > data.len() {
        return Err(CborError::InvalidInput);
    }
    let s = core::str::from_utf8(&data[start..end]).map_err(|_| CborError::InvalidInput)?;
    let total_adv = adv.checked_add(len_usize).ok_or(CborError::InvalidInput)?;
    Ok((s, total_adv))
}

/// Convert IEEE 754 half-precision (binary16) bits to f64.
///
/// Half-precision format: 1 sign bit, 5 exponent bits (bias 15), 10 mantissa bits.
fn f16_to_f64(bits: u16) -> f64 {
    let sign = (bits >> 15) & 1;
    let exp = (bits >> 10) & 0x1f;
    let mant = bits & 0x3ff;

    let val = match exp {
        0 => {
            if mant == 0 {
                0.0
            } else {
                (mant as f64) / 16777216.0
            }
        }
        31 => {
            if mant == 0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => {
            let f64_exp = ((exp as i32) - 15 + 1023) as u64;
            let f64_mant = (mant as u64) << 42;
            let f64_bits = ((sign as u64) << 63) | (f64_exp << 52) | f64_mant;
            f64::from_bits(f64_bits)
        }
    };

    let bits = val.to_bits();
    if sign == 1 {
        f64::from_bits(bits | (1u64 << 63))
    } else {
        val
    }
}

fn dec_f64(data: &[u8], pos: usize) -> Result<(f64, usize), CborError> {
    if pos >= data.len() {
        return Err(CborError::InvalidInput);
    }
    let major = data[pos] >> 5;
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
        0xf9 => {
            // Half-precision float (16-bit)
            if pos + 3 > data.len() {
                return Err(CborError::InvalidInput);
            }
            let bits = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
            Ok((f16_to_f64(bits), 3))
        }
        // RFC 8428 Section 4.3: numeric values can be CBOR integers
        _ if major == 0 || major == 1 => {
            let (i, adv) = dec_int(data, pos)?;
            Ok((i as f64, adv))
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

/// Maximum nesting depth for CBOR arrays/maps to prevent stack overflow.
/// SenML is flat (array of maps), so 16 is more than sufficient.
const MAX_CBOR_DEPTH: usize = 16;

/// Skip one CBOR item starting at `pos`; returns byte count consumed.
fn skip_one(data: &[u8], pos: usize) -> Result<usize, CborError> {
    skip_one_depth(data, pos, 0)
}

/// Skip one CBOR item with depth tracking to prevent stack overflow.
fn skip_one_depth(data: &[u8], pos: usize, depth: usize) -> Result<usize, CborError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CborError::InvalidInput);
    }
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
        26 | 27 | 31 => return Err(CborError::NotImplemented),
        _ => return Err(CborError::InvalidInput),
    };
    match major {
        0 | 1 => Ok(adv),
        2 | 3 => {
            // Use checked arithmetic to prevent overflow on 16-bit platforms.
            // val can be up to 65535 from 2-byte length encoding, which would
            // wrap on 16-bit usize if added carelessly.
            let val_usize = usize::try_from(val).map_err(|_| CborError::InvalidInput)?;
            let skip_len = adv.checked_add(val_usize).ok_or(CborError::InvalidInput)?;
            let end = pos.checked_add(skip_len).ok_or(CborError::InvalidInput)?;
            if end > data.len() {
                return Err(CborError::InvalidInput);
            }
            Ok(skip_len)
        }
        4 => {
            // Use checked arithmetic to prevent overflow on 16-bit platforms.
            let mut cur = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            for _ in 0..val {
                let skip = skip_one_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(skip).ok_or(CborError::InvalidInput)?;
            }
            Ok(cur - pos)
        }
        5 => {
            // Use checked arithmetic to prevent overflow on 16-bit platforms.
            let mut cur = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            for _ in 0..val {
                let skip_key = skip_one_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(skip_key).ok_or(CborError::InvalidInput)?;
                let skip_val = skip_one_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(skip_val).ok_or(CborError::InvalidInput)?;
            }
            Ok(cur - pos)
        }
        6 => {
            // Major type 6 (tags per RFC 8949 §3.1). Consume header (`adv`)
            // then recursively skip the tagged value. Required for compliance
            // and to support tagged values in unknown SenML map keys.
            let cur = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            let inner = skip_one_depth(data, cur, depth + 1)?;
            let total = adv.checked_add(inner).ok_or(CborError::InvalidInput)?;
            Ok(total)
        }
        7 => match info {
            20..=23 => Ok(1),
            24 => Ok(2),
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
/// Returns the number of records decoded. Unknown map keys are skipped;
/// duplicate known keys within a record return `InvalidInput`.
/// Returns an error if the data is not a valid CBOR array-of-maps or if
/// the number of records exceeds `buf.len()`.
pub fn decode<'a>(data: &'a [u8], buf: &mut [Record<'a>]) -> Result<usize, CborError> {
    let (major, n_recs, mut pos) = dec_head(data, 0)?;
    if major != 4 {
        return Err(CborError::InvalidInput);
    }
    let n_recs = n_recs as usize;
    if n_recs > buf.len() {
        return Err(CborError::BufferTooSmall(BufferTooSmall::new(
            n_recs,
            buf.len(),
        )));
    }
    for rec in buf.iter_mut().take(n_recs) {
        let (major, n_kv, adv) = dec_head(data, pos)?;
        if major != 5 {
            return Err(CborError::InvalidInput);
        }
        pos += adv;
        *rec = Record::empty();
        let mut seen_keys = 0u16;
        for _ in 0..n_kv {
            let (key, adv) = dec_int(data, pos)?;
            pos += adv;
            if (-3..=6).contains(&key) {
                let bit = (key + 3) as u32;
                let mask = 1u16 << bit;
                if (seen_keys & mask) != 0 {
                    return Err(CborError::InvalidInput);
                }
                seen_keys |= mask;
            }
            match key {
                -2 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.base_name = Some(s);
                    pos += adv;
                }
                -3 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    rec.base_time = Some(f);
                    pos += adv;
                }
                0 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.name = Some(s);
                    pos += adv;
                }
                1 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.unit = Some(s);
                    pos += adv;
                }
                2 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    rec.value = Some(f);
                    pos += adv;
                }
                3 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.string_value = Some(s);
                    pos += adv;
                }
                4 => {
                    let (b, adv) = dec_bool(data, pos)?;
                    rec.bool_value = Some(b);
                    pos += adv;
                }
                6 => {
                    let (f, adv) = dec_f64(data, pos)?;
                    rec.time = Some(f);
                    pos += adv;
                }
                _ => {
                    pos += skip_one(data, pos)?;
                }
            }
        }
    }
    if pos != data.len() {
        return Err(CborError::InvalidInput);
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
        assert_eq!(decoded[0].base_name, Some("urn:dev:mac:0123456789abcdef:"));
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
        assert!(matches!(
            encode(&records, &mut buf),
            Err(CborError::BufferTooSmall(_))
        ));
    }

    #[test]
    fn decode_invalid_data_returns_error() {
        let data = [0xffu8; 3]; // not a valid CBOR array
        let mut buf = [Record::empty()];
        assert!(decode(&data, &mut buf).is_err());
    }

    #[test]
    fn decode_rejects_duplicate_keys() {
        let data = [0x81u8, 0xa3, 0x00, 0x61, b'a', 0x00, 0x61, b'b', 0x02, 0x17];
        let mut buf = [Record::empty()];
        assert!(decode(&data, &mut buf).is_err());
    }

    #[test]
    fn encode_rejects_multiple_value_fields() {
        // RFC 8428 Section 4.2: at most one of value/string_value/bool_value
        let records = [Record {
            name: Some("test"),
            value: Some(42.0),
            string_value: Some("also set"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 128];
        assert_eq!(encode(&records, &mut buf), Err(CborError::MultipleValues));
    }

    #[test]
    fn encode_rejects_all_three_value_fields() {
        let records = [Record {
            name: Some("test"),
            value: Some(1.0),
            string_value: Some("s"),
            bool_value: Some(true),
            ..Record::empty()
        }];
        let mut buf = [0u8; 128];
        assert_eq!(encode(&records, &mut buf), Err(CborError::MultipleValues));
    }

    #[test]
    fn encode_allows_single_value_field() {
        // Each variant should work individually
        let r1 = [Record {
            value: Some(1.0),
            ..Record::empty()
        }];
        let r2 = [Record {
            string_value: Some("x"),
            ..Record::empty()
        }];
        let r3 = [Record {
            bool_value: Some(true),
            ..Record::empty()
        }];
        let mut buf = [0u8; 64];
        assert!(encode(&r1, &mut buf).is_ok());
        assert!(encode(&r2, &mut buf).is_ok());
        assert!(encode(&r3, &mut buf).is_ok());
    }

    #[test]
    fn encode_allows_no_value_fields() {
        // "Removed" records have no value field (RFC 8428 Section 4.2)
        let records = [Record {
            name: Some("temp"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 32];
        assert!(encode(&records, &mut buf).is_ok());
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
    fn decode_skips_unknown_key_with_tag() {
        // project-LICHEN-z3cf: major type 6 (CBOR tag) as value for unknown map key.
        // array(1) map(2) [key=99, tag(42, text("x"))] [key=0, text("temp")]
        // Tag: 0xd8 0x2a (major 6 + additional 24, tag#=42), then text("x")
        let data = [
            0x81, // array(1)
            0xa2, // map(2)
            0x18, 0x63, // key=99
            0xd8, 0x2a, 0x61, 0x78, // tag(42, text "x")
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
        // Record::parse uses a 1-element buffer, so 2 records => BufferTooSmall
        assert!(matches!(
            Record::parse(&buf[..n]),
            Err(CborError::BufferTooSmall(_))
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let records = [Record {
            name: Some("temp"),
            value: Some(23.5),
            ..Record::empty()
        }];
        let mut buf = [0u8; 64];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        let mut bad = [0u8; 80];
        bad[..n].copy_from_slice(&buf[..n]);
        for b in &mut bad[n..n + 16] {
            *b = 0xaa;
        }
        assert!(matches!(
            decode(&bad[..n + 16], &mut decoded),
            Err(CborError::InvalidInput)
        ));
        assert!(matches!(
            Record::parse(&bad[..n + 16]),
            Err(CborError::InvalidInput)
        ));
    }

    #[test]
    fn roundtrip_long_string_value() {
        // Test string > 255 bytes (requires 2-byte length encoding)
        let long_string = "x".repeat(300);
        let records = [Record {
            name: Some("data"),
            string_value: Some(&long_string),
            ..Record::empty()
        }];
        let mut buf = [0u8; 512];
        let n = encode(&records, &mut buf).unwrap();
        let mut decoded = [Record::empty()];
        let count = decode(&buf[..n], &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(decoded[0].string_value, Some(long_string.as_str()));
    }

    #[test]
    fn enc_head_2byte_length() {
        // Verify 2-byte length encoding (values 256-65535)
        let mut buf = [0u8; 8];
        // Encode length 256 with major type 3 (text string: 0x60)
        let n = enc_head(&mut buf, 0, 0x60, 256).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf[0], 0x79); // major 3 (0x60) | additional 25
        assert_eq!(buf[1], 0x01); // high byte of 256
        assert_eq!(buf[2], 0x00); // low byte of 256

        // Encode length 65535
        let n = enc_head(&mut buf, 0, 0x60, 65535).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf[0], 0x79);
        assert_eq!(buf[1], 0xff);
        assert_eq!(buf[2], 0xff);
    }

    #[test]
    fn enc_head_rejects_values_over_65535() {
        let mut buf = [0u8; 8];
        let result = enc_head(&mut buf, 0, 0x00, 65536);
        assert_eq!(result, Err(CborError::NotImplemented));
    }

    #[test]
    fn dec_f64_accepts_cbor_integers() {
        // RFC 8428 Section 4.3: numeric values can be CBOR integers
        // Positive integer 23 (0x17 = major 0, info 23)
        assert_eq!(dec_f64(&[0x17], 0), Ok((23.0, 1)));
        // Positive integer 100 (0x18 0x64 = major 0, info 24, value 100)
        assert_eq!(dec_f64(&[0x18, 0x64], 0), Ok((100.0, 2)));
        // Negative integer -1 (0x20 = major 1, info 0 = -(0+1) = -1)
        assert_eq!(dec_f64(&[0x20], 0), Ok((-1.0, 1)));
        // Negative integer -100 (0x38 0x63 = major 1, info 24, value 99 = -(99+1) = -100)
        assert_eq!(dec_f64(&[0x38, 0x63], 0), Ok((-100.0, 2)));
    }

    #[test]
    fn decode_record_with_integer_value() {
        // SenML record with integer value: [{0: "temp", 2: 23}]
        // CBOR: 81 a2 00 64 74656d70 02 17
        //   81 = array(1)
        //   a2 = map(2)
        //   00 = key 0 (name)
        //   64 74656d70 = text(4) "temp"
        //   02 = key 2 (value)
        //   17 = unsigned(23)
        let data = [0x81, 0xa2, 0x00, 0x64, 0x74, 0x65, 0x6d, 0x70, 0x02, 0x17];
        let mut decoded = [Record::empty()];
        let count = decode(&data, &mut decoded).unwrap();
        assert_eq!(count, 1);
        assert_eq!(decoded[0].name, Some("temp"));
        assert_eq!(decoded[0].value, Some(23.0));
    }

    #[test]
    fn dec_f64_accepts_half_precision() {
        // 0xf9 = half-precision float marker
        // 0x3c00 = 1.0 in half-precision
        let data = [0xf9, 0x3c, 0x00];
        let (val, adv) = dec_f64(&data, 0).unwrap();
        assert_eq!(adv, 3);
        assert!((val - 1.0).abs() < 1e-10);
    }

    #[test]
    fn dec_f64_half_precision_negative() {
        // 0xbc00 = -1.0 in half-precision (sign bit set)
        let data = [0xf9, 0xbc, 0x00];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!((val - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn dec_f64_half_precision_zero() {
        // 0x0000 = +0.0 in half-precision
        let data = [0xf9, 0x00, 0x00];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert_eq!(val, 0.0);
    }

    #[test]
    fn dec_f64_half_precision_infinity() {
        // 0x7c00 = +Infinity in half-precision
        let data = [0xf9, 0x7c, 0x00];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!(val.is_infinite() && val.is_sign_positive());
    }

    #[test]
    fn dec_f64_half_precision_nan() {
        // 0x7e00 = NaN in half-precision
        let data = [0xf9, 0x7e, 0x00];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!(val.is_nan());
    }

    #[test]
    fn decode_record_with_half_precision_value() {
        // Hand-crafted: array(1) map(2) [key=0 val="temp"] [key=2 val=f16(1.5)]
        // f16 1.5 = 0x3e00 (sign=0, exp=15, mant=512 -> (1+0.5)*2^0 = 1.5)
        let data = [
            0x81, // array(1)
            0xa2, // map(2)
            0x00, // key=0 (n)
            0x64, b't', b'e', b'm', b'p', // text("temp")
            0x02, // key=2 (v)
            0xf9, 0x3e, 0x00, // f16(1.5)
        ];
        let mut buf = [Record::empty()];
        let count = decode(&data, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].name, Some("temp"));
        let val = buf[0].value.unwrap();
        assert!((val - 1.5).abs() < 1e-10);
    }

    #[test]
    fn dec_f64_half_precision_subnormal() {
        let data = [0xf9, 0x00, 0x01];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!((val - 5.960464477539063e-8).abs() < 1e-20);

        let data = [0xf9, 0x03, 0xff];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!((val - 6.097555160522461e-5).abs() < 1e-15);

        let data = [0xf9, 0x80, 0x01];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert!((val + 5.960464477539063e-8).abs() < 1e-20);

        let data = [0xf9, 0x04, 0x00];
        let (val, _) = dec_f64(&data, 0).unwrap();
        assert_eq!(val, 6.103515625e-5);
    }

    #[test]
    fn encode_rejects_long_concatenated_name() {
        let long_suffix = "x".repeat(110);
        let records = [Record {
            base_name: Some("urn:dev:mac:0123456789abcdef:"),
            name: Some(&long_suffix),
            value: Some(42.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 512];
        assert_eq!(encode(&records, &mut buf), Err(CborError::NameTooLong));
    }

    #[test]
    fn encode_rejects_long_single_name() {
        let long_name = "x".repeat(129);
        let records = [Record {
            name: Some(&long_name),
            value: Some(42.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 512];
        assert_eq!(encode(&records, &mut buf), Err(CborError::NameTooLong));
    }
}
