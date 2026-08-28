// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical SenML-CBOR wire codec (RFC 8428 Section 6, Content-Format 112).
//!
//! Cross-implementation parity layer with a complete borrowed [`Record`]. The
//! committed vectors (`test/vectors/senml_location.json`) are matched
//! byte-for-byte by the Python reference codec (`lichen.senml.codec`, via
//! `cbor2`) and by this module; they pin conventions the upstream crate does
//! not follow:
//!
//! * timestamp fields `bt`/`t` carry whole seconds (spec appendix-senml F.12)
//!   and encode as shortest-form CBOR integers when the value is integral
//!   within the exact `i64` window, otherwise as 64-bit floats;
//! * measurement values `v` always encode as 64-bit floats (`0xfb`);
//! * decoding accepts every shortest-form numeric encoding, including the
//!   5-byte (`0x1a`) and 9-byte integer heads the oracle uses for `bt`
//!   (the upstream decoder rejects argument widths above two bytes);
//! * decoding rejects a record carrying more than one of `v`/`vs`/`vb`/`vd`,
//!   matching the Python `unpack` validator (RFC 8428 §4.2 one-of rule).
//!
//! Latitude/longitude range checks are profile policy (spec appendix-senml
//! F.3), not codec policy.

use senml_cbor::cbor::CborError;
use senml_cbor::BufferTooSmall;

/// One complete RFC 8428 SenML record.
///
/// String and data values borrow from the input/output owner, keeping pack
/// decoding allocation-free and suitable for `no_std` nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct Record<'a> {
    pub base_name: Option<&'a str>,
    pub base_time: Option<f64>,
    pub base_unit: Option<&'a str>,
    pub base_value: Option<f64>,
    pub base_sum: Option<f64>,
    pub base_version: Option<u8>,
    pub name: Option<&'a str>,
    pub unit: Option<&'a str>,
    pub value: Option<f64>,
    pub string_value: Option<&'a str>,
    pub bool_value: Option<bool>,
    pub data_value: Option<&'a [u8]>,
    pub sum: Option<f64>,
    pub time: Option<f64>,
    pub update_time: Option<f64>,
}

impl<'a> Record<'a> {
    pub const fn empty() -> Self {
        Self {
            base_name: None,
            base_time: None,
            base_unit: None,
            base_value: None,
            base_sum: None,
            base_version: None,
            name: None,
            unit: None,
            value: None,
            string_value: None,
            bool_value: None,
            data_value: None,
            sum: None,
            time: None,
            update_time: None,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CborError> {
        encode(core::slice::from_ref(self), out)
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, CborError> {
        let mut records = [Record::empty()];
        if decode(data, &mut records)? != 1 {
            return Err(CborError::InvalidInput);
        }
        let [record] = records;
        Ok(record)
    }

    #[inline]
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CborError> {
        Self::parse(data)
    }
}

/// RFC 8428 Table 1 CBOR integer labels.
///
/// This enum is the authoritative Rust mapping for every field defined by
/// RFC 8428. The wire decoder recognizes every standard label for typed field
/// dispatch and duplicate-key validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum SenmlLabel {
    BaseSum = -6,
    BaseValue = -5,
    BaseUnit = -4,
    BaseTime = -3,
    BaseName = -2,
    BaseVersion = -1,
    Name = 0,
    Unit = 1,
    Value = 2,
    StringValue = 3,
    BooleanValue = 4,
    Sum = 5,
    Time = 6,
    UpdateTime = 7,
    DataValue = 8,
}

impl SenmlLabel {
    pub const ALL: [Self; 15] = [
        Self::BaseSum,
        Self::BaseValue,
        Self::BaseUnit,
        Self::BaseTime,
        Self::BaseName,
        Self::BaseVersion,
        Self::Name,
        Self::Unit,
        Self::Value,
        Self::StringValue,
        Self::BooleanValue,
        Self::Sum,
        Self::Time,
        Self::UpdateTime,
        Self::DataValue,
    ];

    /// Resolve an RFC 8428 CBOR integer label.
    pub const fn from_i64(label: i64) -> Option<Self> {
        match label {
            -6 => Some(Self::BaseSum),
            -5 => Some(Self::BaseValue),
            -4 => Some(Self::BaseUnit),
            -3 => Some(Self::BaseTime),
            -2 => Some(Self::BaseName),
            -1 => Some(Self::BaseVersion),
            0 => Some(Self::Name),
            1 => Some(Self::Unit),
            2 => Some(Self::Value),
            3 => Some(Self::StringValue),
            4 => Some(Self::BooleanValue),
            5 => Some(Self::Sum),
            6 => Some(Self::Time),
            7 => Some(Self::UpdateTime),
            8 => Some(Self::DataValue),
            _ => None,
        }
    }

    /// The compact label used as the SenML-CBOR map key.
    pub const fn as_i8(self) -> i8 {
        self as i8
    }

    /// RFC 8428 short field name used by SenML JSON and documentation.
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::BaseName => "bn",
            Self::BaseTime => "bt",
            Self::BaseUnit => "bu",
            Self::BaseValue => "bv",
            Self::BaseSum => "bs",
            Self::BaseVersion => "bver",
            Self::Name => "n",
            Self::Unit => "u",
            Self::Value => "v",
            Self::StringValue => "vs",
            Self::BooleanValue => "vb",
            Self::DataValue => "vd",
            Self::Sum => "s",
            Self::Time => "t",
            Self::UpdateTime => "ut",
        }
    }

    /// Encode this label as one canonical CBOR integer map key.
    pub fn write_cbor_key(self, out: &mut [u8]) -> Result<usize, CborError> {
        let needed = 1;
        if out.len() < needed {
            return Err(CborError::BufferTooSmall(BufferTooSmall::new(
                needed,
                out.len(),
            )));
        }
        let label = self.as_i8();
        Ok(if label < 0 {
            write_key_i8(out, 0, label)
        } else {
            write_key_u8(out, 0, label as u8)
        })
    }

    /// Decode one CBOR integer key into an RFC 8428 label.
    ///
    /// The returned byte count lets callers continue parsing a surrounding
    /// map. Unknown integer labels and non-integer keys are rejected here;
    /// the pack decoder applies RFC 8428's ignore-unknown extension rule at
    /// its higher layer.
    pub fn from_cbor_key(data: &[u8]) -> Result<(Self, usize), CborError> {
        let (label, consumed) = dec_int(data, 0)?;
        Self::from_i64(label)
            .map(|known| (known, consumed))
            .ok_or(CborError::InvalidInput)
    }
}

const LABEL_BN: i8 = SenmlLabel::BaseName as i8;
const LABEL_BT: i8 = SenmlLabel::BaseTime as i8;
const LABEL_BU: i8 = SenmlLabel::BaseUnit as i8;
const LABEL_BV: i8 = SenmlLabel::BaseValue as i8;
const LABEL_BS: i8 = SenmlLabel::BaseSum as i8;
const LABEL_BVER: i8 = SenmlLabel::BaseVersion as i8;
const LABEL_N: u8 = SenmlLabel::Name as u8;
const LABEL_U: u8 = SenmlLabel::Unit as u8;
const LABEL_V: u8 = SenmlLabel::Value as u8;
const LABEL_VS: u8 = SenmlLabel::StringValue as u8;
const LABEL_VB: u8 = SenmlLabel::BooleanValue as u8;
const LABEL_S: u8 = SenmlLabel::Sum as u8;
const LABEL_T: u8 = SenmlLabel::Time as u8;
const LABEL_UT: u8 = SenmlLabel::UpdateTime as u8;
const LABEL_VD: u8 = SenmlLabel::DataValue as u8;

/// Maximum resolved name length (RFC 8428 Section 4.2), mirroring the cap
/// the upstream decoder enforces on names it reads.
const MAX_NAME_LEN: usize = 128;

/// Maximum CBOR nesting depth when skipping unknown values. SenML is flat,
/// so this only guards adversarial inputs against stack exhaustion.
const MAX_SKIP_DEPTH: usize = 16;

const MAJOR_UINT: u8 = 0x00;
const MAJOR_NINT: u8 = 0x20;
const MAJOR_TEXT: u8 = 0x60;
const MAJOR_ARRAY: u8 = 0x80;
const MAJOR_MAP: u8 = 0xa0;

/// Lower bound of the exact `i64` range as `f64` (`i64::MIN` is exact).
const F64_I64_MIN: f64 = -9_223_372_036_854_775_808.0;
/// Exclusive upper bound of the exact `i64` range as `f64` (first power of two).
const F64_I64_MAX: f64 = 9_223_372_036_854_775_808.0;

/// Encode a slice of records into `out` as canonical SenML-CBOR.
///
/// Returns the number of bytes written, or an error if `out` is too small
/// or a record violates RFC 8428 §4.2. Output is deterministic: encoding
/// failures never leave partial writes, and record content alone decides
/// the produced bytes.
pub fn encode(records: &[Record<'_>], out: &mut [u8]) -> Result<usize, CborError> {
    // Validate everything up front so rejections never mutate `out`.
    for r in records {
        let value_fields = r.value.is_some() as usize
            + r.string_value.is_some() as usize
            + r.bool_value.is_some() as usize
            + r.data_value.is_some() as usize;
        if value_fields > 1 {
            return Err(CborError::MultipleValues);
        }
        let name_len = r.base_name.map_or(0, str::len) + r.name.map_or(0, str::len);
        if name_len > MAX_NAME_LEN {
            return Err(CborError::NameTooLong);
        }
        if r.value.is_some_and(|f| !f.is_finite())
            || r.base_time.is_some_and(|f| !f.is_finite())
            || r.base_value.is_some_and(|f| !f.is_finite())
            || r.base_sum.is_some_and(|f| !f.is_finite())
            || r.sum.is_some_and(|f| !f.is_finite())
            || r.time.is_some_and(|f| !f.is_finite())
            || r.update_time.is_some_and(|f| !f.is_finite())
        {
            return Err(CborError::NonFiniteValue);
        }
        if r.base_version
            .is_some_and(|version| !(1..=10).contains(&version))
        {
            return Err(CborError::InvalidInput);
        }
    }

    let needed = encoded_len(records);
    if needed > out.len() {
        return Err(CborError::BufferTooSmall(BufferTooSmall::new(
            needed,
            out.len(),
        )));
    }

    let mut p = 0;
    p += write_head(out, p, MAJOR_ARRAY, records.len() as u64);
    for r in records {
        p += write_head(out, p, MAJOR_MAP, entry_count(r));
        if let Some(s) = r.base_name {
            p += write_key_i8(out, p, LABEL_BN);
            p += write_text(out, p, s);
        }
        if let Some(f) = r.base_time {
            p += write_key_i8(out, p, LABEL_BT);
            p += write_number(out, p, f);
        }
        if let Some(s) = r.base_unit {
            p += write_key_i8(out, p, LABEL_BU);
            p += write_text(out, p, s);
        }
        if let Some(f) = r.base_value {
            p += write_key_i8(out, p, LABEL_BV);
            p += write_f64(out, p, f);
        }
        if let Some(f) = r.base_sum {
            p += write_key_i8(out, p, LABEL_BS);
            p += write_f64(out, p, f);
        }
        if let Some(version) = r.base_version {
            p += write_key_i8(out, p, LABEL_BVER);
            p += write_head(out, p, MAJOR_UINT, u64::from(version));
        }
        if let Some(s) = r.name {
            p += write_key_u8(out, p, LABEL_N);
            p += write_text(out, p, s);
        }
        if let Some(s) = r.unit {
            p += write_key_u8(out, p, LABEL_U);
            p += write_text(out, p, s);
        }
        if let Some(f) = r.value {
            p += write_key_u8(out, p, LABEL_V);
            p += write_f64(out, p, f);
        }
        if let Some(s) = r.string_value {
            p += write_key_u8(out, p, LABEL_VS);
            p += write_text(out, p, s);
        }
        if let Some(b) = r.bool_value {
            p += write_key_u8(out, p, LABEL_VB);
            out[p] = if b { 0xf5 } else { 0xf4 };
            p += 1;
        }
        if let Some(f) = r.sum {
            p += write_key_u8(out, p, LABEL_S);
            p += write_f64(out, p, f);
        }
        if let Some(f) = r.time {
            p += write_key_u8(out, p, LABEL_T);
            p += write_number(out, p, f);
        }
        if let Some(f) = r.update_time {
            p += write_key_u8(out, p, LABEL_UT);
            p += write_number(out, p, f);
        }
        if let Some(bytes) = r.data_value {
            p += write_key_u8(out, p, LABEL_VD);
            p += write_bytes(out, p, bytes);
        }
    }
    debug_assert_eq!(p, needed);
    Ok(p)
}

/// Decode SenML-CBOR bytes into a fixed-size array of records.
///
/// Accepts definite-length CBOR with full integer argument widths (major 0/1
/// with 1-, 2-, 4-, and 8-byte arguments), which the committed oracle vectors
/// require for whole-second `bt` timestamps. Enforces the RFC 8428 §4.2 one-of
/// rule: a record carrying more than one of `v`/`vs`/`vb`/`vd` is rejected with
/// [`CborError::MultipleValues`], matching the Python reference validator
/// (`lichen.senml.codec.unpack`). Trailing bytes, non-array documents,
/// non-map records, duplicate known keys, non-finite floats, and record
/// counts beyond `buf.len()` are rejected. On error the contents of `buf`
/// are unspecified.
pub fn decode<'a>(data: &'a [u8], buf: &mut [Record<'a>]) -> Result<usize, CborError> {
    let (major, n_recs, mut pos) = dec_head(data, 0)?;
    if major != 4 {
        return Err(CborError::InvalidInput);
    }
    let n_recs = usize::try_from(n_recs).map_err(|_| CborError::InvalidInput)?;
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
        let n_kv = usize::try_from(n_kv).map_err(|_| CborError::InvalidInput)?;
        *rec = Record::empty();
        let mut seen_keys = 0u16;
        for _ in 0..n_kv {
            let (key_major, _, _) = dec_head(data, pos)?;
            if key_major == 3 {
                let (extension, adv) = dec_text(data, pos)?;
                pos += adv;
                if extension.ends_with('_') {
                    return Err(CborError::InvalidInput);
                }
                pos += skip_one(data, pos)?;
                continue;
            }
            let (key, adv) = dec_int(data, pos)?;
            pos += adv;
            // Track duplicates for every RFC 8428 label.
            if SenmlLabel::from_i64(key).is_some() {
                let bit = 1u16 << (key + 6) as u32;
                if (seen_keys & bit) != 0 {
                    return Err(CborError::InvalidInput);
                }
                seen_keys |= bit;
            }
            match key {
                -6 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.base_sum = Some(f);
                    pos += adv;
                }
                -5 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.base_value = Some(f);
                    pos += adv;
                }
                -4 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.base_unit = Some(s);
                    pos += adv;
                }
                -2 => {
                    let (s, adv) = dec_text(data, pos)?;
                    rec.base_name = Some(s);
                    pos += adv;
                }
                -3 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.base_time = Some(f);
                    pos += adv;
                }
                -1 => {
                    let (version, adv) = dec_int(data, pos)?;
                    let version = u8::try_from(version).map_err(|_| CborError::InvalidInput)?;
                    if !(1..=10).contains(&version) {
                        return Err(CborError::InvalidInput);
                    }
                    rec.base_version = Some(version);
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
                    let (f, adv) = dec_num(data, pos)?;
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
                5 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.sum = Some(f);
                    pos += adv;
                }
                6 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.time = Some(f);
                    pos += adv;
                }
                7 => {
                    let (f, adv) = dec_num(data, pos)?;
                    rec.update_time = Some(f);
                    pos += adv;
                }
                8 => {
                    let (bytes, adv) = dec_bytes(data, pos)?;
                    rec.data_value = Some(bytes);
                    pos += adv;
                }
                _ => {
                    pos += skip_one(data, pos)?;
                }
            }
        }
        // RFC 8428 §4.2: at most one of v/vs/vb/vd per record.
        let value_fields = rec.value.is_some() as usize
            + rec.string_value.is_some() as usize
            + rec.bool_value.is_some() as usize
            + rec.data_value.is_some() as usize;
        if value_fields > 1 {
            return Err(CborError::MultipleValues);
        }
    }
    if pos != data.len() {
        return Err(CborError::InvalidInput);
    }
    Ok(n_recs)
}

fn entry_count(r: &Record<'_>) -> u64 {
    r.base_name.is_some() as u64
        + r.base_time.is_some() as u64
        + r.base_unit.is_some() as u64
        + r.base_value.is_some() as u64
        + r.base_sum.is_some() as u64
        + r.base_version.is_some() as u64
        + r.name.is_some() as u64
        + r.unit.is_some() as u64
        + r.value.is_some() as u64
        + r.string_value.is_some() as u64
        + r.bool_value.is_some() as u64
        + r.data_value.is_some() as u64
        + r.sum.is_some() as u64
        + r.time.is_some() as u64
        + r.update_time.is_some() as u64
}

fn encoded_len(records: &[Record<'_>]) -> usize {
    let mut total = head_len(records.len() as u64);
    for r in records {
        total += head_len(entry_count(r));
        if let Some(s) = r.base_name {
            total += head_len(nint_arg(i64::from(LABEL_BN))) + text_len(s);
        }
        if let Some(f) = r.base_time {
            total += head_len(nint_arg(i64::from(LABEL_BT))) + number_len(f);
        }
        if let Some(s) = r.base_unit {
            total += head_len(nint_arg(i64::from(LABEL_BU))) + text_len(s);
        }
        if r.base_value.is_some() {
            total += head_len(nint_arg(i64::from(LABEL_BV))) + 9;
        }
        if r.base_sum.is_some() {
            total += head_len(nint_arg(i64::from(LABEL_BS))) + 9;
        }
        if let Some(version) = r.base_version {
            total += head_len(nint_arg(i64::from(LABEL_BVER))) + head_len(u64::from(version));
        }
        if let Some(s) = r.name {
            total += key_u8_len(LABEL_N) + text_len(s);
        }
        if let Some(s) = r.unit {
            total += key_u8_len(LABEL_U) + text_len(s);
        }
        if r.value.is_some() {
            total += key_u8_len(LABEL_V) + 9; // always 0xfb + 8 payload bytes
        }
        if let Some(s) = r.string_value {
            total += key_u8_len(LABEL_VS) + text_len(s);
        }
        if r.bool_value.is_some() {
            total += key_u8_len(LABEL_VB) + 1;
        }
        if r.sum.is_some() {
            total += key_u8_len(LABEL_S) + 9;
        }
        if let Some(f) = r.time {
            total += key_u8_len(LABEL_T) + number_len(f);
        }
        if let Some(f) = r.update_time {
            total += key_u8_len(LABEL_UT) + number_len(f);
        }
        if let Some(bytes) = r.data_value {
            total += key_u8_len(LABEL_VD) + bytes_len(bytes);
        }
    }
    total
}

fn head_len(arg: u64) -> usize {
    match arg {
        0..=23 => 1,
        0x18..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn write_head(out: &mut [u8], pos: usize, major: u8, arg: u64) -> usize {
    let len = head_len(arg);
    out[pos] = match len {
        1 => major | arg as u8,
        2 => major | 24,
        3 => major | 25,
        5 => major | 26,
        _ => major | 27,
    };
    for i in 1..len {
        out[pos + i] = (arg >> (8 * (len - 1 - i))) as u8;
    }
    len
}

fn key_u8_len(k: u8) -> usize {
    head_len(u64::from(k))
}

fn write_key_u8(out: &mut [u8], pos: usize, k: u8) -> usize {
    write_head(out, pos, MAJOR_UINT, u64::from(k))
}

fn write_key_i8(out: &mut [u8], pos: usize, k: i8) -> usize {
    write_head(out, pos, MAJOR_NINT, nint_arg(i64::from(k)))
}

/// CBOR major type 1 argument for negative integer `n`: `-n - 1`.
fn nint_arg(n: i64) -> u64 {
    debug_assert!(n < 0);
    (-(n as i128) - 1) as u64
}

fn text_len(s: &str) -> usize {
    head_len(s.len() as u64) + s.len()
}

fn write_text(out: &mut [u8], pos: usize, s: &str) -> usize {
    let h = write_head(out, pos, MAJOR_TEXT, s.len() as u64);
    out[pos + h..pos + h + s.len()].copy_from_slice(s.as_bytes());
    h + s.len()
}

fn bytes_len(bytes: &[u8]) -> usize {
    head_len(bytes.len() as u64) + bytes.len()
}

fn write_bytes(out: &mut [u8], pos: usize, bytes: &[u8]) -> usize {
    let h = write_head(out, pos, 0x40, bytes.len() as u64);
    out[pos + h..pos + h + bytes.len()].copy_from_slice(bytes);
    h + bytes.len()
}

/// Integral values within exact `i64` bounds encode as shortest-form
/// integers; everything else is a 64-bit float.
///
/// `f64::trunc` is unavailable in `core`, so integrality is tested with a
/// saturating `i128` round trip: within the guarded `i64` window every
/// integral value survives unchanged, while fractional ones do not.
fn number_is_int(f: f64) -> bool {
    if !f.is_finite() {
        return false;
    }
    (F64_I64_MIN..F64_I64_MAX).contains(&f) && f == (f as i128) as f64
}

fn number_len(f: f64) -> usize {
    if !number_is_int(f) {
        return 9;
    }
    if f >= 0.0 {
        head_len(f as u64)
    } else {
        head_len(nint_arg(f as i64))
    }
}

fn write_number(out: &mut [u8], pos: usize, f: f64) -> usize {
    if !number_is_int(f) {
        return write_f64(out, pos, f);
    }
    if f >= 0.0 {
        write_head(out, pos, MAJOR_UINT, f as u64)
    } else {
        write_head(out, pos, MAJOR_NINT, nint_arg(f as i64))
    }
}

fn write_f64(out: &mut [u8], pos: usize, f: f64) -> usize {
    out[pos] = 0xfb; // major 7, additional 27 (8-byte float)
    out[pos + 1..pos + 9].copy_from_slice(&f.to_bits().to_be_bytes());
    9
}

// -- Decoder internals ---------------------------------------------------------

/// Returns `(major_type, argument, header_byte_count)`.
///
/// Unlike the upstream decoder, all definite argument widths (additional
/// info 24..=27) are supported; indefinite lengths are rejected.
fn dec_head(data: &[u8], pos: usize) -> Result<(u8, u64, usize), CborError> {
    let b = *data.get(pos).ok_or(CborError::InvalidInput)?;
    let major = b >> 5;
    let info = b & 0x1f;
    let arg = match info {
        0..=23 => u64::from(info),
        24 => arg_width(data, pos, 1)?,
        25 => arg_width(data, pos, 2)?,
        26 => arg_width(data, pos, 4)?,
        27 => arg_width(data, pos, 8)?,
        _ => return Err(CborError::InvalidInput), // indefinite length
    };
    Ok((major, arg, 1 + info_bytes(info)))
}

fn arg_width(data: &[u8], pos: usize, width: usize) -> Result<u64, CborError> {
    let end = pos.checked_add(1 + width).ok_or(CborError::InvalidInput)?;
    if end > data.len() {
        return Err(CborError::InvalidInput);
    }
    let mut arg = 0u64;
    for i in 0..width {
        arg = (arg << 8) | u64::from(data[pos + 1 + i]);
    }
    Ok(arg)
}

fn info_bytes(info: u8) -> usize {
    match info {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => 0,
    }
}

/// Decode an unsigned or negative integer head into its signed value.
fn dec_int(data: &[u8], pos: usize) -> Result<(i64, usize), CborError> {
    let (major, arg, adv) = dec_head(data, pos)?;
    match major {
        0 => i64::try_from(arg)
            .map(|v| (v, adv))
            .map_err(|_| CborError::InvalidInput),
        1 => {
            if arg > i64::MAX as u64 {
                return Err(CborError::InvalidInput);
            }
            Ok((-1 - (arg as i64), adv))
        }
        _ => Err(CborError::InvalidInput),
    }
}

fn dec_text(data: &[u8], pos: usize) -> Result<(&str, usize), CborError> {
    let (major, len, adv) = dec_head(data, pos)?;
    if major != 3 {
        return Err(CborError::InvalidInput);
    }
    let len = usize::try_from(len).map_err(|_| CborError::InvalidInput)?;
    let start = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
    let end = start.checked_add(len).ok_or(CborError::InvalidInput)?;
    if end > data.len() {
        return Err(CborError::InvalidInput);
    }
    let s = core::str::from_utf8(&data[start..end]).map_err(|_| CborError::InvalidInput)?;
    Ok((s, adv + len))
}

fn dec_bytes(data: &[u8], pos: usize) -> Result<(&[u8], usize), CborError> {
    let (major, len, adv) = dec_head(data, pos)?;
    if major != 2 {
        return Err(CborError::InvalidInput);
    }
    let len = usize::try_from(len).map_err(|_| CborError::InvalidInput)?;
    let start = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
    let end = start.checked_add(len).ok_or(CborError::InvalidInput)?;
    let bytes = data.get(start..end).ok_or(CborError::InvalidInput)?;
    Ok((bytes, adv + len))
}

/// Decode a SenML numeric value: half/single/double floats or any integer
/// form. Non-finite floats are rejected (RFC 8428 decoded numeric policy).
fn dec_num(data: &[u8], pos: usize) -> Result<(f64, usize), CborError> {
    let b = *data.get(pos).ok_or(CborError::InvalidInput)?;
    match b {
        0xfb => {
            let end = pos.checked_add(9).ok_or(CborError::InvalidInput)?;
            if end > data.len() {
                return Err(CborError::InvalidInput);
            }
            let bits = u64::from_be_bytes(data[pos + 1..end].try_into().expect("9-byte slice"));
            let val = f64::from_bits(bits);
            if !val.is_finite() {
                return Err(CborError::NonFiniteValue);
            }
            Ok((val, 9))
        }
        0xfa => {
            let end = pos.checked_add(5).ok_or(CborError::InvalidInput)?;
            if end > data.len() {
                return Err(CborError::InvalidInput);
            }
            let bits = u32::from_be_bytes(data[pos + 1..end].try_into().expect("5-byte slice"));
            let val = f64::from(f32::from_bits(bits));
            if !val.is_finite() {
                return Err(CborError::NonFiniteValue);
            }
            Ok((val, 5))
        }
        0xf9 => {
            let end = pos.checked_add(3).ok_or(CborError::InvalidInput)?;
            if end > data.len() {
                return Err(CborError::InvalidInput);
            }
            let bits = u16::from_be_bytes(data[pos + 1..end].try_into().expect("3-byte slice"));
            let val = f16_to_f64(bits);
            if !val.is_finite() {
                return Err(CborError::NonFiniteValue);
            }
            Ok((val, 3))
        }
        _ => {
            let (major, _, _) = dec_head(data, pos)?;
            if major == 0 || major == 1 {
                // Integers are always finite.
                dec_int(data, pos).map(|(i, adv)| (i as f64, adv))
            } else {
                Err(CborError::InvalidInput)
            }
        }
    }
}

/// Convert IEEE 754 binary16 bits to `f64`.
fn f16_to_f64(bits: u16) -> f64 {
    let exp = ((bits >> 10) & 0x1f) as i32;
    let mant = u64::from(bits & 0x3ff);
    let magnitude: f64 = match exp {
        // Zero and subnormals: value = mantissa * 2^-24.
        0 => (mant as f64) / 16_777_216.0,
        // Infinity / NaN keep their class through the sign application below.
        31 => {
            if mant == 0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        // Normals: rebuild the exact f64 bit pattern (bias 15 -> 1023).
        e => f64::from_bits((u64::from((e - 15 + 1023) as u16)) << 52 | mant << 42),
    };
    if bits >> 15 == 1 {
        -magnitude
    } else {
        magnitude
    }
}

fn dec_bool(data: &[u8], pos: usize) -> Result<(bool, usize), CborError> {
    match data.get(pos) {
        Some(0xf5) => Ok((true, 1)),
        Some(0xf4) => Ok((false, 1)),
        _ => Err(CborError::InvalidInput),
    }
}

/// Skip one well-formed CBOR item starting at `pos`; returns bytes consumed.
///
/// Used for values under unknown map keys. Depth-limited so nested
/// structures cannot exhaust the stack.
fn skip_one(data: &[u8], pos: usize) -> Result<usize, CborError> {
    skip_depth(data, pos, 0)
}

fn skip_depth(data: &[u8], pos: usize, depth: usize) -> Result<usize, CborError> {
    if depth > MAX_SKIP_DEPTH {
        return Err(CborError::InvalidInput);
    }
    let (major, arg, adv) = dec_head(data, pos)?;
    match major {
        0 | 1 => Ok(adv),
        2 | 3 => {
            let len = usize::try_from(arg).map_err(|_| CborError::InvalidInput)?;
            let total = adv.checked_add(len).ok_or(CborError::InvalidInput)?;
            if pos.checked_add(total).ok_or(CborError::InvalidInput)? > data.len() {
                return Err(CborError::InvalidInput);
            }
            Ok(total)
        }
        4 => {
            let mut cur = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            for _ in 0..arg {
                let skip = skip_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(skip).ok_or(CborError::InvalidInput)?;
            }
            Ok(cur - pos)
        }
        5 => {
            let mut cur = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            for _ in 0..arg {
                let k = skip_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(k).ok_or(CborError::InvalidInput)?;
                let v = skip_depth(data, cur, depth + 1)?;
                cur = cur.checked_add(v).ok_or(CborError::InvalidInput)?;
            }
            Ok(cur - pos)
        }
        6 => {
            // Tag: consume header then the tagged item.
            let inner = pos.checked_add(adv).ok_or(CborError::InvalidInput)?;
            let skipped = skip_depth(data, inner, depth + 1)?;
            Ok(adv.checked_add(skipped).ok_or(CborError::InvalidInput)?)
        }
        7 => {
            // `dec_head` sizes major-7 items including their payload bytes,
            // so `adv` alone is the whole item. Sizing from the argument
            // value instead would mis-skip whenever float payload bits
            // collide with the simple-value codes (e.g. f16 0x0019).
            let _ = data.get(pos).ok_or(CborError::InvalidInput)?;
            Ok(adv)
        }
        _ => Err(CborError::InvalidInput),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BN: &str = "urn:dev:mac:0011223344556677:";

    /// Oracle: base record bytes committed as the head of
    /// "senml-location-full" in `test/vectors/senml_location.json`
    /// (`a2 21 781d .. 22 1a66536a90`), wrapped in a single-element array.
    #[test]
    fn integral_base_time_encodes_as_shortest_form_integer() {
        let recs = [Record {
            base_name: Some(BN),
            base_time: Some(1_716_742_800.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 64];
        let n = encode(&recs, &mut buf).unwrap();

        assert_eq!(buf[0], 0x81);
        assert_eq!(buf[1], 0xa2); // map(2): bn + bt
        assert_eq!(&buf[2..4], &[0x21, 0x78]); // key -2, tstr header follows
        assert_eq!(buf[4], BN.len() as u8); // 29 text bytes
        assert_eq!(&buf[5..5 + BN.len()], BN.as_bytes());
        assert_eq!(&buf[5 + BN.len()..n], &[0x22, 0x1a, 0x66, 0x53, 0x6a, 0x90]);
    }

    /// RFC 8949 Appendix A: -5 encodes as the single byte 0x24.
    #[test]
    fn negative_integral_time_uses_major_type_one() {
        let recs = [Record {
            time: Some(-5.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 16];
        let n = encode(&recs, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x81, 0xa1, 0x06, 0x24]);
    }

    /// Fractional times cannot be integers; they fall back to 0xfb floats.
    #[test]
    fn fractional_time_uses_float() {
        let recs = [Record {
            base_time: Some(1716742800.5),
            ..Record::empty()
        }];
        let mut buf = [0u8; 16];
        encode(&recs, &mut buf).unwrap();
        assert_eq!(&buf[..3], &[0x81, 0xa1, 0x22]);
        assert_eq!(buf[3], 0xfb);
    }

    /// Times beyond the exact i64 range must not wrap through `as i64`.
    #[test]
    fn oversized_integral_time_stays_float() {
        let recs = [Record {
            base_time: Some(9_223_372_036_854_775_808.0), // 2^63, not in i64
            ..Record::empty()
        }];
        let mut buf = [0u8; 16];
        encode(&recs, &mut buf).unwrap();
        assert_eq!(buf[3], 0xfb);
    }

    #[test]
    fn rejects_multiple_value_fields_like_upstream_encoder() {
        let recs = [Record {
            name: Some("lat"),
            value: Some(1.0),
            string_value: Some("1.0"),
            ..Record::empty()
        }];
        let mut buf = [0u8; 32];
        assert_eq!(encode(&recs, &mut buf), Err(CborError::MultipleValues));
    }

    #[test]
    fn rejects_non_finite_values() {
        for value in [f64::NAN, f64::INFINITY] {
            let recs = [Record {
                name: Some("lat"),
                value: Some(value),
                ..Record::empty()
            }];
            let mut buf = [0u8; 32];
            assert_eq!(encode(&recs, &mut buf), Err(CborError::NonFiniteValue));
        }
    }

    #[test]
    fn reports_exact_needed_capacity_on_small_buffer() {
        let recs = [
            Record {
                name: Some("lat"),
                unit: Some("lat"),
                value: Some(37.774929),
                ..Record::empty()
            },
            Record {
                name: Some("lon"),
                unit: Some("lon"),
                value: Some(-122.419416),
                ..Record::empty()
            },
        ];
        let mut full = [0u8; 96];
        let n = encode(&recs, &mut full).unwrap();
        for cap in 0..n {
            assert_eq!(
                encode(&recs, &mut full[..cap]),
                Err(CborError::BufferTooSmall(BufferTooSmall::new(n, cap)))
            );
        }
    }

    /// The Python `unpack` validator rejects a record carrying two value
    /// fields; mirror that on decode even though the upstream decoder alone
    /// would accept it. Literal bytes: [{n: "lat", v: f64(1.0), vs: "1.5"}].
    #[test]
    fn decode_rejects_multiple_value_fields() {
        let wire_bytes: [u8; 22] = [
            0x81, 0xa3, 0x00, 0x63, 0x6c, 0x61, 0x74, 0x02, 0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x63, 0x31, 0x2e, 0x35,
        ];
        let mut buf = [const { Record::empty() }; 1];
        assert_eq!(
            decode(&wire_bytes, &mut buf),
            Err(CborError::MultipleValues)
        );
    }

    /// Canonical output survives an encode → decode → encode round trip
    /// unchanged, including the integer-form timestamp and float value.
    #[test]
    fn decode_round_trips_canonical_output() {
        let recs = [
            Record {
                base_name: Some(BN),
                base_time: Some(1_716_742_800.0),
                ..Record::empty()
            },
            Record {
                name: Some("lat"),
                unit: Some("lat"),
                value: Some(37.774929),
                time: Some(0.5),
                ..Record::empty()
            },
        ];
        let mut encoded = [0u8; 128];
        let n = encode(&recs, &mut encoded).unwrap();

        let mut decoded = [const { Record::empty() }; 2];
        let count = decode(&encoded[..n], &mut decoded).unwrap();
        assert_eq!(count, 2);
        assert_eq!(decoded[0].base_time, Some(1_716_742_800.0));
        assert_eq!(decoded[1].value, Some(37.774929));
        assert_eq!(decoded[1].time, Some(0.5));

        let mut again = [0u8; 128];
        let n2 = encode(&decoded, &mut again).unwrap();
        assert_eq!(&again[..n2], &encoded[..n]);
    }

    /// Integer-form timestamps on the wire decode into the same `f64`
    /// fields as float-form ones (RFC 8428 numbers cover both). The 5-byte
    /// `0x1a` argument width is exactly what the committed oracle uses.
    #[test]
    fn decode_accepts_integer_form_timestamps() {
        let wire_bytes: [u8; 40] = [
            0x81, 0xa2, 0x21, 0x78, 0x1d, 0x75, 0x72, 0x6e, 0x3a, 0x64, 0x65, 0x76, 0x3a, 0x6d,
            0x61, 0x63, 0x3a, 0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35,
            0x35, 0x36, 0x36, 0x37, 0x37, 0x3a, 0x22, 0x1a, 0x66, 0x53, 0x6a, 0x90,
        ];
        let mut buf = [const { Record::empty() }; 1];
        let count = decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].base_name, Some(BN));
        assert_eq!(buf[0].base_time, Some(1_716_742_800.0));
    }

    /// Negative integer arguments wider than one byte decode correctly
    /// (RFC 8949 Appendix A: -1000 is 0x39 0x03 0xe7).
    #[test]
    fn decode_accepts_two_byte_negative_integers() {
        // [{t: -1000}]
        let wire_bytes = [0x81u8, 0xa1, 0x06, 0x39, 0x03, 0xe7];
        let mut buf = [const { Record::empty() }; 1];
        let count = decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].time, Some(-1000.0));
    }

    /// Unknown keys are skipped, including values the upstream decoder
    /// could not traverse: nested arrays, nested maps, and tags.
    /// Literal bytes: [{99: [1, [2]], 98: {1: 2}, 97: tag(0, 5), 0: "temp"}].
    #[test]
    fn decode_skips_unknown_keys_with_nested_values() {
        let wire_bytes: [u8; 23] = [
            0x81, // array(1)
            0xa4, // map(4)
            0x18, 0x63, // key 99
            0x82, 0x01, 0x81, 0x02, // [1, [2]]
            0x18, 0x62, // key 98
            0xa1, 0x01, 0x02, // {1: 2}
            0x18, 0x61, // key 97
            0xc0, 0x05, // tag(0, 5)
            0x00, 0x64, 0x74, 0x65, 0x6d, 0x70, // key 0: "temp"
        ];
        let mut buf = [const { Record::empty() }; 1];
        let count = decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].name, Some("temp"));
    }

    /// Regression: major-7 skip sizes come from the item head alone, never
    /// the argument value. Here an unknown key carries a binary16 whose
    /// payload bits are 0x0019 (= 25); sizing by argument would swallow two
    /// extra bytes and desync the following pair. Literal bytes:
    /// [{99: f16(0x0019), 0: "temp"}].
    #[test]
    fn decode_skips_unknown_float16_with_colliding_payload() {
        let wire_bytes: [u8; 13] = [
            0x81, // array(1)
            0xa2, // map(2)
            0x18, 0x63, // key 99 (info 24)
            0xf9, 0x00, 0x19, // binary16, payload bits == 25
            0x00, 0x64, 0x74, 0x65, 0x6d, 0x70, // key 0: "temp"
        ];
        let mut buf = [const { Record::empty() }; 1];
        let count = decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].name, Some("temp"));
        assert_eq!(buf[0].value, None);
    }

    /// Unknown-key binary32 values skip by head size as well.
    /// Literal bytes: [{0: "x", 99: f32(0.0)}].
    #[test]
    fn decode_skips_unknown_float32_value() {
        let wire_bytes: [u8; 12] = [
            0x81, // array(1)
            0xa2, // map(2)
            0x00, 0x61, 0x78, // key 0: "x"
            0x18, 0x63, // key 99 (info 24)
            0xfa, 0x00, 0x00, 0x00, 0x00, // binary32 +0.0 (info 26)
        ];
        let mut buf = [const { Record::empty() }; 1];
        let count = decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(count, 1);
        assert_eq!(buf[0].name, Some("x"));
        assert_eq!(buf[0].value, None);
    }

    /// Duplicate known keys within a record are rejected.
    #[test]
    fn decode_rejects_duplicate_known_keys() {
        // [{n: "a", n: "b"}]
        let wire_bytes = [0x81u8, 0xa2, 0x00, 0x61, 0x61, 0x00, 0x61, 0x62];
        let mut buf = [const { Record::empty() }; 1];
        assert_eq!(decode(&wire_bytes, &mut buf), Err(CborError::InvalidInput));
    }

    /// Trailing garbage after a valid pack is rejected.
    #[test]
    fn decode_rejects_trailing_bytes() {
        let recs = [Record {
            name: Some("lat"),
            value: Some(1.0),
            ..Record::empty()
        }];
        let mut buf = [0u8; 64];
        let n = encode(&recs, &mut buf).unwrap();
        let mut bad = [0u8; 96];
        bad[..n].copy_from_slice(&buf[..n]);
        for tail in &mut bad[n..n + 8] {
            *tail = 0xaa;
        }
        let mut out = [const { Record::empty() }; 4];
        assert_eq!(
            decode(&bad[..n + 8], &mut out),
            Err(CborError::InvalidInput)
        );
    }

    /// Half-precision and single-precision floats decode to their `f64`
    /// values; non-finite forms of any width are rejected.
    #[test]
    fn decode_handles_narrow_float_forms() {
        // [{v: f16(1.5)}] — f16 1.5 is 0x3e00.
        let f16_wire = [0x81u8, 0xa1, 0x02, 0xf9, 0x3e, 0x00];
        let mut buf = [const { Record::empty() }; 1];
        decode(&f16_wire, &mut buf).unwrap();
        assert_eq!(buf[0].value, Some(1.5));

        // [{v: f32(0.5)}] — 0x3f000000.
        let f32_wire = [0x81u8, 0xa1, 0x02, 0xfa, 0x3f, 0x00, 0x00, 0x00];
        decode(&f32_wire, &mut buf).unwrap();
        assert_eq!(buf[0].value, Some(0.5));

        // [{v: f16(NaN)}] — 0x7e00.
        let nan_wire = [0x81u8, 0xa1, 0x02, 0xf9, 0x7e, 0x00];
        assert_eq!(decode(&nan_wire, &mut buf), Err(CborError::NonFiniteValue));
    }

    /// A document that is not an array, or records that are not maps, are
    /// rejected; a pack larger than the output buffer reports capacity.
    #[test]
    fn decode_enforces_document_shape() {
        let mut buf = [const { Record::empty() }; 1];

        // Top-level map, not array.
        assert_eq!(decode(&[0xa0], &mut buf), Err(CborError::InvalidInput));

        // Array containing a scalar, not a map.
        assert_eq!(
            decode(&[0x81, 0x01], &mut buf),
            Err(CborError::InvalidInput)
        );

        // Two records, one slot.
        let two = [0x82u8, 0xa0, 0xa0];
        assert_eq!(
            decode(&two, &mut buf),
            Err(CborError::BufferTooSmall(BufferTooSmall::new(2, 1)))
        );

        // Empty pack decodes to zero records.
        assert_eq!(decode(&[0x80], &mut buf).unwrap(), 0);
    }

    /// Boolean values decode; other simple values under known keys do not.
    #[test]
    fn decode_bool_values() {
        let wire_bytes = [0x81u8, 0xa1, 0x04, 0xf5];
        let mut buf = [const { Record::empty() }; 1];
        decode(&wire_bytes, &mut buf).unwrap();
        assert_eq!(buf[0].bool_value, Some(true));
    }

    /// Regression test for bead project-LICHEN-23fv: skip_one_depth must use
    /// checked arithmetic to prevent overflow on 16-bit platforms when
    /// processing byte/text strings with 2-byte length encodings.
    ///
    /// A byte string claiming 65535 bytes with header adv=3 would cause
    /// `pos + adv + len` to wrap around on 16-bit usize. The decoder must
    /// reject this as truncated input rather than accepting a wrapped index.
    #[test]
    fn skip_one_rejects_length_overflow() {
        // Craft: [{99: bstr(len=65535)}] but truncate the actual bytes.
        // 0x81 array(1)
        // 0xa1 map(1)
        // 0x18 0x63 key 99 (unknown)
        // 0x59 0xff 0xff byte string claiming 65535 bytes
        // ...but only provide a few bytes, not 65535
        let wire_bytes: [u8; 12] = [
            0x81, // array(1)
            0xa1, // map(1)
            0x18, 0x63, // key 99
            0x59, 0xff, 0xff, // bstr header: 2-byte len = 65535
            0x00, 0x00, 0x00, 0x00, 0x00, // only 5 bytes, not 65535
        ];
        let mut buf = [const { Record::empty() }; 1];
        // Must reject as InvalidInput (truncated), not wrap around.
        assert_eq!(decode(&wire_bytes, &mut buf), Err(CborError::InvalidInput));
    }
}
