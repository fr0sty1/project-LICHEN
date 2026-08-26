// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Buffer-oriented RFC 1055 SLIP framing.
//!
//! These functions do not allocate and are suitable for `no_std` targets.
//! [`encode`] adds both the leading synchronization delimiter and the trailing
//! frame delimiter. [`decode`] accepts exactly one delimited frame and rejects
//! malformed escape sequences as required by the LICHEN framing vectors.

use core::fmt;

/// Frame delimiter.
pub const END: u8 = 0xC0;
/// Escape prefix.
pub const ESC: u8 = 0xDB;
/// Escaped representation of [`END`] after [`ESC`].
pub const ESC_END: u8 = 0xDC;
/// Escaped representation of [`ESC`] after [`ESC`].
pub const ESC_ESC: u8 = 0xDD;

/// Maximum data size used by the LICHEN Local Client Interface.
pub const LCI_MAX_DATA_SIZE: usize = 2048;
/// Worst-case encoded size for a maximum-size LCI frame.
pub const LCI_MAX_FRAME_SIZE: usize = LCI_MAX_DATA_SIZE * 2 + 2;

/// SLIP framing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The complete encoded length cannot be represented by `usize`.
    LengthOverflow,
    /// The output buffer cannot hold the complete result.
    BufferTooSmall {
        /// Minimum output length required by the operation.
        needed: usize,
    },
    /// A frame must contain at least its two delimiters.
    FrameTooShort,
    /// The frame does not begin with [`END`].
    MissingStart,
    /// The frame does not end with [`END`].
    MissingEnd,
    /// An additional frame delimiter appeared inside the frame.
    UnexpectedEnd,
    /// An [`ESC`] at the end of the payload has no escaped byte after it.
    TruncatedEscape,
    /// An [`ESC`] was followed by a byte other than [`ESC_END`] or [`ESC_ESC`].
    InvalidEscape(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => write!(f, "SLIP frame length overflow"),
            Self::BufferTooSmall { needed } => {
                write!(f, "SLIP output buffer too small (need {needed} bytes)")
            }
            Self::FrameTooShort => write!(f, "SLIP frame must contain two END delimiters"),
            Self::MissingStart => write!(f, "SLIP frame does not start with END"),
            Self::MissingEnd => write!(f, "SLIP frame does not end with END"),
            Self::UnexpectedEnd => write!(f, "unexpected END inside SLIP frame"),
            Self::TruncatedEscape => write!(f, "truncated SLIP escape sequence"),
            Self::InvalidEscape(byte) => {
                write!(f, "invalid SLIP escape sequence: DB {byte:02X}")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Return the number of bytes needed to encode `data` as one SLIP frame.
pub fn encoded_len(data: &[u8]) -> Result<usize, Error> {
    let escaped_bytes = data
        .iter()
        .filter(|&&byte| byte == END || byte == ESC)
        .count();
    data.len()
        .checked_add(escaped_bytes)
        .and_then(|length| length.checked_add(2))
        .ok_or(Error::LengthOverflow)
}

/// Encode `data` as one SLIP frame in `out`.
///
/// The returned length selects the initialized prefix of `out`. If the buffer
/// is too small, no bytes are written.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let needed = encoded_len(data)?;
    if out.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut position = 0;
    out[position] = END;
    position += 1;

    for &byte in data {
        match byte {
            END => {
                out[position] = ESC;
                out[position + 1] = ESC_END;
                position += 2;
            }
            ESC => {
                out[position] = ESC;
                out[position + 1] = ESC_ESC;
                position += 2;
            }
            _ => {
                out[position] = byte;
                position += 1;
            }
        }
    }

    out[position] = END;
    debug_assert_eq!(position + 1, needed);
    Ok(needed)
}

fn decoded_len(payload: &[u8]) -> Result<usize, Error> {
    let mut length = 0;
    let mut position = 0;

    while position < payload.len() {
        match payload[position] {
            END => return Err(Error::UnexpectedEnd),
            ESC => {
                let escaped = payload
                    .get(position + 1)
                    .copied()
                    .ok_or(Error::TruncatedEscape)?;
                if escaped != ESC_END && escaped != ESC_ESC {
                    return Err(Error::InvalidEscape(escaped));
                }
                position += 2;
            }
            _ => position += 1,
        }
        length += 1;
    }

    Ok(length)
}

/// Decode one complete, delimited SLIP `frame` into `out`.
///
/// Empty frames (`[END, END]`) are valid and return zero. Malformed frames or
/// insufficient output capacity leave `out` unchanged.
pub fn decode(frame: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if frame.len() < 2 {
        return Err(Error::FrameTooShort);
    }
    if frame[0] != END {
        return Err(Error::MissingStart);
    }
    if frame[frame.len() - 1] != END {
        return Err(Error::MissingEnd);
    }

    let payload = &frame[1..frame.len() - 1];
    let needed = decoded_len(payload)?;
    if out.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }

    let mut input_position = 0;
    let mut output_position = 0;
    while input_position < payload.len() {
        let byte = payload[input_position];
        if byte == ESC {
            let escaped = payload[input_position + 1];
            out[output_position] = if escaped == ESC_END { END } else { ESC };
            input_position += 2;
        } else {
            out[output_position] = byte;
            input_position += 1;
        }
        output_position += 1;
    }

    debug_assert_eq!(output_position, needed);
    Ok(needed)
}
