// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CBOR encoding and parsing helpers for EDHOC messages.

use super::types::{ConnectionId, VecExt};
use super::{EdhocError, CONNECTION_ID_CAPACITY};

/// Encode bytes as deterministic CBOR bstr (major type 2) matching zcbor/cbor2.
pub(crate) fn encode_bstr<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    data: &[u8],
) -> Result<(), EdhocError> {
    let len = data.len();
    if len <= 23 {
        buf.push_err(0x40u8 | len as u8)?;
    } else if len <= 0xff {
        buf.push_err(0x58)?;
        buf.push_err(len as u8)?;
    } else if len <= 0xffff {
        buf.push_err(0x59)?;
        buf.push_err((len >> 8) as u8)?;
        buf.push_err((len & 0xff) as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }
    buf.extend_err(data)?;
    Ok(())
}

/// Append a CBOR byte string (major type 2) to the buffer.
pub(crate) fn append_cbor_bstr<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    data: &[u8],
) -> Result<(), EdhocError> {
    let len = data.len();
    if len <= 23 {
        buf.push_err(0x40 | len as u8)?;
    } else if len <= 0xff {
        buf.push_err(0x58)?;
        buf.push_err(len as u8)?;
    } else if len <= 0xffff {
        buf.push_err(0x59)?;
        buf.push_err((len >> 8) as u8)?;
        buf.push_err((len & 0xff) as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }
    buf.extend_err(data)?;
    Ok(())
}

/// Parse a CBOR byte string (major type 2) from the front of `data`.
///
/// Returns (value_bytes, total_consumed) where total_consumed includes the
/// CBOR header.
pub(crate) fn parse_bstr(data: &[u8]) -> Result<(&[u8], usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x40..=0x57).contains(&first) {
        let len = (first - 0x40) as usize;
        if data.len() < 1 + len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((&data[1..1 + len], 1 + len))
    } else if first == 0x58 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = data[1] as usize;
        if data.len() < 2 + len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((&data[2..2 + len], 2 + len))
    } else if first == 0x59 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((&data[3..3 + len], 3 + len))
    } else {
        Err(EdhocError::InvalidMessage)
    }
}

/// Parse an identifier value from canonical CBOR encoding.
///
/// Returns (ConnectionId, bytes_consumed).
/// Rejects non-canonical encodings (e.g. bstr for compact-int values).
#[allow(clippy::needless_return)]
pub(crate) fn parse_identifier(data: &[u8]) -> Result<(ConnectionId, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x00..=0x17).contains(&first) {
        Ok((
            ConnectionId::new(&[first]).map_err(|_| EdhocError::BufferTooSmall)?,
            1,
        ))
    } else if (0x20..=0x37).contains(&first) {
        let n = first - 0x20 + 1;
        let val = 256u16 - n as u16;
        Ok((
            ConnectionId::new(&[val as u8]).map_err(|_| EdhocError::BufferTooSmall)?,
            1,
        ))
    } else if first == 0x18 {
        return Err(EdhocError::InvalidMessage);
    } else if (0x40..=0x57).contains(&first) {
        let len = (first - 0x40) as usize;
        if len == 1 && data.len() >= 2 && data[1] <= 23 {
            return Err(EdhocError::InvalidMessage);
        }
        if data.len() < 1 + len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((
            ConnectionId::new(&data[1..1 + len]).map_err(|_| EdhocError::BufferTooSmall)?,
            1 + len,
        ))
    } else if first == 0x58 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let len = data[1] as usize;
        if data.len() < 2 + len || len > CONNECTION_ID_CAPACITY {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((
            ConnectionId::new(&data[2..2 + len]).map_err(|_| EdhocError::BufferTooSmall)?,
            2 + len,
        ))
    } else {
        Err(EdhocError::InvalidMessage)
    }
}

/// Encode a connection identifier per RFC 9528 compact encoding.
///
/// Matches Python `_encode_connection_id`: single-byte values 0-23 are
/// encoded as CBOR unsigned integers, 232-255 as negative integers,
/// and everything else as a CBOR byte string.
pub(crate) fn encode_identifier<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    id: &ConnectionId,
) -> Result<(), EdhocError> {
    let bytes = id.as_bytes();
    if bytes.len() == 1 {
        let val = bytes[0];
        if val <= 23 {
            buf.push_err(val)?;
            return Ok(());
        }
        if val >= 232 {
            let abs_n = 256 - val as u16;
            buf.push_err(0x20u8 + (abs_n as u8 - 1))?;
            return Ok(());
        }
    }
    encode_bstr(buf, bytes)
}

/// Parse SUITES_I from CBOR per RFC 9528 Section 3.3.2.
///
/// SUITES_I can be either:
/// - A single int (the selected suite)
/// - An array of ints [selected_suite, ...other_supported_suites]
///
/// Returns (selected_suite, bytes_consumed).
pub(crate) fn parse_suites_i(data: &[u8]) -> Result<(u8, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }

    let first = data[0];

    // CBOR major type 0 (unsigned int): 0x00-0x17 (0-23), 0x18 (1-byte follow)
    if first <= 0x17 {
        // Direct int 0-23
        return Ok((first, 1));
    } else if first == 0x18 {
        // 1-byte follow
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((data[1], 2));
    }

    // CBOR major type 4 (array): 0x80-0x97 (array of 0-23 items), 0x98 (1-byte length)
    if (0x80..=0x97).contains(&first) {
        let arr_len = (first - 0x80) as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage); // Empty array not valid
        }
        // Parse first element (selected suite)
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[1];
        if elem <= 0x17 {
            // Count bytes: 1 (array header) + arr_len (each int 0-23 is 1 byte)
            // We only support suite values 0-23 for simplicity
            Ok((elem, 1 + arr_len))
        } else if elem == 0x18 && data.len() >= 3 {
            // First element is 1-byte int
            // Remaining elements assumed to be 1-byte each
            Ok((data[2], 1 + 1 + (arr_len - 1) + 1))
        } else {
            Err(EdhocError::InvalidMessage)
        }
    } else if first == 0x98 {
        // Array with 1-byte length
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        let arr_len = data[1] as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[2];
        if elem <= 0x17 {
            // 1 (0x98) + 1 (length) + arr_len (elements)
            Ok((elem, 2 + arr_len))
        } else {
            Err(EdhocError::InvalidMessage)
        }
    } else {
        Err(EdhocError::InvalidMessage)
    }
}

/// Parse SUITES_R (error) from an EDHOC error message.
///
/// Returns the number of bytes consumed.
pub(crate) fn parse_suites_r(data: &[u8]) -> Result<usize, EdhocError> {
    // SUITES_R is a CBOR array of ints or a single int.
    // We just need to validate and consume it.
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if (0x00..=0x17).contains(&first) {
        Ok(1)
    } else if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        Ok(2)
    } else if (0x80..=0x97).contains(&first) {
        let arr_len = (first - 0x80) as usize;
        if data.len() < 1 + arr_len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok(1 + arr_len)
    } else if first == 0x98 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let arr_len = data[1] as usize;
        if data.len() < 2 + arr_len {
            return Err(EdhocError::InvalidMessage);
        }
        Ok(2 + arr_len)
    } else {
        Err(EdhocError::InvalidMessage)
    }
}
