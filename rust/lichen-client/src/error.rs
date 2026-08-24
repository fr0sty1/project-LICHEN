// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Error type for LICHEN client wire (de)serialization.

use core::fmt;

/// An error encoding or decoding a CBOR payload.
#[derive(Debug)]
pub enum Error {
    /// The CBOR payload did not match the expected LICHEN wire schema.
    Decode(String),
    /// Failed to encode a LICHEN domain type to CBOR.
    Encode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(m) => write!(f, "CBOR decode error: {m}"),
            Error::Encode(m) => write!(f, "CBOR encode error: {m}"),
        }
    }
}

impl std::error::Error for Error {}
