// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Error type for LICHEN client wire (de)serialization.

use core::fmt;

/// An error decoding a CBOR payload into a LICHEN domain type.
#[derive(Debug)]
pub enum Error {
    /// The CBOR payload did not match the expected LICHEN wire schema.
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(m) => write!(f, "CBOR decode error: {m}"),
        }
    }
}

impl std::error::Error for Error {}
