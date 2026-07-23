//! SenML sensor data records for LICHEN (RFC 8428).
//!
//! Provides the `Record` type, CBOR codec (Content-Format 112) in `cbor` and
//! JSON codec (Content-Format 110) via `serde` feature. LICHEN uses
//! SenML-CBOR for sensor payloads, with base names of the form
//! `urn:dev:mac:<EUI-64>:`.

#![no_std]
#![forbid(unsafe_code)]

pub mod cbor;
pub mod record;

pub use cbor::CborError;
pub use record::Record;

#[cfg(feature = "std")]
extern crate std;
