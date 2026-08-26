//! SenML sensor data records for LICHEN (RFC 8428).
//!
//! Provides a complete borrowed [`Record`] and an allocation-free CBOR codec
//! (Content-Format 112). LICHEN uses SenML-CBOR for sensor payloads, with base
//! names of the form `urn:dev:mac:<EUI-64>:`.

#![no_std]
#![forbid(unsafe_code)]

pub mod ipso;
pub mod wire;

/// Allocation-free SenML-CBOR pack codec.
pub mod cbor {
    pub use crate::wire::{decode, encode};
    pub use senml_cbor::cbor::CborError;
}

pub use senml_cbor::CborError;
pub use wire::Record;

#[cfg(feature = "std")]
extern crate std;
