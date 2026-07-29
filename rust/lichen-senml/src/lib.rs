//! SenML sensor data records for LICHEN (RFC 8428).
//!
//! Re-exports from the `senml-cbor` crate. Provides the `Record` type, CBOR
//! codec (Content-Format 112) and JSON codec (Content-Format 110) via `serde`
//! feature. LICHEN uses SenML-CBOR for sensor payloads, with base names of
//! the form `urn:dev:mac:<EUI-64>:`.

#![no_std]
#![forbid(unsafe_code)]

// Re-export core types from senml-cbor
pub use senml_cbor::cbor;
pub use senml_cbor::CborError;
pub use senml_cbor::Record;

#[cfg(feature = "std")]
extern crate std;
