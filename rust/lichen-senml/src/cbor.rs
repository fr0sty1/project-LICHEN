//! SenML-CBOR encode/decode stubs (RFC 8428 §6, Content-Format 112).

use crate::record::Record;

/// Error type for CBOR encode/decode.
#[derive(Debug, PartialEq, Eq)]
pub enum CborError {
    BufferTooSmall,
    InvalidInput,
    NotImplemented,
}

/// Encode a slice of records into `out` as SenML-CBOR.
///
/// Stub — always returns `NotImplemented`.
pub fn encode<'a>(_records: &[Record<'a>], _out: &mut [u8]) -> Result<usize, CborError> {
    Err(CborError::NotImplemented)
}

/// Decode SenML-CBOR bytes into a fixed-size array of records.
///
/// Stub — always returns `NotImplemented`.
pub fn decode<'a>(_data: &'a [u8], _buf: &'a mut [Record<'a>]) -> Result<usize, CborError> {
    Err(CborError::NotImplemented)
}
