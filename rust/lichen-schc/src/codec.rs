//! SCHC compress/decompress stubs (RFC 8724 §7).

use lichen_core::constants::RULE_UNCOMPRESSED;

/// Error returned by compression/decompression.
#[derive(Debug, PartialEq, Eq)]
pub enum SchcError {
    /// No rule matched the packet headers.
    NoMatchingRule,
    /// The compressed buffer is too small.
    BufferTooSmall,
    /// The rule ID in the residue is unknown.
    UnknownRuleId(u8),
    /// The residue is truncated.
    Truncated,
}

/// Compress `packet` into `out`, returning the number of bytes written.
///
/// Stub: falls back to the uncompressed rule (prepend rule ID 255).
pub fn compress(packet: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    let needed = 1 + packet.len();
    if out.len() < needed {
        return Err(SchcError::BufferTooSmall);
    }
    out[0] = RULE_UNCOMPRESSED;
    out[1..needed].copy_from_slice(packet);
    Ok(needed)
}

/// Decompress `residue` into `out`, returning the number of bytes written.
///
/// Stub: handles the uncompressed rule only (strips leading rule ID byte).
pub fn decompress(residue: &[u8], out: &mut [u8]) -> Result<usize, SchcError> {
    if residue.is_empty() {
        return Err(SchcError::Truncated);
    }
    let rule_id = residue[0];
    if rule_id != RULE_UNCOMPRESSED {
        return Err(SchcError::UnknownRuleId(rule_id));
    }
    let payload = &residue[1..];
    if out.len() < payload.len() {
        return Err(SchcError::BufferTooSmall);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(payload.len())
}
