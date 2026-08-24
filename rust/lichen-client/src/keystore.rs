// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Key store client for `/keys` CoAP resource operations.
//!
//! Provides a high-level async API for key store operations:
//! - List all peer keys (`GET /keys`)
//! - Get a single key by IID (`GET /keys/{iid}`)
//! - Pin/update a key (`PUT /keys/{iid}`)
//! - Delete a key (`DELETE /keys/{iid}`)
//!
//! # IID Format
//!
//! Interface identifiers (IIDs) use the format `xxxx:xxxx:xxxx:xxxx` where each
//! segment is exactly 4 lowercase hex digits separated by colons. The client
//! validates IID format before sending requests.
//!
//! # Example
//!
//! ```ignore
//! use lichen_client::keystore::KeyStoreClient;
//! use std::net::SocketAddr;
//!
//! let addr: SocketAddr = "[::1]:5683".parse().unwrap();
//! let mut client = KeyStoreClient::new();
//!
//! // List all keys
//! let keys = client.list(addr).await?;
//!
//! // Get a specific key
//! let key = client.get(addr, "1234:5678:9abc:def0").await?;
//!
//! // Pin a key as verified
//! client.pin(addr, "1234:5678:9abc:def0", "verified").await?;
//!
//! // Delete a key
//! client.delete(addr, "1234:5678:9abc:def0").await?;
//! ```

#[cfg(feature = "tokio")]
use crate::keys::{KeyEntry, KeyList, KeyPin};
#[cfg(feature = "tokio")]
use crate::paths::{keys_iid, KEYS};
use crate::Error;

/// Validates an IID string format.
///
/// Valid format: `xxxx:xxxx:xxxx:xxxx` where each segment is exactly 4
/// lowercase hex digits.
///
/// Returns the normalized (lowercase) IID on success.
pub fn validate_iid(iid: &str) -> Result<String, IidError> {
    let normalized = iid.to_ascii_lowercase();
    let segments: Vec<&str> = normalized.split(':').collect();

    if segments.len() != 4 {
        return Err(IidError::WrongSegmentCount {
            expected: 4,
            got: segments.len(),
        });
    }

    for (i, seg) in segments.iter().enumerate() {
        if seg.len() != 4 {
            return Err(IidError::InvalidSegmentLength {
                segment: i,
                expected: 4,
                got: seg.len(),
            });
        }
        for c in seg.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(IidError::InvalidHexCharacter {
                    segment: i,
                    char: c,
                });
            }
        }
    }

    Ok(normalized)
}

/// Error validating an IID format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IidError {
    /// IID must have exactly 4 segments.
    WrongSegmentCount { expected: usize, got: usize },
    /// Each segment must be exactly 4 hex characters.
    InvalidSegmentLength {
        segment: usize,
        expected: usize,
        got: usize,
    },
    /// IID contains invalid hex character.
    InvalidHexCharacter { segment: usize, char: char },
}

impl core::fmt::Display for IidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongSegmentCount { expected, got } => {
                write!(f, "IID must have {expected} segments, got {got}")
            }
            Self::InvalidSegmentLength {
                segment,
                expected,
                got,
            } => {
                write!(
                    f,
                    "IID segment {segment} must be {expected} chars, got {got}"
                )
            }
            Self::InvalidHexCharacter { segment, char } => {
                write!(
                    f,
                    "IID segment {segment} contains invalid character '{char}'"
                )
            }
        }
    }
}

impl std::error::Error for IidError {}

/// Error from key store operations.
#[derive(Debug)]
pub enum KeyStoreError {
    /// IID format validation failed.
    InvalidIid(IidError),
    /// CoAP transport error.
    #[cfg(feature = "tokio")]
    Transport(lichen_coap::client::ClientError),
    /// CoAP request returned a non-success code.
    CoAPError {
        /// CoAP response code as string (e.g., "4.04").
        code: String,
        /// Operation that failed.
        operation: &'static str,
    },
    /// CBOR decoding failed.
    Decode(Error),
}

impl core::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidIid(e) => write!(f, "invalid IID: {e}"),
            #[cfg(feature = "tokio")]
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::CoAPError { code, operation } => {
                write!(f, "{operation} failed: CoAP {code}")
            }
            Self::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidIid(e) => Some(e),
            #[cfg(feature = "tokio")]
            Self::Transport(e) => Some(e),
            Self::CoAPError { .. } => None,
            Self::Decode(e) => Some(e),
        }
    }
}

impl From<IidError> for KeyStoreError {
    fn from(e: IidError) -> Self {
        Self::InvalidIid(e)
    }
}

impl From<Error> for KeyStoreError {
    fn from(e: Error) -> Self {
        Self::Decode(e)
    }
}

#[cfg(feature = "tokio")]
impl From<lichen_coap::client::ClientError> for KeyStoreError {
    fn from(e: lichen_coap::client::ClientError) -> Self {
        Self::Transport(e)
    }
}

/// High-level client for key store operations.
///
/// Wraps the CoAP client with domain-aware methods for the `/keys` resource.
/// Tracks 5.03 backoff state across requests per spec 07 section 10.2.3.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct KeyStoreClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl KeyStoreClient {
    /// Create a new key store client.
    pub fn new() -> Self {
        Self::default()
    }

    /// List all peer keys from the node.
    ///
    /// Sends `GET /keys` and decodes the response.
    pub async fn list(&mut self, node: std::net::SocketAddr) -> Result<KeyList, KeyStoreError> {
        let resp = self.coap.get(node, KEYS).await?;
        if !resp.is_success() {
            return Err(KeyStoreError::CoAPError {
                code: resp.code_str(),
                operation: "list keys",
            });
        }
        Ok(KeyList::from_cbor(&resp.payload)?)
    }

    /// Get a single key by IID.
    ///
    /// Sends `GET /keys/{iid}` and decodes the response.
    /// Returns `Err(CoAPError { code: "4.04", .. })` if the key is not found.
    pub async fn get(
        &mut self,
        node: std::net::SocketAddr,
        iid: &str,
    ) -> Result<KeyEntry, KeyStoreError> {
        let normalized = validate_iid(iid)?;
        let path = keys_iid(&normalized);
        let resp = self.coap.get(node, &path).await?;
        if !resp.is_success() {
            return Err(KeyStoreError::CoAPError {
                code: resp.code_str(),
                operation: "get key",
            });
        }
        Ok(KeyEntry::from_cbor(&resp.payload)?)
    }

    /// Pin or update a key's trust level.
    ///
    /// Sends `PUT /keys/{iid}` with the given public key and trust level.
    ///
    /// SECURITY: The node TOFU-rejects any request whose `pubkey` differs from
    /// the one already pinned for the IID (4.09 Conflict). This prevents
    /// injecting new keys for existing IIDs.
    pub async fn pin(
        &mut self,
        node: std::net::SocketAddr,
        iid: &str,
        pubkey: &str,
        trust: &str,
    ) -> Result<(), KeyStoreError> {
        let normalized = validate_iid(iid)?;
        let path = keys_iid(&normalized);
        let pin = KeyPin {
            pubkey: pubkey.to_string(),
            trust: trust.to_string(),
        };
        let resp = self.coap.put(node, &path, &pin.to_cbor()).await?;
        if !resp.is_success() {
            return Err(KeyStoreError::CoAPError {
                code: resp.code_str(),
                operation: "pin key",
            });
        }
        Ok(())
    }

    /// Delete a key by IID.
    ///
    /// Sends `DELETE /keys/{iid}`.
    /// Returns `Err(CoAPError { code: "4.04", .. })` if the key is not found.
    pub async fn delete(
        &mut self,
        node: std::net::SocketAddr,
        iid: &str,
    ) -> Result<(), KeyStoreError> {
        let normalized = validate_iid(iid)?;
        let path = keys_iid(&normalized);
        let resp = self.coap.delete(node, &path).await?;
        if !resp.is_success() {
            return Err(KeyStoreError::CoAPError {
                code: resp.code_str(),
                operation: "delete key",
            });
        }
        Ok(())
    }

    /// Clear all backoff state (for testing or explicit reset).
    pub fn clear_all_backoffs(&mut self) {
        self.coap.clear_all_backoffs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IID Validation Tests (from keystore_iid.json vectors) ───────────────

    #[test]
    fn iid_valid_lowercase() {
        let result = validate_iid("1234:5678:9abc:def0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234:5678:9abc:def0");
    }

    #[test]
    fn iid_valid_uppercase_accepted() {
        let result = validate_iid("1234:5678:9ABC:DEF0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234:5678:9abc:def0");
    }

    #[test]
    fn iid_valid_mixed_case() {
        let result = validate_iid("1234:5678:9aBc:DeF0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1234:5678:9abc:def0");
    }

    #[test]
    fn iid_all_zeros() {
        let result = validate_iid("0000:0000:0000:0000");
        assert!(result.is_ok());
    }

    #[test]
    fn iid_all_ones() {
        let result = validate_iid("ffff:ffff:ffff:ffff");
        assert!(result.is_ok());
    }

    #[test]
    fn iid_short_segment_reject() {
        let result = validate_iid("123:5678:9abc:def0");
        assert!(matches!(
            result,
            Err(IidError::InvalidSegmentLength { segment: 0, .. })
        ));
    }

    #[test]
    fn iid_long_segment_reject() {
        let result = validate_iid("12345:5678:9abc:def0");
        assert!(matches!(
            result,
            Err(IidError::InvalidSegmentLength { segment: 0, .. })
        ));
    }

    #[test]
    fn iid_three_segments_reject() {
        let result = validate_iid("1234:5678:9abc");
        assert!(matches!(
            result,
            Err(IidError::WrongSegmentCount {
                expected: 4,
                got: 3
            })
        ));
    }

    #[test]
    fn iid_five_segments_reject() {
        let result = validate_iid("1234:5678:9abc:def0:1111");
        assert!(matches!(
            result,
            Err(IidError::WrongSegmentCount {
                expected: 4,
                got: 5
            })
        ));
    }

    #[test]
    fn iid_non_hex_reject() {
        let result = validate_iid("1234:5678:ghij:def0");
        assert!(matches!(
            result,
            Err(IidError::InvalidHexCharacter {
                segment: 2,
                char: 'g'
            })
        ));
    }

    #[test]
    fn iid_wrong_separator_reject() {
        // Dash separator results in wrong segment count (1 segment with dashes)
        let result = validate_iid("1234-5678-9abc-def0");
        assert!(matches!(
            result,
            Err(IidError::WrongSegmentCount {
                expected: 4,
                got: 1
            })
        ));
    }

    #[test]
    fn iid_no_separator_reject() {
        // No colons means 1 segment
        let result = validate_iid("123456789abcdef0");
        assert!(matches!(
            result,
            Err(IidError::WrongSegmentCount {
                expected: 4,
                got: 1
            })
        ));
    }

    #[test]
    fn iid_empty_reject() {
        let result = validate_iid("");
        assert!(matches!(
            result,
            Err(IidError::WrongSegmentCount {
                expected: 4,
                got: 1
            })
        ));
    }

    // ── Error Display Tests ─────────────────────────────────────────────────

    #[test]
    fn iid_error_display() {
        let err = IidError::WrongSegmentCount {
            expected: 4,
            got: 3,
        };
        assert!(err.to_string().contains("4 segments"));
        assert!(err.to_string().contains("got 3"));

        let err = IidError::InvalidSegmentLength {
            segment: 1,
            expected: 4,
            got: 5,
        };
        assert!(err.to_string().contains("segment 1"));

        let err = IidError::InvalidHexCharacter {
            segment: 2,
            char: 'g',
        };
        assert!(err.to_string().contains("segment 2"));
        assert!(err.to_string().contains("'g'"));
    }

    #[test]
    fn keystore_error_display() {
        let err = KeyStoreError::InvalidIid(IidError::WrongSegmentCount {
            expected: 4,
            got: 3,
        });
        assert!(err.to_string().contains("invalid IID"));

        let err = KeyStoreError::CoAPError {
            code: "4.04".to_string(),
            operation: "get key",
        };
        assert!(err.to_string().contains("get key failed"));
        assert!(err.to_string().contains("4.04"));
    }
}
