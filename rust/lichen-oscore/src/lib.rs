// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! OSCORE (RFC 8613) implementation for LICHEN.
//!
//! This crate re-exports the [`oscore`] crate, providing end-to-end security
//! for CoAP using AES-CCM-16-64-128 and HKDF-SHA256.
//!
//! # Migration Note
//!
//! This crate was previously a standalone OSCORE implementation. It now wraps
//! the published `oscore` crate (version 0.1) which provides the same API.
//! All types and functions are re-exported for backwards compatibility.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

// Re-export everything from the oscore crate
pub use oscore::{
    // Constants
    ALG_AEAD, COAP_OPTION_OSCORE, ID_CONTEXT_CAPACITY, ID_MAX_LEN, KEY_LEN, NONCE_LEN,
    OSCORE_OPTION_MAX_LEN, PIV_MAX_LEN, SALT_MAX_LEN, TAG_LEN, WINDOW_SIZE,
    // Error types
    BufferTooSmall, ContextStoreError, OscoreError, ReservationError,
    // Core types
    Context, ContextId, OscoreSeqNum, PendingResponse, RequestIdentifiers, ReservedSender,
    SenderSequenceState, SenderStateStore,
    // Functions
    request_identifiers, validate_option,
    // Modules
    seqnum,
};

// Re-export EDHOC types when the feature is enabled
#[cfg(feature = "edhoc")]
pub use oscore::edhoc;

#[cfg(feature = "edhoc")]
pub use oscore::{
    ConnectionId, EdhocError, EdhocInitiator, EdhocResponder, IdCred, IdCredReference,
    PeerCredential, PendingMessage2, PendingMessage3,
};

// Re-export heapless for public API compatibility
pub use heapless;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hex_literal::hex;
    use std::format;

    #[test]
    fn context_creation_via_reexport() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let sender_id = &[0x00];
        let recipient_id = &[0x01];

        // Verify the re-exported Context type works
        let result = Context::new(&master_secret, None, None, sender_id, recipient_id);
        assert!(result.is_ok());

        let ctx = result.unwrap();
        assert_eq!(ctx.sender_id(), &[0x00]);
        assert_eq!(ctx.recipient_id(), &[0x01]);
    }

    #[test]
    fn error_types_accessible() {
        // Verify error types are properly re-exported
        let err = OscoreError::InvalidParam;
        assert_eq!(format!("{}", err), "invalid parameter");

        let buf_err = BufferTooSmall::new(100, 50);
        assert!(format!("{}", buf_err).contains("100"));
    }

    #[test]
    fn constants_match_rfc() {
        // RFC 8613 constants
        assert_eq!(KEY_LEN, 16); // AES-128
        assert_eq!(NONCE_LEN, 13); // CCM L=2
        assert_eq!(TAG_LEN, 8); // 64-bit tag
        assert_eq!(ALG_AEAD, 10); // AES-CCM-16-64-128
        assert_eq!(COAP_OPTION_OSCORE, 9);
    }
}
