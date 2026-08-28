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
    // Functions
    request_identifiers,
    // Modules
    seqnum,
    validate_option,
    // Error types
    BufferTooSmall,
    // Core types
    Context,
    ContextId,
    ContextStoreError,
    OscoreError,
    OscoreSeqNum,
    PendingResponse,
    RequestIdentifiers,
    ReservationError,
    ReservedSender,
    SenderSequenceState,
    SenderStateStore,
    // Constants
    ALG_AEAD,
    COAP_OPTION_OSCORE,
    ID_CONTEXT_CAPACITY,
    ID_MAX_LEN,
    KEY_LEN,
    NONCE_LEN,
    OSCORE_OPTION_MAX_LEN,
    PIV_MAX_LEN,
    SALT_MAX_LEN,
    TAG_LEN,
    WINDOW_SIZE,
};

// Re-export EDHOC types when the feature is enabled
#[cfg(feature = "edhoc")]
pub use oscore::edhoc;

#[cfg(feature = "edhoc")]
pub use oscore::{
    ConnectionId, EdhocError, EdhocInitiator, EdhocResponder, IdCred, IdCredReference,
    PeerCredential, PendingMessage2, PendingMessage3,
};

// EDHOC transcript hash helpers (RFC 9528)
#[cfg(feature = "edhoc")]
mod transcript;

#[cfg(feature = "edhoc")]
pub use transcript::transcript_2;

// Re-export heapless for public API compatibility
pub use heapless;

/// Durable pointer to the currently active OSCORE sender context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUpdateState {
    /// Monotonic key generation. Updates advance this by exactly one.
    pub generation: u32,
    /// Durable identifier of the active directional sender context.
    pub context_id: ContextId,
}

/// Durable storage capable of atomically publishing an OSCORE key update.
///
/// The compare-and-swap MUST update both the active-context pointer and the
/// initial sender state as one durable transaction. A torn update could either
/// reactivate retired keys or reuse an OSCORE nonce after recovery.
pub trait KeyUpdateStore: SenderStateStore {
    /// Load the durable active-context pointer.
    fn load_key_update(&mut self) -> Result<Option<KeyUpdateState>, Self::Error>;

    /// Atomically replace `expected`, create `replacement`'s sender state, and
    /// return `Ok(false)` without changing either value on an expectation miss.
    fn compare_exchange_key_update(
        &mut self,
        expected: KeyUpdateState,
        replacement: KeyUpdateState,
        initial_sender_state: SenderSequenceState,
    ) -> Result<bool, Self::Error>;
}

/// Failure to restore or atomically replace an OSCORE key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateError<E> {
    /// The replacement generation was not exactly current + 1, or overflowed.
    InvalidGeneration,
    /// The replacement reproduced the active sender context and nonce space.
    ReusedContext,
    /// New OSCORE key material or identifiers were invalid.
    Oscore(OscoreError),
    /// Durable storage failed.
    Storage(E),
    /// The durable active pointer was absent or did not match this context.
    Stale,
    /// Another owner won the atomic update race.
    Conflict,
}

/// One active, rollback-resistant OSCORE context generation.
pub struct KeyUpdateContext {
    context: Context,
    generation: u32,
}

/// Borrowed key material and identifiers for one replacement OSCORE context.
#[derive(Debug, Clone, Copy)]
pub struct KeyUpdateMaterial<'a> {
    /// AES-128 OSCORE master secret.
    pub master_secret: &'a [u8; KEY_LEN],
    /// Optional OSCORE master salt (at most [`SALT_MAX_LEN`] bytes).
    pub master_salt: Option<&'a [u8]>,
    /// Optional OSCORE ID Context.
    pub id_context: Option<&'a [u8]>,
    /// Local sender identifier.
    pub sender_id: &'a [u8],
    /// Peer recipient identifier.
    pub recipient_id: &'a [u8],
}

impl KeyUpdateContext {
    /// Wrap an already activated initial context.
    pub fn new(context: Context, generation: u32) -> Self {
        Self {
            context,
            generation,
        }
    }

    /// Restore only when the supplied context and generation match durable state.
    pub fn restore_checked<S: KeyUpdateStore>(
        context: Context,
        generation: u32,
        store: &mut S,
    ) -> Result<Self, KeyUpdateError<S::Error>> {
        let expected = KeyUpdateState {
            generation,
            context_id: context.context_id(),
        };
        match store.load_key_update().map_err(KeyUpdateError::Storage)? {
            Some(state) if state == expected => Ok(Self::new(context, generation)),
            _ => Err(KeyUpdateError::Stale),
        }
    }

    /// Return the active OSCORE context.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Return the active OSCORE context mutably for protect/unprotect operations.
    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }

    /// Return the active monotonic key generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Consume the slot and return its active context.
    pub fn into_context(self) -> Context {
        self.context
    }

    /// Derive, durably publish, and activate a replacement context.
    ///
    /// All fallible derivation happens before durable mutation. The store then
    /// publishes the new active pointer and initial sender sequence atomically.
    /// Only after that succeeds is the in-memory pointer swapped; dropping the
    /// previous [`Context`] zeroizes all old key material.
    pub fn update<S: KeyUpdateStore>(
        &mut self,
        material: KeyUpdateMaterial<'_>,
        generation: u32,
        store: &mut S,
    ) -> Result<(), KeyUpdateError<S::Error>> {
        if self.generation == u32::MAX || generation != self.generation + 1 {
            return Err(KeyUpdateError::InvalidGeneration);
        }

        let candidate = Context::new_fresh(
            material.master_secret,
            material.master_salt,
            material.id_context,
            material.sender_id,
            material.recipient_id,
        )
        .map_err(KeyUpdateError::Oscore)?;
        if candidate.context_id() == self.context.context_id() {
            return Err(KeyUpdateError::ReusedContext);
        }

        let expected = KeyUpdateState {
            generation: self.generation,
            context_id: self.context.context_id(),
        };
        let replacement = KeyUpdateState {
            generation,
            context_id: candidate.context_id(),
        };
        let mut adapter = KeyUpdateRegistration {
            store,
            expected,
            replacement,
        };
        let candidate = candidate
            .register_fresh(&mut adapter)
            .map_err(|error| match error {
                ContextStoreError::Oscore(error) => KeyUpdateError::Oscore(error),
                ContextStoreError::Storage(error) => KeyUpdateError::Storage(error),
                ContextStoreError::Missing => KeyUpdateError::Stale,
                ContextStoreError::Conflict => KeyUpdateError::Conflict,
            })?;

        let previous = core::mem::replace(&mut self.context, candidate);
        self.generation = generation;
        drop(previous);
        Ok(())
    }
}

struct KeyUpdateRegistration<'a, S> {
    store: &'a mut S,
    expected: KeyUpdateState,
    replacement: KeyUpdateState,
}

impl<S: KeyUpdateStore> SenderStateStore for KeyUpdateRegistration<'_, S> {
    type Error = S::Error;

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        self.store.load(context_id)
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if expected.is_some() || *context_id != self.replacement.context_id {
            return Ok(false);
        }
        self.store
            .compare_exchange_key_update(self.expected, self.replacement, next)
    }
}

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
