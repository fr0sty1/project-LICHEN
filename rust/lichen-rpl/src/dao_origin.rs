//! Consolidated DAO origin validation (spec section 8.6).
//!
//! This module provides origin validation for DAOs as specified in section 8.6
//! of the LICHEN routing specification. A DAO's origin must be validated against
//! a pre-pinned Announce identity before any route state mutation.
//!
//! The validation requires:
//! 1. The verification key MUST be from an already authenticated and pinned
//!    Announce identity (not self-certified or caller-supplied)
//! 2. The preserved source address IID MUST equal the identity's bound IID
//! 3. The DAO Origin Signature MUST be valid
//!
//! Per spec: "Receipt of a DAO MUST NOT create or replace an Announce pin."

#![forbid(unsafe_code)]

#[cfg(feature = "std")]
use crate::message::{
    Dao, DaoEnvelopeError, SignedDaoEnvelope, DAO_ORIGIN_SIGNATURE_DATA_LEN,
    OPT_DAO_ORIGIN_SIGNATURE,
};
#[cfg(feature = "std")]
use crate::verify::dao_origin_digest;
#[cfg(feature = "std")]
use lichen_link::{schnorr, ygg_addr_from_pubkey};
#[cfg(feature = "std")]
use sha2::{Digest, Sha512};

/// DAO Origin Signature Option type (spec 8.6, temporary value pending IANA).
#[cfg(feature = "std")]
pub const DAO_ORIGIN_SIGNATURE_TYPE: u8 = OPT_DAO_ORIGIN_SIGNATURE;

/// DAO Origin Signature Option data length (8 bytes sequence + 48 bytes Schnorr48).
#[cfg(feature = "std")]
pub const DAO_ORIGIN_SIGNATURE_LENGTH: usize = DAO_ORIGIN_SIGNATURE_DATA_LEN;

/// Rejection reasons for DAO origin validation.
///
/// These map directly to the spec 8.6 validation requirements.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoOriginRejectReason {
    /// Source IID has no pinned pubkey from prior announce.
    OriginNotPinned,
    /// Key-to-IID binding is invalid (pubkey doesn't derive to source IID).
    IidMismatch,
    /// DAO is missing the required DAO Origin Signature Option.
    SignatureMissing,
    /// DAO has duplicate DAO Origin Signature Options.
    SignatureDuplicate,
    /// DAO Origin Signature Option is not the final option.
    SignatureNotFinal,
    /// DAO Origin Signature Option has invalid length.
    SignatureInvalidLength,
    /// Schnorr48 signature verification failed.
    SignatureInvalid,
    /// Origin sequence is lower than the stored floor (replay attack).
    SequenceReplay,
    /// Origin sequence equals floor but DAO bytes differ (replay attack variant).
    SequenceEqualDifferentBytes,
    /// DAO structural malformed (invalid base, wrong instance, wrong DODAG).
    Malformed,
}

/// Result of DAO origin validation.
///
/// Contains all information needed by the caller to decide whether to process
/// the DAO and commit the replay floor.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaoOriginResult {
    /// True if origin validation passed.
    pub valid: bool,
    /// Reason for rejection if valid is false.
    pub reject_reason: Option<DaoOriginRejectReason>,
    /// The pinned public key used for verification (if valid).
    pub pubkey: Option<[u8; 32]>,
    /// The validated origin sequence (if valid).
    pub origin_sequence: Option<u64>,
    /// SHA-512 digest of the complete signed DAO bytes (if valid).
    pub dao_digest: Option<[u8; 64]>,
    /// True if this is a fresh DAO that needs replay floor commit.
    /// False for idempotent retransmissions. Only meaningful when valid is true.
    pub is_fresh: bool,
}

#[cfg(feature = "std")]
impl DaoOriginResult {
    /// Create a rejection result with the specified reason.
    pub fn reject(reason: DaoOriginRejectReason) -> Self {
        Self {
            valid: false,
            reject_reason: Some(reason),
            pubkey: None,
            origin_sequence: None,
            dao_digest: None,
            is_fresh: false,
        }
    }

    /// Create a successful validation result.
    pub fn accept(
        pubkey: [u8; 32],
        origin_sequence: u64,
        dao_digest: [u8; 64],
        is_fresh: bool,
    ) -> Self {
        Self {
            valid: true,
            reject_reason: None,
            pubkey: Some(pubkey),
            origin_sequence: Some(origin_sequence),
            dao_digest: Some(dao_digest),
            is_fresh,
        }
    }
}

/// Protocol for looking up pinned public keys by IID.
///
/// This abstracts access to the announce processor's pin table,
/// allowing DAO origin validation without tight coupling.
#[cfg(feature = "std")]
pub trait PinTable {
    /// Return the pinned 32-byte pubkey for an IID, or None if not pinned.
    fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<[u8; 32]>;
}

/// Protocol for crash-safe origin sequence replay protection.
///
/// Per spec 8.6: "The receiver MUST maintain crash-safe persistent state
/// per pinned public key containing the accepted high-water sequence and
/// a collision-resistant digest of the complete signed DAO bytes."
#[cfg(feature = "std")]
pub trait OriginReplayStore {
    /// Get (sequence, dao_digest) floor for pubkey, or None if no record.
    fn get_floor(&self, pubkey: &[u8; 32]) -> Option<(u64, [u8; 64])>;

    /// Durably commit new (sequence, dao_digest) floor for pubkey.
    fn set_floor(&mut self, pubkey: &[u8; 32], sequence: u64, dao_digest: [u8; 64]);
}

/// Compute collision-resistant digest of complete signed DAO bytes.
///
/// This is used for replay protection per spec 8.6 to detect
/// idempotent retransmissions vs. replay attacks with different content.
#[cfg(feature = "std")]
pub fn compute_dao_digest(signed_dao_bytes: &[u8]) -> [u8; 64] {
    Sha512::digest(signed_dao_bytes).into()
}

/// Consolidated DAO origin validation per spec section 8.6.
///
/// This validator checks:
/// 1. Source IID has a pinned pubkey from a prior announce
/// 2. Key-to-IID binding is valid
/// 3. DAO Origin Signature Option is present, final, and valid
/// 4. Origin sequence passes replay protection
///
/// Usage:
/// ```ignore
/// let validator = DaoOriginValidator::new(&pin_table, Some(&mut replay_store));
/// let result = validator.validate(dao_wire, source_address, rpl_instance_id, active_dodag_id);
/// if !result.valid {
///     reject_dao(result.reject_reason);
/// }
/// ```
#[cfg(feature = "std")]
pub struct DaoOriginValidator<'a, P: PinTable, R: OriginReplayStore> {
    pin_table: &'a P,
    replay_store: Option<&'a R>,
}

#[cfg(feature = "std")]
impl<'a, P: PinTable, R: OriginReplayStore> DaoOriginValidator<'a, P, R> {
    /// Create a new validator with the given pin table and optional replay store.
    pub fn new(pin_table: &'a P, replay_store: Option<&'a R>) -> Self {
        Self {
            pin_table,
            replay_store,
        }
    }

    /// Validate DAO origin per spec 8.6.
    ///
    /// Args:
    ///   wire: The complete DAO wire bytes (base + options including signature).
    ///   origin: The preserved IPv6 source address (origin's 02xx, 16 bytes).
    ///   rpl_instance_id: The expected RPL instance ID.
    ///   active_dodag_id: The active DODAG ID for this instance.
    ///
    /// Returns:
    ///   DaoOriginResult with validation outcome.
    pub fn validate(
        &self,
        wire: &[u8],
        origin: [u8; 16],
        rpl_instance_id: u8,
        active_dodag_id: [u8; 16],
    ) -> DaoOriginResult {
        // Step 1: Parse DAO base and validate structural properties
        let dao = match Dao::from_bytes(wire) {
            Ok(dao) => dao,
            Err(_) => return DaoOriginResult::reject(DaoOriginRejectReason::Malformed),
        };

        // Validate instance ID
        if dao.rpl_instance_id != rpl_instance_id {
            return DaoOriginResult::reject(DaoOriginRejectReason::Malformed);
        }

        // Validate flags and reserved byte
        if dao.flags != 0 || wire.get(2).copied() != Some(0) {
            return DaoOriginResult::reject(DaoOriginRejectReason::Malformed);
        }

        // Validate DODAG ID (D=0 uses Some([0; 16]) sentinel meaning "use receiver's DODAG")
        if dao
            .dodag_id
            .is_some_and(|dodag| dodag != [0u8; 16] && dodag != active_dodag_id)
        {
            return DaoOriginResult::reject(DaoOriginRejectReason::Malformed);
        }

        // Step 2: Parse signed envelope with signature validation
        let envelope = match SignedDaoEnvelope::from_bytes(wire) {
            Ok(env) => env,
            Err(err) => {
                let reason = match err {
                    DaoEnvelopeError::MissingSignature => DaoOriginRejectReason::SignatureMissing,
                    DaoEnvelopeError::DuplicateSignature => {
                        DaoOriginRejectReason::SignatureDuplicate
                    }
                    DaoEnvelopeError::NonTerminalSignature => {
                        DaoOriginRejectReason::SignatureNotFinal
                    }
                    DaoEnvelopeError::InvalidOptionLength => {
                        DaoOriginRejectReason::SignatureInvalidLength
                    }
                    DaoEnvelopeError::UnknownOption(_) | DaoEnvelopeError::Rpl(_) => {
                        DaoOriginRejectReason::Malformed
                    }
                };
                return DaoOriginResult::reject(reason);
            }
        };

        // Step 3: Extract source IID and lookup pinned pubkey
        let source_iid: [u8; 8] = match origin[8..].try_into() {
            Ok(iid) => iid,
            Err(_) => return DaoOriginResult::reject(DaoOriginRejectReason::Malformed),
        };

        let pubkey = match self.pin_table.pinned_pubkey_for(&source_iid) {
            Some(pk) => pk,
            None => return DaoOriginResult::reject(DaoOriginRejectReason::OriginNotPinned),
        };

        // Step 4: Validate key-to-IID binding
        if origin != ygg_addr_from_pubkey(&pubkey) {
            return DaoOriginResult::reject(DaoOriginRejectReason::IidMismatch);
        }

        // Step 5: Verify Schnorr48 signature
        // D=0 uses Some([0; 16]) sentinel - use active_dodag_id for digest.
        let effective_dodag_id = envelope
            .dao
            .dodag_id
            .filter(|id| *id != [0u8; 16])
            .unwrap_or(active_dodag_id);

        let digest = dao_origin_digest(
            origin,
            effective_dodag_id,
            envelope.origin.origin_sequence,
            envelope.unsigned_bytes,
        );

        if !schnorr::verify(&pubkey.into(), &digest, envelope.origin.signature) {
            return DaoOriginResult::reject(DaoOriginRejectReason::SignatureInvalid);
        }

        // Step 6: Compute DAO digest for replay protection
        let dao_digest = compute_dao_digest(wire);
        let origin_sequence = envelope.origin.origin_sequence;

        // Step 7: Replay classification (if store is available)
        // SECURITY: Per spec 8.6, the validator MUST NOT commit the replay floor here.
        // The floor is committed at step 7 (after semantic parsing and Target validation)
        // by the caller (DaoManager). This prevents premature floor commits that would
        // incorrectly block retransmissions when steps 5-6 fail.
        let mut is_fresh = true;

        if let Some(replay_store) = self.replay_store {
            if let Some((floor_seq, floor_digest)) = replay_store.get_floor(&pubkey) {
                if origin_sequence < floor_seq {
                    return DaoOriginResult::reject(DaoOriginRejectReason::SequenceReplay);
                }
                if origin_sequence == floor_seq {
                    // Equal sequence: must be exact retransmission
                    if dao_digest != floor_digest {
                        return DaoOriginResult::reject(
                            DaoOriginRejectReason::SequenceEqualDifferentBytes,
                        );
                    }
                    // Idempotent retransmission - valid but no state change needed
                    is_fresh = false;
                }
            }
        }

        DaoOriginResult::accept(pubkey, origin_sequence, dao_digest, is_fresh)
    }
}

/// Validator that does not use a replay store (for compatibility with existing code).
#[cfg(feature = "std")]
pub struct DaoOriginValidatorNoReplay<'a, P: PinTable> {
    pin_table: &'a P,
}

#[cfg(feature = "std")]
impl<'a, P: PinTable> DaoOriginValidatorNoReplay<'a, P> {
    /// Create a new validator without replay protection.
    pub fn new(pin_table: &'a P) -> Self {
        Self { pin_table }
    }

    /// Validate DAO origin per spec 8.6 (without replay check).
    pub fn validate(
        &self,
        wire: &[u8],
        origin: [u8; 16],
        rpl_instance_id: u8,
        active_dodag_id: [u8; 16],
    ) -> DaoOriginResult {
        // Delegate to the full validator with no replay store
        struct NoOpReplayStore;
        impl OriginReplayStore for NoOpReplayStore {
            fn get_floor(&self, _pubkey: &[u8; 32]) -> Option<(u64, [u8; 64])> {
                None
            }
            fn set_floor(&mut self, _pubkey: &[u8; 32], _sequence: u64, _dao_digest: [u8; 64]) {}
        }

        let noop_store = NoOpReplayStore;
        let validator: DaoOriginValidator<'_, P, NoOpReplayStore> =
            DaoOriginValidator::new(self.pin_table, Some(&noop_store));

        // Since we pass Some(&noop_store) but it always returns None from get_floor,
        // the result will always be is_fresh=true
        validator.validate(wire, origin, rpl_instance_id, active_dodag_id)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::vec;

    /// Mock pin table for testing.
    struct MockPinTable {
        pins: HashMap<[u8; 8], [u8; 32]>,
    }

    impl MockPinTable {
        fn new() -> Self {
            Self {
                pins: HashMap::new(),
            }
        }
    }

    impl PinTable for MockPinTable {
        fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<[u8; 32]> {
            self.pins.get(iid).copied()
        }
    }

    /// Mock replay store for testing.
    struct MockReplayStore {
        floors: HashMap<[u8; 32], (u64, [u8; 64])>,
    }

    impl MockReplayStore {
        fn new() -> Self {
            Self {
                floors: HashMap::new(),
            }
        }
    }

    impl OriginReplayStore for MockReplayStore {
        fn get_floor(&self, pubkey: &[u8; 32]) -> Option<(u64, [u8; 64])> {
            self.floors.get(pubkey).copied()
        }

        fn set_floor(&mut self, pubkey: &[u8; 32], sequence: u64, dao_digest: [u8; 64]) {
            self.floors.insert(*pubkey, (sequence, dao_digest));
        }
    }

    #[test]
    fn test_reject_result() {
        let result = DaoOriginResult::reject(DaoOriginRejectReason::OriginNotPinned);
        assert!(!result.valid);
        assert_eq!(
            result.reject_reason,
            Some(DaoOriginRejectReason::OriginNotPinned)
        );
        assert!(result.pubkey.is_none());
        assert!(result.origin_sequence.is_none());
        assert!(result.dao_digest.is_none());
        assert!(!result.is_fresh);
    }

    #[test]
    fn test_accept_result() {
        let pubkey = [0x42u8; 32];
        let dao_digest = [0x5au8; 64];
        let result = DaoOriginResult::accept(pubkey, 12345, dao_digest, true);
        assert!(result.valid);
        assert!(result.reject_reason.is_none());
        assert_eq!(result.pubkey, Some(pubkey));
        assert_eq!(result.origin_sequence, Some(12345));
        assert_eq!(result.dao_digest, Some(dao_digest));
        assert!(result.is_fresh);
    }

    #[test]
    fn test_compute_dao_digest_deterministic() {
        let dao_bytes = b"test dao bytes";
        let d1 = compute_dao_digest(dao_bytes);
        let d2 = compute_dao_digest(dao_bytes);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // SHA-512
    }

    #[test]
    fn test_compute_dao_digest_changes_with_content() {
        let d1 = compute_dao_digest(b"dao version 1");
        let d2 = compute_dao_digest(b"dao version 2");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_validator_rejects_unpinned_origin() {
        let pin_table = MockPinTable::new(); // Empty - no pins
        let replay_store = MockReplayStore::new();
        let validator = DaoOriginValidator::new(&pin_table, Some(&replay_store));

        // Build a structurally valid DAO with signature option
        // DAO base (20 bytes with D=1): instance=0, K=0 D=1 flags=0, reserved=0, seq=1
        // + signature option (2 bytes header + 56 bytes data) = 78 bytes total
        let mut wire = vec![0u8; 78];
        wire[0] = 0; // instance_id
        wire[1] = 0x40; // K=0, D=1
        wire[2] = 0; // reserved
        wire[3] = 1; // dao_sequence
                     // dodag_id: 16 bytes at offset 4-19
        wire[4] = 0xfd;
        // Signature option at offset 20 (immediately after DAO base with D=1)
        wire[20] = 0x12; // OPT_DAO_ORIGIN_SIGNATURE
        wire[21] = 56; // length
                       // origin_sequence (8 bytes, network byte order) - must be non-zero
        wire[22..30].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // sequence = 1
                                                                 // signature (48 bytes) at offset 30-77

        let origin = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0x01];
        let dodag_id = [0xfdu8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let result = validator.validate(&wire, origin, 0, dodag_id);

        // The validator will reject for OriginNotPinned since the pin table is empty
        assert!(!result.valid);
        assert_eq!(
            result.reject_reason,
            Some(DaoOriginRejectReason::OriginNotPinned)
        );
    }

    #[test]
    fn test_mock_replay_store() {
        let mut store = MockReplayStore::new();
        let pubkey = [0x42u8; 32];
        let dao_digest = [0x5au8; 64];

        assert!(store.get_floor(&pubkey).is_none());

        store.set_floor(&pubkey, 100, dao_digest);

        let floor = store.get_floor(&pubkey);
        assert!(floor.is_some());
        let (seq, digest) = floor.unwrap();
        assert_eq!(seq, 100);
        assert_eq!(digest, dao_digest);
    }
}
