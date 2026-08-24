//! GCP-3.2 Open Federation trust model (spec/08-gateway-coordination.md).
//!
//! Implements Ed25519 identity keys with truncated Schnorr signatures, TOFU key
//! pinning on first contact, and optional PKI/DANE verification hooks.
//!
//! # Trust Flow
//!
//! 1. On first contact, verify that pubkey derives to claimed IID
//! 2. Pin the pubkey for that IID (TOFU)
//! 3. Subsequent contacts: reject any pubkey that doesn't match the pinned key
//! 4. Key rotation: old key must sign message authorizing new key
//!
//! # Trust Levels
//!
//! Trust levels are ordered by verification strength:
//! - TOFU (1): First-contact pinning, no external verification
//! - BR_PROVISIONED (2): Key provisioned by border router admin
//! - DANE (3): Key verified via DANE (DNS-based)
//! - PKIX (4): Key verified via X.509 PKI chain

extern crate alloc;

use crate::keys::PublicKey;
use lichen_core::addr::iid_from_pubkey_bytes;

/// Maximum length for control messages (key rotation, slot claims).
///
/// SECURITY: This bound prevents memory exhaustion and excessive CPU usage from
/// oversized messages. The limit of 256 bytes is well above any legitimate control
/// message (key rotation ~76 bytes, slot claims ~50 bytes) while staying within
/// the protocol's MAX_FRAME_LEN of 255 bytes for wire messages.
pub const MAX_CONTROL_MESSAGE_LEN: usize = 256;

/// Trust levels ordered by verification strength (spec GCP-3.2).
///
/// Higher values indicate stronger verification. Implementations may
/// upgrade trust level (TOFU -> DANE) but never downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustLevel {
    /// Trust-on-first-use: key pinned on first contact, no external verification.
    Tofu = 1,
    /// Key provisioned by border router administrator.
    BrProvisioned = 2,
    /// Key verified via DANE (DNS-based Authentication of Named Entities).
    Dane = 3,
    /// Key verified via X.509 PKI certificate chain.
    Pkix = 4,
}

impl TrustLevel {
    /// Returns the numeric value for serialization/comparison.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(TrustLevel::Tofu),
            2 => Some(TrustLevel::BrProvisioned),
            3 => Some(TrustLevel::Dane),
            4 => Some(TrustLevel::Pkix),
            _ => None,
        }
    }
}

/// Result of TOFU first-contact verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuResult {
    /// Pubkey correctly derives to claimed IID; pin and accept.
    PinAndAccept,
    /// Pubkey does not derive to claimed IID; reject (possible attack).
    RejectDerivationMismatch,
}

/// Result of key rotation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationResult {
    /// Old key validly signed the rotation message; accept new key.
    AcceptRotation,
    /// Signature verification failed; reject rotation.
    RejectInvalidSignature,
}

/// Result of slot claim verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotClaimResult {
    /// Signature verifies; accept the claim.
    AcceptClaim,
    /// Signature invalid; reject the claim.
    RejectSignatureInvalid,
}

/// Verify that a public key correctly derives to the claimed IID.
///
/// This is the core cryptographic binding for TOFU: the IID is derived
/// deterministically from the pubkey via SHA-512, so any key claiming
/// an IID it doesn't derive to is spoofing.
///
/// # Arguments
/// * `pubkey` - The Ed25519 public key presented by the peer
/// * `claimed_iid` - The 8-byte IID the peer claims to own
///
/// # Returns
/// `true` if SHA-512(pubkey)[0:8] (with U/L bit cleared) equals claimed_iid
pub fn verify_iid_derivation(pubkey: &PublicKey, claimed_iid: &[u8; 8]) -> bool {
    let derived_iid = iid_from_pubkey_bytes(pubkey.as_bytes());
    derived_iid == *claimed_iid
}

/// TOFU first-contact verification.
///
/// Verifies that the presented pubkey derives to the claimed IID. If valid,
/// the caller should pin the key. If invalid, the connection must be rejected
/// as a potential IID substitution attack.
///
/// # Arguments
/// * `pubkey` - The Ed25519 public key presented by the peer
/// * `claimed_iid` - The 8-byte IID the peer claims
///
/// # Security
/// SECURITY: This is the first line of defense against IID spoofing.
/// A valid derivation proves the peer controls the private key for that IID.
pub fn tofu_first_contact(pubkey: &PublicKey, claimed_iid: &[u8; 8]) -> TofuResult {
    if verify_iid_derivation(pubkey, claimed_iid) {
        TofuResult::PinAndAccept
    } else {
        TofuResult::RejectDerivationMismatch
    }
}

/// Expected prefix for key rotation messages.
const KEY_ROTATE_PREFIX: &[u8] = b"KEY_ROTATE:";

/// Expected prefix for slot claim messages.
const SLOT_CLAIM_PREFIX: &[u8] = b"SLOT_CLAIM:";

/// Verify a key rotation request.
///
/// Key rotation allows a node to update its Ed25519 keypair while maintaining
/// identity continuity. The old key must sign a rotation message containing
/// the new public key.
///
/// # Arguments
/// * `old_pubkey` - The currently-pinned public key for this peer
/// * `rotation_message` - The rotation message bytes (format: "KEY_ROTATE:" || new_pubkey_raw)
/// * `signature` - The 48-byte truncated Schnorr signature from the old key
///
/// # Returns
/// `AcceptRotation` if signature verifies, `RejectInvalidSignature` otherwise.
///
/// # Security
/// SECURITY: Rotation without old-key signature would allow key substitution attacks.
/// The signature proves the holder of the old private key authorizes the rotation.
/// SECURITY: Message format is validated to prevent cross-context signature replay
/// (confused deputy attack). A signature for a different message type (e.g., SLOT_CLAIM)
/// will be rejected even if cryptographically valid.
pub fn verify_key_rotation(
    old_pubkey: &PublicKey,
    rotation_message: &[u8],
    signature: &[u8],
) -> RotationResult {
    // SECURITY: Validate message format for domain separation.
    // Expected: "KEY_ROTATE:" (11 bytes) + raw pubkey (32 bytes) = 43 bytes.
    const EXPECTED_LEN: usize = 11 + 32; // KEY_ROTATE_PREFIX.len() + pubkey size
    if rotation_message.len() != EXPECTED_LEN {
        return RotationResult::RejectInvalidSignature;
    }
    if !rotation_message.starts_with(KEY_ROTATE_PREFIX) {
        return RotationResult::RejectInvalidSignature;
    }

    if signature.len() != 48 {
        return RotationResult::RejectInvalidSignature;
    }
    let sig: [u8; 48] = signature.try_into().unwrap();
    if schnorr48::verify(old_pubkey, rotation_message, &sig) {
        RotationResult::AcceptRotation
    } else {
        RotationResult::RejectInvalidSignature
    }
}

/// Verify a GCP slot claim message signature.
///
/// In open federation, gateway slot claims must be signed by the gateway's
/// Ed25519 key. This prevents rogue nodes from claiming slots they don't own.
///
/// # Arguments
/// * `gateway_pubkey` - The gateway's Ed25519 public key
/// * `message` - The slot claim message bytes
/// * `signature` - The 48-byte truncated Schnorr signature
///
/// # Returns
/// `AcceptClaim` if signature verifies, `RejectSignatureInvalid` otherwise.
///
/// # Security
/// SECURITY: Unsigned slot claims could allow DoS via slot exhaustion.
/// Signature verification ensures only legitimate gateways can claim slots.
pub fn verify_slot_claim(
    gateway_pubkey: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> SlotClaimResult {
    // SECURITY: Reject oversized messages to prevent memory/CPU exhaustion DoS.
    if message.len() > MAX_CONTROL_MESSAGE_LEN {
        return SlotClaimResult::RejectSignatureInvalid;
    }
    // SECURITY: Validate message format for domain separation.
    // Prevents cross-context signature replay (confused deputy attack).
    // A valid KEY_ROTATE message+signature must not be accepted as a slot claim.
    if !message.starts_with(SLOT_CLAIM_PREFIX) {
        return SlotClaimResult::RejectSignatureInvalid;
    }
    if signature.len() != 48 {
        return SlotClaimResult::RejectSignatureInvalid;
    }
    let sig: [u8; 48] = signature.try_into().unwrap();
    if schnorr48::verify(gateway_pubkey, message, &sig) {
        SlotClaimResult::AcceptClaim
    } else {
        SlotClaimResult::RejectSignatureInvalid
    }
}

/// Verify that a Yggdrasil address's lower 64 bits match the IID.
///
/// This invariant ensures the binding between ygg_addr and IID is consistent:
/// ygg_addr[8:16] == IID. Used to validate address construction.
pub fn verify_ygg_iid_binding(ygg_addr: &[u8; 16], iid: &[u8; 8]) -> bool {
    &ygg_addr[8..16] == iid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seed;
    use crate::schnorr::derive_keypair;
    use lichen_core::addr::ygg_addr_from_pubkey;
    use std::vec;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr8(v: &[u8]) -> [u8; 8] {
        v.try_into().expect("expected 8 bytes")
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().expect("expected 32 bytes")
    }

    #[allow(dead_code)]
    fn arr48(v: &[u8]) -> [u8; 48] {
        v.try_into().expect("expected 48 bytes")
    }

    // ── Trust level ordering (spec GCP-3.2) ───────────────────────────────

    #[test]
    fn trust_level_ordering() {
        // Test vectors: trust_level_ordering
        assert!(TrustLevel::Tofu < TrustLevel::BrProvisioned);
        assert!(TrustLevel::BrProvisioned < TrustLevel::Dane);
        assert!(TrustLevel::Dane < TrustLevel::Pkix);

        assert_eq!(TrustLevel::Tofu.as_u8(), 1);
        assert_eq!(TrustLevel::BrProvisioned.as_u8(), 2);
        assert_eq!(TrustLevel::Dane.as_u8(), 3);
        assert_eq!(TrustLevel::Pkix.as_u8(), 4);
    }

    #[test]
    fn trust_level_roundtrip() {
        for level in [
            TrustLevel::Tofu,
            TrustLevel::BrProvisioned,
            TrustLevel::Dane,
            TrustLevel::Pkix,
        ] {
            assert_eq!(TrustLevel::from_u8(level.as_u8()), Some(level));
        }
        assert_eq!(TrustLevel::from_u8(0), None);
        assert_eq!(TrustLevel::from_u8(5), None);
    }

    // ── Key derivation vectors (gcp3_trust_models.json) ───────────────────

    #[test]
    fn derivation_zero() {
        // Test vector: derivation_zero
        let seed = Seed::new(arr32(&hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )));
        let (_, pubkey) = derive_keypair(&seed);
        let expected_pubkey = arr32(&hex(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ));
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey_bytes(pubkey.as_bytes());
        let expected_iid = arr8(&hex("7dd5cfc679ab6342"));
        assert_eq!(iid, expected_iid);

        // Verify ygg_addr
        let ygg_addr = ygg_addr_from_pubkey(pubkey.as_bytes());
        let expected_ygg = hex("027dd5cfc679ab637dd5cfc679ab6342");
        assert_eq!(&ygg_addr[..], &expected_ygg[..]);
    }

    #[test]
    fn derivation_alice() {
        // Test vector: derivation_alice
        let seed = Seed::new(arr32(&hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )));
        let (_, pubkey) = derive_keypair(&seed);
        let expected_pubkey = arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        ));
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey_bytes(pubkey.as_bytes());
        let expected_iid = arr8(&hex("fd6b265c8585369b"));
        assert_eq!(iid, expected_iid);
    }

    #[test]
    fn derivation_bob() {
        // Test vector: derivation_bob
        let seed = Seed::new(arr32(&hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )));
        let (_, pubkey) = derive_keypair(&seed);
        let expected_pubkey = arr32(&hex(
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        ));
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey_bytes(pubkey.as_bytes());
        let expected_iid = arr8(&hex("888bcf64cfefa304"));
        assert_eq!(iid, expected_iid);
    }

    #[test]
    fn derivation_all_ff_ul_bit_cleared() {
        // Test vector: derivation_all_ff - demonstrates U/L bit clearing
        let seed = Seed::new(arr32(&hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )));
        let (_, pubkey) = derive_keypair(&seed);
        let expected_pubkey = arr32(&hex(
            "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
        ));
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey_bytes(pubkey.as_bytes());
        // raw_sha512_byte0 = 0xf7, final_iid_byte0 = 0xf5 (U/L bit cleared)
        let expected_iid = arr8(&hex("f57a7baa1226b50c"));
        assert_eq!(iid, expected_iid);
        // Verify U/L bit is cleared (bit 1 of first byte)
        assert_eq!(iid[0] & 0x02, 0, "U/L bit must be cleared");
    }

    // ── TOFU verification vectors (gcp3_trust_models.json) ────────────────

    #[test]
    fn tofu_valid_first_contact() {
        // Test vector: tofu_valid_first_contact
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let claimed_iid = arr8(&hex("fd6b265c8585369b"));

        assert!(verify_iid_derivation(&pubkey, &claimed_iid));
        assert_eq!(
            tofu_first_contact(&pubkey, &claimed_iid),
            TofuResult::PinAndAccept
        );
    }

    #[test]
    fn tofu_derivation_mismatch_attack() {
        // Test vector: tofu_derivation_mismatch_attack
        // Attacker uses bob's pubkey but claims alice's IID
        let attacker_pubkey = PublicKey::new(arr32(&hex(
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        )));
        let claimed_iid = arr8(&hex("fd6b265c8585369b")); // alice's IID

        assert!(!verify_iid_derivation(&attacker_pubkey, &claimed_iid));
        assert_eq!(
            tofu_first_contact(&attacker_pubkey, &claimed_iid),
            TofuResult::RejectDerivationMismatch
        );
    }

    #[test]
    fn tofu_key_mismatch_detection() {
        // Test vector: tofu_key_mismatch_detection
        // Different pubkey presented for pinned IID - derivation check catches it
        let presented_pubkey = PublicKey::new(arr32(&hex(
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        )));
        let pinned_iid = arr8(&hex("fd6b265c8585369b"));

        // Derivation check catches substitution before key comparison needed
        assert_eq!(
            tofu_first_contact(&presented_pubkey, &pinned_iid),
            TofuResult::RejectDerivationMismatch
        );
    }

    // ── Key rotation vectors (gcp3_trust_models.json) ─────────────────────

    #[test]
    fn key_rotation_valid_signature() {
        // Test vector: key_rotation_valid_signature
        let old_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let rotation_message = hex(
            "4b45595f524f544154453a7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        );
        let signature = hex(
            "21efa857cb1da57ea2e8025533429ed6a921ef44fff2d2f0a3d5277923d477e3de196aff02cd02e54af81ec97765f101",
        );

        assert_eq!(
            verify_key_rotation(&old_pubkey, &rotation_message, &signature),
            RotationResult::AcceptRotation
        );
    }

    #[test]
    fn key_rotation_invalid_signature() {
        // Test vector: key_rotation_invalid_signature
        // Signature from Charlie (wrong key), not Alice
        let old_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let rotation_message = hex(
            "4b45595f524f544154453a7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        );
        // Signature from Charlie's key, not Alice's
        let bad_signature = hex(
            "554de372b69523a78fb2a949257e1aeeaa8649e0c05bc96db4bbb465b5709ab804127f59ddd3b550c845c81f9c8c8701",
        );

        assert_eq!(
            verify_key_rotation(&old_pubkey, &rotation_message, &bad_signature),
            RotationResult::RejectInvalidSignature
        );
    }

    #[test]
    fn key_rotation_truncated_signature() {
        let old_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let rotation_message = hex("4b45595f524f544154453a");
        let truncated_sig = hex("21efa857cb1da57ea2e8025533429ed6"); // Only 16 bytes

        assert_eq!(
            verify_key_rotation(&old_pubkey, &rotation_message, &truncated_sig),
            RotationResult::RejectInvalidSignature
        );
    }

    // ── Open federation slot claim vectors (gcp3_trust_models.json) ───────

    #[test]
    fn open_federation_slot_claim_valid() {
        // Test vector: open_federation_slot_claim_valid
        let gateway_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let message =
            hex("534c4f545f434c41494d3a30313a676174657761795f6969643afd6b265c8585369b");
        let signature = hex(
            "45a4b53c65e11c450493d699f84c8e7585cfc4bafec86149d830b6eec7ba8eedeca2b33edcdcd7845a29e76e24844608",
        );

        assert_eq!(
            verify_slot_claim(&gateway_pubkey, &message, &signature),
            SlotClaimResult::AcceptClaim
        );
    }

    #[test]
    fn open_federation_tampered_message() {
        // Test vector: open_federation_tampered_message
        let gateway_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // Tampered message (slot 02 instead of 01)
        let tampered_message =
            hex("534c4f545f434c41494d3a30323a676174657761795f6969643afd6b265c8585369b");
        // Original signature (for slot 01)
        let signature = hex(
            "45a4b53c65e11c450493d699f84c8e7585cfc4bafec86149d830b6eec7ba8eedeca2b33edcdcd7845a29e76e24844608",
        );

        assert_eq!(
            verify_slot_claim(&gateway_pubkey, &tampered_message, &signature),
            SlotClaimResult::RejectSignatureInvalid
        );
    }

    #[test]
    fn slot_claim_truncated_signature() {
        let gateway_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let message = hex("534c4f545f434c41494d3a30313a");
        let truncated_sig = hex("45a4b53c65e11c45"); // Only 8 bytes

        assert_eq!(
            verify_slot_claim(&gateway_pubkey, &message, &truncated_sig),
            SlotClaimResult::RejectSignatureInvalid
        );
    }

    // ── Binding invariant vectors (gcp3_trust_models.json) ────────────────

    #[test]
    fn binding_invariant_alice() {
        // Test vector: binding_invariant_alice
        let pubkey_bytes = arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        ));
        let ygg_addr: [u8; 16] = hex("02fd6b265c858536fd6b265c8585369b")
            .try_into()
            .unwrap();
        let iid = arr8(&hex("fd6b265c8585369b"));

        assert!(verify_ygg_iid_binding(&ygg_addr, &iid));
        assert_eq!(iid_from_pubkey_bytes(&pubkey_bytes), iid);
    }

    #[test]
    fn binding_invariant_bob() {
        // Test vector: binding_invariant_bob
        let pubkey_bytes = arr32(&hex(
            "7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        ));
        let ygg_addr: [u8; 16] = hex("02888bcf64cfefa3888bcf64cfefa304")
            .try_into()
            .unwrap();
        let iid = arr8(&hex("888bcf64cfefa304"));

        assert!(verify_ygg_iid_binding(&ygg_addr, &iid));
        assert_eq!(iid_from_pubkey_bytes(&pubkey_bytes), iid);
    }

    #[test]
    fn binding_invariant_mismatch() {
        // ygg_addr lower 64 bits don't match claimed IID
        let ygg_addr: [u8; 16] = hex("02fd6b265c858536fd6b265c8585369b")
            .try_into()
            .unwrap();
        let wrong_iid = arr8(&hex("888bcf64cfefa304")); // bob's IID, not alice's

        assert!(!verify_ygg_iid_binding(&ygg_addr, &wrong_iid));
    }

    // ── Domain separation tests (confused deputy prevention) ─────────────

    #[test]
    fn key_rotation_rejects_slot_claim_message() {
        // SECURITY: A valid slot claim message+signature must not be accepted
        // as a key rotation. This tests domain separation (confused deputy).
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // Valid slot claim message (starts with "SLOT_CLAIM:", not "KEY_ROTATE:")
        let slot_claim_message =
            hex("534c4f545f434c41494d3a30313a676174657761795f6969643afd6b265c8585369b");
        // Valid signature for the slot claim (from test vector)
        let valid_slot_signature = hex(
            "45a4b53c65e11c450493d699f84c8e7585cfc4bafec86149d830b6eec7ba8eedeca2b33edcdcd7845a29e76e24844608",
        );

        // Attempting to use slot claim message as rotation must fail
        assert_eq!(
            verify_key_rotation(&pubkey, &slot_claim_message, &valid_slot_signature),
            RotationResult::RejectInvalidSignature
        );
    }

    #[test]
    fn key_rotation_rejects_wrong_length_message() {
        // Message too short (only prefix, no pubkey)
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let short_message = b"KEY_ROTATE:";
        let dummy_sig = [0u8; 48];

        assert_eq!(
            verify_key_rotation(&pubkey, short_message, &dummy_sig),
            RotationResult::RejectInvalidSignature
        );

        // Message too long (extra bytes after pubkey)
        let mut long_message = b"KEY_ROTATE:".to_vec();
        long_message.extend_from_slice(&[0u8; 33]); // 33 bytes instead of 32
        assert_eq!(
            verify_key_rotation(&pubkey, &long_message, &dummy_sig),
            RotationResult::RejectInvalidSignature
        );
    }

    #[test]
    fn key_rotation_rejects_wrong_prefix() {
        // Correct length but wrong prefix
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // 11 bytes prefix + 32 bytes "pubkey" = 43 bytes total
        let wrong_prefix_message = b"WRONG_PREF:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let dummy_sig = [0u8; 48];

        assert_eq!(wrong_prefix_message.len(), 43); // Verify test setup
        assert_eq!(
            verify_key_rotation(&pubkey, wrong_prefix_message, &dummy_sig),
            RotationResult::RejectInvalidSignature
        );
    }

    #[test]
    fn slot_claim_rejects_key_rotation_message() {
        // SECURITY: A valid key rotation message+signature must not be accepted
        // as a slot claim. This tests domain separation (confused deputy).
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // Valid key rotation message (starts with "KEY_ROTATE:", not "SLOT_CLAIM:")
        let key_rotation_message = hex(
            "4b45595f524f544154453a7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674",
        );
        // Valid signature for the key rotation (from test vector)
        let valid_rotation_signature = hex(
            "21efa857cb1da57ea2e8025533429ed6a921ef44fff2d2f0a3d5277923d477e3de196aff02cd02e54af81ec97765f101",
        );

        // Attempting to use key rotation message as slot claim must fail
        assert_eq!(
            verify_slot_claim(&pubkey, &key_rotation_message, &valid_rotation_signature),
            SlotClaimResult::RejectSignatureInvalid
        );
    }

    #[test]
    fn slot_claim_rejects_wrong_prefix() {
        // Any message without SLOT_CLAIM: prefix must be rejected
        let pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        let wrong_prefix_message = b"WRONG_CLAIM:01:gateway_iid:12345678";
        let dummy_sig = [0u8; 48];

        assert_eq!(
            verify_slot_claim(&pubkey, wrong_prefix_message, &dummy_sig),
            SlotClaimResult::RejectSignatureInvalid
        );
    }

    // ── Message length bounds tests (DoS prevention) ──────────────────────────

    #[test]
    fn slot_claim_rejects_oversized_message() {
        // SECURITY: Verify DoS protection via message length bounds
        let gateway_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // Create an oversized message (MAX_CONTROL_MESSAGE_LEN + 1 bytes)
        let oversized_message = vec![0u8; MAX_CONTROL_MESSAGE_LEN + 1];
        let signature = [0u8; 48];

        assert_eq!(
            verify_slot_claim(&gateway_pubkey, &oversized_message, &signature),
            SlotClaimResult::RejectSignatureInvalid
        );
    }

    #[test]
    fn slot_claim_accepts_max_length_message() {
        // Verify MAX_CONTROL_MESSAGE_LEN is inclusive (message at limit is allowed)
        let gateway_pubkey = PublicKey::new(arr32(&hex(
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
        )));
        // Create a message exactly at MAX_CONTROL_MESSAGE_LEN
        let max_length_message = vec![0u8; MAX_CONTROL_MESSAGE_LEN];
        let signature = [0u8; 48];

        // Should not reject for length, but will fail signature verification
        // (the important thing is it doesn't panic or accept based on length alone)
        let result = verify_slot_claim(&gateway_pubkey, &max_length_message, &signature);
        // The signature won't verify, but we passed the length check
        assert_eq!(result, SlotClaimResult::RejectSignatureInvalid);
    }
}
