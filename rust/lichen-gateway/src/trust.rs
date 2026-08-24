// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! GCP-3 Trust Models implementation.
//!
//! Per spec/08-gateway-coordination.md Section 3, implements both federation modes:
//!
//! - **GCP-3.1 Closed Federation (PSK)**: OSCORE with pre-shared key
//! - **GCP-3.2 Open Federation (Signatures)**: Ed25519 + Schnorr48 with TOFU/PKI
//!
//! # Closed Federation (PSK)
//!
//! - All gateways share a pre-configured PSK
//! - CoAP messages protected with OSCORE using the PSK
//! - Suitable for enterprise, events, single-organization deployments
//! - Simple provisioning: one shared secret per federation
//!
//! # Open Federation (Signatures)
//!
//! - Gateways use their Ed25519 identity keys (same as nodes)
//! - Messages signed using truncated Schnorr signatures (Schnorr48)
//! - Trust established via TOFU on first contact; keys pinned thereafter
//! - Optional PKI/DANE for stronger verification
//! - Enables permissionless community meshes
//!
//! # Trust Levels
//!
//! Trust levels are ordered by verification strength:
//! ```text
//! TOFU (1) < BR_PROVISIONED (2) < DANE (3) < PKIX (4)
//! ```
//!
//! # Key Derivation
//!
//! Pubkey -> IID derivation uses SHA-512 to match Yggdrasil's `AddrForKey`:
//! ```text
//! IID = SHA-512(pubkey)[0:8] with U/L bit cleared
//! ```
//!
//! PSK -> OSCORE context follows RFC 8613 Section 3.2 (HKDF-SHA256).
//!
//! # Security Notes
//!
//! - SECURITY: IID binding MUST be verified before accepting any gateway identity
//! - SECURITY: Key rotation requires signature from the OLD key
//! - SECURITY: PSK derivation uses HKDF-SHA256 per RFC 8613

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lichen_oscore::Context as OscoreContext;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

// Re-export Schnorr types from lichen-link
pub use lichen_link::keys::{PrivateKey, PublicKey, Seed};
pub use schnorr48::{sign, verify};

/// Length of a Schnorr48 signature in bytes.
pub const SIGNATURE_LEN: usize = 48;

/// Canonical key-rotation transcript domain.
pub const KEY_ROTATION_DOMAIN: &[u8] = b"LICHEN-KEY-ROTATION-v1";

/// OSCORE algorithm: AES-CCM-16-64-128 (RFC 8613).
pub const ALG_AEAD: i32 = 10;

/// AES-128 key length.
pub const KEY_LEN: usize = 16;

/// Common IV length for AES-CCM.
pub const IV_LEN: usize = 13;

/// OSCORE permits at most seven ID bytes with the selected nonce profile.
const OSCORE_GATEWAY_ID_LEN: usize = 7;

/// Default maximum number of durable gateway pins.
pub const DEFAULT_MAX_TRUSTED_GATEWAYS: usize = 1_024;

/// Absolute implementation limit for durable gateway pins.
pub const MAX_TRUSTED_GATEWAYS: usize = 4_096;

const TRUST_STORE_MAGIC: &[u8; 8] = b"LCHNTRS1";
const TRUST_STORE_VERSION_LEGACY: u16 = 1;
const TRUST_STORE_VERSION: u16 = 2;
const TRUST_STORE_MAC_DOMAIN: &[u8] = b"LICHEN-GCP-TRUST-STORE-v1";
const IDENTITY_PROOF_DOMAIN: &[u8] = b"LICHEN-GCP-IDENTITY-PROOF-v1";
const IDENTITY_CHALLENGE_DOMAIN: &[u8] = b"LICHEN-GCP-IDENTITY-CHALLENGE-v1";
const IDENTITY_CHALLENGE_AUTHORITY_DOMAIN: &[u8] = b"LICHEN-GCP-IDENTITY-CHALLENGE-AUTHORITY-v1";
const MAX_IDENTITY_CHALLENGES: usize = 4_096;

// ─── Trust Level ─────────────────────────────────────────────────────────────

/// Trust verification level (GCP-3).
///
/// Ordered by verification strength: TOFU < BR_PROVISIONED < DANE < PKIX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustLevel {
    /// Trust-on-first-use: key pinned on first contact.
    Tofu = 1,
    /// Provisioned by border router (out-of-band trust).
    BrProvisioned = 2,
    /// DNS-based Authentication of Named Entities (RFC 6698).
    Dane = 3,
    /// X.509 PKI certificate chain.
    Pkix = 4,
}

impl TrustLevel {
    /// Returns the numeric value for wire encoding.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from wire format.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Tofu),
            2 => Some(Self::BrProvisioned),
            3 => Some(Self::Dane),
            4 => Some(Self::Pkix),
            _ => None,
        }
    }

    /// Returns the name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tofu => "TOFU",
            Self::BrProvisioned => "BR_PROVISIONED",
            Self::Dane => "DANE",
            Self::Pkix => "PKIX",
        }
    }
}

// ─── Trust Error ─────────────────────────────────────────────────────────────

/// Trust verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// Pubkey does not derive to claimed IID.
    DerivationMismatch {
        claimed_iid: [u8; 8],
        derived_iid: [u8; 8],
    },
    /// Key rotation signature is invalid.
    InvalidRotationSignature,
    /// Rotation sequence is zero or does not strictly advance the durable floor.
    InvalidRotationSequence { current: u64, presented: u64 },
    /// Unknown gateway (not in trust store).
    UnknownGateway,
    /// Key conflict: different key presented for pinned IID.
    KeyConflict {
        pinned_pubkey: [u8; 32],
        presented_pubkey: [u8; 32],
    },
    /// Invalid signature on message.
    InvalidSignature,
    /// The challenge was not a fresh, non-zero challenge generated by the verifier.
    InvalidChallenge,
    /// The configured trust-store capacity is invalid.
    InvalidCapacity,
    /// Durable and configured capacity limits disagree.
    CapacityMismatch { stored: usize, configured: usize },
    /// The trust store is full; existing pins are never evicted automatically.
    StoreFull { capacity: usize },
    /// A durable trust store does not exist at the requested path.
    MissingStore,
    /// A durable trust-store record is truncated or malformed.
    CorruptStore,
    /// The durable trust-store integrity check failed.
    IntegrityFailure,
    /// The durable state generation is older than the caller's rollback floor.
    RollbackDetected { stored: u64, minimum: u64 },
    /// The durable state generation cannot be advanced safely.
    GenerationExhausted,
    /// A durable trust-store I/O operation failed.
    StorageIo(String),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DerivationMismatch { .. } => write!(f, "pubkey does not derive to claimed IID"),
            Self::InvalidRotationSignature => write!(f, "invalid key rotation signature"),
            Self::InvalidRotationSequence { current, presented } => write!(
                f,
                "key rotation sequence {presented} does not advance durable floor {current}"
            ),
            Self::UnknownGateway => write!(f, "unknown gateway"),
            Self::KeyConflict { .. } => write!(f, "key conflict for pinned IID"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidChallenge => write!(f, "identity proof challenge is invalid"),
            Self::InvalidCapacity => write!(f, "trust-store capacity is invalid"),
            Self::CapacityMismatch { stored, configured } => write!(
                f,
                "trust-store capacity mismatch (stored {stored}, configured {configured})"
            ),
            Self::StoreFull { capacity } => {
                write!(f, "trust store is full (capacity {capacity})")
            }
            Self::MissingStore => write!(f, "trust store does not exist"),
            Self::CorruptStore => write!(f, "trust store is corrupt"),
            Self::IntegrityFailure => write!(f, "trust-store integrity check failed"),
            Self::RollbackDetected { stored, minimum } => write!(
                f,
                "trust-store rollback detected (stored {stored}, minimum {minimum})"
            ),
            Self::GenerationExhausted => write!(f, "trust-store generation exhausted"),
            Self::StorageIo(message) => write!(f, "trust-store I/O failed: {message}"),
        }
    }
}

impl std::error::Error for TrustError {}

// ─── TOFU Result ─────────────────────────────────────────────────────────────

/// Result of TOFU verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuResult {
    /// First contact: pubkey correctly derives to IID, pinned.
    PinAndAccept,
    /// Existing pinned key matches.
    AcceptKnown,
    /// Key rotation accepted (old key signed new key).
    AcceptRotation {
        old_pubkey: [u8; 32],
        new_pubkey: [u8; 32],
    },
}

/// Proof that a gateway controls the private key bound to its claimed IID.
///
/// Fields are deliberately private. The only constructor verifies a signature
/// over a verifier-provided fresh challenge and the claimed IID.
#[derive(Debug, Clone)]
pub struct VerifiedGatewayIdentity {
    pubkey: [u8; 32],
    iid: [u8; 8],
}

impl VerifiedGatewayIdentity {
    #[cfg(test)]
    #[doc(hidden)]
    /// Compatibility helper for neighboring unit tests. Production callers
    /// cannot manufacture a verified identity without a challenge issuer.
    pub fn verify(
        pubkey: &[u8; 32],
        claimed_iid: &[u8; 8],
        presented_challenge: &[u8; 32],
        expected_challenge: &[u8; 32],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<Self, TrustError> {
        verify_iid_binding(pubkey, claimed_iid)?;
        if presented_challenge != expected_challenge || expected_challenge == &[0; 32] {
            return Err(TrustError::InvalidChallenge);
        }
        let transcript = build_identity_proof_transcript(claimed_iid, expected_challenge);
        if !verify_gateway_message(pubkey, &transcript, signature) {
            return Err(TrustError::InvalidSignature);
        }
        Ok(Self {
            pubkey: *pubkey,
            iid: *claimed_iid,
        })
    }

    /// Verified public key.
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// Verified key-derived IID.
    pub fn iid(&self) -> &[u8; 8] {
        &self.iid
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityChallengeRecord {
    peer_iid: [u8; 8],
    session_id: [u8; 32],
    challenge: [u8; 32],
    expires_at_ms: u64,
}

/// Opaque one-use authority for one gateway proof-of-possession exchange.
///
/// Values are issued only by [`GatewayChallengeIssuer`]. The private fields and
/// lack of `Clone` prevent packet input from manufacturing or duplicating an
/// authority. The challenge bytes themselves are public and may be sent to the
/// peer being enrolled.
pub struct GatewayIdentityChallenge {
    authority_id: [u8; 16],
    token: u64,
    record: IdentityChallengeRecord,
}

/// Peer-supplied proof material presented for one issued identity challenge.
pub struct GatewayIdentityPresentation<'a> {
    pub pubkey: &'a [u8; 32],
    pub claimed_iid: &'a [u8; 8],
    pub challenge: &'a [u8; 32],
    pub signature: &'a [u8; SIGNATURE_LEN],
}

impl GatewayIdentityChallenge {
    /// Fresh challenge bytes to send to the bound peer.
    pub fn challenge(&self) -> &[u8; 32] {
        &self.record.challenge
    }

    /// Peer IID to which this authority is bound.
    pub fn peer_iid(&self) -> &[u8; 8] {
        &self.record.peer_iid
    }

    /// Enrollment-session identifier to which this authority is bound.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.record.session_id
    }
}

/// Bounded owner of fresh, expiring, one-use identity-proof challenges.
///
/// `authority_secret` must be generated from a cryptographically secure random
/// source. It is retained only to generate unpredictable challenges and is
/// zeroized when the issuer is dropped.
pub struct GatewayChallengeIssuer {
    authority_secret: Zeroizing<[u8; 32]>,
    authority_id: [u8; 16],
    outstanding: HashMap<u64, IdentityChallengeRecord>,
    capacity: usize,
    next_token: u64,
    last_now_ms: u64,
}

impl GatewayChallengeIssuer {
    /// Create a challenge owner with a hard bound on outstanding exchanges.
    pub fn new(authority_secret: [u8; 32], capacity: usize) -> Result<Self, TrustError> {
        if authority_secret == [0; 32] || capacity == 0 || capacity > MAX_IDENTITY_CHALLENGES {
            return Err(TrustError::InvalidChallenge);
        }
        let authority_id: [u8; 16] = Sha512::new()
            .chain_update(IDENTITY_CHALLENGE_AUTHORITY_DOMAIN)
            .chain_update(authority_secret)
            .finalize()[..16]
            .try_into()
            .expect("SHA-512 output has a 16-byte prefix");
        Ok(Self {
            authority_secret: Zeroizing::new(authority_secret),
            authority_id,
            outstanding: HashMap::with_capacity(capacity.min(64)),
            capacity,
            next_token: 1,
            last_now_ms: 0,
        })
    }

    /// Issue one challenge bound to an exact peer and enrollment session.
    pub fn issue(
        &mut self,
        peer_iid: [u8; 8],
        session_id: [u8; 32],
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<GatewayIdentityChallenge, TrustError> {
        self.observe_time(now_ms)?;
        if session_id == [0; 32] || ttl_ms == 0 {
            return Err(TrustError::InvalidChallenge);
        }
        self.outstanding
            .retain(|_, record| record.expires_at_ms > now_ms);
        if self.outstanding.len() >= self.capacity {
            return Err(TrustError::StoreFull {
                capacity: self.capacity,
            });
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or(TrustError::InvalidChallenge)?;
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(TrustError::GenerationExhausted)?;
        let challenge: [u8; 32] = Sha512::new()
            .chain_update(IDENTITY_CHALLENGE_DOMAIN)
            .chain_update(self.authority_secret.as_ref())
            .chain_update(self.authority_id)
            .chain_update(token.to_be_bytes())
            .chain_update(peer_iid)
            .chain_update(session_id)
            .chain_update(now_ms.to_be_bytes())
            .chain_update(expires_at_ms.to_be_bytes())
            .finalize()[..32]
            .try_into()
            .expect("SHA-512 output has a 32-byte prefix");
        if challenge == [0; 32] {
            return Err(TrustError::InvalidChallenge);
        }
        let record = IdentityChallengeRecord {
            peer_iid,
            session_id,
            challenge,
            expires_at_ms,
        };
        self.outstanding.insert(token, record.clone());
        Ok(GatewayIdentityChallenge {
            authority_id: self.authority_id,
            token,
            record,
        })
    }

    /// Consume one authority and authenticate the exact bound peer/session.
    ///
    /// A signature failure still consumes the authority, preventing repeated
    /// guesses or later replay of the same proof transcript.
    pub fn verify_identity(
        &mut self,
        authority: GatewayIdentityChallenge,
        session_id: &[u8; 32],
        now_ms: u64,
        presentation: GatewayIdentityPresentation<'_>,
    ) -> Result<VerifiedGatewayIdentity, TrustError> {
        self.observe_time(now_ms)?;
        if authority.authority_id != self.authority_id
            || authority.record.session_id != *session_id
            || authority.record.peer_iid != *presentation.claimed_iid
        {
            return Err(TrustError::InvalidChallenge);
        }
        let Some(record) = self.outstanding.remove(&authority.token) else {
            return Err(TrustError::InvalidChallenge);
        };
        if record != authority.record
            || now_ms >= record.expires_at_ms
            || record.challenge != *presentation.challenge
        {
            return Err(TrustError::InvalidChallenge);
        }
        verify_iid_binding(presentation.pubkey, presentation.claimed_iid)?;
        let transcript =
            build_identity_proof_transcript(presentation.claimed_iid, &record.challenge);
        if !verify_gateway_message(presentation.pubkey, &transcript, presentation.signature) {
            return Err(TrustError::InvalidSignature);
        }
        Ok(VerifiedGatewayIdentity {
            pubkey: *presentation.pubkey,
            iid: *presentation.claimed_iid,
        })
    }

    fn observe_time(&mut self, now_ms: u64) -> Result<(), TrustError> {
        if now_ms < self.last_now_ms {
            return Err(TrustError::InvalidChallenge);
        }
        self.last_now_ms = now_ms;
        Ok(())
    }
}

/// Build the domain-separated transcript used for identity proof.
pub fn build_identity_proof_transcript(iid: &[u8; 8], challenge: &[u8; 32]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(IDENTITY_PROOF_DOMAIN.len() + 8 + 32);
    transcript.extend_from_slice(IDENTITY_PROOF_DOMAIN);
    transcript.extend_from_slice(iid);
    transcript.extend_from_slice(challenge);
    transcript
}

// ─── IID Derivation ──────────────────────────────────────────────────────────

/// Derive IID from Ed25519 pubkey.
///
/// MUST use SHA-512 per Yggdrasil's `AddrForKey` algorithm:
/// ```text
/// IID = SHA-512(pubkey)[0:8] with U/L bit cleared (bit 1 of byte 0)
/// ```
pub fn iid_from_pubkey(pubkey: &[u8; 32]) -> [u8; 8] {
    lichen_core::addr::iid_from_pubkey_bytes(pubkey)
}

/// Derive full 16-byte Yggdrasil 02xx address from pubkey.
pub fn ygg_addr_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    lichen_core::addr::ygg_addr_from_pubkey(pubkey)
}

/// Verify that a pubkey correctly derives to the claimed IID.
///
/// SECURITY: This MUST be called before accepting any gateway identity.
/// Attackers attempting IID substitution will fail this check.
pub fn verify_iid_binding(pubkey: &[u8; 32], claimed_iid: &[u8; 8]) -> Result<(), TrustError> {
    let derived = iid_from_pubkey(pubkey);
    if derived == *claimed_iid {
        Ok(())
    } else {
        Err(TrustError::DerivationMismatch {
            claimed_iid: *claimed_iid,
            derived_iid: derived,
        })
    }
}

/// Verify that a pubkey correctly derives to the claimed DODAGID (full 16-byte address).
///
/// Per spec section 8.4: "Nodes SHOULD verify root legitimacy by checking
/// that DODAGID equals AddrForKey(root_pubkey)."
///
/// This is the full 16-byte check (unlike `verify_iid_binding` which checks only 8 bytes).
/// The DODAGID is a native 0200::/8 address derived deterministically from the pubkey.
///
/// SECURITY: This binding ensures the root controls the private key for the advertised
/// DODAGID. An attacker cannot forge a DIO for a DODAGID they don't control.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_dodagid_binding(pubkey: &[u8; 32], claimed_dodagid: &[u8; 16]) -> bool {
    let derived = ygg_addr_from_pubkey(pubkey);
    // SECURITY: Constant-time comparison prevents timing attacks
    derived
        .iter()
        .zip(claimed_dodagid.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Check the U/L bit test for the derivation.
///
/// Returns (raw_sha512_byte0, final_iid_byte0, ul_bit_was_cleared).
pub fn ul_bit_test(pubkey: &[u8; 32]) -> (u8, u8, bool) {
    let hash = Sha512::digest(pubkey);
    let raw_byte0 = hash[0];
    let iid = iid_from_pubkey(pubkey);
    let final_byte0 = iid[0];
    // U/L bit is bit 1 (0x02). If it was set in raw, it should be cleared in final.
    let ul_bit_was_cleared = (raw_byte0 & 0x02) != 0 && (final_byte0 & 0x02) == 0;
    (raw_byte0, final_byte0, ul_bit_was_cleared)
}

// ─── Key Rotation ────────────────────────────────────────────────────────────

/// Build the key rotation message for signing.
///
/// Format: `LICHEN-KEY-ROTATION-v1 || 0x00 || old_pubkey || old_iid ||
/// new_pubkey || rotation_sequence_be64`.
pub fn build_rotation_message(
    old_pubkey: &[u8; 32],
    old_iid: &[u8; 8],
    new_pubkey: &[u8; 32],
    rotation_sequence: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(KEY_ROTATION_DOMAIN.len() + 1 + 32 + 8 + 32 + 8);
    msg.extend_from_slice(KEY_ROTATION_DOMAIN);
    msg.push(0);
    msg.extend_from_slice(old_pubkey);
    msg.extend_from_slice(old_iid);
    msg.extend_from_slice(new_pubkey);
    msg.extend_from_slice(&rotation_sequence.to_be_bytes());
    msg
}

/// Verify a key rotation signature.
///
/// The OLD key signs a message authorizing the NEW key.
/// The transcript binds both identities and the monotonic rotation sequence.
pub fn verify_key_rotation(
    old_pubkey: &[u8; 32],
    old_iid: &[u8; 8],
    new_pubkey: &[u8; 32],
    rotation_sequence: u64,
    signature: &[u8; 48],
) -> bool {
    let msg = build_rotation_message(old_pubkey, old_iid, new_pubkey, rotation_sequence);
    let pubkey = PublicKey::new(*old_pubkey);
    verify(&pubkey, &msg, signature)
}

/// Sign a key rotation message.
///
/// The OLD key signs authorization for the NEW key.
pub fn sign_key_rotation(
    old_privkey: &[u8; 32],
    old_pubkey: &[u8; 32],
    old_iid: &[u8; 8],
    new_pubkey: &[u8; 32],
    rotation_sequence: u64,
) -> [u8; 48] {
    let msg = build_rotation_message(old_pubkey, old_iid, new_pubkey, rotation_sequence);
    let privkey = PrivateKey::new(*old_privkey);
    let pubkey = PublicKey::new(*old_pubkey);
    sign(&privkey, &pubkey, &msg)
}

// ─── Open Federation Signature Verification ──────────────────────────────────

/// Verify a signed message from a gateway.
///
/// Used for open federation slot claims, handoff requests, etc.
pub fn verify_gateway_message(
    gateway_pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 48],
) -> bool {
    let pubkey = PublicKey::new(*gateway_pubkey);
    verify(&pubkey, message, signature)
}

/// Sign a message with gateway's private key.
///
/// Used for open federation slot claims, handoff requests, etc.
pub fn sign_gateway_message(
    gateway_privkey: &[u8; 32],
    gateway_pubkey: &[u8; 32],
    message: &[u8],
) -> [u8; 48] {
    let privkey = PrivateKey::new(*gateway_privkey);
    let pubkey = PublicKey::new(*gateway_pubkey);
    sign(&privkey, &pubkey, message)
}

// ─── Trust Store (TOFU) ──────────────────────────────────────────────────────

/// A pinned gateway entry in the trust store.
#[derive(Debug, Clone)]
pub struct PinnedGateway {
    /// The pinned Ed25519 public key.
    pub pubkey: [u8; 32],
    /// Trust level.
    pub trust_level: TrustLevel,
    /// When the key was first seen.
    pub first_seen: SystemTime,
    /// Last successful verification.
    pub last_verified: SystemTime,
    /// Number of successful verifications.
    pub verify_count: u64,
    /// Last accepted key-rotation sequence; zero means no rotation accepted.
    pub rotation_sequence: u64,
}

/// Trust store for TOFU key pinning.
///
/// Maps IID -> pinned gateway entry.
#[derive(Debug, Clone)]
pub struct TrustStore {
    entries: HashMap<[u8; 8], PinnedGateway>,
    max_entries: usize,
    generation: u64,
}

impl TrustStore {
    /// Iterate durable pinned identities for runtime security-owner restore.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 8], &PinnedGateway)> {
        self.entries.iter()
    }

    /// Install a public key explicitly authorized by daemon configuration.
    ///
    /// Configuration is an out-of-band trust anchor, so this uses the
    /// `BrProvisioned` level rather than manufacturing a TOFU proof. A key
    /// collision at the derived IID fails closed.
    pub fn provision_configured_peer(&mut self, pubkey: &[u8; 32]) -> Result<bool, TrustError> {
        let iid = iid_from_pubkey(pubkey);
        if let Some(existing) = self.entries.get(&iid) {
            if existing.pubkey != *pubkey {
                return Err(TrustError::KeyConflict {
                    pinned_pubkey: existing.pubkey,
                    presented_pubkey: *pubkey,
                });
            }
            if existing.trust_level >= TrustLevel::BrProvisioned {
                return Ok(false);
            }
            self.bump_generation()?;
            let entry = self
                .entries
                .get_mut(&iid)
                .expect("entry checked immediately above");
            entry.trust_level = TrustLevel::BrProvisioned;
            entry.last_verified = SystemTime::now();
            entry.verify_count = entry.verify_count.saturating_add(1);
            return Ok(true);
        }
        if self.entries.len() >= self.max_entries {
            return Err(TrustError::StoreFull {
                capacity: self.max_entries,
            });
        }
        self.bump_generation()?;
        let now = SystemTime::now();
        self.entries.insert(
            iid,
            PinnedGateway {
                pubkey: *pubkey,
                trust_level: TrustLevel::BrProvisioned,
                first_seen: now,
                last_verified: now,
                verify_count: 1,
                rotation_sequence: 0,
            },
        );
        Ok(true)
    }

    /// Create an explicitly ephemeral trust store.
    ///
    /// Production callers should use [`TrustStore::load`] so missing or corrupt
    /// durable state cannot silently become an empty TOFU store.
    pub fn new_ephemeral(max_entries: usize) -> Result<Self, TrustError> {
        validate_store_capacity(max_entries)?;
        Ok(Self {
            entries: HashMap::with_capacity(max_entries.min(64)),
            max_entries,
            generation: 1,
        })
    }

    /// Load and verify a durable trust store.
    ///
    /// The caller supplies a private sealing seed and a generation floor kept
    /// in independent monotonic storage. Missing, corrupt, forged, and rolled
    /// back stores all fail closed.
    pub fn load(
        path: &Path,
        sealing_seed: &[u8; 32],
        minimum_generation: u64,
        configured_capacity: usize,
    ) -> Result<Self, TrustError> {
        validate_store_capacity(configured_capacity)?;
        let mut file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                TrustError::MissingStore
            } else {
                TrustError::StorageIo(error.to_string())
            }
        })?;
        let max_len = trust_store_encoded_len(configured_capacity);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((max_len + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| TrustError::StorageIo(error.to_string()))?;
        if bytes.len() > max_len || bytes.len() < 8 + 2 + 8 + 4 + 4 + SIGNATURE_LEN {
            return Err(TrustError::CorruptStore);
        }

        let payload_len = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(TrustError::CorruptStore)?;
        let (payload, signature_bytes) = bytes.split_at(payload_len);
        let signature: &[u8; SIGNATURE_LEN] = signature_bytes
            .try_into()
            .map_err(|_| TrustError::CorruptStore)?;
        if !verify_store_seal(payload, signature, sealing_seed) {
            return Err(TrustError::IntegrityFailure);
        }

        let mut cursor = StoreCursor::new(payload);
        if cursor.take(8)? != TRUST_STORE_MAGIC {
            return Err(TrustError::CorruptStore);
        }
        let store_version = cursor.u16()?;
        if store_version != TRUST_STORE_VERSION && store_version != TRUST_STORE_VERSION_LEGACY {
            return Err(TrustError::CorruptStore);
        }
        let generation = cursor.u64()?;
        if generation < minimum_generation {
            return Err(TrustError::RollbackDetected {
                stored: generation,
                minimum: minimum_generation,
            });
        }
        let stored_capacity = cursor.u32()? as usize;
        if stored_capacity != configured_capacity {
            return Err(TrustError::CapacityMismatch {
                stored: stored_capacity,
                configured: configured_capacity,
            });
        }
        let count = cursor.u32()? as usize;
        if count > stored_capacity {
            return Err(TrustError::CorruptStore);
        }

        let mut entries = HashMap::with_capacity(count);
        for _ in 0..count {
            let iid: [u8; 8] = cursor.array()?;
            let pubkey: [u8; 32] = cursor.array()?;
            verify_iid_binding(&pubkey, &iid).map_err(|_| TrustError::CorruptStore)?;
            let trust_level = TrustLevel::from_u8(cursor.u8()?).ok_or(TrustError::CorruptStore)?;
            let first_seen = system_time_from_secs(cursor.u64()?)?;
            let last_verified = system_time_from_secs(cursor.u64()?)?;
            let verify_count = cursor.u64()?;
            let rotation_sequence = if store_version >= TRUST_STORE_VERSION {
                cursor.u64()?
            } else {
                0
            };
            if verify_count == 0 || entries.contains_key(&iid) {
                return Err(TrustError::CorruptStore);
            }
            entries.insert(
                iid,
                PinnedGateway {
                    pubkey,
                    trust_level,
                    first_seen,
                    last_verified,
                    verify_count,
                    rotation_sequence,
                },
            );
        }
        if !cursor.is_empty() {
            return Err(TrustError::CorruptStore);
        }

        Ok(Self {
            entries,
            max_entries: configured_capacity,
            generation,
        })
    }

    /// Atomically seal and persist the complete trust store.
    pub fn save_atomic(&self, path: &Path, sealing_seed: &[u8; 32]) -> Result<(), TrustError> {
        let payload = self.encode_payload()?;
        let signature = sign_store_payload(&payload, sealing_seed);
        let temp_path = temporary_store_path(path, self.generation)?;
        let write_result = (|| -> Result<(), TrustError> {
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            temp.write_all(&payload)
                .and_then(|_| temp.write_all(&signature))
                .and_then(|_| temp.sync_all())
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            fs::rename(&temp_path, path)
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }

    /// Persist the sealed store and its independent rollback floor.
    ///
    /// The store is committed first. A crash before the floor update leaves a
    /// newer store above the old minimum and is therefore safe on restart.
    pub fn save_atomic_with_floor(
        &self,
        path: &Path,
        floor_path: &Path,
        sealing_seed: &[u8; 32],
    ) -> Result<(), TrustError> {
        self.save_atomic(path, sealing_seed)?;
        let name = floor_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(TrustError::CorruptStore)?;
        let temporary = floor_path.with_file_name(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            self.generation
        ));
        let result = (|| -> Result<(), TrustError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            file.write_all(&self.generation.to_be_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            fs::rename(&temporary, floor_path)
                .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            if let Some(parent) = floor_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| TrustError::StorageIo(error.to_string()))?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    /// Verify and potentially pin a proof-bearing gateway identity.
    ///
    /// Returns the TOFU result indicating what action was taken.
    pub fn verify_tofu(
        &mut self,
        identity: &VerifiedGatewayIdentity,
    ) -> Result<TofuResult, TrustError> {
        if let Some(entry) = self.entries.get(identity.iid()) {
            if entry.pubkey == *identity.pubkey() {
                self.bump_generation()?;
                let entry = self
                    .entries
                    .get_mut(identity.iid())
                    .expect("entry checked immediately above");
                entry.last_verified = SystemTime::now();
                entry.verify_count = entry.verify_count.saturating_add(1);
                Ok(TofuResult::AcceptKnown)
            } else {
                Err(TrustError::KeyConflict {
                    pinned_pubkey: entry.pubkey,
                    presented_pubkey: *identity.pubkey(),
                })
            }
        } else {
            if self.entries.len() >= self.max_entries {
                return Err(TrustError::StoreFull {
                    capacity: self.max_entries,
                });
            }
            self.bump_generation()?;
            let now = SystemTime::now();
            self.entries.insert(
                *identity.iid(),
                PinnedGateway {
                    pubkey: *identity.pubkey(),
                    trust_level: TrustLevel::Tofu,
                    first_seen: now,
                    last_verified: now,
                    verify_count: 1,
                    rotation_sequence: 0,
                },
            );
            Ok(TofuResult::PinAndAccept)
        }
    }

    /// Process a key rotation request.
    ///
    /// The old key must sign the rotation message authorizing the new key.
    pub fn process_key_rotation(
        &mut self,
        old_iid: &[u8; 8],
        new_pubkey: &[u8; 32],
        rotation_sequence: u64,
        rotation_signature: &[u8; 48],
    ) -> Result<TofuResult, TrustError> {
        // Get the old pinned entry
        let old_entry = self
            .entries
            .get(old_iid)
            .ok_or(TrustError::UnknownGateway)?;
        let old_pubkey = old_entry.pubkey;
        let old_trust_level = old_entry.trust_level;
        let old_rotation_sequence = old_entry.rotation_sequence;

        if rotation_sequence == 0 || rotation_sequence <= old_rotation_sequence {
            return Err(TrustError::InvalidRotationSequence {
                current: old_rotation_sequence,
                presented: rotation_sequence,
            });
        }

        // Verify the rotation signature
        if !verify_key_rotation(
            &old_pubkey,
            old_iid,
            new_pubkey,
            rotation_sequence,
            rotation_signature,
        ) {
            return Err(TrustError::InvalidRotationSignature);
        }

        // Compute new IID
        let new_iid = iid_from_pubkey(new_pubkey);

        if let Some(existing) = self.entries.get(&new_iid) {
            if new_iid != *old_iid {
                return Err(TrustError::KeyConflict {
                    pinned_pubkey: existing.pubkey,
                    presented_pubkey: *new_pubkey,
                });
            }
        }

        // Remove old entry and add new one
        self.bump_generation()?;
        self.entries.remove(old_iid);
        let now = SystemTime::now();
        self.entries.insert(
            new_iid,
            PinnedGateway {
                pubkey: *new_pubkey,
                trust_level: old_trust_level, // Preserve trust level
                first_seen: now,
                last_verified: now,
                verify_count: 1,
                rotation_sequence,
            },
        );

        Ok(TofuResult::AcceptRotation {
            old_pubkey,
            new_pubkey: *new_pubkey,
        })
    }

    /// Get a pinned gateway entry by IID.
    pub fn get(&self, iid: &[u8; 8]) -> Option<&PinnedGateway> {
        self.entries.get(iid)
    }

    /// Check if an IID is in the trust store.
    pub fn contains(&self, iid: &[u8; 8]) -> bool {
        self.entries.contains_key(iid)
    }

    /// Upgrade trust level for a gateway.
    pub fn upgrade_trust(
        &mut self,
        iid: &[u8; 8],
        new_level: TrustLevel,
    ) -> Result<bool, TrustError> {
        if let Some(entry) = self.entries.get(iid) {
            if new_level > entry.trust_level {
                self.bump_generation()?;
                let entry = self
                    .entries
                    .get_mut(iid)
                    .expect("entry checked immediately above");
                entry.trust_level = new_level;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove a gateway from the trust store.
    pub fn remove(&mut self, iid: &[u8; 8]) -> Result<bool, TrustError> {
        if !self.entries.contains_key(iid) {
            return Ok(false);
        }
        self.bump_generation()?;
        Ok(self.entries.remove(iid).is_some())
    }

    /// List all pinned IIDs.
    pub fn list_iids(&self) -> Vec<[u8; 8]> {
        self.entries.keys().copied().collect()
    }

    /// Get the number of pinned gateways.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the trust store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Durable state generation for an independent rollback floor.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Configured hard capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    fn bump_generation(&mut self) -> Result<(), TrustError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(TrustError::GenerationExhausted)?;
        Ok(())
    }

    fn encode_payload(&self) -> Result<Vec<u8>, TrustError> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by_key(|(iid, _)| **iid);
        let mut bytes = Vec::with_capacity(trust_store_encoded_len(entries.len()));
        bytes.extend_from_slice(TRUST_STORE_MAGIC);
        bytes.extend_from_slice(&TRUST_STORE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.max_entries as u32).to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (iid, entry) in entries {
            bytes.extend_from_slice(iid);
            bytes.extend_from_slice(&entry.pubkey);
            bytes.push(entry.trust_level.as_u8());
            bytes.extend_from_slice(&system_time_secs(entry.first_seen)?.to_be_bytes());
            bytes.extend_from_slice(&system_time_secs(entry.last_verified)?.to_be_bytes());
            bytes.extend_from_slice(&entry.verify_count.to_be_bytes());
            bytes.extend_from_slice(&entry.rotation_sequence.to_be_bytes());
        }
        Ok(bytes)
    }
}

fn validate_store_capacity(capacity: usize) -> Result<(), TrustError> {
    if capacity == 0 || capacity > MAX_TRUSTED_GATEWAYS || capacity > u32::MAX as usize {
        Err(TrustError::InvalidCapacity)
    } else {
        Ok(())
    }
}

fn trust_store_encoded_len(entries: usize) -> usize {
    8 + 2 + 8 + 4 + 4 + entries.saturating_mul(8 + 32 + 1 + 8 + 8 + 8 + 8) + SIGNATURE_LEN
}

fn system_time_secs(time: SystemTime) -> Result<u64, TrustError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TrustError::CorruptStore)
}

fn system_time_from_secs(seconds: u64) -> Result<SystemTime, TrustError> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(TrustError::CorruptStore)
}

fn store_seal_transcript(payload: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(TRUST_STORE_MAC_DOMAIN.len() + payload.len());
    transcript.extend_from_slice(TRUST_STORE_MAC_DOMAIN);
    transcript.extend_from_slice(payload);
    transcript
}

fn sign_store_payload(payload: &[u8], sealing_seed: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    let (private, public) = schnorr48::derive_keypair(&Seed::new(*sealing_seed));
    sign(&private, &public, &store_seal_transcript(payload))
}

fn verify_store_seal(
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    sealing_seed: &[u8; 32],
) -> bool {
    let (_, public) = schnorr48::derive_keypair(&Seed::new(*sealing_seed));
    verify(&public, &store_seal_transcript(payload), signature)
}

fn temporary_store_path(path: &Path, generation: u64) -> Result<PathBuf, TrustError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| TrustError::StorageIo("trust-store path has no UTF-8 file name".into()))?;
    Ok(path.with_file_name(format!(".{name}.tmp-{}-{generation}", std::process::id())))
}

struct StoreCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StoreCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TrustError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(TrustError::CorruptStore)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(TrustError::CorruptStore)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TrustError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TrustError::CorruptStore)
    }

    fn u8(&mut self) -> Result<u8, TrustError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TrustError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, TrustError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, TrustError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

// ─── PSK Federation (Closed) ─────────────────────────────────────────────────

/// PSK federation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PskError {
    /// PSK too short (minimum 16 bytes).
    PskTooShort,
    /// Sender and recipient gateway IIDs are equal.
    EqualGatewayIds,
    /// Two full gateway IIDs map to the same constrained OSCORE ID.
    IdCollision,
    /// The collision registry reached its configured hard bound.
    IdRegistryFull,
    /// The collision registry lock was poisoned.
    RegistryUnavailable,
    /// ID context too long (max 8 bytes per spec).
    IdContextTooLong,
    /// OSCORE context creation failed.
    ContextCreationFailed,
}

impl std::fmt::Display for PskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PskTooShort => write!(f, "PSK too short (min 16 bytes)"),
            Self::EqualGatewayIds => write!(f, "sender and recipient gateway IIDs must differ"),
            Self::IdCollision => write!(f, "gateway OSCORE ID collision"),
            Self::IdRegistryFull => write!(f, "gateway OSCORE ID registry is full"),
            Self::RegistryUnavailable => write!(f, "gateway OSCORE ID registry unavailable"),
            Self::IdContextTooLong => write!(f, "ID context too long (max 8 bytes)"),
            Self::ContextCreationFailed => write!(f, "OSCORE context creation failed"),
        }
    }
}

impl std::error::Error for PskError {}

/// PSK-based closed federation manager.
///
/// Manages OSCORE contexts for gateway coordination using a pre-shared key.
/// Per GCP-3.1, all gateways in a closed federation share the same PSK.
///
/// # Example
///
/// ```ignore
/// use lichen_gateway::trust::PskFederation;
///
/// // Create federation with 32-byte PSK
/// let psk = b"lichen-federation-test-psk-32by";
/// let salt = hex::decode("9e7ca92223786340").unwrap();
/// let federation = PskFederation::new(psk, Some(&salt), None)?;
///
/// // Derive OSCORE context for gateway pair
/// let ctx = federation.derive_context(&[0x00; 8], &[0x01; 8])?;
/// ```
pub struct PskFederation {
    /// Pre-shared key (master secret).
    psk: Zeroizing<Vec<u8>>,
    /// Optional master salt for key derivation.
    master_salt: Option<Zeroizing<Vec<u8>>>,
    /// Optional ID context for federation isolation.
    id_context: Option<Vec<u8>>,
    /// Collision registry for the seven-byte OSCORE nonce IDs.
    oscore_ids: Mutex<HashMap<[u8; OSCORE_GATEWAY_ID_LEN], [u8; 8]>>,
    /// Non-secret comparison handle derived from all federation keying inputs.
    federation_id: [u8; 32],
}

impl PskFederation {
    /// Create a new PSK federation.
    ///
    /// # Arguments
    ///
    /// * `psk` - Pre-shared key (minimum 16 bytes)
    /// * `master_salt` - Optional salt for HKDF (recommended)
    /// * `id_context` - Optional context ID for federation isolation
    ///
    /// # Security
    ///
    /// The PSK should be a cryptographically random 16+ byte value.
    /// Using a predictable PSK compromises all federation traffic.
    pub fn new(
        psk: &[u8],
        master_salt: Option<&[u8]>,
        id_context: Option<&[u8]>,
    ) -> Result<Self, PskError> {
        if psk.len() < KEY_LEN {
            return Err(PskError::PskTooShort);
        }
        if let Some(ctx) = id_context {
            if ctx.len() > 8 {
                return Err(PskError::IdContextTooLong);
            }
        }

        let federation_id = federation_identifier(psk, master_salt, id_context);
        Ok(Self {
            psk: Zeroizing::new(psk.to_vec()),
            master_salt: master_salt.map(|s| Zeroizing::new(s.to_vec())),
            id_context: id_context.map(|c| c.to_vec()),
            oscore_ids: Mutex::new(HashMap::new()),
            federation_id,
        })
    }

    /// Derive an OSCORE context for a gateway pair.
    ///
    /// # Arguments
    ///
    /// * `sender_id` - This gateway's complete 8-byte IID
    /// * `recipient_id` - Peer gateway's complete 8-byte IID
    ///
    /// # Returns
    ///
    /// OSCORE context ready for protecting CoAP messages.
    ///
    /// # Security
    ///
    /// Each gateway pair should use unique sender/recipient IDs.
    /// The sender_id and recipient_id must be swapped on the peer.
    pub fn derive_context(
        &self,
        sender_id: &[u8; 8],
        recipient_id: &[u8; 8],
    ) -> Result<OscoreContext, PskError> {
        if sender_id == recipient_id {
            return Err(PskError::EqualGatewayIds);
        }
        let (sender_oscore_id, recipient_oscore_id) =
            self.register_gateway_pair(sender_id, recipient_id)?;

        // Compress the complete configured PSK into the fixed OSCORE master
        // secret width. Truncation would make distinct federation PSKs with a
        // common prefix produce identical traffic keys.
        let master_secret: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(psk_master_secret(&self.psk));

        // Convert to fixed-size array for master_salt if present
        let salt_ref: Option<&[u8]> = self.master_salt.as_deref().map(Vec::as_slice);
        let id_ctx_ref: Option<&[u8]> = self.id_context.as_deref();

        OscoreContext::new(
            &master_secret,
            salt_ref,
            id_ctx_ref,
            &sender_oscore_id,
            &recipient_oscore_id,
        )
        .map_err(|_| PskError::ContextCreationFailed)
    }

    /// Get the master salt if set.
    pub fn master_salt(&self) -> Option<&[u8]> {
        self.master_salt.as_deref().map(Vec::as_slice)
    }

    /// Get the ID context if set.
    pub fn id_context(&self) -> Option<&[u8]> {
        self.id_context.as_deref()
    }

    /// Check if two federations would produce isolated (different) keys.
    ///
    /// Federations are isolated if they have different:
    /// - PSK values, OR
    /// - master salt values, OR
    /// - ID context values
    pub fn is_isolated_from(&self, other: &PskFederation) -> bool {
        !constant_time_bytes_equal(&self.federation_id, &other.federation_id)
    }

    fn register_gateway_pair(
        &self,
        sender_iid: &[u8; 8],
        recipient_iid: &[u8; 8],
    ) -> Result<([u8; OSCORE_GATEWAY_ID_LEN], [u8; OSCORE_GATEWAY_ID_LEN]), PskError> {
        let sender_id: [u8; OSCORE_GATEWAY_ID_LEN] = sender_iid[..OSCORE_GATEWAY_ID_LEN]
            .try_into()
            .expect("fixed slice length");
        let recipient_id: [u8; OSCORE_GATEWAY_ID_LEN] = recipient_iid[..OSCORE_GATEWAY_ID_LEN]
            .try_into()
            .expect("fixed slice length");
        if sender_id == recipient_id {
            return Err(PskError::IdCollision);
        }
        let mut registry = self
            .oscore_ids
            .lock()
            .map_err(|_| PskError::RegistryUnavailable)?;
        let pairs = [(sender_id, *sender_iid), (recipient_id, *recipient_iid)];
        for (id, iid) in pairs {
            if let Some(existing) = registry.get(&id) {
                if existing != &iid {
                    return Err(PskError::IdCollision);
                }
            }
        }
        let new_entries = pairs
            .iter()
            .filter(|(id, _)| !registry.contains_key(id))
            .count();
        if registry.len().saturating_add(new_entries) > MAX_TRUSTED_GATEWAYS {
            return Err(PskError::IdRegistryFull);
        }
        registry.extend(pairs);
        Ok((sender_id, recipient_id))
    }
}

fn psk_master_secret(psk: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(b"LICHEN-GCP-PSK-MASTER-v1\0");
    hasher.update((psk.len() as u64).to_be_bytes());
    hasher.update(psk);
    hasher.finalize()[..KEY_LEN]
        .try_into()
        .expect("SHA-512 output has enough master-secret bytes")
}

fn federation_identifier(
    psk: &[u8],
    master_salt: Option<&[u8]>,
    id_context: Option<&[u8]>,
) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"LICHEN-GCP-PSK-FEDERATION-v1");
    hasher.update((psk.len() as u64).to_be_bytes());
    hasher.update(psk);
    let salt = master_salt.unwrap_or_default();
    hasher.update((salt.len() as u64).to_be_bytes());
    hasher.update(salt);
    let context = id_context.unwrap_or_default();
    hasher.update((context.len() as u64).to_be_bytes());
    hasher.update(context);
    hasher.finalize()[..32]
        .try_into()
        .expect("SHA-512 output has at least 32 bytes")
}

fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Derive gateway IID from sender_id for OSCORE context.
///
/// Per GCP-6.3, gateways use their 8-byte IID (from Ed25519 key) as
/// the sender ID. Truncation is forbidden because it permits collisions.
///
/// # Arguments
///
/// * `iid` - Gateway's 8-byte Interface Identifier
///
/// Complete IID suitable for an OSCORE sender/recipient ID.
pub fn iid_to_sender_id(iid: &[u8; 8]) -> [u8; 8] {
    *iid
}

/// Create sender/recipient IDs from two gateway IIDs.
///
/// Per spec, each gateway derives its own context with:
/// - sender_id = complete own IID
/// - recipient_id = complete peer IID
///
/// The peer swaps these values in their context.
pub fn derive_gateway_ids(
    own_iid: &[u8; 8],
    peer_iid: &[u8; 8],
) -> Result<([u8; 8], [u8; 8]), PskError> {
    if own_iid == peer_iid {
        return Err(PskError::EqualGatewayIds);
    }
    Ok((iid_to_sender_id(own_iid), iid_to_sender_id(peer_iid)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use schnorr48::derive_keypair;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static TEST_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn presentation<'a>(
        pubkey: &'a [u8; 32],
        iid: &'a [u8; 8],
        challenge: &'a [u8; 32],
        signature: &'a [u8; SIGNATURE_LEN],
    ) -> GatewayIdentityPresentation<'a> {
        GatewayIdentityPresentation {
            pubkey,
            claimed_iid: iid,
            challenge,
            signature,
        }
    }

    fn verified_identity(seed: [u8; 32], issuer_secret: [u8; 32]) -> VerifiedGatewayIdentity {
        let (private, public) = derive_keypair(&Seed::new(seed));
        let pubkey = *public.as_bytes();
        let iid = iid_from_pubkey(&pubkey);
        let session = [0x51; 32];
        let mut issuer = GatewayChallengeIssuer::new(issuer_secret, 1).unwrap();
        let authority = issuer.issue(iid, session, 10, 100).unwrap();
        let challenge = *authority.challenge();
        let transcript = build_identity_proof_transcript(&iid, &challenge);
        let signature = sign(&private, &public, &transcript);
        issuer
            .verify_identity(
                authority,
                &session,
                11,
                presentation(&pubkey, &iid, &challenge, &signature),
            )
            .unwrap()
    }

    fn test_store_path(label: &str) -> PathBuf {
        let sequence = TEST_PATH_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        std::env::temp_dir().join(format!(
            "lichen-gateway-trust-{label}-{}-{sequence}.bin",
            std::process::id()
        ))
    }

    fn duplicate_challenge_for_replay(
        authority: &GatewayIdentityChallenge,
    ) -> GatewayIdentityChallenge {
        GatewayIdentityChallenge {
            authority_id: authority.authority_id,
            token: authority.token,
            record: authority.record.clone(),
        }
    }

    #[test]
    fn identity_proof_transcript_matches_fixed_literal_oracle() {
        let iid = hex!("0102030405060708");
        let challenge = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected = hex!(
            "4c494348454e2d4743502d4944454e544954592d50524f4f462d7631"
            "0102030405060708"
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let public_key = hex!("884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b");
        let signature = hex!(
            "60303a8b9a549f71bd07e31784dd87baad12041e0eb7015a407c609e455c4128"
            "65c00145f88b98b8213f3918323ad204"
        );

        let actual = build_identity_proof_transcript(&iid, &challenge);
        assert_eq!(actual.as_slice(), expected);
        assert!(verify_gateway_message(&public_key, &expected, &signature));
    }

    #[test]
    fn challenge_authority_is_peer_session_bound_expiring_and_one_use() {
        let (private, public) = derive_keypair(&Seed::new([0x31; 32]));
        let pubkey = *public.as_bytes();
        let iid = iid_from_pubkey(&pubkey);
        let session = [0x32; 32];
        let mut issuer = GatewayChallengeIssuer::new([0x33; 32], 4).unwrap();

        let authority = issuer.issue(iid, session, 100, 50).unwrap();
        assert_eq!(authority.peer_iid(), &iid);
        assert_eq!(authority.session_id(), &session);
        let challenge = *authority.challenge();
        let signature = sign(
            &private,
            &public,
            &build_identity_proof_transcript(&iid, &challenge),
        );
        let replay = duplicate_challenge_for_replay(&authority);
        let verified = issuer
            .verify_identity(
                authority,
                &session,
                101,
                presentation(&pubkey, &iid, &challenge, &signature),
            )
            .unwrap();
        assert_eq!(verified.pubkey(), &pubkey);
        assert!(matches!(
            issuer.verify_identity(
                replay,
                &session,
                102,
                presentation(&pubkey, &iid, &challenge, &signature)
            ),
            Err(TrustError::InvalidChallenge)
        ));

        let expiring = issuer.issue(iid, session, 200, 5).unwrap();
        let expiring_challenge = *expiring.challenge();
        let expiring_signature = sign(
            &private,
            &public,
            &build_identity_proof_transcript(&iid, &expiring_challenge),
        );
        assert!(matches!(
            issuer.verify_identity(
                expiring,
                &session,
                205,
                presentation(&pubkey, &iid, &expiring_challenge, &expiring_signature),
            ),
            Err(TrustError::InvalidChallenge)
        ));

        let cross_session = issuer.issue(iid, session, 300, 50).unwrap();
        let cross_challenge = *cross_session.challenge();
        let cross_signature = sign(
            &private,
            &public,
            &build_identity_proof_transcript(&iid, &cross_challenge),
        );
        assert!(matches!(
            issuer.verify_identity(
                cross_session,
                &[0x34; 32],
                301,
                presentation(&pubkey, &iid, &cross_challenge, &cross_signature),
            ),
            Err(TrustError::InvalidChallenge)
        ));
    }

    #[test]
    fn challenge_authorities_cannot_cross_issuers_or_exceed_capacity() {
        let iid = [0x41; 8];
        let session = [0x42; 32];
        let mut first = GatewayChallengeIssuer::new([0x43; 32], 1).unwrap();
        let mut second = GatewayChallengeIssuer::new([0x44; 32], 1).unwrap();
        let foreign = first.issue(iid, session, 10, 100).unwrap();
        assert!(matches!(
            second.verify_identity(
                foreign,
                &session,
                11,
                presentation(&[0; 32], &iid, &[0; 32], &[0; SIGNATURE_LEN]),
            ),
            Err(TrustError::InvalidChallenge)
        ));
        let _held = second.issue(iid, session, 12, 100).unwrap();
        assert!(matches!(
            second.issue([0x45; 8], session, 13, 100),
            Err(TrustError::StoreFull { capacity: 1 })
        ));
    }

    // ── Trust Level Ordering (test vector: trust_level_ordering) ─────────────

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Tofu < TrustLevel::BrProvisioned);
        assert!(TrustLevel::BrProvisioned < TrustLevel::Dane);
        assert!(TrustLevel::Dane < TrustLevel::Pkix);

        assert_eq!(TrustLevel::Tofu.as_u8(), 1);
        assert_eq!(TrustLevel::BrProvisioned.as_u8(), 2);
        assert_eq!(TrustLevel::Dane.as_u8(), 3);
        assert_eq!(TrustLevel::Pkix.as_u8(), 4);
    }

    // ── Key Derivation (test vectors: derivation_*) ──────────────────────────

    #[test]
    fn derivation_zero() {
        // Test vector: derivation_zero
        let seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let (_, pubkey) = derive_keypair(&Seed::new(seed));
        let expected_pubkey: [u8; 32] =
            hex!("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey(&expected_pubkey);
        let expected_iid: [u8; 8] = hex!("7dd5cfc679ab6342");
        assert_eq!(iid, expected_iid);

        let ygg_addr = ygg_addr_from_pubkey(&expected_pubkey);
        let expected_ygg: [u8; 16] = hex!("027dd5cfc679ab637dd5cfc679ab6342");
        assert_eq!(ygg_addr, expected_ygg);
    }

    #[test]
    fn derivation_alice() {
        // Test vector: derivation_alice
        let seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let (_, pubkey) = derive_keypair(&Seed::new(seed));
        let expected_pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey(&expected_pubkey);
        let expected_iid: [u8; 8] = hex!("fd6b265c8585369b");
        assert_eq!(iid, expected_iid);

        let ygg_addr = ygg_addr_from_pubkey(&expected_pubkey);
        let expected_ygg: [u8; 16] = hex!("02fd6b265c858536fd6b265c8585369b");
        assert_eq!(ygg_addr, expected_ygg);
    }

    #[test]
    fn derivation_bob() {
        // Test vector: derivation_bob
        let seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000002");
        let (_, pubkey) = derive_keypair(&Seed::new(seed));
        let expected_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let iid = iid_from_pubkey(&expected_pubkey);
        let expected_iid: [u8; 8] = hex!("888bcf64cfefa304");
        assert_eq!(iid, expected_iid);

        let ygg_addr = ygg_addr_from_pubkey(&expected_pubkey);
        let expected_ygg: [u8; 16] = hex!("02888bcf64cfefa3888bcf64cfefa304");
        assert_eq!(ygg_addr, expected_ygg);
    }

    #[test]
    fn derivation_all_ff_ul_bit() {
        // Test vector: derivation_all_ff (tests U/L bit clearing)
        let seed: [u8; 32] =
            hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let (_, pubkey) = derive_keypair(&Seed::new(seed));
        let expected_pubkey: [u8; 32] =
            hex!("76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5");
        assert_eq!(*pubkey.as_bytes(), expected_pubkey);

        let (raw_byte0, final_byte0, ul_cleared) = ul_bit_test(&expected_pubkey);
        assert_eq!(raw_byte0, 0xf7, "raw SHA512 byte 0");
        assert_eq!(final_byte0, 0xf5, "final IID byte 0");
        assert!(ul_cleared, "U/L bit should be cleared");

        let iid = iid_from_pubkey(&expected_pubkey);
        let expected_iid: [u8; 8] = hex!("f57a7baa1226b50c");
        assert_eq!(iid, expected_iid);
    }

    // ── DODAGID Binding Verification (spec 8.4) ──────────────────────────────

    #[test]
    fn dodagid_binding_valid() {
        // Test vector: verify_dodagid_binding with valid pubkey/DODAGID pair
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let dodagid: [u8; 16] = hex!("02fd6b265c858536fd6b265c8585369b");

        assert!(verify_dodagid_binding(&pubkey, &dodagid));
    }

    #[test]
    fn dodagid_binding_mismatch() {
        // Test vector: verify_dodagid_binding rejects mismatched DODAGID
        // Attacker uses their pubkey but claims victim's DODAGID
        let attacker_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let victim_dodagid: [u8; 16] = hex!("02fd6b265c858536fd6b265c8585369b"); // Alice's DODAGID

        assert!(!verify_dodagid_binding(&attacker_pubkey, &victim_dodagid));
    }

    #[test]
    fn dodagid_binding_wrong_prefix() {
        // Test vector: verify_dodagid_binding rejects wrong prefix byte
        // Valid IID but wrong Yggdrasil prefix
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        // Change prefix from 0x02 to 0x03
        let wrong_prefix: [u8; 16] = hex!("03fd6b265c858536fd6b265c8585369b");

        assert!(!verify_dodagid_binding(&pubkey, &wrong_prefix));
    }

    #[test]
    fn dodagid_binding_all_zeros() {
        // Test vector: all-zeros DODAGID should not match any valid pubkey
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let zeros: [u8; 16] = [0u8; 16];

        assert!(!verify_dodagid_binding(&pubkey, &zeros));
    }

    // ── TOFU Verification (test vectors: tofu_*) ─────────────────────────────

    #[test]
    fn tofu_valid_first_contact() {
        let identity = verified_identity([1; 32], [7; 32]);
        let claimed_iid = *identity.iid();
        let mut store = TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS).unwrap();
        let result = store.verify_tofu(&identity).unwrap();
        assert_eq!(result, TofuResult::PinAndAccept);
        assert!(store.contains(&claimed_iid));
    }

    #[test]
    fn tofu_derivation_mismatch_attack() {
        // Test vector: tofu_derivation_mismatch_attack
        // Attacker claims victim's IID with different pubkey
        let attacker_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let claimed_iid: [u8; 8] = hex!("fd6b265c8585369b"); // Alice's IID, not Bob's

        let challenge = [9; 32];
        let result = VerifiedGatewayIdentity::verify(
            &attacker_pubkey,
            &claimed_iid,
            &challenge,
            &challenge,
            &[0; SIGNATURE_LEN],
        );
        assert!(matches!(result, Err(TrustError::DerivationMismatch { .. })));
    }

    #[test]
    fn tofu_key_mismatch_detection() {
        // Test vector: tofu_key_mismatch_detection
        let bob_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let alice_iid: [u8; 8] = hex!("fd6b265c8585369b");

        let alice_seed = [1; 32];
        let identity = verified_identity(alice_seed, [5; 32]);
        let mut store = TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS).unwrap();
        let result = store.verify_tofu(&identity).unwrap();
        assert_eq!(result, TofuResult::PinAndAccept);

        // Bob tries to claim Alice's IID (derivation fails first)
        let challenge = [8; 32];
        let result = VerifiedGatewayIdentity::verify(
            &bob_pubkey,
            &alice_iid,
            &challenge,
            &challenge,
            &[0; SIGNATURE_LEN],
        );
        assert!(matches!(result, Err(TrustError::DerivationMismatch { .. })));
    }

    #[test]
    fn tofu_rejects_public_key_without_fresh_proof() {
        let seed = Seed::new([11; 32]);
        let (_, public) = derive_keypair(&seed);
        let pubkey = *public.as_bytes();
        let iid = iid_from_pubkey(&pubkey);
        let challenge = [4; 32];

        assert!(matches!(
            VerifiedGatewayIdentity::verify(
                &pubkey,
                &iid,
                &challenge,
                &challenge,
                &[0; SIGNATURE_LEN]
            ),
            Err(TrustError::InvalidSignature)
        ));
        assert!(matches!(
            VerifiedGatewayIdentity::verify(
                &pubkey,
                &iid,
                &[3; 32],
                &challenge,
                &[0; SIGNATURE_LEN]
            ),
            Err(TrustError::InvalidChallenge)
        ));
        let store = TrustStore::new_ephemeral(1).unwrap();
        assert!(store.is_empty());
    }

    // ── Key Rotation (test vectors: key_rotation_*) ──────────────────────────

    #[test]
    fn key_rotation_valid_signature() {
        // Test vector: key_rotation_valid_signature
        let old_seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let (old_private, derived_old_public) = derive_keypair(&Seed::new(old_seed));
        let old_pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        assert_eq!(derived_old_public.as_bytes(), &old_pubkey);
        let old_iid: [u8; 8] = hex!("fd6b265c8585369b");
        let new_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let rotation_sequence = 1;

        // Verify the rotation message format
        let msg = build_rotation_message(&old_pubkey, &old_iid, &new_pubkey, rotation_sequence);
        let expected_msg: Vec<u8> = hex!(
            "4c494348454e2d4b45592d524f544154494f4e2d7631004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29fd6b265c8585369b7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe26740000000000000001"
        )
        .to_vec();
        assert_eq!(msg, expected_msg);

        // Verify signature
        let signature = sign_key_rotation(
            old_private.as_bytes(),
            &old_pubkey,
            &old_iid,
            &new_pubkey,
            rotation_sequence,
        );
        let expected_signature: [u8; 48] = hex!(
            "9fff678a30a746114e67a4ce444cbbf883db290dce9c55c74801c03ac1993f2cd1681a17a27475f43feafe465223ca0d"
        );
        assert_eq!(signature, expected_signature);
        assert!(verify_key_rotation(
            &old_pubkey,
            &old_iid,
            &new_pubkey,
            rotation_sequence,
            &signature
        ));
    }

    #[test]
    fn key_rotation_invalid_signature() {
        // Test vector: key_rotation_invalid_signature
        // Signature from Charlie, not Alice
        let old_pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let old_iid: [u8; 8] = hex!("fd6b265c8585369b");
        let new_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let charlie_seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let (charlie_private, charlie_public) = derive_keypair(&Seed::new(charlie_seed));
        let transcript = build_rotation_message(&old_pubkey, &old_iid, &new_pubkey, 1);
        let signature = sign(&charlie_private, &charlie_public, &transcript);
        let expected_signature: [u8; 48] = hex!(
            "7b676951cc6de2c0519255696606e063d1a3c3177221dd25cdf630e99386f171806a99b249462c31d1f150529a336a0b"
        );
        assert_eq!(signature, expected_signature);

        assert!(!verify_key_rotation(
            &old_pubkey,
            &old_iid,
            &new_pubkey,
            1,
            &signature
        ));
    }

    // ── Open Federation Signatures (test vectors: open_federation_*) ─────────

    #[test]
    fn open_federation_slot_claim_valid() {
        // Test vector: open_federation_slot_claim_valid
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let message: Vec<u8> =
            hex!("534c4f545f434c41494d3a30313a676174657761795f6969643afd6b265c8585369b").to_vec();
        let signature: [u8; 48] = hex!(
            "45a4b53c65e11c450493d699f84c8e7585cfc4bafec86149d830b6eec7ba8eedeca2b33edcdcd7845a29e76e24844608"
        );

        assert!(verify_gateway_message(&pubkey, &message, &signature));
    }

    #[test]
    fn open_federation_tampered_message() {
        // Test vector: open_federation_tampered_message
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let tampered: Vec<u8> =
            hex!("534c4f545f434c41494d3a30323a676174657761795f6969643afd6b265c8585369b").to_vec();
        let signature: [u8; 48] = hex!(
            "45a4b53c65e11c450493d699f84c8e7585cfc4bafec86149d830b6eec7ba8eedeca2b33edcdcd7845a29e76e24844608"
        );

        assert!(!verify_gateway_message(&pubkey, &tampered, &signature));
    }

    // ── Binding Invariants (test vectors: binding_invariant_*) ───────────────

    #[test]
    fn binding_invariant_alice() {
        let pubkey: [u8; 32] =
            hex!("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
        let ygg_addr = ygg_addr_from_pubkey(&pubkey);
        let iid = iid_from_pubkey(&pubkey);

        // ygg_addr[8:16] == IID
        assert_eq!(&ygg_addr[8..16], &iid);
    }

    #[test]
    fn binding_invariant_bob() {
        let pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");
        let ygg_addr = ygg_addr_from_pubkey(&pubkey);
        let iid = iid_from_pubkey(&pubkey);

        // ygg_addr[8:16] == IID
        assert_eq!(&ygg_addr[8..16], &iid);
    }

    // ── Trust Store Operations ───────────────────────────────────────────────

    #[test]
    fn trust_store_upgrade() {
        let identity = verified_identity([1; 32], [12; 32]);
        let iid = *identity.iid();
        let mut store = TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS).unwrap();
        store.verify_tofu(&identity).unwrap();

        assert_eq!(store.get(&iid).unwrap().trust_level, TrustLevel::Tofu);

        // Upgrade to BR_PROVISIONED
        assert!(store
            .upgrade_trust(&iid, TrustLevel::BrProvisioned)
            .unwrap());
        assert_eq!(
            store.get(&iid).unwrap().trust_level,
            TrustLevel::BrProvisioned
        );

        // Cannot downgrade
        assert!(!store.upgrade_trust(&iid, TrustLevel::Tofu).unwrap());
        assert_eq!(
            store.get(&iid).unwrap().trust_level,
            TrustLevel::BrProvisioned
        );
    }

    #[test]
    fn trust_store_key_rotation() {
        // Use Alice's seed to get the correct private key
        let alice_seed: [u8; 32] =
            hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let (alice_privkey, alice_pubkey) = derive_keypair(&Seed::new(alice_seed));
        let alice_pubkey_bytes: [u8; 32] = *alice_pubkey.as_bytes();
        let alice_iid = iid_from_pubkey(&alice_pubkey_bytes);

        let bob_pubkey: [u8; 32] =
            hex!("7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674");

        let mut store = TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS).unwrap();

        // Pin Alice
        let challenge = [13; 32];
        let transcript = build_identity_proof_transcript(&alice_iid, &challenge);
        let identity_signature = sign(&alice_privkey, &alice_pubkey, &transcript);
        let identity = VerifiedGatewayIdentity::verify(
            &alice_pubkey_bytes,
            &alice_iid,
            &challenge,
            &challenge,
            &identity_signature,
        )
        .unwrap();
        store.verify_tofu(&identity).unwrap();

        // Create rotation signature
        let sig = sign_key_rotation(
            alice_privkey.as_bytes(),
            &alice_pubkey_bytes,
            &alice_iid,
            &bob_pubkey,
            1,
        );

        // Process rotation
        let result = store.process_key_rotation(&alice_iid, &bob_pubkey, 1, &sig);
        assert!(matches!(result, Ok(TofuResult::AcceptRotation { .. })));

        // Alice's IID should be removed
        assert!(!store.contains(&alice_iid));

        // Bob's IID should be added
        let bob_iid = iid_from_pubkey(&bob_pubkey);
        assert!(store.contains(&bob_iid));
        assert_eq!(store.get(&bob_iid).unwrap().pubkey, bob_pubkey);
        assert_eq!(store.get(&bob_iid).unwrap().rotation_sequence, 1);

        let generation = store.generation();
        assert!(matches!(
            store.process_key_rotation(&bob_iid, &alice_pubkey_bytes, 1, &sig),
            Err(TrustError::InvalidRotationSequence {
                current: 1,
                presented: 1
            })
        ));
        assert_eq!(store.generation(), generation);
        assert!(store.contains(&bob_iid));
    }

    #[test]
    fn trust_store_rotation_sequence_survives_restart_and_blocks_replay() {
        let path = test_store_path("rotation-sequence");
        let sealing_seed = [0x72; 32];
        let alice_seed = Seed::new(hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let bob_seed = Seed::new(hex!(
            "0000000000000000000000000000000000000000000000000000000000000002"
        ));
        let charlie_seed = Seed::new(hex!(
            "0000000000000000000000000000000000000000000000000000000000000003"
        ));
        let (alice_private, alice_public) = derive_keypair(&alice_seed);
        let (bob_private, bob_public) = derive_keypair(&bob_seed);
        let (_, charlie_public) = derive_keypair(&charlie_seed);
        let alice_pubkey = *alice_public.as_bytes();
        let bob_pubkey = *bob_public.as_bytes();
        let charlie_pubkey = *charlie_public.as_bytes();
        let alice_iid = iid_from_pubkey(&alice_pubkey);
        let bob_iid = iid_from_pubkey(&bob_pubkey);

        let identity = verified_identity(*alice_seed.as_bytes(), [0x39; 32]);
        let mut store = TrustStore::new_ephemeral(4).unwrap();
        store.verify_tofu(&identity).unwrap();
        let first_signature = sign_key_rotation(
            alice_private.as_bytes(),
            &alice_pubkey,
            &alice_iid,
            &bob_pubkey,
            7,
        );
        store
            .process_key_rotation(&alice_iid, &bob_pubkey, 7, &first_signature)
            .unwrap();
        store.save_atomic(&path, &sealing_seed).unwrap();

        let mut loaded = TrustStore::load(&path, &sealing_seed, store.generation(), 4).unwrap();
        assert_eq!(loaded.get(&bob_iid).unwrap().rotation_sequence, 7);
        let replay = sign_key_rotation(
            bob_private.as_bytes(),
            &bob_pubkey,
            &bob_iid,
            &charlie_pubkey,
            7,
        );
        assert!(matches!(
            loaded.process_key_rotation(&bob_iid, &charlie_pubkey, 7, &replay),
            Err(TrustError::InvalidRotationSequence {
                current: 7,
                presented: 7
            })
        ));
        assert!(loaded.contains(&bob_iid));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trust_store_capacity_fails_closed_without_eviction() {
        let first = verified_identity([21; 32], [1; 32]);
        let second = verified_identity([22; 32], [2; 32]);
        let mut store = TrustStore::new_ephemeral(1).unwrap();
        store.verify_tofu(&first).unwrap();

        assert!(matches!(
            store.verify_tofu(&second),
            Err(TrustError::StoreFull { capacity: 1 })
        ));
        assert!(store.contains(first.iid()));
        assert!(!store.contains(second.iid()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn trust_store_restart_round_trip_and_rollback_floor() {
        let path = test_store_path("restart");
        let sealing_seed = [0x51; 32];
        let identity = verified_identity([23; 32], [3; 32]);
        let mut store = TrustStore::new_ephemeral(4).unwrap();
        store.verify_tofu(&identity).unwrap();
        store
            .upgrade_trust(identity.iid(), TrustLevel::Dane)
            .unwrap();
        let generation = store.generation();
        store.save_atomic(&path, &sealing_seed).unwrap();

        let loaded = TrustStore::load(&path, &sealing_seed, generation, 4).unwrap();
        assert_eq!(loaded.generation(), generation);
        assert_eq!(
            loaded.get(identity.iid()).unwrap().trust_level,
            TrustLevel::Dane
        );
        assert!(matches!(
            TrustStore::load(&path, &sealing_seed, generation + 1, 4),
            Err(TrustError::RollbackDetected { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trust_store_rejects_corrupt_torn_and_wrongly_sealed_records() {
        let path = test_store_path("corrupt");
        let sealing_seed = [0x52; 32];
        let identity = verified_identity([24; 32], [4; 32]);
        let mut store = TrustStore::new_ephemeral(4).unwrap();
        store.verify_tofu(&identity).unwrap();
        store.save_atomic(&path, &sealing_seed).unwrap();

        assert!(matches!(
            TrustStore::load(&path, &[0x53; 32], 0, 4),
            Err(TrustError::IntegrityFailure)
        ));

        let mut bytes = fs::read(&path).unwrap();
        bytes[12] ^= 0x80;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            TrustStore::load(&path, &sealing_seed, 0, 4),
            Err(TrustError::IntegrityFailure)
        ));

        fs::write(&path, &bytes[..16]).unwrap();
        assert!(matches!(
            TrustStore::load(&path, &sealing_seed, 0, 4),
            Err(TrustError::CorruptStore)
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trust_store_missing_and_capacity_mismatch_fail_closed() {
        let path = test_store_path("missing");
        assert!(matches!(
            TrustStore::load(&path, &[0x54; 32], 0, 4),
            Err(TrustError::MissingStore)
        ));

        let store = TrustStore::new_ephemeral(4).unwrap();
        store.save_atomic(&path, &[0x54; 32]).unwrap();
        assert!(matches!(
            TrustStore::load(&path, &[0x54; 32], 0, 3),
            Err(TrustError::CapacityMismatch { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    // ── PSK Federation (Closed) Tests ────────────────────────────────────────

    /// Test vector: closed_federation_psk_derivation from gcp3_trust_models.json
    #[test]
    fn psk_context_derivation_test_vector() {
        // PSK: "lichen-federation-test-psk-32by"
        let psk = hex!("6c696368656e2d66656465726174696f6e2d746573742d70736b2d33326279");
        let master_salt = hex!("9e7ca92223786340");
        let sender_id = hex!("0011223344556677");
        let recipient_id = hex!("8899aabbccddeeff");

        let federation = PskFederation::new(&psk, Some(&master_salt), None).unwrap();

        let ctx = federation
            .derive_context(&sender_id, &recipient_id)
            .unwrap();

        // Verify context was created with correct IDs
        assert_eq!(ctx.sender_id(), &sender_id[..OSCORE_GATEWAY_ID_LEN]);
        assert_eq!(ctx.recipient_id(), &recipient_id[..OSCORE_GATEWAY_ID_LEN]);
    }

    /// Test vector: federation isolation with id_context
    #[test]
    fn psk_context_isolation_with_id_context() {
        let psk = hex!("6c696368656e2d66656465726174696f6e2d746573742d70736b2d33326279");
        let id_context = b"lichen";

        // Federation without id_context
        let fed1 = PskFederation::new(&psk, None, None).unwrap();

        // Federation with id_context
        let fed2 = PskFederation::new(&psk, None, Some(id_context)).unwrap();

        // Should be isolated (different contexts)
        assert!(fed1.is_isolated_from(&fed2));

        // Create contexts from both
        let sender = [0x10; 8];
        let recipient = [0x20; 8];
        let ctx1 = fed1.derive_context(&sender, &recipient).unwrap();
        let ctx2 = fed2.derive_context(&sender, &recipient).unwrap();

        // Both should have valid IDs
        assert_eq!(ctx1.sender_id(), &sender[..OSCORE_GATEWAY_ID_LEN]);
        assert_eq!(ctx2.sender_id(), &sender[..OSCORE_GATEWAY_ID_LEN]);
    }

    #[test]
    fn psk_suffix_changes_master_secret() {
        let mut first = [0x41; 24];
        let mut second = first;
        first[23] = 1;
        second[23] = 2;
        let sender = [0x10; 8];
        let recipient = [0x20; 8];
        let fed1 = PskFederation::new(&first, None, None).unwrap();
        let fed2 = PskFederation::new(&second, None, None).unwrap();
        assert!(fed1.is_isolated_from(&fed2));
        assert_ne!(
            fed1.derive_context(&sender, &recipient)
                .unwrap()
                .master_secret(),
            fed2.derive_context(&sender, &recipient)
                .unwrap()
                .master_secret()
        );
    }

    #[test]
    fn psk_too_short_rejected() {
        let short_psk = [0u8; 15]; // Only 15 bytes
        let result = PskFederation::new(&short_psk, None, None);
        assert!(matches!(result, Err(PskError::PskTooShort)));
    }

    #[test]
    fn equal_gateway_ids_rejected() {
        let psk = [0u8; 16];
        let federation = PskFederation::new(&psk, None, None).unwrap();
        let iid = [0x42; 8];
        let result = federation.derive_context(&iid, &iid);
        assert!(matches!(result, Err(PskError::EqualGatewayIds)));
    }

    #[test]
    fn truncated_oscore_id_collision_is_rejected() {
        let federation = PskFederation::new(&[0x55; 16], None, None).unwrap();
        let gateway_a = [1, 2, 3, 4, 5, 6, 7, 8];
        let gateway_b = [1, 2, 3, 4, 5, 6, 7, 9];
        let peer = [9, 8, 7, 6, 5, 4, 3, 2];
        federation.derive_context(&gateway_a, &peer).unwrap();
        assert!(matches!(
            federation.derive_context(&gateway_b, &peer),
            Err(PskError::IdCollision)
        ));
    }

    #[test]
    fn id_context_too_long_rejected() {
        let psk = [0u8; 16];
        let long_ctx = [0u8; 9];
        let result = PskFederation::new(&psk, None, Some(&long_ctx));
        assert!(matches!(result, Err(PskError::IdContextTooLong)));
    }

    #[test]
    fn iid_to_sender_id_uses_complete_iid() {
        let iid = hex!("fd6b265c8585369b");
        assert_eq!(iid_to_sender_id(&iid), iid);
    }

    #[test]
    fn derive_gateway_ids_symmetry() {
        let alice_iid = hex!("fd6b265c8585369b");
        let bob_iid = hex!("888bcf64cfefa304");

        let (alice_sender, alice_recipient) = derive_gateway_ids(&alice_iid, &bob_iid).unwrap();
        let (bob_sender, bob_recipient) = derive_gateway_ids(&bob_iid, &alice_iid).unwrap();

        // Alice's sender should be Bob's recipient
        assert_eq!(alice_sender, bob_recipient);
        // Bob's sender should be Alice's recipient
        assert_eq!(bob_sender, alice_recipient);
    }

    #[test]
    fn psk_federation_secret_storage_requires_drop() {
        let psk = hex!("0102030405060708090a0b0c0d0e0f10");
        let salt = hex!("9e7ca92223786340");
        let fed = PskFederation::new(&psk, Some(&salt), None).unwrap();
        assert!(std::mem::needs_drop::<PskFederation>());
        assert_eq!(fed.master_salt(), Some(salt.as_slice()));
    }

    /// Verify OSCORE context creation with PSK.
    #[test]
    fn psk_context_creation() {
        let psk = hex!("0102030405060708090a0b0c0d0e0f10");
        let federation = PskFederation::new(&psk, None, None).unwrap();

        // Create contexts for Alice and Bob
        let alice = [0x11; 8];
        let bob = [0x22; 8];
        let alice_ctx = federation.derive_context(&alice, &bob).unwrap();
        let bob_ctx = federation.derive_context(&bob, &alice).unwrap();

        // Alice's sender ID should be Bob's recipient ID
        assert_eq!(alice_ctx.sender_id(), bob_ctx.recipient_id());
        // Bob's sender ID should be Alice's recipient ID
        assert_eq!(bob_ctx.sender_id(), alice_ctx.recipient_id());

        // Verify master secrets match (same PSK)
        assert_eq!(alice_ctx.master_secret(), bob_ctx.master_secret());
    }
}
