// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! BR provisioning channel encryption.
//!
//! Per spec section 8.7, BR provisioning channels MUST be encrypted and
//! authenticated. This module provides:
//!
//! 1. [`BRProvisioningSession`]: EDHOC-based secure channel establishment (BR side)
//! 2. [`NodeProvisioningSession`]: EDHOC-based secure channel establishment (node side)
//! 3. [`ProvisioningPayload`]: Encrypted seed + pubkey transfer format
//! 4. Secure key deletion after transfer
//!
//! # Protocol Flow
//!
//! 1. Node boots in commissioning mode
//! 2. Node and BR establish EDHOC session (BR authenticates with Ed25519)
//! 3. BR generates Ed25519 keypair for node
//! 4. BR encrypts seed using session key (AES-CCM-16-64-128)
//! 5. Node decrypts and stores keypair, derives IID/02xx
//! 6. BR securely deletes the seed from memory
//!
//! # Security Notes
//!
//! - Channel MUST be encrypted and authenticated
//! - Plaintext seed transfer is a critical vulnerability (seed compromise = identity theft)
//! - Transport bindings: USB/BLE/LCI per spec

#![allow(unused)] // Module being built incrementally

use core::fmt;

use heapless::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "edhoc")]
use crate::{Context, EdhocError, EdhocInitiator, EdhocResponder, OscoreError};

use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// AES-CCM-16-64-128 as used in Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// AES key length.
pub const CCM_KEY_LEN: usize = 16;
/// AES-CCM nonce length.
pub const CCM_NONCE_LEN: usize = 13;
/// AES-CCM tag length.
pub const CCM_TAG_LEN: usize = 8;
/// Ed25519 seed length.
pub const SEED_LEN: usize = 32;
/// Ed25519 pubkey length.
pub const PUBKEY_LEN: usize = 32;

/// Payload type for seed transfer.
pub const PAYLOAD_TYPE_SEED: u8 = 0x01;
/// Payload type for acknowledgment.
pub const PAYLOAD_TYPE_ACK: u8 = 0x02;

/// AEAD additional data prefix for domain separation.
const PROVISIONING_AAD_PREFIX: &[u8] = b"LICHEN-PROVISION-v1";

/// Provisioning-specific key derivation info.
const PROVISIONING_KEY_INFO: &[u8] = b"LICHEN-PROVISION-KEY";

/// Provisioning channel errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisioningError {
    /// Channel not yet established.
    ChannelNotEstablished,
    /// Authentication failed.
    AuthenticationFailed,
    /// Decryption failed (tampered or wrong key).
    DecryptionFailed,
    /// Invalid protocol state.
    InvalidState,
    /// Payload decode failed.
    DecodeFailed,
    /// Buffer too small.
    BufferTooSmall,
    /// Protocol violation.
    ProtocolViolation,
    /// Pubkey mismatch.
    PubkeyMismatch,
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: Use generic messages to prevent oracle attacks.
        match self {
            Self::ChannelNotEstablished => write!(f, "channel not established"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::DecodeFailed => write!(f, "decode failed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::ProtocolViolation => write!(f, "protocol violation"),
            Self::PubkeyMismatch => write!(f, "pubkey mismatch"),
        }
    }
}

impl core::error::Error for ProvisioningError {}

#[cfg(feature = "edhoc")]
impl From<EdhocError> for ProvisioningError {
    fn from(_: EdhocError) -> Self {
        // SECURITY: Do not reveal EDHOC error details.
        Self::AuthenticationFailed
    }
}

#[cfg(feature = "edhoc")]
impl From<OscoreError> for ProvisioningError {
    fn from(_: OscoreError) -> Self {
        // SECURITY: Do not reveal OSCORE error details.
        Self::ChannelNotEstablished
    }
}

/// Provisioning state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    /// Not started.
    Idle,
    /// EDHOC handshake ongoing.
    EdhocInProgress,
    /// Channel encrypted and authenticated.
    Established,
    /// Seed transferred and verified.
    Completed,
    /// Unrecoverable error.
    Failed,
}

/// Encrypted provisioning payload (CBOR-encoded).
///
/// Wire format:
/// ```text
/// {
///     "type": int,       # PAYLOAD_TYPE_SEED or PAYLOAD_TYPE_ACK
///     "nonce": bytes,    # 13-byte AES-CCM nonce
///     "ct": bytes        # Ciphertext + tag
/// }
/// ```
#[derive(Clone)]
pub struct ProvisioningPayload {
    pub payload_type: u8,
    pub nonce: [u8; CCM_NONCE_LEN],
    pub ciphertext: Vec<u8, 48>, // 32 + 8 tag + margin
}

impl ProvisioningPayload {
    /// Create a new payload.
    pub fn new(payload_type: u8, nonce: [u8; CCM_NONCE_LEN], ciphertext: &[u8]) -> Self {
        let mut ct = Vec::new();
        let _ = ct.extend_from_slice(ciphertext);
        Self {
            payload_type,
            nonce,
            ciphertext: ct,
        }
    }

    /// Encode payload as CBOR for transmission.
    ///
    /// CBOR map: {"type": int, "nonce": bstr, "ct": bstr}
    pub fn encode(&self) -> Result<Vec<u8, 80>, ProvisioningError> {
        let mut out = Vec::new();

        // Map with 3 pairs
        out.push(0xa3).map_err(|_| ProvisioningError::BufferTooSmall)?;

        // "type" key
        encode_tstr(&mut out, "type")?;
        // type value (int)
        out.push(self.payload_type)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;

        // "nonce" key
        encode_tstr(&mut out, "nonce")?;
        // nonce value (bstr 13)
        encode_bstr(&mut out, &self.nonce)?;

        // "ct" key
        encode_tstr(&mut out, "ct")?;
        // ciphertext value
        encode_bstr(&mut out, &self.ciphertext)?;

        Ok(out)
    }

    /// Decode CBOR payload from wire format.
    ///
    /// # Security
    ///
    /// Uses generic error messages to prevent oracle attacks. Does not reveal
    /// WHY decoding failed.
    pub fn decode(data: &[u8]) -> Result<Self, ProvisioningError> {
        // SECURITY: All failures produce the same generic error.
        let err = ProvisioningError::DecodeFailed;

        // Must be a map
        if data.is_empty() || (data[0] & 0xe0) != 0xa0 {
            return Err(err);
        }

        let num_pairs = (data[0] & 0x1f) as usize;
        if num_pairs != 3 {
            return Err(err);
        }

        let mut pos = 1;
        let mut payload_type: Option<u8> = None;
        let mut nonce: Option<[u8; CCM_NONCE_LEN]> = None;
        let mut ciphertext: Option<Vec<u8, 48>> = None;

        for _ in 0..3 {
            // Parse key (text string)
            let (key, consumed) = parse_tstr(&data[pos..]).ok_or(err)?;
            pos += consumed;

            match key {
                "type" => {
                    // Value must be unsigned int (0x00-0x17 for small ints)
                    if pos >= data.len() {
                        return Err(err);
                    }
                    let val = data[pos];
                    // SECURITY: Check bool not masquerading as int (CBOR true=0xf5, false=0xf4)
                    if val == 0xf5 || val == 0xf4 {
                        return Err(err);
                    }
                    if val > 0x17 {
                        return Err(err);
                    }
                    if val != PAYLOAD_TYPE_SEED && val != PAYLOAD_TYPE_ACK {
                        return Err(err);
                    }
                    payload_type = Some(val);
                    pos += 1;
                }
                "nonce" => {
                    let (bytes, consumed) = parse_bstr(&data[pos..]).ok_or(err)?;
                    if bytes.len() != CCM_NONCE_LEN {
                        return Err(err);
                    }
                    let mut n = [0u8; CCM_NONCE_LEN];
                    n.copy_from_slice(bytes);
                    nonce = Some(n);
                    pos += consumed;
                }
                "ct" => {
                    let (bytes, consumed) = parse_bstr(&data[pos..]).ok_or(err)?;
                    let mut ct = Vec::new();
                    ct.extend_from_slice(bytes)
                        .map_err(|_| ProvisioningError::BufferTooSmall)?;
                    ciphertext = Some(ct);
                    pos += consumed;
                }
                _ => return Err(err),
            }
        }

        let payload_type = payload_type.ok_or(err)?;
        let nonce = nonce.ok_or(err)?;
        let ciphertext = ciphertext.ok_or(err)?;

        Ok(Self {
            payload_type,
            nonce,
            ciphertext,
        })
    }
}

/// Derive a provisioning-specific key from OSCORE master secret.
///
/// Uses HKDF-Extract + Expand with a provisioning-specific info string to ensure
/// the provisioning key is domain-separated from OSCORE traffic keys.
#[cfg(feature = "edhoc")]
fn derive_provisioning_key(master_secret: &[u8; 16]) -> [u8; CCM_KEY_LEN] {
    // SECURITY: Domain separation prevents key reuse attacks between
    // provisioning and normal OSCORE traffic.
    // Use HKDF-Extract with empty salt to create a proper 32-byte PRK
    // from the 16-byte master_secret, then expand with provisioning info.
    let (prk, hk) = Hkdf::<Sha256>::extract(None, master_secret);
    let _ = prk; // PRK is consumed by hk
    let mut key = [0u8; CCM_KEY_LEN];
    hk.expand(PROVISIONING_KEY_INFO, &mut key)
        .expect("valid expand");
    key
}

/// Encrypt a 32-byte seed using AES-CCM-16-64-128.
fn encrypt_seed(
    key: &[u8; CCM_KEY_LEN],
    seed: &[u8; SEED_LEN],
    nonce: &[u8; CCM_NONCE_LEN],
) -> Result<ProvisioningPayload, ProvisioningError> {
    let mut aad = [0u8; 20]; // PROVISIONING_AAD_PREFIX + 1 byte type
    aad[..19].copy_from_slice(PROVISIONING_AAD_PREFIX);
    aad[19] = PAYLOAD_TYPE_SEED;

    let cipher = AesCcm::new(key.into());
    let mut buffer = [0u8; SEED_LEN];
    buffer.copy_from_slice(seed);

    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), &aad, &mut buffer)
        .map_err(|_| ProvisioningError::DecryptionFailed)?;

    let mut ciphertext = Vec::new();
    ciphertext
        .extend_from_slice(&buffer)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;
    ciphertext
        .extend_from_slice(&tag)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;

    Ok(ProvisioningPayload {
        payload_type: PAYLOAD_TYPE_SEED,
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypt seed from provisioning payload.
fn decrypt_seed(
    key: &[u8; CCM_KEY_LEN],
    payload: &ProvisioningPayload,
) -> Result<[u8; SEED_LEN], ProvisioningError> {
    // SECURITY: Use generic error messages to prevent oracle attacks.
    let err = ProvisioningError::DecryptionFailed;

    if payload.payload_type != PAYLOAD_TYPE_SEED {
        return Err(err);
    }
    if payload.ciphertext.len() != SEED_LEN + CCM_TAG_LEN {
        return Err(err);
    }

    let mut aad = [0u8; 20];
    aad[..19].copy_from_slice(PROVISIONING_AAD_PREFIX);
    aad[19] = PAYLOAD_TYPE_SEED;

    let cipher = AesCcm::new(key.into());
    let mut buffer = [0u8; SEED_LEN];
    buffer.copy_from_slice(&payload.ciphertext[..SEED_LEN]);
    let mut tag = [0u8; CCM_TAG_LEN];
    tag.copy_from_slice(&payload.ciphertext[SEED_LEN..]);

    cipher
        .decrypt_in_place_detached((&payload.nonce).into(), &aad, &mut buffer, (&tag).into())
        .map_err(|_| err)?;

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&buffer);
    buffer.zeroize();
    Ok(seed)
}

/// Encrypt acknowledgment (derived pubkey) for BR verification.
fn encrypt_ack(
    key: &[u8; CCM_KEY_LEN],
    pubkey: &[u8; PUBKEY_LEN],
    nonce: &[u8; CCM_NONCE_LEN],
) -> Result<ProvisioningPayload, ProvisioningError> {
    let mut aad = [0u8; 20];
    aad[..19].copy_from_slice(PROVISIONING_AAD_PREFIX);
    aad[19] = PAYLOAD_TYPE_ACK;

    let cipher = AesCcm::new(key.into());
    let mut buffer = [0u8; PUBKEY_LEN];
    buffer.copy_from_slice(pubkey);

    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), &aad, &mut buffer)
        .map_err(|_| ProvisioningError::DecryptionFailed)?;

    let mut ciphertext = Vec::new();
    ciphertext
        .extend_from_slice(&buffer)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;
    ciphertext
        .extend_from_slice(&tag)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;

    Ok(ProvisioningPayload {
        payload_type: PAYLOAD_TYPE_ACK,
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypt acknowledgment pubkey from node.
fn decrypt_ack(
    key: &[u8; CCM_KEY_LEN],
    payload: &ProvisioningPayload,
) -> Result<[u8; PUBKEY_LEN], ProvisioningError> {
    // SECURITY: Use generic error messages to prevent oracle attacks.
    let err = ProvisioningError::DecryptionFailed;

    if payload.payload_type != PAYLOAD_TYPE_ACK {
        return Err(err);
    }
    if payload.ciphertext.len() != PUBKEY_LEN + CCM_TAG_LEN {
        return Err(err);
    }

    let mut aad = [0u8; 20];
    aad[..19].copy_from_slice(PROVISIONING_AAD_PREFIX);
    aad[19] = PAYLOAD_TYPE_ACK;

    let cipher = AesCcm::new(key.into());
    let mut buffer = [0u8; PUBKEY_LEN];
    buffer.copy_from_slice(&payload.ciphertext[..PUBKEY_LEN]);
    let mut tag = [0u8; CCM_TAG_LEN];
    tag.copy_from_slice(&payload.ciphertext[PUBKEY_LEN..]);

    cipher
        .decrypt_in_place_detached((&payload.nonce).into(), &aad, &mut buffer, (&tag).into())
        .map_err(|_| err)?;

    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&buffer);
    buffer.zeroize();
    Ok(pubkey)
}

// CBOR encoding helpers

fn encode_tstr<const N: usize>(out: &mut Vec<u8, N>, s: &str) -> Result<(), ProvisioningError> {
    let bytes = s.as_bytes();
    if bytes.len() <= 23 {
        out.push(0x60 | bytes.len() as u8)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
    } else if bytes.len() <= 255 {
        out.push(0x78)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
        out.push(bytes.len() as u8)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
    } else {
        return Err(ProvisioningError::BufferTooSmall);
    }
    out.extend_from_slice(bytes)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;
    Ok(())
}

fn encode_bstr<const N: usize>(out: &mut Vec<u8, N>, b: &[u8]) -> Result<(), ProvisioningError> {
    if b.len() <= 23 {
        out.push(0x40 | b.len() as u8)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
    } else if b.len() <= 255 {
        out.push(0x58)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
        out.push(b.len() as u8)
            .map_err(|_| ProvisioningError::BufferTooSmall)?;
    } else {
        return Err(ProvisioningError::BufferTooSmall);
    }
    out.extend_from_slice(b)
        .map_err(|_| ProvisioningError::BufferTooSmall)?;
    Ok(())
}

fn parse_tstr(data: &[u8]) -> Option<(&str, usize)> {
    if data.is_empty() {
        return None;
    }
    let (len, hdr_size) = if (data[0] & 0xe0) == 0x60 {
        let l = (data[0] & 0x1f) as usize;
        if l <= 23 {
            (l, 1)
        } else if data.len() >= 2 && l == 24 {
            (data[1] as usize, 2)
        } else {
            return None;
        }
    } else {
        return None;
    };
    if data.len() < hdr_size + len {
        return None;
    }
    let s = core::str::from_utf8(&data[hdr_size..hdr_size + len]).ok()?;
    Some((s, hdr_size + len))
}

fn parse_bstr(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }
    let (len, hdr_size) = if (data[0] & 0xe0) == 0x40 {
        let l = (data[0] & 0x1f) as usize;
        if l <= 23 {
            (l, 1)
        } else if data.len() >= 2 && l == 24 {
            (data[1] as usize, 2)
        } else {
            return None;
        }
    } else {
        return None;
    };
    if data.len() < hdr_size + len {
        return None;
    }
    Some((&data[hdr_size..hdr_size + len], hdr_size + len))
}

/// Border router side of provisioning channel.
///
/// The node's ephemeral pubkey must be provided for EDHOC authentication.
/// This can be communicated out-of-band via:
/// - Physical display on node (QR code, hex string)
/// - Pre-provisioned in commissioning manifest
/// - TOFU with physical proximity verification
///
/// # Usage
///
/// ```ignore
/// // Node displays its ephemeral pubkey, BR scans/enters it
/// let node_pubkey = get_node_pubkey_out_of_band();
/// let mut session = BRProvisioningSession::new(br_seed, node_pubkey, &mut rng)?;
///
/// // EDHOC handshake
/// let msg1_from_node = receive();
/// let msg2 = session.process_message_1(&msg1_from_node)?;
/// send(&msg2);
/// let msg3_from_node = receive();
/// session.process_message_3(&msg3_from_node)?;
///
/// // Provision the keypair
/// let node_seed = generate_seed(&mut rng);
/// let encrypted = session.encrypt_seed(&node_seed, &nonce)?;
/// send(&encrypted.encode()?);
///
/// // Verify ACK
/// let ack_data = receive();
/// let ack = ProvisioningPayload::decode(&ack_data)?;
/// session.verify_ack(&ack, &node_seed)?;
///
/// // CRITICAL: Securely delete seed from BR memory
/// session.wipe();
/// ```
#[cfg(feature = "edhoc")]
pub struct BRProvisioningSession {
    responder: EdhocResponder,
    node_pubkey: [u8; PUBKEY_LEN],
    provisioning_key: [u8; CCM_KEY_LEN],
    provisioned_seed: [u8; SEED_LEN],
    state: ProvisioningState,
}

#[cfg(feature = "edhoc")]
impl fmt::Debug for BRProvisioningSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BRProvisioningSession")
            .field("responder", &"[REDACTED]")
            .field("node_pubkey", &self.node_pubkey)
            .field("provisioning_key", &"[REDACTED]")
            .field("provisioned_seed", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(feature = "edhoc")]
impl Drop for BRProvisioningSession {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(feature = "edhoc")]
impl BRProvisioningSession {
    /// Create a new BR provisioning session.
    ///
    /// # Arguments
    /// * `br_seed` - BR's Ed25519 seed (32 bytes)
    /// * `node_pubkey` - Node's ephemeral pubkey (32 bytes, from out-of-band)
    /// * `rng` - RNG for ephemeral key generation
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        br_seed: [u8; 32],
        node_pubkey: [u8; PUBKEY_LEN],
        rng: &mut R,
    ) -> Result<Self, ProvisioningError> {
        let responder = EdhocResponder::new(br_seed, 0x01, rng);
        Ok(Self {
            responder,
            node_pubkey,
            provisioning_key: [0u8; CCM_KEY_LEN],
            provisioned_seed: [0u8; SEED_LEN],
            state: ProvisioningState::Idle,
        })
    }

    /// Process EDHOC Message 1 from node, return Message 2.
    pub fn process_message_1(
        &mut self,
        msg1: &[u8],
    ) -> Result<heapless::Vec<u8, 160>, ProvisioningError> {
        if self.state != ProvisioningState::Idle {
            return Err(ProvisioningError::InvalidState);
        }

        let msg2 = self.responder.process_message_1(msg1)?;
        self.state = ProvisioningState::EdhocInProgress;
        Ok(msg2)
    }

    /// Process EDHOC Message 3 from node, establish secure channel.
    pub fn process_message_3(&mut self, msg3: &[u8]) -> Result<(), ProvisioningError> {
        if self.state != ProvisioningState::EdhocInProgress {
            return Err(ProvisioningError::InvalidState);
        }

        self.responder
            .process_message_3(msg3, &self.node_pubkey)
            .map_err(|_| {
                self.state = ProvisioningState::Failed;
                ProvisioningError::AuthenticationFailed
            })?;

        // Export OSCORE context and derive provisioning key
        let oscore_ctx = self.responder.export_oscore().map_err(|_| {
            self.state = ProvisioningState::Failed;
            ProvisioningError::ChannelNotEstablished
        })?;

        self.provisioning_key = derive_provisioning_key(oscore_ctx.master_secret());
        self.state = ProvisioningState::Established;
        Ok(())
    }

    /// Encrypt a seed for transmission to the node.
    ///
    /// # Security
    ///
    /// After calling this, the BR MUST securely delete the seed from memory
    /// once the node ACKs successful receipt.
    pub fn encrypt_seed(
        &mut self,
        seed: &[u8; SEED_LEN],
        nonce: &[u8; CCM_NONCE_LEN],
    ) -> Result<ProvisioningPayload, ProvisioningError> {
        if self.state != ProvisioningState::Established {
            return Err(ProvisioningError::ChannelNotEstablished);
        }

        // Store temporarily for verification
        self.provisioned_seed = *seed;
        encrypt_seed(&self.provisioning_key, seed, nonce)
    }

    /// Decrypt and verify acknowledgment from node.
    ///
    /// # Security
    ///
    /// Pubkey verification is MANDATORY per spec 8.7. The BR MUST verify that
    /// the node derived the correct pubkey from the provisioned seed.
    pub fn verify_ack(
        &mut self,
        payload: &ProvisioningPayload,
        expected_pubkey: &[u8; PUBKEY_LEN],
    ) -> Result<[u8; PUBKEY_LEN], ProvisioningError> {
        if self.state != ProvisioningState::Established {
            return Err(ProvisioningError::ChannelNotEstablished);
        }

        let received_pubkey = decrypt_ack(&self.provisioning_key, payload)?;

        // SECURITY: Constant-time comparison prevents timing side-channel
        if !constant_time_eq(&received_pubkey, expected_pubkey) {
            self.state = ProvisioningState::Failed;
            return Err(ProvisioningError::PubkeyMismatch);
        }

        self.state = ProvisioningState::Completed;
        Ok(received_pubkey)
    }

    /// Securely clear sensitive material from memory.
    ///
    /// # Security
    ///
    /// Must be called after provisioning completes.
    pub fn wipe(&mut self) {
        self.provisioning_key.zeroize();
        self.provisioned_seed.zeroize();
        self.state = ProvisioningState::Idle;
    }

    /// Current provisioning state.
    pub fn state(&self) -> ProvisioningState {
        self.state
    }
}

/// Node side of provisioning channel (commissioning mode).
///
/// # Usage
///
/// ```ignore
/// // Node has ephemeral identity for initial EDHOC
/// let ephemeral_seed = generate_seed(&mut rng);
/// let mut session = NodeProvisioningSession::new(ephemeral_seed, &mut rng)?;
///
/// // EDHOC handshake
/// let msg1 = session.create_message_1()?;
/// send(&msg1);
/// let msg2_from_br = receive();
/// let msg3 = session.process_message_2(&msg2_from_br, &br_pubkey)?;
/// send(&msg3);
///
/// // Receive and decrypt seed
/// let seed_data = receive();
/// let payload = ProvisioningPayload::decode(&seed_data)?;
/// let new_seed = session.decrypt_seed(&payload)?;
///
/// // Create ACK with derived pubkey
/// let new_identity = Identity::from_seed(new_seed);
/// let ack = session.create_ack(&new_identity.pubkey, &nonce)?;
/// send(&ack.encode()?);
///
/// session.wipe();
/// ```
#[cfg(feature = "edhoc")]
pub struct NodeProvisioningSession {
    initiator: EdhocInitiator,
    provisioning_key: [u8; CCM_KEY_LEN],
    provisioned_pubkey: [u8; PUBKEY_LEN],
    state: ProvisioningState,
}

#[cfg(feature = "edhoc")]
impl fmt::Debug for NodeProvisioningSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeProvisioningSession")
            .field("initiator", &"[REDACTED]")
            .field("provisioning_key", &"[REDACTED]")
            .field("provisioned_pubkey", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(feature = "edhoc")]
impl Drop for NodeProvisioningSession {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(feature = "edhoc")]
impl NodeProvisioningSession {
    /// Create a new node provisioning session.
    ///
    /// # Arguments
    /// * `ephemeral_seed` - Node's ephemeral Ed25519 seed (32 bytes)
    /// * `rng` - RNG for ephemeral key generation
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        ephemeral_seed: [u8; 32],
        rng: &mut R,
    ) -> Result<Self, ProvisioningError> {
        let initiator = EdhocInitiator::new(ephemeral_seed, 0x00, rng);
        Ok(Self {
            initiator,
            provisioning_key: [0u8; CCM_KEY_LEN],
            provisioned_pubkey: [0u8; PUBKEY_LEN],
            state: ProvisioningState::Idle,
        })
    }

    /// Create EDHOC Message 1 to initiate handshake with BR.
    pub fn create_message_1(&mut self) -> Result<heapless::Vec<u8, 64>, ProvisioningError> {
        if self.state != ProvisioningState::Idle {
            return Err(ProvisioningError::InvalidState);
        }

        let msg1 = self.initiator.create_message_1()?;
        self.state = ProvisioningState::EdhocInProgress;
        Ok(msg1)
    }

    /// Process EDHOC Message 2 from BR, return Message 3.
    pub fn process_message_2(
        &mut self,
        msg2: &[u8],
        br_pubkey: &[u8; PUBKEY_LEN],
    ) -> Result<heapless::Vec<u8, 128>, ProvisioningError> {
        if self.state != ProvisioningState::EdhocInProgress {
            return Err(ProvisioningError::InvalidState);
        }

        let msg3 = self
            .initiator
            .process_message_2(msg2, br_pubkey)
            .map_err(|_| {
                self.state = ProvisioningState::Failed;
                ProvisioningError::AuthenticationFailed
            })?;

        // Export OSCORE context and derive provisioning key
        let oscore_ctx = self.initiator.export_oscore().map_err(|_| {
            self.state = ProvisioningState::Failed;
            ProvisioningError::ChannelNotEstablished
        })?;

        self.provisioning_key = derive_provisioning_key(oscore_ctx.master_secret());
        self.state = ProvisioningState::Established;
        Ok(msg3)
    }

    /// Decrypt provisioned seed from BR.
    ///
    /// # Security
    ///
    /// After this call, the node MUST store the new identity securely and
    /// exit commissioning mode.
    pub fn decrypt_seed(
        &mut self,
        payload: &ProvisioningPayload,
    ) -> Result<[u8; SEED_LEN], ProvisioningError> {
        if self.state != ProvisioningState::Established {
            return Err(ProvisioningError::ChannelNotEstablished);
        }

        let seed = decrypt_seed(&self.provisioning_key, payload)?;

        // Derive pubkey from seed for later verification in create_ack
        // This matches Python: Identity.from_seed(seed).pubkey
        let pubkey = derive_pubkey_from_seed(&seed);
        self.provisioned_pubkey = pubkey;

        Ok(seed)
    }

    /// Create encrypted acknowledgment with derived pubkey.
    ///
    /// # Security
    ///
    /// Pubkey verification is MANDATORY per spec 8.7. The node MUST verify
    /// that the pubkey matches what was derived from the provisioned seed.
    pub fn create_ack(
        &mut self,
        pubkey: &[u8; PUBKEY_LEN],
        nonce: &[u8; CCM_NONCE_LEN],
    ) -> Result<ProvisioningPayload, ProvisioningError> {
        if self.state != ProvisioningState::Established {
            return Err(ProvisioningError::ChannelNotEstablished);
        }

        // SECURITY: Verify pubkey matches what was derived from provisioned seed
        if self.provisioned_pubkey == [0u8; PUBKEY_LEN] {
            self.state = ProvisioningState::Failed;
            return Err(ProvisioningError::ProtocolViolation);
        }

        // SECURITY: Constant-time comparison
        if !constant_time_eq(pubkey, &self.provisioned_pubkey) {
            self.state = ProvisioningState::Failed;
            return Err(ProvisioningError::PubkeyMismatch);
        }

        let ack = encrypt_ack(&self.provisioning_key, &self.provisioned_pubkey, nonce)?;
        self.state = ProvisioningState::Completed;
        Ok(ack)
    }

    /// Securely clear sensitive material from memory.
    pub fn wipe(&mut self) {
        self.provisioning_key.zeroize();
        self.provisioned_pubkey.zeroize();
        self.state = ProvisioningState::Idle;
    }

    /// Current provisioning state.
    pub fn state(&self) -> ProvisioningState {
        self.state
    }
}

/// Derive Ed25519 pubkey from seed.
///
/// Uses the same derivation as `lichen-link::identity::Identity::from_seed`.
#[cfg(feature = "edhoc")]
fn derive_pubkey_from_seed(seed: &[u8; 32]) -> [u8; PUBKEY_LEN] {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key: VerifyingKey = (&signing_key).into();
    verifying_key.to_bytes()
}

/// Constant-time byte array comparison using subtle crate.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_encode_decode_roundtrip() {
        let nonce = [0x01u8; CCM_NONCE_LEN];
        let ciphertext = [0xab; SEED_LEN + CCM_TAG_LEN];
        let payload = ProvisioningPayload::new(PAYLOAD_TYPE_SEED, nonce, &ciphertext);

        let encoded = payload.encode().unwrap();
        let decoded = ProvisioningPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.payload_type, PAYLOAD_TYPE_SEED);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext.as_slice(), &ciphertext);
    }

    #[test]
    fn payload_decode_rejects_wrong_type() {
        // Create payload with invalid type
        let mut buf = heapless::Vec::<u8, 80>::new();
        buf.push(0xa3).unwrap(); // map(3)
        encode_tstr(&mut buf, "type").unwrap();
        buf.push(0x99).unwrap(); // invalid type
        encode_tstr(&mut buf, "nonce").unwrap();
        encode_bstr(&mut buf, &[0u8; CCM_NONCE_LEN]).unwrap();
        encode_tstr(&mut buf, "ct").unwrap();
        encode_bstr(&mut buf, &[0u8; 40]).unwrap();

        let result = ProvisioningPayload::decode(&buf);
        assert!(matches!(result, Err(ProvisioningError::DecodeFailed)));
    }

    #[test]
    fn payload_decode_rejects_boolean_type() {
        // CBOR true is 0xf5, false is 0xf4
        let mut buf = heapless::Vec::<u8, 80>::new();
        buf.push(0xa3).unwrap();
        encode_tstr(&mut buf, "type").unwrap();
        buf.push(0xf5).unwrap(); // true (CBOR)
        encode_tstr(&mut buf, "nonce").unwrap();
        encode_bstr(&mut buf, &[0u8; CCM_NONCE_LEN]).unwrap();
        encode_tstr(&mut buf, "ct").unwrap();
        encode_bstr(&mut buf, &[0u8; 40]).unwrap();

        let result = ProvisioningPayload::decode(&buf);
        assert!(matches!(result, Err(ProvisioningError::DecodeFailed)));
    }

    #[test]
    fn seed_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; CCM_KEY_LEN];
        let seed = [0xabu8; SEED_LEN];
        let nonce = [0x11u8; CCM_NONCE_LEN];

        let payload = encrypt_seed(&key, &seed, &nonce).unwrap();
        assert_eq!(payload.payload_type, PAYLOAD_TYPE_SEED);

        let decrypted = decrypt_seed(&key, &payload).unwrap();
        assert_eq!(decrypted, seed);
    }

    #[test]
    fn ack_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; CCM_KEY_LEN];
        let pubkey = [0xcdu8; PUBKEY_LEN];
        let nonce = [0x22u8; CCM_NONCE_LEN];

        let payload = encrypt_ack(&key, &pubkey, &nonce).unwrap();
        assert_eq!(payload.payload_type, PAYLOAD_TYPE_ACK);

        let decrypted = decrypt_ack(&key, &payload).unwrap();
        assert_eq!(decrypted, pubkey);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = [0x42u8; CCM_KEY_LEN];
        let wrong_key = [0x00u8; CCM_KEY_LEN];
        let seed = [0xabu8; SEED_LEN];
        let nonce = [0x11u8; CCM_NONCE_LEN];

        let payload = encrypt_seed(&key, &seed, &nonce).unwrap();
        let result = decrypt_seed(&wrong_key, &payload);
        assert!(matches!(result, Err(ProvisioningError::DecryptionFailed)));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }

    #[cfg(feature = "edhoc")]
    #[test]
    fn full_provisioning_flow() {
        use rand_core::OsRng;

        // Setup identities
        let br_seed = [0x00u8; 32];
        let node_ephemeral_seed = [0x01u8; 32];

        // Get node's ephemeral pubkey (out-of-band)
        let node_pubkey = derive_pubkey_from_seed(&node_ephemeral_seed);

        // Create sessions
        let mut br_session = BRProvisioningSession::new(br_seed, node_pubkey, &mut OsRng).unwrap();
        let mut node_session = NodeProvisioningSession::new(node_ephemeral_seed, &mut OsRng).unwrap();

        // EDHOC handshake
        let msg1 = node_session.create_message_1().unwrap();
        assert_eq!(node_session.state(), ProvisioningState::EdhocInProgress);

        let msg2 = br_session.process_message_1(&msg1).unwrap();
        assert_eq!(br_session.state(), ProvisioningState::EdhocInProgress);

        let br_pubkey = derive_pubkey_from_seed(&br_seed);
        let msg3 = node_session.process_message_2(&msg2, &br_pubkey).unwrap();
        assert_eq!(node_session.state(), ProvisioningState::Established);

        br_session.process_message_3(&msg3).unwrap();
        assert_eq!(br_session.state(), ProvisioningState::Established);

        // BR provisions new keypair
        let new_seed = [0x99u8; 32];
        let nonce = [0xaau8; CCM_NONCE_LEN];
        let encrypted_seed = br_session.encrypt_seed(&new_seed, &nonce).unwrap();

        // Node decrypts and derives identity
        let seed_data = encrypted_seed.encode().unwrap();
        let payload = ProvisioningPayload::decode(&seed_data).unwrap();
        let received_seed = node_session.decrypt_seed(&payload).unwrap();
        assert_eq!(received_seed, new_seed);

        // Node sends ACK
        let new_pubkey = derive_pubkey_from_seed(&new_seed);
        let ack_nonce = [0xbbu8; CCM_NONCE_LEN];
        let ack = node_session.create_ack(&new_pubkey, &ack_nonce).unwrap();
        assert_eq!(node_session.state(), ProvisioningState::Completed);

        // BR verifies ACK
        let received_pubkey = br_session.verify_ack(&ack, &new_pubkey).unwrap();
        assert_eq!(received_pubkey, new_pubkey);
        assert_eq!(br_session.state(), ProvisioningState::Completed);

        // Cleanup
        br_session.wipe();
        node_session.wipe();
    }
}
