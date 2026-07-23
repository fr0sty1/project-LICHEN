// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! EDHOC (RFC 9528) Suite 0 implementation for establishing OSCORE contexts.
//!
//! Suite 0: X25519 + Ed25519 + AES-CCM-16-64-128 + SHA-256
//!
//! # ponytail: minimal Suite 0
//!
//! Rolled minimal implementation because:
//! - lakers only supports Suite 2 (P-256), not Suite 0 (X25519/Ed25519)
//! - Suite 0 matches LICHEN link-layer Ed25519 (Schnorr48)
//! - Python simulator uses Suite 0, so interop requires Suite 0
//!
//! Uses existing crates: x25519-dalek, ed25519-dalek, aes/ccm, hkdf/sha2.
//! Their zeroize features wipe owned secret keys, hash state, and expanded AES schedules on drop.
//! HMAC 0.13 key setup and HKDF 0.13 expansion also use private call-local arrays which their
//! APIs do not expose for wiping. Replacing those vetted primitives locally would violate the
//! project's crypto policy; remediation requires upstream support. Rust likewise cannot
//! guarantee removal of compiler-created register or stack copies.

use crate::{Context, OscoreError, KEY_LEN, NONCE_LEN, TAG_LEN};
use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{CryptoRng, RngCore};

/// AES-CCM for Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// X25519/Ed25519 key length.
pub const KEY_LEN_32: usize = 32;

/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;

/// Suite 0 identifier.
pub const SUITE_0: u8 = 0;

/// Connection identifier capacity supported by this implementation's OSCORE nonce layout.
pub const CONNECTION_ID_CAPACITY: usize = 7;

/// Maximum encoded ID_CRED length accepted by this implementation.
pub const ID_CRED_MAX_LEN: usize = 64;

/// Maximum number of COSE header parameters accepted in an ID_CRED map.
pub const ID_CRED_MAX_PARAMETERS: usize = 8;

/// An EDHOC connection identifier in its raw byte-string form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionId(heapless::Vec<u8, CONNECTION_ID_CAPACITY>);

impl ConnectionId {
    /// Create a bounded connection identifier.
    pub fn new(value: &[u8]) -> Result<Self, EdhocError> {
        let mut id = heapless::Vec::new();
        id.extend_from_slice(value)
            .map_err(|_| EdhocError::BufferTooSmall)?;
        Ok(Self(id))
    }

    /// Return the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<u8> for ConnectionId {
    fn from(value: u8) -> Self {
        let mut id = heapless::Vec::new();
        id.push(value).expect("one byte fits in a connection ID");
        Self(id)
    }
}

/// Credential reference carried by ID_CRED.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdCredReference {
    /// COSE `kid` header parameter.
    Kid(heapless::Vec<u8, ID_CRED_MAX_LEN>),
    /// COSE `x5t` header parameter: hash algorithm and certificate thumbprint.
    X5t {
        algorithm: i128,
        hash: heapless::Vec<u8, ID_CRED_MAX_LEN>,
    },
}

/// Parsed deterministic-CBOR ID_CRED with its exact canonical map encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdCred {
    encoded: heapless::Vec<u8, ID_CRED_MAX_LEN>,
    reference: IdCredReference,
}

impl IdCred {
    /// Return the canonical map encoding used by EDHOC transcript calculations.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the credential reference selected by the peer.
    pub fn reference(&self) -> &IdCredReference {
        &self.reference
    }
}

/// Peer authentication material supplied by the application.
///
/// `id_cred` and `credential` are complete deterministic-CBOR data items. CCS
/// and CWT COSE keys are checked against `public_key`; certificate and
/// application credential trust, including X.509 chain validation, remains the
/// application's responsibility.
#[derive(Clone, Copy)]
pub struct PeerCredential<'a> {
    public_key: &'a [u8; KEY_LEN_32],
    id_cred: &'a [u8],
    credential: &'a [u8],
}

impl<'a> PeerCredential<'a> {
    /// Create peer authentication material.
    pub const fn new(
        public_key: &'a [u8; KEY_LEN_32],
        id_cred: &'a [u8],
        credential: &'a [u8],
    ) -> Self {
        Self {
            public_key,
            id_cred,
            credential,
        }
    }
}

/// EDHOC error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdhocError {
    /// Protocol state error.
    InvalidState,
    /// Invalid message format.
    InvalidMessage,
    /// Unsupported cipher suite.
    UnsupportedSuite,
    /// Signature verification failed.
    SignatureVerification,
    /// AEAD decryption failed.
    DecryptFailed,
    /// Buffer too small.
    BufferTooSmall,
    /// Key derivation function failed.
    KeyDerivation,
}

impl core::fmt::Display for EdhocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "invalid protocol state"),
            Self::InvalidMessage => write!(f, "invalid message format"),
            Self::UnsupportedSuite => write!(f, "unsupported cipher suite"),
            Self::SignatureVerification => write!(f, "signature verification failed"),
            Self::DecryptFailed => write!(f, "AEAD decryption failed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::KeyDerivation => write!(f, "key derivation failed"),
        }
    }
}

impl core::error::Error for EdhocError {}

/// Helper trait for heapless::Vec push/extend with error mapping.
trait VecExt<T, const N: usize> {
    fn push_err(&mut self, item: T) -> Result<(), EdhocError>;
    fn extend_err(&mut self, slice: &[T]) -> Result<(), EdhocError>
    where
        T: Clone;
}

impl<T, const N: usize> VecExt<T, N> for heapless::Vec<T, N> {
    fn push_err(&mut self, item: T) -> Result<(), EdhocError> {
        self.push(item).map_err(|_| EdhocError::BufferTooSmall)
    }

    fn extend_err(&mut self, slice: &[T]) -> Result<(), EdhocError>
    where
        T: Clone,
    {
        self.extend_from_slice(slice)
            .map_err(|_| EdhocError::BufferTooSmall)
    }
}

/// A stack-backed byte buffer which wipes its initialized contents on drop.
struct SecretVec<const N: usize>(heapless::Vec<u8, N>);

impl<const N: usize> SecretVec<N> {
    fn new() -> Self {
        Self(heapless::Vec::new())
    }
}

impl<const N: usize> core::ops::Deref for SecretVec<N> {
    type Target = heapless::Vec<u8, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for SecretVec<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretVec<N> {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// HKDF-Extract with SHA-256.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    // ponytail: Use hkdf crate which we already depend on
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    Zeroizing::new(prk.into())
}

/// EDHOC-KDF (RFC 9528 Section 4.1.2).
///
/// Matches Python reference: EDHOC-KDF(PRK, TH, label, context, length)
/// = HKDF-Expand(PRK, info, length) where info = CBOR(length) + CBOR(TH)
/// + CBOR(label) + CBOR(context).
fn edhoc_kdf(
    prk: &[u8; 32],
    th: &[u8; 32],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut info = heapless::Vec::<u8, 128>::new();

    // length as CBOR uint
    if length <= 23 {
        info.push_err(length as u8)?;
    } else {
        info.push_err(0x18)?;
        info.push_err(length as u8)?;
    }

    // TH as bstr(32)
    info.push_err(0x58)?;
    info.push_err(32)?;
    info.extend_err(th)?;

    // label as tstr
    let label_bytes = label.as_bytes();
    if label_bytes.len() > 255 {
        return Err(EdhocError::BufferTooSmall);
    }
    if label_bytes.len() <= 23 {
        info.push_err(0x60 | label_bytes.len() as u8)?;
    } else {
        info.push_err(0x78)?;
        info.push_err(label_bytes.len() as u8)?;
    }
    info.extend_err(label_bytes)?;

    // context as bstr
    if context.is_empty() {
        info.push_err(0x40)?;
    } else if context.len() <= 23 {
        info.push_err(0x40 | context.len() as u8)?;
        info.extend_err(context)?;
    } else if context.len() <= 255 {
        info.push_err(0x58)?;
        info.push_err(context.len() as u8)?;
        info.extend_err(context)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| EdhocError::KeyDerivation)?;
    let mut okm = SecretVec::new();
    okm.resize(length, 0)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    hk.expand(&info, &mut okm)
        .map_err(|_| EdhocError::KeyDerivation)?;

    let mut result = heapless::Vec::new();
    result.extend_from_slice(okm.as_slice())
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(result)
}

fn export_context(
    prk: &[u8; 32],
    th: &[u8; 32],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> Result<Context, OscoreError> {
    let prk_out_vec = edhoc_kdf(prk, th, "PRK_out", &[], 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_out = Zeroizing::new([0u8; 32]);
    prk_out.copy_from_slice(&prk_out_vec);
    let prk_exporter_vec =
        edhoc_kdf(prk_out.as_ref(), th, "exporter", &[], 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_exporter = Zeroizing::new([0u8; 32]);
    prk_exporter.copy_from_slice(&prk_exporter_vec);

    let master_secret_vec =
        edhoc_kdf(prk_exporter.as_ref(), th, "OSCORE_Master_Secret", &[], KEY_LEN).map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_secret = Zeroizing::new([0u8; KEY_LEN]);
    master_secret.copy_from_slice(&master_secret_vec);

    let master_salt_vec =
        edhoc_kdf(prk_exporter.as_ref(), th, "OSCORE_Master_Salt", &[], 8).map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_salt = Zeroizing::new([0u8; 8]);
    master_salt.copy_from_slice(&master_salt_vec);

    Context::new_fresh(
        &master_secret,
        Some(&master_salt[..]),
        None,
        sender_id,
        recipient_id,
    )
}

/// Compute transcript hash: H(input).
fn compute_th(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Parse SUITES_I from CBOR per RFC 9528 Section 3.3.2.
///
/// SUITES_I can be either:
/// - A single int (the selected suite)
/// - An array of ints [selected_suite, ...other_supported_suites]
///
/// Returns (selected_suite, bytes_consumed).
fn parse_suites_i(data: &[u8]) -> Result<(u8, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }

    let first = data[0];

    // CBOR major type 0 (unsigned int): 0x00-0x17 (0-23), 0x18 (1-byte follow)
    if first <= 0x17 {
        // Direct int 0-23
        return Ok((first, 1));
    } else if first == 0x18 {
        // 1-byte follow
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((data[1], 2));
    }

    // CBOR major type 4 (array): 0x80-0x97 (array of 0-23 items), 0x98 (1-byte length)
    if (0x80..=0x97).contains(&first) {
        let arr_len = (first - 0x80) as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage); // Empty array not valid
        }
        // Parse first element (selected suite)
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[1];
        if elem <= 0x17 {
            // Count bytes: 1 (array header) + arr_len (each int 0-23 is 1 byte)
            // We only support suite values 0-23 for simplicity
            Ok((elem, 1 + arr_len))
        } else if elem == 0x18 && data.len() >= 3 {
            // First element is 1-byte int
            // Remaining elements assumed to be 1-byte each
            Ok((data[2], 1 + 1 + (arr_len - 1) + 1))
        } else {
            Err(EdhocError::InvalidMessage)
        }
    } else if first == 0x98 {
        // Array with 1-byte length
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        let arr_len = data[1] as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[2];
        if elem <= 0x17 {
            // 1 (0x98) + 1 (length) + arr_len (elements)
            Ok((elem, 2 + arr_len))
        } else {
            Err(EdhocError::InvalidMessage)
        }
    } else {
        Err(EdhocError::InvalidMessage)
    }
}

/// EDHOC Initiator (client role).
///
/// Implements EDHOC method 0 (SIGN_SIGN) with Suite 0.
// SECURITY: SigningKey and StaticSecret must be zeroized on drop.
// SigningKey and StaticSecret implement ZeroizeOnDrop themselves.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EdhocInitiator {
    /// Our Ed25519 signing key (implements ZeroizeOnDrop).
    #[zeroize(skip)]
    signing_key: SigningKey,
    /// Our Ed25519 public key.
    #[zeroize(skip)]
    pubkey: VerifyingKey,
    /// Our connection identifier.
    c_i: u8,
    /// Ephemeral X25519 secret (implements ZeroizeOnDrop).
    #[zeroize(skip)]
    eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
    #[zeroize(skip)]
    eph_public: PublicKey,
    /// Protocol state.
    state: InitiatorState,
}

/// Initiator protocol state.
///
/// Contains PRK secrets that must be zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct InitiatorState {
    #[zeroize(skip)]
    msg1: heapless::Vec<u8, 64>,
    g_y: [u8; 32],
    #[zeroize(skip)]
    c_r: ConnectionId,
    prk_2e: [u8; 32],
    prk_3e2m: [u8; 32],
    prk_4e3m: [u8; 32],
    th_2: [u8; 32],
    th_3: [u8; 32],
    th_4: [u8; 32],
    /// True when handshake completed (process_message_2 succeeded).
    completed: bool,
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_y: [0; 32],
            c_r: ConnectionId::new(&[]).expect("empty connection ID fits"),
            prk_2e: [0; 32],
            prk_3e2m: [0; 32],
            prk_4e3m: [0; 32],
            th_2: [0; 32],
            th_3: [0; 32],
            th_4: [0; 32],
            completed: false,
        }
    }
}

impl Zeroize for EdhocInitiator {
    fn zeroize(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Zeroized;
    }
}

impl EdhocInitiator {
    /// Create a new EDHOC initiator using caller-provided entropy.
    pub fn new_with_rng<R: RngCore + CryptoRng, C: Into<ConnectionId>>(
        seed: [u8; 32],
        c_i: C,
        rng: &mut R,
    ) -> Result<Self, OscoreError> {
        let seed = Zeroizing::new(seed);
        let mut eph_seed = Zeroizing::new([0u8; KEY_LEN_32]);
        rng.try_fill_bytes(&mut eph_seed[..])
            .map_err(|_| OscoreError::KeyDerivation)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();
        let eph_secret = StaticSecret::from(*eph_seed);
        eph_seed.zeroize();
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            signing_key,
            pubkey,
            c_i: c_i.into(),
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        })
    }

    /// Create a new EDHOC initiator.
    ///
    /// # Arguments
    /// * `seed` - Ed25519 seed (32 bytes)
    /// * `c_i` - Connection identifier (1 byte)
    /// * `rng` - RNG implementing RngCore + CryptoRng for ephemeral key
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_i: u8, rng: &mut R) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            signing_key,
            pubkey,
            c_i,
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        }
    }

    /// Create EDHOC Message 1.
    ///
    /// message_1 = (METHOD, SUITES_I, G_X, C_I, ? EAD_1)
    pub fn create_message_1(&mut self) -> Result<heapless::Vec<u8, 64>, EdhocError> {
        // METHOD_CORR = method * 4 + corr (method=0, corr=1 for CoAP)
        let method_corr: u8 = 1;

        // Build message_1 as CBOR sequence
        let mut msg1 = heapless::Vec::<u8, 64>::new();

        // method_corr as CBOR uint
        msg1.push_err(method_corr)?;

        // SUITES_I = 0 (Suite 0)
        msg1.push_err(SUITE_0)?;

        // G_X as CBOR bstr (32 bytes)
        msg1.push_err(0x58)?;
        msg1.push_err(32)?;
        msg1.extend_err(self.eph_public.as_bytes())?;

        // C_I - encode as int if 0-23, else as bstr
        if self.c_i <= 23 {
            msg1.push_err(self.c_i)?;
        } else {
            msg1.push_err(0x41)?;
            msg1.push_err(self.c_i)?;
        }

        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push_err(0)?; // METHOD = 0 (signature/signature)
        msg1.push_err(SUITE_0)?;
        encode_bstr(&mut msg1, self.eph_public.as_bytes())?;
        encode_identifier(&mut msg1, &self.c_i)?;

        self.state.msg1 = msg1.clone();
        self.state.lifecycle = Lifecycle::Message1Created;
        Ok(msg1)
    }

    /// Process EDHOC Message 2 and create Message 3.
    ///
    /// # Arguments
    /// * `msg2` - Message 2 from responder
    /// * `peer_pubkey` - Responder's Ed25519 public key
    ///
    /// Returns Message 3 to send back.
    pub fn process_message_2(
        &mut self,
        msg2: &[u8],
        peer_pubkey: &[u8; 32],
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        let (id_cred, credential) = raw_key_credential(peer_pubkey)?;
        self.process_message_2_with_credential(
            msg2,
            PeerCredential::new(peer_pubkey, &id_cred, &credential),
        )
    }

    /// Process Message 2 using application-validated peer authentication material.
    pub fn process_message_2_with_credential(
        &mut self,
        msg2: &[u8],
        peer: PeerCredential<'_>,
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        let pending = self.begin_process_message_2(msg2)?;
        self.finish_process_message_2(&pending, peer)
    }

    /// Decrypt and parse Message 2 so the application can select a credential.
    pub fn begin_process_message_2(&mut self, msg2: &[u8]) -> Result<PendingMessage2, EdhocError> {
        if self.state.lifecycle != Lifecycle::Message1Created || self.eph_secret.is_none() {
            return Err(EdhocError::InvalidState);
        }

        if msg2.first() == Some(&2) {
            let error = match parse_suites_r(&msg2[1..]) {
                Ok(consumed) if consumed + 1 == msg2.len() => EdhocError::UnsupportedSuite,
                _ => EdhocError::InvalidMessage,
            };
            self.poison();
            return Err(error);
        }

        let (g_y_ct2, consumed) = parse_bstr(msg2)?;
        if consumed != msg2.len() || g_y_ct2.len() < KEY_LEN_32 + 1 {
            return Err(EdhocError::InvalidMessage);
        }
        let mut g_y = [0u8; KEY_LEN_32];
        g_y.copy_from_slice(&g_y_ct2[..KEY_LEN_32]);
        let ciphertext_2 = &g_y_ct2[KEY_LEN_32..];

        // Compute shared secret G_XY (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_y);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.g_y = g_y;
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse (RFC 9528 freshness).

        let result = (|| {
            if g_xy.as_bytes() == &[0; KEY_LEN_32] {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(&self.state.g_y, &self.state.msg1)?;

            // PRK_2e = HKDF-Extract(TH_2, G_XY)
            self.state
                .prk_2e
                .copy_from_slice(&hkdf_extract(&self.state.th_2, g_xy.as_bytes())[..]);
            drop(g_xy);

            // Decrypt CIPHERTEXT_2 with KEYSTREAM_2
            let keystream_2 =
                edhoc_kdf(&self.state.prk_2e, &self.state.th_2, "KEYSTREAM_2", &[], ciphertext_2.len())?;
            let mut plaintext_2 = SecretVec::<128>::new();
            for (i, &b) in ciphertext_2.iter().enumerate() {
                plaintext_2.push_err(b ^ keystream_2[i])?;
            }

            // PRK_3e2m = PRK_2e for SIGN_SIGN method
            self.state.prk_3e2m = self.state.prk_2e;

            let pt2 = plaintext_2.as_slice();
            let (c_r, c_r_len) = parse_identifier(pt2)?;
            if c_r == self.c_i {
                return Err(EdhocError::InvalidMessage);
            }
            let (id_cred_r, id_len) = parse_id_cred(&pt2[c_r_len..])?;
            let sig_offset = c_r_len + id_len;
            let (signature_bytes, sig_len) = parse_bstr(&pt2[sig_offset..])?;
            if signature_bytes.len() != SIG_LEN || sig_offset + sig_len != pt2.len() {
                return Err(EdhocError::InvalidMessage);
            }

            let mut plaintext = heapless::Vec::new();
            plaintext.extend_err(pt2)?;
            self.state.lifecycle = Lifecycle::PendingMessage2;
            Ok(PendingMessage2 {
                id_cred: id_cred_r,
                plaintext,
                c_r,
                signature_offset: sig_offset,
                transcript_binding: self.state.th_2,
            })
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Verify a pending Message 2 and create Message 3 with the selected credential.
    pub fn finish_process_message_2(
        &mut self,
        pending: &PendingMessage2,
        peer: PeerCredential<'_>,
    ) -> Result<heapless::Vec<u8, 128>, EdhocError> {
        if self.state.lifecycle != Lifecycle::PendingMessage2
            || pending.transcript_binding != self.state.th_2
        {
            return Err(EdhocError::InvalidState);
        }
        if peer.id_cred != pending.id_cred.as_bytes() {
            return Err(EdhocError::SignatureVerification);
        }

        let result = (|| {
            validate_peer_credential(peer)?;
            let signature_bytes = parse_bstr(&pending.plaintext[pending.signature_offset..])?.0;
            let context_2 = build_context_2(
                &pending.c_r,
                pending.id_cred.as_bytes(),
                &self.state.th_2,
                peer.credential,
            )?;
            let mac_2 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_2, "MAC_2", &context_2, 32)?;
            let m_2 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_2,
                peer.credential,
                &mac_2,
            )?;

            // Verify Signature_2
            let peer_verifying_key = strong_verifying_key(peer.public_key)?;
            let signature_2 = Signature::from_bytes(
                signature_bytes
                    .try_into()
                    .map_err(|_| EdhocError::InvalidMessage)?,
            );
            peer_verifying_key
                .verify_strict(&m_2, &signature_2)
                .map_err(|_| EdhocError::SignatureVerification)?;

            self.state.c_r = pending.c_r.clone();
            self.state.th_3 = transcript_3(&self.state.th_2, &pending.plaintext, peer.credential)?;

            // PRK_4e3m = PRK_3e2m for SIGN_SIGN
            self.state.prk_4e3m = self.state.prk_3e2m;

            let mut credential_i = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_i, self.pubkey.as_bytes())?;
            let mut id_cred_i = heapless::Vec::<u8, 40>::new();
            encode_id_cred(&mut id_cred_i, self.pubkey.as_bytes())?;
            let context_3 = build_context_3(&id_cred_i, &self.state.th_3, &credential_i)?;
            let mac_3 = edhoc_kdf(&self.state.prk_4e3m, &self.state.th_3, "MAC_3", &context_3, 32)?;
            let m_3 =
                build_signature_structure(&id_cred_i, &self.state.th_3, &credential_i, &mac_3)?;
            let signature_3 = self.signing_key.sign(&m_3);
            let mut ciphertext_3 = SecretVec::<128>::new();
            encode_bstr(&mut ciphertext_3, self.pubkey.as_bytes())?;
            encode_bstr(&mut ciphertext_3, &signature_3.to_bytes())?;
            self.state.th_4 = transcript_4(&self.state.th_3, &ciphertext_3, &credential_i)?;

            // K_3 and IV_3 for AEAD
            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "IV_3", &[], NONCE_LEN)?;

            // A_3 (AAD) - simplified Encrypt0 structure
            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?; // array of 3
            a_3.push_err(0x68)?; // tstr "Encrypt0"
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?; // empty bstr
            a_3.push_err(0x58)?; // bstr TH_3
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

            // Encrypt in place (PLAINTEXT_3 -> CIPHERTEXT_3)
            let cipher = AesCcm::new_from_slice(&k_3).map_err(|_| EdhocError::InvalidState)?;
            let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
            nonce.copy_from_slice(&iv_3);
            let tag = cipher
                .encrypt_in_place_detached((&*nonce).into(), &a_3, &mut ciphertext_3)
                .map_err(|_| EdhocError::InvalidState)?;
            ciphertext_3.extend_err(&tag)?;

            self.state.lifecycle = Lifecycle::Complete;
            let mut msg3 = heapless::Vec::new();
            encode_bstr(&mut msg3, &ciphertext_3)?;
            Ok(msg3)
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Export OSCORE security context.
    ///
    /// # Errors
    /// Returns `OscoreError::NoContext` if called before handshake completes
    /// (i.e., before `process_message_2` succeeds).
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        // Use dedicated exporter for full master_secret/salt derivation + new_fresh.
        // IDs: local c_i as sender_id for initiator context.
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_i.as_bytes(),
            self.c_r.as_bytes(),
        )
    }
}

/// EDHOC Responder (server role).
// SECURITY: SigningKey and StaticSecret must be zeroized on drop.
// SigningKey and StaticSecret implement ZeroizeOnDrop themselves.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EdhocResponder {
    /// Our Ed25519 signing key (implements ZeroizeOnDrop).
    #[zeroize(skip)]
    signing_key: SigningKey,
    /// Our Ed25519 public key.
    #[zeroize(skip)]
    pubkey: VerifyingKey,
    /// Our connection identifier.
    c_r: u8,
    /// Ephemeral X25519 secret (implements ZeroizeOnDrop).
    #[zeroize(skip)]
    eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
    #[zeroize(skip)]
    eph_public: PublicKey,
    /// Protocol state.
    state: ResponderState,
}

/// Responder protocol state.
///
/// Contains PRK secrets that must be zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ResponderState {
    #[zeroize(skip)]
    msg1: heapless::Vec<u8, 64>,
    g_x: [u8; 32],
    #[zeroize(skip)]
    c_i: ConnectionId,
    prk_2e: [u8; 32],
    prk_3e2m: [u8; 32],
    prk_4e3m: [u8; 32],
    th_2: [u8; 32],
    th_3: [u8; 32],
    th_4: [u8; 32],
    /// True when handshake completed (process_message_3 succeeded).
    completed: bool,
}

impl Default for ResponderState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_x: [0; 32],
            c_i: ConnectionId::new(&[]).expect("empty connection ID fits"),
            prk_2e: [0; 32],
            prk_3e2m: [0; 32],
            prk_4e3m: [0; 32],
            th_2: [0; 32],
            th_3: [0; 32],
            th_4: [0; 32],
            completed: false,
        }
    }
}

impl Zeroize for EdhocResponder {
    fn zeroize(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Zeroized;
    }
}

impl EdhocResponder {
    /// Create a new EDHOC responder.
    ///
    /// # Arguments
    /// * `seed` - Ed25519 seed (32 bytes)
    /// * `c_r` - Connection identifier (1 byte)
    /// * `rng` - RNG implementing RngCore + CryptoRng for ephemeral key
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_r: u8, rng: &mut R) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            signing_key,
            pubkey,
            c_r: c_r.into(),
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        })
    }

    /// Create a new EDHOC responder.
    #[cfg(feature = "std")]
    pub fn new<C: Into<ConnectionId>>(seed: [u8; 32], c_r: C) -> Result<Self, OscoreError> {
        Self::new_with_rng(seed, c_r, &mut rand_core::OsRng)
    }

    fn poison(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0; KEY_LEN_32]);
        self.eph_secret.zeroize();
        self.state.zeroize();
        self.state.lifecycle = Lifecycle::Failed;
    }

    /// Process EDHOC Message 1 and create Message 2.
    pub fn process_message_1(&mut self, msg1: &[u8]) -> Result<heapless::Vec<u8, 160>, EdhocError> {
        if self.state.lifecycle != Lifecycle::Created || self.eph_secret.is_none() {
            return Err(EdhocError::InvalidState);
        }

        let mut stored_msg1 = heapless::Vec::<u8, 64>::new();
        stored_msg1.extend_err(msg1)?;

        // Parse message_1 = (METHOD, SUITES_I, G_X, C_I, ? EAD_1).
        if msg1.len() < 37 {
            return Err(EdhocError::InvalidMessage);
        }

        if msg1[0] != 1 {
            return Err(EdhocError::InvalidMessage);
        }

        // Parse SUITES_I per RFC 9528 Section 3.3.2:
        // - Single int: the selected suite
        // - Array of ints: [selected_suite, ...other_supported_suites]
        let (selected_suite, suites_i_end) = parse_suites_i(&msg1[1..])?;

        if selected_suite != SUITE_0 {
            return Err(EdhocError::UnsupportedSuite);
        }

        // Parse G_X (32-byte bstr) - starts after METHOD_CORR + SUITES_I
        let g_x_start = 1 + suites_i_end;
        if msg1.len() < g_x_start + 2 + 32 + 1 {
            return Err(EdhocError::InvalidMessage);
        }
        if msg1[g_x_start] != 0x58 || msg1[g_x_start + 1] != 32 {
            return Err(EdhocError::InvalidMessage);
        }
        self.state
            .g_x
            .copy_from_slice(&msg1[g_x_start + 2..g_x_start + 2 + 32]);

        // Parse C_I
        let rest = &msg1[g_x_start + 2 + 32..];
        self.state.c_i = if !rest.is_empty() {
            if rest[0] <= 23 {
                rest[0]
            } else if rest[0] == 0x41 && rest.len() > 1 {
                rest[1]
            } else {
                return Err(EdhocError::InvalidMessage);
            }
        } else {
            return Err(EdhocError::InvalidMessage);
        }
        if c_i == self.c_r {
            self.poison();
            return Err(EdhocError::InvalidMessage);
        }

        // Compute shared secret (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_x);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.msg1 = stored_msg1;
        self.state.g_x = g_x;
        self.state.c_i = c_i;
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse if this function
        // is called multiple times (e.g., due to retransmission handling bugs).

        let result = (|| {
            if g_xy.as_bytes() == &[0; KEY_LEN_32] {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(self.eph_public.as_bytes(), msg1)?;

            // PRK_2e = HKDF-Extract(TH_2, G_XY)
            self.state
                .prk_2e
                .copy_from_slice(&hkdf_extract(&self.state.th_2, g_xy.as_bytes())[..]);
            drop(g_xy);

            // PRK_3e2m = PRK_2e for SIGN_SIGN
            self.state.prk_3e2m = self.state.prk_2e;

        // Compute MAC_2 for signature
        // context_2 = << ID_CRED_R, CRED_R >> per RFC 9528 Section 4.3.2
        let mut context_2 = heapless::Vec::<u8, 128>::new();
        context_2.push_err(0x58)?;
        context_2.push_err(32)?;
        context_2.extend_err(self.pubkey.as_bytes())?; // ID_CRED_R
        context_2.push_err(0x58)?;
        context_2.push_err(32)?;
        context_2.extend_err(self.pubkey.as_bytes())?; // CRED_R
        let mac_2 = edhoc_kdf(
            &self.state.prk_3e2m,
            &self.state.th_2,
            "MAC_2",
            &context_2,
            8,
        )?;

            let mut plaintext_2 = SecretVec::<128>::new();
            encode_identifier(&mut plaintext_2, &self.c_r)?;
            encode_bstr(&mut plaintext_2, self.pubkey.as_bytes())?;
            encode_bstr(&mut plaintext_2, &signature_2.to_bytes())?;

            // Encrypt with KEYSTREAM_2
            let keystream_2 =
                edhoc_kdf(&self.state.prk_2e, &self.state.th_2, "KEYSTREAM_2", &[], plaintext_2.len())?;
            let mut ciphertext_2 = heapless::Vec::<u8, 128>::new();
            for (i, &b) in plaintext_2.iter().enumerate() {
                ciphertext_2.push_err(b ^ keystream_2[i])?;
            }

            self.state.th_3 = transcript_3(&self.state.th_2, &plaintext_2, &credential_r)?;

            let mut msg2 = heapless::Vec::<u8, 160>::new();
            let mut g_y_ciphertext = heapless::Vec::<u8, 144>::new();
            g_y_ciphertext.extend_err(self.eph_public.as_bytes())?;
            g_y_ciphertext.extend_err(&ciphertext_2)?;
            encode_bstr(&mut msg2, &g_y_ciphertext)?;

            self.state.lifecycle = Lifecycle::AwaitingMessage3;
            Ok(msg2)
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Process EDHOC Message 3.
    pub fn process_message_3(
        &mut self,
        msg3: &[u8],
        peer_pubkey: &[u8; 32],
    ) -> Result<(), EdhocError> {
        let (id_cred, credential) = raw_key_credential(peer_pubkey)?;
        self.process_message_3_with_credential(
            msg3,
            PeerCredential::new(peer_pubkey, &id_cred, &credential),
        )
    }

    /// Process Message 3 using application-validated peer authentication material.
    pub fn process_message_3_with_credential(
        &mut self,
        msg3: &[u8],
        peer: PeerCredential<'_>,
    ) -> Result<(), EdhocError> {
        let pending = self.begin_process_message_3(msg3)?;
        self.finish_process_message_3(&pending, peer)
    }

    /// Authenticate-decrypt and parse Message 3 before credential selection.
    pub fn begin_process_message_3(&mut self, msg3: &[u8]) -> Result<PendingMessage3, EdhocError> {
        if self.state.lifecycle != Lifecycle::AwaitingMessage3 {
            return Err(EdhocError::InvalidState);
        }

        let result = (|| {
            let (ciphertext_3, consumed) = parse_bstr(msg3)?;
            if consumed != msg3.len() {
                return Err(EdhocError::InvalidMessage);
            }

            // K_3 and IV_3 for AEAD decryption
            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "IV_3", &[], NONCE_LEN)?;

            // A_3 (AAD)
            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?;
            a_3.push_err(0x68)?;
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?;
            a_3.push_err(0x58)?;
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

            // Decrypt CIPHERTEXT_3
            if ciphertext_3.len() < TAG_LEN {
                return Err(EdhocError::InvalidMessage);
            }
            let tag_start = ciphertext_3.len() - TAG_LEN;
            let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext_3[tag_start..]);
            let cipher = AesCcm::new_from_slice(&k_3).map_err(|_| EdhocError::InvalidState)?;
            let mut plaintext_3 = SecretVec::<128>::new();
            plaintext_3.extend_err(&ciphertext_3[..tag_start])?;
            let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
            nonce.copy_from_slice(&iv_3);
            cipher
                .decrypt_in_place_detached((&*nonce).into(), &a_3, &mut plaintext_3, tag)
                .map_err(|_| EdhocError::DecryptFailed)?;

            let (id_cred_i, id_len) = parse_id_cred(&plaintext_3)?;
            let (sig_bytes, sig_len) = parse_bstr(&plaintext_3[id_len..])?;
            if sig_bytes.len() != SIG_LEN || id_len + sig_len != plaintext_3.len() {
                return Err(EdhocError::InvalidMessage);
            }

            let mut plaintext = heapless::Vec::new();
            plaintext.extend_err(&plaintext_3)?;
            self.state.lifecycle = Lifecycle::PendingMessage3;
            Ok(PendingMessage3 {
                id_cred: id_cred_i,
                plaintext,
                signature_offset: id_len,
                transcript_binding: self.state.th_3,
            })
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Verify a pending Message 3 with the selected peer credential.
    pub fn finish_process_message_3(
        &mut self,
        pending: &PendingMessage3,
        peer: PeerCredential<'_>,
    ) -> Result<(), EdhocError> {
        if self.state.lifecycle != Lifecycle::PendingMessage3
            || pending.transcript_binding != self.state.th_3
        {
            return Err(EdhocError::InvalidState);
        }
        if peer.id_cred != pending.id_cred.as_bytes() {
            return Err(EdhocError::SignatureVerification);
        }

        let result = (|| {
            validate_peer_credential(peer)?;
            let sig_bytes = parse_bstr(&pending.plaintext[pending.signature_offset..])?.0;
            let signature = Signature::from_bytes(
                sig_bytes
                    .try_into()
                    .map_err(|_| EdhocError::InvalidMessage)?,
            );
            let peer_verifying_key = strong_verifying_key(peer.public_key)?;

            self.state.prk_4e3m = self.state.prk_3e2m;
            let context_3 = build_context_3(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
            )?;
            let mac_3 = edhoc_kdf(&self.state.prk_4e3m, &self.state.th_3, "MAC_3", &context_3, 32)?;
            let m_3 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
                &mac_3,
            )?;

            peer_verifying_key
                .verify_strict(&m_3, &signature)
                .map_err(|_| EdhocError::SignatureVerification)?;

            self.state.th_4 = transcript_4(&self.state.th_3, &pending.plaintext, peer.credential)?;
            self.state.lifecycle = Lifecycle::Complete;

            Ok(())
        })();

        if result.is_err() {
            self.poison();
        }

        let sig_start = 2 + 32 + 2;
        let sig_bytes = &plaintext_3[sig_start..sig_start + 64];
        let signature = Signature::from_bytes(
            sig_bytes
                .try_into()
                .map_err(|_| EdhocError::InvalidMessage)?,
        );

        // Build M_3 for verification
        let mut m_3 = heapless::Vec::<u8, 128>::new();
        m_3.push_err(0x83)?;
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(peer_pubkey)?;
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(&self.state.th_3)?;
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(peer_pubkey)?;

        peer_verifying_key
            .verify(&m_3, &signature)
            .map_err(|_| EdhocError::SignatureVerification)?;

        // PRK_4e3m = PRK_3e2m for SIGN_SIGN
        self.state.prk_4e3m = self.state.prk_3e2m;

        // TH_4 = H(TH_3, CIPHERTEXT_3)
        let mut th_4_input = heapless::Vec::<u8, 192>::new();
        th_4_input.push_err(0x58)?;
        th_4_input.push_err(32)?;
        th_4_input.extend_err(&self.state.th_3)?;
        if ciphertext_3.len() <= 23 {
            th_4_input.push_err(0x40 | ciphertext_3.len() as u8)?;
        } else {
            th_4_input.push_err(0x58)?;
            th_4_input.push_err(ciphertext_3.len() as u8)?;
        }
        th_4_input.extend_err(ciphertext_3)?;
        self.state.th_4 = compute_th(&th_4_input);

        // Mark handshake as completed - export_oscore now safe to call
        self.state.completed = true;

        Ok(())
    }

    /// Export OSCORE security context.
    ///
    /// # Errors
    /// Returns `OscoreError::NoContext` if called before handshake completes
    /// (i.e., before `process_message_3` succeeds).
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        // Use dedicated exporter for full master_secret/salt derivation + new_fresh.
        // IDs: local c_r as sender_id for responder context.
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_r.as_bytes(),
            self.c_i.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextId, SenderSequenceState, SenderStateStore};
    use core::num::NonZeroU32;
    use hex_literal::hex;

    #[test]
    fn crypto_schedules_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Aes128>();
        assert_zeroize_on_drop::<Sha256>();
    }

    struct TestStore {
        context_id: ContextId,
        state: Option<SenderSequenceState>,
    }

    impl TestStore {
        fn empty_for(context: &Context) -> Self {
            Self {
                context_id: context.context_id(),
                state: None,
            }
        }
    }

    impl SenderStateStore for TestStore {
        type Error = core::convert::Infallible;

        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok((*context_id == self.context_id)
                .then_some(self.state)
                .flatten())
        }

        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            if *context_id != self.context_id || expected != self.state {
                return Ok(false);
            }
            self.state = Some(next);
            Ok(true)
        }
    }

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    struct FixedRng([u8; 32]);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            panic!("fixed RNG only supports try_fill_bytes")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("fixed RNG only supports try_fill_bytes")
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0[..dest.len()]);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    struct FailingRng;

    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            panic!("constructor must use try_fill_bytes")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("constructor must use try_fill_bytes")
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("constructor must use try_fill_bytes")
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::from(
                NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ))
        }
    }

    impl CryptoRng for FailingRng {}

    fn initiator(seed: [u8; 32], c_i: u8) -> EdhocInitiator {
        EdhocInitiator::new_with_rng(seed, c_i, &mut TestRng(1)).unwrap()
    }

    fn responder(seed: [u8; 32], c_r: u8) -> EdhocResponder {
        EdhocResponder::new_with_rng(seed, c_r, &mut TestRng(2)).unwrap()
    }

    #[test]
    fn embedded_constructors_accept_injected_rng() {
        fn construct<R: RngCore + CryptoRng>(rng: &mut R) {
            let _ = EdhocInitiator::new_with_rng([1; 32], 0, rng).unwrap();
            let _ = EdhocResponder::new_with_rng([2; 32], 1, rng).unwrap();
        }

        construct(&mut TestRng(3));
    }

    #[cfg(feature = "std")]
    #[test]
    fn std_convenience_constructors_remain_available() {
        let _ = EdhocInitiator::new([1; 32], 0).unwrap();
        let _ = EdhocResponder::new([2; 32], 1).unwrap();
    }

    #[test]
    fn constructors_propagate_entropy_failure() {
        assert!(matches!(
            EdhocInitiator::new_with_rng([1; 32], 0, &mut FailingRng),
            Err(OscoreError::KeyDerivation)
        ));
        assert!(matches!(
            EdhocResponder::new_with_rng([2; 32], 1, &mut FailingRng),
            Err(OscoreError::KeyDerivation)
        ));
    }

    #[test]
    fn test_initiator_creation() {
        let seed = [0x01u8; 32];
        let mut rng = rand_core::OsRng;
        let initiator = EdhocInitiator::new(seed, 0x00, &mut rng);
        assert_eq!(initiator.c_i, 0x00);
    }

    #[test]
    fn test_responder_creation() {
        let seed = [0x01u8; 32];
        let mut rng = rand_core::OsRng;
        let responder = EdhocResponder::new(seed, 0x01, &mut rng);
        assert_eq!(responder.c_r, 0x01);
    }

    #[test]
    fn test_message_1_creation() {
        let seed = [0x01u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(seed, 0x05, &mut rng);
        let msg1 = initiator.create_message_1().unwrap();

        // Check basic structure: METHOD, SUITE, G_X, C_I
        assert_eq!(msg1[0], 0); // METHOD = SIGN/SIGN
        assert_eq!(msg1[1], 0); // Suite 0
        assert_eq!(msg1[2], 0x58); // bstr marker
        assert_eq!(msg1[3], 32); // G_X length
                                 // msg1[4..36] is G_X
        assert_eq!(msg1[36], 5); // C_I
    }

    #[test]
    fn rfc9529_signature_trace_vectors() {
        let x = hex!("892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
        let mut initiator = EdhocInitiator::new_with_rng([0; 32], 0x2d, &mut FixedRng(x)).unwrap();
        let message_1 =
            hex!("0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
        assert_eq!(initiator.create_message_1().unwrap().as_slice(), message_1);

        let g_y = hex!("dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
        let th_2 = hex!("c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d");
        assert_eq!(transcript_2(&g_y, &message_1).unwrap(), th_2);

        let prk_2e = hex!("d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
        let keystream_2 = hex!(
            "fd3e7c3f2d6bee643d3c9d2f2847035d73e2ecb0f8db5cd1c6854e24896af21188b2c4344e689ec2984283d9fbc69ce1c5db10dcfff24df9a49a04a94058277bc7fa9ad6c6b194ab328b445eb080490cd786"
        );
        assert_eq!(
            edhoc_kdf(&prk_2e, &th_2, "KEYSTREAM_2", &[], 82).unwrap().as_slice(),
            keystream_2
        );

        let message_2 = hex!(
            "5872dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1cbc26dd270fe9c02c44ce3934794b1cc62ba22f05459f8d358c8d12275ac42c5f96ded5f13cc9084e5b201889a45e5a60a5562dc118619c3daa2fd9f4c9f4d6edad109dd4edf95962aafbaf9ab3f4a1f6b98f"
        );
        let (g_y_ciphertext, consumed) = parse_bstr(&message_2).unwrap();
        assert_eq!(consumed, message_2.len());
        assert_eq!(&g_y_ciphertext[..32], &g_y);

        let plaintext_2 = hex!(
            "4118a11822822e4879f2a41b510c1f9b5840c3b5bd44d1e44a085c03d3aede4e1e6c11c572a1968cc3629b505f98c681608d3d1de793d1c40eb5dd5d89acf1966aea07022b48cdc99870ebc40374e8fa6e09"
        );
        let credential_r = hex!(
            "58f13081ee3081a1a003020102020462319ec4300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323433365a170d3239313233313233303030305a30223120301e06035504030c174544484f4320526573706f6e6465722045643235353139302a300506032b6570032100a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359300506032b6570034100b723bc01eab0928e8b2b6c98de19cc3823d46e7d6987b032478fecfaf14537a1af14cc8be829c6b73044101837eb4abc949565d86dce51cfae52ab82c152cb02"
        );
        let th_3 = hex!("5b7df9b4f58f240ce0418e48191b5fff3a22b5ca57f669b16777996592e928bc");
        assert_eq!(
            transcript_3(&th_2, &plaintext_2, &credential_r).unwrap(),
            th_3
        );

        let message_3 = hex!(
            "585825c345884aaaeb22c527f9b1d2b6787207e0163c69b62a0d43928150427203c31674e4514ea6e383b566eb29763efeb0afa518776ae1c65f856d84bf32af3a7836970466dcb71f76745d39d3025e7703e0c032ebad51947c"
        );
        let (ciphertext_3, consumed) = parse_bstr(&message_3).unwrap();
        assert_eq!(consumed, message_3.len());
        assert_eq!(ciphertext_3.len(), 88);

        let plaintext_3 = hex!(
            "a11822822e48c24ab2fd7643c79f584096e1cd5fceadfac1b5af819443f70924f5719955957fd02655beb4775e1a73186a0d1d3ea683f08f8d03dcecb9cf154e1c6f555a1e12ca118ce42bdba6878907"
        );
        let credential_i = hex!(
            "58f13081ee3081a1a003020102020462319ea0300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323430305a170d3239313233313233303030305a30223120301e06035504030c174544484f4320496e69746961746f722045643235353139302a300506032b6570032100ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e300506032b6570034100521241d8b3a770996bcfc9b9ead4e7e0a1c0db353a3bdf2910b39275ae48b756015981850d27db6734e37f67212267dd05eeff27b9e7a813fa574b72a00b430b"
        );
        let th_4 = hex!("0eb868f263cf3555dccd396dd8dec29d3750d599be42d5a41a5a37c896f294ac");
        assert_eq!(
            transcript_4(&th_3, &plaintext_3, &credential_i).unwrap(),
            th_4
        );

        let responder_public_key =
            hex!("a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
        let id_cred_r = hex!("a11822822e4879f2a41b510c1f9b");
        let mut verifier = EdhocInitiator::new_with_rng(
            hex!("4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8"),
            0x2d,
            &mut FixedRng(x),
        )
        .unwrap();
        assert_eq!(verifier.create_message_1().unwrap().as_slice(), message_1);
        let verified_message_3 = verifier.process_message_2_with_credential(
            &message_2,
            PeerCredential::new(&responder_public_key, &id_cred_r, &credential_r),
        );
        assert!(
            verified_message_3.is_ok(),
            "RFC 9529 Message 2 failed: {verified_message_3:?}"
        );

        let prk_out = hex!("b744cb7d8a87cc0447c3350e165b250dab12ec453325abb922b30307e5c368f0");
        assert_eq!(
            edhoc_kdf(&prk_2e, &th_4, "PRK_out", &[], 32).unwrap().as_slice(),
            prk_out
        );
        let prk_exporter = hex!("2aaec8fc4ab3bc3295def6b551051a2fa561424db301fa84f642f5578a6df51a");
        assert_eq!(
            edhoc_kdf(&prk_out, &th_4, "exporter", &[], 32).unwrap().as_slice(),
            prk_exporter
        );
        assert_eq!(
            edhoc_kdf(&prk_exporter, &th_4, "OSCORE_Master_Secret", &[], 16).unwrap().as_slice(),
            &hex!("1e1c6beac3a8a1cac435de7e2f9ae7ff")
        );
        assert_eq!(
            edhoc_kdf(&prk_exporter, &th_4, "OSCORE_Master_Salt", &[], 8).unwrap().as_slice(),
            &hex!("ce7ab844c0106d73")
        );

        let context = export_context(&prk_2e, &th_4, &[0x18], &[0x2d]).unwrap();
        assert_eq!(context.sender_id(), &[0x18]);
        assert_eq!(context.recipient_id(), &[0x2d]);
    }

    #[test]
    fn identifiers_use_rfc9528_canonical_encoding() {
        for (raw, encoded) in [
            (&[0x0d][..], &[0x0d][..]),
            (&[0x21][..], &[0x21][..]),
            (&[0x18][..], &[0x41, 0x18][..]),
            (&[0x38][..], &[0x41, 0x38][..]),
            (&[][..], &[0x40][..]),
            (&[0xaa, 0xbb][..], &[0x42, 0xaa, 0xbb][..]),
        ] {
            let id = ConnectionId::new(raw).unwrap();
            let mut output = heapless::Vec::<u8, 8>::new();
            encode_identifier(&mut output, &id).unwrap();
            assert_eq!(output.as_slice(), encoded);
            let (parsed, consumed) = parse_identifier(encoded).unwrap();
            assert_eq!(parsed.as_bytes(), raw);
            assert_eq!(consumed, encoded.len());
        }
        assert_eq!(
            parse_identifier(&[0x41, 0x0d]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(
            parse_identifier(&[0x18, 0x0d]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(ConnectionId::new(&[0; 8]), Err(EdhocError::BufferTooSmall));
    }

    #[test]
    fn id_cred_accepts_compact_kid_and_rfc9529_x5t() {
        for (wire, canonical) in [
            (&[0x2d][..], &[0xa1, 0x04, 0x41, 0x2d][..]),
            (&[0x42, 0xaa, 0xbb][..], &[0xa1, 0x04, 0x42, 0xaa, 0xbb][..]),
            (
                &hex!("a11822822e4879f2a41b510c1f9b")[..],
                &hex!("a11822822e4879f2a41b510c1f9b")[..],
            ),
        ] {
            let (parsed, consumed) = parse_id_cred(wire).unwrap();
            assert_eq!(parsed.as_bytes(), canonical);
            assert_eq!(consumed, wire.len());
        }

        assert_eq!(
            parse_id_cred(&hex!("a11822812e")),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(
            parse_id_cred(&[0xa1, 0x04, 0x2d]),
            Err(EdhocError::InvalidMessage)
        );
    }

    #[test]
    fn id_cred_preserves_multi_parameter_maps_and_identifies_references() {
        let kid = hex!("a301270281040442aabb");
        let (parsed, consumed) = parse_id_cred(&kid).unwrap();
        assert_eq!(consumed, kid.len());
        assert_eq!(parsed.as_bytes(), kid);
        assert_eq!(
            parsed.reference(),
            &IdCredReference::Kid(copy_id_cred_value(&[0xaa, 0xbb]).unwrap())
        );

        let text_parameter = hex!("a20441aa63666f6f01");
        let (parsed, consumed) = parse_id_cred(&text_parameter).unwrap();
        assert_eq!(consumed, text_parameter.len());
        assert_eq!(parsed.as_bytes(), text_parameter);

        let x5t = hex!("a201271822822e481122334455667788");
        let (parsed, consumed) = parse_id_cred(&x5t).unwrap();
        assert_eq!(consumed, x5t.len());
        assert_eq!(parsed.as_bytes(), x5t);
        assert_eq!(
            parsed.reference(),
            &IdCredReference::X5t {
                algorithm: -15,
                hash: copy_id_cred_value(&hex!("1122334455667788")).unwrap(),
            }
        );
    }

    #[test]
    fn id_cred_rejects_duplicate_noncanonical_and_ambiguous_headers() {
        for malformed in [
            &hex!("a20441aa0441bb")[..],
            &hex!("a2180441aa0127")[..],
            &hex!("a2045801aa0127")[..],
            &hex!("a301270281010441aa")[..],
            &hex!("a2028118220441aa")[..],
            &hex!("a2028204040441aa")[..],
            &hex!("a20441aa1822822e481122334455667788")[..],
            &hex!("a10127")[..],
            &hex!("a20441aa01")[..],
            &hex!("a20441aa")[..],
            &hex!("a90441aa")[..],
        ] {
            assert_eq!(
                parse_id_cred(malformed),
                Err(EdhocError::InvalidMessage),
                "accepted malformed ID_CRED {malformed:02x?}"
            );
        }
    }

    #[test]
    fn id_cred_accepts_sorted_and_unsorted_literal_maps() {
        let sorted = hex!("a301270281040442aabb");
        let unsorted = hex!("a30442aabb0281040127");
        let (sorted_id, sorted_len) = parse_id_cred(&sorted).unwrap();
        let (unsorted_id, unsorted_len) = parse_id_cred(&unsorted).unwrap();

        assert_eq!(sorted_len, sorted.len());
        assert_eq!(unsorted_len, unsorted.len());
        assert_eq!(sorted_id.reference(), unsorted_id.reference());
        assert_eq!(sorted_id.as_bytes(), sorted);
        assert_eq!(unsorted_id.as_bytes(), unsorted);

        assert_eq!(
            parse_id_cred(&hex!("a30441aa01270441bb")),
            Err(EdhocError::InvalidMessage)
        );
    }

    #[test]
    fn general_map_keys_use_bytewise_lexicographic_order() {
        assert!(validate_deterministic_item(&hex!("a21818006000")).is_ok());
        assert_eq!(
            validate_deterministic_item(&hex!("a26000181800")),
            Err(EdhocError::InvalidMessage)
        );
    }

    #[test]
    fn id_cred_rejects_encoded_capacity_overflow() {
        let mut oversized = heapless::Vec::<u8, 65>::new();
        oversized
            .extend_from_slice(&[0xa1, 0x04, 0x58, 61])
            .unwrap();
        oversized.resize(65, 0).unwrap();
        assert_eq!(parse_id_cred(&oversized), Err(EdhocError::BufferTooSmall));
    }

    #[test]
    fn pending_messages_expose_id_cred_before_retryable_credential_selection() {
        let mut initiator = initiator([0x11; 32], 0);
        let mut responder = responder([0x22; 32], 1);
        let initiator_key = initiator.pubkey.to_bytes();
        let responder_key = responder.pubkey.to_bytes();
        let wrong_key = SigningKey::from_bytes(&[0x33; 32])
            .verifying_key()
            .to_bytes();
        let (wrong_id, wrong_credential) = raw_key_credential(&wrong_key).unwrap();
        let (responder_id, responder_credential) = raw_key_credential(&responder_key).unwrap();
        let (initiator_id, initiator_credential) = raw_key_credential(&initiator_key).unwrap();

        assert_eq!(
            responder.process_message_3(&[0], &initiator_key),
            Err(EdhocError::InvalidState)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Created);

        let message_1 = initiator.create_message_1().unwrap();
        let message_2 = responder.process_message_1(&message_1).unwrap();
        let pending_2 = initiator.begin_process_message_2(&message_2).unwrap();
        assert_eq!(pending_2.id_cred().as_bytes(), responder_id.as_slice());
        assert_eq!(
            initiator.finish_process_message_2(
                &pending_2,
                PeerCredential::new(&wrong_key, &wrong_id, &wrong_credential),
            ),
            Err(EdhocError::SignatureVerification)
        );
        assert_eq!(initiator.state.lifecycle, Lifecycle::PendingMessage2);
        let message_3 = initiator
            .finish_process_message_2(
                &pending_2,
                PeerCredential::new(&responder_key, &responder_id, &responder_credential),
            )
            .unwrap();

        let pending_3 = responder.begin_process_message_3(&message_3).unwrap();
        assert_eq!(pending_3.id_cred().as_bytes(), initiator_id.as_slice());
        assert_eq!(
            responder.finish_process_message_3(
                &pending_3,
                PeerCredential::new(&wrong_key, &wrong_id, &wrong_credential),
            ),
            Err(EdhocError::SignatureVerification)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::PendingMessage3);
        responder
            .finish_process_message_3(
                &pending_3,
                PeerCredential::new(&initiator_key, &initiator_id, &initiator_credential),
            )
            .unwrap();
        assert_eq!(responder.state.lifecycle, Lifecycle::Complete);
    }

    #[test]
    fn credentials_accept_bounded_deterministic_cbor_forms() {
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let (id_cred, ccs) = raw_key_credential(&public_key).unwrap();
        let mut multi_claim_ccs = heapless::Vec::<u8, 96>::new();
        multi_claim_ccs
            .extend_from_slice(&[0xa2, 0x01, 0x63])
            .unwrap();
        multi_claim_ccs.extend_from_slice(b"iss").unwrap();
        multi_claim_ccs.push(0x08).unwrap();
        multi_claim_ccs.extend_from_slice(&ccs[2..]).unwrap();
        validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &multi_claim_ccs))
            .unwrap();

        let mut cwt = heapless::Vec::<u8, 100>::new();
        cwt.extend_from_slice(&[0xd8, 0x3d]).unwrap();
        cwt.extend_from_slice(&multi_claim_ccs).unwrap();
        validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &cwt)).unwrap();

        let x5t = hex!("a11822822e4879f2a41b510c1f9b");
        for credential in [
            &hex!("820141aa")[..],
            &hex!("a201f564726f6c65646e6f6465")[..],
            &hex!("4401020304")[..],
        ] {
            validate_peer_credential(PeerCredential::new(&public_key, &x5t, credential)).unwrap();
        }
    }

    #[test]
    fn malformed_or_unbound_credentials_are_rejected() {
        for malformed in [
            &hex!("a202000100")[..],
            &hex!("a201000100")[..],
            &hex!("9f01ff")[..],
            &hex!("1800")[..],
            &hex!("61ff")[..],
            &hex!("0102")[..],
            &hex!("fa3f800000")[..],
        ] {
            assert_eq!(
                validate_deterministic_item(malformed),
                Err(EdhocError::InvalidMessage),
                "accepted malformed credential {malformed:02x?}"
            );
        }

        let too_deep = [0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x00];
        assert_eq!(
            validate_deterministic_item(&too_deep),
            Err(EdhocError::InvalidMessage)
        );
        let mut too_many = heapless::Vec::<u8, 66>::new();
        too_many.extend_from_slice(&[0x98, 0x40]).unwrap();
        too_many.resize(66, 0).unwrap();
        assert_eq!(
            validate_deterministic_item(&too_many),
            Err(EdhocError::InvalidMessage)
        );

        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let (id_cred, mut credential) = raw_key_credential(&public_key).unwrap();
        *credential.last_mut().unwrap() ^= 1;
        assert_eq!(
            validate_peer_credential(PeerCredential::new(&public_key, &id_cred, &credential,)),
            Err(EdhocError::SignatureVerification)
        );
    }

    #[test]
    fn weak_ed25519_keys_are_rejected_and_responder_is_poisoned() {
        let weak_key = [0; 32];
        let id_cred = hex!("a11822822e4879f2a41b510c1f9b");
        assert_eq!(
            validate_peer_credential(PeerCredential::new(&weak_key, &id_cred, &[0x40])),
            Err(EdhocError::SignatureVerification)
        );

        let mut initiator = initiator([0x11; 32], 0);
        let mut responder = responder([0x22; 32], 1);
        let responder_key = responder.pubkey.to_bytes();
        let message_1 = initiator.create_message_1().unwrap();
        let message_2 = responder.process_message_1(&message_1).unwrap();
        let message_3 = initiator
            .process_message_2(&message_2, &responder_key)
            .unwrap();
        let pending = responder.begin_process_message_3(&message_3).unwrap();
        let (_, weak_credential) = raw_key_credential(&weak_key).unwrap();
        assert_eq!(
            responder.finish_process_message_3(
                &pending,
                PeerCredential::new(&weak_key, pending.id_cred().as_bytes(), &weak_credential),
            ),
            Err(EdhocError::SignatureVerification)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
        assert_eq!(responder.signing_key.to_bytes(), [0; 32]);
    }

    #[test]
    fn equal_connection_ids_are_rejected_and_poisoned() {
        let mut equal_responder = responder([0x22; 32], 0);
        let mut equal_initiator = initiator([0x11; 32], 0);
        let message_1 = equal_initiator.create_message_1().unwrap();
        assert_eq!(
            equal_responder.process_message_1(&message_1),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(equal_responder.state.lifecycle, Lifecycle::Failed);
        assert!(equal_responder.eph_secret.is_none());

        let mut initiator = initiator([0x33; 32], 1);
        let mut responder = responder([0x44; 32], 0);
        let responder_key = responder.pubkey.to_bytes();
        let message_1 = initiator.create_message_1().unwrap();
        let message_2 = responder.process_message_1(&message_1).unwrap();
        initiator.c_i = ConnectionId::from(0);
        assert_eq!(
            initiator.process_message_2(&message_2, &responder_key),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);
        assert!(initiator.eph_secret.is_none());
    }

    #[test]
    fn rejects_unconfigured_ead_trailing_items_and_parses_suite_error() {
        let mut first_initiator = initiator([0x11; 32], 0);
        let mut message_1 = first_initiator.create_message_1().unwrap();
        message_1.push(0).unwrap();
        let mut first_responder = responder([0x22; 32], 1);
        assert_eq!(
            first_responder.process_message_1(&message_1),
            Err(EdhocError::InvalidMessage)
        );
        assert!(first_responder.eph_secret.is_some());

        assert_eq!(
            first_initiator.process_message_2(&[2, 0], &[0; 32]),
            Err(EdhocError::UnsupportedSuite)
        );
        assert_eq!(first_initiator.state.lifecycle, Lifecycle::Failed);
        assert!(first_initiator.eph_secret.is_none());

        let mut malformed_error_initiator = initiator([0x12; 32], 0);
        malformed_error_initiator.create_message_1().unwrap();
        assert_eq!(
            malformed_error_initiator.process_message_2(&[2, 0, 0], &[0; 32]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(malformed_error_initiator.state.lifecycle, Lifecycle::Failed);
        assert!(malformed_error_initiator.eph_secret.is_none());

        let mut initiator = initiator([0x33; 32], 0);
        let mut responder = responder([0x44; 32], 1);
        let message_1 = initiator.create_message_1().unwrap();
        let mut message_2 = responder.process_message_1(&message_1).unwrap();
        message_2.push(0).unwrap();
        assert_eq!(
            initiator.process_message_2(&message_2, &responder.pubkey.to_bytes()),
            Err(EdhocError::InvalidMessage)
        );
        assert!(initiator.eph_secret.is_some());
    }

    #[test]
    fn rfc9528_suites_i_literals() {
        assert_eq!(parse_suites_i(&[0x00, 0xff]), Ok((0, 1, false)));
        assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00, 0xff]), Ok((0, 3, false)));
        assert_eq!(parse_suites_i(&[0x82, 0x00, 0x00]), Ok((0, 3, true)));

        assert_eq!(
            parse_suites_i(&[0x81, 0x00]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(
            parse_suites_i(&[0x9f, 0x00, 0xff]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(
            parse_suites_i(&[0x82, 0x18]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(
            parse_suites_i(&[0x18, 0x00]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(parse_suites_i(&[0x1c]), Err(EdhocError::InvalidMessage));
        assert_eq!(
            parse_suites_i(&[0x82, 0x40, 0x00]),
            Err(EdhocError::InvalidMessage)
        );
    }

    #[test]
    fn suites_i_parses_every_signed_integer_width() {
        let suites = [
            0x8b, 0x17, 0x18, 0x18, 0x19, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x38, 0x18, 0x39, 0x01, 0x00, 0x3a,
            0x00, 0x01, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff,
        ];
        assert_eq!(parse_suites_i(&suites), Ok((0, suites.len() - 1, false)));
    }

    #[test]
    fn responder_applies_suite_selection_rules() {
        let seed = [0x01; 32];
        let mut message = [0u8; 40];
        message[0] = 0;
        message[1..4].copy_from_slice(&[0x82, 0x02, 0x00]);
        message[4..6].copy_from_slice(&[0x58, 32]);
        message[6..38].copy_from_slice(&hex!(
            "31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04"
        ));
        message[38] = 0;

        let result = responder(seed, 1).process_message_1(&message[..39]);
        assert!(result.is_ok(), "valid suite selection failed: {result:?}");

        message[2] = 0;
        assert_eq!(
            responder(seed, 1).process_message_1(&message[..39]),
            Err(EdhocError::UnsupportedSuite)
        );
    }

    #[test]
    fn export_requires_completed_exchange() {
        assert!(matches!(
            initiator([0x11; 32], 0).export_oscore(),
            Err(OscoreError::NoContext)
        ));
        assert!(matches!(
            responder([0x22; 32], 1).export_oscore(),
            Err(OscoreError::NoContext)
        ));

        let mut initiator = initiator([0x33; 32], 2);
        initiator.zeroize();
        assert_eq!(initiator.state.lifecycle, Lifecycle::Zeroized);
        assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));
        assert!(matches!(
            initiator.export_oscore(),
            Err(OscoreError::NoContext)
        ));
    }

    #[test]
    fn pre_dh_parse_failures_are_retryable() {
        let mut initiator = initiator([0x11; 32], 0);
        let mut responder = responder([0x22; 32], 1);
        let responder_pubkey = responder.pubkey.to_bytes();
        let msg1 = initiator.create_message_1().unwrap();

        assert_eq!(
            initiator.process_message_2(&[0], &responder_pubkey),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(initiator.state.lifecycle, Lifecycle::Message1Created);
        assert!(initiator.eph_secret.is_some());

        assert_eq!(
            responder.process_message_1(&[0]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Created);
        assert!(responder.eph_secret.is_some());

        let msg2 = responder.process_message_1(&msg1).unwrap();
        assert!(initiator
            .process_message_2(&msg2, &responder_pubkey)
            .is_ok());
    }

    #[test]
    fn initiator_post_dh_failure_wipes_and_poison_state() {
        let mut initiator = initiator([0x11; 32], 0);
        let peer_key = SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .to_bytes();
        initiator.create_message_1().unwrap();
        let mut msg2 = heapless::Vec::<u8, 40>::new();
        msg2.extend_from_slice(&[0x58, 33]).unwrap();
        msg2.extend_from_slice(&[7; KEY_LEN_32]).unwrap();
        msg2.push(0).unwrap();

        assert_eq!(
            initiator.process_message_2(&msg2, &peer_key),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);
        assert!(initiator.eph_secret.is_none());
        assert_eq!(initiator.signing_key.to_bytes(), [0; KEY_LEN_32]);
        assert_eq!(initiator.state.prk_2e, [0; KEY_LEN_32]);
        assert_eq!(initiator.state.prk_3e2m, [0; KEY_LEN_32]);
        assert_eq!(initiator.state.prk_4e3m, [0; KEY_LEN_32]);
        assert_eq!(initiator.state.th_2, [0; KEY_LEN_32]);
        assert_eq!(initiator.state.th_3, [0; KEY_LEN_32]);
        assert_eq!(initiator.state.th_4, [0; KEY_LEN_32]);
        assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));
        assert_eq!(
            initiator.process_message_2(&msg2, &[0; KEY_LEN_32]),
            Err(EdhocError::InvalidState)
        );
    }

    #[test]
    fn rejects_all_zero_x25519_shared_secret() {
        let mut initiator = initiator([0x11; 32], 0);
        initiator.create_message_1().unwrap();
        let mut message_2 = heapless::Vec::<u8, 40>::new();
        message_2.extend_from_slice(&[0x58, 33]).unwrap();
        message_2.extend_from_slice(&[0; 33]).unwrap();
        assert_eq!(
            initiator.process_message_2(&message_2, &[1; 32]),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(initiator.state.lifecycle, Lifecycle::Failed);

        let mut responder = responder([0x22; 32], 1);
        let mut message_1 = heapless::Vec::<u8, 40>::new();
        message_1.extend_from_slice(&[0, 0, 0x58, 32]).unwrap();
        message_1.extend_from_slice(&[0; 32]).unwrap();
        message_1.push(0).unwrap();
        assert_eq!(
            responder.process_message_1(&message_1),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
    }

    #[test]
    fn responder_post_dh_failure_wipes_and_poison_state() {
        let mut initiator = initiator([0x11; 32], 0);
        let mut responder = responder([0x22; 32], 1);
        let msg1 = initiator.create_message_1().unwrap();
        responder.process_message_1(&msg1).unwrap();

        assert_eq!(
            responder.process_message_3(&[0], &initiator.pubkey.to_bytes()),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
        assert!(responder.eph_secret.is_none());
        assert_eq!(responder.signing_key.to_bytes(), [0; KEY_LEN_32]);
        assert_eq!(responder.state.prk_2e, [0; KEY_LEN_32]);
        assert_eq!(responder.state.prk_3e2m, [0; KEY_LEN_32]);
        assert_eq!(responder.state.prk_4e3m, [0; KEY_LEN_32]);
        assert_eq!(responder.state.th_2, [0; KEY_LEN_32]);
        assert_eq!(responder.state.th_3, [0; KEY_LEN_32]);
        assert_eq!(responder.state.th_4, [0; KEY_LEN_32]);
        assert_eq!(
            responder.process_message_1(&msg1),
            Err(EdhocError::InvalidState)
        );
        assert_eq!(
            responder.process_message_3(&[0], &initiator.pubkey.to_bytes()),
            Err(EdhocError::InvalidState)
        );
    }

    /// Integration test: full EDHOC handshake with key verification.
    #[test]
    fn test_full_handshake() {
        // Create initiator and responder with different seeds
        let initiator_seed = [0x11u8; 32];
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        // Get public keys for verification
        let initiator_pubkey = initiator.pubkey.to_bytes();
        let responder_pubkey = responder.pubkey.to_bytes();

        // Step 1: Initiator creates Message 1
        let msg1 = initiator
            .create_message_1()
            .expect("create_message_1 failed");

        // Step 2: Responder processes Message 1, creates Message 2
        let msg2 = responder
            .process_message_1(&msg1)
            .expect("process_message_1 failed");

        // Step 3: Initiator processes Message 2, creates Message 3
        let msg3 = initiator
            .process_message_2(&msg2, &responder_pubkey)
            .expect("process_message_2 failed");

        // Step 4: Responder processes Message 3
        responder
            .process_message_3(&msg3, &initiator_pubkey)
            .expect("process_message_3 failed");

        assert_eq!(
            initiator.process_message_2(&msg2, &responder_pubkey),
            Err(EdhocError::InvalidState)
        );
        assert_eq!(
            responder.process_message_1(&msg1),
            Err(EdhocError::InvalidState)
        );
        assert_eq!(
            responder.process_message_3(&msg3, &initiator_pubkey),
            Err(EdhocError::InvalidState)
        );
        assert_eq!(initiator.create_message_1(), Err(EdhocError::InvalidState));

        // Step 5: Both export OSCORE contexts
        let mut initiator_ctx = initiator
            .export_oscore()
            .expect("initiator export_oscore failed");
        let mut responder_ctx = responder
            .export_oscore()
            .expect("responder export_oscore failed");

        // Step 6: Verify contexts can communicate via functional roundtrip test.
        // This is more robust than comparing raw keys - it proves the derived
        // key material is correct by demonstrating successful encrypt/decrypt.

        // 6a: Initiator sends request to Responder
        let test_code: u8 = 0x01; // GET
        let test_options: &[u8] = &[0xB1, 0x61]; // Uri-Path "a"
        let test_payload: &[u8] = b"hello from initiator";

        let (ciphertext, oscore_opt) = initiator_ctx
            .reserve_sender(&mut initiator_store)
            .expect("initiator reserve failed")
            .protect_request(test_code, test_options, test_payload)
            .expect("initiator protect_request failed");

        let (recv_code, recv_options, recv_payload) = responder_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .expect("responder unprotect_request failed");

        assert_eq!(recv_code, test_code, "request code mismatch");
        assert_eq!(&recv_options[..], test_options, "request options mismatch");
        assert_eq!(&recv_payload[..], test_payload, "request payload mismatch");

        // 6b: Responder sends response back to Initiator
        // Extract PIV from the request's OSCORE option for response AAD
        let request_piv_len = (oscore_opt[0] & 0x07) as usize;
        let request_piv = &oscore_opt[1..1 + request_piv_len];
        let request_kid = &oscore_opt[1 + request_piv_len..];

        let resp_code: u8 = 0x45; // 2.05 Content
        let resp_options: &[u8] = &[];
        let resp_payload: &[u8] = b"hello from responder";

        let (resp_ciphertext, resp_oscore_opt) = responder_ctx
            .protect_response(
                resp_code,
                resp_options,
                resp_payload,
                request_kid,
                request_piv,
                false,
            )
            .expect("responder protect_response failed");

        let (recv_resp_code, recv_resp_options, recv_resp_payload) = initiator_ctx
            .unprotect_response(&resp_oscore_opt, &resp_ciphertext, request_piv)
            .expect("initiator unprotect_response failed");

        assert_eq!(recv_resp_code, resp_code, "response code mismatch");
        assert_eq!(
            &recv_resp_options[..],
            resp_options,
            "response options mismatch"
        );
        assert_eq!(
            &recv_resp_payload[..],
            resp_payload,
            "response payload mismatch"
        );
    }

    #[test]
    fn test_parse_suites_i_single_int() {
        // Single int 0
        assert_eq!(parse_suites_i(&[0x00]).unwrap(), (0, 1));
        // Single int 2
        assert_eq!(parse_suites_i(&[0x02]).unwrap(), (2, 1));
        // Single int 23 (max direct encoding)
        assert_eq!(parse_suites_i(&[0x17]).unwrap(), (23, 1));
        // Single int 24 (1-byte follow)
        assert_eq!(parse_suites_i(&[0x18, 0x18]).unwrap(), (24, 2));
    }

    #[test]
    fn test_parse_suites_i_array() {
        // Array [0] - single element
        assert_eq!(parse_suites_i(&[0x81, 0x00]).unwrap(), (0, 2));
        // Array [0, 2] - prefer Suite 0, also supports Suite 2
        assert_eq!(parse_suites_i(&[0x82, 0x00, 0x02]).unwrap(), (0, 3));
        // Array [0, 2, 3] - three suites
        assert_eq!(parse_suites_i(&[0x83, 0x00, 0x02, 0x03]).unwrap(), (0, 4));
        // Array [2, 0] - prefer Suite 2
        assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00]).unwrap(), (2, 3));
    }

    #[test]
    fn test_parse_suites_i_errors() {
        // Empty input
        assert!(parse_suites_i(&[]).is_err());
        // Empty array
        assert!(parse_suites_i(&[0x80]).is_err());
        // Truncated 1-byte int
        assert!(parse_suites_i(&[0x18]).is_err());
    }

    /// Test responder accepts Message 1 with array-format SUITES_I (RFC 9528 Section 3.3.2).
    #[test]
    fn test_responder_accepts_suites_i_array() {
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        // Build a Message 1 with SUITES_I as array [0, 2]
        // Format: METHOD_CORR (1) | SUITES_I (array) | G_X (bstr 32) | C_I
        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push(0x01).unwrap(); // METHOD_CORR = 1
        msg1.push(0x82).unwrap(); // CBOR array of 2
        msg1.push(0x00).unwrap(); // Suite 0 (selected)
        msg1.push(0x02).unwrap(); // Suite 2 (also supported)
        msg1.push(0x58).unwrap(); // bstr header
        msg1.push(32).unwrap(); // length 32
                                // G_X: 32 bytes of ephemeral public key (dummy)
        let g_x = [0xAAu8; 32];
        msg1.extend_from_slice(&g_x).unwrap();
        msg1.push(0x05).unwrap(); // C_I = 5

        // Responder should accept this Message 1
        let result = responder.process_message_1(&msg1);
        assert!(
            result.is_ok(),
            "Responder should accept array-format SUITES_I: {:?}",
            result.err()
        );
    }

    /// Test responder rejects unsupported suite even when sent as array.
    #[test]
    fn test_responder_rejects_unsupported_suite_in_array() {
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        // Build a Message 1 with SUITES_I as array [2, 0] - Suite 2 selected
        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push(0x01).unwrap(); // METHOD_CORR = 1
        msg1.push(0x82).unwrap(); // CBOR array of 2
        msg1.push(0x02).unwrap(); // Suite 2 (selected - NOT supported)
        msg1.push(0x00).unwrap(); // Suite 0 (also supported)
        msg1.push(0x58).unwrap(); // bstr header
        msg1.push(32).unwrap(); // length 32
        let g_x = [0xAAu8; 32];
        msg1.extend_from_slice(&g_x).unwrap();
        msg1.push(0x05).unwrap(); // C_I = 5

        let result = responder.process_message_1(&msg1);
        assert!(matches!(result, Err(EdhocError::UnsupportedSuite)));
    }

    /// Test that export_oscore returns NoContext if called before handshake completes.
    #[test]
    fn test_export_before_handshake_returns_error() {
        use crate::OscoreError;

        // Initiator: export_oscore before process_message_2
        let initiator_seed = [0x11u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
        let _msg1 = initiator.create_message_1().unwrap();
        // Handshake incomplete - should fail
        assert!(
            matches!(initiator.export_oscore(), Err(OscoreError::NoContext)),
            "Initiator export_oscore should fail before process_message_2"
        );

        // Responder: export_oscore before process_message_3
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);
        // Even after process_message_1, handshake is incomplete
        let _msg2 = responder.process_message_1(&_msg1).unwrap();
        assert!(
            matches!(responder.export_oscore(), Err(OscoreError::NoContext)),
            "Responder export_oscore should fail before process_message_3"
        );
    }
}
