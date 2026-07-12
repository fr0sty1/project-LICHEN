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

use crate::{Context, OscoreError, KEY_LEN, NONCE_LEN, TAG_LEN};
use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-CCM for Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// X25519/Ed25519 key length.
pub const KEY_LEN_32: usize = 32;

/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;

/// Suite 0 identifier.
pub const SUITE_0: u8 = 0;

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

/// HKDF-Extract with SHA-256.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // ponytail: Use hkdf crate which we already depend on
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// EDHOC-KDF (RFC 9528 Section 4.1.2).
///
/// EDHOC-KDF(PRK, TH, label, context, length) = HKDF-Expand(PRK, info, length)
/// where info = (length, TH, label, context) as CBOR sequence.
fn edhoc_kdf(
    prk: &[u8; 32],
    th: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    // Build info: CBOR sequence of (length, TH, label, context)
    let mut info = heapless::Vec::<u8, 128>::new();

    // length as CBOR uint
    if length <= 23 {
        info.push_err(length as u8)?;
    } else {
        info.push_err(0x18)?;
        info.push_err(length as u8)?;
    }

    // TH as CBOR bstr
    if th.len() <= 23 {
        info.push_err(0x40 | th.len() as u8)?;
    } else {
        info.push_err(0x58)?;
        info.push_err(th.len() as u8)?;
    }
    info.extend_err(th)?;

    // label as CBOR tstr
    let label_bytes = label.as_bytes();
    if label_bytes.len() <= 23 {
        info.push_err(0x60 | label_bytes.len() as u8)?;
    } else {
        info.push_err(0x78)?;
        info.push_err(label_bytes.len() as u8)?;
    }
    info.extend_err(label_bytes)?;

    // context as CBOR bstr
    if context.is_empty() {
        info.push_err(0x40)?; // empty bstr
    } else if context.len() <= 23 {
        info.push_err(0x40 | context.len() as u8)?;
        info.extend_err(context)?;
    } else {
        info.push_err(0x58)?;
        info.push_err(context.len() as u8)?;
        info.extend_err(context)?;
    }

    // HKDF-Expand
    // SECURITY: Propagate errors instead of panicking in crypto code path
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| EdhocError::KeyDerivation)?;
    let mut okm = heapless::Vec::new();
    okm.resize(length, 0)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    hk.expand(&info, &mut okm)
        .map_err(|_| EdhocError::KeyDerivation)?;
    Ok(okm)
}

/// Compute transcript hash: H(input).
fn compute_th(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// EDHOC Initiator (client role).
///
/// Implements EDHOC method 0 (SIGN_SIGN) with Suite 0.
pub struct EdhocInitiator {
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Our Ed25519 public key.
    pubkey: VerifyingKey,
    /// Our connection identifier.
    c_i: u8,
    /// Ephemeral X25519 secret (consumed after use).
    eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
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
    c_r: u8,
    prk_2e: [u8; 32],
    prk_3e2m: [u8; 32],
    prk_4e3m: [u8; 32],
    th_2: [u8; 32],
    th_3: [u8; 32],
    th_4: [u8; 32],
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_y: [0; 32],
            c_r: 0,
            prk_2e: [0; 32],
            prk_3e2m: [0; 32],
            prk_4e3m: [0; 32],
            th_2: [0; 32],
            th_3: [0; 32],
            th_4: [0; 32],
        }
    }
}

impl EdhocInitiator {
    /// Create a new EDHOC initiator.
    ///
    /// # Arguments
    /// * `seed` - Ed25519 seed (32 bytes)
    /// * `c_i` - Connection identifier (1 byte)
    pub fn new(seed: [u8; 32], c_i: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        // Generate ephemeral X25519 key pair
        let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
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
    /// message_1 = (METHOD_CORR, SUITES_I, G_X, C_I)
    pub fn create_message_1(&mut self) -> Result<heapless::Vec<u8, 64>, EdhocError> {
        // METHOD_CORR = method * 4 + corr (method=0, corr=1 for CoAP)
        let method_corr: u8 = 0 * 4 + 1;

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

        self.state.msg1 = msg1.clone();
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
        // message_2 = (G_Y || CIPHERTEXT_2, C_R)
        // First item: bstr containing G_Y (32 bytes) + CIPHERTEXT_2
        // Second item: C_R

        // Parse G_Y || CIPHERTEXT_2 (first CBOR item)
        if msg2.len() < 35 {
            return Err(EdhocError::InvalidMessage);
        }

        let (g_y_ct2, rest) = if msg2[0] == 0x58 {
            // bstr with 1-byte length
            let len = msg2[1] as usize;
            if msg2.len() < 2 + len {
                return Err(EdhocError::InvalidMessage);
            }
            (&msg2[2..2 + len], &msg2[2 + len..])
        } else {
            return Err(EdhocError::InvalidMessage);
        };

        if g_y_ct2.len() < 32 {
            return Err(EdhocError::InvalidMessage);
        }

        self.state.g_y.copy_from_slice(&g_y_ct2[..32]);
        let ciphertext_2 = &g_y_ct2[32..];

        // Parse C_R
        self.state.c_r = if !rest.is_empty() {
            if rest[0] <= 23 {
                rest[0]
            } else if rest[0] == 0x41 && rest.len() > 1 {
                rest[1]
            } else {
                return Err(EdhocError::InvalidMessage);
            }
        } else {
            return Err(EdhocError::InvalidMessage);
        };

        // Compute shared secret G_XY (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(self.state.g_y);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse (RFC 9528 freshness).

        // TH_2 = H(G_Y || H(message_1))
        let h_msg1 = compute_th(&self.state.msg1);
        let mut th_2_input = heapless::Vec::<u8, 64>::new();
        th_2_input.extend_err(&self.state.g_y)?;
        th_2_input.extend_err(&h_msg1)?;
        self.state.th_2 = compute_th(&th_2_input);

        // PRK_2e = HKDF-Extract(TH_2, G_XY)
        self.state.prk_2e = hkdf_extract(&self.state.th_2, g_xy.as_bytes());

        // Decrypt CIPHERTEXT_2 with KEYSTREAM_2
        let keystream_2 = edhoc_kdf(
            &self.state.prk_2e,
            &self.state.th_2,
            "KEYSTREAM_2",
            &[],
            ciphertext_2.len(),
        )?;
        let mut plaintext_2 = heapless::Vec::<u8, 128>::new();
        for (i, &b) in ciphertext_2.iter().enumerate() {
            plaintext_2.push_err(b ^ keystream_2[i])?;
        }

        // PRK_3e2m = PRK_2e for SIGN_SIGN method
        self.state.prk_3e2m = self.state.prk_2e;

        // SECURITY: Parse PLAINTEXT_2 = (ID_CRED_R, Signature_2) and verify Signature_2
        // per RFC 9528 Section 4.3.2. Without this, an attacker could inject forged Message 2.
        // PLAINTEXT_2 format: ID_CRED_R (bstr) || Signature_2 (bstr 64 bytes)
        let pt2 = plaintext_2.as_slice();
        if pt2.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        // Parse ID_CRED_R (skip it, we already have peer_pubkey)
        let (id_cred_r_len, pt2_rest) = if pt2[0] == 0x58 && pt2.len() > 1 {
            let len = pt2[1] as usize;
            if pt2.len() < 2 + len {
                return Err(EdhocError::InvalidMessage);
            }
            (len, &pt2[2 + len..])
        } else if pt2[0] >= 0x40 && pt2[0] <= 0x57 {
            let len = (pt2[0] - 0x40) as usize;
            if pt2.len() < 1 + len {
                return Err(EdhocError::InvalidMessage);
            }
            (len, &pt2[1 + len..])
        } else {
            return Err(EdhocError::InvalidMessage);
        };
        let _ = id_cred_r_len;

        // Parse Signature_2 (64 bytes Ed25519)
        let signature_2_bytes: [u8; SIG_LEN] =
            if pt2_rest.len() >= 2 && pt2_rest[0] == 0x58 && pt2_rest[1] == 64 {
                if pt2_rest.len() < 2 + 64 {
                    return Err(EdhocError::InvalidMessage);
                }
                pt2_rest[2..2 + 64]
                    .try_into()
                    .map_err(|_| EdhocError::InvalidMessage)?
            } else {
                return Err(EdhocError::InvalidMessage);
            };

        // Compute MAC_2 for signature verification
        // context_2 = << ID_CRED_R, CRED_R >> (CRED_R = peer_pubkey for simplified case)
        let mut context_2 = heapless::Vec::<u8, 128>::new();
        context_2.push_err(0x58)?;
        context_2.push_err(32)?;
        context_2.extend_err(peer_pubkey)?; // ID_CRED_R
        context_2.push_err(0x58)?;
        context_2.push_err(32)?;
        context_2.extend_err(peer_pubkey)?; // CRED_R
        let mac_2 = edhoc_kdf(
            &self.state.prk_3e2m,
            &self.state.th_2,
            "MAC_2",
            &context_2,
            8,
        )?;

        // M_2 = ["Signature1", << ID_CRED_R >>, TH_2, << CRED_R >>, MAC_2]
        let mut m_2 = heapless::Vec::<u8, 160>::new();
        m_2.push_err(0x85)?; // array of 5
                             // "Signature1"
        m_2.push_err(0x6A)?; // tstr of 10 chars
        m_2.extend_err(b"Signature1")?;
        // << ID_CRED_R >> bstr-wrapped
        m_2.push_err(0x58)?;
        m_2.push_err(34)?; // 2 + 32
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(peer_pubkey)?;
        // TH_2
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(&self.state.th_2)?;
        // << CRED_R >> bstr-wrapped
        m_2.push_err(0x58)?;
        m_2.push_err(34)?;
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(peer_pubkey)?;
        // MAC_2
        m_2.push_err(0x48)?; // bstr of 8
        m_2.extend_err(&mac_2)?;

        // Verify Signature_2
        let peer_verifying_key =
            VerifyingKey::from_bytes(peer_pubkey).map_err(|_| EdhocError::SignatureVerification)?;
        let signature_2 = Signature::from_bytes(&signature_2_bytes);
        peer_verifying_key
            .verify(&m_2, &signature_2)
            .map_err(|_| EdhocError::SignatureVerification)?;

        // TH_3 = H(TH_2, CIPHERTEXT_2, ID_CRED_R)
        // ponytail: simplified - ID_CRED_R is peer pubkey
        // Size: 34 (TH_2) + 2 + ~100 (ciphertext) + 34 (ID_CRED_R) = ~170 bytes
        let mut th_3_input = heapless::Vec::<u8, 192>::new();
        // TH_2 as CBOR bstr
        th_3_input.push_err(0x58)?;
        th_3_input.push_err(32)?;
        th_3_input.extend_err(&self.state.th_2)?;
        // CIPHERTEXT_2 as CBOR bstr
        if ciphertext_2.len() <= 23 {
            th_3_input.push_err(0x40 | ciphertext_2.len() as u8)?;
        } else {
            th_3_input.push_err(0x58)?;
            th_3_input.push_err(ciphertext_2.len() as u8)?;
        }
        th_3_input.extend_err(ciphertext_2)?;
        // ID_CRED_R as CBOR bstr (pubkey)
        th_3_input.push_err(0x58)?;
        th_3_input.push_err(32)?;
        th_3_input.extend_err(peer_pubkey)?;
        self.state.th_3 = compute_th(&th_3_input);

        // PRK_4e3m = PRK_3e2m for SIGN_SIGN
        self.state.prk_4e3m = self.state.prk_3e2m;

        // Create Message 3
        // PLAINTEXT_3 = (ID_CRED_I, Signature_3)

        // Build M_3 for signature
        let mut m_3 = heapless::Vec::<u8, 128>::new();
        // CBOR array header (simplified)
        m_3.push_err(0x83)?; // array of 3
                             // ID_CRED_I (pubkey)
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(self.pubkey.as_bytes())?;
        // TH_3
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(&self.state.th_3)?;
        // CRED_I (pubkey)
        m_3.push_err(0x58)?;
        m_3.push_err(32)?;
        m_3.extend_err(self.pubkey.as_bytes())?;

        let signature_3 = self.signing_key.sign(&m_3);

        // PLAINTEXT_3 = ID_CRED_I || Signature_3 as CBOR
        // Built directly into ciphertext_3 buffer to avoid clone
        let mut ciphertext_3 = heapless::Vec::<u8, 128>::new();
        // ID_CRED_I
        ciphertext_3.push_err(0x58)?;
        ciphertext_3.push_err(32)?;
        ciphertext_3.extend_err(self.pubkey.as_bytes())?;
        // Signature_3
        ciphertext_3.push_err(0x58)?;
        ciphertext_3.push_err(64)?;
        ciphertext_3.extend_err(&signature_3.to_bytes())?;

        // K_3 and IV_3 for AEAD
        let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
        let iv_3 = edhoc_kdf(
            &self.state.prk_3e2m,
            &self.state.th_3,
            "IV_3",
            &[],
            NONCE_LEN,
        )?;

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
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&iv_3);
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &a_3, &mut ciphertext_3)
            .map_err(|_| EdhocError::InvalidState)?;
        ciphertext_3.extend_err(&tag)?;

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
        th_4_input.extend_err(&ciphertext_3)?;
        self.state.th_4 = compute_th(&th_4_input);

        Ok(ciphertext_3)
    }

    /// Export OSCORE security context.
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        // OSCORE Master Secret = EDHOC-KDF(PRK_4e3m, TH_4, "OSCORE_Master_Secret", h'', 16)
        let master_secret_vec = edhoc_kdf(
            &self.state.prk_4e3m,
            &self.state.th_4,
            "OSCORE_Master_Secret",
            &[],
            KEY_LEN,
        )
        .map_err(|_| OscoreError::KeyDerivation)?;
        let mut master_secret = [0u8; KEY_LEN];
        master_secret.copy_from_slice(&master_secret_vec);

        // OSCORE Master Salt = EDHOC-KDF(PRK_4e3m, TH_4, "OSCORE_Master_Salt", h'', 8)
        let master_salt_vec = edhoc_kdf(
            &self.state.prk_4e3m,
            &self.state.th_4,
            "OSCORE_Master_Salt",
            &[],
            8,
        )
        .map_err(|_| OscoreError::KeyDerivation)?;
        let mut master_salt = [0u8; 8];
        master_salt.copy_from_slice(&master_salt_vec);

        // Initiator: sender_id = C_I, recipient_id = C_R
        Context::new(
            &master_secret,
            Some(&master_salt),
            &[self.c_i],
            &[self.state.c_r],
        )
    }
}

/// EDHOC Responder (server role).
pub struct EdhocResponder {
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Our Ed25519 public key.
    pubkey: VerifyingKey,
    /// Our connection identifier.
    c_r: u8,
    /// Ephemeral X25519 secret.
    eph_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
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
    c_i: u8,
    prk_2e: [u8; 32],
    prk_3e2m: [u8; 32],
    prk_4e3m: [u8; 32],
    th_2: [u8; 32],
    th_3: [u8; 32],
    th_4: [u8; 32],
}

impl Default for ResponderState {
    fn default() -> Self {
        Self {
            msg1: heapless::Vec::new(),
            g_x: [0; 32],
            c_i: 0,
            prk_2e: [0; 32],
            prk_3e2m: [0; 32],
            prk_4e3m: [0; 32],
            th_2: [0; 32],
            th_3: [0; 32],
            th_4: [0; 32],
        }
    }
}

impl EdhocResponder {
    /// Create a new EDHOC responder.
    pub fn new(seed: [u8; 32], c_r: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            signing_key,
            pubkey,
            c_r,
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        }
    }

    /// Process EDHOC Message 1 and create Message 2.
    pub fn process_message_1(&mut self, msg1: &[u8]) -> Result<heapless::Vec<u8, 160>, EdhocError> {
        self.state.msg1.clear();
        self.state.msg1.extend_err(msg1)?;

        // Parse message_1 = (METHOD_CORR, SUITES_I, G_X, C_I)
        // Minimum: 1 (method_corr) + 1 (suite) + 2 (bstr header) + 32 (G_X) + 1 (C_I) = 37
        if msg1.len() < 37 {
            return Err(EdhocError::InvalidMessage);
        }

        let _method_corr = msg1[0];
        let suites_i = msg1[1];

        if suites_i != SUITE_0 {
            return Err(EdhocError::UnsupportedSuite);
        }

        // Parse G_X (32-byte bstr)
        if msg1[2] != 0x58 || msg1[3] != 32 {
            return Err(EdhocError::InvalidMessage);
        }
        self.state.g_x.copy_from_slice(&msg1[4..36]);

        // Parse C_I
        let rest = &msg1[36..];
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
        };

        // Compute shared secret (ephemeral key consumed - single use only)
        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(self.state.g_x);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        // SECURITY: eph_secret is intentionally NOT stored back - single-use semantics
        // prevent cryptographic weakness from ephemeral key reuse if this function
        // is called multiple times (e.g., due to retransmission handling bugs).

        // TH_2 = H(G_Y || H(message_1))
        let h_msg1 = compute_th(msg1);
        let mut th_2_input = heapless::Vec::<u8, 64>::new();
        th_2_input.extend_err(self.eph_public.as_bytes())?;
        th_2_input.extend_err(&h_msg1)?;
        self.state.th_2 = compute_th(&th_2_input);

        // PRK_2e = HKDF-Extract(TH_2, G_XY)
        self.state.prk_2e = hkdf_extract(&self.state.th_2, g_xy.as_bytes());

        // PRK_3e2m = PRK_2e for SIGN_SIGN
        self.state.prk_3e2m = self.state.prk_2e;

        // Compute MAC_2 for signature
        // context_2 = << ID_CRED_R, CRED_R >> per RFC 9528 Section 4.3.2
        let mut context_2 = heapless::Vec::<u8, 128>::new();
        context_2.push_err(0x58)?;
        context_2.push_err(32)?;
        context_2.extend_err(self.pubkey.as_bytes())?;  // ID_CRED_R
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

        // M_2 = ["Signature1", << ID_CRED_R >>, TH_2, << CRED_R >>, MAC_2]
        let mut m_2 = heapless::Vec::<u8, 160>::new();
        m_2.push_err(0x85)?; // array of 5
                             // "Signature1"
        m_2.push_err(0x6A)?; // tstr of 10 chars
        m_2.extend_err(b"Signature1")?;
        // << ID_CRED_R >> bstr-wrapped
        m_2.push_err(0x58)?;
        m_2.push_err(34)?; // 2 + 32
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(self.pubkey.as_bytes())?;
        // TH_2
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(&self.state.th_2)?;
        // << CRED_R >> bstr-wrapped
        m_2.push_err(0x58)?;
        m_2.push_err(34)?;
        m_2.push_err(0x58)?;
        m_2.push_err(32)?;
        m_2.extend_err(self.pubkey.as_bytes())?;
        // MAC_2
        m_2.push_err(0x48)?; // bstr of 8
        m_2.extend_err(&mac_2)?;

        let signature_2 = self.signing_key.sign(&m_2);

        let mut plaintext_2 = heapless::Vec::<u8, 128>::new();
        plaintext_2.push_err(0x58)?;
        plaintext_2.push_err(32)?;
        plaintext_2.extend_err(self.pubkey.as_bytes())?;
        plaintext_2.push_err(0x58)?;
        plaintext_2.push_err(64)?;
        plaintext_2.extend_err(&signature_2.to_bytes())?;

        // Encrypt with KEYSTREAM_2
        let keystream_2 = edhoc_kdf(
            &self.state.prk_2e,
            &self.state.th_2,
            "KEYSTREAM_2",
            &[],
            plaintext_2.len(),
        )?;
        let mut ciphertext_2 = heapless::Vec::<u8, 128>::new();
        for (i, &b) in plaintext_2.iter().enumerate() {
            ciphertext_2.push_err(b ^ keystream_2[i])?;
        }

        // TH_3 = H(TH_2, CIPHERTEXT_2, ID_CRED_R)
        let mut th_3_input = heapless::Vec::<u8, 192>::new();
        th_3_input.push_err(0x58)?;
        th_3_input.push_err(32)?;
        th_3_input.extend_err(&self.state.th_2)?;
        if ciphertext_2.len() <= 23 {
            th_3_input.push_err(0x40 | ciphertext_2.len() as u8)?;
        } else {
            th_3_input.push_err(0x58)?;
            th_3_input.push_err(ciphertext_2.len() as u8)?;
        }
        th_3_input.extend_err(&ciphertext_2)?;
        th_3_input.push_err(0x58)?;
        th_3_input.push_err(32)?;
        th_3_input.extend_err(self.pubkey.as_bytes())?;
        self.state.th_3 = compute_th(&th_3_input);

        // message_2 = (G_Y || CIPHERTEXT_2, C_R)
        // Size: 2 header + 32 G_Y + ~100 ciphertext_2 + 1-2 C_R = ~137 bytes
        let mut msg2 = heapless::Vec::<u8, 160>::new();
        let g_y_ct2_len = 32 + ciphertext_2.len();
        msg2.push_err(0x58)?;
        msg2.push_err(g_y_ct2_len as u8)?;
        msg2.extend_err(self.eph_public.as_bytes())?;
        msg2.extend_err(&ciphertext_2)?;

        // C_R
        if self.c_r <= 23 {
            msg2.push_err(self.c_r)?;
        } else {
            msg2.push_err(0x41)?;
            msg2.push_err(self.c_r)?;
        }

        Ok(msg2)
    }

    /// Process EDHOC Message 3.
    pub fn process_message_3(
        &mut self,
        msg3: &[u8],
        peer_pubkey: &[u8; 32],
    ) -> Result<(), EdhocError> {
        let ciphertext_3 = msg3;

        // K_3 and IV_3 for AEAD decryption
        let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
        let iv_3 = edhoc_kdf(
            &self.state.prk_3e2m,
            &self.state.th_3,
            "IV_3",
            &[],
            NONCE_LEN,
        )?;

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
        let mut plaintext_3 = heapless::Vec::<u8, 128>::new();
        plaintext_3.extend_err(&ciphertext_3[..tag_start])?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&iv_3);
        cipher
            .decrypt_in_place_detached((&nonce).into(), &a_3, &mut plaintext_3, tag)
            .map_err(|_| EdhocError::DecryptFailed)?;

        // Verify Signature_3
        let peer_verifying_key =
            VerifyingKey::from_bytes(peer_pubkey).map_err(|_| EdhocError::SignatureVerification)?;

        // Parse PLAINTEXT_3 = ID_CRED_I || Signature_3
        // ID_CRED_I: 0x58 0x20 [32 bytes]
        // Signature_3: 0x58 0x40 [64 bytes]
        if plaintext_3.len() < 2 + 32 + 2 + 64 {
            return Err(EdhocError::InvalidMessage);
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

        Ok(())
    }

    /// Export OSCORE security context.
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        let master_secret_vec = edhoc_kdf(
            &self.state.prk_4e3m,
            &self.state.th_4,
            "OSCORE_Master_Secret",
            &[],
            KEY_LEN,
        )
        .map_err(|_| OscoreError::KeyDerivation)?;
        let mut master_secret = [0u8; KEY_LEN];
        master_secret.copy_from_slice(&master_secret_vec);

        let master_salt_vec = edhoc_kdf(
            &self.state.prk_4e3m,
            &self.state.th_4,
            "OSCORE_Master_Salt",
            &[],
            8,
        )
        .map_err(|_| OscoreError::KeyDerivation)?;
        let mut master_salt = [0u8; 8];
        master_salt.copy_from_slice(&master_salt_vec);

        // Responder: sender_id = C_R, recipient_id = C_I (swapped)
        Context::new(
            &master_secret,
            Some(&master_salt),
            &[self.c_r],
            &[self.state.c_i],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiator_creation() {
        let seed = [0x01u8; 32];
        let initiator = EdhocInitiator::new(seed, 0x00);
        assert_eq!(initiator.c_i, 0x00);
    }

    #[test]
    fn test_responder_creation() {
        let seed = [0x01u8; 32];
        let responder = EdhocResponder::new(seed, 0x01);
        assert_eq!(responder.c_r, 0x01);
    }

    #[test]
    fn test_message_1_creation() {
        let seed = [0x01u8; 32];
        let mut initiator = EdhocInitiator::new(seed, 0x05);
        let msg1 = initiator.create_message_1().unwrap();

        // Check basic structure: METHOD_CORR, SUITE, G_X, C_I
        assert_eq!(msg1[0], 1); // method_corr = 0*4+1
        assert_eq!(msg1[1], 0); // Suite 0
        assert_eq!(msg1[2], 0x58); // bstr marker
        assert_eq!(msg1[3], 32); // G_X length
                                 // msg1[4..36] is G_X
        assert_eq!(msg1[36], 5); // C_I
    }

    /// Integration test: full EDHOC handshake with key verification.
    #[test]
    fn test_full_handshake() {
        // Create initiator and responder with different seeds
        let initiator_seed = [0x11u8; 32];
        let responder_seed = [0x22u8; 32];

        let mut initiator = EdhocInitiator::new(initiator_seed, 0x00);
        let mut responder = EdhocResponder::new(responder_seed, 0x01);

        // Get public keys for verification
        let initiator_pubkey = initiator.pubkey.to_bytes();
        let responder_pubkey = responder.pubkey.to_bytes();

        // Step 1: Initiator creates Message 1
        let msg1 = initiator.create_message_1().expect("create_message_1 failed");

        // Step 2: Responder processes Message 1, creates Message 2
        let msg2 = responder.process_message_1(&msg1).expect("process_message_1 failed");

        // Step 3: Initiator processes Message 2, creates Message 3
        let msg3 = initiator
            .process_message_2(&msg2, &responder_pubkey)
            .expect("process_message_2 failed");

        // Step 4: Responder processes Message 3
        responder
            .process_message_3(&msg3, &initiator_pubkey)
            .expect("process_message_3 failed");

        // Step 5: Both export OSCORE contexts
        let mut initiator_ctx = initiator.export_oscore().expect("initiator export_oscore failed");
        let mut responder_ctx = responder.export_oscore().expect("responder export_oscore failed");

        // Step 6: Verify contexts can communicate via functional roundtrip test.
        // This is more robust than comparing raw keys - it proves the derived
        // key material is correct by demonstrating successful encrypt/decrypt.

        // 6a: Initiator sends request to Responder
        let test_code: u8 = 0x01; // GET
        let test_options: &[u8] = &[0xB1, 0x61]; // Uri-Path "a"
        let test_payload: &[u8] = b"hello from initiator";

        let (ciphertext, oscore_opt) = initiator_ctx
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
            .protect_response(resp_code, resp_options, resp_payload, request_kid, request_piv, false)
            .expect("responder protect_response failed");

        let (recv_resp_code, recv_resp_options, recv_resp_payload) = initiator_ctx
            .unprotect_response(&resp_oscore_opt, &resp_ciphertext, request_piv)
            .expect("initiator unprotect_response failed");

        assert_eq!(recv_resp_code, resp_code, "response code mismatch");
        assert_eq!(&recv_resp_options[..], resp_options, "response options mismatch");
        assert_eq!(&recv_resp_payload[..], resp_payload, "response payload mismatch");
    }
}
