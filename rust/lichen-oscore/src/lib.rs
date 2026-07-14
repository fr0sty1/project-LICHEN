// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! OSCORE (RFC 8613) implementation for LICHEN.
//!
//! Provides end-to-end security for CoAP using AES-CCM-16-64-128 and HKDF-SHA256.
//!
//! # ponytail: pure-Rust OSCORE
//!
//! Using `ccm` + `hkdf` crates directly until a battle-tested no_std OSCORE crate
//! exists. `liboscore` requires C FFI which complicates embedded cross-compilation.
//! Switch to `liboscore` or `coapcore` when they mature for embedded targets.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod seqnum;

#[cfg(feature = "edhoc")]
pub mod edhoc;

pub use seqnum::OscoreSeqNum;

#[cfg(feature = "edhoc")]
pub use edhoc::{EdhocError, EdhocInitiator, EdhocResponder};

use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use hkdf::Hkdf;
use lichen_core::error::BufferTooSmall;
use sha2::Sha256;
use zeroize::Zeroize;

/// AES-CCM-16-64-128: 128-bit key, 13-byte nonce, 8-byte tag.
type AesCcm = Ccm<Aes128, U8, U13>;

/// Key length (16 bytes for AES-128).
pub const KEY_LEN: usize = 16;

/// Nonce length (13 bytes for CCM L=2).
pub const NONCE_LEN: usize = 13;

/// Authentication tag length (8 bytes).
pub const TAG_LEN: usize = 8;

/// Maximum sender/recipient ID length.
pub const ID_MAX_LEN: usize = 8;

/// Maximum Partial IV length.
pub const PIV_MAX_LEN: usize = 5;

// Nonce layout constants (RFC 8613 Section 5.2):
// +--------+------------------+------------------+
// | 1 byte |     7 bytes      |     5 bytes      |
// +--------+------------------+------------------+
// |   S    | left-padded ID   | left-padded PIV  |
// +--------+------------------+------------------+
//   [0]        [1..8)             [8..13)

/// Nonce field: ID region ends at byte 8 (bytes 1-7 = 7 bytes for ID).
const NONCE_ID_END: usize = 8;

/// Nonce field: PIV region starts at byte 8 (bytes 8-12 = 5 bytes for PIV).
const NONCE_PIV_START: usize = 8;

/// Nonce field: Maximum ID length (7 bytes, fits in bytes 1-7).
const NONCE_ID_LEN: usize = NONCE_ID_END - 1; // = 7

// Compile-time assertions: nonce layout must be consistent
const _: () = assert!(
    NONCE_ID_END == NONCE_PIV_START,
    "ID and PIV fields must be adjacent"
);
const _: () = assert!(
    NONCE_PIV_START + PIV_MAX_LEN == NONCE_LEN,
    "PIV field must fit exactly"
);
const _: () = assert!(
    1 + NONCE_ID_LEN + PIV_MAX_LEN == NONCE_LEN,
    "nonce fields must sum to NONCE_LEN"
);

/// COSE Algorithm ID for AES-CCM-16-64-128.
pub const ALG_AEAD: u8 = 10;

/// OSCORE CoAP option number.
pub const COAP_OPTION_OSCORE: u16 = 9;

/// Replay window size in bits.
pub const WINDOW_SIZE: u32 = 32;

/// OSCORE error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OscoreError {
    /// Invalid parameter provided.
    InvalidParam,
    /// Security context not found.
    NoContext,
    /// Replay attack detected.
    Replay,
    /// Encryption failed.
    EncryptFailed,
    /// Decryption/authentication failed.
    DecryptFailed,
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
    /// Key derivation failed.
    KeyDerivation,
    /// Sender sequence exhausted, key rotation required.
    SeqExhausted,
}

impl From<BufferTooSmall> for OscoreError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

impl core::fmt::Display for OscoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParam => write!(f, "invalid parameter"),
            Self::NoContext => write!(f, "security context not found"),
            Self::Replay => write!(f, "replay attack detected"),
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed"),
            Self::BufferTooSmall(e) => write!(f, "OSCORE {}", e),
            Self::KeyDerivation => write!(f, "key derivation failed"),
            Self::SeqExhausted => write!(f, "sender sequence exhausted, key rotation required"),
        }
    }
}

impl core::error::Error for OscoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

/// OSCORE security context.
///
/// Contains cryptographic material and state for one peer.
///
/// # Thread Safety
///
/// This type is designed for single-threaded use on embedded targets. The replay
/// window (`replay_window` and `recipient_seq`) is not thread-safe: concurrent calls
/// to `check_replay` could race, allowing both to pass the candidate check and both
/// to update the window, potentially losing state or allowing replays.
///
/// For multi-threaded use, wrap in a `Mutex` or use atomic operations.
///
/// # Key Lifecycle
///
/// All key material (master_secret, sender_key, recipient_key) is zeroized on drop
/// via the `Zeroize` derive. Clone is intentionally supported for cases where multiple
/// tasks need the context; both the original and clones will be zeroized when dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Context {
    // Common context
    master_secret: [u8; KEY_LEN],
    master_salt: [u8; 8],
    master_salt_len: u8,
    common_iv: [u8; NONCE_LEN],
    id_context: [u8; 8],
    id_context_len: u8,

    // Sender context
    sender_id: [u8; ID_MAX_LEN],
    sender_id_len: u8,
    sender_key: [u8; KEY_LEN],
    sender_seq: OscoreSeqNum,

    // Recipient context
    recipient_id: [u8; ID_MAX_LEN],
    recipient_id_len: u8,
    recipient_key: [u8; KEY_LEN],
    recipient_seq: OscoreSeqNum,
    replay_window: u32,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("master_secret", &"[REDACTED]")
            .field("master_salt", &"[REDACTED]")
            .field("common_iv", &"[REDACTED]")
            .field("id_context_len", &self.id_context_len)
            .field("sender_id_len", &self.sender_id_len)
            .field("sender_key", &"[REDACTED]")
            .field("sender_seq", &self.sender_seq)
            .field("recipient_id_len", &self.recipient_id_len)
            .field("recipient_key", &"[REDACTED]")
            .field("recipient_seq", &self.recipient_seq)
            .field("replay_window", &self.replay_window)
            .finish()
    }
}

impl Context {
    /// Create a new OSCORE security context.
    ///
    /// Derives sender and recipient keys from master secret using HKDF-SHA256.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParam` if:
    /// - `sender_id` or `recipient_id` exceeds 7 bytes (nonce capacity)
    /// - `master_salt` exceeds 8 bytes
    pub fn new(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, OscoreError> {
        // SECURITY: Validate ID length against nonce capacity (7 bytes), not ID_MAX_LEN (8).
        // RFC 8613 allows IDs up to 8 bytes, but only 7 bytes fit in the nonce layout.
        // Accepting 8-byte IDs would cause silent truncation in compute_nonce.
        if sender_id.len() > NONCE_ID_LEN || recipient_id.len() > NONCE_ID_LEN {
            return Err(OscoreError::InvalidParam);
        }

        let salt = master_salt.unwrap_or(&[]);
        if salt.len() > 8 {
            return Err(OscoreError::InvalidParam);
        }

        let mut ctx = Self {
            master_secret: *master_secret,
            master_salt: [0u8; 8],
            master_salt_len: salt.len() as u8,
            common_iv: [0u8; NONCE_LEN],
            id_context: [0u8; 8],
            id_context_len: 0,
            sender_id: [0u8; ID_MAX_LEN],
            sender_id_len: sender_id.len() as u8,
            sender_key: [0u8; KEY_LEN],
            sender_seq: OscoreSeqNum::new(0),
            recipient_id: [0u8; ID_MAX_LEN],
            recipient_id_len: recipient_id.len() as u8,
            recipient_key: [0u8; KEY_LEN],
            recipient_seq: OscoreSeqNum::new(0),
            replay_window: 0,
        };

        ctx.master_salt[..salt.len()].copy_from_slice(salt);
        ctx.sender_id[..sender_id.len()].copy_from_slice(sender_id);
        ctx.recipient_id[..recipient_id.len()].copy_from_slice(recipient_id);

        // Derive keys
        ctx.sender_key = derive_key(master_secret, salt, sender_id, &[])?;
        ctx.recipient_key = derive_key(master_secret, salt, recipient_id, &[])?;

        // Derive Common IV
        ctx.common_iv = derive_iv(master_secret, salt, &[])?;

        Ok(ctx)
    }

    /// Get the current sender sequence number.
    pub fn sender_seq(&self) -> OscoreSeqNum {
        self.sender_seq
    }

    /// Get sender ID.
    pub fn sender_id(&self) -> &[u8] {
        &self.sender_id[..self.sender_id_len as usize]
    }

    /// Get recipient ID.
    pub fn recipient_id(&self) -> &[u8] {
        &self.recipient_id[..self.recipient_id_len as usize]
    }

    /// Protect (encrypt) a CoAP request.
    ///
    /// Returns (ciphertext, OSCORE option value).
    ///
    /// # Errors
    ///
    /// Returns `SeqExhausted` when the sender sequence number reaches `u32::MAX`.
    /// The security context must be renegotiated before this happens to prevent
    /// nonce reuse (RFC 8613 Section 7.2.1).
    pub fn protect_request(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<(heapless::Vec<u8, 280>, heapless::Vec<u8, 16>), OscoreError> {
        // Check for sequence number exhaustion before incrementing.
        // Wraparound would cause nonce reuse, a critical security violation.
        if self.sender_seq.get() == u32::MAX {
            return Err(OscoreError::SeqExhausted);
        }

        // Get and increment sequence number
        let seq = self.sender_seq.fetch_increment();

        // Encode PIV
        let mut piv = [0u8; PIV_MAX_LEN];
        let piv_len = seq.encode_piv(&mut piv);

        // Compute nonce
        let nonce = compute_nonce(self.sender_id(), &piv[..piv_len], &self.common_iv);

        // Build plaintext directly in ct_out: code || options || 0xFF || payload
        // 0xFF is the CoAP payload marker (RFC 7252 Section 3): it separates
        // the options from the payload and is only present when payload is non-empty.
        // ponytail: empty AAD for now, proper AAD structure in RFC 8613 Section 5.4
        let cipher =
            AesCcm::new_from_slice(&self.sender_key).map_err(|_| OscoreError::KeyDerivation)?;
        const CT_CAP: usize = 280;
        let mut ct_out = heapless::Vec::<u8, CT_CAP>::new();
        // Calculate required size for error reporting
        let ct_required = 1
            + class_e_options.len()
            + if payload.is_empty() {
                0
            } else {
                1 + payload.len()
            }
            + TAG_LEN;
        let ct_err = || BufferTooSmall::new(ct_required, CT_CAP);
        ct_out.push(code).map_err(|_| ct_err())?;
        ct_out
            .extend_from_slice(class_e_options)
            .map_err(|_| ct_err())?;
        if !payload.is_empty() {
            ct_out.push(0xFF).map_err(|_| ct_err())?;
            ct_out.extend_from_slice(payload).map_err(|_| ct_err())?;
        }

        // Build AAD per RFC 8613 Section 5.4 using sender_id as request_kid
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(self.sender_id(), &piv[..piv_len], &mut aad_buf)?;

        // Encrypt in place using detached API (works with plain slices, no Buffer trait needed)
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut ct_out)
            .map_err(|_| OscoreError::EncryptFailed)?;
        ct_out.extend_from_slice(&tag).map_err(|_| ct_err())?;

        // Build OSCORE option
        const OPT_CAP: usize = 16;
        let mut opt = heapless::Vec::<u8, OPT_CAP>::new();
        let flags = 0x08 | (piv_len as u8 & 0x07); // k=1, n=piv_len
        let opt_required = 1 + piv_len + self.sender_id_len as usize;
        let opt_err = || BufferTooSmall::new(opt_required, OPT_CAP);
        opt.push(flags).map_err(|_| opt_err())?;
        opt.extend_from_slice(&piv[..piv_len])
            .map_err(|_| opt_err())?;
        opt.extend_from_slice(self.sender_id())
            .map_err(|_| opt_err())?;

        Ok((ct_out, opt))
    }

    /// Unprotect (decrypt) an OSCORE-protected request.
    ///
    /// Returns (code, class_e_options, payload).
    pub fn unprotect_request(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(OscoreError::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;

        if opt.piv_len == 0 {
            return Err(OscoreError::InvalidParam);
        }

        // SECURITY: Check replay BEFORE decryption, but update window AFTER.
        // This prevents attackers from poisoning the replay window with forged packets.
        let seq = OscoreSeqNum::from_piv(&opt.piv[..opt.piv_len as usize]);
        if self.is_replay(seq) {
            return Err(OscoreError::Replay);
        }

        // Compute nonce
        let nonce = compute_nonce(
            self.recipient_id(),
            &opt.piv[..opt.piv_len as usize],
            &self.common_iv,
        );

        // Build AAD per RFC 8613 Section 5.4 using sender's KID and PIV from request
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(
            &opt.kid[..opt.kid_len as usize],
            &opt.piv[..opt.piv_len as usize],
            &mut aad_buf,
        )?;

        // Decrypt in place using detached API (works with plain slices, no Buffer trait needed)
        // Split ciphertext into encrypted data and tag
        let tag_start = ciphertext.len() - TAG_LEN;
        let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext[tag_start..]);
        let cipher =
            AesCcm::new_from_slice(&self.recipient_key).map_err(|_| OscoreError::KeyDerivation)?;
        const PT_CAP: usize = 256;
        let mut plaintext = heapless::Vec::<u8, PT_CAP>::new();
        plaintext
            .extend_from_slice(&ciphertext[..tag_start])
            .map_err(|_| BufferTooSmall::new(tag_start, PT_CAP))?;
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut plaintext, tag)
            .map_err(|_| OscoreError::DecryptFailed)?;

        // SECURITY: Only update replay window AFTER successful decryption
        self.update_replay_window(seq);

        // Parse plaintext: code || options || 0xFF || payload
        // 0xFF is the CoAP payload marker (RFC 7252 Section 3).
        if plaintext.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        let code = plaintext[0];
        let rest = &plaintext[1..];

        // Find payload marker
        let marker_pos = rest.iter().position(|&b| b == 0xFF);

        let (options_slice, payload_slice) = match marker_pos {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };

        const OUT_CAP: usize = 128;
        let mut options = heapless::Vec::<u8, OUT_CAP>::new();
        options
            .extend_from_slice(options_slice)
            .map_err(|_| BufferTooSmall::new(options_slice.len(), OUT_CAP))?;

        let mut payload = heapless::Vec::<u8, OUT_CAP>::new();
        payload
            .extend_from_slice(payload_slice)
            .map_err(|_| BufferTooSmall::new(payload_slice.len(), OUT_CAP))?;

        Ok((code, options, payload))
    }

    /// Protect (encrypt) an OSCORE response.
    ///
    /// Unlike `protect_request`, responses:
    /// - Use the ORIGINAL request's KID and PIV for the AAD (ties response to request)
    /// - May omit PIV from the OSCORE option (when not generating a new sequence)
    /// - Use sender's sender_id for nonce computation
    ///
    /// Per RFC 8613 Section 5.2, when a response includes a PIV, the nonce uses
    /// the responder's sender_id and the responder's PIV. When omitting PIV, the
    /// nonce uses the responder's sender_id and the original request's PIV.
    ///
    /// Returns (ciphertext, oscore_option_value).
    ///
    /// # Parameters
    /// - `code`: Response code (e.g., 0x45 for 2.05 Content)
    /// - `class_e_options`: Class E CoAP options to encrypt
    /// - `payload`: Response payload to encrypt
    /// - `request_kid`: The KID from the original request (requester's sender_id)
    /// - `request_piv`: The PIV from the original request
    /// - `include_piv`: If true, generate new PIV and include in option; if false, use request_piv
    pub fn protect_response(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
        include_piv: bool,
    ) -> Result<(heapless::Vec<u8, 280>, heapless::Vec<u8, 16>), OscoreError> {
        // Determine PIV for nonce: own sequence if including, else request's PIV
        let (nonce_piv, piv_len, piv_for_option): ([u8; PIV_MAX_LEN], usize, Option<usize>) =
            if include_piv {
                // Generate own PIV
                if self.sender_seq.get() == u32::MAX {
                    return Err(OscoreError::SeqExhausted);
                }
                let seq = self.sender_seq.fetch_increment();
                let mut piv = [0u8; PIV_MAX_LEN];
                let len = seq.encode_piv(&mut piv);
                (piv, len, Some(len))
            } else {
                // Use request PIV for nonce (no new sequence generated)
                if request_piv.is_empty() || request_piv.len() > PIV_MAX_LEN {
                    return Err(OscoreError::InvalidParam);
                }
                let mut piv = [0u8; PIV_MAX_LEN];
                piv[..request_piv.len()].copy_from_slice(request_piv);
                (piv, request_piv.len(), None)
            };

        // Compute nonce using responder's sender_id and the chosen PIV
        let nonce = compute_nonce(self.sender_id(), &nonce_piv[..piv_len], &self.common_iv);

        // Build plaintext: code || options || 0xFF || payload
        const CT_CAP: usize = 280;
        let mut ct_out = heapless::Vec::<u8, CT_CAP>::new();
        let ct_required = 1
            + class_e_options.len()
            + if payload.is_empty() {
                0
            } else {
                1 + payload.len()
            }
            + TAG_LEN;
        let ct_err = || BufferTooSmall::new(ct_required, CT_CAP);
        ct_out.push(code).map_err(|_| ct_err())?;
        ct_out
            .extend_from_slice(class_e_options)
            .map_err(|_| ct_err())?;
        if !payload.is_empty() {
            ct_out.push(0xFF).map_err(|_| ct_err())?;
            ct_out.extend_from_slice(payload).map_err(|_| ct_err())?;
        }

        // Build AAD using ORIGINAL request's KID and PIV
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(request_kid, request_piv, &mut aad_buf)?;

        // Encrypt
        let cipher =
            AesCcm::new_from_slice(&self.sender_key).map_err(|_| OscoreError::KeyDerivation)?;
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut ct_out)
            .map_err(|_| OscoreError::EncryptFailed)?;
        ct_out.extend_from_slice(&tag).map_err(|_| ct_err())?;

        // Build OSCORE option
        const OPT_CAP: usize = 16;
        let mut opt = heapless::Vec::<u8, OPT_CAP>::new();

        if let Some(len) = piv_for_option {
            // Include PIV in option
            let flags = len as u8 & 0x07;
            opt.push(flags)
                .map_err(|_| BufferTooSmall::new(1 + len, OPT_CAP))?;
            opt.extend_from_slice(&nonce_piv[..len])
                .map_err(|_| BufferTooSmall::new(1 + len, OPT_CAP))?;
        } else {
            // No PIV in option - recipient will use request_piv
            opt.push(0x00)
                .map_err(|_| BufferTooSmall::new(1, OPT_CAP))?;
        }

        Ok((ct_out, opt))
    }

    /// Unprotect (decrypt) an OSCORE-protected response.
    ///
    /// Unlike `unprotect_request`, responses:
    /// - May omit PIV (use `request_piv` parameter for nonce if so)
    /// - Don't need replay protection (correlated with the original request)
    /// - Use different AAD structure per RFC 8613 Section 5.4 (includes request_kid/request_piv)
    ///
    /// Returns (code, class_e_options, payload).
    ///
    /// # Parameters
    /// - `oscore_option`: The OSCORE option from the response
    /// - `ciphertext`: The encrypted payload
    /// - `request_piv`: The PIV from the original request, used if response omits PIV
    pub fn unprotect_response(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(OscoreError::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;

        // RFC 8613 Section 5.2: For responses, if PIV is absent, use request_piv for nonce
        let piv = if opt.piv_len > 0 {
            &opt.piv[..opt.piv_len as usize]
        } else {
            if request_piv.is_empty() || request_piv.len() > PIV_MAX_LEN {
                return Err(OscoreError::InvalidParam);
            }
            request_piv
        };

        // Compute nonce using responder's sender_id (= our recipient_id)
        let nonce = compute_nonce(self.recipient_id(), piv, &self.common_iv);

        // Build AAD per RFC 8613 Section 5.4 using ORIGINAL request's KID and PIV
        // We (the client) sent the request, so request_kid is our sender_id
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(self.sender_id(), request_piv, &mut aad_buf)?;

        // Decrypt in place using detached API
        // SECURITY: No replay check for responses - they're correlated with requests
        let tag_start = ciphertext.len() - TAG_LEN;
        let tag = ccm::aead::Tag::<AesCcm>::from_slice(&ciphertext[tag_start..]);
        let cipher =
            AesCcm::new_from_slice(&self.recipient_key).map_err(|_| OscoreError::KeyDerivation)?;
        const PT_CAP: usize = 256;
        let mut plaintext = heapless::Vec::<u8, PT_CAP>::new();
        plaintext
            .extend_from_slice(&ciphertext[..tag_start])
            .map_err(|_| BufferTooSmall::new(tag_start, PT_CAP))?;
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad_buf[..aad_len], &mut plaintext, tag)
            .map_err(|_| OscoreError::DecryptFailed)?;

        // Parse plaintext: code || options || 0xFF || payload
        if plaintext.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        let code = plaintext[0];
        let rest = &plaintext[1..];

        // Find payload marker
        let marker_pos = rest.iter().position(|&b| b == 0xFF);

        let (options_slice, payload_slice) = match marker_pos {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };

        const OUT_CAP: usize = 128;
        let mut options = heapless::Vec::<u8, OUT_CAP>::new();
        options
            .extend_from_slice(options_slice)
            .map_err(|_| BufferTooSmall::new(options_slice.len(), OUT_CAP))?;

        let mut payload = heapless::Vec::<u8, OUT_CAP>::new();
        payload
            .extend_from_slice(payload_slice)
            .map_err(|_| BufferTooSmall::new(payload_slice.len(), OUT_CAP))?;

        Ok((code, options, payload))
    }

    /// Check if sequence number would be rejected as a replay.
    /// Does NOT update the replay window - call update_replay_window after successful decryption.
    fn is_replay(&self, seq: OscoreSeqNum) -> bool {
        let seq_val = seq.get();
        let recipient_seq_val = self.recipient_seq.get();

        if seq_val > recipient_seq_val {
            // New highest - always valid
            false
        } else {
            // Check if within window
            let diff = recipient_seq_val - seq_val;
            if diff >= WINDOW_SIZE {
                return true; // Too old
            }

            let mask = 1u32 << diff;
            self.replay_window & mask != 0 // Already seen
        }
    }

    /// Update replay window after successful decryption.
    /// SECURITY: Must only be called AFTER decryption succeeds to prevent replay-window poisoning.
    fn update_replay_window(&mut self, seq: OscoreSeqNum) {
        let seq_val = seq.get();
        let recipient_seq_val = self.recipient_seq.get();

        if seq_val > recipient_seq_val {
            // New highest - shift window
            let shift = seq_val - recipient_seq_val;
            if shift >= WINDOW_SIZE {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift;
            }
            self.replay_window |= 1;
            self.recipient_seq = seq;
        } else {
            // Mark as seen within window
            let diff = recipient_seq_val - seq_val;
            if diff < WINDOW_SIZE {
                let mask = 1u32 << diff;
                self.replay_window |= mask;
            }
        }
    }
}

/// Parsed OSCORE option.
#[derive(Debug)]
struct OscoreOption {
    piv: [u8; PIV_MAX_LEN],
    piv_len: u8,
    kid: [u8; ID_MAX_LEN],
    kid_len: u8,
}

fn parse_option(data: &[u8]) -> Result<OscoreOption, OscoreError> {
    let mut opt = OscoreOption {
        piv: [0; PIV_MAX_LEN],
        piv_len: 0,
        kid: [0; ID_MAX_LEN],
        kid_len: 0,
    };

    if data.is_empty() {
        return Ok(opt);
    }

    let mut pos = 0;
    let flags = data[pos];
    pos += 1;

    if flags & 0x80 != 0 {
        return Err(OscoreError::InvalidParam); // Reserved bit
    }

    let h_flag = flags & 0x10 != 0;
    let k_flag = flags & 0x08 != 0;
    let n = (flags & 0x07) as usize;

    // PIV
    if n > 0 {
        if n > PIV_MAX_LEN || pos + n > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        opt.piv[..n].copy_from_slice(&data[pos..pos + n]);
        opt.piv_len = n as u8;
        pos += n;
    }

    // KID Context (skip if present)
    if h_flag {
        if pos >= data.len() {
            return Err(OscoreError::InvalidParam);
        }
        let s = data[pos] as usize;
        pos += 1;
        if pos + s > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        pos += s;
    }

    // KID
    if k_flag {
        let remaining = data.len() - pos;
        if remaining > ID_MAX_LEN {
            return Err(OscoreError::InvalidParam);
        }
        opt.kid[..remaining].copy_from_slice(&data[pos..]);
        opt.kid_len = remaining as u8;
    }

    Ok(opt)
}

/// Derive sender/recipient key using HKDF-SHA256 (returns 16-byte AES key).
fn derive_key(
    master_secret: &[u8],
    master_salt: &[u8],
    id: &[u8],
    id_context: &[u8],
) -> Result<[u8; KEY_LEN], OscoreError> {
    // Build CBOR info structure per RFC 8613 Section 3.2.1
    let mut info = [0u8; 64];
    let info_len = build_info_cbor(id, id_context, "Key", KEY_LEN, &mut info)?;

    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info[..info_len], &mut okm)
        .map_err(|_| OscoreError::KeyDerivation)?;

    Ok(okm)
}

/// Derive Common IV using HKDF-SHA256 (returns 13-byte nonce).
fn derive_iv(
    master_secret: &[u8],
    master_salt: &[u8],
    id_context: &[u8],
) -> Result<[u8; NONCE_LEN], OscoreError> {
    // Build CBOR info structure per RFC 8613 Section 3.2.1
    // Common IV uses empty ID per RFC 8613 Section 3.2.1
    let mut info = [0u8; 64];
    let info_len = build_info_cbor(&[], id_context, "IV", NONCE_LEN, &mut info)?;

    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    let mut okm = [0u8; NONCE_LEN];
    hk.expand(&info[..info_len], &mut okm)
        .map_err(|_| OscoreError::KeyDerivation)?;

    Ok(okm)
}

/// Build OSCORE HKDF info CBOR structure per RFC 8613 Section 3.2.1.
///
/// CDDL schema (RFC 8613):
/// ```cddl
/// info = [
///     id: bstr,
///     id_context: bstr / nil,
///     alg_aead: int,
///     type: tstr,
///     L: uint
/// ]
/// ```
///
/// - `id`: Sender ID or Recipient ID (depends on key type being derived)
/// - `id_context`: ID Context if present, otherwise CBOR null (0xf6)
/// - `alg_aead`: AEAD algorithm identifier (10 = AES-CCM-16-64-128)
/// - `type`: "Key" or "IV" indicating which material is being derived
/// - `L`: Output length in bytes (16 for Key, 13 for IV)
fn build_info_cbor(
    id: &[u8],
    id_context: &[u8],
    type_str: &str,
    out_len: usize,
    buf: &mut [u8],
) -> Result<usize, OscoreError> {
    let mut off = 0;

    // Array of 5 elements
    buf[off] = 0x85;
    off += 1;

    // id: bstr
    if id.len() <= 23 {
        buf[off] = 0x40 | (id.len() as u8);
        off += 1;
    } else {
        buf[off] = 0x58;
        buf[off + 1] = id.len() as u8;
        off += 2;
    }
    buf[off..off + id.len()].copy_from_slice(id);
    off += id.len();

    // id_context: bstr or null
    if id_context.is_empty() {
        buf[off] = 0xf6; // null
        off += 1;
    } else {
        if id_context.len() <= 23 {
            buf[off] = 0x40 | (id_context.len() as u8);
            off += 1;
        } else {
            buf[off] = 0x58;
            buf[off + 1] = id_context.len() as u8;
            off += 2;
        }
        buf[off..off + id_context.len()].copy_from_slice(id_context);
        off += id_context.len();
    }

    // alg_aead: int (10)
    buf[off] = ALG_AEAD;
    off += 1;

    // type: tstr
    let type_bytes = type_str.as_bytes();
    if type_bytes.len() <= 23 {
        buf[off] = 0x60 | (type_bytes.len() as u8);
        off += 1;
    } else {
        buf[off] = 0x78;
        buf[off + 1] = type_bytes.len() as u8;
        off += 2;
    }
    buf[off..off + type_bytes.len()].copy_from_slice(type_bytes);
    off += type_bytes.len();

    // L: uint
    if out_len <= 23 {
        buf[off] = out_len as u8;
        off += 1;
    } else {
        buf[off] = 0x18;
        buf[off + 1] = out_len as u8;
        off += 2;
    }

    Ok(off)
}

/// Build OSCORE AAD (Additional Authenticated Data) per RFC 8613 Section 5.4.
///
/// The AAD for OSCORE is a CBOR Enc_structure (RFC 9052 Section 5.3):
/// ```cddl
/// Enc_structure = [
///     "Encrypt0",     // context string
///     h'',            // protected header (empty for OSCORE)
///     external_aad    // bstr wrapping aad_array
/// ]
///
/// aad_array = [
///     oscore_version,  // uint = 1
///     [alg_aead],      // 1-element array with algorithm
///     request_kid,     // bstr
///     request_piv,     // bstr
///     options          // bstr (Class I options, empty)
/// ]
/// ```
///
/// Both requests and responses use the SAME AAD, built from the original
/// request's KID and PIV. This ties the response cryptographically to its request.
fn build_aad_cbor(
    request_kid: &[u8],
    request_piv: &[u8],
    buf: &mut [u8],
) -> Result<usize, OscoreError> {
    // Build the inner aad_array first
    let mut inner = [0u8; 64];
    let mut ioff = 0;

    // aad_array: 5-element array (0x85 = 0x80 | 5)
    inner[ioff] = 0x85;
    ioff += 1;

    // oscore_version: uint = 1
    inner[ioff] = 0x01;
    ioff += 1;

    // algorithms: 1-element array containing alg_aead
    // 0x81 = array of 1 item, then ALG_AEAD = 10
    inner[ioff] = 0x81;
    ioff += 1;
    inner[ioff] = ALG_AEAD;
    ioff += 1;

    // request_kid: bstr
    if request_kid.len() > 23 {
        return Err(OscoreError::InvalidParam);
    }
    inner[ioff] = 0x40 | (request_kid.len() as u8);
    ioff += 1;
    if !request_kid.is_empty() {
        inner[ioff..ioff + request_kid.len()].copy_from_slice(request_kid);
        ioff += request_kid.len();
    }

    // request_piv: bstr
    if request_piv.len() > 23 {
        return Err(OscoreError::InvalidParam);
    }
    inner[ioff] = 0x40 | (request_piv.len() as u8);
    ioff += 1;
    if !request_piv.is_empty() {
        inner[ioff..ioff + request_piv.len()].copy_from_slice(request_piv);
        ioff += request_piv.len();
    }

    // options: empty bstr (Class I options not used)
    inner[ioff] = 0x40;
    ioff += 1;

    // Now build Enc_structure: ["Encrypt0", h'', external_aad]
    let mut off = 0;

    // 3-element array (0x83 = 0x80 | 3)
    if off >= buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x83;
    off += 1;

    // "Encrypt0" as tstr (8 chars): 0x68 = 0x60 | 8
    if off + 9 > buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x68;
    off += 1;
    buf[off..off + 8].copy_from_slice(b"Encrypt0");
    off += 8;

    // empty bstr (protected header): 0x40
    if off >= buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off] = 0x40;
    off += 1;

    // external_aad: bstr wrapping the inner CBOR
    if ioff <= 23 {
        if off >= buf.len() {
            return Err(OscoreError::InvalidParam);
        }
        buf[off] = 0x40 | (ioff as u8);
        off += 1;
    } else {
        if off + 1 >= buf.len() {
            return Err(OscoreError::InvalidParam);
        }
        buf[off] = 0x58;
        buf[off + 1] = ioff as u8;
        off += 2;
    }

    if off + ioff > buf.len() {
        return Err(OscoreError::InvalidParam);
    }
    buf[off..off + ioff].copy_from_slice(&inner[..ioff]);
    off += ioff;

    Ok(off)
}

/// Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
///
/// Nonce layout (NONCE_LEN = 13 bytes):
/// ```text
/// +--------+------------------+------------------+
/// | 1 byte |     7 bytes      |     5 bytes      |
/// +--------+------------------+------------------+
/// |   S    | left-padded ID   | left-padded PIV  |
/// +--------+------------------+------------------+
///   [0]      [1..NONCE_ID_END)  [NONCE_PIV_START..NONCE_LEN)
/// ```
///
/// S = sender_id_len XOR piv_len (RFC 8613 Section 5.2)
/// The entire nonce is XOR'd with Common IV before use.
fn compute_nonce(sender_id: &[u8], piv: &[u8], common_iv: &[u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];

    // Byte 0: S = sender_id_len XOR piv_len
    nonce[0] = (sender_id.len() as u8) ^ (piv.len() as u8);

    // Bytes 1..NONCE_ID_END: left-padded sender ID (right-aligned, max NONCE_ID_LEN bytes)
    if sender_id.len() <= NONCE_ID_LEN {
        let start = NONCE_ID_END - sender_id.len();
        nonce[start..NONCE_ID_END].copy_from_slice(sender_id);
    }

    // Bytes NONCE_PIV_START..NONCE_LEN: left-padded PIV (right-aligned, max PIV_MAX_LEN bytes)
    if !piv.is_empty() && piv.len() <= PIV_MAX_LEN {
        let piv_end = NONCE_LEN;
        nonce[piv_end - piv.len()..piv_end].copy_from_slice(piv);
    }

    // XOR entire nonce with Common IV
    for (i, &b) in common_iv.iter().enumerate() {
        nonce[i] ^= b;
    }

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_piv_encode_decode() {
        let mut piv = [0u8; PIV_MAX_LEN];

        let seq = OscoreSeqNum::new(0);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 0);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).get(), 0);

        let seq = OscoreSeqNum::new(1);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 1);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).get(), 1);

        let seq = OscoreSeqNum::new(256);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 2);
        assert_eq!(&piv[..2], &[0x01, 0x00]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).get(), 256);

        let seq = OscoreSeqNum::new(0x123456);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 3);
        assert_eq!(&piv[..3], &[0x12, 0x34, 0x56]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).get(), 0x123456);
    }

    #[test]
    fn test_context_creation() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let sender_id = &[0x00];
        let recipient_id = &[0x01];

        let ctx = Context::new(&master_secret, None, sender_id, recipient_id).unwrap();

        assert_eq!(ctx.sender_id(), &[0x00]);
        assert_eq!(ctx.recipient_id(), &[0x01]);
        assert_eq!(ctx.sender_seq().get(), 0);
    }

    fn seq(n: u32) -> OscoreSeqNum {
        OscoreSeqNum::new(n)
    }

    #[test]
    fn test_replay_window() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new(&master_secret, None, &[0], &[1]).unwrap();

        // First packet accepted (is_replay returns false for valid packets)
        assert!(!ctx.is_replay(seq(0)));
        ctx.update_replay_window(seq(0));
        // Replay rejected (is_replay returns true for replays)
        assert!(ctx.is_replay(seq(0)));
        // New packet accepted
        assert!(!ctx.is_replay(seq(1)));
        ctx.update_replay_window(seq(1));
        // Earlier replay rejected
        assert!(ctx.is_replay(seq(0)));
        // Jump ahead - accepted
        assert!(!ctx.is_replay(seq(100)));
        ctx.update_replay_window(seq(100));
        // Now 50 is too old (outside window)
        assert!(ctx.is_replay(seq(50)));
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender_ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut recipient_ctx = Context::new(&master_secret, None, &[0x01], &[0x00]).unwrap();

        let code = 0x01; // GET
        let payload = b"hello";

        let (ciphertext, oscore_opt) = sender_ctx.protect_request(code, &[], payload).unwrap();

        let (dec_code, _options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .unwrap();

        assert_eq!(dec_code, code);
        assert_eq!(dec_payload.as_slice(), payload);
    }

    #[test]
    fn test_seq_exhaustion_returns_error() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();

        // Set sender_seq to MAX to simulate exhaustion
        ctx.sender_seq = OscoreSeqNum::new(u32::MAX);

        let result = ctx.protect_request(0x01, &[], b"test");
        assert_eq!(result.unwrap_err(), OscoreError::SeqExhausted);
    }

    #[test]
    fn test_unprotect_response_with_piv() {
        // Simulate Alice -> Bob request, Bob -> Alice response
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice_ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut bob_ctx = Context::new(&master_secret, None, &[0x01], &[0x00]).unwrap();

        // Alice sends request, save request_kid and request_piv
        let (_ciphertext, request_opt) = alice_ctx.protect_request(0x01, &[], b"request").unwrap();
        let request_piv_len = (request_opt[0] & 0x07) as usize;
        let request_piv = &request_opt[1..1 + request_piv_len];
        // Request KID is Alice's sender_id
        let request_kid = alice_ctx.sender_id();

        // Bob sends response using protect_response (with proper AAD)
        let response_code = 0x45; // 2.05 Content
        let (response_ciphertext, response_opt) = bob_ctx
            .protect_response(
                response_code,
                &[],
                b"response",
                request_kid,
                request_piv,
                true,
            )
            .unwrap();

        // Alice decrypts response using unprotect_response
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), b"response");
    }

    #[test]
    fn test_unprotect_response_without_piv_uses_request_piv() {
        // Test that when response has no PIV in OSCORE option, request_piv is used for nonce
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice_ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut bob_ctx = Context::new(&master_secret, None, &[0x01], &[0x00]).unwrap();

        // Alice sends request, save request_kid and request_piv
        let (_ciphertext, request_opt) = alice_ctx.protect_request(0x01, &[], b"request").unwrap();
        let request_piv_len = (request_opt[0] & 0x07) as usize;
        let request_piv = request_opt[1..1 + request_piv_len].to_vec();
        let request_kid = alice_ctx.sender_id();

        // Bob sends response without PIV in OSCORE option (include_piv: false)
        let response_code = 0x45u8;
        let payload = b"response";
        let (response_ciphertext, response_opt) = bob_ctx
            .protect_response(
                response_code,
                &[],
                payload,
                request_kid,
                &request_piv,
                false,
            )
            .unwrap();

        // Verify response option has no PIV (flags = 0x00)
        assert_eq!(response_opt.as_slice(), &[0x00u8]);

        // Alice decrypts using unprotect_response with request_piv
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, &request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), payload);
    }
}
