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

/// Sender sequence state that must be persisted before transmitting a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderSequenceState {
    /// Next sender sequence that may be used.
    pub next_sequence: u64,
    /// Whether the terminal sequence has already been consumed.
    pub exhausted: bool,
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
/// via the `Zeroize` derive. A context cannot be cloned because its sender sequence and
/// replay state must have exactly one synchronized owner.
///
/// ```compile_fail
/// # use lichen_oscore::Context;
/// # let secret = [0; 16];
/// let context = Context::new(&secret, None, b"a", b"b").unwrap();
/// let duplicate = context.clone();
/// ```
#[derive(Zeroize)]
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
    sender_seq_exhausted: bool,
    restored: bool,

    // Recipient context
    recipient_id: [u8; ID_MAX_LEN],
    recipient_id_len: u8,
    recipient_key: [u8; KEY_LEN],
    recipient_seq: OscoreSeqNum,
    replay_window: u32,

    // Requests for which a response without a fresh PIV has already been protected.
    response_seq: OscoreSeqNum,
    response_window: u32,
    response_window_initialized: bool,
    allow_no_piv_response: bool,
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
            .field("sender_seq_exhausted", &self.sender_seq_exhausted)
            .field("restored", &self.restored)
            .field("recipient_id_len", &self.recipient_id_len)
            .field("recipient_key", &"[REDACTED]")
            .field("recipient_seq", &self.recipient_seq)
            .field("replay_window", &self.replay_window)
            .field("response_seq", &self.response_seq)
            .field("response_window", &self.response_window)
            .finish()
    }
}

impl Context {
    /// Create a new OSCORE security context from cryptographically fresh key material.
    ///
    /// Derives sender and recipient keys from master secret using HKDF-SHA256.
    /// This starts the sender sequence at zero and MUST NOT be used to reopen a
    /// previously persisted context. Use [`Context::restore`] with persisted sender
    /// state instead, or nonce reuse can compromise confidentiality.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParam` if:
    /// - `sender_id` or `recipient_id` exceeds 7 bytes (nonce capacity)
    /// - `sender_id` and `recipient_id` are equal
    /// - `master_salt` exceeds 8 bytes
    pub fn new(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, OscoreError> {
        Self::from_sender_state(
            master_secret,
            master_salt,
            sender_id,
            recipient_id,
            OscoreSeqNum::default(),
            false,
            false,
        )
    }

    /// Restore an OSCORE context from persisted sender state.
    ///
    /// `next_sender_sequence` is the next reserved sequence number that may be used.
    /// Persist the advanced reservation before transmitting a protected message. An
    /// exhausted context is represented by `next_sender_sequence == OscoreSeqNum::MAX`
    /// and `sender_sequence_exhausted == true` and cannot protect further messages.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParam` for invalid IDs or salt, a sequence above the 40-bit
    /// maximum, or an inconsistent exhausted state.
    pub fn restore(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
        next_sender_sequence: u64,
        sender_sequence_exhausted: bool,
    ) -> Result<Self, OscoreError> {
        let sender_seq =
            OscoreSeqNum::new(next_sender_sequence).ok_or(OscoreError::InvalidParam)?;
        if sender_sequence_exhausted && next_sender_sequence != OscoreSeqNum::MAX {
            return Err(OscoreError::InvalidParam);
        }
        Self::from_sender_state(
            master_secret,
            master_salt,
            sender_id,
            recipient_id,
            sender_seq,
            sender_sequence_exhausted,
            true,
        )
    }

    fn from_sender_state(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
        sender_seq: OscoreSeqNum,
        sender_seq_exhausted: bool,
        restored: bool,
    ) -> Result<Self, OscoreError> {
        // SECURITY: Validate ID length against nonce capacity (7 bytes), not ID_MAX_LEN (8).
        // RFC 8613 allows IDs up to 8 bytes, but only 7 bytes fit in the nonce layout.
        // Accepting 8-byte IDs would cause silent truncation in compute_nonce.
        if sender_id.len() > NONCE_ID_LEN
            || recipient_id.len() > NONCE_ID_LEN
            || sender_id == recipient_id
        {
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
            sender_seq,
            sender_seq_exhausted,
            restored,
            recipient_id: [0u8; ID_MAX_LEN],
            recipient_id_len: recipient_id.len() as u8,
            recipient_key: [0u8; KEY_LEN],
            recipient_seq: OscoreSeqNum::default(),
            replay_window: 0,
            response_seq: OscoreSeqNum::default(),
            response_window: 0,
            response_window_initialized: false,
            allow_no_piv_response: !restored,
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

    /// Get the next sender sequence number, or `None` if it is exhausted.
    pub fn sender_seq(&self) -> Option<OscoreSeqNum> {
        (!self.sender_seq_exhausted).then_some(self.sender_seq)
    }

    /// Return the sender reservation that must be durable before transmission.
    pub fn sender_sequence_state(&self) -> SenderSequenceState {
        SenderSequenceState {
            next_sequence: self.sender_seq.get(),
            exhausted: self.sender_seq_exhausted,
        }
    }

    /// Return whether this context was reconstructed from persisted state.
    pub fn is_restored(&self) -> bool {
        self.restored
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
    /// Returns `SeqExhausted` when the sender sequence number reaches the 40-bit maximum.
    /// The security context must be renegotiated before this happens to prevent
    /// nonce reuse (RFC 8613 Section 7.2.1).
    pub fn protect_request(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<(heapless::Vec<u8, 280>, heapless::Vec<u8, 16>), OscoreError> {
        let seq = self.next_sender_seq()?;

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

        if opt.piv_len == 0 || !opt.kid_present {
            return Err(OscoreError::InvalidParam);
        }
        if opt.kid_context_present
            && opt.kid_context[..opt.kid_context_len as usize]
                != self.id_context[..self.id_context_len as usize]
        {
            return Err(OscoreError::NoContext);
        }

        // SECURITY: Check replay BEFORE decryption, but update window AFTER.
        // This prevents attackers from poisoning the replay window with forged packets.
        let seq = OscoreSeqNum::from_piv(&opt.piv[..opt.piv_len as usize])
            .ok_or(OscoreError::InvalidParam)?;
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

        let (options_slice, payload_slice) = parse_inner_body(rest)?;

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
    /// - Reuse the request nonce when omitting the response PIV
    ///
    /// Per RFC 8613 Section 5.2, when a response includes a PIV, the nonce uses
    /// the responder's sender_id and the responder's PIV. When omitting PIV, the
    /// nonce uses the requester's ID and the original request's PIV. A response
    /// without a PIV is therefore allowed only once per request KID/PIV. Requests
    /// older than the bounded response window are also rejected conservatively.
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
        if request_kid.len() > NONCE_ID_LEN
            || OscoreSeqNum::from_piv(request_piv).is_none()
            || request_kid != self.recipient_id()
            || (!include_piv && !self.allow_no_piv_response)
        {
            return Err(OscoreError::InvalidParam);
        }

        let request_seq = OscoreSeqNum::from_piv(request_piv).ok_or(OscoreError::InvalidParam)?;
        if !include_piv && self.is_response_reuse(request_seq) {
            return Err(OscoreError::Replay);
        }

        // Determine PIV for nonce: own sequence if including, else request's PIV
        let (nonce_piv, piv_len, piv_for_option): ([u8; PIV_MAX_LEN], usize, Option<usize>) =
            if include_piv {
                // Generate own PIV
                let seq = self.next_sender_seq()?;
                let mut piv = [0u8; PIV_MAX_LEN];
                let len = seq.encode_piv(&mut piv);
                (piv, len, Some(len))
            } else {
                // Use request PIV for nonce (no new sequence generated)
                let mut piv = [0u8; PIV_MAX_LEN];
                piv[..request_piv.len()].copy_from_slice(request_piv);
                (piv, request_piv.len(), None)
            };

        let nonce_id = if include_piv {
            self.sender_id()
        } else {
            request_kid
        };
        let nonce = compute_nonce(nonce_id, &nonce_piv[..piv_len], &self.common_iv);

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
            // An all-zero option value is encoded as a zero-length option.
        }

        if !include_piv {
            self.mark_response_used(request_seq);
        }

        Ok((ct_out, opt))
    }

    /// Protect a response with a fresh sender PIV.
    ///
    /// Use this for Observe notifications or any request that can produce multiple
    /// responses. Each call consumes a sender sequence and therefore uses a unique nonce.
    pub fn protect_response_with_piv(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
        request_kid: &[u8],
        request_piv: &[u8],
    ) -> Result<(heapless::Vec<u8, 280>, heapless::Vec<u8, 16>), OscoreError> {
        self.protect_response(
            code,
            class_e_options,
            payload,
            request_kid,
            request_piv,
            true,
        )
    }

    /// Unprotect (decrypt) an OSCORE-protected response.
    ///
    /// Unlike `unprotect_request`, responses:
    /// - May omit PIV (use `request_piv` parameter for nonce if so)
    /// - Do not use the incoming request replay window
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
        self.unprotect_response_inner(oscore_option, ciphertext, request_piv, false)
    }

    /// Unprotect an Observe notification or another response with a fresh PIV.
    ///
    /// Unlike [`Context::unprotect_response`], this applies the peer sender replay
    /// window and rejects responses that omit a fresh PIV.
    pub fn unprotect_notification(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        self.unprotect_response_inner(oscore_option, ciphertext, request_piv, true)
    }

    fn unprotect_response_inner(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
        request_piv: &[u8],
        check_replay: bool,
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), OscoreError> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(OscoreError::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;
        if opt.kid_context_present
            && opt.kid_context[..opt.kid_context_len as usize]
                != self.id_context[..self.id_context_len as usize]
        {
            return Err(OscoreError::NoContext);
        }

        // RFC 8613 Section 5.2: For responses, if PIV is absent, use request_piv for nonce
        let (piv, response_seq) = if opt.piv_len > 0 {
            let piv = &opt.piv[..opt.piv_len as usize];
            let seq = OscoreSeqNum::from_piv(piv).ok_or(OscoreError::InvalidParam)?;
            (piv, Some(seq))
        } else {
            if check_replay {
                return Err(OscoreError::InvalidParam);
            }
            if OscoreSeqNum::from_piv(request_piv).is_none() {
                return Err(OscoreError::InvalidParam);
            }
            (request_piv, None)
        };

        if response_seq.is_some_and(|seq| check_replay && self.is_replay(seq)) {
            return Err(OscoreError::Replay);
        }

        let nonce_id = if response_seq.is_some() {
            self.recipient_id()
        } else {
            self.sender_id()
        };
        let nonce = compute_nonce(nonce_id, piv, &self.common_iv);

        // Build AAD per RFC 8613 Section 5.4 using ORIGINAL request's KID and PIV
        // We (the client) sent the request, so request_kid is our sender_id
        let mut aad_buf = [0u8; 64];
        let aad_len = build_aad_cbor(self.sender_id(), request_piv, &mut aad_buf)?;

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

        if check_replay {
            self.update_replay_window(response_seq.expect("notification requires a fresh PIV"));
        }

        // Parse plaintext: code || options || 0xFF || payload
        if plaintext.is_empty() {
            return Err(OscoreError::InvalidParam);
        }

        let code = plaintext[0];
        let rest = &plaintext[1..];

        let (options_slice, payload_slice) = parse_inner_body(rest)?;

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

    fn next_sender_seq(&mut self) -> Result<OscoreSeqNum, OscoreError> {
        if self.sender_seq_exhausted {
            return Err(OscoreError::SeqExhausted);
        }

        let seq = self.sender_seq;
        if let Some(next) = seq.increment() {
            self.sender_seq = next;
        } else {
            self.sender_seq_exhausted = true;
        }
        Ok(seq)
    }

    fn is_response_reuse(&self, seq: OscoreSeqNum) -> bool {
        if !self.response_window_initialized || seq.get() > self.response_seq.get() {
            return false;
        }

        let diff = self.response_seq.get() - seq.get();
        diff >= u64::from(WINDOW_SIZE) || self.response_window & (1 << diff as u32) != 0
    }

    fn mark_response_used(&mut self, seq: OscoreSeqNum) {
        if !self.response_window_initialized {
            self.response_seq = seq;
            self.response_window = 1;
            self.response_window_initialized = true;
        } else if seq.get() > self.response_seq.get() {
            let shift = seq.get() - self.response_seq.get();
            self.response_window = if shift >= u64::from(WINDOW_SIZE) {
                1
            } else {
                (self.response_window << shift as u32) | 1
            };
            self.response_seq = seq;
        } else {
            let diff = self.response_seq.get() - seq.get();
            self.response_window |= 1 << diff as u32;
        }
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
            if diff >= u64::from(WINDOW_SIZE) {
                return true; // Too old
            }

            let mask = 1u32 << diff as u32;
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
            if shift >= u64::from(WINDOW_SIZE) {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift as u32;
            }
            self.replay_window |= 1;
            self.recipient_seq = seq;
        } else {
            // Mark as seen within window
            let diff = recipient_seq_val - seq_val;
            if diff < u64::from(WINDOW_SIZE) {
                let mask = 1u32 << diff as u32;
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
    kid_context: [u8; 8],
    kid_context_len: u8,
    kid_context_present: bool,
    kid: [u8; ID_MAX_LEN],
    kid_len: u8,
    kid_present: bool,
}

fn parse_option(data: &[u8]) -> Result<OscoreOption, OscoreError> {
    let mut opt = OscoreOption {
        piv: [0; PIV_MAX_LEN],
        piv_len: 0,
        kid_context: [0; 8],
        kid_context_len: 0,
        kid_context_present: false,
        kid: [0; ID_MAX_LEN],
        kid_len: 0,
        kid_present: false,
    };

    if data.is_empty() {
        return Ok(opt);
    }
    if data == [0] {
        return Err(OscoreError::InvalidParam);
    }

    let mut pos = 0;
    let flags = data[pos];
    pos += 1;

    if flags & 0xe0 != 0 {
        return Err(OscoreError::InvalidParam);
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

    // KID Context
    if h_flag {
        if pos >= data.len() {
            return Err(OscoreError::InvalidParam);
        }
        let s = data[pos] as usize;
        pos += 1;
        if s > opt.kid_context.len() || pos + s > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        opt.kid_context[..s].copy_from_slice(&data[pos..pos + s]);
        opt.kid_context_len = s as u8;
        opt.kid_context_present = true;
        pos += s;
    }

    // KID
    if k_flag {
        opt.kid_present = true;
        let remaining = data.len() - pos;
        if remaining > ID_MAX_LEN {
            return Err(OscoreError::InvalidParam);
        }
        opt.kid[..remaining].copy_from_slice(&data[pos..]);
        opt.kid_len = remaining as u8;
    } else if pos != data.len() {
        return Err(OscoreError::InvalidParam);
    }

    Ok(opt)
}

/// Split an inner CoAP body into encoded options and payload.
fn parse_inner_body(data: &[u8]) -> Result<(&[u8], &[u8]), OscoreError> {
    let mut pos = 0usize;
    let mut option_number = 0u16;

    while pos < data.len() {
        let option_start = pos;
        let header = data[pos];
        pos = pos.checked_add(1).ok_or(OscoreError::InvalidParam)?;

        if header == 0xff {
            if pos == data.len() {
                return Err(OscoreError::InvalidParam);
            }
            return Ok((&data[..option_start], &data[pos..]));
        }

        let mut decode_nibble = |nibble: u8| -> Result<usize, OscoreError> {
            match nibble {
                0..=12 => Ok(nibble as usize),
                13 => {
                    let value = *data.get(pos).ok_or(OscoreError::InvalidParam)? as usize;
                    pos = pos.checked_add(1).ok_or(OscoreError::InvalidParam)?;
                    13usize.checked_add(value).ok_or(OscoreError::InvalidParam)
                }
                14 => {
                    let end = pos.checked_add(2).ok_or(OscoreError::InvalidParam)?;
                    let bytes = data.get(pos..end).ok_or(OscoreError::InvalidParam)?;
                    pos = end;
                    let value = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                    269usize.checked_add(value).ok_or(OscoreError::InvalidParam)
                }
                15 => Err(OscoreError::InvalidParam),
                _ => unreachable!(),
            }
        };

        let delta = decode_nibble(header >> 4)?;
        let length = decode_nibble(header & 0x0f)?;
        let delta = u16::try_from(delta).map_err(|_| OscoreError::InvalidParam)?;
        option_number = option_number
            .checked_add(delta)
            .ok_or(OscoreError::InvalidParam)?;

        let end = pos.checked_add(length).ok_or(OscoreError::InvalidParam)?;
        if end > data.len() {
            return Err(OscoreError::InvalidParam);
        }
        pos = end;
    }

    Ok((data, &[]))
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
/// S = sender_id_len (RFC 8613 Section 5.2)
/// The entire nonce is XOR'd with Common IV before use.
fn compute_nonce(sender_id: &[u8], piv: &[u8], common_iv: &[u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];

    // Byte 0: S = sender ID length.
    nonce[0] = sender_id.len() as u8;

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

        let seq = OscoreSeqNum::new(0).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 0);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 0);

        let seq = OscoreSeqNum::new(1).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 1);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 1);

        let seq = OscoreSeqNum::new(256).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 2);
        assert_eq!(&piv[..2], &[0x01, 0x00]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 256);

        let seq = OscoreSeqNum::new(0x123456).unwrap();
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 3);
        assert_eq!(&piv[..3], &[0x12, 0x34, 0x56]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]).unwrap().get(), 0x123456);
    }

    #[test]
    fn test_context_creation() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let sender_id = &[0x00];
        let recipient_id = &[0x01];

        let ctx = Context::new(&master_secret, None, sender_id, recipient_id).unwrap();

        assert_eq!(ctx.sender_id(), &[0x00]);
        assert_eq!(ctx.recipient_id(), &[0x01]);
        assert_eq!(ctx.sender_seq().unwrap().get(), 0);
        assert_eq!(
            Context::new(&master_secret, None, sender_id, sender_id).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn restored_context_continues_at_reserved_sequence() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::restore(&master_secret, None, &[0], &[1], 0x0102, false).unwrap();

        let (_, option) = ctx.protect_request(0x01, &[], b"restored").unwrap();

        assert_eq!(option.as_slice(), b"\x0a\x01\x02\x00");
        assert_eq!(ctx.sender_seq().unwrap().get(), 0x0103);
        assert!(ctx.is_restored());
        assert_eq!(
            ctx.sender_sequence_state(),
            SenderSequenceState {
                next_sequence: 0x0103,
                exhausted: false
            }
        );
    }

    #[test]
    fn restored_context_rejects_response_without_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::restore(&master_secret, None, &[1], &[0], 7, false).unwrap();

        assert_eq!(
            ctx.protect_response(0x45, &[], b"response", &[0], &[3], false)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn restore_rejects_invalid_sender_state() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");

        assert_eq!(
            Context::restore(
                &master_secret,
                None,
                &[0],
                &[1],
                OscoreSeqNum::MAX + 1,
                false
            )
            .unwrap_err(),
            OscoreError::InvalidParam
        );
        assert_eq!(
            Context::restore(&master_secret, None, &[0], &[1], 7, true).unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn rfc8613_nonce_formula_literal() {
        assert_eq!(
            compute_nonce(&[0xaa, 0xbb], &[0x01, 0x02, 0x03], &[0; NONCE_LEN]),
            hex!("020000000000aabb0000010203")
        );
    }

    #[test]
    fn oscore_option_literals() {
        let empty = parse_option(b"").unwrap();
        assert_eq!(empty.piv_len, 0);
        assert_eq!(empty.kid_len, 0);
        assert!(!empty.kid_present);
        assert!(!empty.kid_context_present);

        let populated = parse_option(b"\x09\x01\xaa").unwrap();
        assert_eq!(&populated.piv[..populated.piv_len as usize], b"\x01");
        assert_eq!(&populated.kid[..populated.kid_len as usize], b"\xaa");
        assert!(populated.kid_present);

        let with_context = parse_option(b"\x19\x01\x02\xbb\xcc\xaa").unwrap();
        assert_eq!(
            &with_context.kid_context[..with_context.kid_context_len as usize],
            b"\xbb\xcc"
        );
        assert!(with_context.kid_context_present);
        assert!(with_context.kid_present);

        for malformed in [
            &b"\x00"[..],
            &b"\x20"[..],
            &b"\x40"[..],
            &b"\x80"[..],
            &b"\x00\xaa"[..],
            &b"\x01\xaa\xbb"[..],
            &b"\x10\x00\xaa"[..],
        ] {
            assert_eq!(
                parse_option(malformed).unwrap_err(),
                OscoreError::InvalidParam
            );
        }
    }

    #[test]
    fn response_without_piv_uses_literal_request_nonce() {
        let master_secret = [0; KEY_LEN];
        let mut responder = Context::new(&master_secret, None, b"\xbb\xcc", b"\xaa").unwrap();
        responder.sender_key = [0x11; KEY_LEN];
        responder.common_iv = [0; NONCE_LEN];

        let (ciphertext, option) = responder
            .protect_response(0x45, &[], &[], b"\xaa", b"\x05", false)
            .unwrap();

        assert_eq!(ciphertext.as_slice(), &hex!("26f4d77f5a397d9c0a"));
        assert!(option.is_empty());
    }

    fn seq(n: u64) -> OscoreSeqNum {
        OscoreSeqNum::new(n).unwrap()
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
    fn five_byte_replay_ordering_and_duplicates() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new(&master_secret, None, &[1], &[0]).unwrap();
        sender.sender_seq = seq(0x1_0000_0000);

        let first = sender.protect_request(0x01, &[], b"first").unwrap();
        let second = sender.protect_request(0x01, &[], b"second").unwrap();
        assert_eq!(&first.1[1..6], b"\x01\x00\x00\x00\x00");

        recipient.unprotect_request(&second.1, &second.0).unwrap();
        recipient.unprotect_request(&first.1, &first.0).unwrap();
        assert_eq!(
            recipient.unprotect_request(&first.1, &first.0).unwrap_err(),
            OscoreError::Replay
        );
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
    fn empty_request_kid_still_requires_k_flag() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new(&master_secret, None, b"", b"\x01").unwrap();
        let mut recipient = Context::new(&master_secret, None, b"\x01", b"").unwrap();
        let (ciphertext, option) = sender.protect_request(0x01, &[], b"request").unwrap();

        assert_eq!(option.as_slice(), b"\x09\x00");
        assert_eq!(
            recipient
                .unprotect_request(b"\x01\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
        recipient.unprotect_request(&option, &ciphertext).unwrap();
    }

    #[test]
    fn unprotect_request_compares_literal_id_context() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new(&master_secret, None, b"\x00", b"\x01").unwrap();
        let (ciphertext, _) = sender.protect_request(0x01, &[], b"request").unwrap();
        let mut matching = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();
        matching.id_context[0] = 0xaa;
        matching.id_context_len = 1;

        matching
            .unprotect_request(b"\x19\x00\x01\xaa\x00", &ciphertext)
            .unwrap();

        let mut tampered = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();
        tampered.id_context[0] = 0xaa;
        tampered.id_context_len = 1;
        assert_eq!(
            tampered
                .unprotect_request(b"\x19\x00\x01\xbb\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::NoContext
        );
    }

    #[test]
    fn terminal_sender_sequence_is_used_once_then_exhausted() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();

        ctx.sender_seq = OscoreSeqNum::new(OscoreSeqNum::MAX).unwrap();

        let (_, option) = ctx.protect_request(0x01, &[], b"last").unwrap();
        assert_eq!(option.as_slice(), b"\x0d\xff\xff\xff\xff\xff\x00");
        assert_eq!(ctx.sender_seq(), None);
        assert_eq!(
            ctx.protect_request(0x01, &[], b"again").unwrap_err(),
            OscoreError::SeqExhausted
        );
        assert_eq!(
            ctx.protect_response(0x45, &[], b"again", &[1], &[0], true)
                .unwrap_err(),
            OscoreError::SeqExhausted
        );
        assert_eq!(ctx.sender_seq(), None);
    }

    #[test]
    fn rfc7252_inner_body_literal() {
        let body = b"\xbb.well-known\x04core\xff</sensors>";
        let (options, payload) = parse_inner_body(body).unwrap();
        assert_eq!(options, b"\xbb.well-known\x04core");
        assert_eq!(payload, b"</sensors>");
    }

    #[test]
    fn inner_body_preserves_ff_in_values_and_extensions() {
        let value = [0x13, 0xaa, 0xff, 0xbb];
        assert_eq!(parse_inner_body(&value).unwrap(), (&value[..], &[][..]));

        let extension = [0xd1, 0xff, 0xff];
        assert_eq!(
            parse_inner_body(&extension).unwrap(),
            (&extension[..], &[][..])
        );

        let mut length_extension = [0u8; 270];
        length_extension[0] = 0x0d;
        length_extension[1] = 0xff;
        length_extension[100] = 0xff;
        assert_eq!(
            parse_inner_body(&length_extension).unwrap(),
            (&length_extension[..], &[][..])
        );
    }

    #[test]
    fn public_roundtrip_preserves_embedded_ff_option_value() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new(&master_secret, None, &[1], &[0]).unwrap();
        let options = [0x13, 0xaa, 0xff, 0xbb];

        let (ciphertext, oscore_option) =
            sender.protect_request(0x02, &options, b"payload").unwrap();
        let (code, decoded_options, payload) = recipient
            .unprotect_request(&oscore_option, &ciphertext)
            .unwrap();

        assert_eq!(code, 0x02);
        assert_eq!(decoded_options.as_slice(), &options);
        assert_eq!(payload.as_slice(), b"payload");
    }

    #[test]
    fn public_unprotect_rejects_malformed_inner_options() {
        let malformed: &[&[u8]] = &[
            &[0xf0],                   // Reserved delta nibble.
            &[0x0f],                   // Reserved length nibble.
            &[0xd0],                   // Truncated one-byte delta extension.
            &[0xe0, 0x00],             // Truncated two-byte delta extension.
            &[0x0d],                   // Truncated one-byte length extension.
            &[0x0e, 0x00],             // Truncated two-byte length extension.
            &[0x02, 0xaa],             // Truncated option value.
            &[0xff],                   // Payload marker with an empty payload.
            &[0xe0, 0xfe, 0xf2, 0x10], // Cumulative option number overflow.
        ];
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");

        for options in malformed {
            let mut sender = Context::new(&master_secret, None, &[0], &[1]).unwrap();
            let mut recipient = Context::new(&master_secret, None, &[1], &[0]).unwrap();
            let (ciphertext, oscore_option) = sender.protect_request(0x02, options, &[]).unwrap();

            assert_eq!(
                recipient
                    .unprotect_request(&oscore_option, &ciphertext)
                    .unwrap_err(),
                OscoreError::InvalidParam,
                "accepted malformed options: {options:02x?}"
            );
        }
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

        let mut forged = response_ciphertext.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            alice_ctx
                .unprotect_response(&response_opt, &forged, request_piv)
                .unwrap_err(),
            OscoreError::DecryptFailed
        );

        // Alice decrypts response using unprotect_response
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), b"response");
        alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, request_piv)
            .unwrap();
    }

    #[test]
    fn notification_rejects_duplicate_response_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        let response = bob
            .protect_response_with_piv(0x45, &[], b"notification", &[0], request_piv)
            .unwrap();

        alice
            .unprotect_notification(&response.1, &response.0, request_piv)
            .unwrap();
        assert_eq!(
            alice
                .unprotect_notification(&response.1, &response.0, request_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn explicit_response_pivs_do_not_use_request_replay_window() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new(&master_secret, None, &[0], &[1]).unwrap();
        let mut bob = Context::new(&master_secret, None, &[1], &[0]).unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        bob.sender_seq = seq(0x1_0000_0000);

        let first = bob
            .protect_response_with_piv(0x45, &[], b"first", &[0], request_piv)
            .unwrap();
        let second = bob
            .protect_response_with_piv(0x45, &[], b"second", &[0], request_piv)
            .unwrap();
        assert_eq!(first.1.as_slice(), b"\x05\x01\x00\x00\x00\x00");
        assert_eq!(second.1.as_slice(), b"\x05\x01\x00\x00\x00\x01");

        alice.recipient_seq = seq(0x1_0000_0001);
        alice.replay_window = u32::MAX;
        let replay_state = (alice.recipient_seq, alice.replay_window);

        alice
            .unprotect_response(&second.1, &second.0, request_piv)
            .unwrap();
        alice
            .unprotect_response(&first.1, &first.0, request_piv)
            .unwrap();
        assert_eq!((alice.recipient_seq, alice.replay_window), replay_state);
    }

    #[test]
    fn response_id_context_is_checked_before_decryption() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut alice = Context::new(&master_secret, None, b"\x00", b"\x01").unwrap();
        let mut bob = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();
        let (_, request_option) = alice.protect_request(0x01, &[], b"request").unwrap();
        let request_piv = &request_option[1..2];
        let (ciphertext, _) = bob
            .protect_response(0x45, &[], b"response", b"\x00", request_piv, true)
            .unwrap();
        alice.id_context[0] = 0xaa;
        alice.id_context_len = 1;

        assert_eq!(
            alice
                .unprotect_response(b"\x11\x00\x01\xbb", &ciphertext, request_piv)
                .unwrap_err(),
            OscoreError::NoContext
        );
    }

    #[test]
    fn response_without_piv_requires_requester_identity() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();

        assert_eq!(
            responder
                .protect_response(0x45, &[], b"response", b"\x02", b"\x00", false)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
        responder
            .protect_response(0x45, &[], b"response", b"\x00", b"\x00", false)
            .unwrap();
    }

    #[test]
    fn response_with_piv_requires_requester_identity() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();

        assert_eq!(
            responder
                .protect_response_with_piv(0x45, &[], b"response", b"\x02", b"\x00")
                .unwrap_err(),
            OscoreError::InvalidParam
        );
    }

    #[test]
    fn response_without_piv_is_one_shot_per_request() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut responder = Context::new(&master_secret, None, b"\x01", b"\x00").unwrap();

        responder
            .protect_response(0x45, &[], b"first", b"\x00", b"\x07", false)
            .unwrap();
        assert_eq!(
            responder
                .protect_response(0x45, &[], b"second", b"\x00", b"\x07", false)
                .unwrap_err(),
            OscoreError::Replay
        );

        responder
            .protect_response(0x45, &[], b"later", b"\x00", b"\x28", false)
            .unwrap();
        assert_eq!(
            responder
                .protect_response(0x45, &[], b"stale", b"\x00", b"\x07", false)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[test]
    fn public_unprotect_rejects_nonminimal_piv() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender = Context::new(&master_secret, None, &[0], &[1]).unwrap();
        let mut recipient = Context::new(&master_secret, None, &[1], &[0]).unwrap();
        let (ciphertext, _) = sender.protect_request(0x01, &[], b"request").unwrap();

        assert_eq!(
            recipient
                .unprotect_request(b"\x0a\x00\x00\x00", &ciphertext)
                .unwrap_err(),
            OscoreError::InvalidParam
        );
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

        assert!(response_opt.is_empty());

        // Alice decrypts using unprotect_response with request_piv
        let (dec_code, _options, dec_payload) = alice_ctx
            .unprotect_response(&response_opt, &response_ciphertext, &request_piv)
            .unwrap();

        assert_eq!(dec_code, response_code);
        assert_eq!(dec_payload.as_slice(), payload);
    }
}
