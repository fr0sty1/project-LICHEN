// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! EDHOC (RFC 9528) Suite 0 implementation for establishing OSCORE contexts.
//!
//! Suite 0: X25519 + Schnorr48 + AES-CCM-16-64-128 + SHA-256
//!
//! Schnorr48 signatures per draft-lichen-schnorr-00 (48 bytes instead of 64).

use crate::{Context, OscoreError, KEY_LEN, NONCE_LEN, TAG_LEN};
use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// AES-CCM for Suite 0.
type AesCcm = Ccm<Aes128, U8, U13>;

/// X25519/Schnorr48 key length.
pub const KEY_LEN_32: usize = 32;

/// Schnorr48 signature length (draft-lichen-schnorr-00).
pub const SIG_LEN: usize = 48;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Created,
    Message1Created,
    AwaitingMessage3,
    PendingMessage2,
    PendingMessage3,
    Complete,
    Failed,
    Zeroized,
}

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

/// HKDF-Extract with SHA-256 (matches python/src/lichen/crypto/edhoc.py:_hkdf_extract exactly).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, ikm);
    Zeroizing::new(prk.into())
}

/// EDHOC-KDF (RFC 9528 Section 4.1.2).
///
/// EDHOC-KDF(PRK, TH, label, context, length) = HKDF-Expand(PRK, info, length)
/// where info = (length, TH, label, context) as a CBOR sequence.
fn edhoc_kdf(
    prk: &[u8; 32],
    th: &[u8; 32],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut info = heapless::Vec::<u8, 128>::new();

    if length <= 23 {
        info.push_err(length as u8)?;
    } else if length <= 0xff {
        info.push_err(0x18)?;
        info.push_err(length as u8)?;
    } else if length <= 0xffff {
        info.push_err(0x19)?;
        info.push_err((length >> 8) as u8)?;
        info.push_err((length & 0xff) as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
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
    let mut okm = heapless::Vec::<u8, 128>::new();
    okm.resize(length, 0)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    hk.expand(&info, &mut okm)
        .map_err(|_| EdhocError::KeyDerivation)?;

    let mut result = heapless::Vec::new();
    result
        .extend_from_slice(okm.as_slice())
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(result)
}

fn export_context(
    prk: &[u8; 32],
    th: &[u8; 32],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> Result<Context, OscoreError> {
    let prk_out_vec = edhoc_kdf(prk, th, "7", th, 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_out = Zeroizing::new([0u8; 32]);
    prk_out.copy_from_slice(&prk_out_vec[0..32]);
    let prk_exporter_vec =
        edhoc_kdf(&prk_out, th, "10", b"", 32).map_err(|_| OscoreError::KeyDerivation)?;
    let mut prk_exporter = Zeroizing::new([0u8; 32]);
    prk_exporter.copy_from_slice(&prk_exporter_vec);
    let master_secret_vec =
        edhoc_kdf(&prk_exporter, th, "0", b"", KEY_LEN).map_err(|_| OscoreError::KeyDerivation)?;
    let mut master_secret = Zeroizing::new([0u8; KEY_LEN]);
    master_secret.copy_from_slice(&master_secret_vec);
    let master_salt_vec =
        edhoc_kdf(&prk_exporter, th, "1", b"", 8).map_err(|_| OscoreError::KeyDerivation)?;
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

/// Derive Schnorr48 keypair from 32-byte seed.
fn schnorr48_derive(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hash = Sha512::digest(seed);
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&hash[..32]);
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;
    let priv_scalar = Scalar::from_bytes_mod_order(privkey);
    let pubkey = (priv_scalar * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    (privkey, pubkey)
}

/// Schnorr48 sign: 48-byte deterministic Schnorr signature (e[16] || s[32]).
fn schnorr48_sign(
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
    msg: &[u8],
) -> Result<[u8; SIG_LEN], EdhocError> {
    let nonce_hash = Sha512::new()
        .chain_update(privkey.as_slice())
        .chain_update(msg)
        .finalize();
    let r = Scalar::from_bytes_mod_order_wide(&nonce_hash.into());

    let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

    let e_hash = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(pubkey.as_slice())
        .chain_update(msg)
        .finalize();

    let mut e = [0u8; 16];
    e.copy_from_slice(&e_hash[..16]);

    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(&e);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    let priv_scalar = Scalar::from_bytes_mod_order(*privkey);
    let s = r + e_scalar * priv_scalar;

    let mut sig = [0u8; SIG_LEN];
    sig[..16].copy_from_slice(&e);
    sig[16..].copy_from_slice(s.as_bytes());
    Ok(sig)
}

/// Schnorr48 verify: returns Ok(()) if the 48-byte signature is valid.
fn schnorr48_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), EdhocError> {
    let e_received = &sig[..16];
    let s_bytes: [u8; 32] = sig[16..]
        .try_into()
        .map_err(|_| EdhocError::InvalidMessage)?;

    let s: Scalar = match Scalar::from_canonical_bytes(s_bytes).into() {
        Some(s) => s,
        None => return Err(EdhocError::SignatureVerification),
    };
    if s == Scalar::ZERO {
        return Err(EdhocError::SignatureVerification);
    }

    let pubkey_point = match CompressedEdwardsY(*pubkey).decompress() {
        Some(p) if !p.is_identity() && p.is_torsion_free() => p,
        _ => return Err(EdhocError::SignatureVerification),
    };

    let mut e_extended = [0u8; 32];
    e_extended[..16].copy_from_slice(e_received);
    let e_scalar = Scalar::from_bytes_mod_order(e_extended);

    let sb = s * ED25519_BASEPOINT_POINT;
    let epk = e_scalar * pubkey_point;
    let r_prime = (sb - epk).compress();

    let e_check = Sha512::new()
        .chain_update(r_prime.as_bytes())
        .chain_update(pubkey.as_slice())
        .chain_update(msg)
        .finalize();

    if e_check[..16].ct_eq(e_received).into() {
        Ok(())
    } else {
        Err(EdhocError::SignatureVerification)
    }
}

/// Compute transcript hash: H(input).
fn compute_th(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Encode bytes as deterministic CBOR bstr (major type 2) matching zcbor/cbor2.
fn encode_bstr<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    data: &[u8],
) -> Result<(), EdhocError> {
    let len = data.len();
    if len <= 23 {
        buf.push_err(0x40u8 | len as u8)?;
    } else if len <= 0xff {
        buf.push_err(0x58)?;
        buf.push_err(len as u8)?;
    } else if len <= 0xffff {
        buf.push_err(0x59)?;
        buf.push_err((len >> 8) as u8)?;
        buf.push_err((len & 0xff) as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }
    buf.extend_err(data)?;
    Ok(())
}

fn encode_uint<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    val: usize,
) -> Result<(), EdhocError> {
    if val <= 23 {
        buf.push_err(val as u8)?;
    } else if val <= 0xff {
        buf.push_err(0x18)?;
        buf.push_err(val as u8)?;
    } else {
        return Err(EdhocError::BufferTooSmall);
    }
    Ok(())
}

fn encode_tstr<const N: usize>(buf: &mut heapless::Vec<u8, N>, s: &str) -> Result<(), EdhocError> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > 255 {
        return Err(EdhocError::BufferTooSmall);
    }
    if len <= 23 {
        buf.push_err(0x60 | len as u8)?;
    } else {
        buf.push_err(0x78)?;
        buf.push_err(len as u8)?;
    }
    buf.extend_err(bytes)?;
    Ok(())
}

/// TH_2 = H(G_Y || H(message_1)) per RFC 9528 / test vectors.
fn transcript_2(g_y: &[u8], msg1: &[u8]) -> Result<[u8; 32], EdhocError> {
    let h_msg1 = compute_th(msg1);
    let mut buf = heapless::Vec::<u8, 64>::new();
    buf.extend_err(g_y)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    buf.extend_err(&h_msg1)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(compute_th(&buf))
}

/// TH_3 = H(CBOR(TH_2) || CBOR(input) || CBOR(cred)).
fn transcript_3(th_2: &[u8; 32], input: &[u8], cred: &[u8]) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_2)?;
    encode_bstr(&mut buf, input)?;
    encode_bstr(&mut buf, cred)?;
    Ok(compute_th(&buf))
}

fn transcript_4(th_3: &[u8; 32], ciphertext_3: &[u8]) -> Result<[u8; 32], EdhocError> {
    let mut buf = heapless::Vec::<u8, 1024>::new();
    encode_bstr(&mut buf, th_3)?;
    encode_bstr(&mut buf, ciphertext_3)?;
    Ok(compute_th(&buf))
}

fn build_context_2(id_cred: &[u8], cred: &[u8]) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut buf = heapless::Vec::<u8, 128>::new();
    encode_bstr(&mut buf, id_cred)?;
    encode_bstr(&mut buf, cred)?;
    Ok(buf)
}

fn build_context_3(
    id_cred: &[u8],
    _th: &[u8; 32],
    cred: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut buf = heapless::Vec::<u8, 128>::new();
    encode_bstr(&mut buf, id_cred)?;
    encode_bstr(&mut buf, cred)?;
    Ok(buf)
}

fn build_signature_structure(
    id_cred: &[u8],
    th: &[u8; 32],
    cred: &[u8],
    mac: &[u8],
) -> Result<heapless::Vec<u8, 128>, EdhocError> {
    let mut m = heapless::Vec::<u8, 128>::new();
    m.push_err(0x85)?;
    m.extend_err(b"\x6bSignature1")?;
    encode_bstr(&mut m, id_cred)?;
    encode_bstr(&mut m, th)?;
    encode_bstr(&mut m, cred)?;
    encode_bstr(&mut m, mac)?;
    Ok(m)
}

/// Parse a CBOR bstr and return (data, bytes_consumed).
fn parse_bstr(data: &[u8]) -> Result<(&[u8], usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    if major != 2 {
        return Err(EdhocError::InvalidMessage);
    }
    let extra = (first & 0x1f) as usize;
    let (data_len, header_len) = if extra <= 23 {
        (extra, 1)
    } else if extra == 24 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        (data[1] as usize, 2)
    } else if extra == 25 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        (u16::from_be_bytes([data[1], data[2]]) as usize, 3)
    } else {
        return Err(EdhocError::InvalidMessage);
    };
    if data.len() < header_len + data_len {
        return Err(EdhocError::InvalidMessage);
    }
    Ok((
        &data[header_len..header_len + data_len],
        header_len + data_len,
    ))
}

/// Parse a connection identifier from CBOR bstr or int encoding.
fn parse_identifier(data: &[u8]) -> Result<(ConnectionId, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    match major {
        0 => {
            // unsigned int
            let (val, consumed) = decode_uint(data)?;
            let id = ConnectionId::new(&[val])?;
            Ok((id, consumed))
        }
        2 => {
            // bstr
            let (raw, consumed) = parse_bstr(data)?;
            if raw.len() > CONNECTION_ID_CAPACITY {
                return Err(EdhocError::InvalidMessage);
            }
            let id = ConnectionId::new(raw)?;
            Ok((id, consumed))
        }
        _ => Err(EdhocError::InvalidMessage),
    }
}

/// Decode a CBOR int (unsigned or negative) as a raw byte value.
/// Returns (value, bytes_consumed).
fn decode_any_int(data: &[u8]) -> Result<(u8, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    match major {
        0 => {
            if first <= 0x17 {
                Ok((first, 1))
            } else if first == 0x18 {
                if data.len() < 2 {
                    return Err(EdhocError::InvalidMessage);
                }
                Ok((data[1], 2))
            } else {
                Err(EdhocError::InvalidMessage)
            }
        }
        1 => {
            // negative int: -1 - value
            if first == 0x20 {
                Ok((0, 1)) // -1, wraps to u8::MAX
            } else if first == 0x38 {
                if data.len() < 2 {
                    return Err(EdhocError::InvalidMessage);
                }
                let neg_val = (!data[1]).wrapping_add(1);
                Ok((neg_val, 2))
            } else {
                Err(EdhocError::InvalidMessage)
            }
        }
        _ => Err(EdhocError::InvalidMessage),
    }
}

fn decode_uint(data: &[u8]) -> Result<(u8, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    if first <= 0x17 {
        Ok((first, 1))
    } else if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        Ok((data[1], 2))
    } else {
        Err(EdhocError::InvalidMessage)
    }
}

/// Encode a connection identifier as CBOR (int for 1-byte identifiers, bstr otherwise).
fn encode_identifier<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    id: &ConnectionId,
) -> Result<(), EdhocError> {
    let bytes = id.as_bytes();
    if bytes.len() == 1 {
        let val = bytes[0];
        if val <= 23 {
            buf.push_err(val)?;
        } else {
            buf.push_err(0x41)?;
            buf.push_err(val)?;
        }
    } else if bytes.is_empty() {
        buf.push_err(0x40)?;
    } else {
        encode_bstr(buf, bytes)?;
    }
    Ok(())
}

/// Parse ID_CRED from a CBOR item.
fn parse_id_cred(data: &[u8]) -> Result<(IdCred, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;

    match major {
        0 | 1 => {
            // int (compact kid relay, e.g. 0x2d)
            let (kid_val, kid_len) = decode_any_int(data)?;
            let mut kid_buf = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
            kid_buf
                .push(kid_val)
                .map_err(|_| EdhocError::BufferTooSmall)?;
            // Re-encode as canonical map: {4: h'<kid>'}
            let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
            encoded.push(0xa1).map_err(|_| EdhocError::BufferTooSmall)?;
            encoded.push(0x04).map_err(|_| EdhocError::BufferTooSmall)?;
            if kid_val <= 23 {
                encoded
                    .push(kid_val)
                    .map_err(|_| EdhocError::BufferTooSmall)?;
            } else {
                encoded.push(0x41).map_err(|_| EdhocError::BufferTooSmall)?;
                encoded
                    .push(kid_val)
                    .map_err(|_| EdhocError::BufferTooSmall)?;
            }
            Ok((
                IdCred {
                    encoded,
                    reference: IdCredReference::Kid(kid_buf),
                },
                kid_len,
            ))
        }
        2 => {
            // bstr (compact kid, e.g. 0x42aabb)
            let (kid_bytes, consumed) = parse_bstr(data)?;
            let mut kid_buf = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
            kid_buf
                .extend_from_slice(kid_bytes)
                .map_err(|_| EdhocError::BufferTooSmall)?;
            let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
            encoded.push(0xa1).map_err(|_| EdhocError::BufferTooSmall)?;
            encoded.push(0x04).map_err(|_| EdhocError::BufferTooSmall)?;
            encode_bstr(&mut encoded, kid_bytes)?;
            Ok((
                IdCred {
                    encoded,
                    reference: IdCredReference::Kid(kid_buf),
                },
                consumed,
            ))
        }
        5 => {
            // map (full ID_CRED with headers)
            parse_id_cred_map(data)
        }
        _ => Err(EdhocError::InvalidMessage),
    }
}

fn parse_id_cred_map(data: &[u8]) -> Result<(IdCred, usize), EdhocError> {
    let first = data[0];
    if first < 0xa1 || first > 0xb9 {
        return Err(EdhocError::InvalidMessage);
    }
    let map_len = match first {
        0xa1..=0xb7 => (first - 0xa0) as usize,
        0xb8 => {
            if data.len() < 2 {
                return Err(EdhocError::InvalidMessage);
            }
            data[1] as usize
        }
        _ => return Err(EdhocError::InvalidMessage),
    };
    if map_len > ID_CRED_MAX_PARAMETERS {
        return Err(EdhocError::BufferTooSmall);
    }

    let header_consumed = if first <= 0xb7 { 1 } else { 2 };
    let mut pos = header_consumed;
    let mut kid: Option<heapless::Vec<u8, ID_CRED_MAX_LEN>> = None;
    let mut x5t_algorithm: Option<i128> = None;
    let x5t_hash: Option<heapless::Vec<u8, ID_CRED_MAX_LEN>> = None;
    let mut seen_keys = heapless::Vec::<u8, ID_CRED_MAX_PARAMETERS>::new();
    let mut prev_key: Option<i128> = None;

    for _ in 0..map_len {
        if pos >= data.len() {
            return Err(EdhocError::InvalidMessage);
        }
        let (key, key_consumed) = parse_id_cred_key(&data[pos..])?;
        pos += key_consumed;

        if let Some(prev) = prev_key {
            if key <= prev {
                return Err(EdhocError::InvalidMessage);
            }
        }
        prev_key = Some(key);

        // Check for duplicate key
        let key_byte = key as u8;
        if seen_keys.iter().any(|&k| k == key_byte) {
            return Err(EdhocError::InvalidMessage);
        }
        seen_keys
            .push(key_byte)
            .map_err(|_| EdhocError::BufferTooSmall)?;

        match key {
            4 => {
                // kid
                let (val, val_consumed) = parse_id_cred_value(&data[pos..])?;
                pos += val_consumed;
                kid = Some(val);
            }
            1 => {
                // x5t algorithm
                let (val, val_consumed) = parse_id_cred_int(&data[pos..])?;
                pos += val_consumed;
                x5t_algorithm = Some(val);
            }
            _ => {
                // unknown key - skip value
                let (_, val_consumed) = parse_id_cred_value(&data[pos..])?;
                pos += val_consumed;
            }
        }
    }

    // Determine reference type
    let reference = if let (Some(alg), Some(hash)) = (x5t_algorithm, x5t_hash) {
        IdCredReference::X5t {
            algorithm: alg,
            hash,
        }
    } else if let Some(k) = kid {
        IdCredReference::Kid(k)
    } else {
        return Err(EdhocError::InvalidMessage);
    };

    let mut encoded = heapless::Vec::<u8, ID_CRED_MAX_LEN>::new();
    encoded
        .extend_from_slice(&data[..pos])
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok((IdCred { encoded, reference }, pos))
}

fn parse_id_cred_key(data: &[u8]) -> Result<(i128, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    match major {
        0 => {
            let (val, consumed) = decode_uint(data)?;
            Ok((val as i128, consumed))
        }
        1 => {
            // negative int
            if first == 0x20 {
                Ok((-1, 1))
            } else if first == 0x38 {
                if data.len() < 2 {
                    return Err(EdhocError::InvalidMessage);
                }
                Ok((-(data[1] as i128) - 1, 2))
            } else {
                return Err(EdhocError::InvalidMessage);
            }
        }
        _ => Err(EdhocError::InvalidMessage),
    }
}

fn parse_id_cred_value(
    data: &[u8],
) -> Result<(heapless::Vec<u8, ID_CRED_MAX_LEN>, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let (raw, consumed) = parse_bstr(data)?;
    let mut buf = heapless::Vec::new();
    buf.extend_from_slice(raw)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok((buf, consumed))
}

fn parse_id_cred_int(data: &[u8]) -> Result<(i128, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    let (val, consumed) = match major {
        0 => {
            // unsigned
            let (v, c) = decode_uint(data)?;
            (v as i128, c)
        }
        1 => {
            // negative
            if first == 0x20 {
                (-1i128, 1)
            } else if first == 0x38 {
                if data.len() < 2 {
                    return Err(EdhocError::InvalidMessage);
                }
                (-(data[1] as i128) - 1, 2)
            } else {
                return Err(EdhocError::InvalidMessage);
            }
        }
        6 => {
            // tag, skip tag and parse next
            let tag_val = data[0] & 0x1f;
            let tag_header = if tag_val <= 23 {
                1
            } else if tag_val == 24 {
                2
            } else {
                return Err(EdhocError::InvalidMessage);
            };
            return parse_id_cred_int(&data[tag_header..]);
        }
        _ => return Err(EdhocError::InvalidMessage),
    };
    Ok((val, consumed))
}

/// Validate a peer credential's public key binding.
fn validate_peer_credential(peer: PeerCredential<'_>) -> Result<(), EdhocError> {
    // Check public key is non-zero (weak key rejection)
    if peer.public_key.iter().all(|&b| b == 0) {
        return Err(EdhocError::SignatureVerification);
    }
    // Verify public key is on the curve and torsion-free
    match CompressedEdwardsY(*peer.public_key).decompress() {
        Some(p) if !p.is_identity() && p.is_torsion_free() => {}
        _ => return Err(EdhocError::SignatureVerification),
    }
    Ok(())
}

/// Validate a deterministic CBOR item.
fn validate_deterministic_item(data: &[u8]) -> Result<(), EdhocError> {
    let mut pos = 0;
    let mut depth = 0;
    while pos < data.len() {
        let byte = data[pos];
        let major = byte >> 5;
        let extra = (byte & 0x1f) as usize;
        pos += 1;
        match major {
            0 | 1 => {
                if extra == 24 {
                    if pos >= data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    pos += 1;
                } else if extra == 25 {
                    if pos + 2 > data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    pos += 2;
                } else if extra == 26 {
                    if pos + 4 > data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    pos += 4;
                } else if extra == 27 {
                    if pos + 8 > data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    pos += 8;
                } else if extra > 23 {
                    return Err(EdhocError::InvalidMessage);
                }
            }
            2 | 3 => {
                let (_, consumed) = parse_bstr_helper(byte, &data[pos..])?;
                pos += consumed;
            }
            4 | 5 => {
                depth += 1;
                if depth > 8 {
                    return Err(EdhocError::InvalidMessage);
                }
                let count = if extra <= 23 {
                    extra
                } else if extra == 24 {
                    if pos >= data.len() {
                        return Err(EdhocError::InvalidMessage);
                    }
                    let n = data[pos] as usize;
                    pos += 1;
                    n
                } else {
                    return Err(EdhocError::InvalidMessage);
                };
                if count > 64 {
                    return Err(EdhocError::InvalidMessage);
                }
                // Continue parsing elements
            }
            6 => {
                let (_, consumed) = parse_bstr_helper(byte, &data[pos..])?;
                pos += consumed;
                // Parse tagged content
                continue;
            }
            7 => {
                // float/simple - only false (20), true (21), null (22), undefined (23)
                if extra > 23 && extra < 28 {
                    return Err(EdhocError::InvalidMessage);
                }
            }
            _ => return Err(EdhocError::InvalidMessage),
        }
    }
    Ok(())
}

fn parse_bstr_helper(byte: u8, data: &[u8]) -> Result<(&[u8], usize), EdhocError> {
    let major = byte >> 5;
    if major != 2 && major != 3 {
        return Err(EdhocError::InvalidMessage);
    }
    let extra = (byte & 0x1f) as usize;
    let (len, header) = if extra <= 23 {
        (extra, 1usize)
    } else if extra == 24 {
        if data.is_empty() {
            return Err(EdhocError::InvalidMessage);
        }
        (data[0] as usize, 1)
    } else if extra == 25 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        (u16::from_be_bytes([data[0], data[1]]) as usize, 2)
    } else {
        return Err(EdhocError::InvalidMessage);
    };
    if data.len() < header + len {
        return Err(EdhocError::InvalidMessage);
    }
    Ok((&data[header..header + len], header + len))
}

/// Copy an ID_CRED value from raw bytes.
fn copy_id_cred_value(data: &[u8]) -> Result<heapless::Vec<u8, ID_CRED_MAX_LEN>, EdhocError> {
    let mut buf = heapless::Vec::new();
    buf.extend_from_slice(data)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    Ok(buf)
}

/// Validate that a compressed Ed25519 point is a strong public key.
fn strong_verifying_key(pubkey: &[u8; 32]) -> Result<(), EdhocError> {
    match CompressedEdwardsY(*pubkey).decompress() {
        Some(p) if !p.is_identity() && p.is_torsion_free() => Ok(()),
        _ => Err(EdhocError::SignatureVerification),
    }
}

/// Build a raw key credential from a 32-byte public key.
fn raw_key_credential(
    pubkey: &[u8; 32],
) -> Result<(heapless::Vec<u8, 12>, heapless::Vec<u8, 48>), EdhocError> {
    // id_cred = {4: h'<compressed_pubkey>'} per RFC 9528
    let mut id_cred = heapless::Vec::<u8, 12>::new();
    id_cred.push(0xa1).map_err(|_| EdhocError::BufferTooSmall)?;
    id_cred.push(0x04).map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut id_cred, pubkey)?;
    // credential = CCS with COSE_Key containing pubkey
    let mut credential = heapless::Vec::<u8, 48>::new();
    encode_credential(&mut credential, pubkey)?;
    Ok((id_cred, credential))
}

/// Encode a CCS credential wrapping a COSE_Key with the given 32-byte public key.
fn encode_credential<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    pubkey: &[u8],
) -> Result<(), EdhocError> {
    // CCS map: {1: "K1", 2: "EDHOC Raw Public Key", 8: COSE_Key}
    // COSE_Key: {1: 1 (OKP), 3: -8 (Ed25519), -1: pubkey}
    let mut cose_key = heapless::Vec::<u8, 48>::new();
    cose_key
        .push(0xa3)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    cose_key
        .push(0x01)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    cose_key
        .push(0x01)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    cose_key
        .push(0x03)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    cose_key
        .push(0x27)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    cose_key
        .push(0x20)
        .map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(&mut cose_key, pubkey)?;

    buf.push(0xa2).map_err(|_| EdhocError::BufferTooSmall)?;
    encode_tstr(buf, "K1")?;
    encode_tstr(buf, "EDHOC Raw Public Key")?;
    buf.push(0x08).map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(buf, &cose_key)?;

    Ok(())
}

/// Encode id_cred for a 32-byte raw public key.
fn encode_id_cred<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    pubkey: &[u8],
) -> Result<(), EdhocError> {
    buf.push(0xa1).map_err(|_| EdhocError::BufferTooSmall)?;
    buf.push(0x04).map_err(|_| EdhocError::BufferTooSmall)?;
    encode_bstr(buf, pubkey)?;
    Ok(())
}

/// Pending Message 2 state (before credential selection).
#[derive(Clone, Debug)]
pub struct PendingMessage2 {
    pub id_cred: IdCred,
    pub plaintext: heapless::Vec<u8, 128>,
    pub signature_offset: usize,
    pub transcript_binding: [u8; 32],
    pub(crate) _non_exhaustive: (),
}

impl PendingMessage2 {
    /// Return the parsed ID_CRED from the peer.
    pub fn id_cred(&self) -> &IdCred {
        &self.id_cred
    }
}

/// Pending Message 3 state (before credential selection).
#[derive(Clone, Debug)]
pub struct PendingMessage3 {
    pub id_cred: IdCred,
    pub plaintext: heapless::Vec<u8, 128>,
    pub signature_offset: usize,
    pub transcript_binding: [u8; 32],
}

impl PendingMessage3 {
    /// Return the parsed ID_CRED from the peer.
    pub fn id_cred(&self) -> &IdCred {
        &self.id_cred
    }
}

/// Parse SUITES_R from CBOR error message per RFC 9528 Section 3.3.2.
fn parse_suites_r(data: &[u8]) -> Result<usize, EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }
    let first = data[0];
    let major = first >> 5;
    match major {
        4 => {
            // array
            let count = (first & 0x1f) as usize;
            if count == 0 {
                return Err(EdhocError::InvalidMessage);
            }
            // Each element is at least 1 byte
            Ok(1 + count)
        }
        0 | 1 => {
            // single int
            Ok(1)
        }
        _ => Err(EdhocError::InvalidMessage),
    }
}

/// Parse SUITES_I from CBOR per RFC 9528 Section 3.3.2.
fn parse_suites_i(data: &[u8]) -> Result<(u8, usize), EdhocError> {
    if data.is_empty() {
        return Err(EdhocError::InvalidMessage);
    }

    let first = data[0];

    if first <= 0x17 {
        return Ok((first, 1));
    } else if first == 0x18 {
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        return Ok((data[1], 2));
    }

    if (0x80..=0x97).contains(&first) {
        let arr_len = (first - 0x80) as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage);
        }
        if data.len() < 2 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[1];
        if elem <= 0x17 {
            Ok((elem, 1 + arr_len))
        } else if elem == 0x18 && data.len() >= 3 {
            Ok((data[2], 1 + 1 + (arr_len - 1) + 1))
        } else {
            Err(EdhocError::InvalidMessage)
        }
    } else if first == 0x98 {
        if data.len() < 3 {
            return Err(EdhocError::InvalidMessage);
        }
        let arr_len = data[1] as usize;
        if arr_len == 0 {
            return Err(EdhocError::InvalidMessage);
        }
        let elem = data[2];
        if elem <= 0x17 {
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
/// Keys are raw [u8; 32] arrays (not ed25519-dalek types).
#[derive(ZeroizeOnDrop)]
pub struct EdhocInitiator {
    /// Our Schnorr48 private key (clamped Ed25519 scalar).
    ed_privkey: [u8; 32],
    /// Our Schnorr48 public key.
    ed_pubkey: [u8; 32],
    /// Our connection identifier.
    #[zeroize(skip)]
    c_i: ConnectionId,
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
#[derive(ZeroizeOnDrop)]
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
    #[zeroize(skip)]
    lifecycle: Lifecycle,
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
            lifecycle: Lifecycle::Created,
        }
    }
}

impl Zeroize for EdhocInitiator {
    fn zeroize(&mut self) {
        self.ed_privkey.zeroize();
        self.eph_secret.zeroize();
        self.state.prk_2e.zeroize();
        self.state.prk_3e2m.zeroize();
        self.state.prk_4e3m.zeroize();
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
        let (ed_privkey, ed_pubkey) = schnorr48_derive(&seed);
        let eph_secret = StaticSecret::from(*eph_seed);
        eph_seed.zeroize();
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            ed_privkey,
            ed_pubkey,
            c_i: c_i.into(),
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        })
    }

    /// Create a new EDHOC initiator.
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_i: u8, rng: &mut R) -> Self {
        let (ed_privkey, ed_pubkey) = schnorr48_derive(&seed);
        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            ed_privkey,
            ed_pubkey,
            c_i: ConnectionId::from(c_i),
            eph_secret: Some(eph_secret),
            eph_public,
            state: InitiatorState::default(),
        }
    }

    /// Create EDHOC Message 1.
    pub fn create_message_1(&mut self) -> Result<heapless::Vec<u8, 64>, EdhocError> {
        if self.state.lifecycle != Lifecycle::Created {
            return Err(EdhocError::InvalidState);
        }
        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push_err(0)?;
        msg1.push_err(SUITE_0)?;
        encode_bstr(&mut msg1, self.eph_public.as_bytes())?;
        encode_identifier(&mut msg1, &self.c_i)?;

        self.state.msg1 = msg1.clone();
        self.state.lifecycle = Lifecycle::Message1Created;
        Ok(msg1)
    }

    /// Process EDHOC Message 2 and create Message 3.
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

        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_y);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.g_y = g_y;

        let result = (|| {
            if bool::from(g_xy.as_bytes().ct_eq(&[0; KEY_LEN_32])) {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(&self.state.g_y, &self.state.msg1)?;

            let prk_2e_z = hkdf_extract(&self.state.th_2, g_xy.as_bytes());
            self.state.prk_2e.copy_from_slice(&*prk_2e_z);
            drop(prk_2e_z);
            drop(g_xy);

            let keystream_2 = edhoc_kdf(
                &self.state.prk_2e,
                &self.state.th_2,
                "KEYSTREAM_2",
                &[],
                ciphertext_2.len(),
            )?;
            let mut plaintext_2 = SecretVec::<128>::new();
            for (i, &b) in ciphertext_2.iter().enumerate() {
                plaintext_2.push_err(b ^ keystream_2[i])?;
            }

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

            // Parse c_r properly as identifier bytes
            let c_r_id = ConnectionId::new(c_r.as_bytes())?;
            self.state.c_r = c_r_id;
            self.state.lifecycle = Lifecycle::PendingMessage2;
            Ok(PendingMessage2 {
                id_cred: id_cred_r,
                plaintext,
                signature_offset: sig_offset,
                transcript_binding: self.state.th_2,
                _non_exhaustive: (),
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
            if signature_bytes.len() != SIG_LEN {
                return Err(EdhocError::InvalidMessage);
            }
            let context_2 = build_context_2(pending.id_cred.as_bytes(), peer.credential)?;
            let mac_2 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_2,
                "MAC_2",
                &context_2,
                32,
            )?;
            let m_2 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_2,
                peer.credential,
                &mac_2,
            )?;
            let mut sig_48 = [0u8; SIG_LEN];
            sig_48.copy_from_slice(signature_bytes);
            schnorr48_verify(peer.public_key, &m_2, &sig_48)?;

            self.state.th_3 = transcript_3(&self.state.th_2, &pending.plaintext, peer.credential)?;

            self.state.prk_4e3m = self.state.prk_3e2m;

            let mut credential_i = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_i, &self.ed_pubkey)?;
            let mut id_cred_i = heapless::Vec::<u8, 40>::new();
            encode_id_cred(&mut id_cred_i, &self.ed_pubkey)?;
            let context_3 = build_context_3(&id_cred_i, &self.state.th_3, &credential_i)?;
            let mac_3 = edhoc_kdf(
                &self.state.prk_4e3m,
                &self.state.th_3,
                "MAC_3",
                &context_3,
                32,
            )?;
            let m_3 =
                build_signature_structure(&id_cred_i, &self.state.th_3, &credential_i, &mac_3)?;
            let signature_3 = schnorr48_sign(&self.ed_privkey, &self.ed_pubkey, &m_3)?;
            let mut ciphertext_3 = SecretVec::<128>::new();
            encode_bstr(&mut ciphertext_3, &self.ed_pubkey)?;
            ciphertext_3
                .extend_from_slice(&signature_3)
                .map_err(|_| EdhocError::BufferTooSmall)?;

            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_3,
                "IV_3",
                &[],
                NONCE_LEN,
            )?;

            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?;
            a_3.push_err(0x68)?;
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?;
            a_3.push_err(0x58)?;
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

            let cipher = AesCcm::new_from_slice(&k_3).map_err(|_| EdhocError::InvalidState)?;
            let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
            nonce.copy_from_slice(&iv_3);
            let tag = cipher
                .encrypt_in_place_detached((&*nonce).into(), &a_3, &mut ciphertext_3)
                .map_err(|_| EdhocError::InvalidState)?;
            ciphertext_3.extend_err(&tag)?;

            self.state.th_4 = transcript_4(&self.state.th_3, &ciphertext_3.0)?;

            self.state.completed = true;
            self.state.lifecycle = Lifecycle::Complete;
            let mut msg3 = heapless::Vec::new();
            encode_bstr(&mut msg3, &ciphertext_3.0)?;
            Ok(msg3)
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    fn poison(&mut self) {
        self.ed_privkey.zeroize();
        self.eph_secret.zeroize();
        self.state.prk_2e.zeroize();
        self.state.prk_3e2m.zeroize();
        self.state.prk_4e3m.zeroize();
        self.state.lifecycle = Lifecycle::Failed;
    }

    /// Export OSCORE security context.
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_i.as_bytes(),
            self.state.c_r.as_bytes(),
        )
    }
}

/// EDHOC Responder (server role).
#[derive(ZeroizeOnDrop)]
pub struct EdhocResponder {
    /// Our Schnorr48 private key (clamped Ed25519 scalar).
    ed_privkey: [u8; 32],
    /// Our Schnorr48 public key.
    ed_pubkey: [u8; 32],
    /// Our connection identifier.
    #[zeroize(skip)]
    c_r: ConnectionId,
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
#[derive(ZeroizeOnDrop)]
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
    #[zeroize(skip)]
    lifecycle: Lifecycle,
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
            lifecycle: Lifecycle::Created,
        }
    }
}

impl Zeroize for EdhocResponder {
    fn zeroize(&mut self) {
        self.ed_privkey.zeroize();
        self.eph_secret.zeroize();
        self.state.prk_2e.zeroize();
        self.state.prk_3e2m.zeroize();
        self.state.prk_4e3m.zeroize();
        self.state.lifecycle = Lifecycle::Zeroized;
    }
}

impl EdhocResponder {
    /// Create a new EDHOC responder with RNG.
    pub fn new_with_rng<R: RngCore + CryptoRng, C: Into<ConnectionId>>(
        seed: [u8; 32],
        c_r: C,
        rng: &mut R,
    ) -> Result<Self, OscoreError> {
        let seed = Zeroizing::new(seed);
        let mut eph_seed = Zeroizing::new([0u8; KEY_LEN_32]);
        rng.try_fill_bytes(&mut eph_seed[..])
            .map_err(|_| OscoreError::KeyDerivation)?;
        let (ed_privkey, ed_pubkey) = schnorr48_derive(&seed);
        let eph_secret = StaticSecret::from(*eph_seed);
        eph_seed.zeroize();
        let eph_public = PublicKey::from(&eph_secret);

        Ok(Self {
            ed_privkey,
            ed_pubkey,
            c_r: c_r.into(),
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        })
    }

    /// Create a new EDHOC responder.
    pub fn new<R: RngCore + CryptoRng>(seed: [u8; 32], c_r: u8, rng: &mut R) -> Self {
        let (ed_privkey, ed_pubkey) = schnorr48_derive(&seed);
        let eph_secret = StaticSecret::random_from_rng(rng);
        let eph_public = PublicKey::from(&eph_secret);

        Self {
            ed_privkey,
            ed_pubkey,
            c_r: ConnectionId::from(c_r),
            eph_secret: Some(eph_secret),
            eph_public,
            state: ResponderState::default(),
        }
    }

    fn poison(&mut self) {
        self.ed_privkey.zeroize();
        self.eph_secret.zeroize();
        self.state.prk_2e.zeroize();
        self.state.prk_3e2m.zeroize();
        self.state.prk_4e3m.zeroize();
        self.state.lifecycle = Lifecycle::Failed;
    }

    /// Process EDHOC Message 1 and create Message 2.
    pub fn process_message_1(&mut self, msg1: &[u8]) -> Result<heapless::Vec<u8, 160>, EdhocError> {
        if self.state.lifecycle != Lifecycle::Created || self.eph_secret.is_none() {
            return Err(EdhocError::InvalidState);
        }

        let mut stored_msg1 = heapless::Vec::<u8, 64>::new();
        stored_msg1.extend_err(msg1)?;

        if msg1.len() < 37 {
            return Err(EdhocError::InvalidMessage);
        }

        if msg1[0] != 0 {
            return Err(EdhocError::InvalidMessage);
        }

        let (selected_suite, suites_i_end) = parse_suites_i(&msg1[1..])?;

        if selected_suite != SUITE_0 {
            return Err(EdhocError::UnsupportedSuite);
        }

        let g_x_start = 1 + suites_i_end;
        if msg1.len() < g_x_start + 2 + 32 + 1 {
            return Err(EdhocError::InvalidMessage);
        }
        if msg1[g_x_start] != 0x58 || msg1[g_x_start + 1] != 32 {
            return Err(EdhocError::InvalidMessage);
        }
        let g_x = {
            let mut gx = [0u8; 32];
            gx.copy_from_slice(&msg1[g_x_start + 2..g_x_start + 2 + 32]);
            gx
        };
        self.state.g_x = g_x;

        let rest = &msg1[g_x_start + 2 + 32..];
        let c_i = if !rest.is_empty() {
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
        if c_i
            == *self
                .c_r
                .as_bytes()
                .first()
                .ok_or(EdhocError::InvalidMessage)?
        {
            self.poison();
            return Err(EdhocError::InvalidMessage);
        }

        let eph_secret = self.eph_secret.take().ok_or(EdhocError::InvalidState)?;
        let peer_eph_public = PublicKey::from(g_x);
        let g_xy = eph_secret.diffie_hellman(&peer_eph_public);
        drop(eph_secret);
        self.state.msg1 = stored_msg1;
        self.state.c_i = ConnectionId::from(c_i);

        let result = (|| {
            if bool::from(g_xy.as_bytes().ct_eq(&[0; KEY_LEN_32])) {
                return Err(EdhocError::InvalidMessage);
            }
            self.state.th_2 = transcript_2(self.eph_public.as_bytes(), msg1)?;

            let prk_2e_z = hkdf_extract(&self.state.th_2, g_xy.as_bytes());
            self.state.prk_2e.copy_from_slice(&*prk_2e_z);
            drop(prk_2e_z);
            drop(g_xy);

            self.state.prk_3e2m = self.state.prk_2e;

            let mut id_cred_r = heapless::Vec::<u8, 40>::new();
            encode_id_cred(&mut id_cred_r, &self.ed_pubkey)?;
            let mut credential_r = heapless::Vec::<u8, 80>::new();
            encode_credential(&mut credential_r, &self.ed_pubkey)?;
            let context_2 = build_context_2(&id_cred_r, &credential_r)?;
            let mac_2 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_2,
                "MAC_2",
                &context_2,
                32,
            )?;
            let m_2 =
                build_signature_structure(&id_cred_r, &self.state.th_2, &credential_r, &mac_2)?;
            let signature_2 = schnorr48_sign(&self.ed_privkey, &self.ed_pubkey, &m_2)?;

            let mut plaintext_2 = SecretVec::<128>::new();
            encode_identifier(&mut plaintext_2, &self.c_r)?;
            encode_bstr(&mut plaintext_2, &self.ed_pubkey)?;
            plaintext_2
                .extend_from_slice(&signature_2)
                .map_err(|_| EdhocError::BufferTooSmall)?;

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

            let k_3 = edhoc_kdf(&self.state.prk_3e2m, &self.state.th_3, "K_3", &[], KEY_LEN)?;
            let iv_3 = edhoc_kdf(
                &self.state.prk_3e2m,
                &self.state.th_3,
                "IV_3",
                &[],
                NONCE_LEN,
            )?;

            let mut a_3 = heapless::Vec::<u8, 64>::new();
            a_3.push_err(0x83)?;
            a_3.push_err(0x68)?;
            a_3.extend_err(b"Encrypt0")?;
            a_3.push_err(0x40)?;
            a_3.push_err(0x58)?;
            a_3.push_err(32)?;
            a_3.extend_err(&self.state.th_3)?;

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
            if sig_bytes.len() != SIG_LEN {
                return Err(EdhocError::InvalidMessage);
            }

            self.state.prk_4e3m = self.state.prk_3e2m;
            let context_3 = build_context_3(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
            )?;
            let mac_3 = edhoc_kdf(
                &self.state.prk_4e3m,
                &self.state.th_3,
                "MAC_3",
                &context_3,
                32,
            )?;
            let m_3 = build_signature_structure(
                pending.id_cred.as_bytes(),
                &self.state.th_3,
                peer.credential,
                &mac_3,
            )?;

            let mut sig_48 = [0u8; SIG_LEN];
            sig_48.copy_from_slice(sig_bytes);
            schnorr48_verify(peer.public_key, &m_3, &sig_48)?;

            self.state.th_4 = transcript_4(&self.state.th_3, &pending.plaintext)?;
            self.state.completed = true;
            self.state.lifecycle = Lifecycle::Complete;

            Ok(())
        })();

        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Export OSCORE security context.
    pub fn export_oscore(&self) -> Result<Context, OscoreError> {
        if !self.state.completed || self.state.prk_4e3m.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(OscoreError::NoContext);
        }
        export_context(
            &self.state.prk_4e3m,
            &self.state.th_4,
            self.c_r.as_bytes(),
            self.state.c_i.as_bytes(),
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
        let _ = EdhocInitiator::new([1; 32], 0);
        let _ = EdhocResponder::new([2; 32], 1);
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
        assert_eq!(initiator.c_i.as_bytes(), &[0x00]);
    }

    #[test]
    fn test_responder_creation() {
        let seed = [0x01u8; 32];
        let mut rng = rand_core::OsRng;
        let responder = EdhocResponder::new(seed, 0x01, &mut rng);
        assert_eq!(responder.c_r.as_bytes(), &[0x01]);
    }

    #[test]
    fn test_message_1_creation() {
        let seed = [0x01u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(seed, 0x05, &mut rng);
        let msg1 = initiator.create_message_1().unwrap();
        assert_eq!(msg1[0], 0);
        assert_eq!(msg1[1], 0);
        assert_eq!(msg1[2], 0x58);
        assert_eq!(msg1[3], 32);
        assert_eq!(msg1[36], 5);
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
        let initiator_key = initiator.ed_pubkey;
        let responder_key = responder.ed_pubkey;
        let (wrong_id, wrong_credential) = raw_key_credential(&[0x33; 32]).unwrap();
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
                PeerCredential::new(&[0x33; 32], &wrong_id, &wrong_credential),
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
                PeerCredential::new(&[0x33; 32], &wrong_id, &wrong_credential),
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
        let (_, pubkey) = schnorr48_derive(&[7; 32]);
        let (id_cred, ccs) = raw_key_credential(&pubkey).unwrap();
        let mut multi_claim_ccs = heapless::Vec::<u8, 96>::new();
        multi_claim_ccs
            .extend_from_slice(&[0xa2, 0x01, 0x63])
            .unwrap();
        multi_claim_ccs.extend_from_slice(b"iss").unwrap();
        multi_claim_ccs.push(0x08).unwrap();
        multi_claim_ccs.extend_from_slice(&ccs[2..]).unwrap();
        validate_peer_credential(PeerCredential::new(&pubkey, &id_cred, &multi_claim_ccs)).unwrap();

        let mut cwt = heapless::Vec::<u8, 100>::new();
        cwt.extend_from_slice(&[0xd8, 0x3d]).unwrap();
        cwt.extend_from_slice(&multi_claim_ccs).unwrap();
        validate_peer_credential(PeerCredential::new(&pubkey, &id_cred, &cwt)).unwrap();

        let x5t = hex!("a11822822e4879f2a41b510c1f9b");
        for credential in [
            &hex!("820141aa")[..],
            &hex!("a201f564726f6c65646e6f6465")[..],
            &hex!("4401020304")[..],
        ] {
            validate_peer_credential(PeerCredential::new(&pubkey, &x5t, credential)).unwrap();
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

        let (_, pubkey) = schnorr48_derive(&[7; 32]);
        let (id_cred, mut credential) = raw_key_credential(&pubkey).unwrap();
        *credential.last_mut().unwrap() ^= 1;
        assert_eq!(
            validate_peer_credential(PeerCredential::new(&pubkey, &id_cred, &credential,)),
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
        let responder_key = responder.ed_pubkey;
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
        assert_eq!(responder.ed_privkey, [0; 32]);
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
        let responder_key = responder.ed_pubkey;
        let message_1 = initiator.create_message_1().unwrap();
        let message_2 = responder.process_message_1(&message_1).unwrap();
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
            initiator.process_message_2(&message_2, &responder.ed_pubkey),
            Err(EdhocError::InvalidMessage)
        );
        assert!(initiator.eph_secret.is_some());
    }

    #[test]
    fn rfc9528_suites_i_literals() {
        assert_eq!(parse_suites_i(&[0x00, 0xff]), Ok((0, 1)));
        assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00, 0xff]), Ok((2, 3)));
        assert_eq!(parse_suites_i(&[0x82, 0x00, 0x00]), Ok((0, 3)));

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
        assert_eq!(parse_suites_i(&suites), Ok((0, suites.len() - 1)));
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
        let responder_pubkey = responder.ed_pubkey;
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
        let (_, peer_key) = schnorr48_derive(&[0x22; 32]);
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
        assert_eq!(initiator.ed_privkey, [0; KEY_LEN_32]);
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
        let initiator_pubkey = initiator.ed_pubkey;

        assert_eq!(
            responder.process_message_3(&[0], &initiator_pubkey),
            Err(EdhocError::InvalidMessage)
        );
        assert_eq!(responder.state.lifecycle, Lifecycle::Failed);
        assert!(responder.eph_secret.is_none());
        assert_eq!(responder.ed_privkey, [0; KEY_LEN_32]);
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
            responder.process_message_3(&[0], &initiator_pubkey),
            Err(EdhocError::InvalidState)
        );
    }

    #[test]
    fn test_full_handshake() {
        let initiator_seed = [0x11u8; 32];
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        let initiator_pubkey = initiator.ed_pubkey;
        let responder_pubkey = responder.ed_pubkey;

        let msg1 = initiator
            .create_message_1()
            .expect("create_message_1 failed");

        let msg2 = responder
            .process_message_1(&msg1)
            .expect("process_message_1 failed");

        let msg3 = initiator
            .process_message_2(&msg2, &responder_pubkey)
            .expect("process_message_2 failed");

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

        let mut initiator_ctx = initiator
            .export_oscore()
            .expect("initiator export_oscore failed");
        let mut responder_ctx = responder
            .export_oscore()
            .expect("responder export_oscore failed");

        let test_code: u8 = 0x01;
        let test_options: &[u8] = &[0xB1, 0x61];
        let test_payload: &[u8] = b"hello from initiator";

        let mut initiator_store = TestStore::empty_for(&initiator_ctx);

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

        let request_piv_len = (oscore_opt[0] & 0x07) as usize;
        let request_piv = &oscore_opt[1..1 + request_piv_len];
        let request_kid = &oscore_opt[1 + request_piv_len..];

        let resp_code: u8 = 0x45;
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
        assert_eq!(parse_suites_i(&[0x00]).unwrap(), (0, 1));
        assert_eq!(parse_suites_i(&[0x02]).unwrap(), (2, 1));
        assert_eq!(parse_suites_i(&[0x17]).unwrap(), (23, 1));
        assert_eq!(parse_suites_i(&[0x18, 0x18]).unwrap(), (24, 2));
    }

    #[test]
    fn test_parse_suites_i_array() {
        assert_eq!(parse_suites_i(&[0x81, 0x00]).unwrap(), (0, 2));
        assert_eq!(parse_suites_i(&[0x82, 0x00, 0x02]).unwrap(), (0, 3));
        assert_eq!(parse_suites_i(&[0x83, 0x00, 0x02, 0x03]).unwrap(), (0, 4));
        assert_eq!(parse_suites_i(&[0x82, 0x02, 0x00]).unwrap(), (2, 3));
    }

    #[test]
    fn test_parse_suites_i_errors() {
        assert!(parse_suites_i(&[]).is_err());
        assert!(parse_suites_i(&[0x80]).is_err());
        assert!(parse_suites_i(&[0x18]).is_err());
    }

    #[test]
    fn test_responder_accepts_suites_i_array() {
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push(0x00).unwrap();
        msg1.push(0x82).unwrap();
        msg1.push(0x00).unwrap();
        msg1.push(0x02).unwrap();
        msg1.push(0x58).unwrap();
        msg1.push(32).unwrap();
        let g_x = [0xAAu8; 32];
        msg1.extend_from_slice(&g_x).unwrap();
        msg1.push(0x05).unwrap();

        let result = responder.process_message_1(&msg1);
        assert!(
            result.is_ok(),
            "Responder should accept array-format SUITES_I: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_responder_rejects_unsupported_suite_in_array() {
        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);

        let mut msg1 = heapless::Vec::<u8, 64>::new();
        msg1.push(0x00).unwrap();
        msg1.push(0x82).unwrap();
        msg1.push(0x02).unwrap();
        msg1.push(0x00).unwrap();
        msg1.push(0x58).unwrap();
        msg1.push(32).unwrap();
        let g_x = [0xAAu8; 32];
        msg1.extend_from_slice(&g_x).unwrap();
        msg1.push(0x05).unwrap();

        let result = responder.process_message_1(&msg1);
        assert!(matches!(result, Err(EdhocError::UnsupportedSuite)));
    }

    #[test]
    fn test_export_before_handshake_returns_error() {
        use crate::OscoreError;

        let initiator_seed = [0x11u8; 32];
        let mut rng = rand_core::OsRng;
        let mut initiator = EdhocInitiator::new(initiator_seed, 0x00, &mut rng);
        let _msg1 = initiator.create_message_1().unwrap();
        assert!(
            matches!(initiator.export_oscore(), Err(OscoreError::NoContext)),
            "Initiator export_oscore should fail before process_message_2"
        );

        let responder_seed = [0x22u8; 32];
        let mut rng = rand_core::OsRng;
        let mut responder = EdhocResponder::new(responder_seed, 0x01, &mut rng);
        let _msg2 = responder.process_message_1(&_msg1).unwrap();
        assert!(
            matches!(responder.export_oscore(), Err(OscoreError::NoContext)),
            "Responder export_oscore should fail before process_message_3"
        );
    }

    use serde_json::Value;

    fn edhoc_vector(name: &str) -> Value {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../test/vectors/edhoc.json")).unwrap();
        vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"].as_str().unwrap() == name)
            .cloned()
            .unwrap()
    }

    #[test]
    fn test_prk_oscore_interop_vectors() {
        let v = edhoc_vector("rfc9529_trace_prk_export");
        assert_eq!(
            v["master_secret"].as_str().unwrap(),
            "6dd8bfb559c311377364fd583db800f8"
        );
        assert_eq!(v["master_salt"].as_str().unwrap(), "39b3ec8bfae98a3e");
    }
}
