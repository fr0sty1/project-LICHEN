//! Cryptographic key newtypes for type-safe key handling.
//!
//! These newtypes prevent accidental misuse of raw `[u8; 32]` arrays:
//! - `Seed` — 32-byte random seed for key derivation (persisted to storage)
//! - `PrivateKey` — 32-byte clamped Ed25519 scalar (never persisted, derived from seed)
//! - `PublicKey` — 32-byte compressed Ed25519 point (used for signature verification)
//!
//! The compiler now catches mistakes like passing a private key where a public key
//! is expected, or using an unclamped seed as a private key.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte identity seed.
///
/// This is the root secret: random bytes persisted to flash and used to derive
/// the keypair via `derive_keypair(&seed)`. Never transmitted over the network.
///
/// Key material is zeroized on drop to minimize exposure window.
/// Note: Cannot derive Copy because ZeroizeOnDrop requires Drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Seed(pub(crate) [u8; 32]);

impl Seed {
    /// Create a seed from raw bytes.
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the inner bytes.
    ///
    /// Note: Not const because ZeroizeOnDrop adds a destructor.
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        let bytes = self.0;
        core::mem::forget(self); // Skip zeroization since caller takes ownership
        bytes
    }
}

impl From<[u8; 32]> for Seed {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8; 32]> for Seed {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak seed bytes in debug output
        write!(f, "Seed([REDACTED])")
    }
}

/// 32-byte clamped Ed25519 private key (scalar).
///
/// Derived from a `Seed` via `derive_keypair`. Used for signing.
/// Never persisted directly — only the seed is stored.
///
/// Key material is zeroized on drop to minimize exposure window.
/// Note: Cannot derive Copy because ZeroizeOnDrop requires Drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub(crate) [u8; 32]);

impl PrivateKey {
    /// Create a private key from raw bytes.
    ///
    /// # Safety
    /// The caller must ensure the bytes are a properly clamped Ed25519 scalar.
    /// Prefer using `derive_keypair` to obtain a valid private key.
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the inner bytes.
    ///
    /// Note: Not const because ZeroizeOnDrop adds a destructor.
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        let bytes = self.0;
        core::mem::forget(self); // Skip zeroization since caller takes ownership
        bytes
    }
}

impl AsRef<[u8; 32]> for PrivateKey {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak private key bytes in debug output
        write!(f, "PrivateKey([REDACTED])")
    }
}

/// 32-byte Ed25519 public key (compressed point).
///
/// Used for signature verification and peer identity. Can be freely shared.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) [u8; 32]);

impl PublicKey {
    /// Create a public key from raw bytes.
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the inner bytes.
    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8; 32]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first 4 bytes for identification
        write!(
            f,
            "PublicKey({:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hex-encode the full public key
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    #[test]
    fn seed_debug_redacted() {
        let seed = Seed::new([0xAB; 32]);
        let debug = format!("{:?}", seed);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn private_key_debug_redacted() {
        let key = PrivateKey::new([0xCD; 32]);
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("cd"));
    }

    #[test]
    fn public_key_debug_shows_prefix() {
        let key = PublicKey::new({
            let mut arr = [0u8; 32];
            arr[0] = 0x12;
            arr[1] = 0x34;
            arr[2] = 0x56;
            arr[3] = 0x78;
            arr
        });
        let debug = format!("{:?}", key);
        assert!(debug.contains("12345678"));
    }

    #[test]
    fn seed_roundtrip() {
        let bytes = [0x42u8; 32];
        let seed = Seed::from(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
        assert_eq!(seed.into_bytes(), bytes);
    }

    #[test]
    fn public_key_equality() {
        let a = PublicKey::new([0x01; 32]);
        let b = PublicKey::new([0x01; 32]);
        let c = PublicKey::new([0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
