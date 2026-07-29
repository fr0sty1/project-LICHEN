//! Cryptographic key newtypes for type-safe key handling.
//!
//! Re-exports from the `schnorr48` crate:
//! - `Seed` — 32-byte random seed for key derivation (persisted to storage)
//! - `PrivateKey` — 32-byte clamped Ed25519 scalar (never persisted, derived from seed)
//! - `PublicKey` — 32-byte compressed Ed25519 point (used for signature verification)
//!
//! The compiler now catches mistakes like passing a private key where a public key
//! is expected, or using an unclamped seed as a private key.

#[cfg(feature = "schnorr")]
pub use schnorr48::{PrivateKey, PublicKey, Seed};
