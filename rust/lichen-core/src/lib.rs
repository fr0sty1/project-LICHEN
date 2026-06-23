//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![no_std]

pub mod constants;
pub mod addr;

#[cfg(feature = "std")]
extern crate std;
