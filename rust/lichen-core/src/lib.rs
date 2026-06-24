//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![no_std]

pub mod addr;
pub mod constants;
pub mod icmpv6;

#[cfg(feature = "std")]
extern crate std;
