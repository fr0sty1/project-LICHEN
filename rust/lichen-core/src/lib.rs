//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![no_std]

pub mod addr;
pub mod announce;
pub mod constants;
pub mod error;
pub mod icmpv6;
pub mod ipv6;
pub mod l2_payload;
pub mod loadng;
pub mod udp;

#[cfg(feature = "std")]
extern crate std;
