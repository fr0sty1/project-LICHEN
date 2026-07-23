//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod addr;
pub mod announce;
pub mod checksum;
pub mod compact_cot;
pub mod constants;
pub mod duty_cycle;
pub mod error;
pub mod icmpv6;
pub mod ipv6;
pub mod l2_payload;
pub mod loadng;
pub mod rf_health;
pub mod tx_queue;
pub mod udp;

#[cfg(feature = "std")]
extern crate std;

pub fn lichen_hash_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193u32);
    }
    hash
}
