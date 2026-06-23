//! CoAP protocol implementation for LICHEN (RFC 7252).
//!
//! Provides message types, option stubs, and blockwise transfer stubs.
//! All CoAP traffic in LICHEN uses UDP port 5683 (or 5684 for DTLS) and is
//! header-compressed via SCHC before transmission over the link layer.

#![no_std]

pub mod message;
pub mod option;

pub use message::{MessageCode, MessageType};

#[cfg(feature = "std")]
extern crate std;
