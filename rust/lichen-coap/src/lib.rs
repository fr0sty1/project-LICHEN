//! CoAP protocol implementation for LICHEN (RFC 7252, RFC 7959).
//!
//! Provides message types, options, and (for LCI/gateway) blockwise support.
//! Blockwise is NOT RECOMMENDED on LoRa mesh (prefer SCHC per spec/07-transport-app.md).
//! All CoAP traffic in LICHEN uses UDP port 5683 (or 5684 for DTLS) and is
//! header-compressed via SCHC before transmission over the link layer.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod block;
pub mod codec;
pub mod message;
pub mod option;

pub use block::{BlockOption, BlockReceiver, BlockSender};
pub use codec::{CoapBuilder, CoapError, CoapOption, CoapPacket};
pub use message::{MessageCode, MessageType};

#[cfg(feature = "tokio")]
pub mod client;
