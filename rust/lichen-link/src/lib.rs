//! LICHEN link layer (spec section 4).
//!
//! Implements the LICHEN frame format with LLSec flags, replay-window tracking,
//! and 48-byte Schnorr-48 link signatures. Encrypted link frames are unsupported.
//!
//! # Frame Types
//!
//! The stack uses distinct types for frames at different processing stages:
//!
//! - [`frame::LichenFrame`]: Raw parsed wire frame (zero-copy, borrowed).
//! - [`link_layer::AuthenticatedFrame`]: Frame after signature verification and
//!   replay check. Contains the inner payload and authenticated sender identity.
//! - `lichen_node::ReceivedIpv6`: Complete RX output with decompressed IPv6 and
//!   radio metadata (RSSI/SNR). This is the type application code receives.
//!
//! A common `Frame` trait is intentionally avoided: these represent different
//! protocol layers with incompatible semantics. Link frames have replay counters
//! and MICs; IPv6 packets have headers and hop limits. Forcing a shared trait
//! would be leaky abstraction.
//!
//! # Threat Model Note
//!
//! Keys are device-held: anyone with physical access has the key. The existing
//! side-channel mitigations (constant-time comparison, zeroize-on-drop) are
//! retained as low-cost best practice, but don't meaningfully improve security
//! for this use case. Remote timing attacks over a high-latency LoRa mesh are
//! impractical. Don't add more crypto hardening without a concrete threat.
//!
//! Wire layout (spec 4.1):
//! ```text
//! +--------+--------+-------+--------+----------+------------+---------+-------+
//! | Length | LLSec  | Epoch | SeqNum | Dst Addr | Signer EUI | Payload |  MIC  |
//! +--------+--------+-------+--------+----------+------------+---------+-------+
//!    1B       1B       1B      2B       0/2/8B       8B*        var      0/48B
//! ```
//! `Signer EUI` is present exactly when the SI bit is set; signed production
//! frames set SI so receivers can perform an exact peer lookup before crypto.
//! ```text
//! ```
//!
//! LLSec byte packs from LSB:
//!   bits 0-1 : AddrMode  (0=broadcast, 1=16-bit, 2=EUI-64, 3=elided)
//!   bits 2-4 : MicLength compatibility selector (0 or 1; ignored for wire MIC length)
//!   bit  5   : signature present (Schnorr-48)
//!   bit  6   : encrypted (unsupported; receivers reject)
//!   bit  7   : signer EUI-64 present (SI)

#![no_std]
#![forbid(unsafe_code)]

pub mod evidence;
pub mod frame;
pub mod keys;
pub mod replay;
pub mod seqnum;
pub mod sos;

pub use evidence::{
    AuthenticatedLinkFrame, DurablePeerKeyGeneration, PeerKeyGeneration, ReceiptClock,
    ReceiptClockError, ReceiptEvidence,
};
#[cfg(feature = "schnorr")]
pub use keys::{PrivateKey, PublicKey, Seed};
pub use seqnum::LinkSeqNum;

#[cfg(feature = "schnorr")]
pub mod schnorr;

#[cfg(feature = "schnorr")]
pub mod identity;
#[cfg(feature = "schnorr")]
pub use identity::{human_address_from_pubkey, iid_from_pubkey};
pub use lichen_core::addr::ygg_addr_from_pubkey;

pub use sos::{
    SosAlert, SosAlertType, SosCborError, SosRateLimitConfig, SosRateLimitConfigError,
    SosRateLimitResult, SosRateLimitState,
};

#[cfg(all(feature = "schnorr", feature = "std"))]
pub mod link_layer;
#[cfg(all(feature = "schnorr", feature = "std"))]
pub use link_layer::LinkRxError;

#[cfg(any(test, feature = "std"))]
extern crate std;

/// Test utilities shared across crate test modules.
#[cfg(test)]
pub(crate) mod test_utils {
    extern crate std;
    use std::vec::Vec;

    /// Parse a hex string into bytes.
    pub fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
