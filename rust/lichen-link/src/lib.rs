//! LICHEN link layer (spec section 4).
//!
//! Implements the LICHEN frame format with LLSec flags, replay-window tracking,
//! and stubs for future AES-CCM encryption and Schnorr-48 link signatures.
//!
//! Wire layout (spec 4.1):
//! ```text
//! +--------+--------+-------+--------+----------+---------+-------+
//! | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload |  MIC  |
//! +--------+--------+-------+--------+----------+---------+-------+
//!    1B       1B       1B      2B       0/2/8B     var      4/8B
//! ```
//!
//! LLSec byte packs from LSB:
//!   bits 0-1 : AddrMode  (0=broadcast, 1=16-bit, 2=EUI-64, 3=elided)
//!   bits 2-4 : MicLength (0=32-bit, 1=64-bit)
//!   bit  5   : signature present (Schnorr-48)
//!   bit  6   : encrypted (AES-CCM)
//!   bit  7   : reserved (must be 0)

#![no_std]

pub mod frame;
pub mod replay;

#[cfg(feature = "std")]
extern crate std;
