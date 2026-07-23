//! KISS protocol interface for TNC app compatibility.
//!
//! KISS (Keep It Simple, Stupid) is a TNC interface standard from 1986.
//! LICHEN uses it for compatibility with ham radio apps (aprs.fi, APRSDroid).
//!
//! # Features
//!
//! - `kiss` - Core KISS framing (encode/decode, escaping)
//! - `kiss-aprs` - APRS synthesis, AX.25 codec (depends on `kiss`)
//! - `kiss-ble` - BLE GATT service (depends on `kiss`)
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "kiss")]
//! # {
//! use lichen_kiss::{KissCommand, kiss_encode, kiss_decode, kiss_unescape};
//!
//! // Encode a data frame on port 0
//! let mut frame_buf = [0u8; 64];
//! let len = kiss_encode(0, KissCommand::Data, b"hello", &mut frame_buf).unwrap();
//!
//! // Decode it back
//! let decoded = kiss_decode(&frame_buf[..len]).unwrap();
//!
//! // Unescape the data
//! let mut data_buf = [0u8; 64];
//! let data_len = kiss_unescape(decoded.data, &mut data_buf).unwrap();
//! assert_eq!(&data_buf[..data_len], b"hello");
//! # }
//! ```

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "kiss")]
pub mod framing;

#[cfg(feature = "kiss-aprs")]
pub mod aprs;

#[cfg(feature = "kiss-ble")]
pub mod ble;

#[cfg(feature = "bridge")]
pub mod bridge;

// Re-export core types when kiss feature is enabled
#[cfg(feature = "kiss")]
pub use framing::{
    kiss_decode, kiss_encode, kiss_escape, kiss_unescape, KissCommand, KissError, KissFrame,
    KissReader, KissWriter, FEND, FESC, TFEND, TFESC,
};

// Re-export bridge types when bridge feature is enabled
#[cfg(feature = "bridge")]
pub use bridge::{BridgeError, DecodedKissFrame, KissBridge, PORT_AX25, PORT_RAW};
