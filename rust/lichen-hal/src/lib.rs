//! Hardware abstraction traits for LICHEN (Radio, Clock, Rng, NonVolatile, storage).
//!
//! UI section (Display, Input, Power, ButtonState etc.) removed as dead code
//! per project-LICHEN-nafo (aligns with rf_health EMA/adaptive-SF minimalism,
//! CCP-9 announce changes, and lichen-tui using ratatui instead). Only core
//! radio traits remain. #![forbid(unsafe_code)] added to match core style from epic.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub mod loopback;

pub mod storage;

/// Received packet metadata.
#[derive(Debug, Clone, Copy)]
pub struct RxPacket {
    /// Payload length in bytes.
    pub len: usize,
    /// RSSI in dBm (if available).
    pub rssi: Option<i16>,
    /// SNR in dB (if available).
    pub snr: Option<i8>,
}

/// Radio configuration.
#[derive(Debug, Clone, Copy)]
pub struct RadioConfig {
    /// Spreading factor (7-12 for LoRa).
    pub spreading_factor: u8,
    /// Bandwidth in Hz (e.g. 125_000).
    pub bandwidth: u32,
    /// Coding rate denominator (5-8 for CR 4/5 to 4/8).
    pub coding_rate: u8,
    /// Transmit power in dBm.
    pub tx_power: i8,
    /// Frequency in Hz.
    pub frequency: u32,
}

/// Common error type for Radio implementations.
///
/// Generic over `E` for hardware-specific errors (e.g., SPI errors).
/// Implementations that cannot fail use `core::convert::Infallible` for `E`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RadioError<E> {
    /// Hardware bus error (SPI, I2C, etc).
    Bus(E),
    /// Radio hardware returned an error or is unresponsive.
    Hardware,
    /// Protocol error (bad response, framing, etc).
    Protocol,
    /// Connection lost (for networked/simulated radios).
    Connection,
}

impl<E: core::fmt::Debug> core::fmt::Display for RadioError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bus(e) => write!(f, "bus error: {:?}", e),
            Self::Hardware => write!(f, "radio hardware error"),
            Self::Protocol => write!(f, "protocol error"),
            Self::Connection => write!(f, "connection lost"),
        }
    }
}

impl<E: core::fmt::Debug + core::error::Error + 'static> core::error::Error for RadioError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bus(e) => Some(e),
            _ => None,
        }
    }
}

impl Default for RadioConfig {
    fn default() -> Self {
        // ponytail: LICHEN defaults from spec
        Self {
            spreading_factor: 10,
            bandwidth: 125_000,
            coding_rate: 5, // CR 4/5 -- denominator only (4 is fixed per LoRa spec)
            tx_power: 14,
            frequency: 915_000_000,
        }
    }
}

/// LoRa radio interface.
///
/// Async-first design for Embassy compatibility. Implementations may use
/// blocking internally on platforms without async (wrapped in executor).
pub trait Radio {
    /// Error type for radio operations.
    type Error;

    /// Transmit a packet. Returns when transmission completes.
    fn transmit(
        &mut self,
        payload: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;

    /// CCP-15: Clear Channel Assessment (CAD/CCA) before TX. Returns true if clear.
    fn cca(&mut self, threshold_dbm: i8) -> impl core::future::Future<Output = Result<bool, Self::Error>>;

    /// Receive a packet with timeout.
    ///
    /// Writes received data to `buf`, returns `Some(RxPacket)` on success,
    /// `None` on timeout. Buffer must be at least 255 bytes for max LoRa payload.
    fn receive(
        &mut self,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> impl core::future::Future<Output = Result<Option<RxPacket>, Self::Error>>;

    /// Apply radio configuration.
    fn configure(&mut self, config: &RadioConfig);
}

/// Monotonic clock source.
pub trait Clock {
    /// Current time in microseconds since arbitrary epoch.
    fn now_us(&self) -> u64;
}

/// Random number generator.
pub trait Rng {
    /// Fill buffer with random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// Non-volatile storage for persistent state.
///
/// Used for identity keys, routing state, etc. Keys are short ASCII strings.
pub trait NonVolatile {
    /// Error type for storage operations.
    type Error;

    /// Read value for key into buffer. Returns bytes read, or None if not found.
    fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize>;

    /// Write value for key. Returns Err if storage full or key too long.
    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error>;

    /// Delete key. Returns true if key existed.
    fn delete(&mut self, key: &str) -> bool;
}

// Device UI traits removed (dead code; superseded by ratatui in lichen-tui and
// not wired to any HAL impl post-CCP-9/15/epic l3j5).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_config_default() {
        let cfg = RadioConfig::default();
        assert_eq!(cfg.spreading_factor, 10);
        assert_eq!(cfg.bandwidth, 125_000);
        assert_eq!(cfg.coding_rate, 5);
    }
}
