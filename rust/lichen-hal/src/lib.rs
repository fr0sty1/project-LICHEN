//! Hardware abstraction traits for LICHEN.
//!
//! Defines the minimal interface between protocol code (lichen-core, lichen-node)
//! and hardware. Implementations live in lichen-embassy (embedded) or use std
//! directly (Linux border router).

#![no_std]

#[cfg(feature = "std")]
extern crate std;

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

impl Default for RadioConfig {
    fn default() -> Self {
        // ponytail: LICHEN defaults from spec
        Self {
            spreading_factor: 10,
            bandwidth: 125_000,
            coding_rate: 5, // CR 4/5
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
    /// Read value for key into buffer. Returns bytes read, or None if not found.
    fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize>;

    /// Write value for key. Returns Err if storage full or key too long.
    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), ()>;

    /// Delete key. Returns true if key existed.
    fn delete(&mut self, key: &str) -> bool;
}

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
