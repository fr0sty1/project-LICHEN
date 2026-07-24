//! Hardware abstraction traits for LICHEN (Radio, Clock, Rng, NonVolatile, storage).
//!
//! UI section (Display, Input, Power, ButtonState etc.) removed as dead code
//! per project-LICHEN-nafo (and project-LICHEN-bpu5 worker23 merge-conflict resolution).
//! Aligns with rf_health EMA/adaptive-SF minimalism, CCP-9, lichen-tui/ratatui.
//! Only core radio traits remain. #![forbid(unsafe_code)] matches core style.

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

/// Channel configuration for multi-channel concentrators (SX1302/RAK2287).
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    pub frequency: u32,
    pub spreading_factor: u8,
    pub bandwidth: u32,
    pub coding_rate: u8,
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
    /// Operation not supported by this radio (e.g. multi-channel on single-radio impl).
    NotSupported,
}

impl<E: core::fmt::Debug> core::fmt::Display for RadioError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bus(e) => write!(f, "bus error: {:?}", e),
            Self::Hardware => write!(f, "radio hardware error"),
            Self::Protocol => write!(f, "protocol error"),
            Self::Connection => write!(f, "connection lost"),
            Self::NotSupported => write!(f, "not supported"),
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
        Self {
            spreading_factor: 10,
            bandwidth: 125_000,
            coding_rate: 5,
            tx_power: 14,
            frequency: 915_000_000,
        }
    }
}

/// LoRa radio interface supporting single and multi-channel gateways.
pub trait Radio {
    /// Error type for radio operations.
    type Error;

    /// Transmit a packet on specified channel (CCP-12/15). Returns when transmission completes.
    fn transmit(
        &mut self,
        channel: u8,
        payload: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;

    /// CCP-15: Clear Channel Assessment (CAD/CCA) on channel before TX. Returns true if clear.
    fn cca(
        &mut self,
        channel: u8,
        threshold_dbm: i8,
    ) -> impl core::future::Future<Output = Result<bool, Self::Error>>;

    /// Receive a packet on specified channel with timeout (CCP rendezvous).
    ///
    /// Writes received data to `buf`, returns `Some(RxPacket)` on success,
    /// `None` on timeout. Buffer must be at least 255 bytes for max LoRa payload.
    fn receive(
        &mut self,
        channel: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> impl core::future::Future<Output = Result<Option<RxPacket>, Self::Error>>;

    fn configure(&mut self, config: &RadioConfig);

    /// Configure multiple channels for concentrator mode (SX1302 gateways).
    fn configure_channels(
        &mut self,
        channels: &[ChannelConfig],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;

    /// Returns rx_channel (preferred RX channel for CCP-9 rendezvous).
    /// Defaults to 0 to mimic single-channel SX126x behavior.
    fn rx_channel(&self) -> u8 {
        0
    }
}

/// Minimal ChannelPlan support (u8 index into regional plan per CCP-4).
pub type ChannelPlan = u8;

/// Operating class identifier for regional channel plans (CCP-3/CCP-4).
///
/// Each variant maps to a set of radio parameters (frequency, SF, BW, CR, power)
/// and regulatory rules (duty cycle region). New classes can be added as the
/// protocol expands to additional regulatory domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperatingClass {
    /// US/CA 915 MHz ISM band (903.9 MHz CH0, 1 W max, no duty cycle limit).
    UsCa = 0,
    /// EU 868 MHz band (868.1 MHz CH0, 14 dBm typical, 1% duty cycle).
    Eu = 1,
    /// AU/NZ 915 MHz ISM band (916.8 MHz CH0, 30 dBm max, <5% duty cycle).
    AuNz = 2,
}

impl OperatingClass {
    /// All defined operating classes, ordered.
    pub const ALL: &[Self] = &[Self::UsCa, Self::Eu, Self::AuNz];

    /// Lookup an operating class by its integer discriminant.
    ///
    /// Returns `None` for unknown values (graceful fallback to CH0-only).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::UsCa),
            1 => Some(Self::Eu),
            2 => Some(Self::AuNz),
            _ => None,
        }
    }

    /// Return the default (first) operating class.
    pub const fn default() -> Self {
        Self::UsCa
    }
}

impl Default for OperatingClass {
    fn default() -> Self {
        Self::default()
    }
}

impl From<OperatingClass> for u8 {
    fn from(c: OperatingClass) -> Self {
        c as u8
    }
}

/// Radio parameters associated with a single operating class.
///
/// Every class defines a fixed PHY profile (SF, BW, CR) per CCP PHY profile ID
/// `0x01` plus the per-class CH0 frequency and regulatory constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatingClassParams {
    /// Operating class discriminant (matches [`OperatingClass`] repr).
    pub class_id: u8,
    /// Human-readable label (e.g. "US/CA", "EU", "AU/NZ").
    pub label: &'static str,
    /// CH0 centre frequency in Hz.
    pub frequency_hz: u32,
    /// Spreading factor (7-12).
    pub spreading_factor: u8,
    /// Bandwidth in Hz.
    pub bandwidth_hz: u32,
    /// Coding rate denominator (5 = 4/5, 6 = 4/6, etc.).
    pub coding_rate: u8,
    /// Max transmit power in dBm.
    pub tx_power_dbm: i8,
    /// Duty cycle region discriminant (matches [`duty_cycle`] `REGION_*` constants).
    pub duty_region: u8,
    /// Base duty cycle in permille (10 = 1%, 1000 = 100%).
    pub duty_permille: u16,
}

/// Operating class lookup table (CCP-3/CCP-4).
///
/// Indexed by [`OperatingClass`] discriminant. Using a slice rather than an
/// array preserves the ability to add entries without changing public API size.
pub static OPERATING_CLASS_TABLE: &[OperatingClassParams] = &[
    OperatingClassParams {
        class_id: 0,
        label: "US/CA",
        frequency_hz: 903_900_000,
        spreading_factor: 10,
        bandwidth_hz: 125_000,
        coding_rate: 5,
        tx_power_dbm: 20,
        duty_region: 1,     // REGION_US
        duty_permille: 1000, // 100 %
    },
    OperatingClassParams {
        class_id: 1,
        label: "EU",
        frequency_hz: 868_100_000,
        spreading_factor: 10,
        bandwidth_hz: 125_000,
        coding_rate: 5,
        tx_power_dbm: 14,
        duty_region: 0,     // REGION_EU
        duty_permille: 10,   // 1 %
    },
    OperatingClassParams {
        class_id: 2,
        label: "AU/NZ",
        frequency_hz: 916_800_000,
        spreading_factor: 10,
        bandwidth_hz: 125_000,
        coding_rate: 5,
        tx_power_dbm: 30,
        duty_region: 0,     // REGION_EU-like limits
        duty_permille: 50,   // 5 %
    },
];

/// Look up operating class parameters by class ID.
///
/// Returns `None` if the class ID is not in the table (caller should fall back
/// to CH0-only operation per spec CCP-4 §2a.6).
pub fn lookup_operating_class(class_id: u8) -> Option<&'static OperatingClassParams> {
    OPERATING_CLASS_TABLE.iter().find(|p| p.class_id == class_id)
}

impl RadioConfig {
    /// Build a [`RadioConfig`] from operating class parameters.
    ///
    /// Convenience constructor for single-channel radios configured to CH0.
    pub fn from_operating_class(params: &OperatingClassParams) -> Self {
        Self {
            spreading_factor: params.spreading_factor,
            bandwidth: params.bandwidth_hz,
            coding_rate: params.coding_rate,
            tx_power: params.tx_power_dbm,
            frequency: params.frequency_hz,
        }
    }
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

#[cfg(feature = "rand")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rand")]
impl<T: Rng + ?Sized> RngCore for T {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as Rng>::fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "rand")]
impl<T: Rng + ?Sized> CryptoRng for T {}

/// Non-volatile storage for persistent state.
///
/// Used for identity keys, routing state, etc. Keys are short ASCII strings.
pub trait NonVolatile {
    /// Error type for storage operations.
    type Error;

    /// Read value for key into buffer. If key exists, returns `Some(stored_len)`
    /// (the full original stored length), copying the first `min(stored_len, buf.len())`
    /// bytes into `buf`. Returns `None` if key not found.
    ///
    /// Callers can detect truncation or size mismatch by comparing the returned
    /// `stored_len` against `buf.len()` and expected size (see `load_*` in storage.rs).
    fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize>;

    /// Atomically and durably replace one value.
    ///
    /// `Ok(())` guarantees the complete new value survives power loss. `Err`
    /// guarantees the old value remains intact. Implementations must not expose
    /// torn, partially written, or acknowledged-but-volatile values.
    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error>;

    /// Delete key. Returns true if key existed.
    fn delete(&mut self, key: &str) -> bool;
}

// Device UI traits removed (dead code; superseded by ratatui in lichen-tui and
// not wired to any HAL impl post-CCP-9/15/epic l3j5).

/// Concentrator interface for RAK2287/SX130x multi-channel (reset, SPI, IRQ, PPS).
pub trait Concentrator {
    type Error;
    fn reset(&mut self) -> impl core::future::Future<Output = Result<(), Self::Error>>;
    fn spi_transfer(
        &mut self,
        write: &[u8],
        read: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
    fn irq_status(&mut self) -> impl core::future::Future<Output = Result<u32, Self::Error>>;
    fn pps_timestamp(&self) -> Option<u64>;
    fn configure(
        &mut self,
        config: &RadioConfig,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
    fn transmit(
        &mut self,
        payload: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
}

#[cfg(feature = "std")]
pub struct Sx1302Concentrator;

#[cfg(feature = "std")]
impl Concentrator for Sx1302Concentrator {
    type Error = RadioError<std::convert::Infallible>;

    async fn reset(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn spi_transfer(&mut self, _write: &[u8], _read: &mut [u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn irq_status(&mut self) -> Result<u32, Self::Error> {
        Ok(1)  // simulate pending packet for RX
    }

    fn pps_timestamp(&self) -> Option<u64> {
        Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64)
    }

    async fn configure(&mut self, _config: &RadioConfig) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn transmit(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
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

    #[test]
    fn operating_class_from_u8_known() {
        assert_eq!(OperatingClass::from_u8(0), Some(OperatingClass::UsCa));
        assert_eq!(OperatingClass::from_u8(1), Some(OperatingClass::Eu));
        assert_eq!(OperatingClass::from_u8(2), Some(OperatingClass::AuNz));
    }

    #[test]
    fn operating_class_from_u8_unknown() {
        assert_eq!(OperatingClass::from_u8(3), None);
        assert_eq!(OperatingClass::from_u8(255), None);
    }

    #[test]
    fn operating_class_default_is_us_ca() {
        assert_eq!(OperatingClass::default(), OperatingClass::UsCa);
    }

    #[test]
    fn operating_class_to_u8() {
        assert_eq!(u8::from(OperatingClass::UsCa), 0);
        assert_eq!(u8::from(OperatingClass::Eu), 1);
        assert_eq!(u8::from(OperatingClass::AuNz), 2);
    }

    #[test]
    fn lookup_known_class() {
        let p = lookup_operating_class(0).expect("UsCa must be in table");
        assert_eq!(p.frequency_hz, 903_900_000);
        assert_eq!(p.duty_permille, 1000);

        let p = lookup_operating_class(1).expect("EU must be in table");
        assert_eq!(p.frequency_hz, 868_100_000);
        assert_eq!(p.duty_permille, 10);

        let p = lookup_operating_class(2).expect("AU/NZ must be in table");
        assert_eq!(p.frequency_hz, 916_800_000);
        assert_eq!(p.duty_permille, 50);
    }

    #[test]
    fn lookup_missing_class_returns_none() {
        assert!(lookup_operating_class(3).is_none());
        assert!(lookup_operating_class(255).is_none());
    }

    #[test]
    fn all_classes_have_labels() {
        for c in OperatingClass::ALL {
            let p = lookup_operating_class(*c as u8).expect("every variant must have params");
            assert!(!p.label.is_empty());
        }
    }

    #[test]
    fn radio_config_from_operating_class() {
        let params = lookup_operating_class(0).unwrap();
        let cfg = RadioConfig::from_operating_class(params);
        assert_eq!(cfg.frequency, 903_900_000);
        assert_eq!(cfg.spreading_factor, 10);
        assert_eq!(cfg.bandwidth, 125_000);
        assert_eq!(cfg.coding_rate, 5);
        assert_eq!(cfg.tx_power, 20);
    }

    #[test]
    fn table_entries_match_constants_toml() {
        // Cross-check against canonical frequency constants
        let us = lookup_operating_class(0).unwrap();
        assert_eq!(us.frequency_hz, 903_900_000);

        let eu = lookup_operating_class(1).unwrap();
        assert_eq!(eu.frequency_hz, 868_100_000);

        let au = lookup_operating_class(2).unwrap();
        assert_eq!(au.frequency_hz, 916_800_000);
    }
}
