//! Embassy HAL implementations for LICHEN.
//!
//! Provides implementations of `lichen_hal` traits for various embedded targets.
//! Each target is feature-gated:
//!
//! - `esp32s3`: ESP32-S3 with SX1262 (esp-hal)
//! - `nrf52840`: nRF52840 with SX1262 (embassy-nrf)
//! - `rp2040`: RP2040 with SX1262 (embassy-rp)
//! - `stm32wl`: STM32WL55 with integrated SubGHz (embassy-stm32)
//! - `mock`: Host-side mock for testing

#![cfg_attr(not(feature = "mock"), no_std)]

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "esp32s3")]
pub mod esp32s3;

// ponytail: other targets stubbed until needed
// #[cfg(feature = "nrf52840")]
// pub mod nrf52840;
// #[cfg(feature = "rp2040")]
// pub mod rp2040;
// #[cfg(feature = "stm32wl")]
// pub mod stm32wl;
