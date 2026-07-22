// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! ESP32-S3 + SX1262 Radio implementation.
//!
//! Wraps lora-phy's SX126x driver to implement lichen_hal::Radio.
//! Targets boards like T-Deck (ESP32-S3 + SX1262 via SPI).

use embedded_hal_async::delay::DelayNs;
use embedded_hal_async::spi::SpiDevice;
use lora_phy::mod_params::{Bandwidth, CodingRate, RadioError as LoraRadioError, SpreadingFactor};
use lora_phy::mod_traits::InterfaceVariant;
use lora_phy::sx126x::{self, Sx1262, Sx126x, TcxoCtrlVoltage};
use lora_phy::{LoRa, RxMode};

use lichen_hal::{ChannelConfig, Radio, RadioConfig, RadioError, RxPacket};

/// SX1262 Radio wrapper implementing lichen_hal::Radio.
///
/// Generic over SPI bus and delay provider to work with any ESP32-S3 pin config.
pub struct Sx1262Radio<SPI, IV, D>
where
    SPI: SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    lora: LoRa<Sx126x<SPI, IV, Sx1262>, D>,
    config: RadioConfig,
}

/// Type alias for SX1262 radio errors using the common RadioError type.
pub type Sx1262Error<E> = RadioError<E>;

impl<SPI, IV, D> Sx1262Radio<SPI, IV, D>
where
    SPI: SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    /// Create a new SX1262 radio.
    ///
    /// # Arguments
    /// * `spi` - SPI device (CS handled internally)
    /// * `iv` - Interface variant (reset, busy, DIO1 pins)
    /// * `delay` - Async delay provider
    /// * `tcxo_voltage` - TCXO voltage if board has TCXO, None for crystal
    pub async fn new(
        spi: SPI,
        iv: IV,
        delay: D,
        tcxo_voltage: Option<TcxoCtrlVoltage>,
    ) -> Result<Self, Sx1262Error<SPI::Error>> {
        let config = sx126x::Config {
            chip: Sx1262,
            tcxo_ctrl: tcxo_voltage,
            use_dcdc: true,
            rx_boost: false,
        };

        let sx126x = Sx126x::new(spi, iv, config);
        let lora = LoRa::new(sx126x, false, delay)
            .await
            .map_err(|_| RadioError::Hardware)?;

        Ok(Self {
            lora,
            config: RadioConfig::default(),
        })
    }

    /// Get spreading factor enum from config.
    fn spreading_factor(&self) -> SpreadingFactor {
        match self.config.spreading_factor {
            7 => SpreadingFactor::_7,
            8 => SpreadingFactor::_8,
            9 => SpreadingFactor::_9,
            10 => SpreadingFactor::_10,
            11 => SpreadingFactor::_11,
            12 => SpreadingFactor::_12,
            _ => SpreadingFactor::_10, // LICHEN default
        }
    }

    /// Get bandwidth enum from config.
    fn bandwidth(&self) -> Bandwidth {
        match self.config.bandwidth {
            125_000 => Bandwidth::_125KHz,
            250_000 => Bandwidth::_250KHz,
            500_000 => Bandwidth::_500KHz,
            _ => Bandwidth::_125KHz,
        }
    }

    /// Get coding rate enum from config.
    fn coding_rate(&self) -> CodingRate {
        match self.config.coding_rate {
            5 => CodingRate::_4_5,
            6 => CodingRate::_4_6,
            7 => CodingRate::_4_7,
            8 => CodingRate::_4_8,
            _ => CodingRate::_4_5,
        }
    }
}

impl<SPI, IV, D> Radio for Sx1262Radio<SPI, IV, D>
where
    SPI: SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    type Error = Sx1262Error<SPI::Error>;

    async fn transmit(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        let mdltn = self
            .lora
            .create_modulation_params(
                self.spreading_factor(),
                self.bandwidth(),
                self.coding_rate(),
                self.config.frequency,
            )
            .map_err(|_| RadioError::Hardware)?;

        let mut tx_params = self
            .lora
            .create_tx_packet_params(8, false, true, false, &mdltn)
            .map_err(|_| RadioError::Hardware)?;

        self.lora
            .prepare_for_tx(&mdltn, &mut tx_params, self.config.tx_power as i32, payload)
            .await
            .map_err(|_| RadioError::Hardware)?;

        self.lora.tx().await.map_err(|_| RadioError::Hardware)?;

        Ok(())
    }

    async fn receive(
        &mut self,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        let mdltn = self
            .lora
            .create_modulation_params(
                self.spreading_factor(),
                self.bandwidth(),
                self.coding_rate(),
                self.config.frequency,
            )
            .map_err(|_| RadioError::Hardware)?;

        let rx_params = self
            .lora
            .create_rx_packet_params(8, false, 255, true, false, &mdltn)
            .map_err(|_| RadioError::Hardware)?;

        // RxMode::Single takes u16, saturate if timeout exceeds u16::MAX
        let timeout = timeout_ms.min(u16::MAX as u32) as u16;

        self.lora
            .prepare_for_rx(RxMode::Single(timeout), &mdltn, &rx_params)
            .await
            .map_err(|_| RadioError::Hardware)?;

        match self.lora.rx(&rx_params, buf).await {
            Ok((len, status)) => Ok(Some(RxPacket {
                len: len as usize,
                rssi: Some(status.rssi),
                snr: Some(status.snr as i8), // lora-phy uses i16, we use i8
            })),
            Err(LoraRadioError::ReceiveTimeout) => Ok(None),
            Err(_) => Err(RadioError::Hardware),
        }
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
        // ponytail: config applied lazily on next TX/RX
    }
}

// ponytail: InterfaceVariant impl for ESP32-S3 GPIO pins would go here,
// but esp-hal may already provide one. Check esp-hal-embassy examples.
