// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! STM32WL integrated SubGHz Radio implementation.
//!
//! The STM32WL55 has an integrated SX1262-like radio connected via internal SPI.
//! lora-phy provides native support via the Stm32wl variant.
//!
//! ponytail: STM32WL is the cleanest target - no external SPI wiring needed.

use embedded_hal_async::delay::DelayNs;
use lora_phy::mod_params::{Bandwidth, CodingRate, RadioError as LoraRadioError, SpreadingFactor};
use lora_phy::mod_traits::InterfaceVariant;
use lora_phy::sx126x::{self, Stm32wl, Sx126x, TcxoCtrlVoltage};
use lora_phy::{LoRa, RxMode};

use lichen_hal::{ChannelConfig, Radio, RadioConfig, RadioError, RxPacket};

/// STM32WL SubGHz Radio wrapper implementing lichen_hal::Radio.
///
/// Uses the internal SPI bus via embassy-stm32's SubGhz peripheral.
pub struct Stm32wlRadio<SPI, IV, D>
where
    SPI: embedded_hal_async::spi::SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    lora: LoRa<Sx126x<SPI, IV, Stm32wl>, D>,
    config: RadioConfig,
}

/// Type alias for STM32WL radio errors using the common RadioError type.
pub type Stm32wlError<E> = RadioError<E>;

impl<SPI, IV, D> Stm32wlRadio<SPI, IV, D>
where
    SPI: embedded_hal_async::spi::SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    /// Create a new STM32WL SubGHz radio.
    ///
    /// # Arguments
    /// * `spi` - SubGhz SPI device from embassy-stm32
    /// * `iv` - Interface variant (busy, DIO1 from SubGhz peripheral)
    /// * `delay` - Async delay provider
    /// * `tcxo_voltage` - TCXO voltage (most STM32WL boards have TCXO)
    pub async fn new(
        spi: SPI,
        iv: IV,
        delay: D,
        tcxo_voltage: Option<TcxoCtrlVoltage>,
    ) -> Result<Self, Stm32wlError<SPI::Error>> {
        let config = sx126x::Config {
            chip: Stm32wl {
                use_high_power_pa: true,
            },
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
            _ => SpreadingFactor::_10,
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

impl<SPI, IV, D> Radio for Stm32wlRadio<SPI, IV, D>
where
    SPI: embedded_hal_async::spi::SpiDevice<u8>,
    IV: InterfaceVariant,
    D: DelayNs,
{
    type Error = Stm32wlError<SPI::Error>;

    async fn transmit(&mut self, _channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
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

    async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn receive(
        &mut self,
        _channel: u8,
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

        let timeout = timeout_ms.min(u16::MAX as u32) as u16;

        self.lora
            .prepare_for_rx(RxMode::Single(timeout), &mdltn, &rx_params)
            .await
            .map_err(|_| RadioError::Hardware)?;

        match self.lora.rx(&rx_params, buf).await {
            Ok((len, status)) => Ok(Some(RxPacket {
                len: len as usize,
                rssi: Some(status.rssi),
                snr: Some(status.snr as i8),
            })),
            Err(LoraRadioError::ReceiveTimeout) => Ok(None),
            Err(_) => Err(RadioError::Hardware),
        }
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
    }

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Err(RadioError::NotSupported)
    }
}
