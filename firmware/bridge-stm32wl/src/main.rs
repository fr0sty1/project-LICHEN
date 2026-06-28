//! LICHEN LoRa Bridge - STM32WL version
//!
//! Uses the STM32WL's integrated SubGHz radio (SX1262-compatible).
//! Implements LoRa TX/RX via lora-phy with queue-based packet handling.

#![no_std]
#![no_main]

mod iv;

use defmt::{error, info, warn};
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_stm32::bind_interrupts;
use embassy_stm32::dma::InterruptHandler as DmaInterruptHandler;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::spi::Spi;
use embassy_stm32::Config;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Delay, Timer};
use lora_phy::mod_params::{Bandwidth, CodingRate, SpreadingFactor};
use lora_phy::sx126x::{self, Sx126x, TcxoCtrlVoltage};
use lora_phy::LoRa;
use {defmt_rtt as _, panic_probe as _};

use iv::{InterruptHandler, RfSwitchMode, Stm32wlInterfaceVariant, SubghzSpiDevice};

// ============================================================================
// Constants
// ============================================================================

/// LICHEN default frequency: 915 MHz (US ISM band).
const LORA_FREQUENCY_HZ: u32 = 915_000_000;

/// Maximum LoRa payload size.
const MAX_PAYLOAD_LEN: usize = 255;

// ============================================================================
// Interrupt bindings
// ============================================================================

bind_interrupts!(struct Irqs {
    SUBGHZ_RADIO => InterruptHandler;
    DMA1_CHANNEL1 => DmaInterruptHandler<embassy_stm32::peripherals::DMA1_CH1>;
    DMA1_CHANNEL2 => DmaInterruptHandler<embassy_stm32::peripherals::DMA1_CH2>;
});

// ============================================================================
// Packet types
// ============================================================================

/// Packet to transmit over radio.
#[derive(Clone, Copy)]
pub struct TxPacket {
    pub data: [u8; MAX_PAYLOAD_LEN],
    pub len: usize,
}

impl TxPacket {
    pub const fn empty() -> Self {
        Self {
            data: [0; MAX_PAYLOAD_LEN],
            len: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut pkt = Self::empty();
        let len = data.len().min(MAX_PAYLOAD_LEN);
        pkt.data[..len].copy_from_slice(&data[..len]);
        pkt.len = len;
        pkt
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Received packet from radio.
#[derive(Clone, Copy)]
pub struct RxPacket {
    pub data: [u8; MAX_PAYLOAD_LEN],
    pub len: usize,
    pub rssi: i16,
    pub snr: i16,
}

impl RxPacket {
    pub const fn empty() -> Self {
        Self {
            data: [0; MAX_PAYLOAD_LEN],
            len: 0,
            rssi: 0,
            snr: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ============================================================================
// Static channels
// ============================================================================

/// Queue for packets to transmit over radio.
static TX_QUEUE: Channel<CriticalSectionRawMutex, TxPacket, 8> = Channel::new();

/// Queue for packets received from radio.
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, 8> = Channel::new();

// ============================================================================
// Main entry
// ============================================================================

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // Configure clocks for SubGHz radio
    // The radio needs HSE enabled for TCXO
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hse = Some(Hse {
            freq: embassy_stm32::time::Hertz(32_000_000),
            mode: HseMode::Bypass, // TCXO provides clock
            prescaler: HsePrescaler::DIV1,
        });
    }

    let p = embassy_stm32::init(config);

    info!("LICHEN bridge (STM32WL) starting...");

    // LED for status (PA5 on Nucleo-WLE5JC)
    let mut led = Output::new(p.PA5, Level::Low, Speed::Low);

    // Initialize SubGHz SPI with DMA
    // The STM32WL has internal SPI to the radio - no external pins needed
    let spi = Spi::new_subghz(p.SUBGHZSPI, p.DMA1_CH1, p.DMA1_CH2, Irqs);
    let spi_device = SubghzSpiDevice::new(spi);

    // RF switch pins for Nucleo-WL55JC1:
    // - PC3: RF_CTRL1 (FE_CTRL1)
    // - PC4: RF_CTRL2 (FE_CTRL2)
    // - PC5: RF_CTRL3 (FE_CTRL3)
    // For high-power TX: CTRL1=low, CTRL2=high, CTRL3=high
    // For RX: CTRL1=high, CTRL2=low, CTRL3=high
    // Simplified: just use CTRL2 for TX, CTRL1 for RX
    let rf_switch_rx = Some(p.PC3);
    let rf_switch_tx = Some(p.PC4);

    // Create interface variant with interrupt binding
    let iv = Stm32wlInterfaceVariant::new(Irqs, rf_switch_rx, rf_switch_tx, RfSwitchMode::HighPower);

    // Configure the Sx126x radio
    let radio_config = sx126x::Config {
        chip: sx126x::Stm32wl {
            use_high_power_pa: true,
        },
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
        use_dcdc: true,
        rx_boost: false,
    };

    // Create LoRa PHY instance
    let mut lora = match LoRa::new(Sx126x::new(spi_device, iv, radio_config), false, Delay).await {
        Ok(lora) => lora,
        Err(e) => {
            error!("LoRa init failed: {:?}", defmt::Debug2Format(&e));
            loop {
                for _ in 0..3 {
                    led.set_high();
                    Timer::after_millis(100).await;
                    led.set_low();
                    Timer::after_millis(100).await;
                }
                Timer::after_millis(500).await;
            }
        }
    };

    info!("SubGHz radio initialized");

    // Blink LED to indicate ready
    led.set_high();
    Timer::after_millis(100).await;
    led.set_low();

    // Create modulation parameters using lora-phy API
    // LICHEN spec: SF10, 125kHz, CR 4/5
    let mdltn_params = match lora.create_modulation_params(
        SpreadingFactor::_10,
        Bandwidth::_125KHz,
        CodingRate::_4_5,
        LORA_FREQUENCY_HZ,
    ) {
        Ok(params) => params,
        Err(e) => {
            error!("Modulation params failed: {:?}", defmt::Debug2Format(&e));
            loop {
                for _ in 0..3 {
                    led.set_high();
                    Timer::after_millis(100).await;
                    led.set_low();
                    Timer::after_millis(100).await;
                }
                Timer::after_millis(500).await;
            }
        }
    };

    info!(
        "Radio config: SF10, 125kHz, {} MHz",
        LORA_FREQUENCY_HZ / 1_000_000
    );

    // Create RX packet parameters
    let rx_pkt_params = match lora.create_rx_packet_params(
        8,                        // preamble_length
        false,                    // implicit_header
        MAX_PAYLOAD_LEN as u8,    // max_payload_length
        true,                     // crc_on
        false,                    // iq_inverted
        &mdltn_params,
    ) {
        Ok(params) => params,
        Err(e) => {
            error!("RX packet params failed: {:?}", defmt::Debug2Format(&e));
            loop {
                for _ in 0..3 {
                    led.set_high();
                    Timer::after_millis(100).await;
                    led.set_low();
                    Timer::after_millis(100).await;
                }
                Timer::after_millis(500).await;
            }
        }
    };

    // Prepare for continuous RX
    if let Err(e) = lora
        .prepare_for_rx(lora_phy::RxMode::Continuous, &mdltn_params, &rx_pkt_params)
        .await
    {
        error!("Failed to prepare for RX: {:?}", defmt::Debug2Format(&e));
    }

    info!("Radio in RX mode, starting main loop");

    // Main radio loop
    let tx_receiver = TX_QUEUE.receiver();
    let rx_sender = RX_QUEUE.sender();
    let mut rx_buf = [0u8; MAX_PAYLOAD_LEN];

    loop {
        // Wait for either: TX packet to send, or RX packet received
        match select(
            tx_receiver.receive(),
            lora.rx(&rx_pkt_params, &mut rx_buf),
        )
        .await
        {
            Either::First(tx_pkt) => {
                // TX packet available - transmit it
                info!("TX {} bytes", tx_pkt.len);
                led.set_high();

                // Create TX packet params (payload_length set to 0 initially, prepare_for_tx sets it)
                let mut tx_pkt_params = match lora.create_tx_packet_params(
                    8,      // preamble_length
                    false,  // implicit_header
                    true,   // crc_on
                    false,  // iq_inverted
                    &mdltn_params,
                ) {
                    Ok(params) => params,
                    Err(e) => {
                        error!("TX packet params failed: {:?}", defmt::Debug2Format(&e));
                        led.set_low();
                        continue;
                    }
                };

                match lora
                    .prepare_for_tx(&mdltn_params, &mut tx_pkt_params, 14, tx_pkt.as_slice())
                    .await
                {
                    Ok(()) => {
                        if let Err(e) = lora.tx().await {
                            error!("TX failed: {:?}", defmt::Debug2Format(&e));
                        } else {
                            info!("TX complete");
                        }
                    }
                    Err(e) => {
                        error!("TX prepare failed: {:?}", defmt::Debug2Format(&e));
                    }
                }

                led.set_low();

                // Return to RX mode
                if let Err(e) = lora
                    .prepare_for_rx(lora_phy::RxMode::Continuous, &mdltn_params, &rx_pkt_params)
                    .await
                {
                    error!("Failed to return to RX: {:?}", defmt::Debug2Format(&e));
                }
            }
            Either::Second(rx_result) => {
                // RX event
                match rx_result {
                    Ok((len, rx_quality)) => {
                        info!(
                            "RX {} bytes, RSSI={}, SNR={}",
                            len, rx_quality.rssi, rx_quality.snr
                        );
                        led.set_high();

                        let mut pkt = RxPacket::empty();
                        pkt.len = len as usize;
                        pkt.data[..pkt.len].copy_from_slice(&rx_buf[..pkt.len]);
                        pkt.rssi = rx_quality.rssi;
                        pkt.snr = rx_quality.snr;

                        if rx_sender.try_send(pkt).is_err() {
                            warn!("RX queue full, dropping packet");
                        }

                        led.set_low();
                    }
                    Err(e) => {
                        // RX error (CRC, timeout in single mode, etc.)
                        // In continuous mode, just continue listening
                        warn!("RX error: {:?}", defmt::Debug2Format(&e));
                    }
                }
            }
        }
    }
}

// ============================================================================
// Public API for packet queuing
// ============================================================================

/// Queue a packet for radio transmission.
///
/// Returns immediately. Packet will be transmitted asynchronously.
#[allow(dead_code)]
pub fn queue_radio_tx(data: &[u8]) -> bool {
    match TX_QUEUE.try_send(TxPacket::from_slice(data)) {
        Ok(()) => true,
        Err(_) => {
            warn!("TX queue full, dropping packet");
            false
        }
    }
}

/// Try to receive a packet from the radio.
///
/// Returns immediately with None if no packet available.
#[allow(dead_code)]
pub fn try_radio_rx() -> Option<RxPacket> {
    RX_QUEUE.try_receive().ok()
}
