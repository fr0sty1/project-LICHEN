//! LICHEN LoRa Bridge - ESP32/Embassy version for LilyGo T-Beam v1.2
//!
//! Build Instructions:
//! -------------------
//! 1. Install Rust Xtensa toolchain:
//!    ```
//!    cargo install espup
//!    espup install
//!    source ~/export-esp.sh  # or add to shell profile
//!    ```
//!
//! 2. Install flash tool:
//!    ```
//!    cargo install espflash
//!    ```
//!
//! 3. Build and flash:
//!    ```
//!    cd firmware/bridge-esp32
//!    cargo build --release
//!    cargo run --release  # builds, flashes, and monitors
//!    ```
//!
//! LilyGo T-Beam v1.2 Pin Assignments:
//! -----------------------------------
//! SX1262 Radio (SPI):
//!   - SCK:   GPIO5
//!   - MISO:  GPIO19
//!   - MOSI:  GPIO27
//!   - NSS:   GPIO18
//!   - RESET: GPIO23
//!   - BUSY:  GPIO32
//!   - DIO1:  GPIO33
//!
//! Other peripherals (not used in this scaffold):
//!   - GPS TX: GPIO34, RX: GPIO12
//!   - AXP192 PMU: I2C on GPIO21/22
//!   - OLED: I2C on GPIO21/22

#![no_std]
#![no_main]

extern crate alloc;

use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::Timer;
use esp_backtrace as _;
use esp_hal::gpio::{Input, Level, Output, Pull};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode as SpiMode;
use esp_hal::Async;
use esp_hal::time::Rate;
use log::{error, info, warn};

// ---- Radio Queue Types ----

/// Packet to transmit over radio.
#[derive(Clone, Copy)]
pub struct TxPacket {
    pub data: [u8; 256],
    pub len: usize,
}

impl TxPacket {
    pub const fn empty() -> Self {
        Self { data: [0; 256], len: 0 }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut pkt = Self::empty();
        let len = data.len().min(256);
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
    pub data: [u8; 256],
    pub len: usize,
    pub rssi: i16,
    pub snr: i8,
}

impl RxPacket {
    pub const fn empty() -> Self {
        Self {
            data: [0; 256],
            len: 0,
            rssi: 0,
            snr: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ---- Static Channels ----
// ponytail: 8-deep queues, sufficient for typical mesh traffic

/// Queue for packets to transmit over radio.
static TX_QUEUE: Channel<CriticalSectionRawMutex, TxPacket, 8> = Channel::new();

/// Queue for packets received from radio.
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, 8> = Channel::new();

// ---- Heap Allocator ----

#[global_allocator]
static ALLOCATOR: esp_alloc::EspHeap = esp_alloc::EspHeap::empty();

fn init_heap() {
    const HEAP_SIZE: usize = 32 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe {
        ALLOCATOR.init(HEAP.as_mut_ptr(), HEAP_SIZE);
    }
}

// ---- Entry Point ----

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    // Initialize heap
    init_heap();

    // Initialize ESP32 peripherals
    let config = esp_hal::Config::default();
    let peripherals = esp_hal::init(config);

    // Initialize logging
    esp_println::logger::init_logger_from_env();

    // Initialize embassy time driver
    let timer0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_hal_embassy::init(timer0.timer0);

    info!("LICHEN bridge (ESP32) starting...");

    // ---- SPI for SX1262 ----
    // T-Beam v1.2 pins: SCK=5, MISO=19, MOSI=27, NSS=18

    let spi_config = SpiConfig::default()
        .with_frequency(Rate::from_mhz(8))
        .with_mode(SpiMode::_0);

    let spi = match Spi::new(peripherals.SPI2, spi_config) {
        Ok(s) => s,
        Err(e) => {
            error!("SPI init failed: {:?}", e);
            loop {
                info!("halted - SPI init failed");
                Timer::after_secs(5).await;
            }
        }
    }
    .with_sck(peripherals.GPIO5)
    .with_miso(peripherals.GPIO19)
    .with_mosi(peripherals.GPIO27)
    .into_async();

    let nss = Output::new(peripherals.GPIO18, Level::High);
    let reset = Output::new(peripherals.GPIO23, Level::High);
    let busy = Input::new(peripherals.GPIO32, Pull::None);
    let dio1 = Input::new(peripherals.GPIO33, Pull::None);

    info!("SPI configured for SX1262");

    // Spawn radio task with SPI and control pins
    if let Err(e) = spawner.spawn(radio_task(spi, nss, reset, busy, dio1)) {
        error!("Failed to spawn radio task: {:?}", e);
    } else {
        info!("Radio task spawned");
    }

    // Main loop - placeholder for USB/UART bridge
    loop {
        Timer::after_secs(10).await;
        info!("heartbeat");
    }
}

// ---- Radio Task ----

/// Radio task: handles TX queue and RX polling.
#[embassy_executor::task]
async fn radio_task(
    mut spi: Spi<'static, Async>,
    mut nss: Output<'static>,
    mut reset: Output<'static>,
    busy: Input<'static>,
    _dio1: Input<'static>,
) {
    info!("radio_task: starting SX1262 init");

    // Reset sequence
    reset.set_low();
    Timer::after_millis(10).await;
    reset.set_high();
    Timer::after_millis(20).await;

    // Wait for BUSY to go low
    for _ in 0..100 {
        if busy.is_low() {
            break;
        }
        Timer::after_millis(1).await;
    }

    if busy.is_high() {
        error!("SX1262 BUSY timeout - check wiring");
        return;
    }

    // Read status (GetStatus command = 0xC0)
    let tx_buf = [0xC0, 0x00];
    let mut rx_buf = [0u8; 2];
    nss.set_low();
    let _ = embedded_hal_async::spi::SpiBus::transfer(&mut spi, &mut rx_buf, &tx_buf).await;
    nss.set_high();

    let status = rx_buf[1];
    info!("SX1262 status: 0x{:02x}", status);

    // Check chip mode bits [6:4] - should be STDBY_RC (0x2) or STDBY_XOSC (0x3)
    let mode = (status >> 4) & 0x07;
    if mode == 0x02 || mode == 0x03 {
        info!("SX1262 initialized OK (mode={})", mode);
    } else {
        error!("SX1262 unexpected mode: {} - check radio module", mode);
    }

    // Main radio loop
    let tx_receiver = TX_QUEUE.receiver();
    let _rx_sender = RX_QUEUE.sender();

    loop {
        // Wait for TX packet or poll timeout
        match select(tx_receiver.receive(), Timer::after_millis(100)).await {
            Either::First(pkt) => {
                info!("radio TX {} bytes", pkt.len);
                // TODO: actual SX1262 transmit
                Timer::after_millis(50).await; // Simulate TX time
            }
            Either::Second(_) => {
                // RX poll timeout - check for received packet
                // TODO: check SX1262 RX buffer via DIO1 or polling
            }
        }
    }
}

// ---- Public API ----

/// Queue a packet for radio transmission.
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
#[allow(dead_code)]
pub fn try_radio_rx() -> Option<RxPacket> {
    RX_QUEUE.try_receive().ok()
}
