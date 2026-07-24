//! LICHEN LoRa Bridge - Rust/Embassy version
//! Minimal "hello world" that initializes USB serial and SX1262 radio.

#![no_std]
#![no_main]

use defmt::{info, error, warn};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_nrf::gpio::{Level, Output, OutputDrive, Input, Pull};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::usb::Driver;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{bind_interrupts, pac, peripherals, usb};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use {defmt_rtt as _, panic_probe as _};

// ─── Radio Queue Types ───────────────────────────────────────────────────────

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
        Self { data: [0; 256], len: 0, rssi: 0, snr: 0 }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ─── Static Channels ─────────────────────────────────────────────────────────
// ponytail: 8-deep queues, sufficient for typical mesh traffic

/// Queue for packets to transmit over radio.
static TX_QUEUE: Channel<CriticalSectionRawMutex, TxPacket, 8> = Channel::new();

/// Queue for packets received from radio.
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, 8> = Channel::new();

bind_interrupts!(struct Irqs {
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
    SPIM3 => embassy_nrf::spim::InterruptHandler<peripherals::SPI3>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    info!("LICHEN bridge (Rust) starting...");

    // Spawn radio task
    if let Err(e) = spawner.spawn(radio_task()) {
        error!("Failed to spawn radio_task: {}", defmt::Debug2Format(&e));
        // Continue without radio - USB echo still works
    }

    // LED for status (Arduino pin 35 = P1.03)
    let mut led = Output::new(p.P1_03, Level::High, OutputDrive::Standard);

    // Enable high-frequency clock (required for USB)
    info!("Enabling HFCLK...");
    pac::CLOCK.tasks_hfclkstart().write_value(1);
    while pac::CLOCK.events_hfclkstarted().read() != 1 {}

    // ─── SPI for SX1262 ───
    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M8;

    let mut spi = Spim::new(
        p.SPI3,
        Irqs,
        p.P1_11,  // SCK
        p.P1_13,  // MISO
        p.P1_12,  // MOSI
        spi_config,
    );

    let mut nss = Output::new(p.P1_10, Level::High, OutputDrive::Standard);
    let mut reset = Output::new(p.P1_06, Level::High, OutputDrive::Standard);
    let busy = Input::new(p.P1_14, Pull::None);
    let _dio1 = Input::new(p.P1_15, Pull::None);

    info!("SPI configured for SX1262");

    // ─── Radio Init ───
    // ponytail: skip full lora-phy init, just probe the chip

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
        error!("SX1262 BUSY timeout");
    }

    // Read status (GetStatus command = 0xC0)
    let tx = [0xC0, 0x00];
    let mut rx = [0u8; 2];
    nss.set_low();
    let _ = spi.transfer(&mut rx, &tx).await;
    nss.set_high();

    let status = rx[1];
    info!("SX1262 status: 0x{:02x}", status);

    // Check chip mode bits [6:4] - should be STDBY_RC (0x2) or STDBY_XOSC (0x3)
    let mode = (status >> 4) & 0x07;
    if mode == 0x02 || mode == 0x03 {
        info!("SX1262 initialized OK (mode={})", mode);
    } else {
        error!("SX1262 unexpected mode: {}", mode);
    }

    led.set_low();

    // ─── USB CDC Setup ───
    let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

    let mut config = Config::new(0x239a, 0x0029);  // Adafruit nRF52840
    config.manufacturer = Some("LICHEN");
    config.product = Some("LoRa Bridge");
    config.serial_number = Some("001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut msos_descriptor = [0; 256];
    let mut control_buf = [0; 64];
    let mut state = State::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buf,
    );

    let mut class = CdcAcmClass::new(&mut builder, &mut state, 64);
    let mut usb = builder.build();

    info!("USB ready");

    // ─── Run USB and echo loop concurrently ───
    let usb_fut = usb.run();

    let echo_fut = async {
        let mut buf = [0u8; 64];
        loop {
            class.wait_connection().await;
            info!("USB connected");

            loop {
                match class.read_packet(&mut buf).await {
                    Ok(n) if n > 0 => {
                        info!("USB rx {} bytes", n);
                        // Echo back with prefix
                        let _ = class.write_packet(b"# echo: ").await;
                        let _ = class.write_packet(&buf[..n]).await;
                        let _ = class.write_packet(b"\r\n").await;
                    }
                    Err(_) => {
                        info!("USB disconnected");
                        break;
                    }
                    _ => {}
                }
            }
        }
    };

    join(usb_fut, echo_fut).await;
}

// ─── Radio Task ──────────────────────────────────────────────────────────────

/// Radio task: handles TX queue and RX polling.
///
/// This is a placeholder for the full radio driver. Currently just demonstrates
/// the queue-based architecture.
#[embassy_executor::task]
async fn radio_task() {
    info!("radio_task started");

    // ponytail: placeholder until full SX1262 driver is integrated
    // Real implementation would:
    // 1. Configure SX1262 for LoRa mode
    // 2. Use DIO1 interrupt for RX done
    // 3. Handle TX/RX state machine

    let tx_receiver = TX_QUEUE.receiver();
    let _rx_sender = RX_QUEUE.sender(); // ponytail: used when full SX1262 driver integrated

    loop {
        // Wait for TX packet or RX timeout
        match select(tx_receiver.receive(), Timer::after_millis(100)).await {
            Either::First(pkt) => {
                // TX packet available
                info!("radio TX {} bytes", pkt.len);
                // TODO: actual SX1262 transmit
                Timer::after_millis(50).await; // Simulate TX time
            }
            Either::Second(_) => {
                // RX poll timeout - check for received packet
                // TODO: check SX1262 RX buffer via DIO1 or polling
                // For now, just continue loop
            }
        }
    }
}

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
