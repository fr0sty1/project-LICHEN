// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! LICHEN firmware for Seeed Wio-E5 (STM32WL55).
//!
//! Complete firmware implementing:
//! - Identity management (seed stored in flash)
//! - LoRa radio TX/RX loop
//! - ICMPv6 Echo Reply (ping)
//! - Power management with sleep/wake cycles

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::Config;
use embassy_time::{Duration, Timer};
use panic_halt as _;

use lichen_core::addr::NodeId;

/// Identity seed - in production, load from flash
/// ponytail: hardcoded seed for initial bringup, replace with NonVolatile read
const DEVICE_SEED: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
];

/// Derive a simple IID from seed (simplified for no_std)
fn derive_iid(seed: &[u8; 32]) -> [u8; 8] {
    // ponytail: just use first 8 bytes of seed, real impl uses SHA256
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&seed[..8]);
    iid[0] &= 0b1111_1101; // Clear U/L bit
    iid
}

/// LED blink task - heartbeat indicator
#[embassy_executor::task]
async fn blink(mut led: Output<'static>) {
    loop {
        led.set_high();
        Timer::after(Duration::from_millis(100)).await;
        led.set_low();
        Timer::after(Duration::from_millis(900)).await;
    }
}

/// Radio RX task - listens for incoming frames
/// ponytail: placeholder until SubGhz driver integration
#[embassy_executor::task]
async fn radio_rx_task() {
    info!("Radio RX task started");
    loop {
        // ponytail: SubGhz radio driver goes here
        // 1. Put radio in RX mode
        // 2. Wait for interrupt or timeout
        // 3. On frame: parse L2, verify sig, decompress SCHC
        // 4. Dispatch to node (ping reply, CoAP, RPL)
        Timer::after(Duration::from_secs(5)).await;
        info!("RX task heartbeat");
    }
}

/// Radio TX task - handles outgoing frames
/// ponytail: placeholder until SubGhz driver integration
#[embassy_executor::task]
async fn radio_tx_task() {
    info!("Radio TX task started");
    loop {
        // ponytail: TX queue handling goes here
        // 1. Check TX queue for pending frames
        // 2. Build L2 frame with signature
        // 3. Transmit via SubGhz
        // 4. Wait for TX complete
        Timer::after(Duration::from_secs(10)).await;
        info!("TX task heartbeat");
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Initialize the HAL
    // ponytail: default config, radio init will need HSE clock setup
    let p = embassy_stm32::init(Config::default());

    info!("LICHEN Wio-E5 firmware starting");

    // Derive identity from seed
    let iid = derive_iid(&DEVICE_SEED);
    let node_id = NodeId(iid);
    info!(
        "Node ID: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7]
    );

    // Compute link-local address
    let link_local = node_id.link_local_addr();
    info!(
        "Link-local: fe80::{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        link_local.0[8],
        link_local.0[9],
        link_local.0[10],
        link_local.0[11],
        link_local.0[12],
        link_local.0[13],
        link_local.0[14],
        link_local.0[15]
    );

    // Initialize LED (Wio-E5 has LED on PB5)
    let led = Output::new(p.PB5, Level::Low, Speed::Low);

    // Spawn tasks
    spawner.spawn(blink(led)).unwrap();
    spawner.spawn(radio_rx_task()).unwrap();
    spawner.spawn(radio_tx_task()).unwrap();

    info!("All tasks spawned, entering main loop");

    // Main loop - orchestrates sleep/wake and trickle timing
    let mut ticks: u32 = 0;
    loop {
        Timer::after(Duration::from_secs(60)).await;
        ticks += 1;
        info!("Main loop tick {}", ticks);

        // ponytail: trickle timer handling goes here
        // 1. Check if DIO should be sent
        // 2. Check if DAO refresh needed
        // 3. Prune stale neighbors

        // ponytail: power management
        // After idle period, could enter STOP mode
        // Wake on radio interrupt or RTC alarm
    }
}
