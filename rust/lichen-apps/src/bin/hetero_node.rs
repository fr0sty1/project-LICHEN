// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Heterogeneous mesh node for cross-implementation testing.
//!
//! Connects to lichen-sim and participates in the mesh alongside Python and
//! Zephyr nodes. Used by ec2-hetero-fleet.sh for interop validation.
//!
//! Usage:
//!   hetero-node <node_id> <sim_host> <sim_port> <x_position> <duration_s>

use std::env;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("Usage: hetero-node <node_id> <sim_host> <sim_port> <x_pos> <duration_s>");
        std::process::exit(1);
    }

    let node_id: u32 = args[1].parse().expect("invalid node_id");
    let host = &args[2];
    let port: u16 = args[3].parse().expect("invalid port");
    let x_pos: f64 = args[4].parse().expect("invalid x_pos");
    let duration_s: u64 = args[5].parse().expect("invalid duration");

    eprintln!("rust-{}: connecting to {}:{} at x={}", node_id, host, port, x_pos);

    // Connect to lichen-sim
    let mut radio = match lichen_embassy::sim::SimRadio::connect(host, port) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rust-{}: connect failed: {:?}", node_id, e);
            std::process::exit(1);
        }
    };

    // Create deterministic identity from node_id
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = (node_id & 0xFF) as u8;
    seed_bytes[1] = ((node_id >> 8) & 0xFF) as u8;
    seed_bytes[2] = ((node_id >> 16) & 0xFF) as u8;
    seed_bytes[3] = ((node_id >> 24) & 0xFF) as u8;

    let seed: lichen_link::keys::Seed = seed_bytes.into();
    let identity = lichen_link::identity::Identity::from_seed(seed);
    let iid_hex: String = identity.iid.iter().map(|b| format!("{:02x}", b)).collect();
    eprintln!("rust-{}: IID={}", node_id, iid_hex);

    let start = Instant::now();
    let mut tx_count = 0u32;
    let mut rx_count = 0u32;
    let mut seq_num = 0u16;
    let mut buf = [0u8; 256];

    // Main loop
    while start.elapsed() < Duration::from_secs(duration_s) {
        // Build announce-like message
        // Format: [0x15 dispatch][type=0x01][seq:2][hop:1][iid:8][signature:48]
        let mut announce = Vec::with_capacity(64);
        announce.push(0x15); // routing dispatch
        announce.push(0x01); // announce type
        announce.extend_from_slice(&seq_num.to_be_bytes());
        announce.push(0x00); // hop count
        announce.extend_from_slice(&identity.iid);

        // Simplified signature (real impl would sign properly)
        announce.extend_from_slice(&[0u8; 48]);

        // Transmit
        match futures::executor::block_on(lichen_hal::Radio::transmit(&mut radio, &announce)) {
            Ok(()) => {
                tx_count += 1;
                seq_num = seq_num.wrapping_add(1);
            }
            Err(e) => {
                eprintln!("rust-{}: TX error: {:?}", node_id, e);
            }
        }

        // Receive window
        for _ in 0..5 {
            match futures::executor::block_on(lichen_hal::Radio::receive(&mut radio, &mut buf, 1000))
            {
                Ok(Some(pkt)) => {
                    rx_count += 1;
                    // Check if it's from a different implementation
                    if pkt.len > 0 {
                        let dispatch = buf[0];
                        let source = if dispatch == 0x15 { "announce" } else { "other" };
                        eprintln!(
                            "rust-{}: RX {} bytes, dispatch={:#x} ({})",
                            node_id, pkt.len, dispatch, source
                        );
                    }
                }
                Ok(None) => {} // timeout
                Err(e) => {
                    eprintln!("rust-{}: RX error: {:?}", node_id, e);
                }
            }
        }

        // Announce interval ~10s with jitter
        std::thread::sleep(Duration::from_millis(8000 + (node_id as u64 % 4000)));
    }

    // Final stats
    println!("rust-{}: TX={} RX={}", node_id, tx_count, rx_count);
}
