// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Heterogeneous mesh node for cross-implementation testing.
//!
//! Connects to lichen-sim and participates in the mesh alongside Python and
//! Zephyr nodes. Used by ec2-hetero-fleet.sh for interop validation.
//!
//! Usage:
//!   hetero-node <node_id> <sim_host> <sim_port> <x_position> <duration_s>

use std::collections::HashSet;
use std::env;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Metrics collected during node operation.
struct NodeMetrics {
    tx_count: u32,
    rx_count: u32,
    tx_bytes: u64,
    rx_bytes: u64,
    unique_peers: HashSet<[u8; 8]>,
    errors: Vec<String>,
    packet_hashes_sent: HashSet<[u8; 16]>,
    packet_hashes_received: HashSet<[u8; 16]>,
}

impl NodeMetrics {
    fn new() -> Self {
        Self {
            tx_count: 0,
            rx_count: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            unique_peers: HashSet::new(),
            errors: Vec::new(),
            packet_hashes_sent: HashSet::new(),
            packet_hashes_received: HashSet::new(),
        }
    }
}

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

    eprintln!(
        "rust-{}: connecting to {}:{} at x={}",
        node_id, host, port, x_pos
    );

    // Connect to lichen-sim
    let node_name = format!("rust-{}", node_id);
    let mut radio = match lichen_embassy::sim::SimRadio::connect_registered(
        host,
        port,
        "hetero-mesh",
        &node_name,
        (x_pos, 0.0, 0.0),
    ) {
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
    let mut metrics = NodeMetrics::new();
    let mut seq_num = 0u16;
    let mut buf = [0u8; 256];

    let emit = |event: &str,
                payload: &[u8],
                status: &str,
                ts_us: u128,
                seq: Option<u16>,
                peer_id: Option<String>,
                rssi: Option<i32>,
                snr: Option<i32>| {
        let hash = format!("{:x}", Sha256::digest(payload));
        println!(
            "TELEMETRY {}",
            serde_json::json!({
                "schema": "lichen.telemetry.v1",
                "event": event,
                "ts_us": ts_us,
                "node_id": format!("rust-{}", node_id),
                "impl": "rust",
                "tx_id": hash[..16].to_string(),
                "packet_hash": hash[..16].to_string(),
                "direction": if event.starts_with("tx") { "tx" } else { "rx" },
                "peer_id": peer_id,
                "payload_len": payload.len(),
                "rssi_dbm": rssi,
                "snr_db": snr,
                "seq": seq,
                "status": status,
            })
        );
    };

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
                metrics.tx_count += 1;
                metrics.tx_bytes += announce.len() as u64;
                let hash = Sha256::digest(&announce);
                let hash_prefix: [u8; 16] = hash[..16].try_into().unwrap();
                metrics.packet_hashes_sent.insert(hash_prefix);
                emit(
                    "tx",
                    &announce,
                    "ok",
                    start.elapsed().as_micros(),
                    Some(seq_num),
                    None,
                    None,
                    None,
                );
                seq_num = seq_num.wrapping_add(1);
            }
            Err(e) => {
                if metrics.errors.len() < 1000 {
                    metrics.errors.push(format!("TX error: {:?}", e));
                }
                eprintln!("rust-{}: TX error: {:?}", node_id, e);
            }
        }

        // Receive window
        for _ in 0..5 {
            match futures::executor::block_on(lichen_hal::Radio::receive(
                &mut radio, &mut buf, 1000,
            )) {
                Ok(Some(pkt)) => {
                    metrics.rx_count += 1;
                    metrics.rx_bytes += pkt.len as u64;

                    // Track packet hash
                    let hash = Sha256::digest(&buf[..pkt.len]);
                    let hash_prefix: [u8; 16] = hash[..16].try_into().unwrap();
                    metrics.packet_hashes_received.insert(hash_prefix);
                    let peer_id = if pkt.len > 12 && buf[0] == 0x15 && buf[1] == 0x01 {
                        Some(buf[5..13].iter().map(|b| format!("{b:02x}")).collect())
                    } else {
                        None
                    };
                    emit(
                        "rx",
                        &buf[..pkt.len],
                        "ok",
                        start.elapsed().as_micros(),
                        None,
                        peer_id,
                        None,
                        None,
                    );

                    // Check if it's from a different implementation
                    if pkt.len > 0 {
                        let dispatch = buf[0];
                        let source = if dispatch == 0x15 {
                            "announce"
                        } else {
                            "other"
                        };
                        eprintln!(
                            "rust-{}: RX {} bytes, dispatch={:#x} ({})",
                            node_id, pkt.len, dispatch, source
                        );

                        // Parse announce to extract peer IID
                        // Format: [0x15 dispatch][type=0x01][seq:2][hop:1][iid:8]...
                        if pkt.len > 10 && buf[0] == 0x15 && buf[1] == 0x01 {
                            let peer_iid: [u8; 8] = buf[5..13].try_into().unwrap();
                            if peer_iid != identity.iid {
                                metrics.unique_peers.insert(peer_iid);
                                eprintln!("rust-{}: announce from peer {:02x?}", node_id, peer_iid);
                            }
                        }
                    }
                }
                Ok(None) => {} // timeout
                Err(e) => {
                    if metrics.errors.len() < 1000 {
                        metrics.errors.push(format!("RX error: {:?}", e));
                    }
                    eprintln!("rust-{}: RX error: {:?}", node_id, e);
                }
            }
        }

        // Announce interval ~10s with jitter
        std::thread::sleep(Duration::from_millis(8000 + (node_id as u64 % 4000)));
    }

    // Final stats (legacy format for compatibility)
    println!(
        "rust-{}: TX={} RX={}",
        node_id, metrics.tx_count, metrics.rx_count
    );

    // Export metrics as JSON
    let metrics_json = serde_json::json!({
        "node_id": node_id,
        "tx_count": metrics.tx_count,
        "rx_count": metrics.rx_count,
        "tx_bytes": metrics.tx_bytes,
        "rx_bytes": metrics.rx_bytes,
        "unique_peers": metrics.unique_peers.len(),
        "errors": metrics.errors.len(),
        "packet_hashes_sent": metrics.packet_hashes_sent.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
        "packet_hashes_received": metrics.packet_hashes_received.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
    });
    println!("METRICS:{}", serde_json::to_string(&metrics_json).unwrap());
}
