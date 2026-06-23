//! lichend — LICHEN border router daemon.
//!
//! Usage:
//!   lichend [OPTIONS]
//!   lichend --config /etc/lichen/gateway.toml
//!   lichend --sim               # use TCP simulator instead of real serial

use clap::Parser;
use lichen_core::addr::NodeId;
use lichen_gateway::{config::Config, slip, Gateway};
use std::path::PathBuf;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    signal,
};
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "lichend", about = "LICHEN border router daemon")]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Connect to the simulator instead of a real serial port.
    /// Overrides mesh.interface in the config file.
    #[arg(long)]
    sim: bool,

    /// Simulator address (used with --sim).
    #[arg(long, default_value = "127.0.0.1:4444")]
    sim_addr: String,

    /// Node identifier (8-byte hex EUI-64, e.g. `0200000000000001`).
    #[arg(long, default_value = "0200000000000001")]
    node_id: String,

    /// Log level filter (e.g. `info`, `debug`, `lichen_gateway=trace`).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    fmt().with_env_filter(EnvFilter::new(&args.log)).init();

    let config = if let Some(path) = &args.config {
        match Config::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                error!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        Config::default_sim()
    };

    let node_id = parse_node_id(&args.node_id).unwrap_or_else(|e| {
        error!("invalid --node-id: {e}");
        std::process::exit(1);
    });

    let use_sim = args.sim || config.mesh.interface == "sim";

    info!(
        interface = if use_sim { &args.sim_addr } else { &config.mesh.interface },
        node_id = ?node_id,
        prefix = %config.ipv6.prefix,
        rpl_mode = %config.rpl.mode,
        "lichend starting"
    );

    let mut gw = Gateway::new(node_id);

    if use_sim {
        run_sim(&mut gw, &args.sim_addr).await;
    } else {
        run_serial(&mut gw, &config.mesh.interface, config.mesh.baud).await;
    }
}

/// Run the daemon connected to the lichen-sim TCP server.
async fn run_sim(gw: &mut Gateway, addr: &str) {
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("cannot connect to simulator at {addr}: {e}");
            return;
        }
    };
    info!("connected to simulator at {addr}");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            result = slip::recv_packet(&mut reader, &mut buf) => {
                match result {
                    Ok(n) => gw.handle_mesh_packet(&buf[..n]),
                    Err(e) => {
                        error!("SLIP receive error: {e}");
                        break;
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

/// Run the daemon connected to a real serial port (SLIP over USB CDC-ACM).
async fn run_serial(gw: &mut Gateway, interface: &str, _baud: u32) {
    // tokio-serial requires a blocking port; bridge via spawn_blocking or
    // use tokio-serial's AsyncSerial. For now, stub with a clear error.
    info!(interface, "opening serial port");
    let mut tty = match tokio_serial::SerialStream::open(
        &tokio_serial::new(interface, _baud),
    ) {
        Ok(p) => p,
        Err(e) => {
            error!("cannot open {interface}: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            result = slip::recv_packet(&mut tty, &mut buf) => {
                match result {
                    Ok(n) => gw.handle_mesh_packet(&buf[..n]),
                    Err(e) => {
                        error!("SLIP receive error: {e}");
                        break;
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }
    let _ = gw; // suppress unused warning in stub
}

fn parse_node_id(hex: &str) -> Result<NodeId, String> {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<u8>, _>>()?;
    if bytes.len() != 8 {
        return Err(format!("expected 8 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(NodeId(arr))
}
