//! lichend — LICHEN border router daemon.
//!
//! Bridges the LoRa mesh (SLIP over serial, TCP simulator, or SX1302/RAK2287 HAT) to the Linux
//! IPv6 stack via a TUN device. Acts as RPL DODAG root in Non-Storing Mode.
//!
//! Usage:
//!   lichend --config /etc/lichen/gateway.toml
//!   lichend --sim                          # TCP simulator, TUN device
//!   lichend --sim --no-tun                 # TCP simulator, logging only (CI)
//!   lichend --hat rak2287                  # RAK2287 HAT with Sx1302Concentrator

use clap::Parser;
use lichen_core::{
    addr::NodeId,
    ipv6::{field, IPV6_HEADER_LEN},
};
use lichen_gateway::{
    config::Config,
    slip::{SlipFramer, SLIP_TX_BUF_SIZE},
    Gateway, RplEvent,
};
use lichen_hal::storage::fs::FileStorage;
use lichen_hal::storage::{load_epoch, load_seed, save_epoch, save_seed};
use lichen_hal::{Concentrator, RadioConfig, Sx1302Concentrator};
use lichen_link::identity::Identity;
use lichen_link::keys::Seed;
use lichen_sim::SimClient;

use std::{path::PathBuf, sync::OnceLock, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    signal,
    sync::mpsc,
    time::{interval, sleep, Duration},
};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(target_os = "linux")]
use lichen_gateway::tun::TunDevice;

#[derive(Parser)]
#[command(name = "lichend", about = "LICHEN border router daemon")]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Connect to the simulator instead of a real serial port.
    #[arg(long)]
    sim: bool,

    /// Simulator address (used with --sim).
    #[arg(long, default_value = "127.0.0.1:4444")]
    sim_addr: String,

    /// Node identifier (8-byte hex EUI-64, e.g. `0200000000000001`).
    #[arg(long, default_value = "0200000000000001")]
    node_id: String,

    /// Simulation ID to join (used with --sim; must match a simulation
    /// already created on the Python server).
    #[arg(long, default_value = "lichen")]
    sim_id: String,

    /// Use RAK2287 HAT with Sx1302Concentrator for RX/TX instead of SLIP or sim.
    #[arg(long, value_name = "TYPE")]
    hat: Option<String>,

    /// Skip TUN device creation (logs packets instead of forwarding).
    /// Required when running without CAP_NET_ADMIN (e.g. CI).
    #[arg(long)]
    no_tun: bool,

    /// Log level filter (e.g. `info`, `debug`, `lichen_gateway=trace`).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,
}

static START_TIME: OnceLock<Instant> = OnceLock::new();

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

    let use_sim_mode = args.sim || config.mesh.interface == "sim";
    let hat = args.hat.clone().or_else(|| config.mesh.hat.clone());
    let use_hat = hat.is_some();
    let storage_path = if use_sim_mode && !use_hat {
        "/tmp/lichen"
    } else {
        "/var/lib/lichen"
    };
    let mut storage = match FileStorage::new(storage_path) {
        Ok(s) => s,
        Err(e) => {
            error!("storage init failed: {}", e);
            std::process::exit(1);
        }
    };
    let seed = match load_seed(&storage) {
        Some(s) => s,
        None => {
            let mut b = [0u8; 32];
            let mut f = match std::fs::File::open("/dev/urandom") {
                Ok(f) => f,
                Err(e) => {
                    error!("cannot open urandom: {}", e);
                    std::process::exit(1);
                }
            };
            let _ = std::io::Read::read_exact(&mut f, &mut b);
            let s = Seed::new(b);
            let _ = save_seed(&mut storage, &s);
            s
        }
    };
    let id = Identity::from_seed(seed);
    if id.iid != node_id.0 {
        error!("configured root IID does not match persisted identity; fail closed");
        std::process::exit(1);
    }
    let epoch = load_epoch(&storage).unwrap_or(128);
    let safe_epoch = if epoch < 128 {
        128
    } else {
        epoch.wrapping_add(1)
    };
    let _ = save_epoch(&mut storage, safe_epoch);

    let use_sim = use_sim_mode && !use_hat;
    let backend = if use_hat {
        hat.as_deref().unwrap_or("hat")
    } else if use_sim {
        args.sim_addr.as_str()
    } else {
        config.mesh.interface.as_str()
    };

    info!(
        backend,
        ?node_id,
        prefix = %config.ipv6.prefix,
        rpl_mode = %config.rpl.mode,
        ygg_peers = config.yggdrasil.peers.len(),
        auto_peer = ?config.yggdrasil.auto_peer,
        "lichend starting"
    );
    if config.rpl.mode != "non-storing" || config.rpl.instance_id != 1 {
        error!("unsupported RPL instance/MOP");
        std::process::exit(1);
    }

    // Open TUN device unless --no-tun or non-Linux.
    #[cfg(target_os = "linux")]
    let tun = if args.no_tun {
        warn!("--no-tun: TUN device skipped; packets will be logged only");
        None
    } else {
        match TunDevice::open("lichen0") {
            Ok(dev) => {
                if let Err(e) = lichen_gateway::tun::configure("lichen0", &config.ipv6.prefix) {
                    error!("TUN configure: {e} (try running as root or with CAP_NET_ADMIN)");
                    std::process::exit(1);
                }
                Some(dev)
            }
            Err(e) => {
                error!("TUN open: {e} (try running as root or with CAP_NET_ADMIN)");
                std::process::exit(1);
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let tun: Option<()> = {
        if !args.no_tun {
            warn!("TUN is only supported on Linux; running in --no-tun mode");
        }
        None
    };

    let mut gw = Gateway::new(node_id);

    if use_hat {
        run_hat(&mut gw, tun).await;
    } else if use_sim {
        run_sim(&mut gw, &args.sim_addr, &args.sim_id, &args.node_id, tun).await;
    } else {
        run_serial(&mut gw, &config.mesh.interface, config.mesh.baud, tun).await;
    }
}

// ── forwarding helpers ────────────────────────────────────────────────────────

/// Resolves to never — used in select! when TUN is absent.
async fn tun_recv_none(_buf: &mut [u8]) -> std::io::Result<usize> {
    std::future::pending().await
}

/// Resolves to never — used in select! when TUN is absent.
async fn tun_send_none(_buf: &[u8]) -> std::io::Result<()> {
    std::future::pending().await
}

// ── sim mode ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_sim(
    gw: &mut Gateway,
    addr: &str,
    sim_id: &str,
    node_id: &str,
    tun: Option<TunDevice>,
) {
    run_sim_inner(gw, addr, sim_id, node_id, tun).await
}

#[cfg(not(target_os = "linux"))]
async fn run_sim(gw: &mut Gateway, addr: &str, sim_id: &str, node_id: &str, _tun: Option<()>) {
    run_sim_inner(gw, addr, sim_id, node_id, None::<()>).await
}

/// Sim mode: connects to the Python simulator and exchanges SCHC frames.
///
/// The simulator protocol is strictly request→response: you cannot send a
/// TX and an RX concurrently. We handle this by running the SimClient in a
/// dedicated task with two channels:
///   tx_send  — gateway → sim task (frames to transmit)
///   rx_recv  — sim task → gateway (frames received from the sim)
///
/// The sim task loops: drain tx_send → receive(50 ms) → push to rx_recv.
/// The gateway task loops: select! on rx_recv, TUN recv, ctrl_c.
async fn run_sim_inner<T>(gw: &mut Gateway, addr: &str, sim_id: &str, node_id: &str, tun: Option<T>)
where
    T: TunLike,
{
    let sock_addr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("invalid sim address '{addr}': {e}");
            return;
        }
    };

    let mut sim = match SimClient::connect(sock_addr, sim_id, node_id, 0.0, 0.0, 0.0).await {
        Ok(s) => s,
        Err(e) => {
            error!("cannot connect to simulator at {addr}: {e}");
            return;
        }
    };
    info!(addr, sim_id, node_id, "connected to simulator");

    // Channels between the gateway task and the sim protocol task.
    let (tx_send, mut tx_recv) = mpsc::channel::<Vec<u8>>(8);
    let (rx_send, mut rx_recv) = mpsc::channel::<Vec<u8>>(8);

    // Sim protocol task: sequential TX-drain → RX(50 ms) loop.
    let sim_task = tokio::spawn(async move {
        loop {
            // Drain all pending TX frames before the next RX window.
            while let Ok(frame) = tx_recv.try_recv() {
                match sim.transmit(&frame).await {
                    Ok(airtime_us) => info!(airtime_us, "TX done"),
                    Err(e) => warn!("TX failed: {e}"),
                }
            }
            // Listen for an incoming frame with a short timeout.
            match sim.receive(50).await {
                Ok(Some((payload, rssi, snr))) => {
                    info!(len = payload.len(), rssi, snr, "RX frame");
                    if rx_send.send(payload).await.is_err() {
                        break; // gateway task dropped rx_recv → shutting down
                    }
                }
                Ok(None) => {} // RX_TIMEOUT — loop again
                Err(e) => {
                    error!("sim receive error: {e}");
                    break;
                }
            }
        }
        // Final drain of any pending TX frames on shutdown (prevents lost transmissions).
        while let Ok(frame) = tx_recv.try_recv() {
            match sim.transmit(&frame).await {
                Ok(airtime_us) => info!(airtime_us, "TX done (shutdown drain)"),
                Err(e) => warn!("shutdown TX failed: {e}"),
            }
        }
    });

    let mut tun_buf = vec![0u8; 1500];
    let mut maintenance = interval(Duration::from_millis(1000));

    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                gw.maintain(now_ms);
            }
            frame_opt = rx_recv.recv() => {
                match frame_opt {
                    Some(frame) => {
                        if let Some(reply) = forward_mesh_to_upstream(gw, &frame, &tun).await {
                            match tx_send.try_send(reply) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!("TX channel full, dropping reply packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    error!("sim task exited, cannot send reply packets");
                                    break;
                                }
                            }
                        }
                    }
                    None => {
                        error!("sim task exited, cannot receive inbound packets");
                        break;
                    }
                }
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                match result {
                    Ok(n) => {
                        if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]) {
                            match tx_send.try_send(schc) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!("TX channel full, dropping outbound packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    error!("sim task exited, cannot send outbound packets");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => { error!("TUN recv: {e}"); break; }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }

    // Graceful shutdown: drop senders so sim_task can drain TX and exit.
    drop(tx_send);
    drop(rx_recv);
    info!("waiting for sim_task to finish draining transmissions");
    tokio::select! {
        _ = &mut sim_task => {
            info!("sim_task completed");
        }
        _ = sleep(Duration::from_secs(5)) => {
            warn!("sim_task did not finish in time, aborting");
            sim_task.abort();
            let _ = sim_task.await;
        }
    }
}

// ── serial mode ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_serial(gw: &mut Gateway, interface: &str, baud: u32, tun: Option<TunDevice>) {
    run_serial_inner(gw, interface, baud, tun).await
}

#[cfg(not(target_os = "linux"))]
async fn run_serial(gw: &mut Gateway, interface: &str, baud: u32, _tun: Option<()>) {
    run_serial_inner(gw, interface, baud, None::<()>).await
}

async fn run_serial_inner<T>(gw: &mut Gateway, interface: &str, baud: u32, tun: Option<T>)
where
    T: TunLike,
{
    info!(interface, "opening serial port");
    let mut tty = match tokio_serial::SerialStream::open(&tokio_serial::new(interface, baud)) {
        Ok(p) => p,
        Err(e) => {
            error!("cannot open {interface}: {e}");
            return;
        }
    };

    let mut slip = SlipFramer::new();
    let mut rx_buf = vec![0u8; 1500];
    let mut tun_buf = vec![0u8; 1500];
    let mut tx_buf = vec![0u8; SLIP_TX_BUF_SIZE];
    let mut maintenance = interval(Duration::from_millis(1000));

    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                gw.maintain(now_ms);
            }
            result = tty.read(&mut rx_buf) => {
                match result {
                    Ok(0) => { info!("serial port closed"); break; }
                    Ok(n) => {
                        let packets: Vec<_> = slip.feed(&rx_buf[..n]).collect();
                        for packet in packets {
                            if let Some(to_tx) = forward_mesh_to_upstream(gw, &packet, &tun).await {
                                if let Err(e) = slip.queue_send(&to_tx) {
                                    warn!("SLIP queue full, dropping reply packet: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => { error!("serial read: {e}"); break; }
                }
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                match result {
                    Ok(n) => {
                        if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]) {
                            if let Err(e) = slip.queue_send(&schc) {
                                warn!("SLIP queue full, dropping packet: {e}");
                            }
                        }
                    }
                    Err(e) => { error!("TUN recv: {e}"); break; }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }

        while let Ok(Some(n)) = slip.try_get_tx(&mut tx_buf) {
            if let Err(e) = tty.write_all(&tx_buf[..n]).await {
                error!("serial write: {e}");
                return;
            }
        }
    }
}

async fn forward_mesh_to_upstream<T: TunLike>(
    gw: &mut Gateway,
    frame: &[u8],
    tun: &Option<T>,
) -> Option<Vec<u8>> {
    let now_ms = {
        let start = START_TIME.get_or_init(Instant::now);
        start.elapsed().as_millis() as u64
    };
    let (reply_opt, event) = gw.process_rpl(frame, now_ms);
    if let RplEvent::DaoReceived {
        route_updated: true,
    } = event
    {
        info!("DAO event: route updated");
    }
    if let Some(reply) = reply_opt {
        info!(len = reply.len(), "mesh reply ready for SLIP TX queue");
        Some(reply)
    } else if let Some(ipv6) = gw.mesh_to_upstream(frame) {
        let mut dst = [0u8; 16];
        if ipv6.len() >= IPV6_HEADER_LEN {
            dst.copy_from_slice(&ipv6[field::DST_OFFSET..field::DST_OFFSET + 16]);
            if gw.is_local_mesh(&dst) {
                return gw.mesh_to_mesh(&ipv6);
            }
        }
        if let Some(t) = tun {
            if let Err(e) = t.send_pkt(&ipv6).await {
                error!("TUN write: {e}");
            }
        }
        None
    } else {
        None
    }
}
// ── TunLike trait (abstracts TunDevice vs. no-op placeholder) ─────────────────

trait TunLike {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a;
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a;
}

#[cfg(target_os = "linux")]
impl TunLike for TunDevice {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a {
        self.recv(buf)
    }
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a {
        self.send(buf)
    }
}

// Placeholder for non-Linux builds (never instantiated).
impl TunLike for () {
    fn recv_pkt<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a {
        tun_recv_none(buf)
    }
    fn send_pkt<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = std::io::Result<()>> + 'a {
        tun_send_none(buf)
    }
}

async fn run_hat_inner<T>(gw: &mut Gateway, tun: Option<T>)
where
    T: TunLike,
{
    info!("initializing Sx1302Concentrator");
    let mut conc = Sx1302Concentrator;
    let _ = conc.reset().await;
    let _ = conc.configure(&RadioConfig::default()).await;
    let mut tun_buf = vec![0u8; 1500];
    let mut maintenance = interval(Duration::from_millis(1000));
    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                gw.maintain(now_ms);
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                if let Ok(n) = result {
                    if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]) {
                        info!(len = schc.len(), "hat TX");
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_hat(gw: &mut Gateway, tun: Option<TunDevice>) {
    run_hat_inner(gw, tun).await
}

#[cfg(not(target_os = "linux"))]
async fn run_hat(gw: &mut Gateway, _tun: Option<()>) {
    run_hat_inner(gw, None::<()>).await
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_node_id(hex: &str) -> Result<NodeId, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
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
