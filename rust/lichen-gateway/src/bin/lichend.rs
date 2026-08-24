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
    tx_queue::{
        TxPriority, TxQueue, TxQueueError, DEADLINE_NORMAL_MS, DEADLINE_ROUTING_MS, DEADLINE_SOS_MS,
    },
};
use lichen_gateway::{
    config::{Config, GatewayCoordinationConfig, GatewayFederationMode, SecretString},
    resources::GatewayCoordinator,
    slip::{SlipFramer, SLIP_TX_BUF_SIZE},
    trust::{PskFederation, TrustStore, DEFAULT_MAX_TRUSTED_GATEWAYS},
    Gateway, GatewayPersistence,
};
use lichen_hal::storage::fs::FileStorage;
use lichen_hal::storage::{keys, load_epoch, save_epoch};
use lichen_hal::{Concentrator, RadioConfig, Sx1302Concentrator};
use lichen_link::identity::Identity;
use lichen_link::keys::Seed;
use lichen_node::RplEvent;
use lichen_sim::SimClient;

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    signal,
    time::{interval, sleep, Duration, MissedTickBehavior},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

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

    /// Node identifier (8-byte hex EUI-64). When omitted, use the IID derived
    /// from the persisted/generated identity key.
    #[arg(long)]
    node_id: Option<String>,

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
async fn main() -> ExitCode {
    let args = Args::parse();
    fmt().with_env_filter(EnvFilter::new(&args.log)).init();

    let mut config = if let Some(path) = &args.config {
        match Config::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                error!("{e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Config::default_sim()
    };

    let use_sim_mode = args.sim || config.mesh.interface == "sim";
    let hat = args.hat.clone().or_else(|| config.mesh.hat.clone());
    let use_hat = hat.is_some();
    let (state_root, _ephemeral_state) = if use_sim_mode && !use_hat {
        match create_ephemeral_state_root() {
            Ok((path, guard)) => (path, Some(guard)),
            Err(e) => {
                error!("secure simulator state initialization failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let path = PathBuf::from("/var/lib/lichen");
        if let Err(e) = ensure_private_state_root(&path) {
            error!("secure state directory rejected: {e}");
            return ExitCode::FAILURE;
        }
        (path, None)
    };
    let (rollback_floor_root, _ephemeral_floor_state) = if use_sim_mode && !use_hat {
        match create_ephemeral_state_root() {
            Ok((path, guard)) => (path, Some(guard)),
            Err(e) => {
                error!("secure simulator rollback-floor initialization failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let Some(path) = config.security.rollback_floor_root.clone() else {
            error!("persistent gateways require security.rollback_floor_root");
            return ExitCode::FAILURE;
        };
        if let Err(e) = ensure_private_state_root(&path) {
            error!("rollback-floor directory rejected: {e}");
            return ExitCode::FAILURE;
        }
        if let Err(e) = verify_independent_rollback_root(&state_root, &path) {
            error!("rollback-floor authority is not independent: {e}");
            return ExitCode::FAILURE;
        }
        (path, None)
    };
    let mut storage = match FileStorage::new(&state_root) {
        Ok(s) => s,
        Err(e) => {
            error!("storage init failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let identity_path = state_root.join(keys::IDENTITY_SEED);
    let (seed, identity_created) = match load_private_seed(&identity_path) {
        Ok(Some(s)) => (s, false),
        Ok(None) => {
            let mut b = Zeroizing::new([0u8; 32]);
            let mut f = match std::fs::File::open("/dev/urandom") {
                Ok(f) => f,
                Err(e) => {
                    error!("cannot open urandom: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = std::io::Read::read_exact(&mut f, b.as_mut()) {
                error!("cannot read from urandom: {}", e);
                return ExitCode::FAILURE;
            }
            let s = Seed::new(*b);
            // SECURITY: Seed persistence is critical for identity stability. If we can't
            // persist the seed, the node will generate a different identity on restart,
            // breaking peer authentication and orphaning mesh routes. Fail closed.
            if let Err(e) = save_private_seed(&identity_path, &s) {
                error!(
                    "seed persistence failed: {}; aborting to prevent identity drift",
                    e
                );
                return ExitCode::FAILURE;
            }
            (s, true)
        }
        Err(e) => {
            error!(
                "seed storage read failed: {}; refusing to replace an unreadable identity",
                e
            );
            return ExitCode::FAILURE;
        }
    };
    let mut sealing_seed = Zeroizing::new(*seed.as_bytes());
    let id = Identity::from_seed(seed);
    let node_id = match resolve_node_id(args.node_id.as_deref(), id.iid) {
        Ok(node_id) => node_id,
        Err(error) => {
            error!("invalid --node-id: {error}");
            return ExitCode::FAILURE;
        }
    };
    let node_id_text = hex::encode(node_id.0);
    let persisted_epoch = match load_epoch(&storage) {
        Ok(epoch) => epoch,
        Err(e) => {
            error!(
                "epoch storage read failed: {}; refusing replay-state rollback",
                e
            );
            return ExitCode::FAILURE;
        }
    };
    let safe_epoch = match persisted_epoch {
        None | Some(0..=127) => 128,
        Some(128..=254) => persisted_epoch.expect("matched Some").saturating_add(1),
        Some(255) => {
            error!("link epoch exhausted at 255; rotate the gateway identity before restarting");
            return ExitCode::FAILURE;
        }
    };
    // SECURITY: Epoch persistence is critical for replay protection. If we can't
    // persist the incremented epoch, peers that saw frames with the higher epoch
    // will reject our frames as replays on restart. Fail closed.
    if let Err(e) = save_epoch(&mut storage, safe_epoch) {
        error!(
            "epoch persistence failed: {}; aborting to prevent replay vulnerability",
            e
        );
        return ExitCode::FAILURE;
    }

    let trust_path = state_root.join("gateway-trust.bin");
    let trust_floor_path = rollback_floor_root.join("gateway-trust.generation");
    let slot_path = state_root.join("gateway-slot-replay.bin");
    let slot_floor_path = rollback_floor_root.join("gateway-slot-replay.generation");
    let manifest_path = state_root.join("gateway-provisioning.manifest");
    let identity_pubkey = *id.pubkey.as_bytes();
    let artifact_presence = [
        trust_path.exists(),
        trust_floor_path.exists(),
        slot_path.exists(),
        slot_floor_path.exists(),
    ];
    let loaded_manifest = match load_provision_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            error!("provisioning manifest rejected: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut manifest = match loaded_manifest {
        Some(manifest) if manifest.identity_pubkey != identity_pubkey => {
            error!("provisioning manifest is bound to a different identity");
            return ExitCode::FAILURE;
        }
        Some(manifest) => Some(manifest),
        None if identity_created || artifact_presence.iter().all(|present| !present) => {
            if identity_created && artifact_presence.iter().any(|present| *present) {
                error!("new identity conflicts with pre-existing gateway security state");
                return ExitCode::FAILURE;
            }
            let manifest = ProvisionManifest {
                stage: PROVISION_STAGE_IDENTITY,
                identity_pubkey,
            };
            if let Err(error) = save_provision_manifest(&manifest_path, manifest) {
                error!("provisioning manifest persistence failed: {error}");
                return ExitCode::FAILURE;
            }
            Some(manifest)
        }
        None if artifact_presence.iter().all(|present| *present) => None,
        None => {
            error!("gateway security artifacts are partial without a provisioning manifest");
            return ExitCode::FAILURE;
        }
    };
    let provision_or_resume = manifest
        .as_ref()
        .is_some_and(|value| value.stage < PROVISION_STAGE_COMPLETE);

    let trust_store = if provision_or_resume {
        let stage = manifest.as_ref().expect("resume manifest").stage;
        let store_exists = trust_path.exists();
        let floor_exists = trust_floor_path.exists();
        if stage >= PROVISION_STAGE_TRUST && (!store_exists || !floor_exists) {
            error!("committed trust provisioning artifacts are missing");
            return ExitCode::FAILURE;
        }
        let trust = match (store_exists, floor_exists) {
            (false, false) => match TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS) {
                Ok(store) => store,
                Err(error) => {
                    error!("trust-store provisioning failed: {error}");
                    return ExitCode::FAILURE;
                }
            },
            (true, false) if stage < PROVISION_STAGE_TRUST => {
                match TrustStore::load(&trust_path, &sealing_seed, 0, DEFAULT_MAX_TRUSTED_GATEWAYS)
                {
                    Ok(store) => store,
                    Err(error) => {
                        error!("interrupted trust-store recovery failed: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            (false, true) if stage < PROVISION_STAGE_TRUST => {
                let floor = load_generation_floor(&trust_floor_path).unwrap_or(u64::MAX);
                let store = match TrustStore::new_ephemeral(DEFAULT_MAX_TRUSTED_GATEWAYS) {
                    Ok(store) => store,
                    Err(error) => {
                        error!("trust-store provisioning failed: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                if floor != store.generation() {
                    error!("orphan trust floor is not the initial generation");
                    return ExitCode::FAILURE;
                }
                store
            }
            (true, true) => {
                let floor = match load_generation_floor(&trust_floor_path) {
                    Ok(floor) => floor,
                    Err(error) => {
                        error!("trust generation load failed: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                match TrustStore::load(
                    &trust_path,
                    &sealing_seed,
                    floor,
                    DEFAULT_MAX_TRUSTED_GATEWAYS,
                ) {
                    Ok(store) => store,
                    Err(error) => {
                        error!("durable trust-store load failed: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            _ => unreachable!("partial trust state handled above"),
        };
        if !initial_resume_state_is_valid(
            stage,
            PROVISION_STAGE_TRUST,
            trust.generation(),
            trust.entries().next().is_none(),
        ) {
            error!("interrupted trust state is not the initial empty generation");
            return ExitCode::FAILURE;
        }
        if !store_exists {
            if let Err(error) = trust.save_atomic(&trust_path, &sealing_seed) {
                error!("trust-store persistence failed: {error}");
                return ExitCode::FAILURE;
            }
        }
        if !floor_exists {
            if let Err(error) = save_generation_floor(&trust_floor_path, trust.generation()) {
                error!("trust generation persistence failed: {error}");
                return ExitCode::FAILURE;
            }
        }
        let next = ProvisionManifest {
            stage: stage.max(PROVISION_STAGE_TRUST),
            identity_pubkey,
        };
        if let Err(error) = save_provision_manifest(&manifest_path, next) {
            error!("trust provisioning commit failed: {error}");
            return ExitCode::FAILURE;
        }
        manifest = Some(next);
        trust
    } else {
        let trust_floor = match load_generation_floor(&trust_floor_path) {
            Ok(floor) => floor,
            Err(error) => {
                error!("trust generation load failed: {error}");
                return ExitCode::FAILURE;
            }
        };
        match TrustStore::load(
            &trust_path,
            &sealing_seed,
            trust_floor,
            DEFAULT_MAX_TRUSTED_GATEWAYS,
        ) {
            Ok(store) => store,
            Err(error) => {
                error!("durable trust-store load failed: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

    let gateway_coordinator = if provision_or_resume {
        let stage = manifest.as_ref().expect("resume manifest").stage;
        let store_exists = slot_path.exists();
        let floor_exists = slot_floor_path.exists();
        if stage >= PROVISION_STAGE_SLOT && (!store_exists || !floor_exists) {
            error!("committed slot provisioning artifacts are missing");
            return ExitCode::FAILURE;
        }
        if store_exists && !floor_exists && stage < PROVISION_STAGE_SLOT {
            if let Err(error) = save_generation_floor(&slot_floor_path, 1) {
                error!("interrupted slot-floor recovery failed: {error}");
                return ExitCode::FAILURE;
            }
        } else if !store_exists && floor_exists && stage < PROVISION_STAGE_SLOT {
            match load_generation_floor(&slot_floor_path) {
                Ok(1) => {}
                Ok(_) => {
                    error!("orphan slot floor is not the initial generation");
                    return ExitCode::FAILURE;
                }
                Err(error) => {
                    error!("orphan slot floor rejected: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        let coordinator_result = if slot_path.exists() {
            GatewayCoordinator::load_persistent(
                lichen_core::addr::ygg_addr_from_pubkey(id.pubkey.as_bytes()),
                60,
                256,
                &slot_path,
                &slot_floor_path,
                &sealing_seed,
            )
        } else {
            GatewayCoordinator::provision_persistent(
                lichen_core::addr::ygg_addr_from_pubkey(id.pubkey.as_bytes()),
                60,
                256,
                &slot_path,
                &slot_floor_path,
                &sealing_seed,
            )
        };
        let coordinator = match coordinator_result {
            Ok(coordinator) => coordinator,
            Err(error) => {
                error!("slot replay provisioning/recovery failed: {error}");
                return ExitCode::FAILURE;
            }
        };
        if !initial_resume_state_is_valid(
            stage,
            PROVISION_STAGE_SLOT,
            coordinator.slot_replay_generation(),
            true,
        ) {
            error!("interrupted slot replay state is not the initial generation");
            return ExitCode::FAILURE;
        }
        let next = ProvisionManifest {
            stage: stage.max(PROVISION_STAGE_SLOT),
            identity_pubkey,
        };
        if let Err(error) = save_provision_manifest(&manifest_path, next) {
            error!("slot provisioning commit failed: {error}");
            return ExitCode::FAILURE;
        }
        manifest = Some(next);
        coordinator
    } else {
        match GatewayCoordinator::load_persistent(
            lichen_core::addr::ygg_addr_from_pubkey(id.pubkey.as_bytes()),
            60,
            256,
            &slot_path,
            &slot_floor_path,
            &sealing_seed,
        ) {
            Ok(coordinator) => coordinator,
            Err(error) => {
                error!("durable slot replay load failed: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

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
        return ExitCode::FAILURE;
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
                    return ExitCode::FAILURE;
                }
                Some(dev)
            }
            Err(e) => {
                error!("TUN open: {e} (try running as root or with CAP_NET_ADMIN)");
                return ExitCode::FAILURE;
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

    let persistence = GatewayPersistence::new(
        storage,
        provision_or_resume,
        state_root,
        rollback_floor_root,
        *sealing_seed,
    );
    sealing_seed.zeroize();
    let mut gw = match Gateway::new_persistent(
        id,
        safe_epoch,
        trust_store,
        gateway_coordinator,
        persistence,
    ) {
        Ok(gateway) => gateway,
        Err(e) => {
            error!("gateway initialization failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = configure_gateway_federation(&mut gw, &mut config.gateway_coordination) {
        error!("gateway federation provisioning failed: {error}");
        return ExitCode::FAILURE;
    }
    if provision_or_resume {
        let complete = ProvisionManifest {
            stage: PROVISION_STAGE_COMPLETE,
            identity_pubkey,
        };
        if let Err(error) = save_provision_manifest(&manifest_path, complete) {
            error!("gateway provisioning commit failed: {error}");
            return ExitCode::FAILURE;
        }
        manifest = Some(complete);
    }
    debug!(
        provisioning_stage = manifest.as_ref().map(|value| value.stage),
        "gateway provisioning state verified"
    );

    if use_hat {
        run_hat(&mut gw, tun).await;
    } else if use_sim {
        run_sim(&mut gw, &args.sim_addr, &args.sim_id, &node_id_text, tun).await;
    } else {
        run_serial(&mut gw, &config.mesh.interface, config.mesh.baud, tun).await;
    }
    ExitCode::SUCCESS
}

fn decode_secret_hex(
    value: &mut Option<SecretString>,
    field: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let encoded = value
        .take()
        .ok_or_else(|| format!("missing gateway_coordination.{field}"))?;
    hex::decode(encoded.expose())
        .map(Zeroizing::new)
        .map_err(|_| format!("gateway_coordination.{field} is not valid hexadecimal"))
}

fn decode_optional_secret_hex(
    value: &mut Option<SecretString>,
    field: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    if value.is_some() {
        decode_secret_hex(value, field).map(Some)
    } else {
        Ok(None)
    }
}

fn configure_gateway_federation(
    gateway: &mut Gateway,
    config: &mut GatewayCoordinationConfig,
) -> Result<(), String> {
    match config.mode {
        GatewayFederationMode::Disabled => {
            if config.psk_hex.is_some()
                || config.master_salt_hex.is_some()
                || config.id_context_hex.is_some()
                || !config.peer_public_keys.is_empty()
            {
                return Err("federation material supplied while mode is disabled".into());
            }
            Ok(())
        }
        GatewayFederationMode::Open => Err(
            "open federation requires explicit PoP plus OSCORE context enrollment; plaintext fallback is forbidden"
                .into(),
        ),
        GatewayFederationMode::Psk => {
            let psk = decode_secret_hex(&mut config.psk_hex, "psk_hex")?;
            let salt =
                decode_optional_secret_hex(&mut config.master_salt_hex, "master_salt_hex")?;
            let id_context =
                decode_optional_secret_hex(&mut config.id_context_hex, "id_context_hex")?;
            let mut peer_pubkeys = Vec::with_capacity(config.peer_public_keys.len());
            for encoded in &config.peer_public_keys {
                let decoded = hex::decode(encoded)
                    .map_err(|_| "peer_public_keys contains invalid hexadecimal".to_string())?;
                let pubkey: [u8; 32] = decoded
                    .try_into()
                    .map_err(|_| "peer_public_keys entries must be exactly 32 bytes".to_string())?;
                peer_pubkeys.push(pubkey);
            }
            let federation = PskFederation::new(
                &psk,
                salt.as_deref().map(Vec::as_slice),
                id_context.as_deref().map(Vec::as_slice),
            )
            .map_err(|error| error.to_string())?;
            gateway
                .provision_closed_federation(&federation, &peer_pubkeys)
                .map_err(|error| error.to_string())?;
            Ok(())
        }
    }
}

/// Push a packet into a synchronous (non-shared) TX queue with appropriate priority and deadline.
fn push_tx_queue_sync(tx_queue: &mut TxQueue, priority: TxPriority, data: &[u8], now_ms: u64) {
    let deadline = match priority {
        TxPriority::Sos => now_ms + DEADLINE_SOS_MS,
        TxPriority::Routing => now_ms + DEADLINE_ROUTING_MS,
        TxPriority::Urgent | TxPriority::Normal | TxPriority::Bulk => now_ms + DEADLINE_NORMAL_MS,
    };
    match tx_queue.push(priority, deadline, now_ms, data) {
        Ok(()) => {
            debug!(depth = tx_queue.len(), "TX queued");
        }
        Err(TxQueueError::QueueFull) => {
            warn!(?priority, "TX queue full, dropping outbound packet");
        }
        Err(TxQueueError::PayloadTooLarge) => {
            warn!(len = data.len(), "TX payload too large");
        }
        Err(_) => {
            warn!("TX queue error");
        }
    }
}

/// Push a packet into the shared TX queue with appropriate priority and deadline.
fn push_tx_queue(tx_queue: &Mutex<TxQueue>, priority: TxPriority, data: &[u8], now_ms: u64) {
    let deadline = match priority {
        TxPriority::Sos => now_ms + DEADLINE_SOS_MS,
        TxPriority::Routing => now_ms + DEADLINE_ROUTING_MS,
        TxPriority::Urgent | TxPriority::Normal | TxPriority::Bulk => now_ms + DEADLINE_NORMAL_MS,
    };
    match tx_queue
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(priority, deadline, now_ms, data)
    {
        Ok(()) => {
            let stats = tx_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .stats();
            debug!(depth = stats.depth, "TX queued");
        }
        Err(TxQueueError::QueueFull) => {
            warn!(?priority, "TX queue full, dropping outbound packet");
        }
        Err(TxQueueError::PayloadTooLarge) => {
            warn!(len = data.len(), "TX payload too large");
        }
        Err(_) => {
            warn!("TX queue error");
        }
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

    // Shared TX queue with priority preemption and deadline expiry.
    let tx_queue = Arc::new(Mutex::new(TxQueue::new()));
    let rx_send: tokio::sync::mpsc::Sender<Vec<u8>>;
    let mut rx_recv: tokio::sync::mpsc::Receiver<Vec<u8>>;
    {
        let (send, recv) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        rx_send = send;
        rx_recv = recv;
    }

    // Sim protocol task: sequential TX-drain → RX(50 ms) loop.
    let sim_tx_queue = tx_queue.clone();
    let mut sim_task = tokio::spawn(async move {
        loop {
            // Drain all pending TX frames before the next RX window.
            let now_ms = {
                let start = START_TIME.get_or_init(Instant::now);
                start.elapsed().as_millis() as u64
            };
            // Collect items under lock, then transmit outside the lock
            let items_to_tx: Vec<_> = {
                let mut q = sim_tx_queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut items = Vec::new();
                while let Some(item) = q.pop(now_ms) {
                    items.push(item.data().to_vec());
                }
                items
            };
            for data in items_to_tx {
                match sim.transmit(&data).await {
                    Ok(airtime_us) => info!(airtime_us, len = data.len(), "TX done"),
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
        let now_ms = {
            let start = START_TIME.get_or_init(Instant::now);
            start.elapsed().as_millis() as u64
        };
        let items_to_tx: Vec<_> = {
            let mut q = sim_tx_queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut items = Vec::new();
            while let Some(item) = q.pop(now_ms) {
                items.push(item.data().to_vec());
            }
            items
        };
        for data in items_to_tx {
            match sim.transmit(&data).await {
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
                // Expire stale entries from TX queue
                tx_queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .expire_before(now_ms);
                let stats = tx_queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .stats();
                debug!(depth = stats.depth, packets_dropped = stats.packets_dropped_full, "TX queue stats");
            }
            frame_opt = rx_recv.recv() => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                match frame_opt {
                    Some(frame) => {
                        if let Some(reply) = forward_mesh_to_upstream(gw, &frame, None, None, &tun).await {
                            push_tx_queue(&tx_queue, TxPriority::Routing, &reply, now_ms);
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
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                match result {
                    Ok(n) => {
                        if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]).await {
                            push_tx_queue(&tx_queue, TxPriority::Normal, &schc, now_ms);
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

    // Graceful shutdown: drop rx channel so sim_task can drain TX and exit.
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
    let mut tx_queue = TxQueue::new();
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
                tx_queue.expire_before(now_ms);
                let stats = tx_queue.stats();
                debug!(depth = stats.depth, "serial TX queue stats");
            }
            result = AsyncReadExt::read(&mut tty, &mut rx_buf) => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                match result {
                    Ok(0) => { info!("serial port closed"); break; }
                    Ok(n) => {
                        let packets: Vec<_> = slip.feed(&rx_buf[..n]).collect();
                        for packet in packets {
                            if let Some(to_tx) = forward_mesh_to_upstream(gw, &packet, None, None, &tun).await {
                                push_tx_queue_sync(&mut tx_queue, TxPriority::Routing, &to_tx, now_ms);
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
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                match result {
                    Ok(n) => {
                        if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]).await {
                            push_tx_queue_sync(&mut tx_queue, TxPriority::Normal, &schc, now_ms);
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

        // Drain TxQueue into SlipFramer, then drain SlipFramer to serial
        while let Some(item) = tx_queue.pop({
            let start = START_TIME.get_or_init(Instant::now);
            start.elapsed().as_millis() as u64
        }) {
            if let Err(e) = slip.queue_send(item.data()) {
                warn!("SLIP queue full, dropping packet: {e}");
            }
        }
        while let Ok(Some(n)) = slip.try_get_tx(&mut tx_buf) {
            if let Err(e) = AsyncWriteExt::write_all(&mut tty, &tx_buf[..n]).await {
                error!("serial write: {e}");
                return;
            }
        }
    }
}

async fn forward_mesh_to_upstream<T: TunLike>(
    gw: &mut Gateway,
    frame: &[u8],
    rssi: Option<i16>,
    snr: Option<i8>,
    tun: &Option<T>,
) -> Option<Vec<u8>> {
    let now_ms = {
        let start = START_TIME.get_or_init(Instant::now);
        start.elapsed().as_millis() as u64
    };
    let mut ingress = match gw.ingest_mesh_frame(frame, rssi, snr, now_ms).await {
        Ok(ingress) => ingress,
        Err(e) => {
            warn!("unauthenticated or malformed mesh frame dropped: {e}");
            return None;
        }
    };
    let event = ingress.rpl_event();
    if matches!(event, RplEvent::DaoReceived) {
        info!("authenticated DAO received and processed");
    }
    if let Some(reply) = ingress.take_mesh_reply() {
        info!(len = reply.len(), "mesh reply ready for SLIP TX queue");
        Some(reply)
    } else if let Some(ipv6) = ingress.into_upstream_ipv6() {
        let mut dst = [0u8; 16];
        if ipv6.len() >= IPV6_HEADER_LEN {
            dst.copy_from_slice(&ipv6[field::DST_OFFSET..field::DST_OFFSET + 16]);
            if gw.is_local_mesh(&dst) {
                return gw.mesh_to_mesh(&ipv6).await;
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
    if let Err(e) = conc.reset().await {
        error!("concentrator reset failed: {e}; aborting HAT mode");
        return;
    }
    if let Err(e) = conc.configure(&RadioConfig::default()).await {
        error!("concentrator configure failed: {e}; aborting HAT mode");
        return;
    }
    let mut tun_buf = vec![0u8; 1500];
    let mut rx_buf = vec![0u8; 255];
    let mut tx_queue = TxQueue::new();
    let mut maintenance = interval(Duration::from_millis(1000));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                gw.maintain(now_ms);
                tx_queue.expire_before(now_ms);
                let stats = tx_queue.stats();
                debug!(depth = stats.depth, "hat TX queue stats");
            }
            result = conc.receive(&mut rx_buf, 100) => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                match result {
                    Ok(Some((len, rssi, snr))) => {
                        info!(len, rssi, snr, "hat RX");
                        if let Some(reply) = forward_mesh_to_upstream(gw, &rx_buf[..len], Some(rssi), Some(snr), &tun).await {
                            push_tx_queue_sync(&mut tx_queue, TxPriority::Routing, &reply, now_ms);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => warn!("concentrator receive: {:?}", e),
                }
            }
            result = async { match &tun {
                Some(t) => t.recv_pkt(&mut tun_buf).await,
                None => tun_recv_none(&mut tun_buf).await,
            }} => {
                let now_ms = {
                    let start = START_TIME.get_or_init(Instant::now);
                    start.elapsed().as_millis() as u64
                };
                if let Ok(n) = result {
                    if let Some(schc) = gw.upstream_to_mesh(&tun_buf[..n]).await {
                        push_tx_queue_sync(&mut tx_queue, TxPriority::Normal, &schc, now_ms);
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
        while let Some(item) = tx_queue.pop({
            let start = START_TIME.get_or_init(Instant::now);
            start.elapsed().as_millis() as u64
        }) {
            if let Err(e) = conc.transmit(item.data()).await {
                warn!("concentrator transmit failed: {:?}", e);
            } else {
                info!(len = item.len(), "hat TX");
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

struct EphemeralStateRoot {
    path: PathBuf,
}

const PROVISION_MANIFEST_MAGIC: &[u8; 8] = b"LCHNPRV1";
const PROVISION_STAGE_IDENTITY: u8 = 0;
const PROVISION_STAGE_TRUST: u8 = 1;
const PROVISION_STAGE_SLOT: u8 = 2;
const PROVISION_STAGE_COMPLETE: u8 = 3;

fn initial_resume_state_is_valid(
    manifest_stage: u8,
    boundary_stage: u8,
    generation: u64,
    is_empty: bool,
) -> bool {
    manifest_stage >= boundary_stage || (generation == 1 && is_empty)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProvisionManifest {
    stage: u8,
    identity_pubkey: [u8; 32],
}

fn load_provision_manifest(path: &Path) -> io::Result<Option<ProvisionManifest>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    verify_private_regular_file(path, &metadata, 0o600, "provisioning manifest")?;
    if metadata.len() != 41 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provisioning manifest has invalid length",
        ));
    }
    let mut encoded = [0u8; 41];
    file.read_exact(&mut encoded)?;
    if &encoded[..8] != PROVISION_MANIFEST_MAGIC || encoded[8] > PROVISION_STAGE_COMPLETE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provisioning manifest has invalid magic or stage",
        ));
    }
    let mut identity_pubkey = [0u8; 32];
    identity_pubkey.copy_from_slice(&encoded[9..]);
    Ok(Some(ProvisionManifest {
        stage: encoded[8],
        identity_pubkey,
    }))
}

fn save_provision_manifest(path: &Path, manifest: ProvisionManifest) -> io::Result<()> {
    let mut encoded = [0u8; 41];
    encoded[..8].copy_from_slice(PROVISION_MANIFEST_MAGIC);
    encoded[8] = manifest.stage;
    encoded[9..].copy_from_slice(&manifest.identity_pubkey);
    write_private_atomic(path, &encoded, "provisioning manifest")
}

fn write_private_atomic(path: &Path, bytes: &[u8], label: &str) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} has no parent"),
        )
    })?;
    verify_private_directory(parent)?;
    let suffix = random_state_suffix()?;
    let temp_path = parent.join(format!(".{label}.{}.tmp", hex::encode(suffix)));
    let result = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        verify_private_regular_file(&temp_path, &metadata, 0o600, label)?;
        fs::rename(&temp_path, path)?;
        fs::File::open(parent)?.sync_all()?;
        let metadata = fs::metadata(path)?;
        verify_private_regular_file(path, &metadata, 0o600, label)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

impl Drop for EphemeralStateRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            if error.kind() != io::ErrorKind::NotFound {
                warn!(path = %self.path.display(), %error, "failed to clean simulator state");
            }
        }
    }
}

fn create_ephemeral_state_root() -> io::Result<(PathBuf, EphemeralStateRoot)> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    for _ in 0..32 {
        let suffix = random_state_suffix()?;
        let path = base.join(format!(
            "lichen-sim-{}-{}",
            std::process::id(),
            hex::encode(suffix)
        ));
        match create_private_directory(&path) {
            Ok(()) => {
                if let Err(error) = verify_private_directory(&path) {
                    let _ = fs::remove_dir(&path);
                    return Err(error);
                }
                return Ok((path.clone(), EphemeralStateRoot { path }));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique simulator state directory",
    ))
}

fn ensure_private_state_root(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_directory(path)?;
            verify_private_directory(path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().create(path)
}

fn verify_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state root must be a real directory, not a link or special file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state root must have mode 0700",
        ));
    }
    verify_effective_owner(&metadata, "state root")
}

fn verify_independent_rollback_root(state_root: &Path, floor_root: &Path) -> io::Result<()> {
    let state = fs::canonicalize(state_root)?;
    let floor = fs::canonicalize(floor_root)?;
    if state == floor || state.starts_with(&floor) || floor.starts_with(&state) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state and rollback-floor roots must not be equal or nested",
        ));
    }
    #[cfg(unix)]
    if fs::metadata(&state)?.dev() == fs::metadata(&floor)?.dev() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rollback-floor root must reside on a different filesystem/rollback domain",
        ));
    }
    Ok(())
}

fn load_private_seed(path: &Path) -> io::Result<Option<Seed>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    verify_private_regular_file(path, &metadata, 0o600, "identity seed")?;
    if metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity seed must be exactly 32 bytes",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    file.read_exact(bytes.as_mut())?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity seed grew while it was being read",
        ));
    }
    Ok(Some(Seed::new(*bytes)))
}

fn save_private_seed(path: &Path, seed: &Seed) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace an existing identity seed",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "identity seed has no parent")
    })?;
    verify_private_directory(parent)?;
    let suffix = random_state_suffix()?;
    let temp_path = parent.join(format!(".id.seed.{}.tmp", hex::encode(suffix)));
    let result = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&temp_path)?;
        file.write_all(seed.as_bytes())?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        verify_private_regular_file(&temp_path, &metadata, 0o600, "temporary identity seed")?;
        fs::hard_link(&temp_path, path)?;
        fs::remove_file(&temp_path)?;
        fs::File::open(parent)?.sync_all()?;
        let metadata = fs::metadata(path)?;
        verify_private_regular_file(path, &metadata, 0o600, "identity seed")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn verify_private_regular_file(
    path: &Path,
    metadata: &fs::Metadata,
    expected_mode: u32,
    label: &str,
) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} is not a regular file"),
        ));
    }
    #[cfg(unix)]
    {
        let path_metadata = fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} path changed or is a symbolic link"),
            ));
        }
        if metadata.permissions().mode() & 0o7777 != expected_mode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} must have mode {expected_mode:04o}"),
            ));
        }
    }
    verify_effective_owner(metadata, label)
}

#[cfg(target_os = "linux")]
fn verify_effective_owner(metadata: &fs::Metadata, label: &str) -> io::Result<()> {
    let effective_uid = fs::metadata("/proc/self")?.uid();
    if metadata.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} is not owned by the effective user"),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_effective_owner(_metadata: &fs::Metadata, _label: &str) -> io::Result<()> {
    Ok(())
}

fn random_state_suffix() -> io::Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    #[cfg(unix)]
    {
        fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    }
    #[cfg(not(unix))]
    {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::process::id().hash(&mut hasher);
        std::time::SystemTime::now().hash(&mut hasher);
        bytes[..8].copy_from_slice(&hasher.finish().to_be_bytes());
        bytes[8..].copy_from_slice(&(hasher.finish() ^ 0xa5a5_a5a5_a5a5_a5a5).to_be_bytes());
    }
    Ok(bytes)
}

fn load_generation_floor(path: &std::path::Path) -> std::io::Result<u64> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() != 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generation floor must be exactly eight bytes",
        ));
    }
    let bytes = std::fs::read(path)?;
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generation floor has invalid length",
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn save_generation_floor(path: &std::path::Path, generation: u64) -> std::io::Result<()> {
    use std::io::Write;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid floor path")
        })?;
    let temp_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        generation
    ));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&generation.to_be_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp_path);
    }
    result
}

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

fn resolve_node_id(explicit: Option<&str>, identity_iid: [u8; 8]) -> Result<NodeId, String> {
    let Some(explicit) = explicit else {
        return Ok(NodeId(identity_iid));
    };
    let requested = parse_node_id(explicit)?;
    if requested.0 != identity_iid {
        return Err("configured root IID does not match persisted identity".to_string());
    }
    Ok(requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_gateway::trust::TrustLevel;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn implicit_node_id_tracks_generated_identity_but_explicit_id_is_validated() {
        let iid = [0x42; 8];
        assert_eq!(resolve_node_id(None, iid).unwrap(), NodeId(iid));
        assert_eq!(
            resolve_node_id(Some("4242424242424242"), iid).unwrap(),
            NodeId(iid)
        );
        assert!(resolve_node_id(Some("4141414141414141"), iid).is_err());
    }

    fn persistent_gateway() -> (Gateway, PathBuf, PathBuf, Identity) {
        let suffix = TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lichend-gcp-config-{}-{suffix}",
            std::process::id()
        ));
        let floor_root = std::env::temp_dir().join(format!(
            "lichend-gcp-floors-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&floor_root).unwrap();
        let identity = Identity::from_seed(Seed::new([0x91; 32]));
        let address = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
        let sealing_seed = *identity.seed.as_bytes();
        let trust = TrustStore::new_ephemeral(8).unwrap();
        trust
            .save_atomic_with_floor(
                &root.join("gateway-trust.bin"),
                &floor_root.join("gateway-trust.generation"),
                &sealing_seed,
            )
            .unwrap();
        let coordinator = GatewayCoordinator::provision_persistent(
            address,
            60,
            8,
            &root.join("gateway-slot-replay.bin"),
            &floor_root.join("gateway-slot-replay.generation"),
            &sealing_seed,
        )
        .unwrap();
        let gateway = Gateway::new_persistent(
            identity.clone(),
            128,
            trust,
            coordinator,
            GatewayPersistence::new(
                FileStorage::new(&root).unwrap(),
                true,
                root.clone(),
                floor_root.clone(),
                sealing_seed,
            ),
        )
        .unwrap();
        (gateway, root, floor_root, identity)
    }

    #[test]
    fn closed_psk_config_provisions_durable_trust_and_runtime_context() {
        let (mut gateway, root, floor_root, _) = persistent_gateway();
        let peer = Identity::from_seed(Seed::new([0x92; 32]));
        let mut config = GatewayCoordinationConfig {
            mode: GatewayFederationMode::Psk,
            psk_hex: Some(SecretString::new("11".repeat(16))),
            master_salt_hex: Some(SecretString::new("22334455".into())),
            id_context_hex: Some(SecretString::new("4c494348454e".into())),
            peer_public_keys: vec![hex::encode(peer.pubkey.as_bytes())],
        };
        configure_gateway_federation(&mut gateway, &mut config).unwrap();
        assert_eq!(gateway.gcp_context_count(), 1);
        assert_eq!(
            gateway.trust_store().get(&peer.iid).unwrap().trust_level,
            TrustLevel::BrProvisioned
        );
        assert!(
            config.psk_hex.is_none(),
            "parsed PSK must leave config memory"
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn disabled_and_open_modes_never_fall_back_to_plaintext() {
        let (mut gateway, root, floor_root, _) = persistent_gateway();
        let mut disabled = GatewayCoordinationConfig {
            psk_hex: Some(SecretString::new("11".repeat(16))),
            ..Default::default()
        };
        assert!(configure_gateway_federation(&mut gateway, &mut disabled).is_err());
        let mut open = GatewayCoordinationConfig {
            mode: GatewayFederationMode::Open,
            ..Default::default()
        };
        assert!(configure_gateway_federation(&mut gateway, &mut open).is_err());
        assert_eq!(gateway.gcp_context_count(), 0);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_seed_is_owner_only_and_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let suffix = TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lichend-private-seed-{}-{suffix}",
            std::process::id()
        ));
        create_private_directory(&root).unwrap();
        let seed_path = root.join(keys::IDENTITY_SEED);
        let seed = Seed::new([0x5a; 32]);
        save_private_seed(&seed_path, &seed).unwrap();
        let metadata = fs::metadata(&seed_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(load_private_seed(&seed_path).unwrap(), Some(seed.clone()));
        assert!(save_private_seed(&seed_path, &Seed::new([0x99; 32])).is_err());
        assert_eq!(load_private_seed(&seed_path).unwrap(), Some(seed));

        fs::remove_file(&seed_path).unwrap();
        let target = root.join("attacker-seed");
        fs::write(&target, [0x5a; 32]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &seed_path).unwrap();
        assert!(load_private_seed(&seed_path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn insecure_state_root_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let suffix = TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lichend-insecure-root-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_private_directory(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn simulator_state_is_unique_and_cleaned_explicitly() {
        let (first_path, first_guard) = create_ephemeral_state_root().unwrap();
        let (second_path, second_guard) = create_ephemeral_state_root().unwrap();
        assert_ne!(first_path, second_path);
        assert!(first_path.exists());
        drop(first_guard);
        assert!(!first_path.exists());
        drop(second_guard);
        assert!(!second_path.exists());
    }

    #[test]
    fn provisioning_manifest_durably_records_every_stage() {
        let (root, guard) = create_ephemeral_state_root().unwrap();
        let path = root.join("gateway-provisioning.manifest");
        let identity_pubkey = [0xa7; 32];
        for stage in [
            PROVISION_STAGE_IDENTITY,
            PROVISION_STAGE_TRUST,
            PROVISION_STAGE_SLOT,
            PROVISION_STAGE_COMPLETE,
        ] {
            let expected = ProvisionManifest {
                stage,
                identity_pubkey,
            };
            save_provision_manifest(&path, expected).unwrap();
            assert_eq!(load_provision_manifest(&path).unwrap(), Some(expected));
        }
        drop(guard);
        assert!(!root.exists());
    }

    #[test]
    fn partial_provisioning_only_reanchors_initial_empty_state() {
        assert!(initial_resume_state_is_valid(
            PROVISION_STAGE_IDENTITY,
            PROVISION_STAGE_TRUST,
            1,
            true
        ));
        assert!(!initial_resume_state_is_valid(
            PROVISION_STAGE_IDENTITY,
            PROVISION_STAGE_TRUST,
            2,
            true
        ));
        assert!(!initial_resume_state_is_valid(
            PROVISION_STAGE_IDENTITY,
            PROVISION_STAGE_TRUST,
            1,
            false
        ));
        assert!(!initial_resume_state_is_valid(
            PROVISION_STAGE_TRUST,
            PROVISION_STAGE_SLOT,
            2,
            true
        ));
        assert!(initial_resume_state_is_valid(
            PROVISION_STAGE_SLOT,
            PROVISION_STAGE_SLOT,
            9,
            false
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rollback_floor_on_same_filesystem_is_rejected() {
        let (state, state_guard) = create_ephemeral_state_root().unwrap();
        let (floor, floor_guard) = create_ephemeral_state_root().unwrap();
        assert!(verify_independent_rollback_root(&state, &floor).is_err());
        drop(state_guard);
        drop(floor_guard);
    }
}
