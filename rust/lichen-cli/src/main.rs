//! lichen — LICHEN node CLI.
//!
//! Connects to a node via CoAP over UDP and provides commands for status,
//! messaging, presence, SOS, position, and node configuration.
//!
//! Examples:
//!   lichen status
//!   lichen neighbors
//!   lichen presence
//!   lichen send --to fe80::1 "hello mesh"
//!   lichen inbox
//!   lichen sos activate
//!   lichen sos status
//!   lichen sos cancel
//!   lichen config get tx_power_dbm
//!   lichen config set tx_power_dbm 10
//!   lichen position show
//!   lichen rd list
//!   lichen rd register --ep my-node --lt 3600
//!   lichen rd delete &lt;id&gt;

mod commands;
mod output;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;

/// LICHEN node command-line interface.
#[derive(Parser)]
#[command(name = "lichen", version, about)]
struct Cli {
    /// CoAP endpoint address of the target node.
    #[arg(short, long, default_value = "[::1]:5683", env = "LICHEN_NODE")]
    node: SocketAddr,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    output: OutputFormat,

    /// Verbosity (-v / -vv).
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::ValueEnum, Clone, Default)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Show node status (rank, role, radio stats).
    Status,

    /// List known neighbors and their link quality.
    Neighbors,

    /// Show the live table of recently-heard mesh peers.
    Presence,

    /// Send a text message to a node.
    Send {
        /// Destination node IPv6 address, or "all" for broadcast.
        #[arg(long)]
        to: String,
        /// Message text.
        message: String,
    },

    /// Show received messages (inbox).
    Inbox,

    /// Emergency SOS beacon.
    Sos {
        #[command(subcommand)]
        action: SosAction,
    },

    /// Key management subcommands.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },

    /// Node configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Position and navigation.
    Position {
        #[command(subcommand)]
        action: PositionAction,
    },

    /// CoAP Resource Directory (RFC 9176).
    Rd {
        #[command(subcommand)]
        action: RdAction,
    },
}

#[derive(Subcommand)]
enum SosAction {
    /// Activate the SOS emergency beacon.
    Activate,
    /// Cancel a previously activated SOS beacon.
    Cancel,
    /// Show the current SOS state.
    Status,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Generate a new Ed25519 keypair (for initial node setup).
    Generate {
        /// Output file for private key (default: stdout).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Print this node's public key fingerprint.
    Fingerprint,
    /// List trusted peer keys.
    List,
    /// Pin a peer's key (prevent automatic rotation).
    Pin {
        /// Peer IPv6 address.
        peer: String,
    },
    /// Unpin a peer's key.
    Unpin {
        /// Peer IPv6 address.
        peer: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Read a configuration value.
    Get {
        /// Key name, e.g. `tx_power_dbm`.
        key: String,
    },
    /// Write a configuration value.
    Set {
        /// Key name.
        key: String,
        /// New value (string; node validates type).
        value: String,
    },
}

#[derive(Subcommand)]
enum PositionAction {
    /// Show this node's last known position.
    Show,
    /// Broadcast this node's position to the mesh.
    Broadcast,
    /// List peer positions (from presence table).
    Peers,
}

#[derive(Subcommand)]
enum RdAction {
    /// List registered endpoints.
    List {
        /// Filter by endpoint name.
        #[arg(long)]
        ep: Option<String>,
    },
    /// Register this node with the Resource Directory.
    Register {
        /// Endpoint name (default: node address).
        #[arg(long)]
        ep: Option<String>,
        /// Lifetime in seconds (default: 3600).
        #[arg(long, default_value_t = 3600)]
        lt: u32,
    },
    /// Delete a registration by ID.
    Delete {
        /// Registration ID returned by `register`.
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .without_time()
        .init();

    let fmt = cli.output;
    let result = match cli.command {
        Command::Status => commands::status(cli.node, &fmt).await,
        Command::Neighbors => commands::neighbors(cli.node, &fmt).await,
        Command::Presence => commands::presence(cli.node, &fmt).await,
        Command::Send { to, message } => commands::send(cli.node, &to, &message, &fmt).await,
        Command::Inbox => commands::inbox(cli.node, &fmt).await,
        Command::Sos { action } => match action {
            SosAction::Activate => commands::sos_activate(cli.node, &fmt).await,
            SosAction::Cancel => commands::sos_cancel(cli.node, &fmt).await,
            SosAction::Status => commands::sos_status(cli.node, &fmt).await,
        },
        Command::Key { action } => commands::key(cli.node, action, &fmt).await,
        Command::Config { action } => commands::config(cli.node, action, &fmt).await,
        Command::Position { action } => commands::position(cli.node, action, &fmt).await,
        Command::Rd { action } => commands::rd(cli.node, action, &fmt).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
