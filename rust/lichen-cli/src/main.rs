//! lichen — LICHEN node CLI.
//!
//! Connects to a node via CoAP over UDP (default [::1]:5683) and provides
//! commands for status, neighbors, messaging, keys, config, and position.
//!
//! Examples:
//!   lichen status
//!   lichen neighbors
//!   lichen send --to fe80::1 "hello mesh"
//!   lichen inbox
//!   lichen key list
//!   lichen config get tx_power_dbm
//!   lichen config set tx_power_dbm 10
//!   lichen position show

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

    /// List known neighbors and their link quality (uses /status/neighbors).
    Neighbors,

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

    /// Position (uses shared lichen-client::pos::Position + /sensors/location).
    Position {
        #[command(subcommand)]
        action: PositionAction,
    },
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
    /// Show this node's last known position (SenML).
    Show,
    /// Broadcast this node's position to the mesh (unimplemented).
    Broadcast,
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
        Command::Send { to, message } => commands::send(cli.node, &to, &message, &fmt).await,
        Command::Inbox => commands::inbox(cli.node, &fmt).await,
        Command::Key { action } => commands::key(cli.node, action, &fmt).await,
        Command::Config { action } => commands::config(cli.node, action, &fmt).await,
        Command::Position { action } => commands::position(cli.node, action, &fmt).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
