//! LICHEN border router (6LBR) daemon for Linux.
//!
//! Bridges the LoRa mesh (via SLIP over serial/USB) to an upstream IPv6
//! network. Acts as RPL DODAG root in Non-Storing Mode. Requires std.

pub mod aprs_is;
pub mod config;
pub mod gateway;
pub mod slip;
#[cfg(target_os = "linux")]
pub mod tun;

pub use aprs_is::{aprs_to_cot, cot_to_aprs, AprsIsClient, CompactCot};
pub use gateway::Gateway;
pub use lichen_node::{RplEvent, RplNode};
