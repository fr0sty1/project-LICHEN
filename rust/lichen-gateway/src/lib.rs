//! LICHEN border router (6LBR) daemon for Linux.
//!
//! Bridges the LoRa mesh (via SLIP over serial/USB) to an upstream IPv6
//! network. Acts as RPL DODAG root in Non-Storing Mode. Requires std.

pub mod config;
pub mod gateway;
pub mod slip;

pub use gateway::Gateway;
