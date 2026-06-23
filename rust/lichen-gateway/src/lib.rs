//! LICHEN border router (6LBR) daemon for Linux.
//!
//! Bridges the LoRa mesh (via a simulated or real radio interface) to an
//! upstream IPv6 network. Holds all routes in RPL Non-Storing Mode and
//! injects source-routing headers for downward traffic. Requires std.

pub mod gateway;

pub use gateway::Gateway;
