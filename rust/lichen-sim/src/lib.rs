//! LICHEN simulator TCP client.
//!
//! Mirrors the Python `SimRadio` in `python/src/lichen/radio/sim_client.py`.
//! Connects to the lichen-sim server over TCP and presents a radio-like
//! interface to the node stack (send/receive byte frames). Requires std.

pub mod client;

pub use client::SimClient;
