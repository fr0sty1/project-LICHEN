//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode) with CCP-16 load balancing.
//!
<<<<<<< HEAD
//! Supports TDMA slot assignment, adaptive-SF, multi-channel, density-aware routing and
//! DIO metrics (see `test/vectors/ccp_load_balancing.json` for canonical test vectors
//! and independent mathematical oracles).
=======
//! Supports TDMA slot assignment, adaptive SF, multi-channel density-aware routing.
>>>>>>> origin/integration/worker11-20260722
//! Modules:
//! - `message`  — DIO / DAO / DIS / DAO-ACK wire codec + TLV option parser
//! - `dodag`    — DODAG state machine with MRHOF parent selection
//! - `routing`  — Non-Storing routing table and DAO manager with CCP-16 extensions
//! - `trickle`  — Trickle timer state machine (RFC 6206)

#![no_std]

pub mod dodag;
pub mod message;
pub mod routing;
pub mod trickle;

#[cfg(feature = "std")]
extern crate std;
