//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode).
//!
//! no_std: message codec, DODAG state machine, trickle timer. `std` feature
//! provides routing table, DAO manager, CCP-16 load balancing, TDMA slot
//! assignment, adaptive SF, density-aware metrics and DIOs (see
//! `test/vectors/ccp_load_balancing.json` and rpl_route_state_vectors.rs for
//! canonical test vectors and independent oracles).
//! Modules:
//! - `message`  — DIO / DAO / DIS / DAO-ACK wire codec + TLV option parser
//! - `dodag`    — DODAG state machine with MRHOF parent selection (CCP-16)
//! - `routing`  — Non-Storing routing table and DAO manager (std)
//! - `trickle`  — Trickle timer state machine (RFC 6206)

#![no_std]
#![forbid(unsafe_code)]

pub mod dodag;
pub mod message;
pub mod routing;
pub mod trickle;

#[cfg(feature = "std")]
extern crate std;
