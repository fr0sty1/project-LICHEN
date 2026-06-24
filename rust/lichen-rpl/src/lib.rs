//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode).
//!
//! Modules:
//! - `messages` — DIO / DAO / DIS / DAO-ACK wire codec + TLV option parser
//! - `dodag`    — DODAG state machine with MRHOF parent selection
//! - `routing`  — Non-Storing routing table and DAO manager
//! - `trickle`  — Trickle timer state machine (RFC 6206)

#![no_std]

pub mod dodag;
pub mod messages;
pub mod routing;
pub mod trickle;

#[cfg(feature = "std")]
extern crate std;
