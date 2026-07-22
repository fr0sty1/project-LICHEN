//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode, CCP-16).
//!
//! Modules:
//! - `message` — DIO/DAO/DIS/DAO-ACK codec + TLV
//! - `dodag` — DODAG state with MRHOF
//! - `routing` — non-storing table + DAO
//! - `trickle` — Trickle timer (RFC 6206)

#![no_std]

pub mod dodag;
pub mod message;
pub mod routing;
pub mod trickle;

#[cfg(feature = "std")]
extern crate std;
