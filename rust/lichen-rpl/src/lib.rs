//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode with CCP-16).
//!
//! **CCP-16 Load Balancing Support**: TDMA scheduling, adaptive SF, multi-channel
//! load balancing, density-aware parent selection via extended DIO metrics
//! (`load_factor`, `preferred_channel`, `num_neighbors`). See
//! `test/vectors/ccp_load_balancing.json` (vectors: gateway_channel_assignment,
//! tdma_slot_assignment, adaptive_sf_density). Python impl is source of truth.
//! Used by mesh-gateway for root coordination.
//!
//! Modules:
//! - `message`  — DIO/DAO/DIS/DAO-ACK codec + CCP TLV parser
//! - `dodag`    — DODAG state machine with MRHOF + density/load metrics
//! - `routing`  — Non-Storing routing table, DAO manager
//! - `trickle`  — Trickle timer (RFC 6206)

#![no_std]

pub mod dodag;
pub mod message;
pub mod routing;
pub mod trickle;

#[cfg(feature = "std")]
extern crate std;

pub fn lollipop_is_newer(new_val: u8, old_val: u8) -> bool {
    const CIRCULAR_BIT: u8 = 128;
    const WINDOW: u8 = 16;
    match (new_val < CIRCULAR_BIT, old_val < CIRCULAR_BIT) {
        (true, true) => new_val > old_val,
        (false, false) => {
            let diff = new_val.wrapping_sub(old_val) & 0x7F;
            diff > 0 && diff <= WINDOW
        }
        (true, false) => true,
        (false, true) => false,
    }
}
