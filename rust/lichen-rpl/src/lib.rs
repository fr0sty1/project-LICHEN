//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode).
//!
//! Modules:
//! - `message`  — DIO / DAO / DIS / DAO-ACK wire codec + TLV option parser
//! - `dodag`    — DODAG state machine with MRHOF parent selection
//! - `routing`  — Non-Storing routing table and DAO manager
//! - `trickle`  — Trickle timer state machine (RFC 6206)

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
