//! RPL routing engine for LICHEN (RFC 6550, Non-Storing Mode).
//!
//! Supports CCP-16 for TDMA scheduling, adaptive SF, multi-channel load balancing,
//! density-aware decisions via extended DIO metrics (load_factor, preferred_channel,
//! num_neighbors). Gateway uses this for root coordination.
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

pub fn hash_32(sfn: u32, key: u64) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in sfn.to_le_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    for b in key.to_le_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

pub fn compute_rendezvous_channel(sfn: u32, peer_eui: u64, n_channels: u8) -> u8 {
    if n_channels <= 1 {
        return 0;
    }
    1 + (hash_32(sfn, peer_eui) % ((n_channels as u32) - 1)) as u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CoordinationMechanism {
    HashBased = 0,
    Scheduled = 1,
    AnnounceDriven = 2,
    Fallback = 3,
}

impl CoordinationMechanism {
    pub fn from_test_vector(s: &str) -> Option<Self> {
        match s {
            "hash_based" => Some(Self::HashBased),
            "scheduled" => Some(Self::Scheduled),
            "announce_driven" => Some(Self::AnnounceDriven),
            "fallback" => Some(Self::Fallback),
            _ => None,
        }
    }
}
