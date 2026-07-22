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

/// FNV-1a 32-bit hash used for CCP-16 rendezvous and TDMA slotting.
///
/// See `test/vectors/ccp_load_balancing.json` and `ccp9-rendezvous.json`
/// for test vectors and boundary behavior (wrapping_sub in related SFN logic).
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

/// Computes channel for CCP-16 rendezvous based on SFN and peer EUI.
///
/// Returns channel in [1, n_channels-1] or 0 for n_channels <= 1.
/// Uses `hash_32` per `test/vectors/ccp_load_balancing.json`.
pub fn compute_rendezvous_channel(sfn: u32, peer_eui: u64, n_channels: u8) -> u8 {
    if n_channels <= 1 {
        return 0;
    }
    1 + (hash_32(sfn, peer_eui) % ((n_channels as u32) - 1)) as u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// Coordination mechanisms for CCP-16 multi-channel / TDMA load balancing.
///
/// Variants map to test vector strings in `test/vectors/ccp_load_balancing.json`.
pub enum CoordinationMechanism {
    HashBased = 0,
    Scheduled = 1,
    AnnounceDriven = 2,
    Fallback = 3,
}

impl CoordinationMechanism {
    /// Parse from test vector string. Used in cross-impl validation.
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
