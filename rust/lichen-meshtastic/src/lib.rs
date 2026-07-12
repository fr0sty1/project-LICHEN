// SPDX-License-Identifier: GPL-3.0-or-later
//! Meshtastic protobuf types for LICHEN bridge.
//!
//! This crate provides Rust bindings for the subset of Meshtastic protobufs
//! needed for the LICHEN-Meshtastic bridge: MeshPacket, Data, Position,
//! User, NodeInfo, and PortNum.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

// Include generated protobuf code
include!("meshtastic.rs");

pub mod address;
pub mod gatt;

// Re-export commonly used types for convenience
pub use address::{AddressMapper, Ipv6AddrMeshtasticExt, MeshtasticNodeId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portnum_values() {
        assert_eq!(PortNum::TextMessageApp as i32, 1);
        assert_eq!(PortNum::PositionApp as i32, 3);
        assert_eq!(PortNum::NodeinfoApp as i32, 4);
    }

    #[test]
    fn test_position_default() {
        let pos = Position::default();
        assert_eq!(pos.latitude_i, None);
        assert_eq!(pos.longitude_i, None);
    }

    #[test]
    fn test_mesh_packet_default() {
        let pkt = MeshPacket::default();
        assert_eq!(pkt.from, 0);
        assert_eq!(pkt.to, 0);
    }
}
