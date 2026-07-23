// SPDX-License-Identifier: GPL-3.0-or-later
//! Meshtastic protobuf types for LICHEN bridge.
//!
//! This crate provides Rust bindings for the Meshtastic protobufs needed for
//! the LICHEN-Meshtastic bridge, including BLE API envelope messages:
//!
//! - **Core types**: `MeshPacket`, `Data`, `Position`, `User`, `NodeInfo`, `PortNum`
//! - **BLE API envelopes**: `ToRadio`, `FromRadio` (phone-to-device/device-to-phone)
//! - **Device info**: `MyNodeInfo`, `DeviceMetadata`, `QueueStatus`
//! - **Routing**: `Routing` with error codes
//! - **Channel/Config**: `Channel`, `ChannelSettings`, `ModuleConfig`
//! - **Firmware**: `XModemPacket` for OTA updates
//!
//! # Bridge Module
//!
//! The [`bridge`] module provides translation between LICHEN IPv6 packets and
//! Meshtastic MeshPackets using IP_TUNNEL_APP (portnum 33).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

// Include generated protobuf code
include!("meshtastic.rs");

pub mod address;
#[cfg(any(feature = "alloc", test))]
pub mod bridge;
pub mod gatt;

// Re-export commonly used types for convenience
pub use address::{AddressMapper, Ipv6AddrMeshtasticExt, MeshtasticNodeId};
#[cfg(any(feature = "alloc", test))]
pub use bridge::{
    is_broadcast, BridgeError, IncomingResult, MeshtasticBridge, RoutingErrorCode, BROADCAST_ADDR,
    MAX_BRIDGE_QUEUE, MAX_TUNNEL_PAYLOAD,
};

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    #[test]
    fn test_portnum_values() {
        assert_eq!(PortNum::TextMessageApp as i32, 1);
        assert_eq!(PortNum::PositionApp as i32, 3);
        assert_eq!(PortNum::NodeinfoApp as i32, 4);
        assert_eq!(PortNum::RoutingApp as i32, 5);
        assert_eq!(PortNum::IpTunnelApp as i32, 33);
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

    #[test]
    fn test_to_radio_variants() {
        // Test want_config_id variant
        let to_radio = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::WantConfigId(12345)),
        };
        assert!(matches!(
            to_radio.payload_variant,
            Some(to_radio::PayloadVariant::WantConfigId(12345))
        ));

        // Test disconnect variant
        let to_radio_disconnect = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Disconnect(true)),
        };
        assert!(matches!(
            to_radio_disconnect.payload_variant,
            Some(to_radio::PayloadVariant::Disconnect(true))
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn test_from_radio_variants() {
        // Test my_info variant
        let my_info = MyNodeInfo {
            my_node_num: 0x12345678,
            has_gps: false,
            max_channels: 8,
            firmware_version: "2.3.0".into(),
            error_code: None,
            error_address: None,
            error_count: None,
            reboot_count: Some(5),
            bitrate: None,
            message_timeout_msec: Some(5000),
            min_app_version: Some(30000),
            max_app_data_size: 237,
            has_wifi: true,
            has_bluetooth: true,
            has_ethernet: false,
            hw_model: HardwareModel::TloraV2 as i32,
            can_shutdown: true,
            has_pkc: true,
            has_position_flags: true,
            device_id: 12345,
            is_managed: false,
        };

        let from_radio = FromRadio {
            id: 1,
            payload_variant: Some(from_radio::PayloadVariant::MyInfo(my_info)),
        };

        if let Some(from_radio::PayloadVariant::MyInfo(info)) = from_radio.payload_variant {
            assert_eq!(info.my_node_num, 0x12345678);
            assert_eq!(info.firmware_version, "2.3.0");
            assert_eq!(info.max_channels, 8);
        } else {
            panic!("Expected MyInfo variant");
        }
    }

    #[test]
    fn test_routing_error_codes() {
        use routing::Error;

        assert_eq!(Error::None as i32, 0);
        assert_eq!(Error::NoRoute as i32, 1);
        assert_eq!(Error::Timeout as i32, 3);
        assert_eq!(Error::NoInterface as i32, 4);
        assert_eq!(Error::DutyCycleLimit as i32, 9);
        assert_eq!(Error::BadRequest as i32, 32);
    }

    #[test]
    fn test_queue_status() {
        let status = QueueStatus {
            res: 0,
            free: 5,
            maxlen: 8,
            mesh_packet_id: 12345,
        };

        assert_eq!(status.free, 5);
        assert_eq!(status.maxlen, 8);
    }

    #[test]
    #[allow(deprecated)]
    fn test_channel_settings() {
        let settings = ChannelSettings {
            channel_num: 0,
            psk: vec![0x01; 32], // 32-byte PSK for AES-256
            name: "LongFast".into(),
            id: 0,
            uplink_enabled: false,
            downlink_enabled: false,
            module_settings: None,
        };

        assert_eq!(settings.name, "LongFast");
        assert_eq!(settings.psk.len(), 32);
    }

    #[test]
    fn test_channel_roles() {
        use channel::Role;

        assert_eq!(Role::Disabled as i32, 0);
        assert_eq!(Role::Primary as i32, 1);
        assert_eq!(Role::Secondary as i32, 2);
    }

    #[test]
    fn test_log_record_levels() {
        use log_record::Level;

        assert_eq!(Level::Unset as i32, 0);
        assert_eq!(Level::Critical as i32, 50);
        assert_eq!(Level::Error as i32, 40);
        assert_eq!(Level::Warning as i32, 30);
        assert_eq!(Level::Info as i32, 20);
        assert_eq!(Level::Debug as i32, 10);
        assert_eq!(Level::Trace as i32, 5);
    }

    #[test]
    fn test_xmodem_controls() {
        use x_modem_packet::Control;

        assert_eq!(Control::Nul as i32, 0);
        assert_eq!(Control::Soh as i32, 1);
        assert_eq!(Control::Stx as i32, 2);
        assert_eq!(Control::Eot as i32, 4);
        assert_eq!(Control::Ack as i32, 6);
        assert_eq!(Control::Nak as i32, 21);
        assert_eq!(Control::Can as i32, 24);
    }

    #[test]
    fn test_device_metadata() {
        let metadata = DeviceMetadata {
            firmware_version: "2.3.0".into(),
            device_state_version: 23,
            can_shutdown: true,
            has_wifi: true,
            has_bluetooth: true,
            has_ethernet: false,
            role: config::device_config::Role::Client as i32,
            position_flags: 0,
            hw_model: HardwareModel::Rak4631 as i32,
            has_remote_hardware: false,
            has_pkc: true,
        };

        assert_eq!(metadata.firmware_version, "2.3.0");
        assert!(metadata.has_pkc);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_to_radio_packet_variant() {
        use prost::Message;

        let data = Data {
            portnum: PortNum::TextMessageApp as i32,
            payload: b"Hello".to_vec(),
            want_response: false,
            dest: 0,
            source: 0,
            request_id: 0,
            reply_id: 0,
            emoji: 0,
            bitfield: None,
        };

        let packet = MeshPacket {
            from: 0x12345678,
            to: 0x87654321,
            channel: 0,
            id: 1,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: false,
            priority: mesh_packet::Priority::Default as i32,
            rx_rssi: 0,
            #[allow(deprecated)]
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: vec![],
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: Some(mesh_packet::PayloadVariant::Decoded(data)),
        };

        let to_radio = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(packet)),
        };

        // Encode and decode
        let mut buf = Vec::new();
        to_radio.encode(&mut buf).unwrap();
        let decoded = ToRadio::decode(buf.as_slice()).unwrap();

        if let Some(to_radio::PayloadVariant::Packet(p)) = decoded.payload_variant {
            assert_eq!(p.from, 0x12345678);
            assert_eq!(p.to, 0x87654321);
        } else {
            panic!("Expected Packet variant");
        }
    }
}
