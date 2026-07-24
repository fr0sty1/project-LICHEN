// SPDX-License-Identifier: GPL-3.0-or-later
//! Bridge logic for translating between LICHEN IPv6 packets and Meshtastic MeshPackets.
//!
// Allow deprecated field usage for Meshtastic protocol compatibility
#![allow(deprecated)]
//!
//! This module provides bidirectional translation:
//! - Meshtastic MeshPacket -> LICHEN IPv6 (for incoming BLE/serial traffic)
//! - LICHEN IPv6 -> Meshtastic MeshPacket (for outgoing to BLE/serial)
//!
//! The bridge uses IP_TUNNEL_APP (portnum 33) for raw IPv6 encapsulation and
//! TEXT_MESSAGE_APP for CoAP message tunneling where appropriate.

use crate::address::{AddressMapper, MeshtasticNodeId};
use crate::{mesh_packet, routing, Data, MeshPacket, PortNum, Routing};
use heapless::Vec;
use lichen_core::addr::Ipv6Addr;
use lichen_core::rf_health::RfHealthMetrics;

/// Maximum payload size for IPv6 tunnel packets.

/// Meshtastic Data payload is limited to ~237 bytes.
pub const MAX_TUNNEL_PAYLOAD: usize = 237;

/// Maximum queued packets for bridging.
pub const MAX_BRIDGE_QUEUE: usize = 8;

/// Error types for bridge operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeError {
    /// Payload too large for Meshtastic encapsulation.
    PayloadTooLarge,
    /// Unknown destination node (no address mapping).
    UnknownDestination,
    /// Invalid packet format.
    InvalidPacket,
    /// Queue is full.
    QueueFull,
    /// Routing error from Meshtastic layer.
    RoutingError(RoutingErrorCode),
    /// No payload in packet.
    EmptyPayload,
}

impl core::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "payload too large for Meshtastic"),
            Self::UnknownDestination => write!(f, "unknown destination node"),
            Self::InvalidPacket => write!(f, "invalid packet format"),
            Self::QueueFull => write!(f, "bridge queue full"),
            Self::RoutingError(e) => write!(f, "routing error: {:?}", e),
            Self::EmptyPayload => write!(f, "empty payload"),
        }
    }
}

impl core::error::Error for BridgeError {}

/// Routing error codes mapped from Meshtastic Routing.Error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoutingErrorCode {
    None,
    NoRoute,
    GotNak,
    Timeout,
    NoInterface,
    MaxRetransmit,
    NoChannel,
    TooLarge,
    NoResponse,
    DutyCycleLimit,
    BadRequest,
    NotAuthorized,
    PkiFailed,
    PkiUnknownPubkey,
}

impl From<i32> for RoutingErrorCode {
    fn from(val: i32) -> Self {
        match val {
            0 => Self::None,
            1 => Self::NoRoute,
            2 => Self::GotNak,
            3 => Self::Timeout,
            4 => Self::NoInterface,
            5 => Self::MaxRetransmit,
            6 => Self::NoChannel,
            7 => Self::TooLarge,
            8 => Self::NoResponse,
            9 => Self::DutyCycleLimit,
            32 => Self::BadRequest,
            33 => Self::NotAuthorized,
            34 => Self::PkiFailed,
            35 => Self::PkiUnknownPubkey,
            _ => Self::None,
        }
    }
}

/// Result of processing an incoming MeshPacket.
#[derive(Debug, PartialEq)]
pub enum IncomingResult {
    /// IPv6 packet extracted from IP_TUNNEL_APP.
    Ipv6Packet {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        data: Vec<u8, MAX_TUNNEL_PAYLOAD>,
    },
    /// Text message (could be CoAP-over-text).
    TextMessage {
        from: MeshtasticNodeId,
        to: MeshtasticNodeId,
        text: Vec<u8, MAX_TUNNEL_PAYLOAD>,
    },
    /// Routing acknowledgment or error.
    RoutingResponse {
        request_id: u32,
        error: Option<RoutingErrorCode>,
    },
    /// Other port number, passthrough.
    OtherPort {
        portnum: PortNum,
        from: MeshtasticNodeId,
        data: Vec<u8, MAX_TUNNEL_PAYLOAD>,
    },
}

/// Bridge for translating between LICHEN and Meshtastic packets.
#[derive(Debug)]
pub struct MeshtasticBridge {
    /// Address mapper for node ID <-> IPv6 translation.
    mapper: AddressMapper,
    /// Our node ID.
    our_node_id: MeshtasticNodeId,
    /// Next packet ID for outgoing messages.
    next_packet_id: u32,
    /// RF health metrics tracking RX SNR/RSSI (for EMA), density, load_factor,
    /// adaptive SF per CCP-16 / rf_health.rs and ccp vectors.
    rf_health: RfHealthMetrics,
}

impl MeshtasticBridge {
    /// Create a new bridge with the given local node ID.
    pub fn new(our_node_id: MeshtasticNodeId) -> Self {
        Self {
            mapper: AddressMapper::new(),
            our_node_id,
            next_packet_id: 1,
            rf_health: RfHealthMetrics::new(),
        }
    }

    /// Get the address mapper for learning/querying node mappings.
    pub fn mapper(&self) -> &AddressMapper {
        &self.mapper
    }

    /// Get mutable access to the address mapper.
    pub fn mapper_mut(&mut self) -> &mut AddressMapper {
        &mut self.mapper
    }

    /// Get our node ID.
    pub fn our_node_id(&self) -> MeshtasticNodeId {
        self.our_node_id
    }

    /// Get RF health metrics (EMA RSSI/SNR, density, load_factor, adaptive_sf()).
    pub fn rf_health(&self) -> &RfHealthMetrics {
        &self.rf_health
    }

    /// Mutable access for updating from announcements, hash-derived load, or tests.
    pub fn rf_health_mut(&mut self) -> &mut RfHealthMetrics {
        &mut self.rf_health
    }

    /// Process an incoming MeshPacket from BLE/serial.
    ///
    /// Returns the extracted payload type or an error.
    pub fn process_incoming(&mut self, packet: &MeshPacket) -> Result<IncomingResult, BridgeError> {
        let from_node = MeshtasticNodeId::new(packet.from);
        let to_node = MeshtasticNodeId::new(packet.to);

        // Record RX SNR into EMA for adaptive SF per rf_health.rs (rssi ignored
        // after dead code removal). Density/load_factor updated via hash/announcements.
        self.rf_health.record_rx(packet.rx_snr as i8);

        // Get decoded data or return error
        let data = match &packet.payload_variant {
            Some(mesh_packet::PayloadVariant::Decoded(d)) => d,
            Some(mesh_packet::PayloadVariant::Encrypted(_)) => {
                return Err(BridgeError::InvalidPacket);
            }
            None => return Err(BridgeError::EmptyPayload),
        };

        let portnum = PortNum::try_from(data.portnum).unwrap_or(PortNum::UnknownApp);

        match portnum {
            PortNum::IpTunnelApp => {
                // Raw IPv6 packet encapsulated; version check + extract src/dst from IPv6 header
                // (bytes 8-23 src, 24-39 dst per worker5/8 patterns and IPv6 spec)
                if data.payload.len() < 40 || (data.payload[0] >> 4) != 6 {
                    return Err(BridgeError::InvalidPacket);
                }

                let src_bytes: [u8; 16] = data.payload[8..24]
                    .try_into()
                    .map_err(|_| BridgeError::InvalidPacket)?;
                let dst_bytes: [u8; 16] = data.payload[24..40]
                    .try_into()
                    .map_err(|_| BridgeError::InvalidPacket)?;

                let src = Ipv6Addr(src_bytes);
                let dst = Ipv6Addr(dst_bytes);

                let mut payload = Vec::new();
                payload
                    .extend_from_slice(&data.payload)
                    .map_err(|_| BridgeError::PayloadTooLarge)?;

                Ok(IncomingResult::Ipv6Packet {
                    src,
                    dst,
                    data: payload,
                })
            }
            PortNum::TextMessageApp => {
                let mut text = Vec::new();
                text.extend_from_slice(&data.payload)
                    .map_err(|_| BridgeError::PayloadTooLarge)?;

                Ok(IncomingResult::TextMessage {
                    from: from_node,
                    to: to_node,
                    text,
                })
            }
            PortNum::RoutingApp => {
                // Parse routing response
                if let Ok(routing) = prost::Message::decode(data.payload.as_slice()) {
                    let routing: Routing = routing;
                    match routing.variant {
                        Some(routing::Variant::ErrorReason(e)) => {
                            let error_code = RoutingErrorCode::from(e);
                            Ok(IncomingResult::RoutingResponse {
                                request_id: data.request_id,
                                error: if error_code == RoutingErrorCode::None {
                                    None
                                } else {
                                    Some(error_code)
                                },
                            })
                        }
                        Some(routing::Variant::RouteReply(id)) => {
                            Ok(IncomingResult::RoutingResponse {
                                request_id: id,
                                error: None,
                            })
                        }
                        Some(routing::Variant::RouteRequest(id)) => {
                            Ok(IncomingResult::RoutingResponse {
                                request_id: id,
                                error: None,
                            })
                        }
                        _ => Ok(IncomingResult::RoutingResponse {
                            request_id: data.request_id,
                            error: None,
                        }),
                    }
                } else {
                    Err(BridgeError::InvalidPacket)
                }
            }
            _ => {
                // Pass through other port numbers
                let mut payload = Vec::new();
                payload
                    .extend_from_slice(&data.payload)
                    .map_err(|_| BridgeError::PayloadTooLarge)?;

                Ok(IncomingResult::OtherPort {
                    portnum,
                    from: from_node,
                    data: payload,
                })
            }
        }
    }

    pub fn encapsulate_ipv6(&mut self, ipv6_data: &[u8]) -> Result<MeshPacket, BridgeError> {
        if ipv6_data.len() > MAX_TUNNEL_PAYLOAD {
            return Err(BridgeError::PayloadTooLarge);
        }
        if ipv6_data.len() < 40 || (ipv6_data[0] >> 4) != 6 {
            return Err(BridgeError::InvalidPacket);
        }
        let dst_bytes: [u8; 16] = ipv6_data[24..40]
            .try_into()
            .map_err(|_| BridgeError::InvalidPacket)?;
        let dst = Ipv6Addr(dst_bytes);
        let dst_node = self
            .mapper
            .ipv6_to_meshtastic(dst)
            .ok_or(BridgeError::UnknownDestination)?;

        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let data = Data {
            portnum: PortNum::IpTunnelApp as i32,
            payload: ipv6_data.to_vec(),
            want_response: false,
            dest: 0,
            source: 0,
            request_id: 0,
            reply_id: 0,
            emoji: 0,
            bitfield: None,
        };

        Ok(MeshPacket {
            from: self.our_node_id.as_u32(),
            to: dst_node.as_u32(),
            channel: 0,
            id: packet_id,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: true,
            priority: mesh_packet::Priority::Default as i32,
            rx_rssi: 0,
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: alloc::vec::Vec::new(),
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: Some(mesh_packet::PayloadVariant::Decoded(data)),
        })
    }

    /// Create a text message packet.
    pub fn create_text_message(
        &mut self,
        text: &[u8],
        dst: MeshtasticNodeId,
    ) -> Result<MeshPacket, BridgeError> {
        if text.len() > MAX_TUNNEL_PAYLOAD {
            return Err(BridgeError::PayloadTooLarge);
        }

        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let data = Data {
            portnum: PortNum::TextMessageApp as i32,
            payload: text.to_vec(),
            want_response: false,
            dest: 0,
            source: 0,
            request_id: 0,
            reply_id: 0,
            emoji: 0,
            bitfield: None,
        };

        Ok(MeshPacket {
            from: self.our_node_id.as_u32(),
            to: dst.as_u32(),
            channel: 0,
            id: packet_id,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: false,
            priority: mesh_packet::Priority::Default as i32,
            rx_rssi: 0,
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: alloc::vec::Vec::new(),
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: Some(mesh_packet::PayloadVariant::Decoded(data)),
        })
    }

    /// Create a routing error response.
    pub fn create_routing_error(
        &mut self,
        request_id: u32,
        error: RoutingErrorCode,
        dst: MeshtasticNodeId,
    ) -> MeshPacket {
        use prost::Message;

        let routing = Routing {
            variant: Some(routing::Variant::ErrorReason(error as i32)),
        };

        let payload = routing.encode_to_vec();

        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let data = Data {
            portnum: PortNum::RoutingApp as i32,
            payload,
            want_response: false,
            dest: 0,
            source: 0,
            request_id,
            reply_id: 0,
            emoji: 0,
            bitfield: None,
        };

        MeshPacket {
            from: self.our_node_id.as_u32(),
            to: dst.as_u32(),
            channel: 0,
            id: packet_id,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: false,
            priority: mesh_packet::Priority::Ack as i32,
            rx_rssi: 0,
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: alloc::vec::Vec::new(),
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: Some(mesh_packet::PayloadVariant::Decoded(data)),
        }
    }

    /// Create a routing acknowledgment.
    pub fn create_routing_ack(&mut self, request_id: u32, dst: MeshtasticNodeId) -> MeshPacket {
        self.create_routing_error(request_id, RoutingErrorCode::None, dst)
    }
}

/// Broadcast destination address (all nodes).
pub const BROADCAST_ADDR: u32 = 0xFFFFFFFF;

/// Check if a destination is a broadcast address.
pub fn is_broadcast(to: u32) -> bool {
    to == BROADCAST_ADDR
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_packet::PayloadVariant;

    #[test]
    fn test_bridge_creation() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let bridge = MeshtasticBridge::new(node_id);
        assert_eq!(bridge.our_node_id(), node_id);
    }

    #[test]
    fn test_encapsulate_ipv6() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let dst_node = MeshtasticNodeId::new(0x87654321);
        let pubkey = lichen_link::PublicKey::new([0xAB; 32]);
        assert!(bridge.mapper_mut().learn_mapping(dst_node, &pubkey));

        let mut ipv6_data = [0u8; 48];
        ipv6_data[0] = 0x60; // Version 6, destination address set at offset 24 to match mapper
        let dst_addr = bridge.mapper().meshtastic_to_ipv6(dst_node);
        ipv6_data[24..40].copy_from_slice(&dst_addr.0);

        let result = bridge.encapsulate_ipv6(&ipv6_data);
        assert!(result.is_ok());

        let packet = result.unwrap();
        assert_eq!(packet.from, node_id.as_u32());
        assert_eq!(packet.to, dst_node.as_u32());

        if let Some(PayloadVariant::Decoded(data)) = packet.payload_variant {
            assert_eq!(data.portnum, PortNum::IpTunnelApp as i32);
            assert_eq!(data.payload.len(), 48);
        } else {
            panic!("Expected decoded payload");
        }
    }

    #[test]
    fn test_payload_too_large() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let large_data = [0u8; 300];
        let result = bridge.encapsulate_ipv6(&large_data);
        assert_eq!(result, Err(BridgeError::PayloadTooLarge));
    }

    #[test]
    fn test_unknown_destination() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let unknown_addr = Ipv6Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);

        let mut data = [0u8; 48];
        data[0] = 0x60;
        data[24..40].copy_from_slice(&unknown_addr.0);
        let result = bridge.encapsulate_ipv6(&data);
        assert_eq!(result, Err(BridgeError::UnknownDestination));
    }

    #[test]
    fn test_process_text_message() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let packet = MeshPacket {
            from: 0x11111111,
            to: 0x12345678,
            channel: 0,
            id: 1,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: false,
            priority: 0,
            rx_rssi: 0,
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: alloc::vec::Vec::new(),
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                portnum: PortNum::TextMessageApp as i32,
                payload: b"Hello LICHEN".to_vec(),
                want_response: false,
                dest: 0,
                source: 0,
                request_id: 0,
                reply_id: 0,
                emoji: 0,
                bitfield: None,
            })),
        };

        let result = bridge.process_incoming(&packet);
        assert!(result.is_ok());

        if let Ok(IncomingResult::TextMessage { from, to, text }) = result {
            assert_eq!(from, MeshtasticNodeId::new(0x11111111));
            assert_eq!(to, MeshtasticNodeId::new(0x12345678));
            assert_eq!(text.as_slice(), b"Hello LICHEN");
        } else {
            panic!("Expected TextMessage result");
        }
    }

    #[test]
    fn test_create_text_message() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let dst = MeshtasticNodeId::new(0x87654321);
        let result = bridge.create_text_message(b"Test message", dst);
        assert!(result.is_ok());

        let packet = result.unwrap();
        assert_eq!(packet.from, node_id.as_u32());
        assert_eq!(packet.to, dst.as_u32());

        if let Some(PayloadVariant::Decoded(data)) = packet.payload_variant {
            assert_eq!(data.portnum, PortNum::TextMessageApp as i32);
            assert_eq!(data.payload, b"Test message");
        } else {
            panic!("Expected decoded payload");
        }
    }

    #[test]
    fn test_routing_error_code_conversion() {
        assert_eq!(RoutingErrorCode::from(0), RoutingErrorCode::None);
        assert_eq!(RoutingErrorCode::from(1), RoutingErrorCode::NoRoute);
        assert_eq!(RoutingErrorCode::from(3), RoutingErrorCode::Timeout);
        assert_eq!(RoutingErrorCode::from(32), RoutingErrorCode::BadRequest);
        assert_eq!(RoutingErrorCode::from(999), RoutingErrorCode::None); // Unknown
    }

    #[test]
    fn test_is_broadcast() {
        assert!(is_broadcast(BROADCAST_ADDR));
        assert!(!is_broadcast(0x12345678));
    }

    #[test]
    fn test_empty_payload() {
        let node_id = MeshtasticNodeId::new(0x12345678);
        let mut bridge = MeshtasticBridge::new(node_id);

        let packet = MeshPacket {
            from: 0x11111111,
            to: 0x12345678,
            channel: 0,
            id: 1,
            rx_time: 0,
            rx_snr: 0.0,
            hop_limit: 3,
            want_ack: false,
            priority: 0,
            rx_rssi: 0,
            delayed: 0,
            via_mqtt: false,
            hop_start: 0,
            public_key: alloc::vec::Vec::new(),
            pki_encrypted: false,
            next_hop: 0,
            relay_node: 0,
            payload_variant: None,
        };

        let result = bridge.process_incoming(&packet);
        assert_eq!(result, Err(BridgeError::EmptyPayload));
    }
}
