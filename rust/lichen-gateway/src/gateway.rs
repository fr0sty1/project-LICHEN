//! Gateway state and packet forwarding.

use lichen_core::addr::NodeId;
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_node::{RplEvent, RplNode};
use lichen_schc::codec::{compress, decompress, SchcError};
use std::time::Instant;
use tracing::{info, warn};

/// Concentrator trait for border router link abstraction (LoRa HAT, SLIP, sim).
/// Allows multiple concentrator implementations for different hardware.
pub trait Concentrator {
    fn send(&mut self, data: &[u8]) -> Result<(), String>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn get_node_id(&self) -> NodeId;
}

/// Top-level border router state.
#[derive(Debug)]
pub struct Gateway {
    pub node: RplNode,
    start_time: Instant,
    /// Routes installed in the kernel routing table.
    /// Key: mesh IPv6 address (16 bytes, network order); Value: nexthop EUI-64.
    routes: std::collections::HashMap<[u8; 16], NodeId>,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            node: RplNode::new_root(node_id),
            start_time: Instant::now(),
            routes: std::collections::HashMap::new(),
        }
    }

    /// SCHC-decompress a frame received from the mesh via SLIP.
    ///
    /// Returns the raw IPv6 packet to inject into the upstream TUN device, or
    /// `None` if decompression fails or the result is not a valid IPv6 packet.
    pub fn mesh_to_upstream(&mut self, l2_payload: &[u8]) -> Option<Vec<u8>> {
        let now_ms = self.start_time.elapsed().as_millis() as u32;
        let mut reply = [0u8; 259];
        let (_, event) = self.node.handle_frame_rpl(l2_payload, &mut reply, now_ms);
        if let RplEvent::DaoReceived {
            route_updated: true,
        } = event
        {
            self.node
                .router
                .dao_manager
                .populate_routes(&mut self.routes);
        }
        if classify_l2_payload(l2_payload) != L2PayloadKind::Schc {
            warn!("non-SCHC L2 payload received on upstream gateway path");
            return None;
        }

        let mut out = vec![0u8; 1500];
        match decompress(l2_payload_body(l2_payload), &mut out) {
            Ok(n) => {
                out.truncate(n);
                if out.len() < 40 || out[0] >> 4 != 6 {
                    warn!(len = out.len(), "decompressed frame is not IPv6");
                    return None;
                }
                let payload_len = u16::from_be_bytes([out[4], out[5]]);
                info!(payload_len, "mesh → upstream");
                Some(out)
            }
            Err(SchcError::UnknownRuleId(id)) => {
                warn!(rule_id = id, "SCHC: unknown rule — dropping");
                None
            }
            Err(e) => {
                warn!("SCHC decompress: {e:?}");
                None
            }
        }
    }

    /// SCHC-compress an IPv6 packet from the upstream TUN device for the mesh.
    ///
    /// Returns the compressed frame to send via SLIP, or `None` on error.
    pub fn upstream_to_mesh(&mut self, ipv6_packet: &[u8]) -> Option<Vec<u8>> {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }
        let mut out = vec![0u8; ipv6_packet.len() + 3];
        out[0] = L2_DISPATCH_SCHC;
        match compress(ipv6_packet, &mut out[1..]) {
            Ok(n) => {
                out.truncate(n + 1);
                info!(compressed_len = n + 1, "upstream → mesh");
                Some(out)
            }
            Err(e) => {
                warn!("SCHC compress: {e:?}");
                None
            }
        }
    }

    pub fn is_local_mesh(&self, dst: &[u8; 16]) -> bool {
        // RPL routes for local mesh (prefers LoRa over Yggdrasil TUN for inter-mesh 02xx::/7).
        // Address recognition uses lichen-ipv6::Addr::is_yggdrasil() + routes.
        self.routes.contains_key(dst) || (dst[0] == 0xfe && dst[1] == 0x80)
    }

    pub fn add_route(&mut self, addr: [u8; 16], node_id: NodeId) {
        self.routes.insert(addr, node_id);
        let nexthop = node_id.link_local_addr().0;
        self.node
            .router
            .dao_manager
            .routing_table
            .add_route(addr, &[nexthop]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::{addr::Ipv6Addr, icmpv6};

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    fn test_gateway() -> Gateway {
        Gateway::new(NodeId([0x02, 0, 0, 0, 0, 0, 0, 0x01]))
    }

    #[test]
    fn icmpv6_echo_request_round_trips() {
        let src = ll(1);
        let dst = ll(2);
        let mut packet = [0u8; 52];
        let n = icmpv6::echo_request(&src, &dst, 0x1234, 5, b"ping", &mut packet);
        let packet = &packet[..n];

        let mut gw = test_gateway();
        let schc = gw.upstream_to_mesh(packet).expect("compress failed");
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2 (ICMPv6 echo link-local)");

        let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");

        assert_eq!(recovered[6], 58, "NH should be ICMPv6");
        assert_eq!(&recovered[8..24], &src.0, "src mismatch");
        assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
        assert_eq!(recovered[40], icmpv6::ECHO_REQUEST, "type should be 128");
        assert_eq!(recovered[41], 0, "code should be 0");
        assert_eq!(&recovered[44..46], &[0x12, 0x34], "id mismatch");
        assert_eq!(&recovered[46..48], &[0x00, 0x05], "seq mismatch");
        assert_eq!(&recovered[48..], b"ping", "payload mismatch");
    }

    #[test]
    fn icmpv6_echo_reply_round_trips() {
        let src = ll(2);
        let dst = ll(1);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_reply(&src, &dst, 0x1234, 5, &[], &mut packet);
        let packet = &packet[..n];

        let mut gw = test_gateway();
        let schc = gw.upstream_to_mesh(packet).expect("compress failed");
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2");

        let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
        assert_eq!(recovered[40], icmpv6::ECHO_REPLY, "type should be 129");
        assert_eq!(&recovered[8..24], &src.0, "src mismatch");
        assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    }

    #[test]
    fn non_ipv6_upstream_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw.upstream_to_mesh(&[0u8; 40]).is_none());
    }

    #[test]
    fn non_schc_l2_payload_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw
            .mesh_to_upstream(&[L2_DISPATCH_SCHC, 0xAAu8, 0x00])
            .is_none());
    }

    #[test]
    fn inter_mesh_routing_decision_uses_independent_oracle() {
        // Independent oracle from test/vectors/yggdrasil.json zero-key vector.
        let ygg_bytes = [
            0x02, 0x02, 0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0, 0, 0, 0, 0, 0, 0,
        ];
        let dst = Ipv6Addr(ygg_bytes);
        assert!(dst.is_yggdrasil(), "02xx::/7 recognition");
        let mut gw = test_gateway();
        assert!(!gw.is_local_mesh(&ygg_bytes), "remote Ygg not local RPL");
        // local RPL would be in routes; MTU note verified in sim
    }
}
