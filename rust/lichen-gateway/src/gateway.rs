//! Gateway state and packet forwarding.

use lichen_core::addr::NodeId;
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::ipv6::{field, next_header, write_extension_header};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_node::{routing::SourceRoutingHeader, RplNode};
use lichen_schc::codec::{compress, decompress, SchcError};
use tracing::{info, warn};

/// Top-level border router state.
#[derive(Debug)]
pub struct Gateway {
    pub node: RplNode,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            node: RplNode::new_root(node_id),
        }
    }

    /// Returns true if `dst` has a route in the DAO-based RoutingTable (non-storing RPL root).
    pub fn is_local_mesh(&self, dst: &[u8; 16]) -> bool {
        (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80) || dst[0] == 0xfd || self.node.router.lookup_route(dst).is_some()
    }

    /// Process incoming DAO to update DAO table / RoutingTable (replaces stale HashMap).
    pub fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
        self.node.router.process_dao(dao_bytes)
    }

    /// SCHC-decompress a frame received from the mesh via SLIP.
    ///
    /// Returns the raw IPv6 packet to inject into the upstream TUN device, or
    /// `None` if decompression fails or the result is not a valid IPv6 packet.
    pub fn mesh_to_upstream(&mut self, l2_payload: &[u8]) -> Option<Vec<u8>> {
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
    /// For local-mesh destinations (per DAO table), inserts SRH for downward
    /// non-storing RPL routing per spec/05-routing.md:8.5 and spec/17-lci.
    pub fn upstream_to_mesh(&mut self, ipv6_packet: &[u8]) -> Option<Vec<u8>> {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }

        let dst_bytes = &ipv6_packet[field::DST_OFFSET..field::DST_OFFSET + 16];
        let dst: [u8; 16] = dst_bytes.try_into().unwrap();
        let mut packet_to_compress = ipv6_packet.to_vec();

        if self.is_local_mesh(&dst) {
            if let Some(path) = self.node.router.lookup_route(&dst) {
                info!(
                    path_len = path.len(),
                    "downward to local mesh — SRH insertion"
                );
                if !path.is_empty() {
                    let first_hop = path[0];
                    packet_to_compress[field::DST_OFFSET..field::DST_OFFSET + 16]
                        .copy_from_slice(&first_hop);
                    if path.len() > 1 {
                        let srh = SourceRoutingHeader {
                            segments_left: (path.len() - 1) as u8,
                            addresses: path[1..].to_vec(),
                        };
                        let original_nh = packet_to_compress[6];
                        packet_to_compress[6] = next_header::ROUTING;
                        let mut srh_inner = [0u8; 6 + 16 * 8];
                        let srh_len = srh.write_to(&mut srh_inner).expect("SRH fits in buffer");
                        let mut ext_buf = [0u8; 128];
                        let ext_len = write_extension_header(
                            next_header::ROUTING,
                            original_nh,
                            &srh_inner[0..srh_len],
                            &mut ext_buf,
                        )
                        .expect("extension header fits");
                        let original_payload = packet_to_compress[40..].to_vec();
                        let new_len = 40 + ext_len + original_payload.len();
                        packet_to_compress.resize(new_len, 0);
                        packet_to_compress[40..40 + ext_len].copy_from_slice(&ext_buf[0..ext_len]);
                        packet_to_compress[40 + ext_len..].copy_from_slice(&original_payload);
                        info!(
                            ?srh,
                            ext_len, "full SRH extension header inserted (next_header=43)"
                        );
                    }
                }
            }
        }

        let mut out = vec![0u8; packet_to_compress.len() + 3];
        out[0] = L2_DISPATCH_SCHC;
        match compress(&packet_to_compress, &mut out[1..]) {
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

        // IPv6 header fields
        assert_eq!(recovered[6], 58, "NH should be ICMPv6");
        assert_eq!(&recovered[8..24], &src.0, "src mismatch");
        assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
        // ICMPv6 fields
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
    fn unknown_schc_rule_is_dropped() {
        let mut gw = test_gateway();
        // Rule 0xAA is not defined
        assert!(gw
            .mesh_to_upstream(&[L2_DISPATCH_SCHC, 0xAAu8, 0x00])
            .is_none());
    }

    #[test]
    fn non_schc_l2_payload_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw.mesh_to_upstream(&[0x15, 0x01]).is_none());
    }
}
