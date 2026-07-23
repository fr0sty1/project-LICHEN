//! Gateway state and packet forwarding. Propagates CCP-9/15/EMA/rf_health
//! alignments, FNV-1a32, and dead-code removal from epic l3j5 (project-LICHEN-nafo).

#![forbid(unsafe_code)]

use lichen_core::addr::{Ipv6Addr, NodeId};
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_node::{RplEvent, RplNode};
use lichen_schc::codec::{compress, decompress, SchcError};
use tracing::{info, warn};

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

    /// SCHC-decompress a frame received from the mesh via SLIP.
    ///
    /// Returns the raw IPv6 packet to inject into the upstream TUN device, or
    /// `None` if decompression fails or the result is not a valid IPv6 packet.
    pub fn mesh_to_upstream(&mut self, l2_payload: &[u8]) -> Option<Vec<u8>> {
        if classify_l2_payload(l2_payload) != L2PayloadKind::Schc {
            warn!("non-SCHC L2 payload received on upstream gateway path");
            return None;
        }

        let mut out = vec![0u8; 1280];
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
        if ipv6_packet.len() < IPV6_HEADER_LEN || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6_packet[field::DST_OFFSET..IPV6_HEADER_LEN]);
        let packet = if self.is_local_mesh(&dst) {
            if let Some(path) = self.node.router.lookup_route(&dst) {
                info!(?path, "SRH downward routing for local mesh dst per spec 5");
                let mut p = ipv6_packet.to_vec();
                if path.len() > 1 {
                    let first = path[0];
                    let remaining = &path[1..];
                    let rh_len = 8 + 16 * remaining.len();
                    let original_next = p[6];
                    p[6] = next_header::ROUTING;
                    let old_plen = u16::from_be_bytes([p[4], p[5]]);
                    let new_plen = old_plen + rh_len as u16;
                    p[4..6].copy_from_slice(&new_plen.to_be_bytes());
                    p[field::DST_OFFSET..IPV6_HEADER_LEN].copy_from_slice(&first);
                    let mut rh = vec![0u8; rh_len];
                    rh[0] = original_next;
                    rh[1] = (2 * remaining.len()) as u8;
                    rh[2] = 3;
                    rh[3] = remaining.len() as u8;
                    for (i, addr) in remaining.iter().enumerate() {
                        rh[8 + i * 16..8 + (i + 1) * 16].copy_from_slice(addr);
                    }
                    p.splice(IPV6_HEADER_LEN..IPV6_HEADER_LEN, rh);
                }
                p
            } else {
                ipv6_packet.to_vec()
            }
        } else {
            ipv6_packet.to_vec()
        };
        let mut out = vec![0u8; packet.len() + 3];
        out[0] = L2_DISPATCH_SCHC;
        match compress(&packet, &mut out[1..]) {
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
        Ipv6Addr(*dst).is_yggdrasil() && self.node.router.lookup_route(dst).is_some()
    }

    /// Process L2 frame through RplNode. Returns (reply, event). reply is Some if
    /// handle_frame_rpl produced compressed reply in reply_buf (e.g. echo). No ignore.
    pub fn process_rpl(&mut self, l2_payload: &[u8], now_ms: u32) -> (Option<Vec<u8>>, RplEvent) {
        let mut reply_buf = [0u8; 256];
        let (reply_len, event) = self
            .node
            .handle_frame_rpl(l2_payload, &mut reply_buf, now_ms);
        let reply = if reply_len > 0 {
            Some(reply_buf[..reply_len].to_vec())
        } else {
            None
        };
        (reply, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::{
        addr::Ipv6Addr,
        icmpv6,
        ipv6::{field, IPV6_HEADER_LEN},
    };

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
        assert_eq!(
            &recovered[field::SRC_OFFSET..field::DST_OFFSET],
            &src.0,
            "src mismatch"
        );
        assert_eq!(
            &recovered[field::DST_OFFSET..IPV6_HEADER_LEN],
            &dst.0,
            "dst mismatch"
        );
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
        assert_eq!(
            &recovered[field::SRC_OFFSET..field::DST_OFFSET],
            &src.0,
            "src mismatch"
        );
        assert_eq!(
            &recovered[field::DST_OFFSET..IPV6_HEADER_LEN],
            &dst.0,
            "dst mismatch"
        );
    }

    #[test]
    fn non_ipv6_upstream_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw.upstream_to_mesh(&[0u8; IPV6_HEADER_LEN]).is_none());
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

    #[test]
    fn yggdrasil_remote_address_not_local_mesh() {
        let gw = test_gateway();
        let remote = [0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert!(
            !gw.is_local_mesh(&remote),
            "remote Yggdrasil addr should route via upstream (Yggdrasil backbone) for cross-mesh"
        );
    }
}
