//! Gateway state and packet forwarding.

#![forbid(unsafe_code)]

use lichen_core::addr::{Ipv6Addr, NodeId};
use lichen_core::constants::{L2_DISPATCH_SCHC, SCHC_MAX_DECOMPRESSED};
use lichen_core::ipv6::field;
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_node::{
    runtime::{RplRuntime, RplRuntimeConfig},
    RplEvent, RplNode,
};
use lichen_rpl::routing::SourceRoutingHeader;
use lichen_schc::codec::{compress, decompress, SchcError};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct Gateway {
    rpl_node: RplNode,
    runtime: RplRuntime,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            rpl_node: RplNode::new_root(node_id),
            runtime: RplRuntime::new(RplRuntimeConfig::default(), 0),
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

        let mut out = vec![0u8; SCHC_MAX_DECOMPRESSED];
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
            Err(SchcError::BufferTooSmall(e)) => {
                warn!(
                    required = e.required,
                    provided = e.provided,
                    "SCHC decompress buffer too small for jumbo packet"
                );
                None
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
    /// Prefers local RPL mesh (with source routing for Non-Storing mode per
    /// RFC 6554 SRH insertion in local_mesh path). Post-SRH size is accounted
    /// for in buffers and SCHC rules (see lichen-schc and SCHC profile in
    /// spec/drafts/draft-lichen-schc-lora-00.md). Returns the compressed
    /// frame to send via SLIP, or `None` on error.
    pub fn upstream_to_mesh(&mut self, ipv6_packet: &[u8]) -> Option<Vec<u8>> {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6_packet[field::DST_OFFSET..field::DST_OFFSET + 16]);
        if self.is_local_mesh(&dst) {
            self.mesh_to_mesh(ipv6_packet)
        } else {
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
    }

    pub fn is_local_mesh(&self, dst: &[u8; 16]) -> bool {
        if dst[0] == 0x00 && dst[1] == 0x64 && dst[2] == 0xff && dst[3] == 0x9b {
            return false;
        }
        (dst[0] == 0xfe && dst[1] == 0x80)
            || dst[0] == 0xfd
            || self.rpl_node.router().lookup_route(dst).is_some()
    }

    pub fn process_rpl(&mut self, frame: &[u8], now_ms: u64) -> (Option<Vec<u8>>, RplEvent) {
        self.maintain(now_ms);
        let mut reply = vec![0u8; 512];
        let (reply_len, event) = self
            .rpl_node
            .handle_frame_rpl(frame, [0u8; 8], &mut reply, now_ms);
        let reply_opt = if reply_len > 0 {
            reply.truncate(reply_len);
            Some(reply)
        } else {
            None
        };
        (reply_opt, event)
    }

    /// Run periodic RPL maintenance (prune_neighbors, DAO expiry) using
    /// monotonic time from Instant::elapsed(). Respects defer-external;
    /// does not auto-admit by TOFU (admission requires explicit pin).
    pub fn maintain(&mut self, now_ms: u64) {
        let _ = self.runtime.poll(&mut self.rpl_node, now_ms);
    }

    pub fn mesh_to_mesh(&self, ipv6: &[u8]) -> Option<Vec<u8>> {
        if ipv6.len() < 40 || ipv6[0] >> 4 != 6 {
            warn!(len = ipv6.len(), "mesh_to_mesh: not IPv6");
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6[field::DST_OFFSET..field::DST_OFFSET + 16]);
        let to_compress = if (dst[0] == 0xfe && dst[1] == 0x80) || dst[0] == 0xfd {
            ipv6.to_vec()
        } else {
            let route = match self.rpl_node.router().lookup_route(&dst) {
                Some(r) => r,
                None => return None,
            };
            if route.len() > 1 {
                let srh = match SourceRoutingHeader::from_route(route) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                let num_addrs = srh.addresses.len();
                let routing_len = 8 + 16 * num_addrs;
                let total_len = ipv6.len() + routing_len;
                let mut routed = vec![0u8; total_len];
                routed[..40].copy_from_slice(&ipv6[..40]);
                let payload_len = u16::from_be_bytes([ipv6[4], ipv6[5]]) as usize + routing_len;
                let routed_payload_len = match u16::try_from(payload_len) {
                    Ok(p) => p,
                    Err(_) => return None,
                };
                routed[4..6].copy_from_slice(&routed_payload_len.to_be_bytes());
                let transport = ipv6[6];
                routed[6] = 43;
                routed[24..40].copy_from_slice(&route[0]);
                routed[40] = transport;
                routed[41] = (routing_len / 8 - 1) as u8;
                if srh.write_to(&mut routed[42..]).is_err() {
                    return None;
                }
                routed[40 + routing_len..].copy_from_slice(&ipv6[40..]);
                routed
            } else {
                ipv6.to_vec()
            }
        };
        let mut out = vec![0u8; to_compress.len() + 20];
        out[0] = L2_DISPATCH_SCHC;
        match compress(&to_compress, &mut out[1..]) {
            Ok(n) => {
                out.truncate(n + 1);
                info!(compressed_len = n + 1, "mesh → mesh");
                Some(out)
            }
            Err(e) => {
                warn!("SCHC compress mesh_to_mesh: {e:?}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::{
        addr::{Ipv6Addr, NodeId},
        icmpv6,
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
    fn yggdrasil_cross_mesh_routing() {
        let gw = test_gateway();
        let local = ll(1);
        let ygg_cross = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let nat64 = [
            0x00u8, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
        ];
        assert!(gw.is_local_mesh(&local.0));
        assert!(!gw.is_local_mesh(&ygg_cross));
        assert!(!gw.is_local_mesh(&nat64));
    }

    #[test]
    fn unknown_route_is_dropped_in_mesh_to_mesh() {
        let gw = test_gateway();
        let dst = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        assert!(!gw.is_local_mesh(&dst));
        let packet = [
            0x60, 0, 0, 0, 40, 0, 58, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        ];
        let result = gw.mesh_to_mesh(&packet);
        assert!(result.is_none());
    }
}
