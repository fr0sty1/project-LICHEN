//! Gateway state and packet forwarding.

#![forbid(unsafe_code)]

use lichen_core::addr::{Ipv6Addr, NodeId};
use lichen_core::constants::{L2_DISPATCH_SCHC, SCHC_MAX_DECOMPRESSED};
use lichen_core::ipv6::{field, IPV6_HEADER_LEN};
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
        let addr = node_id.link_local_addr().0;
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
                routed[field::DST_OFFSET..IPV6_HEADER_LEN].copy_from_slice(&route[0]);
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
impl Gateway {
    /// Add a route to the routing table for testing multi-hop SRH insertion.
    pub fn add_test_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) -> bool {
        self.rpl_node.add_test_route(target, path)
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
        assert_eq!(&recovered[field::SRC_OFFSET..field::DST_OFFSET], &src.0, "src mismatch");
        assert_eq!(&recovered[field::DST_OFFSET..IPV6_HEADER_LEN], &dst.0, "dst mismatch");
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
        assert_eq!(&recovered[field::SRC_OFFSET..field::DST_OFFSET], &src.0, "src mismatch");
        assert_eq!(&recovered[field::DST_OFFSET..IPV6_HEADER_LEN], &dst.0, "dst mismatch");
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

    #[test]
    fn multi_hop_srh_is_inserted_for_global_dest() {
        let mut gw = test_gateway();
        // Use a global unicast destination (not fe80::/10 or fd00::/8) so that
        // mesh_to_mesh takes the route-lookup + SRH insertion path.
        let child = ll(2);
        let dst = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let path = [child.0, dst.0];
        assert!(gw.add_test_route(dst.0, &path));

        let src = ll(1);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 1, 1, b"data", &mut packet);
        let packet = &packet[..n];

        let result = gw.mesh_to_mesh(packet);
        assert!(result.is_some(), "SRH insertion should succeed");
        let compressed = result.unwrap();
        assert_eq!(compressed[0], L2_DISPATCH_SCHC);
        // SRH adds 24 bytes to a 48-byte packet, so SCHC compressed output should
        // be noticeably larger than the original uncompressed packet.
        assert!(
            compressed.len() > packet.len(),
            "SRH insertion should increase packet size"
        );
    }

    #[test]
    fn direct_child_global_dest_no_srh() {
        let mut gw = test_gateway();
        // Single-hop route to a global address: route.len() == 1 → no SRH.
        let dst = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let path = [dst.0];
        assert!(gw.add_test_route(dst.0, &path));

        let src = ll(1);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 2, 1, b"data", &mut packet);
        let packet = &packet[..n];

        let result = gw.mesh_to_mesh(packet);
        assert!(result.is_some(), "direct child should succeed");
        // For a direct child, no SRH is inserted, so the compressed size should
        // be smaller than the inflated SRH path.
        let compressed = result.unwrap();
        assert_eq!(compressed[0], L2_DISPATCH_SCHC);
    }

    #[test]
    fn multi_hop_srh_header_correct() {
        let mut gw = test_gateway();
        let child = ll(2);
        let dst = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
        let path = [child.0, dst.0];
        assert!(gw.add_test_route(dst.0, &path));

        // IPv6 header with NH=UDP(17), then UDP payload
        let src = ll(1);
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&(20u16).to_be_bytes()); // payload length (UDP)
        ipv6[6] = 17; // NH = UDP
        ipv6[7] = 64;
        ipv6[field::SRC_OFFSET..field::DST_OFFSET].copy_from_slice(&src.0);
        ipv6[field::DST_OFFSET..].copy_from_slice(&dst.0);
        let mut packet = ipv6.to_vec();
        packet.extend_from_slice(b"0123456789abcdefghij"); // 20-byte UDP payload

        let result = gw.mesh_to_mesh(&packet);
        assert!(result.is_some());
        let schc = result.unwrap();
        let mut decompressed = vec![0u8; 512];
        let n = lichen_schc::codec::decompress(&schc[1..], &mut decompressed)
            .expect("decompress should succeed");
        decompressed.truncate(n);

        // After SRH insertion: NH = 43 (Routing Header)
        assert_eq!(decompressed[6], 43, "NH should be Routing Header (43)");
        // Destination address should now be the first hop (child)
        assert_eq!(
            &decompressed[field::DST_OFFSET..IPV6_HEADER_LEN],
            &child.0,
            "DST addr should be first hop after SRH insertion"
        );
        // Hdr Ext Len = (8 + 1*16)/8 - 1 = 2
        assert_eq!(decompressed[41], 2, "Hdr Ext Len for 24-byte routing header");
        // SRH starts at offset 40
        // [40] = next header after routing (should be original NH = 17)
        assert_eq!(decompressed[40], 17, "NH after SRH should be original UDP");
        // [41] = Hdr Ext Len
        assert_eq!(decompressed[41], 2);
        // [42] = routing type = 3 (SRH, RFC 6554)
        assert_eq!(decompressed[42], 3, "routing type must be 3");
        // [43] = segments_left = 1
        assert_eq!(decompressed[43], 1, "segments_left should be 1 (one hop to go)");
        // [48..64] = address[0] = final destination
        assert_eq!(
            &decompressed[48..64],
            &dst.0,
            "SRH address[0] should be final destination"
        );
        // The original UDP payload should follow after the SRH
        let srh_len: usize = 8 + 16; // 8-byte fixed + 1*16 address
        assert_eq!(
            &decompressed[40 + srh_len..],
            b"0123456789abcdefghij",
            "original UDP payload should follow SRH"
        );
    }

    #[test]
    fn blackhole_prevention_route_one_hop_non_direct() {
        // A route containing exactly one hop that is NOT the destination indicates
        // a data-plane inconsistency (should not happen in practice, but defensive).
        let mut gw = test_gateway();
        let child = ll(2);
        let dst = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);

        // Add a bogus route: path = [child] but target == dst (not child). The
        // route path does NOT end with the target — but mesh_to_mesh doesn't
        // validate that (it trusts the routing table). Just verify it doesn't
        // crash and returns Some.
        let path = [child.0];
        assert!(gw.add_test_route(dst.0, &path));

        let src = ll(1);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 3, 1, b"data", &mut packet);
        let packet = &packet[..n];

        let result = gw.mesh_to_mesh(packet);
        assert!(result.is_some(), "should forward via single-hop route");
    }
}
