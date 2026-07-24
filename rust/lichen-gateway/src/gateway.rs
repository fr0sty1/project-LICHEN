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
    stack_generation: u64,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            rpl_node: RplNode::new_root(node_id),
            runtime: RplRuntime::new(RplRuntimeConfig::default(), 0),
            stack_generation: 1,
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
                // RFC 4291 §2.7: Source MUST NOT be multicast.
                // Unspecified source MUST NOT be forwarded to upstream.
                if out[8] == 0xff {
                    warn!("mesh_to_upstream: multicast source — dropping");
                    return None;
                }
                if out[8..24].iter().all(|&b| b == 0) {
                    warn!("mesh_to_upstream: unspecified source — dropping");
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
        // RFC 4291 §2.7: Source MUST NOT be multicast. Unspecified source
        // MUST NOT be forwarded into the mesh (only valid for DAD/NDP).
        let src_first = ipv6_packet[8];
        if src_first == 0xff {
            warn!("upstream packet has multicast source — dropping");
            return None;
        }
        if ipv6_packet[8..24].iter().all(|&b| b == 0) {
            warn!("upstream packet has unspecified source — dropping");
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
        (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80)
            || dst[0] == 0xfd
            || self.rpl_node.router().lookup_route(dst).is_some()
    }

    pub fn process_rpl(&mut self, frame: &[u8], now_ms: u64) -> (Option<Vec<u8>>, RplEvent) {
        self.maintain(now_ms);
        let sender_iid = extract_sender_iid(frame);
        let mut reply = vec![0u8; 512];
        let (reply_len, event) = self
            .rpl_node
            .handle_frame_rpl(frame, sender_iid, &mut reply, now_ms);
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
        let _ = self.runtime.poll(&mut self.rpl_node, now_ms, self.stack_generation);
    }

    pub fn mesh_to_mesh(&self, ipv6: &[u8]) -> Option<Vec<u8>> {
        if ipv6.len() < 40 || ipv6[0] >> 4 != 6 {
            warn!(len = ipv6.len(), "mesh_to_mesh: not IPv6");
            return None;
        }
        // RFC 4291 §2.7: Source MUST NOT be multicast.
        if ipv6[8] == 0xff {
            warn!("mesh_to_mesh: multicast source — dropping");
            return None;
        }
        // RFC 4443 §2.2: Unspecified source MUST NOT be forwarded.
        if ipv6[8..24].iter().all(|&b| b == 0) {
            warn!("mesh_to_mesh: unspecified source — dropping");
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6[field::DST_OFFSET..field::DST_OFFSET + 16]);
        let is_mesh_local_addr = (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80) || dst[0] == 0xfd;
        let to_compress = if is_mesh_local_addr {
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

/// Extract sender IID from an SCHC-compressed IPv6 frame.
///
/// Decompresses the frame to read the IPv6 source address and
/// returns its IID (last 8 bytes). On any decompression or parse error
/// returns `[0u8; 8]` so that downstream `handle_frame_rpl` will still
/// process the frame (the `source_matches_sender_iid` check will fail
/// for DIO/DIS but DAOs without admitted origin are rejected at the
/// stack level).
fn extract_sender_iid(frame: &[u8]) -> [u8; 8] {
    if classify_l2_payload(frame) != L2PayloadKind::Schc {
        return [0u8; 8];
    }
    let mut buf = [0u8; 256];
    let n = match decompress(l2_payload_body(frame), &mut buf) {
        Ok(n) if n >= IPV6_HEADER_LEN && buf[0] >> 4 == 6 => n,
        _ => return [0u8; 8],
    };
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&buf[field::SRC_OFFSET + 8..field::SRC_OFFSET + 16]);
    iid
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

    fn ygg_addr(iid_suffix: u8) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr[0] = 0x02;
        addr[15] = iid_suffix;
        Ipv6Addr(addr)
    }

    fn mesh_addr(iid_suffix: u8) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[1] = 0x00;
        addr[15] = iid_suffix;
        Ipv6Addr(addr)
    }

    fn from_hex(s: &str) -> [u8; 16] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        arr
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
        let ygg_cross = ygg_addr(2);
        let nat64 = [
            0x00u8, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
        ];
        assert!(gw.is_local_mesh(&local.0));
        assert!(!gw.is_local_mesh(&ygg_cross.0));
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

    // ── Mesh-to-Internet forwarding tests ──────────────────────────────────

    #[test]
    fn mesh_to_upstream_decompresses_02xx_ygg_packet() {
        let mut gw = test_gateway();
        let src = ll(1);
        let dst = ygg_addr(2);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 1, 1, b"", &mut packet);
        let ipv6 = &packet[..n];

        let schc = gw.upstream_to_mesh(ipv6).expect("compress failed");
        assert_eq!(schc[0], L2_DISPATCH_SCHC);

        let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
        assert_eq!(&recovered[8..24], &src.0);
        assert_eq!(&recovered[24..40], &dst.0);
    }

    #[test]
    fn mesh_to_upstream_packet_with_multicast_source_is_dropped() {
        let mut gw = test_gateway();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 8;
        packet[6] = 58;
        packet[7] = 64;
        packet[8] = 0xff;
        packet[24] = 0x02;
        packet[25] = 0;
        packet[40] = 128;
        let schc = gw.upstream_to_mesh(&packet).expect("compress");
        assert!(gw.mesh_to_upstream(&schc).is_none());
    }

    #[test]
    fn mesh_to_upstream_packet_with_unspecified_source_is_dropped() {
        let mut gw = test_gateway();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 8;
        packet[6] = 58;
        packet[7] = 64;
        packet[24] = 0x02;
        packet[40] = 128;
        let schc = gw.upstream_to_mesh(&packet).expect("compress");
        assert!(gw.mesh_to_upstream(&schc).is_none());
    }

    #[test]
    fn mesh_to_upstream_routing_announce_not_schc_is_dropped() {
        let mut gw = test_gateway();
        let announce = [L2_DISPATCH_ROUTING, 0x01, 0x00];
        assert!(gw.mesh_to_upstream(&announce).is_none());
    }

    // ── Internet-to-Mesh forwarding tests ──────────────────────────────────

    #[test]
    fn upstream_to_mesh_ula_dest_goes_to_mesh() {
        let mut gw = test_gateway();
        let src = ygg_addr(1);
        let dst = mesh_addr(2);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 1, 1, b"", &mut packet);
        let ipv6 = &packet[..n];

        let result = gw.upstream_to_mesh(ipv6).expect("compress");
        assert_eq!(result[0], L2_DISPATCH_SCHC);
    }

    #[test]
    fn upstream_to_mesh_link_local_dest_goes_to_mesh() {
        let mut gw = test_gateway();
        let src = ygg_addr(1);
        let dst = ll(2);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 1, 1, b"", &mut packet);
        let ipv6 = &packet[..n];

        let result = gw.upstream_to_mesh(ipv6).expect("compress");
        assert_eq!(result[0], L2_DISPATCH_SCHC);
    }

    #[test]
    fn upstream_to_mesh_02xx_dest_goes_to_upstream_not_mesh() {
        let mut gw = test_gateway();
        let src = ll(1);
        let dst = ygg_addr(2);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_request(&src, &dst, 1, 1, b"", &mut packet);
        let ipv6 = &packet[..n];

        let result = gw.upstream_to_mesh(ipv6).expect("compress");

        let (_, body) = result.split_at(1);
        let mut decompressed = [0u8; SCHC_MAX_DECOMPRESSED];
        let n = decompress(body, &mut decompressed).unwrap();
        let recovered = &decompressed[..n];

        let mut recovered_dst = [0u8; 16];
        recovered_dst.copy_from_slice(&recovered[24..40]);
        assert_eq!(recovered_dst, dst.0);
    }

    #[test]
    fn upstream_to_mesh_multicast_source_is_dropped() {
        let mut gw = test_gateway();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 8;
        packet[6] = 58;
        packet[7] = 64;
        packet[8] = 0xff;
        packet[24] = 0xfd;
        packet[40] = 128;
        assert!(gw.upstream_to_mesh(&packet).is_none());
    }

    #[test]
    fn upstream_to_mesh_unspecified_source_is_dropped() {
        let mut gw = test_gateway();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 8;
        packet[6] = 58;
        packet[7] = 64;
        packet[24] = 0xfe;
        packet[25] = 0x80;
        packet[40] = 128;
        assert!(gw.upstream_to_mesh(&packet).is_none());
    }

    #[test]
    fn upstream_to_mesh_not_ipv6_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw.upstream_to_mesh(&[0x45, 0, 0, 0]).is_none());
    }

    // ── Gateway route classification tests ─────────────────────────────────

    #[test]
    fn classify_02xx_primary_is_not_local_mesh() {
        let gw = test_gateway();
        let ygg_primary = ygg_addr(0x01);
        let ygg_different = ygg_addr(0x99);
        let link_local = ll(1);
        let ula_local = mesh_addr(1);

        assert!(gw.is_local_mesh(&link_local.0));
        assert!(gw.is_local_mesh(&ula_local.0));
        assert!(!gw.is_local_mesh(&ygg_primary.0));
        assert!(!gw.is_local_mesh(&ygg_different.0));
    }

    #[test]
    fn is_local_mesh_matches_forwarding_test_vectors() {
        let gw = test_gateway();
        let test_cases: &[(&str, &str, bool)] = &[
            ("link_local_mesh_node", "fe800000000000000200000000000001", true),
            ("ula_mesh_node", "fd000000000000010200000000000001", true),
            ("yggdrasil_primary_02xx", "0200000000000000e1b0c44298fc1c14", false),
            ("yggdrasil_02xx_other", "02d4a4a4a4a4a4a40000000000000002", false),
            ("nat64_prefix", "0064ff9b000000000000000000000001", false),
            ("global_unicast_2001", "20010db8000000000000000000000001", false),
            ("multicast", "ff020000000000000000000000000001", false),
            ("link_local_second_octet_bf", "febf0000000000000200000000000001", true),
            ("ula_with_lichen_prefix", "fd006c696368656e0000000000000001", true),
        ];

        for (name, hex_str, expected) in test_cases {
            let addr = from_hex(hex_str);
            let actual = gw.is_local_mesh(&addr);
            assert_eq!(
                actual, *expected,
                "{name}: expected is_local_mesh={expected}, got {actual}"
            );
        }
    }
}
