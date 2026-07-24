//! Gateway state and packet forwarding.

#![forbid(unsafe_code)]

use std::fmt;

use lichen_core::addr::{Ipv6Addr, NodeId};
use lichen_core::constants::{L2_DISPATCH_SCHC, SCHC_MAX_DECOMPRESSED};
use lichen_core::ipv6::{field, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_hal::loopback::LoopbackRadio;
use lichen_hal::storage::mem::MemStorage;
use lichen_link::identity::Identity;
use lichen_link::keys::Seed;
use lichen_node::{
    announce::AnnounceProcessor, gradient::GradientTable, rpl_stack::RplStack, secure::SecureStack,
    stack::add_rpl_source_route, RplEvent,
};
use lichen_schc::codec::{compress, decompress, SchcError};
use tracing::{error, info, warn};

pub struct Gateway {
    rpl_stack: RplStack<LoopbackRadio, MemStorage>,
}

impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway")
            .field("node_id", &self.rpl_stack.rpl_node().node().node_id)
            .finish()
    }
}

impl Gateway {
    /// Create a new root gateway with a deterministic test identity.
    ///
    /// Uses `Seed::new([0x01; 32])` as the node identity. The `node_id`
    /// parameter is retained for backward compatibility; the root address
    /// is derived from the identity's public key per spec.
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let root_addr = identity_pubkey_link_local(&identity);
        let dodag_id = root_addr;
        let (radio, _peer) = LoopbackRadio::pair();
        let stack = SecureStack::from_radio(radio, identity, 128);
        let announces =
            AnnounceProcessor::new(GradientTable::new(64), dodag_id[..8].try_into().unwrap());
        let storage = MemStorage::new();
        let rpl_stack = RplStack::provision_root(stack, root_addr, dodag_id, announces, storage)
            .expect("gateway RPL root provision");
        Self { rpl_stack }
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

    /// Check if a destination address is reachable within the local mesh.
    ///
    /// Per spec §7.2: 02xx::/7 addresses are Yggdrasil-derived primaries.
    /// Local mesh check uses RPL route lookup. Yggdrasil-only addresses
    /// (02xx not in RPL table) are NOT local mesh and should go to the
    /// Yggdrasil TUN.
    pub fn is_local_mesh(&self, dst: &[u8; 16]) -> bool {
        // Link-local: always local
        if dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80 {
            return true;
        }

        // Exclude magic discard prefix
        if dst[0] == 0x00 && dst[1] == 0x64 && dst[2] == 0xff && dst[3] == 0x9b {
            return false;
        }

        // 02xx::/7: local if in RPL route table, otherwise Yggdrasil
        if dst[0] & 0xfe == 0x02 {
            return self
                .rpl_stack
                .rpl_node()
                .router()
                .lookup_route(dst)
                .is_some();
        }

        // Unknown/non-02xx: fallback to RPL check
        self.rpl_stack
            .rpl_node()
            .router()
            .lookup_route(dst)
            .is_some()
    }

    pub fn process_rpl(&mut self, frame: &[u8], now_ms: u64) -> (Option<Vec<u8>>, RplEvent) {
        self.maintain(now_ms);
        let sender_iid = extract_sender_iid(frame);
        let mut reply = vec![0u8; 512];
        let (reply_len, event) = self
            .rpl_stack
            .rpl_node()
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
        self.rpl_stack.maintain(now_ms, 10_000, &());
    }

    /// Route a packet for a destination that is part of the local RPL mesh.
    ///
    /// Implements RFC 6554 source routing for Non-Storing Mode with two paths:
    ///
    ///   **Root-originated /128 host route** — insert an SRH directly into the
    ///   IPv6 header (swap destination with first hop, list remaining hops in
    ///   the Routing header).
    ///
    ///   **Everything else** (upstream/internet-originated traffic, prefix
    ///   routes shorter than /128) — IPv6-in-IPv6 encapsulation per
    ///   `draft-lichen-rpl-lora-00` §7.4 / RFC 6554 §4.1: the original packet
    ///   is preserved as an inner payload; an outer IPv6+SRH header routes to
    ///   `E`, the last node in the path.
    ///
    /// Link-local and ULA destinations are forwarded verbatim without a route
    /// lookup.
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
            let route = match self.rpl_stack.rpl_node().router().lookup_route(&dst) {
                Some(r) => r,
                None => return None,
            };
            if route.len() == 1 {
                ipv6.to_vec()
            } else {
                let root_addr = self.rpl_stack.rpl_node().node().node_id.link_local_addr().0;
                let is_root_origin = ipv6[8..24] == root_addr;
                let is_host_route = route.last() == Some(&dst);
                if is_root_origin && is_host_route {
                    let routing_len = 8 + 16 * (route.len() - 1);
                    let total_len = ipv6.len() + routing_len;
                    let mut routed = vec![0u8; total_len];
                    if add_rpl_source_route(ipv6, route, &mut routed).is_err() {
                        return None;
                    }
                    routed
                } else {
                    let num_addrs = route.len() - 1;
                    let routing_len = 8 + 16 * num_addrs;
                    let outer_payload = routing_len + ipv6.len();
                    let outer_payload_u16 = u16::try_from(outer_payload).ok()?;
                    let outer_hdr = 40 + routing_len;
                    let mut outer = vec![0u8; outer_hdr];
                    outer[0] = 0x60;
                    outer[4..6].copy_from_slice(&outer_payload_u16.to_be_bytes());
                    outer[6] = 43;
                    outer[7] = 64;
                    outer[8..24].copy_from_slice(&root_addr);
                    outer[24..40].copy_from_slice(&route[0]);
                    outer[40] = 41;
                    outer[41] = (routing_len / 8 - 1) as u8;
                    outer[42] = 3;
                    outer[43] = num_addrs as u8;
                    outer[44..48].fill(0);
                    for (i, addr) in route[1..].iter().enumerate() {
                        let start = 48 + i * 16;
                        outer[start..start + 16].copy_from_slice(addr);
                    }
                    let mut encapsulated = Vec::with_capacity(outer_hdr + ipv6.len());
                    encapsulated.extend_from_slice(&outer);
                    encapsulated.extend_from_slice(ipv6);
                    encapsulated
                }
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

/// Build a link-local IPv6 address from an identity's public-key-derived IID.
fn identity_pubkey_link_local(identity: &Identity) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[8..].copy_from_slice(&identity.iid);
    addr
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
        let schc = gw.upstream_to_mesh(packet).unwrap();
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2");

        let recovered = gw.mesh_to_upstream(&schc).unwrap();

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
        let schc = gw.upstream_to_mesh(packet).unwrap();
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2");

        let recovered = gw.mesh_to_upstream(&schc).unwrap();
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

    #[test]
    fn dao_route_makes_ygg_address_local() {
        let gw = test_gateway();
        let node_addr = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];

        // No route yet — not local
        assert!(!gw.rpl_stack.rpl_node().router().is_root());
        assert!(!gw.is_local_mesh(&node_addr));

        // Inject a DAO route
        let root_addr = gw.rpl_stack.rpl_node().node().link_local_addr().0;
        let path = [root_addr, node_addr];
        gw.rpl_stack
            .rpl_node_mut()
            .router_mut()
            .inject_route(node_addr, &path);

        // Now the 02xx address is local mesh
        assert!(gw.is_local_mesh(&node_addr));
    }

    #[test]
    fn root_originated_downward_srh() {
        let mut gw = test_gateway();
        let root_addr = gw.rpl_stack.rpl_node().node().link_local_addr().0;
        let node_addr = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];

        // Inject DAO route: root → node_addr (single hop)
        let path = [root_addr, node_addr];
        gw.rpl_stack
            .rpl_node_mut()
            .router_mut()
            .inject_route(node_addr, &path);

        // Build IPv6 packet FROM root TO node_addr
        let payload = b"hello";
        let payload_len = payload.len() as u16;
        let mut packet = vec![0u8; 40 + payload.len() as usize];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 17; // UDP NH
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&root_addr);
        packet[24..40].copy_from_slice(&node_addr);
        packet[40..].copy_from_slice(payload);

        let result = gw.mesh_to_mesh(&packet);
        assert!(result.is_some(), "expected SRH-compressed payload");
        let compressed = result.unwrap();
        assert_eq!(compressed[0], L2_DISPATCH_SCHC);

        // Decompress and verify SRH was inserted
        let mut decompressed = [0u8; lichen_core::constants::SCHC_MAX_DECOMPRESSED];
        let n = lichen_schc::codec::decompress(&compressed[1..], &mut decompressed)
            .expect("decompress should succeed");
        assert!(n >= 40, "decompressed IPv6 packet");
        assert_eq!(decompressed[6], 43, "NH should be Routing (SRH)");
        assert_eq!(decompressed[24..40], path[0], "dst = first hop (root→node)");
        assert_eq!(decompressed[40], 17, "inner NH should be UDP");
        assert_eq!(
            decompressed[42], 3,
            "SRH routing type = 3 (RPL source route)"
        );
        // Last address in SRH should be the original destination
        let addr_count = (decompressed[41] as usize + 1) * 8;
        let srh_end = 40 + addr_count;
        let last_addr_start = srh_end - 16;
        assert_eq!(
            &decompressed[last_addr_start..srh_end],
            &node_addr,
            "last SRH address = original dst"
        );
    }
}
