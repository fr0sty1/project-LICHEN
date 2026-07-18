//! Node state and receive-path dispatch.

use lichen_core::constants::L2_DISPATCH_SCHC;
#[cfg(feature = "std")]
use lichen_core::constants::RPL_ICMPV6_TYPE;
#[cfg(all(feature = "std", test))]
use lichen_core::constants::RPL_INSTANCE_ID;
#[cfg(feature = "std")]
use lichen_core::icmpv6::hdr_field;
use lichen_core::icmpv6::{echo_field, ICMPV6_HEADER_LEN};
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_core::udp::UDP_HEADER_LEN;
use lichen_core::{addr::Ipv6Addr, addr::NodeId, icmpv6};
use lichen_schc::codec;

use crate::port_dispatch::{dispatch_by_port, Dispatched, UdpDispatchError};

/// IPv6 version number expected in the first 4 bits of the header.
const IPV6_VERSION: u8 = 6;

#[cfg(feature = "std")]
use crate::routing::Router;

/// ICMPv6 RPL message codes.
pub mod rpl_code {
    pub const DIS: u8 = 0;
    pub const DIO: u8 = 1;
    pub const DAO: u8 = 2;
    pub const DAO_ACK: u8 = 3;
}

/// Minimum RPL DIO base message length (RFC 6550 Section 6.3.1).
#[cfg(feature = "std")]
const RPL_DIO_BASE_LEN: usize = 24;
/// Minimum RPL DAO base message length (RFC 6550 Section 6.4).
#[cfg(feature = "std")]
const RPL_DAO_BASE_LEN: usize = 4;

/// RPL event returned from handle_frame when RPL messages are processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RplEvent {
    /// No RPL event.
    None,
    /// DIO received, trickle should be reset if inconsistent.
    DioReceived { inconsistent: bool },
    /// DAO received (root only).
    DaoReceived { route_updated: bool },
    /// DAO packet forwarded unchanged in source and payload toward the root.
    DaoForwarded { next_hop: [u8; 16] },
    /// DIS received, should send DIO.
    DisReceived,
}

/// Top-level node state.
#[derive(Debug)]
pub struct Node {
    pub node_id: NodeId,
}

/// Node with integrated RPL router (std only).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct RplNode {
    pub node: Node,
    pub router: Router,
}

impl Node {
    pub fn new(node_id: NodeId) -> Self {
        Self { node_id }
    }

    /// Process a received authenticated L2 SCHC payload.
    ///
    /// Decompresses the frame and dispatches on protocol:
    /// - ICMPv6 Echo Request addressed to this node → builds a SCHC-compressed
    ///   Echo Reply into `reply` as `0x14 || SCHC` and returns the byte count.
    ///
    /// Returns 0 when no reply should be sent.
    ///
    /// `reply` must be at least 259 bytes (dispatch + 2-byte rule header + max ICMPv6 echo).
    pub fn handle_frame(&self, l2_payload: &[u8], reply: &mut [u8]) -> usize {
        if classify_l2_payload(l2_payload) != L2PayloadKind::Schc {
            return 0;
        }
        let mut ipv6 = [0u8; 256];
        let n = match codec::decompress(l2_payload_body(l2_payload), &mut ipv6) {
            Ok(n) => n,
            Err(_) => return 0,
        };

        let mut reply_ipv6 = [0u8; 256];
        let reply_ipv6_len = self.handle_ipv6(&ipv6[..n], &mut reply_ipv6);
        if reply_ipv6_len > 0 {
            wrap_compressed_reply(&reply_ipv6[..reply_ipv6_len], reply)
        } else {
            0
        }
    }

    /// Process a received IPv6 packet directly (no SCHC layer).
    ///
    /// Dispatches on protocol:
    /// - ICMPv6 Echo Request addressed to this node → builds an IPv6
    ///   Echo Reply into `reply` and returns the byte count.
    ///
    /// Returns 0 when no reply should be sent.
    ///
    /// `reply` must be at least 256 bytes.
    pub fn handle_ipv6(&self, ipv6: &[u8], reply: &mut [u8]) -> usize {
        let n = ipv6.len();
        if n < IPV6_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
            return 0;
        }

        let nh = ipv6[6];
        let min_icmpv6_len = IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;
        if nh == next_header::ICMPV6
            && n >= min_icmpv6_len
            && ipv6[IPV6_HEADER_LEN] == icmpv6::ECHO_REQUEST
        {
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&ipv6[field::DST_OFFSET..IPV6_HEADER_LEN]);
            if dst_bytes == self.node_id.link_local_addr().0 {
                return self.reply_echo_ipv6(ipv6, reply);
            }
        }
        0
    }

    fn reply_echo_ipv6(&self, ipv6: &[u8], out: &mut [u8]) -> usize {
        let mut reply_src = [0u8; 16];
        let mut reply_dst = [0u8; 16];
        // Swap src/dst for reply: original dst = our address becomes reply src
        reply_src.copy_from_slice(&ipv6[field::DST_OFFSET..IPV6_HEADER_LEN]);
        reply_dst.copy_from_slice(&ipv6[field::SRC_OFFSET..field::DST_OFFSET]);

        // ICMPv6 echo fields are at IPv6 header + ICMPv6 header offsets
        let icmpv6_start = IPV6_HEADER_LEN;
        let id_offset = icmpv6_start + echo_field::ID_OFFSET;
        let seq_offset = icmpv6_start + echo_field::SEQ_OFFSET;
        let data_offset = icmpv6_start + echo_field::DATA_OFFSET;

        let id = u16::from_be_bytes([ipv6[id_offset], ipv6[id_offset + 1]]);
        let seq = u16::from_be_bytes([ipv6[seq_offset], ipv6[seq_offset + 1]]);
        let data = &ipv6[data_offset..];

        icmpv6::echo_reply(
            &Ipv6Addr(reply_src),
            &Ipv6Addr(reply_dst),
            id,
            seq,
            data,
            out,
        )
    }

    /// Dispatch a UDP payload based on destination port.
    ///
    /// Parses the IPv6/UDP headers and returns the identified application protocol
    /// along with the UDP payload. Use this to route incoming UDP traffic to the
    /// appropriate application handler.
    ///
    /// # Errors
    ///
    /// - `UdpDispatchError::NotUdp` — packet is not UDP (wrong next header, invalid
    ///   IPv6 version, or truncated headers)
    /// - `UdpDispatchError::UnknownPort` — UDP packet but destination port is not a
    ///   recognized application protocol
    /// - `UdpDispatchError::ReservedPort` — port 5684 (CoAPS) is reserved; use OSCORE
    pub fn dispatch_udp<'a>(&self, ipv6: &'a [u8]) -> Result<Dispatched<'a>, UdpDispatchError> {
        let n = ipv6.len();
        if n < IPV6_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
            return Err(UdpDispatchError::NotUdp);
        }

        let nh = ipv6[6];
        if nh != next_header::UDP {
            return Err(UdpDispatchError::NotUdp);
        }

        let min_udp_len = IPV6_HEADER_LEN + UDP_HEADER_LEN;
        if n < min_udp_len {
            return Err(UdpDispatchError::NotUdp);
        }

        let udp_start = IPV6_HEADER_LEN;
        let dst_port = u16::from_be_bytes([ipv6[udp_start + 2], ipv6[udp_start + 3]]);
        let udp_payload = &ipv6[min_udp_len..];

        dispatch_by_port(dst_port, udp_payload).map_err(UdpDispatchError::from)
    }

    /// Get the UDP destination port from an IPv6 packet.
    ///
    /// Returns `None` if not a UDP packet or headers are invalid.
    pub fn udp_dst_port(&self, ipv6: &[u8]) -> Option<u16> {
        let n = ipv6.len();
        if n < IPV6_HEADER_LEN + UDP_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
            return None;
        }
        if ipv6[6] != next_header::UDP {
            return None;
        }
        let udp_start = IPV6_HEADER_LEN;
        Some(u16::from_be_bytes([
            ipv6[udp_start + 2],
            ipv6[udp_start + 3],
        ]))
    }

    /// Get both source and destination UDP ports from an IPv6 packet.
    ///
    /// Returns `None` if not a UDP packet or headers are invalid.
    pub fn udp_ports(&self, ipv6: &[u8]) -> Option<(u16, u16)> {
        let n = ipv6.len();
        if n < IPV6_HEADER_LEN + UDP_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
            return None;
        }
        if ipv6[6] != next_header::UDP {
            return None;
        }
        let udp_start = IPV6_HEADER_LEN;
        let src_port = u16::from_be_bytes([ipv6[udp_start], ipv6[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([ipv6[udp_start + 2], ipv6[udp_start + 3]]);
        Some((src_port, dst_port))
    }
}

#[cfg(feature = "std")]
impl RplNode {
    /// Create a new RPL-enabled node.
    pub fn new(node_id: NodeId, dodag_id: [u8; 16]) -> Self {
        let node_addr = node_id.link_local_addr().0;
        Self {
            node: Node::new(node_id),
            router: Router::new(node_addr, dodag_id),
        }
    }

    /// Create a new RPL-enabled node as DODAG root.
    pub fn new_root(node_id: NodeId) -> Self {
        let node_addr = node_id.link_local_addr().0;
        Self {
            node: Node::new(node_id),
            router: Router::new_root(node_addr),
        }
    }

    /// Process a received authenticated L2 SCHC payload with RPL handling.
    ///
    /// `sender_iid` is the identity established by link-layer signature verification.
    ///
    /// Returns `(output_len, rpl_event)`. For [`RplEvent::DaoForwarded`], send
    /// the output bytes to `next_hop`; otherwise a nonzero output is a reply.
    pub fn handle_frame_rpl(
        &mut self,
        l2_payload: &[u8],
        sender_iid: [u8; 8],
        reply: &mut [u8],
        now_ms: u64,
    ) -> (usize, RplEvent) {
        self.handle_frame_rpl_inner(l2_payload, sender_iid, reply, now_ms, None)
    }

    /// Process an authenticated SCHC payload with measured link quality.
    /// `now_ms` must use one nondecreasing monotonic `u64` timeline.
    pub fn handle_frame_rpl_with_link(
        &mut self,
        l2_payload: &[u8],
        sender_iid: [u8; 8],
        reply: &mut [u8],
        now_ms: u64,
        etx: f32,
        rssi: i8,
    ) -> (usize, RplEvent) {
        self.handle_frame_rpl_inner(l2_payload, sender_iid, reply, now_ms, Some((etx, rssi)))
    }

    fn handle_frame_rpl_inner(
        &mut self,
        l2_payload: &[u8],
        sender_iid: [u8; 8],
        reply: &mut [u8],
        now_ms: u64,
        link: Option<(f32, i8)>,
    ) -> (usize, RplEvent) {
        if classify_l2_payload(l2_payload) != L2PayloadKind::Schc {
            return (0, RplEvent::None);
        }
        let mut ipv6 = [0u8; 256];
        let n = match codec::decompress(l2_payload_body(l2_payload), &mut ipv6) {
            Ok(n) => n,
            Err(_) => return (0, RplEvent::None),
        };
        if n < IPV6_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
            return (0, RplEvent::None);
        }
        let pkt = &ipv6[..n];

        let nh = pkt[6];
        if nh == next_header::ICMPV6 {
            // ICMPv6 - need at least header + type/code/checksum
            let min_icmpv6 = IPV6_HEADER_LEN + hdr_field::BODY_OFFSET;
            if n < min_icmpv6 {
                return (0, RplEvent::None);
            }
            let icmpv6_start = IPV6_HEADER_LEN;
            let icmp_type = pkt[icmpv6_start + hdr_field::TYPE_OFFSET];
            let icmp_code = pkt[icmpv6_start + hdr_field::CODE_OFFSET];

            if icmp_type == icmpv6::ECHO_REQUEST {
                // Handle ping
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&pkt[field::DST_OFFSET..IPV6_HEADER_LEN]);
                if dst_bytes == self.node.node_id.link_local_addr().0 {
                    let mut reply_ipv6 = [0u8; 256];
                    let reply_ipv6_len = self.node.reply_echo_ipv6(pkt, &mut reply_ipv6);
                    let reply_len = wrap_compressed_reply(&reply_ipv6[..reply_ipv6_len], reply);
                    return (reply_len, RplEvent::None);
                }
            } else if icmp_type == RPL_ICMPV6_TYPE {
                // RPL message
                let mut sender_addr = [0u8; 16];
                sender_addr.copy_from_slice(&pkt[field::SRC_OFFSET..field::DST_OFFSET]);
                let body_offset = icmpv6_start + hdr_field::BODY_OFFSET;

                match icmp_code {
                    rpl_code::DIO => {
                        if !source_matches_sender_iid(&sender_addr, &sender_iid) {
                            return (0, RplEvent::None);
                        }
                        if n < body_offset + RPL_DIO_BASE_LEN {
                            return (0, RplEvent::None);
                        }
                        let dio_bytes = &pkt[body_offset..];
                        if let Ok(dio) = lichen_rpl::message::Dio::from_bytes(dio_bytes) {
                            let inconsistent = match link {
                                Some((etx, rssi)) => self.router.process_dio_with_etx(
                                    &dio,
                                    dio_bytes,
                                    sender_addr,
                                    etx,
                                    rssi,
                                    now_ms,
                                ),
                                None => {
                                    self.router
                                        .process_dio(&dio, dio_bytes, sender_addr, 0, now_ms)
                                }
                            };
                            return (0, RplEvent::DioReceived { inconsistent });
                        }
                    }
                    rpl_code::DAO => {
                        if n < body_offset + RPL_DAO_BASE_LEN {
                            return (0, RplEvent::None);
                        }
                        let dao_bytes = &pkt[body_offset..n];
                        let mut dst = [0u8; 16];
                        dst.copy_from_slice(&pkt[field::DST_OFFSET..IPV6_HEADER_LEN]);
                        let Some(advertised_parents) =
                            crate::routing::dao_parents_for_source(dao_bytes, &sender_addr)
                        else {
                            return (0, RplEvent::None);
                        };
                        if dst != self.router.dodag_id()
                            || (advertised_parents.iter().any(|parent| {
                                same_interface(parent, &self.node.node_id.link_local_addr().0)
                            }) && !source_matches_sender_iid(&sender_addr, &sender_iid))
                        {
                            return (0, RplEvent::None);
                        }

                        if self.router.is_root() {
                            if advertised_parents
                                .iter()
                                .any(|parent| !same_interface(parent, &dst))
                                && (!is_ula_or_global(&sender_addr) || !is_ula_or_global(&dst))
                            {
                                return (0, RplEvent::None);
                            }
                            let route_updated = self.router.process_dao_at_ms(
                                dao_bytes,
                                sender_addr,
                                NodeId(sender_iid).link_local_addr().0,
                                now_ms,
                            );
                            return (0, RplEvent::DaoReceived { route_updated });
                        }

                        if !is_ula_or_global(&sender_addr) || !is_ula_or_global(&dst) {
                            return (0, RplEvent::None);
                        }

                        let Some(next_hop) = self.router.preferred_parent() else {
                            return (0, RplEvent::None);
                        };
                        if pkt[7] <= 1 {
                            return (0, RplEvent::None);
                        }

                        ipv6[7] -= 1;
                        let reply_len = wrap_compressed_reply(&ipv6[..n], reply);
                        if reply_len > 0 {
                            return (reply_len, RplEvent::DaoForwarded { next_hop });
                        }
                    }
                    rpl_code::DIS => {
                        if !source_matches_sender_iid(&sender_addr, &sender_iid) {
                            return (0, RplEvent::None);
                        }
                        return (0, RplEvent::DisReceived);
                    }
                    _ => {}
                }
            }
        }

        (0, RplEvent::None)
    }

    /// Build a DIO message for transmission.
    pub fn build_dio(&self, out: &mut [u8]) -> usize {
        self.router.build_dio(out)
    }

    /// Build a DAO message for transmission to parent.
    #[cfg(feature = "std")]
    pub fn build_dao(&mut self) -> std::vec::Vec<u8> {
        self.router.build_dao()
    }

    /// Check if this node is joined to the DODAG.
    pub fn is_joined(&self) -> bool {
        self.router.is_joined()
    }

    /// Check if this node is the DODAG root.
    pub fn is_root(&self) -> bool {
        self.router.is_root()
    }

    /// Get current rank.
    pub fn rank(&self) -> u16 {
        self.router.rank()
    }

    /// Get preferred parent address.
    pub fn preferred_parent(&self) -> Option<[u8; 16]> {
        self.router.preferred_parent()
    }

    /// Handle trickle timer transmit event.
    pub fn trickle_transmit(&mut self) -> bool {
        self.router.trickle_transmit()
    }

    /// Handle trickle timer expiry.
    pub fn trickle_expire(&mut self, now_ms: u64, rand_offset: u32) {
        self.router.trickle_expire(now_ms, rand_offset);
    }

    /// Reset trickle timer on inconsistency.
    pub fn trickle_reset(&mut self, now_ms: u64, rand_offset: u32) {
        self.router.trickle_reset(now_ms, rand_offset);
    }

    /// Start trickle timer.
    pub fn trickle_start(&mut self, now_ms: u64, rand_offset: u32) {
        self.router.trickle_start(now_ms, rand_offset);
    }
}

#[cfg(feature = "std")]
fn source_matches_sender_iid(source: &[u8; 16], sender_iid: &[u8; 8]) -> bool {
    same_interface(source, &NodeId(*sender_iid).link_local_addr().0)
}

#[cfg(feature = "std")]
fn same_interface(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left[8..] == right[8..]
}

#[cfg(feature = "std")]
fn is_ula_or_global(address: &[u8; 16]) -> bool {
    let address = Ipv6Addr(*address);
    address.is_ula() || address.is_gua()
}

fn wrap_compressed_reply(ipv6: &[u8], reply: &mut [u8]) -> usize {
    if reply.is_empty() {
        return 0;
    }
    reply[0] = L2_DISPATCH_SCHC;
    match codec::compress(ipv6, &mut reply[1..]) {
        Ok(n) => n + 1,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_dispatch::{AppProtocol, UdpDispatchError};

    fn node(iid: u8) -> Node {
        Node::new(NodeId([0x02, 0, 0, 0, 0, 0, 0, iid]))
    }

    #[cfg(feature = "std")]
    fn ula(node_id: NodeId) -> [u8; 16] {
        node_id.ula_addr([0xfd, 0, 0, 0, 0, 0, 0, 0]).0
    }

    #[cfg(feature = "std")]
    #[test]
    fn rpl_source_must_match_authenticated_sender() {
        let source = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]).link_local_addr().0;

        assert!(source_matches_sender_iid(
            &source,
            &[0x02, 0, 0, 0, 0, 0, 0, 2]
        ));
        assert!(!source_matches_sender_iid(
            &source,
            &[0x02, 0, 0, 0, 0, 0, 0, 3]
        ));
    }

    #[cfg(feature = "std")]
    fn l2_rpl_packet(
        source: [u8; 16],
        destination: [u8; 16],
        code: u8,
        body: &[u8],
    ) -> std::vec::Vec<u8> {
        let icmpv6_len = hdr_field::BODY_OFFSET + body.len();
        let mut ipv6 = std::vec![0u8; IPV6_HEADER_LEN + icmpv6_len];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        ipv6[6] = next_header::ICMPV6;
        ipv6[7] = 64;
        ipv6[field::SRC_OFFSET..field::DST_OFFSET].copy_from_slice(&source);
        ipv6[field::DST_OFFSET..IPV6_HEADER_LEN].copy_from_slice(&destination);
        ipv6[IPV6_HEADER_LEN] = RPL_ICMPV6_TYPE;
        ipv6[IPV6_HEADER_LEN + 1] = code;
        ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);

        let mut l2 = std::vec![0u8; 260];
        l2[0] = L2_DISPATCH_SCHC;
        let n = codec::compress(&ipv6, &mut l2[1..]).unwrap();
        l2.truncate(n + 1);
        l2
    }

    #[cfg(feature = "std")]
    fn l2_dao_packet(source: [u8; 16], destination: [u8; 16], dao: &[u8]) -> std::vec::Vec<u8> {
        l2_rpl_packet(source, destination, rpl_code::DAO, dao)
    }

    #[cfg(feature = "std")]
    #[test]
    fn measured_link_quality_reaches_rpl_router() {
        const WRAP: u64 = 0x1_0000_0000;
        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let child_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]);
        let root_addr = root_id.link_local_addr().0;
        let child_addr = child_id.link_local_addr().0;
        let mut child = RplNode {
            node: Node::new(child_id),
            router: Router::new(child_addr, root_addr),
        };
        let dio = lichen_rpl::message::Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let mut dio_bytes = [0u8; lichen_rpl::message::Dio::BASE_LEN];
        dio.write_to(&mut dio_bytes).unwrap();
        let packet = l2_rpl_packet(root_addr, child_addr, rpl_code::DIO, &dio_bytes);

        assert_eq!(
            child.handle_frame_rpl_with_link(
                &packet,
                root_id.0,
                &mut [0u8; 260],
                WRAP + 100,
                2.0,
                -70,
            ),
            (0, RplEvent::DioReceived { inconsistent: true })
        );
        assert_eq!(child.router.rank(), 768);
        assert_eq!(
            child.router.poll_trickle(),
            lichen_rpl::trickle::TrickleEvent::Transmit { at_ms: WRAP + 104 }
        );
        let neighbor = child.router.neighbors().iter().next().unwrap();
        assert_eq!(neighbor.etx, 2.0);
        assert_eq!(neighbor.rssi, -70);
        assert_eq!(neighbor.last_seen_ms, WRAP + 100);

        child.handle_frame_rpl(&packet, root_id.0, &mut [0u8; 260], WRAP + 200);
        assert_eq!(child.router.rank(), 768);
        assert_eq!(child.router.neighbors().iter().next().unwrap().etx, 2.0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn leaf_dao_is_forwarded_by_parent_and_processed_by_root() {
        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let parent_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]);
        let leaf_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 3]);
        let root_addr = ula(root_id);
        let parent_addr = ula(parent_id);
        let leaf_addr = ula(leaf_id);
        let mut root = RplNode {
            node: Node::new(root_id),
            router: Router::new_root(root_addr),
        };
        let mut parent = RplNode {
            node: Node::new(parent_id),
            router: Router::new(parent_addr, root_addr),
        };

        let dio = lichen_rpl::message::Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let mut dio_bytes = [0u8; lichen_rpl::message::Dio::BASE_LEN];
        dio.write_to(&mut dio_bytes).unwrap();
        assert!(parent.router.process_dio(&dio, &dio_bytes, root_addr, 0, 0));

        let mut parent_daos =
            lichen_rpl::routing::DaoManager::new(parent_addr, RPL_INSTANCE_ID, root_addr);
        let parent_dao = parent_daos.build_dao(root_addr);
        let parent_packet = l2_dao_packet(parent_addr, root_addr, &parent_dao);
        let mut output = [0u8; 260];
        assert_eq!(
            root.handle_frame_rpl(&parent_packet, parent_id.0, &mut output, 0),
            (
                0,
                RplEvent::DaoReceived {
                    route_updated: true
                }
            )
        );

        let mut leaf_daos =
            lichen_rpl::routing::DaoManager::new(leaf_addr, RPL_INSTANCE_ID, root_addr);
        let leaf_dao = leaf_daos.build_dao(parent_addr);
        let leaf_packet = l2_dao_packet(leaf_addr, root_addr, &leaf_dao);
        assert_eq!(
            parent.handle_frame_rpl(&leaf_packet, [0x02, 0, 0, 0, 0, 0, 0, 4], &mut output, 0,),
            (0, RplEvent::None)
        );
        let (forwarded_len, event) =
            parent.handle_frame_rpl(&leaf_packet, leaf_id.0, &mut output, 0);
        assert_eq!(
            event,
            RplEvent::DaoForwarded {
                next_hop: root_addr
            }
        );

        let mut forwarded_ipv6 = [0u8; 256];
        codec::decompress(
            l2_payload_body(&output[..forwarded_len]),
            &mut forwarded_ipv6,
        )
        .unwrap();
        assert_eq!(
            &forwarded_ipv6[field::SRC_OFFSET..field::DST_OFFSET],
            &leaf_addr
        );
        assert_eq!(forwarded_ipv6[7], 63);

        assert_eq!(
            root.handle_frame_rpl(&output[..forwarded_len], parent_id.0, &mut [0u8; 260], 0,),
            (
                0,
                RplEvent::DaoReceived {
                    route_updated: true
                }
            )
        );
        assert_eq!(
            root.router.lookup_route(&leaf_addr),
            Some([parent_addr, leaf_addr].as_slice())
        );

        let spoofed = l2_dao_packet(parent_addr, root_addr, &leaf_dao);
        assert_eq!(
            root.handle_frame_rpl(&spoofed, parent_id.0, &mut output, 0),
            (0, RplEvent::None)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn production_dao_time_is_seconds_and_expires_routes() {
        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let first_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]);
        let root_addr = ula(root_id);
        let first_addr = ula(first_id);
        let mut root = RplNode {
            node: Node::new(root_id),
            router: Router::new_root(root_addr),
        };
        assert!(root.router.set_dao_lifetime_unit(1));
        let mut first =
            lichen_rpl::routing::DaoManager::new(first_addr, RPL_INSTANCE_ID, root_addr);
        let first_packet = l2_dao_packet(
            first_addr,
            root_addr,
            &first.build_dao_with_lifetime(root_addr, 1),
        );

        assert_eq!(
            root.handle_frame_rpl(&first_packet, first_id.0, &mut [0u8; 260], 1_999),
            (
                0,
                RplEvent::DaoReceived {
                    route_updated: true
                }
            )
        );
        assert!(root.router.lookup_route_at(&first_addr, 2_999).is_some());
        assert_eq!(
            root.handle_frame_rpl(&first_packet, first_id.0, &mut [0u8; 260], 2_999),
            (
                0,
                RplEvent::DaoReceived {
                    route_updated: false
                }
            )
        );
        assert!(root.router.lookup_route(&first_addr).is_some());
        assert!(root.router.lookup_route_at(&first_addr, 3_000).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn link_local_multi_hop_dao_is_not_forwarded() {
        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let parent_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]);
        let leaf_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 3]);
        let root_addr = root_id.link_local_addr().0;
        let parent_addr = parent_id.link_local_addr().0;
        let leaf_addr = leaf_id.link_local_addr().0;
        let mut parent = RplNode::new(parent_id, root_addr);
        let dio = lichen_rpl::message::Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let mut dio_bytes = [0u8; lichen_rpl::message::Dio::BASE_LEN];
        dio.write_to(&mut dio_bytes).unwrap();
        assert!(parent.router.process_dio(&dio, &dio_bytes, root_addr, 0, 0));

        let mut leaf_daos =
            lichen_rpl::routing::DaoManager::new(leaf_addr, RPL_INSTANCE_ID, root_addr);
        let dao = leaf_daos.build_dao(parent_addr);
        let packet = l2_dao_packet(leaf_addr, root_addr, &dao);

        assert_eq!(
            parent.handle_frame_rpl(&packet, leaf_id.0, &mut [0u8; 260], 0),
            (0, RplEvent::None)
        );
    }

    /// Build an L2-wrapped SCHC-compressed ICMPv6 Echo Request from src_iid to dst_iid.
    fn l2_echo_request(src_iid: u8, dst_iid: u8) -> ([u8; 65], usize) {
        let src = NodeId([0x02, 0, 0, 0, 0, 0, 0, src_iid]).link_local_addr();
        let dst = NodeId([0x02, 0, 0, 0, 0, 0, 0, dst_iid]).link_local_addr();
        let mut pkt = [0u8; 52];
        let n = icmpv6::echo_request(&src, &dst, 42, 7, b"ping", &mut pkt);
        let mut out = [0u8; 65];
        out[0] = L2_DISPATCH_SCHC;
        let clen = codec::compress(&pkt[..n], &mut out[1..]).unwrap();
        (out, clen + 1)
    }

    #[test]
    fn echo_request_to_self_yields_reply() {
        let n = node(1);
        let (req, rlen) = l2_echo_request(2, 1); // from node 2 to node 1
        let mut reply = [0u8; 259];
        let len = n.handle_frame(&req[..rlen], &mut reply);
        assert_ne!(len, 0, "expected a reply");
        assert_eq!(reply[0], L2_DISPATCH_SCHC);
        // Verify reply decompresses to a valid Echo Reply
        let mut ipv6 = [0u8; 256];
        let rn = codec::decompress(l2_payload_body(&reply[..len]), &mut ipv6).unwrap();
        assert_eq!(ipv6[40], icmpv6::ECHO_REPLY, "type should be Echo Reply");
        assert_eq!(&ipv6[48..rn], b"ping", "payload should be echoed");
    }

    #[test]
    fn echo_request_to_other_node_yields_no_reply() {
        let n = node(1);
        let (req, rlen) = l2_echo_request(1, 2); // for node 2, not node 1
        let mut reply = [0u8; 259];
        assert_eq!(n.handle_frame(&req[..rlen], &mut reply), 0);
    }

    #[test]
    fn non_icmpv6_frame_yields_no_reply() {
        let n = node(1);
        let mut reply = [0u8; 259];
        // Rule 255 header + garbage: decompressor will return a short packet
        let frame = [L2_DISPATCH_SCHC, 0xffu8, 0x00];
        assert_eq!(n.handle_frame(&frame, &mut reply), 0);
    }

    #[test]
    fn unwrapped_schc_frame_yields_no_reply() {
        let n = node(1);
        let mut reply = [0u8; 259];
        assert_eq!(n.handle_frame(&[0x02, 0x80], &mut reply), 0);
    }

    /// Build a minimal IPv6/UDP packet for testing port dispatch.
    fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> [u8; 128] {
        let mut pkt = [0u8; 128];

        // IPv6 header (40 bytes)
        pkt[0] = 0x60; // Version 6
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        pkt[4] = (udp_len >> 8) as u8;
        pkt[5] = udp_len as u8;
        pkt[6] = next_header::UDP;
        pkt[7] = 64; // hop limit

        // Source address (fe80::1)
        pkt[8] = 0xfe;
        pkt[9] = 0x80;
        pkt[23] = 0x01;

        // Dest address (fe80::2)
        pkt[24] = 0xfe;
        pkt[25] = 0x80;
        pkt[39] = 0x02;

        // UDP header (8 bytes at offset 40)
        pkt[40] = (src_port >> 8) as u8;
        pkt[41] = src_port as u8;
        pkt[42] = (dst_port >> 8) as u8;
        pkt[43] = dst_port as u8;
        pkt[44] = (udp_len >> 8) as u8;
        pkt[45] = udp_len as u8;
        // checksum at 46-47 left as 0

        // UDP payload
        pkt[48..48 + payload.len()].copy_from_slice(payload);

        pkt
    }

    #[test]
    fn dispatch_udp_coap() {
        use lichen_core::constants::PORT_COAP;

        let n = node(1);
        let coap_payload = [0x44, 0x01, 0x00, 0x01, 0xAB]; // GET request
        let pkt = build_udp_packet(PORT_COAP, PORT_COAP, &coap_payload);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + coap_payload.len();

        let dispatched = n.dispatch_udp(&pkt[..pkt_len]).unwrap();
        assert_eq!(dispatched.protocol, AppProtocol::CoAP);
        assert_eq!(dispatched.payload, &coap_payload);
    }

    #[test]
    fn dispatch_udp_mqtt_sn() {
        use lichen_core::constants::PORT_MQTT_SN;

        let n = node(1);
        let mqtt_payload = [0x04, 0x04, 0x00, 0x01]; // CONNECT
        let pkt = build_udp_packet(12345, PORT_MQTT_SN, &mqtt_payload);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + mqtt_payload.len();

        let dispatched = n.dispatch_udp(&pkt[..pkt_len]).unwrap();
        assert_eq!(dispatched.protocol, AppProtocol::MqttSn);
    }

    #[test]
    fn dispatch_udp_compact_cot() {
        use lichen_core::constants::PORT_COMPACT_COT;

        let n = node(1);
        let cot_payload = [0x02, 0x00, 0x00, 0x01]; // PLI subtype
        let pkt = build_udp_packet(PORT_COMPACT_COT, PORT_COMPACT_COT, &cot_payload);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + cot_payload.len();

        let dispatched = n.dispatch_udp(&pkt[..pkt_len]).unwrap();
        assert_eq!(dispatched.protocol, AppProtocol::CompactCot);
    }

    #[test]
    fn dispatch_udp_unknown_port() {
        let n = node(1);
        let pkt = build_udp_packet(8080, 8080, &[0x00]);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + 1;

        let err = n.dispatch_udp(&pkt[..pkt_len]).unwrap_err();
        assert_eq!(err, UdpDispatchError::UnknownPort(8080));
    }

    #[test]
    fn dispatch_udp_reserved_port_5684() {
        let n = node(1);
        let pkt = build_udp_packet(5684, 5684, &[0x00]);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + 1;

        let err = n.dispatch_udp(&pkt[..pkt_len]).unwrap_err();
        assert_eq!(err, UdpDispatchError::ReservedPort);
    }

    #[test]
    fn dispatch_non_udp_returns_not_udp() {
        let n = node(1);
        // ICMPv6 packet (next header = 58)
        let (req, _) = l2_echo_request(2, 1);
        let mut ipv6 = [0u8; 256];
        let ipv6_len = codec::decompress(l2_payload_body(&req), &mut ipv6).unwrap();

        let err = n.dispatch_udp(&ipv6[..ipv6_len]).unwrap_err();
        assert_eq!(err, UdpDispatchError::NotUdp);
    }

    #[test]
    fn udp_ports_extraction() {
        let n = node(1);
        let pkt = build_udp_packet(5683, 10883, &[0x00]);
        let pkt_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + 1;

        let ports = n.udp_ports(&pkt[..pkt_len]);
        assert_eq!(ports, Some((5683, 10883)));

        let dst = n.udp_dst_port(&pkt[..pkt_len]);
        assert_eq!(dst, Some(10883));
    }

    #[test]
    fn udp_ports_non_udp_returns_none() {
        let n = node(1);
        let (req, _) = l2_echo_request(2, 1);
        let mut ipv6 = [0u8; 256];
        let ipv6_len = codec::decompress(l2_payload_body(&req), &mut ipv6).unwrap();

        assert!(n.udp_ports(&ipv6[..ipv6_len]).is_none());
        assert!(n.udp_dst_port(&ipv6[..ipv6_len]).is_none());
    }
}
