//! Node state and receive-path dispatch.

use lichen_core::constants::L2_DISPATCH_SCHC;
#[cfg(feature = "std")]
use lichen_core::constants::RPL_ICMPV6_TYPE;
#[cfg(feature = "std")]
use lichen_core::icmpv6::hdr_field;
use lichen_core::icmpv6::{echo_field, ICMPV6_HEADER_LEN};
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_core::{addr::Ipv6Addr, addr::NodeId, icmpv6};
use lichen_schc::codec;

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
const RPL_DAO_BASE_LEN: usize = 20;

/// RPL event returned from handle_frame when RPL messages are processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RplEvent {
    /// No RPL event.
    None,
    /// DIO received, trickle should be reset if inconsistent.
    DioReceived { inconsistent: bool },
    /// DAO received (root only).
    DaoReceived { route_updated: bool },
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
    /// Returns (reply_len, rpl_event). reply_len > 0 means a reply should be sent.
    pub fn handle_frame_rpl(
        &mut self,
        l2_payload: &[u8],
        reply: &mut [u8],
        now_ms: u32,
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
                        if n < body_offset + RPL_DIO_BASE_LEN {
                            return (0, RplEvent::None);
                        }
                        let dio_bytes = &pkt[body_offset..];
                        if let Ok(dio) = lichen_rpl::message::Dio::from_bytes(dio_bytes) {
                            // ponytail: use 0 for rssi, real radio would provide it
                            let inconsistent =
                                self.router.process_dio(&dio, sender_addr, 0, now_ms);
                            return (0, RplEvent::DioReceived { inconsistent });
                        }
                    }
                    rpl_code::DAO => {
                        if n < body_offset + RPL_DAO_BASE_LEN {
                            return (0, RplEvent::None);
                        }
                        let dao_bytes = &pkt[body_offset..n];
                        let route_updated = self.router.process_dao(dao_bytes);
                        return (0, RplEvent::DaoReceived { route_updated });
                    }
                    rpl_code::DIS => {
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
    pub fn trickle_expire(&mut self, now_ms: u32, rand_offset: u32) {
        self.router.trickle_expire(now_ms, rand_offset);
    }

    /// Reset trickle timer on inconsistency.
    pub fn trickle_reset(&mut self, now_ms: u32, rand_offset: u32) {
        self.router.trickle_reset(now_ms, rand_offset);
    }

    /// Start trickle timer.
    pub fn trickle_start(&mut self, now_ms: u32, rand_offset: u32) {
        self.router.trickle_start(now_ms, rand_offset);
    }
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

    fn node(iid: u8) -> Node {
        Node::new(NodeId([0x02, 0, 0, 0, 0, 0, 0, iid]))
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
}
