//! Node state and receive-path dispatch.

use lichen_core::constants::L2_DISPATCH_SCHC;
#[cfg(feature = "std")]
use lichen_core::constants::{RPL_ICMPV6_TYPE, RPL_INSTANCE_ID};
#[cfg(feature = "std")]
use lichen_core::icmpv6::hdr_field;
use lichen_core::icmpv6::{echo_field, ICMPV6_HEADER_LEN};
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_core::rf_health::RfHealthMetrics;
use lichen_core::udp::UDP_HEADER_LEN;
use lichen_core::{addr::Ipv6Addr, addr::NodeId, icmpv6};
use lichen_schc::codec;

use crate::port_dispatch::{dispatch_by_port, Dispatched, UdpDispatchError};

/// IPv6 version number expected in the first 4 bits of the header.
const IPV6_VERSION: u8 = 6;

#[cfg(feature = "std")]
use crate::routing::{DioProcessOutcome, Router, RplMaintenanceOutcome, TrickleSafeLivenessPolicy};
#[cfg(feature = "std")]
use crate::{
    announce::AnnounceProcessor,
    routing::{DaoProcessError, DaoProcessOutcome, DaoProvisionError, DaoRxState, DaoVerifyError},
};
#[cfg(feature = "std")]
use lichen_hal::NonVolatile;
#[cfg(feature = "std")]
use lichen_ipv6::{icmpv6_checksum, Addr};
#[cfg(feature = "std")]
use lichen_rpl::routing::SignatureVerifiedDao;

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

/// RPL control event from `handle_frame_rpl` / `Gateway::process_rpl`.
/// `PartialEq`/`Eq`/`Debug`/etc. derived for testing and matching. Field
/// names reflect return values from `Router::process_dio`/`process_dao`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RplEvent {
    /// No RPL event.
    None,
    /// DIO received. `inconsistent = true` → trickle reset (version/rank
    /// change detected).
    DioReceived { inconsistent: bool },
    /// DAO received (root only). `route_updated = true` → routing table
    /// was modified.
    DaoReceived { route_updated: bool },
    /// DAO packet forwarded unchanged in source and payload toward the root.
    DaoForwarded { next_hop: [u8; 16] },
    /// DIS received, should send DIO.
    DisReceived,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoHandlingOutcome {
    Applied,
    Duplicate,
    Malformed,
    UnknownKey,
    WrongScope,
    IidMismatch,
    BadSignature,
    Replay,
    Persistence,
    Stale,
    Exhausted,
    Corrupt,
    RouteRejected,
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
    pub(crate) node: Node,
    pub(crate) router: Router,
    pub(crate) rf_health: RfHealthMetrics,
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
            if dst_bytes == self.node_id.link_local_addr().0
                || dst_bytes[0] == 0xfd
                || (dst_bytes[0] & 0xe0) == 0x20
            {
                return self.reply_echo_ipv6(ipv6, reply);
            }
        }
        0
    }

    fn reply_echo_ipv6(&self, ipv6: &[u8], out: &mut [u8]) -> usize {
        let n = ipv6.len();
        if n < IPV6_HEADER_LEN + ICMPV6_HEADER_LEN {
            return 0;
        }
        let mut reply_src = [0u8; 16];
        let mut reply_dst = [0u8; 16];
        reply_src.copy_from_slice(&ipv6[field::DST_OFFSET..IPV6_HEADER_LEN]);
        reply_dst.copy_from_slice(&ipv6[field::SRC_OFFSET..field::DST_OFFSET]);

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
    #[cfg(test)]
    pub(crate) fn new(node_id: NodeId, dodag_id: [u8; 16]) -> Self {
        let node_addr = node_id.link_local_addr().0;
        Self {
            node: Node::new(node_id),
            router: Router::new(node_addr, dodag_id),
            rf_health: RfHealthMetrics::new(),
        }
    }

    /// Provision component-level root routing state.
    ///
    /// This advanced API does not serialize access to `RplNode`, `DaoRxState`, or
    /// storage. The caller must maintain exclusive ownership of all three. Prefer
    /// [`crate::RplStack`] for production ownership and authenticated dispatch.
    pub fn provision_root<S: NonVolatile>(
        node_id: NodeId,
        storage: &mut S,
    ) -> Result<(Self, DaoRxState), DaoProvisionError<S::Error>> {
        let node_addr = node_id.link_local_addr().0;
        let (router, state) = Router::provision_root(storage, node_addr)?;
        Ok((
            Self {
                node: Node::new(node_id),
                router,
                rf_health: RfHealthMetrics::new(),
            },
            state,
        ))
    }

    /// Open previously provisioned component-level root routing state.
    ///
    /// This advanced API does not serialize access to `RplNode`, `DaoRxState`, or
    /// storage. The caller must maintain exclusive ownership of all three. Prefer
    /// [`crate::RplStack`] for production ownership and authenticated dispatch.
    pub fn open_root<S: NonVolatile>(
        node_id: NodeId,
        storage: &S,
    ) -> Result<(Self, DaoRxState), crate::routing::DaoPersistentOpenError<S::Error>> {
        let node_addr = node_id.link_local_addr().0;
        let (router, state) = Router::open_root(storage, node_addr)?;
        Ok((
            Self {
                node: Node::new(node_id),
                router,
                rf_health: RfHealthMetrics::new(),
            },
            state,
        ))
    }

    /// Verify and apply a DAO received from an authenticated immediate sender.
    ///
    /// `authenticated_sender_iid` **must** be the IID established by link-layer
    /// authentication for the immediate sender of this packet. It is not an IID
    /// claimed by the DAO payload and must never be inferred from `origin`.
    ///
    /// This advanced component API does not serialize ownership of this node,
    /// `rx_state`, or `storage`; the caller must provide exclusive access to all
    /// three for the entire operation. Prefer [`crate::RplStack`] for production
    /// ownership, link authentication, and packet dispatch.
    #[allow(
        clippy::too_many_arguments,
        reason = "security-critical identity and caller-owned state remain explicit"
    )]
    pub fn handle_dao<S: NonVolatile>(
        &mut self,
        dao_bytes: &[u8],
        origin: [u8; 16],
        authenticated_sender_iid: [u8; 8],
        announces: &AnnounceProcessor,
        rx_state: &mut DaoRxState,
        storage: &mut S,
        now_ms: u64,
    ) -> DaoHandlingOutcome {
        let iid = origin[8..].try_into().expect("IPv6 IID is eight bytes");
        let verified = match SignatureVerifiedDao::verify_signature(
            dao_bytes,
            origin,
            RPL_INSTANCE_ID,
            self.router.dodag_id(),
            announces.pinned_pubkey_for(&iid),
        ) {
            Ok(verified) => verified,
            Err(DaoVerifyError::Malformed(_)) => return DaoHandlingOutcome::Malformed,
            Err(DaoVerifyError::UnknownKey) => return DaoHandlingOutcome::UnknownKey,
            Err(DaoVerifyError::WrongInstance | DaoVerifyError::WrongDodag) => {
                return DaoHandlingOutcome::WrongScope
            }
            Err(DaoVerifyError::IidMismatch) => return DaoHandlingOutcome::IidMismatch,
            Err(DaoVerifyError::BadSignature) => return DaoHandlingOutcome::BadSignature,
        };
        match self.router.process_signature_verified_dao_from_at_ms(
            &verified,
            authenticated_sender_iid,
            rx_state,
            storage,
            now_ms,
        ) {
            Ok(DaoProcessOutcome::Applied) => DaoHandlingOutcome::Applied,
            Ok(DaoProcessOutcome::Duplicate) => DaoHandlingOutcome::Duplicate,
            Err(DaoProcessError::Replay) => DaoHandlingOutcome::Replay,
            Err(DaoProcessError::Persistence(_)) => DaoHandlingOutcome::Persistence,
            Err(DaoProcessError::Stale) => DaoHandlingOutcome::Stale,
            Err(DaoProcessError::Exhausted) => DaoHandlingOutcome::Exhausted,
            Err(DaoProcessError::Corrupt) => DaoHandlingOutcome::Corrupt,
            Err(DaoProcessError::RouteRejected) => DaoHandlingOutcome::RouteRejected,
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

        if is_rpl_ipv6(pkt) && !valid_rpl_ipv6(pkt) {
            return (0, RplEvent::None);
        }

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
                if dst_bytes == self.node.node_id.link_local_addr().0
                    || dst_bytes[0] == 0xfd
                    || (dst_bytes[0] & 0xe0) == 0x20
                {
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
                            let outcome = match link {
                                Some((etx, rssi)) => {
                                    self.rf_health.record_rx(rssi);
                                    self.rf_health.record_density(self.router.neighbors().count() as u8);
                                    self.router.process_dio_with_etx_outcome(
                                        &dio,
                                        dio_bytes,
                                        sender_addr,
                                        etx,
                                        rssi,
                                        now_ms,
                                    )
                                }
                                None => {
                                    self.rf_health.record_rx(0);
                                    self.rf_health.record_density(self.router.neighbors().count() as u8);
                                    self.router.process_dio_outcome(
                                        &dio,
                                        dio_bytes,
                                        sender_addr,
                                        0,
                                        now_ms,
                                    )
                                }
                            };
                            return match outcome {
                                DioProcessOutcome::Rejected => (0, RplEvent::None),
                                DioProcessOutcome::Consistent => {
                                    self.router.trickle_consistent();
                                    (
                                        0,
                                        RplEvent::DioReceived {
                                            inconsistent: false,
                                        },
                                    )
                                }
                                DioProcessOutcome::Inconsistent => {
                                    (0, RplEvent::DioReceived { inconsistent: true })
                                }
                            };
                        }
                    }
                    rpl_code::DAO => {
                        if n < body_offset + RPL_DAO_BASE_LEN {
                            return (0, RplEvent::None);
                        }
                        let dao_bytes = &pkt[body_offset..n];
                        let mut dst = [0u8; 16];
                        dst.copy_from_slice(&pkt[field::DST_OFFSET..IPV6_HEADER_LEN]);
                        if dst != self.router.dodag_id() {
                            return (0, RplEvent::None);
                        }
                        if self.router.is_root() {
                            return (0, RplEvent::DaoReceived);
                        }
                        let Some(advertised_parents) =
                            crate::routing::dao_parents_for_source(dao_bytes, &sender_addr)
                        else {
                            return (0, RplEvent::None);
                        };
                        if advertised_parents.iter().any(|parent| {
                            same_interface(parent, &self.node.node_id.link_local_addr().0)
                        }) && !source_matches_sender_iid(&sender_addr, &sender_iid)
                        {
                            return (0, RplEvent::None);
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

    /// Build one signed logical DAO after durably reserving its origin sequence.
    /// Retain the returned bytes unchanged for retransmission.
    pub(crate) fn build_signed_dao<S: NonVolatile>(
        &mut self,
        origin_ipv6: [u8; 16],
        tx_state: &mut crate::routing::DaoTxState,
        storage: &mut S,
        link: &lichen_link::link_layer::LinkLayer,
    ) -> Result<std::vec::Vec<u8>, crate::routing::DaoTxError<S::Error>> {
        self.router
            .build_signed_dao(origin_ipv6, tx_state, storage, link)
    }

    /// Check if this node is joined to the DODAG.
    pub fn is_joined(&self) -> bool {
        self.router.is_joined()
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub fn rf_health_mut(&mut self) -> &mut RfHealthMetrics {
        &mut self.rf_health
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

    /// Run DAO-route and neighbor maintenance from one monotonic observation.
    pub fn maintain<P: TrickleSafeLivenessPolicy>(
        &mut self,
        now_ms: u64,
        neighbor_timeout_ms: u64,
        policy: &P,
    ) -> RplMaintenanceOutcome {
        self.router.maintain(now_ms, neighbor_timeout_ms, policy)
    }

    /// Return the current Trickle deadline without advancing it.
    pub fn poll_trickle(&self) -> lichen_rpl::trickle::TrickleEvent {
        self.router.poll_trickle()
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
    source[8..] == *sender_iid
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

#[cfg(feature = "std")]
pub(crate) fn is_rpl_ipv6(ipv6: &[u8]) -> bool {
    ipv6.len() >= IPV6_HEADER_LEN + hdr_field::BODY_OFFSET
        && ipv6[0] >> 4 == IPV6_VERSION
        && ipv6[6] == next_header::ICMPV6
        && ipv6[IPV6_HEADER_LEN + hdr_field::TYPE_OFFSET] == RPL_ICMPV6_TYPE
}

#[cfg(feature = "std")]
pub(crate) fn claims_rpl_ipv6(ipv6: &[u8]) -> bool {
    ipv6.len() > IPV6_HEADER_LEN
        && ipv6.len() > 6
        && ipv6[6] == next_header::ICMPV6
        && ipv6[IPV6_HEADER_LEN] == RPL_ICMPV6_TYPE
}

#[cfg(feature = "std")]
pub(crate) fn valid_ipv6_envelope(ipv6: &[u8]) -> bool {
    if ipv6.len() < IPV6_HEADER_LEN || ipv6[0] >> 4 != IPV6_VERSION {
        return false;
    }
    let payload_len = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    IPV6_HEADER_LEN.checked_add(payload_len) == Some(ipv6.len())
}

#[cfg(feature = "std")]
pub(crate) fn valid_rpl_ipv6(ipv6: &[u8]) -> bool {
    if !is_rpl_ipv6(ipv6) {
        return false;
    }
    if !valid_ipv6_envelope(ipv6) {
        return false;
    }
    let src = Addr(
        ipv6[field::SRC_OFFSET..field::DST_OFFSET]
            .try_into()
            .unwrap(),
    );
    let dst = Addr(ipv6[field::DST_OFFSET..IPV6_HEADER_LEN].try_into().unwrap());
    let icmpv6 = &ipv6[IPV6_HEADER_LEN..];
    let received = u16::from_be_bytes([icmpv6[2], icmpv6[3]]);
    icmpv6_checksum(&src, &dst, icmpv6).is_ok_and(|computed| computed == received)
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
    fn address_iid(address: [u8; 16]) -> [u8; 8] {
        address[8..].try_into().unwrap()
    }

    #[cfg(feature = "std")]
    #[test]
    fn rpl_source_must_match_authenticated_sender() {
        let source = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]).link_local_addr().0;
        let source_iid: [u8; 8] = source[8..].try_into().unwrap();

        assert!(source_matches_sender_iid(&source, &source_iid));
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
        let checksum =
            icmpv6_checksum(&Addr(source), &Addr(destination), &ipv6[IPV6_HEADER_LEN..]).unwrap();
        ipv6[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());

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
            rf_health: RfHealthMetrics::new(),
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
                address_iid(root_addr),
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

        child.handle_frame_rpl(&packet, address_iid(root_addr), &mut [0u8; 260], WRAP + 200);
        assert_eq!(child.router.rank(), 768);
        assert_eq!(child.router.neighbors().iter().next().unwrap().etx, 2.0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn only_valid_consistent_dios_increment_trickle_redundancy() {
        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let root_addr = root_id.link_local_addr().0;
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

        let make_child = |last: u8| {
            let child_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, last]);
            let child_addr = child_id.link_local_addr().0;
            (
                RplNode {
                    node: Node::new(child_id),
                    router: Router::new(child_addr, root_addr),
                    rf_health: RfHealthMetrics::new(),
                },
                child_addr,
            )
        };
        let (mut suppressed, suppressed_addr) = make_child(2);
        let packet = l2_rpl_packet(root_addr, suppressed_addr, rpl_code::DIO, &dio_bytes);
        assert_eq!(
            suppressed.handle_frame_rpl(&packet, address_iid(root_addr), &mut [0u8; 260], 100,),
            (0, RplEvent::DioReceived { inconsistent: true })
        );
        for now_ms in 101..111 {
            assert_eq!(
                suppressed.handle_frame_rpl(
                    &packet,
                    address_iid(root_addr),
                    &mut [0u8; 260],
                    now_ms,
                ),
                (
                    0,
                    RplEvent::DioReceived {
                        inconsistent: false
                    }
                )
            );
        }
        assert!(!suppressed.trickle_transmit());

        let (mut unsuppressed, unsuppressed_addr) = make_child(3);
        let packet = l2_rpl_packet(root_addr, unsuppressed_addr, rpl_code::DIO, &dio_bytes);
        assert!(matches!(
            unsuppressed.handle_frame_rpl(&packet, address_iid(root_addr), &mut [0u8; 260], 100,),
            (0, RplEvent::DioReceived { inconsistent: true })
        ));
        let mut foreign = dio;
        foreign.rpl_instance_id ^= 1;
        foreign.write_to(&mut dio_bytes).unwrap();
        let foreign_packet = l2_rpl_packet(root_addr, unsuppressed_addr, rpl_code::DIO, &dio_bytes);
        for now_ms in 101..111 {
            assert_eq!(
                unsuppressed.handle_frame_rpl(
                    &foreign_packet,
                    address_iid(root_addr),
                    &mut [0u8; 260],
                    now_ms,
                ),
                (0, RplEvent::None)
            );
        }
        assert!(unsuppressed.trickle_transmit());
    }

    #[cfg(feature = "std")]
    #[test]
    fn leaf_dao_is_forwarded_by_parent_and_processed_by_root() {
        use crate::{announce::AnnounceProcessor, gradient::GradientTable};
        use lichen_hal::storage::mem::MemStorage;
        use lichen_link::{identity::Identity, keys::Seed, link_layer::LinkLayer};

        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let parent_identity = Identity::from_seed(Seed::new([2; 32]));
        let leaf_identity = Identity::from_seed(Seed::new([3; 32]));
        let mut parent_eui64 = parent_identity.iid;
        parent_eui64[0] ^= 0x02;
        let mut leaf_eui64 = leaf_identity.iid;
        leaf_eui64[0] ^= 0x02;
        let parent_id = NodeId(parent_eui64);
        let leaf_id = NodeId(leaf_eui64);
        let root_addr = ula(root_id);
        let parent_addr = ula(parent_id);
        let leaf_addr = ula(leaf_id);
        let mut root_storage = MemStorage::new();
        let (root_router, mut root_rx) =
            Router::provision_root(&mut root_storage, root_addr).unwrap();
        let mut root = RplNode {
            node: Node::new(root_id),
            router: root_router,
            rf_health: RfHealthMetrics::new(),
        };
        let mut parent = RplNode {
            node: Node::new(parent_id),
            router: Router::new(parent_addr, root_addr),
            rf_health: RfHealthMetrics::new(),
        };
        let mut leaf = RplNode {
            node: Node::new(leaf_id),
            router: Router::new(leaf_addr, root_addr),
            rf_health: RfHealthMetrics::new(),
        };
        let mut announces = AnnounceProcessor::new(
            GradientTable::new(crate::announce::MAX_TRACKED_ORIGINATORS),
            root_addr[..8].try_into().unwrap(),
        );
        announces.pin_for_test(parent_identity.pubkey);
        announces.pin_for_test(leaf_identity.pubkey);

        let root_dio = lichen_rpl::message::Dio {
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
        root_dio.write_to(&mut dio_bytes).unwrap();
        assert!(parent
            .router
            .process_dio(&root_dio, &dio_bytes, root_addr, 0, 0));
        let parent_dio = lichen_rpl::message::Dio {
            rank: parent.router.rank(),
            ..root_dio
        };
        parent_dio.write_to(&mut dio_bytes).unwrap();
        assert!(leaf
            .router
            .process_dio(&parent_dio, &dio_bytes, parent_addr, 0, 0));

        let mut parent_storage = MemStorage::new();
        let mut parent_tx = crate::routing::DaoTxState::provision(
            &mut parent_storage,
            parent_identity.pubkey,
            parent_addr,
            RPL_INSTANCE_ID,
            root_addr,
        )
        .unwrap();
        let parent_dao = parent
            .build_signed_dao(
                parent_addr,
                &mut parent_tx,
                &mut parent_storage,
                &LinkLayer::new(parent_identity.clone()),
            )
            .unwrap();
        let parent_packet = l2_dao_packet(parent_addr, root_addr, &parent_dao);
        let mut output = [0u8; 260];
        assert_eq!(
            root.handle_frame_rpl(&parent_packet, parent_identity.iid, &mut output, 0),
            (0, RplEvent::DaoReceived)
        );
        assert_eq!(
            root.handle_dao(
                &parent_dao,
                parent_addr,
                parent_identity.iid,
                &announces,
                &mut root_rx,
                &mut root_storage,
                0,
            ),
            DaoHandlingOutcome::Applied
        );

        let mut leaf_storage = MemStorage::new();
        let mut leaf_tx = crate::routing::DaoTxState::provision(
            &mut leaf_storage,
            leaf_identity.pubkey,
            leaf_addr,
            RPL_INSTANCE_ID,
            root_addr,
        )
        .unwrap();
        let leaf_dao = leaf
            .build_signed_dao(
                leaf_addr,
                &mut leaf_tx,
                &mut leaf_storage,
                &LinkLayer::new(leaf_identity.clone()),
            )
            .unwrap();
        let leaf_packet = l2_dao_packet(leaf_addr, root_addr, &leaf_dao);
        assert_eq!(
            parent.handle_frame_rpl(&leaf_packet, [0x02, 0, 0, 0, 0, 0, 0, 4], &mut output, 0,),
            (0, RplEvent::None)
        );
        let (forwarded_len, event) =
            parent.handle_frame_rpl(&leaf_packet, leaf_identity.iid, &mut output, 0);
        assert_eq!(
            event,
            RplEvent::DaoForwarded {
                next_hop: root_addr
            }
        );

        let mut forwarded_ipv6 = [0u8; 256];
        let forwarded_n = codec::decompress(
            l2_payload_body(&output[..forwarded_len]),
            &mut forwarded_ipv6,
        )
        .unwrap();
        assert_eq!(
            &forwarded_ipv6[field::SRC_OFFSET..field::DST_OFFSET],
            &leaf_addr
        );
        assert_eq!(forwarded_ipv6[7], 63);
        let body_offset = IPV6_HEADER_LEN + hdr_field::BODY_OFFSET;
        let forwarded_dao = &forwarded_ipv6[body_offset..forwarded_n];
        assert_eq!(forwarded_dao, leaf_dao);
        assert!(parent.router.lookup_route(&leaf_addr).is_none());

        assert_eq!(
            root.handle_frame_rpl(
                &output[..forwarded_len],
                parent_identity.iid,
                &mut [0u8; 260],
                0,
            ),
            (0, RplEvent::DaoReceived)
        );
        assert!(root.router.lookup_route(&leaf_addr).is_none());

        let mut tampered = forwarded_dao.to_vec();
        tampered[3] ^= 1;
        assert_eq!(
            root.handle_dao(
                &tampered,
                leaf_addr,
                parent_identity.iid,
                &announces,
                &mut root_rx,
                &mut root_storage,
                0,
            ),
            DaoHandlingOutcome::BadSignature
        );
        assert!(root.router.lookup_route(&leaf_addr).is_none());
        assert_eq!(
            root.handle_dao(
                forwarded_dao,
                leaf_addr,
                parent_identity.iid,
                &announces,
                &mut root_rx,
                &mut root_storage,
                0,
            ),
            DaoHandlingOutcome::Applied
        );
        assert_eq!(
            root.router.lookup_route(&leaf_addr),
            Some([parent_addr, leaf_addr].as_slice())
        );
        assert_eq!(
            root.handle_dao(
                forwarded_dao,
                leaf_addr,
                parent_identity.iid,
                &announces,
                &mut root_rx,
                &mut root_storage,
                0,
            ),
            DaoHandlingOutcome::Duplicate
        );
        assert_eq!(
            root.router.lookup_route(&leaf_addr),
            Some([parent_addr, leaf_addr].as_slice())
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn production_signed_dao_cannot_mutate_equal_path_sequence() {
        use crate::{announce::AnnounceProcessor, gradient::GradientTable};
        use lichen_hal::storage::mem::MemStorage;
        use lichen_link::{identity::Identity, keys::Seed, link_layer::LinkLayer};

        let root_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let root_addr = ula(root_id);
        let identity = Identity::from_seed(Seed::new([0x36; 32]));
        let mut origin = root_addr;
        origin[8..].copy_from_slice(&identity.iid);
        let mut storage = MemStorage::new();
        let (router, mut rx_state) = Router::provision_root(&mut storage, root_addr).unwrap();
        let mut root = RplNode {
            node: Node::new(root_id),
            router,
            rf_health: RfHealthMetrics::new(),
        };
        assert!(root.router.set_dao_lifetime_unit(1));
        let mut announces = AnnounceProcessor::new(
            GradientTable::new(crate::announce::MAX_TRACKED_ORIGINATORS),
            root_addr[..8].try_into().unwrap(),
        );
        announces.pin_for_test(identity.pubkey);
        let link = LinkLayer::new(identity.clone());
        let sign = |unsigned: &[u8], origin_sequence: u64| {
            let digest =
                crate::routing::dao_origin_digest(origin, root_addr, origin_sequence, unsigned);
            let signature = link.sign_digest(&digest);
            let mut wire = unsigned.to_vec();
            let offset = wire.len();
            wire.resize(offset + lichen_rpl::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
            lichen_rpl::message::DaoOriginSignature::write_to(
                origin_sequence,
                &signature,
                &mut wire[offset..],
            )
            .unwrap();
            wire
        };
        let mut sender = lichen_rpl::routing::DaoManager::new(origin, RPL_INSTANCE_ID, root_addr);
        let first_unsigned = sender.build_dao_with_lifetime(root_addr, 10);
        let first = sign(&first_unsigned, 1);
        assert_eq!(
            root.handle_dao(
                &first,
                origin,
                identity.iid,
                &announces,
                &mut rx_state,
                &mut storage,
                100_000,
            ),
            DaoHandlingOutcome::Applied
        );
        let route = root.router.lookup_route(&origin).unwrap().to_vec();

        let mut changed_lifetime = first_unsigned;
        let lifetime_index = changed_lifetime.len() - 17;
        changed_lifetime[lifetime_index] = 20;
        let changed_lifetime = sign(&changed_lifetime, 2);
        assert_eq!(
            root.handle_dao(
                &changed_lifetime,
                origin,
                identity.iid,
                &announces,
                &mut rx_state,
                &mut storage,
                101_000,
            ),
            DaoHandlingOutcome::RouteRejected
        );
        assert_eq!(root.router.lookup_route(&origin), Some(route.as_slice()));
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
            rf_health: RfHealthMetrics::new(),
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
            root.handle_frame_rpl(
                &first_packet,
                address_iid(first_addr),
                &mut [0u8; 260],
                1_999,
            ),
            (0, RplEvent::DaoReceived)
        );
        assert!(root.router.lookup_route_at(&first_addr, 2_999).is_none());
        assert_eq!(
            root.handle_frame_rpl(
                &first_packet,
                address_iid(first_addr),
                &mut [0u8; 260],
                2_999,
            ),
            (0, RplEvent::DaoReceived)
        );
        assert!(root.router.lookup_route(&first_addr).is_none());
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
            parent.handle_frame_rpl(&packet, address_iid(leaf_addr), &mut [0u8; 260], 0),
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

    #[test]
    fn rpl_event_derives_partialeq_eq_debug_clone_copy() {
        use super::RplEvent;
        assert_eq!(RplEvent::None, RplEvent::None);
        assert_eq!(RplEvent::DisReceived, RplEvent::DisReceived);

        let dio_inc = RplEvent::DioReceived { inconsistent: true };
        let dio_cons = RplEvent::DioReceived { inconsistent: false };
        assert_eq!(dio_inc, dio_inc);
        assert_ne!(dio_inc, dio_cons);
        assert_ne!(dio_inc, RplEvent::None);

        let dao_up = RplEvent::DaoReceived { route_updated: true };
        let dao_no = RplEvent::DaoReceived { route_updated: false };
        assert_eq!(dao_up, dao_up);
        assert_ne!(dao_up, dao_no);

        // Exercises Clone/Copy
        let copied = dao_up; // Copy
        assert_eq!(copied, dao_up);
        let cloned = dao_up.clone();
        assert_eq!(cloned, dao_up);

        // Exercises Debug
        let _ = format!("{:?}", dio_inc);
        let _ = format!("{:?}", dao_up);
    }
}
