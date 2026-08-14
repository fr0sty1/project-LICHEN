// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Packet receive and dispatch logic.

use std::vec;
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::constants::L2_DISPATCH_ROUTING;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_hal::{NonVolatile, Radio};
use lichen_ipv6::Ipv6Header;
use lichen_link::identity::iid_from_pubkey;
use lichen_link::link_layer::{AuthenticatedFrame, LinkRxError};
use lichen_schc::codec;

use crate::announce::AnnounceRejectReason;
use crate::node::{
    claims_rpl_ipv6, is_rpl_ipv6, rpl_code, valid_ipv6_envelope, valid_rpl_ipv6,
    DaoHandlingOutcome, RplEvent,
};
use crate::secure::secure_datagram_from_received;
use crate::stack::{ReceivedIpv6, RxError, MAX_FRAME_SIZE};

use super::error::RplReceiveError;
use super::util::{
    advance_rpl_source_route, bootstrap_announce_peer, dao_parts, dio_dis_destination_is_allowed,
    eui64_link_local, ipv6_eui64, link_local_from_iid, multicast_dis_jitter, routing_announce,
    rpl_ipv6_multicast_is_allowed, wire_is_for_local,
};
use super::{RplReceiveOutcome, RplRole, RplStack};

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    /// Receive using a caller-provided packet-processing timestamp.
    ///
    /// The timestamp must be sampled after the radio wait. Production loops
    /// should prefer [`Self::runtime_receive`], which enforces that ordering.
    pub async fn receive(
        &mut self,
        timeout_ms: u32,
        now_ms: u64,
    ) -> Result<Option<RplReceiveOutcome>, RplReceiveError> {
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let channel = self.stack.channel();
        let packet = self
            .stack
            .radio()
            .receive(channel, &mut wire, timeout_ms)
            .await
            .map_err(|_| RplReceiveError::Receive(RxError::RadioRx))?;
        let Some(packet) = packet else {
            return Ok(None);
        };
        if packet.len > wire.len() {
            return Err(RplReceiveError::Receive(RxError::RadioPacketTooLarge));
        }
        self.process_received(&wire[..packet.len], packet, now_ms)
            .await
    }

    pub(crate) async fn process_received(
        &mut self,
        wire: &[u8],
        packet: lichen_hal::RxPacket,
        now_ms: u64,
    ) -> Result<Option<RplReceiveOutcome>, RplReceiveError> {
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        let now_ms = self.routing_now_ms;
        if !wire_is_for_local(wire, self.stack.node_id().0)
            .map_err(|error| RplReceiveError::Receive(RxError::Link(error)))?
        {
            return Ok(None);
        }
        let (frame, bootstrapped) = match self.stack.link().receive_frame(wire) {
            Ok(frame) => (frame, false),
            Err(LinkRxError::UnknownSender) => {
                let peer = bootstrap_announce_peer(wire).ok_or(RplReceiveError::Receive(
                    RxError::Link(LinkRxError::UnknownSender),
                ))?;
                if !matches!(
                    self.stack.link().peer_auth_state(&peer.iid),
                    lichen_link::link_layer::PeerAuthState::Unknown
                ) {
                    return Err(RplReceiveError::Receive(RxError::Link(
                        LinkRxError::KeyChange,
                    )));
                }
                self.stack.add_peer(peer.clone());
                match self.stack.link().receive_frame(wire) {
                    Ok(frame) => (frame, true),
                    Err(error) => {
                        self.stack.link().forget_peer(&peer.iid);
                        return Err(RplReceiveError::Receive(RxError::Link(error)));
                    }
                }
            }
            Err(error) => return Err(RplReceiveError::Receive(RxError::Link(error))),
        };
        self.direct_neighbors.insert(frame.sender.iid);

        match classify_l2_payload(&frame.payload) {
            L2PayloadKind::Routing => self
                .process_announce(frame, bootstrapped, now_ms)
                .await
                .map(Some),
            L2PayloadKind::Schc => {
                let mut ipv6 = vec![0u8; 256];
                let len = codec::decompress(l2_payload_body(&frame.payload), &mut ipv6)
                    .map_err(|_| RplReceiveError::Receive(RxError::SchcDecompress))?;
                ipv6.truncate(len);
                let claims_rpl = claims_rpl_ipv6(&ipv6);
                if !valid_ipv6_envelope(&ipv6) {
                    return if claims_rpl {
                        Ok(Some(RplReceiveOutcome::RplRejected))
                    } else {
                        Err(RplReceiveError::Receive(RxError::SchcDecompress))
                    };
                }
                if claims_rpl && !is_rpl_ipv6(&ipv6) {
                    return Ok(Some(RplReceiveOutcome::RplRejected));
                }
                let received = ReceivedIpv6 {
                    ipv6,
                    sender_iid: frame.sender.iid,
                    rssi: packet.rssi,
                    snr: packet.snr,
                };
                if !is_rpl_ipv6(&received.ipv6) {
                    let header = Ipv6Header::from_bytes(&received.ipv6)
                        .map_err(|_| RplReceiveError::Receive(RxError::SchcDecompress))?;
                    secure_datagram_from_received(&received).map_err(RplReceiveError::Receive)?;
                    if header.next_header == 43 {
                        return self.process_source_route(received, frame.sender.iid).await;
                    }
                    let local_link_addr = self.stack.local_addr().0;
                    if header.dst.0 != self.local_rpl_addr
                        && header.dst.0 != local_link_addr
                        && header.dst.0[0] != 0xff
                    {
                        if header.dst.0[0] == 0xfe && header.dst.0[1] & 0xc0 == 0x80 {
                            return Ok(None);
                        }
                        let from_parent = self
                            .rpl
                            .preferred_parent()
                            .is_some_and(|parent| parent[8..] == frame.sender.iid);
                        let next_hop = self
                            .route_for(header.dst.0, now_ms, from_parent)
                            .map(|route| route.next_hop)
                            .ok_or(RplReceiveError::Transmit(crate::stack::TxError::NoRoute))?;
                        if next_hop == ipv6_eui64(link_local_from_iid(frame.sender.iid)) {
                            return Err(RplReceiveError::Receive(RxError::InvalidSourceRoute));
                        }
                        let mut forwarded = received.ipv6;
                        if forwarded[7] <= 1 {
                            return Err(RplReceiveError::Receive(RxError::HopLimitExceeded));
                        }
                        forwarded[7] -= 1;
                        self.stack
                            .send_ipv6_to(&forwarded, &next_hop)
                            .await
                            .map_err(RplReceiveError::Transmit)?;
                        return Ok(Some(RplReceiveOutcome::Forwarded {
                            next_hop: eui64_link_local(next_hop),
                        }));
                    }
                    return Ok(Some(RplReceiveOutcome::DeliveredIpv6(received)));
                }
                if !rpl_ipv6_multicast_is_allowed(&received.ipv6) {
                    return Ok(None);
                }
                if !valid_rpl_ipv6(&received.ipv6) {
                    return Ok(Some(RplReceiveOutcome::RplRejected));
                }
                if !dio_dis_destination_is_allowed(&received.ipv6, self.local_rpl_addr) {
                    return Ok(Some(RplReceiveOutcome::RplRejected));
                }
                self.process_rpl(frame.payload, received, now_ms)
                    .await
                    .map(Some)
            }
            L2PayloadKind::Unknown => Err(RplReceiveError::Receive(RxError::SchcDecompress)),
        }
    }

    async fn process_source_route(
        &mut self,
        mut received: ReceivedIpv6,
        sender_iid: [u8; 8],
    ) -> Result<Option<RplReceiveOutcome>, RplReceiveError> {
        let local_link_addr = self.stack.local_addr().0;
        let current_destination: [u8; 16] = received.ipv6[24..40].try_into().unwrap();
        if current_destination != self.local_rpl_addr && current_destination != local_link_addr {
            return Err(RplReceiveError::Receive(RxError::InvalidSourceRoute));
        }
        if self.rpl.router.is_root()
            || self
                .rpl
                .preferred_parent()
                .is_none_or(|parent| parent[8..] != sender_iid)
        {
            return Err(RplReceiveError::Receive(RxError::InvalidSourceRoute));
        }
        let source: [u8; 16] = received.ipv6[8..24].try_into().unwrap();
        if source != self.rpl.router.dodag_id() {
            return Err(RplReceiveError::Receive(RxError::InvalidSourceRoute));
        }

        let next_destination =
            advance_rpl_source_route(&mut received.ipv6, current_destination, sender_iid)
                .map_err(RplReceiveError::Receive)?;
        let Some(next_destination) = next_destination else {
            return Ok(Some(RplReceiveOutcome::DeliveredIpv6(received)));
        };
        if received.ipv6[7] <= 1 {
            return Err(RplReceiveError::Receive(RxError::HopLimitExceeded));
        }
        received.ipv6[7] -= 1;
        let next_hop = ipv6_eui64(next_destination);
        self.stack
            .send_ipv6_to(&received.ipv6, &next_hop)
            .await
            .map_err(RplReceiveError::Transmit)?;
        Ok(Some(RplReceiveOutcome::Forwarded {
            next_hop: eui64_link_local(next_hop),
        }))
    }

    pub(crate) async fn process_announce(
        &mut self,
        frame: AuthenticatedFrame,
        bootstrapped: bool,
        now_ms: u64,
    ) -> Result<RplReceiveOutcome, RplReceiveError> {
        let announce_wire = match routing_announce(&frame.payload) {
            Ok(body) => body.to_vec(),
            Err(_) => {
                if bootstrapped {
                    self.stack.link().forget_peer(&frame.sender.iid);
                }
                return Ok(RplReceiveOutcome::AnnouncementRejected(
                    AnnounceRejectReason::Malformed,
                ));
            }
        };
        let (staged_announces, result) = match Announce::from_bytes(&announce_wire) {
            Ok(announce) => {
                if *announce.originator_iid == iid_from_pubkey(&self.stack.local_public_key()) {
                    if bootstrapped {
                        self.stack.link().forget_peer(&frame.sender.iid);
                    }
                    return Ok(RplReceiveOutcome::AnnouncementRejected(
                        AnnounceRejectReason::StaleSeqNum,
                    ));
                }
                let from_neighbor = link_local_from_iid(frame.sender.iid);
                let mut staged = self.announces.clone();
                let result = staged.process(&announce, from_neighbor, now_ms as u32);
                (staged, result)
            }
            Err(_) => {
                if bootstrapped {
                    self.stack.link().forget_peer(&frame.sender.iid);
                }
                return Ok(RplReceiveOutcome::AnnouncementRejected(
                    AnnounceRejectReason::Malformed,
                ));
            }
        };
        if result.accepted {
            let peer = result.peer.expect("accepted announce has peer identity");
            let relayed = if result.should_relay {
                let mut relay = announce_wire;
                relay[2] += 1;
                let mut payload = Vec::with_capacity(relay.len() + 1);
                payload.push(L2_DISPATCH_ROUTING);
                payload.extend_from_slice(&relay);
                if let Err(error) = self.stack.send_l2_payload_to(&payload, &[]).await {
                    if bootstrapped {
                        self.stack.link().forget_peer(&frame.sender.iid);
                    }
                    return Err(RplReceiveError::Transmit(error));
                }
                true
            } else {
                false
            };
            self.announces = staged_announces;
            if let Some(evicted) = result.evicted_iid {
                if let Some(position) = self
                    .bootstrap_peers
                    .iter()
                    .position(|tracked| *tracked == evicted)
                {
                    self.bootstrap_peers.remove(position);
                    self.stack.link().forget_peer(&evicted);
                }
            }
            if peer.iid == frame.sender.iid {
                let announce_peer_is_new = matches!(
                    self.stack.link().peer_auth_state(&peer.iid),
                    lichen_link::link_layer::PeerAuthState::Unknown
                );
                self.stack.add_peer(peer.clone());
                if (bootstrapped || announce_peer_is_new)
                    && !self.bootstrap_peers.contains(&peer.iid)
                {
                    self.bootstrap_peers.push_back(peer.iid);
                }
            }
            Ok(RplReceiveOutcome::AnnouncementAccepted {
                peer,
                should_relay: result.should_relay,
                relayed,
            })
        } else {
            if bootstrapped {
                self.stack.link().forget_peer(&frame.sender.iid);
            }
            Ok(RplReceiveOutcome::AnnouncementRejected(
                result
                    .reject_reason
                    .unwrap_or(AnnounceRejectReason::Malformed),
            ))
        }
    }

    pub(crate) async fn process_rpl(
        &mut self,
        l2_payload: Vec<u8>,
        received: ReceivedIpv6,
        now_ms: u64,
    ) -> Result<RplReceiveOutcome, RplReceiveError> {
        let mut output = [0u8; 260];
        let (output_len, event) =
            self.rpl
                .handle_frame_rpl(&l2_payload, received.sender_iid, &mut output, now_ms);
        match event {
            RplEvent::DaoReceived => {
                let Some((source, dao)) = dao_parts(&received.ipv6) else {
                    return Ok(RplReceiveOutcome::Dao(DaoHandlingOutcome::Malformed));
                };
                let RplRole::Root(rx) = &mut self.role else {
                    return Ok(RplReceiveOutcome::Dao(DaoHandlingOutcome::RouteRejected));
                };
                let origin_iid: [u8; 8] = source[8..].try_into().unwrap();
                let admitted = self
                    .announces
                    .pinned_pubkey_for(&origin_iid)
                    .is_some_and(|key| {
                        self.dao_admissions
                            .as_ref()
                            .is_some_and(|admissions| admissions.contains(key.as_bytes()))
                    });
                if !admitted {
                    return Ok(RplReceiveOutcome::DaoOriginNotAdmitted);
                }
                let admissions = self.dao_admissions.as_ref().expect("root has admissions");
                let outcome = self.rpl.handle_dao(
                    dao,
                    source,
                    received.sender_iid,
                    &self.announces,
                    rx,
                    &mut self.storage,
                    now_ms,
                    admissions,
                );
                Ok(RplReceiveOutcome::Dao(outcome))
            }
            RplEvent::DaoForwarded { next_hop } => {
                if output_len == 0 {
                    return Ok(RplReceiveOutcome::RplRejected);
                }
                self.stack
                    .send_l2_payload_to(&output[..output_len], &ipv6_eui64(next_hop))
                    .await
                    .map_err(RplReceiveError::Transmit)?;
                Ok(RplReceiveOutcome::Forwarded { next_hop })
            }
            RplEvent::DisReceived => {
                let source = received.ipv6[field::SRC_OFFSET..field::DST_OFFSET]
                    .try_into()
                    .expect("validated IPv6 source length");
                let destination: [u8; 16] = received.ipv6[field::DST_OFFSET..IPV6_HEADER_LEN]
                    .try_into()
                    .expect("validated IPv6 destination length");
                if destination[0] == 0xff {
                    let jitter = multicast_dis_jitter(self.stack.node_id().0, source, now_ms);
                    if matches!(
                        self.rpl.router.poll_trickle(),
                        lichen_rpl::trickle::TrickleEvent::Stopped
                    ) {
                        self.trickle_start(now_ms, jitter);
                    } else {
                        self.trickle_reset(now_ms, jitter);
                    }
                    return Ok(RplReceiveOutcome::Rpl(RplEvent::DisReceived));
                }
                self.send_dio(source)
                    .await
                    .map_err(RplReceiveError::Transmit)?;
                Ok(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
            }
            RplEvent::None => Ok(RplReceiveOutcome::RplRejected),
            event => Ok(RplReceiveOutcome::Rpl(event)),
        }
    }

    /// Complete full DAO processing (signature verification, admission check,
    /// route-table update) from a compressed L2 frame payload.
    ///
    /// Call after [`RplNode::handle_frame_rpl`] returns `DaoReceived` when the
    /// stack is acting as a root.
    pub fn complete_dao_from_frame(
        &mut self,
        frame: &[u8],
        sender_iid: [u8; 8],
        now_ms: u64,
    ) -> Option<DaoHandlingOutcome> {
        if classify_l2_payload(frame) != L2PayloadKind::Schc {
            return None;
        }
        let mut ipv6 = [0u8; 256];
        let n = match codec::decompress(l2_payload_body(frame), &mut ipv6) {
            Ok(n) if n >= IPV6_HEADER_LEN + hdr_field::BODY_OFFSET + 4 => n,
            _ => return None,
        };
        if !valid_rpl_ipv6(&ipv6[..n]) || ipv6[IPV6_HEADER_LEN + 1] != rpl_code::DAO {
            return None;
        }
        let source: [u8; 16] = ipv6[field::SRC_OFFSET..field::DST_OFFSET].try_into().ok()?;
        let dao = &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..n];

        let origin_iid: [u8; 8] = source[8..].try_into().unwrap();
        let admitted = self
            .announces
            .pinned_pubkey_for(&origin_iid)
            .is_some_and(|key| {
                self.dao_admissions
                    .as_ref()
                    .is_some_and(|admissions| admissions.contains(key.as_bytes()))
            });
        if !admitted {
            // Origin not admitted - return None to indicate no DAO processing occurred
            return None;
        }
        let RplRole::Root(rx) = &mut self.role else {
            return None;
        };
        let admissions = self.dao_admissions.as_ref()?;
        let outcome = self.rpl.handle_dao(
            dao,
            source,
            sender_iid,
            &self.announces,
            rx,
            &mut self.storage,
            now_ms,
            admissions,
        );
        Some(outcome)
    }
}
