// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Production ownership and dispatch for the std RPL stack.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_core::constants::RPL_ICMPV6_TYPE;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
    L2_ROUTING_TYPE_ANNOUNCE,
};
use lichen_hal::RadioConfig;
use lichen_hal::{NonVolatile, Radio};
use lichen_ipv6::{icmpv6_checksum, Addr, Ipv6Header};
use lichen_link::frame::{AddrMode, LichenFrame};
use lichen_link::identity::{iid_from_pubkey, PeerIdentity};
use lichen_link::link_layer::{AuthenticatedFrame, LinkRxError};
use lichen_link::schnorr::{self, SIGNATURE_LENGTH};
use lichen_rpl::routing::{
    DaoAdmissionState, DaoAdmissionUpdateError, DaoPersistentOpenError, DaoProvisionError,
    DaoTxError, DaoTxState,
};
use lichen_schc::codec;

use crate::announce::{AnnounceProcessor, AnnounceRejectReason};
use crate::node::{
    claims_rpl_ipv6, is_rpl_ipv6, rpl_code, valid_ipv6_envelope, valid_rpl_ipv6,
    DaoHandlingOutcome, Node, RplEvent, RplNode,
};
use crate::routing::{DaoRxState, Router};
use crate::stack::{ReceivedIpv6, RxError, Stack, TxError, MAX_FRAME_SIZE};

const RPL_ALL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplStackProvisionError<E> {
    InvalidOrigin,
    RootAddressMismatch,
    Dao(DaoProvisionError<E>),
    Admission(DaoProvisionError<E>),
    ExistingNonEmpty,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplStackOpenError<E> {
    InvalidOrigin,
    RootAddressMismatch,
    Dao(DaoPersistentOpenError<E>),
    Admission(DaoPersistentOpenError<E>),
    AdmissionInconsistent,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DaoSendError<E> {
    NotLeaf,
    Dao(DaoTxError<E>),
    PacketTooLarge,
    Transmit(TxError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplReceiveError {
    Receive(RxError),
    Transmit(TxError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplControlError {
    MalformedAnnounce,
    Transmit(TxError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DaoAdmissionError<E> {
    NotRoot,
    IdentityNotPinned,
    Capacity,
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
}

impl<E: core::fmt::Debug> core::fmt::Display for RplStackProvisionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOrigin => write!(f, "RPL origin IID does not match the local identity"),
            Self::RootAddressMismatch => write!(f, "root address must equal the DODAG ID"),
            Self::Dao(error) => write!(f, "DAO state provisioning failed: {error:?}"),
            Self::Admission(error) => write!(f, "DAO admission provisioning failed: {error:?}"),
            Self::ExistingNonEmpty => {
                write!(
                    f,
                    "existing DAO root state is nonempty and cannot be reprovisioned"
                )
            }
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for RplStackProvisionError<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for RplStackOpenError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOrigin => write!(f, "RPL origin IID does not match the local identity"),
            Self::RootAddressMismatch => write!(f, "root address must equal the DODAG ID"),
            Self::Dao(error) => write!(f, "DAO state open failed: {error:?}"),
            Self::Admission(error) => write!(f, "DAO admission open failed: {error:?}"),
            Self::AdmissionInconsistent => {
                write!(f, "DAO high-water contains an origin that is not admitted")
            }
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for RplStackOpenError<E> {}

impl<E: core::fmt::Debug> core::fmt::Display for DaoSendError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLeaf => write!(f, "DAO transmission requires a leaf role"),
            Self::Dao(error) => write!(f, "DAO construction failed: {error:?}"),
            Self::PacketTooLarge => write!(f, "DAO packet is too large"),
            Self::Transmit(error) => write!(f, "DAO transmission failed: {error}"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for DaoSendError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transmit(error) => Some(error),
            _ => None,
        }
    }
}

impl core::fmt::Display for RplReceiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Receive(error) => write!(f, "RPL receive failed: {error}"),
            Self::Transmit(error) => write!(f, "RPL forwarding failed: {error}"),
        }
    }
}

impl core::error::Error for RplReceiveError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Receive(error) => Some(error),
            Self::Transmit(error) => Some(error),
        }
    }
}

impl core::fmt::Display for RplControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedAnnounce => write!(f, "invalid local announce"),
            Self::Transmit(error) => write!(f, "control transmission failed: {error}"),
        }
    }
}

impl core::error::Error for RplControlError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MalformedAnnounce => None,
            Self::Transmit(error) => Some(error),
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for DaoAdmissionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRoot => write!(f, "DAO origins can only be admitted at a root"),
            Self::IdentityNotPinned => write!(f, "DAO origin has no currently pinned Announce key"),
            Self::Capacity => write!(f, "DAO origin admission capacity exhausted"),
            Self::Persistence(error) => write!(f, "DAO admission persistence failed: {error:?}"),
            Self::Stale => write!(f, "DAO admission state handle is stale"),
            Self::Exhausted => write!(f, "DAO admission persistence generation exhausted"),
            Self::Corrupt => write!(f, "DAO admission persistence is corrupt"),
        }
    }
}

impl<E: core::fmt::Debug + 'static> core::error::Error for DaoAdmissionError<E> {}

#[derive(Debug)]
pub enum RplReceiveOutcome {
    DeliveredIpv6(ReceivedIpv6),
    AnnouncementAccepted {
        peer: PeerIdentity,
        should_relay: bool,
        relayed: bool,
    },
    AnnouncementRejected(AnnounceRejectReason),
    Rpl(RplEvent),
    RplRejected,
    Dao(DaoHandlingOutcome),
    DaoOriginNotAdmitted,
    Forwarded {
        next_hop: [u8; 16],
    },
}

enum RplRole {
    Leaf(DaoTxState),
    Root(DaoRxState),
}

pub struct RplStack<R: Radio, S: NonVolatile> {
    stack: Stack<R>,
    rpl: RplNode,
    announces: AnnounceProcessor,
    storage: S,
    role: RplRole,
    local_rpl_addr: [u8; 16],
    bootstrap_peers: VecDeque<[u8; 8]>,
    dao_admissions: Option<DaoAdmissionState>,
}

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    pub fn provision_leaf(
        stack: Stack<R>,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        validate_origin(&stack, local_rpl_addr)
            .map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        let key = stack.local_public_key();
        let tx = DaoTxState::provision(
            &mut storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackProvisionError::Dao)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
        })
    }

    pub fn open_leaf(
        stack: Stack<R>,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        validate_origin(&stack, local_rpl_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        let key = stack.local_public_key();
        let tx = DaoTxState::open(
            &storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Dao)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
        })
    }

    pub fn provision_root(
        stack: Stack<R>,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        validate_origin(&stack, root_addr).map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        if root_addr != dodag_id {
            return Err(RplStackProvisionError::RootAddressMismatch);
        }
        let (router, rx, admissions) = provision_or_resume_root_state(
            &mut storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )?;
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
        })
    }

    pub fn open_root(
        stack: Stack<R>,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        validate_origin(&stack, root_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        if root_addr != dodag_id {
            return Err(RplStackOpenError::RootAddressMismatch);
        }
        let (router, rx) =
            Router::open_root(&storage, root_addr).map_err(RplStackOpenError::Dao)?;
        let admissions = DaoAdmissionState::open(
            &storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Admission)?;
        if router
            .dao_origin_keys()
            .iter()
            .any(|key| !admissions.contains(key))
        {
            return Err(RplStackOpenError::AdmissionInconsistent);
        }
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
        })
    }

    pub fn rpl_node(&self) -> &RplNode {
        &self.rpl
    }

    pub fn announces(&self) -> &AnnounceProcessor {
        &self.announces
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Admit the currently pinned Announce identity to create root DAO state.
    ///
    /// Admissions are bounded by durable replay capacity and cannot be retired
    /// through this API. Origins already represented in persisted high-water
    /// state are restored as admitted by [`Self::open_root`].
    pub fn admit_dao_origin(&mut self, iid: [u8; 8]) -> Result<(), DaoAdmissionError<S::Error>> {
        if !matches!(self.role, RplRole::Root(_)) {
            return Err(DaoAdmissionError::NotRoot);
        }
        let key = self
            .announces
            .pinned_pubkey_for(&iid)
            .ok_or(DaoAdmissionError::IdentityNotPinned)?;
        let admissions = self
            .dao_admissions
            .as_mut()
            .ok_or(DaoAdmissionError::NotRoot)?;
        admissions
            .admit(&mut self.storage, *key.as_bytes())
            .map_err(|error| match error {
                DaoAdmissionUpdateError::Persistence(error) => {
                    DaoAdmissionError::Persistence(error)
                }
                DaoAdmissionUpdateError::Stale => DaoAdmissionError::Stale,
                DaoAdmissionUpdateError::Exhausted => DaoAdmissionError::Exhausted,
                DaoAdmissionUpdateError::Corrupt => DaoAdmissionError::Corrupt,
                DaoAdmissionUpdateError::Capacity => DaoAdmissionError::Capacity,
            })
    }

    pub fn last_signed_dao(&self) -> Option<&[u8]> {
        match &self.role {
            RplRole::Leaf(state) => state.last_signed_dao(),
            RplRole::Root(_) => None,
        }
    }

    pub async fn send_ipv6_raw(&mut self, ipv6: &[u8]) -> Result<(), TxError> {
        self.stack.send_ipv6_raw(ipv6).await
    }

    pub async fn send_get(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
    ) -> Result<u16, TxError> {
        self.stack.send_get(dst, uri_path, token).await
    }

    pub async fn send_post(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
        content_format: Option<u16>,
        payload: &[u8],
    ) -> Result<u16, TxError> {
        self.stack
            .send_post(dst, uri_path, token, content_format, payload)
            .await
    }

    pub async fn send_put(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
        content_format: Option<u16>,
        payload: &[u8],
    ) -> Result<u16, TxError> {
        self.stack
            .send_put(dst, uri_path, token, content_format, payload)
            .await
    }

    pub async fn send_coap_raw(&mut self, dst: &Addr, coap: &[u8]) -> Result<(), TxError> {
        self.stack.send_coap_raw(dst, coap).await
    }

    pub fn configure_radio(&mut self, config: &RadioConfig) {
        self.stack.radio().configure(config);
    }

    pub async fn send_announce(
        &mut self,
        announce_wire: &[u8],
        _now_ms: u32,
    ) -> Result<(), RplControlError> {
        let announce =
            Announce::from_bytes(announce_wire).map_err(|_| RplControlError::MalformedAnnounce)?;
        let local_key = self.stack.local_public_key();
        let mut signed = [0u8; 256];
        let signed_len = announce
            .write_signed_data(&mut signed)
            .map_err(|_| RplControlError::MalformedAnnounce)?;
        if *announce.originator_iid != iid_from_pubkey(&local_key)
            || *announce.pubkey != *local_key.as_bytes()
            || !schnorr::verify(&local_key, &signed[..signed_len], announce.signature)
        {
            return Err(RplControlError::MalformedAnnounce);
        }
        let mut payload = Vec::with_capacity(announce_wire.len() + 1);
        payload.push(lichen_core::constants::L2_DISPATCH_ROUTING);
        payload.extend_from_slice(announce_wire);
        self.stack
            .send_l2_payload_to(&payload, &[])
            .await
            .map_err(RplControlError::Transmit)
    }

    pub async fn send_dio(&mut self, destination: [u8; 16]) -> Result<(), TxError> {
        let mut body = [0u8; 64];
        let len = self.rpl.build_dio(&mut body);
        if len == 0 {
            return Err(TxError::BufferTooSmall);
        }
        let packet = rpl_ipv6_packet(
            self.local_rpl_addr,
            destination,
            rpl_code::DIO,
            &body[..len],
        )
        .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(destination);
        self.stack
            .send_ipv6_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
            )
            .await
    }

    pub async fn send_dis(&mut self, destination: [u8; 16]) -> Result<(), TxError> {
        let packet = rpl_ipv6_packet(self.local_rpl_addr, destination, rpl_code::DIS, &[0, 0])
            .ok_or(TxError::BufferTooSmall)?;
        let l2_destination = ipv6_l2_destination(destination);
        self.stack
            .send_ipv6_to(
                &packet,
                l2_destination.as_ref().map_or(&[], <[u8; 8]>::as_slice),
            )
            .await
    }

    pub fn trickle_start(&mut self, now_ms: u64, rand_offset: u32) {
        self.rpl.trickle_start(now_ms, rand_offset);
    }

    pub fn trickle_reset(&mut self, now_ms: u64, rand_offset: u32) {
        self.rpl.trickle_reset(now_ms, rand_offset);
    }

    pub fn trickle_expire(&mut self, now_ms: u64, rand_offset: u32) {
        self.rpl.trickle_expire(now_ms, rand_offset);
    }

    pub fn trickle_transmit(&mut self) -> bool {
        self.rpl.trickle_transmit()
    }

    pub async fn send_dao(&mut self) -> Result<(), DaoSendError<S::Error>> {
        let RplRole::Leaf(tx) = &mut self.role else {
            return Err(DaoSendError::NotLeaf);
        };
        let dao = if let Some(dao) = tx.last_signed_dao() {
            dao.to_vec()
        } else {
            self.rpl
                .build_signed_dao(
                    self.local_rpl_addr,
                    tx,
                    &mut self.storage,
                    self.stack.link(),
                )
                .map_err(DaoSendError::Dao)?
        };
        self.transmit_dao(&dao).await?;
        let RplRole::Leaf(tx) = &mut self.role else {
            unreachable!("DAO sender role changed during transmission")
        };
        tx.clear_transmitted(&mut self.storage)
            .map_err(DaoSendError::Dao)
    }

    async fn transmit_dao(&mut self, dao: &[u8]) -> Result<(), DaoSendError<S::Error>> {
        let dodag_id = self.rpl.router.dodag_id();
        let next_hop = self
            .rpl
            .preferred_parent()
            .ok_or(DaoSendError::Dao(DaoTxError::NotJoined))?;
        let packet = dao_ipv6_packet(self.local_rpl_addr, dodag_id, dao)
            .ok_or(DaoSendError::PacketTooLarge)?;
        self.stack
            .send_ipv6_to(&packet, &ipv6_eui64(next_hop))
            .await
            .map_err(DaoSendError::Transmit)
    }

    pub async fn receive(
        &mut self,
        timeout_ms: u32,
        now_ms: u64,
    ) -> Result<Option<RplReceiveOutcome>, RplReceiveError> {
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let packet = self
            .stack
            .radio()
            .receive(&mut wire, timeout_ms)
            .await
            .map_err(|_| RplReceiveError::Receive(RxError::RadioRx))?;
        let Some(packet) = packet else {
            return Ok(None);
        };
        let wire = &wire[..packet.len];
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

    async fn process_announce(
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
                payload.push(lichen_core::constants::L2_DISPATCH_ROUTING);
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
            let announce_peer_is_new = matches!(
                self.stack.link().peer_auth_state(&peer.iid),
                lichen_link::link_layer::PeerAuthState::Unknown
            );
            self.stack.add_peer(peer.clone());
            if (bootstrapped || announce_peer_is_new) && !self.bootstrap_peers.contains(&peer.iid) {
                self.bootstrap_peers.push_back(peer.iid);
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

    async fn process_rpl(
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
                let outcome = self.rpl.handle_dao(
                    dao,
                    source,
                    received.sender_iid,
                    &self.announces,
                    rx,
                    &mut self.storage,
                    now_ms,
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
                        self.rpl.trickle_start(now_ms, jitter);
                    } else {
                        self.rpl.trickle_reset(now_ms, jitter);
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
}

#[cfg(test)]
impl<R: Radio> RplStack<R, lichen_hal::storage::mem::MemStorage> {
    fn fail_next_storage_write(&mut self) {
        self.storage.fail_next_write();
    }
}

fn validate_origin<R: Radio>(stack: &Stack<R>, origin: [u8; 16]) -> Result<(), ()> {
    let expected = iid_from_pubkey(&stack.local_public_key());
    (origin[8..] == expected).then_some(()).ok_or(())
}

fn provision_or_resume_root_state<S: NonVolatile>(
    storage: &mut S,
    root_addr: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
) -> Result<(Router, DaoRxState, DaoAdmissionState), RplStackProvisionError<S::Error>> {
    let admissions = match DaoAdmissionState::open(storage, root_addr, rpl_instance_id, dodag_id) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => {
            return Err(RplStackProvisionError::Admission(DaoProvisionError::Open(
                error,
            )))
        }
    };
    let replay = match Router::open_root(storage, root_addr) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => return Err(RplStackProvisionError::Dao(DaoProvisionError::Open(error))),
    };

    if admissions.as_ref().is_some_and(|state| !state.is_empty())
        || replay
            .as_ref()
            .is_some_and(|(router, _)| !router.dao_origin_keys().is_empty())
    {
        return Err(RplStackProvisionError::ExistingNonEmpty);
    }

    let admissions = match admissions {
        Some(state) => state,
        None => DaoAdmissionState::provision(storage, root_addr, rpl_instance_id, dodag_id)
            .map_err(RplStackProvisionError::Admission)?,
    };
    let (router, rx) = match replay {
        Some(state) => state,
        None => Router::provision_root(storage, root_addr).map_err(RplStackProvisionError::Dao)?,
    };
    Ok((router, rx, admissions))
}

fn bootstrap_announce_peer(wire: &[u8]) -> Option<PeerIdentity> {
    let frame = LichenFrame::from_bytes(wire).ok()?;
    if !frame.signature.is_present() || frame.payload.len() < SIGNATURE_LENGTH {
        return None;
    }
    let inner_len = frame.payload.len() - SIGNATURE_LENGTH;
    let inner = &frame.payload[..inner_len];
    let announce = Announce::from_bytes(routing_announce(inner).ok()?).ok()?;
    let peer = PeerIdentity::from_pubkey(lichen_link::keys::PublicKey::new(*announce.pubkey));
    if peer.iid != *announce.originator_iid
        || !schnorr::verify_frame(
            frame.epoch,
            frame.seqnum,
            frame.dst_addr,
            frame.payload,
            &peer.pubkey,
        )
    {
        return None;
    }
    Some(peer)
}

fn routing_announce(payload: &[u8]) -> Result<&[u8], AnnounceRejectReason> {
    if classify_l2_payload(payload) != L2PayloadKind::Routing {
        return Err(AnnounceRejectReason::Malformed);
    }
    let body = l2_payload_body(payload);
    match body.first() {
        Some(&L2_ROUTING_TYPE_ANNOUNCE) => Ok(body),
        Some(_) | None => Err(AnnounceRejectReason::Malformed),
    }
}

fn wire_is_for_local(wire: &[u8], local_eui64: [u8; 8]) -> Result<bool, LinkRxError> {
    let frame = LichenFrame::from_bytes(wire)?;
    Ok(match frame.addr_mode {
        AddrMode::None => inspect_schc_ipv6(&frame)
            .is_none_or(|ipv6| !claims_rpl_ipv6(&ipv6) || rpl_ipv6_multicast_is_allowed(&ipv6)),
        AddrMode::Short => false,
        AddrMode::Extended => frame.dst_addr == local_eui64,
        AddrMode::Elided => inspect_schc_ipv6(&frame).is_some_and(|ipv6| {
            if claims_rpl_ipv6(&ipv6) {
                return rpl_ipv6_multicast_is_allowed(&ipv6)
                    && ipv6_destination(&ipv6).is_some_and(|destination| {
                        destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
                    });
            }
            let destination: [u8; 16] =
                ipv6[field::DST_OFFSET..IPV6_HEADER_LEN].try_into().unwrap();
            destination[0] == 0xff || ipv6_eui64(destination) == local_eui64
        }),
    })
}

fn inspect_schc_ipv6(frame: &LichenFrame<'_>) -> Option<Vec<u8>> {
    if !frame.signature.is_present() || frame.payload.len() < SIGNATURE_LENGTH {
        return None;
    }
    let inner = &frame.payload[..frame.payload.len() - SIGNATURE_LENGTH];
    if classify_l2_payload(inner) != L2PayloadKind::Schc {
        return None;
    }
    let mut ipv6 = vec![0u8; 256];
    let len = codec::decompress(l2_payload_body(inner), &mut ipv6).ok()?;
    if len < IPV6_HEADER_LEN || ipv6[0] >> 4 != 6 {
        return None;
    }
    ipv6.truncate(len);
    Some(ipv6)
}

fn ipv6_destination(ipv6: &[u8]) -> Option<[u8; 16]> {
    ipv6.get(field::DST_OFFSET..IPV6_HEADER_LEN)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
}

fn rpl_ipv6_multicast_is_allowed(ipv6: &[u8]) -> bool {
    ipv6_destination(ipv6)
        .is_some_and(|destination| destination[0] != 0xff || destination == RPL_ALL_NODES)
}

fn dio_dis_destination_is_allowed(ipv6: &[u8], local_rpl_addr: [u8; 16]) -> bool {
    let Some(code) = ipv6.get(IPV6_HEADER_LEN + hdr_field::CODE_OFFSET) else {
        return false;
    };
    if !matches!(*code, rpl_code::DIO | rpl_code::DIS) {
        return true;
    }
    ipv6_destination(ipv6)
        .is_some_and(|destination| destination == local_rpl_addr || destination == RPL_ALL_NODES)
}

fn multicast_dis_jitter(local_eui64: [u8; 8], source: [u8; 16], now_ms: u64) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in local_eui64
        .into_iter()
        .chain(source)
        .chain(now_ms.to_be_bytes())
    {
        hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    hash
}

fn dao_parts(ipv6: &[u8]) -> Option<([u8; 16], &[u8])> {
    if !valid_rpl_ipv6(ipv6) || ipv6[IPV6_HEADER_LEN + 1] != rpl_code::DAO {
        return None;
    }
    let source = ipv6[field::SRC_OFFSET..field::DST_OFFSET].try_into().ok()?;
    Some((source, &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..]))
}

fn dao_ipv6_packet(source: [u8; 16], destination: [u8; 16], dao: &[u8]) -> Option<Vec<u8>> {
    rpl_ipv6_packet(source, destination, rpl_code::DAO, dao)
}

fn rpl_ipv6_packet(
    source: [u8; 16],
    destination: [u8; 16],
    code: u8,
    body: &[u8],
) -> Option<Vec<u8>> {
    let payload_len = hdr_field::BODY_OFFSET.checked_add(body.len())?;
    let payload_len = u16::try_from(payload_len).ok()?;
    let mut packet = vec![0u8; IPV6_HEADER_LEN + usize::from(payload_len)];
    let src = Addr(source);
    let dst = Addr(destination);
    Ipv6Header::new(next_header::ICMPV6, src, dst)
        .write_to(payload_len, &mut packet[..IPV6_HEADER_LEN])
        .ok()?;
    packet[IPV6_HEADER_LEN] = RPL_ICMPV6_TYPE;
    packet[IPV6_HEADER_LEN + 1] = code;
    packet[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);
    let checksum = icmpv6_checksum(&src, &dst, &packet[IPV6_HEADER_LEN..]).ok()?;
    packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

fn ipv6_eui64(address: [u8; 16]) -> [u8; 8] {
    let mut eui64: [u8; 8] = address[8..].try_into().unwrap();
    eui64[0] ^= 0x02;
    eui64
}

fn ipv6_l2_destination(address: [u8; 16]) -> Option<[u8; 8]> {
    (address[0] != 0xff).then(|| ipv6_eui64(address))
}

fn link_local_from_iid(iid: [u8; 8]) -> [u8; 16] {
    let mut address = [0u8; 16];
    address[0] = 0xfe;
    address[1] = 0x80;
    address[8..].copy_from_slice(&iid);
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::announce::MAX_TRACKED_ORIGINATORS;
    use lichen_core::announce::AnnounceBuilder;
    use lichen_core::constants::L2_DISPATCH_ROUTING;
    use lichen_hal::loopback::LoopbackRadio;
    use lichen_hal::storage::mem::MemStorage;
    use lichen_hal::{RadioConfig, RxPacket};
    use lichen_link::identity::Identity;
    use lichen_link::keys::Seed;
    use lichen_link::link_layer::LinkLayer;
    use lichen_rpl::message::{DaoOriginSignature, Dio, SignedDaoEnvelope};
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    struct MeshState {
        eui64s: [[u8; 8]; 3],
        queues: [VecDeque<Vec<u8>>; 3],
        sent: Vec<Vec<u8>>,
    }

    #[derive(Clone)]
    struct MeshHarness(Arc<Mutex<MeshState>>);

    struct MeshRadio {
        index: usize,
        state: Arc<Mutex<MeshState>>,
    }

    struct FailOnceRadio {
        inner: LoopbackRadio,
        fail_next: bool,
    }

    impl FailOnceRadio {
        fn fail_next(&mut self) {
            self.fail_next = true;
        }
    }

    impl Radio for FailOnceRadio {
        type Error = ();

        async fn transmit(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
            if core::mem::take(&mut self.fail_next) {
                return Err(());
            }
            self.inner.transmit(payload).await.map_err(|_| ())
        }

        async fn receive(
            &mut self,
            buf: &mut [u8],
            timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            self.inner.receive(buf, timeout_ms).await.map_err(|_| ())
        }

        fn configure(&mut self, config: &RadioConfig) {
            self.inner.configure(config);
        }
    }

    impl MeshHarness {
        fn new(eui64s: [[u8; 8]; 3]) -> (Self, [MeshRadio; 3]) {
            let state = Arc::new(Mutex::new(MeshState {
                eui64s,
                queues: core::array::from_fn(|_| VecDeque::new()),
                sent: Vec::new(),
            }));
            let radios = core::array::from_fn(|index| MeshRadio {
                index,
                state: Arc::clone(&state),
            });
            (Self(state), radios)
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().sent.clone()
        }
    }

    fn deliver(state: &mut MeshState, source: Option<usize>, wire: &[u8]) {
        let frame = LichenFrame::from_bytes(wire).unwrap();
        for index in 0..state.queues.len() {
            if source == Some(index) {
                continue;
            }
            if source.is_some_and(|source| source.abs_diff(index) != 1) {
                continue;
            }
            let addressed = match frame.addr_mode {
                AddrMode::None | AddrMode::Elided => true,
                AddrMode::Short => false,
                AddrMode::Extended => frame.dst_addr == state.eui64s[index],
            };
            if addressed {
                state.queues[index].push_back(wire.to_vec());
            }
        }
    }

    impl Radio for MeshRadio {
        type Error = Infallible;

        async fn transmit(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
            let mut state = self.state.lock().unwrap();
            state.sent.push(payload.to_vec());
            deliver(&mut state, Some(self.index), payload);
            Ok(())
        }

        async fn receive(
            &mut self,
            buf: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            let Some(packet) = self.state.lock().unwrap().queues[self.index].pop_front() else {
                return Ok(None);
            };
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(Some(RxPacket {
                len: packet.len(),
                rssi: Some(-50),
                snr: Some(10),
            }))
        }

        fn configure(&mut self, _config: &RadioConfig) {}
    }

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(Seed::new([seed; 32]))
    }

    fn address(identity: &Identity, host_prefix: u8) -> [u8; 16] {
        let mut address = [0u8; 16];
        address[0] = 0xfd;
        address[7] = host_prefix;
        address[8..].copy_from_slice(&identity.iid);
        address
    }

    fn announces(prefix: [u8; 8]) -> AnnounceProcessor {
        AnnounceProcessor::new(
            crate::GradientTable::new(crate::announce::MAX_TRACKED_ORIGINATORS),
            prefix,
        )
    }

    fn signed_announce(identity: &Identity, sequence: u16) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.extend_from_slice(&identity.iid);
        signed.extend_from_slice(identity.pubkey.as_bytes());
        signed.extend_from_slice(&sequence.to_be_bytes());
        let signature = schnorr::sign(&identity.privkey, &identity.pubkey, &signed);
        let mut wire = vec![0u8; 93];
        let len = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: sequence,
            hop_count: 0,
            signature: &signature,
            app_data: &[],
            flags: 0,
        }
        .write_to(&mut wire)
        .unwrap();
        wire.truncate(len);
        wire
    }

    fn resign_dao(
        unsigned: &[u8],
        origin: [u8; 16],
        dodag_id: [u8; 16],
        sequence: u64,
        link: &LinkLayer,
    ) -> Vec<u8> {
        let digest = crate::routing::dao_origin_digest(origin, dodag_id, sequence, unsigned);
        let signature = link.sign_digest(&digest);
        let mut wire = unsigned.to_vec();
        let offset = wire.len();
        wire.resize(offset + lichen_rpl::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        DaoOriginSignature::write_to(sequence, &signature, &mut wire[offset..]).unwrap();
        wire
    }

    async fn send_announce<R: Radio>(stack: &mut Stack<R>, identity: &Identity, sequence: u16) {
        let announce = signed_announce(identity, sequence);
        let mut payload = Vec::with_capacity(announce.len() + 1);
        payload.push(L2_DISPATCH_ROUTING);
        payload.extend_from_slice(&announce);
        stack.send_l2_payload_to(&payload, &[]).await.unwrap();
    }

    fn dio_packet(root: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
        dio_packet_from(root, destination, root, crate::routing::ROOT_RANK)
    }

    fn dio_packet_from(
        source: [u8; 16],
        destination: [u8; 16],
        dodag_id: [u8; 16],
        rank: u16,
    ) -> Vec<u8> {
        let dio = Dio {
            rpl_instance_id: lichen_core::constants::RPL_INSTANCE_ID,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        let mut body = [0u8; Dio::BASE_LEN];
        let len = dio.write_to(&mut body).unwrap();
        rpl_ipv6_packet(source, destination, rpl_code::DIO, &body[..len])
    }

    fn rpl_ipv6_packet(source: [u8; 16], destination: [u8; 16], code: u8, body: &[u8]) -> Vec<u8> {
        let payload_len = hdr_field::BODY_OFFSET + body.len();
        let mut packet = vec![0u8; IPV6_HEADER_LEN + payload_len];
        let src = Addr(source);
        let dst = Addr(destination);
        Ipv6Header::new(next_header::ICMPV6, src, dst)
            .write_to(payload_len as u16, &mut packet)
            .unwrap();
        packet[IPV6_HEADER_LEN] = RPL_ICMPV6_TYPE;
        packet[IPV6_HEADER_LEN + 1] = code;
        packet[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);
        let checksum = icmpv6_checksum(&src, &dst, &packet[IPV6_HEADER_LEN..]).unwrap();
        packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    async fn join_leaf<R: Radio, L: Radio, S: NonVolatile>(
        sender: &mut Stack<R>,
        leaf: &mut RplStack<L, S>,
        root_identity: &Identity,
        root_addr: [u8; 16],
        leaf_addr: [u8; 16],
    ) where
        R::Error: core::fmt::Debug,
    {
        send_announce(sender, root_identity, 1).await;
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        let mut relayed = [0u8; MAX_FRAME_SIZE];
        assert!(sender
            .radio()
            .receive(&mut relayed, 1)
            .await
            .unwrap()
            .is_some());
        sender
            .send_ipv6_to(&dio_packet(root_addr, leaf_addr), &ipv6_eui64(leaf_addr))
            .await
            .unwrap();
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));
        assert!(leaf.rpl_node().is_joined());
    }

    async fn receive_ipv6(stack: &mut Stack<LoopbackRadio>) -> ReceivedIpv6 {
        stack.receive(1).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn announcement_bootstraps_real_l2_peer_and_rejects_tampering() {
        let root_identity = identity(1);
        let peer_identity = identity(2);
        let root_addr = address(&root_identity, 1);
        let (peer_radio, root_radio) = LoopbackRadio::pair();
        let mut peer = Stack::new_default_epoch(peer_radio, peer_identity.clone());
        let root_stack = Stack::new_default_epoch(root_radio, root_identity);
        let prefix = root_addr[..8].try_into().unwrap();
        let mut root = RplStack::provision_root(
            root_stack,
            root_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();

        send_announce(&mut peer, &peer_identity, 1).await;
        assert!(matches!(
            root.receive(1, 10).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { peer, .. }) if peer.iid == peer_identity.iid
        ));
        assert!(root
            .announces()
            .pinned_pubkey_for(&peer_identity.iid)
            .is_some());

        let mut bad = signed_announce(&peer_identity, 2);
        bad[45] ^= 1;
        let mut payload = vec![L2_DISPATCH_ROUTING];
        payload.extend_from_slice(&bad);
        peer.send_l2_payload_to(&payload, &[]).await.unwrap();
        assert!(matches!(
            root.receive(1, 11).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementRejected(
                AnnounceRejectReason::InvalidSignature
            ))
        ));

        for payload in [vec![L2_DISPATCH_ROUTING], vec![L2_DISPATCH_ROUTING, 0xff]] {
            peer.send_l2_payload_to(&payload, &[]).await.unwrap();
            assert!(matches!(
                root.receive(1, 12).await.unwrap(),
                Some(RplReceiveOutcome::AnnouncementRejected(
                    AnnounceRejectReason::Malformed
                ))
            ));
        }
    }

    #[tokio::test]
    async fn sending_local_announce_does_not_mutate_full_remote_state() {
        let local = identity(250);
        let local_addr = address(&local, 1);
        let prefix = local_addr[..8].try_into().unwrap();
        let mut remote = announces(prefix);
        let mut remote_iids = Vec::new();
        for seed in 0..MAX_TRACKED_ORIGINATORS as u8 {
            let peer = identity(seed);
            let wire = signed_announce(&peer, 1);
            let announce = Announce::from_bytes(&wire).unwrap();
            assert!(
                remote
                    .process(&announce, link_local_from_iid(peer.iid), 0)
                    .accepted
            );
            remote_iids.push(peer.iid);
        }
        let mut before = remote.known_originators();
        before.sort_unstable();
        let (radio, _receiver) = LoopbackRadio::pair();
        let mut stack = RplStack::provision_leaf(
            Stack::new_default_epoch(radio, local.clone()),
            local_addr,
            local_addr,
            remote,
            MemStorage::new(),
        )
        .unwrap();

        stack
            .send_announce(&signed_announce(&local, 1), 0)
            .await
            .unwrap();

        let mut after = stack.announces().known_originators();
        after.sort_unstable();
        assert_eq!(after, before);
        assert!(stack.announces().pinned_pubkey_for(&local.iid).is_none());
        for iid in remote_iids {
            assert!(stack.announces().pinned_pubkey_for(&iid).is_some());
        }
    }

    #[tokio::test]
    async fn failed_announce_relay_can_retry_same_origin_sequence() {
        let root_identity = identity(251);
        let peer_identity = identity(252);
        let root_addr = address(&root_identity, 1);
        let (peer_radio, root_radio) = LoopbackRadio::pair();
        let mut peer = Stack::new_default_epoch(peer_radio, peer_identity.clone());
        let root_stack = Stack::new_default_epoch(
            FailOnceRadio {
                inner: root_radio,
                fail_next: false,
            },
            root_identity,
        );
        let mut root = RplStack::provision_root(
            root_stack,
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();

        send_announce(&mut peer, &peer_identity, 1).await;
        root.stack.radio().fail_next();
        assert!(matches!(
            root.receive(1, 0).await,
            Err(RplReceiveError::Transmit(TxError::RadioTx))
        ));
        assert!(root
            .announces()
            .pinned_pubkey_for(&peer_identity.iid)
            .is_none());
        assert_eq!(root.stack.link().peer_count(), 0);
        assert!(root.bootstrap_peers.is_empty());

        send_announce(&mut peer, &peer_identity, 1).await;
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { relayed: true, .. })
        ));
        assert!(root
            .announces()
            .pinned_pubkey_for(&peer_identity.iid)
            .is_some());
        assert_eq!(root.stack.link().peer_count(), 1);
        assert_eq!(root.bootstrap_peers.len(), 1);
        assert!(root.bootstrap_peers.len() <= MAX_TRACKED_ORIGINATORS);
    }

    #[tokio::test]
    async fn announcement_bootstrap_is_bounded_and_rejection_forgets_replay() {
        let root_identity = identity(20);
        let root_addr = address(&root_identity, 1);
        let (mut transmitter, root_radio) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let mut first_iid = None;
        for seed in 30..=94 {
            let peer = identity(seed);
            first_iid.get_or_insert(peer.iid);
            let announce = signed_announce(&peer, 1);
            let mut payload = vec![L2_DISPATCH_ROUTING];
            payload.extend_from_slice(&announce);
            let link = LinkLayer::new(peer);
            let mut wire = [0u8; MAX_FRAME_SIZE];
            let len = link
                .build_frame(128, 0u16.into(), &[], &payload, &mut wire)
                .unwrap();
            transmitter.transmit(&wire[..len]).await.unwrap();
            assert!(matches!(
                root.receive(1, 0).await.unwrap(),
                Some(RplReceiveOutcome::AnnouncementAccepted { .. })
            ));
        }
        assert_eq!(root.stack.link().peer_count(), MAX_TRACKED_ORIGINATORS);
        assert_eq!(root.bootstrap_peers.len(), MAX_TRACKED_ORIGINATORS);
        assert_eq!(
            root.announces().known_originators().len(),
            MAX_TRACKED_ORIGINATORS
        );
        assert!(root
            .stack
            .link()
            .pinned_pubkey_for(&first_iid.unwrap())
            .is_none());

        let rejected_identity = identity(100);
        let rejected_iid = rejected_identity.iid;
        let mut bad = signed_announce(&rejected_identity, 1);
        bad[45] ^= 1;
        let send = |announce: &[u8], wire: &mut [u8; MAX_FRAME_SIZE]| {
            let mut payload = vec![L2_DISPATCH_ROUTING];
            payload.extend_from_slice(announce);
            LinkLayer::new(rejected_identity.clone())
                .build_frame(129, 0u16.into(), &[], &payload, wire)
                .unwrap()
        };
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let len = send(&bad, &mut wire);
        transmitter.transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementRejected(
                AnnounceRejectReason::InvalidSignature
            ))
        ));
        assert!(root.stack.link().pinned_pubkey_for(&rejected_iid).is_none());
        assert_eq!(root.stack.link().peer_count(), MAX_TRACKED_ORIGINATORS);

        let valid = signed_announce(&rejected_identity, 1);
        let len = send(&valid, &mut wire);
        transmitter.transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        assert_eq!(root.stack.link().peer_count(), MAX_TRACKED_ORIGINATORS);
    }

    #[tokio::test]
    async fn rpl_dispatch_rejects_invalid_ipv6_length_and_checksum() {
        let root_identity = identity(11);
        let leaf_identity = identity(12);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let (root_radio, leaf_radio) = LoopbackRadio::pair();
        let mut root = Stack::new_default_epoch(root_radio, root_identity.clone());
        let leaf_stack = Stack::new_default_epoch(leaf_radio, leaf_identity);
        let prefix = root_addr[..8].try_into().unwrap();
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        join_leaf(&mut root, &mut leaf, &root_identity, root_addr, leaf_addr).await;

        let valid = dio_packet(root_addr, leaf_addr);
        let mut cases = Vec::new();
        let mut bad_length = valid.clone();
        let claimed = u16::from_be_bytes([bad_length[4], bad_length[5]]) + 1;
        bad_length[4..6].copy_from_slice(&claimed.to_be_bytes());
        cases.push(bad_length);
        cases.push(valid[..valid.len() - 1].to_vec());
        let mut trailing = valid.clone();
        trailing.push(0);
        cases.push(trailing);
        let mut bad_checksum = valid;
        bad_checksum[IPV6_HEADER_LEN + 2] ^= 1;
        cases.push(bad_checksum);
        let mut partial_rpl = dio_packet(root_addr, leaf_addr)[..IPV6_HEADER_LEN + 1].to_vec();
        partial_rpl[4..6].copy_from_slice(&1u16.to_be_bytes());
        cases.push(partial_rpl);

        for packet in cases {
            root.send_ipv6_to(&packet, &ipv6_eui64(leaf_addr))
                .await
                .unwrap();
            assert!(matches!(
                leaf.receive(1, 1).await.unwrap(),
                Some(RplReceiveOutcome::RplRejected)
            ));
        }

        for (index, mut malformed) in [
            dio_packet(root_addr, leaf_addr),
            dio_packet(root_addr, leaf_addr),
        ]
        .into_iter()
        .enumerate()
        {
            malformed[6] = next_header::UDP;
            if index == 0 {
                malformed[0] = 0x50;
            } else {
                malformed[4..6].copy_from_slice(&0u16.to_be_bytes());
            }
            root.send_ipv6_to(&malformed, &ipv6_eui64(leaf_addr))
                .await
                .unwrap();
            assert!(matches!(
                leaf.receive(1, 1).await,
                Err(RplReceiveError::Receive(RxError::SchcDecompress))
            ));
        }
    }

    #[tokio::test]
    async fn multicast_dio_and_dis_use_broadcast_l2_destination() {
        let root_identity = identity(253);
        let root_addr = address(&root_identity, 1);
        let unicast = address(&identity(254), 1);
        let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
        let (root_radio, mut observer) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let mut wire = [0u8; MAX_FRAME_SIZE];

        root.send_dio(multicast).await.unwrap();
        let len = observer.receive(&mut wire, 1).await.unwrap().unwrap().len;
        let frame = LichenFrame::from_bytes(&wire[..len]).unwrap();
        assert_eq!(frame.addr_mode, AddrMode::None);
        assert!(frame.dst_addr.is_empty());

        root.send_dis(multicast).await.unwrap();
        let len = observer.receive(&mut wire, 1).await.unwrap().unwrap().len;
        let frame = LichenFrame::from_bytes(&wire[..len]).unwrap();
        assert_eq!(frame.addr_mode, AddrMode::None);
        assert!(frame.dst_addr.is_empty());

        root.send_dio(unicast).await.unwrap();
        let len = observer.receive(&mut wire, 1).await.unwrap().unwrap().len;
        let frame = LichenFrame::from_bytes(&wire[..len]).unwrap();
        assert_eq!(frame.addr_mode, AddrMode::Extended);
        assert_eq!(frame.dst_addr, ipv6_eui64(unicast));
    }

    #[tokio::test]
    async fn multicast_dio_and_dis_are_received() {
        let root_identity = identity(247);
        let leaf_identity = identity(248);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
        let (root_radio, leaf_radio) = LoopbackRadio::pair();
        let mut root_stack = Stack::new_default_epoch(root_radio, root_identity.clone());
        root_stack.add_peer(PeerIdentity::from_pubkey(leaf_identity.pubkey));
        let mut leaf_stack = Stack::new_default_epoch(leaf_radio, leaf_identity.clone());
        leaf_stack.add_peer(PeerIdentity::from_pubkey(root_identity.pubkey));
        let prefix = root_addr[..8].try_into().unwrap();
        let mut root = RplStack::provision_root(
            root_stack,
            root_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();

        root.send_dio(multicast).await.unwrap();
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));
        assert!(leaf.rpl_node().is_joined());

        leaf.send_dis(multicast).await.unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
        ));
        assert!(leaf.receive(1, 0).await.unwrap().is_none());
        assert!(matches!(
            root.rpl_node().router.poll_trickle(),
            lichen_rpl::trickle::TrickleEvent::Transmit { .. }
        ));

        leaf.send_dis(root_addr).await.unwrap();
        assert!(matches!(
            root.receive(1, 1).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
        ));
        assert!(matches!(
            leaf.receive(1, 1).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));
    }

    #[tokio::test]
    async fn multicast_dis_uses_bounded_node_differentiated_jitter() {
        let sender = identity(240);
        let sender_addr = address(&sender, 1);
        let first_identity = identity(241);
        let first_eui64 = ipv6_eui64(address(&first_identity, 1));
        let second_identity = (242..=u8::MAX)
            .map(identity)
            .find(|candidate| {
                multicast_dis_jitter(ipv6_eui64(address(candidate, 1)), sender_addr, 100) % 4
                    != multicast_dis_jitter(first_eui64, sender_addr, 100) % 4
            })
            .expect("four legal jitter offsets provide a distinct test identity");
        let first_addr = address(&first_identity, 1);
        let second_addr = address(&second_identity, 1);
        let (mut first_tx, first_radio) = LoopbackRadio::pair();
        let (mut second_tx, second_radio) = LoopbackRadio::pair();
        let mut first_stack = Stack::new_default_epoch(first_radio, first_identity);
        first_stack.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let mut second_stack = Stack::new_default_epoch(second_radio, second_identity);
        second_stack.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let mut first = RplStack::provision_root(
            first_stack,
            first_addr,
            first_addr,
            announces(first_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let mut second = RplStack::provision_root(
            second_stack,
            second_addr,
            second_addr,
            announces(second_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();

        let packet = rpl_ipv6_packet(sender_addr, RPL_ALL_NODES, rpl_code::DIS, &[0, 0]);
        let mut schc = [0u8; 200];
        let schc_len = codec::compress(&packet, &mut schc).unwrap();
        let mut payload = [0u8; 201];
        payload[0] = lichen_core::constants::L2_DISPATCH_SCHC;
        payload[1..1 + schc_len].copy_from_slice(&schc[..schc_len]);
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let len = LinkLayer::new(sender)
            .build_frame(128, 0u16.into(), &[], &payload[..1 + schc_len], &mut wire)
            .unwrap();
        first_tx.transmit(&wire[..len]).await.unwrap();
        second_tx.transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            first.receive(1, 100).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
        ));
        assert!(matches!(
            second.receive(1, 100).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
        ));
        let at_ms = |stack: &RplStack<_, _>| match stack.rpl_node().router.poll_trickle() {
            lichen_rpl::trickle::TrickleEvent::Transmit { at_ms } => at_ms,
            event => panic!("expected scheduled Trickle transmit, got {event:?}"),
        };
        let first_at = at_ms(&first);
        let second_at = at_ms(&second);
        assert!((104..108).contains(&first_at));
        assert!((104..108).contains(&second_at));
        assert_ne!(first_at, second_at);
    }

    #[tokio::test]
    async fn unrelated_rpl_multicast_does_not_consume_sender_replay_state() {
        let root_identity = identity(245);
        let leaf_identity = identity(246);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let (mut sender_radio, leaf_radio) = LoopbackRadio::pair();
        let mut leaf_stack = Stack::new_default_epoch(leaf_radio, leaf_identity);
        leaf_stack.add_peer(PeerIdentity::from_pubkey(root_identity.pubkey));
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let link = LinkLayer::new(root_identity);
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let mut schc = [0u8; 200];
        let mut payload = [0u8; 201];
        let unrelated = [0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34];

        for (destination, accepted) in [(unrelated, false), (RPL_ALL_NODES, true)] {
            let packet = dio_packet(root_addr, destination);
            let schc_len = codec::compress(&packet, &mut schc).unwrap();
            payload[0] = lichen_core::constants::L2_DISPATCH_SCHC;
            payload[1..1 + schc_len].copy_from_slice(&schc[..schc_len]);
            let len = link
                .build_frame(128, 0u16.into(), &[], &payload[..1 + schc_len], &mut wire)
                .unwrap();
            sender_radio.transmit(&wire[..len]).await.unwrap();
            let outcome = leaf.receive(1, 0).await.unwrap();
            if accepted {
                assert!(matches!(
                    outcome,
                    Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
                ));
            } else {
                assert!(outcome.is_none());
            }
        }
    }

    #[tokio::test]
    async fn broadcast_wrapped_foreign_unicast_dio_dis_are_rejected_without_mutation() {
        let sender = identity(230);
        let leaf_identity = identity(231);
        let root_identity = identity(232);
        let foreign_addr = address(&identity(233), 1);
        let sender_addr = address(&sender, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let root_addr = address(&root_identity, 1);
        let (mut leaf_tx, leaf_radio) = LoopbackRadio::pair();
        let (mut root_tx, root_radio) = LoopbackRadio::pair();
        let mut leaf_stack = Stack::new_default_epoch(leaf_radio, leaf_identity);
        leaf_stack.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let mut root_stack = Stack::new_default_epoch(root_radio, root_identity);
        root_stack.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            sender_addr,
            announces(sender_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let mut root = RplStack::provision_root(
            root_stack,
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let dio = Dio {
            rpl_instance_id: lichen_core::constants::RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: sender_addr,
        };
        let mut dio_body = [0u8; Dio::BASE_LEN];
        dio.write_to(&mut dio_body).unwrap();
        let build_wire = |code: u8, body: &[u8]| {
            let packet = rpl_ipv6_packet(sender_addr, foreign_addr, code, body);
            let mut schc = [0u8; 200];
            let schc_len = codec::compress(&packet, &mut schc).unwrap();
            let mut payload = [0u8; 201];
            payload[0] = lichen_core::constants::L2_DISPATCH_SCHC;
            payload[1..1 + schc_len].copy_from_slice(&schc[..schc_len]);
            let mut wire = vec![0u8; MAX_FRAME_SIZE];
            let len = LinkLayer::new(sender.clone())
                .build_frame(
                    128,
                    u16::from(code).into(),
                    &[],
                    &payload[..1 + schc_len],
                    &mut wire,
                )
                .unwrap();
            wire.truncate(len);
            wire
        };

        let dio_wire = build_wire(rpl_code::DIO, &dio_body);
        leaf_tx.transmit(&dio_wire).await.unwrap();
        assert!(matches!(
            leaf.receive(1, 100).await.unwrap(),
            Some(RplReceiveOutcome::RplRejected)
        ));
        assert!(!leaf.rpl_node().is_joined());

        let dis_wire = build_wire(rpl_code::DIS, &[0, 0]);
        root_tx.transmit(&dis_wire).await.unwrap();
        assert!(matches!(
            root.receive(1, 100).await.unwrap(),
            Some(RplReceiveOutcome::RplRejected)
        ));
        assert_eq!(
            root.rpl_node().router.poll_trickle(),
            lichen_rpl::trickle::TrickleEvent::Stopped
        );
        let mut response = [0u8; MAX_FRAME_SIZE];
        assert!(root_tx.receive(&mut response, 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn non_destination_does_not_consume_sender_replay_state() {
        let sender = identity(13);
        let intended_identity = identity(14);
        let other_identity = identity(15);
        let intended_addr = address(&intended_identity, 1);
        let other_addr = address(&other_identity, 1);
        let (intended_tx, intended_rx) = LoopbackRadio::pair();
        let (other_tx, other_rx) = LoopbackRadio::pair();
        let intended_stack = Stack::new_default_epoch(intended_rx, intended_identity.clone());
        let other_stack = Stack::new_default_epoch(other_rx, other_identity.clone());
        let mut intended = RplStack::provision_root(
            intended_stack,
            intended_addr,
            intended_addr,
            announces(intended_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let mut other = RplStack::provision_root(
            other_stack,
            other_addr,
            other_addr,
            announces(other_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let announce = signed_announce(&sender, 1);
        let mut payload = vec![L2_DISPATCH_ROUTING];
        payload.extend_from_slice(&announce);
        let link = LinkLayer::new(sender);
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let mut expected = intended_identity.iid;
        expected[0] ^= 0x02;
        let len = link
            .build_frame(128, 0u16.into(), &expected, &payload, &mut wire)
            .unwrap();
        let parsed = LichenFrame::from_bytes(&wire[..len]).unwrap();
        assert_eq!(parsed.addr_mode, AddrMode::Extended);
        assert_eq!(parsed.dst_addr, expected);
        let mut intended_tx = intended_tx;
        let mut other_tx = other_tx;
        intended_tx.transmit(&wire[..len]).await.unwrap();
        other_tx.transmit(&wire[..len]).await.unwrap();

        assert!(matches!(
            intended.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        assert!(other.receive(1, 0).await.unwrap().is_none());

        let len = link
            .build_frame(128, 0u16.into(), &[], &payload, &mut wire)
            .unwrap();
        other_tx.transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            other.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
    }

    #[tokio::test]
    async fn leaf_send_allocates_each_update_and_restart_advances_sequence() {
        let root_identity = identity(3);
        let leaf_identity = identity(4);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let (root_radio, leaf_radio) = LoopbackRadio::pair();
        let mut root_sender = Stack::new_default_epoch(root_radio, root_identity.clone());
        root_sender.add_peer(PeerIdentity::from_pubkey(leaf_identity.pubkey));
        let leaf_stack = Stack::new_default_epoch(leaf_radio, leaf_identity.clone());
        let prefix = root_addr[..8].try_into().unwrap();
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        join_leaf(
            &mut root_sender,
            &mut leaf,
            &root_identity,
            root_addr,
            leaf_addr,
        )
        .await;

        leaf.send_dao().await.unwrap();
        let first = receive_ipv6(&mut root_sender).await;
        let (_, first_dao) = dao_parts(&first.ipv6).unwrap();
        assert_eq!(leaf.last_signed_dao(), None);
        let first_sequence = SignedDaoEnvelope::from_bytes(first_dao)
            .unwrap()
            .origin
            .origin_sequence;
        assert_eq!(first_sequence, 1);

        for expected in 2..=20 {
            leaf.send_dao().await.unwrap();
            let update = receive_ipv6(&mut root_sender).await;
            let sequence = SignedDaoEnvelope::from_bytes(dao_parts(&update.ipv6).unwrap().1)
                .unwrap()
                .origin
                .origin_sequence;
            assert_eq!(sequence, expected);
        }

        let persisted = leaf.storage().clone();
        let (root_radio, leaf_radio) = LoopbackRadio::pair();
        let mut root_sender = Stack::new(root_radio, root_identity.clone(), 129);
        root_sender.add_peer(PeerIdentity::from_pubkey(leaf_identity.pubkey));
        let leaf_stack = Stack::new(leaf_radio, leaf_identity.clone(), 129);
        let mut leaf = RplStack::open_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(prefix),
            persisted,
        )
        .unwrap();
        assert!(matches!(
            leaf.send_dao().await,
            Err(DaoSendError::Dao(DaoTxError::NotJoined))
        ));
        join_leaf(
            &mut root_sender,
            &mut leaf,
            &root_identity,
            root_addr,
            leaf_addr,
        )
        .await;
        leaf.send_dao().await.unwrap();
        let second = receive_ipv6(&mut root_sender).await;
        let second_sequence = SignedDaoEnvelope::from_bytes(dao_parts(&second.ipv6).unwrap().1)
            .unwrap()
            .origin
            .origin_sequence;
        assert_eq!(second_sequence, first_sequence + 20);
    }

    #[tokio::test]
    async fn dao_radio_failure_retains_exact_finalized_bytes() {
        let root_identity = identity(101);
        let leaf_identity = identity(102);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let (root_radio, leaf_radio) = LoopbackRadio::pair();
        let mut root = Stack::new_default_epoch(root_radio, root_identity.clone());
        root.add_peer(PeerIdentity::from_pubkey(leaf_identity.pubkey));
        let leaf_stack = Stack::new_default_epoch(
            FailOnceRadio {
                inner: leaf_radio,
                fail_next: false,
            },
            leaf_identity,
        );
        let mut leaf = RplStack::provision_leaf(
            leaf_stack,
            leaf_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        join_leaf(&mut root, &mut leaf, &root_identity, root_addr, leaf_addr).await;

        leaf.stack.radio().fail_next();
        assert_eq!(
            leaf.send_dao().await,
            Err(DaoSendError::Transmit(TxError::RadioTx))
        );
        let finalized = leaf.last_signed_dao().unwrap().to_vec();
        leaf.send_dao().await.unwrap();
        let received = receive_ipv6(&mut root).await;
        assert_eq!(dao_parts(&received.ipv6).unwrap().1, finalized);
        assert_eq!(leaf.last_signed_dao(), None);
    }

    #[tokio::test]
    async fn relay_forwards_original_source_and_signed_body() {
        let root_identity = identity(5);
        let relay_identity = identity(6);
        let leaf_identity = identity(7);
        let root_addr = address(&root_identity, 1);
        let relay_addr = address(&relay_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let (root_radio, relay_radio) = LoopbackRadio::pair();
        let mut root = Stack::new_default_epoch(root_radio, root_identity.clone());
        root.add_peer(PeerIdentity::from_pubkey(relay_identity.pubkey));
        let relay_stack = Stack::new_default_epoch(relay_radio, relay_identity.clone());
        let prefix = root_addr[..8].try_into().unwrap();
        let mut relay = RplStack::provision_leaf(
            relay_stack,
            relay_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        join_leaf(&mut root, &mut relay, &root_identity, root_addr, relay_addr).await;

        let leaf_announce = signed_announce(&leaf_identity, 1);
        let mut payload = vec![L2_DISPATCH_ROUTING];
        payload.extend_from_slice(&leaf_announce);
        let leaf_link = LinkLayer::new(leaf_identity.clone());
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let len = leaf_link
            .build_frame(128, 0u16.into(), &[], &payload, &mut wire)
            .unwrap();
        root.radio().transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        let mut relayed = [0u8; MAX_FRAME_SIZE];
        assert!(root
            .radio()
            .receive(&mut relayed, 1)
            .await
            .unwrap()
            .is_some());

        let mut storage = MemStorage::new();
        let mut tx = DaoTxState::provision(
            &mut storage,
            leaf_identity.pubkey,
            leaf_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            root_addr,
        )
        .unwrap();
        let mut leaf_router = Router::new(leaf_addr, root_addr);
        let dio = Dio::from_bytes(&dio_packet(root_addr, leaf_addr)[44..]).unwrap();
        let mut dio_body = [0u8; Dio::BASE_LEN];
        let dio_len = dio.write_to(&mut dio_body).unwrap();
        assert!(leaf_router.process_dio(&dio, &dio_body[..dio_len], relay_addr, 0, 0));
        let signed = leaf_router
            .build_signed_dao(leaf_addr, &mut tx, &mut storage, &leaf_link)
            .unwrap();
        let packet = dao_ipv6_packet(leaf_addr, root_addr, &signed).unwrap();
        let mut schc = [0u8; 200];
        let schc_len = codec::compress(&packet, &mut schc).unwrap();
        payload.clear();
        payload.push(lichen_core::constants::L2_DISPATCH_SCHC);
        payload.extend_from_slice(&schc[..schc_len]);
        let len = leaf_link
            .build_frame(128, 1u16.into(), &[], &payload, &mut wire)
            .unwrap();
        root.radio().transmit(&wire[..len]).await.unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Forwarded { next_hop }) if next_hop == root_addr
        ));

        let forwarded = receive_ipv6(&mut root).await;
        assert_eq!(
            &forwarded.ipv6[field::SRC_OFFSET..field::DST_OFFSET],
            &leaf_addr
        );
        assert_eq!(forwarded.ipv6[7], 63);
        assert_eq!(dao_parts(&forwarded.ipv6).unwrap().1, signed);
    }

    #[tokio::test]
    async fn three_rpl_stacks_send_leaf_dao_via_preferred_parent() {
        let root_identity = identity(16);
        let relay_identity = identity(17);
        let leaf_identity = identity(18);
        let root_addr = address(&root_identity, 1);
        let relay_addr = address(&relay_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let mut root_eui64 = root_identity.iid;
        root_eui64[0] ^= 0x02;
        let mut relay_eui64 = relay_identity.iid;
        relay_eui64[0] ^= 0x02;
        let mut leaf_eui64 = leaf_identity.iid;
        leaf_eui64[0] ^= 0x02;
        let (mesh, [root_radio, relay_radio, leaf_radio]) =
            MeshHarness::new([root_eui64, relay_eui64, leaf_eui64]);
        let prefix = root_addr[..8].try_into().unwrap();
        let mut root = RplStack::provision_root(
            Stack::new(root_radio, root_identity.clone(), 128),
            root_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        let mut relay = RplStack::provision_leaf(
            Stack::new(relay_radio, relay_identity.clone(), 129),
            relay_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        let mut leaf = RplStack::provision_leaf(
            Stack::new(leaf_radio, leaf_identity.clone(), 129),
            leaf_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();

        relay
            .send_announce(&signed_announce(&relay_identity, 1), 0)
            .await
            .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        for _ in 0..2 {
            assert!(matches!(
                relay.receive(1, 0).await,
                Err(RplReceiveError::Receive(RxError::Link(
                    LinkRxError::UnknownSender
                )))
            ));
        }

        root.send_announce(&signed_announce(&root_identity, 1), 0)
            .await
            .unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementRejected(
                AnnounceRejectReason::StaleSeqNum
            ))
        ));
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        assert!(matches!(
            relay.receive(1, 0).await,
            Err(RplReceiveError::Receive(RxError::Link(
                LinkRxError::UnknownSender
            )))
        ));
        root.send_dio(relay_addr).await.unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));

        relay.send_dio(leaf_addr).await.unwrap();
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));
        assert_eq!(leaf.rpl_node().preferred_parent(), Some(relay_addr));

        leaf.send_announce(&signed_announce(&leaf_identity, 1), 0)
            .await
            .unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { relayed: true, .. })
        ));
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { peer, .. })
                if peer.iid == leaf_identity.iid
        ));
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementRejected(
                AnnounceRejectReason::StaleSeqNum
            ))
        ));
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementRejected(
                AnnounceRejectReason::StaleSeqNum
            ))
        ));
        root.admit_dao_origin(relay_identity.iid).unwrap();
        root.admit_dao_origin(leaf_identity.iid).unwrap();

        leaf.send_dis(relay_addr).await.unwrap();
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DisReceived))
        ));
        assert!(matches!(
            leaf.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Rpl(RplEvent::DioReceived { .. }))
        ));

        relay.send_dao().await.unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Applied))
        ));
        let before_leaf = mesh.sent().len();

        leaf.send_dao().await.unwrap();
        let sent = mesh.sent();
        let originated = LichenFrame::from_bytes(&sent[before_leaf]).unwrap();
        assert_eq!(originated.addr_mode, AddrMode::Extended);
        assert_eq!(originated.dst_addr, relay_eui64);
        assert!(matches!(
            relay.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Forwarded { next_hop }) if next_hop == root_addr
        ));
        let sent = mesh.sent();
        let forwarded = LichenFrame::from_bytes(&sent[before_leaf + 1]).unwrap();
        assert_eq!(forwarded.addr_mode, AddrMode::Extended);
        assert_eq!(forwarded.dst_addr, root_eui64);
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Applied))
        ));
        assert_eq!(
            root.rpl_node().router.lookup_route(&leaf_addr),
            Some([relay_addr, leaf_addr].as_slice())
        );
    }

    #[tokio::test]
    async fn root_dispatch_installs_route_and_failures_do_not_mutate() {
        let root_identity = identity(8);
        let leaf_identity = identity(9);
        let unknown_identity = identity(10);
        let root_addr = address(&root_identity, 1);
        let leaf_addr = address(&leaf_identity, 1);
        let unknown_addr = address(&unknown_identity, 1);
        let (leaf_radio, root_radio) = LoopbackRadio::pair();
        let mut leaf = Stack::new_default_epoch(leaf_radio, leaf_identity.clone());
        leaf.add_peer(PeerIdentity::from_pubkey(root_identity.pubkey));
        let root_stack = Stack::new_default_epoch(root_radio, root_identity.clone());
        let prefix = root_addr[..8].try_into().unwrap();
        let mut root = RplStack::provision_root(
            root_stack,
            root_addr,
            root_addr,
            announces(prefix),
            MemStorage::new(),
        )
        .unwrap();
        send_announce(&mut leaf, &leaf_identity, 1).await;
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        let mut leaf_storage = MemStorage::new();
        let mut leaf_tx = DaoTxState::provision(
            &mut leaf_storage,
            leaf_identity.pubkey,
            leaf_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            root_addr,
        )
        .unwrap();
        let leaf_link = LinkLayer::new(leaf_identity.clone());
        let mut leaf_router = Router::new(leaf_addr, root_addr);
        let dio = Dio {
            rpl_instance_id: lichen_core::constants::RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let mut dio_body = [0u8; Dio::BASE_LEN];
        let dio_len = dio.write_to(&mut dio_body).unwrap();
        assert!(leaf_router.process_dio(&dio, &dio_body[..dio_len], root_addr, 0, 0));
        let signed = leaf_router
            .build_signed_dao(leaf_addr, &mut leaf_tx, &mut leaf_storage, &leaf_link)
            .unwrap();
        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &signed).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::DaoOriginNotAdmitted)
        ));
        assert!(root.rpl.router.dao_origin_keys().is_empty());
        assert!(root.rpl_node().router.lookup_route(&leaf_addr).is_none());

        root.admit_dao_origin(leaf_identity.iid).unwrap();
        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &signed).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Applied))
        ));
        assert_eq!(
            root.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );
        let persisted = root.storage().clone();
        let mut replay_only = MemStorage::new();
        for key in ["rpl.rx.a", "rpl.rx.b"] {
            if let Some(value) = persisted.raw(key) {
                replay_only.set_raw(key, value);
            }
        }
        assert!(matches!(
            provision_or_resume_root_state(
                &mut replay_only,
                root_addr,
                lichen_core::constants::RPL_INSTANCE_ID,
                root_addr,
            ),
            Err(RplStackProvisionError::ExistingNonEmpty)
        ));
        assert!(matches!(
            DaoAdmissionState::open(
                &replay_only,
                root_addr,
                lichen_core::constants::RPL_INSTANCE_ID,
                root_addr,
            ),
            Err(DaoPersistentOpenError::Missing)
        ));
        let (_peer_radio, reopened_radio) = LoopbackRadio::pair();
        let reopened = RplStack::open_root(
            Stack::new(reopened_radio, root_identity.clone(), 129),
            root_addr,
            root_addr,
            announces(prefix),
            persisted,
        )
        .unwrap();
        assert!(reopened
            .dao_admissions
            .as_ref()
            .is_some_and(|admissions| admissions.contains(leaf_identity.pubkey.as_bytes())));

        let mut substituted_source = leaf_addr;
        substituted_source[0] ^= 1;
        leaf.send_ipv6_to(
            &dao_ipv6_packet(substituted_source, root_addr, &signed).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::BadSignature))
        ));
        assert!(root
            .rpl_node()
            .router
            .lookup_route(&substituted_source)
            .is_none());

        let before = root.rpl_node().router.lookup_route(&unknown_addr);
        assert!(before.is_none());
        let mut unknown_storage = MemStorage::new();
        let mut unknown_tx = DaoTxState::provision(
            &mut unknown_storage,
            unknown_identity.pubkey,
            unknown_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            root_addr,
        )
        .unwrap();
        let unknown_link = LinkLayer::new(unknown_identity.clone());
        let mut unknown_router = Router::new(unknown_addr, root_addr);
        assert!(unknown_router.process_dio(&dio, &dio_body[..dio_len], leaf_addr, 0, 0));
        let unknown_dao = unknown_router
            .build_signed_dao(
                unknown_addr,
                &mut unknown_tx,
                &mut unknown_storage,
                &unknown_link,
            )
            .unwrap();
        leaf.send_ipv6_to(
            &dao_ipv6_packet(unknown_addr, root_addr, &unknown_dao).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::DaoOriginNotAdmitted)
        ));
        assert!(root.rpl_node().router.lookup_route(&unknown_addr).is_none());

        let mut second = leaf_router
            .build_signed_dao(leaf_addr, &mut leaf_tx, &mut leaf_storage, &leaf_link)
            .unwrap();
        second[3] ^= 1;
        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &second).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::BadSignature))
        ));
        assert_eq!(
            root.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );

        let third = leaf_router
            .build_signed_dao(leaf_addr, &mut leaf_tx, &mut leaf_storage, &leaf_link)
            .unwrap();
        root.fail_next_storage_write();
        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &third).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Persistence))
        ));
        assert_eq!(
            root.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );

        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &third).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Applied))
        ));

        let mut malformed_unsigned = SignedDaoEnvelope::from_bytes(&signed)
            .unwrap()
            .unsigned_bytes
            .to_vec();
        assert_eq!(malformed_unsigned[20], lichen_rpl::message::OPT_RPL_TARGET);
        malformed_unsigned[23] = 127;
        let malformed_replay = resign_dao(&malformed_unsigned, leaf_addr, root_addr, 1, &leaf_link);
        let fourth = leaf_router
            .build_signed_dao(leaf_addr, &mut leaf_tx, &mut leaf_storage, &leaf_link)
            .unwrap();

        let persisted = root.storage().clone();
        let (leaf_radio, root_radio) = LoopbackRadio::pair();
        let mut leaf = Stack::new(leaf_radio, leaf_identity.clone(), 129);
        let root_stack = Stack::new(root_radio, root_identity, 129);
        let mut reopened = RplStack::open_root(
            root_stack,
            root_addr,
            root_addr,
            announces(prefix),
            persisted,
        )
        .unwrap();
        send_announce(&mut leaf, &leaf_identity, 1).await;
        assert!(matches!(
            reopened.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::AnnouncementAccepted { .. })
        ));
        reopened.fail_next_storage_write();
        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &third).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            reopened.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Duplicate))
        ));
        assert_eq!(
            reopened.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );

        for replay in [&signed, &malformed_replay] {
            leaf.send_ipv6_to(
                &dao_ipv6_packet(leaf_addr, root_addr, replay).unwrap(),
                &ipv6_eui64(root_addr),
            )
            .await
            .unwrap();
            assert!(matches!(
                reopened.receive(1, 0).await.unwrap(),
                Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Replay))
            ));
        }
        assert_eq!(
            reopened.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );

        leaf.send_ipv6_to(
            &dao_ipv6_packet(leaf_addr, root_addr, &fourth).unwrap(),
            &ipv6_eui64(root_addr),
        )
        .await
        .unwrap();
        assert!(matches!(
            reopened.receive(1, 0).await.unwrap(),
            Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Persistence))
        ));
        assert_eq!(
            reopened.rpl_node().router.lookup_route(&leaf_addr),
            Some([leaf_addr].as_slice())
        );
    }

    #[test]
    fn announce_tofu_churn_does_not_admit_dao_origins() {
        let root_identity = identity(200);
        let root_addr = address(&root_identity, 1);
        let (_peer_radio, root_radio) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();

        for seed in 0..=u8::MAX {
            root.announces.pin_for_test(identity(seed).pubkey);
        }
        assert!(root
            .dao_admissions
            .as_ref()
            .is_some_and(DaoAdmissionState::is_empty));
        assert!(root.rpl.router.dao_origin_keys().is_empty());
    }

    #[test]
    fn dao_origin_admission_is_bounded_without_eviction() {
        let root_identity = identity(201);
        let root_addr = address(&root_identity, 1);
        let (_peer_radio, root_radio) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        let identity_for = |value: u16| {
            let mut seed = [0u8; 32];
            seed[..2].copy_from_slice(&value.to_be_bytes());
            Identity::from_seed(Seed::new(seed))
        };

        for value in 0..lichen_rpl::routing::MAX_DAO_ORIGINS as u16 {
            let identity = identity_for(value);
            root.announces.pin_for_test(identity.pubkey);
            root.admit_dao_origin(identity.iid).unwrap();
        }
        let first = identity_for(0);
        assert!(root
            .dao_admissions
            .as_ref()
            .is_some_and(|admissions| admissions.contains(first.pubkey.as_bytes())));
        let overflow = identity_for(lichen_rpl::routing::MAX_DAO_ORIGINS as u16);
        root.announces.pin_for_test(overflow.pubkey);
        assert_eq!(
            root.admit_dao_origin(overflow.iid),
            Err(DaoAdmissionError::Capacity)
        );
        assert_eq!(
            root.dao_admissions.as_ref().map(DaoAdmissionState::len),
            Some(lichen_rpl::routing::MAX_DAO_ORIGINS)
        );
    }

    #[test]
    fn dao_origin_admission_survives_restart_before_first_dao() {
        let root_identity = identity(202);
        let root_addr = address(&root_identity, 1);
        let admitted = identity(203);
        let (_peer_radio, root_radio) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity.clone()),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        root.announces.pin_for_test(admitted.pubkey);
        root.admit_dao_origin(admitted.iid).unwrap();
        assert!(root.rpl.router.dao_origin_keys().is_empty());

        let storage = root.storage().clone();
        let (_peer_radio, reopened_radio) = LoopbackRadio::pair();
        let reopened = RplStack::open_root(
            Stack::new_default_epoch(reopened_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            storage,
        )
        .unwrap();
        assert!(reopened.rpl.router.dao_origin_keys().is_empty());
        assert!(reopened
            .dao_admissions
            .as_ref()
            .is_some_and(|admissions| admissions.contains(admitted.pubkey.as_bytes())));
    }

    #[test]
    fn failed_dao_admission_write_changes_neither_ram_nor_storage() {
        let root_identity = identity(204);
        let root_addr = address(&root_identity, 1);
        let admitted = identity(205);
        let (_peer_radio, root_radio) = LoopbackRadio::pair();
        let mut root = RplStack::provision_root(
            Stack::new_default_epoch(root_radio, root_identity.clone()),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap();
        root.announces.pin_for_test(admitted.pubkey);
        root.fail_next_storage_write();
        assert!(matches!(
            root.admit_dao_origin(admitted.iid),
            Err(DaoAdmissionError::Persistence(_))
        ));
        assert!(!root
            .dao_admissions
            .as_ref()
            .is_some_and(|admissions| admissions.contains(admitted.pubkey.as_bytes())));

        let storage = root.storage().clone();
        let (_peer_radio, reopened_radio) = LoopbackRadio::pair();
        let reopened = RplStack::open_root(
            Stack::new_default_epoch(reopened_radio, root_identity),
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            storage,
        )
        .unwrap();
        assert!(!reopened
            .dao_admissions
            .as_ref()
            .is_some_and(|admissions| admissions.contains(admitted.pubkey.as_bytes())));
    }

    #[test]
    fn root_provisioning_resumes_each_write_boundary() {
        let root_identity = identity(206);
        let root_addr = address(&root_identity, 1);
        let instance = lichen_core::constants::RPL_INSTANCE_ID;

        for successful_writes in 0..=1 {
            let mut storage = MemStorage::new();
            storage.fail_after_writes(successful_writes);
            let error =
                provision_or_resume_root_state(&mut storage, root_addr, instance, root_addr)
                    .unwrap_err();
            if successful_writes == 0 {
                assert!(matches!(
                    error,
                    RplStackProvisionError::Admission(DaoProvisionError::Storage(_))
                ));
                assert!(matches!(
                    DaoAdmissionState::open(&storage, root_addr, instance, root_addr),
                    Err(DaoPersistentOpenError::Missing)
                ));
            } else {
                assert!(matches!(
                    error,
                    RplStackProvisionError::Dao(DaoProvisionError::Storage(_))
                ));
                assert!(DaoAdmissionState::open(&storage, root_addr, instance, root_addr).is_ok());
            }
            assert!(matches!(
                Router::open_root(&storage, root_addr),
                Err(DaoPersistentOpenError::Missing)
            ));

            provision_or_resume_root_state(&mut storage, root_addr, instance, root_addr).unwrap();
            assert!(DaoAdmissionState::open(&storage, root_addr, instance, root_addr).is_ok());
            assert!(Router::open_root(&storage, root_addr).is_ok());
        }
    }

    #[test]
    fn root_provisioning_resumes_either_matching_empty_partial_state() {
        let root_identity = identity(207);
        let root_addr = address(&root_identity, 1);
        let instance = lichen_core::constants::RPL_INSTANCE_ID;

        let mut admission_only = MemStorage::new();
        DaoAdmissionState::provision(&mut admission_only, root_addr, instance, root_addr).unwrap();
        let (_peer, radio) = LoopbackRadio::pair();
        assert!(matches!(
            RplStack::open_root(
                Stack::new_default_epoch(radio, root_identity.clone()),
                root_addr,
                root_addr,
                announces(root_addr[..8].try_into().unwrap()),
                admission_only.clone(),
            ),
            Err(RplStackOpenError::Dao(DaoPersistentOpenError::Missing))
        ));
        provision_or_resume_root_state(&mut admission_only, root_addr, instance, root_addr)
            .unwrap();

        let mut replay_only = MemStorage::new();
        Router::provision_root(&mut replay_only, root_addr).unwrap();
        let (_peer, radio) = LoopbackRadio::pair();
        assert!(matches!(
            RplStack::open_root(
                Stack::new_default_epoch(radio, root_identity),
                root_addr,
                root_addr,
                announces(root_addr[..8].try_into().unwrap()),
                replay_only.clone(),
            ),
            Err(RplStackOpenError::Admission(
                DaoPersistentOpenError::Missing
            ))
        ));
        provision_or_resume_root_state(&mut replay_only, root_addr, instance, root_addr).unwrap();
        assert!(Router::open_root(&replay_only, root_addr).is_ok());
        assert!(DaoAdmissionState::open(&replay_only, root_addr, instance, root_addr).is_ok());
    }

    #[test]
    fn root_provisioning_rejects_mismatched_and_nonempty_partials() {
        let root_identity = identity(208);
        let root_addr = address(&root_identity, 1);
        let other_addr = address(&identity(209), 1);
        let instance = lichen_core::constants::RPL_INSTANCE_ID;

        let mut wrong_admission = MemStorage::new();
        DaoAdmissionState::provision(&mut wrong_admission, other_addr, instance, other_addr)
            .unwrap();
        assert!(matches!(
            provision_or_resume_root_state(&mut wrong_admission, root_addr, instance, root_addr,),
            Err(RplStackProvisionError::Admission(DaoProvisionError::Open(
                DaoPersistentOpenError::ScopeMismatch
            )))
        ));
        assert!(matches!(
            Router::open_root(&wrong_admission, root_addr),
            Err(DaoPersistentOpenError::Missing)
        ));

        let mut wrong_replay = MemStorage::new();
        Router::provision_root(&mut wrong_replay, other_addr).unwrap();
        assert!(matches!(
            provision_or_resume_root_state(&mut wrong_replay, root_addr, instance, root_addr),
            Err(RplStackProvisionError::Dao(DaoProvisionError::Open(
                DaoPersistentOpenError::ScopeMismatch
            )))
        ));
        assert!(matches!(
            DaoAdmissionState::open(&wrong_replay, root_addr, instance, root_addr),
            Err(DaoPersistentOpenError::Missing)
        ));

        let mut nonempty_admission = MemStorage::new();
        let mut admissions =
            DaoAdmissionState::provision(&mut nonempty_admission, root_addr, instance, root_addr)
                .unwrap();
        admissions
            .admit(&mut nonempty_admission, *identity(210).pubkey.as_bytes())
            .unwrap();
        assert!(matches!(
            provision_or_resume_root_state(&mut nonempty_admission, root_addr, instance, root_addr,),
            Err(RplStackProvisionError::ExistingNonEmpty)
        ));
        assert!(matches!(
            Router::open_root(&nonempty_admission, root_addr),
            Err(DaoPersistentOpenError::Missing)
        ));
    }
}
