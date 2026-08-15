// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Tests for the RPL stack.

use std::vec;

use super::*;
use crate::announce::MAX_TRACKED_ORIGINATORS;
use crate::routing::{DaoRxState, Router, ROOT_RANK};
use crate::runtime::{RplRuntimeAction, RplRuntimeActionError, RplRuntimeConfig};
use crate::secure::SecureStack;
use crate::stack::{Priority, Stack, TxError, MAX_FRAME_SIZE};

use lichen_core::announce::AnnounceBuilder;
use lichen_core::constants::L2_DISPATCH_ROUTING;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_hal::loopback::LoopbackRadio;
use lichen_hal::storage::mem::MemStorage;
use lichen_hal::{ChannelConfig, Radio, RadioConfig, RxPacket};
use lichen_ipv6::{Addr, Ipv6Header};
use lichen_link::frame::{AddrMode, LichenFrame};
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::keys::Seed;
use lichen_link::link_layer::{LinkLayer, LinkRxError};
use lichen_link::schnorr;
use lichen_oscore::{Context, SenderStateStore};
use lichen_rpl::message::{DaoOriginSignature, Dio, SignedDaoEnvelope};
use lichen_rpl::routing::{
    DaoAdmissionState, DaoPersistentOpenError, DaoProvisionError, DaoTxError, DaoTxState,
};
use lichen_schc::codec;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use crate::announce::{AnnounceProcessor, AnnounceRejectReason};
use crate::node::{rpl_code, valid_rpl_ipv6, RplEvent};
use crate::runtime::RplRuntime;
use crate::secure::{SecureResponse, SecureResponseData};

use super::error::{RplReceiveError, RplRuntimeReceiveError, RplRuntimeTrickleError};
use super::provisioning::provision_or_resume_root_state;
use super::util::{
    advance_rpl_source_route, dao_ipv6_packet, dao_parts, eui64_link_local, ipv6_eui64,
    link_local_from_iid, multicast_dis_jitter, rpl_ipv6_packet, RPL_ALL_NODES,
};

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

#[derive(Default)]
struct RuntimeRadioState {
    receive_timeouts: Vec<u32>,
    transmitted: Vec<Vec<u8>>,
}

struct RuntimeRadio(Arc<Mutex<RuntimeRadioState>>);

#[derive(Default)]
struct TestOscoreStore(Option<(lichen_oscore::ContextId, lichen_oscore::SenderSequenceState)>);

impl SenderStateStore for TestOscoreStore {
    type Error = ();

    fn load(
        &mut self,
        context_id: &lichen_oscore::ContextId,
    ) -> Result<Option<lichen_oscore::SenderSequenceState>, Self::Error> {
        Ok(Some(
            self.0
                .filter(|(stored_context, _)| stored_context == context_id)
                .map_or(
                    lichen_oscore::SenderSequenceState {
                        next_sequence: 0,
                        exhausted: false,
                    },
                    |(_, state)| state,
                ),
        ))
    }

    fn compare_exchange(
        &mut self,
        context_id: &lichen_oscore::ContextId,
        expected: Option<lichen_oscore::SenderSequenceState>,
        next: lichen_oscore::SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.load(context_id)? != expected {
            return Ok(false);
        }
        self.0 = Some((*context_id, next));
        Ok(true)
    }
}

impl Radio for RuntimeRadio {
    type Error = Infallible;

    async fn transmit(&mut self, _channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        self.0.lock().unwrap().transmitted.push(payload.to_vec());
        Ok(())
    }

    async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn receive(
        &mut self,
        _channel: u8,
        _buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        self.0.lock().unwrap().receive_timeouts.push(timeout_ms);
        Ok(None)
    }

    fn configure(&mut self, _config: &RadioConfig) {}

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl FailOnceRadio {
    fn fail_next(&mut self) {
        self.fail_next = true;
    }
}

impl Radio for FailOnceRadio {
    type Error = ();

    async fn transmit(&mut self, channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.fail_next) {
            return Err(());
        }
        self.inner.transmit(channel, payload).await.map_err(|_| ())
    }

    async fn cca(&mut self, channel: u8, threshold_dbm: i8) -> Result<bool, Self::Error> {
        self.inner.cca(channel, threshold_dbm).await.map_err(|_| ())
    }

    async fn receive(
        &mut self,
        channel: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        self.inner
            .receive(channel, buf, timeout_ms)
            .await
            .map_err(|_| ())
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.inner.configure(config);
    }

    async fn configure_channels(&mut self, channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        self.inner
            .configure_channels(channels)
            .await
            .map_err(|_| ())
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

    async fn transmit(&mut self, _channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.sent.push(payload.to_vec());
        deliver(&mut state, Some(self.index), payload);
        Ok(())
    }

    async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn receive(
        &mut self,
        _channel: u8,
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

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn identity(seed: u8) -> Identity {
    Identity::from_seed(Seed::new([seed; 32]))
}

fn runtime_root() -> (
    RplStack<RuntimeRadio, MemStorage>,
    Arc<Mutex<RuntimeRadioState>>,
) {
    let identity = identity(254);
    let root_addr = address(&identity, 1);
    let state = Arc::new(Mutex::new(RuntimeRadioState::default()));
    let stack = Stack::new_default_epoch(RuntimeRadio(Arc::clone(&state)), identity);
    (
        RplStack::provision_root(
            stack,
            root_addr,
            root_addr,
            announces(root_addr[..8].try_into().unwrap()),
            MemStorage::new(),
        )
        .unwrap(),
        state,
    )
}

#[tokio::test]
async fn runtime_receive_uses_planned_timeout_and_post_await_clock() {
    let (mut root, radio) = runtime_root();
    let mut runtime = RplRuntime::new(RplRuntimeConfig::default(), 0);
    let poll = root.runtime_poll(&mut runtime, 0).unwrap();
    let action = poll.action;
    assert_eq!(action, RplRuntimeAction::Receive { timeout_ms: 1_000 });

    assert!(matches!(
        root.runtime_poll(&mut runtime, 10),
        Err(RplRuntimeActionError::PollWithPending)
    ));

    let completion = root
        .runtime_receive(&mut runtime, action, || 1_000)
        .await
        .unwrap();
    assert_eq!(completion.now_ms, 1_000);
    assert_eq!(
        completion.maintenance,
        Some(RplMaintenanceOutcome::default())
    );
    assert!(completion.received.is_none());
    assert_eq!(radio.lock().unwrap().receive_timeouts, [1_000]);

    assert!(matches!(
        root.runtime_receive(
            &mut runtime,
            RplRuntimeAction::Receive { timeout_ms: 9_999 },
            || 2_000,
        )
        .await,
        Err(RplRuntimeReceiveError::Action(
            RplRuntimeActionError::ActionNotPending
        ))
    ));
    assert_eq!(radio.lock().unwrap().receive_timeouts, [1_000]);
}

#[tokio::test]
async fn runtime_completes_trickle_multicast_suppression_and_expiry() {
    let (mut root, radio) = runtime_root();
    // Configure a small trickle interval (imin=8ms) for fast test execution.
    // With imin=8, half=4, so transmit_time=0+4=4 and interval_end=0+8=8.
    root.rpl.router.trickle = lichen_rpl::trickle::TrickleTimer::new(8, 8, 10);
    root.trickle_start(0, 0);
    let mut runtime = RplRuntime::new(RplRuntimeConfig::default(), 0);
    let transmit = root.runtime_poll(&mut runtime, 4).unwrap().action;
    assert_eq!(transmit, RplRuntimeAction::TrickleTransmit);
    assert_eq!(
        root.runtime_complete_trickle_transmit(&mut runtime, transmit, 4)
            .await
            .unwrap(),
        RplTrickleTransmitOutcome::Sent
    );
    let sent = radio.lock().unwrap().transmitted.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        LichenFrame::from_bytes(&sent[0]).unwrap().addr_mode,
        AddrMode::None
    );

    let expire = root.runtime_poll(&mut runtime, 8).unwrap().action;
    assert_eq!(expire, RplRuntimeAction::TrickleExpire);
    root.runtime_complete_trickle_expire(&mut runtime, expire, 8, 0)
        .unwrap();
    assert_eq!(
        root.runtime_poll(&mut runtime, 8).unwrap().action,
        RplRuntimeAction::Receive { timeout_ms: 8 }
    );

    let (mut suppressed, suppressed_radio) = runtime_root();
    // Same small trickle interval for suppression test
    suppressed.rpl.router.trickle = lichen_rpl::trickle::TrickleTimer::new(8, 8, 10);
    suppressed.trickle_start(0, 0);
    for _ in 0..10 {
        suppressed.rpl.router.trickle_consistent();
    }
    let mut runtime = RplRuntime::new(RplRuntimeConfig::default(), 0);
    let action = suppressed.runtime_poll(&mut runtime, 4).unwrap().action;
    assert_eq!(
        suppressed
            .runtime_complete_trickle_transmit(&mut runtime, action, 4)
            .await
            .unwrap(),
        RplTrickleTransmitOutcome::Suppressed
    );
    assert!(suppressed_radio.lock().unwrap().transmitted.is_empty());
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

#[test]
fn rfc6554_route_crosses_two_relays_and_restores_packet() {
    let source = address(&identity(60), 1);
    let relay_one = address(&identity(61), 1);
    let relay_two = address(&identity(62), 1);
    let destination = address(&identity(63), 1);
    let mut plain = vec![0u8; IPV6_HEADER_LEN + 8];
    Ipv6Header::new(59, Addr(source), Addr(destination))
        .write_to(8, &mut plain)
        .unwrap();
    plain[IPV6_HEADER_LEN..].copy_from_slice(b"payload!");

    let mut wire = [0u8; 512];
    let len =
        crate::stack::add_rpl_source_route(&plain, &[relay_one, relay_two, destination], &mut wire)
            .unwrap();
    let mut routed = wire[..len].to_vec();
    assert_eq!(&routed[24..40], &relay_one);
    assert_eq!(&routed[40..48], &[59, 4, 3, 2, 0, 0, 0, 0]);
    assert_eq!(&routed[48..64], &relay_two);
    assert_eq!(&routed[64..80], &destination);
    assert_eq!(routed[43], 2);

    assert_eq!(
        advance_rpl_source_route(&mut routed, relay_one, source[8..].try_into().unwrap()).unwrap(),
        Some(relay_two)
    );
    assert_eq!(routed[43], 1);
    assert_eq!(
        advance_rpl_source_route(&mut routed, relay_two, relay_one[8..].try_into().unwrap(),)
            .unwrap(),
        Some(destination)
    );
    assert_eq!(routed[43], 0);
    assert_eq!(
        advance_rpl_source_route(&mut routed, destination, relay_two[8..].try_into().unwrap(),)
            .unwrap(),
        None
    );
    assert_eq!(routed, plain);
}

#[tokio::test]
async fn plaintext_coap_is_not_delivered_by_rpl_owner() {
    let (sender_radio, receiver_radio) = LoopbackRadio::pair();
    let sender_identity = identity(51);
    let receiver_identity = identity(52);
    let receiver_addr = address(&receiver_identity, 1);

    let mut sender = Stack::new_default_epoch(sender_radio, sender_identity.clone());
    sender.add_peer(PeerIdentity::from_pubkey(receiver_identity.pubkey));
    let mut receiver =
        SecureStack::new(Stack::new_default_epoch(receiver_radio, receiver_identity));
    receiver.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let mut owner = RplStack::provision_leaf(
        receiver,
        receiver_addr,
        receiver_addr,
        announces(receiver_addr[..8].try_into().unwrap()),
        MemStorage::new(),
    )
    .unwrap();

    sender
        .send_coap_raw(&Addr(receiver_addr), &[0x40, 0x01, 0x12, 0x34], Priority::Normal)
        .await
        .unwrap();

    assert!(matches!(
        owner.receive(0, 0).await,
        Err(RplReceiveError::Receive(
            crate::stack::RxError::PlaintextCoap
        ))
    ));

    let mut extension = vec![0u8; IPV6_HEADER_LEN + 8];
    Ipv6Header::new(43, Addr(receiver_addr), Addr(receiver_addr))
        .write_to(8, &mut extension)
        .unwrap();
    assert_eq!(
        owner.send_ipv6(&extension, 0).await.unwrap_err(),
        TxError::UnsupportedIpv6Extension
    );
}

fn signed_announce(identity: &Identity, sequence: u16) -> Vec<u8> {
    let rx_channel = 3;
    let mut signed = Vec::new();
    signed.extend_from_slice(&identity.iid);
    signed.extend_from_slice(identity.pubkey.as_bytes());
    signed.extend_from_slice(&sequence.to_be_bytes());
    signed.push(rx_channel);
    let signature = schnorr::sign(&identity.privkey, &identity.pubkey, &signed);
    let mut wire = vec![0u8; 93];
    let len = AnnounceBuilder {
        originator_iid: &identity.iid,
        pubkey: identity.pubkey.as_bytes(),
        seq_num: sequence,
        hop_count: 0,
        rx_channel,
        signature: &signature,
        app_data: &[],
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
    dio_packet_from(root, destination, root, ROOT_RANK)
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
    rpl_ipv6_packet(source, destination, rpl_code::DIO, &body[..len]).unwrap()
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
        .receive(0, &mut relayed, 1)
        .await
        .unwrap()
        .is_some());
    sender
        .send_ipv6_to(&dio_packet(root_addr, leaf_addr), &ipv6_eui64(leaf_addr), Priority::Routing)
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
        let announce = lichen_core::announce::Announce::from_bytes(&wire).unwrap();
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
        transmitter.transmit(0, &wire[..len]).await.unwrap();
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
    transmitter.transmit(0, &wire[..len]).await.unwrap();
    assert!(matches!(
        root.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::AnnouncementRejected(
            AnnounceRejectReason::InvalidSignature
        ))
    ));
    assert!(root.stack.link().pinned_pubkey_for(&rejected_iid).is_none());
    // Bootstrap added the peer (evicting oldest), then rejection removed it.
    // Net result: one fewer peer than before the bad announce.
    assert_eq!(root.stack.link().peer_count(), MAX_TRACKED_ORIGINATORS - 1);

    let valid = signed_announce(&rejected_identity, 1);
    let len = send(&valid, &mut wire);
    transmitter.transmit(0, &wire[..len]).await.unwrap();
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
        root.send_ipv6_to(&packet, &ipv6_eui64(leaf_addr), Priority::Routing)
            .await
            .unwrap();
        assert!(matches!(
            leaf.receive(1, 1).await.unwrap(),
            Some(RplReceiveOutcome::RplRejected)
        ));
    }

    // Note: Tests that corrupt version (byte 0) or payload length (bytes 4-5)
    // cannot work via send_ipv6_to because SCHC compression elides these fields.
    // Decompression reconstructs them from the rule, so corruptions are "healed".
    // Testing SCHC rejection of malformed compressed payloads requires sending
    // raw link-layer frames with corrupted SCHC data, which is out of scope here.
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
    let len = observer
        .receive(0, &mut wire, 1)
        .await
        .unwrap()
        .unwrap()
        .len;
    let frame = LichenFrame::from_bytes(&wire[..len]).unwrap();
    assert_eq!(frame.addr_mode, AddrMode::None);
    assert!(frame.dst_addr.is_empty());

    root.send_dis(multicast).await.unwrap();
    let len = observer
        .receive(0, &mut wire, 1)
        .await
        .unwrap()
        .unwrap()
        .len;
    let frame = LichenFrame::from_bytes(&wire[..len]).unwrap();
    assert_eq!(frame.addr_mode, AddrMode::None);
    assert!(frame.dst_addr.is_empty());

    root.send_dio(unicast).await.unwrap();
    let len = observer
        .receive(0, &mut wire, 1)
        .await
        .unwrap()
        .unwrap()
        .len;
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
    // Default DodagConfig uses dio_int_min=12, so imin=4096ms, range=2048ms.
    // Find a second identity with a different jitter offset (mod 2048).
    let second_identity = (242..=u8::MAX)
        .map(identity)
        .find(|candidate| {
            multicast_dis_jitter(ipv6_eui64(address(candidate, 1)), sender_addr, 100) % 2048
                != multicast_dis_jitter(first_eui64, sender_addr, 100) % 2048
        })
        .expect("hash-based jitter provides distinct offsets for different identities");
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

    let packet = rpl_ipv6_packet(sender_addr, RPL_ALL_NODES, rpl_code::DIS, &[0, 0]).unwrap();
    let mut schc = [0u8; 200];
    let schc_len = codec::compress(&packet, &mut schc).unwrap();
    let mut payload = [0u8; 201];
    payload[0] = lichen_core::constants::L2_DISPATCH_SCHC;
    payload[1..1 + schc_len].copy_from_slice(&schc[..schc_len]);
    let mut wire = [0u8; MAX_FRAME_SIZE];
    let len = LinkLayer::new(sender)
        .build_frame(128, 0u16.into(), &[], &payload[..1 + schc_len], &mut wire)
        .unwrap();
    first_tx.transmit(0, &wire[..len]).await.unwrap();
    second_tx.transmit(0, &wire[..len]).await.unwrap();
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
    // Default DodagConfig: dio_int_min=12 -> imin=4096ms.
    // Trickle transmit_time = now + half + (jitter % range) where half=2048, range=2048.
    // For now=100: transmit_time in [100+2048, 100+2048+2048) = [2148, 4196).
    assert!(
        (2148..4196).contains(&first_at),
        "first_at={first_at} not in [2148, 4196)"
    );
    assert!(
        (2148..4196).contains(&second_at),
        "second_at={second_at} not in [2148, 4196)"
    );
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
    let unrelated = [0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 0];

    for (destination, accepted) in [(unrelated, false), (RPL_ALL_NODES, true)] {
        let packet = dio_packet_from(root_addr, destination, root_addr, ROOT_RANK);
        let schc_len = codec::compress(&packet, &mut schc).unwrap();
        payload[0] = lichen_core::constants::L2_DISPATCH_SCHC;
        payload[1..1 + schc_len].copy_from_slice(&schc[..schc_len]);
        let len = link
            .build_frame(128, 0u16.into(), &[], &payload[..1 + schc_len], &mut wire)
            .unwrap();
        sender_radio.transmit(0, &wire[..len]).await.unwrap();
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
        rank: ROOT_RANK,
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
        let packet = rpl_ipv6_packet(sender_addr, foreign_addr, code, body).unwrap();
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
    leaf_tx.transmit(0, &dio_wire).await.unwrap();
    assert!(matches!(
        leaf.receive(1, 100).await.unwrap(),
        Some(RplReceiveOutcome::RplRejected)
    ));
    assert!(!leaf.rpl_node().is_joined());

    let dis_wire = build_wire(rpl_code::DIS, &[0, 0]);
    root_tx.transmit(0, &dis_wire).await.unwrap();
    assert!(matches!(
        root.receive(1, 100).await.unwrap(),
        Some(RplReceiveOutcome::RplRejected)
    ));
    assert_eq!(
        root.rpl_node().router.poll_trickle(),
        lichen_rpl::trickle::TrickleEvent::Stopped
    );
    let mut response = [0u8; MAX_FRAME_SIZE];
    assert!(root_tx
        .receive(0, &mut response, 1)
        .await
        .unwrap()
        .is_none());
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
    intended_tx.transmit(0, &wire[..len]).await.unwrap();
    other_tx.transmit(0, &wire[..len]).await.unwrap();

    assert!(matches!(
        intended.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::AnnouncementAccepted { .. })
    ));
    assert!(other.receive(1, 0).await.unwrap().is_none());

    let len = link
        .build_frame(128, 0u16.into(), &[], &payload, &mut wire)
        .unwrap();
    other_tx.transmit(0, &wire[..len]).await.unwrap();
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
    let mut root_sender = Stack::new(root_radio, root_identity.clone(), 129, 0);
    root_sender.add_peer(PeerIdentity::from_pubkey(leaf_identity.pubkey));
    let leaf_stack = Stack::new(leaf_radio, leaf_identity.clone(), 129, 0);
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
    root.radio().transmit(0, &wire[..len]).await.unwrap();
    assert!(matches!(
        relay.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::AnnouncementAccepted { .. })
    ));
    let mut relayed = [0u8; MAX_FRAME_SIZE];
    assert!(root
        .radio()
        .receive(0, &mut relayed, 1)
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
    root.radio().transmit(0, &wire[..len]).await.unwrap();
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
        Stack::new(root_radio, root_identity.clone(), 128, 0),
        root_addr,
        root_addr,
        announces(prefix),
        MemStorage::new(),
    )
    .unwrap();
    let mut relay = RplStack::provision_leaf(
        Stack::new(relay_radio, relay_identity.clone(), 129, 0),
        relay_addr,
        root_addr,
        announces(prefix),
        MemStorage::new(),
    )
    .unwrap();
    let mut leaf = RplStack::provision_leaf(
        Stack::new(leaf_radio, leaf_identity.clone(), 129, 0),
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
            Err(RplReceiveError::Receive(crate::stack::RxError::Link(
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
        Err(RplReceiveError::Receive(crate::stack::RxError::Link(
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
    let unknown_downward = address(&identity(99), 1);
    assert!(leaf.route_for(unknown_downward, 0, true).is_none());

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

    let secret = [0x42; 16];
    let mut leaf_store = TestOscoreStore::default();
    let mut root_store = TestOscoreStore::default();
    let leaf_context = Context::new(&secret, None, None, &[0x00], &[0x01])
        .unwrap()
        .restore_existing(&mut leaf_store)
        .unwrap();
    let root_context = Context::new(&secret, None, None, &[0x01], &[0x00])
        .unwrap()
        .restore_existing(&mut root_store)
        .unwrap();
    leaf.restore_context(root_identity.iid, leaf_context, &mut leaf_store)
        .unwrap();
    root.restore_context(leaf_identity.iid, root_context, &mut root_store)
        .unwrap();

    let mut correlation = leaf
        .send_secure_get(
            &Addr(root_addr),
            &root_identity.iid,
            &["status"],
            &[0xa1],
            &mut leaf_store,
            0,
        )
        .await
        .unwrap();
    assert!(matches!(
        relay.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::Forwarded { next_hop })
            if next_hop == eui64_link_local(root_eui64)
    ));
    let Some(RplReceiveOutcome::DeliveredIpv6(received)) = root.receive(1, 0).await.unwrap() else {
        panic!("root did not receive routed secure CoAP");
    };
    let datagram = root.secure_datagram(&received).unwrap().unwrap();
    let request = root.decrypt_request(&datagram).unwrap();
    assert_eq!(request.sender_iid, leaf_identity.iid);
    assert_eq!(request.code.0, 1);

    root.send_secure_response(
        &Addr(leaf_addr),
        &leaf_identity.iid,
        &request,
        SecureResponseData {
            code: lichen_coap::message::MessageCode(0x45),
            options: &[],
            payload: b"ok",
        },
        &mut root_store,
        0,
    )
    .await
    .unwrap();
    assert!(matches!(
        relay.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::Forwarded { next_hop })
            if next_hop == eui64_link_local(leaf_eui64)
    ));
    let Some(RplReceiveOutcome::DeliveredIpv6(received)) = leaf.receive(1, 0).await.unwrap() else {
        panic!("leaf did not receive routed secure response");
    };
    let response = leaf.secure_datagram(&received).unwrap().unwrap();
    assert!(matches!(
        leaf.decrypt_response(&response, &mut correlation, 0)
            .await
            .unwrap(),
        SecureResponse::Decrypted { payload, .. } if payload == b"ok"
    ));
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
        rank: ROOT_RANK,
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
        Priority::Routing,
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
        Priority::Routing,
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
        Stack::new(reopened_radio, root_identity.clone(), 129, 0),
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
        Priority::Routing,
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
        Priority::Routing,
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
        Priority::Routing,
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
        Priority::Routing,
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
        Priority::Routing,
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
    let mut leaf = Stack::new(leaf_radio, leaf_identity.clone(), 129, 0);
    let root_stack = Stack::new(root_radio, root_identity, 129, 0);
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
        Priority::Routing,
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

    // First replay: valid DAO with old sequence should be detected as Replay
    leaf.send_ipv6_to(
        &dao_ipv6_packet(leaf_addr, root_addr, &signed).unwrap(),
        &ipv6_eui64(root_addr),
        Priority::Routing,
    )
    .await
    .unwrap();
    assert!(matches!(
        reopened.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Replay))
    ));

    // Second replay: malformed DAO (prefix_len=127) with old sequence is rejected
    // as Replay first (replay check precedes route validation per RFC 6550).
    leaf.send_ipv6_to(
        &dao_ipv6_packet(leaf_addr, root_addr, &malformed_replay).unwrap(),
        &ipv6_eui64(root_addr),
        Priority::Routing,
    )
    .await
    .unwrap();
    assert!(matches!(
        reopened.receive(1, 0).await.unwrap(),
        Some(RplReceiveOutcome::Dao(DaoHandlingOutcome::Replay))
    ));
    assert_eq!(
        reopened.rpl_node().router.lookup_route(&leaf_addr),
        Some([leaf_addr].as_slice())
    );

    leaf.send_ipv6_to(
        &dao_ipv6_packet(leaf_addr, root_addr, &fourth).unwrap(),
        &ipv6_eui64(root_addr),
        Priority::Routing,
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
        let error = provision_or_resume_root_state(&mut storage, root_addr, instance, root_addr)
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
    provision_or_resume_root_state(&mut admission_only, root_addr, instance, root_addr).unwrap();

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
    DaoAdmissionState::provision(&mut wrong_admission, other_addr, instance, other_addr).unwrap();
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
