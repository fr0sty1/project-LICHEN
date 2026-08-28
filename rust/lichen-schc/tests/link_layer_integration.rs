// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Compressed and fragmented SCHC packets through the authenticated link layer.
//!
//! Single-frame IPv6 recovery is checked against `test/vectors/schc_compression.json`.

use lichen_core::checksum::upper_layer_checksum;
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::l2_payload::{body, classify, L2PayloadKind};
use lichen_link::frame::AddrMode;
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::link_layer::LinkLayer;
use lichen_link::{LinkSeqNum, Seed};
use lichen_schc::fragment::{
    FragmentationPolicy, SenderOutput, SenderStatus, MAX_FRAGMENT_WIRE_SIZE, TILE_SIZE,
};
use lichen_schc::link::{
    accept_authenticated_schc_packet, compress_schc_for_peer, create_fragment_sender,
    requires_fragmentation, wrap_unfragmented_schc, AuthenticatedSchcPolicy,
    MAX_SINGLE_FRAME_SCHC_PACKET,
};
use lichen_schc::{
    decompress, AuthenticatedFragmentReceiver, AuthenticatedPeerSchcContext, ExpectedDioRole,
    SchcError,
};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/schc_compression.json");

#[derive(Deserialize)]
struct Document {
    vectors: Vec<CompressionVector>,
}

#[derive(Deserialize)]
struct CompressionVector {
    name: String,
    #[serde(default)]
    packet: Option<String>,
    #[serde(default)]
    compressed: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn identity(seed: u8) -> Identity {
    Identity::from_seed(Seed::new([seed; 32]))
}

fn dio_payload_with_version(sender: &Identity, version: u8) -> (Vec<u8>, [u8; 16]) {
    let mut source = [0u8; 16];
    source[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    source[8..].copy_from_slice(&sender.iid);
    let destination = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
    let dodag = lichen_link::ygg_addr_from_pubkey(sender.pubkey.as_bytes());
    let mut ipv6 = vec![0u8; 40 + 4 + 27];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&31u16.to_be_bytes());
    ipv6[6] = 58;
    ipv6[7] = 255;
    ipv6[8..24].copy_from_slice(&source);
    ipv6[24..40].copy_from_slice(&destination);
    ipv6[40] = 155;
    ipv6[41] = 1;
    ipv6[44..52].copy_from_slice(&[0, 1, 1, 0, 0x08, 0, 0, 0]);
    ipv6[52..68].copy_from_slice(&dodag);
    ipv6[68..71].copy_from_slice(&[0x13, 0x01, version]);
    let checksum = upper_layer_checksum(&source, &destination, 58, &ipv6[40..]);
    ipv6[42..44].copy_from_slice(&checksum.to_be_bytes());
    let mut payload = vec![L2_DISPATCH_SCHC, 0xff];
    payload.extend_from_slice(&ipv6);
    (payload, dodag)
}

fn sign_and_receive(
    sender: &LinkLayer,
    receiver: &mut LinkLayer,
    payload: &[u8],
    dst: &[u8],
    seqnum: u16,
    now_ms: u64,
) -> lichen_link::link_layer::AuthenticatedFrame {
    let mut wire = [0u8; 256];
    let length = sender
        .build_frame(0, LinkSeqNum::new(seqnum), dst, payload, &mut wire)
        .unwrap();
    receiver.receive_frame_at(&wire[..length], now_ms).unwrap()
}

fn sign_and_receive_mode(
    sender: &LinkLayer,
    receiver: &mut LinkLayer,
    payload: &[u8],
    dst: &[u8],
    destination_mode: AddrMode,
    seqnum: u16,
    now_ms: u64,
) -> lichen_link::link_layer::AuthenticatedFrame {
    let mut wire = [0u8; 256];
    let length = sender
        .build_frame_with_addr_mode(
            0,
            LinkSeqNum::new(seqnum),
            dst,
            payload,
            destination_mode,
            &mut wire,
        )
        .unwrap();
    receiver.receive_frame_at(&wire[..length], now_ms).unwrap()
}

fn admit_root_dio(
    sender: &LinkLayer,
    receiver: &mut LinkLayer,
    policy: &mut AuthenticatedSchcPolicy,
    sender_id: &Identity,
    seqnum: u16,
    now_ms: u64,
) -> AuthenticatedPeerSchcContext {
    let peer = root_dio_context(sender, receiver, sender_id, 3, seqnum, now_ms);
    policy.install(receiver, &peer).unwrap();
    peer
}

fn root_dio_context(
    sender: &LinkLayer,
    receiver: &mut LinkLayer,
    sender_id: &Identity,
    version: u8,
    seqnum: u16,
    now_ms: u64,
) -> AuthenticatedPeerSchcContext {
    let (payload, dodag) = dio_payload_with_version(sender_id, version);
    let frame = sign_and_receive(sender, receiver, &payload, &[], seqnum, now_ms);
    AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &dodag,
        1,
        ExpectedDioRole::Root,
    )
    .unwrap()
}

fn enlarge_udp_payload(packet: &[u8], extra: usize) -> Vec<u8> {
    let mut out = packet.to_vec();
    out.extend(vec![0x61; extra]);
    let udp_len = u16::try_from(out.len() - 40).unwrap();
    out[4..6].copy_from_slice(&udp_len.to_be_bytes());
    out[44..46].copy_from_slice(&udp_len.to_be_bytes());
    out[46..48].copy_from_slice(&[0, 0]);
    let src: [u8; 16] = out[8..24].try_into().unwrap();
    let dst: [u8; 16] = out[24..40].try_into().unwrap();
    let mut checksum = upper_layer_checksum(&src, &dst, 17, &out[40..]);
    if checksum == 0 {
        checksum = 0xffff;
    }
    out[46..48].copy_from_slice(&checksum.to_be_bytes());
    out
}

fn with_udp_destination(packet: &[u8], destination: [u8; 16]) -> Vec<u8> {
    let mut out = packet.to_vec();
    out[24..40].copy_from_slice(&destination);
    out[46..48].copy_from_slice(&[0, 0]);
    let source: [u8; 16] = out[8..24].try_into().unwrap();
    let mut checksum = upper_layer_checksum(&source, &destination, 17, &out[40..]);
    if checksum == 0 {
        checksum = 0xffff;
    }
    out[46..48].copy_from_slice(&checksum.to_be_bytes());
    out
}

const _: () = assert!(MAX_SINGLE_FRAME_SCHC_PACKET == 185);
const _: () = assert!(TILE_SIZE < MAX_SINGLE_FRAME_SCHC_PACKET);

#[test]
fn compression_vectors_recover_ipv6_from_authenticated_link_payload() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let alice_id = identity(0xe5);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    let bob_eui = bob.local_eui64();
    let mut policy = AuthenticatedSchcPolicy::new();
    let alice_peer = admit_root_dio(&alice, &mut bob, &mut policy, &alice_id, 1, 1);

    let roundtrips: Vec<_> = corpus
        .vectors
        .iter()
        .filter(|vector| {
            vector.packet.is_some()
                && vector.compressed.is_some()
                && vector.category.as_deref() != Some("malformed_input")
                && vector.category.as_deref() != Some("size_boundary")
        })
        .collect();
    assert!(!roundtrips.is_empty());

    for (index, vector) in roundtrips.iter().enumerate() {
        let packet = hex(vector.packet.as_ref().unwrap());
        let expected = hex(vector.compressed.as_ref().unwrap());
        let mut compressed = [0u8; 512];
        let schc_len = compress_schc_for_peer(
            &bob,
            &policy,
            &alice_peer,
            &packet,
            &mut compressed,
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        )
        .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(
            &compressed[..schc_len],
            expected.as_slice(),
            "{}",
            vector.name
        );
        assert!(
            !requires_fragmentation(&compressed[..schc_len]),
            "{}",
            vector.name
        );

        let mut wrapped = [0u8; 512];
        let l2 = wrap_unfragmented_schc(&compressed[..schc_len], &mut wrapped).unwrap();
        assert_eq!(classify(l2), L2PayloadKind::Schc);
        assert_eq!(body(l2), &expected[..]);

        let frame = sign_and_receive(
            &alice,
            &mut bob,
            l2,
            &bob_eui,
            u16::try_from(index + 2).unwrap(),
            u64::try_from(index + 2).unwrap(),
        );
        let mut ipv6 = [0u8; 512];
        let ipv6_len = accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &frame,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        )
        .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(&ipv6[..ipv6_len], packet.as_slice(), "{}", vector.name);
    }
}

#[test]
fn live_policy_supersedes_refresh_version_change_root_switch_and_rollback() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == "coap_linklocal")
        .unwrap();
    let packet = hex(vector.packet.as_ref().unwrap());

    let alice_id = identity(0xe5);
    let charlie_id = identity(0xa7);
    let alice = LinkLayer::new(identity(0xe5));
    let charlie = LinkLayer::new(identity(0xa7));
    let mut bob = LinkLayer::new(identity(0xf6));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    bob.add_peer(PeerIdentity::from_pubkey(charlie_id.pubkey));
    let bob_eui = bob.local_eui64();
    let mut policy = AuthenticatedSchcPolicy::new();

    let old = root_dio_context(&alice, &mut bob, &alice_id, 3, 10, 10);
    policy.install(&bob, &old).unwrap();
    let mut compressed = [0u8; 512];
    let compressed_len = compress_schc_for_peer(
        &bob,
        &policy,
        &old,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .unwrap();
    assert_eq!(compressed[0], 0);

    let refreshed = root_dio_context(&alice, &mut bob, &alice_id, 3, 20, 20);
    policy.install(&bob, &refreshed).unwrap();
    assert_eq!(
        compress_schc_for_peer(
            &bob,
            &policy,
            &old,
            &packet,
            &mut compressed,
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );

    let mut wrapped = [0u8; 512];
    let l2 = wrap_unfragmented_schc(&compressed[..compressed_len], &mut wrapped).unwrap();
    let data = sign_and_receive(&alice, &mut bob, l2, &bob_eui, 21, 21);
    let mut ipv6 = [0xa5; 512];
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &old,
            &data,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert_eq!(ipv6, [0xa5; 512]);
    let length = accept_authenticated_schc_packet(
        &bob,
        &policy,
        &refreshed,
        &data,
        &mut ipv6,
        MAX_SINGLE_FRAME_SCHC_PACKET,
    )
    .unwrap();
    assert_eq!(&ipv6[..length], packet.as_slice());

    let rollback = root_dio_context(&alice, &mut bob, &alice_id, 3, 15, 22);
    assert_eq!(
        policy.install(&bob, &rollback),
        Err(SchcError::InvalidPeerEvidence)
    );

    let incompatible = root_dio_context(&alice, &mut bob, &alice_id, 1, 30, 30);
    policy.install(&bob, &incompatible).unwrap();
    assert_eq!(
        compress_schc_for_peer(
            &bob,
            &policy,
            &refreshed,
            &packet,
            &mut compressed,
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    let rule255_len = compress_schc_for_peer(
        &bob,
        &policy,
        &incompatible,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .unwrap();
    assert_eq!(compressed[0], 0xff);
    assert_eq!(rule255_len, packet.len() + 1);

    let new_root = root_dio_context(&charlie, &mut bob, &charlie_id, 3, 10, 40);
    policy.install(&bob, &new_root).unwrap();
    assert_eq!(
        policy.install(&bob, &rollback),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert_eq!(
        compress_schc_for_peer(
            &bob,
            &policy,
            &incompatible,
            &packet,
            &mut compressed,
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert!(compress_schc_for_peer(
        &bob,
        &policy,
        &new_root,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .is_ok());
}

#[test]
fn unfragmented_ingress_admits_only_local_or_broadcast_wire_destinations() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == "coap_linklocal")
        .unwrap();
    let packet = hex(vector.packet.as_ref().unwrap());

    let alice_id = identity(0xe5);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    let charlie = LinkLayer::new(identity(0xa7));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    let bob_eui = bob.local_eui64();
    let charlie_eui = charlie.local_eui64();
    let mut policy = AuthenticatedSchcPolicy::new();
    let alice_peer = admit_root_dio(&alice, &mut bob, &mut policy, &alice_id, 1, 1);

    let mut compressed = [0u8; 512];
    let schc_len = compress_schc_for_peer(
        &bob,
        &policy,
        &alice_peer,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .unwrap();
    let mut wrapped = [0u8; 512];
    let l2 = wrap_unfragmented_schc(&compressed[..schc_len], &mut wrapped).unwrap();

    let foreign =
        sign_and_receive_mode(&alice, &mut bob, l2, &charlie_eui, AddrMode::Extended, 2, 2);
    let mut ipv6 = [0xa5; 512];
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &foreign,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert_eq!(ipv6, [0xa5; 512]);

    let local = sign_and_receive_mode(&alice, &mut bob, l2, &bob_eui, AddrMode::Extended, 3, 3);
    let ipv6_len = accept_authenticated_schc_packet(
        &bob,
        &policy,
        &alice_peer,
        &local,
        &mut ipv6,
        MAX_SINGLE_FRAME_SCHC_PACKET,
    )
    .unwrap();
    assert_eq!(&ipv6[..ipv6_len], packet.as_slice());

    let broadcast = sign_and_receive_mode(&alice, &mut bob, l2, &[], AddrMode::None, 4, 4);
    let ipv6_len = accept_authenticated_schc_packet(
        &bob,
        &policy,
        &alice_peer,
        &broadcast,
        &mut ipv6,
        MAX_SINGLE_FRAME_SCHC_PACKET,
    )
    .unwrap();
    assert_eq!(&ipv6[..ipv6_len], packet.as_slice());

    let short = sign_and_receive_mode(&alice, &mut bob, l2, &[0x12, 0x34], AddrMode::Short, 5, 5);
    ipv6.fill(0xa5);
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &short,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert_eq!(ipv6, [0xa5; 512]);

    let mut bob_link_local = [0u8; 16];
    bob_link_local[..2].copy_from_slice(&[0xfe, 0x80]);
    bob_link_local[8..].copy_from_slice(&bob.local_iid());
    let bob_native = lichen_link::ygg_addr_from_pubkey(bob.local_public_key().as_bytes());
    let mut charlie_link_local = [0u8; 16];
    charlie_link_local[..2].copy_from_slice(&[0xfe, 0x80]);
    charlie_link_local[8..].copy_from_slice(&charlie.local_iid());
    let multicast = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    for (seqnum, destination, accepted) in [
        (6, bob_link_local, true),
        (7, bob_native, true),
        (8, multicast, true),
        (9, charlie_link_local, false),
    ] {
        let addressed_packet = with_udp_destination(&packet, destination);
        let schc_len = compress_schc_for_peer(
            &bob,
            &policy,
            &alice_peer,
            &addressed_packet,
            &mut compressed,
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        )
        .unwrap();
        let l2 = wrap_unfragmented_schc(&compressed[..schc_len], &mut wrapped).unwrap();
        let elided = sign_and_receive_mode(
            &alice,
            &mut bob,
            l2,
            &[],
            AddrMode::Elided,
            seqnum,
            u64::from(seqnum),
        );
        ipv6.fill(0xa5);
        let result = accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &elided,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        );
        if accepted {
            let length = result.unwrap();
            assert_eq!(&ipv6[..length], addressed_packet.as_slice());
        } else {
            assert_eq!(result, Err(SchcError::InvalidPeerEvidence));
            assert_eq!(ipv6, [0xa5; 512]);
        }
    }
}

#[test]
fn oversized_schc_fragments_and_reassembles_through_link() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == "coap_linklocal")
        .unwrap();
    let packet = enlarge_udp_payload(&hex(vector.packet.as_ref().unwrap()), 200);

    let alice_id = identity(0xe5);
    let bob_id = identity(0xf6);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    let mut alice_rx = LinkLayer::new(identity(0xe5));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    alice_rx.add_peer(PeerIdentity::from_pubkey(bob_id.pubkey));
    let alice_eui = alice_rx.local_eui64();
    let bob_eui = bob.local_eui64();

    let mut bob_policy = AuthenticatedSchcPolicy::new();
    let mut alice_rx_policy = AuthenticatedSchcPolicy::new();
    let alice_peer = admit_root_dio(&alice, &mut bob, &mut bob_policy, &alice_id, 1, 10);
    let bob_peer = admit_root_dio(&bob, &mut alice_rx, &mut alice_rx_policy, &bob_id, 1, 11);

    let mut compressed = [0u8; 512];
    let schc_len = compress_schc_for_peer(
        &alice_rx,
        &alice_rx_policy,
        &bob_peer,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        true,
    )
    .unwrap();
    assert!(requires_fragmentation(&compressed[..schc_len]));
    assert_eq!(
        compress_schc_for_peer(
            &alice_rx,
            &alice_rx_policy,
            &bob_peer,
            &packet,
            &mut [0u8; 512],
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPacket(
            "SCHC packet requires authenticated fragmentation"
        ))
    );

    let mut alice_policy = FragmentationPolicy::<1>::new().unwrap();
    let alice_permit = alice_policy.accept_peer(&alice_rx, &bob_peer, 12).unwrap();
    let mut sender = create_fragment_sender(
        &alice_policy,
        &alice_permit,
        &alice_rx,
        &bob_peer,
        &compressed[..schc_len],
        1281,
        13,
    )
    .unwrap();
    sender
        .start_current(&alice_policy, &alice_rx, &bob_peer, 14)
        .unwrap();
    assert!(sender.fragment_count() >= 2);

    let mut bob_policy = FragmentationPolicy::<1>::new().unwrap();
    let bob_permit = bob_policy.accept_peer(&bob, &alice_peer, 15).unwrap();
    let mut storage = [0u8; 1281];
    let mut receiver = AuthenticatedFragmentReceiver::new(
        &bob_policy,
        &bob_permit,
        &bob,
        &alice_peer,
        &mut storage,
        16,
    )
    .unwrap();

    let mut ack_payload = [0u8; 16];
    let mut ack_len = 0;
    for index in 0..sender.fragment_count() {
        let fragment = sender
            .get_fragment_current(
                &alice_policy,
                &alice_rx,
                &bob_peer,
                index,
                17 + index as u64,
            )
            .unwrap()
            .unwrap();
        let mut payload = [0u8; MAX_FRAGMENT_WIRE_SIZE];
        let payload_len = fragment.write_to(&mut payload).unwrap();
        assert_ne!(payload[0], L2_DISPATCH_SCHC);
        let frame = sign_and_receive(
            &alice,
            &mut bob,
            &payload[..payload_len],
            &bob_eui,
            u16::try_from(index + 2).unwrap(),
            20 + index as u64,
        );
        let result = receiver
            .receive_frame(&bob_policy, &bob, &alice_peer, &frame)
            .unwrap();
        if let Some(response) = result.response {
            ack_len = response.write_to(&mut ack_payload).unwrap();
        }
        if let Some(packet_len) = result.packet_len {
            assert_eq!(
                &receiver.packet().unwrap()[..packet_len],
                &compressed[..schc_len]
            );
        }
    }
    assert!(ack_len > 0);
    assert_eq!(receiver.packet(), Some(&compressed[..schc_len]));

    let mut recovered = [0u8; 512];
    let recovered_len = decompress(receiver.packet().unwrap(), &mut recovered).unwrap();
    assert_eq!(&recovered[..recovered_len], packet.as_slice());

    let ack_frame = sign_and_receive(
        &bob,
        &mut alice_rx,
        &ack_payload[..ack_len],
        &alice_eui,
        2,
        40,
    );
    let output = sender
        .handle_ack_frame(&alice_policy, &alice_rx, &bob_peer, &ack_frame)
        .unwrap();
    assert_eq!(output, SenderOutput::Success);
    assert_eq!(sender.status(), SenderStatus::Succeeded);
}

#[test]
fn fragment_wires_are_rejected_as_unfragmented_schc() {
    let alice_id = identity(0xe5);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    let bob_eui = bob.local_eui64();
    let mut policy = AuthenticatedSchcPolicy::new();
    let alice_peer = admit_root_dio(&alice, &mut bob, &mut policy, &alice_id, 1, 1);
    let raw = sign_and_receive(&alice, &mut bob, &[0x78, 0x7c], &bob_eui, 2, 2);
    let mut ipv6 = [0u8; 40];
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &raw,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPacket("missing SCHC L2 dispatch"))
    );
    let wrapped = sign_and_receive(
        &alice,
        &mut bob,
        &[L2_DISPATCH_SCHC, 0x78, 0x7c],
        &bob_eui,
        3,
        3,
    );
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &wrapped,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPacket(
            "fragmentation packets require authenticated reassembly"
        ))
    );
}

#[test]
fn accept_and_compress_bind_peer_context_to_receiving_link() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == "coap_linklocal")
        .unwrap();
    let packet = hex(vector.packet.as_ref().unwrap());

    let alice_id = identity(0xe5);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    let mut charlie = LinkLayer::new(identity(0xa7));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    charlie.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    let bob_eui = bob.local_eui64();
    let charlie_eui = charlie.local_eui64();

    let mut bob_policy = AuthenticatedSchcPolicy::new();
    let mut charlie_policy = AuthenticatedSchcPolicy::new();
    let alice_on_bob = admit_root_dio(&alice, &mut bob, &mut bob_policy, &alice_id, 1, 1);
    let alice_on_charlie =
        admit_root_dio(&alice, &mut charlie, &mut charlie_policy, &alice_id, 1, 1);

    let mut compressed = [0u8; 512];
    let schc_len = compress_schc_for_peer(
        &charlie,
        &charlie_policy,
        &alice_on_charlie,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .unwrap();
    assert_eq!(
        compress_schc_for_peer(
            &charlie,
            &charlie_policy,
            &alice_on_bob,
            &packet,
            &mut [0u8; 512],
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );

    let mut wrapped = [0u8; 512];
    let l2 = wrap_unfragmented_schc(&compressed[..schc_len], &mut wrapped).unwrap();
    let charlie_frame = sign_and_receive(&alice, &mut charlie, l2, &charlie_eui, 2, 2);

    let mut ipv6 = [0u8; 512];
    assert_eq!(
        accept_authenticated_schc_packet(
            &charlie,
            &charlie_policy,
            &alice_on_bob,
            &charlie_frame,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    let ipv6_len = accept_authenticated_schc_packet(
        &charlie,
        &charlie_policy,
        &alice_on_charlie,
        &charlie_frame,
        &mut ipv6,
        MAX_SINGLE_FRAME_SCHC_PACKET,
    )
    .unwrap();
    assert_eq!(&ipv6[..ipv6_len], packet.as_slice());

    let bob_frame = sign_and_receive(&alice, &mut bob, l2, &bob_eui, 2, 2);
    bob.unpin_peer(&alice_id.iid);
    assert_eq!(
        compress_schc_for_peer(
            &bob,
            &bob_policy,
            &alice_on_bob,
            &packet,
            &mut [0u8; 512],
            MAX_SINGLE_FRAME_SCHC_PACKET,
            false,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &bob_policy,
            &alice_on_bob,
            &bob_frame,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );

    let post_unpin = sign_and_receive(&alice, &mut bob, l2, &bob_eui, 3, 3);
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &bob_policy,
            &alice_on_bob,
            &post_unpin,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );
    assert!(compress_schc_for_peer(
        &charlie,
        &charlie_policy,
        &alice_on_charlie,
        &packet,
        &mut [0u8; 512],
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .is_ok());
}

#[test]
fn accept_rejects_in_window_data_at_or_below_dio_admission_floor() {
    let corpus: Document = serde_json::from_str(VECTORS_JSON).unwrap();
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == "coap_linklocal")
        .unwrap();
    let packet = hex(vector.packet.as_ref().unwrap());

    let alice_id = identity(0xe5);
    let alice = LinkLayer::new(identity(0xe5));
    let mut bob = LinkLayer::new(identity(0xf6));
    bob.add_peer(PeerIdentity::from_pubkey(alice_id.pubkey));
    let bob_eui = bob.local_eui64();

    let floor = 5u16;
    let mut policy = AuthenticatedSchcPolicy::new();
    let alice_peer = admit_root_dio(&alice, &mut bob, &mut policy, &alice_id, floor, 1);

    let mut compressed = [0u8; 512];
    let schc_len = compress_schc_for_peer(
        &bob,
        &policy,
        &alice_peer,
        &packet,
        &mut compressed,
        MAX_SINGLE_FRAME_SCHC_PACKET,
        false,
    )
    .unwrap();
    let mut wrapped = [0u8; 512];
    let l2 = wrap_unfragmented_schc(&compressed[..schc_len], &mut wrapped).unwrap();

    let mut ipv6 = [0u8; 512];
    let dio_frame = alice_peer.authenticated_frame().unwrap();
    assert_eq!(u16::from(dio_frame.seqnum()), floor);
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            dio_frame,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );

    let delayed = sign_and_receive(&alice, &mut bob, l2, &bob_eui, floor - 1, 2);
    assert_eq!(u16::from(delayed.seqnum()), floor - 1);
    assert_eq!(
        accept_authenticated_schc_packet(
            &bob,
            &policy,
            &alice_peer,
            &delayed,
            &mut ipv6,
            MAX_SINGLE_FRAME_SCHC_PACKET,
        ),
        Err(SchcError::InvalidPeerEvidence)
    );

    let next = sign_and_receive(&alice, &mut bob, l2, &bob_eui, floor + 1, 3);
    assert_eq!(u16::from(next.seqnum()), floor + 1);
    let ipv6_len = accept_authenticated_schc_packet(
        &bob,
        &policy,
        &alice_peer,
        &next,
        &mut ipv6,
        MAX_SINGLE_FRAME_SCHC_PACKET,
    )
    .unwrap();
    assert_eq!(&ipv6[..ipv6_len], packet.as_slice());
}
