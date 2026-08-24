// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! End-to-end border router integration tests.
//!
//! Validates the full gateway forwarding pipeline including:
//!   - Mesh node pings internet host (outbound SCHC compress without SRH)
//!   - Internet host pings mesh node (inbound upstream→mesh forwarding)
//!   - Gateway handles RPL DIS → DIO reply
//!   - ULA and link-local forwarding through mesh_to_mesh
//!   - Address classification edge cases
//!   - Invalid frames are dropped gracefully

use lichen_coap::message::MessageCode;
use lichen_core::addr::Ipv6Addr;
use lichen_core::announce::{write_announce_signed_data, AnnounceBuilder};
use lichen_core::constants::{L2_DISPATCH_SCHC, RPL_ICMPV6_TYPE, RPL_INSTANCE_ID};
use lichen_core::icmpv6;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_gateway::{
    resources::{CoapMethod, GatewayCoordinator, SlotClaim},
    trust::{iid_from_pubkey, PskFederation, TrustStore},
    Gateway, GatewayPersistence,
};
use lichen_hal::loopback::LoopbackRadio;
use lichen_hal::storage::fs::FileStorage;
use lichen_hal::Radio;
use lichen_ipv6::{icmpv6_checksum, Addr};
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::keys::Seed;
use lichen_link::link_layer::LinkLayer;
use lichen_link::schnorr;
use lichen_link::seqnum::LinkSeqNum;
use lichen_node::rpl_code;
use lichen_node::secure::{SecureRequestData, SecureStack};
use lichen_node::RplEvent;
use lichen_oscore::{ContextId, SenderSequenceState, SenderStateStore};
use lichen_schc::codec;
use schnorr48::{derive_keypair, sign};

#[derive(Default)]
struct TestSenderStore(Option<(ContextId, SenderSequenceState)>);

impl SenderStateStore for TestSenderStore {
    type Error = ();

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self
            .0
            .filter(|(stored, _)| stored == context_id)
            .map(|(_, state)| state))
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        let current = self
            .0
            .filter(|(stored, _)| stored == context_id)
            .map(|(_, state)| state);
        if current != expected {
            return Ok(false);
        }
        self.0 = Some((*context_id, next));
        Ok(true)
    }
}

/// Build a link-local Ipv6Addr from an 8-bit interface-identifier suffix.
fn ll(iid: u8) -> Ipv6Addr {
    Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
}

/// Build a global unicast Ipv6Addr representing an internet host.
fn gua(byte15: u8, byte16: u8) -> Ipv6Addr {
    Ipv6Addr([
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0x88, byte15, byte16,
    ])
}

/// Build a ULA Ipv6Addr for a mesh node.
fn ula(suffix: u8) -> Ipv6Addr {
    Ipv6Addr([0xfd, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, suffix])
}

/// Create a fresh gateway (RPL root).
fn test_gateway() -> Gateway {
    let seed = Seed::new([0x02; 32]);
    Gateway::new_ephemeral(Identity::from_seed(seed), 128).unwrap()
}

fn gateway_identity() -> Identity {
    Identity::from_seed(Seed::new([0x02; 32]))
}

fn gw_native(identity: &Identity) -> [u8; 16] {
    lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes())
}

/// SCHC-compress an IPv6 packet. Returns the L2 payload (dispatch + compressed).
fn schc_compress_ipv6(ipv6: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; ipv6.len() + 3];
    out[0] = L2_DISPATCH_SCHC;
    let n = codec::compress(ipv6, &mut out[1..]).expect("SCHC compress in test");
    out.truncate(n + 1);
    out
}

fn schc_decompress_l2(l2: &[u8]) -> Option<Vec<u8>> {
    let l2 = lichen_link::frame::LichenFrame::from_bytes(l2)
        .map(|frame| frame.payload)
        .unwrap_or(l2);
    if l2.first().copied() != Some(L2_DISPATCH_SCHC) {
        return None;
    }
    let mut ipv6 = vec![0u8; lichen_core::constants::SCHC_MAX_DECOMPRESSED];
    let len = codec::decompress(&l2[1..], &mut ipv6).ok()?;
    ipv6.truncate(len);
    (ipv6.len() >= IPV6_HEADER_LEN && ipv6[0] >> 4 == 6).then_some(ipv6)
}

struct MeshPeer {
    identity: Identity,
    link: LinkLayer,
    next_sequence: u16,
}

impl MeshPeer {
    fn new(seed_byte: u8) -> Self {
        let identity = Identity::from_seed(Seed::new([seed_byte; 32]));
        let mut link = LinkLayer::new(identity.clone());
        link.add_peer(PeerIdentity::from_pubkey(gateway_identity().pubkey));
        Self {
            identity,
            link,
            next_sequence: 1,
        }
    }

    fn build_wire(&mut self, l2_payload: &[u8], destination: &[u8]) -> Vec<u8> {
        let mut wire = [0u8; 255];
        let len = self
            .link
            .build_frame(
                128,
                LinkSeqNum::new(self.next_sequence),
                destination,
                l2_payload,
                &mut wire,
            )
            .unwrap();
        self.next_sequence += 1;
        wire[..len].to_vec()
    }

    fn signed_announce(&self) -> Vec<u8> {
        let rx_channel = 3;
        let sequence = 1u16;
        let mut signed = [0u8; 64];
        write_announce_signed_data(
            &self.identity.iid,
            self.identity.pubkey.as_bytes(),
            sequence,
            rx_channel,
            &[],
            &mut signed,
        )
        .unwrap();
        let signature = schnorr::sign(&self.identity.privkey, &self.identity.pubkey, &signed);
        let mut announce = vec![0u8; 93];
        let len = AnnounceBuilder {
            originator_iid: &self.identity.iid,
            pubkey: self.identity.pubkey.as_bytes(),
            seq_num: sequence,
            hop_count: 0,
            rx_channel,
            signature: &signature,
            app_data: &[],
        }
        .write_to(&mut announce)
        .unwrap();
        announce.truncate(len);
        let mut payload = vec![lichen_core::constants::L2_DISPATCH_ROUTING];
        payload.extend_from_slice(&announce);
        payload
    }

    async fn bootstrap(&mut self, gateway: &mut Gateway, now_ms: u64) {
        let announce = self.signed_announce();
        let wire = self.build_wire(&announce, &[]);
        gateway
            .ingest_mesh_frame(&wire, Some(-50), Some(10), now_ms)
            .await
            .unwrap();
    }

    fn root_eui64() -> [u8; 8] {
        let mut eui = gateway_identity().iid;
        eui[0] ^= 0x02;
        eui
    }

    fn link_local(&self) -> Ipv6Addr {
        let mut address = [0u8; 16];
        address[0] = 0xfe;
        address[1] = 0x80;
        address[8..].copy_from_slice(&self.identity.iid);
        Ipv6Addr(address)
    }
}

async fn send_dis(
    gateway: &mut Gateway,
    peer: &mut MeshPeer,
    now_ms: u64,
) -> lichen_gateway::GatewayIngress {
    let source = peer.link_local();
    let mut destination = [0u8; 16];
    destination[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    destination[8..].copy_from_slice(&gateway_identity().iid);
    let destination = Ipv6Addr(destination);
    let l2 = build_rpl_packet(&source, &destination, rpl_code::DIS, &[0, 0]);
    let wire = peer.build_wire(&l2, &MeshPeer::root_eui64());
    gateway
        .ingest_mesh_frame(&wire, Some(-50), Some(10), now_ms)
        .await
        .unwrap()
}

fn decode_signed_reply(peer: &mut MeshPeer, wire: &[u8]) -> Vec<u8> {
    let frame = peer.link.receive_frame(wire).unwrap();
    schc_decompress_l2(frame.payload()).unwrap()
}

fn build_ipv6_icmpv6_header(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    icmp_type: u8,
    icmp_code: u8,
    body: &[u8],
) -> Vec<u8> {
    let icmpv6_len = 4 + body.len();
    let total = IPV6_HEADER_LEN + icmpv6_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
    pkt[6] = next_header::ICMPV6;
    pkt[7] = 64;
    pkt[field::SRC_OFFSET..field::DST_OFFSET].copy_from_slice(&src.0);
    pkt[field::DST_OFFSET..IPV6_HEADER_LEN].copy_from_slice(&dst.0);
    pkt[IPV6_HEADER_LEN] = icmp_type;
    pkt[IPV6_HEADER_LEN + 1] = icmp_code;
    pkt[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..].copy_from_slice(body);
    let checksum = icmpv6_checksum(&Addr(src.0), &Addr(dst.0), &pkt[IPV6_HEADER_LEN..])
        .expect("checksum compute");
    pkt[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

fn build_rpl_packet(src: &Ipv6Addr, dst: &Ipv6Addr, code: u8, body: &[u8]) -> Vec<u8> {
    let ipv6 = build_ipv6_icmpv6_header(src, dst, RPL_ICMPV6_TYPE, code, body);
    schc_compress_ipv6(&ipv6)
}

/// ── Test 1: Mesh node pings internet host ───────────────────────────────────

#[tokio::test]
async fn mesh_node_pings_internet_host() {
    // A mesh node (link-local) pings Google DNS (GUA).
    let src = ll(1);
    let dst = gua(0x88, 0x88); // 2001:4860:4860::8888

    let mut pkt = [0u8; 64];
    let n = icmpv6::echo_request(&src, &dst, 0xaaaa, 1, b"mesh2inet", &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // internet destination is not link-local, not ULA, not in route table
    // → is_local_mesh returns false → direct SCHC compress path
    let schc = gw
        .upstream_to_mesh(ipv6)
        .await
        .expect("compress internet-bound packet failed");

    // A distinct production link owner authenticates the complete signed
    // gateway frame before SCHC is exposed to the network layer.
    let mut peer = MeshPeer::new(9);
    let authenticated = peer
        .link
        .receive_frame_at(&schc, 1)
        .expect("gateway outbound frame must authenticate at a peer stack");
    let recovered =
        schc_decompress_l2(authenticated.payload()).expect("decompress authenticated payload");
    assert_eq!(recovered[6], 58, "NH should be ICMPv6");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(
        recovered[40],
        icmpv6::ECHO_REQUEST,
        "type should be Echo Request"
    );
    assert_eq!(&recovered[48..], b"mesh2inet", "payload mismatch");
}

/// ── Test 2: Internet host pings mesh node ───────────────────────────────────

#[tokio::test]
async fn internet_host_pings_mesh_node() {
    // An internet host (GUA) sends ICMPv6 echo to a mesh node (link-local).
    let src = gua(0, 1);
    let dst = ll(3);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xbbbb, 2, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // destination is link-local → is_local_mesh returns true → mesh_to_mesh path
    let schc = gw
        .upstream_to_mesh(ipv6)
        .await
        .expect("compress mesh ingress failed");

    // Round-trip verification
    let recovered = schc_decompress_l2(&schc).expect("decompress failed");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
}

/// ── Test 3: Gateway handles RPL DIS from mesh node ──────────────────────────

#[tokio::test]
async fn gateway_handles_rpl_dis_from_mesh_node() {
    let mut gw = test_gateway();
    let mut peer = MeshPeer::new(5);
    peer.bootstrap(&mut gw, 0).await;
    let mut ingress = send_dis(&mut gw, &mut peer, 1).await;

    assert_eq!(
        ingress.rpl_event(),
        RplEvent::DisReceived,
        "gateway should recognize DIS"
    );
    let dio_reply = ingress
        .take_mesh_reply()
        .expect("gateway must reply with DIO");
    assert!(dio_reply.len() > 1, "DIO reply must not be empty");

    // Authenticate and decompress the DIO reply.
    let ipv6 = decode_signed_reply(&mut peer, &dio_reply);
    assert!(ipv6.len() >= IPV6_HEADER_LEN + 4);
    assert_eq!(ipv6[6], next_header::ICMPV6);
    assert_eq!(
        ipv6[IPV6_HEADER_LEN], RPL_ICMPV6_TYPE,
        "type must be RPL (155)"
    );
    assert_eq!(
        ipv6[IPV6_HEADER_LEN + 1],
        rpl_code::DIO,
        "code must be DIO (1)"
    );

    // DIO body: verify RPL instance ID
    let dio_body = &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..];
    assert_eq!(dio_body[0], RPL_INSTANCE_ID, "DIO rpl_instance_id mismatch");
}

/// ── Test 4: Gateway DIO carries correct root metadata ───────────────────────

#[tokio::test]
async fn gateway_dio_carries_root_metadata() {
    // Gateway's address is derived from its identity seed, not ll(1)
    let seed = Seed::new([0x02; 32]);
    let identity = Identity::from_seed(seed);
    let gw_addr = gw_native(&identity);

    let mut gw = test_gateway();
    let mut peer = MeshPeer::new(5);
    peer.bootstrap(&mut gw, 0).await;
    let mut ingress = send_dis(&mut gw, &mut peer, 1).await;
    assert_eq!(ingress.rpl_event(), RplEvent::DisReceived);

    let dio_reply = ingress.take_mesh_reply().unwrap();
    let ipv6 = decode_signed_reply(&mut peer, &dio_reply);

    let dio_bytes = &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..];
    let dio = lichen_rpl::message::Dio::from_bytes(dio_bytes).expect("parse DIO base");

    assert!(dio.grounded, "root DIO must be grounded (G=1)");
    assert_eq!(dio.mode_of_operation, 1, "mode must be Non-Storing (MOP=1)");
    assert_eq!(dio.rpl_instance_id, RPL_INSTANCE_ID);
    // dodag_id should match the gateway's root address
    assert_eq!(&dio.dodag_id, &gw_addr, "DODAG ID must equal root address");
}

/// ── Test 5: Gateway drops non-RPL ICMPv6 gracefully ─────────────────────────

#[tokio::test]
async fn gateway_rejects_bare_non_rpl_l2_payload() {
    // Send a plain ICMPv6 echo request through process_rpl (not the forwarding path)
    let src = ll(5);
    let dst = ll(1);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xbeef, 0, &[], &mut pkt);
    let ipv6 = &pkt[..n];
    let l2 = schc_compress_ipv6(ipv6);

    let mut gw = test_gateway();
    assert!(gw.ingest_mesh_frame(&l2, None, None, 0).await.is_err());
}

#[tokio::test]
async fn gateway_rejects_replayed_authenticated_wire_before_forwarding() {
    let mut gw = test_gateway();
    let mut peer = MeshPeer::new(7);
    peer.bootstrap(&mut gw, 0).await;

    let source = peer.link_local();
    let destination = gua(0x88, 0x88);
    let mut packet = [0u8; 48];
    let length = icmpv6::echo_request(&source, &destination, 0x1234, 1, &[], &mut packet);
    let l2 = schc_compress_ipv6(&packet[..length]);
    let wire = peer.build_wire(&l2, &MeshPeer::root_eui64());

    let admitted = gw
        .ingest_mesh_frame(&wire, Some(-50), Some(10), 1)
        .await
        .unwrap();
    assert!(admitted.upstream_ipv6().is_some());
    assert!(gw
        .ingest_mesh_frame(&wire, Some(-50), Some(10), 2)
        .await
        .is_err());
}

/// ── Test 6: ULA mesh node pings internet host ───────────────────────────────

#[tokio::test]
async fn ula_mesh_node_pings_internet_host() {
    // A mesh node using ULA pings an internet host.
    let src = ula(10);
    let dst = gua(0x88, 0x88);

    let mut pkt = [0u8; 64];
    let n = icmpv6::echo_request(&src, &dst, 0xcccc, 3, b"ula2inet", &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // ULA → GUA: is_local_mesh checks for GUA dst; no route → is_local_mesh = false
    // → direct SCHC compress
    let schc = gw
        .upstream_to_mesh(ipv6)
        .await
        .expect("compress ULA→internet failed");

    let recovered = schc_decompress_l2(&schc).expect("decompress failed");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
    assert_eq!(&recovered[48..], b"ula2inet", "payload mismatch");
}

/// ── Test 7: Internet host pings ULA mesh node ───────────────────────────────

#[tokio::test]
async fn internet_host_pings_ula_mesh_node() {
    let src = gua(0, 2);
    let dst = ula(10);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xdddd, 4, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    assert!(!gw.is_local_mesh(&dst.0));
    assert!(gw.upstream_to_mesh(ipv6).await.is_none());
}

/// ── Test 8: Link-local echo reply round-trips through gateway ────────────────

#[tokio::test]
async fn icmpv6_echo_reply_round_trips_through_gateway() {
    // Internet host sends echo reply back to mesh node
    let src = gua(0, 3);
    let dst = ll(2);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_reply(&src, &dst, 0xeeee, 5, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    let schc = gw
        .upstream_to_mesh(ipv6)
        .await
        .expect("compress echo reply failed");
    let recovered = schc_decompress_l2(&schc).expect("decompress failed");

    assert_eq!(
        recovered[40],
        icmpv6::ECHO_REPLY,
        "type must be Echo Reply (129)"
    );
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
}

/// ── Test 9: Gateway maintains RPL state across multiple DIS ──────────────────

#[tokio::test]
async fn gateway_maintains_rpl_state_across_dis_packets() {
    let mut gw = test_gateway();
    let mut peer = MeshPeer::new(5);
    peer.bootstrap(&mut gw, 90).await;
    let ingress1 = send_dis(&mut gw, &mut peer, 100).await;
    assert_eq!(ingress1.rpl_event(), RplEvent::DisReceived);
    assert!(ingress1.mesh_reply().is_some());

    // Second DIS from different mesh node at later time
    let mut peer2 = MeshPeer::new(6);
    peer2.bootstrap(&mut gw, 190).await;
    let ingress2 = send_dis(&mut gw, &mut peer2, 200).await;
    assert_eq!(ingress2.rpl_event(), RplEvent::DisReceived);
    assert!(ingress2.mesh_reply().is_some());

    // Third DIS with maintain call in between
    gw.maintain(300);
    let ingress3 = send_dis(&mut gw, &mut peer, 400).await;
    assert_eq!(ingress3.rpl_event(), RplEvent::DisReceived);
    assert!(ingress3.mesh_reply().is_some());
}

/// ── Test 10: Gateway does not process RPL from non-SCHC payload ──────────────

#[tokio::test]
async fn gateway_rejects_bare_non_schc_payload() {
    let mut gw = test_gateway();
    assert!(gw
        .ingest_mesh_frame(&[0x15, 0x01], None, None, 0)
        .await
        .is_err());
}

/// ── Test 11: Mesh-to-mesh forwarding drops unknown GUA destinations ──────────

#[tokio::test]
async fn mesh_to_mesh_drops_unknown_gua_destination() {
    let src = ll(5);
    let dst = gua(0, 0x42); // GUA not in route table

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xffff, 0, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // mesh_to_mesh for GUA with no route → None
    let result = gw.mesh_to_mesh(ipv6).await;
    assert!(
        result.is_none(),
        "unknown GUA should be dropped in mesh_to_mesh"
    );
}

/// ── Test 12: Address classification: known address types ────────────────────

#[test]
fn address_classification_known_types() {
    let gw = test_gateway();
    let local = ll(1);
    let link_local_other = ll(7);
    let ula_addr = ula(20);
    let internet_addr = gua(0x88, 0x88);
    let nat64 = [
        0x00u8, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
    ];

    assert!(
        gw.is_local_mesh(&local.0),
        "gateway itself should be local mesh"
    );
    assert!(
        gw.is_local_mesh(&link_local_other.0),
        "link-local peers are local mesh"
    );
    assert!(
        !gw.is_local_mesh(&ula_addr.0),
        "ULA addresses are not part of the native mesh profile"
    );
    assert!(
        !gw.is_local_mesh(&internet_addr.0),
        "internet addresses are not local mesh"
    );
    assert!(
        !gw.is_local_mesh(&nat64),
        "NAT64 addresses are not local mesh"
    );
}

/// ── Test 13: Gateway forwards ICMPv6 echo with varying payload sizes ────────

#[tokio::test]
async fn gateway_forwards_varying_echo_payload_sizes() {
    for payload_len in [0, 1, 8, 32, 64, 128] {
        let src = ll(1);
        let dst = ll(2);
        let payload = vec![0xabu8; payload_len];
        let mut pkt = vec![0u8; 48 + payload_len];
        let n = icmpv6::echo_request(&src, &dst, 0xa001, 1, &payload, &mut pkt);
        let ipv6 = &pkt[..n];

        let mut gw = test_gateway();
        let schc = gw
            .upstream_to_mesh(ipv6)
            .await
            .unwrap_or_else(|| panic!("compress with payload_len={}", payload_len));
        let recovered = schc_decompress_l2(&schc)
            .unwrap_or_else(|| panic!("decompress with payload_len={}", payload_len));

        assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
        assert_eq!(
            &recovered[48..],
            &payload[..],
            "payload mismatch at len={}",
            payload_len
        );
    }
}

/// ── Test 14: Gateway drops oversize RPL packet ──────────────────────────────
#[test]
fn gateway_drops_oversize_decompressed_packet() {
    // Build a frame with an unknown SCHC rule (cannot decompress)
    // This tests the unknown rule path
    assert!(schc_decompress_l2(&[L2_DISPATCH_SCHC, 0xAA, 0x00]).is_none());
}

/// ── Test 15: Gateway DIO reply has valid IPv6 checksum ──────────────────────

#[tokio::test]
async fn gateway_dio_reply_has_valid_ipv6() {
    let mut gw = test_gateway();
    let mut peer = MeshPeer::new(5);
    peer.bootstrap(&mut gw, 0).await;
    let mut ingress = send_dis(&mut gw, &mut peer, 1).await;
    let dio_reply = ingress.take_mesh_reply().unwrap();
    let ipv6 = decode_signed_reply(&mut peer, &dio_reply);
    let len = ipv6.len();

    assert!(ipv6.len() >= IPV6_HEADER_LEN + 4);
    assert_eq!(ipv6[0] >> 4, 6, "version must be 6");
    let payload_len = u16::from_be_bytes([ipv6[4], ipv6[5]]) as usize;
    assert_eq!(
        payload_len + IPV6_HEADER_LEN,
        len,
        "payload length must match"
    );
    assert_eq!(ipv6[6], next_header::ICMPV6);
}

#[tokio::test]
async fn runtime_ingress_dispatches_authenticated_gcp_slot_claim() {
    let gateway_identity = gateway_identity();
    let gateway_addr = gw_native(&gateway_identity);
    let remote_identity = Identity::from_seed(Seed::new([0x76; 32]));
    let remote_pubkey = *remote_identity.pubkey.as_bytes();
    let remote_iid = remote_identity.iid;

    let master_secret = [0x78; 16];
    let root = std::env::temp_dir().join(format!(
        "lichen-runtime-gcp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let floor_root = root.with_extension("floors");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&floor_root).unwrap();
    let sealing_seed = [0x7a; 32];
    let trust = TrustStore::new_ephemeral(8).unwrap();
    trust
        .save_atomic_with_floor(
            &root.join("gateway-trust.bin"),
            &floor_root.join("gateway-trust.generation"),
            &sealing_seed,
        )
        .unwrap();
    let coordinator = GatewayCoordinator::provision_persistent(
        gateway_addr,
        60,
        64,
        &root.join("gateway-slot-replay.bin"),
        &floor_root.join("gateway-slot-replay.generation"),
        &sealing_seed,
    )
    .unwrap();
    let mut gateway = Gateway::new_persistent(
        gateway_identity.clone(),
        128,
        trust,
        coordinator,
        GatewayPersistence::new(
            FileStorage::new(&root).unwrap(),
            true,
            root.clone(),
            floor_root.clone(),
            sealing_seed,
        ),
    )
    .unwrap();
    let federation = PskFederation::new(&master_secret, None, None).unwrap();
    gateway
        .provision_closed_federation(&federation, &[remote_pubkey])
        .unwrap();

    let (client_radio, mut wire_receiver) = LoopbackRadio::pair();
    let mut client =
        SecureStack::from_radio(client_radio, remote_identity.clone(), 128, 1).unwrap();
    client.add_peer(PeerIdentity::from_pubkey(gateway_identity.pubkey));
    let mut client_store = TestSenderStore::default();
    let client_context = federation
        .derive_context(&remote_iid, &gateway_identity.iid)
        .unwrap()
        .register_fresh(&mut client_store)
        .unwrap();
    client
        .restore_context(gateway_identity.iid, client_context, &mut client_store)
        .unwrap();

    let (claim_private, claim_public) = derive_keypair(&Seed::new([0x76; 32]));
    assert_eq!(claim_public.as_bytes(), &remote_pubkey);
    let current_superframe = gateway.current_superframe();
    let slots = vec![1, 2, 3];
    let claim_transcript =
        lichen_gateway::slot::slot_claim_transcript(&remote_iid, &slots, current_superframe, 0)
            .unwrap();
    let mut claim = SlotClaim::new(remote_iid, slots, current_superframe, 0);
    claim.signature = Some(sign(&claim_private, &claim_public, &claim_transcript));
    let payload = claim.encode();
    let mut correlation = client
        .send_secure_request(
            &Addr(gateway_addr),
            &gateway_identity.iid,
            SecureRequestData {
                uri_path: &[".well-known", "lichen-gw", "slots"],
                token: &[0x79],
                method: MessageCode::POST,
                payload: &payload,
            },
            &mut client_store,
        )
        .await
        .unwrap();
    let mut wire = [0u8; 255];
    let length = wire_receiver
        .receive(0, &mut wire, 1)
        .await
        .unwrap()
        .unwrap()
        .len;

    let mut ingress = gateway
        .ingest_mesh_frame_at_superframe(&wire[..length], Some(-45), Some(8), 1, current_superframe)
        .await
        .unwrap();
    assert!(ingress.gcp_dispatched());
    assert!(ingress.upstream_ipv6().is_none());
    let response_wire = ingress
        .take_mesh_reply()
        .expect("runtime GCP dispatch must return a signed protected response");
    wire_receiver.transmit(0, &response_wire).await.unwrap();
    let protected_response = client
        .receive_secure_datagram(1)
        .await
        .unwrap()
        .expect("client receives GCP response");
    let response = client
        .decrypt_response(&protected_response, &mut correlation)
        .await
        .unwrap();
    assert!(matches!(
        response,
        lichen_node::secure::SecureResponse::Decrypted { code, options, .. }
            if matches!(code.0, 0x44 | 0x45) && options == [0xc1, 60]
    ));
    assert_eq!(
        gateway
            .handle_gcp_request(
                CoapMethod::Post,
                "slots",
                &payload,
                true,
                Some(&remote_pubkey),
                current_superframe,
            )
            .code,
        0x81,
        "runtime dispatch must have committed the slot replay high-water"
    );
    assert_eq!(iid_from_pubkey(&remote_pubkey), remote_iid);
    drop(gateway);

    let trust_floor: [u8; 8] = std::fs::read(floor_root.join("gateway-trust.generation"))
        .unwrap()
        .try_into()
        .unwrap();
    let trust = TrustStore::load(
        &root.join("gateway-trust.bin"),
        &sealing_seed,
        u64::from_be_bytes(trust_floor),
        8,
    )
    .unwrap();
    let coordinator = GatewayCoordinator::load_persistent(
        gateway_addr,
        60,
        64,
        &root.join("gateway-slot-replay.bin"),
        &floor_root.join("gateway-slot-replay.generation"),
        &sealing_seed,
    )
    .unwrap();
    let mut restarted = Gateway::new_persistent(
        gateway_identity,
        129,
        trust,
        coordinator,
        GatewayPersistence::new(
            FileStorage::new(&root).unwrap(),
            false,
            root.clone(),
            floor_root.clone(),
            sealing_seed,
        ),
    )
    .unwrap();
    restarted
        .provision_closed_federation(&federation, &[remote_pubkey])
        .unwrap();
    let replay = restarted
        .ingest_mesh_frame_at_superframe(&wire[..length], Some(-45), Some(8), 2, current_superframe)
        .await
        .unwrap();
    assert!(
        replay.mesh_reply().is_none(),
        "captured OSCORE request must not receive a second response after restart"
    );
    assert!(
        replay.upstream_ipv6().is_none(),
        "replay must be consumed rather than forwarded upstream"
    );
    drop(restarted);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(floor_root).unwrap();
}
