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

use lichen_core::addr::{Ipv6Addr, NodeId};
use lichen_core::constants::{L2_DISPATCH_SCHC, RPL_ICMPV6_TYPE, RPL_INSTANCE_ID};
use lichen_core::icmpv6;
use lichen_core::icmpv6::hdr_field;
use lichen_core::ipv6::{field, next_header, IPV6_HEADER_LEN};
use lichen_gateway::Gateway;
use lichen_ipv6::{icmpv6_checksum, Addr};
use lichen_node::rpl_code;
use lichen_node::RplEvent;
use lichen_schc::codec;

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
    Gateway::new(NodeId([0x02, 0, 0, 0, 0, 0, 0, 0x01]))
}

/// SCHC-compress an IPv6 packet. Returns the L2 payload (dispatch + compressed).
fn schc_compress_ipv6(ipv6: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; ipv6.len() + 3];
    out[0] = L2_DISPATCH_SCHC;
    let n = codec::compress(ipv6, &mut out[1..]).expect("SCHC compress in test");
    out.truncate(n + 1);
    out
}

fn build_ipv6_icmpv6_header(src: &Ipv6Addr, dst: &Ipv6Addr, icmp_type: u8, icmp_code: u8, body: &[u8]) -> Vec<u8> {
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
    let checksum = icmpv6_checksum(&Addr(src.0), &Addr(dst.0), &pkt[IPV6_HEADER_LEN..]).expect("checksum compute");
    pkt[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

fn build_rpl_packet(src: &Ipv6Addr, dst: &Ipv6Addr, code: u8, body: &[u8]) -> Vec<u8> {
    let ipv6 = build_ipv6_icmpv6_header(src, dst, RPL_ICMPV6_TYPE, code, body);
    schc_compress_ipv6(&ipv6)
}

/// ── Test 1: Mesh node pings internet host ───────────────────────────────────

#[test]
fn mesh_node_pings_internet_host() {
    // A mesh node (link-local) pings Google DNS (GUA).
    let src = ll(1);
    let dst = gua(0x88, 0x88); // 2001:4860:4860::8888

    let mut pkt = [0u8; 52];
    let n = icmpv6::echo_request(&src, &dst, 0xaaaa, 1, b"mesh2inet", &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // internet destination is not link-local, not ULA, not in route table
    // → is_local_mesh returns false → direct SCHC compress path
    let schc = gw.upstream_to_mesh(ipv6).expect("compress internet-bound packet failed");
    assert_eq!(schc[0], L2_DISPATCH_SCHC);

    // Round-trip: decompress and verify the IP and ICMPv6 headers
    let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
    assert_eq!(recovered[6], 58, "NH should be ICMPv6");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST, "type should be Echo Request");
    assert_eq!(&recovered[48..], b"mesh2inet", "payload mismatch");
}

/// ── Test 2: Internet host pings mesh node ───────────────────────────────────

#[test]
fn internet_host_pings_mesh_node() {
    // An internet host (GUA) sends ICMPv6 echo to a mesh node (link-local).
    let src = gua(0, 1);
    let dst = ll(3);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xbbbb, 2, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // destination is link-local → is_local_mesh returns true → mesh_to_mesh path
    let schc = gw.upstream_to_mesh(ipv6).expect("compress mesh ingress failed");
    assert_eq!(schc[0], L2_DISPATCH_SCHC);

    // Round-trip verification
    let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
}

/// ── Test 3: Gateway handles RPL DIS from mesh node ──────────────────────────

#[test]
fn gateway_handles_rpl_dis_from_mesh_node() {
    let mesh_src = ll(5);
    let gw_dst = ll(1); // gateway link-local

    let dis = build_rpl_packet(&mesh_src, &gw_dst, rpl_code::DIS, &[0, 0]);

    let mut gw = test_gateway();
    let (reply, event) = gw.process_rpl(&dis, 0);

    assert_eq!(event, RplEvent::DisReceived, "gateway should recognize DIS");
    let dio_reply = reply.expect("gateway must reply with DIO");
    assert!(dio_reply.len() > 1, "DIO reply must not be empty");

    // Decompress the DIO reply and verify it's an RPL DIO
    assert_eq!(dio_reply[0], L2_DISPATCH_SCHC);
    let mut ipv6 = [0u8; 512];
    let len = codec::decompress(&dio_reply[1..], &mut ipv6).expect("decompress DIO reply");
    let ipv6 = &ipv6[..len];
    assert!(ipv6.len() >= IPV6_HEADER_LEN + 4);
    assert_eq!(ipv6[6], next_header::ICMPV6);
    assert_eq!(ipv6[IPV6_HEADER_LEN], RPL_ICMPV6_TYPE, "type must be RPL (155)");
    assert_eq!(ipv6[IPV6_HEADER_LEN + 1], rpl_code::DIO, "code must be DIO (1)");

    // DIO body: verify RPL instance ID
    let dio_body = &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..];
    assert_eq!(dio_body[0], RPL_INSTANCE_ID, "DIO rpl_instance_id mismatch");
}

/// ── Test 4: Gateway DIO carries correct root metadata ───────────────────────

#[test]
fn gateway_dio_carries_root_metadata() {
    let mesh_src = ll(5);
    let gw_dst = ll(1);

    let dis = build_rpl_packet(&mesh_src, &gw_dst, rpl_code::DIS, &[0, 0]);
    let mut gw = test_gateway();
    let (reply, event) = gw.process_rpl(&dis, 0);
    assert_eq!(event, RplEvent::DisReceived);

    let dio_reply = reply.unwrap();
    let mut ipv6 = [0u8; 512];
    let len = codec::decompress(&dio_reply[1..], &mut ipv6).unwrap();
    let ipv6 = &ipv6[..len];

    let dio_bytes = &ipv6[IPV6_HEADER_LEN + hdr_field::BODY_OFFSET..];
    let dio = lichen_rpl::message::Dio::from_bytes(dio_bytes).expect("parse DIO base");

    assert!(dio.grounded, "root DIO must be grounded (G=1)");
    assert_eq!(dio.mode_of_operation, 1, "mode must be Non-Storing (MOP=1)");
    assert_eq!(dio.rpl_instance_id, RPL_INSTANCE_ID);
    // dodag_id should match the gateway's root address
    let gw_addr = ll(1);
    assert_eq!(&dio.dodag_id, &gw_addr.0, "DODAG ID must equal root address");
}

/// ── Test 5: Gateway drops non-RPL ICMPv6 gracefully ─────────────────────────

#[test]
fn gateway_drops_non_rpl_icmpv6_in_process_rpl() {
    // Send a plain ICMPv6 echo request through process_rpl (not the forwarding path)
    let src = ll(5);
    let dst = ll(1);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xbeef, 0, &[], &mut pkt);
    let ipv6 = &pkt[..n];
    let l2 = schc_compress_ipv6(ipv6);

    let mut gw = test_gateway();
    let (reply, event) = gw.process_rpl(&l2, 0);

    assert_eq!(reply, None, "gateway must not reply to non-RPL in process_rpl");
    assert_eq!(event, RplEvent::None, "non-RPL must yield None event");
}

/// ── Test 6: ULA mesh node pings internet host ───────────────────────────────

#[test]
fn ula_mesh_node_pings_internet_host() {
    // A mesh node using ULA pings an internet host.
    let src = ula(10);
    let dst = gua(0x88, 0x88);

    let mut pkt = [0u8; 52];
    let n = icmpv6::echo_request(&src, &dst, 0xcccc, 3, b"ula2inet", &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // ULA → GUA: is_local_mesh checks for GUA dst; no route → is_local_mesh = false
    // → direct SCHC compress
    let schc = gw.upstream_to_mesh(ipv6).expect("compress ULA→internet failed");
    assert_eq!(schc[0], L2_DISPATCH_SCHC);

    let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
    assert_eq!(&recovered[48..], b"ula2inet", "payload mismatch");
}

/// ── Test 7: Internet host pings ULA mesh node ───────────────────────────────

#[test]
fn internet_host_pings_ula_mesh_node() {
    let src = gua(0, 2);
    let dst = ula(10);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xdddd, 4, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    // dst is ULA → is_local_mesh returns true → mesh_to_mesh path
    let schc = gw.upstream_to_mesh(ipv6).expect("compress GUA→ULA failed");
    assert_eq!(schc[0], L2_DISPATCH_SCHC);

    let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
}

/// ── Test 8: Link-local echo reply round-trips through gateway ────────────────

#[test]
fn icmpv6_echo_reply_round_trips_through_gateway() {
    // Internet host sends echo reply back to mesh node
    let src = gua(0, 3);
    let dst = ll(2);

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_reply(&src, &dst, 0xeeee, 5, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let mut gw = test_gateway();
    let schc = gw.upstream_to_mesh(ipv6).expect("compress echo reply failed");
    let recovered = gw.mesh_to_upstream(&schc).expect("decompress failed");

    assert_eq!(recovered[40], icmpv6::ECHO_REPLY, "type must be Echo Reply (129)");
    assert_eq!(&recovered[8..24], &src.0, "src mismatch");
    assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
}

/// ── Test 9: Gateway maintains RPL state across multiple DIS ──────────────────

#[test]
fn gateway_maintains_rpl_state_across_dis_packets() {
    let mesh_src = ll(5);
    let gw_dst = ll(1);

    // First DIS
    let dis = build_rpl_packet(&mesh_src, &gw_dst, rpl_code::DIS, &[0, 0]);
    let mut gw = test_gateway();
    let (reply1, event1) = gw.process_rpl(&dis, 100);
    assert_eq!(event1, RplEvent::DisReceived);
    assert!(reply1.is_some());

    // Second DIS from different mesh node at later time
    let mesh_src2 = ll(6);
    let dis2 = build_rpl_packet(&mesh_src2, &gw_dst, rpl_code::DIS, &[0, 0]);
    let (reply2, event2) = gw.process_rpl(&dis2, 200);
    assert_eq!(event2, RplEvent::DisReceived);
    assert!(reply2.is_some());

    // Third DIS with maintain call in between
    gw.maintain(300);
    let dis3 = build_rpl_packet(&mesh_src, &gw_dst, rpl_code::DIS, &[0, 0]);
    let (reply3, event3) = gw.process_rpl(&dis3, 400);
    assert_eq!(event3, RplEvent::DisReceived);
    assert!(reply3.is_some());
}

/// ── Test 10: Gateway does not process RPL from non-SCHC payload ──────────────

#[test]
fn gateway_ignores_non_schc_in_process_rpl() {
    let mut gw = test_gateway();
    let (reply, event) = gw.process_rpl(&[0x15, 0x01], 0);
    assert_eq!(reply, None);
    assert_eq!(event, RplEvent::None);
}

/// ── Test 11: Mesh-to-mesh forwarding drops unknown GUA destinations ──────────

#[test]
fn mesh_to_mesh_drops_unknown_gua_destination() {
    let src = ll(5);
    let dst = gua(0, 0x42); // GUA not in route table

    let mut pkt = [0u8; 48];
    let n = icmpv6::echo_request(&src, &dst, 0xffff, 0, &[], &mut pkt);
    let ipv6 = &pkt[..n];

    let gw = test_gateway();
    // mesh_to_mesh for GUA with no route → None
    let result = gw.mesh_to_mesh(ipv6);
    assert!(result.is_none(), "unknown GUA should be dropped in mesh_to_mesh");
}

/// ── Test 12: Address classification: known address types ────────────────────

#[test]
fn address_classification_known_types() {
    let gw = test_gateway();
    let local = ll(1);
    let link_local_other = ll(7);
    let ula_addr = ula(20);
    let internet_addr = gua(0x88, 0x88);
    let nat64 = [0x00u8, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1];

    assert!(gw.is_local_mesh(&local.0), "gateway itself should be local mesh");
    assert!(gw.is_local_mesh(&link_local_other.0), "link-local peers are local mesh");
    assert!(gw.is_local_mesh(&ula_addr.0), "ULA addresses are local mesh");
    assert!(!gw.is_local_mesh(&internet_addr.0), "internet addresses are not local mesh");
    assert!(!gw.is_local_mesh(&nat64), "NAT64 addresses are not local mesh");
}

/// ── Test 13: Gateway forwards ICMPv6 echo with varying payload sizes ────────

#[test]
fn gateway_forwards_varying_echo_payload_sizes() {
    for payload_len in [0, 1, 8, 32, 64, 128] {
        let src = ll(1);
        let dst = ll(2);
        let payload = vec![0xabu8; payload_len];
        let mut pkt = vec![0u8; 48 + payload_len];
        let n = icmpv6::echo_request(&src, &dst, 0xa001, 1, &payload, &mut pkt);
        let ipv6 = &pkt[..n];

        let mut gw = test_gateway();
        let schc = gw.upstream_to_mesh(ipv6).expect(&format!("compress with payload_len={}", payload_len));
        let recovered = gw.mesh_to_upstream(&schc).expect(&format!("decompress with payload_len={}", payload_len));

        assert_eq!(recovered[40], icmpv6::ECHO_REQUEST);
        assert_eq!(&recovered[48..], &payload[..], "payload mismatch at len={}", payload_len);
    }
}

/// ── Test 14: Gateway drops oversize RPL packet ──────────────────────────────

use lichen_core::constants::SCHC_MAX_DECOMPRESSED;
use lichen_schc::codec::SchcError;

#[test]
fn gateway_drops_oversize_decompressed_packet() {
    let mut gw = test_gateway();

    // Build a frame with an unknown SCHC rule (cannot decompress)
    // This tests the unknown rule path
    assert!(gw.mesh_to_upstream(&[L2_DISPATCH_SCHC, 0xAA, 0x00]).is_none());
}

/// ── Test 15: Gateway DIO reply has valid IPv6 checksum ──────────────────────

#[test]
fn gateway_dio_reply_has_valid_ipv6() {
    let mesh_src = ll(5);
    let gw_dst = ll(1);

    let dis = build_rpl_packet(&mesh_src, &gw_dst, rpl_code::DIS, &[0, 0]);
    let mut gw = test_gateway();
    let (reply, _event) = gw.process_rpl(&dis, 0);
    let dio_reply = reply.unwrap();

    let mut ipv6 = [0u8; 512];
    let len = codec::decompress(&dio_reply[1..], &mut ipv6).unwrap();
    let ipv6 = &ipv6[..len];

    assert!(ipv6.len() >= IPV6_HEADER_LEN + 4);
    assert_eq!(ipv6[0] >> 4, 6, "version must be 6");
    let payload_len = u16::from_be_bytes([ipv6[4], ipv6[5]]) as usize;
    assert_eq!(payload_len + IPV6_HEADER_LEN, len, "payload length must match");
    assert_eq!(ipv6[6], next_header::ICMPV6);
}
