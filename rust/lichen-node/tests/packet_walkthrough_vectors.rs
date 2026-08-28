// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Consume spec 09 section 13.1 CoAP-to-PHY walkthrough vectors.

use lichen_coap::option::content_format::CBOR;
use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
use lichen_core::addr::Ipv6Addr;
use lichen_core::airtime::airtime_us;
use lichen_core::constants::L2_DISPATCH_SCHC;
use lichen_core::ipv6::write_header;
use lichen_core::l2_payload::{body, classify, L2PayloadKind};
use lichen_core::udp::write_datagram;
use lichen_link::frame::{AddrMode, Encryption, LichenFrame, MicLength, Signature};
use lichen_link::LinkSeqNum;
use lichen_schc::compress;
use serde_json::Value;

const JSON: &str = include_str!("../../../test/vectors/packet_walkthrough.json");

fn document() -> Value {
    serde_json::from_str(JSON).expect("packet_walkthrough.json must parse")
}

fn vector(name: &str) -> Value {
    document()["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("missing vector {name}"))
        .clone()
}

fn hex_field(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} hex")),
    )
    .expect("hex")
}

#[test]
fn walkthrough_vector_set_is_complete() {
    let document = document();
    let names: Vec<&str> = document["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|vector| vector["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        [
            "coap_temperature_content",
            "ipv6_udp_envelope",
            "schc_rule0_compress",
            "l2_schc_dispatch",
            "link_frame_signed_short",
            "phy_sf10_airtime",
            "spec_13_1_complete_walkthrough",
        ]
    );
    assert_eq!(document["format_version"], 2);
}

#[test]
fn layer_outputs_chain_into_the_complete_walkthrough() {
    let names = [
        "coap_temperature_content",
        "ipv6_udp_envelope",
        "schc_rule0_compress",
        "l2_schc_dispatch",
        "link_frame_signed_short",
        "phy_sf10_airtime",
    ];
    for window in names.windows(2) {
        assert_eq!(
            vector(window[0])["output_hex"],
            vector(window[1])["input_hex"],
            "{} -> {}",
            window[0],
            window[1]
        );
    }
    let walkthrough = vector("spec_13_1_complete_walkthrough");
    let layers = &walkthrough["layers"];
    assert_eq!(
        layers["coap_hex"],
        vector("coap_temperature_content")["output_hex"]
    );
    assert_eq!(
        layers["ipv6_udp_hex"],
        vector("ipv6_udp_envelope")["output_hex"]
    );
    assert_eq!(
        layers["schc_hex"],
        vector("schc_rule0_compress")["output_hex"]
    );
    assert_eq!(layers["l2_hex"], vector("l2_schc_dispatch")["output_hex"]);
    assert_eq!(
        layers["link_hex"],
        vector("link_frame_signed_short")["output_hex"]
    );
    assert_eq!(
        layers["phy_payload_hex"],
        vector("phy_sf10_airtime")["output_hex"]
    );
    assert_eq!(walkthrough["app_payload_len"], 16);
    assert_eq!(walkthrough["schc_packet_len"], 43);
    assert_eq!(walkthrough["l2_payload_len"], 44);
    assert_eq!(walkthrough["body_bytes"], 106);
    assert_eq!(walkthrough["total_on_wire"], 107);
}

#[test]
fn coap_layer_matches_production_builder() {
    let vector = vector("coap_temperature_content");
    let fields = &vector["fields"];
    let payload = hex_field(fields, "payload_hex");
    let token = hex_field(fields, "token_hex");
    let mut buffer = [0u8; 64];
    let mut builder = CoapBuilder::new(
        &mut buffer,
        MessageType::NonConfirmable,
        MessageCode::CONTENT,
        u16::try_from(fields["mid"].as_u64().expect("mid")).expect("mid"),
        &token,
    )
    .expect("coap header");
    builder
        .content_format(CBOR)
        .expect("content-format")
        .payload(&payload)
        .expect("payload");
    let encoded = builder.as_bytes().to_vec();
    assert_eq!(encoded, hex_field(&vector, "output_hex"));
    let parsed = CoapPacket::from_bytes(&encoded).expect("parse coap");
    assert_eq!(parsed.msg_type(), MessageType::NonConfirmable);
    assert_eq!(parsed.code(), MessageCode::CONTENT);
    assert_eq!(parsed.message_id(), 0);
    assert_eq!(parsed.token(), token.as_slice());
    assert_eq!(parsed.payload(), payload.as_slice());
    let option = parsed
        .options()
        .next()
        .expect("content-format option")
        .expect("option parse");
    assert!(option.is_content_format());
    assert_eq!(option.as_uint().expect("uint"), u32::from(CBOR));
}

#[test]
fn ipv6_udp_layer_matches_production_headers() {
    let vector = vector("ipv6_udp_envelope");
    let fields = &vector["fields"];
    let coap = hex_field(&vector, "input_hex");
    let src = Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let src_port = u16::try_from(fields["src_port"].as_u64().expect("src_port")).expect("port");
    let dst_port = u16::try_from(fields["dst_port"].as_u64().expect("dst_port")).expect("port");
    let hop_limit = u8::try_from(fields["hop_limit"].as_u64().expect("hop")).expect("hop");
    let mut udp = [0u8; 128];
    let udp_len = write_datagram(&src, &dst, src_port, dst_port, &coap, &mut udp).expect("udp");
    let mut packet = [0u8; 256];
    let header_len = write_header(
        &src,
        &dst,
        17,
        hop_limit,
        u16::try_from(udp_len).expect("udp len"),
        &mut packet,
    )
    .expect("ipv6");
    packet[header_len..header_len + udp_len].copy_from_slice(&udp[..udp_len]);
    let encoded = &packet[..header_len + udp_len];
    assert_eq!(encoded, hex_field(&vector, "output_hex"));
}

#[test]
fn schc_layer_matches_rule0() {
    let vector = vector("schc_rule0_compress");
    let packet = hex_field(&vector, "input_hex");
    let mut out = [0u8; 256];
    let written = compress(&packet, &mut out).expect("compress");
    assert_eq!(&out[..written], hex_field(&vector, "output_hex"));
    assert_eq!(out[0], 0);
    assert_eq!(written, 43);
}

#[test]
fn l2_layer_matches_schc_dispatch() {
    let vector = vector("l2_schc_dispatch");
    let schc = hex_field(&vector, "input_hex");
    let mut wrapped = Vec::with_capacity(1 + schc.len());
    wrapped.push(L2_DISPATCH_SCHC);
    wrapped.extend_from_slice(&schc);
    assert_eq!(wrapped, hex_field(&vector, "output_hex"));
    assert_eq!(classify(&wrapped), L2PayloadKind::Schc);
    assert_eq!(body(&wrapped), schc.as_slice());
    assert_eq!(wrapped.len(), 44);
}

#[test]
fn link_layer_matches_signed_short_frame() {
    let vector = vector("link_frame_signed_short");
    let fields = &vector["fields"];
    let payload = hex_field(&vector, "input_hex");
    let signature = hex_field(fields, "signature_hex");
    let signer = hex_field(fields, "signer_eui64_hex");
    let dst = [
        u8::try_from(fields["DstAddr"].as_u64().expect("dst") >> 8).expect("hi"),
        u8::try_from(fields["DstAddr"].as_u64().expect("dst") & 0xFF).expect("lo"),
    ];
    let frame = LichenFrame {
        epoch: u8::try_from(fields["Epoch"].as_u64().expect("epoch")).expect("epoch"),
        seqnum: LinkSeqNum::new(
            u16::try_from(fields["SeqNum"].as_u64().expect("seq")).expect("seq"),
        ),
        dst_addr: &dst,
        signer_eui64: &signer,
        payload: &payload,
        mic: &signature,
        addr_mode: AddrMode::Short,
        mic_length: MicLength::Bits32,
        signature: Signature::Present,
        encryption: Encryption::Plaintext,
    };
    let mut buffer = [0u8; 256];
    let written = frame.write_to(&mut buffer).expect("encode frame");
    assert_eq!(&buffer[..written], hex_field(&vector, "output_hex"));
    assert_eq!(
        buffer[0],
        u8::try_from(fields["Length"].as_u64().expect("len")).expect("len")
    );
    assert_eq!(
        buffer[1],
        u8::try_from(fields["LLSec"].as_u64().expect("llsec")).expect("llsec")
    );
    assert_eq!(written, 107);
    let parsed = LichenFrame::from_bytes(&buffer[..written]).expect("parse frame");
    assert_eq!(parsed.epoch, frame.epoch);
    assert_eq!(parsed.seqnum, frame.seqnum);
    assert_eq!(parsed.dst_addr, dst);
    assert_eq!(parsed.payload, payload.as_slice());
    assert_eq!(parsed.mic, signature.as_slice());
}

#[test]
fn phy_layer_matches_default_airtime() {
    let vector = vector("phy_sf10_airtime");
    let fields = &vector["fields"];
    let payload = hex_field(&vector, "input_hex");
    assert_eq!(payload, hex_field(&vector, "output_hex"));
    assert_eq!(payload.len(), 107);
    assert_eq!(fields["payload_len"], 107);
    assert_eq!(
        airtime_us(u16::try_from(fields["payload_len"].as_u64().expect("len")).expect("len"))
            .expect("airtime"),
        fields["airtime_us"].as_u64().expect("airtime")
    );
    assert_eq!(fields["airtime_us"], 1_067_008);
    assert_eq!(fields["preamble_symbols"], 8);
    assert_eq!(fields["sf"], 10);
    assert_eq!(fields["bw_hz"], 125_000);
}
