// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Focused compression coverage for SCHC Rule 5 (link-local OSCORE).

use lichen_core::constants::{RULE_LINK_LOCAL_COAP, RULE_LINK_LOCAL_OSCORE};
use lichen_schc::{compress, decompress, SchcError};
use serde::Deserialize;

const MAX_PACKET_SIZE: usize = 22_554;
const SRC: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    packet: Option<String>,
    compressed: Option<String>,
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn checksum_bytes(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn udp_checksum(payload: &[u8]) -> u16 {
    let udp_len = u16::try_from(8 + payload.len()).unwrap();
    let mut sum = checksum_bytes(&SRC) + checksum_bytes(&DST);
    sum += u32::from(udp_len) + 17;
    sum += u32::from(5683u16) * 2 + u32::from(udp_len);
    sum += checksum_bytes(payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

fn packet(options_and_payload: &[u8], token: &[u8]) -> Vec<u8> {
    assert!(token.len() <= 8);
    let mut coap = vec![0x40 | token.len() as u8, 1, 0x12, 0x34];
    coap.extend_from_slice(token);
    coap.extend_from_slice(options_and_payload);
    let udp_len = u16::try_from(8 + coap.len()).unwrap();
    let mut result = vec![0u8; 40 + usize::from(udp_len)];
    result[0] = 0x60;
    result[4..6].copy_from_slice(&udp_len.to_be_bytes());
    result[6] = 17;
    result[7] = 64;
    result[8..24].copy_from_slice(&SRC);
    result[24..40].copy_from_slice(&DST);
    result[40..42].copy_from_slice(&5683u16.to_be_bytes());
    result[42..44].copy_from_slice(&5683u16.to_be_bytes());
    result[44..46].copy_from_slice(&udp_len.to_be_bytes());
    result[48..].copy_from_slice(&coap);
    let checksum = udp_checksum(&coap);
    result[46..48].copy_from_slice(&checksum.to_be_bytes());
    result
}

fn compressed(packet: &[u8]) -> Result<Vec<u8>, SchcError> {
    let mut output = vec![0u8; packet.len() + 1];
    let length = compress(packet, &mut output)?;
    output.truncate(length);
    Ok(output)
}

#[test]
fn canonical_shared_vector_matches_python_oracle() {
    let document: VectorFile =
        serde_json::from_str(include_str!("../../../test/vectors/schc_compression.json")).unwrap();
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.name == "oscore_linklocal")
        .unwrap();
    let packet = hex(vector.packet.as_deref().unwrap());
    let expected = hex(vector.compressed.as_deref().unwrap());

    assert_eq!(compressed(&packet).unwrap(), expected);
}

#[test]
fn empty_oscore_option_without_payload_selects_rule5() {
    let packet = packet(&[0x90], &[]);
    let compressed = compressed(&packet).unwrap();

    assert_eq!(compressed[0], RULE_LINK_LOCAL_OSCORE);
    let mut restored = vec![0u8; packet.len()];
    let length = decompress(&compressed, &mut restored).unwrap();
    assert_eq!(&restored[..length], packet);
}

#[test]
fn malformed_or_duplicate_oscore_options_never_select_rule5() {
    for tail in [
        &[0x9f][..],
        &[0x9d][..],
        &[0x91, 0x01][..],
        &[0x90, 0x00, 0x90][..],
        &[0x90, 0xff][..],
    ] {
        let encoded = compressed(&packet(tail, &[])).unwrap();
        assert_eq!(encoded[0], RULE_LINK_LOCAL_COAP, "tail {tail:02x?}");
    }
}

#[test]
fn valid_oscore_option_forms_select_rule5() {
    for tail in [
        &[0x90][..],
        &[0x92, 0x09, 0x01][..],
        &[0x92, 0x01, 0x01][..],
        &[0x95, 0x19, 0x01, 0x01, 0xaa, 0xbb][..],
    ] {
        assert_eq!(
            compressed(&packet(tail, &[])).unwrap()[0],
            RULE_LINK_LOCAL_OSCORE,
            "tail {tail:02x?}"
        );
    }
}

#[test]
fn exact_profile_boundary_is_accepted_and_one_over_is_rejected() {
    let mut tail = vec![0u8; MAX_PACKET_SIZE - 23];
    tail[0] = 0x90;
    tail[1] = 0xff;
    let exact_packet = packet(&tail, &[]);
    let exact = compressed(&exact_packet).unwrap();
    assert_eq!(exact.len(), MAX_PACKET_SIZE);
    assert_eq!(exact[0], RULE_LINK_LOCAL_OSCORE);

    tail.push(0);
    assert!(matches!(
        compressed(&packet(&tail, &[])),
        Err(SchcError::InvalidPacket(
            "SCHC packet exceeds profile limit"
        ))
    ));
}

#[test]
fn undersized_output_is_reported_without_partial_success() {
    let packet = packet(&[0x90, 0xff, 0xaa], &[]);
    let mut output = [0xa5; 22];
    assert!(matches!(
        compress(&packet, &mut output),
        Err(SchcError::BufferTooSmall(_))
    ));
}
