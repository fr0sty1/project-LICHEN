// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Current-spec compression coverage for SCHC Rule 6 (global OSCORE).

use lichen_core::constants::{RULE_GLOBAL_COAP, RULE_GLOBAL_OSCORE, RULE_UNCOMPRESSED};
use lichen_schc::{compress, decompress, SchcError};
use serde::Deserialize;

const MAX_PACKET_SIZE: usize = 22_554;
const SRC: [u8; 16] = [
    0x02, 0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63, 0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63, 0x42,
];
const DST: [u8; 16] = [
    0x02, 0xf7, 0x7a, 0x7b, 0xaa, 0x12, 0x26, 0xb5, 0xf5, 0x7a, 0x7b, 0xaa, 0x12, 0x26, 0xb5, 0x0c,
];

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

fn udp_checksum(src: &[u8; 16], dst: &[u8; 16], payload: &[u8]) -> u16 {
    let udp_len = u16::try_from(8 + payload.len()).unwrap();
    let mut sum = checksum_bytes(src) + checksum_bytes(dst);
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

fn packet(options_and_payload: &[u8], src: &[u8; 16], dst: &[u8; 16]) -> Vec<u8> {
    let mut coap = vec![0x40, 1, 0x12, 0x34];
    coap.extend_from_slice(options_and_payload);
    let udp_len = u16::try_from(8 + coap.len()).unwrap();
    let mut result = vec![0u8; 40 + usize::from(udp_len)];
    result[0] = 0x60;
    result[4..6].copy_from_slice(&udp_len.to_be_bytes());
    result[6] = 17;
    result[7] = 64;
    result[8..24].copy_from_slice(src);
    result[24..40].copy_from_slice(dst);
    result[40..42].copy_from_slice(&5683u16.to_be_bytes());
    result[42..44].copy_from_slice(&5683u16.to_be_bytes());
    result[44..46].copy_from_slice(&udp_len.to_be_bytes());
    result[48..].copy_from_slice(&coap);
    result[46..48].copy_from_slice(&udp_checksum(src, dst, &coap).to_be_bytes());
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
        .find(|vector| vector.name == "oscore_global")
        .unwrap();
    let packet = hex(vector.packet.as_deref().unwrap());
    let expected = hex(vector.compressed.as_deref().unwrap());

    assert_eq!(compressed(&packet).unwrap(), expected);
}

#[test]
fn valid_oscore_forms_select_rule6_and_round_trip() {
    for tail in [
        &[0x90][..],
        &[0x92, 0x09, 0x01][..],
        &[0x92, 0x01, 0x01][..],
        &[0x95, 0x19, 0x01, 0x01, 0xaa, 0xbb][..],
    ] {
        let packet = packet(tail, &SRC, &DST);
        let compressed = compressed(&packet).unwrap();
        assert_eq!(compressed[0], RULE_GLOBAL_OSCORE);
        let mut restored = vec![0u8; packet.len()];
        let length = decompress(&compressed, &mut restored).unwrap();
        assert_eq!(&restored[..length], packet);
    }
}

#[test]
fn malformed_or_duplicate_oscore_never_selects_rule6() {
    for tail in [
        &[][..],
        &[0x9f][..],
        &[0x9d][..],
        &[0x91, 0x01][..],
        &[0x90, 0x00][..],
        &[0x90, 0xff][..],
    ] {
        let encoded = compressed(&packet(tail, &SRC, &DST)).unwrap();
        assert_eq!(encoded[0], RULE_GLOBAL_COAP, "tail {tail:02x?}");
    }
}

#[test]
fn rule6_requires_both_current_yggdrasil_prefixes() {
    let non_ygg = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (src, dst) in [(&non_ygg, &DST), (&SRC, &non_ygg)] {
        let encoded = compressed(&packet(&[0x90], src, dst)).unwrap();
        assert_ne!(encoded[0], RULE_GLOBAL_OSCORE);
        assert_eq!(encoded[0], RULE_UNCOMPRESSED);
    }
}

#[test]
fn exact_profile_boundary_is_accepted_and_one_over_is_rejected() {
    let mut tail = vec![0u8; MAX_PACKET_SIZE - 37];
    tail[0] = 0x90;
    tail[1] = 0xff;
    let exact_packet = packet(&tail, &SRC, &DST);
    let exact = compressed(&exact_packet).unwrap();
    assert_eq!(exact.len(), MAX_PACKET_SIZE);
    assert_eq!(exact[0], RULE_GLOBAL_OSCORE);

    tail.push(0);
    assert!(matches!(
        compressed(&packet(&tail, &SRC, &DST)),
        Err(SchcError::InvalidPacket(
            "SCHC packet exceeds profile limit"
        ))
    ));
}

#[test]
fn undersized_output_fails_atomically() {
    let packet = packet(&[0x90, 0xff, 0xaa], &SRC, &DST);
    let mut output = [0xa5; 39];
    assert!(matches!(
        compress(&packet, &mut output),
        Err(SchcError::BufferTooSmall(_))
    ));
    assert_eq!(output, [0xa5; 39]);
}

#[test]
fn invalid_checksum_fails_before_output_mutation() {
    let mut packet = packet(&[0x90], &SRC, &DST);
    packet[47] ^= 1;
    let mut output = [0xa5; 128];
    assert!(matches!(
        compress(&packet, &mut output),
        Err(SchcError::InvalidPacket(_))
    ));
    assert_eq!(output, [0xa5; 128]);
}
