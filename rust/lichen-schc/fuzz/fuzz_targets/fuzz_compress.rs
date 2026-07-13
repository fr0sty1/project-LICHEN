#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured input for compression fuzzing
#[derive(Arbitrary, Debug)]
struct CompressInput {
    // IPv6-like header fields
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    // UDP-like fields
    src_port: u16,
    dst_port: u16,
    // Payload
    payload: Vec<u8>,
}

fuzz_target!(|input: CompressInput| {
    // Build a packet-like structure and try to compress it
    // This tests the compressor with valid-ish structured input

    if input.payload.len() > 1200 {
        return;  // Skip unreasonably large payloads
    }

    // Build a fake IPv6+UDP packet
    let mut packet = Vec::with_capacity(48 + input.payload.len());

    // IPv6 header (40 bytes)
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);  // Version, traffic class, flow label
    let payload_len = (8 + input.payload.len()) as u16;  // UDP header + payload
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.push(17);  // Next header: UDP
    packet.push(64);  // Hop limit
    packet.extend_from_slice(&input.src_addr);
    packet.extend_from_slice(&input.dst_addr);

    // UDP header (8 bytes)
    packet.extend_from_slice(&input.src_port.to_be_bytes());
    packet.extend_from_slice(&input.dst_port.to_be_bytes());
    let udp_len = (8 + input.payload.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);  // Checksum (0 for fuzzing)

    // Payload
    packet.extend_from_slice(&input.payload);

    // Try to parse and match rules
    if let Ok(parsed) = lichen_schc::CoapUdpLinkLocalProfile::parse(&packet) {
        for rule_id in [0u8, 1, 2, 3, 4, 255] {
            let _ = lichen_schc::rule_matches(&parsed, rule_id);
        }
    }
});
