#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lichen_schc::PacketProfile;

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
        return; // Skip unreasonably large payloads
    }

    // Build a fake IPv6+UDP packet
    let mut packet = Vec::with_capacity(48 + input.payload.len());

    // IPv6 header (40 bytes)
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, traffic class, flow label
    let payload_len = (8 + input.payload.len()) as u16; // UDP header + payload
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.push(17); // Next header: UDP
    packet.push(64); // Hop limit
    packet.extend_from_slice(&input.src_addr);
    packet.extend_from_slice(&input.dst_addr);

    // UDP header (8 bytes)
    packet.extend_from_slice(&input.src_port.to_be_bytes());
    packet.extend_from_slice(&input.dst_port.to_be_bytes());
    let udp_len = (8 + input.payload.len()) as u16;
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (0 for fuzzing)

    // Payload
    packet.extend_from_slice(&input.payload);

    // Exercise the production compressor and strict inverse. Invalid UDP
    // checksums and non-CoAP payloads deliberately select Rule 255.
    let mut compressed = vec![0u8; packet.len() + 1];
    if let Ok(compressed_len) = lichen_schc::compress(&packet, &mut compressed) {
        let mut decompressed = vec![0u8; packet.len()];
        if let Ok(decompressed_len) =
            lichen_schc::decompress(&compressed[..compressed_len], &mut decompressed)
        {
            assert_eq!(&decompressed[..decompressed_len], packet.as_slice());
        }
    }

    // Also exercise the independent descriptor parser/matcher.
    let profile = lichen_schc::CoapUdpLinkLocalProfile;
    if let Ok(parsed) = profile.parse(&packet) {
        let _ = lichen_schc::rule_matches(profile.rule(), parsed.as_slice());
    }
});
