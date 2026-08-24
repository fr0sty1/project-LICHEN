//! Vector tests for TDMA beacon header and slot selection.

use lichen_core::lichen_hash_32;
use lichen_core::tdma_beacon::{flags, TdmaBeaconHeader, HEADER_SIZE, MIN_BEACON_SIZE};

/// Compute slot matching Python: (hash_32(eui64) + sfn) % num_slots
fn slot_for(eui: &[u8; 8], sfn: u32, num_slots: u16) -> u16 {
    let h = lichen_hash_32(eui);
    ((h.wrapping_add(sfn)) % num_slots as u32) as u16
}

#[test]
fn test_slot_sfn_zero() {
    let eui = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let hash = lichen_hash_32(&eui);
    assert_eq!(hash, 0xc0e31bbd, "hash mismatch");
    let slot = slot_for(&eui, 0, 16);
    assert_eq!(slot, 13, "slot at sfn=0 mismatch");
}

#[test]
fn test_slot_sfn_one() {
    let eui = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let slot = slot_for(&eui, 1, 16);
    // (0xc0e31bbd + 1) % 16 = 14
    assert_eq!(slot, 14, "slot at sfn=1 should be 14 (matching Python)");
}

#[test]
fn test_slot_sfn_max_wrap() {
    let eui = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let slot = slot_for(&eui, 0xFFFFFFFF, 16);
    // (0xc0e31bbd + 0xFFFFFFFF) wrapping = 0xc0e31bbc, % 16 = 12
    assert_eq!(slot, 12, "slot at sfn=max should wrap correctly");
}

#[test]
fn test_beacon_header_roundtrip_canonical() {
    // Canonical test beacon from spec
    let hdr = TdmaBeaconHeader {
        epoch: 1000,
        num_slots: 16,
        sfn: 42,
        timestamp: 1234567890,
        flags: flags::SCHEDULED | flags::GNSS_PPS,
        rx_chains: 2,
        setup_window: 100,
        occupied_time: 1800,
        guard: 100,
        channel_mask: 0x000000FF, // CH0-7 enabled
    };

    let mut buf = [0u8; HEADER_SIZE];
    hdr.serialize(&mut buf).unwrap();

    // Verify big-endian encoding at specific offsets
    assert_eq!(&buf[0..4], &1000u32.to_be_bytes(), "epoch at offset 0");
    assert_eq!(buf[4], 16, "num_slots at offset 4");
    assert_eq!(&buf[5..9], &42u32.to_be_bytes(), "sfn at offset 5");
    assert_eq!(
        &buf[9..13],
        &1234567890u32.to_be_bytes(),
        "timestamp at offset 9"
    );
    assert_eq!(
        buf[13],
        flags::SCHEDULED | flags::GNSS_PPS,
        "flags at offset 13"
    );

    let parsed = TdmaBeaconHeader::parse(&buf).unwrap();
    assert_eq!(hdr, parsed);
}

#[test]
fn test_beacon_min_size() {
    // Minimum beacon is header + signature
    assert_eq!(MIN_BEACON_SIZE, 24 + 48);
}
