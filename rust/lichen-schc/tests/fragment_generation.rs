//! Fixed-profile SCHC fragment generation boundaries and deterministic codec checks.

#![cfg(all(feature = "std", feature = "raw-fragment-codec"))]

mod support;

use lichen_schc::fragment::{
    compute_mic, Fragment, FragmentError, FragmentReceiver, ALL_1_FCN, FRAGMENT_M, FRAGMENT_N,
    FRAGMENT_T, MAX_FRAGMENT_WIRE_SIZE, MAX_PACKET_SIZE, MIC_LENGTH, TILE_SIZE, WINDOW_SIZE,
};

fn patterned_packet(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
        .collect()
}

#[test]
fn generation_uses_fixed_profile_fields_and_has_no_dtag() {
    assert_eq!((FRAGMENT_M, FRAGMENT_N, FRAGMENT_T), (1, 6, 0));
    assert_eq!(TILE_SIZE, 179);
    assert_eq!(WINDOW_SIZE, 63);
    assert_eq!(MAX_PACKET_SIZE, 2 * WINDOW_SIZE * TILE_SIZE);
    assert_eq!(MAX_FRAGMENT_WIRE_SIZE, TILE_SIZE + MIC_LENGTH + 2);

    for rule_id in [0x78, 0x79] {
        let packet = patterned_packet(TILE_SIZE + 1);
        let sender = support::fragment_sender(&packet, rule_id, packet.len()).unwrap();
        let first = sender.get_fragment(0).unwrap();
        let final_fragment = sender.get_fragment(1).unwrap();
        assert_eq!((first.rule_id, first.window, first.fcn), (rule_id, 0, 62));
        assert_eq!(
            (
                final_fragment.rule_id,
                final_fragment.window,
                final_fragment.fcn,
            ),
            (rule_id, 0, ALL_1_FCN)
        );

        let mut wire = [0u8; MAX_FRAGMENT_WIRE_SIZE];
        let length = first.write_to(&mut wire).unwrap();
        // T=0 means the bit immediately after the eight-bit Rule ID is W;
        // there is no caller-selected or encoded DTag field.
        assert_eq!(&wire[..2], &[rule_id, 0x7c]);
        assert_eq!(length, TILE_SIZE + 2);
    }
}

#[test]
fn every_tile_and_window_boundary_round_trips_deterministically() {
    let lengths = [
        1,
        TILE_SIZE,
        TILE_SIZE + 1,
        TILE_SIZE * (WINDOW_SIZE - 1) + 1,
        TILE_SIZE * WINDOW_SIZE,
        TILE_SIZE * WINDOW_SIZE + 1,
        MAX_PACKET_SIZE,
    ];

    for length in lengths {
        let packet = patterned_packet(length);
        let sender = support::fragment_sender(&packet, 0x78, length).unwrap();
        let expected_count = length.div_ceil(TILE_SIZE);
        assert_eq!(sender.fragment_count(), expected_count);
        assert_eq!(
            sender.final_window() as usize,
            (expected_count - 1) / WINDOW_SIZE
        );

        let mut reassembly = vec![0u8; length];
        let mut receiver = FragmentReceiver::new(&mut reassembly).unwrap();
        let mut completed = None;

        for index in 0..expected_count {
            let fragment = sender.get_fragment(index).unwrap();
            let final_fragment = index + 1 == expected_count;
            assert_eq!(fragment.rule_id, 0x78);
            assert_eq!(usize::from(fragment.window), index / WINDOW_SIZE);
            assert_eq!(
                fragment.fcn,
                if final_fragment {
                    ALL_1_FCN
                } else {
                    62 - (index % WINDOW_SIZE) as u8
                }
            );
            assert_eq!(
                fragment.payload.len(),
                if final_fragment {
                    length - index * TILE_SIZE
                } else {
                    TILE_SIZE
                }
            );
            assert_eq!(
                fragment.mic,
                if final_fragment {
                    compute_mic(&packet)
                } else {
                    [0; MIC_LENGTH]
                }
            );

            let mut first_wire = [0u8; MAX_FRAGMENT_WIRE_SIZE];
            let first_len = fragment.write_to(&mut first_wire).unwrap();
            let mut second_wire = [0u8; MAX_FRAGMENT_WIRE_SIZE];
            let second_len = fragment.write_to(&mut second_wire).unwrap();
            assert_eq!(first_len, second_len);
            assert_eq!(first_wire, second_wire);
            assert!(first_len <= MAX_FRAGMENT_WIRE_SIZE);

            let mut tile = [0u8; TILE_SIZE];
            let decoded = Fragment::from_bytes(&first_wire[..first_len], &mut tile).unwrap();
            assert_eq!(decoded, fragment);
            completed = Some(receiver.receive(&decoded));
        }

        assert_eq!(completed.unwrap().packet_len, Some(length));
        assert_eq!(receiver.packet(), Some(packet.as_slice()));
        assert!(sender.get_fragment(expected_count).is_none());
    }
}

#[test]
fn all_zero_and_all_one_are_assigned_only_at_profile_boundaries() {
    let packet = patterned_packet(TILE_SIZE * WINDOW_SIZE + 1);
    let sender = support::fragment_sender(&packet, 0x79, packet.len()).unwrap();
    assert_eq!(sender.fragment_count(), WINDOW_SIZE + 1);

    let all_zero = sender.get_fragment(WINDOW_SIZE - 1).unwrap();
    assert_eq!((all_zero.window, all_zero.fcn), (0, 0));
    assert_eq!(all_zero.payload.len(), TILE_SIZE);
    assert_eq!(all_zero.mic, [0; MIC_LENGTH]);

    let all_one = sender.get_fragment(WINDOW_SIZE).unwrap();
    assert_eq!((all_one.window, all_one.fcn), (1, ALL_1_FCN));
    assert_eq!(all_one.payload, &[packet[packet.len() - 1]]);
    assert_eq!(all_one.mic, compute_mic(&packet));
}

#[test]
fn generation_and_codec_enforce_packet_receiver_and_mtu_limits() {
    assert!(matches!(
        support::fragment_sender(&[], 0x78, MAX_PACKET_SIZE),
        Err(FragmentError::EmptyPacket)
    ));
    assert!(matches!(
        support::fragment_sender(&[0], 0x78, 0),
        Err(FragmentError::InvalidReceiverLimit)
    ));
    assert!(matches!(
        support::fragment_sender(&[0], 0x78, MAX_PACKET_SIZE + 1),
        Err(FragmentError::InvalidReceiverLimit)
    ));
    assert!(matches!(
        support::fragment_sender(&[0, 1], 0x78, 1),
        Err(FragmentError::PacketTooLarge)
    ));
    let oversized = vec![0u8; MAX_PACKET_SIZE + 1];
    assert!(matches!(
        support::fragment_sender(&oversized, 0x78, MAX_PACKET_SIZE),
        Err(FragmentError::PacketTooLarge)
    ));

    let maximum = patterned_packet(MAX_PACKET_SIZE);
    let sender = support::fragment_sender(&maximum, 0x78, MAX_PACKET_SIZE).unwrap();
    let final_fragment = sender.get_fragment(sender.fragment_count() - 1).unwrap();
    let mut exact = [0u8; MAX_FRAGMENT_WIRE_SIZE];
    assert_eq!(final_fragment.write_to(&mut exact).unwrap(), exact.len());
    assert!(matches!(
        final_fragment.write_to(&mut exact[..MAX_FRAGMENT_WIRE_SIZE - 1]),
        Err(FragmentError::BufferTooSmall(_))
    ));

    let mut tile = [0u8; TILE_SIZE];
    assert!(matches!(
        Fragment::from_bytes(&[0x78, 0x7e], &mut tile),
        Err(FragmentError::InvalidTileLength)
    ));
    let oversized_wire = [0u8; MAX_FRAGMENT_WIRE_SIZE + 1];
    assert!(matches!(
        Fragment::from_bytes(&oversized_wire, &mut tile),
        Err(FragmentError::InvalidTileLength)
    ));
}
