//! Integration test: SCHC fragmentation end-to-end.
//!
//! Tests that large payloads fragment and reassemble correctly through the
//! sender/receiver API.

mod support;

use lichen_schc::fragment::{
    receiver_abort, sender_abort, Ack, Fragment, FragmentError, FragmentReceiver, ReceiverResponse,
    SenderOutput, SenderStatus, BITMAP_MASK, MAX_ACK_REQUESTS, MAX_PACKET_SIZE, TILE_SIZE,
    WINDOW_SIZE,
};

#[test]
fn sender_receiver_literal_recovery() {
    let mut packet = vec![0; 375];
    packet[187..374].fill(0x11);
    packet[374] = 0xa5;
    let mut sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    sender.start().unwrap();
    assert_eq!(sender.attempts(), 1);

    let fragments: Vec<_> = sender.iter().collect();
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert_eq!(receiver.receive(&fragments[0]).response, None);
    let failure = receiver.receive(&fragments[2]);
    assert_eq!(failure.mic_ok, Some(false));
    let ReceiverResponse::Ack(ack) = failure.response.unwrap() else {
        panic!("expected ACK")
    };
    let mut wire = [0u8; 193];
    let length = ack.write_to(&mut wire).unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x20, 0, 0, 0, 0, 0, 0, 0]);

    let mut output = sender.handle_ack(ack);
    sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..2], &[0x78, 0x7a]);
    let recovered = receiver.receive(&fragments[1]);
    assert_eq!(recovered.response, None);
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x00]);
    assert_eq!(sender.write_next(&mut output, &mut wire).unwrap(), None);

    let success = receiver.receive_bytes(&wire[..length]).unwrap();
    assert_eq!(success.packet_len, Some(packet.len()));
    assert_eq!(receiver.packet(), Some(packet.as_slice()));
    let ReceiverResponse::Ack(ack) = success.response.unwrap() else {
        panic!("expected ACK")
    };
    assert_eq!(sender.handle_ack(ack), SenderOutput::Success);
    assert_eq!(sender.status(), SenderStatus::Succeeded);
}

#[test]
fn multi_fragment_single_window() {
    let payload: Vec<u8> = (0u8..=255).cycle().take(TILE_SIZE * 4).collect();
    let sender = support::fragment_sender(&payload, 0x78, payload.len()).unwrap();

    assert_eq!(sender.fragment_count(), 4);
    assert_eq!(sender.window_count(), 1);
    assert_eq!(sender.final_window(), 0);

    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 4);

    assert_eq!(frags[0].fcn, 62);
    assert_eq!(frags[1].fcn, 61);
    assert_eq!(frags[2].fcn, 60);
    assert!(frags[3].is_all_1());

    assert_eq!(frags[0].payload.len(), TILE_SIZE);
    assert_eq!(frags[1].payload.len(), TILE_SIZE);
    assert_eq!(frags[2].payload.len(), TILE_SIZE);
    assert_eq!(frags[3].payload.len(), TILE_SIZE);
}

#[test]
fn duplicate_regular_must_match() {
    let packet = [0xa5; TILE_SIZE + 1];
    let sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    let regular = sender.get_fragment(0).unwrap();
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert!(!receiver.receive(&regular).aborted);
    assert!(!receiver.receive(&regular).aborted);
    let changed = [0x5a; TILE_SIZE];
    let conflict = Fragment {
        payload: &changed,
        ..regular
    };
    assert!(receiver.receive(&conflict).aborted);
}

#[test]
fn retry_limits_emit_aborts() {
    let packet = [0xa5; TILE_SIZE + 1];
    let mut sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    sender.start().unwrap();
    for _ in 1..MAX_ACK_REQUESTS {
        let mut output = sender.timeout().unwrap();
        let mut wire = [0u8; 3];
        sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    }
    let mut output = sender.timeout().unwrap();
    let mut wire = [0u8; 3];
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0xfe]);
    assert_eq!(sender.status(), SenderStatus::Aborted);

    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    for _ in 0..MAX_ACK_REQUESTS {
        assert!(!receiver.receive_bytes(&[0x78, 0x00]).unwrap().aborted);
    }
    let result = receiver.receive_bytes(&[0x78, 0x00]).unwrap();
    assert!(result.aborted);
    let length = result.response.unwrap().write_to(&mut wire).unwrap();
    assert_eq!(&wire[..length], &[0x78, 0xff, 0xff]);
}

#[test]
fn malformed_codec_inputs_are_rejected() {
    assert!(Fragment::from_bytes(&[0x78], &mut [0u8; 1]).is_err());
    assert!(Fragment::from_bytes(&[0x78, 0x7c, 0], &mut [0u8; 0]).is_err());
    assert!(Ack::from_bytes(&[0x78, 0x40, 0]).is_err());
    assert!(Ack::from_bytes_for(
        &[0x78, 0x38, 0, 0, 0, 0, 0, 0, 0],
        Some(0x6000_0000_0000_0001)
    )
    .is_err());

    let tile = [0u8; TILE_SIZE];
    let invalid = Fragment {
        rule_id: 0x78,
        window: 0,
        fcn: 64,
        payload: &tile,
        mic: [0; 4],
    };
    let mut storage = [0u8; MAX_PACKET_SIZE];
    assert!(
        FragmentReceiver::new(&mut storage)
            .unwrap()
            .receive(&invalid)
            .aborted
    );
}

#[test]
fn ack_bitmap_compression_round_trips_every_trailing_one_boundary() {
    for window in 0..=1 {
        for trailing in 0..=WINDOW_SIZE {
            let bitmap = if trailing == WINDOW_SIZE {
                BITMAP_MASK
            } else {
                BITMAP_MASK & !(1u64 << trailing)
            };
            let ack = Ack::new(0x78, window, bitmap, false);
            let mut wire = [0u8; 10];
            let length = ack.write_to(&mut wire).unwrap();
            let retained_bits = WINDOW_SIZE - trailing;
            let expected_length = 1 + (2 + retained_bits).div_ceil(8);
            assert_eq!(length, expected_length);
            assert_eq!(wire[1] >> 7, window);
            assert_eq!(Ack::from_bytes(&wire[..length]), Ok(ack));
        }
    }

    for window in 0..=1 {
        let all_zero = Ack::new(0x78, window, 0, false);
        let mut wire = [0u8; 10];
        let length = all_zero.write_to(&mut wire).unwrap();
        assert_eq!(length, 10);
        assert_eq!(wire[1], window << 7);
        assert!(wire[2..length].iter().all(|byte| *byte == 0));
        assert_eq!(Ack::from_bytes(&wire[..length]), Ok(all_zero));

        let all_one = Ack::new(0x78, window, BITMAP_MASK, false);
        let length = all_one.write_to(&mut wire).unwrap();
        assert_eq!(&wire[..length], &[0x78, (window << 7) | 0x3f]);
        assert_eq!(Ack::from_bytes(&wire[..length]), Ok(all_one));

        let complete = Ack::new(0x78, window, 0, true);
        let length = complete.write_to(&mut wire).unwrap();
        assert_eq!(&wire[..length], &[0x78, (window << 7) | 0x40]);
        assert_eq!(Ack::from_bytes(&wire[..length]), Ok(complete));
    }
}

#[test]
fn ack_parser_rejects_invalid_sizes_and_sender_matches_rule_and_window() {
    assert!(matches!(
        Ack::from_bytes(&[0x78]),
        Err(FragmentError::TooShort(_))
    ));
    assert_eq!(
        Ack::from_bytes(&[0x78, 0x40, 0]),
        Err(FragmentError::MalformedAck)
    );
    assert_eq!(
        Ack::from_bytes(&[0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(FragmentError::MalformedAck)
    );
    assert_eq!(
        Ack::from_bytes(&[0x78, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(FragmentError::NonCanonicalAck)
    );
    assert_eq!(
        Ack::from_bytes(&[0x78, 0x35, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,]),
        Err(FragmentError::NonCanonicalAck)
    );

    let packet = vec![0u8; TILE_SIZE * 63 + 1];
    let mut sender = support::fragment_sender(&packet, 0x78, packet.len()).unwrap();
    sender.start().unwrap();
    assert_eq!(
        sender.handle_ack(Ack::new(0x79, 1, 0, true)),
        SenderOutput::None
    );
    assert_eq!(
        sender.handle_ack(Ack::new(0x78, 0, 0, true)),
        SenderOutput::None
    );
    assert_eq!(sender.status(), SenderStatus::Active);
    assert_eq!(
        sender.handle_ack(Ack::new(0x78, 1, 0, true)),
        SenderOutput::Success
    );
}

#[test]
fn sender_output_retries_after_small_buffer() {
    let packet = [0xa5; TILE_SIZE + 1];
    let mut wire = [0u8; TILE_SIZE + 2];

    let mut sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    sender.start().unwrap();
    let mut output = sender.handle_ack(Ack::new(0x78, 0, 1, false));
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(length, TILE_SIZE + 2);
    assert_eq!(&wire[..2], &[0x78, 0x7d]);
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x00]);

    let mut sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    sender.start().unwrap();
    let mut output = sender.timeout().unwrap();
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x00]);

    for _ in 2..MAX_ACK_REQUESTS {
        sender.timeout().unwrap();
    }
    let mut output = sender.timeout().unwrap();
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0xfe]);
}

#[test]
fn terminal_sender_invalidates_queued_output() {
    let packet = [0xa5; TILE_SIZE + 1];
    let mut sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    sender.start().unwrap();
    let mut output = sender.handle_ack(Ack::new(0x78, 0, 1, false));
    let mut abort = [0u8; 3];
    let length = receiver_abort(0x78).write_to(&mut abort).unwrap();
    assert_eq!(
        sender.handle_ack_bytes(&abort[..length]).unwrap(),
        SenderOutput::None
    );
    assert_eq!(sender.status(), SenderStatus::Aborted);
    assert_eq!(
        sender.write_next(&mut output, &mut [0u8; 193]).unwrap(),
        None
    );
}

#[test]
fn receiver_routes_abort_by_role_and_preserves_reassembly() {
    let packet = [0xa5; TILE_SIZE + 1];
    let sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    let fragments: Vec<_> = sender.iter().collect();
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert_eq!(receiver.receive(&fragments[0]).response, None);

    let mut wire = [0u8; 10];
    let length = receiver_abort(0x78).write_to(&mut wire).unwrap();
    assert_eq!(
        receiver.receive_bytes(&wire[..length]),
        Err(FragmentError::MalformedAck)
    );
    let length = Ack::new(0x78, 0, 0, true).write_to(&mut wire).unwrap();
    assert_eq!(
        receiver.receive_bytes(&wire[..length]),
        Err(FragmentError::MalformedAck)
    );
    assert_eq!(
        receiver.receive(&fragments[1]).packet_len,
        Some(packet.len())
    );
    assert_eq!(receiver.packet(), Some(packet.as_slice()));

    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert_eq!(receiver.receive(&fragments[0]).response, None);
    let length = sender_abort(0x78).write_to(&mut wire).unwrap();
    let result = receiver.receive_bytes(&wire[..length]).unwrap();
    assert!(result.aborted);
    assert_eq!(result.response, None);
    assert!(receiver.is_done());
    assert_eq!(receiver.packet(), None);
}

#[test]
fn malformed_abort_variants_fail_closed_and_release_state() {
    for wire in [
        &[0x78, 0xfe, 0x00][..],
        &[0x78, 0xff, 0x00][..],
        &[0x78, 0xff, 0xff, 0x00][..],
    ] {
        let packet = [0xa5; TILE_SIZE + 1];
        let sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
        let mut storage = [0u8; MAX_PACKET_SIZE];
        let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
        assert_eq!(
            receiver.receive(&sender.get_fragment(0).unwrap()).response,
            None
        );

        let result = receiver.receive_bytes(wire).unwrap();
        assert!(result.aborted);
        assert_eq!(
            result.response,
            Some(ReceiverResponse::ReceiverAbort { rule_id: 0x78 })
        );
        assert!(receiver.is_done());
        assert_eq!(receiver.packet(), None);
    }
}

#[test]
fn ack_request_after_completion_starts_empty_context() {
    let packet = [0xa5];
    let sender = support::fragment_sender(&packet, 0x78, MAX_PACKET_SIZE).unwrap();
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert_eq!(
        receiver
            .receive(&sender.get_fragment(0).unwrap())
            .packet_len,
        Some(1)
    );
    assert!(receiver.is_done());

    let result = receiver.receive_bytes(&[0x78, 0x00]).unwrap();
    assert_eq!(result.packet_len, None);
    assert_eq!(receiver.packet(), None);
    assert!(!receiver.is_done());
    let mut wire = [0xff; 10];
    let length = result.response.unwrap().write_to(&mut wire).unwrap();
    assert_eq!(length, 10);
    assert_eq!(&wire[..length], &[0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn missing_all0_still_requests_final_window_ack() {
    let packet = vec![0u8; TILE_SIZE * 63 + 1];
    let mut sender = support::fragment_sender(&packet, 0x78, packet.len()).unwrap();
    sender.start().unwrap();
    let mut output = sender.handle_ack(Ack::new(0x78, 0, u64::MAX << 1, false));
    let mut wire = [0u8; TILE_SIZE + 2];

    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(length, TILE_SIZE + 2);
    assert_eq!(&wire[..2], &[0x78, 0x00]);
    let mut buf = [0u8; TILE_SIZE];
    let fragment = Fragment::from_bytes(&wire[..length], &mut buf).unwrap();
    assert_eq!((fragment.window, fragment.fcn), (0, 0));
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x80]);
    assert_eq!(sender.write_next(&mut output, &mut wire).unwrap(), None);
}

#[test]
fn released_receiver_accepts_fresh_fragments() {
    let first = [0xa5];
    let second = [0x5a];
    let first_sender = support::fragment_sender(&first, 0x78, MAX_PACKET_SIZE).unwrap();
    let second_sender = support::fragment_sender(&second, 0x78, MAX_PACKET_SIZE).unwrap();
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();

    assert_eq!(
        receiver
            .receive(&first_sender.get_fragment(0).unwrap())
            .packet_len,
        Some(1)
    );
    assert_eq!(receiver.packet(), Some(first.as_slice()));
    assert_eq!(
        receiver
            .receive(&second_sender.get_fragment(0).unwrap())
            .packet_len,
        Some(1)
    );
    assert_eq!(receiver.packet(), Some(second.as_slice()));

    assert!(receiver.expire().is_none());
    let abort = [0x78, 0xfe];
    assert!(receiver.receive_bytes(&abort).unwrap().aborted);
    assert_eq!(
        receiver
            .receive(&first_sender.get_fragment(0).unwrap())
            .packet_len,
        Some(1)
    );

    let partial = [0u8; TILE_SIZE + 1];
    let partial_sender = support::fragment_sender(&partial, 0x78, MAX_PACKET_SIZE).unwrap();
    assert_eq!(
        receiver
            .receive(&partial_sender.get_fragment(0).unwrap())
            .response,
        None
    );
    assert!(receiver.expire().is_some());
    assert_eq!(
        receiver
            .receive(&second_sender.get_fragment(0).unwrap())
            .packet_len,
        Some(1)
    );
}
