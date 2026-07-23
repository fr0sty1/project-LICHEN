//! Integration test: SCHC fragmentation end-to-end.
//!
//! Tests that large payloads fragment and reassemble correctly through the
//! sender/receiver API.

#[cfg(feature = "std")]
use lichen_schc::fragment::FragmentReceiver;
use lichen_schc::fragment::{compute_mic, Ack, Fragment, FragmentSender, DEFAULT_WINDOW_SIZE};

#[test]
fn sender_receiver_literal_recovery() {
    let mut packet = vec![0; 375];
    packet[187..374].fill(0x11);
    packet[374] = 0xa5;
    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    sender.start().unwrap();
    assert_eq!(sender.attempts(), 1);

    let fragments: Vec<_> = sender.iter().collect();
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
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
    let payload: Vec<u8> = (0u8..20).collect();
    let tile_size = 5;
    let sender = FragmentSender::new(&payload, 20, tile_size, 7).unwrap(); // explicit for test; profile default is now 32

    assert_eq!(sender.fragment_count(), 4); // 20 bytes / 5 bytes per tile
    assert_eq!(sender.window_count(), 1);

    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 4);

    // First fragments have descending FCN (for window_size=7)
    assert_eq!(frags[0].fcn, 6); // 7-1-0 = 6
    assert_eq!(frags[1].fcn, 5);
    assert_eq!(frags[2].fcn, 4);
    assert!(frags[3].is_all_1()); // Last fragment

    // Verify payloads
    assert_eq!(frags[0].payload, &[0, 1, 2, 3, 4]);
    assert_eq!(frags[1].payload, &[5, 6, 7, 8, 9]);
    assert_eq!(frags[2].payload, &[10, 11, 12, 13, 14]);
    assert_eq!(frags[3].payload, &[15, 16, 17, 18, 19]);
}

#[test]
fn duplicate_regular_must_match() {
    let packet = [0xa5; TILE_SIZE + 1];
    let sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    let regular = sender.get_fragment(0).unwrap();
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
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
    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
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

    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
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
    let mut tile = [0; TILE_SIZE];
    assert!(Fragment::from_bytes(&[0x78, 0x7c, 0], &mut tile).is_err());
    let regular_nonzero_padding = [0xff; TILE_SIZE + 2];
    assert!(Fragment::from_bytes(&regular_nonzero_padding, &mut tile).is_err());
    assert!(Ack::from_bytes(&[0x78, 0x40, 0]).is_err());
    assert!(Ack::from_bytes_for(
        &[0x78, 0x38, 0, 0, 0, 0, 0, 0, 0],
        Some(0x6000_0000_0000_0001)
    )
    .is_err());

    let invalid = Fragment {
        rule_id: 0x78,
        window: 0,
        fcn: 64,
        payload: &tile,
        mic: [0; 4],
    };
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
    assert!(
        FragmentReceiver::new(&mut storage)
            .unwrap()
            .receive(&invalid)
            .aborted
    );
}

#[test]
fn sender_output_retries_after_small_buffer() {
    let packet = [0xa5; TILE_SIZE + 1];
    let mut wire = [0u8; TILE_SIZE + 2];

    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    sender.start().unwrap();
    let mut output = sender.handle_ack(Ack::new(0x78, 0, 1, false));
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(length, TILE_SIZE + 2);
    assert_eq!(&wire[..2], &[0x78, 0x7d]);
    assert!(sender.write_next(&mut output, &mut [0u8; 1]).is_err());
    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x00]);

    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
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
    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
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
fn ack_request_after_completion_starts_empty_context() {
    let packet = [0xa5];
    let sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
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
    let mut sender = FragmentSender::new(&packet, 0x78, packet.len()).unwrap();
    sender.start().unwrap();
    let mut output = sender.handle_ack(Ack::new(0x78, 0, u64::MAX << 1, false));
    let mut wire = [0u8; TILE_SIZE + 2];

    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(length, TILE_SIZE + 2);
    assert_eq!(&wire[..2], &[0x78, 0x00]);
    let mut tile = [0u8; TILE_SIZE];
    let fragment = Fragment::from_bytes(&wire[..length], &mut tile).unwrap();
    assert_eq!((fragment.window, fragment.fcn), (0, 0));

    let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    assert_eq!(&wire[..length], &[0x78, 0x80]);
    assert_eq!(sender.write_next(&mut output, &mut wire).unwrap(), None);
}

#[test]
fn released_receiver_accepts_fresh_fragments() {
    let first = [0xa5];
    let second = [0x5a];
    let first_sender = FragmentSender::new(&first, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    let second_sender = FragmentSender::new(&second, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
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
    let partial_sender = FragmentSender::new(&partial, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
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
