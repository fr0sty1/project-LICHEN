//! Integration test: SCHC fragmentation end-to-end.
//!
//! Tests that large payloads fragment and reassemble correctly through the
//! sender/receiver API.

use lichen_schc::fragment::{
    receiver_abort, Ack, Fragment, FragmentReceiver, FragmentSender, ReceiverResponse,
    SenderOutput, SenderStatus, DEFAULT_RECEIVER_LIMIT, MAX_ACK_REQUESTS, MIC_LENGTH,
    TILE_SIZE,
};

#[test]
fn sender_receiver_literal_recovery() {
    // Single-fragment packet: immediate success
    let packet = [0xa5];
    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    sender.start().unwrap();
    assert_eq!(sender.attempts(), 1);

    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    let fragment = sender.get_fragment(0).unwrap();
    let result = receiver.receive(&fragment);
    assert!(fragment.is_all_1());
    assert_eq!(result.packet_len, Some(1));
    assert_eq!(receiver.packet(), Some(packet.as_slice()));
    let ReceiverResponse::Ack(ack) = result.response.unwrap() else {
        panic!("expected ACK")
    };
    assert!(ack.complete);
    assert_eq!(sender.handle_ack(ack), SenderOutput::Success);
    assert_eq!(sender.status(), SenderStatus::Succeeded);
}

#[test]
fn multi_fragment_single_window() {
    let payload: Vec<u8> = (0u8..32).collect();
    let sender = FragmentSender::new(&payload, 20, DEFAULT_RECEIVER_LIMIT).unwrap();

    assert_eq!(sender.fragment_count(), 4); // 32 bytes / 8 bytes per tile
    assert_eq!(sender.window_count(), 1);

    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 4);

    // First fragments have descending FCN; last is All-1
    assert_eq!(frags[0].fcn, 62);
    assert_eq!(frags[1].fcn, 61);
    assert_eq!(frags[2].fcn, 60);
    assert!(frags[3].is_all_1()); // Last fragment = All-1

    // Verify payloads
    assert_eq!(frags[0].payload, &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(frags[1].payload, &[8, 9, 10, 11, 12, 13, 14, 15]);
    assert_eq!(frags[2].payload, &[16, 17, 18, 19, 20, 21, 22, 23]);
    assert_eq!(frags[3].payload, &[24, 25, 26, 27, 28, 29, 30, 31]);
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
    let tile = [0; TILE_SIZE];
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    // [0x78, 0x7c, 0] is a byte-valid regular fragment (rule 0x78, fcn=62, 1-byte payload),
    // but the receiver should reject it because payload is not TILE_SIZE bytes.
    let fragment = Fragment::from_bytes(&[0x78, 0x7c, 0]).unwrap();
    assert!(receiver.receive(&fragment).aborted);
    let regular_nonzero_padding = [0xff; TILE_SIZE + 2];
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
    let mut wire = [0x00; 11];
    let length = result.response.unwrap().write_to(&mut wire).unwrap();
    assert_eq!(length, 11);
    assert_eq!(&wire[..11], &[0x78, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn missing_all0_still_requests_final_window_ack() {
    let packet = vec![0u8; TILE_SIZE * 63];
    let mut sender = FragmentSender::new(&packet, 0x78, DEFAULT_RECEIVER_LIMIT).unwrap();
    sender.start().unwrap();
    // ACK indicating all regular fragments received, All-1 (bit 0) missing
    let acked = (u64::MAX >> 1) & !1;
    let mut output = sender.handle_ack(Ack::new(0x78, 0, acked, false));
    let mut wire = [0u8; TILE_SIZE + MIC_LENGTH + 2];
    let n = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
    let fragment = Fragment::from_bytes(&wire[..n]).unwrap();
    assert!(fragment.is_all_1());
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
