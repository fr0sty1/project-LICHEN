//! Integration test: SCHC fragmentation end-to-end.
//!
//! Tests that large payloads fragment and reassemble correctly through the
//! sender/receiver API.

#[cfg(feature = "std")]
use lichen_schc::fragment::FragmentReceiver;
use lichen_schc::fragment::{compute_mic, Ack, Fragment, FragmentSender, DEFAULT_WINDOW_SIZE};

/// Test small payload fits in single fragment.
#[test]
fn single_fragment_payload() {
    let payload = b"hello world";
    let sender = FragmentSender::new(payload, 20, 50, DEFAULT_WINDOW_SIZE).unwrap();

    assert_eq!(sender.fragment_count(), 1);
    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 1);
    assert!(frags[0].is_all_1());
    assert_eq!(frags[0].payload, payload.as_slice());
    assert_eq!(frags[0].mic, compute_mic(payload));
}

/// Test multi-fragment payload within single window.
#[test]
fn multi_fragment_single_window() {
    let payload: Vec<u8> = (0u8..20).collect();
    let tile_size = 5;
    let window_size = 7;
    let sender = FragmentSender::new(&payload, 20, tile_size, window_size).unwrap();

    assert_eq!(sender.fragment_count(), 4); // 20 bytes / 5 bytes per tile
    assert_eq!(sender.window_count(), 1);

    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 4);

    // First fragments have descending FCN
    assert_eq!(frags[0].fcn, 6); // window_size - 1 - 0 = 6
    assert_eq!(frags[1].fcn, 5);
    assert_eq!(frags[2].fcn, 4);
    assert!(frags[3].is_all_1()); // Last fragment

    // Verify payloads
    assert_eq!(frags[0].payload, &[0, 1, 2, 3, 4]);
    assert_eq!(frags[1].payload, &[5, 6, 7, 8, 9]);
    assert_eq!(frags[2].payload, &[10, 11, 12, 13, 14]);
    assert_eq!(frags[3].payload, &[15, 16, 17, 18, 19]);
}

/// Test multi-fragment payload spanning multiple windows.
#[test]
fn multi_window_fragmentation() {
    let payload: Vec<u8> = (0u8..50).collect();
    let tile_size = 5;
    let window_size = 3; // Small window to force multiple windows
    let sender = FragmentSender::new(&payload, 20, tile_size, window_size).unwrap();

    assert_eq!(sender.fragment_count(), 10); // 50 bytes / 5 bytes per tile
    assert_eq!(sender.window_count(), 4); // ceil(10 / 3) = 4 windows

    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 10);

    // Check window bit alternates
    assert_eq!(frags[0].window, 0); // Window 0
    assert_eq!(frags[1].window, 0);
    assert_eq!(frags[2].window, 0); // All-0 (FCN=0) at end of window 0
    assert_eq!(frags[3].window, 1); // Window 1
    assert_eq!(frags[4].window, 1);
    assert_eq!(frags[5].window, 1);
    assert_eq!(frags[6].window, 0); // Window 2 (wire bit = 0)
    assert!(frags[9].is_all_1()); // Last fragment
}

/// Test full sender -> receiver reassembly.
#[test]
fn sender_receiver_reassembly() {
    let payload: Vec<u8> = (0u8..100).collect();
    let tile_size = 10;
    let window_size = 4;

    let sender = FragmentSender::new(&payload, 20, tile_size, window_size).unwrap();
    let mut receiver = FragmentReceiver::new(window_size);

    let mut reassembled = None;
    for frag in sender.iter() {
        let result = receiver.receive(&frag);
        if result.reassembled.is_some() {
            reassembled = result.reassembled;
        }
    }

    assert!(reassembled.is_some(), "should reassemble");
    assert_eq!(reassembled.as_deref(), Some(payload.as_slice()));
}

/// Test reassembly with out-of-order fragments.
#[test]
fn out_of_order_reassembly() {
    let payload: Vec<u8> = (0u8..20).collect();
    let tile_size = 5;
    let sender = FragmentSender::new(&payload, 20, tile_size, DEFAULT_WINDOW_SIZE).unwrap();
    let frags: Vec<_> = sender.iter().collect();

    let mut receiver = FragmentReceiver::new(DEFAULT_WINDOW_SIZE);

    // Receive in reverse order (except All-1 last)
    let result = receiver.receive(&frags[2]);
    assert!(result.reassembled.is_none());

    let result = receiver.receive(&frags[1]);
    assert!(result.reassembled.is_none());

    let result = receiver.receive(&frags[0]);
    assert!(result.reassembled.is_none());

    // All-1 triggers reassembly
    let result = receiver.receive(&frags[3]);
    assert!(result.reassembled.is_some());
    assert_eq!(result.reassembled.as_deref(), Some(payload.as_slice()));
}

/// Test ACK generation on All-0 (end of window).
#[test]
fn ack_on_all_0() {
    let payload: Vec<u8> = (0u8..50).collect();
    let tile_size = 5;
    let window_size = 3;
    let sender = FragmentSender::new(&payload, 20, tile_size, window_size).unwrap();
    let frags: Vec<_> = sender.iter().collect();

    let mut receiver = FragmentReceiver::new(window_size);

    // Send first window
    let result = receiver.receive(&frags[0]);
    assert!(result.ack.is_none());

    let result = receiver.receive(&frags[1]);
    assert!(result.ack.is_none());

    // All-0 (FCN=0) triggers ACK
    let result = receiver.receive(&frags[2]);
    assert!(result.ack.is_some());
    let ack = result.ack.unwrap();
    assert_eq!(ack.window, 0);
    assert!(!ack.complete);

    // Check bitmap shows all fragments received
    assert!(ack.bitmap[0]);
    assert!(ack.bitmap[1]);
    assert!(ack.bitmap[2]);
}

/// Test retransmit iterator for missing fragments.
#[test]
fn retransmit_missing() {
    let payload: Vec<u8> = (0u8..20).collect();
    let tile_size = 5;
    let sender = FragmentSender::new(&payload, 20, tile_size, DEFAULT_WINDOW_SIZE).unwrap();

    // Bitmap showing fragments 0 and 2 received, 1 and 3 missing
    let bitmap = [true, false, true, false];
    let retransmit: Vec<_> = sender.retransmit(0, &bitmap).collect();

    // Should retransmit fragments at positions 1 and 3
    assert_eq!(retransmit.len(), 2);
    assert_eq!(retransmit[0].payload, &[5, 6, 7, 8, 9]);
    assert!(retransmit[1].is_all_1()); // position 3 is the All-1
}

/// Test fragment serialization round-trip.
#[test]
fn fragment_wire_roundtrip() {
    let payload: Vec<u8> = (0u8..30).collect();
    let sender = FragmentSender::new(&payload, 20, 10, DEFAULT_WINDOW_SIZE).unwrap();

    for frag in sender.iter() {
        let mut wire = [0u8; 64];
        let n = frag.write_to(&mut wire).unwrap();

        let restored = Fragment::from_bytes(&wire[..n]).unwrap();
        assert_eq!(restored.rule_id, frag.rule_id);
        assert_eq!(restored.window, frag.window);
        assert_eq!(restored.fcn, frag.fcn);
        assert_eq!(restored.payload, frag.payload);
        if frag.is_all_1() {
            assert_eq!(restored.mic, frag.mic);
        }
    }
}

/// Test ACK serialization round-trip.
#[test]
fn ack_wire_roundtrip() {
    let bitmap = [true, false, true, true, false, true, false];
    let ack = Ack::new(20, 1, &bitmap, false);

    let mut wire = [0u8; 16];
    let n = ack.write_to(&mut wire).unwrap();

    let restored = Ack::from_bytes(&wire[..n]).unwrap();
    assert_eq!(restored.rule_id, 20);
    assert_eq!(restored.window, 1);
    assert!(!restored.complete);
    assert_eq!(restored.bitmap_len, 7);
    assert_eq!(&restored.bitmap[..7], &bitmap);
}

/// Test MIC validation fails on corrupted payload.
#[test]
fn mic_validation_failure() {
    let payload: Vec<u8> = (0u8..20).collect();
    let sender = FragmentSender::new(&payload, 20, 5, DEFAULT_WINDOW_SIZE).unwrap();
    let frags: Vec<_> = sender.iter().collect();

    let mut receiver = FragmentReceiver::new(DEFAULT_WINDOW_SIZE);

    // Receive first fragment normally
    receiver.receive(&frags[0]);

    // Receive corrupted second fragment
    let corrupt_buf: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let corrupt_frag = Fragment {
        rule_id: frags[1].rule_id,
        window: frags[1].window,
        fcn: frags[1].fcn,
        payload: corrupt_buf,
        mic: [0; 4],
    };
    receiver.receive(&corrupt_frag);

    receiver.receive(&frags[2]);

    // MIC check should fail when All-1 is received
    let result = receiver.receive(&frags[3]);
    // Either mic_ok is false, or reassembly failed
    assert!(result.mic_ok == Some(false) || result.reassembled.is_none());
}

/// Test empty payload.
#[test]
fn empty_payload() {
    let payload: &[u8] = &[];
    let sender = FragmentSender::new(payload, 20, 10, DEFAULT_WINDOW_SIZE).unwrap();

    assert_eq!(sender.fragment_count(), 1);
    let frags: Vec<_> = sender.iter().collect();
    assert_eq!(frags.len(), 1);
    assert!(frags[0].is_all_1());
    assert!(frags[0].payload.is_empty());
}

/// Test complete ACK on successful reassembly.
#[test]
fn complete_ack_on_success() {
    let payload: Vec<u8> = (0u8..20).collect();
    let sender = FragmentSender::new(&payload, 20, 5, DEFAULT_WINDOW_SIZE).unwrap();
    let mut receiver = FragmentReceiver::new(DEFAULT_WINDOW_SIZE);

    let mut final_ack = None;
    for frag in sender.iter() {
        let result = receiver.receive(&frag);
        if result.ack.is_some() {
            final_ack = result.ack;
        }
    }

    assert!(final_ack.is_some());
    let ack = final_ack.unwrap();
    assert!(ack.complete, "ACK should have complete flag set on success");
}
