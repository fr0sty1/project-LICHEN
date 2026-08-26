// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! Reassembly state-machine coverage using the canonical fragmentation wires.
//!
//! The recovery literals below are shared with Python's
//! `tests/schc/test_reassembly.py` and originate in
//! `test/vectors/schc_fragmentation.json`.

mod support;

use lichen_schc::fragment::{
    sender_abort, Fragment, FragmentReceiver, ReceiverResponse, INACTIVITY_TIMEOUT_S,
    MAX_PACKET_SIZE, TILE_SIZE, WINDOW_SIZE,
};

const RECOVERY_PACKET_LEN: usize = TILE_SIZE * 2 + 1;

fn recovery_packet() -> [u8; RECOVERY_PACKET_LEN] {
    let mut packet = [0u8; RECOVERY_PACKET_LEN];
    packet[TILE_SIZE..TILE_SIZE * 2].fill(0x11);
    packet[TILE_SIZE * 2] = 0xa5;
    packet
}

fn canonical_tile_0() -> [u8; TILE_SIZE + 2] {
    let mut wire = [0u8; TILE_SIZE + 2];
    wire[..2].copy_from_slice(&[0x78, 0x7c]);
    wire
}

fn canonical_tile_1() -> [u8; TILE_SIZE + 2] {
    let mut wire = [0u8; TILE_SIZE + 2];
    wire[..2].copy_from_slice(&[0x78, 0x7a]);
    wire[2..].fill(0x22);
    wire
}

fn response_wire(response: ReceiverResponse) -> Vec<u8> {
    let mut wire = [0u8; 10];
    let length = response.write_to(&mut wire).unwrap();
    wire[..length].to_vec()
}

#[test]
fn canonical_out_of_order_missing_and_duplicate_recovery() {
    let packet = recovery_packet();
    let tile_0 = canonical_tile_0();
    let tile_1 = canonical_tile_1();
    let all_1 = [0x78, 0x7e, 0xbf, 0xb4, 0x0b, 0x51, 0x4a];
    let mut storage = [0u8; RECOVERY_PACKET_LEN];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();

    assert_eq!(receiver.receive_bytes(&tile_0).unwrap().response, None);
    // A byte-identical duplicate is idempotent.
    assert_eq!(receiver.receive_bytes(&tile_0).unwrap().response, None);

    // All-1 arrives before tile 1 and produces the canonical missing-tile ACK.
    let missing = receiver.receive_bytes(&all_1).unwrap();
    assert_eq!(
        response_wire(missing.response.unwrap()),
        [0x78, 0x20, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(missing.mic_ok, Some(false));

    assert_eq!(receiver.receive_bytes(&tile_1).unwrap().response, None);
    let complete = receiver.receive_bytes(&[0x78, 0x00]).unwrap();
    assert_eq!(response_wire(complete.response.unwrap()), [0x78, 0x40]);
    assert_eq!(complete.packet_len, Some(packet.len()));
    assert_eq!(complete.mic_ok, Some(true));
    assert_eq!(receiver.packet(), Some(packet.as_slice()));
}

#[test]
fn conflicting_duplicate_aborts_and_releases_partial_packet() {
    let tile_0 = canonical_tile_0();
    let mut storage = [0u8; RECOVERY_PACKET_LEN];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    receiver.receive_bytes(&tile_0).unwrap();

    let conflicting_tile = [0x5a; TILE_SIZE];
    let conflict = Fragment {
        rule_id: 0x78,
        window: 0,
        fcn: 62,
        payload: &conflicting_tile,
        mic: [0; 4],
    };
    let result = receiver.receive(&conflict);
    assert!(result.aborted);
    assert_eq!(response_wire(result.response.unwrap()), [0x78, 0xff, 0xff]);
    assert_eq!(receiver.packet(), None);
}

#[test]
fn inactivity_and_sender_abort_release_reassembly_state() {
    assert_eq!(INACTIVITY_TIMEOUT_S, 60);
    let tile_0 = canonical_tile_0();
    let mut storage = [0u8; RECOVERY_PACKET_LEN];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    receiver.receive_bytes(&tile_0).unwrap();

    assert_eq!(
        response_wire(receiver.expire().unwrap()),
        [0x78, 0xff, 0xff]
    );
    assert!(receiver.is_done());
    assert_eq!(receiver.expire(), None);

    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    receiver.receive_bytes(&tile_0).unwrap();
    let mut abort = [0u8; 2];
    let length = sender_abort(0x78).write_to(&mut abort).unwrap();
    let result = receiver.receive_bytes(&abort[..length]).unwrap();
    assert!(result.aborted);
    assert_eq!(result.response, None);
    assert!(receiver.is_done());
    assert_eq!(receiver.packet(), None);
}

#[test]
fn canonical_rcs_mismatch_requests_all_1_retransmission() {
    let tile_0 = canonical_tile_0();
    let tile_1 = canonical_tile_1();
    let corrupt_all_1 = [0x78, 0x7f, 0xd8, 0x05, 0x35, 0xad, 0x4a];
    let mut storage = [0u8; RECOVERY_PACKET_LEN];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    receiver.receive_bytes(&tile_0).unwrap();
    receiver.receive_bytes(&tile_1).unwrap();

    let result = receiver.receive_bytes(&corrupt_all_1).unwrap();
    assert_eq!(result.mic_ok, Some(false));
    assert_eq!(
        response_wire(result.response.unwrap()),
        [0x78, 0x30, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(receiver.packet(), None);
}

#[test]
fn multi_window_reassembly_completes_after_early_all_1() {
    let packet = vec![0xa5; WINDOW_SIZE * TILE_SIZE + 1];
    let sender = support::fragment_sender(&packet, 0x78, packet.len()).unwrap();
    assert_eq!(sender.fragment_count(), WINDOW_SIZE + 1);
    assert_eq!(sender.final_window(), 1);

    let mut storage = vec![0u8; packet.len()];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    assert_eq!(
        receiver.receive(&sender.get_fragment(0).unwrap()).response,
        None
    );
    let early_all_1 = receiver
        .receive(&sender.get_fragment(WINDOW_SIZE).unwrap())
        .response
        .unwrap();
    let ReceiverResponse::Ack(ack) = early_all_1 else {
        panic!("expected missing-window ACK")
    };
    assert_eq!(ack.window, 0);
    assert!(!ack.complete);
    assert_eq!(ack.bitmap, 1u64 << 62);

    // The remaining window-0 tiles arrive in reverse order.
    for index in (1..WINDOW_SIZE).rev() {
        assert_eq!(
            receiver
                .receive(&sender.get_fragment(index).unwrap())
                .response,
            None
        );
    }
    let complete = receiver.receive_bytes(&[0x78, 0x80]).unwrap();
    assert_eq!(response_wire(complete.response.unwrap()), [0x78, 0xc0]);
    assert_eq!(complete.packet_len, Some(packet.len()));
    assert_eq!(receiver.packet(), Some(packet.as_slice()));
}

#[test]
fn receiver_capacity_bounds_are_enforced_during_reassembly() {
    assert!(FragmentReceiver::new(&mut []).is_err());
    assert!(FragmentReceiver::with_limit(&mut [0u8; 1], 0).is_err());
    assert!(FragmentReceiver::with_limit(&mut [0u8; 1], 2).is_err());
    assert!(FragmentReceiver::with_limit(&mut [0u8; 1], MAX_PACKET_SIZE + 1).is_err());

    // 1281 octets is the mandatory receiver boundary from the profile.
    let packet = vec![0xa5; 1281];
    let sender = support::fragment_sender(&packet, 0x78, packet.len()).unwrap();
    let mut storage = vec![0u8; packet.len()];
    let mut receiver = FragmentReceiver::with_limit(&mut storage, packet.len()).unwrap();
    let mut result = None;
    for fragment in sender.iter() {
        result = Some(receiver.receive(&fragment));
    }
    assert_eq!(result.unwrap().packet_len, Some(packet.len()));
    assert_eq!(receiver.packet(), Some(packet.as_slice()));

    let mut undersized_storage = vec![0u8; packet.len() - 1];
    let mut undersized =
        FragmentReceiver::with_limit(&mut undersized_storage, packet.len() - 1).unwrap();
    let mut result = None;
    for fragment in sender.iter() {
        result = Some(undersized.receive(&fragment));
        if result.as_ref().unwrap().aborted {
            break;
        }
    }
    let result = result.unwrap();
    assert!(result.aborted);
    assert_eq!(response_wire(result.response.unwrap()), [0x78, 0xff, 0xff]);
    assert_eq!(undersized.packet(), None);
}
