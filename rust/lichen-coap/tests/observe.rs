// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_coap::observe::{
    decode_observe_value, ClientEvent, ClientNotification, ObserveError, ObserveKey,
    ObserveRequest, ObserveSequence, ObserveServer, SequenceRelation, ServerNotification,
    OBSERVE_MAX_VALUE,
};
use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType, ObserveClient};

fn key(peer: u8, token: &[u8]) -> ObserveKey<u8> {
    ObserveKey::new(peer, token).unwrap()
}

fn notification(
    message_id: u16,
    observe: Option<u32>,
    block2_num: Option<u32>,
) -> ClientNotification {
    ClientNotification {
        message_type: MessageType::NonConfirmable,
        message_id,
        observe,
        block2_num,
        max_age_ms: 300_000,
    }
}

fn server_notification(
    resource: u16,
    sequence: u32,
    message_id: u16,
    confirmable: bool,
    wire: &[u8],
    now_ms: u64,
) -> ServerNotification<'_> {
    ServerNotification {
        resource,
        sequence: ObserveSequence::new(sequence).unwrap(),
        message_id,
        confirmable,
        wire,
        now_ms,
    }
}

#[test]
fn independent_rfc7641_serial_vectors_cover_boundaries() {
    let cases = [
        (100, 101, SequenceRelation::Newer),
        (100, 100, SequenceRelation::Equal),
        (100, 99, SequenceRelation::Older),
        (OBSERVE_MAX_VALUE, 0, SequenceRelation::Newer),
        (OBSERVE_MAX_VALUE - 1, 1, SequenceRelation::Newer),
        (10, OBSERVE_MAX_VALUE - 15, SequenceRelation::Older),
        (1000, 8_389_607, SequenceRelation::Newer),
        (1000, 8_389_608, SequenceRelation::Ambiguous),
        (1000, 8_390_000, SequenceRelation::Older),
    ];
    for (old, new, expected) in cases {
        let old = ObserveSequence::new(old).unwrap();
        let new = ObserveSequence::new(new).unwrap();
        assert_eq!(new.relation_to(old), expected, "{old:?} -> {new:?}");
    }
    assert_eq!(
        ObserveSequence::new(OBSERVE_MAX_VALUE).unwrap().next(),
        ObserveSequence::new(0).unwrap()
    );
    assert_eq!(
        ObserveSequence::new(OBSERVE_MAX_VALUE + 1),
        Err(ObserveError::InvalidObserveValue)
    );
}

#[test]
fn observe_option_is_canonical_and_request_values_are_strict() {
    assert_eq!(decode_observe_value(&[]), Ok(0));
    assert_eq!(decode_observe_value(&[1]), Ok(1));
    assert_eq!(decode_observe_value(&[0x12, 0x34, 0x56]), Ok(0x12_34_56));
    assert_eq!(
        decode_observe_value(&[0]),
        Err(ObserveError::InvalidObserveValue)
    );
    assert_eq!(
        decode_observe_value(&[0, 1]),
        Err(ObserveError::InvalidObserveValue)
    );
    assert_eq!(
        decode_observe_value(&[1, 2, 3, 4]),
        Err(ObserveError::InvalidObserveValue)
    );
    assert_eq!(ObserveRequest::decode(None), Ok(None));
    assert_eq!(
        ObserveRequest::decode(Some(&[])),
        Ok(Some(ObserveRequest::Register))
    );
    assert_eq!(
        ObserveRequest::decode(Some(&[1])),
        Ok(Some(ObserveRequest::Deregister))
    );
    assert_eq!(
        ObserveRequest::decode(Some(&[2])),
        Err(ObserveError::InvalidRequestValue)
    );

    let mut wire = [0u8; 32];
    let mut builder = CoapBuilder::new(
        &mut wire,
        MessageType::Acknowledgement,
        MessageCode::CONTENT,
        0x1234,
        b"tk",
    )
    .unwrap();
    builder.observe(0x12_34).unwrap();
    builder.payload(b"ok").unwrap();
    let length = builder.finish();
    let parsed = CoapPacket::from_bytes(&wire[..length]).unwrap();
    let option = parsed.options().next().unwrap().unwrap();
    assert!(option.is_observe());
    assert_eq!(option.as_observe(), Ok(0x12_34));
    assert_eq!(option.value, &[0x12, 0x34]);
}

#[test]
fn server_registry_is_bounded_and_registration_replaces_atomically() {
    let mut server = ObserveServer::<u8, 2, 16>::new(1000, 100, 2).unwrap();
    let a = key(1, b"a");
    let b = key(2, b"b");
    let c = key(3, b"c");
    server.register(a, 10, 0).unwrap();
    server.register(b, 10, 0).unwrap();
    assert_eq!(server.len(), 2);
    assert_eq!(server.register(c, 10, 0), Err(ObserveError::RegistryFull));
    assert!(!server.contains(&c));
    server.register(a, 11, 10).unwrap();
    assert_eq!(server.len(), 2);
    assert_eq!(server.observers(10).count(), 1);
    assert_eq!(server.observers(11).next().unwrap().key, a);
    assert!(server.deregister(&a));
    assert!(!server.deregister(&a));
}

#[test]
fn confirmable_notification_reuses_exact_bytes_until_ack() {
    let mut server = ObserveServer::<u8, 1, 16>::new(1000, 100, 2).unwrap();
    let observer = key(1, b"tok");
    server.register(observer, 7, 0).unwrap();
    let original = [0x43, 0x45, 0x12, 0x34, b't', b'o', b'k'];
    server
        .queue_notification(
            &observer,
            server_notification(7, 10, 0x1234, true, &original, 10),
        )
        .unwrap();
    assert_eq!(
        server.queue_notification(
            &observer,
            server_notification(7, 11, 0x1235, true, b"next", 10),
        ),
        Err(ObserveError::Backpressure)
    );
    let initial = server.next_due(10).unwrap();
    assert!(!initial.retransmission);
    assert_eq!(initial.wire(), original);
    assert!(server.next_due(109).is_none());
    let retry = server.next_due(110).unwrap();
    assert!(retry.retransmission);
    assert_eq!(retry.wire(), initial.wire());
    assert!(server.acknowledge(1, 0x1234, 111));
    assert!(server.next_due(500).is_none());
    assert!(server.contains(&observer));
}

#[test]
fn server_rejects_stale_ambiguous_and_oversize_without_partial_state() {
    let mut server = ObserveServer::<u8, 1, 4>::new(1000, 100, 1).unwrap();
    let observer = key(1, b"t");
    server.register(observer, 7, 0).unwrap();
    assert_eq!(
        server.queue_notification(&observer, server_notification(7, 1, 1, true, b"12345", 0),),
        Err(ObserveError::PacketTooLarge)
    );
    server
        .queue_notification(&observer, server_notification(7, 10, 2, true, b"one", 0))
        .unwrap();
    assert!(server.acknowledge(1, 2, 1));
    assert_eq!(
        server.queue_notification(&observer, server_notification(7, 10, 3, true, b"eq", 2),),
        Err(ObserveError::StaleSequence)
    );
    assert_eq!(
        server.queue_notification(
            &observer,
            server_notification(7, 10 + 0x80_0000, 4, true, b"amb", 2),
        ),
        Err(ObserveError::AmbiguousSequence)
    );
    server
        .queue_notification(&observer, server_notification(7, 11, 5, true, b"new", 2))
        .unwrap();
    assert_eq!(server.next_due(2).unwrap().wire(), b"new");
}

#[test]
fn rst_retry_exhaustion_and_idle_timeout_cleanup_relationships() {
    let mut server = ObserveServer::<u8, 2, 8>::new(500, 10, 1).unwrap();
    let a = key(1, b"a");
    let b = key(2, b"b");
    server.register(a, 1, 0).unwrap();
    server.register(b, 1, 0).unwrap();
    server
        .queue_notification(&a, server_notification(1, 1, 10, true, b"x", 0))
        .unwrap();
    assert!(server.next_due(0).is_some());
    assert!(server.next_due(10).unwrap().retransmission);
    assert!(server.next_due(20).is_none());
    assert!(!server.contains(&a));

    server
        .queue_notification(&b, server_notification(1, 1, 11, true, b"y", 20))
        .unwrap();
    assert!(server.reset(2, 11));
    assert!(!server.contains(&b));

    server.register(a, 1, 100).unwrap();
    assert_eq!(server.cleanup(599), 0);
    assert_eq!(server.cleanup(600), 1);
}

#[test]
fn non_confirmable_notification_is_retired_after_one_dispatch() {
    let mut server = ObserveServer::<u8, 1, 8>::new(500, 10, 4).unwrap();
    let observer = key(1, b"n");
    server.register(observer, 1, 0).unwrap();
    server
        .queue_notification(&observer, server_notification(1, 1, 10, false, b"non", 0))
        .unwrap();
    let delivery = server.next_due(0).unwrap();
    assert!(!delivery.confirmable);
    assert!(!delivery.retransmission);
    assert_eq!(delivery.wire(), b"non");
    assert!(server.next_due(10).is_none());
    assert!(server.contains(&observer));
}

#[test]
fn client_subscription_orders_notifications_and_handles_time_fallback() {
    let mut client = ObserveClient::<u8, 1>::new();
    let subscription = key(1, b"obs");
    client.subscribe(subscription, 7, 0, 1000).unwrap();
    assert_eq!(
        client.process(&subscription, 7, notification(1, Some(100), None), 10),
        Ok(ClientEvent::Registered(ObserveSequence::new(100).unwrap()))
    );
    assert_eq!(
        client.process(&subscription, 7, notification(2, Some(101), None), 20),
        Ok(ClientEvent::Notification {
            sequence: ObserveSequence::new(101).unwrap(),
            fresh_by_time: false,
        })
    );
    assert_eq!(
        client.process(&subscription, 7, notification(3, Some(101), None), 21),
        Ok(ClientEvent::Duplicate)
    );
    assert_eq!(
        client.process(&subscription, 7, notification(4, Some(100), None), 22),
        Ok(ClientEvent::Stale)
    );
    assert_eq!(
        client.process(
            &subscription,
            7,
            notification(5, Some(101 + 0x80_0000), None),
            23,
        ),
        Ok(ClientEvent::Ambiguous)
    );
    assert_eq!(
        client.process(&subscription, 7, notification(6, Some(50), None), 128_021,),
        Ok(ClientEvent::Notification {
            sequence: ObserveSequence::new(50).unwrap(),
            fresh_by_time: true,
        })
    );
}

#[test]
fn client_handles_block_boundaries_cancel_rst_capacity_and_cleanup() {
    let mut client = ObserveClient::<u8, 1>::new();
    let subscription = key(1, b"obs");
    let other = key(2, b"other");
    client.subscribe(subscription, 7, 0, 100).unwrap();
    assert_eq!(
        client.subscribe(other, 8, 0, 100),
        Err(ObserveError::RegistryFull)
    );
    assert_eq!(
        client.process(&subscription, 7, notification(1, None, Some(1)), 1),
        Err(ObserveError::InvalidBlockwise)
    );
    client
        .process(&subscription, 7, notification(2, Some(1), Some(0)), 2)
        .unwrap();
    assert_eq!(
        client.process(&subscription, 7, notification(3, None, Some(1)), 3),
        Ok(ClientEvent::BlockContinuation)
    );
    assert_eq!(
        client.process(&subscription, 7, notification(4, Some(2), Some(1)), 4),
        Err(ObserveError::InvalidBlockwise)
    );
    assert!(client.reset(1, 3));
    assert!(!client.contains(&subscription));

    client.subscribe(subscription, 7, 10, 50).unwrap();
    assert_eq!(client.cleanup(59), 0);
    assert_eq!(client.cleanup(60), 1);
    client.subscribe(subscription, 7, 70, 50).unwrap();
    assert!(client.cancel(&subscription));
    assert!(!client.cancel(&subscription));
}

#[test]
fn terminal_response_removes_relationship_without_advancing_state() {
    let mut client = ObserveClient::<u8, 1>::new();
    let subscription = key(1, b"obs");
    client.subscribe(subscription, 7, 0, 100).unwrap();
    client
        .process(&subscription, 7, notification(1, Some(1), None), 1)
        .unwrap();
    assert_eq!(
        client.process(&subscription, 7, notification(2, None, None), 2),
        Ok(ClientEvent::Terminated)
    );
    assert!(!client.contains(&subscription));
}
