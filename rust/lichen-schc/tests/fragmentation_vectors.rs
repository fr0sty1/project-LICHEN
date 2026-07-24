//! Production integration against independently derived shared vectors.

use std::collections::BTreeSet;

use lichen_schc::fragment::{
    ack_request, compute_mic, receiver_abort, sender_abort, Ack, Fragment, FragmentReceiver,
    FragmentSender, ReceiverResponse, SenderStatus, MAX_PACKET_SIZE, MAX_SCHC_PACKET, TILE_SIZE,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const VECTORS_JSON: &str = include_str!("../../../test/vectors/schc_fragmentation.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format_version: u8,
    description: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    name: String,
    category: String,
    provenance: String,
    rule_id: Option<u8>,
    packet: Option<BytesValue>,
    packet_length: Option<usize>,
    packet_sha256: Option<String>,
    rcs: Option<String>,
    fragment_count: Option<usize>,
    #[serde(default)]
    fragments: Vec<FragmentVector>,
    loss: Option<Loss>,
    controls: Option<Controls>,
    attempts_before: Option<u8>,
    trigger: Option<BytesValue>,
    expected_message: Option<BytesValue>,
    expect_status: Option<String>,
    wire: Option<BytesValue>,
    assigned_fcns: Option<Vec<u8>>,
    expect_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BytesValue {
    Hex(String),
    Parts { parts: Vec<BytePart> },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BytePart {
    Hex(String),
    Repeat { repeat_byte: String, count: usize },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FragmentVector {
    name: String,
    kind: String,
    window: u8,
    fcn: u8,
    tile_ordinal: usize,
    wire: BytesValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Loss {
    drop_fragment: String,
    ack_failure: BytesValue,
    retransmission: Option<BytesValue>,
    ack_req: BytesValue,
    ack_success: BytesValue,
    corrupt_all1: Option<BytesValue>,
    rcs_failure_ack: Option<BytesValue>,
    next_sender_message: Option<BytesValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Controls {
    rule_78: ControlSet,
    rule_79: ControlSet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlSet {
    ack_success_w0: BytesValue,
    ack_success_w1: BytesValue,
    ack_req_w0: BytesValue,
    ack_req_w1: BytesValue,
    sender_abort: BytesValue,
    receiver_abort: BytesValue,
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length hex: {value}");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("invalid hex"))
        .collect()
}

fn expand(value: &BytesValue) -> Vec<u8> {
    match value {
        BytesValue::Hex(value) => decode_hex(value),
        BytesValue::Parts { parts } => {
            let mut output = Vec::new();
            for part in parts {
                match part {
                    BytePart::Hex(value) => output.extend(decode_hex(value)),
                    BytePart::Repeat { repeat_byte, count } => {
                        let byte = decode_hex(repeat_byte);
                        assert_eq!(byte.len(), 1);
                        output.extend(std::iter::repeat_n(byte[0], *count));
                    }
                }
            }
            output
        }
    }
}

fn write_fragment(fragment: &Fragment<'_>) -> Vec<u8> {
    let mut wire = [0u8; TILE_SIZE + 6];
    let length = fragment.write_to(&mut wire).unwrap();
    wire[..length].to_vec()
}

fn write_response(response: ReceiverResponse) -> Vec<u8> {
    let mut wire = [0u8; 10];
    let length = response.write_to(&mut wire).unwrap();
    wire[..length].to_vec()
}

#[test]
fn shared_vectors_drive_production_implementations() {
    let document: Document = serde_json::from_str(VECTORS_JSON).expect("invalid vector JSON");
    assert_eq!(document.format_version, 1);
    assert!(!document.description.is_empty());
    let mut categories = BTreeSet::new();

    for vector in &document.vectors {
        categories.insert(vector.category.as_str());
        assert!(!vector.name.is_empty());
        assert!(!vector.provenance.is_empty());
        if let Some(packet) = &vector.packet {
            let digest = Sha256::digest(expand(packet));
            let expected = decode_hex(vector.packet_sha256.as_ref().unwrap());
            assert_eq!(&digest[..], expected);
        }

        match vector.category.as_str() {
            "recovery" | "window_transition" => exercise_transfer(vector),
            "controls" => exercise_controls(vector.controls.as_ref().unwrap()),
            "retry_exhaustion" => exercise_retry(vector),
            "capacity" => exercise_capacity(vector),
            "malformed" => exercise_malformed(vector),
            category => panic!("unhandled category {category}"),
        }
    }

    assert_eq!(
        categories,
        BTreeSet::from([
            "capacity",
            "controls",
            "malformed",
            "recovery",
            "retry_exhaustion",
            "window_transition",
        ])
    );
}

fn exercise_transfer(vector: &Vector) {
    let packet = expand(vector.packet.as_ref().unwrap());
    assert_eq!(packet.len(), vector.packet_length.unwrap());
    let rule_id = vector.rule_id.unwrap();
    let sender = FragmentSender::new(&packet, rule_id, packet.len()).unwrap();
    if let Some(count) = vector.fragment_count {
        assert_eq!(sender.fragment_count(), count, "{}", vector.name);
    }
    assert_eq!(
        compute_mic(&packet).to_vec(),
        decode_hex(vector.rcs.as_ref().unwrap())
    );

    for expected in &vector.fragments {
        assert!(matches!(
            expected.kind.as_str(),
            "regular" | "all0" | "all1"
        ));
        assert!(!expected.name.is_empty());
        let fragment = sender.get_fragment(expected.tile_ordinal).unwrap();
        assert_eq!(fragment.window, expected.window);
        assert_eq!(fragment.fcn, expected.fcn);
        let wire = expand(&expected.wire);
        assert_eq!(
            write_fragment(&fragment),
            wire,
            "{} {}",
            vector.name,
            expected.name
        );
        let mut tile = [0u8; TILE_SIZE];
        let parsed = Fragment::from_bytes(&wire, &mut tile).unwrap();
        assert_eq!(parsed, fragment);
    }

    let loss = vector.loss.as_ref().unwrap();
    let dropped = vector
        .fragments
        .iter()
        .find(|fragment| fragment.name == loss.drop_fragment)
        .unwrap();
    let mut storage = vec![0u8; packet.len()];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    let mut failure = None;
    for index in 0..sender.fragment_count() {
        if index == dropped.tile_ordinal {
            continue;
        }
        let result = receiver.receive(&sender.get_fragment(index).unwrap());
        if result.response.is_some() {
            failure = result.response;
        }
    }
    assert_eq!(write_response(failure.unwrap()), expand(&loss.ack_failure));

    if let Some(retransmission) = &loss.retransmission {
        let wire = expand(retransmission);
        let mut tile = [0u8; TILE_SIZE];
        let fragment = Fragment::from_bytes(&wire, &mut tile).unwrap();
        assert_eq!(receiver.receive(&fragment).response, None);
        let result = receiver.receive_bytes(&expand(&loss.ack_req)).unwrap();
        assert_eq!(
            write_response(result.response.unwrap()),
            expand(&loss.ack_success)
        );
        assert_eq!(receiver.packet(), Some(packet.as_slice()));
    }

    if let (Some(corrupt), Some(expected)) = (&loss.corrupt_all1, &loss.rcs_failure_ack) {
        let mut storage = vec![0u8; packet.len()];
        let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
        for index in 0..sender.fragment_count() - 1 {
            receiver.receive(&sender.get_fragment(index).unwrap());
        }
        let result = receiver.receive_bytes(&expand(corrupt)).unwrap();
        assert_eq!(result.mic_ok, Some(false));
        assert_eq!(write_response(result.response.unwrap()), expand(expected));

        let mut sender = FragmentSender::new(&packet, rule_id, packet.len()).unwrap();
        sender.start().unwrap();
        let mut output = sender.handle_ack_bytes(&expand(expected)).unwrap();
        let mut wire = [0u8; TILE_SIZE + 6];
        let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
        assert_eq!(
            &wire[..length],
            expand(loss.next_sender_message.as_ref().unwrap())
        );
    }
}

fn exercise_controls(controls: &Controls) {
    for (rule_id, set) in [(0x78, &controls.rule_78), (0x79, &controls.rule_79)] {
        for (window, expected) in [(0, &set.ack_success_w0), (1, &set.ack_success_w1)] {
            let ack = Ack::new(rule_id, window, 0, true);
            let mut wire = [0u8; 10];
            let length = ack.write_to(&mut wire).unwrap();
            assert_eq!(&wire[..length], expand(expected));
            assert_eq!(Ack::from_bytes(&wire[..length]).unwrap(), ack);
        }
        for (window, expected) in [(0, &set.ack_req_w0), (1, &set.ack_req_w1)] {
            let mut wire = [0u8; 3];
            let length = ack_request(rule_id, window).write_to(&mut wire).unwrap();
            assert_eq!(&wire[..length], expand(expected));
        }
        let mut wire = [0u8; 3];
        let length = sender_abort(rule_id).write_to(&mut wire).unwrap();
        assert_eq!(&wire[..length], expand(&set.sender_abort));
        let length = receiver_abort(rule_id).write_to(&mut wire).unwrap();
        assert_eq!(&wire[..length], expand(&set.receiver_abort));
    }
}

fn exercise_retry(vector: &Vector) {
    assert_eq!(vector.attempts_before, Some(4));
    assert_eq!(vector.expect_status.as_deref(), Some("aborted"));
    let rule_id = vector.rule_id.unwrap();
    let expected = expand(vector.expected_message.as_ref().unwrap());
    assert_eq!(
        expand(vector.trigger.as_ref().unwrap()),
        vec![rule_id, 0x80]
    );
    if vector.name.starts_with("sender") {
        let packet = [0xa5];
        let mut sender = FragmentSender::new(&packet, rule_id, 1).unwrap();
        sender.start().unwrap();
        for _ in 1..4 {
            sender.timeout().unwrap();
        }
        let mut output = sender.timeout().unwrap();
        let mut wire = [0u8; 3];
        let length = sender.write_next(&mut output, &mut wire).unwrap().unwrap();
        assert_eq!(&wire[..length], expected);
        assert_eq!(sender.status(), SenderStatus::Aborted);
    } else {
        let mut storage = [0u8; 1];
        let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
        for _ in 0..4 {
            receiver.receive_bytes(&[rule_id, 0x80]).unwrap();
        }
        let result = receiver.receive_bytes(&[rule_id, 0x80]).unwrap();
        assert!(result.aborted);
        assert_eq!(write_response(result.response.unwrap()), expected);
    }
}

fn exercise_capacity(vector: &Vector) {
    let packet = expand(vector.packet.as_ref().unwrap());
    assert_eq!(packet.len(), vector.packet_length.unwrap());
    let result = FragmentSender::new(&packet, 0x78, MAX_PACKET_SIZE);
    if packet.len() > MAX_PACKET_SIZE {
        assert!(result.is_err());
        assert_eq!(vector.fragment_count, Some(0));
        assert_eq!(vector.expect_status.as_deref(), Some("packet_too_large"));
        return;
    }
    let sender = result.unwrap();
    assert_eq!(sender.fragment_count(), vector.fragment_count.unwrap());
    assert_eq!(
        compute_mic(&packet).to_vec(),
        decode_hex(vector.rcs.as_ref().unwrap())
    );
    assert_eq!(vector.expect_status.as_deref(), Some("ok"));
    if packet.len() <= MAX_SCHC_PACKET {
        let mut storage = vec![0u8; packet.len()];
        let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
        let mut result = None;
        for fragment in sender.iter() {
            result = Some(receiver.receive(&fragment));
        }
        assert_eq!(result.unwrap().packet_len, Some(packet.len()));
        assert_eq!(receiver.packet(), Some(packet.as_slice()));
    }
}

fn exercise_malformed(vector: &Vector) {
    assert!(vector
        .expect_error
        .as_ref()
        .is_some_and(|error| !error.is_empty()));
    let wire = expand(vector.wire.as_ref().unwrap());
    let mut tile = [0u8; TILE_SIZE];
    match vector.name.as_str() {
        "ack_success_extra_octet" | "malformed_control" => {
            assert!(Ack::from_bytes(&wire).is_err());
        }
        "unassigned_bitmap_bit" => {
            let mask = vector
                .assigned_fcns
                .as_ref()
                .unwrap()
                .iter()
                .fold(0, |mask, &fcn| {
                    mask | if fcn == 63 { 1 } else { 1u64 << fcn }
                });
            assert!(Ack::from_bytes_for(&wire, Some(mask)).is_err());
        }
        _ => assert!(Fragment::from_bytes(&wire, &mut tile).is_err()),
    }
}
