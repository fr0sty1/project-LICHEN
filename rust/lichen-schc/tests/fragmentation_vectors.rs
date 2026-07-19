//! Fixture-integrity checks for the shared RFC 8724 fragmentation vectors.

use std::collections::BTreeSet;

use serde::Deserialize;

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
    fragments: Vec<Fragment>,
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
struct Fragment {
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

#[test]
fn shared_fragmentation_vectors_are_complete_and_well_formed() {
    let document: Document = serde_json::from_str(VECTORS_JSON).expect("invalid vector JSON");
    assert_eq!(document.format_version, 1);
    assert!(!document.description.is_empty());

    let mut names = BTreeSet::new();
    let mut categories = BTreeSet::new();
    for vector in &document.vectors {
        assert!(names.insert(&vector.name), "duplicate vector name");
        categories.insert(vector.category.as_str());
        assert!(!vector.provenance.is_empty());

        if let Some(packet) = &vector.packet {
            assert_eq!(
                expand(packet).len(),
                vector.packet_length.expect("packet length")
            );
            assert_eq!(vector.packet_sha256.as_ref().map(String::len), Some(64));
        }
        if let Some(rcs) = &vector.rcs {
            assert_eq!(decode_hex(rcs).len(), 4);
        }
        if let Some(rule_id) = vector.rule_id {
            assert!(matches!(rule_id, 0x78 | 0x79));
        }

        for fragment in &vector.fragments {
            let wire = expand(&fragment.wire);
            assert_eq!(wire.first().copied(), vector.rule_id);
            assert_eq!(wire[1] >> 7, fragment.window);
            assert_eq!((wire[1] >> 1) & 0x3f, fragment.fcn);
            assert!(matches!(
                fragment.kind.as_str(),
                "regular" | "all0" | "all1"
            ));
            assert!(fragment.tile_ordinal < 126);
            assert!(!fragment.name.is_empty());
        }
        assert_eq!(
            vector
                .fragments
                .iter()
                .map(|fragment| fragment.name.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            vector.fragments.len(),
            "duplicate fragment name in {}",
            vector.name
        );

        if let Some(loss) = &vector.loss {
            let dropped = vector
                .fragments
                .iter()
                .find(|fragment| fragment.name == loss.drop_fragment)
                .expect("loss target");
            if let Some(retransmission) = &loss.retransmission {
                assert_eq!(expand(retransmission), expand(&dropped.wire));
            }
            for message in [
                Some(&loss.ack_failure),
                Some(&loss.ack_req),
                Some(&loss.ack_success),
                loss.corrupt_all1.as_ref(),
                loss.rcs_failure_ack.as_ref(),
                loss.next_sender_message.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(expand(message)[0], vector.rule_id.expect("loss rule"));
            }
        }

        if let Some(controls) = &vector.controls {
            for (rule_id, control_set) in [(0x78, &controls.rule_78), (0x79, &controls.rule_79)] {
                for message in [
                    &control_set.ack_success_w0,
                    &control_set.ack_success_w1,
                    &control_set.ack_req_w0,
                    &control_set.ack_req_w1,
                    &control_set.sender_abort,
                    &control_set.receiver_abort,
                ] {
                    assert_eq!(expand(message)[0], rule_id);
                }
            }
        }

        if vector.category == "malformed" {
            assert!(!expand(vector.wire.as_ref().expect("malformed wire")).is_empty());
            assert!(vector
                .expect_error
                .as_ref()
                .is_some_and(|error| !error.is_empty()));
        }

        if vector.category == "retry_exhaustion" {
            assert_eq!(vector.attempts_before, Some(4));
            assert_eq!(
                expand(vector.trigger.as_ref().expect("retry trigger"))[0],
                vector.rule_id.expect("retry rule")
            );
            let expected = expand(
                vector
                    .expected_message
                    .as_ref()
                    .expect("retry expected message"),
            );
            assert_eq!(expected[0], vector.rule_id.expect("retry rule"));
            assert!(matches!(
                expected.as_slice(),
                [0x78, 0xfe] | [0x78, 0xff, 0xff]
            ));
            assert_eq!(vector.expect_status.as_deref(), Some("aborted"));
        }

        if let Some(fcns) = &vector.assigned_fcns {
            assert_eq!(
                fcns.iter().copied().collect::<BTreeSet<_>>().len(),
                fcns.len()
            );
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
            "window_transition"
        ])
    );
    assert!(document
        .vectors
        .iter()
        .any(|vector| vector.fragment_count == Some(126)));
    assert!(document
        .vectors
        .iter()
        .any(|vector| vector.packet_length == Some(23_563) && vector.fragment_count == Some(0)));
}
