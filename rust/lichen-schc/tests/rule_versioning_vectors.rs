//! Executable cross-implementation oracle for SCHC Rule Set Version 3.

use std::fs;
use std::path::Path;

use lichen_link::identity::{Identity, PeerIdentity};
use lichen_link::keys::Seed;
use lichen_link::link_layer::{AuthenticatedFrame, LinkLayer};
use lichen_link::LinkSeqNum;
use lichen_schc::fragment::{FragmentError, FragmentSender, FragmentationPolicy};
use lichen_schc::{
    decode_rule255, encode_rule255, rule_set_v3_descriptor_hash, versions_compatible,
    AuthenticatedPeerSchcContext, ExpectedDioRole, Mo, RuleVersionFailureTracker, SchcContext,
    SchcError, SchcRuleVersionOption, RULE_SET_V3, RULE_SET_VERSION,
};

const DODAG_ID: [u8; 16] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn hex_decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn authenticated_dio_options(options: &[u8]) -> (LinkLayer, AuthenticatedFrame) {
    authenticated_dio_options_with_link(options, 0x11, 1)
}

fn authenticated_dio_options_from(
    options: &[u8],
    sender_seed: u8,
) -> (LinkLayer, AuthenticatedFrame) {
    authenticated_dio_options_with_link(options, sender_seed, 1)
}

fn authenticated_dio_options_with_link(
    options: &[u8],
    sender_seed: u8,
    seqnum: u16,
) -> (LinkLayer, AuthenticatedFrame) {
    let sender_identity = Identity::from_seed(Seed::new([sender_seed; 32]));
    let sender_iid = sender_identity.iid;
    let receiver_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let mut receiver = LinkLayer::new(receiver_identity);
    receiver.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let sender = LinkLayer::new(sender_identity);
    let frame = receive_dio_options(&mut receiver, &sender, sender_iid, options, seqnum);
    (receiver, frame)
}

fn receive_dio_options(
    receiver: &mut LinkLayer,
    sender: &LinkLayer,
    sender_iid: [u8; 8],
    options: &[u8],
    seqnum: u16,
) -> AuthenticatedFrame {
    let mut dio = vec![0u8; 24];
    dio[2..4].copy_from_slice(&512u16.to_be_bytes());
    dio[4] = 1 << 3;
    dio[8..24].copy_from_slice(&DODAG_ID);
    dio.extend_from_slice(options);
    let mut icmp = vec![155, 1, 0, 0];
    icmp.extend_from_slice(&dio);
    let mut src = [0u8; 16];
    src[0] = 0xfe;
    src[1] = 0x80;
    src[8..].copy_from_slice(&sender_iid);
    let dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
    let checksum = lichen_core::checksum::upper_layer_checksum(&src, &dst, 58, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut ipv6 = vec![0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6[6] = 58;
    ipv6[7] = 255;
    ipv6[8..24].copy_from_slice(&src);
    ipv6[24..40].copy_from_slice(&dst);
    ipv6.extend_from_slice(&icmp);
    let mut compressed = [0u8; 128];
    let compressed_len = lichen_schc::compress(&ipv6, &mut compressed).unwrap();
    let mut recovered = [0u8; 128];
    let recovered_len =
        lichen_schc::decompress(&compressed[..compressed_len], &mut recovered).unwrap();
    assert_eq!(&recovered[..recovered_len], ipv6.as_slice());
    let mut link_payload = vec![lichen_core::constants::L2_DISPATCH_SCHC];
    link_payload.extend_from_slice(&compressed[..compressed_len]);
    let mut wire = vec![0u8; 160];
    let length = sender
        .build_frame(1, LinkSeqNum::new(seqnum), &[], &link_payload, &mut wire)
        .unwrap();
    receiver.receive_frame(&wire[..length]).unwrap()
}

fn authenticated_dio(version: u8) -> (LinkLayer, AuthenticatedFrame) {
    authenticated_dio_options(&[0x13, 1, version])
}

fn peer_context(frame: AuthenticatedFrame) -> Result<AuthenticatedPeerSchcContext, SchcError> {
    AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
        frame,
        0,
        &DODAG_ID,
        1,
        ExpectedDioRole::Peer,
    )
}

#[test]
fn fragmentation_requires_current_owner_validated_peer_evidence() {
    let sender_identity = Identity::from_seed(Seed::new([0x11; 32]));
    let sender_iid = sender_identity.iid;
    let receiver_identity = Identity::from_seed(Seed::new([0x22; 32]));
    let mut matching_link = LinkLayer::new(receiver_identity);
    matching_link.add_peer(PeerIdentity::from_pubkey(sender_identity.pubkey));
    let sender = LinkLayer::new(sender_identity);
    let matching_frame =
        receive_dio_options(&mut matching_link, &sender, sender_iid, &[0x13, 1, 3], 1);
    let matching = peer_context(matching_frame).unwrap();
    let mut owner = FragmentationPolicy::<2>::new().unwrap();
    let permit = owner.accept_peer(&matching_link, &matching, 1).unwrap();
    for rule in [0, 7, 255] {
        let packet = [rule, 0xaa];
        let mut isolated_owner = FragmentationPolicy::<1>::new().unwrap();
        let isolated_permit = isolated_owner
            .accept_peer(&matching_link, &matching, 1)
            .unwrap();
        let _sender = FragmentSender::new(
            &isolated_owner,
            &isolated_permit,
            &matching_link,
            &matching,
            &packet,
            64,
            1,
        )
        .unwrap();
    }
    let foreign_owner = FragmentationPolicy::<2>::new().unwrap();
    assert!(matches!(
        FragmentSender::new(
            &foreign_owner,
            &permit,
            &matching_link,
            &matching,
            &[0, 1],
            64,
            1,
        ),
        Err(FragmentError::InvalidPeerEvidence)
    ));

    let other_identity = Identity::from_seed(Seed::new([0x33; 32]));
    let other_iid = other_identity.iid;
    matching_link.add_peer(PeerIdentity::from_pubkey(other_identity.pubkey));
    let other_sender = LinkLayer::new(other_identity);
    let other_frame = receive_dio_options(
        &mut matching_link,
        &other_sender,
        other_iid,
        &[0x13, 1, 3],
        1,
    );
    let other_peer = peer_context(other_frame).unwrap();
    assert!(matches!(
        FragmentSender::new(&owner, &permit, &matching_link, &other_peer, &[0, 1], 64, 1,),
        Err(FragmentError::InvalidPeerEvidence)
    ));

    let mismatched_frame =
        receive_dio_options(&mut matching_link, &sender, sender_iid, &[0x13, 1, 2], 2);
    let mismatched = peer_context(mismatched_frame).unwrap();
    assert_eq!(
        owner.accept_peer(&matching_link, &mismatched, 2),
        Err(FragmentError::VersionMismatch)
    );
    assert!(matches!(
        FragmentSender::new(&owner, &permit, &matching_link, &matching, &[0, 1], 64, 2,),
        Err(FragmentError::InvalidPeerEvidence)
    ));

    let replacement_frame =
        receive_dio_options(&mut matching_link, &sender, sender_iid, &[0x13, 1, 3], 3);
    let replacement_peer = peer_context(replacement_frame).unwrap();
    let replacement = owner
        .accept_peer(&matching_link, &replacement_peer, 3)
        .unwrap();
    let _sender = FragmentSender::new(
        &owner,
        &replacement,
        &matching_link,
        &replacement_peer,
        &[0, 1],
        64,
        3,
    )
    .unwrap();
    drop(_sender);

    let (foreign_link, foreign_frame) = authenticated_dio_options_with_link(&[0x13, 1, 3], 0x11, 4);
    let foreign_peer = peer_context(foreign_frame).unwrap();
    assert_eq!(
        owner.accept_peer(&foreign_link, &foreign_peer, 4),
        Err(FragmentError::InvalidPeerEvidence)
    );

    let authenticated_frame = matching.authenticated_frame().unwrap();
    let signer_iid = matching_link
        .pinned_pubkey_for(&authenticated_frame.sender().iid)
        .map(|_| authenticated_frame.sender().iid)
        .unwrap();
    matching_link.unpin_peer(&signer_iid);
    assert!(matches!(
        FragmentSender::new(
            &owner,
            &replacement,
            &matching_link,
            &replacement_peer,
            &[0, 1],
            64,
            4,
        ),
        Err(FragmentError::InvalidPeerEvidence)
    ));
}

#[test]
fn tracked_ingress_is_per_peer_and_capacity_fails_closed_without_eviction() {
    let (_first_link, first_frame) = authenticated_dio_options_from(&[0x13, 1, 3], 0x11);
    let (_second_link, second_frame) = authenticated_dio_options_from(&[0x13, 1, 3], 0x33);
    let first = peer_context(first_frame).unwrap();
    let second = peer_context(second_frame).unwrap();
    let mut tracker = RuleVersionFailureTracker::<2>::new(2).unwrap();
    let mut notices = Vec::new();
    let mut out = [0u8; 128];

    for peer in [&first, &second, &first] {
        let result = peer.decompress_tracked(&[8], &mut out, 128, &mut tracker, |source| {
            notices.push(*source)
        });
        assert!(matches!(result, Err(SchcError::UnknownRuleId(8))));
    }
    assert_eq!(notices, vec![*first.signer_identity()]);

    let mut bounded = RuleVersionFailureTracker::<1>::new(2).unwrap();
    assert!(matches!(
        first.decompress_tracked(&[8], &mut out, 128, &mut bounded, |_| {}),
        Err(SchcError::UnknownRuleId(8))
    ));
    assert!(matches!(
        second.decompress_tracked(&[8], &mut out, 128, &mut bounded, |_| {}),
        Err(SchcError::UnknownRuleId(8))
    ));
    assert_eq!(bounded.capacity_events(), 1);
    assert!(matches!(
        first.decompress_tracked(&[8], &mut out, 128, &mut bounded, |_| {}),
        Err(SchcError::UnknownRuleId(8))
    ));
}

fn raw_ipv6(length: usize) -> Vec<u8> {
    let mut packet = vec![0u8; length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8] = 0xfe;
    packet[9] = 0x80;
    packet[23] = 1;
    packet[24] = 0xfe;
    packet[25] = 0x80;
    packet[39] = 2;
    packet
}

#[test]
fn authenticated_dio_policy_rejects_noncanonical_options() {
    for options in [
        &[][..],
        &[0x13, 0][..],
        &[0x13, 2, 3, 3][..],
        &[0x13, 1, 3, 0x13, 1, 3][..],
        &[0x13, 2, 3][..],
    ] {
        let (_link, frame) = authenticated_dio_options(options);
        assert!(
            peer_context(frame).is_err(),
            "accepted noncanonical options {options:02x?}"
        );
    }
}

#[test]
fn authenticated_dio_policy_binds_dodag_scope() {
    let wrong_dodag = [0x42; 16];
    let (_link1, frame1) = authenticated_dio(3);
    let (_link2, frame2) = authenticated_dio(3);
    let (_link3, frame3) = authenticated_dio(3);
    let (_link4, frame4) = authenticated_dio(3);
    for result in [
        AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame1,
            1,
            &DODAG_ID,
            1,
            ExpectedDioRole::Peer,
        ),
        AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame2,
            0,
            &wrong_dodag,
            1,
            ExpectedDioRole::Peer,
        ),
        AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame3,
            0,
            &DODAG_ID,
            2,
            ExpectedDioRole::Peer,
        ),
        AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame4,
            0,
            &DODAG_ID,
            1,
            ExpectedDioRole::Root,
        ),
    ] {
        assert!(result.is_err());
    }
}

#[test]
fn every_rule_versioning_vector_executes() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/rule_versioning.json");
    let document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(document["format_version"], 2);
    let vectors = document["vectors"].as_array().unwrap();
    let mut executed = 0usize;

    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        match vector["category"].as_str().unwrap() {
            "registry" => {
                assert_eq!(
                    vector["registry_version"].as_u64().unwrap() as u8,
                    RULE_SET_VERSION,
                    "{name}"
                );
                let context = SchcContext::new(RULE_SET_V3);
                let expected_ids = vector["rule_ids"].as_array().unwrap();
                assert_eq!(context.len(), expected_ids.len(), "{name}");
                assert!(context.iter().zip(expected_ids).all(|(rule, expected)| {
                    u64::from(rule.rule_id) == expected.as_u64().unwrap()
                }));
                assert_eq!(
                    format!("{:016x}", rule_set_v3_descriptor_hash()),
                    vector["descriptor_hash"].as_str().unwrap(),
                    "{name}"
                );
                for rule_id in vector["get_present"].as_array().unwrap() {
                    assert!(
                        context.get(rule_id.as_u64().unwrap() as u8).is_some(),
                        "{name}"
                    );
                }
                for rule_id in vector["get_absent"].as_array().unwrap() {
                    assert!(
                        context.get(rule_id.as_u64().unwrap() as u8).is_none(),
                        "{name}"
                    );
                }
                for selection in vector["default_selection"].as_array().unwrap() {
                    let descriptor_rule = context
                        .get(selection["fields_from_rule"].as_u64().unwrap() as u8)
                        .unwrap();
                    let fields: Vec<(&'static str, u128)> = descriptor_rule
                        .fields
                        .iter()
                        .map(|descriptor| {
                            let value = if descriptor.mo == Mo::MatchMapping {
                                descriptor.mapping.unwrap()[0]
                            } else {
                                descriptor.target_value
                            };
                            (descriptor.field_id, value)
                        })
                        .collect();
                    assert_eq!(
                        context.select_rule(&fields).unwrap().rule_id,
                        selection["selected_rule"].as_u64().unwrap() as u8,
                        "{name}"
                    );
                }
            }
            "rule_version" => {
                if let Some(wire_hex) = vector.get("wire").and_then(|value| value.as_str()) {
                    let wire = hex_decode(wire_hex);
                    let parse_error = matches!(
                        vector.get("expect_error").and_then(|value| value.as_str()),
                        Some("truncated" | "wrong_type" | "wrong_length" | "trailing_bytes")
                    );
                    if parse_error {
                        assert!(SchcRuleVersionOption::from_bytes(&wire).is_none(), "{name}");
                    } else {
                        let option = SchcRuleVersionOption::from_bytes(&wire).expect(name);
                        assert_eq!(option.version, vector["version"].as_u64().unwrap() as u8);
                        assert_eq!(option.to_bytes().as_slice(), wire.as_slice());
                        assert_eq!(
                            SchcRuleVersionOption::local(option.version).is_some(),
                            option.version == RULE_SET_VERSION,
                            "{name}"
                        );
                    }
                }
                if let (Some(local), Some(remote)) = (
                    vector.get("local_version").and_then(|value| value.as_u64()),
                    vector
                        .get("remote_version")
                        .and_then(|value| value.as_u64()),
                ) {
                    assert_eq!(
                        versions_compatible(local as u8, remote as u8),
                        vector["expect_compatible"].as_bool().unwrap(),
                        "{name}"
                    );
                }
                if let Some(version) = vector.get("dio_version").and_then(|value| value.as_u64()) {
                    let (_link, frame) = authenticated_dio(version as u8);
                    let peer = peer_context(frame).expect(name);
                    assert_eq!(
                        peer.allows_dodag_join(),
                        vector["expect_join"].as_bool().unwrap(),
                        "{name}"
                    );
                }
                if let Some(threshold) = vector
                    .get("failure_threshold")
                    .and_then(|value| value.as_u64())
                {
                    if vector.get("failure_tracker_capacity").is_some() {
                        assert_eq!(vector["capacity_policy"], "fail_closed_no_eviction");
                        let (_first_link, first_frame) =
                            authenticated_dio_options_from(&[0x13, 1, 3], 0x11);
                        let (_second_link, second_frame) =
                            authenticated_dio_options_from(&[0x13, 1, 3], 0x33);
                        let first = peer_context(first_frame).unwrap();
                        let second = peer_context(second_frame).unwrap();
                        let sources = vector["sources"].as_array().unwrap();
                        assert_eq!(
                            first.signer_identity().as_slice(),
                            hex_decode(sources[0].as_str().unwrap())
                        );
                        assert_eq!(
                            second.signer_identity().as_slice(),
                            hex_decode(sources[1].as_str().unwrap())
                        );
                        let mut tracker =
                            RuleVersionFailureTracker::<1>::new(threshold as u16).unwrap();
                        let mut out = [0u8; 64];
                        let mut notified = false;
                        assert!(matches!(
                            first.decompress_tracked(&[8], &mut out, 64, &mut tracker, |_| {}),
                            Err(SchcError::UnknownRuleId(8))
                        ));
                        assert!(matches!(
                            second.decompress_tracked(&[8], &mut out, 64, &mut tracker, |_| {}),
                            Err(SchcError::UnknownRuleId(8))
                        ));
                        assert_eq!(tracker.capacity_events(), 1);
                        assert!(matches!(
                            first.decompress_tracked(&[8], &mut out, 64, &mut tracker, |_| {
                                notified = true
                            },),
                            Err(SchcError::UnknownRuleId(8))
                        ));
                        assert!(notified);
                        executed += 1;
                        continue;
                    }
                    assert_eq!(vector["action"], "notify_operator", "{name}");
                    let source: [u8; 32] = hex_decode(vector["source"].as_str().unwrap())
                        .try_into()
                        .unwrap();
                    let (_link, frame) = authenticated_dio(3);
                    let peer = peer_context(frame).unwrap();
                    assert_eq!(peer.signer_identity(), &source);
                    let mut tracker =
                        RuleVersionFailureTracker::<1>::new(threshold as u16).unwrap();
                    let actual: Vec<bool> = vector["expected_notifications"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|_| {
                            let mut notified = false;
                            let mut out = [0u8; 128];
                            assert!(peer
                                .decompress_tracked(&[8, 0xaa], &mut out, 128, &mut tracker, |_| {
                                    notified = true
                                },)
                                .is_err());
                            notified
                        })
                        .collect();
                    let expected: Vec<bool> = vector["expected_notifications"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_bool().unwrap())
                        .collect();
                    assert_eq!(actual, expected, "{name}");
                    let packet = raw_ipv6(40);
                    let mut compressed = [0u8; 64];
                    let compressed_len = lichen_schc::compress(&packet, &mut compressed).unwrap();
                    let mut decoded = [0u8; 64];
                    peer.decompress_tracked(
                        &compressed[..compressed_len],
                        &mut decoded,
                        64,
                        &mut tracker,
                        |_| panic!("success must not notify"),
                    )
                    .unwrap();
                    let mut notified = false;
                    assert!(peer
                        .decompress_tracked(&[8], &mut decoded, 64, &mut tracker, |_| notified =
                            true,)
                        .is_err());
                    assert_eq!(notified, threshold == 1, "{name}");
                }
                if vector.get("packet_requires_fragmentation").is_some() {
                    let (_link, frame) =
                        authenticated_dio(vector["remote_version"].as_u64().unwrap() as u8);
                    let peer = peer_context(frame).expect(name);
                    let mut out = vec![0u8; 400];
                    assert!(
                        peer.compress(&raw_ipv6(300), &mut out, 200).is_err(),
                        "{name}"
                    );
                }
            }
            "uncompressed" => {
                if let Some(packet_hex) = vector.get("packet").and_then(|value| value.as_str()) {
                    let packet = hex_decode(packet_hex);
                    let expected = hex_decode(vector["compressed"].as_str().unwrap());
                    let mut encoded = vec![0u8; expected.len()];
                    let length = encode_rule255(&packet, &mut encoded, usize::MAX).unwrap();
                    assert_eq!(&encoded[..length], expected.as_slice(), "{name}");
                    let mut decoded = vec![0u8; packet.len()];
                    let length = decode_rule255(&expected, &mut decoded, usize::MAX).unwrap();
                    assert_eq!(&decoded[..length], packet.as_slice(), "{name}");
                } else if vector.get("max_single_frame_packet").is_some() {
                    let maximum = vector["max_single_frame_packet"].as_u64().unwrap() as usize;
                    let schc_limit = vector["schc_packet_limit"].as_u64().unwrap() as usize;
                    let packet = raw_ipv6(maximum);
                    let mut encoded = vec![0u8; schc_limit];
                    assert_eq!(
                        encode_rule255(&packet, &mut encoded, schc_limit).unwrap(),
                        schc_limit
                    );
                } else if vector.get("scenario").is_some() {
                    let (_link, frame) =
                        authenticated_dio(vector["remote_version"].as_u64().unwrap() as u8);
                    let peer = peer_context(frame).expect(name);
                    let packet = raw_ipv6(40);
                    let mut encoded = [0u8; 64];
                    let length = peer.compress(&packet, &mut encoded, 64).unwrap();
                    assert_eq!(&encoded[..length], [&[0xff], packet.as_slice()].concat());
                } else {
                    let packet = raw_ipv6(vector["packet_size"].as_u64().unwrap() as usize);
                    let mut encoded = vec![0u8; packet.len() + 1];
                    assert!(encode_rule255(
                        &packet,
                        &mut encoded,
                        vector["single_frame_limit"].as_u64().unwrap() as usize,
                    )
                    .is_err());
                }
            }
            "rejection" => {
                let wire = hex_decode(vector.get("wire").and_then(|v| v.as_str()).unwrap_or(""));
                let mut output = [0u8; 1500];
                if vector.get("scenario").is_some() {
                    let mut invalid = [0u8; 41];
                    invalid[0] = 0xff;
                    invalid[1] = 0x40;
                    assert!(
                        decode_rule255(&invalid, &mut output, usize::MAX).is_err(),
                        "{name}"
                    );
                } else {
                    assert!(
                        lichen_schc::decompress(&wire, &mut output).is_err(),
                        "{name}"
                    );
                }
            }
            category => panic!("{name}: unhandled rule_versioning category {category}"),
        }
        executed += 1;
    }
    assert_eq!(executed, vectors.len());
}
