//! Tests against shared test vectors from test/vectors/schc_adaptation.json
//!
//! These vectors cover security-critical unknown rule ID rejection (P0),
//! Rule 255 uncompressed fallback, port boundary compression, and fragmentation
//! control messages for both directions (rules 0x78 and 0x79).

use std::fs;
use std::path::Path;

use lichen_schc::fragment::{canonical_fragmentation_rule, Ack, FragmentError, WINDOW_SIZE};
use serde::Deserialize;

#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
use lichen_schc::fragment::{Fragment, ReceiverResponse, TILE_SIZE};

#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
use lichen_schc::fragment::{AuthenticatedFragmentReceiver, FragmentSender, FragmentationPolicy};
#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
use lichen_schc::{ExpectedDioRole, PeerContextAuthority};

#[derive(Deserialize)]
struct ExpectedCounts {
    p0: usize,
    endpoint_direction: usize,
    rule7_address_policy: usize,
    #[cfg_attr(
        not(all(feature = "raw-fragment-codec", feature = "test-utils")),
        allow(dead_code)
    )]
    duplicate_idempotence: usize,
}

#[derive(Deserialize)]
struct VectorFile {
    format_version: u32,
    expected_counts: ExpectedCounts,
    vectors: Vec<AdaptationVector>,
}

#[derive(Deserialize)]
struct AdaptationVector {
    name: String,
    category: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    wire: Option<String>,
    #[serde(default)]
    packet: Option<String>,
    #[serde(default)]
    compressed: Option<String>,
    #[serde(default)]
    compressed_size: Option<usize>,
    #[serde(default)]
    rule_id: Option<u8>,
    #[serde(default)]
    expect_error: Option<String>,
    #[serde(default)]
    expect_rule_id: Option<u8>,
    #[serde(default)]
    message_type: Option<String>,
    #[serde(default)]
    window: Option<u8>,
    #[serde(default)]
    c_bit: Option<u8>,
    #[serde(default)]
    assigned_fcns: Option<Vec<u8>>,
    #[serde(default)]
    received_bitmap_bits: Option<String>,
    #[serde(default)]
    unassigned_zero_bits: Option<usize>,
    #[serde(default)]
    final_all_1_received: Option<bool>,
    #[serde(default)]
    received_bitmap_prefix_bits: Option<String>,
    #[serde(default)]
    trailing_received_bits: Option<usize>,
    #[serde(default)]
    version: Option<u8>,
    #[serde(default)]
    option_type: Option<u8>,
    #[serde(default)]
    option_length: Option<u8>,
    #[serde(default)]
    query_type: Option<u8>,
    #[serde(default)]
    response_type: Option<u8>,
    #[serde(default)]
    flags: Option<u8>,
    #[serde(default)]
    status: Option<u8>,
    #[serde(default)]
    local_version: Option<u8>,
    #[serde(default)]
    remote_version: Option<u8>,
    #[serde(default)]
    residue_bits: Option<usize>,
    #[serde(default)]
    padding_bits: Option<usize>,
    #[serde(default)]
    local_public_key_hex: Option<String>,
    #[serde(default)]
    peer_public_key_hex: Option<String>,
    #[serde(default)]
    local_endpoint: Option<String>,
    #[serde(default)]
    message_origin: Option<String>,
    #[serde(default)]
    data_sender_endpoint: Option<String>,
    #[serde(default)]
    expect_accept: Option<bool>,
    #[serde(default)]
    expect_state_mutation: Option<bool>,
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    #[serde(default)]
    t_value: Option<u8>,
    #[serde(default)]
    scenario: Option<String>,
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    #[serde(default)]
    expect_duplicate_discarded: Option<bool>,
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    #[serde(default)]
    expect_reassembly_reset: Option<bool>,
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    #[serde(default)]
    expect_tile_state_mutation: Option<bool>,
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    #[serde(default)]
    expect_high_water_counter_advanced: Option<bool>,
    #[serde(default)]
    source_ipv6: Option<String>,
    #[serde(default)]
    destination_ipv6: Option<String>,
    #[serde(default)]
    expect_valid: Option<bool>,
    #[serde(default)]
    source_encoding: Option<String>,
    #[serde(default)]
    destination_encoding: Option<String>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    if !s.len().is_multiple_of(2) {
        panic!("hex_decode: odd-length hex string (len={})", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rule7_udp_packet(source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
    let payload = [0x01, 0x00];
    let source_port = 10883u16;
    let destination_port = 61616u16;
    let udp_len = 8 + payload.len();
    let mut udp = vec![0u8; udp_len];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(&payload);
    let checksum = lichen_core::checksum::upper_layer_checksum(&source, &destination, 17, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = vec![0u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40..].copy_from_slice(&udp);
    packet
}

#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
fn vector_peer_authority(
    local_signer: [u8; 32],
    peer_signer: [u8; 32],
) -> (
    PeerContextAuthority<1>,
    lichen_schc::AuthenticatedPeerSchcContext,
    [u8; 8],
    [u8; 8],
) {
    use core::sync::atomic::AtomicBool;
    use lichen_link::{frame::AddrMode, AuthenticatedLinkFrame, LinkSeqNum, ReceiptEvidence};

    const DODAG_ID: [u8; 16] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let local_iid = lichen_core::addr::iid_from_pubkey_bytes(&local_signer);
    let peer_iid = lichen_core::addr::iid_from_pubkey_bytes(&peer_signer);
    let mut local_eui = local_iid;
    local_eui[0] ^= 0x02;

    let mut source = [0u8; 16];
    source[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    source[8..].copy_from_slice(&peer_iid);
    let mut destination = [0u8; 16];
    destination[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    destination[8..].copy_from_slice(&local_iid);

    let mut dio = vec![0u8; 27];
    dio[2..4].copy_from_slice(&512u16.to_be_bytes());
    dio[4] = 1 << 3;
    dio[8..24].copy_from_slice(&DODAG_ID);
    dio[24..].copy_from_slice(&[0x13, 1, lichen_schc::rules::RULE_SET_VERSION]);
    let mut icmp = vec![155, 1, 0, 0];
    icmp.extend_from_slice(&dio);
    let checksum = lichen_core::checksum::upper_layer_checksum(&source, &destination, 58, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut ipv6 = vec![0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6[6] = 58;
    ipv6[7] = 255;
    ipv6[8..24].copy_from_slice(&source);
    ipv6[24..40].copy_from_slice(&destination);
    ipv6.extend_from_slice(&icmp);
    let mut compressed = [0u8; 128];
    let compressed_len = lichen_schc::compress(&ipv6, &mut compressed).unwrap();
    let mut link_payload = vec![lichen_core::constants::L2_DISPATCH_SCHC];
    link_payload.extend_from_slice(&compressed[..compressed_len]);

    let receiving_link_retired = AtomicBool::new(false);
    let peer_generation_retired = AtomicBool::new(false);
    let mut peer_eui64 = peer_iid;
    peer_eui64[0] ^= 0x02;
    let evidence = AuthenticatedLinkFrame::from_test_parts(
        &link_payload,
        &local_eui,
        AddrMode::Extended,
        peer_signer,
        peer_eui64,
        0,
        LinkSeqNum::new(1),
        ReceiptEvidence::from_test_parts(7, 1, Some(1)),
        lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
        lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
        &receiving_link_retired,
        &peer_generation_retired,
    );
    let mut authority = PeerContextAuthority::<1>::new(local_signer).unwrap();
    let peer = authority
        .issue_from_authenticated_dio(evidence, 0, &DODAG_ID, 1, ExpectedDioRole::Peer)
        .unwrap();
    (authority, peer, local_eui, peer_iid)
}

#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
fn authenticated_fragment<'a>(
    payload: &'a [u8],
    local_eui: &'a [u8; 8],
    peer_signer: [u8; 32],
    peer_iid: [u8; 8],
    counter: u16,
    receiving_link_retired: &'a core::sync::atomic::AtomicBool,
    peer_generation_retired: &'a core::sync::atomic::AtomicBool,
) -> lichen_link::AuthenticatedLinkFrame<'a> {
    let mut peer_eui64 = peer_iid;
    peer_eui64[0] ^= 0x02;
    lichen_link::AuthenticatedLinkFrame::from_test_parts(
        payload,
        local_eui,
        lichen_link::frame::AddrMode::Extended,
        peer_signer,
        peer_eui64,
        0,
        lichen_link::LinkSeqNum::new(counter),
        lichen_link::ReceiptEvidence::from_test_parts(
            7,
            u64::from(counter),
            Some(u64::from(counter)),
        ),
        lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
        lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
        receiving_link_retired,
        peer_generation_retired,
    )
}

#[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
fn execute_endpoint_direction(vector: &AdaptationVector) -> Result<(), String> {
    use core::sync::atomic::AtomicBool;

    let local: [u8; 32] = hex_decode(
        vector
            .local_public_key_hex
            .as_deref()
            .ok_or("missing local public key")?,
    )
    .try_into()
    .map_err(|_| "local public key is not 32 bytes")?;
    let peer_signer: [u8; 32] = hex_decode(
        vector
            .peer_public_key_hex
            .as_deref()
            .ok_or("missing peer public key")?,
    )
    .try_into()
    .map_err(|_| "peer public key is not 32 bytes")?;
    let supplied_rule = vector.rule_id.ok_or("missing rule ID")?;
    let (authority, peer, local_eui, peer_iid) = vector_peer_authority(local, peer_signer);
    let mut policy = FragmentationPolicy::<1>::new().map_err(|error| format!("{error:?}"))?;
    let empty = policy.snapshot_for_tests();
    let permit_result = policy.accept_peer_with_authority(&authority, &peer, 1);

    if local == peer_signer {
        if permit_result != Err(FragmentError::InvalidPeerEvidence)
            || policy.snapshot_for_tests() != empty
        {
            return Err("equal endpoint keys mutated or were admitted by policy".into());
        }
        return Ok(());
    }

    let permit = permit_result.map_err(|error| format!("peer admission failed: {error:?}"))?;
    let receiving_link_retired = AtomicBool::new(false);
    let peer_generation_retired = AtomicBool::new(false);
    let inbound_rule = policy
        .inbound_rule(&permit)
        .map_err(|error| format!("inbound direction failed: {error:?}"))?;

    if vector.expect_accept == Some(false) {
        let mut storage = [0u8; lichen_schc::fragment::MAX_PACKET_SIZE];
        let mut receiver = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut storage,
            1,
        )
        .map_err(|error| format!("receiver reservation failed: {error:?}"))?;
        let tile = [0x23; TILE_SIZE];
        let wrong = Fragment {
            rule_id: supplied_rule,
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; 4],
        };
        let mut wrong_wire = [0u8; TILE_SIZE + 2];
        let wrong_len = wrong
            .write_to(&mut wrong_wire)
            .map_err(|error| format!("wrong fragment encode failed: {error:?}"))?;
        let before = policy.snapshot_for_tests();
        let wrong_input = authenticated_fragment(
            &wrong_wire[..wrong_len],
            &local_eui,
            peer_signer,
            peer_iid,
            2,
            &receiving_link_retired,
            &peer_generation_retired,
        );
        if receiver.receive_link_verified(&policy, &authority, &peer, wrong_input)
            != Err(FragmentError::InvalidPeerEvidence)
            || policy.snapshot_for_tests() != before
        {
            return Err("wrong-direction input mutated policy/session high-water".into());
        }

        // Reuse the same authenticated counter with the canonical rule. Its
        // success proves the rejected rule consumed neither receiver nor
        // policy replay/high-water state.
        let correct = Fragment {
            rule_id: inbound_rule,
            ..wrong
        };
        let mut correct_wire = [0u8; TILE_SIZE + 2];
        let correct_len = correct
            .write_to(&mut correct_wire)
            .map_err(|error| format!("correct fragment encode failed: {error:?}"))?;
        let correct_input = authenticated_fragment(
            &correct_wire[..correct_len],
            &local_eui,
            peer_signer,
            peer_iid,
            2,
            &receiving_link_retired,
            &peer_generation_retired,
        );
        receiver
            .receive_link_verified(&policy, &authority, &peer, correct_input)
            .map_err(|error| format!("canonical retry failed after rejection: {error:?}"))?;
        let after = policy.snapshot_for_tests();
        if after.max_receiver_high_counter != Some(2) || after == before {
            return Err("canonical retry did not advance receiver high-water".into());
        }
        return Ok(());
    }

    match vector.message_type.as_deref() {
        Some("data") => {
            let before = policy.snapshot_for_tests();
            let payload = [0x42];
            let sender = FragmentSender::new_with_authority(
                &policy,
                &permit,
                &authority,
                &peer,
                &payload,
                payload.len(),
                1,
            )
            .map_err(|error| format!("sender reservation failed: {error:?}"))?;
            let after = policy.snapshot_for_tests();
            if sender.rule_id() != supplied_rule
                || after == before
                || after.sender_session_count != before.sender_session_count + 1
            {
                return Err("accepted data did not reserve the derived sender session".into());
            }
        }
        Some("ack") | Some("receiver_abort") => {
            let mut storage = [0u8; lichen_schc::fragment::MAX_PACKET_SIZE];
            let mut receiver = AuthenticatedFragmentReceiver::new_with_authority(
                &policy,
                &permit,
                &authority,
                &peer,
                &mut storage,
                1,
            )
            .map_err(|error| format!("receiver reservation failed: {error:?}"))?;
            if inbound_rule != supplied_rule {
                return Err("reverse control does not retain the inbound data rule".into());
            }
            if vector.message_type.as_deref() == Some("ack") {
                // T=0 ACK/control cannot allocate a session. Model the
                // vector's stated accepted A-to-B data first, using the sole
                // canonical W=0/FCN=62 opener, then request its ACK.
                let first_tile = [0x23; TILE_SIZE];
                let first = Fragment {
                    rule_id: inbound_rule,
                    window: 0,
                    fcn: 62,
                    payload: &first_tile,
                    mic: [0; 4],
                };
                let mut first_wire = [0u8; TILE_SIZE + 2];
                let first_len = first.write_to(&mut first_wire).unwrap();
                let first_input = authenticated_fragment(
                    &first_wire[..first_len],
                    &local_eui,
                    peer_signer,
                    peer_iid,
                    2,
                    &receiving_link_retired,
                    &peer_generation_retired,
                );
                receiver
                    .receive_link_verified(&policy, &authority, &peer, first_input)
                    .map_err(|error| format!("first receiver tile failed: {error:?}"))?;
                let before = policy.snapshot_for_tests();
                let request = [inbound_rule, 0x00];
                let input = authenticated_fragment(
                    &request,
                    &local_eui,
                    peer_signer,
                    peer_iid,
                    3,
                    &receiving_link_retired,
                    &peer_generation_retired,
                );
                let result = receiver
                    .receive_link_verified(&policy, &authority, &peer, input)
                    .map_err(|error| format!("ACK request failed: {error:?}"))?;
                if !matches!(result.response, Some(ReceiverResponse::Ack(ack)) if ack.rule_id == supplied_rule)
                {
                    return Err("receiver did not emit ACK under retained data rule".into());
                }
                if policy.snapshot_for_tests() == before {
                    return Err("accepted ACK request did not advance session state".into());
                }
            } else {
                let before = policy.snapshot_for_tests();
                let first_tile = [0x23; TILE_SIZE];
                let first = Fragment {
                    rule_id: inbound_rule,
                    window: 0,
                    fcn: 62,
                    payload: &first_tile,
                    mic: [0; 4],
                };
                let mut first_wire = [0u8; TILE_SIZE + 2];
                let first_len = first.write_to(&mut first_wire).unwrap();
                let first_input = authenticated_fragment(
                    &first_wire[..first_len],
                    &local_eui,
                    peer_signer,
                    peer_iid,
                    2,
                    &receiving_link_retired,
                    &peer_generation_retired,
                );
                receiver
                    .receive_link_verified(&policy, &authority, &peer, first_input)
                    .map_err(|error| format!("first receiver tile failed: {error:?}"))?;

                let conflicting_tile = [0x5a; TILE_SIZE];
                let conflicting = Fragment {
                    payload: &conflicting_tile,
                    ..first
                };
                let mut conflict_wire = [0u8; TILE_SIZE + 2];
                let conflict_len = conflicting.write_to(&mut conflict_wire).unwrap();
                let conflict_input = authenticated_fragment(
                    &conflict_wire[..conflict_len],
                    &local_eui,
                    peer_signer,
                    peer_iid,
                    3,
                    &receiving_link_retired,
                    &peer_generation_retired,
                );
                let result = receiver
                    .receive_link_verified(&policy, &authority, &peer, conflict_input)
                    .map_err(|error| format!("conflicting tile transition failed: {error:?}"))?;
                if !result.aborted
                    || result.response
                        != Some(ReceiverResponse::ReceiverAbort {
                            rule_id: supplied_rule,
                        })
                {
                    return Err("receiver did not abort under retained data rule".into());
                }
                let after = policy.snapshot_for_tests();
                if after == before
                    || after.max_receiver_high_counter <= before.max_receiver_high_counter
                {
                    return Err(
                        "accepted reverse control path did not mutate session high-water".into(),
                    );
                }
            }
        }
        other => return Err(format!("unsupported endpoint message type {other:?}")),
    }
    Ok(())
}

#[test]
fn test_schc_adaptation_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schc_adaptation.json");

    if !vectors_path.exists() {
        // SECURITY: These vectors include P0 security-critical tests.
        // In CI, fail hard so missing vectors are never silently ignored.
        if std::env::var("CI").is_ok() {
            panic!(
                "Vectors file not found at {:?}. P0 security vectors must be present in CI.",
                vectors_path
            );
        }
        eprintln!(
            "WARNING: Vectors file not found at {:?}, skipping. \
             Set CI=1 to require vectors.",
            vectors_path
        );
        return;
    }

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vectors: VectorFile = serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );

    let mut failures = Vec::new();
    let mut p0_count = 0;
    let mut endpoint_direction_count = 0;
    let mut rule7_address_policy_count = 0;
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    let mut duplicate_idempotence_count = 0;

    for vector in &vectors.vectors {
        let name = &vector.name;
        let category = &vector.category;

        if vector.priority.as_deref() == Some("P0") {
            p0_count += 1;
        }

        match category.as_str() {
            "rejection" => {
                // P0 security-critical: unknown rule IDs must reject cleanly
                let wire = vector.wire.as_deref().map(hex_decode).unwrap_or_default();

                if vector.expect_error.as_deref() == Some("unknown_rule_id") {
                    // SECURITY: Do not default to 0 - rule 0 (RULE_LINK_LOCAL_COAP) is valid.
                    // Missing expect_rule_id in a vector would silently pass if the rejected
                    // rule happened to be 0. Force proper vector configuration instead.
                    let expected_rule_id = vector
                        .expect_rule_id
                        .expect("unknown_rule_id rejection vector must specify expect_rule_id");

                    // Test decompress rejects unknown rule ID
                    let mut out = [0u8; 1500];
                    match lichen_schc::decompress(&wire, &mut out) {
                        Ok(_) => {
                            failures.push(format!(
                                "{}: expected UnknownRuleId error for rule {}",
                                name, expected_rule_id
                            ));
                        }
                        Err(lichen_schc::SchcError::UnknownRuleId(id)) => {
                            if id != expected_rule_id {
                                failures.push(format!(
                                    "{}: expected rule ID {}, got {}",
                                    name, expected_rule_id, id
                                ));
                            } else {
                                println!(
                                    "Vector '{}' (P0 rejection): correctly rejected rule {}",
                                    name, id
                                );
                            }
                        }
                        Err(e) => {
                            failures.push(format!("{}: expected UnknownRuleId, got {:?}", name, e));
                        }
                    }
                } else if vector.expect_error.as_deref() == Some("empty_packet") {
                    // Empty packet should error
                    let mut out = [0u8; 1500];
                    match lichen_schc::decompress(&wire, &mut out) {
                        Ok(_) => {
                            failures.push(format!("{}: expected error for empty packet", name));
                        }
                        Err(_) => {
                            println!(
                                "Vector '{}' (P0 rejection): correctly rejected empty packet",
                                name
                            );
                        }
                    }
                }
            }

            "uncompressed" => {
                // Rule 255 uncompressed fallback tests
                let packet = hex_decode(vector.packet.as_deref().unwrap_or(""));
                let compressed = hex_decode(vector.compressed.as_deref().unwrap_or(""));
                let expected_size = vector.compressed_size.unwrap_or(0);

                if compressed.is_empty() {
                    failures.push(format!("{}: empty compressed data", name));
                    continue;
                }

                if compressed[0] != 255 {
                    failures.push(format!(
                        "{}: expected Rule 255 prefix, got {}",
                        name, compressed[0]
                    ));
                }

                if compressed.len() != expected_size {
                    failures.push(format!(
                        "{}: compressed size mismatch: expected {}, got {}",
                        name,
                        expected_size,
                        compressed.len()
                    ));
                }

                // Verify decompression
                let mut out = [0u8; 1500];
                match lichen_schc::decompress(&compressed, &mut out) {
                    Ok(n) => {
                        if &out[..n] != packet.as_slice() {
                            failures.push(format!(
                                "{}: decompress mismatch: expected {} bytes, got {}",
                                name,
                                packet.len(),
                                n
                            ));
                        } else {
                            println!(
                                "Vector '{}' (Rule 255): {} -> {} bytes",
                                name,
                                compressed.len(),
                                n
                            );
                        }
                    }
                    Err(e) => {
                        failures.push(format!("{}: decompress failed: {:?}", name, e));
                    }
                }
            }

            "fragmentation_direction" => {
                // Rule 0x79 B-to-A direction vectors
                let wire = hex_decode(vector.wire.as_deref().unwrap_or(""));
                let rule_id = vector.rule_id.unwrap_or(0);

                if wire.is_empty() {
                    failures.push(format!("{}: empty wire data", name));
                    continue;
                }

                if wire[0] != rule_id {
                    failures.push(format!(
                        "{}: rule ID mismatch: expected {}, got {}",
                        name, rule_id, wire[0]
                    ));
                } else {
                    println!("Vector '{}' (frag rule {}): wire format OK", name, rule_id);
                }
                if let Some(window) = vector.window {
                    let parsed_window = wire[1] >> 7;
                    if parsed_window != window {
                        failures.push(format!(
                            "{}: window mismatch: expected {}, got {}",
                            name, window, parsed_window
                        ));
                    }
                }
            }

            "fragmentation_endpoint_direction" => {
                endpoint_direction_count += 1;
                let local: [u8; 32] = hex_decode(
                    vector
                        .local_public_key_hex
                        .as_deref()
                        .expect("endpoint direction vector local key"),
                )
                .try_into()
                .expect("32-byte local public key");
                let peer: [u8; 32] = hex_decode(
                    vector
                        .peer_public_key_hex
                        .as_deref()
                        .expect("endpoint direction vector peer key"),
                )
                .try_into()
                .expect("32-byte peer public key");
                let supplied_rule = vector.rule_id.expect("endpoint direction rule ID");
                let expect_accept = vector
                    .expect_accept
                    .expect("endpoint direction acceptance result");
                let message_origin = vector
                    .message_origin
                    .as_deref()
                    .expect("endpoint direction message origin");
                let message_type = vector
                    .message_type
                    .as_deref()
                    .expect("endpoint direction message type");

                let local_label = match local.cmp(&peer) {
                    std::cmp::Ordering::Less => Some("A"),
                    std::cmp::Ordering::Greater => Some("B"),
                    std::cmp::Ordering::Equal => None,
                };
                if vector.local_endpoint.as_deref() != local_label {
                    failures.push(format!(
                        "{}: endpoint label mismatch: expected {:?}, derived {:?}",
                        name, vector.local_endpoint, local_label
                    ));
                }

                let control_is_data_direction =
                    matches!(message_type, "data" | "ack_request" | "sender_abort");
                let control_is_local = message_origin == "local";
                let data_is_outbound = if control_is_data_direction {
                    control_is_local
                } else {
                    !control_is_local
                };
                let derived = canonical_fragmentation_rule(&local, &peer, data_is_outbound);

                if let Some(data_sender_endpoint) = vector.data_sender_endpoint.as_deref() {
                    let expected_sender = if data_is_outbound {
                        local_label
                    } else {
                        match local_label {
                            Some("A") => Some("B"),
                            Some("B") => Some("A"),
                            _ => None,
                        }
                    };
                    if Some(data_sender_endpoint) != expected_sender {
                        failures.push(format!(
                            "{}: data sender endpoint mismatch: expected {:?}, derived {:?}",
                            name, data_sender_endpoint, expected_sender
                        ));
                    }
                }

                match (expect_accept, derived) {
                    (true, Ok(rule)) if rule == supplied_rule => {
                        if vector.expect_state_mutation != Some(true) {
                            failures.push(format!(
                                "{}: accepted direction vector must expect state mutation",
                                name
                            ));
                        }
                    }
                    (false, Ok(rule)) if rule != supplied_rule => {
                        if vector.expect_error.as_deref() != Some("wrong_direction_rule")
                            || vector.expect_state_mutation != Some(false)
                        {
                            failures.push(format!(
                                "{}: wrong-direction rejection metadata is inconsistent",
                                name
                            ));
                        }
                    }
                    (false, Err(FragmentError::InvalidPeerEvidence)) if local == peer => {
                        if vector.expect_error.as_deref() != Some("equal_endpoint_keys")
                            || vector.expect_state_mutation != Some(false)
                        {
                            failures.push(format!(
                                "{}: equal-key rejection metadata is inconsistent",
                                name
                            ));
                        }
                    }
                    (_, result) => failures.push(format!(
                        "{}: direction result {:?} does not match supplied rule {:#04x} and acceptance {}",
                        name, result, supplied_rule, expect_accept
                    )),
                }

                #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
                if let Err(error) = execute_endpoint_direction(vector) {
                    failures.push(format!("{}: {error}", name));
                }
            }

            "single_active"
                if vector.scenario.as_deref() == Some("receive_tile_0_then_tile_0_again") =>
            {
                #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
                {
                    duplicate_idempotence_count += 1;
                    if vector.t_value != Some(0)
                        || vector.expect_duplicate_discarded != Some(true)
                        || vector.expect_reassembly_reset != Some(false)
                        || vector.expect_tile_state_mutation != Some(false)
                        || vector.expect_high_water_counter_advanced != Some(true)
                    {
                        failures.push(format!(
                            "{}: duplicate-tile vector metadata is inconsistent",
                            name
                        ));
                        continue;
                    }

                    let rule_id = vector.rule_id.expect("duplicate tile rule ID");
                    let local_signer = [0x22; 32];
                    let peer_signer = [0x11; 32];
                    let (authority, peer, local_eui, peer_iid) =
                        vector_peer_authority(local_signer, peer_signer);
                    let mut policy = FragmentationPolicy::<1>::new().unwrap();
                    let permit = policy
                        .accept_peer_with_authority(&authority, &peer, 1)
                        .unwrap();
                    if policy.inbound_rule(&permit) != Ok(rule_id) {
                        failures.push(format!(
                            "{}: duplicate vector rule is not canonical inbound rule",
                            name
                        ));
                        continue;
                    }
                    let mut storage = [0u8; lichen_schc::fragment::MAX_PACKET_SIZE];
                    let mut receiver = AuthenticatedFragmentReceiver::new_with_authority(
                        &policy,
                        &permit,
                        &authority,
                        &peer,
                        &mut storage,
                        1,
                    )
                    .unwrap();
                    let tile = [0xa5; TILE_SIZE];
                    let regular = Fragment {
                        rule_id,
                        window: 0,
                        fcn: 62,
                        payload: &tile,
                        mic: [0; 4],
                    };
                    let mut regular_wire = [0u8; TILE_SIZE + 2];
                    let regular_len = regular.write_to(&mut regular_wire).unwrap();
                    let receiving_link_retired = core::sync::atomic::AtomicBool::new(false);
                    let peer_generation_retired = core::sync::atomic::AtomicBool::new(false);
                    let first = authenticated_fragment(
                        &regular_wire[..regular_len],
                        &local_eui,
                        peer_signer,
                        peer_iid,
                        2,
                        &receiving_link_retired,
                        &peer_generation_retired,
                    );
                    if receiver.receive_link_verified(&policy, &authority, &peer, first)
                        != Ok(Default::default())
                    {
                        failures.push(format!("{}: first tile was not accepted", name));
                        continue;
                    }
                    let before_duplicate = policy.snapshot_for_tests();
                    let duplicate = authenticated_fragment(
                        &regular_wire[..regular_len],
                        &local_eui,
                        peer_signer,
                        peer_iid,
                        3,
                        &receiving_link_retired,
                        &peer_generation_retired,
                    );
                    if receiver.receive_link_verified(&policy, &authority, &peer, duplicate)
                        != Ok(Default::default())
                    {
                        failures.push(format!(
                            "{}: exact duplicate was not discarded idempotently",
                            name
                        ));
                    }
                    let after_duplicate = policy.snapshot_for_tests();
                    if before_duplicate.receiver_session_count
                        != after_duplicate.receiver_session_count
                        || before_duplicate.receiver_tombstone_count
                            != after_duplicate.receiver_tombstone_count
                        || before_duplicate.max_receiver_high_counter != Some(2)
                        || after_duplicate.max_receiver_high_counter != Some(3)
                    {
                        failures.push(format!(
                            "{}: duplicate did not preserve session while advancing high-water",
                            name
                        ));
                    }

                    // A conflicting retransmission of the same ordinal must
                    // still see the retained first tile and terminate rather
                    // than proving that the duplicate reset reassembly state.
                    let conflicting_tile = [0x5a; TILE_SIZE];
                    let conflicting = Fragment {
                        payload: &conflicting_tile,
                        ..regular
                    };
                    let mut conflict_wire = [0u8; TILE_SIZE + 2];
                    let conflict_len = conflicting.write_to(&mut conflict_wire).unwrap();
                    let conflict_input = authenticated_fragment(
                        &conflict_wire[..conflict_len],
                        &local_eui,
                        peer_signer,
                        peer_iid,
                        4,
                        &receiving_link_retired,
                        &peer_generation_retired,
                    );
                    let conflict = receiver
                        .receive_link_verified(&policy, &authority, &peer, conflict_input)
                        .unwrap();
                    if !conflict.aborted
                        || conflict.response != Some(ReceiverResponse::ReceiverAbort { rule_id })
                    {
                        failures.push(format!(
                            "{}: conflicting same-ordinal tile did not terminate retained session",
                            name
                        ));
                    }
                }

                #[cfg(not(all(feature = "raw-fragment-codec", feature = "test-utils")))]
                println!(
                    "Vector '{}' duplicate transition requires raw-fragment-codec + test-utils",
                    name
                );
            }

            "rule7_address_policy" => {
                use std::net::Ipv6Addr;
                use std::str::FromStr;

                rule7_address_policy_count += 1;
                let source = Ipv6Addr::from_str(
                    vector
                        .source_ipv6
                        .as_deref()
                        .expect("Rule 7 vector source address"),
                )
                .expect("valid Rule 7 source literal")
                .octets();
                let destination = Ipv6Addr::from_str(
                    vector
                        .destination_ipv6
                        .as_deref()
                        .expect("Rule 7 vector destination address"),
                )
                .expect("valid Rule 7 destination literal")
                .octets();
                let expect_valid = vector.expect_valid.expect("Rule 7 validity result");

                let link_local_mode = source[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
                    && destination[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0];
                for (label, expected_encoding) in [
                    ("source", vector.source_encoding.as_deref()),
                    ("destination", vector.destination_encoding.as_deref()),
                ] {
                    if let Some(expected_encoding) = expected_encoding {
                        let derived_encoding = if link_local_mode {
                            "link_local_iid"
                        } else {
                            "full"
                        };
                        if derived_encoding != expected_encoding {
                            failures.push(format!(
                                "{}: {} encoding expected {}, derived {}",
                                name, label, expected_encoding, derived_encoding
                            ));
                        }
                    }
                }

                let packet = rule7_udp_packet(source, destination);
                let mut compressed = [0u8; 512];
                match (
                    expect_valid,
                    lichen_schc::compress(&packet, &mut compressed),
                ) {
                    (true, Ok(length)) => {
                        if compressed[0] != lichen_core::constants::RULE_MQTT_SN {
                            failures.push(format!(
                                "{}: valid Rule 7 address pair selected rule {}",
                                name, compressed[0]
                            ));
                            continue;
                        }
                        let encoded_full_mode = compressed[2] & 0x80 != 0;
                        if encoded_full_mode == link_local_mode {
                            failures.push(format!(
                                "{}: Rule 7 residue selected the wrong shared address mode",
                                name
                            ));
                        }
                        let mut decoded = [0u8; 512];
                        match lichen_schc::decompress(&compressed[..length], &mut decoded) {
                            Ok(decoded_len) if decoded[..decoded_len] == packet => {}
                            Ok(_) => failures.push(format!(
                                "{}: valid Rule 7 address pair did not round-trip",
                                name
                            )),
                            Err(error) => failures.push(format!(
                                "{}: valid Rule 7 residue rejected: {:?}",
                                name, error
                            )),
                        }
                    }
                    (false, Err(lichen_schc::SchcError::InvalidPacket(actual))) => {
                        let expected = match vector.expect_error.as_deref() {
                            Some("invalid_source_address") => "invalid IPv6 source address",
                            Some("invalid_destination_address") => {
                                "invalid IPv6 destination address"
                            }
                            Some("invalid_destination_scope") => {
                                "invalid IPv6 destination multicast scope"
                            }
                            other => {
                                failures.push(format!(
                                    "{}: unknown Rule 7 rejection token {:?}",
                                    name, other
                                ));
                                continue;
                            }
                        };
                        if actual != expected {
                            failures.push(format!(
                                "{}: expected error {:?}, got {:?}",
                                name, expected, actual
                            ));
                        }
                    }
                    (true, Err(error)) => failures.push(format!(
                        "{}: valid Rule 7 address pair rejected: {:?}",
                        name, error
                    )),
                    (false, Ok(_)) => failures.push(format!(
                        "{}: invalid Rule 7 address pair was accepted",
                        name
                    )),
                    (false, Err(error)) => failures.push(format!(
                        "{}: invalid Rule 7 address pair returned wrong error: {:?}",
                        name, error
                    )),
                }
            }

            "rule_version" => {
                // SCHC Rule Version Option tests
                if let Some(wire_hex) = &vector.wire {
                    let wire = hex_decode(wire_hex);
                    let flags = vector.flags.unwrap_or(0);

                    if let Some(response_type) = vector.response_type {
                        // Version Response: Type(1) + Version(1) + Status(1) + Flags(1)
                        // For negotiation flows, wire contains remote_version; else use version
                        let version = vector.remote_version.or(vector.version).unwrap_or(0);
                        let status = vector.status.unwrap_or(0);
                        if wire.len() != 4 {
                            failures.push(format!(
                                "{}: expected 4-byte response, got {} bytes",
                                name,
                                wire.len()
                            ));
                        } else if wire[0] != response_type {
                            failures.push(format!(
                                "{}: response type mismatch: expected {}, got {}",
                                name, response_type, wire[0]
                            ));
                        } else if wire[1] != version {
                            failures.push(format!(
                                "{}: version mismatch: expected {}, got {}",
                                name, version, wire[1]
                            ));
                        } else if wire[2] != status {
                            failures.push(format!(
                                "{}: status mismatch: expected {}, got {}",
                                name, status, wire[2]
                            ));
                        } else if wire[3] != flags {
                            failures.push(format!(
                                "{}: flags mismatch: expected {}, got {}",
                                name, flags, wire[3]
                            ));
                        } else {
                            println!(
                                "Vector '{}' (rule version {}): wire format OK",
                                name, version
                            );
                        }
                    } else if let Some(query_type) = vector.query_type {
                        // Version Query: Type(1) + Version(1) + Flags(1)
                        // For queries, use local_version (the version we're advertising) or version
                        let version = vector.local_version.or(vector.version).unwrap_or(0);
                        if wire.len() != 3 {
                            failures.push(format!(
                                "{}: expected 3-byte query, got {} bytes",
                                name,
                                wire.len()
                            ));
                        } else if wire[0] != query_type {
                            failures.push(format!(
                                "{}: query type mismatch: expected {}, got {}",
                                name, query_type, wire[0]
                            ));
                        } else if wire[1] != version {
                            failures.push(format!(
                                "{}: version mismatch: expected {}, got {}",
                                name, version, wire[1]
                            ));
                        } else if wire[2] != flags {
                            failures.push(format!(
                                "{}: flags mismatch: expected {}, got {}",
                                name, flags, wire[2]
                            ));
                        } else {
                            println!(
                                "Vector '{}' (rule version {}): wire format OK",
                                name, version
                            );
                        }
                    } else {
                        let option_type = vector
                            .option_type
                            .expect("Rule Version option type or query/response type");
                        let option_length =
                            vector.option_length.expect("Rule Version option length");
                        let version = vector.version.expect("Rule Version option version");
                        if wire != [option_type, option_length, version] {
                            failures.push(format!("{}: Rule Version option bytes mismatch", name));
                        }
                    }
                } else if vector.expect_error.is_none() {
                    // Vectors without wire that have expect_error are logical
                    // tests (e.g., version mismatch), not wire format tests.
                    failures.push(format!("{}: rule_version vector missing wire field", name));
                }
            }

            "padding" => {
                // Octet alignment padding tests
                let residue_bits = vector.residue_bits.unwrap_or(0);
                let expected_padding = vector.padding_bits.unwrap_or(0);
                let computed_padding = (8 - (residue_bits % 8)) % 8;

                if computed_padding != expected_padding {
                    failures.push(format!(
                        "{}: padding mismatch: expected {}, computed {}",
                        name, expected_padding, computed_padding
                    ));
                } else {
                    println!(
                        "Vector '{}' (padding): {} bits -> {} padding bits",
                        name, residue_bits, computed_padding
                    );
                }
            }

            "ack_bitmap" => {
                // Drive the production ACK parser and serializer against the
                // shared cross-implementation bitmap vectors.
                let wire = hex_decode(vector.wire.as_deref().unwrap_or(""));
                let rule_id = vector.rule_id.unwrap_or(0);
                let c_bit = vector.c_bit.unwrap_or(0);
                let window = vector.window.unwrap_or(0);

                if wire.len() < 2 {
                    failures.push(format!("{}: ACK too short", name));
                    continue;
                }

                if wire[0] != rule_id {
                    failures.push(format!(
                        "{}: rule ID mismatch: expected {}, got {}",
                        name, rule_id, wire[0]
                    ));
                }

                let assigned = vector.assigned_fcns.as_ref().map(|fcns| {
                    fcns.iter().fold(0u64, |mask, &fcn| {
                        mask | if fcn == 63 { 1 } else { 1u64 << fcn }
                    })
                });
                match Ack::from_bytes_for(&wire, assigned) {
                    Ok(ack) => {
                        if ack.rule_id != rule_id {
                            failures.push(format!(
                                "{}: decoded rule ID mismatch: expected {}, got {}",
                                name, rule_id, ack.rule_id
                            ));
                        }
                        if ack.window != window {
                            failures.push(format!(
                                "{}: ACK window mismatch: expected {}, got {}",
                                name, window, ack.window
                            ));
                        }
                        if u8::from(ack.complete) != c_bit {
                            failures.push(format!(
                                "{}: C bit mismatch: expected {}, got {}",
                                name,
                                c_bit,
                                u8::from(ack.complete)
                            ));
                        }
                        if !ack.complete {
                            let expected_bits =
                                if let Some(prefix) = vector.received_bitmap_bits.as_deref() {
                                    let mut bits = prefix.to_owned();
                                    bits.extend(core::iter::repeat_n(
                                        '0',
                                        vector.unassigned_zero_bits.unwrap_or(0),
                                    ));
                                    bits.push(if vector.final_all_1_received.unwrap_or(false) {
                                        '1'
                                    } else {
                                        '0'
                                    });
                                    bits
                                } else {
                                    let mut bits = vector
                                        .received_bitmap_prefix_bits
                                        .as_deref()
                                        .unwrap_or("")
                                        .to_owned();
                                    bits.extend(core::iter::repeat_n(
                                        '1',
                                        vector.trailing_received_bits.unwrap_or(0),
                                    ));
                                    bits
                                };
                            if expected_bits.len() != WINDOW_SIZE
                                || expected_bits.bytes().any(|bit| !matches!(bit, b'0' | b'1'))
                            {
                                failures.push(format!(
                                    "{}: vector does not declare an exact {}-bit bitmap",
                                    name, WINDOW_SIZE
                                ));
                            } else {
                                let expected_bitmap = expected_bits
                                    .bytes()
                                    .fold(0u64, |bits, bit| (bits << 1) | u64::from(bit == b'1'));
                                if ack.bitmap != expected_bitmap {
                                    failures.push(format!(
                                        "{}: decoded bitmap does not match declared bitmap semantics",
                                        name
                                    ));
                                }
                            }
                        }
                        let mut encoded = [0u8; 10];
                        match ack.write_to(&mut encoded) {
                            Ok(length) if encoded[..length] == wire => {
                                println!("Vector '{}' (ACK bitmap): C={} OK", name, c_bit);
                            }
                            Ok(_) => failures.push(format!(
                                "{}: ACK did not serialize to its canonical vector bytes",
                                name
                            )),
                            Err(error) => failures
                                .push(format!("{}: ACK serialization failed: {}", name, error)),
                        }
                    }
                    Err(error) => failures.push(format!("{}: ACK parse failed: {}", name, error)),
                }
            }

            _ => {
                // Skip other categories (port_boundary, compressed_size, single_active)
                // These are validated by the Python tests
                println!(
                    "Vector '{}' ({}): skipped (category not tested in Rust)",
                    name, category
                );
            }
        }
    }

    // Verify expected counts from vector file metadata
    let expected = &vectors.expected_counts;
    if p0_count != expected.p0 {
        failures.push(format!(
            "Expected {} P0 security-critical vectors (per metadata), found {}",
            expected.p0, p0_count
        ));
    }
    if endpoint_direction_count != expected.endpoint_direction {
        failures.push(format!(
            "Expected {} endpoint-direction vectors (per metadata), found {}",
            expected.endpoint_direction, endpoint_direction_count
        ));
    }
    if rule7_address_policy_count != expected.rule7_address_policy {
        failures.push(format!(
            "Expected {} Rule 7 address-policy vectors (per metadata), found {}",
            expected.rule7_address_policy, rule7_address_policy_count
        ));
    }
    #[cfg(all(feature = "raw-fragment-codec", feature = "test-utils"))]
    if duplicate_idempotence_count != expected.duplicate_idempotence {
        failures.push(format!(
            "Expected {} duplicate-idempotence vector (per metadata), found {}",
            expected.duplicate_idempotence, duplicate_idempotence_count
        ));
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} SCHC adaptation vector(s) failed", failures.len());
    }

    println!(
        "Validated {} SCHC adaptation vectors ({} P0 security-critical)",
        vectors.vectors.len(),
        p0_count
    );
}

#[test]
fn test_schc_adaptation_coverage() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schc_adaptation.json");

    if !vectors_path.exists() {
        // SECURITY: This coverage test validates P0 security vectors are present.
        // In CI, fail hard so missing vectors are never silently ignored.
        if std::env::var("CI").is_ok() {
            panic!(
                "Vectors file not found at {:?}. P0 security vectors must be present in CI.",
                vectors_path
            );
        }
        eprintln!(
            "WARNING: Vectors file not found at {:?}, skipping coverage check.",
            vectors_path
        );
        return;
    }

    let content = fs::read_to_string(&vectors_path).unwrap();
    let vectors: VectorFile = serde_json::from_str(&content).unwrap();

    // Track categories covered
    let mut categories = std::collections::HashSet::new();
    for v in &vectors.vectors {
        categories.insert(v.category.clone());
    }

    println!("SCHC adaptation categories: {:?}", categories);

    // Expect key categories
    let expected = vec![
        "rejection",
        "uncompressed",
        "fragmentation_direction",
        "fragmentation_endpoint_direction",
        "rule7_address_policy",
        "rule_version",
        "ack_bitmap",
    ];
    for cat in expected {
        if !categories.contains(cat) {
            eprintln!("WARNING: Missing category '{}'", cat);
        }
    }
}
