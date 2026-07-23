// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::addr::NodeId;
use lichen_core::announce::{Announce, AnnounceBuilder};
use lichen_hal::storage::mem::MemStorage;
use lichen_link::identity::Identity;
use lichen_link::keys::Seed;
use lichen_link::schnorr::sign;
use lichen_node::announce::{AnnounceProcessor, MAX_TRACKED_ORIGINATORS};
use lichen_node::gradient::GradientTable;
use lichen_node::node::{DaoHandlingOutcome, RplNode};

const JSON: &str = include_str!("../../../test/vectors/dao_origin_signature.json");

fn root_id(dodag: [u8; 16]) -> NodeId {
    assert_eq!(&dodag[..8], &[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    let mut eui: [u8; 8] = dodag[8..].try_into().unwrap();
    eui[0] ^= 0x02;
    NodeId(eui)
}

fn iid(address: [u8; 16]) -> [u8; 8] {
    address[8..].try_into().unwrap()
}

fn field<'a>(object: &'a str, name: &str) -> &'a str {
    object
        .split_once(&format!("\"{name}\": "))
        .unwrap_or_else(|| panic!("missing {name}"))
        .1
}

fn string_field<'a>(object: &'a str, name: &str) -> &'a str {
    field(object, name)
        .strip_prefix('"')
        .unwrap()
        .split_once('"')
        .unwrap()
        .0
}

fn bool_field(object: &str, name: &str) -> bool {
    field(object, name).starts_with("true")
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex(value)
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes"))
}

fn vectors() -> impl Iterator<Item = &'static str> {
    JSON.split("      \"name\": \"").skip(1).map(|tail| {
        tail.split_once("\n    },")
            .map_or(tail, |(vector, _)| vector)
    })
}

fn pinned_announces(identity: &Identity, prefix: [u8; 8], root_id: NodeId) -> AnnounceProcessor {
    let rx_channel = 0;
    let mut signed = [0u8; 43];
    signed[..8].copy_from_slice(&identity.iid);
    signed[8..40].copy_from_slice(identity.pubkey.as_bytes());
    signed[40..42].copy_from_slice(&1u16.to_be_bytes());
    signed[42] = rx_channel;
    let signature = sign(&identity.privkey, &identity.pubkey, &signed);
    let mut wire = [0u8; 128];
    let len = AnnounceBuilder {
        originator_iid: &identity.iid,
        pubkey: identity.pubkey.as_bytes(),
        seq_num: 1,
        hop_count: 0,
        rx_channel,
        signature: &signature,
        app_data: &[],
    }
    .write_to(&mut wire)
    .unwrap();
    let announce = Announce::from_bytes(&wire[..len]).unwrap();
    let mut processor = AnnounceProcessor::new(GradientTable::new(MAX_TRACKED_ORIGINATORS), prefix);
    assert!(
        processor
            .process(&announce, root_id.link_local_addr().0, 0)
            .accepted
    );
    processor
}

fn expected_outcome(reason: &str) -> DaoHandlingOutcome {
    match reason {
        "accepted" => DaoHandlingOutcome::Applied,
        "idempotent" | "reconciled" => DaoHandlingOutcome::Duplicate,
        "missing_signature" | "zero_sequence" | "bad_option_length" | "truncated"
        | "malformed_dao" | "unsupported_flags" | "nonzero_reserved" | "duplicate_option"
        | "nonterminal_option" | "unknown_option" => DaoHandlingOutcome::Malformed,
        "unknown_key" => DaoHandlingOutcome::UnknownKey,
        "instance_mismatch" | "dodag_mismatch" => DaoHandlingOutcome::WrongScope,
        // Public pin lookup is keyed by claimed IID; a forged IID has no key.
        "iid_mismatch" => DaoHandlingOutcome::UnknownKey,
        "invalid_signature" => DaoHandlingOutcome::BadSignature,
        "sequence_conflict" | "replay" => DaoHandlingOutcome::Replay,
        "missing_target"
        | "missing_transit"
        | "duplicate_target"
        | "multiple_target"
        | "non128_target"
        | "target_mismatch"
        | "inconsistent_transit"
        | "unsupported_transit_e" => DaoHandlingOutcome::RouteRejected,
        other => panic!("unknown expected reason {other}"),
    }
}

fn storage_snapshot(storage: &MemStorage) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        storage.raw("rpl.rx.a").map(<[u8]>::to_vec),
        storage.raw("rpl.rx.b").map(<[u8]>::to_vec),
    )
}

#[test]
fn fixed_dao_origin_vectors_match_rpl_node_handler() {
    let mut failures = Vec::new();
    let mut count = 0;
    for vector in vectors() {
        count += 1;
        let name = vector.split_once('"').unwrap().0;
        let seed = array(string_field(vector, "signing_seed"));
        let identity = Identity::from_seed(Seed::new(seed));
        let source = array(string_field(vector, "source_ipv6"));
        let active_dodag = array(string_field(vector, "active_dodag_id"));
        let root_id = root_id(active_dodag);
        let wire = hex(string_field(vector, "signed_dao"));
        let reason = string_field(vector, "reason");
        let announces = pinned_announces(&identity, source[..8].try_into().unwrap(), root_id);
        let unpinned = AnnounceProcessor::new(
            GradientTable::new(MAX_TRACKED_ORIGINATORS),
            source[..8].try_into().unwrap(),
        );
        let mut storage = MemStorage::new();
        let (mut node, mut rx_state) = RplNode::provision_root(root_id, &mut storage).unwrap();

        let prior = field(vector, "prior");
        if prior.starts_with('{') {
            let prior_wire = hex(string_field(prior, "signed_dao"));
            let prior_source = array(string_field(prior, "source_ipv6"));
            assert_eq!(
                node.handle_dao(
                    &prior_wire,
                    prior_source,
                    iid(prior_source),
                    &announces,
                    &mut rx_state,
                    &mut storage,
                    1,
                ),
                DaoHandlingOutcome::Applied,
                "{name}: prior setup"
            );
            if !bool_field(prior, "route_present") {
                (node, rx_state) = RplNode::open_root(root_id, &storage).unwrap();
            }
        }

        let victim = array::<16>("fd424c494348454e0011223344556677");
        let routes_before = (
            node.router()
                .lookup_route(&source)
                .map(<[[u8; 16]]>::to_vec),
            node.router()
                .lookup_route(&victim)
                .map(<[[u8; 16]]>::to_vec),
        );
        let storage_before = storage_snapshot(&storage);
        let processor = if reason == "unknown_key" {
            &unpinned
        } else {
            &announces
        };
        let outcome = node.handle_dao(
            &wire,
            source,
            iid(source),
            processor,
            &mut rx_state,
            &mut storage,
            2,
        );
        let expected = expected_outcome(reason);
        if outcome != expected {
            failures.push(format!("{name}: got {outcome:?}, expected {expected:?}"));
        }

        if reason == "target_mismatch" {
            assert_eq!(
                routes_before,
                (
                    node.router()
                        .lookup_route(&source)
                        .map(<[[u8; 16]]>::to_vec),
                    node.router()
                        .lookup_route(&victim)
                        .map(<[[u8; 16]]>::to_vec),
                ),
                "{name}: route mutation"
            );
            assert_eq!(
                storage_snapshot(&storage),
                storage_before,
                "{name}: persistence"
            );
            if prior.starts_with('{') {
                let prior_wire = hex(string_field(prior, "signed_dao"));
                assert_eq!(
                    node.handle_dao(
                        &prior_wire,
                        source,
                        iid(source),
                        &announces,
                        &mut rx_state,
                        &mut storage,
                        3,
                    ),
                    DaoHandlingOutcome::Duplicate,
                    "{name}: replay floor mutation"
                );
            }
        }
    }
    assert_eq!(count, 50);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unavailable_replay_storage_leaves_dao_state_unchanged() {
    let vector = vectors().next().unwrap();
    let identity = Identity::from_seed(Seed::new(array(string_field(vector, "signing_seed"))));
    let source = array(string_field(vector, "source_ipv6"));
    let active_dodag = array(string_field(vector, "active_dodag_id"));
    let root_id = root_id(active_dodag);
    let wire = hex(string_field(vector, "signed_dao"));
    let announces = pinned_announces(&identity, source[..8].try_into().unwrap(), root_id);
    let mut storage = MemStorage::new();
    let (mut node, mut rx_state) = RplNode::provision_root(root_id, &mut storage).unwrap();
    let storage_before = storage_snapshot(&storage);

    storage.fail_next_write();
    assert_eq!(
        node.handle_dao(
            &wire,
            source,
            iid(source),
            &announces,
            &mut rx_state,
            &mut storage,
            1,
        ),
        DaoHandlingOutcome::Persistence
    );
    assert_eq!(node.router().lookup_route(&source), None);
    assert_eq!(storage_snapshot(&storage), storage_before);

    assert_eq!(
        node.handle_dao(
            &wire,
            source,
            iid(source),
            &announces,
            &mut rx_state,
            &mut storage,
            2,
        ),
        DaoHandlingOutcome::Applied
    );
}
