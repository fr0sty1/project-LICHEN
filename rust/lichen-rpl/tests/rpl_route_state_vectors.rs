// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_rpl::message::{
    Dao, DaoOriginSignature, OptionIter, TransitInfo, DAO_ORIGIN_SIGNATURE_LEN, OPT_TRANSIT_INFO,
};
use lichen_rpl::routing::{
    dao_origin_digest, DaoAdmissionState, DaoDiagnosticDisposition, DaoDiagnosticLimits,
    DaoDiagnosticTarget, DaoManager, DaoProcessError, DaoProcessOutcome, DaoProcessTiming,
    RoutingTable, SignatureVerifiedDao, MAX_ROUTE_HOPS,
};
use serde_json::{json, Value};
use std::sync::{Arc, Barrier, Mutex};

const VECTORS: &str = include_str!("../../../test/vectors/rpl_route_state.json");

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn address(value: &Value) -> [u8; 16] {
    hex_bytes(value.as_str().unwrap()).try_into().unwrap()
}

fn hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        use core::fmt::Write;
        write!(encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn snapshot(targets: Vec<DaoDiagnosticTarget>) -> Value {
    let routes: Vec<_> = targets
        .iter()
        .filter_map(|target| {
            let selected = target.selected_candidate.as_ref()?;
            let candidate = target
                .candidates
                .iter()
                .find(|candidate| candidate.parent == selected.parent)?;
            Some(json!({
                "prefix_length": target.prefix_length,
                "prefix": hex(&target.prefix),
                "path": selected.path.iter().map(|hop| hex(hop)).collect::<Vec<_>>(),
                "path_lifetime": candidate.path_lifetime,
                "installed_at": candidate.installed_at,
                "expires_at": candidate.expires_at,
            }))
        })
        .collect();
    let targets: Vec<_> = targets
        .into_iter()
        .map(|target| {
            let disposition = match target.disposition {
                DaoDiagnosticDisposition::Active => "active",
                DaoDiagnosticDisposition::Withdrawn => "withdrawn",
                DaoDiagnosticDisposition::Expired => "expired",
            };
            let candidates: Vec<_> = target
                .candidates
                .into_iter()
                .map(|candidate| {
                    json!({
                        "parent": hex(&candidate.parent),
                        "external": candidate.external,
                        "path_control": candidate.path_control,
                        "path_lifetime": candidate.path_lifetime,
                        "installed_at": candidate.installed_at,
                        "expires_at": candidate.expires_at,
                    })
                })
                .collect();
            let selected_candidate = target.selected_candidate.map(|selected| {
                json!({
                    "parent": hex(&selected.parent),
                    "preference_subfield": selected.preference_subfield,
                    "path": selected.path.iter().map(|hop| hex(hop)).collect::<Vec<_>>(),
                })
            });
            json!({
                "prefix_length": target.prefix_length,
                "prefix": hex(&target.prefix),
                "descriptor": target.descriptor,
                "sequence_authority": hex(&target.sequence_authority),
                "path_sequence": target.path_sequence,
                "disposition": disposition,
                "candidates": candidates,
                "selected_candidate": selected_candidate,
            })
        })
        .collect();
    json!({
        "targets": targets,
        "routing_table": { "routes": routes },
    })
}

fn assert_routes(manager: &DaoManager, expected: &Value, name: &str) {
    for target in expected["targets"].as_array().unwrap() {
        let prefix = address(&target["prefix"]);
        if target["selected_candidate"].is_null() {
            assert_eq!(
                manager.routing_table().lookup(&prefix),
                None,
                "{name}: unexpected route"
            );
        } else {
            let path: Vec<[u8; 16]> = target["selected_candidate"]["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(address)
                .collect();
            assert_eq!(
                manager.routing_table().lookup(&prefix),
                Some(path.as_slice()),
                "{name}: route path"
            );
        }
    }
}

fn route_dao(dao_sequence: u8, path_sequence: u8, target: [u8; 16], parent: [u8; 16]) -> Vec<u8> {
    let mut wire = vec![0, 0, 0, dao_sequence, 5, 18, 0, 128];
    wire.extend_from_slice(&target);
    wire.extend_from_slice(&[6, 20, 0, 0x80, path_sequence, 255]);
    wire.extend_from_slice(&parent);
    wire
}

fn dao_sequences_and_lifetime(wire: &[u8]) -> (u8, u8, u8) {
    let dao = Dao::from_bytes(wire).unwrap();
    let transit = OptionIter::new(Dao::options_tail(wire))
        .map(Result::unwrap)
        .find(|option| option.opt_type == OPT_TRANSIT_INFO)
        .map(|option| TransitInfo::from_bytes(option.data).unwrap())
        .unwrap();
    (
        dao.dao_sequence,
        transit.path_sequence,
        transit.path_lifetime,
    )
}

fn grouped_route_dao(
    dao_sequence: u8,
    path_sequence: u8,
    target: [u8; 16],
    candidates: &[([u8; 16], u8, u8)],
) -> Vec<u8> {
    let mut wire = vec![0, 0, 0, dao_sequence, 5, 18, 0, 128];
    wire.extend_from_slice(&target);
    for (parent, path_control, path_lifetime) in candidates {
        wire.extend_from_slice(&[
            OPT_TRANSIT_INFO,
            20,
            0,
            *path_control,
            path_sequence,
            *path_lifetime,
        ]);
        wire.extend_from_slice(parent);
    }
    wire
}

fn signed_dao(
    unsigned: &[u8],
    origin: [u8; 16],
    dodag_id: [u8; 16],
    origin_sequence: u64,
    link: &lichen_link::link_layer::LinkLayer,
) -> Vec<u8> {
    let digest = dao_origin_digest(origin, dodag_id, origin_sequence, unsigned);
    let signature = link.sign_digest(&digest);
    let mut wire = unsigned.to_vec();
    let offset = wire.len();
    wire.resize(offset + DAO_ORIGIN_SIGNATURE_LEN, 0);
    DaoOriginSignature::write_to(origin_sequence, &signature, &mut wire[offset..]).unwrap();
    wire
}

#[test]
fn canonical_route_state_vectors_match_production_manager() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["vector_type"], "rpl_route_state");
    assert_eq!(document["format_version"], 2);
    let oracle = &document["oracle"];
    assert_eq!(
        oracle["path_control_size"],
        lichen_rpl::routing::PATH_CONTROL_SIZE
    );
    let max_route_hops = oracle["max_route_hops"].as_u64().unwrap() as usize;
    assert_eq!(max_route_hops, MAX_ROUTE_HOPS);
    let lifetime_unit_seconds = oracle["lifetime_unit_seconds"].as_u64().unwrap();
    let rpl_instance_id = oracle["rpl_instance_id"].as_u64().unwrap() as u8;
    let dodag_id = address(&oracle["dodag_id"]);
    let sequence_authority = address(&oracle["sequence_authority"]);
    let limits = DaoDiagnosticLimits {
        max_targets: oracle["limits"]["max_targets"].as_u64().unwrap() as usize,
        max_candidates_per_target: oracle["limits"]["max_candidates_per_target"]
            .as_u64()
            .unwrap() as usize,
        max_candidates: oracle["limits"]["max_candidates"].as_u64().unwrap() as usize,
    };

    for relation in document["sequence_relations"].as_array().unwrap() {
        let name = relation["name"].as_str().unwrap();
        let current = relation["current"].as_u64().unwrap() as u8;
        let incoming = relation["incoming"].as_u64().unwrap() as u8;
        let target = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let parent = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let timing = DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds,
            max_deadline_seconds: u64::MAX,
        };
        let mut relation_manager = DaoManager::diagnostic_root(dodag_id, rpl_instance_id, dodag_id);
        relation_manager
            .process_route_state_diagnostic(
                &route_dao(1, current, target, parent),
                sequence_authority,
                timing,
                limits,
            )
            .unwrap();

        let result = relation_manager.process_route_state_diagnostic(
            &route_dao(2, incoming, target, parent),
            sequence_authority,
            timing,
            limits,
        );
        match relation["expected"].as_str().unwrap() {
            "equal" => assert_eq!(result, Ok(false), "{name}"),
            "newer" => assert_eq!(result, Ok(true), "{name}"),
            "stale" | "incomparable" => assert!(result.is_err(), "{name}"),
            expected => panic!("{name}: unknown sequence relation {expected}"),
        }
        let state =
            relation_manager.route_state_diagnostic(sequence_authority, lifetime_unit_seconds);
        assert_eq!(state.len(), 1, "{name}");
        assert_eq!(
            state[0].path_sequence,
            if relation["expected"] == "newer" {
                incoming
            } else {
                current
            },
            "{name}: committed path sequence"
        );
    }

    let mut tx_manager = DaoManager::new(sequence_authority, rpl_instance_id, dodag_id);
    let mut last_logical_lifetime = None;
    for transition in document["tx_sequence_transitions"].as_array().unwrap() {
        let name = transition["name"].as_str().unwrap();
        let path_lifetime = transition["path_lifetime"].as_u64().unwrap() as u8;
        let advance_path_sequence = transition["advance_path_sequence"].as_bool().unwrap();
        let (wire, encoded_lifetime) = if advance_path_sequence {
            last_logical_lifetime = Some(path_lifetime);
            (
                tx_manager.build_dao_with_lifetime(dodag_id, path_lifetime),
                path_lifetime,
            )
        } else {
            let exact_lifetime = last_logical_lifetime.unwrap();
            (
                tx_manager
                    .build_dao_copy_with_lifetime(dodag_id, exact_lifetime)
                    .unwrap(),
                exact_lifetime,
            )
        };
        let (dao_sequence, path_sequence, actual_lifetime) = dao_sequences_and_lifetime(&wire);
        assert_eq!(
            dao_sequence,
            transition["expected_dao_sequence"].as_u64().unwrap() as u8,
            "{name}: DAOSequence"
        );
        assert_eq!(
            path_sequence,
            transition["expected_path_sequence"].as_u64().unwrap() as u8,
            "{name}: Transit Path Sequence"
        );
        assert_eq!(actual_lifetime, encoded_lifetime, "{name}: Path Lifetime");
        assert_eq!(
            wire,
            hex_bytes(transition["expected_wire"].as_str().unwrap()),
            "{name}: canonical leaf DAO wire"
        );
    }

    for boundary in document["route_hop_boundaries"].as_array().unwrap() {
        let name = boundary["name"].as_str().unwrap();
        let path: Vec<[u8; 16]> = boundary["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(address)
            .collect();
        let target = *path.last().unwrap();
        let expected_accepted = boundary["accepted"].as_bool().unwrap();
        let mut table = RoutingTable::new();
        assert_eq!(
            table.add_route(target, &path),
            expected_accepted,
            "{name}: route acceptance"
        );
        assert_eq!(
            table.lookup(&target),
            expected_accepted.then_some(path.as_slice()),
            "{name}: route installation"
        );
        assert_eq!(
            path.len() <= max_route_hops,
            expected_accepted,
            "{name}: oracle hop boundary"
        );
    }

    let mut manager = DaoManager::diagnostic_root(dodag_id, rpl_instance_id, dodag_id);

    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        assert_eq!(
            snapshot(manager.route_state_diagnostic(sequence_authority, lifetime_unit_seconds)),
            vector["before"],
            "{name}: before snapshot"
        );
        let now_seconds = vector["now_seconds"].as_u64().unwrap();
        let (accepted, state_changed) = if vector["event"] == "expire" {
            (true, manager.expire_routes(now_seconds))
        } else {
            let dao = hex_bytes(vector["dao_hex"].as_str().unwrap());
            match manager.process_route_state_diagnostic(
                &dao,
                sequence_authority,
                DaoProcessTiming {
                    now_seconds,
                    lifetime_unit_seconds,
                    max_deadline_seconds: u64::MAX,
                },
                limits,
            ) {
                Ok(changed) => (true, changed),
                Err(_) => (false, false),
            }
        };
        assert_eq!(accepted, vector["expected"]["accepted"], "{name}");
        assert_eq!(state_changed, vector["expected"]["state_changed"], "{name}");
        assert_eq!(
            vector["expected"]["refreshed"].as_bool(),
            Some(false),
            "{name}"
        );
        // `reason` is an oracle diagnostic; the production API exposes no reason value.
        let reason = vector["expected"]["reason"].as_str().unwrap();
        assert!(
            !reason.is_empty()
                && reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name}: reason must be a canonical diagnostic string"
        );
        assert_eq!(
            snapshot(manager.route_state_diagnostic(sequence_authority, lifetime_unit_seconds)),
            vector["expected"]["state"],
            "{name}: expected snapshot"
        );
        assert_routes(&manager, &vector["expected"]["state"], name);
    }
}

#[test]
fn zero_length_transit_is_rejected_without_public_state_mutation() {
    let root = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let target = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut authority = [0; 16];
    authority[0] = 0xfd;
    authority[15] = 0xaa;
    let timing = DaoProcessTiming {
        now_seconds: 0,
        lifetime_unit_seconds: 10,
        max_deadline_seconds: u64::MAX,
    };
    let limits = DaoDiagnosticLimits {
        max_targets: 2,
        max_candidates_per_target: 2,
        max_candidates: 2,
    };
    let mut manager = DaoManager::diagnostic_root(root, 0, root);
    manager
        .process_route_state_diagnostic(&route_dao(1, 1, target, root), authority, timing, limits)
        .unwrap();
    let before = manager.route_state_diagnostic(authority, timing.lifetime_unit_seconds);
    let route_before = manager.routing_table().lookup(&target).unwrap().to_vec();
    let mut malformed = vec![0, 0, 0, 2, 5, 18, 0, 128];
    malformed.extend_from_slice(&target);
    malformed.extend_from_slice(&[OPT_TRANSIT_INFO, 0]);

    assert!(manager
        .process_route_state_diagnostic(&malformed, authority, timing, limits)
        .is_err());
    assert_eq!(
        manager.route_state_diagnostic(authority, timing.lifetime_unit_seconds),
        before
    );
    assert_eq!(
        manager.routing_table().lookup(&target),
        Some(route_before.as_slice())
    );

    let mut non_host_target = route_dao(2, 2, target, root);
    non_host_target[7] = 127;
    assert!(manager
        .process_route_state_diagnostic(&non_host_target, authority, timing, limits)
        .is_err());
    assert_eq!(
        manager.route_state_diagnostic(authority, timing.lifetime_unit_seconds),
        before
    );
    assert_eq!(
        manager.routing_table().lookup(&target),
        Some(route_before.as_slice())
    );
}

#[test]
fn authenticated_new_origin_sequence_cannot_bypass_path_sequence_freshness() {
    use lichen_hal::storage::mem::MemStorage;
    use lichen_link::{identity::Identity, keys::Seed, link_layer::LinkLayer};

    let root = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let identity = Identity::from_seed(Seed::new([0x44; 32]));
    let origin = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
    let link = LinkLayer::new(identity.clone());
    let mut storage = MemStorage::new();
    let (mut manager, mut rx_state) =
        DaoManager::provision_root(&mut storage, root, 0, root).unwrap();
    let mut admission = DaoAdmissionState::provision(&mut storage, root, 0, root).unwrap();
    admission
        .admit(&mut storage, *identity.pubkey.as_bytes())
        .unwrap();
    let timing = DaoProcessTiming {
        now_seconds: 100,
        lifetime_unit_seconds: 1,
        max_deadline_seconds: u64::MAX,
    };
    let mut sender = DaoManager::new(origin, 0, root);

    let first_unsigned = sender.build_dao_with_lifetime(root, 10);
    let first_wire = signed_dao(&first_unsigned, origin, root, 1, &link);
    let first =
        SignatureVerifiedDao::verify_signature(&first_wire, origin, 0, root, Some(identity.pubkey))
            .unwrap();
    assert_eq!(
        manager.process_signature_verified(
            &first,
            first.origin_iid(),
            &mut rx_state,
            &mut storage,
            timing,
            &admission,
        ),
        Ok(DaoProcessOutcome::Applied)
    );
    let first_state = manager.route_state_diagnostic(origin, 1);
    assert_eq!(first_state[0].path_sequence, 241);
    assert_eq!(manager.origin_high_water()[0].origin_sequence, 1);

    let mut stale_unsigned = first_unsigned.clone();
    let path_sequence_index = stale_unsigned.len() - 18;
    stale_unsigned[path_sequence_index] = 240;
    let stale_wire = signed_dao(&stale_unsigned, origin, root, 2, &link);
    let stale =
        SignatureVerifiedDao::verify_signature(&stale_wire, origin, 0, root, Some(identity.pubkey))
            .unwrap();
    assert_eq!(
        manager.process_signature_verified(
            &stale,
            stale.origin_iid(),
            &mut rx_state,
            &mut storage,
            DaoProcessTiming {
                now_seconds: 101,
                ..timing
            },
            &admission,
        ),
        Err(DaoProcessError::RouteRejected)
    );
    assert_eq!(manager.route_state_diagnostic(origin, 1), first_state);
    assert_eq!(manager.origin_high_water()[0].origin_sequence, 1);

    let second_unsigned = sender.build_dao_with_lifetime(root, 10);
    let second_wire = signed_dao(&second_unsigned, origin, root, 2, &link);
    let second = SignatureVerifiedDao::verify_signature(
        &second_wire,
        origin,
        0,
        root,
        Some(identity.pubkey),
    )
    .unwrap();
    assert_eq!(
        manager.process_signature_verified(
            &second,
            second.origin_iid(),
            &mut rx_state,
            &mut storage,
            DaoProcessTiming {
                now_seconds: 101,
                ..timing
            },
            &admission,
        ),
        Ok(DaoProcessOutcome::Applied)
    );
    let second_state = manager.route_state_diagnostic(origin, 1);
    assert_eq!(second_state[0].path_sequence, 242);
    assert_eq!(second_state[0].candidates[0].expires_at, Some(111));

    let equal_unsigned = sender.build_dao_copy_with_lifetime(root, 10).unwrap();
    let equal_wire = signed_dao(&equal_unsigned, origin, root, 3, &link);
    let equal =
        SignatureVerifiedDao::verify_signature(&equal_wire, origin, 0, root, Some(identity.pubkey))
            .unwrap();
    assert_eq!(
        manager.process_signature_verified(
            &equal,
            equal.origin_iid(),
            &mut rx_state,
            &mut storage,
            DaoProcessTiming {
                now_seconds: 105,
                ..timing
            },
            &admission,
        ),
        Ok(DaoProcessOutcome::Applied)
    );
    assert_eq!(manager.route_state_diagnostic(origin, 1), second_state);
    assert_eq!(manager.origin_high_water()[0].origin_sequence, 3);

    let mut changed_equal_unsigned = equal_unsigned;
    let lifetime_index = changed_equal_unsigned.len() - 17;
    changed_equal_unsigned[lifetime_index] = 20;
    let changed_equal_wire = signed_dao(&changed_equal_unsigned, origin, root, 4, &link);
    let changed_equal = SignatureVerifiedDao::verify_signature(
        &changed_equal_wire,
        origin,
        0,
        root,
        Some(identity.pubkey),
    )
    .unwrap();
    assert_eq!(
        manager.process_signature_verified(
            &changed_equal,
            changed_equal.origin_iid(),
            &mut rx_state,
            &mut storage,
            DaoProcessTiming {
                now_seconds: 106,
                ..timing
            },
            &admission,
        ),
        Err(DaoProcessError::RouteRejected)
    );
    assert_eq!(manager.route_state_diagnostic(origin, 1), second_state);
    assert_eq!(manager.origin_high_water()[0].origin_sequence, 3);
}

#[test]
fn concurrent_newer_snapshots_never_publish_a_mixed_candidate_set() {
    let root = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let target = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let authority = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
    let parents = [
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
    ];
    let limits = DaoDiagnosticLimits {
        max_targets: 1,
        max_candidates_per_target: 2,
        max_candidates: 2,
    };
    let timing = DaoProcessTiming {
        now_seconds: 1,
        lifetime_unit_seconds: 1,
        max_deadline_seconds: u64::MAX,
    };
    let manager = Arc::new(Mutex::new(DaoManager::diagnostic_root(root, 0, root)));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (sequence, candidate_set) in [
        (1, [(parents[0], 0x80, 255), (parents[1], 0x40, 255)]),
        (2, [(parents[2], 0x80, 255), (parents[3], 0x40, 255)]),
    ] {
        let manager = Arc::clone(&manager);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let dao = grouped_route_dao(sequence, sequence, target, &candidate_set);
            barrier.wait();
            manager
                .lock()
                .unwrap()
                .process_route_state_diagnostic(&dao, authority, timing, limits)
        }));
    }
    barrier.wait();
    for worker in workers {
        let _ = worker.join().unwrap();
    }

    let state = manager.lock().unwrap().route_state_diagnostic(authority, 1);
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].path_sequence, 2);
    assert_eq!(
        state[0]
            .candidates
            .iter()
            .map(|candidate| candidate.parent)
            .collect::<Vec<_>>(),
        vec![parents[2], parents[3]]
    );
}
