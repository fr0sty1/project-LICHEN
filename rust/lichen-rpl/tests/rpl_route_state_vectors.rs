// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_rpl::message::{Dao, OptionIter, TransitInfo, OPT_TRANSIT_INFO};
use lichen_rpl::routing::{
    DaoDiagnosticDisposition, DaoDiagnosticLimits, DaoDiagnosticTarget, DaoManager,
    DaoProcessTiming, RoutingTable, MAX_ROUTE_HOPS,
};
use serde_json::{json, Value};

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

#[test]
fn canonical_route_state_vectors_match_production_manager() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["vector_type"], "rpl_route_state");
    assert_eq!(document["format_version"], 1);
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
}
