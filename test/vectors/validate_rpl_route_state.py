#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Validate canonical route-state vectors without project implementation code."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

VECTOR_PATH = Path(__file__).with_name("rpl_route_state.json")
REQUIRED_CASES = {
    "install_parent_2_to_root",
    "install_parent_3_to_root",
    "install_parent_4_via_parent_2",
    "initial_multi_parent_grouped_install",
    "equal_exact_semantic_replay_no_refresh",
    "equal_reordered_equivalence_no_refresh",
    "equal_descriptor_change_rejected",
    "equal_descriptor_removal_rejected",
    "equal_descriptor_addition_rejected",
    "equal_candidate_add_rejected",
    "equal_candidate_remove_rejected",
    "equal_parent_mutation_rejected",
    "equal_lifetime_mutation_rejected",
    "equal_path_control_mutation_rejected",
    "stale_path_sequence_rejected",
    "incomparable_path_sequence_rejected",
    "newer_sequence_replaces_candidate_set",
    "stale_withdrawal_rejected",
    "newer_withdrawal",
    "finite_lifetime_expiry",
    "equal_sequence_after_expiry_does_not_revive",
    "newer_sequence_reinstalls_expired_target",
    "malformed_inconsistent_group_rejected",
    "reserved_dao_flags_rejected",
    "reserved_dao_byte_rejected",
    "unsupported_dao_option_rejected",
    "duplicate_target_rejected",
    "orphan_target_descriptor_rejected",
    "duplicate_target_descriptor_rejected",
    "target_descriptor_short_length_rejected",
    "target_descriptor_long_length_rejected",
    "target_descriptor_after_transit_rejected",
    "external_transit_rejected",
    "child_before_parent_retains_candidate",
    "parent_arrival_activates_child_route",
    "cycle_rejected_atomically",
    "per_target_candidate_capacity_failure_is_atomic",
    "candidate_capacity_failure_is_atomic",
    "target_capacity_failure_is_atomic",
    "delayed_finite_lifetime_expiry",
    "withdrawal_tombstone_not_reclaimed_early",
    "withdrawal_tombstone_reclaimed_at_deadline",
    "expiry_tombstone_not_reclaimed_early",
    "expiry_tombstone_reclaimed_at_deadline",
    "withdraw_target_c_for_group_reservation",
    "withdraw_target_d_for_group_reservation",
    "grouped_equal_target_is_reserved_during_reclamation",
}


def _decode_dao(vector: dict, oracle: dict) -> list[dict]:
    wire = bytes.fromhex(vector["dao_hex"])
    assert len(wire) >= 20
    assert wire[:4] == bytes(
        [
            oracle["rpl_instance_id"],
            0x40 | vector.get("flags", 0),
            vector.get("reserved", 0),
            vector["dao_sequence"],
        ]
    )
    assert wire[4:20].hex() == oracle["dodag_id"]
    decoded = []
    offset = 20
    while offset < len(wire):
        assert offset + 2 <= len(wire)
        option_type, length = wire[offset : offset + 2]
        end = offset + 2 + length
        assert end <= len(wire)
        data = wire[offset + 2 : end]
        encoded = wire[offset:end].hex()
        if option_type == 5:
            assert length == 18 and data[0] == 0 and data[1] == 128
            decoded.append(
                {
                    "kind": "target",
                    "prefix_length": data[1],
                    "prefix": data[2:18].hex(),
                    "encoded": encoded,
                }
            )
        elif option_type == 9:
            if length == 4:
                decoded.append(
                    {
                        "kind": "descriptor",
                        "value": int.from_bytes(data, "big"),
                        "encoded": encoded,
                    }
                )
            else:
                decoded.append({"kind": "raw_descriptor", "data": data.hex(), "encoded": encoded})
        elif option_type == 6:
            assert length == 20 and data[0] & 0x7F == 0
            decoded.append(
                {
                    "kind": "transit",
                    "external": bool(data[0] & 0x80),
                    "path_control": data[1],
                    "path_sequence": data[2],
                    "path_lifetime": data[3],
                    "parent": data[4:20].hex(),
                    "encoded": encoded,
                }
            )
        else:
            decoded.append(
                {
                    "kind": "unsupported",
                    "option_type": option_type,
                    "data": data.hex(),
                    "encoded": encoded,
                }
            )
        offset = end
    assert decoded == vector["options"]
    return decoded


def _relation(incoming: int, current: int) -> str:
    if incoming == current:
        return "equal"
    if incoming < 128 and current < 128:
        clockwise = (incoming - current) % 128
        counterclockwise = (current - incoming) % 128
        if clockwise in range(1, 17):
            return "newer"
        if counterclockwise in range(1, 17):
            return "stale"
        return "incomparable"
    if incoming >= 128 and current >= 128:
        distance = abs(incoming - current)
        if distance > 16:
            return "incomparable"
        return "newer" if incoming > current else "stale"
    linear = incoming if incoming >= 128 else current
    circular = current if incoming >= 128 else incoming
    circular_follows_linear = (256 - linear) + circular <= 16
    if incoming < 128:
        return "newer" if circular_follows_linear else "stale"
    return "stale" if circular_follows_linear else "newer"


def _resolve_routes(state: dict[str, dict], root: str) -> tuple[dict[str, dict], dict[str, dict]]:
    cache: dict[str, tuple[dict, dict] | None] = {}

    def resolve(prefix: str, visiting: frozenset[str]) -> tuple[dict, dict] | None:
        if prefix in cache:
            return cache[prefix]
        record = state.get(prefix)
        if record is None or record["disposition"] != "active" or prefix in visiting:
            return None
        choices = []
        for candidate in record["candidates"]:
            if candidate["parent"] == root:
                path = [prefix]
            else:
                parent = resolve(candidate["parent"], visiting | {prefix})
                if parent is None:
                    continue
                path = parent[0]["path"] + [prefix]
            control = candidate["path_control"]
            subfield = next(index for index in range(1, 5) if (control >> (8 - index * 2)) & 0x03)
            choices.append((subfield, path, candidate))
        if not choices:
            cache[prefix] = None
            return None
        subfield, path, candidate = min(choices, key=lambda item: (item[0], item[1]))
        route = {
            "prefix_length": record["prefix_length"],
            "prefix": prefix,
            "path": path,
            "path_lifetime": candidate["path_lifetime"],
            "installed_at": candidate["installed_at"],
            "expires_at": candidate["expires_at"],
        }
        selected = {
            "parent": candidate["parent"],
            "preference_subfield": subfield,
            "path": path,
        }
        cache[prefix] = (route, selected)
        return route, selected

    for prefix in sorted(state):
        resolve(prefix, frozenset())
    routes = {prefix: result[0] for prefix, result in cache.items() if result is not None}
    selected = {prefix: result[1] for prefix, result in cache.items() if result is not None}
    return routes, selected


def _semantic(candidates: list[dict]) -> list[dict]:
    ignored = {"installed_at", "expires_at"}
    return sorted(
        (
            {key: value for key, value in candidate.items() if key not in ignored}
            for candidate in candidates
        ),
        key=lambda item: item["parent"],
    )


def _snapshot(state: dict[str, dict], root: str) -> dict:
    routes, selected = _resolve_routes(state, root)
    targets = []
    for prefix in sorted(state):
        record = deepcopy(state[prefix])
        for key in [key for key in record if key.startswith("_")]:
            record.pop(key)
        record["candidates"] = sorted(record["candidates"], key=lambda item: item["parent"])
        record["selected_candidate"] = selected.get(prefix)
        targets.append(record)
    return {
        "targets": targets,
        "routing_table": {"routes": [routes[prefix] for prefix in sorted(routes)]},
    }


def _reject(state: dict[str, dict], reason: str) -> tuple[dict[str, dict], dict]:
    return state, {
        "accepted": False,
        "state_changed": False,
        "refreshed": False,
        "reason": reason,
    }


def _cyclic(state: dict[str, dict]) -> bool:
    remaining = {prefix for prefix, record in state.items() if record["disposition"] == "active"}
    while remaining:
        removable = {
            prefix
            for prefix in remaining
            if not any(
                candidate["parent"] in remaining for candidate in state[prefix]["candidates"]
            )
        }
        if not removable:
            return True
        remaining -= removable
    return False


def _apply_dao(state: dict[str, dict], vector: dict, oracle: dict) -> tuple[dict[str, dict], dict]:
    options = _decode_dao(vector, oracle)
    if vector.get("flags", 0) != 0 or vector.get("reserved", 0) != 0:
        return _reject(state, "malformed_group")
    groups = []
    targets, transits = [], []
    seen = set()
    for option in options:
        if option["kind"] == "target":
            if transits:
                groups.append((targets, transits))
                targets, transits = [], []
            if option["prefix"] in seen:
                return _reject(state, "duplicate_target")
            seen.add(option["prefix"])
            targets.append({"target": option, "descriptor": None})
        elif option["kind"] == "descriptor":
            if not targets or transits or targets[-1]["descriptor"] is not None:
                return _reject(state, "malformed_descriptor")
            targets[-1]["descriptor"] = option["value"]
        elif option["kind"] == "raw_descriptor":
            return _reject(state, "malformed_descriptor")
        elif option["kind"] == "unsupported":
            return _reject(state, "malformed_group")
        elif not targets:
            return _reject(state, "malformed_group")
        else:
            transits.append(option)
    if targets and transits:
        groups.append((targets, transits))
    else:
        return _reject(state, "malformed_group")

    proposal = deepcopy(state)
    changed = False
    reason = "semantic_replay"
    protected_prefixes = {
        qualified_target["target"]["prefix"]
        for group_targets, _ in groups
        for qualified_target in group_targets
    }
    for group_targets, group_transits in groups:
        sequences = {item["path_sequence"] for item in group_transits}
        lifetimes = {item["path_lifetime"] for item in group_transits}
        external = {item["external"] for item in group_transits}
        if any(external):
            return _reject(state, "unsupported_external")
        if len(sequences) != 1 or len(lifetimes) != 1 or len(external) != 1:
            return _reject(state, "inconsistent_group")
        sequence = next(iter(sequences))
        lifetime = next(iter(lifetimes))
        candidates = []
        for transit in group_transits:
            expires_at = (
                None
                if lifetime in (0, 255)
                else vector["now_seconds"] + lifetime * oracle["lifetime_unit_seconds"]
            )
            candidates.append(
                {
                    "parent": transit["parent"],
                    "external": transit["external"],
                    "path_control": transit["path_control"],
                    "path_lifetime": lifetime,
                    "installed_at": vector["now_seconds"],
                    "expires_at": expires_at,
                }
            )
        if len(candidates) > oracle["limits"]["max_candidates_per_target"]:
            return _reject(state, "capacity")
        for qualified_target in group_targets:
            target = qualified_target["target"]
            prefix = target["prefix"]
            current = proposal.get(prefix)
            if current is None and len(proposal) >= oracle["limits"]["max_targets"]:
                reclaimable = [
                    (record["_updated_at"], retained_prefix)
                    for retained_prefix, record in proposal.items()
                    if retained_prefix not in protected_prefixes
                    and record["disposition"] != "active"
                    and record["_retain_until"] <= vector["now_seconds"]
                ]
                if not reclaimable:
                    return _reject(state, "capacity")
                proposal.pop(min(reclaimable)[1])
            if current is not None:
                relation = _relation(sequence, current["path_sequence"])
                if relation == "equal":
                    if (
                        _semantic(candidates) != _semantic(current["candidates"])
                        or current["descriptor"] != qualified_target["descriptor"]
                    ):
                        return _reject(state, "equal_sequence_mutation")
                    if not changed:
                        reason = (
                            "equal_expired_no_revival"
                            if current["disposition"] == "expired"
                            else "semantic_replay"
                        )
                    continue
                if relation != "newer":
                    if lifetime == 0 and relation == "stale":
                        return _reject(state, "stale_withdrawal")
                    return _reject(state, f"{relation}_sequence")
            proposal[prefix] = {
                "prefix_length": target["prefix_length"],
                "prefix": prefix,
                "descriptor": qualified_target["descriptor"],
                "sequence_authority": oracle["sequence_authority"],
                "path_sequence": sequence,
                "disposition": "withdrawn" if lifetime == 0 else "active",
                "candidates": candidates,
                "_updated_at": vector["now_seconds"],
                "_retain_until": (
                    vector["now_seconds"] + oracle["freshness_retention_seconds"]
                    if lifetime == 0
                    else (
                        candidates[0]["expires_at"] + oracle["freshness_retention_seconds"]
                        if candidates[0]["expires_at"] is not None
                        else None
                    )
                ),
            }
            changed = True
            if lifetime == 0:
                reason = "withdrawn"
            elif current is None:
                reason = "installed"
            elif current["disposition"] == "expired":
                reason = "reinstalled"
            else:
                reason = "replaced"

    active_candidates = sum(
        len(record["candidates"])
        for record in proposal.values()
        if record["disposition"] == "active"
    )
    limits = oracle["limits"]
    if _cyclic(proposal):
        return _reject(state, "cycle")
    if len(proposal) > limits["max_targets"] or active_candidates > limits["max_candidates"]:
        return _reject(state, "capacity")
    return proposal, {
        "accepted": True,
        "state_changed": changed,
        "refreshed": False,
        "reason": reason,
    }


def validate(document: dict) -> None:
    assert document["vector_type"] == "rpl_route_state"
    assert document["format_version"] == 2
    names = [vector["name"] for vector in document["vectors"]]
    assert set(names) == REQUIRED_CASES
    assert len(names) == len(set(names))
    relation_names = [case["name"] for case in document["sequence_relations"]]
    assert len(relation_names) == len(set(relation_names))
    for case in document["sequence_relations"]:
        assert _relation(case["incoming"], case["current"]) == case["expected"], case["name"]

    oracle = document["oracle"]
    assert oracle["max_route_hops"] == 8
    dao_sequence = 240
    path_sequence = 240
    for case in document["tx_sequence_transitions"]:
        dao_sequence = 0 if dao_sequence in (127, 255) else dao_sequence + 1
        if case["advance_path_sequence"]:
            path_sequence = 0 if path_sequence in (127, 255) else path_sequence + 1
        assert dao_sequence == case["expected_dao_sequence"], case["name"]
        assert path_sequence == case["expected_path_sequence"], case["name"]
    for case in document["route_hop_boundaries"]:
        assert case["accepted"] == (len(case["path"]) <= oracle["max_route_hops"]), case["name"]
    state: dict[str, dict] = {}
    for vector in document["vectors"]:
        assert vector["before"] == _snapshot(state, oracle["dodag_id"]), vector["name"]
        if vector["event"] == "expire":
            changed = False
            for record in state.values():
                if record["disposition"] == "active" and all(
                    candidate["expires_at"] is not None
                    and candidate["expires_at"] <= vector["now_seconds"]
                    for candidate in record["candidates"]
                ):
                    record["disposition"] = "expired"
                    changed = True
            outcome = {
                "accepted": True,
                "state_changed": changed,
                "refreshed": False,
                "reason": "expired",
            }
        else:
            state, outcome = _apply_dao(state, vector, oracle)
        assert outcome == {key: vector["expected"][key] for key in outcome}, vector["name"]
        assert vector["expected"]["state"] == _snapshot(state, oracle["dodag_id"]), vector["name"]
        if not outcome["accepted"]:
            assert vector["expected"]["state"] == vector["before"], vector["name"]


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else VECTOR_PATH
    validate(json.loads(path.read_text()))
    print(f"validated {len(json.loads(path.read_text())['vectors'])} route-state vectors")


if __name__ == "__main__":
    main()
