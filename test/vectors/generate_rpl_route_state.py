#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate fixed, implementation-independent RPL route-state vectors."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

OUT = Path(__file__).with_name("rpl_route_state.json")
DODAG = "fd000000000000000000000000000001"
AUTHORITY = "fd0000000000000000000000000000aa"
TARGET_A = "20010db8000100000000000000000001"
TARGET_B = "20010db8000200000000000000000002"
TARGET_C = "20010db8000300000000000000000003"
TARGET_D = "20010db8000400000000000000000004"
TARGET_E = "20010db8000500000000000000000005"
PARENT_2 = "fd000000000000000000000000000002"
PARENT_3 = "fd000000000000000000000000000003"
PARENT_4 = "fd000000000000000000000000000004"
PARENT_5 = "fd000000000000000000000000000005"
CHILD_6 = "fd000000000000000000000000000006"
SEQUENCE_RELATIONS = [
    {"name": "equal", "current": 10, "incoming": 10, "expected": "equal"},
    {
        "name": "circular_exact_16_newer",
        "current": 0,
        "incoming": 16,
        "expected": "newer",
    },
    {
        "name": "circular_exact_17_incomparable",
        "current": 0,
        "incoming": 17,
        "expected": "incomparable",
    },
    {
        "name": "circular_exact_16_stale",
        "current": 16,
        "incoming": 0,
        "expected": "stale",
    },
    {
        "name": "circular_wrap_127_to_0",
        "current": 127,
        "incoming": 0,
        "expected": "newer",
    },
    {
        "name": "circular_wrap_reverse_stale",
        "current": 0,
        "incoming": 127,
        "expected": "stale",
    },
    {
        "name": "linear_exact_16_newer",
        "current": 239,
        "incoming": 255,
        "expected": "newer",
    },
    {
        "name": "linear_exact_17_incomparable",
        "current": 238,
        "incoming": 255,
        "expected": "incomparable",
    },
    {"name": "linear_stale", "current": 255, "incoming": 250, "expected": "stale"},
    {
        "name": "linear_wrap_255_to_0",
        "current": 255,
        "incoming": 0,
        "expected": "newer",
    },
    {
        "name": "cross_region_within_window",
        "current": 250,
        "incoming": 5,
        "expected": "newer",
    },
    {
        "name": "cross_region_outside_window",
        "current": 240,
        "incoming": 5,
        "expected": "stale",
    },
    {
        "name": "cross_region_linear_newer",
        "current": 120,
        "incoming": 128,
        "expected": "newer",
    },
    {
        "name": "cross_region_circular_stale",
        "current": 128,
        "incoming": 0,
        "expected": "stale",
    },
]
TX_SEQUENCE_TRANSITIONS = [
    {
        "name": "first_new_update",
        "advance_path_sequence": True,
        "path_lifetime": 255,
        "expected_dao_sequence": 241,
        "expected_path_sequence": 241,
    },
    {
        "name": "explicit_logical_copy",
        "advance_path_sequence": False,
        "path_lifetime": 255,
        "expected_dao_sequence": 242,
        "expected_path_sequence": 241,
    },
    {
        "name": "next_new_update",
        "advance_path_sequence": True,
        "path_lifetime": 0,
        "expected_dao_sequence": 243,
        "expected_path_sequence": 242,
    },
]
HOP_ADDRESSES = [f"fd0000000000000000000000000000{value:02x}" for value in range(0x10, 0x19)]
ROUTE_HOP_BOUNDARIES = [
    {"name": "eight_hops_accepted", "path": HOP_ADDRESSES[:8], "accepted": True},
    {"name": "nine_hops_rejected", "path": HOP_ADDRESSES, "accepted": False},
]


def target(prefix: str) -> dict:
    encoded = bytes([5, 18, 0, 128]) + bytes.fromhex(prefix)
    return {
        "kind": "target",
        "prefix_length": 128,
        "prefix": prefix,
        "encoded": encoded.hex(),
    }


def descriptor(value: int) -> dict:
    encoded = bytes([9, 4]) + value.to_bytes(4, "big")
    return {"kind": "descriptor", "value": value, "encoded": encoded.hex()}


def raw_descriptor(data: bytes) -> dict:
    encoded = bytes([9, len(data)]) + data
    return {"kind": "raw_descriptor", "data": data.hex(), "encoded": encoded.hex()}


def unsupported_option(option_type: int, data: bytes = b"") -> dict:
    encoded = bytes([option_type, len(data)]) + data
    return {
        "kind": "unsupported",
        "option_type": option_type,
        "data": data.hex(),
        "encoded": encoded.hex(),
    }


def transit(
    parent: str, sequence: int, lifetime: int, control: int, *, external: bool = False
) -> dict:
    encoded = bytes([6, 20, 0x80 if external else 0, control, sequence, lifetime]) + bytes.fromhex(
        parent
    )
    return {
        "kind": "transit",
        "external": external,
        "path_control": control,
        "path_sequence": sequence,
        "path_lifetime": lifetime,
        "parent": parent,
        "encoded": encoded.hex(),
    }


def dao(
    name: str,
    now: int,
    dao_sequence: int,
    options: list[dict],
    *,
    flags: int = 0,
    reserved: int = 0,
) -> dict:
    base = bytes([0, 0x40 | flags, reserved, dao_sequence]) + bytes.fromhex(DODAG)
    event = {
        "name": name,
        "event": "dao",
        "now_seconds": now,
        "dao_sequence": dao_sequence,
        "options": options,
        "dao_hex": (base + b"".join(bytes.fromhex(option["encoded"]) for option in options)).hex(),
    }
    if flags:
        event["flags"] = flags
    if reserved:
        event["reserved"] = reserved
    return event


def candidate(option: dict, now: int, lifetime_unit: int) -> dict:
    lifetime = option["path_lifetime"]
    return {
        "parent": option["parent"],
        "external": option["external"],
        "path_control": option["path_control"],
        "path_lifetime": lifetime,
        "installed_at": now,
        "expires_at": None if lifetime in (0, 255) else now + lifetime * lifetime_unit,
    }


def sequence_relation(incoming: int, current: int) -> str:
    if incoming == current:
        return "equal"
    incoming_circular = incoming < 128
    current_circular = current < 128
    if incoming_circular and current_circular:
        forward = (incoming - current) & 0x7F
        backward = (current - incoming) & 0x7F
        if forward <= 16:
            return "newer"
        return "stale" if backward <= 16 else "incomparable"
    if not incoming_circular and not current_circular:
        difference = incoming - current
        if 1 <= difference <= 16:
            return "newer"
        if -16 <= difference <= -1:
            return "stale"
        return "incomparable"
    if incoming_circular:
        return "newer" if 256 + incoming - current <= 16 else "stale"
    return "stale" if 256 + current - incoming <= 16 else "newer"


def preference_subfield(path_control: int) -> int:
    masks = (0xC0, 0x30, 0x0C, 0x03)
    return next(index for index, mask in enumerate(masks, 1) if path_control & mask)


def routing_table(state: dict[str, dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    routes: dict[str, dict] = {}
    selected: dict[str, dict] = {}
    unresolved = {prefix for prefix, record in state.items() if record["disposition"] == "active"}
    while unresolved:
        progress = False
        for prefix in sorted(unresolved):
            if any(
                item["parent"] != DODAG
                and item["parent"] in unresolved
                and state[item["parent"]]["disposition"] == "active"
                for item in state[prefix]["candidates"]
            ):
                continue
            candidates = []
            for item in state[prefix]["candidates"]:
                if item["parent"] == DODAG:
                    path = [prefix]
                elif item["parent"] in routes:
                    path = routes[item["parent"]]["path"] + [prefix]
                else:
                    continue
                candidates.append((preference_subfield(item["path_control"]), path, item))
            if not candidates:
                continue
            subfield, path, winner = min(candidates, key=lambda value: (value[0], value[1]))
            selected[prefix] = {
                "parent": winner["parent"],
                "preference_subfield": subfield,
                "path": path,
            }
            routes[prefix] = {
                "prefix_length": state[prefix]["prefix_length"],
                "prefix": prefix,
                "path": path,
                "path_lifetime": winner["path_lifetime"],
                "installed_at": winner["installed_at"],
                "expires_at": winner["expires_at"],
            }
            unresolved.remove(prefix)
            progress = True
            break
        if not progress:
            break
    return routes, selected


def snapshot(state: dict[str, dict]) -> dict:
    routes, selected = routing_table(state)
    records = []
    for prefix in sorted(state):
        record = deepcopy(state[prefix])
        for key in [key for key in record if key.startswith("_")]:
            record.pop(key)
        record["candidates"].sort(key=lambda item: item["parent"])
        record["selected_candidate"] = selected.get(prefix)
        records.append(record)
    return {
        "targets": records,
        "routing_table": {"routes": [routes[prefix] for prefix in sorted(routes)]},
    }


def contains_cycle(state: dict[str, dict]) -> bool:
    active = {prefix for prefix, record in state.items() if record["disposition"] == "active"}
    visiting: set[str] = set()
    complete: set[str] = set()

    def visit(prefix: str) -> bool:
        if prefix in visiting:
            return True
        if prefix in complete:
            return False
        visiting.add(prefix)
        for item in state[prefix]["candidates"]:
            if item["parent"] in active and visit(item["parent"]):
                return True
        visiting.remove(prefix)
        complete.add(prefix)
        return False

    return any(visit(prefix) for prefix in sorted(active))


def apply_dao(
    state: dict[str, dict],
    event: dict,
    limits: dict,
    lifetime_unit: int,
    retention_seconds: int,
) -> tuple[dict, dict]:
    if event.get("flags", 0) != 0 or event.get("reserved", 0) != 0:
        return state, {
            "accepted": False,
            "state_changed": False,
            "refreshed": False,
            "reason": "malformed_group",
        }
    groups: list[tuple[list[dict], list[dict]]] = []
    targets: list[dict] = []
    transits: list[dict] = []
    seen: set[str] = set()
    for option in event["options"]:
        if option["kind"] == "target":
            if transits:
                groups.append((targets, transits))
                targets, transits = [], []
            if option["prefix"] in seen:
                return state, {
                    "accepted": False,
                    "state_changed": False,
                    "refreshed": False,
                    "reason": "duplicate_target",
                }
            seen.add(option["prefix"])
            targets.append({"target": option, "descriptor": None})
        elif option["kind"] == "descriptor":
            if not targets or transits or targets[-1]["descriptor"] is not None:
                return state, {
                    "accepted": False,
                    "state_changed": False,
                    "refreshed": False,
                    "reason": "malformed_descriptor",
                }
            targets[-1]["descriptor"] = option["value"]
        elif option["kind"] == "raw_descriptor":
            return state, {
                "accepted": False,
                "state_changed": False,
                "refreshed": False,
                "reason": "malformed_descriptor",
            }
        elif option["kind"] == "unsupported":
            return state, {
                "accepted": False,
                "state_changed": False,
                "refreshed": False,
                "reason": "malformed_group",
            }
        else:
            if not targets:
                return state, {
                    "accepted": False,
                    "state_changed": False,
                    "refreshed": False,
                    "reason": "malformed_group",
                }
            transits.append(option)
    if targets and transits:
        groups.append((targets, transits))
    elif targets or transits:
        return state, {
            "accepted": False,
            "state_changed": False,
            "refreshed": False,
            "reason": "malformed_group",
        }

    proposal = deepcopy(state)
    changed = False
    result_reason = "semantic_replay"
    protected_prefixes = {
        grouped_target["target"]["prefix"]
        for group_targets, _ in groups
        for grouped_target in group_targets
    }
    for group_targets, group_transits in groups:
        sequences = {item["path_sequence"] for item in group_transits}
        lifetimes = {item["path_lifetime"] for item in group_transits}
        external = {item["external"] for item in group_transits}
        if any(external):
            return state, {
                "accepted": False,
                "state_changed": False,
                "refreshed": False,
                "reason": "unsupported_external",
            }
        if len(sequences) != 1 or len(lifetimes) != 1 or len(external) != 1:
            return state, {
                "accepted": False,
                "state_changed": False,
                "refreshed": False,
                "reason": "inconsistent_group",
            }
        sequence = next(iter(sequences))
        incoming = [candidate(item, event["now_seconds"], lifetime_unit) for item in group_transits]
        if len(incoming) > limits["max_candidates_per_target"]:
            return state, {
                "accepted": False,
                "state_changed": False,
                "refreshed": False,
                "reason": "capacity",
            }
        incoming_semantic = [
            {key: value for key, value in item.items() if key not in ("installed_at", "expires_at")}
            for item in incoming
        ]
        incoming_semantic.sort(key=lambda item: item["parent"])
        for grouped_target in group_targets:
            item = grouped_target["target"]
            prefix = item["prefix"]
            current = proposal.get(prefix)
            if current is None and len(proposal) >= limits["max_targets"]:
                reclaimable = [
                    (record["_updated_at"], retained_prefix)
                    for retained_prefix, record in proposal.items()
                    if retained_prefix not in protected_prefixes
                    and record["disposition"] != "active"
                    and record["_retain_until"] <= event["now_seconds"]
                ]
                if not reclaimable:
                    return state, {
                        "accepted": False,
                        "state_changed": False,
                        "refreshed": False,
                        "reason": "capacity",
                    }
                proposal.pop(min(reclaimable)[1])
            if current is not None:
                relation = sequence_relation(sequence, current["path_sequence"])
                current_semantic = [
                    {
                        key: value
                        for key, value in candidate_item.items()
                        if key not in ("installed_at", "expires_at")
                    }
                    for candidate_item in current["candidates"]
                ]
                current_semantic.sort(key=lambda value: value["parent"])
                if relation == "equal":
                    if (
                        current_semantic != incoming_semantic
                        or current["descriptor"] != grouped_target["descriptor"]
                    ):
                        return state, {
                            "accepted": False,
                            "state_changed": False,
                            "refreshed": False,
                            "reason": "equal_sequence_mutation",
                        }
                    if not changed:
                        result_reason = (
                            "equal_expired_no_revival"
                            if current["disposition"] == "expired"
                            else "semantic_replay"
                        )
                    continue
                if relation != "newer":
                    reason = (
                        "stale_withdrawal"
                        if next(iter(lifetimes)) == 0 and relation == "stale"
                        else f"{relation}_sequence"
                    )
                    return state, {
                        "accepted": False,
                        "state_changed": False,
                        "refreshed": False,
                        "reason": reason,
                    }
            lifetime = next(iter(lifetimes))
            disposition = "withdrawn" if lifetime == 0 else "active"
            proposal[prefix] = {
                "prefix_length": item["prefix_length"],
                "prefix": prefix,
                "descriptor": grouped_target["descriptor"],
                "sequence_authority": AUTHORITY,
                "path_sequence": sequence,
                "disposition": disposition,
                "candidates": incoming,
                "_updated_at": event["now_seconds"],
                "_retain_until": (
                    event["now_seconds"] + retention_seconds
                    if lifetime == 0
                    else (
                        incoming[0]["expires_at"] + retention_seconds
                        if incoming[0]["expires_at"] is not None
                        else None
                    )
                ),
            }
            changed = True
            if lifetime == 0:
                result_reason = "withdrawn"
            elif current is None:
                result_reason = "installed"
            elif current["disposition"] == "expired":
                result_reason = "reinstalled"
            else:
                result_reason = "replaced"

    candidate_count = sum(
        len(record["candidates"])
        for record in proposal.values()
        if record["disposition"] == "active"
    )
    if contains_cycle(proposal):
        return state, {
            "accepted": False,
            "state_changed": False,
            "refreshed": False,
            "reason": "cycle",
        }
    if len(proposal) > limits["max_targets"] or candidate_count > limits["max_candidates"]:
        return state, {
            "accepted": False,
            "state_changed": False,
            "refreshed": False,
            "reason": "capacity",
        }
    return proposal, {
        "accepted": True,
        "state_changed": changed,
        "refreshed": False,
        "reason": result_reason,
    }


def build_document() -> dict:
    limits = {
        "max_targets": 7,
        "max_candidates_per_target": 4,
        "max_candidates": 8,
    }
    lifetime_unit = 10
    retention_seconds = 3600
    two_targets = [target(TARGET_A), descriptor(0x01020304), target(TARGET_B)]
    two_parents = [transit(PARENT_2, 10, 10, 0x10), transit(PARENT_3, 10, 10, 0x40)]
    events = [
        dao(
            "install_parent_2_to_root",
            10,
            1,
            [target(PARENT_2), transit(DODAG, 1, 255, 0x80)],
        ),
        dao(
            "install_parent_3_to_root",
            20,
            2,
            [target(PARENT_3), transit(DODAG, 1, 255, 0x80)],
        ),
        dao(
            "install_parent_4_via_parent_2",
            30,
            3,
            [target(PARENT_4), transit(PARENT_2, 1, 255, 0x80)],
        ),
        dao("initial_multi_parent_grouped_install", 100, 4, two_targets + two_parents),
        dao("equal_exact_semantic_replay_no_refresh", 110, 5, two_targets + two_parents),
        dao(
            "equal_reordered_equivalence_no_refresh",
            120,
            6,
            two_targets + list(reversed(two_parents)),
        ),
        dao(
            "equal_descriptor_change_rejected",
            120,
            7,
            [
                target(TARGET_A),
                descriptor(0xA0B0C0D0),
                *two_parents,
            ],
        ),
        dao(
            "equal_descriptor_removal_rejected",
            120,
            8,
            [target(TARGET_A), *two_parents],
        ),
        dao(
            "equal_descriptor_addition_rejected",
            120,
            9,
            [
                target(TARGET_B),
                descriptor(0x01020304),
                *two_parents,
            ],
        ),
        dao(
            "equal_candidate_add_rejected",
            121,
            7,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                *two_parents,
                transit(PARENT_4, 10, 10, 0x04),
            ],
        ),
        dao(
            "equal_candidate_remove_rejected",
            122,
            8,
            [target(TARGET_A), two_parents[0]],
        ),
        dao(
            "equal_parent_mutation_rejected",
            123,
            9,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                two_parents[0],
                transit(PARENT_4, 10, 10, 0x40),
            ],
        ),
        dao(
            "equal_lifetime_mutation_rejected",
            124,
            10,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                transit(PARENT_2, 10, 11, 0x10),
                transit(PARENT_3, 10, 11, 0x40),
            ],
        ),
        dao(
            "equal_path_control_mutation_rejected",
            125,
            11,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                transit(PARENT_2, 10, 10, 0x20),
                two_parents[1],
            ],
        ),
        dao(
            "stale_path_sequence_rejected",
            126,
            12,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                transit(PARENT_2, 9, 10, 0x10),
                transit(PARENT_3, 9, 10, 0x40),
            ],
        ),
        dao(
            "incomparable_path_sequence_rejected",
            127,
            13,
            [
                target(TARGET_A),
                descriptor(0x01020304),
                transit(PARENT_2, 40, 10, 0x10),
                transit(PARENT_3, 40, 10, 0x40),
            ],
        ),
        dao(
            "newer_sequence_replaces_candidate_set",
            130,
            14,
            [target(TARGET_A), descriptor(0x01020304), transit(PARENT_4, 11, 20, 0x80)],
        ),
        dao(
            "stale_withdrawal_rejected",
            140,
            15,
            [target(TARGET_A), descriptor(0x01020304), transit(PARENT_4, 10, 0, 0x80)],
        ),
        dao(
            "newer_withdrawal",
            141,
            16,
            [target(TARGET_A), descriptor(0x01020304), transit(PARENT_4, 12, 0, 0x80)],
        ),
        {"name": "finite_lifetime_expiry", "event": "expire", "now_seconds": 200},
        dao(
            "equal_sequence_after_expiry_does_not_revive",
            201,
            17,
            [target(TARGET_B), *two_parents],
        ),
        dao(
            "newer_sequence_reinstalls_expired_target",
            202,
            18,
            [target(TARGET_B), transit(PARENT_2, 11, 5, 0x80)],
        ),
        dao(
            "malformed_inconsistent_group_rejected",
            203,
            19,
            [
                target(TARGET_B),
                transit(PARENT_2, 12, 5, 0x80),
                transit(PARENT_3, 13, 5, 0x40),
            ],
        ),
        dao(
            "reserved_dao_flags_rejected",
            203,
            19,
            [target(TARGET_B), transit(PARENT_2, 12, 5, 0x80)],
            flags=1,
        ),
        dao(
            "reserved_dao_byte_rejected",
            203,
            19,
            [target(TARGET_B), transit(PARENT_2, 12, 5, 0x80)],
            reserved=1,
        ),
        dao(
            "unsupported_dao_option_rejected",
            203,
            19,
            [target(TARGET_B), transit(PARENT_2, 12, 5, 0x80), unsupported_option(0xEE)],
        ),
        dao(
            "duplicate_target_rejected",
            204,
            20,
            [target(TARGET_B), target(TARGET_B), transit(PARENT_2, 12, 5, 0x80)],
        ),
        dao(
            "orphan_target_descriptor_rejected",
            205,
            21,
            [descriptor(0xA0B0C0D0), target(TARGET_B), transit(PARENT_2, 12, 5, 0x80)],
        ),
        dao(
            "duplicate_target_descriptor_rejected",
            206,
            22,
            [
                target(TARGET_B),
                descriptor(0x01020304),
                descriptor(0xA0B0C0D0),
                transit(PARENT_2, 12, 5, 0x80),
            ],
        ),
        dao(
            "target_descriptor_short_length_rejected",
            207,
            23,
            [
                target(TARGET_B),
                raw_descriptor(b"\x01\x02\x03"),
                transit(PARENT_2, 12, 5, 0x80),
            ],
        ),
        dao(
            "target_descriptor_long_length_rejected",
            208,
            24,
            [
                target(TARGET_B),
                raw_descriptor(b"\x01\x02\x03\x04\x05"),
                transit(PARENT_2, 12, 5, 0x80),
            ],
        ),
        dao(
            "target_descriptor_after_transit_rejected",
            209,
            25,
            [target(TARGET_B), transit(PARENT_2, 12, 5, 0x80), descriptor(0x01020304)],
        ),
        dao(
            "external_transit_rejected",
            210,
            26,
            [target(TARGET_B), transit(PARENT_2, 12, 5, 0x80, external=True)],
        ),
        dao(
            "child_before_parent_retains_candidate",
            211,
            27,
            [target(CHILD_6), transit(PARENT_5, 1, 255, 0x80)],
        ),
        dao(
            "parent_arrival_activates_child_route",
            212,
            28,
            [target(PARENT_5), transit(DODAG, 1, 255, 0x80)],
        ),
        dao(
            "cycle_rejected_atomically",
            213,
            29,
            [target(PARENT_5), transit(CHILD_6, 2, 255, 0x80)],
        ),
        dao(
            "per_target_candidate_capacity_failure_is_atomic",
            214,
            30,
            [
                target(TARGET_B),
                transit(PARENT_2, 12, 5, 0x80),
                transit(PARENT_3, 12, 5, 0x40),
                transit(PARENT_4, 12, 5, 0x10),
                transit(PARENT_5, 12, 5, 0x04),
                transit(DODAG, 12, 5, 0x01),
            ],
        ),
        dao(
            "candidate_capacity_failure_is_atomic",
            214,
            30,
            [
                target(TARGET_B),
                transit(PARENT_2, 12, 5, 0x80),
                transit(PARENT_3, 12, 5, 0x40),
                transit(PARENT_4, 12, 5, 0x10),
                transit(DODAG, 12, 5, 0x04),
            ],
        ),
        dao(
            "target_capacity_failure_is_atomic",
            215,
            31,
            [target(TARGET_C), transit(PARENT_3, 1, 5, 0x80)],
        ),
        {
            "name": "delayed_finite_lifetime_expiry",
            "event": "expire",
            "now_seconds": 260,
        },
        dao(
            "withdrawal_tombstone_not_reclaimed_early",
            3740,
            32,
            [target(TARGET_C), transit(PARENT_3, 1, 255, 0x80)],
        ),
        dao(
            "withdrawal_tombstone_reclaimed_at_deadline",
            3741,
            33,
            [target(TARGET_C), transit(PARENT_3, 1, 255, 0x80)],
        ),
        dao(
            "expiry_tombstone_not_reclaimed_early",
            3851,
            34,
            [target(TARGET_D), transit(PARENT_3, 1, 255, 0x80)],
        ),
        dao(
            "expiry_tombstone_reclaimed_at_deadline",
            3852,
            35,
            [target(TARGET_D), transit(PARENT_3, 1, 255, 0x80)],
        ),
        dao(
            "withdraw_target_c_for_group_reservation",
            4000,
            36,
            [target(TARGET_C), transit(PARENT_3, 2, 0, 0x80)],
        ),
        dao(
            "withdraw_target_d_for_group_reservation",
            4001,
            37,
            [target(TARGET_D), transit(PARENT_3, 2, 0, 0x80)],
        ),
        dao(
            "grouped_equal_target_is_reserved_during_reclamation",
            7601,
            38,
            [target(TARGET_E), target(TARGET_C), transit(PARENT_3, 2, 0, 0x80)],
        ),
    ]

    state: dict[str, dict] = {}
    vectors = []
    for event in events:
        before = snapshot(state)
        if event["event"] == "expire":
            changed = False
            for record in state.values():
                if (
                    record["disposition"] == "active"
                    and record["candidates"]
                    and all(
                        item["expires_at"] is not None
                        and item["expires_at"] <= event["now_seconds"]
                        for item in record["candidates"]
                    )
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
            state, outcome = apply_dao(state, event, limits, lifetime_unit, retention_seconds)
        event["before"] = before
        event["expected"] = {**outcome, "state": snapshot(state)}
        vectors.append(event)

    return {
        "vector_type": "rpl_route_state",
        "format_version": 2,
        "description": (
            "Canonical post-provenance RPL DAO route-state transitions from fixed "
            "RFC 6550 option bytes and LICHEN Section 8.8 semantics (v2 schema)."
        ),
        "oracle": {
            "basis": (
                "RFC 6550 Sections 6.7.7-6.7.11, 7.2, and 9.9; spec/05-routing.md Sections 8.8-8.9"
            ),
            "scope": (
                "Route-state processing after DAO provenance, authorization, and "
                "origin replay acceptance"
            ),
            "sequence_policy": (
                "RFC 6550 Section 7.2 rule 2 direct increments 127->0 and 255->0 "
                "are newer; all other comparisons use rule 3 with SEQUENCE_WINDOW=16"
            ),
            "lifetime_unit_seconds": lifetime_unit,
            "freshness_retention_seconds": retention_seconds,
            "path_control_size": 7,
            "max_route_hops": 8,
            "rpl_instance_id": 0,
            "dodag_id": DODAG,
            "sequence_authority": AUTHORITY,
            "limits": limits,
        },
        "sequence_relations": SEQUENCE_RELATIONS,
        "tx_sequence_transitions": TX_SEQUENCE_TRANSITIONS,
        "route_hop_boundaries": ROUTE_HOP_BOUNDARIES,
        "vectors": vectors,
    }


def main() -> None:
    document = build_document()
    for case in document["sequence_relations"]:
        actual = sequence_relation(case["incoming"], case["current"])
        if actual != case["expected"]:
            raise SystemExit(f"{case['name']}: generated {actual}, expected {case['expected']}")
    if sys.argv[1:] == ["--check"]:
        if json.loads(OUT.read_text()) != document:
            raise SystemExit(f"{OUT.name} is not deterministically generated")
        print(f"checked {len(document['vectors'])} vectors in {OUT.name}")
        return
    if sys.argv[1:]:
        raise SystemExit("usage: generate_rpl_route_state.py [--check]")
    OUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {len(document['vectors'])} vectors to {OUT.name}")


if __name__ == "__main__":
    main()
