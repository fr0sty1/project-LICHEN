# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate C constants directly from the canonical B.2 JSON vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


def _object_no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_non_finite_constant(constant: str) -> float:
    raise ValueError(f"non-finite JSON constant {constant!r}")


def _ensure_finite(value: Any, source: str) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _ensure_finite(item, source)
    elif isinstance(value, list):
        for item in value:
            _ensure_finite(item, source)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{source}: non-finite JSON number {value!r}")


def load(vectors_dir: Path, name: str) -> dict[str, Any]:
    with (vectors_dir / name).open(encoding="utf-8") as source:
        document = json.load(
            source,
            object_pairs_hook=_object_no_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    if not isinstance(document, dict):
        raise ValueError(f"{name}: top level must be an object")
    _ensure_finite(document, name)
    return document


def integer(mapping: dict[str, Any], key: str, source: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{source}: {key} must be an integer")
    return value


def strict_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            strict_json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def behavior_digest(document: dict[str, Any]) -> str:
    metadata = {"description", "note", "reason", "evicted_reason"}

    def project(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: project(item) for key, item in value.items() if key not in metadata}
        if isinstance(value, list):
            return [project(item) for item in value]
        return value

    encoded = json.dumps(
        project(document), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def named_cases(document: dict[str, Any], source: str) -> dict[str, dict[str, Any]]:
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        raise ValueError(f"{source}: vectors must be an array")
    result: dict[str, dict[str, Any]] = {}
    for case in vectors:
        if not isinstance(case, dict) or not isinstance(case.get("name"), str):
            raise ValueError(f"{source}: every vector must be a named object")
        name = case["name"]
        if name in result:
            raise ValueError(f"{source}: duplicate vector name {name}")
        result[name] = case
    return result


def expect_path(
    cases: dict[str, dict[str, Any]],
    case_name: str,
    path: tuple[str, ...],
    expected: Any,
    source: str,
) -> None:
    if case_name not in cases:
        raise ValueError(f"{source}: missing vector {case_name}")
    value: Any = cases[case_name]
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"{source}: {case_name} missing {'.'.join(path)}")
        value = value[key]
    if not strict_json_equal(value, expected):
        raise ValueError(
            f"{source}: {case_name} {'.'.join(path)} is {value!r}, "
            f"expected {expected!r}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    bounded = load(args.vectors_dir, "tx_queue_bounded.json")
    expiry = load(args.vectors_dir, "tx_queue_expiry.json")
    priority = load(args.vectors_dir, "tx_queue_priority.json")
    implementation = load(args.vectors_dir, "tx_queue_implementation.json")

    expected_digests = {
        "tx_queue_bounded.json": "6d2d4724777086b7e538b13e71b4e9903c1e5c13c0d8ac06c120445818ac0952",
        "tx_queue_expiry.json": "88ad5fa59ec81cbeda4ae3043936232a7e2627eef9552d3712269846554cda95",
        "tx_queue_priority.json": (
            "d6b6aafa9339d40b8fac918466464db9baffcbefef6a5544e35543cc80da942e"
        ),
        "tx_queue_implementation.json": (
            "d6c304d3f61e246c2980b78d196b0c354cbb624c588b0b6bcf02638475d53d63"
        ),
    }
    for source, document in (
        ("tx_queue_bounded.json", bounded),
        ("tx_queue_expiry.json", expiry),
        ("tx_queue_priority.json", priority),
        ("tx_queue_implementation.json", implementation),
    ):
        actual = behavior_digest(document)
        if actual != expected_digests[source]:
            raise ValueError(
                f"{source}: unconsumed behavior changed (digest {actual}); "
                "update the C vector consumer deliberately"
            )

    bounded_cases = named_cases(bounded, "tx_queue_bounded.json")
    expiry_cases = named_cases(expiry, "tx_queue_expiry.json")
    priority_cases_document = named_cases(priority, "tx_queue_priority.json")
    implementation_cases = named_cases(
        implementation, "tx_queue_implementation.json"
    )
    bounded_capacity = integer(
        bounded_cases["capacity_default_4"]["expected"],
        "capacity",
        "tx_queue_bounded.json",
    )
    expiry_constants = expiry.get("constants")
    priority_constants = priority.get("constants")
    implementation_constants = implementation.get("constants")
    if not all(
        isinstance(value, dict)
        for value in (expiry_constants, priority_constants, implementation_constants)
    ):
        raise ValueError("vector constants must be objects")

    values = {
        "VECTOR_TX_QUEUE_CAPACITY": bounded_capacity,
        "VECTOR_PRIORITY_SOS": integer(priority_constants, "PRIORITY_SOS", "priority"),
        "VECTOR_PRIORITY_ROUTING": integer(
            priority_constants, "PRIORITY_ROUTING", "priority"
        ),
        "VECTOR_PRIORITY_ACK": integer(priority_constants, "PRIORITY_ACK", "priority"),
        "VECTOR_PRIORITY_URGENT": integer(
            priority_constants, "PRIORITY_URGENT", "priority"
        ),
        "VECTOR_PRIORITY_NORMAL": integer(
            priority_constants, "PRIORITY_NORMAL", "priority"
        ),
        "VECTOR_PRIORITY_BULK": integer(priority_constants, "PRIORITY_BULK", "priority"),
        "VECTOR_DEADLINE_SOS_MS": integer(expiry_constants, "DEADLINE_SOS_MS", "expiry"),
        "VECTOR_DEADLINE_ROUTING_MS": integer(
            expiry_constants, "DEADLINE_ROUTING_MS", "expiry"
        ),
        "VECTOR_DEADLINE_ACK_MS": integer(expiry_constants, "DEADLINE_ACK_MS", "expiry"),
        "VECTOR_DEADLINE_URGENT_MS": integer(
            expiry_constants, "DEADLINE_URGENT_MS", "expiry"
        ),
        "VECTOR_DEADLINE_NORMAL_MS": integer(
            expiry_constants, "DEADLINE_NORMAL_MS", "expiry"
        ),
        "VECTOR_DEADLINE_BULK_MS": integer(
            expiry_constants, "DEADLINE_BULK_MS", "expiry"
        ),
        "VECTOR_ENOBUFS": integer(implementation_constants, "ENOBUFS", "implementation"),
    }

    capacity_sources = (
        integer(priority_constants, "CAPACITY", "priority"),
        integer(expiry_constants, "CAPACITY", "expiry"),
        integer(implementation_constants, "TX_QUEUE_SIZE", "implementation"),
    )
    if any(capacity != bounded_capacity for capacity in capacity_sources):
        raise ValueError("canonical vector files disagree on TX queue capacity")
    if values["VECTOR_PRIORITY_ACK"] != values["VECTOR_PRIORITY_ROUTING"]:
        raise ValueError("canonical vectors require ACK to alias ROUTING")

    bounded_priority_cases = {
        "priority_p0_sos": "SOS",
        "priority_p1_routing": "ROUTING",
        "priority_p2_urgent": "URGENT",
        "priority_p3_normal": "NORMAL",
        "priority_p4_bulk": "BULK",
    }
    for case_name, priority_name in bounded_priority_cases.items():
        expect_path(
            bounded_cases,
            case_name,
            ("expected", "priority_value"),
            values[f"VECTOR_PRIORITY_{priority_name}"],
            "tx_queue_bounded.json",
        )

    deadline_cases = {
        "deadline_sos_2000ms": "SOS",
        "deadline_routing_5000ms": "ROUTING",
        "deadline_urgent_30000ms": "URGENT",
        "deadline_normal_60000ms": "NORMAL",
        "deadline_bulk_120000ms": "BULK",
    }
    for case_name, priority_name in deadline_cases.items():
        expect_path(
            bounded_cases,
            case_name,
            ("expected", "deadline_ms"),
            values[f"VECTOR_DEADLINE_{priority_name}_MS"],
            "tx_queue_bounded.json",
        )

    bounded_expectations = (
        ("preemption_higher_evicts_lower", ("expected", "action"), "preempt"),
        (
            "preemption_higher_evicts_lower",
            ("expected", "evicted_priority"),
            "BULK",
        ),
        ("backpressure_same_priority_rejected", ("expected", "action"), "reject"),
        ("backpressure_lower_priority_rejected", ("expected", "action"), "reject"),
        ("expiry_drops_stale_packets", ("expected", "action"), "drop"),
        (
            "expiry_drops_stale_packets",
            ("expected", "stat_increment"),
            "packets_dropped_deadline",
        ),
        (
            "pop_order_by_priority_then_fifo",
            ("expected", "pop_order"),
            ["routing1", "routing2", "bulk1", "bulk2"],
        ),
    )
    for case_name, path, expected in bounded_expectations:
        expect_path(bounded_cases, case_name, path, expected, "tx_queue_bounded.json")

    implementation_expectations = (
        ("push_checks_deadline_before_admission", ("expected", "action"), "accept"),
        (
            "push_checks_deadline_before_admission",
            ("expected", "stats", "packets_dropped_deadline"),
            2,
        ),
        (
            "push_preempts_lowest_when_full_higher_priority",
            ("expected", "action"),
            "preempt",
        ),
        (
            "push_preempts_lowest_when_full_higher_priority",
            ("expected", "evicted_priority"),
            "BULK",
        ),
        ("push_rejects_same_priority_when_full", ("expected", "error"), "ENOBUFS"),
        ("push_rejects_lower_priority_when_full", ("expected", "error"), "ENOBUFS"),
        (
            "push_preempts_oldest_among_same_lowest",
            ("expected", "evicted_data"),
            "bulk1",
        ),
    )
    for case_name, path, expected in implementation_expectations:
        expect_path(
            implementation_cases,
            case_name,
            path,
            expected,
            "tx_queue_implementation.json",
        )

    priority_by_name = {
        name: values[f"VECTOR_PRIORITY_{name}"]
        for name in ("SOS", "ROUTING", "ACK", "URGENT", "NORMAL", "BULK")
    }
    bounded_scenarios = (
        (
            "preemption_higher_evicts_lower",
            ("scenario", "initial_packets"),
            [
                {"data": "bulk1", "priority": "BULK"},
                {"data": "bulk2", "priority": "BULK"},
            ],
        ),
        (
            "preemption_higher_evicts_lower",
            ("scenario", "incoming"),
            {"data": "routing", "priority": "ROUTING"},
        ),
        (
            "backpressure_same_priority_rejected",
            ("scenario", "incoming", "priority"),
            "BULK",
        ),
        (
            "backpressure_lower_priority_rejected",
            ("scenario", "initial_packets"),
            [
                {"data": "urgent1", "priority": "URGENT"},
                {"data": "urgent2", "priority": "URGENT"},
            ],
        ),
        (
            "backpressure_lower_priority_rejected",
            ("scenario", "incoming", "priority"),
            "BULK",
        ),
        (
            "expiry_drops_stale_packets",
            ("scenario", "packet", "deadline_ms"),
            100,
        ),
        ("expiry_drops_stale_packets", ("scenario", "time_advance_ms"), 200),
        (
            "pop_order_by_priority_then_fifo",
            ("scenario", "push_sequence"),
            [
                {"data": "bulk1", "priority": "BULK"},
                {"data": "routing1", "priority": "ROUTING"},
                {"data": "bulk2", "priority": "BULK"},
                {"data": "routing2", "priority": "ROUTING"},
            ],
        ),
    )
    for case_name, path, expected in bounded_scenarios:
        expect_path(bounded_cases, case_name, path, expected, "tx_queue_bounded.json")

    implementation_scenarios = (
        ("push_checks_deadline_before_admission", ("scenario", "now_ms"), 200),
        (
            "push_checks_deadline_before_admission",
            ("scenario", "incoming", "deadline_ms"),
            10000,
        ),
        (
            "push_preempts_lowest_when_full_higher_priority",
            ("scenario", "incoming", "priority"),
            "ROUTING",
        ),
        (
            "push_rejects_same_priority_when_full",
            ("scenario", "incoming", "priority"),
            "BULK",
        ),
        (
            "push_rejects_lower_priority_when_full",
            ("scenario", "incoming", "priority"),
            "BULK",
        ),
        (
            "push_preempts_oldest_among_same_lowest",
            ("scenario", "operations"),
            [
                {
                    "action": "push",
                    "data": "bulk1",
                    "deadline_ms": 120000,
                    "priority": "BULK",
                    "enqueue_time_ms": 0,
                },
                {
                    "action": "push",
                    "data": "bulk2",
                    "deadline_ms": 120000,
                    "priority": "BULK",
                    "enqueue_time_ms": 10,
                },
                {
                    "action": "push",
                    "data": "bulk3",
                    "deadline_ms": 120000,
                    "priority": "BULK",
                    "enqueue_time_ms": 20,
                },
                {
                    "action": "push",
                    "data": "urgent",
                    "priority": "URGENT",
                    "deadline_ms": 30000,
                    "enqueue_time_ms": 30,
                },
            ],
        ),
    )
    for case_name, path, expected in implementation_scenarios:
        expect_path(
            implementation_cases,
            case_name,
            path,
            expected,
            "tx_queue_implementation.json",
        )

    expiry_defaults = {
        "default_deadline_sos": ("SOS", 0),
        "default_deadline_routing": ("ROUTING", 0),
        "default_deadline_ack": ("ACK", 0),
        "default_deadline_urgent": ("URGENT", 0),
        "default_deadline_normal": ("NORMAL", 0),
        "default_deadline_bulk": ("BULK", 0),
    }
    for case_name, (priority_name, enqueue_ms) in expiry_defaults.items():
        expect_path(
            expiry_cases,
            case_name,
            ("priority",),
            priority_by_name[priority_name],
            "tx_queue_expiry.json",
        )
        expected_deadline = (
            values["VECTOR_DEADLINE_ROUTING_MS"]
            if priority_name == "ACK"
            else values[f"VECTOR_DEADLINE_{priority_name}_MS"]
        )
        expect_path(
            expiry_cases,
            case_name,
            ("expected_deadline_ms",),
            enqueue_ms + expected_deadline,
            "tx_queue_expiry.json",
        )
        expect_path(
            expiry_cases,
            case_name,
            ("enqueue_time_ms",),
            enqueue_ms,
            "tx_queue_expiry.json",
        )

    boundary = expiry_cases["boundary_condition_exact"]
    expect_path(
        expiry_cases,
        "boundary_condition_exact",
        ("test_times",),
        [
            {"now_ms": 199, "expired": False, "reason": "one ms before"},
            {"now_ms": 200, "expired": True, "reason": "exactly at deadline"},
            {"now_ms": 201, "expired": True, "reason": "one ms after"},
        ],
        "tx_queue_expiry.json",
    )
    values["VECTOR_EXPIRY_ENQUEUE_MS"] = integer(
        boundary, "enqueue_time_ms", "boundary_condition_exact"
    )
    values["VECTOR_EXPIRY_DEADLINE_MS"] = integer(
        boundary, "custom_deadline_ms", "boundary_condition_exact"
    )
    values["VECTOR_EXPIRY_BEFORE_MS"] = boundary["test_times"][0]["now_ms"]
    values["VECTOR_EXPIRY_EXACT_MS"] = boundary["test_times"][1]["now_ms"]

    alias_case = priority_cases_document["ack_alias_same_as_routing"]
    alias_pushes = alias_case.get("scenario", {}).get("push_sequence")
    alias_order = alias_case.get("expected", {}).get("pop_order")
    expected_alias_pushes = [
        {"data": "bulk", "priority": "BULK"},
        {"data": "ack", "priority": "ACK"},
        {"data": "routing", "priority": "ROUTING"},
        {"data": "urgent", "priority": "URGENT"},
    ]
    expected_alias_order = ["ack", "routing", "urgent", "bulk"]
    if alias_pushes != expected_alias_pushes or alias_order != expected_alias_order:
        raise ValueError("tx_queue_priority.json: ACK alias scenario is not canonical")

    expect_path(
        priority_cases_document,
        "fifo_within_same_priority",
        ("expected", "pop_order"),
        ["bulk_first", "bulk_second", "bulk_third", "bulk_fourth"],
        "tx_queue_priority.json",
    )
    expect_path(
        priority_cases_document,
        "preemption_sos_evicts_bulk",
        ("scenario", "incoming", "priority"),
        "SOS",
        "tx_queue_priority.json",
    )
    expect_path(
        priority_cases_document,
        "preemption_sos_evicts_bulk",
        ("expected", "evicted_priority"),
        "BULK",
        "tx_queue_priority.json",
    )
    payload_by_name = {
        operation["data"]: index + 1 for index, operation in enumerate(alias_pushes)
    }
    for index, operation in enumerate(alias_pushes):
        values[f"VECTOR_ALIAS_PUSH_{index}_DATA"] = payload_by_name[operation["data"]]
        values[f"VECTOR_ALIAS_PUSH_{index}_PRIORITY"] = priority_by_name[
            operation["priority"]
        ]
    for index, data_name in enumerate(alias_order):
        values[f"VECTOR_ALIAS_POP_{index}_DATA"] = payload_by_name[data_name]

    lines = [
        "/* Generated from test/vectors/tx_queue_*.json; do not edit. */",
        "#ifndef LICHEN_TEST_TX_QUEUE_VECTORS_H_",
        "#define LICHEN_TEST_TX_QUEUE_VECTORS_H_",
        "",
    ]
    lines.extend(f"#define {name} ({value})" for name, value in values.items())
    lines.extend(["", "#endif", ""])
    args.output.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
