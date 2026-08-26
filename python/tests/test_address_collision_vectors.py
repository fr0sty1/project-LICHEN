# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Canonical tests for authenticated IPv6 address collision detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen import (
    ADDRESS_CLAIM_LIFETIME_SECONDS,
    MAX_COLLISION_ADDRESSES,
    MAX_KEYS_PER_ADDRESS,
    AddressBindingError,
    AddressCollisionCapacityError,
    AddressCollisionDetector,
    AddressCollisionError,
    AddressCollisionTimeError,
    CollisionObservation,
    verify_native_address_binding,
)

_VECTORS_PATH = Path(__file__).parents[2] / "test" / "vectors" / "address_collision.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("address_collision.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text()))


def _expected_exception(code: str) -> type[AddressCollisionError]:
    if code in {
        "binding_mismatch",
        "invalid_key_length",
        "invalid_key_point",
        "invalid_native_address",
    }:
        return AddressBindingError
    if code in {"time_regression", "timestamp_overflow"}:
        return AddressCollisionTimeError
    if code in {"address_capacity", "key_capacity"}:
        return AddressCollisionCapacityError
    return AddressCollisionError


def _invoke(
    table: AddressCollisionDetector, operation: dict[str, Any]
) -> CollisionObservation | tuple[bytes, ...] | bytes:
    now_s = operation["now_s"]
    if operation["op"] == "observe":
        return table.observe_authenticated(
            operation["address"],
            bytes.fromhex(operation["public_key_hex"]),
            now_s,
            source=operation["source"],
            link_scope=operation.get("link_scope"),
        )
    if operation["op"] == "observe_bound_native":
        return table.observe_bound_native(
            operation["address"],
            bytes.fromhex(operation["public_key_hex"]),
            now_s,
            source=operation["source"],
        )
    if operation["op"] == "query":
        return table.keys_for(operation["address"], now_s, link_scope=operation.get("link_scope"))
    return table.snapshot(now_s)


def _assert_error(code: str, error: AddressCollisionError) -> None:
    fragment = {
        "invalid_source": "unauthenticated",
        "address_capacity": "collision table is full",
        "key_capacity": "key capacity is full",
        "missing_scope": "link_scope",
        "native_scope": "must not have",
        "time_regression": "regressed",
        "timestamp_overflow": "overflow",
        "binding_mismatch": "does not match",
        "invalid_key_length": "exactly 32",
        "invalid_key_point": "prime-order",
        "invalid_native_address": "unscoped native 0200::/8",
    }[code]
    assert fragment in str(error)


def _run_operation(
    table: AddressCollisionDetector, operation: dict[str, Any]
) -> AddressCollisionDetector:
    error_code = operation.get("expected_error")
    if error_code is not None:
        with pytest.raises(_expected_exception(error_code)) as caught:
            _invoke(table, operation)
        _assert_error(error_code, caught.value)
    elif operation["op"] in {"observe", "observe_bound_native"}:
        result = _invoke(table, operation)
        assert isinstance(result, CollisionObservation)
        assert result.status.value == operation["expected_status"]
        assert result.is_collision is operation["expected_collision"]
        assert len(result.public_keys) == operation["expected_key_count"]
        assert result.expires_at_s == operation["expected_expires_at_s"]
    elif operation["op"] == "query":
        result = _invoke(table, operation)
        assert isinstance(result, tuple)
        assert len(result) == operation["expected_key_count"]
        assert (
            table.is_collision(
                operation["address"],
                operation["now_s"],
                link_scope=operation.get("link_scope"),
            )
            is operation["expected_collision"]
        )
    else:
        snapshot = _invoke(table, operation)
        assert isinstance(snapshot, bytes)
        assert snapshot == table.snapshot(operation["now_s"])
        table = AddressCollisionDetector.from_snapshot(snapshot, operation["now_s"])
    assert len(table) == operation["expected_size"]
    return table


def test_address_collision_document_matches_dedicated_schema() -> None:
    """Keep collision cases closed and structurally deterministic."""
    schema = json.loads(_SCHEMA_PATH.read_text())
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


@pytest.mark.parametrize("scenario", _document()["scenarios"], ids=lambda item: item["name"])
def test_address_collision_scenario(scenario: dict[str, Any]) -> None:
    """Execute the canonical trace without wall-clock or identity-module coupling."""
    table = AddressCollisionDetector(
        max_addresses=scenario["max_addresses"],
        max_keys_per_address=scenario["max_keys_per_address"],
    )
    for operation in scenario["operations"]:
        table = _run_operation(table, operation)


def test_public_constants_match_canonical_vector() -> None:
    document = _document()
    assert ADDRESS_CLAIM_LIFETIME_SECONDS == document["claim_lifetime_seconds"] == 1200
    assert MAX_COLLISION_ADDRESSES == 32
    assert MAX_KEYS_PER_ADDRESS == 4


def test_public_binding_helper_returns_canonical_address() -> None:
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    result = verify_native_address_binding("020e:02a5:0225:b4ba:0c02:a502:25b4:baaa", public_key)
    assert result.packed.hex() == "020e02a50225b4ba0c02a50225b4baaa"


def test_restart_rejects_regression_and_malformed_state() -> None:
    table = AddressCollisionDetector()
    table.observe_authenticated("0200::1", bytes(32), 10, source="link_signature")
    snapshot = table.snapshot(20)

    with pytest.raises(AddressCollisionTimeError, match="regressed"):
        AddressCollisionDetector.from_snapshot(snapshot, 19)
    with pytest.raises(AddressCollisionError, match="invalid"):
        AddressCollisionDetector.from_snapshot(b"not-json", 20)
    with pytest.raises(AddressCollisionError, match="invalid"):
        AddressCollisionDetector.from_snapshot(b"[]", 20)


@pytest.mark.parametrize("max_addresses", [0, -1, True, 1.5])
def test_invalid_address_capacity_is_rejected(max_addresses: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        AddressCollisionDetector(max_addresses=max_addresses)  # type: ignore[arg-type]
