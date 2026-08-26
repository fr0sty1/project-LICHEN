# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Canonical routing address-classification table tests."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.rpl import (
    AddressClassification,
    AddressClassificationError,
    AddressClassificationTable,
    EvidenceCapacityError,
    EvidenceError,
    EvidenceTimeError,
    GradientEntry,
)

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "address_classification.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("address_classification.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text()))


def _expected_exception(code: str) -> type[Exception]:
    return {
        "invalid_source": EvidenceError,
        "non_primary": AddressClassificationError,
        "capacity": EvidenceCapacityError,
        "time_regression": EvidenceTimeError,
        "timestamp_overflow": EvidenceTimeError,
        "invalid_address": AddressClassificationError,
    }[code]


def _run_operation(table: AddressClassificationTable, operation: dict[str, Any]) -> None:
    def invoke() -> object:
        if operation["op"] == "update":
            return table.update_authenticated(
                operation["address"], operation["now_s"], source=operation["source"]
            )
        return table.classify(operation["address"], operation["now_s"])

    error_code = operation.get("expected_error")
    if error_code is not None:
        with pytest.raises(_expected_exception(error_code)) as caught:
            invoke()
        expected_fragment = {
            "invalid_source": "unauthenticated",
            "non_primary": "primary 0200::/8",
            "capacity": "full",
            "time_regression": "regressed",
            "timestamp_overflow": "overflow",
            "invalid_address": "invalid IPv6",
        }[error_code]
        assert expected_fragment in str(caught.value)
    else:
        result = invoke()
        if operation["op"] == "update":
            assert isinstance(result, GradientEntry)
            assert result.expires_at_s == operation["expected_expires_at_s"]
        else:
            assert isinstance(result, AddressClassification)
            assert result.value == operation["expected_classification"]
    assert len(table) == operation["expected_size"]


def test_address_classification_document_matches_dedicated_schema() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


@pytest.mark.parametrize("scenario", _document()["scenarios"], ids=lambda item: item["name"])
def test_address_classification_scenario(scenario: dict[str, Any]) -> None:
    table = AddressClassificationTable(max_peers=scenario["max_peers"])
    for operation in scenario["operations"]:
        _run_operation(table, operation)


def test_public_classification_values_match_vector_table() -> None:
    assert {classification.value for classification in AddressClassification} == set(
        _document()["classifications"]
    )


def test_ipv6address_input_uses_same_canonical_key() -> None:
    table = AddressClassificationTable()
    table.update_authenticated(IPv6Address("0200::1"), 0, source="data")
    assert table.classify("200:0:0:0:0:0:0:1", 0) is AddressClassification.LOCAL_MESH
