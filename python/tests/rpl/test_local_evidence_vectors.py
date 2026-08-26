# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Canonical tests for bounded LOADng local-evidence lifetime tracking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.rpl import (
    LOCAL_EVIDENCE_LIFETIME_SECONDS,
    MAX_LOCAL_EVIDENCE_PEERS,
    EvidenceCapacityError,
    EvidenceError,
    EvidenceTable,
    EvidenceTimeError,
    GradientEntry,
)

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "local_evidence.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("local_evidence.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text()))


def _expected_exception(code: str) -> type[EvidenceError]:
    return {
        "time_regression": EvidenceTimeError,
        "timestamp_overflow": EvidenceTimeError,
        "capacity": EvidenceCapacityError,
        "invalid_source": EvidenceError,
    }[code]


def _run_operation(table: EvidenceTable, operation: dict[str, Any]) -> None:
    def invoke() -> object:
        if operation["op"] == "refresh":
            return table.refresh(
                operation["destination"],
                operation["now_s"],
                source=operation["source"],
            )
        return table.has_evidence(operation["destination"], operation["now_s"])

    error_code = operation.get("expected_error")
    if error_code is not None:
        with pytest.raises(_expected_exception(error_code)) as caught:
            invoke()
        if error_code == "time_regression":
            assert "regressed" in str(caught.value)
        elif error_code == "timestamp_overflow":
            assert "overflow" in str(caught.value)
        elif error_code == "capacity":
            assert "full" in str(caught.value)
        elif error_code == "invalid_source":
            assert "unauthenticated" in str(caught.value)
    else:
        result = invoke()
        if operation["op"] == "refresh":
            assert isinstance(result, GradientEntry)
            assert result.expires_at_s == operation["expected_expires_at_s"]
            assert result.expires_at_s - result.observed_at_s == 1200
        else:
            assert result is operation["expected_result"]
    assert len(table) == operation["expected_size"]


def test_local_evidence_vector_document_matches_dedicated_schema() -> None:
    """Keep the operation corpus closed and structurally deterministic."""
    schema = json.loads(_SCHEMA_PATH.read_text())
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


@pytest.mark.parametrize("scenario", _document()["scenarios"], ids=lambda item: item["name"])
def test_local_evidence_scenario(scenario: dict[str, Any]) -> None:
    """Execute every operation without hidden wall-clock dependencies."""
    table = EvidenceTable(max_peers=scenario["max_peers"])
    for operation in scenario["operations"]:
        _run_operation(table, operation)


def test_public_constants_match_canonical_vector() -> None:
    document = _document()
    assert LOCAL_EVIDENCE_LIFETIME_SECONDS == document["lifetime_seconds"] == 1200
    assert MAX_LOCAL_EVIDENCE_PEERS == document["default_max_peers"] == 32


@pytest.mark.parametrize("source", ["announce", "rrep", "rpl", "data"])
def test_all_authenticated_sources_refresh_exact_lifetime(source: str) -> None:
    table = EvidenceTable()
    entry = table.refresh("0200::10", 50, source=source)
    assert entry.expires_at_s == 1250


def test_prune_reclaims_all_expired_peers() -> None:
    table = EvidenceTable(max_peers=2)
    table.refresh("0200::1", 0, source="announce")
    table.refresh("0200::2", 1, source="rrep")
    assert table.prune(1200) == 1
    assert len(table) == 1
    assert table.prune(1201) == 1
    assert len(table) == 0


@pytest.mark.parametrize("max_peers", [0, -1, True, 1.5])
def test_invalid_capacity_is_rejected(max_peers: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        EvidenceTable(max_peers=max_peers)  # type: ignore[arg-type]
