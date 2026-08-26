# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: LCI access control vs shared vectors.

Drives ``lichen.coap.access`` against every section of
``test/vectors/access_levels.json`` (spec/11-lci.md 17.6.3).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.coap.access import AccessLevel, can_access, level_for_transport

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "access_levels.json"

_LEVEL_BY_NAME = {lvl.value: lvl for lvl in AccessLevel}


def _doc() -> dict:
    return json.loads(_VECTORS_PATH.read_text())


@pytest.mark.parametrize("case", _doc()["vectors"]["transport_binding"], ids=lambda v: v["name"])
def test_transport_binding(case: dict) -> None:
    assert level_for_transport(case["transport"]) is _LEVEL_BY_NAME[case["expected_level"]]


def test_unknown_transport_rejected() -> None:
    with pytest.raises(ValueError):
        level_for_transport("smoke-signal")


def _authz_cases(section: str) -> list[dict]:
    return _doc()["vectors"][section]


@pytest.mark.parametrize(
    "case",
    [
        c
        for section in ("read_only_level", "standard_level", "admin_level", "edge_cases")
        for c in _authz_cases(section)
    ],
    ids=lambda v: v["name"],
)
def test_authorization_matrix(case: dict) -> None:
    level = _LEVEL_BY_NAME[case["access_level"]]
    allowed, code = can_access(
        level,
        case["method"],
        case["resource"],
        observe=case.get("observe", False),
    )
    assert allowed is case["allowed"], case["description"]
    if case["allowed"]:
        assert code is None
    else:
        assert code == case["error_code"], f"{case['name']}: got {code}, want {case['error_code']}"


def test_unknown_resource_404_precedes_level() -> None:
    # Even read_only gets the same 4.04 as admin on a missing resource.
    for lvl in (_LEVEL_BY_NAME["read_only"], _LEVEL_BY_NAME["admin"]):
        allowed, code = can_access(lvl, "GET", "/nonexistent")
        assert (allowed, code) == (False, "4.04")
