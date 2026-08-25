# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume every ``ccp4_regional_channel_plans.json`` vector through the real oracle.

Drives ``lichen.channel_plan`` (the oracle declared by the vector file header)
through all committed CCP-4 regional channel plan vectors per spec
02a-coordinated-capacity.md:164-182.

Known divergence (deliberate, documented, tracked in beads): the vectors
``get_plan_unknown_fallback`` and ``get_plan_by_name_unknown_fallback`` expect
an unknown plan id/name to resolve to EU868. Neither spec 02a:178 nor the
current oracle supports that reading. Spec 02a:178 requires *CH0 fallback*
(operate on control channel CH0), not substitution of another region's
regulatory limits; ``lichen.channel_plan.get_plan`` /
``get_plan_by_name`` fail closed with :class:`UnknownPlanError`, and
:func:`lichen.channel_plan.ch0_fallback_required` is the normative signal for
the required CH0 fallback. These two tests therefore assert the oracle's
fail-closed contract and the CH0-fallback signal instead of the stale EU868
substitution expectation. All other vectors are asserted byte-exact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.channel_plan import (
    REGIONAL_PLANS,
    ChannelPlan,
    RegulatoryMode,
    UnknownPlanError,
    ch0_fallback_required,
    channel_frequency,
    get_plan,
    get_plan_by_name,
    validate_plan_id,
)

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
VECTOR_FILE = "ccp4_regional_channel_plans.json"

MODE_NAMES = {
    RegulatoryMode.DUTY_CYCLE: "duty_cycle",
    RegulatoryMode.DWELL_TIME: "dwell_time",
    RegulatoryMode.LBT: "lbt",
}

HANDLED_TYPES = frozenset(
    {
        "validate_plan_id",
        "ch0_fallback_required",
        "validate_channel_mask",
        "is_valid_power",
        "get_plan",
        "get_plan_by_name",
        "channel_frequency",
        "regulatory_rules",
        "plan_compliance",
        "channel_spacing",
    }
)


def _load() -> dict[str, Any]:
    doc = json.loads((VECTORS_DIR / VECTOR_FILE).read_text())
    assert doc["format_version"] == 2
    return doc


def _cases(vector_type: str) -> list[tuple[str, dict[str, Any]]]:
    cases = [
        (vector["name"], vector)
        for vector in _load()["vectors"]
        if vector["type"] == vector_type
    ]
    assert cases, f"{VECTOR_FILE} lost its {vector_type} vectors"
    return cases


def _regulatory_params(rules: Any) -> dict[str, Any]:
    if rules.mode is RegulatoryMode.DUTY_CYCLE:
        return {"duty_cycle_percent": rules.duty_cycle_percent}
    if rules.mode is RegulatoryMode.DWELL_TIME:
        return {"dwell_time_ms": rules.dwell_time_ms}
    assert rules.mode is RegulatoryMode.LBT
    return {"lbt_threshold_dbm": rules.lbt_threshold_dbm}


@pytest.mark.parametrize("name,vector", _cases("validate_plan_id"))
def test_validate_plan_id_vector(name: str, vector: dict[str, Any]) -> None:
    assert validate_plan_id(vector["input"]["plan_id"]) is vector["output"]["valid"]


@pytest.mark.parametrize("name,vector", _cases("ch0_fallback_required"))
def test_ch0_fallback_required_vector(name: str, vector: dict[str, Any]) -> None:
    result = ch0_fallback_required(vector["input"]["plan_id"], vector["input"]["version"])
    assert result is vector["output"]["fallback_required"]


@pytest.mark.parametrize("name,vector", _cases("validate_channel_mask"))
def test_validate_channel_mask_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    masked = plan.validate_channel_mask(vector["input"]["mask"])
    assert masked == vector["output"]["valid_mask"]


@pytest.mark.parametrize("name,vector", _cases("is_valid_power"))
def test_is_valid_power_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    valid = plan.is_valid_power(vector["input"]["channel_index"], vector["input"]["power_dbm"])
    assert valid is vector["output"]["valid"]


@pytest.mark.parametrize("name,vector", _cases("get_plan"))
def test_get_plan_unknown_fails_closed_with_ch0_fallback(
    name: str, vector: dict[str, Any]
) -> None:
    """Divergence from the stale vector expectation, see module docstring.

    The JSON expects ``{"plan_name": "EU868", "plan_id": 1}``; the declared
    oracle raises :class:`UnknownPlanError` (fail-closed) and signals the
    spec-required CH0 fallback via :func:`ch0_fallback_required`.
    """
    with pytest.raises(UnknownPlanError):
        get_plan(vector["input"]["plan_id"])
    assert ch0_fallback_required(vector["input"]["plan_id"]) is True


@pytest.mark.parametrize("name,vector", _cases("get_plan_by_name"))
def test_get_plan_by_name_unknown_fails_closed_with_ch0_fallback(
    name: str, vector: dict[str, Any]
) -> None:
    """Divergence from the stale vector expectation, see module docstring."""
    with pytest.raises(UnknownPlanError, match="UNKNOWN"):
        get_plan_by_name(vector["input"]["plan_name"])


@pytest.mark.parametrize("name,vector", _cases("channel_frequency"))
def test_channel_frequency_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    index = vector["input"]["channel_index"]
    expected = vector["output"]["frequency_hz"]
    assert plan.frequency(index) == expected
    assert channel_frequency(plan, index + 1) == expected


@pytest.mark.parametrize("name,vector", _cases("regulatory_rules"))
def test_regulatory_rules_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    rules = plan.regulatory_rules
    assert MODE_NAMES[rules.mode] == vector["output"]["mode"]
    expected_params = {k: v for k, v in vector["output"].items() if k != "mode"}
    assert _regulatory_params(rules) == expected_params


@pytest.mark.parametrize("name,vector", _cases("plan_compliance"))
def test_plan_compliance_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    num_channels = plan.num_channels
    assert num_channels == vector["output"]["num_channels"]
    compliant = num_channels >= vector["output"]["min_required"]
    assert compliant is vector["output"]["compliant"]


@pytest.mark.parametrize("name,vector", _cases("channel_spacing"))
def test_channel_spacing_vector(name: str, vector: dict[str, Any]) -> None:
    plan = get_plan_by_name(vector["input"]["plan_name"])
    spacings = {
        later.frequency_hz - earlier.frequency_hz
        for earlier, later in zip(plan.channels, plan.channels[1:])
    }
    assert len(spacings) == 1
    assert spacings.pop() == vector["output"]["spacing_hz"]


def test_plans_table_matches_implementation() -> None:
    """Every plan definition in the JSON table matches the oracle constants."""
    doc = _load()
    assert len(doc["plans"]) == len(REGIONAL_PLANS)
    for entry in doc["plans"]:
        plan: ChannelPlan = REGIONAL_PLANS[entry["plan_id"]]
        assert plan.name == entry["name"]
        assert plan.version == entry["version"]
        assert plan.num_channels == entry["num_channels"]
        assert plan.channels[0].frequency_hz == entry["ch0_frequency_hz"]
        assert plan.channels[0].max_power_dbm == entry["ch0_max_power_dbm"]
        assert MODE_NAMES[plan.regulatory_rules.mode] == entry["regulatory_mode"]
        json_params = {
            key: value
            for key, value in entry.items()
            if key in {"duty_cycle_percent", "dwell_time_ms", "lbt_threshold_dbm"}
        }
        assert _regulatory_params(plan.regulatory_rules) == json_params


def test_all_vector_types_and_names_are_consumed() -> None:
    """Guard: no vector type may appear without a handler above (no silent skips)."""
    doc = _load()
    types = {vector["type"] for vector in doc["vectors"]}
    unhandled = types - HANDLED_TYPES
    assert not unhandled, f"{VECTOR_FILE} gained unhandled vector types: {sorted(unhandled)}"
    names = [vector["name"] for vector in doc["vectors"]]
    assert len(names) == len(set(names)), "duplicate vector names"
