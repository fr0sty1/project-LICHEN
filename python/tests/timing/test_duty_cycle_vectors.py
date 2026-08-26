# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the canonical cross-implementation duty-cycle vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from lichen.timing.airtime import airtime_us_with_params
from lichen.timing.duty_cycle import (
    RegionalDutyCycleEnforcer,
    get_regional_limit,
    max_packets_per_hour,
)

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "duty_cycle_calculation.json"
sys.path.insert(0, str(VECTORS_PATH.parent))
from generate import duty_cycle_calculation_vectors  # noqa: E402


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert document["format_version"] == 2
    return document["vectors"]


def test_document_validates_against_canonical_schema() -> None:
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    schema = json.loads((VECTORS_PATH.parent / "schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


def test_document_is_reproducible_from_independent_generator() -> None:
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert document["vectors"] == duty_cycle_calculation_vectors()


def test_exact_airtime_and_packet_budgets() -> None:
    vector = next(v for v in _vectors() if v["category"] == "exact_airtime")
    radio = vector["radio"]
    expected = vector["expected"]

    airtime_us = airtime_us_with_params(
        radio["payload_len"],
        sf=radio["spreading_factor"],
        bw_hz=radio["bandwidth_hz"],
        cr=radio["coding_rate"],
        preamble_symbols=radio["preamble_symbols"],
        crc_enabled=radio["crc_enabled"],
        implicit_header=radio["implicit_header"],
    )
    assert airtime_us == expected["airtime_us"]
    assert max_packets_per_hour(airtime_us / 1000, 1.0) == expected["eu_1_percent_packets_per_hour"]
    assert (
        max_packets_per_hour(airtime_us / 1000, 10.0)
        == expected["spec_10_percent_packets_per_hour"]
    )


@pytest.mark.parametrize(
    "vector", [v for v in _vectors() if v["category"] == "tracking"], ids=lambda v: v["name"]
)
def test_regional_tracking_vectors(vector: dict[str, Any]) -> None:
    profile = vector["profile"]
    expected = vector["expected"]
    limit = get_regional_limit(profile["region"])
    assert limit.duty_cycle_percent == profile["duty_cycle_percent"]
    assert limit.window_s * 1000 == profile["window_ms"]
    assert limit.max_dwell_time_ms == profile["max_dwell_time_ms"]

    enforcer = RegionalDutyCycleEnforcer(profile["region"])
    for transmission in vector["transmissions"]:
        assert enforcer.try_transmit(
            transmission["duration_ms"] * 1000,
            transmission["start_ms"] * 1000,
        ), vector["name"]

    query_us = vector["query_ms"] * 1000
    max_airtime_ms = profile["window_ms"] * profile["duty_permille"] // 1000
    usage_ratio = enforcer.usage(query_us)
    assert usage_ratio * max_airtime_ms == pytest.approx(expected["used_ms"])
    assert max(0, max_airtime_ms - expected["used_ms"]) == expected["remaining_ms"]
    assert int(usage_ratio * profile["duty_permille"]) == expected["usage_permille"]

    before = enforcer.usage(query_us)
    allowed = enforcer.try_transmit(vector["proposed_duration_ms"] * 1000, query_us)
    assert allowed is expected["can_transmit"]
    if not allowed:
        assert enforcer.usage(query_us) == before


def test_vector_categories_and_required_regional_edges_are_complete() -> None:
    vectors = _vectors()
    names = {vector["name"] for vector in vectors}
    assert names == {
        "sf9_exact_airtime_and_packet_budgets",
        "eu868_exact_limit_denial",
        "eu868_accumulates_multiple_transmissions",
        "rolling_boundary_still_denied",
        "rolling_boundary_partial_recovery",
        "rolling_boundary_full_recovery",
        "us915_fcc_dwell_exact_limit",
        "us915_fcc_dwell_over_limit",
        "u64_timestamp_saturates_without_budget_overflow",
    }
