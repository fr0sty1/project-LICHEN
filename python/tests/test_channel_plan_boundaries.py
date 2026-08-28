# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Boundary and canonical-vector tests for bounded channel-plan selection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.channel_plan import (
    ChannelEntry,
    ChannelPlan,
    _select_channel_index,
    hash_32,
    select_channel,
)

_VECTORS_PATH = Path(__file__).parents[2] / "test" / "vectors" / "channel_plan_selection.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("channel_plan_selection.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text()))


def _plan(n_channels: int) -> ChannelPlan:
    return ChannelPlan(
        plan_id=0xFE,
        version=1,
        name=f"BOUNDARY-{n_channels}",
        channels=tuple(ChannelEntry(900_000_000 + index) for index in range(n_channels)),
    )


def _reference_hash(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def test_channel_plan_selection_document_matches_dedicated_schema() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


@pytest.mark.parametrize("case", _document()["cases"], ids=lambda item: item["name"])
def test_channel_plan_selection_vector(case: dict[str, Any]) -> None:
    eui64 = bytes.fromhex(case["eui64_hex"])
    epoch = case["epoch"]
    density = case["density"]
    n_channels = case["n_channels"]
    hash_input = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
    assert _reference_hash(hash_input) == case["hash_32"] == hash_32(hash_input)

    plan = _plan(n_channels)
    expected = case["expected_channel"]
    assert plan.select_channel(eui64, epoch, density) == expected
    assert select_channel(eui64, epoch, density, plan) == expected
    assert 0 <= expected < n_channels


@pytest.mark.parametrize("n_channels", _document()["invalid_counts"])
def test_nonpositive_channel_counts_are_rejected(n_channels: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _select_channel_index(bytes(8), 0, 0, n_channels)


def test_empty_plan_is_rejected_through_both_public_selection_apis() -> None:
    empty = _plan(0)
    with pytest.raises(ValueError, match="positive integer"):
        empty.select_channel(bytes(8), 0, 0)
    with pytest.raises(ValueError, match="positive integer"):
        select_channel(bytes(8), 0, 0, plan=empty)


@pytest.mark.parametrize("n_channels", [1, 2, 3, 4, 8, 64])
def test_exhaustive_epoch_boundaries_stay_deterministic_and_in_range(n_channels: int) -> None:
    plan = _plan(n_channels)
    eui64 = bytes.fromhex("aabbccddeeff0011")
    for epoch in [*range(256), 0xFFFFFFFF, 0x1_0000_0000]:
        first = plan.select_channel(eui64, epoch, density=8)
        second = select_channel(eui64, epoch, density=8, plan=plan)
        assert first == second
        assert 0 <= first < n_channels
        if n_channels == 1:
            assert first == 0
        elif n_channels == 2:
            assert first == 1
        else:
            assert 1 <= first < n_channels
        assert plan.select_channel(eui64, epoch, density=9) == 0
