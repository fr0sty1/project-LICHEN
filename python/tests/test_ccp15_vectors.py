# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Drive Python CCP-15 implementations from the shared cross-language vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.ccp import (
    adaptive_sf_select,
    hash_32,
    interference_score,
    select_channel,
    slot_hash,
)
from lichen.timing.csma import CsmaState

_VECTOR_PATH = Path(__file__).parents[2] / "test" / "vectors" / "ccp15.json"
_VECTORS: list[dict[str, Any]] = json.loads(_VECTOR_PATH.read_text())["vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda vector: vector["name"])
def test_ccp15_vector(vector: dict[str, Any]) -> None:
    inputs = vector["input"]
    expected = vector["expected"]
    category = vector["category"]

    if category == "cca":
        state = CsmaState(inputs["backoff_exp"], inputs["retries"])
        result = state.on_cad_result(inputs["channel_busy"])
        assert result.value == expected["result"]
        assert state.backoff_exp == expected["backoff_exp"]
        assert state.retries == expected["retries"]
        assert (result.value == "tx_success") is expected["tx_allowed"]
    elif category == "interference":
        score = interference_score(
            float(inputs["busy_percent"]),
            inputs["packet_error_permille"] / 1000.0,
        )
        assert score * 10 == pytest.approx(expected["score_tenths"])
    elif category == "frequency_agility":
        eui64 = bytes.fromhex(inputs["eui64_hex"])
        hash_input = eui64 + inputs["epoch"].to_bytes(4, "little")
        assert hash_32(hash_input) == int(expected["hash_32"], 16)
        assert (
            select_channel(
                eui64,
                inputs["epoch"],
                inputs["density"],
                inputs["n_channels"],
            )
            == expected["channel"]
        )
    elif category == "sf_adaptation":
        result = adaptive_sf_select(
            inputs["assigned_sf"],
            inputs["density"],
            inputs["ema_snr"],
            inputs["ema_loss_permille"] / 1000.0,
            inputs["utilization"],
            inputs["load_factor_permille"] / 1000.0,
        )
        assert result.sf == expected["sf"]
        assert result.tx_allowed is expected["tx_allowed"]
    elif category == "tdma":
        eui64 = bytes.fromhex(inputs["eui64_hex"])
        assert hash_32(eui64) == int(expected["hash_32"], 16)
        assert slot_hash(eui64, inputs["sfn"], inputs["num_slots"]) == expected["slot"]
    else:  # pragma: no cover - schema validation rejects unknown categories
        raise AssertionError(f"unknown CCP-15 category: {category}")


def test_ccp15_covers_every_required_behavior() -> None:
    assert {vector["category"] for vector in _VECTORS} == {
        "cca",
        "interference",
        "frequency_agility",
        "sf_adaptation",
        "tdma",
    }
