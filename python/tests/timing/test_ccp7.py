# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from lichen.timing.ccp7 import (
    beacon_delta_ms,
    correction_ms,
    drift_bound,
    drift_ppm,
    guard_sufficient,
    holdover_expired,
    in_guard,
    tx_allowed,
)

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_ccp7_holdover_vectors() -> None:
    document = _load("ccp7_holdover.json")
    for vector in document["vectors"]:
        name = vector["name"]
        category = vector["category"]
        if category == "drift_bound":
            assert drift_bound(vector["b0"], vector["rho"], vector["h"]) == vector[
                "expected_bound"
            ], name
        elif category == "guard_budget":
            need = (
                vector["b_i"]
                + vector["b_j"]
                + vector["j_i"]
                + vector["j_j"]
                + vector["p"]
                + vector["m"]
            )
            assert need == vector["need"], name
            assert (
                guard_sufficient(
                    vector["guard"],
                    vector["b_i"],
                    vector["b_j"],
                    vector["j_i"],
                    vector["j_j"],
                    vector["p"],
                    vector["m"],
                )
                is vector["expected_sufficient"]
            ), name
        elif category == "holdover":
            assert (
                holdover_expired(vector["measured_drift_ppm"], vector["guard_ppm"])
                is vector["expected_expired"]
            ), name
        elif category == "drift_ppm":
            ppm = drift_ppm(vector["delta_ms"], vector["beacon_interval_ms"])
            assert ppm == vector["expected_ppm"], name
            assert (
                correction_ms(ppm, vector["future_delta_ms"])
                == vector["expected_correction_ms"]
            ), name
        else:
            raise AssertionError(f"unknown category {category}")


def test_ccp_tdma_guard_and_offset() -> None:
    document = _load("ccp_tdma.json")
    for vector in document["vectors"]:
        name = vector["name"]
        if name in ("data_window_last_millisecond", "guard_boundary_start"):
            start = vector["slot_start_ms"]
            current = vector["current_ms"]
            duration = vector["slot_duration_ms"]
            guard = vector["guard_ms"]
            assert in_guard(start, current, duration, guard) is vector["expected_in_guard"]
            assert tx_allowed(start, current, duration, guard) is vector[
                "expected_tx_allowed"
            ]
        elif name == "drift_compensation":
            assert (
                beacon_delta_ms(
                    vector["local_beacon_rx_ms"], vector["expected_beacon_ms"]
                )
                == vector["expected_correction_ms"]
            )
