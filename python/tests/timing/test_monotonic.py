# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from lichen.timing.monotonic import MonotonicError, MonotonicUptime

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_monotonic_uptime_sequences_vector() -> None:
    document = _load("packets-timing.json")
    vector = next(v for v in document["vectors"] if v["name"] == "monotonic_uptime_sequences")
    for case in vector["cases"]:
        clock = MonotonicUptime()
        last_ok: int | None = None
        for ticks, accept in zip(
            case["observations"], case["expected_acceptance"], strict=True
        ):
            if accept:
                assert clock.observe(ticks) == ticks, case["name"]
                last_ok = ticks
            else:
                with pytest.raises(MonotonicError):
                    clock.observe(ticks)
                assert clock.now == last_ok, case["name"]
