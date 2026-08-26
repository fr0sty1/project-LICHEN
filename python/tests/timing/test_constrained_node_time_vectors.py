# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from lichen.senml.codec import SenmlRecord
from lichen.senml.relative_time import stamp_record
from lichen.timing.time_fallback import MonotonicFallback, UnixSeconds, consumer_timestamp
from lichen.timing.wall_clock import TimeSourceClass, WallClockValidity

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_constrained_node_time_vectors() -> None:
    document = _load("constrained_node_time.json")
    for case in document["vectors"]:
        clock = WallClockValidity()
        if case["wall_clock_valid"]:
            clock.establish(TimeSourceClass(case["source"]))
        stamp = consumer_timestamp(clock, case["unix"], case["uptime_ticks"])
        record = stamp_record(
            SenmlRecord(n="temp", u="Cel", v=1.0),
            clock,
            unix=case["unix"],
            uptime_s=case["uptime_ticks"],
            relative_s=case["relative_s"],
        )
        if case["expected_kind"] == "monotonic":
            assert stamp == MonotonicFallback(case["expected_ticks"]), case["name"]
            assert record.bt is case["expected_bt"]
        else:
            assert stamp == UnixSeconds(
                case["expected_unix"], TimeSourceClass(case["expected_source"])
            )
            assert record.bt == case["expected_bt"]
        assert record.t == case["expected_t"], case["name"]
