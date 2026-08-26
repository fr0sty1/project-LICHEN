# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Appendix B.5 congestion scenarios vs spec/appendix-bufferbloat.md Testing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"

SPEC_TX_CAPACITY = 4
SPEC_FORWARDING_PER_SOURCE = 2
SPEC_FORWARDING_SOURCES = 8
SPEC_DEADLINE_ROUTING_MS = 5000
SPEC_DEADLINE_ACK_MS = 10000
SPEC_DEADLINE_APP_MS = 60000


def _load() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((VECTORS / "bufferbloat_congestion.json").read_text(encoding="utf-8")),
    )


def test_b5_congestion_scenarios_match_spec() -> None:
    document = _load()
    by_name = {case["name"]: case for case in document["vectors"]}
    assert set(by_name) == {
        "queue_full",
        "deadline_expiry",
        "priority_preemption",
        "multihop_latency",
        "fairness",
    }
    assert by_name["queue_full"]["tx_capacity"] == SPEC_TX_CAPACITY
    assert by_name["queue_full"]["expected"] == "ENOBUFS"
    expiry = by_name["deadline_expiry"]
    assert expiry["routing_deadline_ms"] == SPEC_DEADLINE_ROUTING_MS
    assert expiry["ack_deadline_ms"] == SPEC_DEADLINE_ACK_MS
    assert expiry["app_deadline_ms"] == SPEC_DEADLINE_APP_MS
    assert expiry["expected"] == "drop_before_tx"
    assert by_name["priority_preemption"]["expected"] == "higher_preempts_lower"
    assert by_name["multihop_latency"]["expected"] == "bounded_e2e_delay"
    fairness = by_name["fairness"]
    assert fairness["max_packets_per_source"] == SPEC_FORWARDING_PER_SOURCE
    assert fairness["max_forwarding_sources"] == SPEC_FORWARDING_SOURCES
    assert fairness["expected"] == "nack_when_source_full"
