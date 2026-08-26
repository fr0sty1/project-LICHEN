# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Spec appendix-bufferbloat B.2 table vs shared vector oracles.

Literals below are copied from spec/appendix-bufferbloat.md (not from
implementation modules). The JSON files are the independent oracle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"

# spec/appendix-bufferbloat.md Design Principles.
SPEC_TX_QUEUE_CAPACITY = 4
SPEC_FORWARDING_PER_SOURCE = 2
SPEC_FORWARDING_SOURCES = 8
SPEC_FORWARDING_TOTAL = 16
SPEC_DEADLINE_ROUTING_MS = 5000
SPEC_DEADLINE_ACK_MS = 10000
SPEC_DEADLINE_APP_MS = 60000


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_bounded_vector_capacity_is_spec_four() -> None:
    document = _load("tx_queue_bounded.json")
    case = next(v for v in document["vectors"] if v["name"] == "capacity_default_4")
    assert case["expected"]["capacity"] == SPEC_TX_QUEUE_CAPACITY


def test_expiry_vector_deadlines_include_spec_b2() -> None:
    constants = _load("tx_queue_expiry.json")["constants"]
    assert constants["DEADLINE_ROUTING_MS"] == SPEC_DEADLINE_ROUTING_MS
    assert constants["DEADLINE_ACK_MS"] == SPEC_DEADLINE_ACK_MS
    assert constants["DEADLINE_NORMAL_MS"] == SPEC_DEADLINE_APP_MS
    assert constants["CAPACITY"] == SPEC_TX_QUEUE_CAPACITY


def test_priority_vector_capacity() -> None:
    constants = _load("tx_queue_priority.json")["constants"]
    assert constants["CAPACITY"] == SPEC_TX_QUEUE_CAPACITY


def test_forwarding_buffer_oracle_is_spec_b2() -> None:
    oracle = _load("forwarding_buffer.json")["oracle"]
    assert oracle["max_packets_per_source"] == SPEC_FORWARDING_PER_SOURCE
    assert oracle["max_forwarding_sources"] == SPEC_FORWARDING_SOURCES
    assert oracle["total_capacity"] == SPEC_FORWARDING_TOTAL
