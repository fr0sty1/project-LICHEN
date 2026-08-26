# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: hop-aware broadcast rate limiting vs shared vectors.

Drives ``lichen.link.broadcast_limit`` against
``test/vectors/broadcast_rate_limiting.json`` (spec 04-network.md §6.3.3).

The ``yellow_zone_probabilistic`` vector is intentionally not asserted: its
expected label contradicts the file's own ``budget-1 -> relay`` case under
any deterministic rule. Flagged for human decision on bead
project-LICHEN-worker6-heog.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.broadcast_limit import (
    BroadcastRateLimiter,
    broadcast_budget,
    classify_broadcast,
)

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "broadcast_rate_limiting.json"


def _load_vectors() -> list[dict]:
    return json.loads(_VECTORS_PATH.read_text())["vectors"]


class TestBudgetTable:
    @pytest.mark.parametrize(
        ("hop_limit", "budget"),
        [(1, 200), (2, 100), (3, 30), (4, 30), (5, 10), (6, 10), (7, 10)],
    )
    def test_tiers(self, hop_limit: int, budget: int) -> None:
        assert broadcast_budget(hop_limit) == budget

    @pytest.mark.parametrize("hop_limit", [0, 8, -1])
    def test_rejects_out_of_range(self, hop_limit: int) -> None:
        with pytest.raises(ValueError):
            broadcast_budget(hop_limit)


class TestClassify:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "scenarios" not in v and "idle_seconds" not in v],
        ids=lambda v: v["name"],
    )
    def test_deterministic_vectors(self, case: dict) -> None:
        expected = case["expected"]
        if case["name"] == "yellow_zone_probabilistic":
            pytest.skip("underdetermined yellow-zone semantics; see heog")
        action, budget = classify_broadcast(case["hop_limit"], case["count_in_window"])
        assert budget == expected["budget"], case["name"]
        if expected["action"] in ("relay", "drop"):
            assert action == expected["action"], f"{case['name']}: {action} != {expected['action']}"

    def test_budget_boundary_is_inclusive_accept(self) -> None:
        # 200th packet (count_in_window=199 prior) is accepted.
        assert classify_broadcast(1, 199)[0] == "relay"
        # 201st packet is dropped.
        assert classify_broadcast(1, 200)[0] == "drop"

    def test_per_sender_independence(self) -> None:
        clock = {"t": 0.0}
        limiter = BroadcastRateLimiter(clock=lambda: clock["t"])
        iid_a = "aabbccddeeff0011"
        iid_b = "1122334455667788"
        for _ in range(200):
            action, _ = limiter.admit(iid_a, hop_limit=1)
            assert action == "relay"
        assert limiter.admit(iid_a, hop_limit=1)[0] == "drop"
        # A different sender still has a full budget.
        assert limiter.admit(iid_b, hop_limit=1)[0] == "relay"

    def test_sender_state_expires_after_idle(self) -> None:
        clock = {"t": 0.0}
        limiter = BroadcastRateLimiter(clock=lambda: clock["t"])
        iid = "0011223344556677"
        for _ in range(200):
            limiter.admit(iid, hop_limit=1)
        assert limiter.admit(iid, hop_limit=1)[0] == "drop"
        clock["t"] += 7201  # just past the 2h idle expiry
        assert limiter.admit(iid, hop_limit=1)[0] == "relay"

    def test_window_rolls_hourly(self) -> None:
        clock = {"t": 0.0}
        limiter = BroadcastRateLimiter(window_s=3600.0, clock=lambda: clock["t"])
        iid = "0011223344556677"
        for _ in range(200):
            limiter.admit(iid, hop_limit=1)
        assert limiter.admit(iid, hop_limit=1)[0] == "drop"
        clock["t"] += 3601  # first admissions fall out of the window
        assert limiter.admit(iid, hop_limit=1)[0] == "relay"
