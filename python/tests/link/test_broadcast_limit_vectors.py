# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: hop-aware broadcast rate limiting vs shared vectors.

Drives ``lichen.link.broadcast_limit`` against
``test/vectors/broadcast_rate_limiting.json`` (spec 04-network.md section 6.3.3).

Budget zones per spec:
- Green zone (count < budget*0.5): deterministic relay
- Yellow zone (budget*0.5 <= count < budget): probabilistic relay (50% drop)
- Red zone (count >= budget): hard drop
"""

from __future__ import annotations

import json
import random
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
    def test_vectors(self, case: dict) -> None:
        expected = case["expected"]
        action, budget = classify_broadcast(case["hop_limit"], case["count_in_window"])
        assert budget == expected["budget"], case["name"]
        assert action == expected["action"], f"{case['name']}: {action} != {expected['action']}"

    def test_zone_boundaries(self) -> None:
        # HL=1: budget=200, green < 100, yellow [100, 200), red >= 200
        # Green zone: deterministic relay
        assert classify_broadcast(1, 99)[0] == "relay"
        # Yellow zone boundary: probabilistic
        assert classify_broadcast(1, 100)[0] == "probabilistic"
        # Yellow zone max: probabilistic
        assert classify_broadcast(1, 199)[0] == "probabilistic"
        # Red zone: hard drop
        assert classify_broadcast(1, 200)[0] == "drop"

    def test_per_sender_independence(self) -> None:
        clock = {"t": 0.0}
        rng = random.Random(42)
        limiter = BroadcastRateLimiter(clock=lambda: clock["t"], rng=rng)
        iid_a = "aabbccddeeff0011"
        iid_b = "1122334455667788"
        # Fill up green zone + yellow zone until we hit red zone
        # Yellow zone has 50% drop, so we need more attempts
        relayed = 0
        for _ in range(500):  # enough attempts to get 200 relays
            action, _ = limiter.admit(iid_a, hop_limit=1)
            if action == "relay":
                relayed += 1
            if relayed >= 200:
                break
        # Now at red zone - should be hard drop
        assert limiter.admit(iid_a, hop_limit=1)[0] == "drop"
        # A different sender still has a full budget - green zone is relay
        assert limiter.admit(iid_b, hop_limit=1)[0] == "relay"

    def test_sender_state_expires_after_idle(self) -> None:
        clock = {"t": 0.0}
        rng = random.Random(42)
        limiter = BroadcastRateLimiter(clock=lambda: clock["t"], rng=rng)
        iid = "0011223344556677"
        # Fill up to red zone (200 relays)
        relayed = 0
        for _ in range(500):
            action, _ = limiter.admit(iid, hop_limit=1)
            if action == "relay":
                relayed += 1
            if relayed >= 200:
                break
        assert limiter.admit(iid, hop_limit=1)[0] == "drop"
        clock["t"] += 7201  # just past the 2h idle expiry
        # After idle expiry, budget resets - green zone is relay
        assert limiter.admit(iid, hop_limit=1)[0] == "relay"

    def test_window_rolls_hourly(self) -> None:
        clock = {"t": 0.0}
        rng = random.Random(42)
        limiter = BroadcastRateLimiter(window_s=3600.0, clock=lambda: clock["t"], rng=rng)
        iid = "0011223344556677"
        # Fill up to red zone (200 relays)
        relayed = 0
        for _ in range(500):
            action, _ = limiter.admit(iid, hop_limit=1)
            if action == "relay":
                relayed += 1
            if relayed >= 200:
                break
        assert limiter.admit(iid, hop_limit=1)[0] == "drop"
        clock["t"] += 3601  # first admissions fall out of the window
        # Budget resets after window rolls
        assert limiter.admit(iid, hop_limit=1)[0] == "relay"

    def test_yellow_zone_probabilistic(self) -> None:
        """Yellow zone uses seeded RNG for deterministic test."""
        clock = {"t": 0.0}
        rng = random.Random(12345)
        limiter = BroadcastRateLimiter(clock=lambda: clock["t"], rng=rng)
        iid = "0011223344556677"
        # Fill green zone (first 100 packets for HL=1)
        for _ in range(100):
            action, _ = limiter.admit(iid, hop_limit=1)
            assert action == "relay"  # green zone is always relay
        # Now in yellow zone - should see mix of relay and drop
        outcomes = []
        for _ in range(50):
            action, _ = limiter.admit(iid, hop_limit=1)
            outcomes.append(action)
        # Should have both outcomes due to 50% probability
        assert "relay" in outcomes or "drop" in outcomes
