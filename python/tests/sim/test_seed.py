# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for seeded RNG support / reproducible simulations (j34)."""

from __future__ import annotations

import random

import pytest

from lora_medium import LossRule
from lora_medium import RxCandidate
from lichen.sim.simulation import Simulation
from lora_medium import Transmission


def _candidate(source_node_id: str = "sender") -> RxCandidate:
    return RxCandidate(
        transmission=Transmission(
            source_node_id=source_node_id,
            payload=b"x",
            tx_power_dbm=14,
            start_time_us=0,
            end_time_us=1000,
        ),
        rssi=-70.0,
        snr=50.0,
    )


def test_same_seed_gives_same_sequence() -> None:
    a = Simulation("a", seed=42)
    b = Simulation("b", seed=42)
    seq_a = [a.rng.random() for _ in range(10)]
    seq_b = [b.rng.random() for _ in range(10)]
    assert seq_a == seq_b


def test_different_seeds_diverge() -> None:
    a = Simulation("a", seed=1)
    b = Simulation("b", seed=2)
    assert [a.rng.random() for _ in range(5)] != [b.rng.random() for _ in range(5)]


def test_seed_property() -> None:
    assert Simulation("s", seed=7).seed == 7
    assert Simulation("s").seed is None


def test_reseed_restores_sequence() -> None:
    sim = Simulation("s", seed=99)
    first = [sim.rng.random() for _ in range(5)]
    sim.reseed(99)
    assert [sim.rng.random() for _ in range(5)] == first


def test_unseeded_simulation_has_working_rng() -> None:
    sim = Simulation("s")
    assert 0.0 <= sim.rng.random() < 1.0


def test_loss_rule_probability_zero_never_drops() -> None:
    rule = LossRule(node_id="sender", loss_probability=0.0, rng=random.Random(1))
    assert all(rule.apply(_candidate()) is not None for _ in range(20))


def test_loss_rule_probability_one_always_drops() -> None:
    rule = LossRule(node_id="sender", loss_probability=1.0, rng=random.Random(1))
    assert all(rule.apply(_candidate()) is None for _ in range(20))


def test_loss_rule_is_reproducible_with_same_seed() -> None:
    rule_a = LossRule(node_id="sender", loss_probability=0.5, rng=random.Random(123))
    rule_b = LossRule(node_id="sender", loss_probability=0.5, rng=random.Random(123))
    drops_a = [rule_a.apply(_candidate()) is None for _ in range(30)]
    drops_b = [rule_b.apply(_candidate()) is None for _ in range(30)]
    assert drops_a == drops_b
    # And the pattern is non-trivial (some dropped, some kept).
    assert any(drops_a) and not all(drops_a)


def test_loss_rule_uses_simulation_rng() -> None:
    # Wiring a Simulation's seeded rng into a LossRule makes the run reproducible.
    sim1 = Simulation("s1", seed=5)
    sim2 = Simulation("s2", seed=5)
    r1 = LossRule(node_id="sender", loss_probability=0.5, rng=sim1.rng)
    r2 = LossRule(node_id="sender", loss_probability=0.5, rng=sim2.rng)
    assert [r1.apply(_candidate()) is None for _ in range(20)] == [
        r2.apply(_candidate()) is None for _ in range(20)
    ]


def test_loss_rule_rejects_invalid_probability() -> None:
    with pytest.raises(ValueError):
        LossRule(node_id="sender", loss_probability=1.5)
    with pytest.raises(ValueError):
        LossRule(node_id="sender", loss_probability=-0.1)


def test_loss_rule_matches_direction() -> None:
    rule = LossRule(node_id="sender", loss_probability=1.0, direction="tx")
    tx = _candidate().transmission
    assert rule.matches(tx, "other") is True  # sender matches tx direction
    assert rule.matches(tx, "sender") is True
    rx_rule = LossRule(node_id="rxnode", loss_probability=1.0, direction="rx")
    assert rx_rule.matches(tx, "rxnode") is True
    assert rx_rule.matches(tx, "other") is False
