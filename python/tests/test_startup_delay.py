# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for boot storm mitigation / startup delay (spec 09-packets-timing.md).

Validates against test/vectors/packets-timing.json "density_startup_delay" vector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.timing.startup_delay import (
    DELAY_PER_NODE_S,
    LISTEN_PERIOD_MAX_S,
    LISTEN_PERIOD_MIN_S,
    MAX_STARTUP_DELAY_S,
    BootStormMitigation,
    compute_startup_delay_ms,
    compute_startup_delay_s,
    random_listen_period_s,
    random_startup_delay_s,
)

VECTORS_DIR = Path(__file__).parent.parent.parent / "test" / "vectors"


def _load_density_startup_vector() -> dict:
    """Load the density_startup_delay test vector."""
    with open(VECTORS_DIR / "packets-timing.json") as f:
        doc = json.load(f)
    for vector in doc["vectors"]:
        if vector["name"] == "density_startup_delay":
            return vector
    raise ValueError("density_startup_delay vector not found")


class TestConstants:
    """Verify constants match test vectors."""

    def test_constants_match_vector(self):
        """Verify constants match packets-timing.json."""
        vector = _load_density_startup_vector()
        constants = vector["constants"]

        assert constants["LISTEN_PERIOD_MIN_S"] == LISTEN_PERIOD_MIN_S
        assert constants["LISTEN_PERIOD_MAX_S"] == LISTEN_PERIOD_MAX_S
        assert constants["DELAY_PER_NODE_S"] == DELAY_PER_NODE_S
        assert constants["MAX_STARTUP_DELAY_S"] == MAX_STARTUP_DELAY_S


class TestComputeStartupDelay:
    """Test compute_startup_delay_s against test vectors."""

    def test_delay_0_nodes(self):
        """0 nodes heard => 0 delay."""
        vector = _load_density_startup_vector()
        expected = vector["delay_0_nodes"]
        assert compute_startup_delay_s(0) == expected

    def test_delay_10_nodes(self):
        """10 nodes heard => 50s delay (10 * 5)."""
        vector = _load_density_startup_vector()
        expected = vector["delay_10_nodes"]
        assert compute_startup_delay_s(10) == expected

    def test_delay_100_nodes(self):
        """100 nodes heard => 300s delay (capped at MAX)."""
        vector = _load_density_startup_vector()
        expected = vector["delay_100_nodes"]
        assert compute_startup_delay_s(100) == expected

    def test_delay_capped_at_max(self):
        """Delay is capped at MAX_STARTUP_DELAY_S."""
        # 61 nodes would be 305s, but capped at 300
        assert compute_startup_delay_s(61) == 300
        assert compute_startup_delay_s(1000) == 300

    def test_ms_conversion(self):
        """compute_startup_delay_ms returns milliseconds."""
        assert compute_startup_delay_ms(10) == 50_000
        assert compute_startup_delay_ms(100) == 300_000

    def test_invalid_nodes_heard(self):
        """Negative nodes_heard raises ValueError."""
        with pytest.raises(ValueError, match="non-negative integer"):
            compute_startup_delay_s(-1)

    def test_non_integer_nodes_heard(self):
        """Non-integer nodes_heard raises ValueError."""
        with pytest.raises(ValueError, match="non-negative integer"):
            compute_startup_delay_s(10.5)  # type: ignore[arg-type]


class TestRandomListenPeriod:
    """Test random_listen_period_s."""

    def test_listen_period_in_range(self):
        """Listen period is in [30, 60] seconds."""
        for _ in range(100):
            period = random_listen_period_s()
            assert LISTEN_PERIOD_MIN_S <= period <= LISTEN_PERIOD_MAX_S


class TestRandomStartupDelay:
    """Test random_startup_delay_s."""

    def test_random_delay_in_range(self):
        """Random delay is in [0, computed_max]."""
        for nodes in [0, 5, 10, 50, 100]:
            max_delay = compute_startup_delay_s(nodes)
            for _ in range(50):
                delay = random_startup_delay_s(nodes)
                assert 0 <= delay <= max_delay

    def test_random_delay_zero_nodes(self):
        """0 nodes heard => delay is always 0."""
        for _ in range(10):
            assert random_startup_delay_s(0) == 0


class TestBootStormMitigation:
    """Test BootStormMitigation stateful tracker."""

    def test_initial_state(self):
        """New mitigation has valid listen period and no nodes."""
        mitigation = BootStormMitigation()
        assert LISTEN_PERIOD_MIN_S <= mitigation.listen_period_s <= LISTEN_PERIOD_MAX_S
        assert mitigation.nodes_heard_count == 0

    def test_observe_node_deduplication(self):
        """observe_node deduplicates by identifier."""
        mitigation = BootStormMitigation()

        # First observation returns True
        assert mitigation.observe_node(b"\x00\x01\x02\x03\x04\x05\x06\x07") is True
        assert mitigation.nodes_heard_count == 1

        # Second observation of same node returns False
        assert mitigation.observe_node(b"\x00\x01\x02\x03\x04\x05\x06\x07") is False
        assert mitigation.nodes_heard_count == 1

        # Different node increments count
        assert mitigation.observe_node(b"\x10\x11\x12\x13\x14\x15\x16\x17") is True
        assert mitigation.nodes_heard_count == 2

    def test_get_max_startup_delay(self):
        """get_max_startup_delay_s based on observed density."""
        mitigation = BootStormMitigation()

        # No nodes => 0 delay
        assert mitigation.get_max_startup_delay_s() == 0

        # Add 10 nodes
        for i in range(10):
            mitigation.observe_node(bytes([i] * 8))

        assert mitigation.get_max_startup_delay_s() == 50

    def test_get_random_startup_delay(self):
        """get_random_startup_delay_s in valid range."""
        mitigation = BootStormMitigation()

        # Add 20 nodes
        for i in range(20):
            mitigation.observe_node(bytes([i] * 8))

        max_delay = mitigation.get_max_startup_delay_s()
        assert max_delay == 100

        for _ in range(50):
            delay = mitigation.get_random_startup_delay_s()
            assert 0 <= delay <= max_delay

    def test_listen_period_ms(self):
        """listen_period_ms returns milliseconds."""
        mitigation = BootStormMitigation()
        assert mitigation.listen_period_ms == mitigation.listen_period_s * 1000

    def test_reset(self):
        """reset clears nodes and selects new listen period."""
        mitigation = BootStormMitigation()

        # Add some nodes
        for i in range(5):
            mitigation.observe_node(bytes([i] * 8))
        assert mitigation.nodes_heard_count == 5

        # Reset
        mitigation.reset()
        assert mitigation.nodes_heard_count == 0
        # Listen period might be same (random) but nodes are cleared


class TestSpecCompliance:
    """Verify full spec compliance."""

    def test_first_announce_delay_sequence(self):
        """Full boot storm mitigation sequence per spec.

        1. On boot, listen-only for random [30s, 60s]
        2. Count unique nodes heard
        3. Compute initial_delay = min(300, nodes_heard * 5)
        4. Delay by random(0, initial_delay) before first TX
        """
        mitigation = BootStormMitigation()

        # Step 1: Listen period in valid range
        assert LISTEN_PERIOD_MIN_S <= mitigation.listen_period_s <= LISTEN_PERIOD_MAX_S

        # Simulate hearing 25 nodes during listen
        for i in range(25):
            mitigation.observe_node(bytes([i] * 8))

        # Step 2: Count verified
        assert mitigation.nodes_heard_count == 25

        # Step 3: Compute max delay = min(300, 25 * 5) = 125
        assert mitigation.get_max_startup_delay_s() == 125

        # Step 4: Random delay in [0, 125]
        for _ in range(20):
            delay = mitigation.get_random_startup_delay_s()
            assert 0 <= delay <= 125

    def test_high_density_capped(self):
        """High density (300+ nodes) caps delay at 300s."""
        mitigation = BootStormMitigation()

        # Simulate very high density
        for i in range(500):
            mitigation.observe_node(i.to_bytes(8, "big"))

        assert mitigation.nodes_heard_count == 500
        assert mitigation.get_max_startup_delay_s() == MAX_STARTUP_DELAY_S
