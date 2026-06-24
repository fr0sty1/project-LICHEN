# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RREQ jitter in scheduled_send().

Why these tests: LOADng uses jitter to reduce collision probability when
multiple nodes forward the same RREQ simultaneously. If jitter is broken:
- All nodes transmit at the same time, causing collisions
- Route discovery fails under load
- Mesh performance degrades

Test categories:
1. Delay verification - scheduled_send waits before sending
2. Config defaults - Uses rreq_jitter_min/max_ms from NodeConfig
3. Custom delays - Can override min/max per call
4. Distribution - Multiple calls produce varied delays
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import patch

import pytest

from lichen.crypto.identity import Identity
from lichen.node import Node, NodeConfig


class MockRadio:
    """Mock radio for testing Node without real radio or simulator."""

    def __init__(self):
        self.tx_history: list[bytes] = []

    async def transmit(self, payload: bytes) -> bool:
        self.tx_history.append(payload)
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        await asyncio.sleep(timeout_ms / 1000)
        return None

    async def cad(self, timeout_ms: int) -> bool:
        """Mock CAD - always returns False (channel clear)."""
        return False

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        pass


@pytest.fixture
def identity() -> Identity:
    return Identity.from_seed(bytes(32))


@pytest.fixture
def radio() -> MockRadio:
    return MockRadio()


@pytest.fixture
def node(identity: Identity, radio: MockRadio) -> Node:
    return Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            receive_timeout_ms=100,
            announce_interval_ms=10000,
            announce_jitter_ms=0,
            rreq_jitter_min_ms=10,
            rreq_jitter_max_ms=50,
        ),
    )


class TestScheduledSendDelay:
    """Tests that scheduled_send delays transmission."""

    @pytest.mark.asyncio
    async def test_scheduled_send_delays_transmission(
        self, node: Node, radio: MockRadio
    ):
        """scheduled_send() waits before sending."""
        data = b"test_data"
        delay_ms = 25

        # Mock random to return a known delay
        with patch("lichen.node.random.randint", return_value=delay_ms):
            # Track timing
            start = asyncio.get_event_loop().time()
            task = node.scheduled_send(data)
            await task
            elapsed_ms = (asyncio.get_event_loop().time() - start) * 1000

        # Verify delay occurred (allow some timing slack)
        assert elapsed_ms >= delay_ms - 5
        assert elapsed_ms < delay_ms + 50  # generous upper bound for CI

        # Verify data was sent
        assert len(radio.tx_history) == 1

    @pytest.mark.asyncio
    async def test_scheduled_send_returns_task(self, node: Node):
        """scheduled_send() returns an asyncio Task."""
        data = b"test_data"

        with patch("lichen.node.random.randint", return_value=0):
            task = node.scheduled_send(data)

        assert isinstance(task, asyncio.Task)
        await task

    @pytest.mark.asyncio
    async def test_scheduled_send_zero_delay(self, node: Node, radio: MockRadio):
        """scheduled_send() with zero delay sends immediately."""
        data = b"test_data"

        with patch("lichen.node.random.randint", return_value=0):
            start = asyncio.get_event_loop().time()
            task = node.scheduled_send(data)
            await task
            elapsed_ms = (asyncio.get_event_loop().time() - start) * 1000

        # Should complete very quickly (under 20ms)
        assert elapsed_ms < 20
        assert len(radio.tx_history) == 1


class TestConfigDefaults:
    """Tests that scheduled_send uses config defaults."""

    @pytest.mark.asyncio
    async def test_scheduled_send_uses_config_defaults(
        self, identity: Identity, radio: MockRadio
    ):
        """Uses rreq_jitter_min/max_ms from config when not overridden."""
        config = NodeConfig(
            receive_timeout_ms=100,
            rreq_jitter_min_ms=20,
            rreq_jitter_max_ms=80,
        )
        node = Node(identity=identity, radio=radio, config=config)

        # Capture the arguments passed to randint
        with patch("lichen.node.random.randint", return_value=50) as mock_randint:
            task = node.scheduled_send(b"test")
            # Let the task start (calls randint immediately)
            await asyncio.sleep(0)

        mock_randint.assert_called_once_with(20, 80)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_default_config_values(self, identity: Identity, radio: MockRadio):
        """NodeConfig defaults are 0-100ms for RREQ jitter."""
        node = Node(identity=identity, radio=radio)

        assert node.config.rreq_jitter_min_ms == 0
        assert node.config.rreq_jitter_max_ms == 100


class TestCustomDelays:
    """Tests that scheduled_send accepts custom delay parameters."""

    @pytest.mark.asyncio
    async def test_scheduled_send_accepts_custom_delays(
        self, node: Node, radio: MockRadio
    ):
        """Can override min/max delay per call."""
        data = b"test_data"

        with patch("lichen.node.random.randint", return_value=150) as mock_randint:
            task = node.scheduled_send(data, min_delay_ms=100, max_delay_ms=200)
            await asyncio.sleep(0)

        mock_randint.assert_called_once_with(100, 200)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_custom_min_only(self, node: Node):
        """Can override just min_delay_ms."""
        # Node config has max=50

        with patch("lichen.node.random.randint", return_value=30) as mock_randint:
            task = node.scheduled_send(b"test", min_delay_ms=25)
            await asyncio.sleep(0)

        # min from param, max from config
        mock_randint.assert_called_once_with(25, 50)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_custom_max_only(self, node: Node):
        """Can override just max_delay_ms."""
        # Node config has min=10

        with patch("lichen.node.random.randint", return_value=30) as mock_randint:
            task = node.scheduled_send(b"test", max_delay_ms=75)
            await asyncio.sleep(0)

        # min from config, max from param
        mock_randint.assert_called_once_with(10, 75)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


class TestJitterDistribution:
    """Tests that multiple calls produce varied delays."""

    @pytest.mark.asyncio
    async def test_jitter_distribution(self, node: Node, radio: MockRadio):
        """Multiple calls produce varied delays (not all identical)."""
        delays_observed: list[int] = []

        # Run multiple scheduled_sends and capture the actual delays used
        original_randint = __import__("random").randint

        def capture_randint(min_val: int, max_val: int) -> int:
            delay = original_randint(min_val, max_val)
            delays_observed.append(delay)
            return delay

        with patch("lichen.node.random.randint", side_effect=capture_randint):
            tasks = [node.scheduled_send(b"test") for _ in range(10)]
            # Let all tasks start (they call randint immediately)
            await asyncio.sleep(0)

            # Cancel all tasks to avoid waiting
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await t

        # With 10 samples from a range of [10, 50], we should see variation
        assert len(delays_observed) == 10
        # Not all values should be identical (extremely unlikely with real random)
        unique_delays = set(delays_observed)
        assert len(unique_delays) > 1, f"All delays identical: {delays_observed}"

    @pytest.mark.asyncio
    async def test_delays_within_bounds(self, node: Node):
        """All delays should fall within [min, max] bounds."""
        delays_observed: list[int] = []

        original_randint = __import__("random").randint

        def capture_randint(min_val: int, max_val: int) -> int:
            delay = original_randint(min_val, max_val)
            delays_observed.append(delay)
            return delay

        with patch("lichen.node.random.randint", side_effect=capture_randint):
            tasks = [node.scheduled_send(b"test") for _ in range(20)]
            await asyncio.sleep(0)

            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await t

        # All delays should be within the configured bounds [10, 50]
        for delay in delays_observed:
            assert 10 <= delay <= 50, f"Delay {delay} out of bounds [10, 50]"
