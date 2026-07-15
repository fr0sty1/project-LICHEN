# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests that the Simulation core emits structured logs for key events."""

from __future__ import annotations

from collections.abc import Generator

import pytest
import structlog

from lichen.sim.simulation import (
    Simulation,
    disable_debug,
    enable_debug,
    is_debug_enabled,
)


@pytest.fixture(autouse=True)
def reset_debug_state() -> Generator[None, None, None]:
    """Keep the process-wide debug toggle isolated between tests."""
    was_enabled = is_debug_enabled()
    disable_debug()
    try:
        yield
    finally:
        if was_enabled:
            enable_debug()
        else:
            disable_debug()


def _events(logs: list[dict]) -> list[str]:
    return [entry["event"] for entry in logs]


def test_logs_transmission_start_and_reception() -> None:
    enable_debug()
    sim = Simulation("log-sim")
    sim.add_node("tx", 0.0, 0.0, 0.0)
    sim.add_node("rx", 100.0, 0.0, 0.0)

    with structlog.testing.capture_logs() as logs:
        sim.start_transmission("tx", b"hello world")
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is not None

    events = _events(logs)
    assert "tx_start" in events
    assert "rx_success" in events
    rx_log = next(entry for entry in logs if entry["event"] == "rx_success")
    assert rx_log["from_node_id"] == "tx"
    assert rx_log["payload_len"] == len(b"hello world")


def test_logs_rx_start_and_timeout() -> None:
    enable_debug()
    sim = Simulation("log-sim")
    sim.add_node("rx", 0.0, 0.0, 0.0)

    with structlog.testing.capture_logs() as logs:
        sim.start_receive("rx", timeout_ms=1)
        sim.advance_to(10_000)  # past the timeout -> fires RxTimeoutEvent

    events = _events(logs)
    assert "rx_start" in events
    assert "rx_timeout" in events


def test_logs_collision() -> None:
    enable_debug()
    sim = Simulation("log-sim")
    # Equidistant transmitters -> capture fails -> collision.
    sim.add_node("tx1", 0.0, 100.0, 0.0)
    sim.add_node("rx", 0.0, 0.0, 0.0)
    sim.add_node("tx2", 0.0, -100.0, 0.0)

    with structlog.testing.capture_logs() as logs:
        sim.start_transmission("tx1", b"a")
        sim.start_transmission("tx2", b"b")
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None

    collision_logs = [e for e in logs if e["event"] == "collision"]
    assert len(collision_logs) == 1
    assert len(collision_logs[0]["tx_ids"]) == 2
