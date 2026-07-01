# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SimNode state tracking."""

from __future__ import annotations

import asyncio

import pytest

from lichen.sim import NodeState, SimNode
from lichen.state_machine import StateError, StateMachine


class TestNodeState:
    """Tests for NodeState enum."""

    def test_enum_values_exist(self) -> None:
        """NodeState should have IDLE, TX, and RX_WAIT values."""
        assert NodeState.IDLE is not None
        assert NodeState.TX is not None
        assert NodeState.RX_WAIT is not None

    def test_enum_values_distinct(self) -> None:
        """Each state should be distinct."""
        states = [NodeState.IDLE, NodeState.TX, NodeState.RX_WAIT]
        assert len(states) == len(set(states))


class TestSimNodeCreation:
    """Tests for SimNode initialization."""

    def test_minimal_creation(self) -> None:
        """Node can be created with just an ID."""
        node = SimNode(id="node-1")
        assert node.id == "node-1"

    def test_default_position(self) -> None:
        """Default position should be origin."""
        node = SimNode(id="node-1")
        assert node.position == (0.0, 0.0, 0.0)

    def test_default_tx_power(self) -> None:
        """Default TX power should be 22 dBm."""
        node = SimNode(id="node-1")
        assert node.tx_power_dbm == 22

    def test_default_state(self) -> None:
        """Default state should be IDLE."""
        node = SimNode(id="node-1")
        assert node.state == NodeState.IDLE

    def test_default_pending_rx_future(self) -> None:
        """Default pending_rx_future should be None."""
        node = SimNode(id="node-1")
        assert node.pending_rx_future is None

    def test_default_connected(self) -> None:
        """Default connected should be False."""
        node = SimNode(id="node-1")
        assert node.connected is False

    def test_default_last_seen_time(self) -> None:
        """Default last_seen_time_us should be 0."""
        node = SimNode(id="node-1")
        assert node.last_seen_time_us == 0

    def test_custom_values(self) -> None:
        """Node can be created with custom values."""
        node = SimNode(
            id="custom-node",
            position=(10.0, 20.0, 5.0),
            tx_power_dbm=14,
            state=NodeState.TX,
            connected=True,
            last_seen_time_us=1000000,
        )
        assert node.id == "custom-node"
        assert node.position == (10.0, 20.0, 5.0)
        assert node.tx_power_dbm == 14
        assert node.state == NodeState.TX
        assert node.connected is True
        assert node.last_seen_time_us == 1000000


class TestSetPosition:
    """Tests for position updates."""

    def test_set_position_updates_coordinates(self) -> None:
        """set_position should update all coordinates."""
        node = SimNode(id="mobile")
        node.set_position(100.0, 200.0, 10.0)
        assert node.position == (100.0, 200.0, 10.0)

    def test_set_position_replaces_previous(self) -> None:
        """set_position should replace the previous position."""
        node = SimNode(id="mobile", position=(1.0, 2.0, 3.0))
        node.set_position(4.0, 5.0, 6.0)
        assert node.position == (4.0, 5.0, 6.0)

    def test_set_position_accepts_negative(self) -> None:
        """set_position should accept negative coordinates."""
        node = SimNode(id="mobile")
        node.set_position(-50.0, -100.0, -5.0)
        assert node.position == (-50.0, -100.0, -5.0)

    def test_set_position_accepts_floats(self) -> None:
        """set_position should accept fractional coordinates."""
        node = SimNode(id="mobile")
        node.set_position(1.5, 2.75, 0.125)
        assert node.position == (1.5, 2.75, 0.125)


class TestDisconnect:
    """Tests for disconnect behavior."""

    def test_disconnect_sets_connected_false(self) -> None:
        """disconnect should set connected to False."""
        node = SimNode(id="node-1", connected=True)
        node.disconnect()
        assert node.connected is False

    def test_disconnect_already_disconnected(self) -> None:
        """disconnect on already disconnected node should be safe."""
        node = SimNode(id="node-1", connected=False)
        node.disconnect()
        assert node.connected is False

    def test_disconnect_clears_pending_future(self) -> None:
        """disconnect should set pending_rx_future to None."""
        loop = asyncio.new_event_loop()
        try:
            future: asyncio.Future[None] = loop.create_future()
            node = SimNode(id="node-1", connected=True, pending_rx_future=future)
            node.disconnect()
            assert node.pending_rx_future is None
        finally:
            loop.close()

    def test_disconnect_cancels_pending_future(self) -> None:
        """disconnect should cancel an incomplete future."""
        loop = asyncio.new_event_loop()
        try:
            future: asyncio.Future[None] = loop.create_future()
            node = SimNode(id="node-1", connected=True, pending_rx_future=future)
            node.disconnect()
            assert future.cancelled()
        finally:
            loop.close()

    def test_disconnect_handles_completed_future(self) -> None:
        """disconnect should handle already-completed future gracefully."""
        loop = asyncio.new_event_loop()
        try:
            future: asyncio.Future[None] = loop.create_future()
            future.set_result(None)
            node = SimNode(id="node-1", connected=True, pending_rx_future=future)
            node.disconnect()
            assert node.pending_rx_future is None
            assert not future.cancelled()
        finally:
            loop.close()

    def test_disconnect_handles_cancelled_future(self) -> None:
        """disconnect should handle already-cancelled future gracefully."""
        loop = asyncio.new_event_loop()
        try:
            future: asyncio.Future[None] = loop.create_future()
            future.cancel()
            node = SimNode(id="node-1", connected=True, pending_rx_future=future)
            node.disconnect()
            assert node.pending_rx_future is None
        finally:
            loop.close()


class TestIsOnline:
    """Tests for is_online method."""

    def test_is_online_when_connected(self) -> None:
        """is_online should return True when connected."""
        node = SimNode(id="node-1", connected=True)
        assert node.is_online() is True

    def test_is_online_when_disconnected(self) -> None:
        """is_online should return False when not connected."""
        node = SimNode(id="node-1", connected=False)
        assert node.is_online() is False

    def test_is_online_after_disconnect(self) -> None:
        """is_online should return False after disconnect."""
        node = SimNode(id="node-1", connected=True)
        assert node.is_online() is True
        node.disconnect()
        assert node.is_online() is False


class TestStateTransitions:
    """Tests for state field transitions."""

    def test_idle_to_tx(self) -> None:
        """Node can transition from IDLE to TX."""
        node = SimNode(id="node-1", state=NodeState.IDLE)
        node.state = NodeState.TX
        assert node.state == NodeState.TX

    def test_idle_to_rx_wait(self) -> None:
        """Node can transition from IDLE to RX_WAIT."""
        node = SimNode(id="node-1", state=NodeState.IDLE)
        node.state = NodeState.RX_WAIT
        assert node.state == NodeState.RX_WAIT

    def test_tx_to_idle(self) -> None:
        """Node can transition from TX to IDLE."""
        node = SimNode(id="node-1", state=NodeState.TX)
        node.state = NodeState.IDLE
        assert node.state == NodeState.IDLE

    def test_rx_wait_to_idle(self) -> None:
        """Node can transition from RX_WAIT to IDLE."""
        node = SimNode(id="node-1", state=NodeState.RX_WAIT)
        node.state = NodeState.IDLE
        assert node.state == NodeState.IDLE

    def test_idle_to_idle_noop(self) -> None:
        """A repeated state assignment is a no-op."""
        node = SimNode(id="node-1", state=NodeState.IDLE)
        node.state = NodeState.IDLE
        assert node.state == NodeState.IDLE

    def test_state_machine_invalid_transition_raises(self) -> None:
        """The shared verifier rejects transitions outside its table."""
        machine = StateMachine(
            initial=NodeState.TX,
            transitions={NodeState.TX: frozenset({NodeState.IDLE})},
            name="test-node",
        )
        with pytest.raises(StateError, match="invalid transition TX -> RX_WAIT"):
            machine.transition(NodeState.RX_WAIT)

    def test_state_machine_invalid_initial_state_raises(self) -> None:
        """The shared verifier rejects an initial state absent from the table."""
        with pytest.raises(StateError, match="initial state TX is not in transition table"):
            StateMachine(
                initial=NodeState.TX,
                transitions={NodeState.IDLE: frozenset({NodeState.RX_WAIT})},
                name="test-node",
            )

    def test_non_state_value_raises(self) -> None:
        """Only NodeState values are accepted."""
        node = SimNode(id="node-1")
        with pytest.raises(StateError, match="invalid state value"):
            node.state = "TX"  # type: ignore[assignment]
