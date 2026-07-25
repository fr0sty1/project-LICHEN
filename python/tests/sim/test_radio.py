# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for radio transmission and reception in the Simulation class."""

import pytest

from lichen.sim.events import RxTimeoutEvent, TxEndEvent
from lichen.sim.node import NodeState
from lichen.sim.simulation import Simulation
from lichen.sim.transmission import airtime_us


class TestTransmission:
    """Test transmission operations."""

    def test_start_transmission_sets_tx_state(self) -> None:
        """start_transmission sets node to TX state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.start_transmission("node1", b"test payload")

        assert node.state == NodeState.TX

    def test_start_transmission_returns_tx_id(self) -> None:
        """start_transmission returns a transmission ID."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        tx_id = sim.start_transmission("node1", b"test payload")

        assert isinstance(tx_id, str)
        assert len(tx_id) > 0

    def test_start_transmission_queues_tx_end_event(self) -> None:
        """start_transmission queues TxEndEvent."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        tx_id = sim.start_transmission("node1", b"test payload")

        event = sim.event_queue.peek()
        assert isinstance(event, TxEndEvent)
        assert event.node_id == "node1"
        assert event.transmission_id == tx_id

    def test_start_transmission_calculates_airtime(self) -> None:
        """start_transmission queues TxEndEvent at correct time."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        payload = b"test payload"
        expected_airtime = airtime_us(len(payload))

        sim.start_transmission("node1", payload)

        event = sim.event_queue.peek()
        assert event.time_us == expected_airtime

    def test_start_transmission_nonexistent_node_raises(self) -> None:
        """start_transmission raises ValueError for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        with pytest.raises(ValueError, match="does not exist"):
            sim.start_transmission("nonexistent", b"test")

    def test_start_transmission_disconnected_node_raises(self) -> None:
        """start_transmission raises ValueError for disconnected node."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        node.disconnect()

        with pytest.raises(ValueError, match="not connected"):
            sim.start_transmission("node1", b"test")

    def test_tx_end_event_returns_to_idle(self) -> None:
        """TxEndEvent processing returns node to IDLE state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_transmission("node1", b"test")

        # Process the TxEndEvent
        sim.process_next_event()

        assert node.state == NodeState.IDLE


class TestReceive:
    """Test receive operations."""

    def test_start_receive_sets_rx_wait_state(self) -> None:
        """start_receive sets node to RX_WAIT state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.start_receive("node1", timeout_ms=100)

        assert node.state == NodeState.RX_WAIT

    def test_start_receive_queues_timeout_event(self) -> None:
        """start_receive queues RxTimeoutEvent."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.start_receive("node1", timeout_ms=100)

        event = sim.event_queue.peek()
        assert isinstance(event, RxTimeoutEvent)
        assert event.node_id == "node1"
        assert event.time_us == 100 * 1000  # 100ms in microseconds

    def test_start_receive_nonexistent_node_raises(self) -> None:
        """start_receive raises ValueError for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        with pytest.raises(ValueError, match="does not exist"):
            sim.start_receive("nonexistent", timeout_ms=100)

    def test_start_receive_disconnected_node_raises(self) -> None:
        """start_receive raises ValueError for disconnected node."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        node.disconnect()

        with pytest.raises(ValueError, match="not connected"):
            sim.start_receive("node1", timeout_ms=100)

    def test_rx_timeout_event_returns_to_idle(self) -> None:
        """RxTimeoutEvent processing returns node to IDLE state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        # Process the RxTimeoutEvent
        sim.process_next_event()

        assert node.state == NodeState.IDLE


class TestRxResult:
    """Test receive result checking."""

    def test_get_rx_result_no_transmission(self) -> None:
        """get_rx_result returns None when no transmission."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        result = sim.get_rx_result("node1")

        assert result is None

    def test_get_rx_result_successful_reception(self) -> None:
        """get_rx_result returns payload for successful reception."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)  # 100m away

        payload = b"hello world"
        sim.start_transmission("tx_node", payload)

        # Advance time into the transmission
        sim.advance_to(1000)

        result = sim.get_rx_result("rx_node")

        assert result is not None
        rx_payload, rssi, snr = result
        assert rx_payload == payload
        assert isinstance(rssi, int)
        assert isinstance(snr, int)
        assert rssi < 0  # RSSI is negative dBm
        assert snr > 0  # SNR is positive

    def test_get_rx_result_excludes_self(self) -> None:
        """get_rx_result does not receive own transmission."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.start_transmission("node1", b"test")
        sim.advance_to(1000)

        result = sim.get_rx_result("node1")

        assert result is None

    def test_get_rx_result_nonexistent_node_raises(self) -> None:
        """get_rx_result raises ValueError for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        with pytest.raises(ValueError, match="does not exist"):
            sim.get_rx_result("nonexistent")

    def test_get_rx_result_after_transmission_ends(self) -> None:
        """get_rx_result returns None after transmission ends."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        sim.start_transmission("tx_node", b"test")

        # Get the transmission end time
        end_time = sim.event_queue.peek().time_us

        # Advance past the end
        sim.advance_to(end_time + 1000)

        result = sim.get_rx_result("rx_node")

        assert result is None


class TestEnterRxMode:
    """Test callback-based RX mode operations."""

    def test_enter_rx_mode_sets_rx_wait_state(self) -> None:
        """enter_rx_mode sets node to RX_WAIT state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        assert node.state == NodeState.RX_WAIT

    def test_enter_rx_mode_stores_callbacks(self) -> None:
        """enter_rx_mode stores the callbacks in node state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        def on_packet(p: bytes, r: int, s: int) -> None:
            pass

        def on_timeout() -> None:
            pass

        sim.enter_rx_mode("node1", timeout_us=100_000, on_packet=on_packet, on_timeout=on_timeout)

        assert node.rx_callbacks is not None
        assert node.rx_callbacks[0] is on_packet
        assert node.rx_callbacks[1] is on_timeout

    def test_enter_rx_mode_queues_timeout_event(self) -> None:
        """enter_rx_mode queues RxTimeoutEvent."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        event = sim.event_queue.peek()
        assert isinstance(event, RxTimeoutEvent)
        assert event.node_id == "node1"
        assert event.time_us == 100_000

    def test_enter_rx_mode_nonexistent_node_raises(self) -> None:
        """enter_rx_mode raises ValueError for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        with pytest.raises(ValueError, match="does not exist"):
            sim.enter_rx_mode(
                "nonexistent",
                timeout_us=100_000,
                on_packet=lambda p, r, s: None,
                on_timeout=lambda: None,
            )

    def test_enter_rx_mode_disconnected_node_raises(self) -> None:
        """enter_rx_mode raises ValueError for disconnected node."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        node.disconnect()

        with pytest.raises(ValueError, match="not connected"):
            sim.enter_rx_mode(
                "node1",
                timeout_us=100_000,
                on_packet=lambda p, r, s: None,
                on_timeout=lambda: None,
            )

    def test_timeout_callback_fires_on_timeout(self) -> None:
        """on_timeout callback fires when timeout expires."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        timeout_called = []

        def on_timeout() -> None:
            timeout_called.append(True)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=on_timeout,
        )

        # Process the timeout event
        sim.process_next_event()

        assert len(timeout_called) == 1

    def test_timeout_callback_clears_node_state(self) -> None:
        """Timeout processing clears rx_callbacks and returns to IDLE."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        sim.process_next_event()

        assert node.state == NodeState.IDLE
        assert node.rx_callbacks is None

    def test_packet_callback_fires_on_reception(self) -> None:
        """on_packet callback fires when packet is received."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        received = []

        def on_packet(payload: bytes, rssi: int, snr: int) -> None:
            received.append((payload, rssi, snr))

        payload = b"hello world"
        sim.start_transmission("tx_node", payload)

        # Advance time into the transmission
        sim.advance_to(1000)

        # Now enter RX mode with callback
        sim.enter_rx_mode(
            "rx_node",
            timeout_us=1_000_000,
            on_packet=on_packet,
            on_timeout=lambda: None,
        )

        # Deliver pending packets
        delivered = sim.deliver_pending_packets()

        assert delivered == 1
        assert len(received) == 1
        assert received[0][0] == payload
        assert isinstance(received[0][1], int)  # rssi
        assert isinstance(received[0][2], int)  # snr

    def test_packet_callback_clears_node_state(self) -> None:
        """Packet delivery clears rx_callbacks and returns to IDLE."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        rx_node = sim.add_node("rx_node", 100.0, 0.0, 0.0)

        sim.start_transmission("tx_node", b"test")
        sim.advance_to(1000)

        sim.enter_rx_mode(
            "rx_node",
            timeout_us=1_000_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        sim.deliver_pending_packets()

        assert rx_node.state == NodeState.IDLE
        assert rx_node.rx_callbacks is None

    def test_only_one_callback_fires(self) -> None:
        """Only on_packet or on_timeout fires, not both."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        packet_called = []
        timeout_called = []

        def on_packet(p: bytes, r: int, s: int) -> None:
            packet_called.append(True)

        def on_timeout() -> None:
            timeout_called.append(True)

        sim.start_transmission("tx_node", b"test")
        sim.advance_to(1000)

        sim.enter_rx_mode(
            "rx_node",
            timeout_us=100_000,
            on_packet=on_packet,
            on_timeout=on_timeout,
        )

        # Packet delivery should fire on_packet
        sim.deliver_pending_packets()

        # Process timeout event (should be no-op, node already back to IDLE)
        sim.process_next_event()

        assert len(packet_called) == 1
        assert len(timeout_called) == 0

    def test_exit_rx_mode_cancels_timeout(self) -> None:
        """exit_rx_mode cancels pending timeout and clears state."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        timeout_called = []

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: timeout_called.append(True),
        )

        assert not sim.event_queue.is_empty()

        sim.exit_rx_mode("node1")

        assert node.state == NodeState.IDLE
        assert node.rx_callbacks is None
        assert sim.event_queue.is_empty()

    def test_exit_rx_mode_nonexistent_node_safe(self) -> None:
        """exit_rx_mode with nonexistent ID does not raise."""
        sim = Simulation(sim_id="test-sim")

        sim.exit_rx_mode("nonexistent")  # Should not raise

    def test_barrier_sync_advances_with_callback_rx(self) -> None:
        """BARRIER_SYNC advances time when callback-based RX node is waiting."""
        from lichen.sim.simulation import TimeMode

        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is True
        assert sim.current_time_us > initial_time
        assert sim.current_time_us == 100_000

    def test_deliver_pending_packets_no_packet_returns_zero(self) -> None:
        """deliver_pending_packets returns 0 when no packets available."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )

        delivered = sim.deliver_pending_packets()

        assert delivered == 0

    def test_deliver_pending_packets_no_callback_nodes_returns_zero(self) -> None:
        """deliver_pending_packets returns 0 when no nodes have callbacks."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        # Use regular start_receive (no callbacks)
        sim.start_receive("rx_node", timeout_ms=1000)
        sim.start_transmission("tx_node", b"test")
        sim.advance_to(1000)

        delivered = sim.deliver_pending_packets()

        assert delivered == 0

    def test_callback_reception_updates_metrics_and_observer(self) -> None:
        """Callback RX records global metrics and emits the RX event."""
        sim = Simulation("callback-telemetry")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)
        events: list[dict[str, object]] = []

        class Observer:
            def on_rx_success(self, **kwargs: object) -> None:
                events.append(kwargs)

        sim.add_observer(Observer())
        sim.start_transmission("tx", b"hello")
        sim.advance_to(1000)
        sim.enter_rx_mode("rx", 1_000_000, lambda *_: None, lambda: None)

        assert sim.deliver_pending_packets() == 1
        assert sim.metrics.receptions == 1
        assert events == [
            {
                "sim_id": "callback-telemetry",
                "node_id": "rx",
                "tx_id": events[0]["tx_id"],
                "from_node_id": "tx",
                "payload_len": 5,
                "rssi": events[0]["rssi"],
                "snr": events[0]["snr"],
                "time_us": 1000,
            }
        ]

    def test_callback_collision_updates_metrics_and_observer(self) -> None:
        """Callback RX reports collisions just like direct RX."""
        sim = Simulation("callback-collision")
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)
        collisions: list[dict[str, object]] = []

        class Observer:
            def on_collision(self, **kwargs: object) -> None:
                collisions.append(kwargs)

        sim.add_observer(Observer())
        sim.start_transmission("tx1", b"a")
        sim.start_transmission("tx2", b"b")
        sim.advance_to(1000)
        sim.enter_rx_mode("rx", 1_000_000, lambda *_: None, lambda: None)

        assert sim.deliver_pending_packets() == 0
        assert sim.deliver_pending_packets() == 0
        assert sim.metrics.collisions == 1
        assert len(collisions) == 1
        assert collisions[0]["node_id"] == "rx"
        assert len(collisions[0]["tx_ids"]) == 2  # type: ignore[arg-type]
