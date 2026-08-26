# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for radio transmission and reception in the Simulation class."""

import pytest
from lora_medium import airtime_us

from lichen.sim.events import RxTimeoutEvent, TxEndEvent, TxStartDelayedEvent
from lichen.sim.node import NodeState
from lichen.sim.simulation import Simulation


class TestTransmission:
    """Test transmission operations."""

    def test_delayed_tx_uses_live_position_and_hop_channel(self) -> None:
        """A move (and hop change) during jitter is used at the actual TX instant."""
        sim = Simulation(sim_id="live-pos", jitter_min_us=5000, jitter_max_us=5000)
        tx_node = sim.add_node("tx", 0.0, 0.0, 0.0)
        tx_node.hop_schedule = (0,)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        assert sim.start_transmission("tx", b"move") == ""
        delayed = [
            e
            for e in sim.event_queue
            if isinstance(e, TxStartDelayedEvent) and e.node_id == "tx"
        ]
        assert delayed
        assert delayed[0].position == (0.0, 0.0, 0.0)
        sim.update_position("tx", 1000.0, 0.0, 0.0)
        tx_node.hop_schedule = (3,)
        sim.advance_to(5000)
        active = [t for t in sim.medium._active_transmissions if t.source_node_id == "tx"]
        assert len(active) == 1
        assert active[0].channel == 3
        assert sim.medium._tx_positions[active[0].id] == (1000.0, 0.0, 0.0)

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

    def test_get_rx_result_success_is_idempotent(self) -> None:
        """A second poll during airtime must not inflate rx_count or re-notify."""
        sim = Simulation(sim_id="rx-idempotent")
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        rx_node = sim.add_node("rx_node", 100.0, 0.0, 0.0)
        events: list[dict[str, object]] = []

        class Observer:
            def on_rx_success(self, **kwargs: object) -> None:
                events.append(kwargs)

        sim.add_observer(Observer())
        payload = b"hello world"
        sim.start_transmission("tx_node", payload)
        sim.advance_to(1000)

        first = sim.get_rx_result("rx_node")
        second = sim.get_rx_result("rx_node")

        assert first is not None
        assert second is not None
        assert first[0] == payload
        assert second[0] == payload
        assert sim.metrics.receptions == 1
        assert rx_node.metrics.rx_count == 1
        assert len(events) == 1


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
        assert not any(isinstance(e, RxTimeoutEvent) for e in sim.event_queue)

    def test_exit_rx_mode_preserves_delayed_tx(self) -> None:
        """exit_rx_mode must not cancel TxStartDelayedEvent (jitter path)."""
        sim = Simulation(sim_id="jitter-rx", jitter_min_us=1000, jitter_max_us=1000)
        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.enter_rx_mode(
            "node1",
            timeout_us=100_000,
            on_packet=lambda p, r, s: None,
            on_timeout=lambda: None,
        )
        tx_id = sim.start_transmission("node1", b"later")
        assert tx_id == ""
        sim.exit_rx_mode("node1")
        events = list(sim.event_queue)
        assert any(isinstance(e, TxStartDelayedEvent) for e in events)
        assert not any(isinstance(e, RxTimeoutEvent) and e.node_id == "node1" for e in events)
        sim.process_next_event()
        assert node.state == NodeState.TX
        assert any(isinstance(e, TxEndEvent) and e.node_id == "node1" for e in sim.event_queue)

    def test_deliver_pending_preserves_tx_end(self) -> None:
        """deliver_pending_packets must not remove this node's TxEndEvent."""
        sim = Simulation(sim_id="deliver-tx-end")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        rx = sim.add_node("rx", 100.0, 0.0, 0.0)
        sim.start_transmission("rx", b"self-tx")
        sim.start_transmission("tx", b"hello")
        sim.advance_to(1000)
        received: list[bytes] = []
        sim.enter_rx_mode("rx", 1_000_000, lambda p, r, s: received.append(p), lambda: None)
        sim.deliver_pending_packets()
        assert received == []
        assert any(isinstance(e, TxEndEvent) and e.node_id == "rx" for e in sim.event_queue)
        while not sim.event_queue.is_empty():
            event = sim.event_queue.peek()
            if event is None or event.time_us > sim.current_time_us + 10_000_000:
                break
            sim.process_next_event()
        assert rx.state != NodeState.TX
        assert not any(isinstance(e, TxEndEvent) and e.node_id == "rx" for e in sim.event_queue)

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


class TestDelayedRxStash:
    """LatencyRule stash TTL, chaos re-apply, and fail-closed eviction."""

    ADDED_US = 50_000

    def _sim_with_latency(self, node_id: str = "rx") -> tuple[Simulation, int]:
        from lichen.sim import ChaosEngine, LatencyRule

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id=node_id, added_us=self.ADDED_US))
        sim = Simulation(sim_id="delayed-rx", chaos_engine=chaos, seed=42)
        return sim, self.ADDED_US

    def test_delayed_packet_delivers_at_expire(self) -> None:
        """Polling at end_time + added_us still receives the delayed frame."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"on-time"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload

    def test_missed_poll_does_not_replay(self) -> None:
        """A candidate not taken at expiry is gone on a later poll."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"stale"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + added_us + 1)
        assert sim.get_rx_result("rx") is None
        sim.advance_to(airtime + added_us + airtime)
        assert sim.get_rx_result("rx") is None

    def test_stale_payload_is_not_next_hop_rx(self) -> None:
        """Missing the first frame's poll must not return it as the next TX."""
        sim, added_us = self._sim_with_latency("src")
        sim.add_node("src", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        first = b"first-frame"
        second = b"second-frame"
        sim.start_transmission("src", first)
        airtime_first = airtime_us(len(first))
        sim.advance_to(airtime_first + added_us + 1)
        sim.start_transmission("src", second)
        airtime_second = airtime_us(len(second))
        sim.advance_to(sim.current_time_us + airtime_second + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == second

    def test_unpolled_ghost_does_not_collide_later_tx(self) -> None:
        """An unpolled delayed TX expires and does not collide with a new TX."""
        sim, added_us = self._sim_with_latency("tx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.start_transmission("tx", b"ghost")
        airtime = airtime_us(len(b"ghost"))
        sim.advance_to(airtime + added_us + 1)
        payload = b"fresh"
        sim.start_transmission("tx", payload)
        airtime2 = airtime_us(len(payload))
        sim.advance_to(sim.current_time_us + airtime2 + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload
        assert sim.metrics.collisions == 0

    def test_aborted_tx_is_not_delivered(self) -> None:
        """Half-duplex replace drops the superseded TX's delayed stash."""
        sim, added_us = self._sim_with_latency("tx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.start_transmission("tx", b"aborted")
        sim.start_transmission("tx", b"keeper")
        airtime = airtime_us(len(b"keeper"))
        sim.advance_to(airtime + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == b"keeper"

    def test_drop_after_tx_end_still_drops(self) -> None:
        """Chaos added after TxEnd is applied on re-inject, not bypassed."""
        from lichen.sim import ChaosEngine, DropRule, LatencyRule

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        sim = Simulation(sim_id="delayed-drop", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"dropped-late"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime)
        chaos.add_rule(DropRule(node_id="rx", direction="rx"))
        sim.advance_to(airtime + self.ADDED_US)
        assert sim.get_rx_result("rx") is None

    def test_jam_after_tx_end_still_jams(self) -> None:
        """Jammer covering the receiver after TxEnd drops the delayed frame."""
        from lichen.sim import ChaosEngine, JammerRule, LatencyRule

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        sim = Simulation(sim_id="delayed-jam", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"jammed-late"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime)
        chaos.add_rule(JammerRule(x=50.0, y=0.0, z=0.0, radius_m=5.0))
        sim.advance_to(airtime + self.ADDED_US)
        assert sim.get_rx_result("rx") is None

    def test_partition_after_tx_end_still_partitions(self) -> None:
        """Partition added after TxEnd drops the delayed frame."""
        from lichen.sim import ChaosEngine, LatencyRule, PartitionRule

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        sim = Simulation(sim_id="delayed-part", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"part-late"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime)
        chaos.add_rule(PartitionRule(groups=[{"tx"}, {"rx"}]))
        sim.advance_to(airtime + self.ADDED_US)
        assert sim.get_rx_result("rx") is None

    def test_delayed_collision_does_not_permanently_silence(self) -> None:
        """Equal-RSSI delayed frames collide once, then the node can RX again."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx1", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, 0.0, 0.0)
        sim.add_node("rx", 80.0, 0.0, 0.0)
        sim.start_transmission("tx1", b"aaa")
        sim.start_transmission("tx2", b"bbb")
        airtime = max(airtime_us(len(b"aaa")), airtime_us(len(b"bbb")))
        sim.advance_to(airtime + added_us)
        assert sim.get_rx_result("rx") is None
        assert sim.get_rx_result("rx") is None
        payload = b"after-collision"
        sim.start_transmission("tx1", payload)
        airtime2 = airtime_us(len(payload))
        sim.advance_to(sim.current_time_us + airtime2 + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload

    def test_sender_match_does_not_grow_unbounded_on_unpolled_nodes(self) -> None:
        """LatencyRule sender-match must not accumulate stash on unpolled src."""
        sim, added_us = self._sim_with_latency("relay")
        sim.add_node("src", 0.0, 0.0, 0.0)
        sim.add_node("relay", 75.0, 0.0, 0.0)
        sim.add_node("dst", 150.0, 0.0, 0.0)
        for i in range(8):
            payload = f"n{i}".encode()
            sim.start_transmission("src", payload)
            airtime = airtime_us(len(payload))
            sim.advance_to(sim.current_time_us + airtime + added_us)
            result = sim.get_rx_result("relay")
            if result is None:
                continue
            sim.start_transmission("relay", result[0])
            airtime_r = airtime_us(len(result[0]))
            sim.advance_to(sim.current_time_us + airtime_r + added_us)
            sim.get_rx_result("dst")
        sim.advance_to(sim.current_time_us + 1)
        sim.get_rx_result("dst")
        delayed = getattr(sim, "_delayed_rx", {})
        src_keys = [k for k in delayed if k[0] == "src"]
        assert src_keys == []

    def test_remove_node_drops_stash(self) -> None:
        """remove_node must not leave a delayed frame for a re-added id."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"removed"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.remove_node("rx")
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.advance_to(airtime + added_us)
        assert sim.get_rx_result("rx") is None

    def test_rx_timeout_drops_stash(self) -> None:
        """RxTimeout ends the receive window; the delayed frame is not delivered."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"timeout"
        sim.start_receive("rx", timeout_ms=1)
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(1_000)
        sim.advance_to(airtime + added_us)
        assert sim.get_rx_result("rx") is None

    def test_tx_node_rx_timeout_does_not_drop_other_receivers(self) -> None:
        """A transmitter's RxTimeout must not evict other nodes' delayed copies."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"keep-me"
        sim.start_receive("tx", timeout_ms=1)
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        assert airtime > 1_000
        sim.advance_to(1_000)
        sim.advance_to(airtime + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload

    def test_exit_rx_on_tx_does_not_drop_other_receivers(self) -> None:
        """exit_rx_mode on the transmitter leaves other receivers' stash."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"keep-exit"
        sim.start_receive("tx", timeout_ms=1000)
        sim.start_transmission("tx", payload)
        sim.exit_rx_mode("tx")
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + added_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload

    def test_hop_channel_mismatch_drops_stash(self) -> None:
        """A delayed frame is not delivered after the receiver hops away."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        rx = sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"hopped"
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        channel = rx.get_hop_channel()
        rx.hop_schedule = ((channel + 1) % 8,)
        sim.advance_to(airtime + added_us)
        assert sim.get_rx_result("rx") is None

    def test_live_drop_pops_stash_no_resurrect(self) -> None:
        """A live apply_all None during airtime must pop stash so expire cannot resurrect.

        With chaos cache (bug 9098.20 fix), apply_all results are cached per
        (rx_node_id, tx_id). The first call (during stash) decides the fate
        for all subsequent polls. If the first call returns None, the stash
        entry is never created, preventing resurrection at expire.
        """
        from lora_medium import ChaosEngine, ChaosRule, LatencyRule, RxCandidate

        class DropOnFirstCall(ChaosRule):
            """Drop the packet on first apply() call."""

            def __init__(self) -> None:
                self.id = "drop-on-first"
                self.calls = 0

            def matches(self, tx: object, rx_node_id: str) -> bool:
                return rx_node_id == "rx"

            def apply(
                self,
                candidate: RxCandidate,
                rx_position: tuple[float, float, float] | None = None,
            ) -> RxCandidate | None:
                self.calls += 1
                # Drop on first call - with caching, this is the only call
                return None

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        dropper = DropOnFirstCall()
        chaos.add_rule(dropper)
        sim = Simulation(sim_id="live-drop-stash", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"no-resurrect"
        sim.start_transmission("tx", payload)
        # First call happens during _stash_delayed_rx_candidates
        assert dropper.calls == 1
        sim.advance_to(1000)
        # With caching, get_rx_result uses cached None - no second apply() call
        assert sim.get_rx_result("rx") is None
        assert dropper.calls == 1  # Cache prevents re-call
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + self.ADDED_US)
        # At expire time, packet is still dropped (cached result)
        assert sim.get_rx_result("rx") is None
        delayed = getattr(sim, "_delayed_rx", {})
        assert ("rx",) not in {k[:1] for k in delayed}

    def test_gilbert_elliott_live_drop_does_not_resurrect(self) -> None:
        """GilbertElliottRule drop during airtime must not be undone at expire."""
        import random

        from lichen.sim import ChaosEngine, GilbertElliottRule, LatencyRule

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        chaos.add_rule(
            GilbertElliottRule(
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=1.0,
                loss_prob_bad=1.0,
                rng=random.Random(0),
            )
        )
        sim = Simulation(sim_id="ge-live-drop", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"ge-dropped"
        sim.start_transmission("tx", payload)
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + self.ADDED_US)
        assert sim.get_rx_result("rx") is None

    def test_callback_delivery_with_latency_rule(self) -> None:
        """Callback RX with LatencyRule: deliver_pending_packets + maybe_advance_time.

        This is the bug 9098.18 regression test. Before the fix, maybe_advance_time
        jumped from TxEnd straight to RxTimeout, skipping the expire_us instant.
        The DelayedRxReadyEvent ensures time lands on eligibility.
        """
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"callback-delayed"
        received: list[bytes] = []

        def on_rx(data: bytes, _rssi: int, _snr: int) -> None:
            received.append(data)

        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime - 1)
        sim.enter_rx_mode("rx", 1_000_000, on_rx, lambda: None)
        sim.deliver_pending_packets()
        while sim.maybe_advance_time():
            sim.deliver_pending_packets()
            if received:
                break
        assert received == [payload], (
            f"Expected callback delivery at expire_us; got {received}. "
            "Bug 9098.18: DelayedRxReadyEvent must be queued so BARRIER_SYNC "
            "lands on eligibility instead of jumping to RxTimeout."
        )

    def test_gilbert_elliott_cache_prevents_reroll_on_poll(self) -> None:
        """Transition-capable GE is applied once; every poll matches that draw."""
        import random
        from unittest.mock import patch

        from lichen.sim import ChaosEngine, GilbertElliottRule

        apply_calls: list[str] = []
        original = GilbertElliottRule.apply

        def counting_apply(self, candidate, rx_position=None):  # type: ignore[no-untyped-def]
            apply_calls.append(candidate.transmission.id)
            return original(self, candidate, rx_position)

        chaos = ChaosEngine()
        chaos.add_rule(
            GilbertElliottRule(
                node_id="rx",
                direction="rx",
                p_good_to_bad=1.0,
                p_bad_to_good=0.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(42),
            )
        )
        with patch.object(GilbertElliottRule, "apply", counting_apply):
            sim = Simulation(sim_id="ge-cache-test", chaos_engine=chaos, seed=42)
            sim.add_node("tx", 0.0, 0.0, 0.0)
            sim.add_node("rx", 50.0, 0.0, 0.0)
            payload = b"ge-cache-test"
            sim.start_transmission("tx", payload)
            sim.start_receive("rx", timeout_ms=10000)
            sim.advance_to(1000)
            results = [sim.get_rx_result("rx") for _ in range(20)]

        assert len(apply_calls) == 1
        payloads = {None if r is None else r[0] for r in results}
        assert len(payloads) == 1

    def test_same_tick_timeout_does_not_drop_delayed_callback(self) -> None:
        """enter_rx_mode timeout at expire_us still delivers via DelayedRxReady."""
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"same-tick"
        received: list[bytes] = []
        timed_out: list[bool] = []

        def on_rx(data: bytes, _rssi: int, _snr: int) -> None:
            received.append(data)

        airtime = airtime_us(len(payload))
        timeout_us = airtime + added_us
        sim.enter_rx_mode("rx", timeout_us, on_rx, lambda: timed_out.append(True))
        sim.start_transmission("tx", payload)
        while sim.maybe_advance_time():
            sim.deliver_pending_packets()
            if received or timed_out:
                break
        assert received == [payload]
        assert timed_out == []
        sim.advance_to(timeout_us + 1)
        assert sim.get_rx_result("rx") is None

    def test_same_tick_timeout_after_tx_still_delivers(self) -> None:
        """Reversing enter_rx / TX order still delivers at expire == timeout."""
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"reverse-order"
        received: list[bytes] = []
        sim.start_transmission("tx", payload)
        airtime = airtime_us(len(payload))
        sim.enter_rx_mode(
            "rx", airtime + added_us, lambda p, r, s: received.append(p), lambda: None
        )
        while sim.maybe_advance_time():
            sim.deliver_pending_packets()
            if received:
                break
        assert received == [payload]

    def test_enter_rx_during_own_tx_does_not_hear_neighbor(self) -> None:
        """Half-duplex: RX_ENTER while TX is in flight cannot decode a neighbor."""
        sim = Simulation(sim_id="half-duplex-rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)
        sim.start_transmission("rx", b"self-tx")
        sim.start_transmission("tx", b"hello")
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None
        received: list[bytes] = []
        sim.enter_rx_mode("rx", 1_000_000, lambda p, r, s: received.append(p), lambda: None)
        assert sim.deliver_pending_packets() == 0
        assert received == []
        assert sim.get_rx_result("rx") is None

    def test_live_drop_stays_dead_across_second_poll(self) -> None:
        """A live apply_all None must not be restashed by a later airtime poll."""
        from lora_medium import ChaosEngine, ChaosRule, LatencyRule, RxCandidate

        class DropOnLivePoll(ChaosRule):
            def __init__(self) -> None:
                self.id = "drop-on-live-repeat"
                self.calls = 0

            def matches(self, tx: object, rx_node_id: str) -> bool:
                return rx_node_id == "rx"

            def apply(
                self,
                candidate: RxCandidate,
                rx_position: tuple[float, float, float] | None = None,
            ) -> RxCandidate | None:
                self.calls += 1
                if self.calls >= 2:
                    return None
                return candidate

        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="rx", added_us=self.ADDED_US))
        dropper = DropOnLivePoll()
        chaos.add_rule(dropper)
        sim = Simulation(sim_id="live-drop-sticky", chaos_engine=chaos, seed=42)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"stay-dead"
        sim.start_transmission("tx", payload)
        assert dropper.calls == 1
        delayed = getattr(sim, "_delayed_rx", {})
        tx_id = next(iter(sim._active_transmissions.values()))
        key = ("rx", tx_id)
        assert key in delayed
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None
        assert dropper.calls == 2
        delayed = getattr(sim, "_delayed_rx", {})
        assert key not in delayed
        ready_before = sum(
            1
            for e in sim.event_queue
            if e.__class__.__name__ == "DelayedRxReadyEvent" and getattr(e, "node_id", None) == "rx"
        )
        sim.advance_to(2000)
        assert sim.get_rx_result("rx") is None
        delayed = getattr(sim, "_delayed_rx", {})
        assert key not in delayed
        ready_after = sum(
            1
            for e in sim.event_queue
            if e.__class__.__name__ == "DelayedRxReadyEvent" and getattr(e, "node_id", None) == "rx"
        )
        assert ready_after <= ready_before
        airtime = airtime_us(len(payload))
        sim.advance_to(airtime + self.ADDED_US)
        assert sim.get_rx_result("rx") is None

    def test_ge_zero_loss_survives_many_polls(self) -> None:
        """Always-good GE must still deliver after N polls during one airtime."""
        import random

        from lichen.sim import ChaosEngine, GilbertElliottRule

        chaos = ChaosEngine()
        chaos.add_rule(
            GilbertElliottRule(
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(1),
            )
        )
        sim = Simulation(sim_id="ge-no-loss", chaos_engine=chaos, seed=1)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"ge-keep"
        sim.start_transmission("tx", payload)
        sim.advance_to(1000)
        for _ in range(20):
            result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload
        assert sim.metrics.receptions == 1
        assert sim._nodes["rx"].metrics.rx_count == 1

    def test_ge_full_loss_stays_dropped_across_polls(self) -> None:
        """Always-loss GE returns None on poll 1 and poll N."""
        import random

        from lichen.sim import ChaosEngine, GilbertElliottRule

        chaos = ChaosEngine()
        chaos.add_rule(
            GilbertElliottRule(
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=1.0,
                loss_prob_bad=1.0,
                rng=random.Random(2),
            )
        )
        sim = Simulation(sim_id="ge-all-loss", chaos_engine=chaos, seed=2)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"ge-gone"
        sim.start_transmission("tx", payload)
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None
        for _ in range(19):
            assert sim.get_rx_result("rx") is None
        assert sim.metrics.receptions == 0

    def test_ge_poll_count_does_not_change_receptions(self) -> None:
        """2 vs 20 polls agree on last-poll identity for a transitioning GE."""
        import random
        from unittest.mock import patch

        from lichen.sim import ChaosEngine, GilbertElliottRule

        apply_counts: list[int] = []
        original = GilbertElliottRule.apply

        def counting_apply(self, candidate, rx_position=None):  # type: ignore[no-untyped-def]
            counting_apply.calls += 1  # type: ignore[attr-defined]
            return original(self, candidate, rx_position)

        def run(polls: int) -> tuple[bytes | None, int, int]:
            counting_apply.calls = 0  # type: ignore[attr-defined]
            chaos = ChaosEngine()
            chaos.add_rule(
                GilbertElliottRule(
                    node_id="rx",
                    direction="rx",
                    p_good_to_bad=1.0,
                    p_bad_to_good=0.0,
                    loss_prob_good=0.0,
                    loss_prob_bad=1.0,
                    rng=random.Random(7),
                )
            )
            with patch.object(GilbertElliottRule, "apply", counting_apply):
                sim = Simulation(sim_id=f"ge-polls-{polls}", chaos_engine=chaos, seed=7)
                sim.add_node("tx", 0.0, 0.0, 0.0)
                sim.add_node("rx", 50.0, 0.0, 0.0)
                sim.start_transmission("tx", b"abc")
                sim.advance_to(1000)
                last = None
                for _ in range(polls):
                    last = sim.get_rx_result("rx")
                apply_counts.append(counting_apply.calls)  # type: ignore[attr-defined]
                payload = None if last is None else last[0]
                return payload, sim.metrics.receptions, apply_counts[-1]

        payload_2, rx_2, calls_2 = run(2)
        payload_20, rx_20, calls_20 = run(20)
        assert payload_2 == payload_20
        assert rx_2 == rx_20
        assert calls_2 == calls_20 == 1

    def test_staggered_overlap_counts_one_collision(self) -> None:
        """Growing overlap frozensets are one collision epoch, not one per poll."""
        sim = Simulation(sim_id="collision-epoch")
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)
        sim.add_node("tx3", 100.0, 0.0, 0.0)
        sim.start_transmission("tx1", b"aaa")
        sim.start_transmission("tx2", b"bbb")
        sim.advance_to(500)
        assert sim.get_rx_result("rx") is None
        assert sim.metrics.collisions == 1
        sim.start_transmission("tx3", b"ccc")
        sim.advance_to(1000)
        for _ in range(5):
            assert sim.get_rx_result("rx") is None
        assert sim.metrics.collisions == 1
        rx_channel = sim._nodes["rx"].get_hop_channel()
        assert sim.metrics.collisions_by_channel.get(rx_channel, 0) == 1
        assert any(event[1] == "collision" for event in sim.metrics._time_series)

    def test_delivered_frame_does_not_also_count_collision(self) -> None:
        """A reception must not be followed by a collision that includes that tx."""
        sim = Simulation(sim_id="rx-then-collide")
        sim.add_node("tx1", 50.0, 0.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 50.0, 0.0, 0.0)
        sim.start_transmission("tx1", b"first-only")
        sim.advance_to(1000)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert sim.metrics.receptions == 1
        sim.start_transmission("tx2", b"overlap")
        sim.advance_to(2000)
        sim.get_rx_result("rx")
        assert sim.metrics.receptions == 1
        assert sim.metrics.collisions == 0

    def test_ge_two_receivers_independent_of_add_order(self) -> None:
        """GE per-link draws do not follow _nodes insertion order."""
        import random
        from unittest.mock import patch

        from lichen.sim import ChaosEngine, GilbertElliottRule

        apply_calls: list[int] = []
        original = GilbertElliottRule.apply

        def counting_apply(self, candidate, rx_position=None):  # type: ignore[no-untyped-def]
            apply_calls.append(1)
            return original(self, candidate, rx_position)

        def run(rx_order: tuple[str, str]) -> dict[str, bytes | None]:
            apply_calls.clear()
            ge = GilbertElliottRule(
                node_id=None,
                direction="both",
                p_good_to_bad=0.0,
                p_bad_to_good=0.0,
                loss_prob_good=0.5,
                loss_prob_bad=1.0,
                rng=random.Random(11),
            )
            chaos = ChaosEngine()
            chaos.add_rule(ge)
            with patch.object(GilbertElliottRule, "apply", counting_apply):
                sim = Simulation(sim_id=f"ge-order-{rx_order[0]}", chaos_engine=chaos, seed=11)
                sim.add_node("tx", 0.0, 0.0, 0.0)
                for name in rx_order:
                    sim.add_node(name, 50.0, 0.0, 0.0)
                sim.start_transmission("tx", b"multi-rx")
                sim.advance_to(1000)
                out: dict[str, bytes | None] = {}
                for name in ("rx_a", "rx_b"):
                    for _ in range(5):
                        result = sim.get_rx_result(name)
                    out[name] = None if result is None else result[0]
                assert len(apply_calls) == 2
                return out

        first = run(("rx_a", "rx_b"))
        second = run(("rx_b", "rx_a"))
        assert first == second

    def test_ge_burst_state_persists_across_transmissions(self) -> None:
        """Good→Bad on packet 1 must still be Bad for packet 2 on the same link."""
        import random

        from lora_medium import RxCandidate, Transmission

        from lichen.sim import ChaosEngine, GilbertElliottRule

        def make_rule(seed: int) -> GilbertElliottRule:
            return GilbertElliottRule(
                node_id="rx",
                direction="rx",
                p_good_to_bad=1.0,
                p_bad_to_good=0.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(seed),
            )

        oracle = make_rule(13)
        tx1 = Transmission(
            source_node_id="tx",
            payload=b"pkt1",
            tx_power_dbm=14,
            start_time_us=0,
            end_time_us=1000,
        )
        tx2 = Transmission(
            source_node_id="tx",
            payload=b"pkt2",
            tx_power_dbm=14,
            start_time_us=2000,
            end_time_us=3000,
        )
        first_direct = oracle.apply(RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0))
        second_direct = oracle.apply(RxCandidate(transmission=tx2, rssi=-70.0, snr=50.0))

        chaos = ChaosEngine()
        chaos.add_rule(make_rule(13))
        sim = Simulation(sim_id="ge-burst", chaos_engine=chaos, seed=13)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.start_transmission("tx", b"pkt1")
        sim.advance_to(1000)
        first_radio = sim.get_rx_result("rx")
        air = airtime_us(len(b"pkt1"))
        sim.advance_to(air + 1)
        sim.start_transmission("tx", b"pkt2")
        sim.advance_to(sim.current_time_us + 1000)
        second_radio = sim.get_rx_result("rx")

        # GilbertElliottRule transitions state BEFORE loss decision, so with
        # p_good_to_bad=1.0 both packets land in Bad state and are dropped.
        assert (first_direct is not None) == (first_radio is not None)
        assert (second_direct is not None) == (second_radio is not None)
        # Both should be None (dropped in Bad state)
        assert first_radio is None
        assert second_radio is None

    def test_second_ge_rule_can_drop_after_first_survives(self) -> None:
        """Stacked GE rules all run; a later always-drop GE still kills the packet."""
        import random

        from lichen.sim import ChaosEngine, GilbertElliottRule

        chaos = ChaosEngine()
        chaos.add_rule(
            GilbertElliottRule(
                id="ge-keep",
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(1),
            )
        )
        chaos.add_rule(
            GilbertElliottRule(
                id="ge-drop",
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=1.0,
                loss_prob_bad=1.0,
                rng=random.Random(2),
            )
        )
        sim = Simulation(sim_id="ge-two-rules-drop", chaos_engine=chaos, seed=1)
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.start_transmission("tx", b"stacked-ge")
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None

    def test_two_ge_rules_apply_once_each_per_tx(self) -> None:
        """Two surviving GE rules each apply once; extra polls do not re-roll."""
        import random
        from unittest.mock import patch

        from lichen.sim import ChaosEngine, GilbertElliottRule

        apply_ids: list[str] = []
        original = GilbertElliottRule.apply

        def counting_apply(self, candidate, rx_position=None):  # type: ignore[no-untyped-def]
            apply_ids.append(self.id)
            return original(self, candidate, rx_position)

        chaos = ChaosEngine()
        chaos.add_rule(
            GilbertElliottRule(
                id="ge-a",
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(3),
            )
        )
        chaos.add_rule(
            GilbertElliottRule(
                id="ge-b",
                node_id="rx",
                direction="rx",
                p_good_to_bad=0.0,
                p_bad_to_good=1.0,
                loss_prob_good=0.0,
                loss_prob_bad=1.0,
                rng=random.Random(4),
            )
        )
        with patch.object(GilbertElliottRule, "apply", counting_apply):
            sim = Simulation(sim_id="ge-two-rules-keep", chaos_engine=chaos, seed=3)
            sim.add_node("tx", 0.0, 0.0, 0.0)
            sim.add_node("rx", 50.0, 0.0, 0.0)
            payload = b"both-live"
            sim.start_transmission("tx", payload)
            sim.advance_to(1000)
            results = [sim.get_rx_result("rx") for _ in range(20)]

        assert apply_ids == ["ge-a", "ge-b"]
        assert all(r is not None and r[0] == payload for r in results)

    def test_collision_epoch_closes_after_tx_end_without_poll(self) -> None:
        """A new disjoint overlap after TxEnd counts; epoch is not stuck open."""
        sim = Simulation(sim_id="collision-epoch-close")
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)
        sim.add_node("tx3", 100.0, 0.0, 0.0)
        sim.add_node("tx4", -100.0, 0.0, 0.0)
        sim.start_transmission("tx1", b"aaa")
        sim.start_transmission("tx2", b"bbb")
        sim.advance_to(500)
        assert sim.get_rx_result("rx") is None
        assert sim.metrics.collisions == 1
        air = airtime_us(len(b"aaa"))
        sim.advance_to(air + 1)
        sim.start_transmission("tx3", b"ccc")
        sim.start_transmission("tx4", b"ddd")
        sim.advance_to(sim.current_time_us + 500)
        assert sim.get_rx_result("rx") is None
        assert sim.metrics.collisions == 2

    def test_same_tick_timeout_delivers_polling_rx(self) -> None:
        """Polling RX at expire == timeout still returns the delayed frame."""
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        sim.add_node("tx", 0.0, 0.0, 0.0)
        rx = sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"poll-tick"
        airtime = airtime_us(len(payload))
        timeout_us = airtime + added_us
        rx.state = NodeState.RX_WAIT
        sim._pending_rx_timeouts["rx"] = timeout_us
        sim.event_queue.push(RxTimeoutEvent(time_us=timeout_us, node_id="rx"))
        sim.start_transmission("tx", payload)
        sim.advance_to(timeout_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload

    def test_parked_poll_consumed_allows_later_tx(self) -> None:
        """After pulling delayed frame A, TX B in the same start_receive window is visible."""
        sim, added_us = self._sim_with_latency("rx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        sim.start_receive("rx", timeout_ms=10000)
        payload_a = b"frame-a"
        sim.start_transmission("tx", payload_a)
        air_a = airtime_us(len(payload_a))
        sim.advance_to(air_a + added_us)
        first = sim.get_rx_result("rx")
        assert first is not None
        assert first[0] == payload_a
        payload_b = b"frame-b"
        sim.start_transmission("tx", payload_b)
        air_b = airtime_us(len(payload_b))
        sim.advance_to(sim.current_time_us + air_b + added_us)
        second = sim.get_rx_result("rx")
        assert second is not None
        assert second[0] == payload_b

    def test_parked_poll_does_not_latch_after_timeout(self) -> None:
        """After RxTimeout, a second get_rx_result without start_receive is None."""
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        sim.add_node("tx", 0.0, 0.0, 0.0)
        rx = sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"once-only"
        airtime = airtime_us(len(payload))
        timeout_us = airtime + added_us
        rx.state = NodeState.RX_WAIT
        sim._pending_rx_timeouts["rx"] = timeout_us
        sim.event_queue.push(RxTimeoutEvent(time_us=timeout_us, node_id="rx"))
        sim.start_transmission("tx", payload)
        sim.advance_to(timeout_us)
        first = sim.get_rx_result("rx")
        assert first is not None
        assert first[0] == payload
        assert sim.get_rx_result("rx") is None

    def test_same_tick_timeout_polling_does_not_fire_rx_timeout(self) -> None:
        """Polling capture at expire==timeout notifies on_rx_success, not on_rx_timeout."""
        from lichen.sim.simulation.base import TimeMode

        sim, added_us = self._sim_with_latency("rx")
        sim._time_mode = TimeMode.BARRIER_SYNC
        events: list[str] = []

        class Observer:
            def on_rx_success(self, **kwargs: object) -> None:
                events.append("success")

            def on_rx_timeout(self, **kwargs: object) -> None:
                events.append("timeout")

        sim.add_observer(Observer())
        sim.add_node("tx", 0.0, 0.0, 0.0)
        rx = sim.add_node("rx", 50.0, 0.0, 0.0)
        payload = b"poll-obs"
        airtime = airtime_us(len(payload))
        timeout_us = airtime + added_us
        rx.state = NodeState.RX_WAIT
        sim._pending_rx_timeouts["rx"] = timeout_us
        sim.event_queue.push(RxTimeoutEvent(time_us=timeout_us, node_id="rx"))
        sim.start_transmission("tx", payload)
        sim.advance_to(timeout_us)
        result = sim.get_rx_result("rx")
        assert result is not None
        assert result[0] == payload
        assert "success" in events
        assert "timeout" not in events


class TestDutyCycleAndRemoveNode:
    """Duty-cycle reject and remove_node medium cleanup."""

    def test_duty_cycle_reject_does_not_crash_or_stick_tx(self) -> None:
        """Filling the 1s/30% window returns '' and leaves the node idle."""
        from lora_medium import Medium

        sim = Simulation(sim_id="duty-reject")
        sim._medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )
        node = sim.add_node("n", 0.0, 0.0, 0.0)
        tx1 = sim.start_transmission("n", b"test")
        assert tx1
        assert node.state == NodeState.TX
        sim.process_next_event()
        assert node.state == NodeState.IDLE
        tx2 = sim.start_transmission("n", b"test")
        assert tx2 == ""
        assert node.state == NodeState.IDLE
        recovery_us = airtime_us(len(b"test")) + 1_000_000 + 1
        sim.advance_to(recovery_us)
        tx3 = sim.start_transmission("n", b"test")
        assert tx3
        assert node.state == NodeState.TX

    def test_duty_cycle_reject_preserves_rx_wait(self) -> None:
        """A rejected TX must not tear down an RX_WAIT window."""
        from lora_medium import Medium

        sim = Simulation(sim_id="duty-rx")
        sim._medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )
        node = sim.add_node("n", 0.0, 0.0, 0.0)
        sim.start_transmission("n", b"test")
        sim.process_next_event()
        sim.enter_rx_mode("n", 1_000_000, lambda *_a: None, lambda: None)
        callbacks = node.rx_callbacks
        assert node.state == NodeState.RX_WAIT
        assert sim.start_transmission("n", b"test") == ""
        assert node.state == NodeState.RX_WAIT
        assert node.rx_callbacks is callbacks

    def test_duty_cycle_reject_keeps_in_flight_tx(self) -> None:
        """Rejecting a replacement TX must not abort the previous airtime."""
        from lora_medium import Medium

        sim = Simulation(sim_id="duty-keep-tx")
        sim._medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )
        node = sim.add_node("n", 0.0, 0.0, 0.0)
        tx1 = sim.start_transmission("n", b"test")
        assert tx1
        assert node.state == NodeState.TX
        assert sim.start_transmission("n", b"test") == ""
        assert node.state == NodeState.TX
        assert any(
            isinstance(e, TxEndEvent) and e.transmission_id == tx1 for e in sim.event_queue
        )
        sim.process_next_event()
        assert node.state == NodeState.IDLE

    def test_remove_node_ends_medium_tx(self) -> None:
        """remove_node calls medium.end_tx so the frame cannot be decoded."""
        sim = Simulation(sim_id="remove-tx")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 50.0, 0.0, 0.0)
        tx_id = sim.start_transmission("tx", b"hello")
        sim.remove_node("tx")
        active = sim.medium.get_active_transmissions(sim.current_time_us)
        assert all(t.id != tx_id for t in active)
        assert tx_id not in sim.medium._tx_positions
        sim.advance_to(1000)
        assert sim.get_rx_result("rx") is None
        for i in range(5):
            nid = f"n{i}"
            sim.add_node(nid, 0.0, 0.0, 0.0)
            sim.start_transmission(nid, b"x")
            sim.remove_node(nid)
        assert sim.medium._active_transmissions == []


class TestDensityAwareStartup:
    """listen_period_us and log(1+heard) backoff."""

    def test_isolated_node_has_zero_density_delay(self) -> None:
        """heard=0 → log(1+0)=0 so the density term is always 0."""
        sim = Simulation(
            sim_id="density-zero",
            density_aware_startup=True,
            listen_period_us=0,
            density_scale_factor=2000.0,
            seed=0,
        )
        node = sim.add_node("n", 0.0, 0.0, 0.0)
        assert sim.calculate_startup_delay(node) == 0

    def test_density_delay_is_log_not_linear(self) -> None:
        """heard=10 is scaled by log(11), not by 11."""
        import math

        sim = Simulation(
            sim_id="density-log",
            density_aware_startup=True,
            listen_period_us=0,
            density_scale_factor=1000.0,
            seed=1,
        )
        node = sim.add_node("n", 0.0, 0.0, 0.0)
        node.heard_set.update(str(i) for i in range(10))
        delay = sim.calculate_startup_delay(node)
        log_cap = int(1000.0 * math.log1p(10))
        linear_cap = int(1000.0 * 11)
        assert 0 <= delay <= log_cap
        assert log_cap < linear_cap

    def test_listen_period_delays_first_tx(self) -> None:
        """listen_period_us is consumed before the first TX is queued."""
        sim = Simulation(
            sim_id="density-listen",
            density_aware_startup=True,
            listen_period_us=50_000,
            density_scale_factor=1000.0,
            seed=3,
        )
        sim.add_node("n", 0.0, 0.0, 0.0)
        tx_id = sim.start_transmission("n", b"first")
        assert tx_id == ""
        delayed = [
            e
            for e in sim.event_queue
            if isinstance(e, TxStartDelayedEvent) and e.node_id == "n"
        ]
        assert delayed
        assert 0 <= delayed[0].time_us <= 50_000
        assert sim.listen_period_us == 50_000
