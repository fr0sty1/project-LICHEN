"""Tests for the Simulation class."""

import pytest

from lichen.sim.events import RxTimeoutEvent, TxEndEvent
from lichen.sim.medium import Medium
from lichen.sim.node import NodeState, SimNode
from lichen.sim.simulation import Simulation, TimeMode
from lichen.sim.transmission import airtime_us


class TestSimulationInit:
    """Test Simulation initialization."""

    def test_init_with_defaults(self) -> None:
        """Simulation initializes with default values."""
        sim = Simulation(sim_id="test-sim")

        assert sim.id == "test-sim"
        assert sim.current_time_us == 0
        assert sim.time_mode == TimeMode.BARRIER_SYNC
        assert isinstance(sim.medium, Medium)
        assert sim.event_queue.is_empty()

    def test_init_with_realtime_mode(self) -> None:
        """Simulation can be initialized with REALTIME mode."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.REALTIME)

        assert sim.time_mode == TimeMode.REALTIME


class TestNodeManagement:
    """Test node add/remove/get operations."""

    def test_add_node_creates_node(self) -> None:
        """add_node creates a SimNode with correct parameters."""
        sim = Simulation(sim_id="test-sim")

        node = sim.add_node("node1", x=10.0, y=20.0, z=5.0)

        assert isinstance(node, SimNode)
        assert node.id == "node1"
        assert node.position == (10.0, 20.0, 5.0)
        assert node.connected is True
        assert node.state == NodeState.IDLE

    def test_add_node_returns_same_node(self) -> None:
        """add_node returns the node that was created."""
        sim = Simulation(sim_id="test-sim")

        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        retrieved = sim.get_node("node1")

        assert retrieved is node

    def test_add_duplicate_node_raises(self) -> None:
        """add_node raises ValueError for duplicate node ID."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        with pytest.raises(ValueError, match="already exists"):
            sim.add_node("node1", 1.0, 1.0, 1.0)

    def test_get_node_returns_none_for_missing(self) -> None:
        """get_node returns None for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        result = sim.get_node("nonexistent")

        assert result is None

    def test_remove_node_removes_from_simulation(self) -> None:
        """remove_node removes node from simulation."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.remove_node("node1")

        assert sim.get_node("node1") is None

    def test_remove_node_disconnects_node(self) -> None:
        """remove_node disconnects the node."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.remove_node("node1")

        assert node.connected is False

    def test_remove_node_purges_events(self) -> None:
        """remove_node removes pending events for that node."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Queue events for both nodes
        sim.start_receive("node1", timeout_ms=1000)
        sim.start_receive("node2", timeout_ms=2000)

        assert len(sim.event_queue) == 2

        # Remove node1 - its events should be purged
        sim.remove_node("node1")

        assert len(sim.event_queue) == 1
        # Remaining event should be for node2
        event = sim.event_queue.peek()
        assert event is not None
        assert event.node_id == "node2"  # type: ignore[union-attr]

    def test_remove_nonexistent_node_is_safe(self) -> None:
        """remove_node with nonexistent ID does not raise."""
        sim = Simulation(sim_id="test-sim")

        sim.remove_node("nonexistent")  # Should not raise

    def test_get_connected_node_count(self) -> None:
        """get_connected_node_count returns correct count."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 1.0, 0.0, 0.0)

        assert sim.get_connected_node_count() == 2

        sim.remove_node("node1")
        assert sim.get_connected_node_count() == 1

    def test_get_all_nodes(self) -> None:
        """get_all_nodes returns all nodes."""
        sim = Simulation(sim_id="test-sim")
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 1.0, 0.0, 0.0)

        nodes = sim.get_all_nodes()

        assert len(nodes) == 2
        assert node1 in nodes
        assert node2 in nodes


class TestTimeAdvancement:
    """Test time advancement mechanics."""

    def test_advance_to_updates_time(self) -> None:
        """advance_to updates current_time_us."""
        sim = Simulation(sim_id="test-sim")

        sim.advance_to(1000)

        assert sim.current_time_us == 1000

    def test_advance_to_negative_raises(self) -> None:
        """advance_to raises ValueError for time in the past."""
        sim = Simulation(sim_id="test-sim")
        sim.advance_to(1000)

        with pytest.raises(ValueError, match="Cannot advance backwards"):
            sim.advance_to(500)

    def test_advance_to_processes_events(self) -> None:
        """advance_to processes events up to target time."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        # Start a transmission that will end at some time
        sim.start_transmission("node1", b"test")
        tx_end_time = sim.event_queue.peek().time_us

        # Advance past the transmission end
        sim.advance_to(tx_end_time + 1000)

        # Node should be back to IDLE
        assert node.state == NodeState.IDLE

    def test_advance_to_does_not_process_future_events(self) -> None:
        """advance_to does not process events after target time."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        # Start receive with long timeout
        sim.start_receive("node1", timeout_ms=10000)

        # Advance to before timeout
        sim.advance_to(5000)

        # Node should still be in RX_WAIT
        assert node.state == NodeState.RX_WAIT

    def test_process_next_event_returns_event(self) -> None:
        """process_next_event returns the processed event."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        event = sim.process_next_event()

        assert isinstance(event, RxTimeoutEvent)
        assert event.node_id == "node1"

    def test_process_next_event_empty_queue_returns_none(self) -> None:
        """process_next_event returns None for empty queue."""
        sim = Simulation(sim_id="test-sim")

        result = sim.process_next_event()

        assert result is None

    def test_process_next_event_updates_time(self) -> None:
        """process_next_event updates current_time_us to event time."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        sim.process_next_event()

        assert sim.current_time_us == 100 * 1000  # 100ms in microseconds


class TestBarrierSync:
    """Test BARRIER_SYNC time advancement mode."""

    def test_maybe_advance_time_all_blocked(self) -> None:
        """maybe_advance_time advances when all nodes are in RX_WAIT."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Put both nodes in RX_WAIT
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=200)

        # Both nodes are blocked, should advance to first timeout
        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is True
        assert sim.current_time_us > initial_time

    def test_maybe_advance_time_idle_node_does_not_block(self) -> None:
        """An idle node must not hold the barrier (regression: fgk deadlock).

        When a receiver is waiting, time advances even if other nodes are idle;
        otherwise a node that transmitted then went idle would freeze the clock
        and the receiver's timeout could never fire.
        """
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)  # stays IDLE

        sim.start_receive("node1", timeout_ms=100)

        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is True
        assert sim.current_time_us > initial_time

    def test_maybe_advance_time_no_receiver_waiting(self) -> None:
        """No advance when nothing is waiting on the clock, even with events."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        # A transmission schedules a TxEnd event, but no node is in RX_WAIT.
        sim.start_transmission("node1", b"hello")

        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is False
        assert sim.current_time_us == initial_time

    def test_maybe_advance_time_no_events(self) -> None:
        """maybe_advance_time returns False when no events pending."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node1.state = NodeState.RX_WAIT

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_maybe_advance_time_no_nodes(self) -> None:
        """maybe_advance_time returns False when no connected nodes."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_maybe_advance_time_realtime_mode(self) -> None:
        """maybe_advance_time returns False in REALTIME mode."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.REALTIME)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_barrier_sync_excludes_disconnected_nodes(self) -> None:
        """Barrier sync ignores disconnected nodes."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 100.0, 0.0, 0.0)

        # Put node1 in RX_WAIT, disconnect node2
        sim.start_receive("node1", timeout_ms=100)
        node2.disconnect()

        # Only connected node is blocked, should advance
        advanced = sim.maybe_advance_time()

        assert advanced is True


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


class TestTransmissionReceiveFlow:
    """Test complete transmission/receive flow."""

    def test_tx_rx_flow_with_barrier_sync(self) -> None:
        """Test complete TX/RX flow using barrier sync.

        Time advances to the next event while any node is waiting to receive;
        an idle node (e.g. one whose timeout already fired) does not block a
        still-waiting receiver. Once no node is waiting, the clock stops.
        """
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 100.0, 0.0, 0.0)

        # Both nodes start listening with different timeouts
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=200)
        assert node1.state == NodeState.RX_WAIT
        assert node2.state == NodeState.RX_WAIT

        # First advance processes node1's earlier timeout.
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 100 * 1000
        assert node1.state == NodeState.IDLE

        # node2 is still waiting, so the clock advances to its timeout even
        # though node1 is now idle.
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 200 * 1000
        assert node2.state == NodeState.IDLE

        # Nothing is waiting now, so the clock stops.
        advanced = sim.maybe_advance_time()
        assert advanced is False

    def test_multiple_transmitters_collision(self) -> None:
        """Test collision when two nodes transmit simultaneously."""
        sim = Simulation(sim_id="test-sim")

        # Three nodes in a line, equidistant
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)

        # Both transmit at same time, same power, same distance to RX
        sim.start_transmission("tx1", b"packet1")
        sim.start_transmission("tx2", b"packet2")

        # Check during transmission
        sim.advance_to(1000)

        result = sim.get_rx_result("rx")

        # Should be collision (equal power, both lost)
        assert result is None

    def test_capture_effect_stronger_wins(self) -> None:
        """Test capture effect where stronger signal wins."""
        sim = Simulation(sim_id="test-sim")

        # TX1 close, TX2 far (10x distance = 26.6dB difference with n=2.7)
        sim.add_node("tx1", 50.0, 0.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 500.0, 0.0, 0.0)

        payload1 = b"strong signal"
        payload2 = b"weak signal"

        sim.start_transmission("tx1", payload1)
        sim.start_transmission("tx2", payload2)

        # Check during transmission
        sim.advance_to(1000)

        result = sim.get_rx_result("rx")

        # Strong signal should win via capture effect
        assert result is not None
        rx_payload, rssi, snr = result
        assert rx_payload == payload1


class TestEventOrdering:
    """Test event ordering and processing."""

    def test_events_processed_in_time_order(self) -> None:
        """Events are processed in time order."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Create events in reverse order
        sim.start_receive("node1", timeout_ms=200)
        sim.start_receive("node2", timeout_ms=100)

        # First event should be node2's timeout (earlier)
        event1 = sim.process_next_event()
        assert isinstance(event1, RxTimeoutEvent)
        assert event1.node_id == "node2"

        event2 = sim.process_next_event()
        assert isinstance(event2, RxTimeoutEvent)
        assert event2.node_id == "node1"

    def test_same_time_events_fifo(self) -> None:
        """Events at same time are processed FIFO."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Same timeout for both
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=100)

        # First queued should be first processed
        event1 = sim.process_next_event()
        assert event1.node_id == "node1"

        event2 = sim.process_next_event()
        assert event2.node_id == "node2"


class TestChaosEngineIntegration:
    """Tests that chaos rules actually affect simulation results."""

    def test_drop_rule_blocks_reception(self) -> None:
        """DropRule prevents node from receiving packets."""
        from lichen.sim.chaos import ChaosEngine, DropRule

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="receiver", direction="rx"))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        # Sender transmits
        sim.start_transmission("sender", b"hello")
        # Advance time into the transmission (not past it)
        sim.advance_to(1000)

        # Receiver should NOT get the packet due to drop rule
        result = sim.get_rx_result("receiver")
        assert result is None

    def test_drop_rule_blocks_transmission(self) -> None:
        """DropRule on sender prevents receiver from getting packet."""
        from lichen.sim.chaos import ChaosEngine, DropRule

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="sender", direction="tx"))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is None

    def test_no_chaos_engine_allows_reception(self) -> None:
        """Without chaos engine, reception works normally."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is not None
        assert result[0] == b"hello"

    def test_partition_rule_blocks_cross_partition(self) -> None:
        """PartitionRule blocks communication between partitions."""
        from lichen.sim.chaos import ChaosEngine, PartitionRule

        chaos = ChaosEngine()
        chaos.add_rule(PartitionRule(groups=[{"node-a"}, {"node-b"}]))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("node-a", 0.0, 0.0, 0.0)
        sim.add_node("node-b", 100.0, 0.0, 0.0)

        sim.start_transmission("node-a", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("node-b")
        assert result is None

    def test_degrade_rule_reduces_rssi(self) -> None:
        """DegradeRule reduces received signal strength."""
        from lichen.sim.chaos import ChaosEngine, DegradeRule

        # First get baseline RSSI without degradation
        sim_baseline = Simulation(sim_id="baseline")
        sim_baseline.add_node("sender", 0.0, 0.0, 0.0)
        sim_baseline.add_node("receiver", 100.0, 0.0, 0.0)
        sim_baseline.start_transmission("sender", b"test")
        sim_baseline.advance_to(1000)
        baseline_result = sim_baseline.get_rx_result("receiver")
        assert baseline_result is not None
        baseline_rssi = baseline_result[1]

        # Now with degradation
        chaos = ChaosEngine()
        chaos.add_rule(DegradeRule(node_id="receiver", rssi_penalty_db=20.0))

        sim_degraded = Simulation(sim_id="degraded", chaos_engine=chaos)
        sim_degraded.add_node("sender", 0.0, 0.0, 0.0)
        sim_degraded.add_node("receiver", 100.0, 0.0, 0.0)
        sim_degraded.start_transmission("sender", b"test")
        sim_degraded.advance_to(1000)
        degraded_result = sim_degraded.get_rx_result("receiver")
        assert degraded_result is not None
        degraded_rssi = degraded_result[1]

        # Degraded RSSI should be ~20 dB lower
        assert baseline_rssi - degraded_rssi >= 19  # Allow 1 dB tolerance

    def test_jammer_blocks_nearby_receivers(self) -> None:
        """JammerRule blocks reception for nodes within radius."""
        from lichen.sim.chaos import ChaosEngine, JammerRule

        chaos = ChaosEngine()
        # Jammer at (50, 0, 0) with 100m radius - receiver at (100, 0, 0) is 50m away
        chaos.add_rule(JammerRule(x=50.0, y=0.0, z=0.0, radius_m=100.0))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is None

    def test_chaos_engine_setter(self) -> None:
        """Chaos engine can be set after construction."""
        from lichen.sim.chaos import ChaosEngine, DropRule

        sim = Simulation(sim_id="test-sim")
        assert sim.chaos_engine is None

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="node", direction="both"))
        sim.chaos_engine = chaos

        assert sim.chaos_engine is chaos
