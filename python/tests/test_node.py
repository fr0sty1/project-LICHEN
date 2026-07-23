# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LICHEN Node class integration.

Why these tests: The Node is the main entry point. Bugs here mean:
- Node won't start/stop properly (lifecycle failure)
- Announces not sent/received (routing failure)
- Peers not discovered (mesh formation failure)
- Application data not delivered (communication failure)

Test categories:
1. Lifecycle (start/stop)
2. Peer management
3. Announce sending/receiving
4. Application data flow
"""

import asyncio
import contextlib
from typing import Any, cast

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.l2_payload import L2_DISPATCH_ROUTING
from lichen.node import Node, NodeConfig, NodeState
from lichen.state_machine import StateError


class MockRadio:
    """Mock radio for testing Node without real radio or simulator.

    Why mock: Tests should be fast and deterministic. Mock controls
    exactly what frames are received and captures what's transmitted.
    """

    def __init__(self):
        self.tx_history: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []
        self._rx_event = asyncio.Event()

    async def transmit(self, payload: bytes) -> bool:
        """Record transmitted frame."""
        self.tx_history.append(payload)
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Return next queued frame or None after timeout."""
        if self.rx_queue:
            return self.rx_queue.pop(0)

        # Wait briefly to simulate timeout
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                self._rx_event.wait(),
                timeout=timeout_ms / 1000,
            )

        if self.rx_queue:
            self._rx_event.clear()
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """No-op for mock."""
        pass

    async def cad(self, timeout_ms: int) -> bool:
        """Mock CAD always reports a clear channel."""
        return False

    def queue_rx(self, data: bytes, rssi: int = -50, snr: int = 10) -> None:
        """Queue a frame for reception."""
        self.rx_queue.append((data, rssi, snr))
        self._rx_event.set()


@pytest.fixture
def identity() -> Identity:
    """Test node identity."""
    return Identity.from_seed(bytes(32))


@pytest.fixture
def peer_identity() -> Identity:
    """Test peer identity."""
    return Identity.from_seed(bytes([1] + [0] * 31))


@pytest.fixture
def radio() -> MockRadio:
    """Mock radio for testing."""
    return MockRadio()


@pytest.fixture
def node(identity: Identity, radio: MockRadio) -> Node:
    """Create a test node."""
    return Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            receive_timeout_ms=100,  # Short timeout for tests
            announce_interval_ms=10000,  # 10 seconds for tests
            announce_jitter_ms=0,  # No jitter for determinism
        ),
    )


class TestNodeLifecycle:
    """Tests for Node start/stop lifecycle."""

    def test_initial_state_is_stopped(self, node: Node):
        """Node starts in STOPPED state."""
        assert node.state == NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_start_sets_running(self, node: Node):
        """start() transitions to RUNNING state."""
        await node.start()
        assert node.state == NodeState.RUNNING
        await node.stop()

    @pytest.mark.asyncio
    async def test_stop_sets_stopped(self, node: Node):
        """stop() transitions to STOPPED state."""
        await node.start()
        await node.stop()
        assert node.state == NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_start_twice_raises(self, node: Node):
        """Cannot start() an already running node."""
        await node.start()
        with pytest.raises(StateError, match="expected STOPPED"):
            await node.start()
        await node.stop()

    @pytest.mark.asyncio
    async def test_stop_idempotent(self, node: Node):
        """stop() is safe to call on stopped node."""
        await node.stop()  # Should not raise
        assert node.state == NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_start_scheduler_failure_rolls_back_receive_task(self, node: Node):
        primary = RuntimeError("scheduler start failed")

        class Scheduler:
            stop_calls = 0

            async def start(self) -> None:
                raise primary

            async def stop(self) -> None:
                self.stop_calls += 1

        scheduler = Scheduler()
        node._scheduler = cast(Any, scheduler)

        with pytest.raises(RuntimeError) as raised:
            await node.start()

        assert raised.value is primary
        assert scheduler.stop_calls == 1
        assert node._receive_task is None
        assert node.state is NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_start_adapter_failure_preserves_primary_and_stops_all(self, node: Node):
        primary = RuntimeError("adapter start failed")

        class Stage:
            def __init__(self, start_error: BaseException | None = None) -> None:
                self.start_error = start_error
                self.stop_calls = 0

            async def start(self) -> None:
                if self.start_error is not None:
                    raise self.start_error

            async def stop(self) -> None:
                self.stop_calls += 1
                raise RuntimeError("cleanup failed")

        scheduler = Stage()
        adapter = Stage(primary)
        node._scheduler = cast(Any, scheduler)
        node._meshtastic_adapter = cast(Any, adapter)

        with pytest.raises(RuntimeError) as raised:
            await node.start()

        assert raised.value is primary
        assert scheduler.stop_calls == 1
        assert adapter.stop_calls == 1
        assert node._receive_task is None
        assert node.state is NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_receive_task_start_failure_rolls_back_without_leak(self, node: Node):
        primary = RuntimeError("receive task failed")

        async def fail_receive() -> None:
            raise primary

        node._receive_loop = fail_receive  # type: ignore[method-assign]
        with pytest.raises(RuntimeError) as raised:
            await node.start()

        assert raised.value is primary
        assert node._receive_task is None
        assert node.state is NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_stop_attempts_all_cleanup_and_is_retry_safe(self, node: Node):
        class Stage:
            def __init__(self, error: BaseException) -> None:
                self.error = error
                self.stop_calls = 0

            async def start(self) -> None:
                pass

            async def stop(self) -> None:
                self.stop_calls += 1
                raise self.error

        adapter_error = RuntimeError("adapter stop failed")
        scheduler = Stage(RuntimeError("scheduler stop failed"))
        adapter = Stage(adapter_error)
        node._scheduler = cast(Any, scheduler)
        node._meshtastic_adapter = cast(Any, adapter)
        await node.start()

        with pytest.raises(RuntimeError) as raised:
            await node.stop()
        await node.stop()

        assert raised.value is adapter_error
        assert adapter.stop_calls == 1
        assert scheduler.stop_calls == 1
        assert node._receive_task is None
        assert node.state is NodeState.STOPPED

    @pytest.mark.asyncio
    async def test_concurrent_start_stop_are_serialized(self, node: Node):
        entered = asyncio.Event()
        release = asyncio.Event()

        class Scheduler:
            async def start(self) -> None:
                entered.set()
                await release.wait()

            async def stop(self) -> None:
                pass

        node._scheduler = cast(Any, Scheduler())
        start = asyncio.create_task(node.start())
        await entered.wait()
        stop = asyncio.create_task(node.stop())
        await asyncio.sleep(0)
        assert not stop.done()
        release.set()
        await asyncio.gather(start, stop)
        assert node.state is NodeState.STOPPED


class TestPeerManagement:
    """Tests for peer database management."""

    def test_add_peer(self, node: Node, peer_identity: Identity):
        """add_peer adds peer to database."""
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)

        assert peer.iid in node.peer_db
        assert node.peer_db[peer.iid] == peer

    def test_remove_peer(self, node: Node, peer_identity: Identity):
        """remove_peer removes peer from database."""
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)
        node.remove_peer(peer.iid)

        assert peer.iid not in node.peer_db

    def test_remove_nonexistent_peer_ok(self, node: Node):
        """remove_peer is safe for nonexistent IID."""
        node.remove_peer(bytes(8))  # Should not raise


class TestAnnouncing:
    """Tests for announce message handling."""

    @pytest.mark.asyncio
    async def test_send_announce(self, node: Node, radio: MockRadio):
        """Node can send an announce."""
        await node._send_announce()

        assert len(radio.tx_history) == 1
        # Frame should be parseable
        from lichen.link.frame import LichenFrame
        frame = LichenFrame.from_bytes(radio.tx_history[0])
        assert frame.signature_present is True
        assert frame.payload[0] == L2_DISPATCH_ROUTING

    @pytest.mark.asyncio
    async def test_transmit_announce_wraps_routing_payload(
        self, node: Node, radio: MockRadio
    ):
        """Scheduler announce sends use the authenticated routing namespace."""
        await node.transmit_announce(b"\x01announce")

        from lichen.link.frame import LichenFrame

        frame = LichenFrame.from_bytes(radio.tx_history[0])
        assert frame.payload.startswith(b"\x15\x01announce")

    @pytest.mark.asyncio
    async def test_announce_increments_seq(self, node: Node, radio: MockRadio):
        """Each announce increments seq_num."""
        await node._send_announce()
        await node._send_announce()

        assert node._announce_seq == 2

    # ponytail: Complex async receive test deferred to integration tests.
    # Full end-to-end announce receive requires careful async coordination
    # that's better tested with the simulator.


class TestStatus:
    """Tests for node status reporting."""

    def test_get_status(self, node: Node):
        """get_status returns expected fields."""
        status = node.get_status()

        assert "iid" in status
        assert "state" in status
        assert "peers" in status
        assert "gradients" in status
        assert status["state"] == "STOPPED"
        assert status["peers"] == 0

    def test_status_reflects_peers(self, node: Node, peer_identity: Identity):
        """Status peer count updates when peers added."""
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)

        status = node.get_status()
        assert status["peers"] == 1

    def test_get_queue_stats(self, node: Node):
        """get_queue_stats returns expected fields per bufferbloat spec."""
        stats = node.get_queue_stats()

        # Fields from spec/appendix-bufferbloat.md lines 138-152
        assert "packets_queued" in stats
        assert "packets_dropped_deadline" in stats
        assert "packets_dropped_full" in stats
        assert "max_latency_ms" in stats
        assert "avg_latency_ms" in stats

        # All values should be integers
        for key, value in stats.items():
            assert isinstance(value, int), f"{key} should be int, got {type(value)}"

        # Initial values should be zero
        assert stats["packets_queued"] == 0
        assert stats["max_latency_ms"] == 0
        assert stats["avg_latency_ms"] == 0


class TestCallback:
    """Tests for receive callback."""

    def test_set_callback(self, node: Node):
        """set_on_receive sets the callback."""
        received = []
        node.set_on_receive(lambda data, sender: received.append((data, sender)))

        assert node._on_receive is not None

    def test_owner_registration_is_conditional(self, node: Node):
        first_owner = object()
        second_owner = object()

        def callback(_data, _sender):
            pass

        node.register_on_receive(first_owner, callback)

        with pytest.raises(RuntimeError, match="already has an owner"):
            node.register_on_receive(second_owner, callback)
        with pytest.raises(RuntimeError, match="already has an owner"):
            node.set_on_receive(callback)
        assert not node.unregister_on_receive(second_owner)
        assert node._on_receive is callback
        assert node.unregister_on_receive(first_owner)
        assert node._on_receive is None

    def test_none_owner_is_rejected_before_mutation(self, node: Node):
        callback_calls = []

        def callback(data, sender):
            callback_calls.append((data, sender))

        with pytest.raises(ValueError, match="must not be None"):
            node.register_on_receive(None, callback)
        assert node._on_receive is None
        assert node._on_receive_owner is None

        owner = object()
        node.register_on_receive(owner, callback)
        with pytest.raises(ValueError, match="must not be None"):
            node.unregister_on_receive(None)
        assert node._on_receive is callback
        assert node._on_receive_owner is owner
        assert callback_calls == []


def test_set_config_validates_all_values_before_mutation(node: Node) -> None:
    node.set_config({"receive_timeout_ms": "250", "announce_interval_ms": "500"})
    assert node.get_config() == {
        "receive_timeout_ms": 250,
        "announce_interval_ms": 500,
    }

    with pytest.raises(ValueError):
        node.set_config({
            "receive_timeout_ms": "300",
            "announce_interval_ms": "invalid",
        })

    assert node.get_config() == {
        "receive_timeout_ms": 250,
        "announce_interval_ms": 500,
    }


def test_set_config_rejects_unknown_fields_before_mutation(node: Node) -> None:
    before = node.get_config()
    with pytest.raises(ValueError, match="unknown config keys"):
        node.set_config({"receive_timeout_ms": 300, "unknown": 1})
    assert node.get_config() == before
