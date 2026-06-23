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

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.node import Node, NodeConfig, NodeState


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
        with pytest.raises(RuntimeError, match="cannot start"):
            await node.start()
        await node.stop()

    @pytest.mark.asyncio
    async def test_stop_idempotent(self, node: Node):
        """stop() is safe to call on stopped node."""
        await node.stop()  # Should not raise
        assert node.state == NodeState.STOPPED


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


class TestCallback:
    """Tests for receive callback."""

    def test_set_callback(self, node: Node):
        """set_on_receive sets the callback."""
        received = []
        node.set_on_receive(lambda data, sender: received.append((data, sender)))

        assert node._on_receive is not None
