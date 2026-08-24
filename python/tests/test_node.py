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
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import Any, cast

import pytest

from lichen.announce.messages import MAX_ANNOUNCE_APP_DATA, AnnounceError, AnnounceMessage
from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.crypto.schnorr48 import sign
from lichen.gradient import (
    DATA_GRADIENT_TIMEOUT_MS,
    GradientEntry,
    GradientSource,
)
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.l2_payload import L2_DISPATCH_ROUTING, l2_payload_body, wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, AddrMode, LichenFrame
from lichen.link.link_layer import (
    MAX_SINGLE_FRAME_SCHC_PACKET,
    LinkPersistenceError,
    LinkSecurityClockError,
    ReceiveError,
    RxFrame,
)
from lichen.link.tx_queue import Priority
from lichen.node import (
    _NATIVE_MESH_PREFIX,
    PEER_DB_MAX_SIZE,
    RECEIVE_TIMEOUT_MAX_MS,
    RELAY_SEEN_WINDOW_MS,
    Node,
    NodeConfig,
    NodeState,
    PeerDatabaseFullError,
    PeerIdentityCollisionError,
    PeerInUseError,
    _OutboundFragmentSession,
)
from lichen.routing.router import AddressClass, RouteDecision
from lichen.rpl.dodag import DodagRole
from lichen.rpl.messages import DIO, RPL_ICMPV6_TYPE, RplCode
from lichen.schc.fragment import (
    MAX_ACK_REQUESTS,
    TILE_SIZE,
    Fragment,
    FragmentError,
    ack_request,
    fragmentation_rule_for_sender,
    receiver_abort,
    sender_abort,
)
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.reassembly import ReceiverResult
from lichen.state_machine import StateError


def test_native_mesh_prefix_is_exactly_0200_slash_8() -> None:
    assert str(_NATIVE_MESH_PREFIX) == "200::/8"
    assert IPv6Address("0200::1") in _NATIVE_MESH_PREFIX
    assert IPv6Address("0300::1") not in _NATIVE_MESH_PREFIX


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

    @pytest.mark.asyncio
    async def test_terminal_receive_failure_supervises_running_services(self, node: Node):
        entered = asyncio.Event()
        fail = asyncio.Event()
        terminal = LinkPersistenceError("terminal after running")

        async def receive(_timeout_ms: int) -> None:
            entered.set()
            await fail.wait()
            raise terminal

        node.link.receive = receive  # type: ignore[method-assign]
        await node.start()
        await entered.wait()
        assert node.state is NodeState.RUNNING
        assert node._scheduler.is_running

        fail.set()
        for _ in range(100):
            if node.state is NodeState.STOPPED:
                break
            await asyncio.sleep(0.001)

        assert node.state is NodeState.STOPPED
        assert node._scheduler.is_running is False
        assert node._receive_task is None
        assert node.terminal_error is terminal


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
        assert node.remove_peer(peer.iid)

        assert peer.iid not in node.peer_db

    def test_remove_nonexistent_peer_ok(self, node: Node):
        """remove_peer is safe for nonexistent IID."""
        assert node.remove_peer(bytes(8)) is False

    def test_peer_database_view_rejects_direct_mutation(
        self, node: Node, peer_identity: Identity
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        with pytest.raises(TypeError):
            node.peer_db[peer.iid] = peer  # type: ignore[index]
        with pytest.raises(AttributeError, match="read-only"):
            node.peer_db = {peer.iid: peer}
        assert peer.iid not in node.peer_db

    def test_remove_peer_refuses_link_pin(self, node: Node, peer_identity: Identity) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)
        node.link._pinned_keys[peer.iid] = peer.pubkey

        with pytest.raises(PeerInUseError, match="live protocol state"):
            node.remove_peer(peer.iid)
        assert peer.iid in node.peer_db

    def test_remove_peer_refuses_live_route(self, node: Node, peer_identity: Identity) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)
        node.gradient_table.update(
            GradientEntry(
                destination=yggdrasil_address(peer.pubkey),
                next_hop=IPv6Address(IPv6Address("fe80::").packed[:8] + peer.iid),
                hop_count=1,
                seq_num=1,
                source=GradientSource.DATA,
                expires=2**63,
            ),
            now=0,
        )

        with pytest.raises(PeerInUseError, match="live protocol state"):
            node.remove_peer(peer.iid)

    def test_remove_peer_refuses_active_fragment(self, node: Node, peer_identity: Identity) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(peer)
        node._fragment_sessions[peer.pubkey] = cast(Any, object())

        with pytest.raises(PeerInUseError, match="live protocol state"):
            node.remove_peer(peer.iid)

    def test_add_peer_rejects_iid_not_derived_from_public_key(
        self, node: Node, peer_identity: Identity
    ) -> None:
        noncanonical = PeerIdentity(pubkey=peer_identity.pubkey, iid=bytes(8))

        with pytest.raises(ValueError, match="IID does not match"):
            node.add_peer(noncanonical)

        assert node.peer_db == {}

    def test_constructor_rejects_noncanonical_peer_database(
        self,
        identity: Identity,
        peer_identity: Identity,
        radio: MockRadio,
    ) -> None:
        canonical = PeerIdentity.from_pubkey(peer_identity.pubkey)
        with pytest.raises(ValueError, match="database key"):
            Node(identity=identity, radio=radio, peer_db={bytes(8): canonical})

        noncanonical = PeerIdentity(pubkey=peer_identity.pubkey, iid=bytes(8))
        with pytest.raises(ValueError, match="IID does not match"):
            Node(identity=identity, radio=radio, peer_db={bytes(8): noncanonical})

    def test_constructor_rejects_peer_database_over_link_trust_capacity(
        self,
        identity: Identity,
        radio: MockRadio,
    ) -> None:
        peers = [
            PeerIdentity.from_pubkey(Identity.from_seed(index.to_bytes(32, "big")).pubkey)
            for index in range(1, PEER_DB_MAX_SIZE + 2)
        ]
        oversized = {peer.iid: peer for peer in peers}

        with pytest.raises(ValueError, match="cannot exceed"):
            Node(identity=identity, radio=cast(Any, radio), peer_db=oversized)

    def test_peer_database_evicts_oldest_peer_without_live_state(self, node: Node) -> None:
        peers = [
            PeerIdentity.from_pubkey(Identity.from_seed(index.to_bytes(32, "big")).pubkey)
            for index in range(1, PEER_DB_MAX_SIZE + 2)
        ]
        for peer in peers[:PEER_DB_MAX_SIZE]:
            node.add_peer(peer)

        node.add_peer(peers[-1])

        assert len(node.peer_db) == PEER_DB_MAX_SIZE
        assert peers[0].iid not in node.peer_db
        assert peers[-1].iid in node.peer_db

    def test_peer_database_fails_closed_when_every_peer_is_security_live(self, node: Node) -> None:
        peers = [
            PeerIdentity.from_pubkey(Identity.from_seed(index.to_bytes(32, "big")).pubkey)
            for index in range(1, PEER_DB_MAX_SIZE + 2)
        ]
        for peer in peers[:PEER_DB_MAX_SIZE]:
            node.add_peer(peer)
            node.link._pinned_keys[peer.iid] = peer.pubkey

        with pytest.raises(PeerDatabaseFullError, match="protected entries"):
            node.add_peer(peers[-1])

        assert len(node.peer_db) == PEER_DB_MAX_SIZE
        assert peers[0].iid in node.peer_db
        assert peers[-1].iid not in node.peer_db

    @pytest.mark.parametrize("pinned", [False, True])
    def test_add_peer_preserves_incumbent_on_controlled_iid_collision(
        self,
        node: Node,
        monkeypatch: pytest.MonkeyPatch,
        pinned: bool,
    ) -> None:
        collision_iid = b"collisio"
        incumbent = PeerIdentity(pubkey=bytes([0x11]) * 32, iid=collision_iid)
        candidate = PeerIdentity(pubkey=bytes([0x22]) * 32, iid=collision_iid)
        monkeypatch.setattr("lichen.node._canonical_peer", lambda peer: peer)
        node.add_peer(incumbent)
        if pinned:
            node.link._pinned_keys[collision_iid] = incumbent.pubkey

        with pytest.raises(PeerIdentityCollisionError, match="IID collision"):
            node.add_peer(candidate)

        assert node.peer_db[collision_iid] is incumbent
        if pinned:
            assert node.link._pinned_keys[collision_iid] == incumbent.pubkey


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
    async def test_transmit_announce_wraps_routing_payload(self, node: Node, radio: MockRadio):
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

    @pytest.mark.asyncio
    async def test_announce_application_data_boundary_fits_dispatched_link_frame(
        self, node: Node, radio: MockRadio
    ) -> None:
        node._scheduler.app_data = bytes(MAX_ANNOUNCE_APP_DATA)
        await node._send_announce()
        frame = LichenFrame.from_bytes(radio.tx_history[-1])
        assert len(frame.payload) == 1 + 93 + MAX_ANNOUNCE_APP_DATA

        node._scheduler.app_data = bytes(MAX_ANNOUNCE_APP_DATA + 1)
        with pytest.raises(AnnounceError, match="link profile limit"):
            await node._send_announce()

    @pytest.mark.asyncio
    async def test_authenticated_relayed_announce_flood_keeps_peer_database_bounded(
        self,
        node: Node,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        relay_sender = PeerIdentity.from_pubkey(Identity.from_seed(bytes([0xFE]) * 32).pubkey)

        async def no_relay(_announce: AnnounceMessage) -> None:
            return None

        monkeypatch.setattr(node, "_relay_announce", no_relay)
        for index in range(1, PEER_DB_MAX_SIZE + 2):
            origin = Identity.from_seed(index.to_bytes(32, "big"))
            unsigned = AnnounceMessage(
                originator_iid=origin.iid,
                pubkey=origin.pubkey,
                seq_num=1,
            )
            announce = AnnounceMessage(
                originator_iid=origin.iid,
                pubkey=origin.pubkey,
                seq_num=1,
                signature=sign(origin.privkey, origin.pubkey, unsigned.signed_data()),
            )
            await node._process_announce(announce.to_bytes(), relay_sender, -80)

        assert len(node.peer_db) == PEER_DB_MAX_SIZE
        peer_lookup_all = node.link.peer_lookup_all
        assert peer_lookup_all is not None
        assert len(peer_lookup_all()) == PEER_DB_MAX_SIZE

    @pytest.mark.asyncio
    async def test_rx_channel_binds_to_origin_and_expires(
        self, node: Node, peer_identity: Identity, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        origin_node = Node(identity=peer_identity, radio=cast(Any, MockRadio()))
        announce = origin_node._scheduler.build_announce()
        relay = PeerIdentity.from_pubkey(Identity.from_seed(bytes([9]) * 32).pubkey)

        async def no_relay(_announce: AnnounceMessage) -> None:
            return None

        monkeypatch.setattr(node, "_relay_announce", no_relay)
        await node._process_announce(announce.with_incremented_hop_count().to_bytes(), relay, -80)

        assert relay.iid not in node._peer_rx_channel
        binding = node._peer_rx_channel[peer_identity.iid]
        assert binding.channel == announce.rx_channel
        node._purge_expired_peer_rx_channels(binding.expires_ms - 1)
        assert peer_identity.iid in node._peer_rx_channel
        node._purge_expired_peer_rx_channels(binding.expires_ms)
        assert peer_identity.iid not in node._peer_rx_channel

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
    node.set_config({"receive_timeout_ms": 250, "announce_interval_ms": 500})
    assert node.get_config() == {
        "receive_timeout_ms": 250,
        "announce_interval_ms": 500,
    }

    with pytest.raises(ValueError):
        node.set_config(
            {
                "receive_timeout_ms": 300,
                "announce_interval_ms": "500",
            }
        )

    assert node.get_config() == {
        "receive_timeout_ms": 250,
        "announce_interval_ms": 500,
    }


def test_set_config_rejects_unknown_fields_before_mutation(node: Node) -> None:
    before = node.get_config()
    with pytest.raises(ValueError, match="unknown config keys"):
        node.set_config({"receive_timeout_ms": 300, "unknown": 1})
    assert node.get_config() == before


def test_set_config_rejects_negative_float_between_minus_one_and_zero(node: Node) -> None:
    """Negative floats must not be coerced into a receive timeout or interval."""
    before = node.get_config()
    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"receive_timeout_ms": -0.5})
    assert node.get_config() == before

    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"announce_interval_ms": -0.5})
    assert node.get_config() == before


def test_set_config_rejects_zero(node: Node) -> None:
    """Zero values must be rejected as timeouts/intervals must be positive."""
    before = node.get_config()
    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"receive_timeout_ms": 0})
    assert node.get_config() == before

    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"announce_interval_ms": 0})
    assert node.get_config() == before


def test_set_config_rejects_negative_integers(node: Node) -> None:
    """Negative integers must be rejected."""
    before = node.get_config()
    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"receive_timeout_ms": -1})
    assert node.get_config() == before

    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"announce_interval_ms": -100})
    assert node.get_config() == before


@pytest.mark.parametrize(
    "timeout",
    [False, True, 0, -1, RECEIVE_TIMEOUT_MAX_MS + 1, 1.0, "1"],
)
def test_constructor_rejects_non_exact_or_progress_defeating_receive_timeout(
    identity: Identity,
    radio: MockRadio,
    timeout: object,
) -> None:
    with pytest.raises(ValueError, match="integer in"):
        Node(
            identity=identity,
            radio=cast(Any, radio),
            config=NodeConfig(receive_timeout_ms=cast(Any, timeout)),
        )


@pytest.mark.parametrize("timeout", [False, True, 1.0, "1", RECEIVE_TIMEOUT_MAX_MS + 1])
def test_set_config_rejects_coercive_or_excessive_receive_timeout_atomically(
    node: Node,
    timeout: object,
) -> None:
    before = node.get_config()
    with pytest.raises(ValueError, match="integer in"):
        node.set_config(
            {
                "receive_timeout_ms": timeout,
                "announce_interval_ms": 123,
            }
        )
    assert node.get_config() == before


@pytest.mark.parametrize("interval", [False, True, 1.0, "1", 86_400_001])
def test_set_config_rejects_coercive_or_excessive_announce_interval_atomically(
    node: Node, interval: object
) -> None:
    before = node.get_config()
    scheduler_before = node._scheduler.config.interval_ms
    with pytest.raises(ValueError, match="integer in"):
        node.set_config({"receive_timeout_ms": 250, "announce_interval_ms": interval})
    assert node.get_config() == before
    assert node._scheduler.config.interval_ms == scheduler_before


def test_set_config_propagates_announce_interval_to_scheduler(node: Node) -> None:
    node.set_config({"announce_interval_ms": 1234})
    assert node.config.announce_interval_ms == 1234
    assert node._scheduler.config.interval_ms == 1234


def test_receive_timeout_update_does_not_restart_announce_schedule(node: Node) -> None:
    revision = node._scheduler._config_revision
    node.set_config({"receive_timeout_ms": 250})
    assert node._scheduler._config_revision == revision


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("announce_interval_ms", True),
        ("announce_jitter_ms", 1.5),
        ("pending_timeout_ms", "1"),
        ("rreq_jitter_min_ms", -1),
        ("rreq_jitter_max_ms", 86_400_001),
    ],
)
def test_constructor_rejects_invalid_timing_config(
    identity: Identity, radio: MockRadio, field: str, value: object
) -> None:
    with pytest.raises(ValueError, match=f"{field} must be an integer"):
        Node(
            identity=identity,
            radio=cast(Any, radio),
            config=NodeConfig(**{field: value}),  # type: ignore[arg-type]
        )


def test_constructor_rejects_inverted_rreq_jitter(identity: Identity, radio: MockRadio) -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        Node(
            identity=identity,
            radio=cast(Any, radio),
            config=NodeConfig(rreq_jitter_min_ms=20, rreq_jitter_max_ms=10),
        )


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [(True, 1), (0.5, 1), ("0", 1), (-1, 1), (0, 86_400_001), (2, 1)],
)
def test_scheduled_send_rejects_invalid_jitter_before_task_creation(
    node: Node, minimum: object, maximum: object
) -> None:
    with pytest.raises(ValueError):
        node.scheduled_send(
            b"rreq",
            min_delay_ms=minimum,  # type: ignore[arg-type]
            max_delay_ms=maximum,  # type: ignore[arg-type]
        )


def _verified_rx(payload: bytes, peer: PeerIdentity) -> RxFrame:
    value = object.__new__(RxFrame)
    object.__setattr__(value, "sender", peer)
    object.__setattr__(value, "rssi_dbm", -90)
    object.__setattr__(value, "snr_db", 4)
    object.__setattr__(value, "_authenticated_payload", payload)
    object.__setattr__(value, "_authenticated_sender_pubkey", peer.pubkey)
    return value


def _signed_link_wire(
    remote: Identity,
    payload: bytes,
    counter: int,
) -> bytes:
    """Build an independent signed broadcast frame for Node ingress tests."""
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    signer_eui64 = iid_to_eui64(remote.iid)
    llsec = 0xA0
    length = 4 + len(signer_eui64) + len(payload) + 48
    transcript = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, llsec, epoch))
        + seqnum.to_bytes(2, "big")
        + b"\x00"
        + signer_eui64
        + payload
    )
    signature = sign(remote.privkey, remote.pubkey, transcript)
    return LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=signature,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


def _signed_extended_link_wire(
    remote: Identity,
    payload: bytes,
    counter: int,
    destination: bytes,
) -> bytes:
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    signer_eui64 = iid_to_eui64(remote.iid)
    llsec = 0xA0 | int(AddrMode.EXTENDED)
    length = 4 + len(destination) + len(signer_eui64) + len(payload) + 48
    transcript = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, llsec, epoch))
        + seqnum.to_bytes(2, "big")
        + bytes((len(destination),))
        + destination
        + signer_eui64
        + payload
    )
    return LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=destination,
        addr_mode=AddrMode.EXTENDED,
        payload=payload,
        mic=sign(remote.privkey, remote.pubkey, transcript),
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


def _dio_schc_payload(remote: Identity, dodag_id: IPv6Address) -> bytes:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=512,
        dtsn=1,
        dodag_id=dodag_id,
        mode_of_operation=1,
    )
    source = IPv6Address(IPv6Address("fe80::").packed[:8] + remote.iid)
    destination = IPv6Address("ff02::1a")
    icmp = Icmpv6Message(
        RPL_ICMPV6_TYPE,
        int(RplCode.DIO),
        dio.to_bytes(),
    ).to_bytes(source, destination)
    raw = IPv6Packet(
        IPv6Header(
            src_addr=source,
            dst_addr=destination,
            next_header=NextHeader.ICMPV6,
            hop_limit=255,
        ),
        payload=icmp,
    ).to_bytes()
    return wrap_schc_payload(compress_packet(raw))


@pytest.mark.asyncio
async def test_production_schc_ingress_notifies_once_and_success_resets(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(schc_failure_threshold=3, schc_failure_max_sources=2),
    )
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    notifications: list[bytes] = []
    delivered: list[tuple[bytes, PeerIdentity]] = []
    node.set_on_rule_version_failure(notifications.append)
    node.set_on_receive(lambda payload, sender: delivered.append((payload, sender)))
    malformed = _verified_rx(wrap_schc_payload(b"\xfe"), peer)

    def accept_packet(received: RxFrame) -> bytes:
        body = l2_payload_body(received.payload)
        if body == b"\xfe":
            raise ValueError("malformed SCHC")
        return decompress_packet(body)

    monkeypatch.setattr(node.link, "accept_authenticated_schc_packet", accept_packet)

    for _ in range(4):
        await node._process_received(malformed)
    assert notifications == [peer.pubkey]
    assert delivered == []

    raw = IPv6Header(
        src_addr=IPv6Address("fe80::1"),
        dst_addr=node.router.node_address,
        next_header=NextHeader.NO_NEXT_HEADER,
        payload_length=0,
    ).to_bytes()
    await node._process_received(_verified_rx(wrap_schc_payload(compress_packet(raw)), peer))
    for _ in range(3):
        await node._process_received(malformed)
    assert notifications == [peer.pubkey, peer.pubkey]
    assert delivered == [(wrap_schc_payload(compress_packet(raw)), peer)]


@pytest.mark.asyncio
async def test_production_schc_ingress_interleaves_peers_and_fails_closed_at_capacity(
    identity: Identity, radio: MockRadio
) -> None:
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(schc_failure_threshold=2, schc_failure_max_sources=2),
    )
    peers = [
        PeerIdentity.from_pubkey(Identity.from_seed(bytes([seed]) * 32).pubkey)
        for seed in (11, 22, 33)
    ]
    notifications: list[bytes] = []
    delivered: list[tuple[bytes, PeerIdentity]] = []
    node.set_on_rule_version_failure(notifications.append)
    node.set_on_receive(lambda payload, sender: delivered.append((payload, sender)))

    for peer in peers[:2]:
        await node._process_received(_verified_rx(wrap_schc_payload(b"\xfe"), peer))
    assert notifications == []

    # A new signer cannot evict either authenticated signer's partial run.
    await node._process_received(_verified_rx(wrap_schc_payload(b"\xfe"), peers[2]))
    assert notifications == []
    for peer in peers[:2]:
        await node._process_received(_verified_rx(wrap_schc_payload(b"\xfe"), peer))
    assert notifications == [peers[0].pubkey, peers[1].pubkey]
    assert delivered == []


@pytest.mark.asyncio
async def test_invalid_decompressed_ipv6_counts_toward_same_failure_streak(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(schc_failure_threshold=3),
    )
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    notifications: list[bytes] = []
    delivered: list[tuple[bytes, PeerIdentity]] = []
    node.set_on_rule_version_failure(notifications.append)
    node.set_on_receive(lambda payload, sender: delivered.append((payload, sender)))
    malformed = _verified_rx(wrap_schc_payload(b"\xfe"), peer)
    await node._process_received(malformed)

    invalid_ipv6 = bytes.fromhex("6000000000013b40") + bytes(32)

    def accept_invalid(received: RxFrame) -> bytes:
        if l2_payload_body(received.payload) == b"\xfe":
            raise ValueError("malformed SCHC")
        return invalid_ipv6

    monkeypatch.setattr(node.link, "accept_authenticated_schc_packet", accept_invalid)
    await node._process_received(_verified_rx(wrap_schc_payload(b"\x00"), peer))
    assert notifications == []
    await node._process_received(_verified_rx(wrap_schc_payload(b"\x00"), peer))
    assert notifications == [peer.pubkey]
    assert delivered == []


@pytest.mark.asyncio
async def test_peer_schc_transmit_uses_link_issued_fragment_batch(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []

    class Sender:
        status = "succeeded"

        def start(self) -> list[bytes]:
            return [b"issued-1", b"issued-2"]

        def cancel(self) -> None:
            raise AssertionError("successful batch must not be cancelled")

    def create_sender(payload: bytes, remote: bytes) -> Sender:
        assert len(payload) > MAX_SINGLE_FRAME_SCHC_PACKET
        assert remote == peer.pubkey
        return Sender()

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "create_fragment_sender", create_sender)
    monkeypatch.setattr(node.link, "send", send)
    assert await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    assert sent == [
        (b"issued-1", iid_to_eui64(peer.iid), AddrMode.EXTENDED, Priority.BULK),
        (b"issued-2", iid_to_eui64(peer.iid), AddrMode.EXTENDED, Priority.BULK),
    ]
    await asyncio.sleep(0)
    assert node._fragment_sessions == {}


@pytest.mark.asyncio
async def test_peer_schc_single_frame_uses_exact_extended_next_hop(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "send", send)
    schc = b"\x02canonical"
    assert await node._transmit_peer_schc(schc, peer)
    assert sent == [
        (
            wrap_schc_payload(schc),
            iid_to_eui64(peer.iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    ]


@pytest.mark.asyncio
async def test_canonical_peer_database_drives_link_local_lookup_and_extended_target(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node.add_peer(peer)
    link_local = IPv6Address(IPv6Address("fe80::").packed[:8] + peer.iid)
    resolved = node._peer_for_next_hop(link_local)
    assert resolved == peer

    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "send", send)
    assert resolved is not None
    assert await node._transmit_peer_schc(b"\x02canonical", resolved)
    assert sent == [
        (
            wrap_schc_payload(b"\x02canonical"),
            iid_to_eui64(peer.iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    ]


@pytest.mark.asyncio
async def test_peer_schc_transmit_cancels_prepared_sender_when_start_fails(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    cancelled = False

    class Sender:
        def start(self) -> list[bytes]:
            raise FragmentError("setup failed")

        def cancel(self) -> None:
            nonlocal cancelled
            cancelled = True

    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: Sender())
    assert not await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    assert cancelled


@pytest.mark.asyncio
async def test_fragment_sender_outputs_target_peer_with_control_priority(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    fragment = Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes()
    request = ack_request(0x78, 0)
    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_sender_control",
        lambda _received: [fragment, request],
    )

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "send", send)
    await node._process_received(_verified_rx(request, peer))
    assert sent == [
        (fragment, iid_to_eui64(peer.iid), AddrMode.EXTENDED, Priority.BULK),
        (request, iid_to_eui64(peer.iid), AddrMode.EXTENDED, Priority.ACK),
    ]


@pytest.mark.asyncio
async def test_reassembly_response_targets_authenticated_peer_at_ack_priority(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    response = bytes.fromhex("7840")
    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_sender_control",
        lambda _received: None,
    )
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_fragment",
        lambda _received: (ReceiverResult(response=response), None),
    )

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "send", send)
    await node._process_received(_verified_rx(ack_request(0x78, 0), peer))
    assert sent == [(response, iid_to_eui64(peer.iid), AddrMode.EXTENDED, Priority.ACK)]


@pytest.mark.asyncio
async def test_fragment_sender_timeout_retries_are_driven_to_terminal_abort(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    sent: list[bytes] = []

    class Sender:
        status = "ready"
        attempts = 0
        rule_id = 0x78

        def start(self) -> list[bytes]:
            self.status = "active"
            self.attempts = 1
            return [b"initial-all-1"]

        def timeout(self) -> bytes:
            if self.attempts >= MAX_ACK_REQUESTS:
                self.status = "aborted"
                return sender_abort(self.rule_id)
            self.attempts += 1
            return ack_request(self.rule_id, 0)

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: sender)
    monkeypatch.setattr(
        node.link,
        "cancel_fragment_sender",
        lambda value: (value.cancel(), sender_abort(value.rule_id))[1],
    )
    monkeypatch.setattr("lichen.node.SCHC_RETRANSMISSION_TIMEOUT_SECONDS", 0.001)

    async def send(
        payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        sent.append(payload)
        return True

    monkeypatch.setattr(node.link, "send", send)
    assert await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    for _ in range(100):
        if sender.status == "aborted":
            break
        await asyncio.sleep(0.001)

    assert sender.attempts == MAX_ACK_REQUESTS
    assert sent == [
        b"initial-all-1",
        ack_request(0x78, 0),
        ack_request(0x78, 0),
        ack_request(0x78, 0),
        sender_abort(0x78),
    ]
    await asyncio.sleep(0)
    assert node._fragment_sessions == {}


@pytest.mark.asyncio
async def test_fragment_sender_ack_success_stops_retransmission_timer(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)

    class Sender:
        status = "ready"
        rule_id = 0x78

        def start(self) -> list[bytes]:
            self.status = "active"
            return [b"initial"]

        def timeout(self) -> bytes:
            raise AssertionError("successful ACK must stop the timer")

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: sender)

    async def send(
        _payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        return True

    monkeypatch.setattr(node.link, "send", send)
    assert await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)

    def accept_control(_received: RxFrame) -> list[bytes]:
        sender.status = "succeeded"
        return []

    monkeypatch.setattr(node.link, "accept_authenticated_schc_sender_control", accept_control)
    await node._process_received(_verified_rx(bytes.fromhex("78c0"), peer))
    await asyncio.sleep(0)

    assert sender.status == "succeeded"
    assert node._fragment_sessions == {}


@pytest.mark.asyncio
async def test_fragment_retry_timer_is_paused_until_repair_batch_finishes(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    repair = Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes()
    repair_started = asyncio.Event()
    release_repair = asyncio.Event()

    class Sender:
        status = "ready"
        rule_id = 0x78
        timeout_calls = 0

        def start(self) -> list[bytes]:
            self.status = "active"
            return [b"initial"]

        def timeout(self) -> bytes:
            self.timeout_calls += 1
            return ack_request(0x78, 0)

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: sender)
    monkeypatch.setattr(
        node.link,
        "cancel_fragment_sender",
        lambda value: (value.cancel(), sender_abort(value.rule_id))[1],
    )
    monkeypatch.setattr("lichen.node.SCHC_RETRANSMISSION_TIMEOUT_SECONDS", 0.005)
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_sender_control",
        lambda _received: [repair],
    )

    async def send(
        payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        if payload == repair:
            repair_started.set()
            await release_repair.wait()
        return True

    monkeypatch.setattr(node.link, "send", send)
    assert await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    process = asyncio.create_task(node._process_received(_verified_rx(bytes.fromhex("7800"), peer)))
    await repair_started.wait()
    await asyncio.sleep(0.02)
    assert sender.timeout_calls == 0

    release_repair.set()
    await process
    await node.stop()


@pytest.mark.asyncio
async def test_fragment_repair_radio_failure_sends_terminal_abort(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    fragment = Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes()
    sent: list[bytes] = []

    class Sender:
        status = "active"
        rule_id = 0x78

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    owned = _OutboundFragmentSession(sender=cast(Any, sender), peer=peer)
    node._fragment_sessions[peer.pubkey] = owned
    monkeypatch.setattr(
        node.link,
        "cancel_fragment_sender",
        lambda value: (value.cancel(), sender_abort(value.rule_id))[1],
    )
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_sender_control",
        lambda _received: [fragment],
    )

    async def send(
        payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        sent.append(payload)
        return payload == sender_abort(0x78)

    monkeypatch.setattr(node.link, "send", send)
    await node._process_received(_verified_rx(bytes.fromhex("7800"), peer))

    assert sender.status == "aborted"
    assert sent == [fragment, sender_abort(0x78)]
    assert node._fragment_sessions == {}


@pytest.mark.asyncio
async def test_fragment_shutdown_cancels_driver_and_sends_abort(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    sent: list[bytes] = []

    class Sender:
        status = "ready"
        rule_id = 0x78

        def start(self) -> list[bytes]:
            self.status = "active"
            return [b"initial"]

        def timeout(self) -> bytes:
            return ack_request(0x78, 0)

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: sender)
    monkeypatch.setattr(
        node.link,
        "cancel_fragment_sender",
        lambda value: (value.cancel(), sender_abort(value.rule_id))[1],
    )

    async def send(
        payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        sent.append(payload)
        return True

    monkeypatch.setattr(node.link, "send", send)
    assert await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    await node.stop()

    assert sender.status == "aborted"
    assert sent == [b"initial", sender_abort(0x78)]
    assert node._fragment_sessions == {}


@pytest.mark.asyncio
async def test_shutdown_during_initial_fragment_batch_reports_failure_and_stops_batch(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    first_send_started = asyncio.Event()
    release_first_send = asyncio.Event()
    sent: list[bytes] = []

    class Sender:
        status = "ready"
        rule_id = 0x78

        def start(self) -> list[bytes]:
            self.status = "active"
            return [b"initial-1", b"initial-2"]

        def cancel(self) -> None:
            self.status = "aborted"

    sender = Sender()
    monkeypatch.setattr(node.link, "create_fragment_sender", lambda *_args: sender)
    monkeypatch.setattr(
        node.link,
        "cancel_fragment_sender",
        lambda value: (value.cancel(), sender_abort(value.rule_id))[1],
    )

    async def send(
        payload: bytes,
        _dst_addr: bytes,
        _addr_mode: AddrMode,
        _priority: Priority,
    ) -> bool:
        sent.append(payload)
        if payload == b"initial-1":
            first_send_started.set()
            await release_first_send.wait()
        return True

    monkeypatch.setattr(node.link, "send", send)
    transmit = asyncio.create_task(
        node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    )
    await first_send_started.wait()
    shutdown = asyncio.create_task(node.stop())
    await asyncio.sleep(0)
    release_first_send.set()

    assert not await transmit
    await shutdown
    assert sender.status == "aborted"
    assert sent == [b"initial-1", sender_abort(0x78)]
    assert node._fragment_sessions == {}

    assert not await node._transmit_peer_schc(bytes(MAX_SINGLE_FRAME_SCHC_PACKET + 1), peer)
    assert sent == [b"initial-1", sender_abort(0x78)]


@pytest.mark.asyncio
async def test_inbound_reassembly_inactivity_abort_uses_authenticated_destination(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    destination = iid_to_eui64(peer.iid)
    wire = receiver_abort(0x78)
    sent: list[tuple[bytes, bytes, AddrMode, Priority]] = []
    monkeypatch.setattr(
        node.link,
        "expire_authenticated_schc_reassembly",
        lambda: [(peer.pubkey, destination, wire)],
    )

    async def send(
        payload: bytes,
        dst_addr: bytes,
        addr_mode: AddrMode,
        priority: Priority,
    ) -> bool:
        sent.append((payload, dst_addr, addr_mode, priority))
        return True

    monkeypatch.setattr(node.link, "send", send)
    await node._send_expired_reassembly_aborts()
    assert sent == [(wire, destination, AddrMode.EXTENDED, Priority.ACK)]


@pytest.mark.asyncio
async def test_node_bootstraps_authenticated_dio_before_ordinary_schc_data(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    dodag_id = IPv6Address("fe80::1")
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            rpl_instance_id=0,
            rpl_dodag_id=dodag_id,
            rpl_dodag_version=1,
            rpl_mop=1,
            rpl_dio_expected_role="peer",
        ),
        peer_db={peer.iid: peer},
    )
    raw = _relay_test_packet(
        src=yggdrasil_address(peer_identity.pubkey),
        dst=yggdrasil_address(identity.pubkey),
        hop_limit=64,
    )
    encoded = compress_packet(raw)
    with pytest.raises(ValueError, match="authenticated replay-accepted peer DIO"):
        node.link.compress_schc_for_peer(raw, peer.pubkey)

    dio_payload = _dio_schc_payload(peer_identity, dodag_id)
    radio.queue_rx(_signed_link_wire(peer_identity, dio_payload, 0))
    dio_received = await node.link.receive(100)
    assert isinstance(dio_received, RxFrame)
    await node._process_received(dio_received)

    assert node.dodag is not None
    assert node.dodag.role is DodagRole.JOINED
    assert node.dodag.preferred_parent == IPv6Address(IPv6Address("fe80::").packed[:8] + peer.iid)
    assert node.link.compress_schc_for_peer(raw, peer.pubkey) == encoded

    delivered: list[tuple[bytes, PeerIdentity]] = []
    node.set_on_receive(lambda payload, sender: delivered.append((payload, sender)))
    wrapped = wrap_schc_payload(encoded)
    radio.queue_rx(_signed_link_wire(peer_identity, wrapped, 1))
    data_received = await node.link.receive(100)
    assert isinstance(data_received, RxFrame)
    await node._process_received(data_received)

    assert delivered == [(wrapped, peer)]


@pytest.mark.asyncio
async def test_link_issues_authenticated_dio_from_verified_reassembly(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    dodag_id = IPv6Address("fe80::1")
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            rpl_instance_id=0,
            rpl_dodag_id=dodag_id,
            rpl_dodag_version=1,
            rpl_mop=1,
            rpl_dio_expected_role="peer",
        ),
        peer_db={peer.iid: peer},
    )
    dio_payload = _dio_schc_payload(peer_identity, dodag_id)
    radio.queue_rx(_signed_link_wire(peer_identity, dio_payload, 0))
    bootstrap = await node.link.receive(100)
    assert isinstance(bootstrap, RxFrame)
    await node._process_received(bootstrap)

    raw_dio = decompress_packet(l2_payload_body(dio_payload))
    receiver_result = ReceiverResult(reassembled=b"reassembled")

    def reassemble_rule255(
        *_args: object,
        validate_packet: Callable[[bytes], bytes],
        **_kwargs: object,
    ) -> tuple[ReceiverResult, bytes]:
        return receiver_result, validate_packet(b"\xff" + raw_dio)

    monkeypatch.setattr(
        node.link._schc_reassembly_manager,
        "receive",
        reassemble_rule255,
    )

    fragment = Fragment(
        fragmentation_rule_for_sender(peer_identity.pubkey, identity.pubkey),
        0,
        62,
        bytes(TILE_SIZE),
    ).to_bytes()
    wire = _signed_extended_link_wire(
        peer_identity,
        fragment,
        1,
        iid_to_eui64(identity.iid),
    )
    radio.queue_rx(wire)
    received = await node.link.receive(100)
    assert isinstance(received, RxFrame)

    result, ipv6, authenticated = node.link.accept_authenticated_schc_fragment_dio(
        received,
        expected_rpl_instance_id=0,
        expected_dodag_id=dodag_id,
        expected_mop=1,
        expected_role="peer",
    )
    assert result is receiver_result
    assert ipv6 == raw_dio
    assert authenticated is not None
    assert authenticated.ipv6 == raw_dio
    assert authenticated.sender_pubkey == peer_identity.pubkey
    assert node.link.accepts_authenticated_dio(authenticated)

    malformed_dio = bytearray(raw_dio)
    malformed_dio[42] ^= 0x01  # Corrupt the ICMPv6 checksum while retaining DIO type/code.

    def reassemble_malformed_rule255(
        *_args: object,
        validate_packet: Callable[[bytes], bytes],
        **_kwargs: object,
    ) -> tuple[ReceiverResult, bytes]:
        return receiver_result, validate_packet(b"\xff" + bytes(malformed_dio))

    monkeypatch.setattr(
        node.link._schc_reassembly_manager,
        "receive",
        reassemble_malformed_rule255,
    )
    saves: list[None] = []
    monkeypatch.setattr(node.link, "_save_persisted_state", lambda: saves.append(None))
    radio.queue_rx(
        _signed_extended_link_wire(
            peer_identity,
            fragment,
            2,
            iid_to_eui64(identity.iid),
        )
    )
    malformed_received = await node.link.receive(100)
    assert isinstance(malformed_received, RxFrame)
    saves.clear()
    with pytest.raises(ValueError, match="valid RPL DIO"):
        node.link.accept_authenticated_schc_fragment_dio(
            malformed_received,
            expected_rpl_instance_id=0,
            expected_dodag_id=dodag_id,
            expected_mop=1,
            expected_role="peer",
        )
    assert saves == [None]

    # A mock (or alternate backend) that bypasses the validation callback has
    # no authenticated SCHC Rule provenance and must not issue DIO evidence.
    monkeypatch.setattr(
        node.link._schc_reassembly_manager,
        "receive",
        lambda *_args, **_kwargs: (receiver_result, raw_dio),
    )
    radio.queue_rx(
        _signed_extended_link_wire(
            peer_identity,
            fragment,
            3,
            iid_to_eui64(identity.iid),
        )
    )
    provenance_missing = await node.link.receive(100)
    assert isinstance(provenance_missing, RxFrame)
    with pytest.raises(ValueError, match="Rule 255"):
        node.link.accept_authenticated_schc_fragment_dio(
            provenance_missing,
            expected_rpl_instance_id=0,
            expected_dodag_id=dodag_id,
            expected_mop=1,
            expected_role="peer",
        )


@pytest.mark.asyncio
async def test_fragmented_dio_evidence_uses_dodag_admission_not_data_delivery(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            rpl_instance_id=0,
            rpl_dodag_id=IPv6Address("fe80::1"),
            rpl_dio_expected_role="peer",
        ),
        peer_db={peer.iid: peer},
    )
    evidence = object()
    admitted: list[object] = []
    delivered: list[bytes] = []
    node.set_on_receive(lambda payload, _sender: delivered.append(payload))
    monkeypatch.setattr(node.link, "accept_authenticated_schc_sender_control", lambda _rx: None)
    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_fragment_dio",
        lambda *_args, **_kwargs: (
            ReceiverResult(reassembled=b"compressed-dio"),
            bytes.fromhex("6000000000003b40") + bytes(32),
            evidence,
        ),
    )
    assert node.dodag is not None
    monkeypatch.setattr(
        node.dodag,
        "process_authenticated_dio_evidence",
        lambda _link, authenticated, **_kwargs: admitted.append(authenticated),
    )

    fragment = Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes()
    await node._process_received(_verified_rx(fragment, peer))

    assert admitted == [evidence]
    assert delivered == []


@pytest.mark.asyncio
async def test_malformed_fragmented_dio_is_not_delivered_as_data(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            rpl_instance_id=0,
            rpl_dodag_id=IPv6Address("fe80::1"),
            rpl_dio_expected_role="peer",
        ),
        peer_db={peer.iid: peer},
    )
    delivered: list[bytes] = []
    node.set_on_receive(lambda payload, _sender: delivered.append(payload))
    monkeypatch.setattr(node.link, "accept_authenticated_schc_sender_control", lambda _rx: None)

    def reject(*_args: object, **_kwargs: object) -> object:
        raise ValueError("malformed reassembled DIO")

    monkeypatch.setattr(node.link, "accept_authenticated_schc_fragment_dio", reject)
    fragment = Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes()
    await node._process_received(_verified_rx(fragment, peer))
    assert delivered == []


@pytest.mark.parametrize(
    "config,match",
    [
        (NodeConfig(rpl_instance_id=0), "requires instance ID"),
        (
            NodeConfig(
                rpl_instance_id=True,
                rpl_dodag_id=IPv6Address("fe80::1"),
                rpl_dio_expected_role="peer",
            ),
            "instance ID",
        ),
        (
            NodeConfig(
                rpl_instance_id=0,
                rpl_dodag_id=IPv6Address("fe80::1"),
                rpl_mop=2,
                rpl_dio_expected_role="peer",
            ),
            "non-storing MOP 1",
        ),
    ],
)
def test_node_rejects_incomplete_or_unsupported_rpl_admission_scope(
    identity: Identity,
    radio: MockRadio,
    config: NodeConfig,
    match: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=match):
        Node(identity=identity, radio=radio, config=config)


@pytest.mark.asyncio
async def test_rule_failure_callback_rejects_async_and_retries_raise_once(
    identity: Identity, peer_identity: Identity, radio: MockRadio
) -> None:
    node = Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(schc_failure_threshold=1),
    )

    async def async_callback(_source: bytes) -> None:
        return None

    with pytest.raises(TypeError, match="synchronous"):
        node.set_on_rule_version_failure(async_callback)

    calls = 0

    def raise_once(_source: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("notify failed")

    node.set_on_rule_version_failure(raise_once)
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    malformed = _verified_rx(wrap_schc_payload(b"\xfe"), peer)
    with pytest.raises(RuntimeError, match="notify failed"):
        await node._process_received(malformed)
    await node._process_received(malformed)
    assert calls == 2


@pytest.mark.asyncio
async def test_receive_loop_surfaces_terminal_link_failure(
    identity: Identity, radio: MockRadio
) -> None:
    node = Node(identity=identity, radio=radio)
    calls = 0

    async def failed_receive(_timeout_ms: int) -> None:
        nonlocal calls
        calls += 1
        raise LinkPersistenceError("terminal")

    node.link.receive = failed_receive  # type: ignore[method-assign]
    with pytest.raises(LinkPersistenceError, match="terminal"):
        await node._receive_loop()
    assert calls == 1


@pytest.mark.asyncio
async def test_receive_loop_surfaces_terminal_link_security_clock_failure(
    identity: Identity, radio: MockRadio
) -> None:
    node = Node(identity=identity, radio=radio)
    calls = 0

    async def failed_receive(_timeout_ms: int) -> None:
        nonlocal calls
        calls += 1
        raise LinkSecurityClockError("terminal clock")

    node.link.receive = failed_receive  # type: ignore[method-assign]
    with pytest.raises(LinkSecurityClockError, match="terminal clock"):
        await node._receive_loop()
    assert calls == 1


@pytest.mark.asyncio
async def test_receive_loop_sweeps_expiry_before_each_bounded_receive(
    node: Node,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    async def sweep() -> None:
        events.append("sweep")

    async def receive(timeout_ms: int) -> None:
        events.append(timeout_ms)
        raise LinkPersistenceError("stop after observing one receive")

    monkeypatch.setattr(node, "_send_expired_reassembly_aborts", sweep)
    monkeypatch.setattr(node.link, "receive", receive)
    with pytest.raises(LinkPersistenceError, match="stop after"):
        await node._receive_loop()

    assert events == ["sweep", node.config.receive_timeout_ms]
    assert 1 <= node.config.receive_timeout_ms <= RECEIVE_TIMEOUT_MAX_MS


@pytest.mark.asyncio
@pytest.mark.parametrize("destination", [IPv6Address("fe80::abcd"), IPv6Address("ff02::1")])
@pytest.mark.parametrize(("hop_limit", "forwarded_hop_limit"), [(0, None), (1, None), (2, 1)])
async def test_ipv6_forwarding_enforces_hop_limit_boundary(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
    destination: IPv6Address,
    hop_limit: int,
    forwarded_hop_limit: int | None,
) -> None:
    ingress_peer = PeerIdentity.from_pubkey(Identity.from_seed(bytes([7]) * 32).pubkey)
    next_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node.add_peer(next_peer)
    next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + next_peer.iid)
    source = IPv6Address("fe80::1234")
    raw = IPv6Packet(
        IPv6Header(
            src_addr=source,
            dst_addr=destination,
            next_header=NextHeader.NO_NEXT_HEADER,
            hop_limit=hop_limit,
        ),
        payload=b"bounded",
    ).to_bytes()
    encoded = wrap_schc_payload(b"\x02test")
    compressed_inputs: list[bytes] = []
    transmitted: list[bytes] = []

    monkeypatch.setattr(node.link, "accept_authenticated_schc_packet", lambda _rx: raw)
    monkeypatch.setattr(
        node.router,
        "route",
        lambda _packet, _now: (RouteDecision.FORWARD, next_hop),
    )

    def compress(ipv6: bytes, remote: bytes, *, allow_fragmentation: bool) -> bytes:
        assert remote == next_peer.pubkey
        assert allow_fragmentation
        compressed_inputs.append(ipv6)
        return b"forwarded-schc"

    async def transmit(schc: bytes, peer: PeerIdentity) -> bool:
        assert peer == next_peer
        transmitted.append(schc)
        return True

    monkeypatch.setattr(node.link, "compress_schc_for_peer", compress)
    monkeypatch.setattr(node, "_transmit_peer_schc", transmit)

    await node._process_received(_verified_rx(encoded, ingress_peer))

    if forwarded_hop_limit is None:
        assert compressed_inputs == []
        assert transmitted == []
        assert source not in node.gradient_table
    else:
        assert transmitted == [b"forwarded-schc"]
        assert len(compressed_inputs) == 1
        forwarded = IPv6Packet.from_bytes(compressed_inputs[0], strict=True)
        assert forwarded.header.hop_limit == forwarded_hop_limit
        assert forwarded.header.src_addr == source
        assert forwarded.header.dst_addr == destination
        assert forwarded.payload == b"bounded"
    assert source not in node.gradient_table


def test_node_uses_key_derived_native_primary_and_routes_native_mesh_peers(
    node: Node,
    peer_identity: Identity,
) -> None:
    local = yggdrasil_address(node.identity.pubkey)
    remote = yggdrasil_address(peer_identity.pubkey)
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + peer.iid)
    packet = IPv6Packet(
        IPv6Header(
            src_addr=local,
            dst_addr=local,
            next_header=NextHeader.NO_NEXT_HEADER,
        )
    )

    assert node.router.node_address == local
    assert node.router.classify_address(remote) is AddressClass.MESH_LOCAL
    assert node.router.route(packet, now_ms=10) == (RouteDecision.DELIVER_LOCAL, None)

    node.gradient_table.update(
        GradientEntry(
            destination=remote,
            next_hop=next_hop,
            hop_count=1,
            seq_num=1,
            source=GradientSource.DATA,
            expires=10 + DATA_GRADIENT_TIMEOUT_MS,
        ),
        now=10,
    )
    packet.header.dst_addr = remote
    assert node.router.route(packet, now_ms=10) == (RouteDecision.FORWARD, next_hop)


@pytest.mark.asyncio
async def test_node_send_local_rejects_invalid_udp_checksum(
    node: Node,
) -> None:
    local = yggdrasil_address(node.identity.pubkey)
    malformed_udp = (
        (1234).to_bytes(2, "big") + (5683).to_bytes(2, "big") + (8).to_bytes(2, "big") + b"\x00\x00"
    )
    raw = IPv6Packet(
        IPv6Header(
            src_addr=local,
            dst_addr=local,
            next_header=NextHeader.UDP,
            hop_limit=64,
        ),
        payload=malformed_udp,
    ).to_bytes()

    assert not await node.send(raw)


@pytest.mark.asyncio
async def test_node_announce_gradient_uses_exact_key_derived_native_address(
    node: Node,
    peer_identity: Identity,
    radio: MockRadio,
) -> None:
    peer_node = Node(identity=peer_identity, radio=cast(Any, MockRadio()))
    announce = peer_node._scheduler.build_announce()
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)

    await node._process_announce(announce.to_bytes(), peer, -80)

    exact = yggdrasil_address(peer_identity.pubkey)
    entry = node.gradient_table.lookup(exact)
    assert entry is not None
    assert entry.destination == exact
    assert radio.tx_history  # Valid announces remain eligible for relay.


@pytest.mark.asyncio
async def test_node_reboot_restores_announce_pin_and_reconciles_exact_origin(
    tmp_path,
    identity: Identity,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Anchor:
        def __init__(self) -> None:
            self.revisions: dict[bytes, int] = {}

        def read(self, key: bytes) -> int | None:
            return self.revisions.get(key)

        def advance(self, key: bytes, expected: int | None, revision: int) -> None:
            assert self.revisions.get(key) == expected
            assert revision == (expected or 0) + 1
            self.revisions[key] = revision

    anchor = Anchor()
    persist_path = str(tmp_path / "node-state")
    unsigned = AnnounceMessage(peer_identity.iid, peer_identity.pubkey, 7)
    announce = AnnounceMessage(
        peer_identity.iid,
        peer_identity.pubkey,
        7,
        signature=sign(peer_identity.privkey, peer_identity.pubkey, unsigned.signed_data()),
    )
    first = Node(
        identity=identity,
        radio=cast(Any, MockRadio()),
        config=NodeConfig(persist_path=persist_path),
        persistence_revision_anchor=anchor,
        allow_persistence_bootstrap=True,
    )
    first_relay = PeerIdentity.from_pubkey(Identity.from_seed(bytes([7]) * 32).pubkey)

    def fail_gradient(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("injected gradient admission failure")

    monkeypatch.setattr(first.gradient_table, "update", fail_gradient)
    with pytest.raises(RuntimeError, match="injected gradient"):
        await first._process_announce(announce.to_bytes(), first_relay, -80)
    assert first.announce_processor.pinned_pubkey_for(peer_identity.iid) is None
    assert first.gradient_table.lookup(yggdrasil_address(peer_identity.pubkey)) is None

    second_radio = MockRadio()
    restarted = Node(
        identity=identity,
        radio=cast(Any, second_radio),
        config=NodeConfig(persist_path=persist_path),
        persistence_revision_anchor=anchor,
        allow_persistence_bootstrap=False,
    )
    assert restarted.announce_processor.pinned_pubkey_for(peer_identity.iid) == peer_identity.pubkey
    assert restarted.gradient_table.lookup(yggdrasil_address(peer_identity.pubkey)) is None

    different_relay = PeerIdentity.from_pubkey(Identity.from_seed(bytes([8]) * 32).pubkey)
    add_peer = restarted.add_peer

    def fail_peer_admission(_peer: PeerIdentity) -> None:
        raise PeerDatabaseFullError("injected peer capacity race")

    monkeypatch.setattr(restarted, "add_peer", fail_peer_admission)
    await restarted._process_announce(
        announce.with_incremented_hop_count().to_bytes(), different_relay, -70
    )
    assert restarted.gradient_table.lookup(yggdrasil_address(peer_identity.pubkey)) is None
    monkeypatch.setattr(restarted, "add_peer", add_peer)
    await restarted._process_announce(
        announce.with_incremented_hop_count().to_bytes(), different_relay, -70
    )
    assert restarted.gradient_table.lookup(yggdrasil_address(peer_identity.pubkey)) is not None
    assert peer_identity.iid in restarted.peer_db
    assert second_radio.tx_history


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retained", "first_sequence", "second_sequence"),
    [(0, 1, 2), (0x7FFE, 0x7FFF, 0x8000), (0xFFFE, 0xFFFF, 0)],
)
async def test_two_nodes_preserve_origin_sequence_across_reboot_boundaries(
    tmp_path,
    identity: Identity,
    peer_identity: Identity,
    retained: int,
    first_sequence: int,
    second_sequence: int,
) -> None:
    class Anchor:
        def __init__(self) -> None:
            self.revisions: dict[bytes, int] = {}

        def read(self, key: bytes) -> int | None:
            return self.revisions.get(key)

        def advance(self, key: bytes, expected: int | None, revision: int) -> None:
            assert self.revisions.get(key) == expected
            assert revision == (expected or 0) + 1
            self.revisions[key] = revision

    origin_anchor = Anchor()
    receiver_anchor = Anchor()
    origin_path = str(tmp_path / "origin")
    receiver_path = str(tmp_path / "receiver")
    origin = Node(
        identity=peer_identity,
        radio=cast(Any, MockRadio()),
        config=NodeConfig(persist_path=origin_path),
        persistence_revision_anchor=origin_anchor,
        allow_persistence_bootstrap=True,
    )
    if retained:
        assert origin._announce_persistence is not None
        with origin._announce_persistence._lock():
            revision, _local, pins, floors = origin._announce_persistence._read_state()
            origin._announce_persistence._publish_state(revision, retained, pins, floors)
        origin._scheduler.set_seq_num(retained)
    receiver = Node(
        identity=identity,
        radio=cast(Any, MockRadio()),
        config=NodeConfig(persist_path=receiver_path),
        persistence_revision_anchor=receiver_anchor,
        allow_persistence_bootstrap=True,
    )
    sender = PeerIdentity.from_pubkey(peer_identity.pubkey)
    first = origin._scheduler.build_announce()
    assert first.seq_num == first_sequence
    await receiver._process_announce(first.to_bytes(), sender, -80)

    restarted = Node(
        identity=peer_identity,
        radio=cast(Any, MockRadio()),
        config=NodeConfig(persist_path=origin_path),
        persistence_revision_anchor=origin_anchor,
        allow_persistence_bootstrap=False,
    )
    second = restarted._scheduler.build_announce()
    assert second.seq_num == second_sequence
    await receiver._process_announce(second.to_bytes(), sender, -80)
    assert receiver.announce_processor.known_originators() == [peer_identity.iid]
    route = receiver.gradient_table.lookup(yggdrasil_address(peer_identity.pubkey))
    assert route is not None and route.seq_num == second_sequence


@pytest.mark.asyncio
async def test_node_configures_post_dad_short_address_for_exact_destination_admission(
    identity: Identity,
    peer_identity: Identity,
    radio: MockRadio,
) -> None:
    node = Node(
        identity=identity,
        radio=cast(Any, radio),
        config=NodeConfig(local_short_addr=0x1234),
    )
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node.add_peer(peer)
    peer_radio = MockRadio()
    peer_node = Node(identity=peer_identity, radio=cast(Any, peer_radio))

    assert await peer_node.link.send(b"matching", bytes.fromhex("1234"), AddrMode.SHORT)
    radio.queue_rx(peer_radio.tx_history[-1])
    accepted = await node.link.receive(100)
    assert isinstance(accepted, RxFrame)
    assert accepted.payload == b"matching"

    assert await peer_node.link.send(b"other", bytes.fromhex("1235"), AddrMode.SHORT)
    radio.queue_rx(peer_radio.tx_history[-1])
    assert await node.link.receive(100) is ReceiveError.NOT_FOR_US


@pytest.mark.parametrize("short_addr", [True, 1.5, 0x0000, 0xFFFE, 0xFFFF, -1, 0x10000])
def test_node_rejects_nonassigned_or_reserved_short_address(
    identity: Identity,
    radio: MockRadio,
    short_addr: object,
) -> None:
    with pytest.raises(ValueError, match="non-reserved 16-bit"):
        Node(
            identity=identity,
            radio=cast(Any, radio),
            config=NodeConfig(local_short_addr=cast(Any, short_addr)),
        )


def _relay_test_packet(*, src: IPv6Address, dst: IPv6Address, hop_limit: int) -> bytes:
    return IPv6Packet(
        IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=NextHeader.NO_NEXT_HEADER,
            hop_limit=hop_limit,
        ),
        payload=b"stable-application-packet",
    ).to_bytes()


def test_relay_dedup_expires_without_authenticated_preplay_refresh(node: Node) -> None:
    identity = b"one immutable IPv6 packet"
    first_seen_ms = 10_000
    deadline = first_seen_ms + RELAY_SEEN_WINDOW_MS

    node._remember_relay(identity, first_seen_ms)
    original_deadline = node._relay_seen[identity]
    assert node._relay_seen_recently(identity, deadline - 1)

    # An admitted forwarder can repeat the exact packet, but cannot extend the
    # fixed window and suppress a later legitimate copy indefinitely.
    node._remember_relay(identity, deadline - 1)
    assert node._relay_seen[identity] == original_deadline
    assert not node._relay_seen_recently(identity, deadline)

    node._remember_relay(identity, deadline)
    assert node._relay_seen[identity] == deadline + RELAY_SEEN_WINDOW_MS


@pytest.mark.asyncio
async def test_relay_dedup_survives_hop_limit_and_peer_schc_encoding_changes(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ingress = PeerIdentity.from_pubkey(Identity.from_seed(bytes([7]) * 32).pubkey)
    next_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node.add_peer(next_peer)
    next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + next_peer.iid)
    source = yggdrasil_address(ingress.pubkey)
    destination = yggdrasil_address(next_peer.pubkey)
    first_encoding = wrap_schc_payload(b"\x02peer-a-context")
    loop_encoding = wrap_schc_payload(b"\x03peer-b-context")
    decoded = {
        first_encoding: _relay_test_packet(src=source, dst=destination, hop_limit=5),
        loop_encoding: _relay_test_packet(src=source, dst=destination, hop_limit=3),
    }
    transmitted: list[bytes] = []

    monkeypatch.setattr(
        node.link,
        "accept_authenticated_schc_packet",
        lambda rx: decoded[rx.payload],
    )
    monkeypatch.setattr(
        node.router, "route", lambda _packet, _now: (RouteDecision.FORWARD, next_hop)
    )
    monkeypatch.setattr(
        node.link,
        "compress_schc_for_peer",
        lambda _ipv6, _remote, *, allow_fragmentation: b"next-hop-context",
    )

    async def transmit(schc: bytes, _peer: PeerIdentity) -> bool:
        transmitted.append(schc)
        return True

    monkeypatch.setattr(node, "_transmit_peer_schc", transmit)

    await node._process_received(_verified_rx(first_encoding, ingress))
    await node._process_received(_verified_rx(loop_encoding, ingress))

    assert transmitted == [b"next-hop-context"]
    assert len(node._relay_seen) == 1


@pytest.mark.asyncio
async def test_locally_originated_packet_suppresses_looped_peer_encoding(
    node: Node,
    peer_identity: Identity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    next_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    node.add_peer(next_peer)
    next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + next_peer.iid)
    local = _relay_test_packet(
        src=yggdrasil_address(node.identity.pubkey),
        dst=yggdrasil_address(next_peer.pubkey),
        hop_limit=12,
    )
    looped = _relay_test_packet(
        src=yggdrasil_address(node.identity.pubkey),
        dst=yggdrasil_address(next_peer.pubkey),
        hop_limit=9,
    )
    loop_encoding = wrap_schc_payload(b"\x03loop-context")
    transmitted: list[bytes] = []

    monkeypatch.setattr(
        node.router, "route", lambda _packet, _now: (RouteDecision.FORWARD, next_hop)
    )
    monkeypatch.setattr(
        node.link,
        "compress_schc_for_peer",
        lambda _ipv6, _remote, *, allow_fragmentation: b"origin-context",
    )
    monkeypatch.setattr(node.link, "accept_authenticated_schc_packet", lambda _rx: looped)

    async def transmit(schc: bytes, _peer: PeerIdentity) -> bool:
        transmitted.append(schc)
        return True

    monkeypatch.setattr(node, "_transmit_peer_schc", transmit)

    assert await node.send(local)
    await node._process_received(_verified_rx(loop_encoding, next_peer))

    assert transmitted == [b"origin-context"]
    assert len(node._relay_seen) == 1
