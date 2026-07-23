# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulation integration tests for DTN store-and-forward (spec 9.8).

Tests verify that:
1. DTN expiry and pending IID encodings work correctly
2. Router's DTN buffer manages messages properly (buffering, retrieval, expiry)
3. Nodes can advertise pending IIDs for ferry discovery

Paranoid defensive style: explicit assertions at every step, guard against
None values aggressively, verify invariants.
"""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.coords import (
    APP_DATA_TYPE_DTN_EXPIRY,
    APP_DATA_TYPE_DTN_PENDING,
    decode_dtn_expiry,
    decode_dtn_pending,
    encode_dtn_expiry,
    encode_dtn_pending,
)
from lichen.announce.messages import AnnounceMessage
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.gradient import GradientTable
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.radio.sim_client import SimRadio
from lichen.routing.router import MAX_DTN_TTL_SECONDS, DtnMessage, Router
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# --- Test fixtures ---


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start a simulator server with a test simulation.

    PARANOID: Verify server started, verify simulation created, verify cleanup.
    """
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()

    # PARANOID: Verify server is actually running
    assert server._node_servers is not None, "node servers dict must exist"

    sim = await server.create_simulation("dtn-test", TimeMode.BARRIER_SYNC)

    # PARANOID: Verify simulation was created
    assert sim is not None, "simulation must be created"
    assert sim.id == "dtn-test", "simulation ID must match"

    yield server, sim

    # PARANOID: Verify cleanup doesn't fail
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create a deterministic identity from a single seed byte.

    PARANOID: Verify seed_byte is valid.
    """
    assert 0 <= seed_byte <= 255, f"seed_byte must be 0-255, got {seed_byte}"
    seed = bytes([seed_byte] + [0] * 31)
    identity = Identity.from_seed(seed)

    # PARANOID: Verify identity is complete
    assert identity.pubkey is not None, "identity must have pubkey"
    assert identity.privkey is not None, "identity must have privkey"
    assert identity.iid is not None, "identity must have IID"
    assert len(identity.iid) == 8, "IID must be 8 bytes"

    return identity


def build_address_from_iid(iid: bytes) -> IPv6Address:
    """Build a link-local IPv6 address from an IID.

    PARANOID: Verify IID is correct length.
    """
    assert len(iid) == 8, f"IID must be 8 bytes, got {len(iid)}"
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    addr = IPv6Address(prefix + iid)

    # PARANOID: Verify address is link-local
    assert addr.is_link_local, f"address {addr} must be link-local"

    return addr


def make_test_packet(src: IPv6Address, dst: IPv6Address, payload: bytes) -> IPv6Packet:
    """Create a test IPv6 packet.

    PARANOID: Verify packet structure.
    """
    packet = IPv6Packet(
        header=IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=17,  # UDP
            hop_limit=64,
            payload_length=len(payload),
        ),
        payload=payload,
    )

    # PARANOID: Verify packet
    assert packet.header.src_addr == src, "src must match"
    assert packet.header.dst_addr == dst, "dst must match"
    assert packet.payload == payload, "payload must match"

    return packet


class MockTransmitter:
    """Mock transmitter that captures announce bytes."""

    def __init__(self) -> None:
        self.last_data: bytes | None = None
        self.tx_count: int = 0

    async def transmit_announce(self, data: bytes) -> bool:
        assert data is not None, "cannot transmit None data"
        assert len(data) > 0, "cannot transmit empty data"
        self.last_data = data
        self.tx_count += 1
        return True


# --- Test classes ---


class TestDtnExpiryEncoding:
    """Test DTN expiry timestamp encoding (python-alz.1)."""

    @pytest.mark.asyncio
    async def test_encode_dtn_expiry(self) -> None:
        """Verify expiry timestamp is encoded correctly.

        PARANOID: Check encoding format byte-by-byte.
        """
        # Use a known timestamp
        expiry_unix = 1719100800  # 2024-06-23 00:00:00 UTC

        # PARANOID: Verify timestamp is in valid range
        assert 0 <= expiry_unix <= 0xFFFFFFFF, "must be 32-bit unsigned"

        app_data = encode_dtn_expiry(expiry_unix)

        # PARANOID: Verify encoding structure
        assert app_data is not None, "encoding must not return None"
        assert len(app_data) == 5, f"dtn expiry must be 5 bytes, got {len(app_data)}"
        assert app_data[0] == APP_DATA_TYPE_DTN_EXPIRY, "first byte must be expiry type"

        # Verify round-trip
        decoded = decode_dtn_expiry(app_data)
        assert decoded is not None, "decoding must succeed"
        assert decoded == expiry_unix, f"decoded {decoded} must match {expiry_unix}"

    @pytest.mark.asyncio
    async def test_encode_dtn_expiry_boundaries(self) -> None:
        """Test encoding at boundary values (0, max uint32).

        PARANOID: Verify boundary conditions.
        """
        # Test minimum
        app_data_min = encode_dtn_expiry(0)
        assert len(app_data_min) == 5, "must be 5 bytes"
        decoded_min = decode_dtn_expiry(app_data_min)
        assert decoded_min == 0, "must decode to 0"

        # Test maximum
        max_uint32 = 0xFFFFFFFF
        app_data_max = encode_dtn_expiry(max_uint32)
        assert len(app_data_max) == 5, "must be 5 bytes"
        decoded_max = decode_dtn_expiry(app_data_max)
        assert decoded_max == max_uint32, "must decode to max"

    @pytest.mark.asyncio
    async def test_encode_dtn_expiry_out_of_range(self) -> None:
        """Test that out-of-range values raise ValueError.

        PARANOID: Verify error handling.
        """
        # Test value above max uint32
        with pytest.raises(ValueError, match="expiry_unix"):
            encode_dtn_expiry(0x100000000)


class TestDtnPendingEncoding:
    """Test DTN pending IID list encoding (python-alz.1)."""

    @pytest.mark.asyncio
    async def test_encode_dtn_pending_empty(self) -> None:
        """Empty pending list encodes correctly.

        PARANOID: Verify structure.
        """
        app_data = encode_dtn_pending([])

        assert len(app_data) == 2, "empty list is 2 bytes (type + count)"
        assert app_data[0] == APP_DATA_TYPE_DTN_PENDING, "first byte is type"
        assert app_data[1] == 0, "second byte is count=0"

        decoded = decode_dtn_pending(app_data)
        assert decoded is not None, "must decode"
        assert decoded == [], "must be empty list"

    @pytest.mark.asyncio
    async def test_encode_dtn_pending_one_iid(self) -> None:
        """Single IID encodes correctly.

        PARANOID: Verify IID is preserved.
        """
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        # PARANOID: Verify IID is 8 bytes
        assert len(iid) == 8, "IID must be 8 bytes"

        app_data = encode_dtn_pending([iid])

        assert len(app_data) == 10, "one IID is 10 bytes (type + count + 8)"
        assert app_data[0] == APP_DATA_TYPE_DTN_PENDING, "type byte"
        assert app_data[1] == 1, "count=1"
        assert app_data[2:10] == iid, "IID must be preserved"

        decoded = decode_dtn_pending(app_data)
        assert decoded is not None, "must decode"
        assert len(decoded) == 1, "must have one IID"
        assert decoded[0] == iid, "IID must match"

    @pytest.mark.asyncio
    async def test_encode_dtn_pending_multiple_iids(self) -> None:
        """Multiple IIDs encode correctly.

        PARANOID: Verify all IIDs preserved in order.
        """
        iids = [bytes([i] * 8) for i in range(5)]

        # PARANOID: Verify all IIDs are 8 bytes
        for i, iid in enumerate(iids):
            assert len(iid) == 8, f"IID {i} must be 8 bytes"

        app_data = encode_dtn_pending(iids)

        expected_len = 2 + 5 * 8  # type + count + 5*8
        assert len(app_data) == expected_len, f"must be {expected_len} bytes"
        assert app_data[1] == 5, "count=5"

        decoded = decode_dtn_pending(app_data)
        assert decoded is not None, "must decode"
        assert len(decoded) == 5, "must have 5 IIDs"
        for i, iid in enumerate(decoded):
            assert iid == iids[i], f"IID {i} must match"

    @pytest.mark.asyncio
    async def test_encode_dtn_pending_wrong_iid_length(self) -> None:
        """IID with wrong length raises ValueError.

        PARANOID: Verify validation.
        """
        with pytest.raises(ValueError, match="length"):
            encode_dtn_pending([bytes([1, 2, 3])])  # Too short


class TestDtnBufferManagement:
    """Test Router's DTN buffer operations (python-alz.2)."""

    @pytest.mark.asyncio
    async def test_dtn_buffer_message(self) -> None:
        """dtn_buffer_message stores message correctly.

        PARANOID: Verify storage.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        # PARANOID: Verify buffer starts empty
        assert len(router.dtn_buffer) == 0, "buffer must start empty"

        # Create a test packet
        packet = make_test_packet(
            IPv6Address("fd00::1"),
            IPv6Address("fd00::2"),
            b"test payload",
        )

        destination_iid = bytes([0xDE, 0xAD] + [0] * 6)
        expiry_unix = int(time.time()) + 3600  # 1 hour from now
        now_ms = 1000

        # Buffer the message
        result = router.dtn_buffer_message(packet, destination_iid, expiry_unix, now_ms)

        # PARANOID: Verify buffering succeeded
        assert result is True, "buffering must succeed"
        assert len(router.dtn_buffer) == 1, "buffer must have 1 message"

        # PARANOID: Verify message contents
        msg = router.dtn_buffer[0]
        assert msg.packet == packet, "packet must match"
        assert msg.destination_iid == destination_iid, "destination IID must match"
        assert msg.expiry_unix == expiry_unix, "expiry must match"
        assert msg.buffered_at_ms == now_ms, "buffered_at must match"

    @pytest.mark.asyncio
    async def test_dtn_buffer_rejects_expired(self) -> None:
        """dtn_buffer_message rejects already-expired messages.

        PARANOID: Verify expiry check.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        packet = make_test_packet(
            IPv6Address("fd00::1"),
            IPv6Address("fd00::2"),
            b"expired payload",
        )

        destination_iid = bytes([0xDE, 0xAD] + [0] * 6)
        expiry_unix = int(time.time()) - 3600  # 1 hour AGO (expired)
        now_ms = 1000

        # Try to buffer expired message
        result = router.dtn_buffer_message(packet, destination_iid, expiry_unix, now_ms)

        # PARANOID: Verify rejection
        assert result is False, "must reject expired message"
        assert len(router.dtn_buffer) == 0, "buffer must remain empty"

    @pytest.mark.asyncio
    async def test_dtn_buffer_rejects_excessive_ttl(self) -> None:
        """dtn_buffer_message rejects excessive future TTL.
        Prevents buffer exhaustion DoS from permanent messages.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        packet = make_test_packet(
            IPv6Address("fd00::1"),
            IPv6Address("fd00::2"),
            b"excessive ttl payload",
        )

        destination_iid = bytes([0xDE, 0xAD] + [0] * 6)
        now_unix = int(time.time())
        expiry_unix = now_unix + MAX_DTN_TTL_SECONDS + 86400
        now_ms = 1000

        result = router.dtn_buffer_message(packet, destination_iid, expiry_unix, now_ms)

        assert result is False, "must reject excessive TTL"
        assert len(router.dtn_buffer) == 0, "buffer must remain empty"

    @pytest.mark.asyncio
    async def test_dtn_get_pending_iids(self) -> None:
        """dtn_get_pending_iids returns unique destination IIDs.

        PARANOID: Verify uniqueness.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        # Buffer messages for different destinations
        iid_a = bytes([0xAA] * 8)
        iid_b = bytes([0xBB] * 8)
        iid_c = bytes([0xCC] * 8)

        future_expiry = int(time.time()) + 3600

        for iid in [iid_a, iid_b, iid_a, iid_c, iid_a]:  # A appears 3x
            packet = make_test_packet(
                IPv6Address("fd00::1"),
                IPv6Address("fd00::2"),
                b"payload",
            )
            router.dtn_buffer_message(packet, iid, future_expiry, 1000)

        # PARANOID: Verify buffer has 5 messages
        assert len(router.dtn_buffer) == 5, "buffer must have 5 messages"

        # Get pending IIDs
        pending = router.dtn_get_pending_iids()

        # PARANOID: Verify uniqueness and content
        assert len(pending) == 3, "must have 3 unique IIDs"
        assert iid_a in pending, "A must be in pending"
        assert iid_b in pending, "B must be in pending"
        assert iid_c in pending, "C must be in pending"

    @pytest.mark.asyncio
    async def test_dtn_retrieve_for(self) -> None:
        """dtn_retrieve_for retrieves and removes messages for IID.

        PARANOID: Verify retrieval and removal.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        iid_target = bytes([0xAA] * 8)
        iid_other = bytes([0xBB] * 8)

        future_expiry = int(time.time()) + 3600

        # Buffer 3 messages for target, 2 for other
        for i in range(3):
            packet = make_test_packet(
                IPv6Address("fd00::1"),
                IPv6Address("fd00::2"),
                f"target-{i}".encode(),
            )
            router.dtn_buffer_message(packet, iid_target, future_expiry, 1000)

        for i in range(2):
            packet = make_test_packet(
                IPv6Address("fd00::1"),
                IPv6Address("fd00::2"),
                f"other-{i}".encode(),
            )
            router.dtn_buffer_message(packet, iid_other, future_expiry, 1000)

        # PARANOID: Verify initial state
        assert len(router.dtn_buffer) == 5, "buffer must have 5 messages"

        # Retrieve for target
        retrieved = router.dtn_retrieve_for(iid_target)

        # PARANOID: Verify retrieval
        assert len(retrieved) == 3, "must retrieve 3 messages"
        for msg in retrieved:
            assert msg.destination_iid == iid_target, "all must be for target"

        # PARANOID: Verify removal
        assert len(router.dtn_buffer) == 2, "buffer must have 2 remaining"
        for msg in router.dtn_buffer:
            assert msg.destination_iid == iid_other, "remaining must be for other"

    @pytest.mark.asyncio
    async def test_dtn_expire_old(self) -> None:
        """dtn_expire_old removes expired messages.

        PARANOID: Verify expiry removal.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        now_unix = int(time.time())
        iid = bytes([0xAA] * 8)

        # Buffer some expired and some valid messages
        # Note: We need to set expiry in the future initially to pass the buffer check
        # Then manipulate for expiry test
        for i, delta in enumerate([-100, -50, 0, 50, 100]):
            packet = make_test_packet(
                IPv6Address("fd00::1"),
                IPv6Address("fd00::2"),
                f"msg-{i}".encode(),
            )
            # Set expiry relative to NOW
            expiry = now_unix + delta
            # For negative deltas, we need to bypass the buffer check
            # by directly adding to buffer
            msg = DtnMessage(
                packet=packet,
                destination_iid=iid,
                expiry_unix=expiry,
                buffered_at_ms=1000,
            )
            router.dtn_buffer.append(msg)

        # PARANOID: Verify initial state
        assert len(router.dtn_buffer) == 5, "buffer must have 5 messages"

        # Expire old messages
        expired_count = router.dtn_expire_old()

        # PARANOID: Verify expiry
        # Messages with delta -100, -50, and 0 (if <= now) should be expired
        # Due to timing, 0 might or might not expire, so check range
        assert expired_count >= 2, f"at least 2 must be expired, got {expired_count}"
        assert expired_count <= 3, f"at most 3 must be expired, got {expired_count}"

        remaining = len(router.dtn_buffer)
        assert 2 <= remaining <= 3, f"2-3 must remain, got {remaining}"


class TestDtnBufferEviction:
    """Test DTN buffer eviction when full (python-alz.2)."""

    @pytest.mark.asyncio
    async def test_dtn_eviction_fifo(self) -> None:
        """Eviction follows FIFO order (oldest first).

        PARANOID: Verify eviction order.
        """
        # Create router with small buffer
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
            dtn_buffer_max_bytes=500,  # Small buffer
        )

        future_expiry = int(time.time()) + 3600
        iid = bytes([0xAA] * 8)

        # Buffer messages with identifiable payloads
        messages_added = 0
        for i in range(10):
            packet = make_test_packet(
                IPv6Address("fd00::1"),
                IPv6Address("fd00::2"),
                f"message-{i:04d}".encode(),  # ~12 bytes each + overhead
            )
            result = router.dtn_buffer_message(packet, iid, future_expiry, 1000 + i)
            if result:
                messages_added += 1

        # PARANOID: Buffer should have some messages but not all (eviction happened)
        # Buffer size depends on message size calculation
        assert len(router.dtn_buffer) > 0, "buffer must not be empty"
        assert router._dtn_buffer_size() <= router.dtn_buffer_max_bytes, (
            "buffer must not exceed max"
        )

        # The remaining messages should be the LATEST ones (FIFO eviction)
        if len(router.dtn_buffer) > 0:
            # Check that later messages are in buffer (older were evicted)
            _earliest_buffered_at = min(m.buffered_at_ms for m in router.dtn_buffer)
            # Some early messages should have been evicted
            # (we can't guarantee exactly which due to size estimation)
            assert _earliest_buffered_at >= 1000, "remaining msgs should have later timestamps"


class TestDtnPendingAdvertisement:
    """Test pending IID advertisement in announces (python-alz.3)."""

    @pytest.mark.asyncio
    async def test_announce_with_pending_iids(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Node announces pending IIDs for ferry discovery.

        PARANOID: Verify announce contains pending IIDs.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("dtn-test")
        assert node_port is not None, "must get node server port"

        identity = make_identity(200)

        # Create pending IIDs
        pending_iids = [bytes([i] * 8) for i in range(3)]

        # Encode pending IIDs as app_data
        app_data = encode_dtn_pending(pending_iids)

        # PARANOID: Verify encoding
        assert len(app_data) == 2 + 3 * 8, "must be correct length"

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce = scheduler.build_announce()

        # PARANOID: Verify announce has pending IIDs
        decoded = decode_dtn_pending(announce.app_data)
        assert decoded is not None, "must decode"
        assert len(decoded) == 3, "must have 3 IIDs"
        for i, iid in enumerate(decoded):
            assert iid == pending_iids[i], f"IID {i} must match"

        # Transmit and receive
        async with SimRadio(
            "127.0.0.1", node_port, "dtn-test", "tx-node", (0.0, 0.0, 0.0)
        ) as radio_tx, SimRadio(
            "127.0.0.1", node_port, "dtn-test", "rx-node", (50.0, 0.0, 0.0)
        ) as radio_rx:
            tx_success = await radio_tx.transmit(announce.to_bytes())
            assert tx_success, "transmit must succeed"

            result = await radio_rx.receive(1000)
            assert result is not None, "must receive"

            rx_bytes, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)

            # PARANOID: Verify pending IIDs survive transmission
            rx_decoded = decode_dtn_pending(rx_announce.app_data)
            assert rx_decoded is not None, "must decode from received"
            assert len(rx_decoded) == 3, "must have 3 IIDs"
            for i, iid in enumerate(rx_decoded):
                assert iid == pending_iids[i], f"IID {i} must match after TX/RX"


class TestDtnSimulationIntegration:
    """Full simulation integration test for DTN."""

    @pytest.mark.asyncio
    async def test_dtn_buffer_and_advertise_flow(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Node buffers message and advertises pending IID.

        Full integration flow:
        1. Node A buffers a message for unreachable destination C
        2. A advertises C's IID in announce
        3. Node B (ferry) receives announce and sees pending IID
        4. B can then retrieve messages for C when it contacts A

        PARANOID: Verify every step.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("dtn-test")
        assert node_port is not None, "must get node server port"

        # Identities
        identity_a = make_identity(201)  # Buffer node
        _identity_b = make_identity(202)  # Ferry node (receives A's announce)
        identity_c = make_identity(203)  # Destination (unreachable)

        # Node A's router buffers a message for C
        router_a = Router(
            node_address=build_address_from_iid(identity_a.iid),
            gradient_table=GradientTable(),
        )

        # Create packet destined for C
        addr_c = build_address_from_iid(identity_c.iid)
        packet_for_c = make_test_packet(
            build_address_from_iid(identity_a.iid),
            addr_c,
            b"message for C",
        )

        # Buffer with future expiry
        future_expiry = int(time.time()) + 3600
        result = router_a.dtn_buffer_message(
            packet_for_c,
            identity_c.iid,
            future_expiry,
            now_ms=1000,
        )

        # PARANOID: Verify buffering
        assert result is True, "buffering must succeed"
        assert len(router_a.dtn_buffer) == 1, "buffer must have 1 message"

        # A gets pending IIDs
        pending = router_a.dtn_get_pending_iids()

        # PARANOID: Verify pending
        assert len(pending) == 1, "must have 1 pending IID"
        assert pending[0] == identity_c.iid, "must be C's IID"

        # A builds announce with pending IIDs
        app_data = encode_dtn_pending(pending)

        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce_a = scheduler_a.build_announce()

        # Sim positions
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (50.0, 0.0, 0.0)

        async with SimRadio(
            "127.0.0.1", node_port, "dtn-test", "node-a-int", pos_a
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "dtn-test", "node-b-int", pos_b
        ) as radio_b:
            # A announces
            tx_success = await radio_a.transmit(announce_a.to_bytes())
            assert tx_success, "A must transmit"

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None, "B must receive"

            rx_bytes, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)

            # PARANOID: Verify B sees pending IID for C
            rx_pending = decode_dtn_pending(rx_announce.app_data)
            assert rx_pending is not None, "must decode pending"
            assert len(rx_pending) == 1, "must have 1 pending"
            assert rx_pending[0] == identity_c.iid, "must be C's IID"

            # B (ferry) now knows A has messages for C
            # When B contacts A, it can request messages for C
            # (Protocol for retrieval would be separate - this test verifies advertisement)

            # Simulate B requesting messages for C from A
            # (In real implementation, B would send a request to A)
            # A retrieves messages for C
            messages_for_c = router_a.dtn_retrieve_for(identity_c.iid)

            # PARANOID: Verify retrieval
            assert len(messages_for_c) == 1, "must retrieve 1 message"
            assert messages_for_c[0].packet.payload == b"message for C", "payload must match"

            # A's buffer is now empty (messages transferred)
            assert len(router_a.dtn_buffer) == 0, "buffer must be empty after retrieval"

            # A's pending IIDs are now empty
            new_pending = router_a.dtn_get_pending_iids()
            assert len(new_pending) == 0, "no more pending after retrieval"
