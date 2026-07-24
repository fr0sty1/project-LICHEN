# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulation integration tests for backpressure congestion routing (spec 11.4).

Tests verify that:
1. Announces carry queue depth (congestion) in app_data
2. Nodes extract and store neighbor queue depths from announces
3. Router tracks congestion levels for path selection decisions

Paranoid defensive style: explicit assertions at every step, guard against
None values aggressively, verify invariants.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.coords import (
    APP_DATA_TYPE_CONGESTION,
    decode_congestion,
    encode_congestion,
)
from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.gradient import GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.routing.router import Router
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

    sim = await server.create_simulation("backpressure-test", TimeMode.BARRIER_SYNC)

    # PARANOID: Verify simulation was created
    assert sim is not None, "simulation must be created"
    assert sim.id == "backpressure-test", "simulation ID must match"

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


class MockTransmitter:
    """Mock transmitter that captures announce bytes.

    PARANOID: Track all transmissions for verification.
    """

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


class TestCongestionEncoding:
    """Test congestion encoding in announces (python-sso.1)."""

    @pytest.mark.asyncio
    async def test_encode_congestion_in_app_data(self) -> None:
        """Verify queue depth is encoded correctly in app_data.

        PARANOID: Check encoding format byte-by-byte.
        """
        queue_depth = 42

        # PARANOID: Verify queue_depth is in valid range
        assert 0 <= queue_depth <= 255, f"queue_depth {queue_depth} out of range"

        app_data = encode_congestion(queue_depth)

        # PARANOID: Verify encoding structure
        assert app_data is not None, "encoding must not return None"
        assert len(app_data) == 2, f"congestion app_data must be 2 bytes, got {len(app_data)}"
        assert app_data[0] == APP_DATA_TYPE_CONGESTION, "first byte must be congestion type"
        assert app_data[1] == queue_depth, "second byte must be queue_depth"

        # Verify round-trip decoding
        decoded = decode_congestion(app_data)
        assert decoded is not None, "decoding must succeed"
        assert decoded == queue_depth, f"decoded value {decoded} must match {queue_depth}"

    @pytest.mark.asyncio
    async def test_encode_congestion_boundary_values(self) -> None:
        """Test encoding at boundary values (0, 255).

        PARANOID: Verify boundary conditions.
        """
        # Test minimum value
        app_data_min = encode_congestion(0)
        assert len(app_data_min) == 2, "must be 2 bytes"
        assert app_data_min[1] == 0, "must encode 0"

        decoded_min = decode_congestion(app_data_min)
        assert decoded_min == 0, "must decode to 0"

        # Test maximum value
        app_data_max = encode_congestion(255)
        assert len(app_data_max) == 2, "must be 2 bytes"
        assert app_data_max[1] == 255, "must encode 255"

        decoded_max = decode_congestion(app_data_max)
        assert decoded_max == 255, "must decode to 255"

    @pytest.mark.asyncio
    async def test_encode_congestion_out_of_range(self) -> None:
        """Test that out-of-range values raise ValueError.

        PARANOID: Verify error handling.
        """
        # Test value above max
        with pytest.raises(ValueError, match="queue_depth"):
            encode_congestion(256)

        # Test negative value
        with pytest.raises(ValueError, match="queue_depth"):
            encode_congestion(-1)

    @pytest.mark.asyncio
    async def test_scheduler_builds_announce_with_congestion(self) -> None:
        """AnnounceScheduler includes congestion in announce app_data.

        PARANOID: Verify every field of the announce.
        """
        identity = make_identity(100)
        queue_depth = 50

        # Encode congestion as app_data
        app_data = encode_congestion(queue_depth)
        assert len(app_data) == 2, "congestion must be 2 bytes"

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        # Build announce
        announce = scheduler.build_announce()

        # PARANOID: Verify announce structure
        assert announce is not None, "announce must be built"
        assert announce.originator_iid == identity.iid, "IID must match"
        assert announce.pubkey == identity.pubkey, "pubkey must match"
        assert announce.seq_num == 1, "first seq_num must be 1"
        assert announce.hop_count == 0, "originator hop_count must be 0"
        assert announce.signature is not None, "signature must be present"

        # PARANOID: Verify app_data contains congestion
        assert announce.app_data == app_data, "app_data must contain congestion"

        # Verify congestion can be decoded from announce
        decoded = decode_congestion(announce.app_data)
        assert decoded is not None, "congestion must be decodable from announce"
        assert decoded == queue_depth, "queue_depth must match"


class TestCongestionTransmission:
    """Test congestion data survives simulation transmission (python-sso.1)."""

    @pytest.mark.asyncio
    async def test_announce_with_congestion_survives_transmission(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce with congestion survives simulation TX/RX.

        PARANOID: Verify byte-for-byte match after transmission.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("backpressure-test")

        # PARANOID: Verify we got a valid port
        assert node_port is not None, "must get node server port"
        assert node_port > 0, "port must be positive"

        identity = make_identity(101)
        queue_depth = 75

        app_data = encode_congestion(queue_depth)

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce = scheduler.build_announce()
        original_bytes = announce.to_bytes()

        # PARANOID: Verify serialization
        assert original_bytes is not None, "serialization must succeed"
        assert len(original_bytes) > 0, "serialized announce must not be empty"

        async with (
            SimRadio(
                "127.0.0.1", node_port, "backpressure-test", "tx-node", (0.0, 0.0, 0.0)
            ) as radio_tx,
            SimRadio(
                "127.0.0.1", node_port, "backpressure-test", "rx-node", (50.0, 0.0, 0.0)
            ) as radio_rx,
        ):
            tx_success = await radio_tx.transmit(original_bytes)
            assert tx_success is True, "transmit must succeed"

            result = await radio_rx.receive(1000)

            # PARANOID: Verify reception
            assert result is not None, "must receive data"

            rx_bytes, rssi, snr = result

            # PARANOID: Verify signal quality
            assert rssi is not None, "rssi must be present"
            assert snr is not None, "snr must be present"
            assert rssi > -140, f"rssi {rssi} too weak (below sensitivity)"

            # PARANOID: Verify byte-for-byte match
            assert rx_bytes == original_bytes, "received bytes must match sent bytes"

            # Parse and verify congestion survives
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"

            rx_congestion = decode_congestion(rx_announce.app_data)
            assert rx_congestion is not None, "congestion must be decodable"
            assert rx_congestion == queue_depth, "queue_depth must match after TX/RX"


class TestQueueDepthTracking:
    """Test Router tracks neighbor queue depths (python-sso.2)."""

    @pytest.mark.asyncio
    async def test_update_neighbor_queue_depth(self) -> None:
        """Router.update_neighbor_queue_depth stores depth correctly.

        PARANOID: Verify storage and retrieval.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        neighbor = IPv6Address("fe80::2")
        depth = 100

        # PARANOID: Verify no depth initially
        initial = router.get_neighbor_queue_depth(neighbor)
        assert initial == 0, "unknown neighbor should return 0"

        # Update depth
        router.update_neighbor_queue_depth(neighbor, depth)

        # PARANOID: Verify depth is stored
        stored = router.get_neighbor_queue_depth(neighbor)
        assert stored == depth, f"stored depth {stored} must match {depth}"

    @pytest.mark.asyncio
    async def test_update_neighbor_queue_depth_overwrites(self) -> None:
        """Updating queue depth overwrites previous value.

        PARANOID: Verify overwrite behavior.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        neighbor = IPv6Address("fe80::2")

        # Set initial depth
        router.update_neighbor_queue_depth(neighbor, 50)
        assert router.get_neighbor_queue_depth(neighbor) == 50, "initial depth"

        # Update to new depth
        router.update_neighbor_queue_depth(neighbor, 200)
        assert router.get_neighbor_queue_depth(neighbor) == 200, "updated depth"

        # Update to lower depth
        router.update_neighbor_queue_depth(neighbor, 10)
        assert router.get_neighbor_queue_depth(neighbor) == 10, "lowered depth"

    @pytest.mark.asyncio
    async def test_multiple_neighbors_independent(self) -> None:
        """Queue depths for different neighbors are independent.

        PARANOID: Verify neighbor isolation.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        neighbor_a = IPv6Address("fe80::a")
        neighbor_b = IPv6Address("fe80::b")
        neighbor_c = IPv6Address("fe80::c")

        # Set different depths for each
        router.update_neighbor_queue_depth(neighbor_a, 10)
        router.update_neighbor_queue_depth(neighbor_b, 100)
        router.update_neighbor_queue_depth(neighbor_c, 255)

        # PARANOID: Verify each is independent
        assert router.get_neighbor_queue_depth(neighbor_a) == 10, "A depth"
        assert router.get_neighbor_queue_depth(neighbor_b) == 100, "B depth"
        assert router.get_neighbor_queue_depth(neighbor_c) == 255, "C depth"

        # Update one, others unchanged
        router.update_neighbor_queue_depth(neighbor_b, 50)

        assert router.get_neighbor_queue_depth(neighbor_a) == 10, "A unchanged"
        assert router.get_neighbor_queue_depth(neighbor_b) == 50, "B updated"
        assert router.get_neighbor_queue_depth(neighbor_c) == 255, "C unchanged"


class TestCongestionExtraction:
    """Test processor extracts congestion from announces (python-sso.2)."""

    @pytest.mark.asyncio
    async def test_processor_returns_congestion(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """AnnounceProcessor returns congestion in result.

        PARANOID: Verify congestion is extracted and returned.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("backpressure-test")
        assert node_port is not None, "must get node server port"

        identity_a = make_identity(102)
        queue_depth = 150

        app_data = encode_congestion(queue_depth)

        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce_a = scheduler_a.build_announce()
        announce_bytes = announce_a.to_bytes()

        # Node B's processor
        gradient_table_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_table_b,
            address_builder=build_address_from_iid,
        )

        async with (
            SimRadio(
                "127.0.0.1", node_port, "backpressure-test", "node-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "backpressure-test", "node-b", (50.0, 0.0, 0.0)
            ) as radio_b,
        ):
            # A transmits
            tx_success = await radio_a.transmit(announce_bytes)
            assert tx_success is True, "A must transmit successfully"

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None, "B must receive announce"

            rx_bytes, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"

            # B processes
            from_neighbor = build_address_from_iid(identity_a.iid)
            process_result = processor_b.process(rx_announce, from_neighbor, now_ms=1000)

            # PARANOID: Verify processing succeeded
            assert process_result.accepted is True, "announce must be accepted"
            assert process_result.peer is not None, "peer identity must be returned"

            # PARANOID: Verify congestion is in result
            assert process_result.congestion is not None, "congestion must be in result"
            assert process_result.congestion == queue_depth, (
                f"congestion {process_result.congestion} must match {queue_depth}"
            )


class TestCongestionAwareRouting:
    """Test congestion-aware path selection (python-sso.3)."""

    @pytest.mark.asyncio
    async def test_router_can_compare_path_congestion(self) -> None:
        """Router can compare congestion between different paths.

        This is a foundational test - the actual path selection logic
        would be implemented in a higher layer that uses this data.

        PARANOID: Verify congestion data is accessible for comparison.
        """
        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        # Two possible next-hops with different congestion levels
        path_a = IPv6Address("fe80::a")  # Light load
        path_b = IPv6Address("fe80::b")  # Heavy load

        router.update_neighbor_queue_depth(path_a, 10)  # 10 packets queued
        router.update_neighbor_queue_depth(path_b, 200)  # 200 packets queued

        # PARANOID: Verify we can compare
        depth_a = router.get_neighbor_queue_depth(path_a)
        depth_b = router.get_neighbor_queue_depth(path_b)

        assert depth_a < depth_b, "path_a must have less congestion"

        # Select less congested path
        selected = path_a if depth_a <= depth_b else path_b

        assert selected == path_a, "should select path_a (less congested)"

    @pytest.mark.asyncio
    async def test_congestion_comparison_with_equal_hops(self) -> None:
        """When hop counts are equal, congestion should be the tiebreaker.

        PARANOID: Verify congestion can serve as tiebreaker.
        """
        from lichen.gradient import GradientEntry, GradientSource

        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        destination = IPv6Address("fd00::dead")
        path_a = IPv6Address("fe80::a")
        path_b = IPv6Address("fe80::b")

        # Both paths have same hop count to destination
        entry_a = GradientEntry(
            destination=destination,
            next_hop=path_a,
            hop_count=2,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=10000,
        )
        entry_b = GradientEntry(
            destination=destination,
            next_hop=path_b,
            hop_count=2,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=10000,
        )

        # Path A has lower congestion
        router.update_neighbor_queue_depth(path_a, 20)
        router.update_neighbor_queue_depth(path_b, 150)

        # PARANOID: Verify equal hop counts
        assert entry_a.hop_count == entry_b.hop_count, "hop counts must be equal"

        # Congestion tiebreaker
        depth_a = router.get_neighbor_queue_depth(entry_a.next_hop)
        depth_b = router.get_neighbor_queue_depth(entry_b.next_hop)

        assert depth_a < depth_b, "A must have less congestion"

        # Path selection logic (application of backpressure)
        # If hop counts equal, prefer less congested path
        if entry_a.hop_count == entry_b.hop_count:
            selected_hop = entry_a.next_hop if depth_a <= depth_b else entry_b.next_hop
        elif entry_a.hop_count < entry_b.hop_count:
            selected_hop = entry_a.next_hop
        else:
            selected_hop = entry_b.next_hop

        assert selected_hop == path_a, "should select less congested path"


class TestBackpressureSimulationIntegration:
    """Full simulation integration test for backpressure."""

    @pytest.mark.asyncio
    async def test_announce_with_congestion_builds_neighbor_knowledge(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce with congestion allows neighbor load knowledge to be built.

        Full integration flow:
        1. B announces with queue_depth
        2. A receives and extracts congestion
        3. A can use that info for routing decisions

        PARANOID: Verify every step of the process.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("backpressure-test")

        assert node_port is not None, "must get node server port"

        # Create identities
        identity_a = make_identity(103)
        identity_b = make_identity(104)

        # B has moderate congestion
        queue_depth_b = 80

        # Build B's announce with congestion
        mock_tx = MockTransmitter()
        scheduler_b = AnnounceScheduler(
            identity=identity_b,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=encode_congestion(queue_depth_b),
        )
        announce_b = scheduler_b.build_announce()

        # Node A's state
        gradient_a = GradientTable()
        processor_a = AnnounceProcessor(
            gradient_table=gradient_a,
            address_builder=build_address_from_iid,
        )

        # Sim positions
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (50.0, 0.0, 0.0)

        async with (
            SimRadio("127.0.0.1", node_port, "backpressure-test", "node-a-int", pos_a) as radio_a,
            SimRadio("127.0.0.1", node_port, "backpressure-test", "node-b-int", pos_b) as radio_b,
        ):
            # B announces
            tx_success = await radio_b.transmit(announce_b.to_bytes())
            assert tx_success, "B must transmit successfully"

            # A receives
            result = await radio_a.receive(1000)
            assert result is not None, "A must receive B's announce"

            rx_bytes, rssi, snr = result

            # PARANOID: Verify signal quality
            assert rssi > -140, f"rssi {rssi} too weak"

            # Parse announce
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"
            assert rx_announce.originator_iid == identity_b.iid, "must be B's announce"

            # A processes announce
            from_b = build_address_from_iid(identity_b.iid)
            process_result = processor_a.process(rx_announce, from_b, now_ms=1000)

            # PARANOID: Verify processing
            assert process_result.accepted, "announce must be accepted"

            # PARANOID: Verify congestion is extracted
            assert process_result.congestion is not None, "congestion must be extracted"
            assert process_result.congestion == queue_depth_b, "congestion must match"

            # Now A creates a router and updates congestion info
            router_a = Router(
                node_address=build_address_from_iid(identity_a.iid),
                gradient_table=gradient_a,
            )

            # A learns B's queue depth
            router_a.update_neighbor_queue_depth(from_b, process_result.congestion)

            # PARANOID: Verify router knows B's congestion
            stored_depth = router_a.get_neighbor_queue_depth(from_b)
            assert stored_depth == queue_depth_b, (
                f"stored depth {stored_depth} must match {queue_depth_b}"
            )

            # A can now use this info for routing decisions
            # e.g., if another path has lower congestion, prefer it
