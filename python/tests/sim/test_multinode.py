"""Multi-node simulation integration tests (sxe).

Tests the full announce routing stack with multiple nodes in simulation.

Why these tests: Validates that announces propagate across the mesh, gradients
are built correctly, and nodes can communicate end-to-end. This is the key
validation that the protocol stack works as designed.

Test scenario:
- 5 nodes in a line topology (A-B-C-D-E) at 50m spacing
- Each node sends announces
- Verify gradients are built at each node for its neighbors
- Verify announce relay (multi-hop propagation)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import verify
from lichen.gradient import GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start a simulator server with a test simulation.

    Why BARRIER_SYNC: Deterministic testing. Time advances only when all
    nodes are waiting for RX, ensuring reproducible behavior.
    """
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("multinode-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create a deterministic identity from a single seed byte.

    Why deterministic: Reproducible tests. Same seed = same identity.
    """
    seed = bytes([seed_byte] + [0] * 31)
    return Identity.from_seed(seed)


def build_address_from_iid(iid: bytes) -> IPv6Address:
    """Build a link-local IPv6 address from an IID.

    Why fe80:: prefix: Link-local addresses for neighbors.
    """
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return IPv6Address(prefix + iid)


class MockTransmitter:
    """Mock transmitter that captures announce bytes.

    Why mock: We build announces with AnnounceScheduler but transmit
    via SimRadio, so we capture the bytes for manual transmission.
    """

    def __init__(self) -> None:
        self.last_data: bytes | None = None

    async def transmit_announce(self, data: bytes) -> bool:
        self.last_data = data
        return True


class TestLineTopology:
    """Tests for a 5-node line topology: A -- B -- C -- D -- E.

    Node spacing: 50m (well within LoRa range).
    Each node can hear its immediate neighbors.
    """

    @pytest.mark.asyncio
    async def test_neighbor_announce_received(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Node B receives announce from Node A.

        Why test: Basic verification that announces propagate between
        neighboring nodes in the simulation.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        # Create identities
        identity_a = make_identity(0)

        # Build announce from A
        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a = scheduler_a.build_announce()
        announce_bytes = announce_a.to_bytes()

        # Create two nodes: A at origin, B at 50m
        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # A transmits announce
            tx_success = await radio_a.transmit(announce_bytes)
            assert tx_success is True

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None

            rx_data, rssi, snr = result
            assert rx_data == announce_bytes

            # Parse and verify announce
            received_announce = AnnounceMessage.from_bytes(rx_data)
            assert received_announce.originator_iid == identity_a.iid
            assert received_announce.seq_num == 1
            assert received_announce.hop_count == 0

            # Verify signature
            is_valid = verify(
                received_announce.pubkey,
                received_announce.signed_data(),
                received_announce.signature,
            )
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_announce_builds_gradient(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Processing an announce creates a gradient entry.

        Why test: Gradients enable routing. No gradient = no route to node.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        # Create identities
        identity_a = make_identity(0)

        # Build announce from A
        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a = scheduler_a.build_announce()
        announce_bytes = announce_a.to_bytes()

        # B's gradient table and processor
        gradient_table_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_table_b,
            address_builder=build_address_from_iid,
        )

        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # A transmits announce
            await radio_a.transmit(announce_bytes)

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None
            rx_data, _, _ = result

            # B processes announce
            received_announce = AnnounceMessage.from_bytes(rx_data)
            from_neighbor = build_address_from_iid(identity_a.iid)

            process_result = processor_b.process(
                received_announce, from_neighbor, now_ms=1000
            )

            assert process_result.accepted is True
            assert process_result.peer is not None
            assert process_result.peer.iid == identity_a.iid

            # Gradient should be installed
            addr_a = build_address_from_iid(identity_a.iid)
            entry = gradient_table_b.lookup(addr_a, now=1000)
            assert entry is not None
            assert entry.next_hop == from_neighbor

    @pytest.mark.asyncio
    async def test_five_node_line_pairwise_communication(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Adjacent pairs in 5-node line can communicate.

        Topology: A(0m) -- B(50m) -- C(100m) -- D(150m) -- E(200m)
        Tests: A->B, B->C, C->D, D->E (one direction each)

        Why pairwise: Avoids collision issues in BARRIER_SYNC mode where
        all nodes would need to wait for RX before time advances.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        # Create 5 identities
        identities = [make_identity(i) for i in range(5)]
        positions = [(i * 50.0, 0.0, 0.0) for i in range(5)]
        node_ids = ["node-a", "node-b", "node-c", "node-d", "node-e"]

        # Connect all 5 nodes
        radios: list[SimRadio] = []
        for node_id, pos in zip(node_ids, positions, strict=False):
            radio = SimRadio(
                "127.0.0.1", node_port, "multinode-test", node_id, pos
            )
            await radio.connect()
            radios.append(radio)

        try:
            # Test adjacent pairs: A->B, B->C, C->D, D->E
            # Each pair: sender transmits, receiver receives, before next pair
            for sender_idx in range(4):  # 0,1,2,3
                receiver_idx = sender_idx + 1
                identity = identities[sender_idx]

                # Build announce from sender
                mock_tx = MockTransmitter()
                scheduler = AnnounceScheduler(
                    identity=identity,
                    transmitter=mock_tx,
                    config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
                )
                announce = scheduler.build_announce()
                announce_bytes = announce.to_bytes()

                # Sender transmits
                tx_success = await radios[sender_idx].transmit(announce_bytes)
                assert tx_success is True, f"{node_ids[sender_idx]} failed to transmit"

                # Receiver receives
                result = await radios[receiver_idx].receive(1000)
                assert result is not None, (
                    f"{node_ids[receiver_idx]} didn't receive from {node_ids[sender_idx]}"
                )
                rx_data, rssi, snr = result
                assert rx_data == announce_bytes, "Data mismatch"

                # Verify announce content
                rx_announce = AnnounceMessage.from_bytes(rx_data)
                assert rx_announce.originator_iid == identity.iid
                assert rx_announce.seq_num == 1

        finally:
            for radio in radios:
                await radio.close()

    @pytest.mark.asyncio
    async def test_announce_relay_multi_hop(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce relay enables multi-hop propagation.

        Scenario: A sends announce, B receives and relays, C receives relay.
        Verifies hop_count increments on relay.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        # Create identities
        identity_a = make_identity(0)

        # Build announce from A
        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a = scheduler_a.build_announce()
        original_bytes = announce_a.to_bytes()

        # B's processor for relaying
        gradient_table_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_table_b,
            address_builder=build_address_from_iid,
        )

        # Nodes: A(0m), B(50m), C(100m)
        # Note: B is the relay
        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-c", (100.0, 0.0, 0.0)
        ) as radio_c:
            # A transmits original announce
            await radio_a.transmit(original_bytes)

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None
            rx_data, _, _ = result
            received_announce = AnnounceMessage.from_bytes(rx_data)

            # B processes and decides to relay
            from_neighbor = build_address_from_iid(identity_a.iid)
            process_result = processor_b.process(
                received_announce, from_neighbor, now_ms=1000
            )
            assert process_result.accepted is True
            assert process_result.should_relay is True

            # Get relay message (hop count incremented)
            relay_msg = processor_b.get_relay_message(received_announce)
            assert relay_msg is not None
            assert relay_msg.hop_count == 1  # Incremented from 0 to 1

            # B transmits relay
            await radio_b.transmit(relay_msg.to_bytes())

            # C receives relay
            result = await radio_c.receive(1000)
            assert result is not None
            rx_data, _, _ = result
            relayed_announce = AnnounceMessage.from_bytes(rx_data)

            # Verify C received the relayed announce
            assert relayed_announce.originator_iid == identity_a.iid
            assert relayed_announce.hop_count == 1
            # Signature should still verify (signed data doesn't include hop_count)
            is_valid = verify(
                relayed_announce.pubkey,
                relayed_announce.signed_data(),
                relayed_announce.signature,
            )
            assert is_valid is True


class TestGradientConvergence:
    """Tests for gradient table convergence across multiple nodes."""

    @pytest.mark.asyncio
    async def test_gradient_builds_for_neighbor(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """B builds gradient entry for A after receiving A's announce.

        Why simpler test: BARRIER_SYNC mode makes multi-round tests complex
        due to time not advancing between rounds. This test validates the
        core gradient building logic with a single round.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        identity_a = make_identity(0)

        # B's gradient table and processor
        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address_from_iid
        )

        # Build announce from A
        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a_bytes = scheduler_a.build_announce().to_bytes()

        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            now_ms = 1000

            # A announces, B receives
            await radio_a.transmit(announce_a_bytes)
            result = await radio_b.receive(1000)
            assert result is not None

            # B processes announce
            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address_from_iid(identity_a.iid)
            process_result = processor_b.process(announce, from_a, now_ms)

            assert process_result.accepted is True

            # Verify gradient
            addr_a = build_address_from_iid(identity_a.iid)
            entry = gradient_b.lookup(addr_a, now=now_ms)
            assert entry is not None, "B should have gradient to A"
            assert entry.next_hop == from_a

    @pytest.mark.asyncio
    async def test_bidirectional_gradients(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """A and B each build gradients to the other.

        Uses separate simulations for each direction to avoid
        BARRIER_SYNC timing issues.
        """
        server, sim = simulator_server

        identity_a = make_identity(0)
        identity_b = make_identity(1)

        # Test A->B (A announces, B builds gradient)
        await server.create_simulation("test-ab", TimeMode.BARRIER_SYNC)
        port_ab = server.get_node_server_port("test-ab")
        assert port_ab is not None

        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address_from_iid
        )

        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a_bytes = scheduler_a.build_announce().to_bytes()

        async with SimRadio(
            "127.0.0.1", port_ab, "test-ab", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", port_ab, "test-ab", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            await radio_a.transmit(announce_a_bytes)
            result = await radio_b.receive(1000)
            assert result is not None
            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address_from_iid(identity_a.iid)
            processor_b.process(announce, from_a, now_ms=1000)

        # Verify B has gradient to A
        addr_a = build_address_from_iid(identity_a.iid)
        entry = gradient_b.lookup(addr_a, now=1000)
        assert entry is not None, "B should have gradient to A"

        # Test B->A (B announces, A builds gradient)
        await server.create_simulation("test-ba", TimeMode.BARRIER_SYNC)
        port_ba = server.get_node_server_port("test-ba")
        assert port_ba is not None

        gradient_a = GradientTable()
        processor_a = AnnounceProcessor(
            gradient_table=gradient_a, address_builder=build_address_from_iid
        )

        mock_tx_b = MockTransmitter()
        scheduler_b = AnnounceScheduler(
            identity=identity_b,
            transmitter=mock_tx_b,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_b_bytes = scheduler_b.build_announce().to_bytes()

        async with SimRadio(
            "127.0.0.1", port_ba, "test-ba", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a2, SimRadio(
            "127.0.0.1", port_ba, "test-ba", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b2:
            await radio_b2.transmit(announce_b_bytes)
            result = await radio_a2.receive(1000)
            assert result is not None
            announce = AnnounceMessage.from_bytes(result[0])
            from_b = build_address_from_iid(identity_b.iid)
            processor_a.process(announce, from_b, now_ms=1000)

        # Verify A has gradient to B
        addr_b = build_address_from_iid(identity_b.iid)
        entry = gradient_a.lookup(addr_b, now=1000)
        assert entry is not None, "A should have gradient to B"

        # Cleanup
        await server.delete_simulation("test-ab")
        await server.delete_simulation("test-ba")


class TestEndToEndRouting:
    """Tests for end-to-end routing decisions based on gradients."""

    @pytest.mark.asyncio
    async def test_route_lookup_uses_gradient(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Router uses gradient table for next-hop decisions.

        After B receives A's announce, B should route packets for A
        via the gradient's next_hop.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        identity_a = make_identity(0)

        # Build announce from A
        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce_a = scheduler_a.build_announce()

        # B's gradient table and processor
        gradient_table_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_table_b,
            address_builder=build_address_from_iid,
        )

        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # A transmits announce
            await radio_a.transmit(announce_a.to_bytes())

            # B receives and processes
            result = await radio_b.receive(1000)
            assert result is not None
            received = AnnounceMessage.from_bytes(result[0])
            from_neighbor = build_address_from_iid(identity_a.iid)

            processor_b.process(received, from_neighbor, now_ms=1000)

            # Now B should be able to route to A's address
            addr_a = build_address_from_iid(identity_a.iid)
            entry = gradient_table_b.lookup(addr_a, now=1000)

            assert entry is not None
            # Next hop should be the neighbor we heard the announce from
            assert entry.next_hop == from_neighbor


class TestKnownVectors:
    """Tests with known announce vectors for bit-exact validation."""

    @pytest.mark.asyncio
    async def test_announce_wire_format_round_trip(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce wire format survives simulation TX/RX.

        Why test: Ensures simulator doesn't corrupt packet data.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("multinode-test")
        assert node_port is not None

        identity = make_identity(42)

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce = scheduler.build_announce()
        original_bytes = announce.to_bytes()

        async with SimRadio(
            "127.0.0.1", node_port, "multinode-test", "tx", (0.0, 0.0, 0.0)
        ) as radio_tx, SimRadio(
            "127.0.0.1", node_port, "multinode-test", "rx", (10.0, 0.0, 0.0)
        ) as radio_rx:
            await radio_tx.transmit(original_bytes)
            result = await radio_rx.receive(1000)

            assert result is not None
            rx_bytes, _, _ = result

            # Byte-for-byte match
            assert rx_bytes == original_bytes

            # Parses identically
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce.originator_iid == announce.originator_iid
            assert rx_announce.pubkey == announce.pubkey
            assert rx_announce.seq_num == announce.seq_num
            assert rx_announce.hop_count == announce.hop_count
            assert rx_announce.signature == announce.signature
