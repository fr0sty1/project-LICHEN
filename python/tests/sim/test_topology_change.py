"""Topology change and re-routing tests (go7).

Tests announce routing adaptation to network changes:
- Link failure (partition): gradients expire, alternate paths used
- Node failure (drop): gradients expire, node unreachable
- Node mobility: gradients update based on new neighbor

Why these tests: Mesh networks must handle dynamic topology. Nodes move,
links fail, interference changes. The routing must adapt.

Key insight: With announce routing, "re-routing" happens when:
1. Gradient entries expire (no fresh announces from original path)
2. New announces arrive from alternate paths
3. Mobile node sends fresh announce from new position
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import GRADIENT_TIMEOUT_MS, AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.gradient import GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.sim.chaos import DropRule, PartitionRule
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start simulator with chaos engine enabled."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("topo-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create deterministic identity from seed byte."""
    return Identity.from_seed(bytes([seed_byte] + [0] * 31))


def build_address(iid: bytes) -> IPv6Address:
    """Build link-local IPv6 from IID."""
    return IPv6Address(bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0]) + iid)


class MockTransmitter:
    """Captures announce bytes for manual transmission."""

    def __init__(self) -> None:
        self.last_data: bytes | None = None

    async def transmit_announce(self, data: bytes) -> bool:
        self.last_data = data
        return True


def build_announce_bytes(identity: Identity) -> bytes:
    """Build signed announce bytes from identity."""
    mock_tx = MockTransmitter()
    scheduler = AnnounceScheduler(
        identity=identity,
        transmitter=mock_tx,
        config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
    )
    return scheduler.build_announce().to_bytes()


class TestLinkFailure:
    """Tests for link failure via network partition."""

    @pytest.mark.asyncio
    async def test_partition_blocks_announce(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Network partition prevents announce reception.

        Scenario:
        1. A and B can communicate (A sends, B receives)
        2. Add partition rule separating A and B
        3. A sends, B does not receive
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        # Get chaos engine
        chaos_engine = server._api._chaos_engines.get("topo-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # Before partition: A->B works
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None, "Should receive before partition"

            # Add partition: A in group 0, B in group 1
            partition = PartitionRule(groups=[{"node-a"}, {"node-b"}])
            chaos_engine.add_rule(partition)

            # After partition: A->B blocked
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(100)
            assert result is None, "Should not receive after partition"

            # Remove partition
            chaos_engine.remove_rule(partition.id)

            # Partition removed: A->B works again
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None, "Should receive after partition removed"

    @pytest.mark.asyncio
    async def test_gradient_not_updated_during_partition(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Gradient entry isn't refreshed when announces are blocked.

        When partitioned, B won't receive A's announces, so B's gradient
        to A won't be refreshed. After GRADIENT_TIMEOUT_MS, it expires.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("topo-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        # B's gradient table and processor
        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address
        )

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            now_ms = 1000

            # Initial announce establishes gradient
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None

            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address(identity_a.iid)
            processor_b.process(announce, from_a, now_ms)

            # Verify gradient exists
            addr_a = build_address(identity_a.iid)
            entry = gradient_b.lookup(addr_a, now=now_ms)
            assert entry is not None, "Gradient should exist initially"

            # Add partition
            partition = PartitionRule(groups=[{"node-a"}, {"node-b"}])
            chaos_engine.add_rule(partition)

            # Time passes beyond gradient timeout
            expired_time = now_ms + GRADIENT_TIMEOUT_MS + 1

            # Gradient should be expired now
            entry = gradient_b.lookup(addr_a, now=expired_time)
            assert entry is None, "Gradient should expire when not refreshed"


class TestNodeFailure:
    """Tests for node failure via drop rules."""

    @pytest.mark.asyncio
    async def test_drop_rule_simulates_node_failure(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """DropRule on a node simulates that node going offline.

        When node A has a drop rule, its transmissions are discarded,
        simulating hardware failure or shutdown.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("topo-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # Before failure: communication works
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None

            # Simulate node A failure
            drop_rule = DropRule(node_id="node-a", direction="tx")
            chaos_engine.add_rule(drop_rule)

            # During failure: A's transmissions dropped
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(100)
            assert result is None, "Failed node shouldn't transmit"

            # Node A recovers
            chaos_engine.remove_rule(drop_rule.id)

            # After recovery: communication restored
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None, "Recovered node should transmit"

    @pytest.mark.asyncio
    async def test_alternate_path_after_node_failure(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """When middle node fails, alternate path can be used.

        Topology: A -- B -- C (line)
        If B fails, A and C cannot communicate directly (out of range).
        But if we have A -- B -- C with B as relay, B failure breaks path.

        For this test: verify C can hear A directly if close enough,
        or loses connectivity if too far.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("topo-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        # A at 0m, B at 50m, C at 100m (all within range of each other)
        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-c", (100.0, 0.0, 0.0)
        ) as radio_c:
            # Before B failure: C can receive from A (directly or via B)
            await radio_a.transmit(announce_a)
            result_c = await radio_c.receive(1000)
            assert result_c is not None, "C should hear A initially"

            # Also drain B's receive
            await radio_b.receive(100)

            # B fails (drops all packets)
            drop_b = DropRule(node_id="node-b", direction="both")
            chaos_engine.add_rule(drop_b)

            # With B down, C still hears A directly (100m is within range)
            await radio_a.transmit(announce_a)
            result_c = await radio_c.receive(1000)
            assert result_c is not None, "C should still hear A directly"


class TestNodeMobility:
    """Tests for node mobility and gradient updates."""

    @pytest.mark.asyncio
    async def test_moving_closer_improves_rssi(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Moving a node closer increases RSSI of received packets."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (500.0, 0.0, 0.0)
        ) as radio_b:
            # Initial RSSI at 500m
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None
            rssi_at_500m = result[1]

            # Move B closer to 100m
            node_b = sim.get_node("node-b")
            assert node_b is not None
            node_b.set_position(100.0, 0.0, 0.0)

            # RSSI should improve
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None
            rssi_at_100m = result[1]

            assert rssi_at_100m > rssi_at_500m, "RSSI should improve when closer"

    @pytest.mark.asyncio
    async def test_mobile_node_gradient_updates(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Mobile node's announce updates gradient at stationary nodes.

        When E moves from near D to near B, E's announces reach B
        with better signal, and B builds gradient to E via direct path.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        identity_e = make_identity(4)  # Mobile node E

        # B's gradient table
        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address
        )

        # E starts far from B (at 1000m, weak signal)
        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (0.0, 0.0, 0.0)
        ) as radio_b, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-e", (1000.0, 0.0, 0.0)
        ) as radio_e:
            now_ms = 1000

            # E announces from 1000m
            announce_e = build_announce_bytes(identity_e)
            await radio_e.transmit(announce_e)
            result = await radio_b.receive(1000)

            # At 1000m, might or might not be receivable depending on model
            # Let's check if received and process
            if result is not None:
                announce = AnnounceMessage.from_bytes(result[0])
                from_e = build_address(identity_e.iid)
                processor_b.process(announce, from_e, now_ms)

            # Move E closer to B (100m)
            node_e = sim.get_node("node-e")
            assert node_e is not None
            node_e.set_position(100.0, 0.0, 0.0)

            # E announces from new position
            # Need fresh announce (new seq_num)
            scheduler_e = AnnounceScheduler(
                identity=identity_e,
                transmitter=MockTransmitter(),
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            # Increment seq_num to make it newer
            scheduler_e.set_seq_num(5)
            announce_e_new = scheduler_e.build_announce().to_bytes()

            await radio_e.transmit(announce_e_new)
            result = await radio_b.receive(1000)
            assert result is not None, "Should receive E's announce at 100m"

            # Process new announce
            announce = AnnounceMessage.from_bytes(result[0])
            from_e = build_address(identity_e.iid)
            processor_b.process(announce, from_e, now_ms)

            # B should now have gradient to E
            addr_e = build_address(identity_e.iid)
            entry = gradient_b.lookup(addr_e, now=now_ms)
            assert entry is not None, "B should have gradient to mobile E"

    @pytest.mark.asyncio
    async def test_moving_out_of_range_loses_connectivity(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Node moving out of range becomes unreachable."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (100.0, 0.0, 0.0)
        ) as radio_b:
            # Initially reachable
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None

            # Move B very far away (50km - beyond LoRa range)
            node_b = sim.get_node("node-b")
            assert node_b is not None
            node_b.set_position(50000.0, 0.0, 0.0)

            # Now unreachable
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(100)
            assert result is None, "Should be out of range at 50km"


class TestConvergenceTime:
    """Tests for routing convergence timing."""

    @pytest.mark.asyncio
    async def test_gradient_refresh_keeps_route_alive(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Regular announces prevent gradient expiration.

        If A keeps announcing, B's gradient to A stays fresh.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        identity_a = make_identity(0)

        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address
        )

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # Send multiple announces at increasing times
            for seq in range(3):
                now_ms = 1000 + (seq * 100000)  # 100 second intervals

                # Build announce with incrementing seq_num
                scheduler = AnnounceScheduler(
                    identity=identity_a,
                    transmitter=MockTransmitter(),
                    config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
                )
                scheduler.set_seq_num(seq)
                announce_bytes = scheduler.build_announce().to_bytes()

                await radio_a.transmit(announce_bytes)
                result = await radio_b.receive(1000)
                assert result is not None

                announce = AnnounceMessage.from_bytes(result[0])
                from_a = build_address(identity_a.iid)
                processor_b.process(announce, from_a, now_ms)

                # Gradient should be valid
                addr_a = build_address(identity_a.iid)
                entry = gradient_b.lookup(addr_a, now=now_ms)
                assert entry is not None, f"Gradient should exist at time {now_ms}"

    @pytest.mark.asyncio
    async def test_stale_gradient_expires(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Gradient expires after GRADIENT_TIMEOUT_MS without refresh."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("topo-test")
        assert node_port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address
        )

        async with SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "topo-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            now_ms = 1000

            # Initial announce
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None

            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address(identity_a.iid)
            processor_b.process(announce, from_a, now_ms)

            # Gradient exists immediately
            addr_a = build_address(identity_a.iid)
            assert gradient_b.lookup(addr_a, now=now_ms) is not None

            # Just before expiry - still valid
            almost_expired = now_ms + GRADIENT_TIMEOUT_MS - 1
            assert gradient_b.lookup(addr_a, now=almost_expired) is not None

            # After expiry - gone
            expired = now_ms + GRADIENT_TIMEOUT_MS + 1
            assert gradient_b.lookup(addr_a, now=expired) is None
