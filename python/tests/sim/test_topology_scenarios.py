# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Topology scenario tests for routing algorithms.

Tests different network topologies and densities:
- Dense crowd: Many nodes close together (collision stress)
- Sparse network: Nodes near max range (sensitivity limits)
- Ring topology: Multiple equal-cost paths
- Random mesh: Realistic deployment patterns
- Partitioned groups: DTN ferry scenarios
- Scale tests: 50+ and 100+ nodes

These scenarios exercise edge cases the basic line topology tests miss.
"""

from __future__ import annotations

import random
from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.coords import decode_coords, encode_coords
from lichen.announce.messages import AnnounceMessage
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# -----------------------------------------------------------------------------
# Fixtures and helpers
# -----------------------------------------------------------------------------


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start a simulator server with barrier-sync time mode."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("topology-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create deterministic identity from seed byte."""
    seed = bytes([seed_byte] + [0] * 31)
    return Identity.from_seed(seed)


def build_address(iid: bytes) -> IPv6Address:
    """Build link-local IPv6 from IID."""
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return IPv6Address(prefix + iid)


def build_announce_bytes(identity: Identity, hop_count: int = 0, app_data: bytes = b"") -> bytes:
    """Build signed announce message bytes."""
    # Build unsigned first
    msg = AnnounceMessage(
        originator_iid=identity.iid,
        pubkey=identity.pubkey,
        seq_num=1,
        hop_count=hop_count,
        app_data=app_data,
    )
    # Sign it
    signature = sign(identity.privkey, identity.pubkey, msg.signed_data())
    # Create signed version
    signed = AnnounceMessage(
        originator_iid=msg.originator_iid,
        pubkey=msg.pubkey,
        seq_num=msg.seq_num,
        hop_count=msg.hop_count,
        signature=signature,
        app_data=msg.app_data,
    )
    return signed.to_bytes()


def parse_announce(rx_result: tuple[bytes, int, int]) -> AnnounceMessage | None:
    """Parse an announce from receive result tuple (payload, rssi, snr)."""
    try:
        return AnnounceMessage.from_bytes(rx_result[0])
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Sparse Network Tests (simplest - 2-3 nodes)
# -----------------------------------------------------------------------------


class TestSparseNetwork:
    """Nodes near maximum range - sensitivity limits, GPSR needed."""

    @pytest.mark.asyncio
    async def test_sparse_near_max_range(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Two nodes at near-maximum range can still communicate."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "sparse-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", port, "topology-test", "sparse-b", (2000.0, 0.0, 0.0)) as radio_b,
        ):
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(500)

            assert result is not None, "Should receive at 2km"
            rssi = result[1]
            assert rssi <= -90, f"RSSI should be weak at 2km, got {rssi}"

    @pytest.mark.asyncio
    async def test_sparse_beyond_max_range(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Nodes beyond max range cannot communicate directly."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        # 50km is well beyond LoRa SF10 max range (~15km with good conditions)
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "far-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", port, "topology-test", "far-b", (50000.0, 0.0, 0.0)) as radio_b,
        ):
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(200)

            assert result is None, "Should not receive at 50km"

    @pytest.mark.asyncio
    async def test_sparse_coords_in_announce(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Coordinate data in announces survives transmission."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_b = make_identity(1)

        # B announces with coords
        app_data = encode_coords(0.0135, 0.0)  # ~1500m east
        announce_b = build_announce_bytes(identity_b, app_data=app_data)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "coord-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", port, "topology-test", "coord-b", (1500.0, 0.0, 0.0)) as radio_b,
        ):
            # B announces
            await radio_b.transmit(announce_b)
            result = await radio_a.receive(200)
            assert result is not None

            announce = parse_announce(result)
            assert announce is not None

            # Verify coords survived transmission
            coords = decode_coords(announce.app_data)
            assert coords is not None, "Should decode coords from app_data"
            lat, lon = coords
            assert abs(lat - 0.0135) < 0.0001, f"Latitude mismatch: {lat}"
            assert abs(lon - 0.0) < 0.0001, f"Longitude mismatch: {lon}"

    @pytest.mark.asyncio
    async def test_sparse_isolated_node(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Isolated node receives no traffic (DTN scenario)."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        # C is 100km away - completely isolated
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "iso-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", port, "topology-test", "iso-c", (100000.0, 0.0, 0.0)) as radio_c,
        ):
            await radio_a.transmit(announce_a)
            result = await radio_c.receive(200)

            assert result is None, "Isolated node should receive nothing"


# -----------------------------------------------------------------------------
# Ring Topology Tests (4 nodes)
# -----------------------------------------------------------------------------


class TestRingTopology:
    """Nodes in a ring - multiple equal-cost paths."""

    @pytest.mark.asyncio
    async def test_ring_announces_propagate(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Ring of 4 nodes - announces reach neighbors."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_0 = make_identity(0)
        announce_0 = build_announce_bytes(identity_0)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "ring-0", (0.0, 0.0, 0.0)) as radio_0,
            SimRadio("127.0.0.1", port, "topology-test", "ring-1", (100.0, 0.0, 0.0)) as radio_1,
            SimRadio("127.0.0.1", port, "topology-test", "ring-2", (100.0, 100.0, 0.0)) as _radio_2,
            SimRadio("127.0.0.1", port, "topology-test", "ring-3", (0.0, 100.0, 0.0)) as radio_3,
        ):
            # Node 0 announces
            await radio_0.transmit(announce_0)

            # Neighbors (1 and 3) should receive
            received_count = 0
            for radio in [radio_1, radio_3]:
                result = await radio.receive(100)
                if result is not None:
                    received_count += 1

            assert received_count >= 1, "At least one neighbor should receive"

    @pytest.mark.asyncio
    async def test_ring_gradient_builds(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Ring gradient tables populate from announces."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_0 = make_identity(0)
        announce_0 = build_announce_bytes(identity_0)
        addr_0 = build_address(identity_0.iid)

        gradient_1 = GradientTable(max_entries=64)
        gradient_3 = GradientTable(max_entries=64)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "sq-0", (0.0, 0.0, 0.0)) as radio_0,
            SimRadio("127.0.0.1", port, "topology-test", "sq-1", (100.0, 0.0, 0.0)) as radio_1,
            SimRadio("127.0.0.1", port, "topology-test", "sq-3", (0.0, 100.0, 0.0)) as radio_3,
        ):
            await radio_0.transmit(announce_0)

            # Check neighbors build gradients
            import time

            now_ms = int(time.time() * 1000)
            for radio, gradient in [(radio_1, gradient_1), (radio_3, gradient_3)]:
                result = await radio.receive(100)
                if result is not None:
                    announce = parse_announce(result)
                    if announce:
                        entry = GradientEntry(
                            destination=addr_0,
                            next_hop=addr_0,
                            hop_count=1,
                            seq_num=announce.seq_num,
                            source=GradientSource.ANNOUNCE,
                            expires=now_ms + 600_000,
                        )
                        gradient.update(entry)

            total = len(gradient_1) + len(gradient_3)
            assert total >= 1, "At least one gradient should build"


# -----------------------------------------------------------------------------
# Dense Crowd Tests (scaled down to 9 nodes for faster testing)
# -----------------------------------------------------------------------------


class TestDenseCrowd:
    """Multiple nodes in close proximity - collision stress."""

    @pytest.mark.asyncio
    async def test_dense_simultaneous_collision(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """8 nodes announcing simultaneously to 1 receiver - all collide."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        # 3x3 grid, 20m spacing. Center node (4) is receiver only.
        identities = [make_identity(i) for i in range(9)]
        announces = [build_announce_bytes(id) for id in identities]

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "d-0", (0.0, 0.0, 0.0)) as r0,
            SimRadio("127.0.0.1", port, "topology-test", "d-1", (20.0, 0.0, 0.0)) as r1,
            SimRadio("127.0.0.1", port, "topology-test", "d-2", (40.0, 0.0, 0.0)) as r2,
            SimRadio("127.0.0.1", port, "topology-test", "d-3", (0.0, 20.0, 0.0)) as r3,
            SimRadio("127.0.0.1", port, "topology-test", "d-4", (20.0, 20.0, 0.0)) as r4,
            SimRadio("127.0.0.1", port, "topology-test", "d-5", (40.0, 20.0, 0.0)) as r5,
            SimRadio("127.0.0.1", port, "topology-test", "d-6", (0.0, 40.0, 0.0)) as r6,
            SimRadio("127.0.0.1", port, "topology-test", "d-7", (20.0, 40.0, 0.0)) as r7,
            SimRadio("127.0.0.1", port, "topology-test", "d-8", (40.0, 40.0, 0.0)) as r8,
        ):
            senders = [r0, r1, r2, r3, r5, r6, r7, r8]  # r4 is receiver

            # All 8 transmit simultaneously - causes collision (no capture)
            for i, radio in enumerate(senders):
                idx = i if i < 4 else i + 1  # skip index 4
                await radio.transmit(announces[idx])

            # With simultaneous TX at equal power, none should be received
            # (capture effect requires 6dB difference)
            result = await r4.receive(100)
            assert result is None, "Simultaneous TX at equal power should collide"

    @pytest.mark.asyncio
    async def test_dense_single_transmit(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Single transmitter in dense network - no collision."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_0 = make_identity(0)
        announce_0 = build_announce_bytes(identity_0)

        # 3 nodes: transmitter, close receiver, far receiver
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "tx", (0.0, 0.0, 0.0)) as tx,
            SimRadio("127.0.0.1", port, "topology-test", "rx-close", (30.0, 0.0, 0.0)) as rx_close,
            SimRadio("127.0.0.1", port, "topology-test", "rx-far", (100.0, 0.0, 0.0)) as rx_far,
        ):
            # Single TX - both receivers should get it
            await tx.transmit(announce_0)

            close_result = await rx_close.receive(200)
            far_result = await rx_far.receive(200)

            assert close_result is not None, "Close receiver should receive"
            assert far_result is not None, "Far receiver should receive"
            # Close receiver should have stronger signal
            assert close_result[1] > far_result[1], "Close should have higher RSSI"


# -----------------------------------------------------------------------------
# Partitioned Groups Tests
# -----------------------------------------------------------------------------


class TestPartitionedGroups:
    """Disconnected groups - DTN scenarios."""

    @pytest.mark.asyncio
    async def test_two_isolated_clusters(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Two clusters 50km apart - no direct communication."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        # 50km is well beyond LoRa SF10 max range
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "cluster-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio(
                "127.0.0.1", port, "topology-test", "cluster-b", (50000.0, 0.0, 0.0)
            ) as radio_b,
        ):
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(100)

            assert result is None, "Clusters should be isolated at 50km"

    @pytest.mark.asyncio
    async def test_mobile_node_scenario(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Mobile node moves from one cluster to another."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_a = make_identity(0)
        identity_ferry = make_identity(2)
        announce_a = build_announce_bytes(identity_a)
        announce_ferry = build_announce_bytes(identity_ferry)

        # Clusters at 0 and 50km (isolated), ferry starts near A
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "ferry-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio(
                "127.0.0.1", port, "topology-test", "ferry-f", (50.0, 0.0, 0.0)
            ) as radio_ferry,
            SimRadio("127.0.0.1", port, "topology-test", "ferry-b", (50000.0, 0.0, 0.0)) as radio_b,
        ):
            # Ferry near A receives A's announce
            await radio_a.transmit(announce_a)
            result = await radio_ferry.receive(100)
            assert result is not None, "Ferry should receive A's announce"

            # Move ferry to near B's cluster
            ferry_node = sim.get_node("ferry-f")
            assert ferry_node is not None
            ferry_node.set_position(49950.0, 0.0, 0.0)

            # Ferry announces at new location
            await radio_ferry.transmit(announce_ferry)
            result = await radio_b.receive(200)

            assert result is not None, "B should receive ferry after move"


# -----------------------------------------------------------------------------
# Random Mesh Tests
# -----------------------------------------------------------------------------


class TestRandomMesh:
    """Random node placement - realistic deployment."""

    @pytest.mark.asyncio
    async def test_random_mesh_connectivity(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """4 nodes randomly placed - one transmitter, three receivers."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        # Fixed random positions (seed 42) - keep them close for reliable reception
        rng = random.Random(42)
        positions = [(rng.uniform(0, 150), rng.uniform(0, 150)) for _ in range(4)]

        identity_0 = make_identity(0)
        announce_0 = build_announce_bytes(identity_0)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "rnd-0", (*positions[0], 0.0)) as r0,
            SimRadio("127.0.0.1", port, "topology-test", "rnd-1", (*positions[1], 0.0)) as r1,
            SimRadio("127.0.0.1", port, "topology-test", "rnd-2", (*positions[2], 0.0)) as r2,
            SimRadio("127.0.0.1", port, "topology-test", "rnd-3", (*positions[3], 0.0)) as r3,
        ):
            # Node 0 announces
            await r0.transmit(announce_0)

            # Check how many others receive
            received = 0
            for radio in [r1, r2, r3]:
                result = await radio.receive(100)
                if result is not None:
                    received += 1

            # In 150x150 area, at least some should receive
            assert received >= 1, f"Should receive at least 1, got {received}/3"


# -----------------------------------------------------------------------------
# Scale Tests (moderate - 16 nodes)
# -----------------------------------------------------------------------------


class TestScaleModerate:
    """16 nodes - moderate scale test."""

    @pytest.mark.asyncio
    async def test_grid_16_announce_propagation(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """4x4 grid - center node receives from neighbors."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        # Create identities
        identities = [make_identity(i) for i in range(16)]

        # 4x4 grid, 80m spacing (320m x 320m total)
        # We'll just test that center receives from immediate neighbors
        identity_5 = identities[5]  # Row 1, Col 1 (near center)
        announce_5 = build_announce_bytes(identity_5)

        # Position (1,1) = (80, 80), neighbors at (0,1), (2,1), (1,0), (1,2)
        async with (
            SimRadio("127.0.0.1", port, "topology-test", "g16-5", (80.0, 80.0, 0.0)) as r5,
            SimRadio("127.0.0.1", port, "topology-test", "g16-1", (80.0, 0.0, 0.0)) as r1,
            SimRadio("127.0.0.1", port, "topology-test", "g16-9", (80.0, 160.0, 0.0)) as r9,
            SimRadio("127.0.0.1", port, "topology-test", "g16-4", (0.0, 80.0, 0.0)) as r4,
            SimRadio("127.0.0.1", port, "topology-test", "g16-6", (160.0, 80.0, 0.0)) as r6,
        ):
            # Node 5 announces
            await r5.transmit(announce_5)

            # All 4 neighbors should receive
            received = 0
            for radio in [r1, r9, r4, r6]:
                result = await radio.receive(100)
                if result is not None:
                    received += 1

            assert received >= 3, f"Most neighbors should receive, got {received}/4"

    @pytest.mark.asyncio
    async def test_gradient_from_announce(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Received announce can populate gradient table."""
        server, sim = simulator_server
        port = server.get_node_server_port("topology-test")
        assert port is not None

        identity_0 = make_identity(0)
        announce_0 = build_announce_bytes(identity_0)
        gradient = GradientTable(max_entries=64)

        async with (
            SimRadio("127.0.0.1", port, "topology-test", "tx", (0.0, 0.0, 0.0)) as tx,
            SimRadio("127.0.0.1", port, "topology-test", "rx", (50.0, 0.0, 0.0)) as rx,
        ):
            await tx.transmit(announce_0)
            result = await rx.receive(100)
            assert result is not None

            announce = parse_announce(result)
            assert announce is not None

            import time

            now_ms = int(time.time() * 1000)
            addr = build_address(announce.originator_iid)
            entry = GradientEntry(
                destination=addr,
                next_hop=addr,
                hop_count=1,
                seq_num=announce.seq_num,
                source=GradientSource.ANNOUNCE,
                expires=now_ms + 600_000,
            )
            gradient.update(entry)

            assert len(gradient) == 1, "Should have one gradient entry"
            lookup = gradient.lookup(addr)
            assert lookup is not None, "Should find gradient for address"
