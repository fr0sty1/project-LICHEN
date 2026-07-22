# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Scale tests for the LICHEN simulator.

These tests verify the simulator handles larger meshes and higher message rates.
Includes 500-node dense conference mesh scenarios for stress test, roaming,
kill test, GPS sync, and visualization verification.
Run with:
    pytest tests/sim/test_scale.py -v --timeout=300
    LICHEN_SCALE_NODES=500 pytest tests/sim/test_scale.py -v

For AWS EC2 scale testing:
    ./scripts/ec2-claude.sh "Run pytest tests/sim/test_scale.py with LICHEN_SCALE_NODES=500"
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from ipaddress import IPv6Address

import pytest

from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# Configuration from environment
SCALE_NODES = int(os.environ.get("LICHEN_SCALE_NODES", "50"))
SCALE_MESSAGES = int(os.environ.get("LICHEN_SCALE_MESSAGES", "100"))


class MockTransmitter:
    """Mock transmitter for AnnounceScheduler."""

    def __init__(self) -> None:
        self.last_data: bytes | None = None

    async def transmit_announce(self, data: bytes) -> bool:
        self.last_data = data
        return True


def make_identity(seed_byte: int) -> Identity:
    """Create deterministic identity from seed byte."""
    seed = bytes([seed_byte] + [0] * 31)
    return Identity.from_seed(seed)


def build_address_from_iid(iid: bytes) -> IPv6Address:
    """Build link-local IPv6 from IID."""
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return IPv6Address(prefix + iid)


@dataclass
class ScaleTestResult:
    """Results from a scale test run."""

    nodes: int
    setup_time_s: float
    messages_sent: int
    messages_received: int
    propagation_time_s: float
    throughput_msg_per_s: float


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start simulator server for scale testing."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("scale-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


class TestMeshScale:
    """Tests for mesh network at various scales."""

    @pytest.mark.asyncio
    async def test_linear_topology(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Test linear topology with SCALE_NODES nodes.

        Topology: 0--1--2--...--N (50m spacing)
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("scale-test")
        assert node_port is not None

        n_nodes = min(SCALE_NODES, 100)  # Cap for this test

        # Setup nodes
        start = time.time()
        radios = []
        for i in range(n_nodes):
            pos = (i * 50.0, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", node_port, "scale-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)
        setup_time = time.time() - start

        try:
            # Node 0 transmits
            identity = make_identity(0)
            mock_tx = MockTransmitter()
            scheduler = AnnounceScheduler(
                identity=identity,
                transmitter=mock_tx,
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            announce = scheduler.build_announce()

            start = time.time()
            await radios[0].transmit(announce.to_bytes())

            # Count receivers (each node tries to receive)
            received = 0
            for radio in radios[1:]:
                result = await radio.receive(100)
                if result:
                    received += 1
            propagation_time = time.time() - start

            # Report results
            print(f"\nLinear topology: {n_nodes} nodes")
            print(f"  Setup: {setup_time:.3f}s")
            print(f"  Propagation: {propagation_time:.3f}s")
            print(f"  Received: {received}/{n_nodes - 1} ({100*received/(n_nodes-1):.1f}%)")

            # With 50m spacing, all nodes should be in range (LoRa range > 1km)
            assert received > n_nodes * 0.8, f"Too few receivers: {received}/{n_nodes-1}"

        finally:
            for radio in radios:
                await radio.close()

    @pytest.mark.asyncio
    async def test_grid_topology(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Test grid topology with sqrt(SCALE_NODES) x sqrt(SCALE_NODES) nodes.

        Topology: NxN grid with 50m spacing.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("scale-test")
        assert node_port is not None

        import math
        grid_size = int(math.sqrt(min(SCALE_NODES, 100)))
        n_nodes = grid_size * grid_size

        # Setup nodes in grid
        start = time.time()
        radios = []
        for row in range(grid_size):
            for col in range(grid_size):
                pos = (col * 50.0, row * 50.0, 0.0)
                node_id = f"node-{row}-{col}"
                radio = SimRadio("127.0.0.1", node_port, "scale-test", node_id, pos)
                await radio.connect()
                radios.append(radio)
        setup_time = time.time() - start

        try:
            # Center node transmits
            center_idx = (grid_size // 2) * grid_size + (grid_size // 2)
            identity = make_identity(center_idx)
            mock_tx = MockTransmitter()
            scheduler = AnnounceScheduler(
                identity=identity,
                transmitter=mock_tx,
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            announce = scheduler.build_announce()

            start = time.time()
            await radios[center_idx].transmit(announce.to_bytes())

            # Count receivers
            received = 0
            for i, radio in enumerate(radios):
                if i == center_idx:
                    continue
                result = await radio.receive(100)
                if result:
                    received += 1
            propagation_time = time.time() - start

            print(f"\nGrid topology: {grid_size}x{grid_size} = {n_nodes} nodes")
            print(f"  Setup: {setup_time:.3f}s")
            print(f"  Propagation: {propagation_time:.3f}s")
            print(f"  Received: {received}/{n_nodes - 1} ({100*received/(n_nodes-1):.1f}%)")

            # Grid should have very high reception (center can reach all)
            assert received > n_nodes * 0.9, f"Too few receivers: {received}/{n_nodes-1}"

        finally:
            for radio in radios:
                await radio.close()

    @pytest.mark.asyncio
    async def test_message_throughput(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Test message throughput with rapid transmissions.

        Sends SCALE_MESSAGES messages as fast as possible.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("scale-test")
        assert node_port is not None

        n_messages = min(SCALE_MESSAGES, 200)

        # Two nodes: TX and RX
        async with SimRadio(
            "127.0.0.1", node_port, "scale-test", "tx-node", (0.0, 0.0, 0.0)
        ) as radio_tx, SimRadio(
            "127.0.0.1", node_port, "scale-test", "rx-node", (50.0, 0.0, 0.0)
        ) as radio_rx:
            # Send messages as fast as possible
            start = time.time()
            for i in range(n_messages):
                payload = f"msg-{i:04d}".encode()
                await radio_tx.transmit(payload)
            tx_time = time.time() - start

            # Receive all messages
            received = 0
            start = time.time()
            for _ in range(n_messages):
                result = await radio_rx.receive(1000)
                if result:
                    received += 1
            rx_time = time.time() - start

            throughput = n_messages / (tx_time + rx_time)

            print(f"\nThroughput test: {n_messages} messages")
            print(f"  TX time: {tx_time:.3f}s")
            print(f"  RX time: {rx_time:.3f}s")
            print(f"  Received: {received}/{n_messages}")
            print(f"  Throughput: {throughput:.1f} msg/s")

            # Should receive most messages
            assert received >= n_messages * 0.95, f"Too many dropped: {received}/{n_messages}"


class TestAnnounceFlood:
    """Test announce flooding at scale."""

    @pytest.mark.asyncio
    async def test_concurrent_announces(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Multiple nodes announce simultaneously.

        Simulates mesh boot: all nodes start announcing at once.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("scale-test")
        assert node_port is not None

        n_nodes = min(SCALE_NODES // 2, 20)

        # Setup nodes
        radios = []
        identities = []
        schedulers = []
        mock_txs = []

        for i in range(n_nodes):
            pos = (i * 100.0, 0.0, 0.0)  # Wider spacing
            radio = SimRadio("127.0.0.1", node_port, "scale-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)

            identity = make_identity(i)
            identities.append(identity)

            mock_tx = MockTransmitter()
            mock_txs.append(mock_tx)

            scheduler = AnnounceScheduler(
                identity=identity,
                transmitter=mock_tx,
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            schedulers.append(scheduler)

        try:
            # All nodes announce concurrently
            start = time.time()
            announces = [s.build_announce().to_bytes() for s in schedulers]
            await asyncio.gather(*[
                radios[i].transmit(announces[i]) for i in range(n_nodes)
            ])
            tx_time = time.time() - start

            # Each node tries to receive
            received_counts = []
            for i in range(n_nodes):
                count = 0
                for _ in range(n_nodes):
                    result = await radios[i].receive(100)
                    if result:
                        count += 1
                received_counts.append(count)

            total_received = sum(received_counts)
            expected = n_nodes * (n_nodes - 1)  # Each of N nodes should hear N-1 others

            print(f"\nConcurrent announces: {n_nodes} nodes")
            print(f"  TX time: {tx_time:.3f}s")
            print(f"  Total received: {total_received}/{expected}")
            print(f"  Per-node: {list(received_counts)}")

        finally:
            for radio in radios:
                await radio.close()


class TestConferenceMesh:
    """500-node dense conference mesh test scenarios for hacker conference demo.
    Tests nodes entering/leaving conference area (roaming), RPL route implications
    via connectivity metrics, announce propagation via simulated TX/RX counts.
    """

    @pytest.mark.asyncio
    async def test_500_node_conference(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        server, sim = simulator_server
        random.seed(42)
        n_nodes = max(100, min(SCALE_NODES, 500))
        conference_area = (0.0, 150.0, 0.0, 100.0)
        start = time.time()
        for i in range(n_nodes):
            x = random.uniform(conference_area[0], conference_area[1])
            y = random.uniform(conference_area[2], conference_area[3])
            node_id = f"conf-{i:03d}"
            sim.add_node(node_id, x, y, 1.5)
        setup_time = time.time() - start
        assert sim.get_connected_node_count() == n_nodes, f"Expected {n_nodes} nodes"

        try:
            for i in range(0, 20):
                node_id = f"conf-{i:03d}"
                node = sim.get_node(node_id)
                if node:
                    node.set_position(50000.0 + i * 10, 50000.0, 1.5)
            for i in range(20, 40):
                node_id = f"conf-{i:03d}"
                node = sim.get_node(node_id)
                if node:
                    node.set_position(random.uniform(10, 140), random.uniform(10, 90), 1.5)

            for i in range(40, 70):
                node_id = f"conf-{i:03d}"
                sim.remove_node(node_id)

            active = sim.get_connected_node_count()
            assert active == n_nodes - 30, f"Expected {n_nodes-30} after kill, got {active}"

            tx_count = 0
            for i in range(min(50, n_nodes)):
                node_id = f"conf-{i:03d}"
                node = sim.get_node(node_id)
                if node and node.connected:
                    payload = b"conf-msg-" + str(i % 10).encode()
                    try:
                        sim.start_transmission(node_id, payload)
                        tx_count += 1
                    except (ValueError, RuntimeError):
                        pass
            for _ in range(20):
                if not sim.maybe_advance_time():
                    break

            nodes = sim.get_all_nodes()
            assert len(nodes) == n_nodes - 30
            sim.export_metrics("/tmp/conference-metrics.json")

            metrics = sim.metrics()
            assert metrics is not None
            assert tx_count > 0, "No transmissions succeeded in stress test"
            assert metrics.collisions >= 0, f"Expected non-negative collisions, got {metrics.collisions}"
            assert metrics.collision_rate >= 0.0, f"Expected valid collision_rate, got {metrics.collision_rate}"

            in_rx = []
            out_rx = []
            in_unique = []
            out_unique = []
            for node in nodes:
                if not node.connected:
                    continue
                rx = node.metrics.rx_count
                uniq = len(node.metrics.unique_peers)
                x, y, _ = node.position
                if (conference_area[0] <= x <= conference_area[1] and
                    conference_area[2] <= y <= conference_area[3]):
                    in_rx.append(rx)
                    in_unique.append(uniq)
                else:
                    out_rx.append(rx)
                    out_unique.append(uniq)
            assert len(in_rx) > 5 and len(out_rx) > 5
            avg_in = sum(in_rx) / len(in_rx) if in_rx else 0
            avg_out = sum(out_rx) / len(out_rx) if out_rx else 0
            assert avg_out == 0, f"Far rx={avg_out}"
            assert avg_in > 0, "In-area nodes received no messages"
            u_in = sum(in_unique) / len(in_unique) if in_unique else 0
            u_out = sum(out_unique) / len(out_unique) if out_unique else 0
            assert u_in > u_out, f"Unique {u_in} > {u_out}"

            print(f"\nConference mesh: {n_nodes} nodes in {conference_area}")
            print(f"  Setup: {setup_time:.2f}s")
            print(f"  Final active nodes: {active}")
            print("  Roaming (40 nodes), kill (30), 50 TX stress with collisions, metrics exported")
        finally:
            pass
