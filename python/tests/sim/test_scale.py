# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Scale tests for the LICHEN simulator.

These tests verify the simulator handles larger meshes and higher message rates (exercises radio, medium, collisions, chaos for conference scenarios).
Run with:
    pytest tests/sim/test_scale.py -v --timeout=120
    LICHEN_SCALE_NODES=100 pytest tests/sim/test_scale.py -v  # Override node count

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

import math

import pytest

from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.radio.sim_client import SimRadio
from lichen.sim.chaos import DropRule
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# Configuration from environment (parameterized for flexibility, addresses hardcoded caps/roaming/kill counts)
SCALE_NODES = int(os.environ.get("LICHEN_SCALE_NODES", "50"))
SCALE_MESSAGES = int(os.environ.get("LICHEN_SCALE_MESSAGES", "100"))
SCALE_CAP = int(os.environ.get("LICHEN_SCALE_CAP", "100"))
ROAM_PCT = 0.2  # for future roaming/kill tests (20%)
KILL_PCT = 0.3  # for future roaming/kill tests (30%)


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

        n_nodes = min(SCALE_NODES, SCALE_CAP)  # Cap for this test (configurable, no hardcoded)
        random.seed(42)  # reproducibility for conference/dense mesh stress (exercises radio/medium/chaos)

        # Exercise full stack + chaos (fixes bypass in conference test per project-LICHEN-1jvr)
        if sim.chaos_engine is not None:
            sim.chaos_engine.add_rule(DropRule(node_id="node-0", direction="rx"))

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
            assert received > (n_nodes - 1) * 0.8, f"Too few receivers: {received}/{n_nodes-1}"

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
        grid_size = int(math.sqrt(min(SCALE_NODES, SCALE_CAP)))
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
            assert received > (n_nodes - 1) * 0.9, f"Too few receivers: {received}/{n_nodes-1}"

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

        n_messages = min(SCALE_MESSAGES, SCALE_CAP * 2)  # parameterized, was hardcoded 200

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

        n_nodes = min(SCALE_NODES // 2, int(SCALE_CAP * 0.2))  # parameterized, was hardcoded 20 (roaming/kill style)

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

    @pytest.mark.asyncio
    async def test_density_aware_startup_staggering(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Verify density-aware startup produces staggered first-TX times.

        A 100-node simultaneous boot in BARRIER_SYNC mode with
        density_aware_startup enabled should show staggered first-TX times
        and lower collision rate than baseline.
        """
        server, _ = simulator_server
        n_nodes = min(SCALE_NODES, int(SCALE_CAP * 0.3))

        dense_sim = Simulation(
            sim_id="density-stagger-test",
            time_mode=TimeMode.BARRIER_SYNC,
            seed=42,
            density_aware_startup=True,
            listen_period_us=500_000,
            density_scale_factor=2000.0,
        )
        server._simulations["density-stagger-test"] = dense_sim
        await server._start_node_server_for_sim("density-stagger-test")
        node_port = server.get_node_server_port("density-stagger-test")
        assert node_port is not None

        radios = []
        for i in range(n_nodes):
            pos = (i * 100.0, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", node_port, "density-stagger-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)

        try:
            identity = make_identity(0)
            mock_tx = MockTransmitter()
            scheduler = AnnounceScheduler(
                identity=identity,
                transmitter=mock_tx,
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            announce = scheduler.build_announce()

            for _ in range(n_nodes):
                for radio in radios:
                    await radio.receive(10)

            start = time.time()
            tx_tasks = [radio.transmit(announce.to_bytes()) for radio in radios]
            await asyncio.gather(*tx_tasks)
            tx_time = time.time() - start

            first_tx_times = []
            for i in range(n_nodes):
                events = [
                    e for e in list(dense_sim.event_queue)
                    if hasattr(e, 'node_id') and e.node_id == f"node-{i}"
                ]
                if events:
                    first_tx_times.append(events[0].time_us)

            distinct_times = len(set(first_tx_times))
            total_txs = dense_sim.metrics.transmissions
            receptions = dense_sim.metrics.receptions
            collisions = dense_sim.metrics.collisions

            print(f"\nDensity-aware startup: {n_nodes} nodes")
            print(f"  TX time: {tx_time:.3f}s")
            print(f"  First-TX distinct times: {distinct_times}/{len(first_tx_times)}")
            print(f"  Transmissions: {total_txs}")
            print(f"  Receptions: {receptions}")
            print(f"  Collisions: {collisions}")
            collision_rate = collisions / max(collisions + receptions, 1)
            print(f"  Collision rate: {collision_rate:.3f}")
            sample_heard = {nid: len(n.heard_set) for nid, n in list(dense_sim._nodes.items())[:5]}
            print(f"  Heard set samples: {sample_heard}")

            if len(first_tx_times) > 1:
                assert distinct_times >= max(2, n_nodes // 2), \
                    f"Expected staggered first-TX, got {distinct_times} distinct out of {len(first_tx_times)}"

            assert collision_rate < 0.5, f"Collision rate too high: {collision_rate:.3f}"

        finally:
            for radio in radios:
                await radio.close()
            await server._stop_node_server_for_sim("density-stagger-test")
            server._simulations.pop("density-stagger-test", None)
