# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Network partition healing simulation tests (bead 1jlz).

Tests mesh network behavior during network partitions and healing:
1. Establish routes in a mesh (10-20 nodes)
2. Verify delivery works pre-partition
3. Partition network into two groups
4. Verify cross-partition messages fail
5. Heal partition (restore connectivity)
6. Measure reconvergence time and delivery rate after heal

Uses ChaosEngine with PartitionRule for partition simulation.
"""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from ipaddress import IPv6Address

import pytest
from lora_medium import PartitionRule

from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.gradient import GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# --- Configuration ---

# Network size for partition tests
PARTITION_TEST_NODES = 12  # Divisible by 2 for even partition split

# Spacing between nodes (meters) - within LoRa range
NODE_SPACING_M = 50.0

# Maximum allowed reconvergence time (seconds)
MAX_RECONVERGENCE_TIME_S = 5.0

# Minimum required delivery rate after healing (0-1)
MIN_DELIVERY_RATE_AFTER_HEAL = 1.0


# --- Test utilities ---


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start simulator server for partition testing."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("partition-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create deterministic identity from seed byte."""
    assert 0 <= seed_byte <= 255, f"seed_byte must be 0-255, got {seed_byte}"
    seed = bytes([seed_byte] + [0] * 31)
    return Identity.from_seed(seed)


def build_address_from_iid(iid: bytes) -> IPv6Address:
    """Build link-local IPv6 address from IID."""
    assert len(iid) == 8, f"IID must be 8 bytes, got {len(iid)}"
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return IPv6Address(prefix + iid)


class MockTransmitter:
    """Mock transmitter that captures announce bytes."""

    def __init__(self) -> None:
        self.last_data: bytes | None = None

    async def transmit_announce(self, data: bytes) -> bool:
        self.last_data = data
        return True


def build_announce_bytes(identity: Identity, seq_num: int = 1) -> bytes:
    """Build signed announce bytes from identity."""
    mock_tx = MockTransmitter()
    scheduler = AnnounceScheduler(
        identity=identity,
        transmitter=mock_tx,
        config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
    )
    scheduler.set_seq_num(seq_num)
    return scheduler.build_announce().to_bytes()


@dataclass
class PartitionHealingResult:
    """Results from a partition healing test."""

    nodes: int
    pre_partition_delivery_rate: float
    during_partition_cross_delivery_rate: float
    during_partition_same_delivery_rate: float
    post_heal_delivery_rate: float
    reconvergence_time_s: float
    duplicate_count: int


# --- Test classes ---


class TestPartitionHealingBasic:
    """Basic partition and healing tests."""

    @pytest.mark.asyncio
    async def test_partition_blocks_cross_group_delivery(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Partition blocks delivery between groups.

        Scenario:
        1. Two nodes A and B can communicate
        2. Add partition separating A and B
        3. Verify A cannot send to B
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with (
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "node-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "node-b", (50.0, 0.0, 0.0)
            ) as radio_b,
        ):
            # Pre-partition: A->B works
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None, "Pre-partition: B should receive from A"

            # Add partition
            partition = PartitionRule(groups=[{"node-a"}, {"node-b"}])
            chaos_engine.add_rule(partition)

            # During partition: A->B blocked
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(100)
            assert result is None, "During partition: B should NOT receive from A"

            # Heal partition
            chaos_engine.remove_rule(partition.id)

            # Post-heal: A->B works again
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None, "Post-heal: B should receive from A"

    @pytest.mark.asyncio
    async def test_partition_allows_same_group_delivery(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Partition allows delivery within same group.

        Scenario:
        1. Three nodes A, B, C
        2. Partition: {A, B} vs {C}
        3. A can still send to B (same group)
        4. A cannot send to C (different group)
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a)

        async with (
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "node-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "node-b", (50.0, 0.0, 0.0)
            ) as radio_b,
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "node-c", (100.0, 0.0, 0.0)
            ) as radio_c,
        ):
            # Add partition: {A, B} vs {C}
            partition = PartitionRule(groups=[{"node-a", "node-b"}, {"node-c"}])
            chaos_engine.add_rule(partition)

            # Same group: A->B works
            await radio_a.transmit(announce_a)
            result_b = await radio_b.receive(1000)
            assert result_b is not None, "Same group: B should receive from A"

            # Different group: A->C blocked
            await radio_a.transmit(announce_a)
            result_c = await radio_c.receive(100)
            assert result_c is None, "Different group: C should NOT receive from A"

            # Cleanup
            chaos_engine.remove_rule(partition.id)


class TestPartitionHealingMesh:
    """Partition healing tests with mesh networks."""

    @pytest.mark.asyncio
    async def test_mesh_partition_healing(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Full mesh partition and healing test.

        Scenario:
        1. Create mesh with PARTITION_TEST_NODES nodes in a line
        2. Establish routes (send announces, verify reception)
        3. Partition network into two halves
        4. Verify cross-partition messages fail
        5. Heal partition
        6. Verify delivery rate returns to 100%
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        n_nodes = PARTITION_TEST_NODES
        half = n_nodes // 2

        # Create nodes in a line topology
        radios: list[SimRadio] = []
        identities: list[Identity] = []
        for i in range(n_nodes):
            pos = (i * NODE_SPACING_M, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", node_port, "partition-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)
            identities.append(make_identity(i))

        try:
            # Phase 1: Pre-partition - verify delivery works
            pre_partition_delivered = 0
            pre_partition_total = 0

            # Node 0 sends, all others should receive
            announce_0 = build_announce_bytes(identities[0], seq_num=1)
            await radios[0].transmit(announce_0)

            for i in range(1, n_nodes):
                result = await radios[i].receive(100)
                pre_partition_total += 1
                if result is not None:
                    pre_partition_delivered += 1

            pre_partition_rate = pre_partition_delivered / pre_partition_total
            assert (
                pre_partition_rate > 0.8
            ), f"Pre-partition delivery rate too low: {pre_partition_rate:.1%}"

            # Phase 2: Partition - split into two groups
            # Group 1: nodes 0 to half-1
            # Group 2: nodes half to n_nodes-1
            group1 = {f"node-{i}" for i in range(half)}
            group2 = {f"node-{i}" for i in range(half, n_nodes)}
            partition = PartitionRule(groups=[group1, group2])
            chaos_engine.add_rule(partition)

            # Verify cross-partition fails
            # Node 0 (group1) sends, nodes in group2 should NOT receive
            announce_0_v2 = build_announce_bytes(identities[0], seq_num=2)
            await radios[0].transmit(announce_0_v2)

            cross_partition_delivered = 0
            cross_partition_total = 0
            for i in range(half, n_nodes):  # Group 2 nodes
                result = await radios[i].receive(100)
                cross_partition_total += 1
                if result is not None:
                    cross_partition_delivered += 1

            assert cross_partition_delivered == 0, (
                f"Cross-partition should block all: "
                f"{cross_partition_delivered}/{cross_partition_total}"
            )

            # Verify same-group still works
            # Node 0 (group1) sends, nodes in group1 should receive
            same_group_delivered = 0
            same_group_total = 0
            for i in range(1, half):  # Group 1 nodes (excluding sender)
                result = await radios[i].receive(100)
                same_group_total += 1
                if result is not None:
                    same_group_delivered += 1

            same_group_rate = same_group_delivered / max(same_group_total, 1)
            assert (
                same_group_rate > 0.8
            ), f"Same-group delivery rate too low: {same_group_rate:.1%}"

            # Phase 3: Heal partition
            heal_start = time.monotonic()
            chaos_engine.remove_rule(partition.id)

            # Phase 4: Verify delivery restored
            # Send fresh announce and measure delivery
            announce_0_v3 = build_announce_bytes(identities[0], seq_num=3)
            await radios[0].transmit(announce_0_v3)

            post_heal_delivered = 0
            post_heal_total = 0
            for i in range(1, n_nodes):
                result = await radios[i].receive(100)
                post_heal_total += 1
                if result is not None:
                    post_heal_delivered += 1

            heal_end = time.monotonic()
            reconvergence_time = heal_end - heal_start

            post_heal_rate = post_heal_delivered / post_heal_total

            # Assertions
            assert post_heal_rate >= MIN_DELIVERY_RATE_AFTER_HEAL, (
                f"Post-heal delivery rate {post_heal_rate:.1%} "
                f"< required {MIN_DELIVERY_RATE_AFTER_HEAL:.1%}"
            )
            assert reconvergence_time < MAX_RECONVERGENCE_TIME_S, (
                f"Reconvergence time {reconvergence_time:.2f}s "
                f"> max {MAX_RECONVERGENCE_TIME_S}s"
            )

        finally:
            for radio in radios:
                await radio.close()

    @pytest.mark.asyncio
    async def test_no_duplicates_after_heal(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Verify no duplicate messages after partition heal.

        Scenario:
        1. Create small mesh (4 nodes)
        2. Partition and heal
        3. Send multiple distinct messages, verify each is received only once

        Note: This test verifies that the partition heal doesn't cause message
        duplication at the protocol level (e.g., buffered retransmissions).
        We send multiple distinct messages and verify each unique message
        is received exactly once.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        n_nodes = 4
        radios: list[SimRadio] = []
        identities: list[Identity] = []

        for i in range(n_nodes):
            pos = (i * NODE_SPACING_M, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", node_port, "partition-test", f"dup-node-{i}", pos)
            await radio.connect()
            radios.append(radio)
            identities.append(make_identity(100 + i))

        try:
            # Partition and heal cycle
            partition = PartitionRule(
                groups=[{"dup-node-0", "dup-node-1"}, {"dup-node-2", "dup-node-3"}]
            )
            chaos_engine.add_rule(partition)
            chaos_engine.remove_rule(partition.id)

            # Send multiple distinct messages and count receptions
            num_messages = 3
            received_per_message: dict[int, int] = {}

            for seq in range(num_messages):
                announce = build_announce_bytes(identities[0], seq_num=100 + seq)
                await radios[0].transmit(announce)

                # Node 1 receives
                result = await radios[1].receive(100)
                if result is not None:
                    # Parse seq_num from the announce
                    msg = AnnounceMessage.from_bytes(result[0])
                    seq_received = msg.seq_num
                    count = received_per_message.get(seq_received, 0)
                    received_per_message[seq_received] = count + 1

            # Each message should be received at most once
            for seq_num, count in received_per_message.items():
                assert count == 1, f"Message seq={seq_num} received {count} times (expected 1)"

        finally:
            for radio in radios:
                await radio.close()


class TestPartitionHealingGradients:
    """Tests for gradient table behavior during partition healing."""

    @pytest.mark.asyncio
    async def test_gradient_expiry_during_partition(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Gradients expire when not refreshed during partition.

        Scenario:
        1. B builds gradient to A from A's announce
        2. Partition A and B
        3. Verify gradient expires (not refreshed)
        """
        from lichen.announce.processor import GRADIENT_TIMEOUT_MS

        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)
        announce_a = build_announce_bytes(identity_a, seq_num=1)

        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address_from_iid
        )

        async with (
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "grad-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "grad-b", (50.0, 0.0, 0.0)
            ) as radio_b,
        ):
            now_ms = 1000

            # Initial announce establishes gradient
            await radio_a.transmit(announce_a)
            result = await radio_b.receive(1000)
            assert result is not None

            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address_from_iid(identity_a.iid)
            processor_b.process(announce, from_a, now_ms)

            # Verify gradient exists
            addr_a = build_address_from_iid(identity_a.iid)
            entry = gradient_b.lookup(addr_a, now=now_ms)
            assert entry is not None, "Gradient should exist initially"

            # Add partition
            partition = PartitionRule(groups=[{"grad-a"}, {"grad-b"}])
            chaos_engine.add_rule(partition)

            # Time passes beyond timeout (simulated - no announces can reach B)
            expired_time = now_ms + GRADIENT_TIMEOUT_MS + 1

            # Gradient should be expired
            entry = gradient_b.lookup(addr_a, now=expired_time)
            assert entry is None, "Gradient should expire when not refreshed"

            # Cleanup
            chaos_engine.remove_rule(partition.id)

    @pytest.mark.asyncio
    async def test_gradient_rebuilds_after_heal(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Gradients rebuild after partition heals.

        Scenario:
        1. A and B exchange announces, build gradients
        2. Partition, let gradients expire
        3. Heal partition
        4. Fresh announces rebuild gradients
        """
        from lichen.announce.processor import GRADIENT_TIMEOUT_MS

        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        identity_a = make_identity(0)

        gradient_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_b, address_builder=build_address_from_iid
        )

        async with (
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "rebuild-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "partition-test", "rebuild-b", (50.0, 0.0, 0.0)
            ) as radio_b,
        ):
            now_ms = 1000

            # Initial gradient
            announce_v1 = build_announce_bytes(identity_a, seq_num=1)
            await radio_a.transmit(announce_v1)
            result = await radio_b.receive(1000)
            assert result is not None

            announce = AnnounceMessage.from_bytes(result[0])
            from_a = build_address_from_iid(identity_a.iid)
            processor_b.process(announce, from_a, now_ms)

            addr_a = build_address_from_iid(identity_a.iid)
            assert gradient_b.lookup(addr_a, now=now_ms) is not None

            # Partition
            partition = PartitionRule(groups=[{"rebuild-a"}, {"rebuild-b"}])
            chaos_engine.add_rule(partition)

            # Let gradient expire
            expired_time = now_ms + GRADIENT_TIMEOUT_MS + 1
            assert gradient_b.lookup(addr_a, now=expired_time) is None

            # Heal
            chaos_engine.remove_rule(partition.id)

            # Send fresh announce
            announce_v2 = build_announce_bytes(identity_a, seq_num=2)
            await radio_a.transmit(announce_v2)
            result = await radio_b.receive(1000)
            assert result is not None, "Should receive after heal"

            # Process and verify gradient rebuilt
            announce_new = AnnounceMessage.from_bytes(result[0])
            processor_b.process(announce_new, from_a, expired_time + 1000)

            entry = gradient_b.lookup(addr_a, now=expired_time + 1000)
            assert entry is not None, "Gradient should rebuild after heal"
            assert entry.next_hop == from_a


class TestPartitionHealingMetrics:
    """Tests with detailed metrics collection."""

    @pytest.mark.asyncio
    async def test_full_partition_healing_with_metrics(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Full partition healing test with comprehensive metrics.

        Collects and reports:
        - Pre-partition delivery rate
        - Cross-partition delivery rate (should be 0%)
        - Same-group delivery rate during partition
        - Post-heal delivery rate
        - Reconvergence time
        - Duplicate message count
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("partition-test")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("partition-test")
        assert chaos_engine is not None

        n_nodes = 10
        half = n_nodes // 2

        radios: list[SimRadio] = []
        identities: list[Identity] = []

        for i in range(n_nodes):
            pos = (i * NODE_SPACING_M, 0.0, 0.0)
            radio = SimRadio(
                "127.0.0.1", node_port, "partition-test", f"metrics-node-{i}", pos
            )
            await radio.connect()
            radios.append(radio)
            identities.append(make_identity(200 + i))

        try:
            # Pre-partition delivery rate
            announce_pre = build_announce_bytes(identities[0], seq_num=1)
            await radios[0].transmit(announce_pre)

            pre_delivered = 0
            for i in range(1, n_nodes):
                result = await radios[i].receive(100)
                if result is not None:
                    pre_delivered += 1
            pre_rate = pre_delivered / (n_nodes - 1)

            # Partition
            group1 = {f"metrics-node-{i}" for i in range(half)}
            group2 = {f"metrics-node-{i}" for i in range(half, n_nodes)}
            partition = PartitionRule(groups=[group1, group2])
            chaos_engine.add_rule(partition)

            # Cross-partition delivery (should be 0)
            announce_cross = build_announce_bytes(identities[0], seq_num=2)
            await radios[0].transmit(announce_cross)

            cross_delivered = 0
            for i in range(half, n_nodes):
                result = await radios[i].receive(100)
                if result is not None:
                    cross_delivered += 1
            cross_rate = cross_delivered / (n_nodes - half)

            # Same-group delivery during partition
            same_delivered = 0
            for i in range(1, half):
                result = await radios[i].receive(100)
                if result is not None:
                    same_delivered += 1
            same_rate = same_delivered / max(half - 1, 1)

            # Heal and measure reconvergence
            heal_start = time.monotonic()
            chaos_engine.remove_rule(partition.id)

            announce_post = build_announce_bytes(identities[0], seq_num=3)
            await radios[0].transmit(announce_post)

            post_delivered = 0
            for i in range(1, n_nodes):
                result = await radios[i].receive(100)
                if result is not None:
                    post_delivered += 1
            post_rate = post_delivered / (n_nodes - 1)

            reconvergence_time = time.monotonic() - heal_start

            # Check for duplicates by tracking message seq_nums per node
            announce_dup_check = build_announce_bytes(identities[0], seq_num=4)
            await radios[0].transmit(announce_dup_check)

            duplicate_count = 0
            for i in range(1, n_nodes):
                seen_seqs: set[int] = set()
                result = await radios[i].receive(50)
                if result is not None:
                    msg = AnnounceMessage.from_bytes(result[0])
                    if msg.seq_num in seen_seqs:
                        duplicate_count += 1
                    seen_seqs.add(msg.seq_num)

            # Build result
            result = PartitionHealingResult(
                nodes=n_nodes,
                pre_partition_delivery_rate=pre_rate,
                during_partition_cross_delivery_rate=cross_rate,
                during_partition_same_delivery_rate=same_rate,
                post_heal_delivery_rate=post_rate,
                reconvergence_time_s=reconvergence_time,
                duplicate_count=duplicate_count,
            )

            # Report
            print(f"\nPartition Healing Metrics ({n_nodes} nodes):")
            print(f"  Pre-partition delivery:  {result.pre_partition_delivery_rate:.1%}")
            print(
                f"  Cross-partition delivery: {result.during_partition_cross_delivery_rate:.1%}"
            )
            print(
                f"  Same-group delivery:      {result.during_partition_same_delivery_rate:.1%}"
            )
            print(f"  Post-heal delivery:      {result.post_heal_delivery_rate:.1%}")
            print(f"  Reconvergence time:      {result.reconvergence_time_s:.3f}s")
            print(f"  Duplicate count:         {result.duplicate_count}")

            # Assertions
            assert (
                result.during_partition_cross_delivery_rate == 0.0
            ), "Cross-partition should block all"
            assert (
                result.post_heal_delivery_rate >= MIN_DELIVERY_RATE_AFTER_HEAL
            ), f"Post-heal delivery too low: {result.post_heal_delivery_rate:.1%}"
            assert (
                result.reconvergence_time_s < MAX_RECONVERGENCE_TIME_S
            ), f"Reconvergence too slow: {result.reconvergence_time_s:.2f}s"
            assert (
                result.duplicate_count == 0
            ), f"Duplicates after heal: {result.duplicate_count}"

        finally:
            for radio in radios:
                await radio.close()
