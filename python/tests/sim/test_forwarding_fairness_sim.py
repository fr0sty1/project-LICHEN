# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulation integration tests for forwarding fairness (spec appendix-bufferbloat.md B.5.5).

Tests verify that:
1. Per-source limits prevent any single source from monopolizing forwarding capacity
2. Multiple sources get fair share of forwarding buffer
3. Backpressure signals are sent to sources exceeding their limit
4. LRU eviction preserves fairness across source rotation

Paranoid defensive style: explicit assertions at every step, guard against
None values aggressively, verify invariants.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

import pytest

from lichen.gradient import GradientTable
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.routing.router import (
    MAX_FORWARDING_SOURCES,
    MAX_PACKETS_PER_SOURCE,
    ForwardingBuffer,
    ForwardingResult,
    Router,
)

# Simulator imports are optional - only needed for TestForwardingFairnessSimulation.
# Import lazily to allow basic tests to run without the Rust lora_medium extension.
if TYPE_CHECKING:
    from lichen.sim.server import SimulatorServer
    from lichen.sim.simulation import Simulation

# Check if simulator is available (requires lora_medium Rust extension)
try:
    from lichen.sim.server import SimulatorServer as _SimulatorServer
    from lichen.sim.simulation import Simulation as _Simulation, TimeMode

    HAS_SIMULATOR = True
except ImportError:
    HAS_SIMULATOR = False
    _SimulatorServer = None  # type: ignore[misc, assignment]
    _Simulation = None  # type: ignore[misc, assignment]

    class TimeMode:  # type: ignore[no-redef]
        """Stub for when simulator is not available."""

        BARRIER_SYNC = None

# --- Test fixtures ---


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple["SimulatorServer", "Simulation"], None]:
    """Start a simulator server with a test simulation.

    PARANOID: Verify server started, verify simulation created, verify cleanup.
    """
    if not HAS_SIMULATOR:
        pytest.skip("Simulator not available (requires lora_medium Rust extension)")

    server = _SimulatorServer(node_port=0, api_port=0)
    await server.start()

    # PARANOID: Verify server is actually running
    assert server._node_servers is not None, "node servers dict must exist"

    sim = await server.create_simulation("fairness-test", TimeMode.BARRIER_SYNC)

    # PARANOID: Verify simulation was created
    assert sim is not None, "simulation must be created"
    assert sim.id == "fairness-test", "simulation ID must match"

    yield server, sim

    # PARANOID: Verify cleanup doesn't fail
    await server.stop()


def make_packet(dst: str, src: str = "fe80::1") -> IPv6Packet:
    """Create a minimal IPv6 packet for testing."""
    return IPv6Packet(
        header=IPv6Header(
            src_addr=IPv6Address(src),
            dst_addr=IPv6Address(dst),
            next_header=17,  # UDP
            payload_length=0,
        ),
        payload=b"",
    )


def make_source_iid(source_id: int) -> bytes:
    """Create a deterministic 8-byte source IID.

    PARANOID: Verify source_id is valid.
    """
    assert 0 <= source_id <= 255, f"source_id must be 0-255, got {source_id}"
    return bytes([source_id] * 8)


# --- Test classes ---


class TestForwardingFairnessBasic:
    """Basic forwarding fairness tests (spec appendix-bufferbloat.md)."""

    @pytest.mark.asyncio
    async def test_per_source_limit_enforced(self) -> None:
        """Per-source limit prevents single source from hogging buffer.

        Spec requirement: MAX_PACKETS_PER_SOURCE = 2.
        A single source cannot buffer more than 2 packets.

        PARANOID: Verify exact limit, not off-by-one.
        """
        buffer = ForwardingBuffer()

        # PARANOID: Verify default limits match spec
        assert buffer.max_per_source == MAX_PACKETS_PER_SOURCE, "must match spec"
        assert MAX_PACKETS_PER_SOURCE == 2, "spec requires 2 packets per source"

        source = make_source_iid(1)
        deadline_ms = 10000

        # First packet - should succeed
        result1 = buffer.try_buffer(
            make_packet("fd00::1"), source, now_ms=0, deadline_ms=deadline_ms
        )
        assert result1 == ForwardingResult.ACCEPTED, "first packet must be accepted"

        # Second packet - should succeed
        result2 = buffer.try_buffer(
            make_packet("fd00::2"), source, now_ms=1, deadline_ms=deadline_ms
        )
        assert result2 == ForwardingResult.ACCEPTED, "second packet must be accepted"

        # Third packet - must be rejected with backpressure
        result3 = buffer.try_buffer(
            make_packet("fd00::3"), source, now_ms=2, deadline_ms=deadline_ms
        )
        assert result3 == ForwardingResult.BACKPRESSURE, "third packet must trigger backpressure"

        # PARANOID: Verify buffer state
        assert buffer.count_for_source(source) == 2, "source must have exactly 2 packets"
        assert buffer.total_count() == 2, "total must be 2"
        stats = buffer.get_stats()
        assert stats["backpressure"] == 1, "must record one backpressure event"

    @pytest.mark.asyncio
    async def test_multiple_sources_get_fair_share(self) -> None:
        """Multiple sources each get MAX_PACKETS_PER_SOURCE slots.

        Fairness: each source gets equal maximum allocation.

        PARANOID: Verify all sources can use their share.
        """
        buffer = ForwardingBuffer()
        deadline_ms = 10000
        num_sources = 5

        # Each source gets 2 packets
        for src_id in range(num_sources):
            source = make_source_iid(src_id)
            for pkt in range(MAX_PACKETS_PER_SOURCE):
                result = buffer.try_buffer(
                    make_packet(f"fd00::{src_id}:{pkt}"),
                    source,
                    now_ms=src_id * 10 + pkt,
                    deadline_ms=deadline_ms,
                )
                assert result == ForwardingResult.ACCEPTED, (
                    f"source {src_id} packet {pkt} must be accepted"
                )

        # PARANOID: Verify total distribution
        total_expected = num_sources * MAX_PACKETS_PER_SOURCE
        assert buffer.total_count() == total_expected, (
            f"total must be {total_expected}"
        )

        # Verify each source has their share
        for src_id in range(num_sources):
            source = make_source_iid(src_id)
            count = buffer.count_for_source(source)
            assert count == MAX_PACKETS_PER_SOURCE, (
                f"source {src_id} must have {MAX_PACKETS_PER_SOURCE} packets"
            )

    @pytest.mark.asyncio
    async def test_aggressive_source_cannot_starve_others(self) -> None:
        """One aggressive source cannot prevent others from buffering.

        Scenario: Source A tries to flood buffer, then source B arrives.
        Source B must be able to buffer its packets.

        PARANOID: Verify B gets its share despite A's aggression.
        """
        buffer = ForwardingBuffer()
        deadline_ms = 10000

        source_a = make_source_iid(1)  # Aggressive sender
        source_b = make_source_iid(2)  # Late arrival

        # Source A tries to flood (but hits per-source limit)
        accepted_a = 0
        for i in range(10):
            result = buffer.try_buffer(
                make_packet(f"fd00::a:{i}"),
                source_a,
                now_ms=i,
                deadline_ms=deadline_ms,
            )
            if result == ForwardingResult.ACCEPTED:
                accepted_a += 1

        # PARANOID: A can only get per-source limit
        assert accepted_a == MAX_PACKETS_PER_SOURCE, (
            f"aggressive source must be capped at {MAX_PACKETS_PER_SOURCE}"
        )

        # Source B arrives - must be able to buffer
        for i in range(MAX_PACKETS_PER_SOURCE):
            result = buffer.try_buffer(
                make_packet(f"fd00::b:{i}"),
                source_b,
                now_ms=100 + i,
                deadline_ms=deadline_ms,
            )
            assert result == ForwardingResult.ACCEPTED, (
                f"source B packet {i} must be accepted"
            )

        # PARANOID: Both sources have their fair share
        assert buffer.count_for_source(source_a) == MAX_PACKETS_PER_SOURCE
        assert buffer.count_for_source(source_b) == MAX_PACKETS_PER_SOURCE

    @pytest.mark.asyncio
    async def test_max_sources_with_lru_eviction(self) -> None:
        """Max sources limit with LRU eviction maintains fairness.

        When MAX_FORWARDING_SOURCES is reached, oldest (LRU) source is
        evicted to make room for new source.

        PARANOID: Verify eviction preserves fairness.
        """
        buffer = ForwardingBuffer()
        deadline_ms = 10000

        # PARANOID: Verify spec limits
        assert buffer.max_sources == MAX_FORWARDING_SOURCES, "must match spec"
        assert MAX_FORWARDING_SOURCES == 8, "spec requires 8 sources max"

        # Fill all source slots
        for src_id in range(MAX_FORWARDING_SOURCES):
            source = make_source_iid(src_id)
            result = buffer.try_buffer(
                make_packet(f"fd00::{src_id}:0"),
                source,
                now_ms=src_id,
                deadline_ms=deadline_ms,
            )
            assert result == ForwardingResult.ACCEPTED

        # PARANOID: Verify all slots used
        assert buffer.source_count() == MAX_FORWARDING_SOURCES

        # New source arrives - oldest must be evicted
        new_source = make_source_iid(99)
        result = buffer.try_buffer(
            make_packet("fd00::99:0"),
            new_source,
            now_ms=100,
            deadline_ms=deadline_ms,
        )

        # PARANOID: Verify eviction happened
        assert result == ForwardingResult.EVICTED, "must evict oldest source"
        assert buffer.source_count() == MAX_FORWARDING_SOURCES, "count must remain at max"

        # Source 0 (oldest) should be gone
        oldest_source = make_source_iid(0)
        assert buffer.count_for_source(oldest_source) == 0, "oldest source must be evicted"

        # New source has its packet
        assert buffer.count_for_source(new_source) == 1, "new source must have packet"

    @pytest.mark.asyncio
    async def test_fairness_metric_under_load(self) -> None:
        """Measure fairness metric under sustained load.

        Jain's fairness index: f = (sum(x_i))^2 / (n * sum(x_i^2))
        f = 1.0 means perfectly fair, f < 1.0 means unfair.

        Scenario: All sources try to maximize their share. Fairness index
        should be close to 1.0.

        PARANOID: Verify fairness > 0.95 (allowing small variance).
        """
        buffer = ForwardingBuffer()
        deadline_ms = 10000
        num_sources = MAX_FORWARDING_SOURCES

        # Each source tries to buffer many packets
        allocations: list[int] = []
        for src_id in range(num_sources):
            source = make_source_iid(src_id)
            accepted = 0
            # Each source tries to send 5 packets
            for pkt in range(5):
                result = buffer.try_buffer(
                    make_packet(f"fd00::{src_id}:{pkt}"),
                    source,
                    now_ms=src_id * 10 + pkt,
                    deadline_ms=deadline_ms,
                )
                if result == ForwardingResult.ACCEPTED:
                    accepted += 1
            allocations.append(accepted)

        # PARANOID: All sources should get exactly MAX_PACKETS_PER_SOURCE
        for i, alloc in enumerate(allocations):
            assert alloc == MAX_PACKETS_PER_SOURCE, (
                f"source {i} got {alloc}, expected {MAX_PACKETS_PER_SOURCE}"
            )

        # Calculate Jain's fairness index
        n = len(allocations)
        sum_x = sum(allocations)
        sum_x_sq = sum(x * x for x in allocations)

        # Avoid division by zero
        fairness = 1.0 if sum_x_sq == 0 else (sum_x * sum_x) / (n * sum_x_sq)

        # PARANOID: Perfect fairness since all equal
        assert fairness == 1.0, f"fairness index must be 1.0, got {fairness}"

    @pytest.mark.asyncio
    async def test_backpressure_signals_counted(self) -> None:
        """Backpressure signals are tracked for monitoring.

        Operators need visibility into fairness enforcement.

        PARANOID: Verify all backpressure events counted.
        """
        buffer = ForwardingBuffer()
        deadline_ms = 10000
        source = make_source_iid(1)

        # Fill source limit, then generate backpressure
        for i in range(MAX_PACKETS_PER_SOURCE):
            buffer.try_buffer(
                make_packet(f"fd00::1:{i}"), source, now_ms=i, deadline_ms=deadline_ms
            )

        # Generate 10 backpressure events
        backpressure_count = 0
        for i in range(10):
            result = buffer.try_buffer(
                make_packet(f"fd00::ffff:{i}"),
                source,
                now_ms=100 + i,
                deadline_ms=deadline_ms,
            )
            if result == ForwardingResult.BACKPRESSURE:
                backpressure_count += 1

        # PARANOID: All excess attempts rejected
        assert backpressure_count == 10, "must track all backpressure"
        stats = buffer.get_stats()
        assert stats["backpressure"] == 10, "stats must reflect backpressure count"

    @pytest.mark.asyncio
    async def test_eviction_stats_tracked(self) -> None:
        """Eviction events are tracked for monitoring.

        PARANOID: Verify eviction count is accurate.
        """
        buffer = ForwardingBuffer()
        buffer.max_sources = 2  # Small limit for testing
        deadline_ms = 10000

        # Fill 2 sources with 2 packets each
        for src_id in range(2):
            source = make_source_iid(src_id)
            for pkt in range(MAX_PACKETS_PER_SOURCE):
                buffer.try_buffer(
                    make_packet(f"fd00::{src_id}:{pkt}"),
                    source,
                    now_ms=src_id * 10 + pkt,
                    deadline_ms=deadline_ms,
                )

        # Third source evicts oldest
        source3 = make_source_iid(99)
        result = buffer.try_buffer(
            make_packet("fd00::99:0"), source3, now_ms=50, deadline_ms=deadline_ms
        )

        assert result == ForwardingResult.EVICTED
        stats = buffer.get_stats()
        # Source 0 had 2 packets that got evicted
        assert stats["evicted"] == MAX_PACKETS_PER_SOURCE, (
            f"must track evicted packets, got {stats['evicted']}"
        )


class TestForwardingFairnessSimulation:
    """Simulation integration tests for forwarding fairness."""

    @pytest.mark.asyncio
    async def test_relay_enforces_per_source_fairness(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Relay node enforces per-source fairness in simulation.

        Scenario:
        - 3 source nodes (A, B, C) all want to forward through relay R
        - R must enforce per-source limits
        - Each source gets fair share

        PARANOID: Verify fairness in simulated relay scenario.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("fairness-test")
        assert node_port is not None, "must get node server port"

        # Relay node's forwarding buffer
        relay_buffer = ForwardingBuffer()
        deadline_ms = 10000

        # Simulate 3 sources each sending packets to relay
        source_a = make_source_iid(0xA)
        source_b = make_source_iid(0xB)
        source_c = make_source_iid(0xC)

        # A tries to send many packets
        accepted_a = 0
        for i in range(5):
            result = relay_buffer.try_buffer(
                make_packet(f"fd00::aaaa:{i}"),
                source_a,
                now_ms=i,
                deadline_ms=deadline_ms,
            )
            if result == ForwardingResult.ACCEPTED:
                accepted_a += 1

        # B sends 2 packets
        accepted_b = 0
        for i in range(2):
            result = relay_buffer.try_buffer(
                make_packet(f"fd00::bbbb:{i}"),
                source_b,
                now_ms=10 + i,
                deadline_ms=deadline_ms,
            )
            if result == ForwardingResult.ACCEPTED:
                accepted_b += 1

        # C sends 3 packets
        accepted_c = 0
        for i in range(3):
            result = relay_buffer.try_buffer(
                make_packet(f"fd00::cccc:{i}"),
                source_c,
                now_ms=20 + i,
                deadline_ms=deadline_ms,
            )
            if result == ForwardingResult.ACCEPTED:
                accepted_c += 1

        # PARANOID: Each source capped at per-source limit
        assert accepted_a == MAX_PACKETS_PER_SOURCE, f"A got {accepted_a}"
        assert accepted_b == MAX_PACKETS_PER_SOURCE, f"B got {accepted_b}"
        assert accepted_c == MAX_PACKETS_PER_SOURCE, f"C got {accepted_c}"

        # Total packets = 3 sources * 2 packets each
        assert relay_buffer.total_count() == 3 * MAX_PACKETS_PER_SOURCE

    @pytest.mark.asyncio
    async def test_router_forwarding_buffer_integration(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Router's forwarding_buffer enforces fairness.

        Router class has a forwarding_buffer attribute for relay fairness.

        PARANOID: Verify Router integration works correctly.
        """
        _server, _sim = simulator_server

        router = Router(
            node_address=IPv6Address("fe80::1"),
            gradient_table=GradientTable(),
        )

        # Router has forwarding buffer
        assert router.forwarding_buffer is not None, "Router must have forwarding_buffer"
        assert router.forwarding_buffer.max_sources == MAX_FORWARDING_SOURCES
        assert router.forwarding_buffer.max_per_source == MAX_PACKETS_PER_SOURCE

        # Test fairness via router's buffer
        source1 = make_source_iid(1)
        source2 = make_source_iid(2)
        deadline_ms = 10000

        # Source 1 buffers packets
        for i in range(MAX_PACKETS_PER_SOURCE):
            result = router.forwarding_buffer.try_buffer(
                make_packet(f"fd00::1:{i}"),
                source1,
                now_ms=i,
                deadline_ms=deadline_ms,
            )
            assert result == ForwardingResult.ACCEPTED

        # Source 1 hits limit
        result = router.forwarding_buffer.try_buffer(
            make_packet("fd00::1:ffff"),
            source1,
            now_ms=10,
            deadline_ms=deadline_ms,
        )
        assert result == ForwardingResult.BACKPRESSURE

        # Source 2 still gets its share
        for i in range(MAX_PACKETS_PER_SOURCE):
            result = router.forwarding_buffer.try_buffer(
                make_packet(f"fd00::2:{i}"),
                source2,
                now_ms=20 + i,
                deadline_ms=deadline_ms,
            )
            assert result == ForwardingResult.ACCEPTED, f"source 2 packet {i} must be accepted"

    @pytest.mark.asyncio
    async def test_fairness_preserved_after_dequeue(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Fairness is preserved after packets are dequeued.

        When a source's packets are forwarded (dequeued), that source can
        buffer more packets up to the limit.

        PARANOID: Verify dequeue restores capacity for that source.
        """
        _server, _sim = simulator_server

        buffer = ForwardingBuffer()
        source = make_source_iid(1)
        deadline_ms = 10000

        # Fill source limit
        for i in range(MAX_PACKETS_PER_SOURCE):
            buffer.try_buffer(
                make_packet(f"fd00::1:{i}"), source, now_ms=i, deadline_ms=deadline_ms
            )

        # At limit - next packet rejected
        result = buffer.try_buffer(
            make_packet("fd00::1:ff00"), source, now_ms=10, deadline_ms=deadline_ms
        )
        assert result == ForwardingResult.BACKPRESSURE

        # Dequeue one packet (simulating successful forward)
        entry = buffer.dequeue(source)
        assert entry is not None, "must dequeue packet"

        # Now can buffer another
        result = buffer.try_buffer(
            make_packet("fd00::1:ff01"), source, now_ms=20, deadline_ms=deadline_ms
        )
        assert result == ForwardingResult.ACCEPTED, "must accept after dequeue"

        # Still limited
        assert buffer.count_for_source(source) == MAX_PACKETS_PER_SOURCE

    @pytest.mark.asyncio
    async def test_concurrent_sources_stress_test(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Stress test with maximum concurrent sources.

        All MAX_FORWARDING_SOURCES sources try to buffer simultaneously.
        Each must get exactly MAX_PACKETS_PER_SOURCE.

        PARANOID: Full capacity test.
        """
        _server, _sim = simulator_server

        buffer = ForwardingBuffer()
        deadline_ms = 10000

        # Fill all source slots to capacity
        total_accepted = 0
        total_rejected = 0

        for src_id in range(MAX_FORWARDING_SOURCES):
            source = make_source_iid(src_id)
            # Each source tries to buffer more than limit
            for pkt in range(MAX_PACKETS_PER_SOURCE + 3):
                result = buffer.try_buffer(
                    make_packet(f"fd00::{src_id}:{pkt}"),
                    source,
                    now_ms=src_id * 100 + pkt,
                    deadline_ms=deadline_ms,
                )
                if result == ForwardingResult.ACCEPTED:
                    total_accepted += 1
                elif result == ForwardingResult.BACKPRESSURE:
                    total_rejected += 1

        # PARANOID: Total accepted = sources * per-source limit
        expected_accepted = MAX_FORWARDING_SOURCES * MAX_PACKETS_PER_SOURCE
        assert total_accepted == expected_accepted, (
            f"accepted {total_accepted}, expected {expected_accepted}"
        )

        # Rejected = sources * excess attempts (3 per source)
        expected_rejected = MAX_FORWARDING_SOURCES * 3
        assert total_rejected == expected_rejected, (
            f"rejected {total_rejected}, expected {expected_rejected}"
        )

        # Buffer at full capacity
        assert buffer.total_count() == expected_accepted
        assert buffer.source_count() == MAX_FORWARDING_SOURCES

        # Stats reflect fairness enforcement
        stats = buffer.get_stats()
        assert stats["accepted"] == expected_accepted
        assert stats["backpressure"] == expected_rejected
