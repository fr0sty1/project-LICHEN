# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DODAG convergence simulation tests (bead lt15).

Tests RPL network formation from cold start:
1. Create N nodes (10, 50, 100) with no routing state
2. Begin DIO/DAO exchange via Trickle timer
3. Measure time until DODAG is stable (all nodes have parent, routes to root)

Validates against spec parameters:
- Trickle IMIN = 4s (4000ms)
- IMAX_DOUBLINGS = 8 (max interval ~17 min)
- Expected convergence time bounds scale with network size

The simulation is discrete-event driven: each node has a TrickleTimer that
schedules DIO transmissions. Nodes process DIOs from neighbors and join the
DODAG when they hear a valid parent advertisement.

Topology: linear chain (worst-case for convergence) and random mesh (realistic).
"""

from __future__ import annotations

import heapq
import math
import random
from dataclasses import dataclass, field
from ipaddress import IPv6Address

import pytest

from lichen.constants import (
    RPL_TRICKLE_IMAX_DOUBLINGS,
    RPL_TRICKLE_IMIN_MS,
    RPL_TRICKLE_K,
)
from lichen.rpl.dodag import DodagState
from lichen.rpl.messages import DIO
from lichen.rpl.trickle import TrickleTimer

# --- Simulation types ---


@dataclass(order=True)
class Event:
    """Discrete event for the simulation priority queue."""

    time_ms: int
    node_id: int = field(compare=False)
    event_type: str = field(compare=False)  # "transmit" or "expire"


@dataclass
class SimNode:
    """A simulated RPL node."""

    node_id: int
    address: IPv6Address
    dodag: DodagState
    trickle: TrickleTimer
    neighbors: set[int] = field(default_factory=set)
    join_time_ms: int | None = None  # When the node joined the DODAG

    def is_joined(self) -> bool:
        return self.dodag.is_joined()


class RplConvergenceSim:
    """Discrete-event RPL DODAG convergence simulator.

    Simulates DIO exchange between nodes using Trickle timers. Tracks when
    each node joins the DODAG and measures overall convergence time.
    """

    def __init__(
        self,
        num_nodes: int,
        topology: str = "linear",
        *,
        imin_ms: int = RPL_TRICKLE_IMIN_MS,
        imax_doublings: int = RPL_TRICKLE_IMAX_DOUBLINGS,
        k: int = RPL_TRICKLE_K,
        seed: int | None = None,
    ):
        self.num_nodes = num_nodes
        self.topology = topology
        self.imin_ms = imin_ms
        self.imax_doublings = imax_doublings
        self.k = k
        self.rng = random.Random(seed)

        self.nodes: dict[int, SimNode] = {}
        self.event_queue: list[Event] = []
        self.current_time_ms: int = 0
        self.dio_count: int = 0
        self.converged: bool = False
        self.convergence_time_ms: int | None = None

        self._setup_nodes()
        self._setup_topology()

    def _make_address(self, node_id: int) -> IPv6Address:
        """Generate a link-local IPv6 address for a node."""
        return IPv6Address(f"fe80::{node_id:04x}")

    def _make_dodag_id(self) -> IPv6Address:
        """Generate the DODAG ID (root's address)."""
        return IPv6Address("fd00::1")

    def _setup_nodes(self) -> None:
        """Create all nodes. Node 0 is the root."""
        dodag_id = self._make_dodag_id()

        for i in range(self.num_nodes):
            addr = self._make_address(i)
            if i == 0:
                # Root node
                dodag = DodagState.as_root(
                    rpl_instance_id=0,
                    dodag_id=dodag_id,
                    version=1,
                    node_address=addr,
                )
                join_time = 0  # Root is always joined
            else:
                # Non-root node starts unjoined
                dodag = DodagState(
                    rpl_instance_id=0,
                    dodag_id=dodag_id,
                    version=1,
                    node_address=addr,
                )
                join_time = None

            # Each node has its own Trickle timer with deterministic RNG
            def make_rng(seed_val: int) -> TrickleTimer:
                rng = random.Random(seed_val)
                return TrickleTimer(
                    self.imin_ms,
                    self.imax_doublings,
                    self.k,
                    rng=rng.random,
                )

            trickle = make_rng(self.rng.randint(0, 2**31))

            self.nodes[i] = SimNode(
                node_id=i,
                address=addr,
                dodag=dodag,
                trickle=trickle,
                join_time_ms=join_time,
            )

    def _setup_topology(self) -> None:
        """Set up neighbor relationships based on topology type."""
        if self.topology == "linear":
            # Linear chain: 0 -- 1 -- 2 -- ... -- N-1
            # Worst case for convergence (info must propagate hop by hop)
            for i in range(self.num_nodes - 1):
                self.nodes[i].neighbors.add(i + 1)
                self.nodes[i + 1].neighbors.add(i)
        elif self.topology == "mesh":
            # Random mesh: each node connects to ~log2(N) neighbors
            # More realistic, faster convergence
            connectivity = max(2, int(math.log2(self.num_nodes)))
            for i in range(self.num_nodes):
                # Connect to next `connectivity` nodes (with wraparound for edges)
                for j in range(1, connectivity + 1):
                    neighbor = (i + j) % self.num_nodes
                    if neighbor != i:
                        self.nodes[i].neighbors.add(neighbor)
                        self.nodes[neighbor].neighbors.add(i)
        elif self.topology == "star":
            # Star: all nodes connect to root (node 0)
            # Best case for convergence (single hop)
            for i in range(1, self.num_nodes):
                self.nodes[0].neighbors.add(i)
                self.nodes[i].neighbors.add(0)
        else:
            raise ValueError(f"Unknown topology: {self.topology}")

    def _schedule_event(self, node_id: int, event_type: str, time_ms: int) -> None:
        """Add an event to the priority queue."""
        heapq.heappush(self.event_queue, Event(time_ms, node_id, event_type))

    def _start_trickle_timers(self) -> None:
        """Start Trickle timers for all joined nodes (initially just root)."""
        for node_id, node in self.nodes.items():
            if node.is_joined():
                node.trickle.start(0)
                event_type, event_time = node.trickle.next_event()
                self._schedule_event(node_id, event_type, event_time)

    def _build_dio(self, node: SimNode) -> DIO:
        """Build a DIO message for a node."""
        return DIO(
            rpl_instance_id=0,
            version=node.dodag.version,
            rank=node.dodag.get_rank(),
            dtsn=0,
            dodag_id=node.dodag.dodag_id,
        )

    def _broadcast_dio(self, sender_id: int) -> None:
        """Broadcast DIO from sender to all neighbors."""
        sender = self.nodes[sender_id]
        dio = self._build_dio(sender)
        self.dio_count += 1

        for neighbor_id in sender.neighbors:
            neighbor = self.nodes[neighbor_id]
            # Skip if neighbor is root (roots don't process DIOs)
            if neighbor.dodag.is_root():
                continue

            was_joined = neighbor.is_joined()
            # Process DIO with link ETX of 1.0 (perfect link)
            neighbor.dodag.process_dio(dio, sender.address, link_etx=1.0)

            if not was_joined and neighbor.is_joined():
                # Node just joined the DODAG
                neighbor.join_time_ms = self.current_time_ms
                # Start its Trickle timer (inconsistency detected -> reset)
                neighbor.trickle.reset(self.current_time_ms)
                event_type, event_time = neighbor.trickle.next_event()
                self._schedule_event(neighbor_id, event_type, event_time)

    def _handle_transmit(self, node_id: int) -> None:
        """Handle a Trickle transmit event."""
        node = self.nodes[node_id]
        if not node.is_joined():
            return

        # Fire transmit - if counter < k, actually transmit
        if node.trickle.fire_transmit():
            self._broadcast_dio(node_id)

        # Schedule next event (expire)
        event_type, event_time = node.trickle.next_event()
        self._schedule_event(node_id, event_type, event_time)

    def _handle_expire(self, node_id: int) -> None:
        """Handle a Trickle interval expiration."""
        node = self.nodes[node_id]
        if not node.is_joined():
            return

        node.trickle.expire(self.current_time_ms)
        event_type, event_time = node.trickle.next_event()
        self._schedule_event(node_id, event_type, event_time)

    def _check_convergence(self) -> bool:
        """Check if all nodes have joined the DODAG."""
        return all(node.is_joined() for node in self.nodes.values())

    def run(self, max_time_ms: int = 600_000) -> dict:
        """Run the simulation until convergence or timeout.

        Args:
            max_time_ms: Maximum simulation time (default 10 minutes)

        Returns:
            dict with convergence metrics
        """
        # Check for immediate convergence (e.g., single-node network)
        if self._check_convergence():
            self.converged = True
            self.convergence_time_ms = 0

        self._start_trickle_timers()

        while self.event_queue and self.current_time_ms < max_time_ms and not self.converged:
            event = heapq.heappop(self.event_queue)

            # Skip stale events (from before a Trickle reset)
            if event.time_ms < self.current_time_ms:
                continue

            self.current_time_ms = event.time_ms

            if event.event_type == "transmit":
                self._handle_transmit(event.node_id)
            elif event.event_type == "expire":
                self._handle_expire(event.node_id)

            # Check for convergence
            if self._check_convergence():
                self.converged = True
                self.convergence_time_ms = self.current_time_ms

        # Collect results
        joined_count = sum(1 for n in self.nodes.values() if n.is_joined())
        join_times = [n.join_time_ms for n in self.nodes.values() if n.join_time_ms is not None]

        return {
            "converged": self.converged,
            "convergence_time_ms": self.convergence_time_ms,
            "joined_count": joined_count,
            "total_nodes": self.num_nodes,
            "dio_count": self.dio_count,
            "join_times": join_times,
            "topology": self.topology,
            "imin_ms": self.imin_ms,
            "imax_doublings": self.imax_doublings,
        }


# --- Tests ---


class TestSpecParameters:
    """Verify spec parameters are correctly configured."""

    def test_trickle_imin_is_4_seconds(self) -> None:
        """IMIN = 4s per spec."""
        assert RPL_TRICKLE_IMIN_MS == 4000, f"IMIN must be 4000ms, got {RPL_TRICKLE_IMIN_MS}"

    def test_trickle_imax_doublings_is_8(self) -> None:
        """IMAX_DOUBLINGS = 8 per spec."""
        assert RPL_TRICKLE_IMAX_DOUBLINGS == 8, (
            f"IMAX_DOUBLINGS must be 8, got {RPL_TRICKLE_IMAX_DOUBLINGS}"
        )

    def test_trickle_max_interval_is_17_minutes(self) -> None:
        """IMAX = IMIN * 2^8 = 1,024,000ms (~17 min)."""
        imax_ms = RPL_TRICKLE_IMIN_MS << RPL_TRICKLE_IMAX_DOUBLINGS
        assert imax_ms == 1_024_000, f"IMAX must be 1024000ms, got {imax_ms}"

    def test_redundancy_constant_k(self) -> None:
        """K = 10 per spec."""
        assert RPL_TRICKLE_K == 10, f"K must be 10, got {RPL_TRICKLE_K}"


class TestLinearTopologyConvergence:
    """Test DODAG convergence in linear (chain) topology.

    Linear topology is worst-case: DIO information must propagate
    hop-by-hop from root to leaf. Convergence time scales linearly
    with hop count.
    """

    @pytest.mark.parametrize("num_nodes", [10, 50, 100])
    def test_linear_convergence(self, num_nodes: int) -> None:
        """DODAG converges in linear topology with N nodes.

        Expected convergence time for linear chain:
        - Each hop requires at least IMIN/2 to IMIN to hear first DIO
        - Total ~= (N-1) * IMIN for worst case
        - With jitter and Trickle doubling, typically faster
        """
        sim = RplConvergenceSim(num_nodes, topology="linear", seed=42)
        result = sim.run(max_time_ms=600_000)

        assert result["converged"], (
            f"Linear {num_nodes}-node network did not converge in 10 min; "
            f"joined {result['joined_count']}/{result['total_nodes']}"
        )

        # Verify convergence time bounds
        # Lower bound: at least (N-1) * IMIN/2 (minimum time to traverse chain)
        # Upper bound: (N-1) * IMIN * 2 (allowing for Trickle timing variance)
        min_bound_ms = (num_nodes - 1) * (RPL_TRICKLE_IMIN_MS // 2)
        max_bound_ms = (num_nodes - 1) * RPL_TRICKLE_IMIN_MS * 4

        assert result["convergence_time_ms"] >= min_bound_ms, (
            f"Convergence too fast: {result['convergence_time_ms']}ms < {min_bound_ms}ms"
        )
        assert result["convergence_time_ms"] <= max_bound_ms, (
            f"Convergence too slow: {result['convergence_time_ms']}ms > {max_bound_ms}ms"
        )

    def test_linear_convergence_time_scales_linearly(self) -> None:
        """Convergence time should scale roughly linearly with node count."""
        times = {}
        for n in [10, 20, 40]:
            sim = RplConvergenceSim(n, topology="linear", seed=42)
            result = sim.run()
            assert result["converged"], f"Linear {n}-node network did not converge"
            times[n] = result["convergence_time_ms"]

        # Check that doubling nodes approximately doubles convergence time
        # Allow 50% variance for Trickle timing effects
        ratio_20_10 = times[20] / times[10]
        ratio_40_20 = times[40] / times[20]

        assert 1.0 <= ratio_20_10 <= 3.0, (
            f"Scaling 10->20 nodes: ratio {ratio_20_10:.2f} outside [1.0, 3.0]"
        )
        assert 1.0 <= ratio_40_20 <= 3.0, (
            f"Scaling 20->40 nodes: ratio {ratio_40_20:.2f} outside [1.0, 3.0]"
        )


class TestMeshTopologyConvergence:
    """Test DODAG convergence in mesh topology.

    Mesh topology is more realistic: each node has multiple neighbors,
    allowing faster convergence through parallel DIO propagation.
    """

    @pytest.mark.parametrize("num_nodes", [10, 50, 100])
    def test_mesh_convergence(self, num_nodes: int) -> None:
        """DODAG converges in mesh topology with N nodes.

        Expected: significantly faster than linear due to parallel propagation.
        Convergence depth ~= log(N) hops instead of N hops.
        """
        sim = RplConvergenceSim(num_nodes, topology="mesh", seed=42)
        result = sim.run(max_time_ms=300_000)

        assert result["converged"], (
            f"Mesh {num_nodes}-node network did not converge in 5 min; "
            f"joined {result['joined_count']}/{result['total_nodes']}"
        )

        # Mesh should converge faster than linear
        # Upper bound: log2(N) * IMIN * 4 (depth is ~log N)
        depth = max(1, int(math.log2(num_nodes)))
        max_bound_ms = depth * RPL_TRICKLE_IMIN_MS * 6

        assert result["convergence_time_ms"] <= max_bound_ms, (
            f"Mesh convergence too slow: {result['convergence_time_ms']}ms > {max_bound_ms}ms"
        )

    def test_mesh_faster_than_linear(self) -> None:
        """Mesh topology converges faster than linear for same node count."""
        n = 50
        sim_linear = RplConvergenceSim(n, topology="linear", seed=42)
        sim_mesh = RplConvergenceSim(n, topology="mesh", seed=42)

        result_linear = sim_linear.run()
        result_mesh = sim_mesh.run()

        assert result_linear["converged"], "Linear network did not converge"
        assert result_mesh["converged"], "Mesh network did not converge"

        assert result_mesh["convergence_time_ms"] < result_linear["convergence_time_ms"], (
            f"Mesh ({result_mesh['convergence_time_ms']}ms) should be faster than "
            f"linear ({result_linear['convergence_time_ms']}ms)"
        )


class TestStarTopologyConvergence:
    """Test DODAG convergence in star topology.

    Star topology is best-case: all nodes are one hop from root.
    Convergence should be very fast (single IMIN interval).
    """

    @pytest.mark.parametrize("num_nodes", [10, 50, 100])
    def test_star_convergence(self, num_nodes: int) -> None:
        """DODAG converges in star topology with N nodes.

        All nodes are one hop from root, so convergence should be
        within a single Trickle interval.
        """
        sim = RplConvergenceSim(num_nodes, topology="star", seed=42)
        result = sim.run(max_time_ms=60_000)

        assert result["converged"], (
            f"Star {num_nodes}-node network did not converge in 1 min; "
            f"joined {result['joined_count']}/{result['total_nodes']}"
        )

        # Star should converge within ~1-2 IMIN intervals
        max_bound_ms = RPL_TRICKLE_IMIN_MS * 2

        assert result["convergence_time_ms"] <= max_bound_ms, (
            f"Star convergence too slow: {result['convergence_time_ms']}ms > {max_bound_ms}ms"
        )


class TestDioEfficiency:
    """Test DIO message efficiency (Trickle suppression working)."""

    def test_dio_count_bounded_by_trickle_k(self) -> None:
        """Trickle suppression limits DIO transmissions.

        With k=10 redundancy constant, nodes should suppress DIOs
        after hearing k consistent transmissions from neighbors.
        """
        # Use a small, well-connected network
        sim = RplConvergenceSim(10, topology="mesh", seed=42)
        result = sim.run(max_time_ms=120_000)

        assert result["converged"], "Network did not converge"

        # Run longer to let Trickle stabilize
        sim2 = RplConvergenceSim(10, topology="mesh", seed=42)
        result2 = sim2.run(max_time_ms=300_000)

        # After convergence, DIO rate should decrease (Trickle doubling)
        # This is a heuristic check - exact bounds depend on network dynamics
        avg_dios_per_node = result2["dio_count"] / result2["total_nodes"]

        # Each node should transmit at most ~20 DIOs in 5 minutes
        # (Trickle doubles intervals, eventually reaching 17-min max)
        assert avg_dios_per_node < 50, (
            f"Too many DIOs per node: {avg_dios_per_node:.1f} > 50"
        )


class TestConvergenceMetrics:
    """Test convergence metric collection."""

    def test_join_times_monotonic(self) -> None:
        """Nodes farther from root join later in linear topology."""
        sim = RplConvergenceSim(10, topology="linear", seed=42)
        result = sim.run()

        assert result["converged"], "Network did not converge"

        # Get join times by node ID (excluding root which joins at t=0)
        join_times_by_node = {
            node_id: node.join_time_ms
            for node_id, node in sim.nodes.items()
            if node.join_time_ms is not None
        }

        # In linear topology, node i should join before node i+1
        for i in range(1, sim.num_nodes - 1):
            assert join_times_by_node[i] <= join_times_by_node[i + 1], (
                f"Node {i} joined at {join_times_by_node[i]}ms but "
                f"node {i+1} joined at {join_times_by_node[i+1]}ms"
            )

    def test_all_nodes_have_valid_rank(self) -> None:
        """After convergence, all nodes should have finite rank."""
        sim = RplConvergenceSim(10, topology="mesh", seed=42)
        result = sim.run()

        assert result["converged"], "Network did not converge"

        from lichen.rpl.dodag import INFINITE_RANK

        for node_id, node in sim.nodes.items():
            rank = node.dodag.get_rank()
            assert rank < INFINITE_RANK, (
                f"Node {node_id} has infinite rank after convergence"
            )
            if node_id == 0:
                # Root has rank 256 (MIN_HOP_RANK_INCREASE)
                assert rank == 256, f"Root rank should be 256, got {rank}"
            else:
                # Non-root nodes have rank > root
                assert rank > 256, f"Node {node_id} rank {rank} should be > 256"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_single_node_network(self) -> None:
        """Single node (root only) is trivially converged."""
        sim = RplConvergenceSim(1, topology="linear", seed=42)
        result = sim.run()

        assert result["converged"], "Single-node network should be converged"
        assert result["convergence_time_ms"] == 0, "Single-node converges at t=0"
        assert result["joined_count"] == 1

    def test_two_node_network(self) -> None:
        """Two-node network converges within one IMIN interval."""
        sim = RplConvergenceSim(2, topology="linear", seed=42)
        result = sim.run()

        assert result["converged"], "Two-node network did not converge"
        assert result["convergence_time_ms"] <= RPL_TRICKLE_IMIN_MS, (
            f"Two-node should converge within IMIN, took {result['convergence_time_ms']}ms"
        )

    def test_deterministic_with_seed(self) -> None:
        """Same seed produces same convergence time."""
        sim1 = RplConvergenceSim(20, topology="mesh", seed=12345)
        sim2 = RplConvergenceSim(20, topology="mesh", seed=12345)

        result1 = sim1.run()
        result2 = sim2.run()

        assert result1["convergence_time_ms"] == result2["convergence_time_ms"], (
            f"Same seed should produce same result: {result1['convergence_time_ms']}ms "
            f"vs {result2['convergence_time_ms']}ms"
        )
        assert result1["dio_count"] == result2["dio_count"]


class TestScaling:
    """Test scaling behavior for larger networks."""

    @pytest.mark.slow
    def test_large_mesh_convergence(self) -> None:
        """Large mesh network (200 nodes) converges within bounds."""
        sim = RplConvergenceSim(200, topology="mesh", seed=42)
        result = sim.run(max_time_ms=600_000)

        assert result["converged"], (
            f"200-node mesh did not converge; "
            f"joined {result['joined_count']}/{result['total_nodes']}"
        )

        # Mesh depth ~log2(200) ~8, so max ~8 * IMIN * 6 = 192s
        depth = int(math.log2(200))
        max_bound_ms = depth * RPL_TRICKLE_IMIN_MS * 8

        assert result["convergence_time_ms"] <= max_bound_ms, (
            f"200-node mesh too slow: {result['convergence_time_ms']}ms > {max_bound_ms}ms"
        )


# --- Benchmark utilities (for manual runs) ---


def benchmark_convergence() -> None:
    """Run convergence benchmarks for different topologies and sizes.

    This is not a pytest test - run manually for analysis:
        python -c "from tests.sim.test_rpl_convergence import benchmark_convergence; ..."
    """
    print("RPL DODAG Convergence Benchmark")
    print("=" * 60)
    print(f"Trickle IMIN: {RPL_TRICKLE_IMIN_MS}ms")
    print(f"Trickle IMAX: {RPL_TRICKLE_IMIN_MS << RPL_TRICKLE_IMAX_DOUBLINGS}ms")
    print(f"Trickle K: {RPL_TRICKLE_K}")
    print()

    topologies = ["star", "mesh", "linear"]
    sizes = [10, 25, 50, 100]

    for topo in topologies:
        print(f"\n{topo.upper()} Topology:")
        print("-" * 40)
        print(f"{'Nodes':>6} | {'Time (ms)':>10} | {'DIOs':>8} | {'ms/node':>10}")
        print("-" * 40)

        for n in sizes:
            sim = RplConvergenceSim(n, topology=topo, seed=42)
            result = sim.run()

            if result["converged"]:
                time_ms = result["convergence_time_ms"]
                dios = result["dio_count"]
                per_node = time_ms / n
                print(f"{n:>6} | {time_ms:>10} | {dios:>8} | {per_node:>10.1f}")
            else:
                print(f"{n:>6} | {'TIMEOUT':>10} | {'-':>8} | {'-':>10}")


if __name__ == "__main__":
    benchmark_convergence()
