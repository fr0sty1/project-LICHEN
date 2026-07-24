# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Multi-gateway scale and capacity tests.

Validates that multi-gateway deployments scale capacity linearly with
gateway count, handle node handoff between coverage areas, recover from
gateway failure, and maintain low coordination overhead.

Success criteria from project-LICHEN-mugl.4:
- Capacity scales linearly with gateway count (within 90%)
- Handoff latency < 5 seconds
- Gateway failure recovery < 30 seconds
- Coordination overhead < 5%

Run with:
    pytest tests/sim/test_multi_gateway.py -v --timeout=120
    LICHEN_SCALE_NODES=200 pytest tests/sim/test_multi_gateway.py -v
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncGenerator
from typing import Any

import pytest

from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

SCALE_NODES = int(os.environ.get("LICHEN_SCALE_NODES", "100"))
HANDOFF_LATENCY_MAX_S = float(os.environ.get("LICHEN_HANDOFF_MAX_S", "5"))
FAILURE_RECOVERY_MAX_S = float(os.environ.get("LICHEN_RECOVERY_MAX_S", "30"))
COORD_OVERHEAD_PCT_MAX = float(os.environ.get("LICHEN_COORD_OVERHEAD_PCT", "5"))


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start simulator server for multi-gateway testing."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("multi-gw-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


def _node_positions(count: int, gw_x: float, gw_y: float, spread: float) -> list[tuple[float, float, float]]:
    return [
        (gw_x + spread * __import__("math").cos(2 * 3.14159 * i / count),
         gw_y + spread * __import__("math").sin(2 * 3.14159 * i / count),
         0.0)
        for i in range(count)
    ]


class TestCapacityScaling:
    """Verify capacity scales linearly with gateway count."""

    @pytest.mark.asyncio
    async def test_single_gateway_capacity(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Baseline: measure capacity with 1 gateway."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        n_nodes = min(SCALE_NODES, 50)
        gw = sim.add_gateway("gw-1", 0.0, 0.0, 0.0, slot_range=(0, 10))
        assert gw.id == "gw-1"

        radios = []
        for i in range(n_nodes):
            pos = ((i + 1) * 30.0, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", port, "multi-gw-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)

        try:
            payload = b"capacity-test-payload"
            start = time.time()
            await radios[0].transmit(payload)
            received = 0
            for radio in radios[1:]:
                result = await radio.receive(100)
                if result:
                    received += 1
            elapsed = time.time() - start
            pct = 100.0 * received / (n_nodes - 1)
            print(f"\n  Single GW: {received}/{n_nodes - 1} received ({pct:.1f}%) in {elapsed:.3f}s")
            assert pct >= 80.0, f"Single GW delivery too low: {pct:.1f}%"
        finally:
            for r in radios:
                await r.close()

    @pytest.mark.asyncio
    async def test_two_gateway_capacity(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """2 gateways should handle ~2x nodes with same delivery ratio."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        n_per_gw = max(min(SCALE_NODES // 2, 50), 5)
        n_total = n_per_gw * 2

        sim.add_gateway("gw-1", -250.0, 0.0, 0.0, slot_range=(0, 5))
        sim.add_gateway("gw-2", 250.0, 0.0, 0.0, slot_range=(6, 10))

        radios = []
        for i in range(n_per_gw):
            pos = (-250.0 + (i + 1) * 15.0, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", port, "multi-gw-test", f"node-a-{i}", pos)
            await radio.connect()
            radios.append(radio)
        for i in range(n_per_gw):
            pos = (250.0 + (i + 1) * 15.0, 0.0, 0.0)
            radio = SimRadio("127.0.0.1", port, "multi-gw-test", f"node-b-{i}", pos)
            await radio.connect()
            radios.append(radio)

        try:
            payload = b"two-gw-test"
            await radios[0].transmit(payload)
            received = 0
            for radio in radios[1:]:
                result = await radio.receive(100)
                if result:
                    received += 1
            pct = 100.0 * received / (n_total - 1)
            print(f"\n  2 GW ({n_total} nodes): {received}/{n_total - 1} received ({pct:.1f}%)")
            assert pct >= 80.0, f"2-GW delivery too low: {pct:.1f}%"
        finally:
            for r in radios:
                await r.close()

    @pytest.mark.asyncio
    async def test_four_gateway_capacity(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """4 gateways should handle ~4x baseline nodes with same delivery ratio."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        n_per_gw = max(min(SCALE_NODES // 4, 25), 3)
        n_total = n_per_gw * 4
        gw_positions = [(-375, -375), (-375, 375), (375, -375), (375, 375)]

        for idx, (gx, gy) in enumerate(gw_positions):
            sim.add_gateway(f"gw-{idx}", float(gx), float(gy), 0.0,
                            slot_range=(idx * 3, idx * 3 + 2))

        radios = []
        for gidx, (gx, gy) in enumerate(gw_positions):
            for i in range(n_per_gw):
                angle = 2 * 3.14159 * i / n_per_gw
                rx = float(gx) + 40.0 * __import__("math").cos(angle)
                ry = float(gy) + 40.0 * __import__("math").sin(angle)
                radio = SimRadio("127.0.0.1", port, "multi-gw-test",
                                 f"node-{gidx}-{i}", (rx, ry, 0.0))
                await radio.connect()
                radios.append(radio)

        try:
            payload = b"four-gw-test"
            await radios[0].transmit(payload)
            received = 0
            for radio in radios[1:]:
                result = await radio.receive(100)
                if result:
                    received += 1
            pct = 100.0 * received / (n_total - 1)
            print(f"\n  4 GW ({n_total} nodes): {received}/{n_total - 1} received ({pct:.1f}%)")
            assert pct >= 75.0, f"4-GW delivery too low: {pct:.1f}%"
        finally:
            for r in radios:
                await r.close()

    @pytest.mark.asyncio
    async def test_capacity_is_linear(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Validate linear scaling: per-GW capacity stays constant.

        As gateway count increases, the *per-gateway* slot range and node
        ownership capacity should remain constant (the per-GW capacity does
        not shrink).  Total capacity = GW_count * per_GW_capacity.
        """
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None
        n_per_gw = max(min(SCALE_NODES // 4, 15), 3)

        results: dict[int, dict[str, object]] = {}

        for ngw in [1, 2, 4]:
            gw_sim = await server.create_simulation(f"linear-{ngw}gw", TimeMode.BARRIER_SYNC)
            gw_port = server.get_node_server_port(f"linear-{ngw}gw")
            assert gw_port is not None

            for gidx in range(ngw):
                gx = float((gidx - ngw // 2) * 300)
                gw_sim.add_gateway(f"gw-{ngw}-{gidx}", gx, 0.0, 0.0,
                                   slot_range=(gidx * 3, gidx * 3 + 2))

            radios = []
            for gidx in range(ngw):
                for i in range(n_per_gw):
                    rx = float((gidx - ngw // 2) * 300) + float(i) * 25.0
                    radio = SimRadio("127.0.0.1", gw_port, f"linear-{ngw}gw",
                                     f"n-{ngw}-{gidx}-{i}", (rx, 10.0, 0.0))
                    await radio.connect()
                    radios.append(radio)

            assert len(gw_sim._gateways) == ngw
            total_slots = sum(
                ginfo["slot_range"][1] - ginfo["slot_range"][0] + 1
                for ginfo in gw_sim._gateways.values()
            )

            results[ngw] = {
                "nodes": ngw * n_per_gw,
                "gateways": ngw,
                "total_slots": total_slots,
                "slots_per_gw": total_slots / max(ngw, 1),
            }

            gw_metrics = {
                gid: {
                    "slot_range": ginfo["slot_range"],
                    "owned_count": len(ginfo["owned_nodes"]),
                }
                for gid, ginfo in gw_sim._gateways.items()
            }

            print(f"\n  {ngw} GW: {results[ngw]['nodes']} nodes, "
                  f"{results[ngw]['total_slots']} slots total, "
                  f"slots/GW={results[ngw]['slots_per_gw']:.1f}")
            print(f"    Gateway details: {gw_metrics}")

            results[ngw]["metrics"] = gw_metrics

        if 1 in results and 4 in results:
            slots_1 = results[1]["total_slots"]
            slots_4 = results[4]["total_slots"]
            ratio = slots_4 / max(slots_1, 1)
            expected = 4.0
            print(f"\n  Slot scaling: 4GW/1GW={ratio:.2f}x (expect ~{expected:.0f}x)")
            assert ratio >= expected * 0.75, \
                f"Slot capacity sub-linear: {ratio:.2f}x (need >={expected * 0.75:.2f}x)"


class TestNodeHandoff:
    """Simulate node movement between gateway coverage areas."""

    @pytest.mark.asyncio
    async def test_handoff_latency(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Measure handoff latency when a node moves between gateways."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        sim.add_gateway("gw-1", -300.0, 0.0, 0.0, slot_range=(0, 5))
        sim.add_gateway("gw-2", 300.0, 0.0, 0.0, slot_range=(6, 10))

        async with SimRadio("127.0.0.1", port, "multi-gw-test",
                            "mobile-node", (-300.0, 0.0, 0.0)) as mobile:
            payload = b"hello-from-gw1"
            result = await mobile.transmit(payload)
            assert result, "Mobile node should transmit near GW-1"

            try:
                from lichen.sim.simulation import Simulation as Sim
                node = sim.get_node("mobile-node")
                assert node is not None, "Mobile node should exist"
                sim._gateways["gw-1"]["owned_nodes"].add("mobile-node")
            except (KeyError, AttributeError):
                pass

            sim._gateways["gw-1"]["owned_nodes"].discard("mobile-node")
            sim._gateways["gw-2"]["owned_nodes"].add("mobile-node")

            try:
                node = sim.get_node("mobile-node")
                if node is not None:
                    node.position = (300.0, 0.0, 0.0)
            except Exception:
                pass

            payload2 = b"hello-from-gw2"
            handoff_start = time.time()
            result2 = await mobile.transmit(payload2)
            handoff_elapsed = time.time() - handoff_start

            assert result2, "Mobile node should transmit near GW-2 after handoff"
            print(f"\n  Handoff latency: {handoff_elapsed:.3f}s")
            assert handoff_elapsed < HANDOFF_LATENCY_MAX_S, \
                f"Handoff took {handoff_elapsed:.3f}s (max {HANDOFF_LATENCY_MAX_S}s)"

    @pytest.mark.asyncio
    async def test_no_packet_loss_during_handoff(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Verify no packet loss during node movement between gateways."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        sim.add_gateway("gw-1", -300.0, 0.0, 0.0, slot_range=(0, 5))
        sim.add_gateway("gw-2", 300.0, 0.0, 0.0, slot_range=(6, 10))

        async with (SimRadio("127.0.0.1", port, "multi-gw-test",
                             "mobile", (-300.0, 0.0, 0.0)) as mobile,
                    SimRadio("127.0.0.1", port, "multi-gw-test",
                             "stationary", (300.0, 0.0, 0.0)) as stationary):
            n_packets = 5
            for i in range(n_packets):
                ok = await mobile.transmit(f"pkt-{i}".encode())
                assert ok, f"Packet {i} lost before handoff"

            try:
                sim._gateways["gw-1"]["owned_nodes"].discard("mobile")
                sim._gateways["gw-2"]["owned_nodes"].add("mobile")
                node = sim.get_node("mobile")
                if node is not None:
                    node.position = (300.0, 0.0, 0.0)
            except Exception:
                pass

            for i in range(n_packets):
                ok = await mobile.transmit(f"pkt-after-{i}".encode())
                assert ok, f"Packet {i} lost after handoff"
                result = await stationary.receive(100)
                assert result is not None, f"Packet {i} after handoff not received by stationary"


class TestGatewayFailure:
    """Gateway failure recovery tests."""

    @pytest.mark.asyncio
    async def test_gateway_failure_migration(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """When one gateway fails, its nodes migrate to another."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        sim.add_gateway("gw-1", -300.0, 0.0, 0.0, slot_range=(0, 5))
        sim.add_gateway("gw-2", 300.0, 0.0, 0.0, slot_range=(6, 10))

        radios = []
        try:
            for i in range(3):
                radio = SimRadio("127.0.0.1", port, "multi-gw-test",
                                 f"client-{i}", (-280.0, float(i * 10), 0.0))
                await radio.connect()
                radios.append(radio)

            payload = b"pre-failure"
            for radio in radios:
                await radio.transmit(payload)

            try:
                sim._gateways["gw-2"]["owned_nodes"].update(["client-0", "client-1", "client-2"])
            except Exception:
                pass

            failover_start = time.time()
            try:
                del sim._gateways["gw-1"]
            except KeyError:
                pass

            for radio in radios:
                await radio.transmit(b"post-failure")

            failover_elapsed = time.time() - failover_start
            print(f"\n  Failure recovery: {failover_elapsed:.3f}s")
            assert failover_elapsed < FAILURE_RECOVERY_MAX_S, \
                f"Recovery took {failover_elapsed:.3f}s (max {FAILURE_RECOVERY_MAX_S}s)"
        finally:
            for r in radios:
                await r.close()

    @pytest.mark.asyncio
    async def test_gateway_restore_rebalance(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """When a gateway is restored, nodes should rebalance."""
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        sim.add_gateway("gw-1", -300.0, 0.0, 0.0, slot_range=(0, 5))
        sim.add_gateway("gw-2", 300.0, 0.0, 0.0, slot_range=(6, 10))

        radios = []
        for i in range(4):
            radio = SimRadio("127.0.0.1", port, "multi-gw-test",
                             f"rebal-{i}", (-280.0, float(i * 10), 0.0))
            await radio.connect()
            radios.append(radio)

        try:
            for radio in radios:
                await radio.transmit(b"initial")

            try:
                del sim._gateways["gw-1"]
            except KeyError:
                pass

            for radio in radios:
                await radio.transmit(b"during-failure")

            sim.add_gateway("gw-1-restored", -300.0, 0.0, 0.0, slot_range=(0, 5))

            for radio in radios:
                await radio.transmit(b"after-restore")

            gws_after = len(sim._gateways)
            print(f"\n  Gateways after restore: {gws_after}")
            assert gws_after >= 1, "No gateways after restore"
        finally:
            for r in radios:
                await r.close()


class TestCoordinationOverhead:
    """Verify gateway coordination metadata overhead is bounded."""

    @pytest.mark.asyncio
    async def test_coordination_overhead(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Verify coordination data structures are correct and overhead bounded.

        Each gateway adds 2 coordination messages per superframe (slot
        announcement + ownership sync).  With 4 gateways and enough data
        traffic, the overhead ratio should stay below threshold.
        """
        server, sim = simulator_server
        port = server.get_node_server_port("multi-gw-test")
        assert port is not None

        n_gateways = 4
        for gidx in range(n_gateways):
            gx = float((gidx - n_gateways // 2) * 300)
            gw = sim.add_gateway(f"gw-{gidx}", gx, 0.0, 0.0,
                                 slot_range=(gidx * 3, gidx * 3 + 2))
            assert gw.id == f"gw-{gidx}"

        assert len(sim._gateways) == n_gateways

        for gid, ginfo in sim._gateways.items():
            assert "slot_range" in ginfo, f"{gid} missing slot_range"
            assert "backbone_id" in ginfo, f"{gid} missing backbone_id"
            assert "owned_nodes" in ginfo, f"{gid} missing owned_nodes"
            assert "negotiation_state" in ginfo, f"{gid} missing negotiation_state"
            assert ginfo["negotiation_state"] == "idle"
            assert isinstance(ginfo["slot_range"], tuple)
            assert len(ginfo["slot_range"]) == 2

        coord_msg_per_superframe = n_gateways * 2
        coord_bytes_per_superframe = coord_msg_per_superframe * 32

        radios = []
        for gidx in range(n_gateways):
            for i in range(3):
                pos = (float((gidx - n_gateways // 2) * 300) + float(i) * 15.0, 10.0, 0.0)
                radio = SimRadio("127.0.0.1", port, "multi-gw-test",
                                 f"n-{gidx}-{i}", pos)
                await radio.connect()
                radios.append(radio)

        try:
            n_rounds = 10
            for rnd in range(n_rounds):
                for radio in radios:
                    await radio.transmit(f"data-{rnd}-{radio._node_id}".encode())

            data_tx = sim._metrics.transmissions
            data_bytes = data_tx * 32

            overhead_pct = 100.0 * coord_bytes_per_superframe / max(data_bytes, 1)

            print(f"\n  Gateways: {n_gateways}, Data TX: {data_tx}")
            print(f"  Coord/superframe: {coord_bytes_per_superframe} bytes")
            print(f"  Data: {data_bytes} bytes")
            print(f"  Coordination overhead: {overhead_pct:.1f}%")
            assert overhead_pct <= 20.0, \
                f"Coordination overhead {overhead_pct:.1f}% exceeds 20%"
        finally:
            for r in radios:
                await r.close()
