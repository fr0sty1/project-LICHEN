#!/usr/bin/env python3
"""
Pytest-based multi-node mesh test harness for Renode.

Tests mesh formation and message routing between N simulated nodes.
Requires firmware built for target boards.

Usage:
    pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py -v
    pytest ... --board=rak4631  # Different board
    pytest ... --nodes=3        # More nodes
"""

import asyncio
import os
import pytest
import pytest_asyncio
from pathlib import Path

# Skip entire module if Renode not available
pytest.importorskip("lichen.sim.simulation")

# Repo root: .../lichen/boards/renode/nrf52840_lichen/test_mesh.py -> parents[4]
project_root = Path(__file__).resolve().parents[4]
import sys
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.simulation import Simulation
from lichen.sim.renode_server import start_renode_server


@pytest.fixture
def board(request):
    return request.config.getoption("--board")


@pytest.fixture
def num_nodes(request):
    return request.config.getoption("--nodes")


def _find_firmware(board: str) -> Path | None:
    """Locate a firmware ELF for the board, if one has been built."""
    candidates = [
        # Renode build with the UART console overlay (see renode_console.overlay)
        project_root / f"build/{board}_renode/zephyr/zephyr.elf",
        project_root / f"build/{board}/zephyr/zephyr.elf",
        project_root / "build/zephyr/zephyr.elf",
    ]
    for elf in candidates:
        if elf.exists():
            return elf
    return None


@pytest.fixture
def firmware_path(board):
    """Find firmware ELF for the board."""
    elf = _find_firmware(board)
    if elf is None:
        pytest.skip(f"No firmware found for {board}")
    return elf


class RenodeNode:
    """Wrapper for a Renode node process."""

    def __init__(self, node_id: int, board: str, port: int, firmware: Path):
        self.node_id = node_id
        self.board = board
        self.port = port
        self.firmware = firmware
        self.proc = None
        self.uart_lines: list[str] = []

    async def start(self):
        """Start the Renode process."""
        sx1262_cs = project_root / "lichen/boards/renode/peripherals/SX1262.cs"
        platform = project_root / f"lichen/boards/renode/{self.board}/support/{self.board}.repl"

        # Per-node FICR DEVICEID so each node derives a unique EUI-64 / IPv6.
        script = f"""\
:name: TestNode{self.node_id}
include @{sx1262_cs}
mach create "node{self.node_id}"
machine LoadPlatformDescription @{platform}
spi1.sx1262 SimPort {self.port}
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" 0x1CE1{self.node_id:04X}
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" 0x1CE2{self.node_id:04X}
sysbus LoadELF @{self.firmware}
cpu PerformanceInMips 64
start
"""
        script_path = project_root / f"lichen/boards/renode/nrf52840_lichen/_test_node{self.node_id}.resc"
        script_path.write_text(script)

        self.proc = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            "--port", str(10100 + self.node_id),
            str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

    async def stop(self):
        """Stop the Renode process."""
        if self.proc:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except TimeoutError:
                self.proc.kill()


@pytest_asyncio.fixture
async def mesh_simulation(board, num_nodes, firmware_path):
    """Create and manage a multi-node mesh simulation."""
    sim = Simulation("test-mesh")
    servers = []
    nodes = []

    try:
        # Start simulation servers
        for i in range(num_nodes):
            port = 6000 + i
            x = i * 50.0  # 50m spacing
            server, _ = await start_renode_server(
                sim, f"node{i}", port=port, position=(x, 0.0, 0.0)
            )
            servers.append(server)

            node = RenodeNode(i, board, port, firmware_path)
            nodes.append(node)

        # Start Renode processes
        for node in nodes:
            await node.start()

        # Wait for boot
        await asyncio.sleep(3)

        yield {"sim": sim, "nodes": nodes, "servers": servers}

    finally:
        # Cleanup
        for node in nodes:
            await node.stop()
        for server in servers:
            await server.stop()

        # Remove temp scripts
        for i in range(num_nodes):
            script = project_root / f"lichen/boards/renode/nrf52840_lichen/_test_node{i}.resc"
            script.unlink(missing_ok=True)


_NO_FIRMWARE = _find_firmware("t_echo") is None and _find_firmware("rak4631") is None


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No firmware built")
async def test_mesh_boots(mesh_simulation):
    """Test that all nodes boot successfully."""
    nodes = mesh_simulation["nodes"]

    # Verify all processes are running
    for node in nodes:
        assert node.proc is not None
        assert node.proc.returncode is None, f"Node {node.node_id} crashed"


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No firmware built")
async def test_mesh_tx(mesh_simulation):
    """Test that nodes transmit LoRa frames into lichen-sim.

    Validated on Renode 1.16.1: the T-Echo puck firmware beacons over the
    SX1262 bridge, so at least one transmission reaches the simulation.

    Note: end-to-end RX into firmware is not asserted here — the SX1262.cs
    RX path is one-shot at SetRx (see bead project-LICHEN-r7h4.6) and the
    bridge/time-model interaction is unresolved (project-LICHEN-r7h4.7).
    """
    sim = mesh_simulation["sim"]

    # Wait for nodes to boot and emit their first beacon.
    await asyncio.sleep(10)

    # metrics.transmissions counts frames handed to the medium by any node.
    assert sim.metrics.transmissions > 0, "No LoRa transmissions reached lichen-sim"
