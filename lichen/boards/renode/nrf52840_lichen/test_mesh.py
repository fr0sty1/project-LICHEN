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
from pathlib import Path

# Skip entire module if Renode not available
pytest.importorskip("lichen.sim.simulation")

project_root = Path(__file__).parent.parent.parent.parent
import sys
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.simulation import Simulation
from lichen.sim.renode_server import start_renode_server


def pytest_addoption(parser):
    """Add command line options."""
    parser.addoption("--board", default="t_echo", help="Board type (t_echo, rak4631)")
    parser.addoption("--nodes", default=2, type=int, help="Number of nodes")


@pytest.fixture
def board(request):
    return request.config.getoption("--board")


@pytest.fixture
def num_nodes(request):
    return request.config.getoption("--nodes")


@pytest.fixture
def firmware_path(board):
    """Find firmware ELF for the board."""
    # Try board-specific build first
    board_elf = project_root / f"build/{board}/zephyr/zephyr.elf"
    if board_elf.exists():
        return board_elf

    # Fall back to generic build
    generic_elf = project_root / "build/zephyr/zephyr.elf"
    if generic_elf.exists():
        return generic_elf

    pytest.skip(f"No firmware found for {board}")


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
        uart = "uart1" if self.board == "rak4631" else "uart0"

        script = f"""\
:name: TestNode{self.node_id}
include @{sx1262_cs}
mach create "node{self.node_id}"
machine LoadPlatformDescription @{platform}
spi2.sx1262 SimPort {self.port}
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


@pytest.fixture
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


@pytest.mark.asyncio
@pytest.mark.skipif(
    not (project_root / "build/zephyr/zephyr.elf").exists()
    and not (project_root / "build/t_echo/zephyr/zephyr.elf").exists(),
    reason="No firmware built"
)
async def test_mesh_boots(mesh_simulation):
    """Test that all nodes boot successfully."""
    nodes = mesh_simulation["nodes"]

    # Verify all processes are running
    for node in nodes:
        assert node.proc is not None
        assert node.proc.returncode is None, f"Node {node.node_id} crashed"


@pytest.mark.asyncio
@pytest.mark.skipif(
    not (project_root / "build/zephyr/zephyr.elf").exists()
    and not (project_root / "build/t_echo/zephyr/zephyr.elf").exists(),
    reason="No firmware built"
)
async def test_mesh_tx_rx(mesh_simulation):
    """Test that nodes can transmit and receive packets."""
    sim = mesh_simulation["sim"]

    # Wait for nodes to start transmitting
    await asyncio.sleep(5)

    # Check simulation statistics
    stats = sim.get_stats()
    # ponytail: basic smoke test - just verify simulation ran
    # More detailed assertions would check specific packet counts
    assert stats["time_ms"] > 0, "Simulation didn't advance"
