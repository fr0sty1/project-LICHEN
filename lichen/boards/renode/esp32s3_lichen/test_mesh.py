#!/usr/bin/env python3
"""
Pytest-based multi-node mesh test harness for ESP32-S3 Renode.

Tests mesh formation and message routing between N simulated ESP32-S3 nodes.
Requires firmware built for target boards.

Usage:
    pytest lichen/boards/renode/esp32s3_lichen/test_mesh.py -v
    pytest ... --board=heltec_wifi_lora32_v3  # Explicit board
    pytest ... --nodes=3                       # More nodes
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

import pytest
import pytest_asyncio

# Skip entire module if Renode not available
pytest.importorskip("lichen.sim.simulation")

# Repo root: .../lichen/boards/renode/esp32s3_lichen/test_mesh.py -> parents[4]
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server  # noqa: E402
from lichen.sim.simulation import Simulation  # noqa: E402

# ESP32-S3 does not use MCUboot; firmware entry is handled by the ROM bootloader
# and Zephyr's ESP32 startup code. No manual vector table manipulation needed.

# Rotating base for each test's sim ports (and the +4000 Renode monitor ports),
# so consecutive test cases in one run never reuse the same ports.
_port_base_counter = [7000]  # Different from nRF52840 to avoid collisions


def _next_port_base() -> int:
    base = _port_base_counter[0]
    _port_base_counter[0] += 20
    return base


@pytest.fixture
def board(request):
    return request.config.getoption("--board")


@pytest.fixture
def num_nodes(request):
    return request.config.getoption("--nodes")


def _find_firmware(board: str) -> Path | None:
    """Locate a firmware ELF for the board, if one has been built."""
    candidates = [
        # Renode build with the UART console overlay
        project_root / f"build/{board}_renode/zephyr/zephyr.elf",
        project_root / f"build/{board}/zephyr/zephyr.elf",
        # ESP32-S3 boards use procpu qualifier
        project_root / f"build/{board}_procpu_renode/zephyr/zephyr.elf",
        project_root / f"build/{board}_procpu/zephyr/zephyr.elf",
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
    """Wrapper for a Renode ESP32-S3 node process."""

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
        platform = project_root / "lichen/boards/renode/esp32s3_lichen/support/esp32s3_lichen.repl"

        # Per-node EFUSE MAC so each node derives a unique EUI-64 / IPv6.
        # ESP32-S3 MAC is read from EFUSE block 1 (0x60010044+)
        script = f"""\
:name: TestNode{self.node_id}
include @{sx1262_cs}
mach create "node{self.node_id}"
machine LoadPlatformDescription @{platform}
spi2.sx1262 SimPort {self.port}
# Per-node MAC address via EFUSE tags
sysbus Tag <0x60010044, 0x60010047> "EFUSE_MAC0" 0x1CE1{self.node_id:04X}
sysbus Tag <0x60010048, 0x6001004B> "EFUSE_MAC1" 0x1CE2{self.node_id:04X}
sysbus LoadELF @{self.firmware}
cpu0 PerformanceInMips 240
start
"""
        script_path = project_root / (
            f"lichen/boards/renode/esp32s3_lichen/_test_node{self.node_id}.resc"
        )
        script_path.write_text(script)

        self.proc = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            # Monitor port derived from the (per-test rotated) sim port so two
            # test cases never collide on a lingering Renode's fixed port.
            "--port", str(self.port + 4000),
            str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # Own session/process group: Renode runs under Mono and spawns
            # children that a plain terminate() on the parent leaves alive,
            # holding ports and corrupting the next test. Kill the whole group.
            start_new_session=True,
        )

    async def stop(self):
        """Stop the Renode process."""
        if self.proc is None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            self.proc.terminate()
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=5)
        except (TimeoutError, asyncio.TimeoutError):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)


@pytest_asyncio.fixture
async def mesh_simulation(board, num_nodes, firmware_path):
    """Create and manage a multi-node mesh simulation."""
    sim = Simulation("test-mesh-esp32")
    servers = []
    nodes = []

    # Fresh sim-port range per test so a lingering Renode from a prior test
    # cannot reconnect onto this test's node sockets.
    base_port = _next_port_base()

    try:
        # Start simulation servers
        for i in range(num_nodes):
            port = base_port + i
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

        # Wait for boot - ESP32-S3 may need longer due to ROM bootloader
        await asyncio.sleep(5)

        yield {"sim": sim, "nodes": nodes, "servers": servers}

    finally:
        # Cleanup
        for node in nodes:
            await node.stop()
        for server in servers:
            await server.stop()

        # Remove temp scripts
        for i in range(num_nodes):
            script = project_root / f"lichen/boards/renode/esp32s3_lichen/_test_node{i}.resc"
            script.unlink(missing_ok=True)


_NO_FIRMWARE = _find_firmware("heltec_wifi_lora32_v3") is None


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No ESP32-S3 firmware built")
async def test_mesh_boots(mesh_simulation):
    """Test that all ESP32-S3 nodes boot successfully."""
    nodes = mesh_simulation["nodes"]

    # Verify all processes are running
    for node in nodes:
        assert node.proc is not None
        assert node.proc.returncode is None, f"Node {node.node_id} crashed"


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No ESP32-S3 firmware built")
async def test_mesh_tx(mesh_simulation):
    """Test that ESP32-S3 nodes transmit LoRa frames into lichen-sim.

    ESP32-S3 boot is simpler than nRF52840 MCUboot: ROM bootloader hands off
    to Zephyr directly. Wait for initialization and first TX.
    """
    sim = mesh_simulation["sim"]

    # ESP32-S3 init may be slower in simulation; wait for radio init
    await asyncio.sleep(15)

    # metrics.transmissions counts frames handed to the medium by any node.
    assert sim.metrics.transmissions > 0, "No LoRa transmissions reached lichen-sim"


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No ESP32-S3 firmware built")
async def test_mesh_rx(mesh_simulation):
    """Test that a frame from one ESP32-S3 node is delivered to another.

    Exercises the full receive path: node A transmits, the sim medium
    propagates the frame to node B within range, and the SX1262 bridge
    delivers it into B's firmware.
    """
    sim = mesh_simulation["sim"]
    nodes = mesh_simulation["nodes"]
    if len(nodes) < 2:
        pytest.skip("inter-node delivery needs >= 2 nodes")

    await asyncio.sleep(20)  # past settle + aligned RX windows
    assert sim.metrics.receptions > 0, "No frames were delivered between nodes"
