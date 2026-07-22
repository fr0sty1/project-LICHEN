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
import contextlib
import os
import signal
import sys
from pathlib import Path

import pytest
import pytest_asyncio

# Skip entire module if Renode not available
pytest.importorskip("lichen.sim.simulation")

# Repo root: .../lichen/boards/renode/nrf52840_lichen/test_mesh.py -> parents[4]
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server  # noqa: E402
from lichen.sim.simulation import Simulation  # noqa: E402

# The T-Echo/RAK4631 firmware is built as an MCUboot slot-0 application: its
# vector table lives at `_vector_table` (slot0 base + CONFIG_ROM_START_OFFSET,
# e.g. 0x32200), NOT at flash 0x0. On real hardware MCUboot chain-loads it; in
# Renode there is no MCUboot, so a bare `LoadELF` + `start` leaves the Cortex-M
# reading its initial SP/PC from an empty 0x0 -> "PC and SP are equal to zero.
# CPU was halted." -> the firmware never runs (and no LoRa frames are sent).
#
# Seed the reset state from the application's own vector table so the CPU boots
# the image directly. Symbol-based so it works regardless of the exact offset.
# Seed VTOR, initial MSP, and PC from the app vector table. A `$vt` variable
# holds the table address so the SP read is a single un-nested monitor
# expression (the nested-parens form intermittently fails to tokenize).
_BOOT_MCUBOOT_APP = """\
$vt=`sysbus GetSymbolAddress "_vector_table"`
cpu VectorTableOffset $vt
cpu SP `sysbus ReadDoubleWord $vt`
cpu PC `sysbus GetSymbolAddress "__start"`
cpu IsHalted false"""

# Rotating base for each test's sim ports (and the +4000 Renode monitor ports),
# so consecutive test cases in one run never reuse the same ports.
_port_base_counter = [6000]


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
        # Renode build with the UART console overlay (see renode_console.overlay)
        project_root / f"build/{board}_renode/zephyr/zephyr.elf",
        project_root / f"build/{board}/zephyr/zephyr.elf",
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
{_BOOT_MCUBOOT_APP}
cpu PerformanceInMips 64
start
"""
        script_path = project_root / (
            f"lichen/boards/renode/nrf52840_lichen/_test_node{self.node_id}.resc"
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
    sim = Simulation("test-mesh")
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

    Passes on Renode 1.16.1 after the yot8 fix chain: boot the MCUboot slot-0
    app from its own vector table, disable Renode-useless USB
    (renode_console.conf) so the app reaches main(), wait past the puck's ~10 s
    USB-settle window, and make the SX1262 RX path asynchronous so a node can
    leave RX to transmit (SX1262.cs). The puck then boots, provisions its dev
    peers, sends a CoAP GET, and the frame reaches the simulation medium.
    """
    sim = mesh_simulation["sim"]

    # The puck holds its net interface (and radio RX thread) down for a ~10 s
    # "USB settle" window before net_if_up(); the first CoAP TX follows shortly
    # after. Wait past that so a transmission has a chance to occur.
    await asyncio.sleep(20)

    # metrics.transmissions counts frames handed to the medium by any node.
    assert sim.metrics.transmissions > 0, "No LoRa transmissions reached lichen-sim"


@pytest.mark.asyncio
@pytest.mark.skipif(_NO_FIRMWARE, reason="No firmware built")
async def test_mesh_rx(mesh_simulation):
    """Test that a frame from one node is delivered to another over the air.

    Exercises the full receive path that the async SX1262 reader unlocked
    (yot8): node A transmits, the sim medium propagates the frame to node B
    within range, and the SX1262 bridge delivers it (RX_PACKET) into B's
    firmware. Unlike test_mesh_tx (a frame merely *reaching* the medium), this
    asserts inter-node *delivery*, so it requires >= 2 nodes.
    """
    sim = mesh_simulation["sim"]
    nodes = mesh_simulation["nodes"]
    if len(nodes) < 2:
        pytest.skip("inter-node delivery needs >= 2 nodes")

    # Wait past the ~10 s settle, then poll: once both nodes are up, deliveries
    # are frequent, but a single half-duplex RX/TX alignment is timing-
    # dependent, so poll rather than sampling one fixed instant. Pass as soon
    # as any frame is delivered.
    for _ in range(12):
        await asyncio.sleep(5)
        if sim.metrics.receptions > 0:
            break

    assert sim.metrics.receptions > 0, "No frames were delivered between nodes"
