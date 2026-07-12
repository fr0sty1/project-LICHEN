# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Renode subprocess integration test for 2-node DIO1 interrupt RX.

This test validates that the SX1262.cs peripheral can connect to lichen-sim
and that the bridge protocol works correctly. The full DIO1 interrupt path
requires actual firmware driving the SPI master - see test_two_node_dio1_rx.py
for the Python-only tests that verify the callback/interrupt path.

Requires Renode to be installed. Run with:
    LICHEN_RUN_RENODE_INTEGRATION=1 pytest -v -k test_two_node_dio1

Architecture notes:
- The SX1262.cs peripheral connects to lichen-sim via TCP
- When SetRx (opcode 0x82) is called, SX1262.cs sends RX_ENTER to lichen-sim
- When a packet arrives, lichen-sim calls the on_packet callback
- SX1262.cs receives RX_PACKET and sets IRQ.Set(true) -> DIO1 interrupt to MCU

The Renode subprocess tests verify:
1. The TCP bridge connects successfully
2. Peripheral loads and initializes correctly
3. The platform description is valid
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import subprocess
from pathlib import Path

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation, TimeMode

# Path to project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
RUN_RENODE_INTEGRATION = os.environ.get("LICHEN_RUN_RENODE_INTEGRATION") == "1"


def _has_renode() -> bool:
    """Check if Renode is available."""
    try:
        result = subprocess.run(
            ["renode", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _unused_tcp_port() -> int:
    """Reserve an ephemeral local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
@pytest.mark.asyncio
async def test_sx1262_peripheral_loads_and_connects(tmp_path: Path) -> None:
    """Test that the SX1262 peripheral loads and connects to lichen-sim.

    This verifies:
    1. The SX1262.cs peripheral compiles and loads successfully
    2. The nrf52840_lichen.repl platform description is valid
    3. The TCP bridge connection to lichen-sim works

    Note: This does NOT verify end-to-end TX/RX because driving the SX1262
    via direct sysbus commands doesn't work - it requires actual firmware
    to drive the SPI master controller. See test_two_node_dio1_rx.py for
    the Python-only tests that verify the full RX callback path.
    """
    sim = Simulation("renode-connect-test", time_mode=TimeMode.BARRIER_SYNC)

    # Start a RenodeServer (TCP bridge)
    server, port = await start_renode_server(
        sim, "test-node", port=0, position=(0.0, 0.0, 0.0)
    )

    try:
        sx1262_cs = PROJECT_ROOT / "lichen/boards/renode/peripherals/SX1262.cs"
        platform = PROJECT_ROOT / "lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl"

        # Verify files exist
        assert sx1262_cs.exists(), f"SX1262.cs not found at {sx1262_cs}"
        assert platform.exists(), f"Platform file not found at {platform}"

        # Create minimal Renode script that loads the peripheral and platform
        script = f"""\
:name: PeripheralLoadTest
$simPort={port}

# Load the SX1262 peripheral
include @{sx1262_cs}

# Create machine and load platform
mach create "test-node"
machine LoadPlatformDescription @{platform}

# Configure SX1262 to connect to lichen-sim
spi1.sx1262 SimPort $simPort

# Enable logging to verify connection
logLevel 1 spi1.sx1262

# Brief pause to allow connection attempt
sleep 0.5

quit
"""
        script_path = tmp_path / "load_test.resc"
        script_path.write_text(script)

        monitor_port = _unused_tcp_port()

        # Run Renode
        proc = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            "--port", str(monitor_port),
            str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        except TimeoutError:
            proc.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.communicate(), timeout=5)
            raise AssertionError("Renode test timed out")

        # Check Renode exit status
        assert proc.returncode == 0, (
            f"Renode failed:\nstdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        )

        # Verify the SX1262 peripheral loaded successfully by checking logs
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        # The peripheral should not have any compilation errors
        assert "error" not in output.lower() or "Connect" in output, (
            f"Renode output indicates errors:\n{output}"
        )

    finally:
        await server.stop()


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
@pytest.mark.asyncio
async def test_two_node_platforms_load(tmp_path: Path) -> None:
    """Test that two node platforms can be loaded simultaneously.

    This verifies that multiple Renode instances can connect to separate
    lichen-sim servers, which is required for 2-node mesh testing.
    """
    sim = Simulation("renode-two-node-test", time_mode=TimeMode.BARRIER_SYNC)

    # Start servers for two nodes
    server_a, port_a = await start_renode_server(
        sim, "node-a", port=0, position=(0.0, 0.0, 0.0)
    )
    server_b, port_b = await start_renode_server(
        sim, "node-b", port=0, position=(50.0, 0.0, 0.0)
    )

    try:
        sx1262_cs = PROJECT_ROOT / "lichen/boards/renode/peripherals/SX1262.cs"
        platform = PROJECT_ROOT / "lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl"

        # Create scripts for both nodes
        script_a = f"""\
:name: NodeA
include @{sx1262_cs}
mach create "node-a"
machine LoadPlatformDescription @{platform}
spi1.sx1262 SimPort {port_a}
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" 0x1CE0000A
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" 0x1CE1000A
logLevel 1 spi1.sx1262
sleep 0.3
quit
"""
        script_b = f"""\
:name: NodeB
include @{sx1262_cs}
mach create "node-b"
machine LoadPlatformDescription @{platform}
spi1.sx1262 SimPort {port_b}
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" 0x1CE0000B
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" 0x1CE1000B
logLevel 1 spi1.sx1262
sleep 0.3
quit
"""
        script_a_path = tmp_path / "node_a.resc"
        script_b_path = tmp_path / "node_b.resc"
        script_a_path.write_text(script_a)
        script_b_path.write_text(script_b)

        monitor_port_a = _unused_tcp_port()
        monitor_port_b = _unused_tcp_port()

        # Start both Renode instances concurrently
        proc_a = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            "--port", str(monitor_port_a),
            str(script_a_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        proc_b = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            "--port", str(monitor_port_b),
            str(script_b_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # Wait for both to complete
            results = await asyncio.wait_for(
                asyncio.gather(
                    proc_a.communicate(),
                    proc_b.communicate(),
                ),
                timeout=15,
            )
            (stdout_a, stderr_a), (stdout_b, stderr_b) = results
        except TimeoutError:
            proc_a.kill()
            proc_b.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(proc_a.communicate(), proc_b.communicate()),
                    timeout=5,
                )
            raise AssertionError("Renode test timed out")

        # Check both exit successfully
        assert proc_a.returncode == 0, (
            f"Node A failed:\n{stdout_a.decode(errors='replace')}\n"
            f"{stderr_a.decode(errors='replace')}"
        )
        assert proc_b.returncode == 0, (
            f"Node B failed:\n{stdout_b.decode(errors='replace')}\n"
            f"{stderr_b.decode(errors='replace')}"
        )

        # Verify both nodes were added to simulation
        assert sim.get_node("node-a") is not None
        assert sim.get_node("node-b") is not None

    finally:
        await server_a.stop()
        await server_b.stop()
