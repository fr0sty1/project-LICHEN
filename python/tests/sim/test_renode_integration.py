# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration test for Renode SubGHz <-> lichen-sim bridge.

Requires Renode to be installed. Run with:
LICHEN_RUN_RENODE_INTEGRATION=1 pytest -v -k renode_integration
"""

import asyncio
import contextlib
import os
import socket
import subprocess
from pathlib import Path

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation

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
    """Reserve an ephemeral local TCP port long enough to learn its number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(RUN_RENODE_INTEGRATION and not _has_renode(), reason="Renode not installed")
@pytest.mark.asyncio
async def test_renode_integration_tx(tmp_path: Path) -> None:  # now includes ESP32-S3 via updated repl
    """Test TX from Renode peripheral reaches lichen-sim."""
    sim = Simulation("renode-test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    # Track transmissions
    tx_received = []

    class TxObserver:
        def on_tx_start(
            self,
            sim_id: str,
            node_id: str,
            tx_id: str,
            payload_len: int,
            time_us: int,
        ) -> None:
            tx_received.append((node_id, payload_len))

    sim.add_observer(TxObserver())

    try:
        # Create Renode test script
        renode_dir = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc"
        peripheral = renode_dir / "peripherals/LichenSubGHz.cs"
        rcc_peripheral = renode_dir / "peripherals/STM32WL_RCC.cs"
        pwr_peripheral = renode_dir / "peripherals/STM32WL_PWR.cs"
        platform = renode_dir / "support/stm32wl55.repl"
        script = f"""\
:name: Integration Test
include @{peripheral}
include @{rcc_peripheral}
include @{pwr_peripheral}
mach create "test"
machine LoadPlatformDescription @{platform}

# Point the Renode peripheral at the ephemeral lichen-sim port.
subghz SimPort {port}

# Connect to lichen-sim
sysbus WriteDoubleWord 0x58010024 1

# Write payload "TEST" to TX buffer
sysbus WriteDoubleWord 0x58010100 0x54534554

# Set TX length = 4
sysbus WriteDoubleWord 0x58010000 4

# Trigger TX
sysbus WriteDoubleWord 0x58010004 1

# Brief pause for socket IO
sleep 0.1

quit
"""
        script_path = tmp_path / "integration_test.resc"
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
        except TimeoutError as exc:
            proc.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.communicate(), timeout=5)
            raise AssertionError("Renode integration script timed out") from exc

        assert proc.returncode == 0, (
            "Renode integration script failed\n"
            f"stdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        )
        assert tx_received == [("renode-node", 4)]

    finally:
        await server.stop()
