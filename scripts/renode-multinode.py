#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Multi-node Renode test runner.

Runs multiple Renode instances with actual Zephyr firmware, connected through
lichen-sim for RF propagation simulation.

Usage:
    # Build firmware first (nrf52840_lichen is the Renode platform, not a
    # Zephyr board; build for the real t_echo/nrf52840 board):
    west build -b t_echo/nrf52840 lichen/samples/lora_ping -d build/lora_ping -- \
        -DEXTRA_DTC_OVERLAY_FILE=$PWD/lichen/boards/renode/nrf52840_lichen/support/renode_console.overlay \
        -DEXTRA_CONF_FILE=$PWD/lichen/boards/renode/nrf52840_lichen/support/renode_console.conf

    # Run 2-node test:
    python scripts/renode-multinode.py --nodes 2 --firmware build/lora_ping/zephyr/zephyr.elf

    # Run 5-node mesh test:
    python scripts/renode-multinode.py --nodes 5 --firmware build/puck/zephyr/zephyr.elf --duration 60

Requirements:
    - Renode installed and in PATH
    - Zephyr firmware built for t_echo/nrf52840 (loaded into the nrf52840_lichen
      Renode machine)
    - Python lichen package (pip install -e python/)
"""

import argparse
import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "python/src"))

from lichen.sim.server import SimulatorServer  # noqa: E402
from lichen.sim.simulation import TimeMode  # noqa: E402


async def start_renode_node(
    node_id: str,
    firmware_path: Path,
    sim_port: int,
    device_id: int,
    repl_path: Path,
    sx1262_path: Path,
    log_dir: Path,
) -> subprocess.Popen:
    """Start a Renode instance for one node.

    Args:
        node_id: Unique node identifier
        firmware_path: Path to zephyr.elf
        sim_port: lichen-sim TCP port for this node
        device_id: Unique device ID for FICR
        repl_path: Path to platform .repl file
        sx1262_path: Path to SX1262.cs peripheral
        log_dir: Directory for log files

    Returns:
        Renode subprocess
    """
    # Create Renode script
    script = f"""\
:name: {node_id}
$simPort={sim_port}

# Load SX1262 peripheral
include @{sx1262_path}

# Create machine
mach create "{node_id}"
machine LoadPlatformDescription @{repl_path}

# Configure SX1262 to connect to lichen-sim
spi1.sx1262 SimPort $simPort

# Set unique device ID
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" {device_id & 0xFFFFFFFF:#010x}
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" {(device_id >> 32) | 0x1CE00000:#010x}

# Load firmware
sysbus LoadELF @{firmware_path}

# Enable logging
logLevel 1 spi1.sx1262
logFile @{log_dir}/{node_id}.log true

# Start execution
start
"""
    script_path = log_dir / f"{node_id}.resc"
    script_path.write_text(script)

    # Find an available port for Renode monitor
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        monitor_port = s.getsockname()[1]

    # Start Renode
    proc = subprocess.Popen(
        [
            "renode",
            "--disable-gui",
            "--port", str(monitor_port),
            str(script_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return proc


async def run_multinode_test(
    n_nodes: int,
    firmware_path: Path,
    duration_s: int,
    spacing_m: float = 50.0,
) -> dict:
    """Run a multi-node Renode test.

    Args:
        n_nodes: Number of nodes to simulate
        firmware_path: Path to Zephyr firmware ELF
        duration_s: Test duration in seconds
        spacing_m: Distance between nodes in meters

    Returns:
        Test results dict
    """
    # Paths
    repl_path = PROJECT_ROOT / "lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl"
    sx1262_path = PROJECT_ROOT / "lichen/boards/renode/peripherals/SX1262.cs"

    if not repl_path.exists():
        raise FileNotFoundError(f"Platform file not found: {repl_path}")
    if not sx1262_path.exists():
        raise FileNotFoundError(f"SX1262.cs not found: {sx1262_path}")
    if not firmware_path.exists():
        raise FileNotFoundError(f"Firmware not found: {firmware_path}")

    # Create temp directory for logs
    log_dir = Path(tempfile.mkdtemp(prefix="renode-multinode-"))
    print(f"Logs: {log_dir}")

    # Start lichen-sim server
    print("Starting lichen-sim server...")
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("renode-multinode", TimeMode.REALTIME)
    node_port = server.get_node_server_port("renode-multinode")
    print(f"lichen-sim listening on port {node_port}")

    # Start Renode bridge servers for each node
    from lichen.sim.renode_server import start_renode_server

    renode_servers = []
    renode_procs = []

    try:
        # Create nodes
        for i in range(n_nodes):
            node_id = f"node-{i}"
            position = (i * spacing_m, 0.0, 0.0)

            # Start Renode server (TCP bridge to lichen-sim)
            renode_srv, port = await start_renode_server(
                sim, node_id, port=0, position=position
            )
            renode_servers.append(renode_srv)
            print(f"  {node_id}: sim bridge port {port}, position {position}")

            # Start Renode instance
            proc = await start_renode_node(
                node_id=node_id,
                firmware_path=firmware_path,
                sim_port=port,
                device_id=0x1CE00000 + i,
                repl_path=repl_path,
                sx1262_path=sx1262_path,
                log_dir=log_dir,
            )
            renode_procs.append(proc)

        print(f"\nRunning {n_nodes} nodes for {duration_s}s...")
        await asyncio.sleep(duration_s)

        # Collect results
        results = {
            "nodes": n_nodes,
            "duration_s": duration_s,
            "spacing_m": spacing_m,
            "logs": [],
        }

        for i, proc in enumerate(renode_procs):
            log_file = log_dir / f"node-{i}.log"
            if log_file.exists():
                log_content = log_file.read_text()
                results["logs"].append({
                    "node": f"node-{i}",
                    "lines": len(log_content.splitlines()),
                    "has_tx": "TX" in log_content or "Send" in log_content,
                    "has_rx": "RX" in log_content or "Recv" in log_content,
                })

        return results

    finally:
        # Cleanup
        print("\nCleaning up...")
        for proc in renode_procs:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        for srv in renode_servers:
            await srv.stop()

        await server.stop()


def main():
    parser = argparse.ArgumentParser(description="Run multi-node Renode test")
    parser.add_argument("--nodes", type=int, default=2, help="Number of nodes")
    parser.add_argument("--firmware", type=Path, required=True, help="Path to zephyr.elf")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    parser.add_argument("--spacing", type=float, default=50.0, help="Node spacing in meters")
    args = parser.parse_args()

    # Check Renode is installed
    try:
        subprocess.run(["renode", "--version"], capture_output=True, check=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("ERROR: Renode not found. Install from https://renode.io/")
        sys.exit(1)

    # Run test
    results = asyncio.run(run_multinode_test(
        n_nodes=args.nodes,
        firmware_path=args.firmware.resolve(),
        duration_s=args.duration,
        spacing_m=args.spacing,
    ))

    # Print results
    print("\n=== Results ===")
    print(f"Nodes: {results['nodes']}")
    print(f"Duration: {results['duration_s']}s")
    for log in results["logs"]:
        tx_rx = []
        if log["has_tx"]:
            tx_rx.append("TX")
        if log["has_rx"]:
            tx_rx.append("RX")
        print(f"  {log['node']}: {log['lines']} log lines, {'/'.join(tx_rx) or 'no activity'}")


if __name__ == "__main__":
    main()
