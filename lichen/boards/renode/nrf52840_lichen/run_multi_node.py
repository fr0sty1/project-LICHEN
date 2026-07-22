#!/usr/bin/env python3
"""
Run multiple nRF52840 Renode instances with lichen-sim RF simulation.

Supports T-Echo, RAK4631, or mixed board topologies.

Usage:
    python3 run_multi_node.py                    # 2x T-Echo
    python3 run_multi_node.py 3                  # 3x T-Echo
    python3 run_multi_node.py t_echo rak4631     # 1 T-Echo + 1 RAK4631
"""

import asyncio
import sys
from pathlib import Path

# Repo root: .../lichen/boards/renode/nrf52840_lichen/run_multi_node.py -> parents[4]
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server  # noqa: E402
from lichen.sim.simulation import Simulation  # noqa: E402

SUPPORTED_BOARDS = {"t_echo", "rak4631"}

RENODE_SCRIPT_TEMPLATE = """\
:name: Node {node_id}

include @{sx1262_cs}

mach create "node{node_id}"
machine LoadPlatformDescription @{platform}

# Override SX1262 port for this node
spi1.sx1262 SimPort {port}

# Per-node FICR DEVICEID so every node derives a unique EUI-64 / IPv6 address.
# Without this, all nodes share the platform's default id and collide.
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" {devid0}
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" {devid1}

# Load firmware
sysbus LoadELF @{elf}
cpu SetPCFromResetVector

# Console output to file (headless mode)
logFile @{log_file} true
{uart} CreateFileBackend @{uart_file} true

# 64 MHz nRF52840
cpu PerformanceInMips 64
# The MCUboot application starts at the configured flash load offset.
cpu VectorTableOffset 0x32000

start
"""


async def run_simulation(boards: list[str]):
    """Run multi-node simulation with specified boards."""
    num_nodes = len(boards)
    print(f"Starting lichen-sim with {num_nodes} nodes: {', '.join(boards)}")

    sim = Simulation("multi-node-test")
    servers = []
    procs = []

    peripherals_dir = project_root / "lichen/boards/renode/peripherals"
    sx1262_cs = peripherals_dir / "SX1262.cs"

    try:
        # Start Renode servers for each node
        base_port = 5555
        for i, board in enumerate(boards):
            node_id = f"node{i}"
            port = base_port + i
            # Position nodes in a line, 50m apart
            x = i * 50.0
            server, actual_port = await start_renode_server(
                sim, node_id, port=port, position=(x, 0.0, 0.0)
            )
            servers.append(server)
            print(f"  Node {i} ({board}): port {actual_port}, position ({x}, 0, 0)")

        print("\nStarting Renode instances...")

        # Create and start Renode processes
        log_dir = project_root / "lichen/boards/renode/nrf52840_lichen"
        uart_files = []
        for i, board in enumerate(boards):
            port = base_port + i
            log_file = log_dir / f"_node{i}.log"
            uart_file = log_dir / f"_node{i}_uart.log"
            uart_files.append(uart_file)

            # Board-specific paths
            platform = project_root / f"lichen/boards/renode/{board}/support/{board}.repl"
            if not platform.exists():
                print(f"ERROR: Platform not found: {platform}")
                return

            # Firmware must match the board-specific devicetree.
            candidates = [
                project_root / f"build/{board}_renode/zephyr/zephyr.elf",
                project_root / f"build/{board}/zephyr/zephyr.elf",
            ]
            firmware = next((c for c in candidates if c.exists()), None)
            if firmware is None:
                print(f"ERROR: Firmware not found for {board}")
                for c in candidates:
                    print(f"  Tried: {c}")
                print(f"Build with: west build -b {board}/nrf52840 ...")
                return

            # The renode_console.overlay routes the console to uart0 for all
            # nRF52840 boards, so capture uart0 regardless of board default.
            uart = "uart0"

            script = RENODE_SCRIPT_TEMPLATE.format(
                node_id=i,
                sx1262_cs=sx1262_cs,
                platform=platform,
                port=port,
                elf=firmware,
                log_file=log_file,
                uart_file=uart_file,
                uart=uart,
                devid0=f"0x1CE1{i:04X}",
                devid1=f"0x1CE2{i:04X}",
            )

            script_path = log_dir / f"_node{i}.resc"
            script_path.write_text(script)

            proc = await asyncio.create_subprocess_exec(
                "renode",
                "--disable-gui",
                "--port", str(10000 + i),  # Different monitor ports
                str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            procs.append((proc, script_path))
            print(f"  Started Renode for node{i} ({board}) PID {proc.pid}")

        print("\n" + "=" * 60)
        print("Multi-node simulation running!")
        print("Press Ctrl+C to stop.")
        print("=" * 60 + "\n")

        # Tail UART log files for output
        async def tail_uart(uart_file: Path, node_id: int, board: str):
            """Tail a UART log file, printing new lines."""
            await asyncio.sleep(1)  # Wait for file to be created
            pos = 0
            while True:
                try:
                    if uart_file.exists():
                        content = uart_file.read_text()
                        if len(content) > pos:
                            for line in content[pos:].splitlines():
                                if line.strip():
                                    print(f"[{board}{node_id}] {line}")
                            pos = len(content)
                except Exception:
                    pass
                await asyncio.sleep(0.1)

        # Run output tailers
        tasks = [
            asyncio.create_task(tail_uart(uart_file, i, boards[i]))
            for i, uart_file in enumerate(uart_files)
        ]

        # Wait for all processes or interrupt
        try:
            await asyncio.gather(*[p.wait() for p, _ in procs])
        except asyncio.CancelledError:
            pass
        finally:
            for t in tasks:
                t.cancel()

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up Renode processes
        for proc, script_path in procs:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
            script_path.unlink(missing_ok=True)

        # Clean up log files
        for uart_file in uart_files:
            uart_file.unlink(missing_ok=True)
            log_file = log_dir / uart_file.name.replace("_uart", "")
            log_file.unlink(missing_ok=True)

        # Clean up servers
        for server in servers:
            await server.stop()

        print("Done.")


def parse_args(args: list[str]) -> list[str]:
    """Parse command line arguments into board list."""
    if not args:
        return ["t_echo", "t_echo"]  # Default: 2x T-Echo

    # If single integer, create N T-Echo nodes
    if len(args) == 1 and args[0].isdigit():
        return ["t_echo"] * int(args[0])

    # Otherwise, treat as board names
    boards = []
    for arg in args:
        if arg.lower() in SUPPORTED_BOARDS:
            boards.append(arg.lower())
        else:
            print(f"Unknown board: {arg}")
            print(f"Supported: {', '.join(sorted(SUPPORTED_BOARDS))}")
            sys.exit(1)
    return boards


if __name__ == "__main__":
    boards = parse_args(sys.argv[1:])
    asyncio.run(run_simulation(boards))
