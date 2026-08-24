#!/usr/bin/env python3
"""
Run multiple ESP32-S3 Renode instances with lichen-sim RF simulation.

Supports Heltec V3 and other ESP32-S3 + SX1262 boards.

Usage:
    python3 run_multi_node.py                           # 2x Heltec V3
    python3 run_multi_node.py 3                         # 3x Heltec V3
    python3 run_multi_node.py heltec_wifi_lora32_v3     # Explicit board
"""

import asyncio
import sys
from pathlib import Path

# Repo root: .../lichen/boards/renode/esp32s3_lichen/run_multi_node.py -> parents[4]
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server  # noqa: E402
from lichen.sim.simulation import Simulation  # noqa: E402

SUPPORTED_BOARDS = {"heltec_wifi_lora32_v3"}

RENODE_SCRIPT_TEMPLATE = """\
:name: Node {node_id}

include @{sx1262_cs}

mach create "node{node_id}"
machine LoadPlatformDescription @{platform}

# Override SX1262 port for this node
spi2.sx1262 SimPort {port}

# Per-node EFUSE MAC so every node derives a unique EUI-64 / IPv6 address.
# Without this, all nodes share the platform's default id and collide.
sysbus Tag <0x60010044, 0x60010047> "EFUSE_MAC0" {mac0}
sysbus Tag <0x60010048, 0x6001004B> "EFUSE_MAC1" {mac1}

# Load firmware
sysbus LoadELF @{elf}

# Console output to file (headless mode)
logFile @{log_file} true
{uart} CreateFileBackend @{uart_file} true

# 240 MHz ESP32-S3
cpu0 PerformanceInMips 240

start
"""


async def run_simulation(boards: list[str]):
    """Run multi-node simulation with specified boards."""
    num_nodes = len(boards)
    print(f"Starting lichen-sim with {num_nodes} ESP32-S3 nodes: {', '.join(boards)}")

    sim = Simulation("multi-node-esp32-test")
    servers = []
    procs = []

    peripherals_dir = project_root / "lichen/boards/renode/peripherals"
    sx1262_cs = peripherals_dir / "SX1262.cs"
    platform = project_root / "lichen/boards/renode/esp32s3_lichen/support/esp32s3_lichen.repl"

    if not platform.exists():
        print(f"ERROR: Platform not found: {platform}")
        return

    try:
        # Start Renode servers for each node
        base_port = 6555
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
        log_dir = project_root / "lichen/boards/renode/esp32s3_lichen"
        uart_files = []
        for i, board in enumerate(boards):
            port = base_port + i
            log_file = log_dir / f"_node{i}.log"
            uart_file = log_dir / f"_node{i}_uart.log"
            uart_files.append(uart_file)

            # Firmware must match the board-specific devicetree.
            # ESP32-S3 boards use _procpu suffix for single-core build
            candidates = [
                project_root / f"build/{board}_renode/zephyr/zephyr.elf",
                project_root / f"build/{board}/zephyr/zephyr.elf",
                project_root / f"build/{board}_procpu_renode/zephyr/zephyr.elf",
                project_root / f"build/{board}_procpu/zephyr/zephyr.elf",
            ]
            firmware = next((c for c in candidates if c.exists()), None)
            if firmware is None:
                print(f"ERROR: Firmware not found for {board}")
                for c in candidates:
                    print(f"  Tried: {c}")
                print(f"Build with: west build -b {board}/esp32s3/procpu ...")
                return

            # ESP32-S3 console is on uart0
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
                mac0=f"0x1CE1{i:04X}",
                mac1=f"0x1CE2{i:04X}",
            )

            script_path = log_dir / f"_node{i}.resc"
            script_path.write_text(script)

            proc = await asyncio.create_subprocess_exec(
                "renode",
                "--disable-gui",
                "--port", str(11000 + i),  # Different monitor ports
                str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            procs.append((proc, script_path))
            print(f"  Started Renode for node{i} ({board}) PID {proc.pid}")

        print("\n" + "=" * 60)
        print("Multi-node ESP32-S3 simulation running!")
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
        return ["heltec_wifi_lora32_v3", "heltec_wifi_lora32_v3"]  # Default: 2x Heltec V3

    # If single integer, create N Heltec V3 nodes
    if len(args) == 1 and args[0].isdigit():
        return ["heltec_wifi_lora32_v3"] * int(args[0])

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
