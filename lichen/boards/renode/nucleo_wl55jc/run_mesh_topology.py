#!/usr/bin/env python3
"""
Run Renode mesh with topology requiring multi-hop.

Creates a grid of nodes where each node can only reach neighbors,
requiring multi-hop to reach distant nodes.

Node arrangement (3x3 grid, 2km apart):
    0 --- 1 --- 2
    |     |     |
    3 --- 4 --- 5
    |     |     |
    6 --- 7 --- 8

With ~3km range (reduced TX power), nodes can only reach immediate neighbors.
"""

import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation

# Grid topology: 3x3 at 2km spacing with -5dBm TX power (~3.5km range)
# This means:
#   - Adjacent nodes (2km): can communicate
#   - Diagonal nodes (~2.83km): marginal (might work)
#   - 2 hops away (4km): cannot communicate -> requires multi-hop
GRID_SIZE = 3
SPACING_M = 2000.0  # 2km between adjacent nodes
TX_POWER_DBM = -5  # Low power for limited range (~3.5km with default model)

RENODE_SCRIPT_TEMPLATE = """\
:name: Node {node_id}

include @{rcc_cs}
include @{pwr_cs}
include @{subghz_cs}

mach create "node{node_id}"
machine LoadPlatformDescription @{platform}

# Override SubGHz port for this node
subghz SimPort {port}

# Load firmware
sysbus LoadELF @{elf}

# Console output to file (headless mode)
logFile @{log_file} true
lpuart1 CreateFileBackend @{uart_file} true

# 48 MHz system clock
cpu PerformanceInMips 48

start
"""


def grid_position(node_idx: int) -> tuple[float, float, float]:
    """Return (x, y, z) for a node in a 3x3 grid."""
    row = node_idx // GRID_SIZE
    col = node_idx % GRID_SIZE
    return (col * SPACING_M, row * SPACING_M, 0.0)


async def run_simulation(num_nodes: int = 9):
    """Run mesh topology simulation."""
    print(f"Starting mesh simulation with {num_nodes} nodes in {GRID_SIZE}x{GRID_SIZE} grid...")
    print(f"Grid spacing: {SPACING_M}m (only neighbors reachable)")
    print()

    sim = Simulation("mesh-topology")
    servers = []
    procs = []

    peripherals_dir = project_root / "lichen/boards/renode/nucleo_wl55jc/peripherals"
    rcc_cs = peripherals_dir / "STM32WL_RCC.cs"
    pwr_cs = peripherals_dir / "STM32WL_PWR.cs"
    subghz_cs = peripherals_dir / "LichenSubGHz.cs"
    platform = project_root / "lichen/boards/renode/nucleo_wl55jc/support/stm32wl55.repl"
    elf = project_root / "build/zephyr/zephyr.elf"

    if not elf.exists():
        print(f"ERROR: Firmware not found at {elf}")
        return

    # Print topology
    print("Topology (2km spacing, ~3km range):")
    for row in range(GRID_SIZE):
        line = ""
        for col in range(GRID_SIZE):
            idx = row * GRID_SIZE + col
            if idx < num_nodes:
                line += f"  {idx}  "
            else:
                line += "     "
            if col < GRID_SIZE - 1 and idx < num_nodes - 1:
                line += "---"
        print(line)
        if row < GRID_SIZE - 1:
            for col in range(GRID_SIZE):
                idx = row * GRID_SIZE + col
                if idx < num_nodes and idx + GRID_SIZE < num_nodes:
                    print("  |  ", end="")
                else:
                    print("     ", end="")
                if col < GRID_SIZE - 1:
                    print("   ", end="")
            print()
    print()

    try:
        # Start Renode servers for each node
        base_port = 5555
        for i in range(num_nodes):
            node_id = f"node{i}"
            port = base_port + i
            pos = grid_position(i)
            server, actual_port = await start_renode_server(
                sim, node_id, port=port, position=pos, tx_power_dbm=TX_POWER_DBM
            )
            servers.append(server)
            print(f"  Node {i}: port {actual_port}, position ({pos[0]:.0f}, {pos[1]:.0f}, 0), TX={TX_POWER_DBM}dBm")

        print("\nStarting Renode instances...")

        # Create and start Renode processes
        log_dir = project_root / "lichen/boards/renode/nucleo_wl55jc"
        uart_files = []
        for i in range(num_nodes):
            port = base_port + i
            log_file = log_dir / f"_mesh{i}.log"
            uart_file = log_dir / f"_mesh{i}_uart.log"
            uart_files.append(uart_file)
            script = RENODE_SCRIPT_TEMPLATE.format(
                node_id=i,
                rcc_cs=rcc_cs,
                pwr_cs=pwr_cs,
                subghz_cs=subghz_cs,
                platform=platform,
                port=port,
                elf=elf,
                log_file=log_file,
                uart_file=uart_file,
            )

            script_path = log_dir / f"_mesh{i}.resc"
            script_path.write_text(script)

            proc = await asyncio.create_subprocess_exec(
                "renode",
                "--disable-gui",
                "--port", str(10000 + i),
                str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            procs.append((proc, script_path))
            print(f"  Started Renode for node{i} (PID {proc.pid})")

        print("\n" + "="*60)
        print("Mesh topology simulation running!")
        print("Nodes transmit PING, only neighbors receive (2km spacing).")
        print("Press Ctrl+C to stop.")
        print("="*60 + "\n")

        # Tail UART log files
        async def tail_uart(uart_file: Path, node_id: int):
            await asyncio.sleep(1)
            pos = 0
            while True:
                try:
                    if uart_file.exists():
                        content = uart_file.read_text()
                        if len(content) > pos:
                            for line in content[pos:].splitlines():
                                if line.strip():
                                    print(f"[node{node_id}] {line}")
                            pos = len(content)
                except Exception:
                    pass
                await asyncio.sleep(0.1)

        tasks = [
            asyncio.create_task(tail_uart(uart_file, i))
            for i, uart_file in enumerate(uart_files)
        ]

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
        for proc, script_path in procs:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
            script_path.unlink(missing_ok=True)

        for uart_file in uart_files:
            uart_file.unlink(missing_ok=True)
            log_file = uart_file.with_name(uart_file.name.replace('_uart', ''))
            log_file.unlink(missing_ok=True)

        for server in servers:
            await server.stop()

        print("Done.")


if __name__ == "__main__":
    num_nodes = int(sys.argv[1]) if len(sys.argv) > 1 else 9
    asyncio.run(run_simulation(num_nodes))
