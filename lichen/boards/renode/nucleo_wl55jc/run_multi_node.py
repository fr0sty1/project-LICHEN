#!/usr/bin/env python3
"""
Run multiple Renode instances with lichen-sim RF simulation.

Usage: python3 run_multi_node.py [num_nodes]
"""

import asyncio
import sys
from pathlib import Path

# Add project python path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root / "python" / "src"))

from lichen.sim.renode_server import start_renode_server  # noqa: E402
from lichen.sim.simulation import Simulation  # noqa: E402

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


async def run_simulation(num_nodes: int = 2):
    """Run multi-node simulation."""
    print(f"Starting lichen-sim with {num_nodes} nodes...")

    sim = Simulation("multi-node-test")
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
        print("Build with: west build -b nucleo_wl55jc lichen/samples/lora_ping ...")
        return

    try:
        # Start Renode servers for each node
        base_port = 5555
        for i in range(num_nodes):
            node_id = f"node{i}"
            port = base_port + i
            # Position nodes in a line, 50m apart
            x = i * 50.0
            server, actual_port = await start_renode_server(
                sim, node_id, port=port, position=(x, 0.0, 0.0)
            )
            servers.append(server)
            print(f"  Node {i}: port {actual_port}, position ({x}, 0, 0)")

        print("\nStarting Renode instances...")

        # Create and start Renode processes
        log_dir = project_root / "lichen/boards/renode/nucleo_wl55jc"
        uart_files = []
        for i in range(num_nodes):
            port = base_port + i
            log_file = log_dir / f"_node{i}.log"
            uart_file = log_dir / f"_node{i}_uart.log"
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

            script_path = project_root / f"lichen/boards/renode/nucleo_wl55jc/_node{i}.resc"
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
            print(f"  Started Renode for node{i} (PID {proc.pid})")

        print("\n" + "="*60)
        print("Multi-node simulation running!")
        print("Nodes are transmitting PING messages every 2 seconds.")
        print("Press Ctrl+C to stop.")
        print("="*60 + "\n")

        # Tail UART log files for output
        async def tail_uart(uart_file: Path, node_id: int):
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
                                    print(f"[node{node_id}] {line}")
                            pos = len(content)
                except Exception:
                    pass
                await asyncio.sleep(0.1)

        # Run output tailers
        tasks = [
            asyncio.create_task(tail_uart(uart_file, i))
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
            log_file = uart_file.with_suffix('.log').with_name(
                uart_file.name.replace('_uart', '')
            )
            log_file.unlink(missing_ok=True)

        # Clean up servers
        for server in servers:
            await server.stop()

        print("Done.")


if __name__ == "__main__":
    num_nodes = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    asyncio.run(run_simulation(num_nodes))
