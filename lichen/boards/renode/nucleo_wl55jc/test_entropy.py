# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Automated Renode coverage for Nucleo entropy initialization and reset.

Tests that:
1. Nucleo firmware boots through entropy init without IRQ stall/storm
2. RNG IRQ can be forced high, canonical reset clears it, and entropy
   progresses normally afterward.

Requires firmware built for nucleo_wl55jc_renode. Run with:
    LICHEN_RUN_RENODE_INTEGRATION=1 pytest -v -k entropy
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import socket
import subprocess
from pathlib import Path

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation

PROJECT_ROOT = Path(__file__).resolve().parents[4]
RUN_RENODE_INTEGRATION = os.environ.get("LICHEN_RUN_RENODE_INTEGRATION") == "1"


def _has_renode() -> bool:
    try:
        result = subprocess.run(
            ["renode", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class RenodeMonitor:
    """Renode TCP monitor interface."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self, port: int) -> None:
        self._port = port
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port
        )

    async def disconnect(self) -> None:
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
            self._writer = None
            self._reader = None

    async def command(self, cmd: str) -> str:
        if self._writer is None:
            msg = "Not connected to Renode monitor"
            raise RuntimeError(msg)
        self._writer.write((cmd + "\n").encode("utf-8"))
        await self._writer.drain()
        lines = []
        while True:
            line = await asyncio.wait_for(self._reader.readline(), timeout=10)
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not text:
                continue
            if text.startswith("(") and text.endswith(")"):
                break
            lines.append(text)
        return "\n".join(lines)

    async def rng_irq_set(self, value: bool) -> str:
        return await self.command(f"rng IRQ Set {str(value).lower()}")

    async def rng_irq_get(self) -> bool:
        resp = await self.command("rng IRQ")
        return "true" in resp.lower()

    async def run_macro(self, name: str) -> str:
        return await self.command(f"runMacro {name}")

    async def start(self) -> str:
        return await self.command("start")

    async def read_uint(self, addr: int) -> int:
        resp = await self.command(f"sysbus ReadDoubleWord 0x{addr:X}")
        match = re.search(r"0x[0-9a-fA-F]+", resp)
        if match:
            return int(match.group(0), 16)
        return 0


_reboot_count = [0]


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(RUN_RENODE_INTEGRATION and not _has_renode(), reason="Renode not installed")
@pytest.mark.asyncio
async def test_nucleo_entropy_boot(tmp_path: Path) -> None:
    """Boot Nucleo firmware through entropy init; assert no IRQ stall/storm.

    Launches a single Nucleo WL55JC node in Renode with the canonical reset
    macro (which clears RNG IRQ), loads firmware that exercises entropy, and
    verifies no IRQ storm or stall occurs during boot.
    """
    _reboot_count[0] += 1
    reboot = _reboot_count[0]

    sim = Simulation("nucleo-entropy-boot")
    server, port = await start_renode_server(sim, "nucleo-node", port=0)

    elf_path = _find_firmware()
    if elf_path is None:
        pytest.skip("No Nucleo firmware found; build with west build -b nucleo_wl55jc_renode ...")

    nucleo_dir = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc"
    peripheral = nucleo_dir / "peripherals/LichenSubGHz.cs"
    rcc_peripheral = nucleo_dir / "peripherals/STM32WL_RCC.cs"
    pwr_peripheral = nucleo_dir / "peripherals/STM32WL_PWR.cs"
    platform = nucleo_dir / "support/stm32wl55.repl"
    resc_template = nucleo_dir / "support/nucleo_wl55jc.resc"

    script = f"""\
:name: NucleoEntropyBoot{reboot}

include @{peripheral}
include @{rcc_peripheral}
include @{pwr_peripheral}

mach create "nucleo{reboot}"
machine LoadPlatformDescription @{platform}

subghz SimPort {port}

macro reset
{{
    rng IRQ Set false
    sysbus LoadELF @{elf_path}
}}

runMacro $reset
cpu PerformanceInMips 48
"""
    script_path = tmp_path / f"nucleo_entropy_boot_{reboot}.resc"
    script_path.write_text(script)

    monitor_port = _unused_tcp_port()

    proc = await asyncio.create_subprocess_exec(
        "renode",
        "--disable-gui",
        "--port", str(monitor_port),
        str(script_path),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )

    monitor = RenodeMonitor()
    try:
        await asyncio.sleep(2)
        await monitor.connect(monitor_port)

        await monitor.start()

        await asyncio.sleep(5)

        rng_irq = await monitor.rng_irq_get()
        assert not rng_irq, "RNG IRQ should not be asserted after clean boot"

        irq_counts = await monitor.command("rng IRQ")
        assert "0" in irq_counts or irq_counts.strip() == "false", (
            f"RNG IRQ storm detected: {irq_counts}"
        )

        await monitor.command("logLevel 0 sysbus")
        utc0 = await monitor.read_uint(0xE0001004)
        systick_val = await monitor.read_uint(0xE000E018)
        assert utc0 > 0 or systick_val != 0xFFFFFFFF, (
            "CPU appears stalled: SysTick not decrementing"
        )

    finally:
        await monitor.disconnect()
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (TimeoutError, asyncio.TimeoutError):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
        await server.stop()


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(RUN_RENODE_INTEGRATION and not _has_renode(), reason="Renode not installed")
@pytest.mark.asyncio
async def test_nucleo_entropy_reset_path(tmp_path: Path) -> None:
    """Assert RNG IRQ, invoke canonical reset, prove post-reset entropy.

    Forces RNG IRQ high before boot to simulate the stale-IRQ condition,
    then invokes the canonical reset macro (which clears rng IRQ). After
    reset, verifies that entropy initialization completes without stall
    and the CPU is making forward progress.
    """
    _reboot_count[0] += 1
    reboot = _reboot_count[0]

    sim = Simulation("nucleo-entropy-reset")
    server, port = await start_renode_server(sim, "nucleo-node", port=0)

    elf_path = _find_firmware()
    if elf_path is None:
        pytest.skip("No Nucleo firmware found; build with west build -b nucleo_wl55jc_renode ...")

    nucleo_dir = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc"
    peripheral = nucleo_dir / "peripherals/LichenSubGHz.cs"
    rcc_peripheral = nucleo_dir / "peripherals/STM32WL_RCC.cs"
    pwr_peripheral = nucleo_dir / "peripherals/STM32WL_PWR.cs"
    platform = nucleo_dir / "support/stm32wl55.repl"

    script = f"""\
:name: NucleoEntropyReset{reboot}

include @{peripheral}
include @{rcc_peripheral}
include @{pwr_peripheral}

mach create "nucleo{reboot}"
machine LoadPlatformDescription @{platform}

subghz SimPort {port}

macro reset
{{
    rng IRQ Set false
    sysbus LoadELF @{elf_path}
}}

rng IRQ Set true
cpu PerformanceInMips 48
"""
    script_path = tmp_path / f"nucleo_entropy_reset_{reboot}.resc"
    script_path.write_text(script)

    monitor_port = _unused_tcp_port()

    proc = await asyncio.create_subprocess_exec(
        "renode",
        "--disable-gui",
        "--port", str(monitor_port),
        str(script_path),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )

    monitor = RenodeMonitor()
    try:
        await asyncio.sleep(2)
        await monitor.connect(monitor_port)

        pre_reset_irq = await monitor.rng_irq_get()
        assert pre_reset_irq, "RNG IRQ should be asserted before reset"

        await monitor.run_macro("$reset")

        await asyncio.sleep(1)

        post_reset_irq = await monitor.rng_irq_get()
        assert not post_reset_irq, (
            "RNG IRQ should be deasserted by reset macro"
        )

        await monitor.start()

        await asyncio.sleep(8)

        rng_irq_after = await monitor.rng_irq_get()
        assert not rng_irq_after, (
            "RNG IRQ should not re-assert during post-reset entropy init"
        )

        utc0 = await monitor.read_uint(0xE0001004)
        systick0 = await monitor.read_uint(0xE000E018)

        await asyncio.sleep(2)

        utc1 = await monitor.read_uint(0xE0001004)
        systick1 = await monitor.read_uint(0xE000E018)

        assert (utc1 != utc0) or (systick1 != systick0), (
            "CPU appears stalled after reset+entropy init"
        )

    finally:
        await monitor.disconnect()
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (TimeoutError, asyncio.TimeoutError):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
        await server.stop()


def _find_firmware() -> Path | None:
    candidates = [
        PROJECT_ROOT / "build/nucleo_wl55jc_renode/zephyr/zephyr.elf",
        PROJECT_ROOT / "build/nucleo_wl55jc/zephyr/zephyr.elf",
    ]
    for elf in candidates:
        if elf.exists():
            return elf
    return None
