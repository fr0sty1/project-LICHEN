# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Regression test for Nucleo STM32WL RNG IRQ reset behavior in Renode.

Tests that:
1. RNG peripheral generates entropy and asserts IRQ when DRDY is set.
2. The canonical reset macro (rng IRQ Set false) deasserts an asserted RNG IRQ.
3. Post-reset, the RNG peripheral can still generate fresh entropy (no
   side-effect from having forcibly cleared the IRQ line).

The STM32F4_RNG Renode model asserts its level IRQ on DRDY but does NOT
deassert it on RNG_DR read, on disable, or on Reset().  The reset macro in
nucleo_wl55jc.resc (rng IRQ Set false) fixes this.  This test guards against
removing or breaking that fix.

Run with:
    LICHEN_RUN_RENODE_INTEGRATION=1 pytest -v -k renode_entropy
"""

import asyncio
import contextlib
import os
import socket
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
RUN_RENODE_INTEGRATION = os.environ.get("LICHEN_RUN_RENODE_INTEGRATION") == "1"

# STM32WL RNG register offsets (base 0x58001000)
RNG_CR = 0x58001000  # Control register
RNG_SR = 0x58001004  # Status register
RNG_DR = 0x58001008  # Data register

RNGEN = 0x04  # RNG enable bit in CR
IE = 0x08  # Interrupt enable bit in CR
DRDY = 0x01  # Data ready bit in SR


def _has_renode() -> bool:
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _monitor_capture(
    renode_bin: str,
    script_text: str,
    tmp_path: Path,
    monitor_port: int,
    timeout: float = 20,
) -> str:
    """Run a Renode script that includes monitor commands and capture the
    monitor output.  Uses logLevel to emit monitor responses as structured
    log lines on stderr, which we can parse."""
    script_path = tmp_path / "capture.resc"
    script_path.write_text(script_text)

    proc = await asyncio.create_subprocess_exec(
        renode_bin,
        "--disable-gui",
        "--port", str(monitor_port),
        str(script_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        connect_start = asyncio.get_event_loop().time()
        reader = None
        writer = None
        while True:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", monitor_port),
                    timeout=2,
                )
                break
            except (ConnectionRefusedError, OSError):
                if asyncio.get_event_loop().time() - connect_start > 10:
                    raise
                await asyncio.sleep(0.5)

        # Drain all output to the end of the script (it ends with "quit")
        output = ""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except (TimeoutError, asyncio.TimeoutError):
                break
            if not chunk:
                break
            output += chunk.decode(errors="replace")

        await asyncio.sleep(1)
        _, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=5)

        return output + "\n" + stderr_data.decode(errors="replace")

    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        if proc.returncode is None:
            proc.kill()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=5)


def _parse_hex_values(text: str) -> list[int]:
    """Extract all hex integer values (0x...) from text."""
    vals = []
    for token in text.split():
        token = token.strip()
        if token.startswith("0x"):
            try:
                vals.append(int(token, 16))
            except ValueError:
                pass
    return vals


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(RUN_RENODE_INTEGRATION and not _has_renode(), reason="Renode not installed")
@pytest.mark.asyncio
async def test_nucleo_entropy_reset_regression(tmp_path: Path) -> None:
    """Verify RNG IRQ reset macro and post-reset entropy generation."""
    renode_dir = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc"
    peripheral_sg = renode_dir / "peripherals/LichenSubGHz.cs"
    peripheral_rcc = renode_dir / "peripherals/STM32WL_RCC.cs"
    peripheral_pwr = renode_dir / "peripherals/STM32WL_PWR.cs"
    platform = renode_dir / "support/stm32wl55.repl"

    script = f"""\
:name: Entropy Reset Regression
include @{peripheral_sg}
include @{peripheral_rcc}
include @{peripheral_pwr}
mach create "NUCLEO-WL55JC"
machine LoadPlatformDescription @{platform}

# Phase 1: RNG generates entropy, IRQ set on DRDY
sysbus WriteDoubleWord {RNG_CR:#x} {IE | RNGEN:#x}
sleep 0.05
sysbus ReadDoubleWord {RNG_SR:#x}
rng IRQ
sysbus ReadDoubleWord {RNG_DR:#x}

# Phase 2: canonical reset macro deasserts IRQ
rng IRQ Set false
rng IRQ

# Phase 3: post-reset entropy still works
sysbus WriteDoubleWord {RNG_CR:#x} {IE | RNGEN:#x}
sleep 0.05
sysbus ReadDoubleWord {RNG_DR:#x}

quit
"""
    monitor_port = _unused_tcp_port()
    renode_bin = "renode"
    output = await _monitor_capture(renode_bin, script, tmp_path, monitor_port)

    # Parse hex values from the output
    hex_vals = _parse_hex_values(output)

    # Find GPIO: set / GPIO: unset lines
    has_gpio_set = "GPIO: set" in output
    has_gpio_unset = "GPIO: unset" in output

    # We should have hex values from:
    # - RNG_SR (expected 0x00000001 = DRDY)
    # - RNG_DR first read (some non-zero random value)
    # - RNG_DR second read (some non-zero random value)
    cmd_addresses = {str(hex(v)) for v in [RNG_SR, RNG_DR]}
    result_hex = [v for v in hex_vals if hex(v) not in cmd_addresses]

    assert len(result_hex) >= 3, (
        f"Expected at least 3 result hex values (SR + 2x DR), found {len(result_hex)}: "
        f"{[hex(v) for v in result_hex]}\n"
        f"Output:\n{output}"
    )

    # First result = SR value
    sr_val = result_hex[0]
    assert sr_val & DRDY, (
        f"Expected DRDY bit set in RNG_SR, got 0x{sr_val:08x}\nOutput:\n{output}"
    )

    # Next two = DR values
    dr1_val = result_hex[1]
    dr2_val = result_hex[2]

    assert dr1_val != 0, f"First RNG_DR read returned 0\nOutput:\n{output}"
    assert dr2_val != 0, f"Second RNG_DR read returned 0\nOutput:\n{output}"
    assert dr1_val != dr2_val, (
        f"Two RNG_DR reads returned identical value 0x{dr1_val:08x} — "
        f"RNG may have stalled after IRQ reset\nOutput:\n{output}"
    )

    # IRQ was set after enable, then unset after reset macro
    assert has_gpio_set, (
        f"Expected 'GPIO: set' (RNG IRQ asserted) in output\nOutput:\n{output}"
    )
    assert has_gpio_unset, (
        f"Expected 'GPIO: unset' (RNG IRQ deasserted) in output\nOutput:\n{output}"
    )
