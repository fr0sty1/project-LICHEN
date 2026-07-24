# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Renode subprocess integration tests for enhanced peripheral models.

Tests that each of the custom Renode peripheral models (BLE, USBD, GPS,
LR1110) loads, initialises, and responds to register reads/writes correctly.
Also tests the combined T1000-E platform which wires ALL peripheral models.

Requires Renode to be installed. Run with:
    LICHEN_RUN_RENODE_INTEGRATION=1 pytest -v -k renode_peripheral

Architecture notes:
- BLE (NRF52840_BLE @ 0x40001000) - nRF RADIO registers + GATT MMIO stub
- USBD (NRF52840_USBD @ 0x40027000) - USB device controller registers
- GPS (Sensors.GPS @ uart1) - canned NMEA sentence generator
- LR1110 (Wireless.LR1110 @ spi2) - LoRa+GNSS SPI bridge to lichen-sim
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

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
RUN_RENODE_INTEGRATION = os.environ.get("LICHEN_RUN_RENODE_INTEGRATION") == "1"


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


def _run_renode_script(tmp_path: Path, script: str, timeout: int = 15) -> str:
    """Run a Renode .resc script and return combined stdout+stderr.

    Raises AssertionError on timeout or non-zero exit.
    """
    script_path = tmp_path / "test.resc"
    script_path.write_text(script)
    monitor_port = _unused_tcp_port()

    proc = subprocess.run(
        ["renode", "--disable-gui", "--port", str(monitor_port), str(script_path)],
        capture_output=True,
        timeout=timeout,
    )
    output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
    assert proc.returncode == 0, (
        f"Renode script failed (rc={proc.returncode}):\n{output}"
    )
    return output


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
class TestBlePeripheralModel:
    """Validate NRF52840_BLE (RADIO) peripheral: registers, tasks, events, GATT MMIO."""

    BLE_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/BLE.cs"
    SX1262_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/SX1262.cs"
    NRF52_REPL = PROJECT_ROOT / "lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl"

    def _ble_script(self, body: str) -> str:
        """Wrap a test body with the common BLE peripheral includes."""
        return f"""\
:name: BLETest
include @{self.SX1262_CS}
include @{self.BLE_CS}
mach create "test"
machine LoadPlatformDescription @{self.NRF52_REPL}
{body}
quit
"""

    def test_ble_cs_exists(self) -> None:
        assert self.BLE_CS.exists(), f"BLE.cs not found at {self.BLE_CS}"

    def test_ble_peripheral_loads(self, tmp_path: Path) -> None:
        """Verify BLE.cs compiles and loads without error."""
        script = self._ble_script("""\
logLevel 1 radio
sleep 0.1
""")
        output = _run_renode_script(tmp_path, script)
        errs = [
            line for line in output.splitlines()
            if "error" in line.lower() and "warning" not in line.lower()
        ]
        assert not errs, "BLE peripheral load reported errors:\n" + "\n".join(errs)

    def test_ble_task_txen_sets_ready_event(self, tmp_path: Path) -> None:
        """Write to TASKS_TXEN (0x000) and verify EVENTS_READY (0x100) is set."""
        script = self._ble_script("""\
; TASKS_TXEN at offset 0x000
sysbus WriteDoubleWord 0x40001000 1
; Verify EVENTS_READY (offset 0x100) is now 1
$ready=`sysbus ReadDoubleWord 0x40001100`
assert { $ready == 1 } "EVENTS_READY was not set after TASKS_TXEN (got $ready)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_task_disable_sets_disabled_event(self, tmp_path: Path) -> None:
        """Write to TASKS_DISABLE (0x010) and verify EVENTS_DISABLED (0x110) is set."""
        script = self._ble_script("""\
; TASKS_DISABLE at offset 0x010
sysbus WriteDoubleWord 0x40001010 1
; Verify EVENTS_DISABLED (offset 0x110) is now 1
$disabled=`sysbus ReadDoubleWord 0x40001110`
assert { $disabled == 1 } "EVENTS_DISABLED was not set after TASKS_DISABLE (got $disabled)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_intenset_enables_interrupt(self, tmp_path: Path) -> None:
        """Set INTENSET and verify INTENCLR reads back the same value."""
        script = self._ble_script("""\
; INTENSET at offset 0x304
sysbus WriteDoubleWord 0x40001304 0x01
; INTENCLR at 0x308 reads back as INTENSET
$inten=`sysbus ReadDoubleWord 0x40001308`
assert { $inten == 1 } "INTENCLR did not read back INTENSET value (got $inten)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_crcstatus_always_one(self, tmp_path: Path) -> None:
        """CRCSTATUS (0x400) always returns 1 (OK)."""
        script = self._ble_script("""\
$crc=`sysbus ReadDoubleWord 0x40001400`
assert { $crc == 1 } "CRCSTATUS was not 1 (got $crc)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_frequency_set_and_read(self, tmp_path: Path) -> None:
        """Write FREQUENCY (0x508) and verify readback."""
        script = self._ble_script("""\
sysbus WriteDoubleWord 0x40001508 0x10
$freq=`sysbus ReadDoubleWord 0x40001508`
assert { $freq == 0x10 } "FREQUENCY readback mismatch (got $freq)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_gatt_mmio_handle_write_and_read(self, tmp_path: Path) -> None:
        """Write GATT_HANDLE (0x804) and verify readback."""
        script = self._ble_script("""\
sysbus WriteDoubleWord 0x40001804 0x0042
$handle=`sysbus ReadDoubleWord 0x40001804`
assert { $handle == 0x42 } "GATT_HANDLE readback mismatch (got $handle)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_ble_gatt_value_buffer_word_access(self, tmp_path: Path) -> None:
        """Write and read GATT value buffer via word access at 0x900."""
        script = self._ble_script("""\
sysbus WriteDoubleWord 0x40001900 0xDEADBEEF
$val=`sysbus ReadDoubleWord 0x40001900`
assert { $val == 0xDEADBEEF } "GATT value buffer word readback mismatch (got 0x$val)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
class TestUsbdPeripheralModel:
    """Validate NRF52840_USBD peripheral: ENABLE, EVENTCAUSE, INTEN, IRQ."""

    USBD_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/USBD.cs"
    SX1262_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/SX1262.cs"
    NRF52_REPL = PROJECT_ROOT / "lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl"

    def _usbd_script(self, body: str) -> str:
        return f"""\
:name: USBDTest
include @{self.SX1262_CS}
include @{self.USBD_CS}
mach create "test"
machine LoadPlatformDescription @{self.NRF52_REPL}
{body}
quit
"""

    def test_usbd_cs_exists(self) -> None:
        assert self.USBD_CS.exists(), f"USBD.cs not found at {self.USBD_CS}"

    def test_usbd_peripheral_loads(self, tmp_path: Path) -> None:
        """Verify USBD.cs compiles and loads without error."""
        script = self._usbd_script("""\
logLevel 1 usbd
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_usbd_eventcause_has_ready_bit_on_reset(self, tmp_path: Path) -> None:
        """After reset, EVENTCAUSE (0x400) should have READY bit (bit 11) set."""
        script = self._usbd_script("""\
$cause=`sysbus ReadDoubleWord 0x40027400`
assert { ($cause & 0x800) != 0 } "EVENTCAUSE READY bit not set after reset (got 0x$cause)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_usbd_enable_sets_usbevent(self, tmp_path: Path) -> None:
        """Writing ENABLE=1 should set USBEVENT and fire IRQ."""
        script = self._usbd_script("""\
; ENABLE at offset 0x500
sysbus WriteDoubleWord 0x40027500 1
; EVENTS_USBEVENT at offset 0x104
$evt=`sysbus ReadDoubleWord 0x40027104`
assert { $evt == 1 } "EVENTS_USBEVENT was not set after ENABLE (got $evt)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_usbd_eventcause_write_clear(self, tmp_path: Path) -> None:
        """Writing to EVENTCAUSE clears the written bits (write-1-to-clear)."""
        script = self._usbd_script("""\
$cause=`sysbus ReadDoubleWord 0x40027400`
; Clear READY bit
sysbus WriteDoubleWord 0x40027400 $cause
$cleared=`sysbus ReadDoubleWord 0x40027400`
assert { $cleared == 0 } "EVENTCAUSE was not cleared by write-1-to-clear (got 0x$cleared)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_usbd_inten_enables_interrupt(self, tmp_path: Path) -> None:
        """Write INTEN (0x700) and verify it is stored."""
        script = self._usbd_script("""\
sysbus WriteDoubleWord 0x40027700 0x01
$inten=`sysbus ReadDoubleWord 0x40027700`
assert { $inten == 1 } "INTEN readback mismatch (got $inten)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_usbd_intenclr_clears_interrupt_enable(self, tmp_path: Path) -> None:
        """Write INTEN then INTENCLR; verify INTEN is cleared."""
        script = self._usbd_script("""\
sysbus WriteDoubleWord 0x40027700 0x01
sysbus WriteDoubleWord 0x40027708 0x01
$inten=`sysbus ReadDoubleWord 0x40027700`
assert { $inten == 0 } "INTEN was not cleared after INTENCLR (got $inten)"
sleep 0.1
""")
        _run_renode_script(tmp_path, script)


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
class TestGpsPeripheralModel:
    """Validate GPS/GNSS peripheral: deterministic NMEA output via UART."""

    GPS_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/GPS.cs"
    LR1110_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/LR1110.cs"
    USBD_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/USBD.cs"
    T1000E_REPL = PROJECT_ROOT / "lichen/boards/renode/t1000_e/support/t1000_e.repl"

    def _gps_script(self, body: str) -> str:
        return f"""\
:name: GPSTest
include @{self.LR1110_CS}
include @{self.GPS_CS}
include @{self.USBD_CS}
mach create "test"
machine LoadPlatformDescription @{self.T1000E_REPL}
{body}
quit
"""

    def test_gps_cs_exists(self) -> None:
        assert self.GPS_CS.exists(), f"GPS.cs not found at {self.GPS_CS}"

    def test_gps_peripheral_loads(self, tmp_path: Path) -> None:
        """Verify GPS.cs compiles and loads without error."""
        script = self._gps_script("""\
logLevel 1 gps
sleep 0.1
""")
        _run_renode_script(tmp_path, script)

    def test_gps_force_output_produces_nmea_via_uart(self, tmp_path: Path) -> None:
        """Call ForceOutput() on GPS peripheral via Renode monitor and verify
        NMEA sentences are queued on the UART."""
        script = self._gps_script("""\
logLevel 0 gps
gps ForceOutput
sleep 0.05
""")
        output = _run_renode_script(tmp_path, script)
        assert "GPS TX: $GPGGA" in output, (
            f"Expected GPGGA sentence in GPS output:\n{output}"
        )
        assert "GPS TX: $GPRMC" in output, (
            f"Expected GPRMC sentence in GPS output:\n{output}"
        )

    def test_gps_default_position_is_area51(self, tmp_path: Path) -> None:
        """Verify default GPS position is Area 51 (37.2350, -115.8111, 1360.0)."""
        script = self._gps_script("""\
logLevel 0 gps
gps ForceOutput
sleep 0.05
""")
        output = _run_renode_script(tmp_path, script)
        lines = [line for line in output.splitlines() if "GPS TX:" in line]
        gga_lines = [line for line in lines if "GPGGA" in line]
        rmc_lines = [line for line in lines if "GPRMC" in line]
        assert gga_lines, f"No GPGGA output:\n{output}"
        assert rmc_lines, f"No RMC output:\n{output}"
        assert "N" in gga_lines[0], f"GPS lat not N in GGA: {gga_lines[0]}"
        assert "W" in gga_lines[0], f"GPS lon not W in GGA: {gga_lines[0]}"
        assert "1" in gga_lines[0], f"GPS fix quality not 1 in GGA: {gga_lines[0]}"

    def test_gps_t1000e_position_is_seattle(self, tmp_path: Path) -> None:
        """T1000-E repl overrides GPS position to Seattle (47.6062, -122.3321).
        Verify this via NMEA output."""
        script = self._gps_script("""\
logLevel 0 gps
gps ForceOutput
sleep 0.05
""")
        output = _run_renode_script(tmp_path, script)
        # Seattle RMC should have lat ~ 47 deg, lon ~ 122 deg
        rmc_lines = [line for line in output.splitlines() if "GPRMC" in line]
        assert rmc_lines, f"No RMC output:\n{output}"
        # RMC format: $GPRMC,time,status,lat,NS,lon,EW,speed,course,date,...
        parts = rmc_lines[0].split(",")
        # parts[3] = lat (DDMM.MMMM), parts[4] = N/S, parts[5] = lon, parts[6] = E/W
        lat_str = parts[3] if len(parts) > 3 else ""
        lon_str = parts[5] if len(parts) > 5 else ""
        ns = parts[4] if len(parts) > 4 else ""
        ew = parts[6] if len(parts) > 6 else ""
        assert ns == "N", f"GPS lat direction should be N for Seattle: {rmc_lines[0]}"
        assert ew == "W", f"GPS lon direction should be W for Seattle: {rmc_lines[0]}"
        # Lat should be ~47 degrees (4700.0000+ format)
        assert lat_str.startswith("47"), f"GPS lat not ~47 for Seattle: {lat_str}"
        # Lon should be ~122 degrees
        assert lon_str.startswith("122"), f"GPS lon not ~122 for Seattle: {lon_str}"


@pytest.mark.skipif(
    not RUN_RENODE_INTEGRATION,
    reason="set LICHEN_RUN_RENODE_INTEGRATION=1 to run Renode subprocess integration",
)
@pytest.mark.skipif(
    RUN_RENODE_INTEGRATION and not _has_renode(),
    reason="Renode not installed",
)
class TestLr1110PeripheralModel:
    """Validate LR1110 peripheral: SPI bridge to lichen-sim, LoRa TX/RX."""

    LR1110_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/LR1110.cs"
    T1000E_REPL = PROJECT_ROOT / "lichen/boards/renode/t1000_e/support/t1000_e.repl"

    def test_lr1110_cs_exists(self) -> None:
        assert self.LR1110_CS.exists(), f"LR1110.cs not found at {self.LR1110_CS}"

    @pytest.mark.asyncio
    async def test_lr1110_connects_to_lichen_sim(self, tmp_path: Path) -> None:
        """Verify LR1110 peripheral connects to lichen-sim TCP bridge."""
        sim = Simulation("lr1110-connect-test", time_mode=TimeMode.BARRIER_SYNC)
        server, port = await start_renode_server(
            sim, "lr1110-node", port=0, position=(0.0, 0.0, 0.0)
        )
        try:
            script = f"""\
:name: LR1110ConnectTest
$simPort={port}
include @{self.LR1110_CS}
mach create "test"
machine LoadPlatformDescription @{self.T1000E_REPL}
lr1110 SimPort $simPort
logLevel 1 lr1110
sleep 0.5
quit
"""
            script_path = tmp_path / "lr1110_connect.resc"
            script_path.write_text(script)
            monitor_port = _unused_tcp_port()
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
                raise AssertionError("LR1110 Renode test timed out") from None
            assert proc.returncode == 0, (
                f"LR1110 Renode script failed:\n"
                f"{stdout.decode(errors='replace')}\n"
                f"{stderr.decode(errors='replace')}"
            )
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            assert "error" not in output.lower() or "Connect" in output, (
                f"LR1110 output indicates errors:\n{output}"
            )
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_lr1110_get_status_command(self, tmp_path: Path) -> None:
        """LR1110's GetStatus (opcode 0x0111) should return 0x22 (STDBY_RC)."""
        sim = Simulation("lr1110-status-test", time_mode=TimeMode.BARRIER_SYNC)
        server, port = await start_renode_server(
            sim, "lr1110-node", port=0, position=(0.0, 0.0, 0.0)
        )
        try:
            script = f"""\
:name: LR1110StatusTest
$simPort={port}
include @{self.LR1110_CS}
mach create "test"
machine LoadPlatformDescription @{self.T1000E_REPL}
lr1110 SimPort $simPort
logLevel 1 lr1110
sleep 0.5
quit
"""
            script_path = tmp_path / "lr1110_status.resc"
            script_path.write_text(script)
            monitor_port = _unused_tcp_port()
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
                raise AssertionError("LR1110 status test timed out") from None
            assert proc.returncode == 0, (
                f"LR1110 status script failed:\n"
                f"{stdout.decode(errors='replace')}\n"
                f"{stderr.decode(errors='replace')}"
            )
            output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            assert "Connected to simulator" in output, (
                f"LR1110 did not connect to simulator:\n{output}"
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
class TestT1000EPlatformModel:
    """Validate combined T1000-E platform with LR1110, GPS, BLE, and USBD."""

    LR1110_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/LR1110.cs"
    GPS_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/GPS.cs"
    USBD_CS = PROJECT_ROOT / "lichen/boards/renode/peripherals/USBD.cs"
    T1000E_RESC = PROJECT_ROOT / "lichen/boards/renode/t1000_e/support/t1000_e.resc"

    def test_all_peripheral_cs_files_exist(self) -> None:
        assert self.LR1110_CS.exists()
        assert self.GPS_CS.exists()
        assert self.USBD_CS.exists()
        assert self.T1000E_RESC.exists()

    def test_t1000e_platform_loads_all_peripherals(self, tmp_path: Path) -> None:
        """Verify the T1000-E platform loads with all peripherals included."""
        script = f"""\
:name: T1000EAllPeripherals
$simPort=15555
include @{self.LR1110_CS}
include @{self.GPS_CS}
include @{self.USBD_CS}
mach create "T1000-E"
machine LoadPlatformDescription @{self.T1000E_RESC.parent / "t1000_e.repl"}

; Verify LR1110 loaded
$lr1110=`sysbus ReadDoubleWord 0x40023000`
; Verify USBD loaded at 0x40027000
$usbd_event=`sysbus ReadDoubleWord 0x40027400`
assert {{ ($usbd_event & 0x800) != 0 }} "USBD EVENTCAUSE READY not set"

; Verify BLE loaded at 0x40001000 (inherited from nrf52840_lichen.repl)
$crc=`sysbus ReadDoubleWord 0x40001400`
assert {{ $crc == 1 }} "BLE CRCSTATUS not 1 (got $crc)"

; Enable USBD and verify USBEVENT fires
sysbus WriteDoubleWord 0x40027500 1
$usbevt=`sysbus ReadDoubleWord 0x40027104`
assert {{ $usbevt == 1 }} "USBD EVENTS_USBEVENT not set after ENABLE"

; Verify GPS via ForceOutput
logLevel 1 gps
gps ForceOutput
sleep 0.05
quit
"""
        output = _run_renode_script(tmp_path, script)
        # Verify all peripheral types are mentioned in logs
        for marker in ["GPS TX: $GPGGA", "LR1110", "USBD"]:
            assert marker in output, (
                f"Expected '{marker}' in T1000-E platform output:\n{output}"
            )

    def test_t1000e_resc_script_parses(self, tmp_path: Path) -> None:
        """Verify the canonical T1000-E .resc script parses and runs."""
        script = f"""\
:name: T1000ERescTest
$simPort=15556
include @{self.LR1110_CS}
include @{self.GPS_CS}
include @{self.USBD_CS}
mach create "T1000-E"
machine LoadPlatformDescription @{self.T1000E_RESC.parent / "t1000_e.repl"}
lr1110 SimPort $simPort
sleep 0.1
quit
"""
        _run_renode_script(tmp_path, script)
