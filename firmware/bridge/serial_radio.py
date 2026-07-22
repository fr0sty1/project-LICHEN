# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
Serial radio interface for LICHEN bridge firmware.

Connects Python code to real LoRa hardware via USB serial.
Drop-in replacement for SimRadio in the simulator.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import serial
import serial.tools.list_ports


@dataclass
class RxPacket:
    """Received packet with metadata."""
    data: bytes
    rssi: float
    snr: float


class SerialRadio:
    """Interface to LoRa radio via serial bridge firmware."""

    def __init__(self, port: str, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self._serial: serial.Serial | None = None
        self._rx_queue: asyncio.Queue[RxPacket] = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None

    async def connect(self) -> None:
        """Open serial connection and start reader."""
        self._serial = serial.Serial(self.port, self.baudrate, timeout=0.1)
        self._reader_task = asyncio.create_task(self._reader_loop())

        # Wait for ready
        await asyncio.sleep(0.5)

    async def close(self) -> None:
        """Close connection."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._serial:
            self._serial.close()

    async def _reader_loop(self) -> None:
        """Background task to read incoming packets."""
        assert self._serial is not None

        loop = asyncio.get_event_loop()
        buffer = b""

        while True:
            # Read in executor to avoid blocking
            chunk = await loop.run_in_executor(
                None, lambda: self._serial.read(256)
            )
            if chunk:
                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    await self._process_line(line.decode("utf-8", errors="ignore").strip())

            await asyncio.sleep(0.01)

    async def _process_line(self, line: str) -> None:
        """Process a line from the radio."""
        if line.startswith("RX "):
            # RX <rssi> <snr> <hex>
            parts = line[3:].split(" ", 2)
            if len(parts) == 3:
                rssi = float(parts[0])
                snr = float(parts[1])
                data = bytes.fromhex(parts[2])
                await self._rx_queue.put(RxPacket(data, rssi, snr))
        elif line.startswith("#"):
            # Comment/debug output
            print(f"[radio] {line}")
        elif line.startswith("OK") or line.startswith("ERR"):
            # Response to command - could track these properly
            print(f"[radio] {line}")

    async def transmit(self, data: bytes) -> bool:
        """Transmit a packet."""
        assert self._serial is not None
        cmd = f"TX {data.hex()}\n"
        self._serial.write(cmd.encode())
        return True  # ponytail: no ack tracking, add if needed

    async def receive(self, timeout: float = None) -> RxPacket | None:
        """Wait for a received packet."""
        try:
            return await asyncio.wait_for(self._rx_queue.get(), timeout)
        except asyncio.TimeoutError:
            return None

    async def configure(
        self,
        sf: int = 10,
        bw: float = 125.0,
        cr: int = 5,
        freq_hz: int = 915_000_000,
        power: int = 22,
    ) -> None:
        """Configure radio parameters."""
        assert self._serial is not None
        cmd = f"CFG SF={sf} BW={bw} CR={cr} FREQ={freq_hz} PWR={power}\n"
        self._serial.write(cmd.encode())
        await asyncio.sleep(0.1)  # ponytail: wait for config, proper ack later


def find_rak4631() -> str | None:
    """Find a RAK4631 serial port."""
    for port in serial.tools.list_ports.comports():
        # nRF52840 shows up as usbmodem
        if "usbmodem" in port.device:
            return port.device
    return None


async def demo():
    """Demo: transmit and receive."""
    port = find_rak4631()
    if not port:
        print("No RAK4631 found")
        return

    print(f"Using {port}")
    radio = SerialRadio(port)
    await radio.connect()

    # Configure LICHEN defaults
    await radio.configure(sf=10, bw=125, cr=5, freq_hz=915_000_000)

    # Transmit test packet
    await radio.transmit(b"LICHEN test")

    # Listen for packets
    print("Listening for packets (Ctrl-C to stop)...")
    try:
        while True:
            pkt = await radio.receive(timeout=1.0)
            if pkt:
                print(f"RX: rssi={pkt.rssi} snr={pkt.snr} data={pkt.data}")
    except KeyboardInterrupt:
        pass

    await radio.close()


if __name__ == "__main__":
    asyncio.run(demo())
