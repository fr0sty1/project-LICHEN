# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
KISS serial transport.

Async serial connection for KISS TNC mode.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import serial

from .framing import KissReader
from .handler import DefaultKissConfig, KissHandler

log = logging.getLogger(__name__)

# Frame callback type: receives (port, payload) from DATA frames
FrameCallback = Callable[[int, bytes], None]


@dataclass
class KissSerialConnection:
    """
    Async serial connection for KISS mode.

    Attributes:
        port: Serial port path.
        baudrate: Baud rate.
        handler: KissHandler for command dispatch.
        on_frame: Called with (port, payload) when DATA frame received.
    """

    port: str
    baudrate: int = 115200
    handler: KissHandler = field(default_factory=lambda: KissHandler(config=DefaultKissConfig()))
    on_frame: FrameCallback | None = None
    _serial: serial.Serial | None = field(default=None, repr=False)
    _reader: KissReader = field(default_factory=KissReader)
    _closed: bool = False
    _loop: asyncio.AbstractEventLoop | None = field(default=None, repr=False)
    _open_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __post_init__(self) -> None:
        # Wire up handler's TX callback to our on_frame
        if self.on_frame is not None:
            self.handler.on_tx_frame = self.on_frame

    async def open(self) -> None:
        """Open the serial port."""
        async with self._open_lock:
            if self._serial is not None:
                return

            self._loop = asyncio.get_running_loop()

            def _open():
                return serial.Serial(
                    self.port,
                    self.baudrate,
                    timeout=0.1,
                )

            self._serial = await self._loop.run_in_executor(None, _open)
            log.info("opened KISS serial %s at %d baud", self.port, self.baudrate)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def is_open(self) -> bool:
        return self._serial is not None and self._serial.is_open

    async def send_frame(self, payload: bytes, port: int = 0) -> None:
        """Send a frame to the KISS host (radio RX -> host)."""
        if self._closed or self._serial is None or self._loop is None:
            raise ConnectionError("serial port not open")

        data = self.handler.rx_frame(payload, port)
        ser = self._serial

        def _write():
            if ser is None or not ser.is_open:
                return
            ser.write(data)
            ser.flush()

        await self._loop.run_in_executor(None, _write)

    async def recv(self) -> bool:
        """
        Read and process available data.

        Returns:
            True if still running, False if closed or RETURN received.
        """
        if self._serial is None or self._loop is None:
            raise ConnectionError("serial port not open")

        if self._closed or self.handler.exited:
            return False

        ser = self._serial

        def _read():
            if ser is None or not ser.is_open:
                return None
            waiting = ser.in_waiting
            if waiting > 0:
                return ser.read(min(waiting, 4096))
            return ser.read(1)

        try:
            chunk = await self._loop.run_in_executor(None, _read)
        except (serial.SerialException, OSError) as exc:
            log.error("KISS serial read error: %s", exc)
            self._closed = True
            raise ConnectionError(str(exc)) from exc

        if chunk is None:
            self._closed = True
            return False

        if chunk:
            self._reader.feed(chunk)
            for frame in self._reader:
                self.handler.handle(frame)
                if self.handler.exited:
                    return False

        return True

    async def run(self) -> None:
        """
        Run receive loop until closed or RETURN command.

        Dispatches DATA frames to on_frame callback.
        """
        try:
            while await self.recv():
                await asyncio.sleep(0.001)  # Yield to other tasks
        except ConnectionError:
            pass
        finally:
            await self.close()

    async def close(self) -> None:
        """Close the serial port."""
        if self._closed:
            return
        self._closed = True

        ser = self._serial
        if ser is not None:
            def _close():
                with contextlib.suppress(Exception):
                    ser.close()

            if self._loop:
                await self._loop.run_in_executor(None, _close)
            self._serial = None

        log.info("closed KISS serial %s", self.port)


async def open_kiss_serial(
    port: str,
    baudrate: int = 115200,
    on_frame: FrameCallback | None = None,
) -> KissSerialConnection:
    """
    Open a KISS serial connection.

    Args:
        port: Serial port path.
        baudrate: Baud rate.
        on_frame: Callback for DATA frames (payload to transmit).

    Returns:
        Open KissSerialConnection.
    """
    conn = KissSerialConnection(port=port, baudrate=baudrate, on_frame=on_frame)
    await conn.open()
    return conn
