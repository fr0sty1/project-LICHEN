"""
Serial transport for the legacy LICHEN Native CBOR protocol.

Current LCI sessions use IPv6 + CoAP from spec/11-lci.md. This module preserves
the historical spec/lichen-native serial framing for prototype compatibility.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import serial
from serial.tools import list_ports

from lichen.interface.framing import FrameReader, frame
from lichen.interface.messages import Message, decode_message, encode_message

log = logging.getLogger(__name__)

# Type alias for message handler
MessageHandler = Callable[[Message], Awaitable[Message | None]]


def list_serial_ports() -> list[str]:
    """List available serial ports."""
    return [p.device for p in list_ports.comports()]


@dataclass
class SerialConnection:
    """
    Async serial connection using legacy LICHEN Native CBOR framing.

    Uses a background thread for blocking serial I/O,
    with asyncio integration via run_in_executor.
    """

    port: str
    baudrate: int = 115200
    handler: MessageHandler | None = None
    _serial: serial.Serial | None = field(default=None, repr=False)
    _frame_reader: FrameReader = field(default_factory=FrameReader)
    _closed: bool = False
    _loop: asyncio.AbstractEventLoop | None = field(default=None, repr=False)

    async def open(self) -> None:
        """Open the serial port."""
        if self._serial is not None:
            return

        self._loop = asyncio.get_running_loop()

        # Open serial port (blocking, run in executor)
        def _open():
            return serial.Serial(
                self.port,
                self.baudrate,
                timeout=0.1,  # Short timeout for non-blocking reads
            )

        self._serial = await self._loop.run_in_executor(None, _open)
        log.info("opened serial port %s at %d baud", self.port, self.baudrate)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def is_open(self) -> bool:
        return self._serial is not None and self._serial.is_open

    async def send(self, msg: Message) -> None:
        """Send a message."""
        if self._closed or self._serial is None:
            raise ConnectionError("serial port not open")

        data = frame(encode_message(msg))

        def _write():
            self._serial.write(data)
            self._serial.flush()

        await self._loop.run_in_executor(None, _write)

    async def recv(self) -> Message | None:
        """
        Receive one message.

        Returns None on close.
        Raises ConnectionError on error.
        """
        if self._serial is None:
            raise ConnectionError("serial port not open")

        while not self._closed:
            # Check buffer first
            for payload in self._frame_reader:
                return decode_message(payload)

            # Read more data (non-blocking via timeout)
            def _read():
                if self._serial is None or not self._serial.is_open:
                    return None
                # Read available bytes (up to 4096)
                waiting = self._serial.in_waiting
                if waiting > 0:
                    return self._serial.read(min(waiting, 4096))
                # Nothing available, do a short blocking read
                return self._serial.read(1)

            try:
                chunk = await self._loop.run_in_executor(None, _read)
            except (serial.SerialException, OSError) as e:
                log.error("serial read error: %s", e)
                self._closed = True
                raise ConnectionError(str(e)) from e

            if chunk is None:
                self._closed = True
                return None

            if chunk:
                self._frame_reader.feed(chunk)
            else:
                # Yield to other tasks on empty read
                await asyncio.sleep(0.01)

        return None

    async def run(self) -> None:
        """
        Run receive loop, dispatching to handler.

        Stops on close or error.
        """
        if self.handler is None:
            raise ValueError("no handler set")

        try:
            while not self._closed:
                msg = await self.recv()
                if msg is None:
                    break

                response = await self.handler(msg)
                if response is not None:
                    await self.send(response)
        except ConnectionError:
            pass
        finally:
            await self.close()

    async def close(self) -> None:
        """Close the serial port."""
        if self._closed:
            return
        self._closed = True

        if self._serial is not None:
            def _close():
                with contextlib.suppress(Exception):
                    self._serial.close()

            if self._loop:
                await self._loop.run_in_executor(None, _close)
            self._serial = None

        log.info("closed serial port %s", self.port)


async def open_serial(
    port: str,
    baudrate: int = 115200,
    handler: MessageHandler | None = None,
) -> SerialConnection:
    """
    Open a serial connection to a LICHEN device.

    Args:
        port: Serial port path (e.g., "/dev/ttyUSB0", "COM3")
        baudrate: Baud rate (default 115200)
        handler: Optional message handler for run() loop

    Returns:
        Open SerialConnection
    """
    conn = SerialConnection(port=port, baudrate=baudrate, handler=handler)
    await conn.open()
    return conn
