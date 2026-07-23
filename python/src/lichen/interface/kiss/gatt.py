# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
BLE GATT service for KISS TNC compatibility.

Exposes KISS interface over BLE for TNC apps (aprs.fi, APRSDroid).
This is a stub implementation - real BLE requires platform-specific code.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from .framing import KissReader
from .handler import KissHandler

log = logging.getLogger(__name__)

# GATT Service UUIDs
SERVICE_UUID = "00000001-ba2a-46c9-ae49-01b0961f68bb"
TX_CHAR_UUID = "00000002-ba2a-46c9-ae49-01b0961f68bb"  # App writes to device
RX_CHAR_UUID = "00000003-ba2a-46c9-ae49-01b0961f68bb"  # Device notifies app

# BLE MTU constraints
DEFAULT_MTU = 20  # 23 byte MTU minus 3 byte overhead
MAX_MTU = 512


@dataclass
class KissGattService:
    """BLE GATT service for KISS.

    This is a stub that provides the interface without actual BLE.
    Real implementations will subclass or wrap this with platform-specific
    BLE code (e.g., bless on desktop, Zephyr APIs on embedded).

    Attributes:
        handler: KissHandler for command dispatch.
        on_notify: Callback when RX data ready for client.
        mtu: Current MTU (for packet sizing).
    """

    handler: KissHandler
    on_notify: Callable[[bytes], None] | None = None
    mtu: int = DEFAULT_MTU
    _reader: KissReader = field(default_factory=KissReader)
    _running: bool = False
    _connected: bool = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def start(self) -> None:
        """Start the GATT service (advertising).

        In a real implementation, this would:
        1. Register the GATT service
        2. Start BLE advertising
        """
        if self._running:
            return
        self._running = True
        log.info("KISS GATT service started (stub)")

    async def stop(self) -> None:
        """Stop the GATT service."""
        if not self._running:
            return
        self._running = False
        self._connected = False
        log.info("KISS GATT service stopped")

    def on_connect(self, mtu: int = DEFAULT_MTU) -> None:
        """Called when a client connects.

        Args:
            mtu: Negotiated MTU size.
        """
        self._connected = True
        self.mtu = mtu
        self._reader.clear()
        log.info("GATT client connected, MTU=%d", mtu)

    def on_disconnect(self) -> None:
        """Called when client disconnects."""
        self._connected = False
        self._reader.clear()
        log.info("GATT client disconnected")

    def on_tx_write(self, data: bytes) -> None:
        """Called when client writes to TX characteristic.

        Processes incoming KISS frames and dispatches to handler.
        Handles reassembly of frames split across BLE packets.

        Args:
            data: Raw bytes from BLE write.
        """
        if not self._connected:
            return

        self._reader.feed(data)

        for frame in self._reader:
            self.handler.handle(frame)
            if self.handler.exited:
                log.info("KISS RETURN received, client should disconnect")
                break

    async def send_frame(self, data: bytes) -> None:
        """Send KISS frame to client via RX notify.

        Splits large frames across multiple BLE packets if needed.

        Args:
            data: KISS-encoded frame bytes.
        """
        if not self._connected:
            return

        # Split into MTU-sized chunks
        for i in range(0, len(data), self.mtu):
            chunk = data[i : i + self.mtu]
            if self.on_notify:
                self.on_notify(chunk)
            # Small yield between chunks to allow BLE stack to process
            await asyncio.sleep(0)

    def send_frame_sync(self, data: bytes) -> list[bytes]:
        """Synchronous version that returns chunks to send.

        Useful for BLE stacks that handle their own async.

        Args:
            data: KISS-encoded frame bytes.

        Returns:
            List of MTU-sized chunks to send via notify. Returns [b""] for
            empty input so iteration over result always executes at least once.
        """
        return [data[i : i + self.mtu] for i in range(0, len(data) or 1, self.mtu)]


# ponytail: real BLE peripheral needs platform-specific code (bless/Zephyr)
# This stub enables testing KISS ↔ GATT flow without hardware
