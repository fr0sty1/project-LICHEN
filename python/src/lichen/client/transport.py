# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Transport protocols for native LICHEN clients."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol


class PacketTransport(Protocol):
    """Packet-oriented IPv6 transport for BLE/serial SLIP LCI links."""

    async def connect(self) -> None:
        """Open the packet transport."""

    async def close(self) -> None:
        """Close the packet transport and release resources."""

    async def send_packet(self, packet: bytes) -> None:
        """Send one IPv6 packet over the transport."""

    def packets(self) -> AsyncIterator[bytes]:
        """Yield received IPv6 packets until the transport closes."""
