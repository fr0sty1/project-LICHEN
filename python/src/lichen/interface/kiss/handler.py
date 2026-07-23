# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
KISS command handler.

Dispatches KISS frames by command type:
- DATA (0x00): send/receive link layer frames
- TXDELAY/PERSISTENCE/SLOTTIME/TXTAIL/FULLDUPLEX: config
- RETURN (0x0F): exit KISS mode
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from .framing import KissCommand, KissFrame, kiss_encode


class KissConfig(Protocol):
    """Protocol for KISS-configurable parameters.

    TNC apps expect to set these via KISS commands. Map them to
    whatever makes sense for the node (or ignore if not applicable).
    """

    @property
    def txdelay_ms(self) -> int:
        """TX key-up delay in 10ms units (0-255 -> 0-2550ms)."""
        ...

    @txdelay_ms.setter
    def txdelay_ms(self, value: int) -> None: ...

    @property
    def persistence(self) -> int:
        """CSMA p-value (0-255, p = value/256)."""
        ...

    @persistence.setter
    def persistence(self, value: int) -> None: ...

    @property
    def slottime_ms(self) -> int:
        """CSMA slot interval in 10ms units."""
        ...

    @slottime_ms.setter
    def slottime_ms(self, value: int) -> None: ...

    @property
    def txtail_ms(self) -> int:
        """TX tail time in 10ms units."""
        ...

    @txtail_ms.setter
    def txtail_ms(self, value: int) -> None: ...

    @property
    def fullduplex(self) -> bool:
        """True for full duplex, False for half duplex."""
        ...

    @fullduplex.setter
    def fullduplex(self, value: bool) -> None: ...


@dataclass
class DefaultKissConfig:
    """Default KISS config that stores values but doesn't affect anything."""

    txdelay_ms: int = 50  # 500ms default
    persistence: int = 63  # p=0.25
    slottime_ms: int = 10  # 100ms
    txtail_ms: int = 10  # 100ms
    fullduplex: bool = False


@dataclass
class KissHandler:
    """KISS command dispatcher.

    Attributes:
        config: KISS-configurable parameters.
        on_tx_frame: Called with (port, payload) when DATA frame received.
        on_exit: Called when RETURN command received.
        port_filter: Only handle frames for this port (None = all ports).
    """

    config: KissConfig = field(default_factory=DefaultKissConfig)
    on_tx_frame: Callable[[int, bytes], None] | None = None
    on_exit: Callable[[], None] | None = None
    port_filter: int | None = None
    _exited: bool = field(default=False, repr=False)

    @property
    def exited(self) -> bool:
        """True if RETURN command was received."""
        return self._exited

    def handle(self, frame: KissFrame) -> None:
        """Process a KISS frame.

        Args:
            frame: Decoded KISS frame from KissReader.
        """
        if self._exited:
            return

        if self.port_filter is not None and frame.port != self.port_filter:
            return

        cmd = frame.command

        if cmd == KissCommand.DATA:
            self._handle_data(frame)
        elif cmd == KissCommand.TXDELAY:
            self._handle_txdelay(frame)
        elif cmd == KissCommand.PERSISTENCE:
            self._handle_persistence(frame)
        elif cmd == KissCommand.SLOTTIME:
            self._handle_slottime(frame)
        elif cmd == KissCommand.TXTAIL:
            self._handle_txtail(frame)
        elif cmd == KissCommand.FULLDUPLEX:
            self._handle_fullduplex(frame)
        elif cmd == KissCommand.RETURN:
            self._handle_return(frame)
        # ponytail: unknown commands silently ignored per KISS spec

    def _handle_data(self, frame: KissFrame) -> None:
        """Forward data frame to TX callback."""
        if self.on_tx_frame is not None:
            self.on_tx_frame(frame.port, frame.data)

    def _handle_txdelay(self, frame: KissFrame) -> None:
        """Set TX delay (10ms units)."""
        if frame.data:
            self.config.txdelay_ms = frame.data[0]

    def _handle_persistence(self, frame: KissFrame) -> None:
        """Set CSMA persistence."""
        if frame.data:
            self.config.persistence = frame.data[0]

    def _handle_slottime(self, frame: KissFrame) -> None:
        """Set CSMA slot time (10ms units)."""
        if frame.data:
            self.config.slottime_ms = frame.data[0]

    def _handle_txtail(self, frame: KissFrame) -> None:
        """Set TX tail time (10ms units)."""
        if frame.data:
            self.config.txtail_ms = frame.data[0]

    def _handle_fullduplex(self, frame: KissFrame) -> None:
        """Set half/full duplex mode."""
        if frame.data:
            self.config.fullduplex = frame.data[0] != 0

    def _handle_return(self, frame: KissFrame) -> None:
        """Exit KISS mode."""
        self._exited = True
        if self.on_exit is not None:
            self.on_exit()

    def rx_frame(self, payload: bytes, port: int = 0) -> bytes:
        """Encode a received frame to send to the KISS host.

        Call this when a frame is received from the radio to forward
        it to the connected TNC app.

        Args:
            payload: Raw frame data from radio.
            port: KISS port (0-15).

        Returns:
            KISS-encoded frame bytes ready to send to host.
        """
        return kiss_encode(port, KissCommand.DATA, payload)

    def reset(self) -> None:
        """Reset handler state (clear exited flag)."""
        self._exited = False
