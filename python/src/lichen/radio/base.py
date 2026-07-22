# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

"""Radio protocol definition for LICHEN.

This module defines the Radio protocol that all radio implementations must satisfy.
The protocol supports LoRa radio operations: transmission, reception, and configuration.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Radio(Protocol):
    """Protocol defining the interface for radio implementations.

    All radio implementations (simulated or hardware) must satisfy this protocol.
    Methods are async to support non-blocking I/O with real hardware.
    """

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        """Transmit a payload over the radio on specified channel.

        Args:
            payload: The raw bytes to transmit.
            channel: Channel index (0 = control per CCP-9/da2q.2; default 0).

        Returns:
            True if transmission succeeded, False otherwise.
        """
        ...

    async def receive(self, timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        """Receive a payload from the radio on specified channel (for rendezvous).

        Blocks until a packet is received or timeout expires. Channel used for
        rendezvous per ccp9 vectors (CH0 fallback for unknown peers).

        Args:
            timeout_ms: Maximum time to wait for a packet, in milliseconds.
            channel: Expected channel for RX (default 0 = control).

        Returns:
            A tuple of (payload, rssi_dbm, snr_db) if a packet was received,
            or None if the timeout expired without receiving a packet.
            - payload: The raw received bytes
            - rssi_dbm: Received Signal Strength Indicator in dBm (negative)
            - snr_db: Signal-to-Noise Ratio in dB (can be negative)
        """
        ...

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """Configure the radio parameters.

        Args:
            freq_hz: Center frequency in Hz (e.g., 915_000_000 for 915 MHz).
            tx_power_dbm: Transmit power in dBm (e.g., 14 for 14 dBm / 25 mW).
        """
        ...

    async def cad(self, timeout_ms: int) -> bool:
        """Perform Channel Activity Detection (CAD).

        CAD listens briefly for LoRa preamble activity without fully receiving
        a packet. This is used for carrier-sense before transmitting (CSMA/CA)
        and for low-power wake-on-radio applications.

        The operation completes quickly (typically 2-4 symbol periods) or when
        the timeout expires, whichever comes first.

        Args:
            timeout_ms: Maximum time to wait for CAD completion, in milliseconds.
                        Typical values are 20-50ms for SF10/125kHz.

        Returns:
            True if channel activity (LoRa preamble) was detected,
            False if the channel appears clear or timeout expired without detection.
        """
        ...
