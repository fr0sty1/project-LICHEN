# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio protocol definition for LICHEN.

This module defines the Radio protocol that all radio implementations must satisfy.
The protocol supports LoRa radio operations: transmission, reception, and configuration.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class Radio(Protocol):
    """Protocol defining the interface for radio implementations.

    All radio implementations (simulated or hardware) must satisfy this protocol.
    Methods are async to support non-blocking I/O with real hardware.
    """

    async def transmit(self, payload: bytes) -> bool:
        """Transmit a payload over the radio.

        Args:
            payload: The raw bytes to transmit.

        Returns:
            True if transmission succeeded, False otherwise.
        """
        ...

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Receive a payload from the radio.

        Blocks until a packet is received or timeout expires.

        Args:
            timeout_ms: Maximum time to wait for a packet, in milliseconds.

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
