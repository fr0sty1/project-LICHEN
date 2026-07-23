# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

"""Radio protocol definition for LICHEN.

This module defines the Radio protocol that all radio implementations must satisfy.
The protocol supports LoRa radio operations: transmission, reception, and configuration.
"""

from typing import Protocol, runtime_checkable  # noqa: E402

MAX_LORA_PAYLOAD = 255
"""Maximum LoRa PHY payload size (bytes). All Radio.transmit() implementations
MUST reject payloads exceeding this with ValueError(f"payload length ... exceeds
LoRa MTU..."). Matches sim_client.py and real LoRa hardware constraints (SF7-12).
"""


@runtime_checkable
class Radio(Protocol):
    """Protocol defining the interface for radio implementations.

    All radio implementations (simulated or hardware) must satisfy this protocol.
    Methods are async to support non-blocking I/O with real hardware.
    """

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        """Transmit a payload over the radio on specified channel.

        Args:
            payload: The raw bytes to transmit. MUST be <= MAX_LORA_PAYLOAD (255
                bytes); implementations raise ValueError for larger payloads.
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

        Advisory only. Implementations MUST store values for the ``freq_hz``
        and ``tx_power_dbm`` properties. Some (e.g. SimRadio) do not send
        configuration over the wire; a future CONFIGURE protocol message
        would be required for full synchronization with the simulator.

        Args:
            freq_hz: Center frequency in Hz (e.g., 915_000_000 for 915 MHz).
            tx_power_dbm: Transmit power in dBm (e.g., 14 for 14 dBm / 25 mW).
        """
        ...

    async def cad(self, timeout_ms: int, channel: int = 0) -> bool:
        """Perform Channel Activity Detection (CAD) on specified channel.

        CAD for per-channel listen-before-talk and rendezvous (CCP-9). Uses
        channel from link selector or control CH0.

        The operation completes quickly (typically 2-4 symbol periods) or when
        the timeout expires, whichever comes first.

        Args:
            timeout_ms: Maximum time to wait for CAD completion, in milliseconds.
                        Typical values are 20-50ms for SF10/125kHz.
            channel: Channel for CAD (default 0 = control).

        Returns:
            True if channel activity (LoRa preamble) was detected.
            False if the channel is clear (no activity detected within timeout).
            Note: Current protocol (P4 design) conflates timeout with clear into False.
            Hardware implementations should raise on error; link_layer treats False
            as safe-to-TX (per project-LICHEN-b4pw).
        """
        ...
