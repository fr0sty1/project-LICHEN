# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa transmission modeling for the LICHEN simulator.

This module provides dataclasses and functions for modeling LoRa radio
transmissions, including airtime calculations for the fixed SF10/125kHz
configuration used by LICHEN.
"""

from dataclasses import dataclass, field
from math import ceil
from uuid import uuid4

# Fixed LoRa parameters for LICHEN
_SF = 10  # Spreading factor
_BW = 125_000  # Bandwidth in Hz
_CR = 5  # Coding rate numerator (4/5 means CR=5)
_PREAMBLE = 8  # Preamble symbols
_HEADER_OVERHEAD = 28  # 8 sync + 20 header (explicit mode)
_CRC_BITS = 16  # CRC bits


def airtime_us(payload_len: int) -> int:
    """Calculate LoRa airtime in microseconds for a given payload length.

    Uses fixed SF10/125kHz/CR4-5 parameters as specified for LICHEN.

    The formula is:
        T = T_symbol * (preamble + 4.25 + 8 + N_payload)

    Where:
        T_symbol = 2^SF / BW
        N_payload = max(ceil((8*PL - 4*SF + 28 + 16) / (4*SF)) * CR, 0)

    Args:
        payload_len: Length of payload in bytes.

    Returns:
        Airtime in microseconds.

    Raises:
        ValueError: If payload_len is negative.
    """
    if payload_len < 0:
        raise ValueError(f"payload_len must be non-negative, got {payload_len}")

    # Symbol time in seconds: 2^SF / BW
    t_symbol_s = (2**_SF) / _BW

    # Payload symbol count
    # Formula: max(ceil((8*PL - 4*SF + 28 + 16) / (4*SF)) * CR, 0)
    numerator = 8 * payload_len - 4 * _SF + _HEADER_OVERHEAD + _CRC_BITS
    denominator = 4 * _SF
    n_payload = max(ceil(numerator / denominator) * _CR, 0)

    # Total symbols: preamble + 4.25 + 8 (header symbols) + payload symbols
    total_symbols = _PREAMBLE + 4.25 + 8 + n_payload

    # Total time in seconds, convert to microseconds
    airtime_s = t_symbol_s * total_symbols
    return int(airtime_s * 1_000_000)


def lr_fhss_airtime_us(payload_len: int) -> int:
    if payload_len < 0:
        raise ValueError(f"payload_len must be non-negative, got {payload_len}")
    return airtime_us(payload_len) * 2


@dataclass
class Transmission:
    """A LoRa radio transmission in the simulated channel.

    Represents a single transmission from a node, including its timing,
    power, payload, and channel. Used by the channel simulator to
    model propagation and interference. Different channels are orthogonal
    (independent collision/propagation oracle).

    Attributes:
        id: Unique identifier for this transmission (UUID).
        source_node_id: ID of the node transmitting.
        payload: Raw bytes being transmitted.
        tx_power_dbm: Transmit power in dBm.
        start_time_us: Simulation time when transmission starts (microseconds).
        end_time_us: Simulation time when transmission ends (microseconds).
        frequency_hz: Carrier frequency in Hz (default 915 MHz).
        channel: Channel index for multi-channel support and rendezvous
            (default 0). RX only sees matching channel.
    """

    source_node_id: str
    payload: bytes
    tx_power_dbm: int
    start_time_us: int
    end_time_us: int
    id: str = field(default_factory=lambda: str(uuid4()))
    frequency_hz: int = 915_000_000
    channel: int = 0
    phy_mode: str = "lora"
