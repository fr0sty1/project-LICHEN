# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Time synchronization oracle (spec 09-packets-timing.md §14.6).

Covers time provider architecture, source classes, epoch floor, stratum
and DIO Time Option.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# Source classes by trust/precedence (§14.6 table)
SOURCE_CLASSES: tuple[str, ...] = (
    "GNSS",
    "Network",
    "Local-client",
    "Manual/static",
    "Internal RTC",
    "Monotonic",
)

# Whether each class can establish wall clock (spec table)
SOURCE_CAN_ESTABLISH_WALL_CLOCK: dict[str, bool] = {
    "GNSS": True,
    "Network": True,
    "Local-client": True,
    "Manual/static": True,
    "Internal RTC": True,
    "Monotonic": False,
}


class Stratum(IntEnum):
    """Time stratum propagated in DIO Time Option (§14.6)."""

    NO_SYNC = 0  # Monotonic counters only
    MESH_DERIVED = 1  # Network (peer DIO)
    ROUGHTIME = 2  # Network (BR)
    NTS = 3  # Network (BR)
    GNSS_GPSD = 4  # GNSS or Local-client


STRATUM_SOURCE_CLASS: dict[Stratum, str] = {
    Stratum.NO_SYNC: "Monotonic",
    Stratum.MESH_DERIVED: "Network",
    Stratum.ROUGHTIME: "Network",
    Stratum.NTS: "Network",
    Stratum.GNSS_GPSD: "GNSS",
}

# DIO Time Option wire format (§14.6)
# +--------+--------+--------+--------+--------+
# | Type 1B| Len 1B |Stratum 1B|Reserved 1B|Timestamp 4B (Unix epoch)|
DIO_TIME_OPTION_LEN: int = 6  # payload after Type/Length (total 8B)
DIO_TIME_OPTION_TOTAL: int = 8


@dataclass(frozen=True)
class DioTimeOption:
    """DIO Time Option (Type TBD, 8 bytes on wire)."""

    stratum: Stratum
    timestamp: int  # Unix epoch seconds, 4B
    reserved: int = 0

    def encode(self) -> bytes:
        return (
            b"\x00"  # Type TBD placeholder
            + DIO_TIME_OPTION_LEN.to_bytes(1, "big")
            + self.stratum.to_bytes(1, "big")
            + self.reserved.to_bytes(1, "big")
            + self.timestamp.to_bytes(4, "big")
        )

    @classmethod
    def decode(cls, data: bytes) -> DioTimeOption:
        if len(data) != DIO_TIME_OPTION_TOTAL:
            raise ValueError("DIO Time Option must be 8 bytes")
        # data[0]=Type, data[1]=Length
        stratum = Stratum(data[2])
        reserved = data[3]
        timestamp = int.from_bytes(data[4:8], "big")
        return cls(stratum=stratum, timestamp=timestamp, reserved=reserved)


def effective_epoch_floor(firmware_build_epoch: int, board_provision_epoch: int | None) -> int:
    """Return effective epoch floor = max(firmware, board) per spec."""
    if board_provision_epoch is None:
        return firmware_build_epoch
    return max(firmware_build_epoch, board_provision_epoch)


def can_establish_wall_clock(source_class: str, timestamp: int, epoch_floor: int) -> bool:
    """Return True iff source can establish wall clock per spec."""
    if timestamp < epoch_floor:
        return False
    return SOURCE_CAN_ESTABLISH_WALL_CLOCK.get(source_class, False)


def should_adopt_time(
    local_stratum: Stratum,
    received_stratum: Stratum,
    received_timestamp: int,
    epoch_floor: int,
) -> bool:
    """Return True iff node should adopt DIO time.

    Rules: higher stratum MAY be adopted; lower stratum MUST NOT; timestamp
    below floor MUST be rejected.
    """
    if received_timestamp < epoch_floor:
        return False
    return received_stratum > local_stratum


__all__ = [
    "DIO_TIME_OPTION_LEN",
    "DIO_TIME_OPTION_TOTAL",
    "SOURCE_CAN_ESTABLISH_WALL_CLOCK",
    "SOURCE_CLASSES",
    "STRATUM_SOURCE_CLASS",
    "DioTimeOption",
    "Stratum",
    "can_establish_wall_clock",
    "effective_epoch_floor",
    "should_adopt_time",
]
