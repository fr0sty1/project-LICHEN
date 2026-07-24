# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Operating class parameter definitions and lookup tables (CCP-3/CCP-4).

Each operating class maps to a set of radio parameters (frequency, SF, BW, CR,
power) and regulatory rules (duty cycle region). Provisioned at compile time;
over-the-air messages MUST NOT expand the local plan per
spec/02a-coordinated-capacity.md section CCP-4.
"""

from __future__ import annotations

import enum
from typing import ClassVar


class OperatingClass(enum.IntEnum):
    """Operating class identifiers for regional channel plans."""

    US_CA = 0  #: 903.9 MHz CH0, 1 W max, no duty cycle limit
    EU = 1  #: 868.1 MHz CH0, 14 dBm typical, 1 % duty cycle
    AU_NZ = 2  #: 916.8 MHz CH0, 30 dBm max, <5 % duty cycle


REGION_NAMES: dict[OperatingClass, str] = {
    OperatingClass.US_CA: "US/CA",
    OperatingClass.EU: "EU",
    OperatingClass.AU_NZ: "AU/NZ",
}


class OperatingClassParams:
    """Radio parameters associated with a single operating class.

    Fields match the C struct lichen_op_class_params and the Rust
    OperatingClassParams struct.
    """

    def __init__(
        self,
        class_id: int,
        label: str,
        frequency_hz: int,
        spreading_factor: int,
        bandwidth_hz: int,
        coding_rate: int,
        tx_power_dbm: int,
        duty_region: int,
        duty_permille: int,
    ) -> None:
        self.class_id = class_id
        self.label = label
        self.frequency_hz = frequency_hz
        self.spreading_factor = spreading_factor
        self.bandwidth_hz = bandwidth_hz
        self.coding_rate = coding_rate
        self.tx_power_dbm = tx_power_dbm
        self.duty_region = duty_region
        self.duty_permille = duty_permille

    def __repr__(self) -> str:
        return (
            f"OperatingClassParams(class_id={self.class_id}, label={self.label!r}, "
            f"freq={self.frequency_hz} Hz, SF={self.spreading_factor}, "
            f"BW={self.bandwidth_hz} Hz, CR=4/{self.coding_rate}, "
            f"tx_power={self.tx_power_dbm} dBm, "
            f"duty={self.duty_permille}/1000)"
        )


OPERATING_CLASS_TABLE: ClassVar[dict[int, OperatingClassParams]] = {
    OperatingClass.US_CA: OperatingClassParams(
        class_id=0,
        label="US/CA",
        frequency_hz=903_900_000,
        spreading_factor=10,
        bandwidth_hz=125_000,
        coding_rate=5,
        tx_power_dbm=20,
        duty_region=1,
        duty_permille=1000,
    ),
    OperatingClass.EU: OperatingClassParams(
        class_id=1,
        label="EU",
        frequency_hz=868_100_000,
        spreading_factor=10,
        bandwidth_hz=125_000,
        coding_rate=5,
        tx_power_dbm=14,
        duty_region=0,
        duty_permille=10,
    ),
    OperatingClass.AU_NZ: OperatingClassParams(
        class_id=2,
        label="AU/NZ",
        frequency_hz=916_800_000,
        spreading_factor=10,
        bandwidth_hz=125_000,
        coding_rate=5,
        tx_power_dbm=30,
        duty_region=0,
        duty_permille=50,
    ),
}


def lookup_operating_class(class_id: int) -> OperatingClassParams | None:
    """Look up operating class by integer class_id. Returns None if not found."""
    return OPERATING_CLASS_TABLE.get(class_id)
