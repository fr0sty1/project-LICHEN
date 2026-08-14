# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa PHY parameter validation (spec 02-physical-link.md §3.2).

Recommended defaults: SF10, BW 125 kHz, CR 4/5, Preamble 8, Sync 0x34, CRC enabled.
This oracle validates combinations and exposes the normative defaults used by
OperatingClass (CCP-3/CCP-4) and constants.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from lichen.constants import (
    LORA_BANDWIDTH_HZ,
    LORA_PREAMBLE_SYMBOLS,
    LORA_SPREADING_FACTOR,
    LORA_SYNC_WORD,
)

VALID_SF = range(7, 13)  # 7..12 inclusive
VALID_BW_HZ = (125_000, 250_000, 500_000)
VALID_CR_NUM = (5, 6, 7, 8)  # denominator of 4/N

DEFAULT_PHY_PARAMS = {
    "sf": LORA_SPREADING_FACTOR,
    "bw_hz": LORA_BANDWIDTH_HZ,
    "cr": 5,
    "preamble_symbols": LORA_PREAMBLE_SYMBOLS,
    "sync_word": LORA_SYNC_WORD,
    "crc_enabled": True,
}


@dataclass(frozen=True)
class PhyParams:
    sf: int = LORA_SPREADING_FACTOR
    bw_hz: int = LORA_BANDWIDTH_HZ
    cr: int = 5
    preamble_symbols: int = LORA_PREAMBLE_SYMBOLS
    sync_word: int = LORA_SYNC_WORD
    crc_enabled: bool = True
    freq_hz: int | None = None
    tx_power_dbm: int | None = None

    def validate(self) -> None:
        if self.sf not in VALID_SF:
            raise ValueError(f"sf {self.sf} out of range 7..12")
        if self.bw_hz not in VALID_BW_HZ:
            raise ValueError(f"bw_hz {self.bw_hz} not in {VALID_BW_HZ}")
        if self.cr not in VALID_CR_NUM:
            raise ValueError(f"cr 4/{self.cr} not in 4/5..4/8")
        if not 6 <= self.preamble_symbols <= 65535:
            raise ValueError(f"preamble_symbols {self.preamble_symbols} out of range")
        if not 0 <= self.sync_word <= 0xFF:
            raise ValueError(f"sync_word {self.sync_word:#x} out of range")
        if self.freq_hz is not None and not 100_000_000 <= self.freq_hz <= 1_000_000_000:
            raise ValueError(f"freq_hz {self.freq_hz} out of range")
        if self.tx_power_dbm is not None and not -10 <= self.tx_power_dbm <= 30:
            raise ValueError(f"tx_power_dbm {self.tx_power_dbm} out of range")


def is_valid_phy_combination(sf: int, bw_hz: int, cr: int) -> bool:
    try:
        PhyParams(sf=sf, bw_hz=bw_hz, cr=cr).validate()
        return True
    except ValueError:
        return False


__all__ = [
    "DEFAULT_PHY_PARAMS",
    "PhyParams",
    "VALID_BW_HZ",
    "VALID_CR_NUM",
    "VALID_SF",
    "is_valid_phy_combination",
]
