# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CSMA/CA oracle (spec 09-packets-timing.md §14.5)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# §14.5 table
CSMA_CAD_TIMEOUT_SYMBOLS: int = 3
CSMA_BACKOFF_UNIT_MS: int = 10
CSMA_BACKOFF_MAX: int = 5  # CW = 2^backoff - 1, max 31 slots
CSMA_RETRY_LIMIT: int = 3


class CsmaResult(Enum):
    """Result of a CSMA/CA attempt."""

    TX_SUCCESS = "tx_success"
    CAD_BUSY = "cad_busy"
    RETRY_EXHAUSTED = "retry_exhausted"


@dataclass
class CsmaState:
    """CAD-based backoff state machine."""

    backoff_exp: int = 0  # current backoff exponent 0..CSMA_BACKOFF_MAX
    retries: int = 0

    def next_backoff_slots(self, rng_value: float) -> int:
        """Return random slots in [0, 2^exp -1] given rng in [0,1)."""
        if not 0 <= rng_value < 1:
            raise ValueError("rng_value must be in [0,1)")
        cw = (1 << self.backoff_exp) - 1 if self.backoff_exp > 0 else 0
        if cw == 0:
            return 0
        return int(rng_value * (cw + 1))  # 0..cw inclusive

    def backoff_ms(self, slots: int) -> int:
        """Convert slots to milliseconds."""
        return slots * CSMA_BACKOFF_UNIT_MS

    def on_cad_busy(self) -> CsmaResult:
        """Advance state on CAD busy; return whether to retry."""
        self.retries += 1
        if self.retries > CSMA_RETRY_LIMIT:
            return CsmaResult.RETRY_EXHAUSTED
        self.backoff_exp = min(self.backoff_exp + 1, CSMA_BACKOFF_MAX)
        return CsmaResult.CAD_BUSY

    def on_success(self) -> None:
        """Reset after successful TX."""
        self.backoff_exp = 0
        self.retries = 0


def cw_for_exponent(exp: int) -> int:
    """Return contention window size for exponent (CW = 2^exp -1)."""
    if not 0 <= exp <= CSMA_BACKOFF_MAX:
        raise ValueError("exp out of range")
    return (1 << exp) - 1 if exp > 0 else 0


__all__ = [
    "CSMA_BACKOFF_MAX",
    "CSMA_BACKOFF_UNIT_MS",
    "CSMA_CAD_TIMEOUT_SYMBOLS",
    "CSMA_RETRY_LIMIT",
    "CsmaResult",
    "CsmaState",
    "cw_for_exponent",
]
