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

    def __post_init__(self) -> None:
        """Reject state that cannot be produced by the CSMA/CA machine."""
        if type(self.backoff_exp) is not int:
            raise TypeError("backoff_exp must be an exact integer")
        if not 0 <= self.backoff_exp <= CSMA_BACKOFF_MAX:
            raise ValueError(f"backoff_exp must be in [0,{CSMA_BACKOFF_MAX}]")
        if type(self.retries) is not int:
            raise TypeError("retries must be an exact integer")
        if not 0 <= self.retries <= CSMA_RETRY_LIMIT + 1:
            raise ValueError(f"retries must be in [0,{CSMA_RETRY_LIMIT + 1}]")

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
        # Retry exhaustion is terminal until a successful transmission resets
        # the machine.  Keeping this transition idempotent prevents repeated
        # busy indications from growing an unbounded counter.
        if self.retries > CSMA_RETRY_LIMIT:
            return CsmaResult.RETRY_EXHAUSTED

        self.retries += 1
        if self.retries > CSMA_RETRY_LIMIT:
            return CsmaResult.RETRY_EXHAUSTED
        self.backoff_exp = min(self.backoff_exp + 1, CSMA_BACKOFF_MAX)
        return CsmaResult.CAD_BUSY

    def on_cad_clear(self) -> CsmaResult:
        """Record a clear CAD result and reset contention after transmission."""
        self.backoff_exp = 0
        self.retries = 0
        return CsmaResult.TX_SUCCESS

    def on_cad_result(self, channel_busy: bool) -> CsmaResult:
        """Apply one CAD indication and return the resulting transmit state."""
        if type(channel_busy) is not bool:
            raise TypeError("channel_busy must be a bool")
        if channel_busy:
            return self.on_cad_busy()
        return self.on_cad_clear()

    def on_success(self) -> CsmaResult:
        """Reset after successful TX (compatibility alias for a clear CAD path)."""
        return self.on_cad_clear()


def cw_for_exponent(exp: int) -> int:
    """Return contention window size for exponent (CW = 2^exp -1)."""
    if type(exp) is not int:
        raise TypeError("exp must be an exact integer")
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
