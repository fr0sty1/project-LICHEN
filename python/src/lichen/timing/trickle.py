# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Trickle timer oracle (spec 09-packets-timing.md §14.1, RFC 6206).

Re-exports and validates :class:`lichen.rpl.trickle.TrickleTimer` against the
spec constants Imin=4s, Imax=17min (≈1_024_000 ms), k=10.
"""

from __future__ import annotations

from lichen.constants import (
    RPL_TRICKLE_IMAX_DOUBLINGS,
    RPL_TRICKLE_IMAX_MS,
    RPL_TRICKLE_IMIN_MS,
    RPL_TRICKLE_K,
)
from lichen.rpl.trickle import TrickleTimer  # noqa: F401  # re-export for oracle parity

# Spec §14.1 table
TRICKLE_IMIN_MS: int = 4000
TRICKLE_IMAX_DOUBLINGS: int = 8
TRICKLE_IMAX_MS: int = RPL_TRICKLE_IMAX_MS  # exact: 1_024_000 ms = 1024 s
TRICKLE_IMAX_EXACT_MS: int = TRICKLE_IMAX_MS  # compatibility alias
TRICKLE_K: int = 10

# Human-readable rationale per spec
TRICKLE_RATIONALE: dict[str, str] = {
    "Imin": "Allow network stabilization",
    "Imax": "Reduce steady-state overhead",
    "k": "Suppress redundant DIOs",
}


def spec_constants_valid() -> bool:
    """Return True iff runtime constants match spec §14.1."""
    return (
        RPL_TRICKLE_IMIN_MS == TRICKLE_IMIN_MS
        and RPL_TRICKLE_IMAX_DOUBLINGS == TRICKLE_IMAX_DOUBLINGS
        and RPL_TRICKLE_K == TRICKLE_K
        and TRICKLE_IMAX_EXACT_MS == 1_024_000
    )


__all__ = [
    "TRICKLE_IMAX_EXACT_MS",
    "TRICKLE_IMAX_DOUBLINGS",
    "TRICKLE_IMAX_MS",
    "TRICKLE_IMIN_MS",
    "TRICKLE_K",
    "TRICKLE_RATIONALE",
    "TrickleTimer",
    "spec_constants_valid",
]
