# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DAO timing oracle (spec 09-packets-timing.md §14.2)."""

from __future__ import annotations

# §14.2 DAO Timing table
DAO_INITIAL_DELAY_MIN_MS: int = 0
DAO_INITIAL_DELAY_MAX_MS: int = 2000  # Random 0-2 seconds after joining
DAO_RETRY_DELAYS_MS: tuple[int, ...] = (4000, 8000, 16000)  # exponential backoff
DAO_REFRESH_S: int = 15 * 60  # 15 minutes
DAO_SOFT_STATE_LIFETIME_S: int = 30 * 60  # 30 minutes (refresh = lifetime / 2)
DAO_SEQUENCE_MAX: int = 0xFFFFFFFFFFFFFFFF
DAO_SEQUENCE_START_MIN: int = 1  # starts above zero, must not wrap


def dao_retry_delay(attempt: int) -> int | None:
    """Return retry delay for ``attempt`` (0-indexed: 0->4s,1->8s,2->16s)."""
    if attempt < 0:
        raise ValueError("attempt must be non-negative")
    if attempt < len(DAO_RETRY_DELAYS_MS):
        return DAO_RETRY_DELAYS_MS[attempt]
    return None  # exhausted


def dao_retry_exhausted(attempts: int) -> bool:
    """True if retry attempts exceed ``DAO_RETRY_DELAYS_MS`` length."""
    return attempts >= len(DAO_RETRY_DELAYS_MS)


def is_valid_dao_sequence(seq: int, prev_max: int | None = None) -> bool:
    """Validate DAO Origin Sequence per spec persistence rules."""
    if not 0 <= seq <= DAO_SEQUENCE_MAX:
        return False
    if seq == 0:
        return False  # must start above zero
    if prev_max is not None and seq <= prev_max:
        return False  # must advance
    return seq != DAO_SEQUENCE_MAX


__all__ = [
    "DAO_INITIAL_DELAY_MAX_MS",
    "DAO_INITIAL_DELAY_MIN_MS",
    "DAO_REFRESH_S",
    "DAO_RETRY_DELAYS_MS",
    "DAO_SEQUENCE_MAX",
    "DAO_SEQUENCE_START_MIN",
    "DAO_SOFT_STATE_LIFETIME_S",
    "dao_retry_delay",
    "dao_retry_exhausted",
    "is_valid_dao_sequence",
]
