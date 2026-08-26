# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Raw-diagnostic arming TTL (spec/11-lci.md section 17.5.4).

Raw diagnostics are a sensitive capability that MUST be disabled by
default and, when armed, only stay armed for a finite lifetime with
auto-disable:

* default/maximum TTL is 300 s; requests above the max are clamped
* ``ttl_s`` is REQUIRED when enabling (missing or negative -> ``4.00``)
* ``ttl_s == 0`` disables immediately; an explicit ``enabled=false``
  disables regardless of remaining time
* ``remaining_s`` counts down and hits zero exactly at expiry
* re-arming resets the countdown

Conformed against ``test/vectors/raw_diag_ttl.json``.
"""

from __future__ import annotations

import time
from collections.abc import Callable

MAX_TTL_S = 300

CODE_CHANGED = "2.04 Changed"
CODE_BAD_REQUEST = "4.00 Bad Request"


class RawDiagTTL:
    """Arming lifetime state for raw diagnostics."""

    def __init__(
        self,
        *,
        max_ttl_s: int = MAX_TTL_S,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_ttl_s < 1:
            raise ValueError("max_ttl_s must be >= 1")
        self._max_ttl_s = max_ttl_s
        self._clock = clock or time.monotonic
        self._expires_at: float | None = None

    @property
    def max_ttl_s(self) -> int:
        return self._max_ttl_s

    @property
    def enabled(self) -> bool:
        if self._expires_at is None:
            return False
        return self._clock() < self._expires_at

    def remaining_s(self) -> int:
        """Whole seconds of armed life left; 0 when disabled/expired."""
        if self._expires_at is None:
            return 0
        return max(0, int(round(self._expires_at - self._clock())))

    def arm(
        self,
        *,
        enabled: bool,
        ttl_s: int | None = None,
    ) -> tuple[bool, str]:
        """Process an arm/disarm request.

        Returns ``(accepted, response_code)``. On acceptance the new
        state (including clamping) is already applied.
        """
        if not enabled:
            self._expires_at = None
            return (True, CODE_CHANGED)

        if ttl_s is None:
            return (False, CODE_BAD_REQUEST)
        if isinstance(ttl_s, bool) or ttl_s < 0:
            return (False, CODE_BAD_REQUEST)

        if ttl_s == 0:
            self._expires_at = None
            return (True, CODE_CHANGED)

        accepted = min(ttl_s, self._max_ttl_s)
        self._expires_at = self._clock() + accepted
        return (True, CODE_CHANGED)

    def disarm(self) -> None:
        """Disable immediately regardless of remaining time."""
        self._expires_at = None
