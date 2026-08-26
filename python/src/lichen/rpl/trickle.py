# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import asyncio
import math
import random
from collections.abc import Awaitable, Callable
from ipaddress import IPv6Address

from lichen.constants import (
    RPL_TRICKLE_IMAX_DOUBLINGS,
    RPL_TRICKLE_IMIN_MS,
    RPL_TRICKLE_K,
)

"""Trickle timer (RFC 6206) for RPL DIO pacing per appendix-rpl.md
and constants.toml (imax_doublings=8 for 2^20 ms ceiling). Deterministic
state machine driven by explicit clock (ms). Async run() loop for simulator
and production with injectable clock.
"""

# rng() returns a float in [0, 1); now_fn() returns a time in milliseconds.
RngFn = Callable[[], float]
NowFn = Callable[[], int]
MAX_MONOTONIC_MS = (1 << 64) - 1


class TrickleTimer:
    """RFC 6206 Trickle timer with an injectable clock and RNG."""

    def __init__(
        self,
        imin_ms: int,
        imax_doublings: int,
        k: int,
        *,
        rng: RngFn | None = None,
        dodag_id: IPv6Address | bytes | None = None,
        dodag_version: int | None = None,
    ) -> None:
        if imin_ms <= 0:
            raise ValueError("imin_ms must be positive")
        if imax_doublings < 0:
            raise ValueError("imax_doublings must be non-negative")
        self.imin = imin_ms
        self.imax_doublings = imax_doublings
        if imax_doublings == 0:
            self.max_interval = imin_ms
        elif imax_doublings >= 32 or (imin_ms >> (32 - imax_doublings)) > 0:
            self.max_interval = (1 << 32) - 1
        else:
            self.max_interval = imin_ms << imax_doublings
        self.k = k
        self._rng: RngFn = rng if rng is not None else random.random
        if (dodag_id is None) != (dodag_version is None):
            raise ValueError("dodag_id and dodag_version must be configured together")
        self._dodag_id: bytes | None = None
        self._dodag_version: int | None = None
        if dodag_id is not None and dodag_version is not None:
            self.set_scope(dodag_id, dodag_version)

        self.interval = imin_ms
        self.counter = 0
        self.interval_start = 0
        self.transmit_time = 0
        self._transmitted = False
        self._generation = 0
        self._stopped = True

    @classmethod
    def lichen_profile(
        cls,
        *,
        rng: RngFn | None = None,
        dodag_id: IPv6Address | bytes | None = None,
        dodag_version: int | None = None,
    ) -> TrickleTimer:
        """Construct the exact spec profile: 4 s, eight doublings, k=10."""
        return cls(
            RPL_TRICKLE_IMIN_MS,
            RPL_TRICKLE_IMAX_DOUBLINGS,
            RPL_TRICKLE_K,
            rng=rng,
            dodag_id=dodag_id,
            dodag_version=dodag_version,
        )

    def start(self, now: int) -> None:
        """Begin the first interval at ``now`` (RFC 6206 step 1-2)."""
        self._validate_now(now)
        self.interval = self.imin
        self._begin_interval(now)

    @staticmethod
    def _validate_now(now: int) -> None:
        if type(now) is not int or not 0 <= now <= MAX_MONOTONIC_MS:
            raise ValueError("now must be a u64 monotonic timestamp")

    def _begin_interval(self, now: int) -> None:
        self._validate_now(now)
        if now > MAX_MONOTONIC_MS - self.interval:
            # A wrapping deadline is not a future deadline. Fail closed until
            # the caller supplies a representable clock value (for example,
            # after reboot and timer reconstruction).
            self.interval_start = now
            self.counter = 0
            self._transmitted = False
            self._generation += 1
            self.transmit_time = now
            self._stopped = True
            return
        half = (self.interval + 1) // 2
        range_size = self.interval - half
        sample = self._rng()
        if type(sample) not in (int, float) or not math.isfinite(sample) or not 0 <= sample < 1:
            raise ValueError("rng must return a finite value in [0, 1)")
        transmit_time = now + half + int(sample * range_size)
        self.interval_start = now
        self.counter = 0
        self._transmitted = False
        self._generation += 1
        self.transmit_time = transmit_time
        self._stopped = False

    @property
    def interval_end(self) -> int:
        """Absolute time at which the current interval ends."""
        return min(self.interval_start + self.interval, MAX_MONOTONIC_MS)

    @property
    def stopped(self) -> bool:
        """Whether no future event fits in the u64 monotonic clock domain."""
        return self._stopped

    def set_scope(self, dodag_id: IPv6Address | bytes, dodag_version: int) -> None:
        """Bind consistency observations to one DODAG and version.

        Scope changes never reset the interval implicitly; after an authorized
        version transition the caller invokes :meth:`reset` separately.
        """
        packed = dodag_id.packed if isinstance(dodag_id, IPv6Address) else bytes(dodag_id)
        if len(packed) != 16:
            raise ValueError("dodag_id must encode exactly 16 bytes")
        if type(dodag_version) is not int or not 0 <= dodag_version <= 0xFF:
            raise ValueError("dodag_version must be a u8")
        self._dodag_id = packed
        self._dodag_version = dodag_version

    def heard_consistent(
        self,
        dodag_id: IPv6Address | bytes | None = None,
        dodag_version: int | None = None,
    ) -> bool:
        """Record a matching transmission in the active interval.

        Counter uses saturating increment to match Rust/C behavior and
        prevent wraparound from causing spurious transmits. Scoped timers
        require the observed DODAG ID and version to match exactly. Rejected
        observations do not mutate the interval and never trigger reset.
        """
        if self._stopped:
            return False
        if self._dodag_id is not None:
            if dodag_id is None or dodag_version is None:
                return False
            packed = dodag_id.packed if isinstance(dodag_id, IPv6Address) else bytes(dodag_id)
            if packed != self._dodag_id or dodag_version != self._dodag_version:
                return False
        elif dodag_id is not None or dodag_version is not None:
            return False
        if self.counter < (1 << 32) - 1:
            self.counter += 1
        return True

    def should_transmit(self) -> bool:
        """Whether a transmission is due at ``t`` (c < k, RFC 6206 step 4)."""
        return not self._stopped and self.counter < self.k

    def fire_transmit(self) -> bool:
        """Mark the transmit instant reached; return whether to transmit."""
        self._transmitted = True
        return self.should_transmit()

    def expire(self, now: int) -> None:
        """End the interval: double (capped) and start a new one (step 5)."""
        self._validate_now(now)
        self.interval = min(self.interval * 2, self.max_interval)
        self._begin_interval(now)

    def reset(self, now: int) -> None:
        """Handle inconsistency by setting I=Imin and restarting the interval.

        Every accepted inconsistency is a fresh scheduling event, including at
        Imin: ``c`` is cleared and a new transmit point is sampled. This keeps
        repeated topology changes observable to the timer driver.
        ``now`` must be current time (no default) to keep transmit_time
        in the future; see _lowest_rank tracking analogue in dodag.py.
        """
        self._validate_now(now)
        self.interval = self.imin
        self._begin_interval(now)

    def next_event(self) -> tuple[str, int]:
        """Return the next transmit, expiry, or terminal stopped event."""
        if self._stopped:
            return ("stopped", self.interval_start)
        if not self._transmitted:
            return ("transmit", self.transmit_time)
        return ("expire", self.interval_end)

    async def run(
        self,
        transmit: Callable[[], Awaitable[None]],
        *,
        now_fn: NowFn,
        sleep_fn: Callable[[float], Awaitable[None]] | None = None,
        max_intervals: int | None = None,
    ) -> None:
        """Drive the Trickle loop, awaiting ``transmit()`` when a DIO is due.

        ``sleep_fn`` takes a duration in milliseconds (defaults to
        :func:`asyncio.sleep` converted from ms). ``max_intervals`` bounds the
        loop for testing; ``None`` runs indefinitely.
        """
        sleep = sleep_fn if sleep_fn is not None else (lambda ms: asyncio.sleep(ms / 1000))
        self.start(now_fn())
        if self._stopped:
            return
        completed = 0
        while max_intervals is None or completed < max_intervals:
            gen = self._generation
            await sleep(max(0, self.transmit_time - now_fn()))
            if self._generation != gen:
                # reset() was called during sleep; restart with the new interval
                if self._stopped:
                    return
                continue
            if self.fire_transmit():
                await transmit()
                if self._generation != gen:
                    # reset() was called during transmit; restart with the new interval
                    if self._stopped:
                        return
                    continue
            await sleep(max(0, self.interval_end - now_fn()))
            if self._generation != gen:
                # reset() was called during sleep; restart with the new interval
                if self._stopped:
                    return
                continue
            self.expire(now_fn())
            completed += 1
