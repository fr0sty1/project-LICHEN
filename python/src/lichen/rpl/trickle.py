# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable

"""Trickle timer (RFC 6206), used by RPL to pace DIO transmissions.

The timer is a deterministic state machine driven by an explicit clock (all
times are integer milliseconds) rather than being bound to the asyncio wall
clock. This keeps it testable and lets the simulator drive it in logical time.
An async :meth:`TrickleTimer.run` loop is provided for production use with an
injectable clock and sleep.

Note on parameters: RFC 6206 defines ``Imax`` as the maximum number of
*doublings* of ``Imin`` (max interval = ``Imin * 2**Imax``). Spec appendix B.3
lists ``Imax = 20`` alongside "2**20 ms", which reads ``Imax`` as an absolute
exponent instead. We follow the RFC: pass ``imax_doublings``. To get the spec's
intended ~17 min ceiling from ``Imin = 4096`` ms (2**12), use
``imax_doublings = 8`` (2**12 * 2**8 = 2**20 ms).
"""

# rng() returns a float in [0, 1); now_fn() returns a time in milliseconds.
RngFn = Callable[[], float]
NowFn = Callable[[], int]


class TrickleTimer:
    """RFC 6206 Trickle timer with an injectable clock and RNG."""

    def __init__(
        self,
        imin_ms: int,
        imax_doublings: int,
        k: int,
        *,
        rng: RngFn | None = None,
    ) -> None:
        if imin_ms <= 0:
            raise ValueError("imin_ms must be positive")
        if imax_doublings < 0:
            raise ValueError("imax_doublings must be non-negative")
        self.imin = imin_ms
        self.imax_doublings = imax_doublings
        self.max_interval = imin_ms << imax_doublings
        self.k = k
        self._rng: RngFn = rng if rng is not None else random.random

        self.interval = imin_ms
        self.counter = 0
        self.interval_start = 0
        self.transmit_time = 0
        self._transmitted = False
        self._generation = 0  # Incremented on each interval start to detect resets

    def start(self, now: int = 0) -> None:
        """Begin the first interval at ``now`` (RFC 6206 step 1-2)."""
        self.interval = self.imin
        self._begin_interval(now)

    def _begin_interval(self, now: int) -> None:
        # RFC 6206 step 2: reset c, pick transmit time t uniformly in [I/2, I).
        self.interval_start = now
        self.counter = 0
        self._transmitted = False
        self._generation += 1
        half = (self.interval + 1) // 2
        self.transmit_time = now + half + int(self._rng() * (self.interval - half))

    @property
    def interval_end(self) -> int:
        """Absolute time at which the current interval ends."""
        return self.interval_start + self.interval

    def heard_consistent(self) -> None:
        """Record a consistent transmission (RFC 6206 step 3)."""
        self.counter += 1

    def should_transmit(self) -> bool:
        """Whether a transmission is due at ``t`` (c < k, RFC 6206 step 4)."""
        return self.counter < self.k

    def fire_transmit(self) -> bool:
        """Mark the transmit instant reached; return whether to transmit."""
        self._transmitted = True
        return self.should_transmit()

    def expire(self, now: int) -> None:
        """End the interval: double (capped) and start a new one (step 5)."""
        self.interval = min(self.interval * 2, self.max_interval)
        self._begin_interval(now)

    def reset(self, now: int) -> None:
        if self._generation == 0 or self.interval != self.imin:
            self.interval = self.imin
            self._begin_interval(now)

    def next_event(self) -> tuple[str, int]:
        """The next scheduled event: ``("transmit", t)`` or ``("expire", end)``."""
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
        completed = 0
        while max_intervals is None or completed < max_intervals:
            gen = self._generation
            await sleep(max(0, self.transmit_time - now_fn()))
            if self._generation != gen:
                # reset() was called during sleep; restart with the new interval
                continue
            if self.fire_transmit():
                await transmit()
                if self._generation != gen:
                    # reset() was called during transmit; restart with the new interval
                    continue
            await sleep(max(0, self.interval_end - now_fn()))
            if self._generation != gen:
                # reset() was called during sleep; restart with the new interval
                continue
            self.expire(now_fn())
            completed += 1
