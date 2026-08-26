# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Data-traffic timing (spec 09 section 14.3).

Telemetry is 5-60 minutes. Heartbeat/keepalive is 30 minutes if no data
has been sent. Elapsed time is wrap-safe unsigned 64-bit.
"""

from __future__ import annotations

TELEMETRY_MIN_MS: int = 5 * 60 * 1000
TELEMETRY_MAX_MS: int = 60 * 60 * 1000
HEARTBEAT_MS: int = 30 * 60 * 1000
_U64: int = (1 << 64) - 1


def elapsed(now: int, then: int) -> int:
    """Wrap-safe ``now - then`` on the u64 tick ring."""
    if type(now) is not int or type(then) is not int:
        raise TypeError("ticks must be int")
    if now < 0 or then < 0:
        raise ValueError("ticks must be non-negative")
    return (now - then) & _U64


class TelemetryIntervalError(ValueError):
    """Interval outside 5-60 minutes."""


class TelemetryInterval:
    """Configured telemetry period in ``[5 min, 60 min]``."""

    __slots__ = ("_interval_ms",)

    def __init__(self, interval_ms: int) -> None:
        if type(interval_ms) is not int:
            raise TypeError("interval_ms must be int")
        if interval_ms < TELEMETRY_MIN_MS or interval_ms > TELEMETRY_MAX_MS:
            raise TelemetryIntervalError("telemetry interval must be 5-60 minutes")
        self._interval_ms = interval_ms

    @property
    def interval_ms(self) -> int:
        return self._interval_ms

    def due(self, now_ms: int, last_tx_ms: int | None) -> bool:
        if last_tx_ms is None:
            return True
        return elapsed(now_ms, last_tx_ms) >= self._interval_ms


class Heartbeat:
    """30-minute keepalive if no data has been sent."""

    __slots__ = ("_interval_ms",)

    def __init__(self) -> None:
        self._interval_ms = HEARTBEAT_MS

    def due(self, now_ms: int, last_data_tx_ms: int | None) -> bool:
        if last_data_tx_ms is None:
            return True
        return elapsed(now_ms, last_data_tx_ms) >= self._interval_ms
