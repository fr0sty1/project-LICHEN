# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Data traffic timing guidelines (spec 09-packets-timing.md §14.3)."""

from __future__ import annotations

TELEMETRY_INTERVAL_MIN_S: int = 5 * 60  # 5 minutes
TELEMETRY_INTERVAL_MAX_S: int = 60 * 60  # 60 minutes
HEARTBEAT_INTERVAL_S: int = 30 * 60  # 30 minutes keepalive

RECOMMENDED_INTERVALS: dict[str, str] = {
    "periodic_telemetry": "5-60 minutes",
    "event_driven": "As needed",
    "heartbeat_keepalive": "30 minutes",
}


def is_valid_telemetry_interval(seconds: int) -> bool:
    """Return True iff telemetry interval is within 5-60 minutes."""
    return TELEMETRY_INTERVAL_MIN_S <= seconds <= TELEMETRY_INTERVAL_MAX_S


def is_valid_heartbeat_interval(seconds: int) -> bool:
    """Return True iff heartbeat interval equals 30 minutes (±0)."""
    return seconds == HEARTBEAT_INTERVAL_S


__all__ = [
    "HEARTBEAT_INTERVAL_S",
    "RECOMMENDED_INTERVALS",
    "TELEMETRY_INTERVAL_MAX_S",
    "TELEMETRY_INTERVAL_MIN_S",
    "is_valid_heartbeat_interval",
    "is_valid_telemetry_interval",
]
