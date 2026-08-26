# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""`/status` time object (spec 11).

When wall_clock_valid is false, unix_time is omitted.
"""

from __future__ import annotations

from typing import Any

import cbor2

from lichen.timing.wall_clock import TimeSourceClass, WallClockValidity


def status_time_object(
    clock: WallClockValidity,
    *,
    unix_time: int | None,
    source_name: str | None = None,
    age_s: int = 0,
    stratum: int = 0,
) -> dict[str, Any]:
    """Build the spec 11 `time` map for a status payload."""
    if type(clock) is not WallClockValidity:
        raise TypeError("clock must be WallClockValidity")
    if type(age_s) is not int or age_s < 0:
        raise ValueError("age_s must be a non-negative int")
    if type(stratum) is not int or not 0 <= stratum <= 4:
        raise ValueError("stratum must be 0..4")
    source = clock.source if clock.source is not None else TimeSourceClass.MONOTONIC
    payload: dict[str, Any] = {
        "wall_clock_valid": clock.is_valid,
        "source_class": source.value,
        "age_s": age_s,
        "stratum": stratum,
    }
    if source_name is not None:
        if type(source_name) is not str:
            raise TypeError("source_name must be str")
        payload["source_name"] = source_name
    if clock.is_valid:
        if type(unix_time) is not int:
            raise TypeError("unix_time must be int when wall clock is valid")
        payload["unix_time"] = unix_time
    return payload


def to_cbor(payload: dict[str, Any]) -> bytes:
    return cbor2.dumps(payload)


def from_cbor(raw: bytes) -> dict[str, Any]:
    decoded = cbor2.loads(raw)
    if type(decoded) is not dict:
        raise ValueError("status time CBOR must be a map")
    return decoded
