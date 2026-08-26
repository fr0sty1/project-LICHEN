# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SenML time fields when the firmware wall clock may be invalid.

Spec appendix F.12: senders SHOULD include ``bt`` only when
``wall_clock_valid`` is true. Constrained nodes fall back to relative ``t``.
"""

from __future__ import annotations

from lichen.senml.codec import SenmlRecord
from lichen.timing.time_fallback import MonotonicFallback, consumer_timestamp
from lichen.timing.wall_clock import WallClockValidity


def stamp_record(
    record: SenmlRecord,
    clock: WallClockValidity,
    *,
    unix: int,
    uptime_s: int,
    relative_s: int | float = 0,
) -> SenmlRecord:
    """Attach SenML time fields without inventing Unix time.

    When the wall clock is valid, ``bt`` is the Unix seconds and ``t`` is the
    offset from that base. When invalid, ``bt`` is omitted and ``t`` is the
    relative/monotonic offset so receivers do not treat it as Unix time.
    """
    if type(record) is not SenmlRecord:
        raise TypeError("record must be SenmlRecord")
    stamp = consumer_timestamp(clock, unix, uptime_s)
    if type(stamp) is MonotonicFallback:
        record.bt = None
        record.t = relative_s
        return record
    record.bt = stamp.unix
    record.t = relative_s
    return record
