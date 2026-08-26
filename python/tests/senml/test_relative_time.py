# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

from lichen.senml.codec import SenmlRecord
from lichen.senml.relative_time import stamp_record
from lichen.timing.wall_clock import TimeSourceClass, WallClockValidity


def test_valid_clock_sets_unix_base_time() -> None:
    clock = WallClockValidity()
    clock.establish(TimeSourceClass.GNSS)
    record = stamp_record(
        SenmlRecord(n="temp", u="Cel", v=23.5),
        clock,
        unix=1_716_742_800,
        uptime_s=10,
        relative_s=60,
    )
    assert record.bt == 1_716_742_800
    assert record.t == 60


def test_invalid_clock_omits_bt_and_uses_relative_t() -> None:
    record = stamp_record(
        SenmlRecord(n="temp", u="Cel", v=23.5, bt=1),
        WallClockValidity(),
        unix=1_716_742_800,
        uptime_s=10,
        relative_s=5,
    )
    assert record.bt is None
    assert record.t == 5
