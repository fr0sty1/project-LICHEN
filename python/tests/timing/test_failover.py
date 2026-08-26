# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

from lichen.timing.failover import select_wall_clock_source
from lichen.timing.wall_clock import TimeSourceClass


def test_falls_back_when_gnss_missing() -> None:
    assert (
        select_wall_clock_source([TimeSourceClass.NETWORK, TimeSourceClass.MONOTONIC])
        is TimeSourceClass.NETWORK
    )
    assert select_wall_clock_source([TimeSourceClass.MONOTONIC]) is None
    assert (
        select_wall_clock_source([TimeSourceClass.MANUAL, TimeSourceClass.GNSS])
        is TimeSourceClass.GNSS
    )
