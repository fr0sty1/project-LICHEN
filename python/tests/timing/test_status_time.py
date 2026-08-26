# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

from lichen.timing.status_time import from_cbor, status_time_object, to_cbor
from lichen.timing.wall_clock import TimeSourceClass, WallClockValidity


def test_valid_clock_includes_unix_time() -> None:
    clock = WallClockValidity()
    clock.establish(TimeSourceClass.GNSS)
    payload = status_time_object(
        clock, unix_time=1_716_742_800, source_name="onboard-gnss", age_s=120, stratum=4
    )
    assert payload["wall_clock_valid"] is True
    assert payload["unix_time"] == 1_716_742_800
    assert payload["source_class"] == "GNSS"
    assert payload["stratum"] == 4
    decoded = from_cbor(to_cbor(payload))
    assert decoded["unix_time"] == 1_716_742_800


def test_invalid_clock_omits_unix_time() -> None:
    payload = status_time_object(WallClockValidity(), unix_time=1_716_742_800, age_s=0, stratum=0)
    assert payload["wall_clock_valid"] is False
    assert "unix_time" not in payload
    assert payload["source_class"] == "Monotonic"
    decoded = from_cbor(to_cbor(payload))
    assert "unix_time" not in decoded
