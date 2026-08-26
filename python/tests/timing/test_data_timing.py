# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import pytest

from lichen.timing.data_timing import (
    HEARTBEAT_MS,
    TELEMETRY_MAX_MS,
    TELEMETRY_MIN_MS,
    Heartbeat,
    TelemetryInterval,
    TelemetryIntervalError,
    elapsed,
)


def test_telemetry_rejects_out_of_range() -> None:
    with pytest.raises(TelemetryIntervalError):
        TelemetryInterval(TELEMETRY_MIN_MS - 1)
    with pytest.raises(TelemetryIntervalError):
        TelemetryInterval(TELEMETRY_MAX_MS + 1)
    assert TelemetryInterval(TELEMETRY_MIN_MS).interval_ms == TELEMETRY_MIN_MS
    assert TelemetryInterval(TELEMETRY_MAX_MS).interval_ms == TELEMETRY_MAX_MS


def test_telemetry_due_after_interval() -> None:
    period = TelemetryInterval(TELEMETRY_MIN_MS)
    assert period.due(0, None)
    assert not period.due(TELEMETRY_MIN_MS - 1, 0)
    assert period.due(TELEMETRY_MIN_MS, 0)


def test_heartbeat_due_after_30_min() -> None:
    hb = Heartbeat()
    assert hb.due(0, None)
    assert not hb.due(HEARTBEAT_MS - 1, 0)
    assert hb.due(HEARTBEAT_MS, 0)


def test_wrap_safe_elapsed() -> None:
    assert elapsed(5, 1) == 4
    assert elapsed(0, (1 << 64) - 1) == 1
    period = TelemetryInterval(TELEMETRY_MIN_MS)
    assert period.due(TELEMETRY_MIN_MS - 1, (1 << 64) - 1)
