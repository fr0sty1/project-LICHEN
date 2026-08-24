# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Canonical TDMA simulator scheduling boundaries."""

import json
from pathlib import Path

import pytest

from lichen.sim.tdma import TDMAScheduler, TDMAState
from lichen.timing.sfn import TDMA_GUARD_MS, TDMA_SLOT_MS, slot_for

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def test_simulator_uses_canonical_slot_hash_and_defaults() -> None:
    scheduler = TDMAScheduler()
    eui64 = bytes.fromhex("0011223344556677")
    assert scheduler.slot_duration_ms == TDMA_SLOT_MS == 2346
    assert scheduler.guard_ms == TDMA_GUARD_MS == 50
    for sfn in (0, 1, 0xFFFFFFFF, 0x100000000):
        assert scheduler.hash_slot(eui64, 16, sfn) == slot_for(eui64, sfn, 16)


def test_implicit_beacon_assignment_rotates_with_sfn() -> None:
    scheduler = TDMAScheduler()
    scheduler.eui64 = bytes.fromhex("0011223344556677")
    scheduler.num_slots = 16

    scheduler.sync_from_beacon(1, 1)

    assert scheduler.assigned_slot == slot_for(scheduler.eui64, 1, 16)


@pytest.mark.parametrize(
    ("rx_time_us", "sfn", "assigned"),
    [
        (True, 1, 0),
        (-1, 1, 0),
        (1, True, 0),
        (1, -1, 0),
        (1, 0x100000000, 0),
        (1, 1, True),
        (1, 1, -2),
        (1, 1, 8),
    ],
)
def test_invalid_beacon_assignment_is_failure_atomic(
    rx_time_us: object,
    sfn: object,
    assigned: object,
) -> None:
    scheduler = TDMAScheduler()
    scheduler.state = TDMAState.DRIFTING
    scheduler.assigned_slot = 3
    scheduler.clock.sfn = 7
    scheduler.clock.base_time_us = 9
    scheduler.clock.last_sync_us = 11

    with pytest.raises(ValueError):
        scheduler.sync_from_beacon(  # type: ignore[arg-type]
            rx_time_us,
            sfn,
            assigned,
        )

    assert scheduler.state is TDMAState.DRIFTING
    assert scheduler.assigned_slot == 3
    assert scheduler.clock.sfn == 7
    assert scheduler.clock.base_time_us == 9
    assert scheduler.clock.last_sync_us == 11


@pytest.mark.parametrize("num_slots", [True, False, 0, -1, 1.5])
def test_invalid_slot_count_rejects_beacon_without_state_mutation(num_slots: object) -> None:
    scheduler = TDMAScheduler()
    scheduler.state = TDMAState.DRIFTING
    scheduler.num_slots = num_slots  # type: ignore[assignment]

    with pytest.raises(ValueError, match="num_slots"):
        scheduler.sync_from_beacon(1, 1)

    assert scheduler.state is TDMAState.DRIFTING
    assert scheduler.clock.sfn == 0
    assert scheduler.clock.last_sync_us == 0


def test_transmit_window_excludes_trailing_guard_and_neighbors() -> None:
    scheduler = TDMAScheduler()
    scheduler.num_slots = 2
    beacon_time_us = 123_456_789
    scheduler.sync_from_beacon(beacon_time_us, 0xFFFF_FFFE, assigned=1)
    slot_start_us = beacon_time_us + TDMA_SLOT_MS * 1000
    guard_start_us = slot_start_us + (TDMA_SLOT_MS - TDMA_GUARD_MS) * 1000
    slot_end_us = slot_start_us + TDMA_SLOT_MS * 1000

    assert not scheduler.is_tx_allowed(slot_start_us - 1)
    assert scheduler.is_tx_allowed(slot_start_us)
    assert scheduler.is_tx_allowed(guard_start_us - 1)
    assert not scheduler.is_tx_allowed(guard_start_us)
    assert not scheduler.is_tx_allowed(slot_end_us - 1)
    assert not scheduler.is_tx_allowed(slot_end_us)


@pytest.mark.parametrize("current_time_us", [-1, True, 1.5, "1", None])
def test_transmit_window_rejects_invalid_clock_values(current_time_us: object) -> None:
    scheduler = TDMAScheduler()
    with pytest.raises(ValueError, match="current_time_us"):
        scheduler.is_tx_allowed(current_time_us)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("slot_duration_ms", "guard_ms"),
    [(0, 0), (-1, 0), (True, 0), (100, -1), (100, 100), (100, 101), (100, True)],
)
def test_invalid_timing_configuration_rejects_sync_without_mutation(
    slot_duration_ms: object,
    guard_ms: object,
) -> None:
    scheduler = TDMAScheduler()
    scheduler.state = TDMAState.DRIFTING
    scheduler.slot_duration_ms = slot_duration_ms  # type: ignore[assignment]
    scheduler.guard_ms = guard_ms  # type: ignore[assignment]

    with pytest.raises(ValueError):
        scheduler.sync_from_beacon(123, 4, assigned=0)

    assert scheduler.state is TDMAState.DRIFTING
    assert scheduler.clock.sfn == 0
    assert scheduler.clock.base_time_us == 0
    assert scheduler.clock.last_sync_us == 0


def test_load_balancing_vectors_pin_canonical_tdma_values() -> None:
    document = json.loads((VECTORS_DIR / "ccp_load_balancing.json").read_text())
    vectors = {vector["name"]: vector for vector in document["vectors"]}
    slot = vectors["tdma_slot_assignment_static_hash"]
    assert slot["sfn"] == 0
    assert slot["expected_slot"] == 13
    assert slot_for(
        bytes.fromhex(slot["eui64_hex"]),
        slot["sfn"],
        slot["num_slots"],
    ) == slot["expected_slot"]

    guard = vectors["guard_time_boundary_sf10"]
    assert guard["slot_ms"] == TDMA_SLOT_MS == 2346
    assert guard["guard_ms"] == TDMA_GUARD_MS == 50
    maximum_drift_ms = guard["superframe_ms"] * guard["drift_ppm"] / 1_000_000
    assert maximum_drift_ms < guard["guard_ms"]


@pytest.mark.parametrize(
    "vector",
    [
        {},
        {"unknown": 1},
        {"eui64_hex": "0000000000000001", "sfn": 0, "n_slots": 8},
        {"expected_channel": 1, "sfn": 0, "seed": 0},
        {
            "slot_start_ms": 0,
            "current_ms": 0,
            "slot_duration_ms": TDMA_SLOT_MS,
            "guard_ms": TDMA_GUARD_MS,
            "expected_in_guard": False,
        },
        {"local_beacon_rx_ms": 1, "expected_beacon_ms": 1},
    ],
)
def test_vector_validation_fails_closed_without_complete_oracle(vector: dict[str, object]) -> None:
    assert not TDMAScheduler().validate_vector(vector)
