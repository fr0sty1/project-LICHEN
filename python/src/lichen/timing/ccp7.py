# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CCP-7 slot-clock formulas (spec 02a-tdma drift, guard, holdover).

Integer arithmetic matches rust/lichen-link/src/tdma_clock.rs. Shared
vectors live in test/vectors/ccp7_holdover.json and ccp_tdma.json.
"""

from __future__ import annotations

GUARD_PPM: int = 5000


def beacon_delta_ms(local_rx_ms: int, expected_beacon_ms: int) -> int:
    if type(local_rx_ms) is not int or type(expected_beacon_ms) is not int:
        raise TypeError("timestamps must be int")
    return local_rx_ms - expected_beacon_ms


def drift_ppm(delta_ms: int, beacon_interval_ms: int) -> int:
    if type(delta_ms) is not int or type(beacon_interval_ms) is not int:
        raise TypeError("delta and interval must be int")
    if beacon_interval_ms <= 0:
        raise ValueError("beacon_interval_ms must be positive")
    return (delta_ms * 1_000_000) // beacon_interval_ms


def correction_ms(ppm: int, future_delta_ms: int) -> int:
    if type(ppm) is not int or type(future_delta_ms) is not int:
        raise TypeError("ppm and future_delta_ms must be int")
    return (ppm * future_delta_ms) // 1_000_000


def drift_bound(b0: int, rho: int, h: int) -> int:
    if type(b0) is not int or type(rho) is not int or type(h) is not int:
        raise TypeError("B(h) inputs must be int")
    if b0 < 0 or rho < 0 or h < 0:
        raise ValueError("B(h) inputs must be non-negative")
    return b0 + rho * h


def guard_sufficient(
    guard: int, b_i: int, b_j: int, j_i: int, j_j: int, p: int, m: int
) -> bool:
    values = (guard, b_i, b_j, j_i, j_j, p, m)
    if any(type(v) is not int for v in values):
        raise TypeError("guard-budget inputs must be int")
    if any(v < 0 for v in values):
        raise ValueError("guard-budget inputs must be non-negative")
    return guard >= b_i + b_j + j_i + j_j + p + m


def in_guard(
    slot_start_ms: int, current_ms: int, slot_duration_ms: int, guard_ms: int
) -> bool:
    if any(
        type(v) is not int
        for v in (slot_start_ms, current_ms, slot_duration_ms, guard_ms)
    ):
        raise TypeError("slot times must be int")
    if slot_duration_ms < guard_ms or guard_ms < 0:
        return False
    guard_start = slot_start_ms + slot_duration_ms - guard_ms
    slot_end = slot_start_ms + slot_duration_ms
    return guard_start <= current_ms < slot_end


def tx_allowed(
    slot_start_ms: int, current_ms: int, slot_duration_ms: int, guard_ms: int
) -> bool:
    if current_ms < slot_start_ms:
        return False
    slot_end = slot_start_ms + slot_duration_ms
    return (not in_guard(slot_start_ms, current_ms, slot_duration_ms, guard_ms)) and (
        current_ms < slot_end
    )


def holdover_expired(measured_drift_ppm: int, guard_ppm: int = GUARD_PPM) -> bool:
    if type(measured_drift_ppm) is not int or type(guard_ppm) is not int:
        raise TypeError("ppm values must be int")
    if guard_ppm < 0:
        raise ValueError("guard_ppm must be non-negative")
    return abs(measured_drift_ppm) > guard_ppm
