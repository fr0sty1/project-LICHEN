# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from lichen.timing.sfn import TDMA_GUARD_MS, TDMA_SLOT_MS, hash_32, slot_for


def synchronized_hop_channel(sfn: int, seed: int = 0, num_channels: int = 8) -> int:
    data = seed.to_bytes(4, "little") + ((sfn & 0xFFFFFFFF).to_bytes(4, "little"))
    h = hash_32(data)
    n = max(num_channels, 3)
    return 1 + (h % n)


@dataclass
class SuperframeClock:
    sfn: int = 0
    base_time_us: int = 0
    drift_ppm: float = 10.0
    last_sync_us: int = 0


class TDMAState(Enum):
    UNSYNCED = auto()
    SYNCED = auto()
    DRIFTING = auto()


class TDMAScheduler:
    def __init__(self) -> None:
        self.state = TDMAState.UNSYNCED
        self.assigned_slot = 0
        self.num_slots = 8
        self.slot_duration_ms = TDMA_SLOT_MS
        self.guard_ms = TDMA_GUARD_MS
        self.clock = SuperframeClock()
        self.eui64 = bytes(8)

    def hash_slot(self, eui64: bytes, n_slots: int = 8, sfn: int = 0) -> int:
        return slot_for(eui64, sfn, n_slots)

    def _timing_us(self) -> tuple[int, int]:
        if type(self.slot_duration_ms) is not int or self.slot_duration_ms <= 0:
            raise ValueError("slot_duration_ms must be a positive exact integer")
        if (
            type(self.guard_ms) is not int
            or self.guard_ms < 0
            or self.guard_ms >= self.slot_duration_ms
        ):
            raise ValueError("guard_ms must be an exact integer smaller than slot_duration_ms")
        return self.slot_duration_ms * 1000, self.guard_ms * 1000

    def sync_from_beacon(self, rx_time_us: int, sfn: int, assigned: int = -1) -> None:
        if type(rx_time_us) is not int or rx_time_us < 0:
            raise ValueError("rx_time_us must be a non-negative exact integer")
        if type(sfn) is not int or not 0 <= sfn <= 0xFFFFFFFF:
            raise ValueError("sfn must be an unsigned 32-bit exact integer")
        if type(self.num_slots) is not int or self.num_slots <= 0:
            raise ValueError("num_slots must be a positive exact integer")
        if type(assigned) is not int or not -1 <= assigned < self.num_slots:
            raise ValueError("assigned must be -1 or a valid slot index")
        self._timing_us()
        self.clock.sfn = sfn
        self.clock.base_time_us = rx_time_us
        self.clock.last_sync_us = rx_time_us
        self.state = TDMAState.SYNCED
        if assigned >= 0:
            self.assigned_slot = assigned
        else:
            self.assigned_slot = self.hash_slot(self.eui64, self.num_slots, sfn)

    def is_tx_allowed(self, current_time_us: int) -> bool:
        if type(current_time_us) is not int or current_time_us < 0:
            raise ValueError("current_time_us must be a non-negative exact integer")
        if self.state != TDMAState.SYNCED:
            return True
        d, guard_us = self._timing_us()
        slot_start_us = self.clock.base_time_us + self.assigned_slot * d
        tx_end_us = slot_start_us + d - guard_us
        return slot_start_us <= current_time_us < tx_end_us

    def apply_drift(self, current_time_us: int) -> int:
        if self.clock.last_sync_us == 0:
            return 0
        delta = current_time_us - self.clock.last_sync_us
        drift = int(delta * self.clock.drift_ppm / 1000000)
        return drift

    def validate_vector(self, vector: dict[str, Any]) -> bool:
        if "eui64_hex" in vector:
            if not {"sfn", "n_slots", "expected_slot"} <= vector.keys():
                return False
            eui = bytes.fromhex(vector["eui64_hex"])
            computed = self.hash_slot(eui, vector["n_slots"], vector["sfn"])
            return bool(computed == vector["expected_slot"])
        if "expected_channel" in vector:
            if not {"sfn", "seed", "num_channels"} <= vector.keys():
                return False
            computed = synchronized_hop_channel(
                vector["sfn"], vector["seed"], vector["num_channels"]
            )
            return bool(computed == vector["expected_channel"])
        if "slot_start_ms" in vector:
            if not {
                "current_ms",
                "slot_duration_ms",
                "guard_ms",
                "expected_in_guard",
                "expected_tx_allowed",
            } <= vector.keys():
                return False
            t = vector["current_ms"] * 1000
            start = vector["slot_start_ms"] * 1000
            dur = vector["slot_duration_ms"] * 1000
            g = vector["guard_ms"] * 1000
            guard_start = start + dur - g
            actual_in_guard = guard_start <= t < start + dur
            actual_tx_allowed = start <= t < guard_start
            return bool(
                actual_in_guard == vector["expected_in_guard"]
                and actual_tx_allowed == vector["expected_tx_allowed"]
            )
        if "local_beacon_rx_ms" in vector and "expected_beacon_ms" in vector:
            if "expected_correction_ms" not in vector:
                return False
            local = vector["local_beacon_rx_ms"]
            expected = vector["expected_beacon_ms"]
            return bool(abs(local - expected) == vector["expected_correction_ms"])
        if "observed_ms" in vector and "beacon_nominal_ms" in vector:
            if not {"expected_ppm", "slot_adjust_ticks"} <= vector.keys():
                return False
            observed = vector["observed_ms"]
            nominal = vector["beacon_nominal_ms"]
            deviations = [abs(o - nominal) for o in observed]
            max_dev = max(deviations)
            computed_ppm = max_dev * 1000000 // nominal
            return bool(
                computed_ppm == vector["expected_ppm"]
                and max_dev == vector["slot_adjust_ticks"]
            )
        if "superframe_ms" in vector and "drift_ppm" in vector and "guard_ms" in vector:
            max_drift = vector["superframe_ms"] * vector["drift_ppm"] / 1000000
            return bool(max_drift < vector["guard_ms"])
        return False

    def get_hop_channel(self, sfn: int | None = None, seed: int = 0, num_channels: int = 8) -> int:
        if sfn is None:
            sfn = self.clock.sfn
        return synchronized_hop_channel(sfn, seed, num_channels)
