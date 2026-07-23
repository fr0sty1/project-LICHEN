# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


def hash_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h

def synchronized_hop_channel(sfn: int, seed: int = 0, num_channels: int = 8) -> int:
    data = seed.to_bytes(4, "little") + ((sfn & 0xffffffff).to_bytes(4, "little"))
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
        self.slot_duration_ms = 250
        self.guard_ms = 50
        self.clock = SuperframeClock()
        self.eui64 = bytes(8)
    def hash_slot(self, eui64: bytes, n_slots: int = 8, epoch: int = 0) -> int:
        data = eui64 + epoch.to_bytes(4, "little")
        return hash_32(data) % n_slots
    def sync_from_beacon(self, rx_time_us: int, sfn: int, assigned: int = -1) -> None:
        self.clock.sfn = sfn
        self.clock.last_sync_us = rx_time_us
        self.state = TDMAState.SYNCED
        if assigned >= 0:
            self.assigned_slot = assigned
        else:
            self.assigned_slot = self.hash_slot(self.eui64, self.num_slots)
    def is_tx_allowed(self, current_time_us: int) -> bool:
        if self.state != TDMAState.SYNCED:
            return True
        d = self.slot_duration_ms * 1000
        slot_start_us = self.clock.sfn * self.num_slots * d + self.assigned_slot * d
        slot_end_us = slot_start_us + d
        guard_us = self.guard_ms * 1000
        return (slot_start_us - guard_us) <= current_time_us <= (slot_end_us + guard_us)
    def apply_drift(self, current_time_us: int) -> int:
        if self.clock.last_sync_us == 0:
            return 0
        delta = current_time_us - self.clock.last_sync_us
        drift = int(delta * self.clock.drift_ppm / 1000000)
        return drift
    def validate_vector(self, vector: dict) -> bool:
        if "eui64_hex" in vector:
            eui = bytes.fromhex(vector["eui64_hex"])
            computed = self.hash_slot(eui, vector.get("n_slots", 8), vector.get("epoch", 0))
            return computed == vector.get("expected_slot", 0)
        if "sfn" in vector or "expected_channel" in vector:
            sfn = vector.get("sfn", 0)
            computed = synchronized_hop_channel(sfn, vector.get("seed", 0), vector.get("num_channels", 8))
            return computed == vector.get("expected_channel", 0)
        if "slot_start_ms" in vector:
            t = vector["current_ms"] * 1000
            start = vector["slot_start_ms"] * 1000
            dur = vector.get("slot_duration_ms", 250) * 1000
            g = vector.get("guard_ms", 50) * 1000
            in_window = (start - g) <= t <= (start + dur + g)
            return in_window == (not vector.get("expected_in_guard", False))
        return True
    def get_hop_channel(self, sfn: int | None = None, seed: int = 0, num_channels: int = 8) -> int:
        if sfn is None:
            sfn = self.clock.sfn
        return synchronized_hop_channel(sfn, seed, num_channels)
