# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TDMA SFN oracle (spec 09-packets-timing.md §14.7-14.8)."""

from __future__ import annotations

from enum import Enum, auto

# Guard time and minimum slot duration per §14.8.  The slot covers the
# profile-maximum 255-byte PHY payload at SF10/125 kHz plus the one canonical
# guard interval.
TDMA_GUARD_MS: int = 50
TDMA_SLOT_MS: int = 2346
TDMA_BEACON_TIMEOUT_SUPERFRAMES: int = 3
TDMA_REJOIN_TIMEOUT_SUPERFRAMES: int = 10  # 10 × superframe length


def hash_32(data: bytes) -> int:
    """FNV-1a 32-bit hash (lichen hallmark, spec precedent §4.5)."""
    if type(data) is not bytes:
        raise TypeError("data must be exact bytes")
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def slot_for(eui64: bytes, sfn: int, num_slots: int) -> int:
    """Return ``(hash_32(eui64) + u32(sfn)) mod num_slots`` per spec §14.7.

    ``sfn`` and ``num_slots`` must be exact integers (booleans are rejected).
    SFNs outside the unsigned-32 range are normalized modulo ``2**32`` so the
    Python oracle models the fixed-width protocol counter at wraparound.
    """
    if type(eui64) is not bytes:
        raise TypeError("eui64 must be exact bytes")
    if len(eui64) != 8:
        raise ValueError("eui64 must be 8 bytes")
    if type(sfn) is not int:
        raise TypeError("sfn must be an integer")
    if type(num_slots) is not int:
        raise TypeError("num_slots must be an integer")
    if num_slots <= 0:
        raise ValueError("num_slots must be positive")
    wrapped_sum = (hash_32(eui64) + (sfn & 0xFFFFFFFF)) & 0xFFFFFFFF
    return wrapped_sum % num_slots


def sfn_delta(curr: int, last: int) -> int:
    """Unsigned 32-bit SFN delta: (curr - last) mod 2^32."""
    if type(curr) is not int:
        raise TypeError("curr must be an integer")
    if type(last) is not int:
        raise TypeError("last must be an integer")
    return (curr - last) & 0xFFFFFFFF


# Desynchronization Recovery FSM (§14.7)

DESYNC_CONSTANTS: dict[str, int] = {
    "LISTEN_PERIOD_MIN_S": 30,
    "LISTEN_PERIOD_MAX_S": 60,
    "DELAY_PER_NODE_S": 5,
    "MAX_STARTUP_DELAY_S": 300,
}


def initial_startup_delay(nodes_heard: int) -> int:
    """Compute initial_delay = min(MAX_STARTUP_DELAY, nodes_heard * DELAY_PER_NODE)."""
    if type(nodes_heard) is not int or nodes_heard < 0:
        raise ValueError("nodes_heard must be a non-negative integer")
    return min(
        DESYNC_CONSTANTS["MAX_STARTUP_DELAY_S"], nodes_heard * DESYNC_CONSTANTS["DELAY_PER_NODE_S"]
    )


class DesyncState(Enum):
    SYNCED = auto()
    DESYNCED = auto()
    RECOVERING = auto()


class DesyncFSM:
    """Desynchronization Recovery FSM (§14.7 table)."""

    def __init__(self) -> None:
        self.state = DesyncState.SYNCED
        self.consecutive_valid = 0
        self.missed_superframes = 0

    def on_sfn_wrap(self, time_valid: bool) -> DesyncState:
        if not time_valid and self.state == DesyncState.SYNCED:
            self.state = DesyncState.DESYNCED
            self.consecutive_valid = 0
            self.missed_superframes = 0
        return self.state

    def on_beacon(self, valid: bool) -> DesyncState:
        if self.state == DesyncState.DESYNCED and valid:
            self.state = DesyncState.RECOVERING
            self.consecutive_valid = 1
            self.missed_superframes = 0
        elif self.state == DesyncState.RECOVERING:
            if valid:
                self.consecutive_valid += 1
                self.missed_superframes = 0
                if self.consecutive_valid >= 3:
                    self.state = DesyncState.SYNCED
                    self.consecutive_valid = 0
            else:
                self.state = DesyncState.DESYNCED
                self.consecutive_valid = 0
                self.missed_superframes = 0
        return self.state

    def on_missed_superframe(self) -> DesyncState:
        """Advance the bounded RECOVERING listen timeout by one superframe."""
        if self.state != DesyncState.RECOVERING:
            return self.state
        self.missed_superframes += 1
        if self.missed_superframes >= TDMA_BEACON_TIMEOUT_SUPERFRAMES:
            self.state = DesyncState.DESYNCED
            self.consecutive_valid = 0
            self.missed_superframes = 0
        return self.state


# CCP FSM for desync/rejoin robustness (§14.8)


class CcpState(Enum):
    UNJOINED = auto()
    ACQUIRING = auto()
    SYNCED = auto()
    DRIFTING = auto()
    REJOINING = auto()


__all__ = [
    "CcpState",
    "DESYNC_CONSTANTS",
    "DesyncFSM",
    "DesyncState",
    "TDMA_BEACON_TIMEOUT_SUPERFRAMES",
    "TDMA_GUARD_MS",
    "TDMA_REJOIN_TIMEOUT_SUPERFRAMES",
    "TDMA_SLOT_MS",
    "hash_32",
    "initial_startup_delay",
    "sfn_delta",
    "slot_for",
]
