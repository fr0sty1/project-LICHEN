# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TDMA CCP desync/rejoin FSM (spec 09 section 14.8)."""

from __future__ import annotations

from enum import StrEnum


class TdmaState(StrEnum):
    UNJOINED = "UNJOINED"
    ACQUIRING = "ACQUIRING"
    SYNCED = "SYNCED"
    DRIFTING = "DRIFTING"
    REJOINING = "REJOINING"


def on_event(state: TdmaState, event: str, missed: int | None = None) -> TdmaState:
    """Apply a 14.8 table event. Unknown pairs stay in ``state``."""
    if type(state) is not TdmaState:
        raise TypeError("state must be TdmaState")
    if type(event) is not str:
        raise TypeError("event must be str")
    if state is TdmaState.UNJOINED and event == "init":
        return TdmaState.ACQUIRING
    if state is TdmaState.ACQUIRING and event == "valid_beacon":
        return TdmaState.SYNCED
    if state is TdmaState.SYNCED and event == "beacon_in_slot":
        return TdmaState.SYNCED
    if state is TdmaState.SYNCED and event == "missed_beacons":
        if type(missed) is not int:
            raise TypeError("missed must be int")
        return TdmaState.DRIFTING if missed > 3 else TdmaState.SYNCED
    if state is TdmaState.SYNCED and event == "rpl_version_increment":
        return TdmaState.DRIFTING
    if state is TdmaState.DRIFTING and event == "valid_beacon":
        return TdmaState.ACQUIRING
    if state is TdmaState.DRIFTING and event == "invalid_beacon":
        return TdmaState.DRIFTING
    if state is TdmaState.DRIFTING and event == "dao_ack_with_slot":
        return TdmaState.SYNCED
    if state is TdmaState.REJOINING and event == "dao_ack_with_slot":
        return TdmaState.SYNCED
    return state
