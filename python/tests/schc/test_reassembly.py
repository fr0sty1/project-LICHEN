# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC receiver and context manager tests."""

from __future__ import annotations

import pytest

from lichen.schc.fragment import Fragment, FragmentError
from lichen.schc.reassembly import FragmentReceiver, ReassemblyManager

RECOVERY_PACKET = bytes(187) + b"\x11" * 187 + b"\xa5"
TILE_0 = bytes.fromhex("787c") + bytes(187)
TILE_1 = bytes.fromhex("787a") + b"\x22" * 187
ALL_1 = bytes.fromhex("787fd90535ad4a")


def test_clean_reassembly_uses_literal_recovery_wires() -> None:
    receiver = FragmentReceiver()

    assert receiver.receive_bytes(TILE_0).response is None
    assert receiver.receive_bytes(TILE_1).response is None
    result = receiver.receive_bytes(ALL_1)
    assert result.response == bytes.fromhex("7840")
    assert result.reassembled == RECOVERY_PACKET
    assert receiver.done
    assert receiver._tiles == {}


def test_dropped_regular_tile_uses_literal_recovery_wires() -> None:
    receiver = FragmentReceiver()

    assert receiver.receive_bytes(TILE_0).response is None
    assert receiver.receive_bytes(ALL_1).response == bytes.fromhex("782000000000000000")
    assert receiver.receive_bytes(TILE_1).response is None
    result = receiver.receive_bytes(bytes.fromhex("7800"))
    assert result.response == bytes.fromhex("7840")
    assert result.reassembled == RECOVERY_PACKET


def test_two_window_all0_no_ack_and_w1_completion() -> None:
    final = Fragment(0x78, 1, 63, b"\xa5", bytes.fromhex("8727c8e5"))
    incomplete = FragmentReceiver(max_size=11782)
    assert incomplete.receive(final).response == bytes.fromhex("78000000000000000000")

    receiver = FragmentReceiver(max_size=11782)
    for fcn in range(62, -1, -1):
        result = receiver.receive(Fragment(0x78, 0, fcn, b"\xa5" * 187))
        assert result.response is None
    completed = receiver.receive(final)
    assert completed.response == bytes.fromhex("78c0")
    assert completed.reassembled == b"\xa5" * 11782


def test_mandatory_receiver_limit_and_configured_overflow() -> None:
    packet = b"\xa5" * 1281
    fragments = [Fragment(0x78, 0, fcn, b"\xa5" * 187) for fcn in range(62, 56, -1)]
    fragments.append(Fragment(0x78, 0, 63, b"\xa5" * 159, bytes.fromhex("daca2bc3")))

    receiver = FragmentReceiver()
    result = None
    for fragment in fragments:
        result = receiver.receive(fragment)
    assert result is not None and result.response == bytes.fromhex("7840")
    assert result.reassembled == packet

    receiver = FragmentReceiver(max_size=1280)
    for fragment in fragments:
        result = receiver.receive(fragment)
    assert result is not None and result.response == bytes.fromhex("78ffff")
    assert result.aborted and receiver.done and receiver._tiles == {}


def test_identical_repeated_all1_repeats_current_ack() -> None:
    receiver = FragmentReceiver()
    expected = bytes.fromhex("780000000000000000")
    assert receiver.receive_bytes(ALL_1).response == expected
    assert receiver.receive_bytes(ALL_1).response == expected
    assert receiver.attempts == 2


def test_one_tile_all1() -> None:
    receiver = FragmentReceiver()
    result = receiver.receive_bytes(bytes.fromhex("787f4c7fc202f0"))
    assert result.response == bytes.fromhex("7840")
    assert result.reassembled == b"x"


def test_rule_79_one_tile_reassembly_literal() -> None:
    result = FragmentReceiver().receive_bytes(bytes.fromhex("797f4c7fc202f0"))
    assert result.response == bytes.fromhex("7940")
    assert result.reassembled == b"x"


def test_all1_first_capacity_includes_retained_final_tile() -> None:
    receiver = FragmentReceiver(max_size=100)
    oversized = Fragment(0x78, 0, 63, bytes(101), bytes(4))
    result = receiver.receive(oversized)
    assert result.response == bytes.fromhex("78ffff")
    assert result.aborted and receiver.done and receiver._all1 is None

    receiver = FragmentReceiver(max_size=187)
    assert receiver.receive_bytes(ALL_1).response == bytes.fromhex("780000000000000000")
    result = receiver.receive_bytes(TILE_0)
    assert result.response == bytes.fromhex("78ffff")
    assert result.aborted and receiver.done and receiver._all1 is None


def test_rcs_failure_ack_literal() -> None:
    receiver = FragmentReceiver()
    receiver.receive_bytes(TILE_0)
    receiver.receive_bytes(TILE_1)
    result = receiver.receive_bytes(bytes.fromhex("787fd80535ad4a"))
    assert result.response == bytes.fromhex("783000000000000000")
    assert result.mic_ok is False


def test_ack_request_without_state_and_retry_exhaustion() -> None:
    receiver = FragmentReceiver()
    expected = bytes.fromhex("78000000000000000000")

    for _ in range(4):
        assert receiver.receive_bytes(bytes.fromhex("7880")).response == expected
    result = receiver.receive_bytes(bytes.fromhex("7880"))
    assert result.response == bytes.fromhex("78ffff")
    assert result.aborted and receiver.done


def test_duplicate_conflicts_abort() -> None:
    receiver = FragmentReceiver()
    assert receiver.receive_bytes(TILE_0).response is None
    assert receiver.receive_bytes(TILE_0).response is None
    conflict = Fragment(0x78, 0, 62, b"x" * 187)
    assert receiver.receive(conflict).response == bytes.fromhex("78ffff")

    receiver = FragmentReceiver()
    receiver.receive_bytes(ALL_1)
    conflict = Fragment(0x78, 0, 63, b"y", bytes.fromhex("ec829ad6"))
    assert receiver.receive(conflict).response == bytes.fromhex("78ffff")


def test_expire_and_abort_controls_release() -> None:
    receiver = FragmentReceiver()
    receiver.receive_bytes(TILE_0)
    assert receiver.expire() == bytes.fromhex("78ffff")
    assert receiver.expire() is None

    for control in (bytes.fromhex("78fe"), bytes.fromhex("78ffff")):
        receiver = FragmentReceiver()
        receiver.receive_bytes(TILE_0)
        result = receiver.receive_bytes(control)
        assert result.aborted and result.response is None and receiver.done


def test_malformed_input_and_resource_limit_abort() -> None:
    receiver = FragmentReceiver()
    assert receiver.receive_bytes(bytes.fromhex("78ff")).response == bytes.fromhex("78ffff")

    receiver = FragmentReceiver(max_size=187)
    assert receiver.receive_bytes(TILE_0).response is None
    second = Fragment(0x78, 0, 61, bytes(187))
    assert receiver.receive(second).response == bytes.fromhex("78ffff")


def test_manager_validates_before_allocating_and_never_evicts() -> None:
    manager = ReassemblyManager(max_contexts=1)
    assert manager.receive_bytes("bad", bytes.fromhex("78")).response == bytes.fromhex("78ffff")
    assert len(manager) == 0
    assert manager.receive_bytes("bad", bytes.fromhex("78ff")).response == bytes.fromhex("78ffff")
    assert len(manager) == 0

    with pytest.raises(FragmentError):
        manager.receive("bad", Fragment(0x77, 0, 62, bytes(187)))
    assert len(manager) == 0

    malformed = Fragment(0x78, 0, 62, b"short")
    assert manager.receive("bad", malformed).response == bytes.fromhex("78ffff")
    assert len(manager) == 0

    assert manager.receive_bytes("peer", TILE_0).response is None
    assert manager.receive_bytes("other", bytes.fromhex("78ff")).aborted
    assert len(manager) == 1
    rejected = manager.receive_bytes("other", TILE_0)
    assert rejected.response == bytes.fromhex("78ffff")
    assert len(manager) == 1

    assert manager.receive_bytes("peer", bytes.fromhex("78ff")).aborted
    assert len(manager) == 0


@pytest.mark.parametrize("max_size", [0, 23563])
def test_manager_rejects_invalid_max_size(max_size: int) -> None:
    with pytest.raises(ValueError, match="max_size"):
        ReassemblyManager(max_size=max_size)
