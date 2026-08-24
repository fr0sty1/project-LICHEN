# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC receiver and context manager tests."""

from __future__ import annotations

import threading

import pytest

from lichen.schc.fragment import (
    MAX_PACKET_SIZE,
    TILE_SIZE,
    WINDOW_SIZE,
    Fragment,
    FragmentError,
    compute_mic,
)
from lichen.schc.reassembly import (
    FragmentReceiver,
    ReassemblyManager,
    _AuthenticatedReassemblyManager,
)

RECOVERY_PACKET = bytes(TILE_SIZE) + b"\x11" * TILE_SIZE + b"\xa5"
TILE_0 = bytes.fromhex("787c") + bytes(TILE_SIZE)
TILE_1 = bytes.fromhex("787a") + b"\x22" * TILE_SIZE
ALL_1 = bytes.fromhex("787ebfb40b514a")


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
    max_size = WINDOW_SIZE * TILE_SIZE + 1
    packet = b"\xa5" * max_size
    final = Fragment(0x78, 1, 63, b"\xa5", compute_mic(packet))
    incomplete = FragmentReceiver(max_size=max_size)
    assert incomplete.receive(final).response == bytes.fromhex("78000000000000000000")

    receiver = FragmentReceiver(max_size=max_size)
    for fcn in range(62, -1, -1):
        result = receiver.receive(Fragment(0x78, 0, fcn, b"\xa5" * TILE_SIZE))
        assert result.response is None
    completed = receiver.receive(final)
    assert completed.response == bytes.fromhex("78c0")
    assert completed.reassembled == packet


def test_mandatory_receiver_limit_and_configured_overflow() -> None:
    packet = b"\xa5" * 1281
    regular_count, final_size = divmod(len(packet), TILE_SIZE)
    fragments = [
        Fragment(0x78, 0, 62 - index, b"\xa5" * TILE_SIZE) for index in range(regular_count)
    ]
    fragments.append(Fragment(0x78, 0, 63, b"\xa5" * final_size, compute_mic(packet)))

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

    receiver = FragmentReceiver(max_size=TILE_SIZE)
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
    conflict = Fragment(0x78, 0, 62, b"x" * TILE_SIZE)
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

    receiver = FragmentReceiver(max_size=TILE_SIZE)
    assert receiver.receive_bytes(TILE_0).response is None
    second = Fragment(0x78, 0, 61, bytes(TILE_SIZE))
    assert receiver.receive(second).response == bytes.fromhex("78ffff")


def test_manager_validates_before_allocating_and_never_evicts() -> None:
    manager = ReassemblyManager(max_contexts=1)
    assert manager.receive_bytes("bad", bytes.fromhex("78")).response == bytes.fromhex("78ffff")
    assert len(manager) == 0
    assert manager.receive_bytes("bad", bytes.fromhex("78ff")).response == bytes.fromhex("78ffff")
    assert len(manager) == 0

    with pytest.raises(FragmentError):
        manager.receive("bad", Fragment(0x77, 0, 62, bytes(TILE_SIZE)))
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


@pytest.mark.parametrize("max_size", [0, MAX_PACKET_SIZE + 1])
def test_manager_rejects_invalid_max_size(max_size: int) -> None:
    with pytest.raises(ValueError, match="max_size"):
        ReassemblyManager(max_size=max_size)


@pytest.mark.parametrize("window_size", [True, False, 1.5])
def test_receiver_rejects_non_integer_window_size(window_size: object) -> None:
    with pytest.raises(FragmentError, match="window_size must be integer"):
        FragmentReceiver(window_size=window_size)  # type: ignore[arg-type]


@pytest.mark.parametrize("max_size", [True, False, 0, 1.5, MAX_PACKET_SIZE + 1])
def test_receiver_rejects_non_integer_max_size(max_size: object) -> None:
    with pytest.raises(ValueError, match="max_size"):
        FragmentReceiver(max_size=max_size)  # type: ignore[arg-type]


def test_receiver_accepts_exact_profile_capacity() -> None:
    assert FragmentReceiver(max_size=MAX_PACKET_SIZE).max_size == MAX_PACKET_SIZE


@pytest.mark.parametrize("max_contexts", [True, False, 1.5])
def test_manager_rejects_non_integer_max_contexts(max_contexts: object) -> None:
    with pytest.raises(ValueError, match="max_contexts must be a positive integer"):
        ReassemblyManager(max_contexts=max_contexts)  # type: ignore[arg-type]


@pytest.mark.parametrize("max_size", [True, False, 1.5])
def test_manager_rejects_non_integer_max_size(max_size: object) -> None:
    with pytest.raises(ValueError, match="max_size must be a positive integer"):
        ReassemblyManager(max_size=max_size)  # type: ignore[arg-type]


@pytest.mark.parametrize("max_size", [True, False, 0, 1.5, MAX_PACKET_SIZE + 1])
def test_authenticated_manager_rejects_invalid_max_size(max_size: object) -> None:
    with pytest.raises(ValueError, match="max_size"):
        _AuthenticatedReassemblyManager(
            bytes(32),
            security_lock=threading.RLock(),
            max_size=max_size,  # type: ignore[arg-type]
        )


def test_authenticated_manager_accepts_exact_profile_capacity() -> None:
    manager = _AuthenticatedReassemblyManager(
        bytes(32),
        security_lock=threading.RLock(),
        max_size=MAX_PACKET_SIZE,
    )
    assert manager._max_size == MAX_PACKET_SIZE
