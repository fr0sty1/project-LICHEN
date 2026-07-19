# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC fragmentation codec and sender tests."""

from __future__ import annotations

import pytest

from lichen.schc.fragment import (
    ALL_1,
    MAX_PACKET_SIZE,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
    ack_request,
    compute_mic,
    receiver_abort,
    sender_abort,
)


def test_recovery_vector_codec_and_mic() -> None:
    packet = bytes(187) + b"\x11" * 187 + b"\xa5"
    sender = FragmentSender(packet)
    wires = [fragment.to_bytes() for fragment in sender.all_fragments()]

    assert compute_mic(packet) == bytes.fromhex("ec829ad6")
    assert wires == [
        bytes.fromhex("787c") + bytes(187),
        bytes.fromhex("787a") + b"\x22" * 187,
        bytes.fromhex("787fd90535ad4a"),
    ]
    assert [Fragment.from_bytes(wire) for wire in wires] == sender.all_fragments()


def test_window_transition_vector_fragments() -> None:
    sender = FragmentSender(b"\xa5" * 11782, receiver_limit=MAX_PACKET_SIZE)
    fragments = sender.all_fragments()

    assert sender.fragment_count == 64
    assert fragments[0].to_bytes() == bytes.fromhex("787d") + b"\x4b" * 186 + b"\x4a"
    assert fragments[31].to_bytes() == bytes.fromhex("783f") + b"\x4b" * 186 + b"\x4a"
    assert fragments[62].to_bytes() == bytes.fromhex("7801") + b"\x4b" * 186 + b"\x4a"
    assert fragments[63].to_bytes() == bytes.fromhex("78ff0e4f91cb4a")


def test_rule_79_one_tile_data_path_literal() -> None:
    wire = bytes.fromhex("797f4c7fc202f0")
    sender = FragmentSender(b"x", rule_id=0x79)

    assert wire[2:6] == bytes.fromhex("4c7fc202")
    assert sender.start() == [wire]
    assert Fragment.from_bytes(wire) == sender.all_fragments()[0]
    assert sender.handle_ack_bytes(bytes.fromhex("7940")) == []
    assert sender.status == "succeeded"


def test_ack_and_control_vectors() -> None:
    failure = bytes.fromhex("782000000000000000")
    ack = Ack.from_bytes(failure, assigned_fcns=(62, 61, ALL_1))

    assert ack.to_bytes() == failure
    assert ack.bitmap[0] and not ack.bitmap[1] and ack.bitmap[-1]
    assert Ack(0x78, 0, complete=True).to_bytes() == bytes.fromhex("7840")
    assert Ack.from_bytes(bytes.fromhex("78c0")) == Ack(0x78, 1, complete=True)
    assert ack_request(0x78, 0) == bytes.fromhex("7800")
    assert ack_request(0x79, 1) == bytes.fromhex("7980")
    assert sender_abort(0x78) == bytes.fromhex("78fe")
    assert receiver_abort(0x79) == bytes.fromhex("79ffff")


def test_all_zero_ack_bitmap_round_trip() -> None:
    ack = Ack(0x78, 0, (False,) * 63)
    assert ack.to_bytes() == bytes.fromhex("78000000000000000000")
    assert Ack.from_bytes(ack.to_bytes()) == ack


@pytest.mark.parametrize(
    "wire",
    [bytes.fromhex("783fff"), bytes.fromhex("7800000000000000000000")],
)
def test_noncanonical_c0_ack_rejected(wire: bytes) -> None:
    with pytest.raises(FragmentError, match="canonical|padding"):
        Ack.from_bytes(wire)


@pytest.mark.parametrize(
    "wire",
    [
        bytes.fromhex("787c00"),
        bytes.fromhex("787c") + bytes(186) + b"\x01",
        bytes.fromhex("787e00000000"),
        bytes.fromhex("7880") + bytes(187),
    ],
)
def test_malformed_fragment_vectors(wire: bytes) -> None:
    with pytest.raises(FragmentError):
        Fragment.from_bytes(wire)


@pytest.mark.parametrize("wire", [bytes.fromhex("784000"), bytes.fromhex("78ff")])
def test_malformed_ack_vectors(wire: bytes) -> None:
    with pytest.raises(FragmentError):
        Ack.from_bytes(wire)


def test_unassigned_bitmap_bit_rejected() -> None:
    with pytest.raises(FragmentError):
        Ack.from_bytes(bytes.fromhex("783800000000000000"), assigned_fcns=(62, 61, ALL_1))


def test_sender_recovers_missing_regular_tile() -> None:
    packet = bytes(187) + b"\x11" * 187 + b"\xa5"
    sender = FragmentSender(packet)
    sender.start()

    messages = sender.handle_ack_bytes(bytes.fromhex("782000000000000000"))
    assert messages == [bytes.fromhex("787a") + b"\x22" * 187, bytes.fromhex("7800")]
    assert sender.attempts == 2
    assert sender.handle_ack_bytes(bytes.fromhex("7840")) == []
    assert sender.status == "succeeded"
    assert sender.payload == b""


def test_sender_retry_exhaustion_and_rcs_failure_abort() -> None:
    sender = FragmentSender(b"x")
    sender.start()
    assert [sender.timeout().hex() for _ in range(3)] == ["7800", "7800", "7800"]
    assert sender.timeout() == bytes.fromhex("78fe")
    assert sender.status == "aborted"

    sender = FragmentSender(bytes(187) + b"\x11" * 187 + b"\xa5")
    sender.start()
    assert sender.handle_ack_bytes(bytes.fromhex("783000000000000000")) == [bytes.fromhex("78fe")]


def test_sender_limits_and_nonfinal_success() -> None:
    with pytest.raises(FragmentError):
        FragmentSender(b"")
    with pytest.raises(FragmentError):
        FragmentSender(b"x" * 1282)
    with pytest.raises(FragmentError):
        FragmentSender(b"x" * (MAX_PACKET_SIZE + 1), receiver_limit=MAX_PACKET_SIZE)

    sender = FragmentSender(b"x" * 11782, receiver_limit=MAX_PACKET_SIZE)
    sender.start()
    assert sender.handle_ack_bytes(bytes.fromhex("7840")) == []
    assert sender.status == "active"


@pytest.mark.parametrize(
    "wire",
    [bytes.fromhex("78bf"), bytes.fromhex("788000000000000000")],
)
def test_sender_ignores_c0_for_unused_window(wire: bytes) -> None:
    sender = FragmentSender(b"x")
    sender.start()
    attempts = sender.attempts

    assert sender.handle_ack_bytes(wire) == []
    assert sender.status == "active"
    assert sender.attempts == attempts


def test_sender_ignores_complete_nonfinal_c0() -> None:
    sender = FragmentSender(b"x" * 11782, receiver_limit=MAX_PACKET_SIZE)
    sender.start()
    attempts = sender.attempts

    assert sender.handle_ack_bytes(bytes.fromhex("783f")) == []
    assert sender.status == "active"
    assert sender.attempts == attempts


def test_receiver_abort_only_affects_matching_active_sender() -> None:
    ready = FragmentSender(b"x")
    assert ready.handle_ack_bytes(bytes.fromhex("78ffff")) == []
    assert ready.handle_ack_bytes(bytes.fromhex("78ff")) == []
    assert ready.status == "ready" and ready.payload == b"x"

    active = FragmentSender(b"x")
    active.start()
    assert active.handle_ack_bytes(bytes.fromhex("79ffff")) == []
    assert active.handle_ack_bytes(bytes.fromhex("79ff")) == []
    assert active.status == "active" and active.payload == b"x"
    with pytest.raises(FragmentError):
        active.handle_ack_bytes(bytes.fromhex("78ff"))
    assert active.handle_ack_bytes(bytes.fromhex("78ffff")) == []
    assert active.status == "aborted" and active.payload == b""

    succeeded = FragmentSender(b"x")
    succeeded.start()
    succeeded.handle_ack_bytes(bytes.fromhex("7840"))
    assert succeeded.handle_ack_bytes(bytes.fromhex("78ff")) == []
    assert succeeded.handle_ack_bytes(bytes.fromhex("78ffff")) == []
    assert succeeded.status == "succeeded"
