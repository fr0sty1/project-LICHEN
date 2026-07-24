# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC fragmentation codec and sender tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.schc.fragment import (
    ALL_1,
    MAX_SCHC_PACKET,
    TILE_SIZE,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
    ack_request,
    compute_mic,
    receiver_abort,
    sender_abort,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"

SCHC_FRAGMENT_VECTORS = json.loads(
    (VECTORS_DIR / "schc_fragment.json").read_text()
)["vectors"]


def v(name: str) -> dict:
    return next(x for x in SCHC_FRAGMENT_VECTORS if x["name"] == name)


def test_single_fragment_vector() -> None:
    vec = v("single_fragment")
    packet = bytes.fromhex(vec["packet"])
    wire = bytes.fromhex(vec["fragments"][0])
    frag = Fragment.from_bytes(wire)
    assert frag.rule_id == vec["rule_id"]
    assert frag.is_all_1
    assert compute_mic(packet).hex() == vec["mic"]
    assert frag.to_bytes() == wire


def test_ack_on_error_mic_fail_vector() -> None:
    vec = v("ack_on_error_mic_fail")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_ooo_retransmit_vector_mic() -> None:
    vec = v("ooo_retransmit")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_multi_fragment_vector_mic() -> None:
    vec = v("multi_fragment")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_all1_requires_mic() -> None:
    with pytest.raises(FragmentError):
        Fragment(rule_id=0x78, window=0, fcn=ALL_1, payload=b"x").to_bytes()


def test_window_and_fcn_schedule() -> None:
    sender = FragmentSender(
        payload=bytes(range(7)), rule_id=0x78, tile_size=1, window_size=3
    )
    frags = sender.all_fragments()
    assert sender.fragment_count == 7
    assert [(f.window, f.fcn) for f in frags] == [
        (0, 2),
        (0, 1),
        (0, 0),
        (1, 2),
        (1, 1),
        (1, 0),
        (0, ALL_1),
    ]
    assert all(f.mic == b"" for f in frags[:-1])
    assert frags[-1].mic


def test_rule_79_one_tile_data_path_literal() -> None:
    wire = bytes.fromhex("797f4c7fc202f0")
    sender = FragmentSender(b"x", rule_id=0x79)
    assert Fragment.from_bytes(wire) == sender.all_fragments()[0]


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


def test_complete_ack_round_trip() -> None:
    ack = Ack(0x78, 0, complete=True)
    assert ack.to_bytes() == bytes.fromhex("7840")
    assert Ack.from_bytes(bytes.fromhex("7840")) == ack
    ack1 = Ack(0x78, 1, complete=True)
    assert ack1.to_bytes() == bytes.fromhex("78c0")
    assert Ack.from_bytes(bytes.fromhex("78c0")) == ack1


def test_invalid_sender_parameters() -> None:
    with pytest.raises(FragmentError):
        FragmentSender(payload=b"x", rule_id=0x78, tile_size=1, window_size=0)


def test_fragment_sender_rejects_by_default() -> None:
    with pytest.raises(FragmentError, match="payload too large"):
        FragmentSender(payload=bytes(MAX_SCHC_PACKET + 1))
    with pytest.raises(FragmentError, match="payload too large"):
        FragmentSender(payload=bytes(MAX_SCHC_PACKET + 1), receiver_limit=MAX_SCHC_PACKET)
    with pytest.raises(FragmentError, match="payload too large"):
        FragmentSender(payload=bytes(MAX_SCHC_PACKET + 1), receiver_limit=MAX_SCHC_PACKET)


def test_ack_rejects_oversized_bitmap() -> None:
    with pytest.raises(FragmentError, match="bitmap size exceeds"):
        Ack.from_bytes(bytes.fromhex("7800") + b"\x00" * 20)
    with pytest.raises(FragmentError, match="bitmap size exceeds"):
        Ack.from_bytes(bytes.fromhex("7800") + b"\x00" * 10)


@pytest.mark.parametrize("wire", [bytes.fromhex("784000"), bytes.fromhex("78ff")])
def test_malformed_ack_vectors(wire: bytes) -> None:
    with pytest.raises(FragmentError):
        FragmentSender(payload=b"x", rule_id=0x78, tile_size=1, window_size=0)
    with pytest.raises(FragmentError):
        FragmentSender(payload=bytes(1282), rule_id=0x78, tile_size=10, window_size=7)
