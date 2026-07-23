# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC fragmentation codec and sender tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.schc.fragment import (
    ALL_1,
    MAX_PACKET_SIZE,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
)

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
VECTORS = json.loads((VECTORS_DIR / "schc_fragment.json").read_text())["vectors"]


def test_compute_mic_canonical_crc32() -> None:
    v = next(v for v in VECTORS if v["name"] == "canonical_crc32")
    assert bytes.fromhex(v["mic"]) == b"\xcb\xf4\x39\x26"


def test_fragment_regular_round_trip() -> None:
    frag = Fragment(rule_id=20, window=1, fcn=5, payload=b"tile")
    restored = Fragment.from_bytes(frag.to_bytes())
    assert restored == frag
    assert frag.to_bytes()[:2] == bytes([20, 0x45])


def test_fragment_all1_carries_mic() -> None:
    mic = b"\x00\x00\x00\x00"
    frag = Fragment(rule_id=20, window=0, fcn=ALL_1, payload=b"end", mic=mic)
    raw = frag.to_bytes()
    assert raw[:2] == bytes([20, ALL_1])
    assert raw[2:6] == mic
    restored = Fragment.from_bytes(raw)
    assert restored == frag
    assert restored.is_all_1


def test_all1_requires_mic() -> None:
    with pytest.raises(FragmentError):
        Fragment(rule_id=1, window=0, fcn=ALL_1, payload=b"x").to_bytes()


def test_window_and_fcn_schedule() -> None:
    sender = FragmentSender(payload=bytes(range(7)), rule_id=20, tile_size=1, window_size=3)
    frags = sender.all_fragments()
    assert sender.fragment_count == 7
    assert [(f.window, f.fcn) for f in frags] == [
        (0, 2), (0, 1), (0, 0),
        (1, 2), (1, 1), (1, 0),
        (0, ALL_1),
    ]
    v = next(v for v in VECTORS if v["name"] == "7tiles")
    assert frags[-1].mic == bytes.fromhex(v["mic"])
    assert all(f.mic == b"" for f in frags[:-1])


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


def test_ack_round_trip() -> None:
    ack = Ack(rule_id=20, window=1, bitmap=(True, False, True, True, False), complete=False)
    # independent oracle: rule 20=0x14, byte1=0x40 (W=1,C=0), n=5, bitmap 0b10110 padded to 0xb0
    expected = b"\x14\x40\x05\xb0"
    restored = Ack.from_bytes(expected)
    assert restored == ack


def test_ack_complete_flag() -> None:
    ack = Ack(rule_id=20, window=0, bitmap=(), complete=True)
    # independent oracle per RFC 8724 8.3.3: 2-byte complete ACK (no n/bitmap)
    expected = b"\x14\x01"
    assert ack.to_bytes() == expected
    restored = Ack.from_bytes(expected)
    assert restored.complete is True
    assert restored == ack


def test_invalid_sender_parameters() -> None:
    with pytest.raises(FragmentError):
        Fragment.from_bytes(wire)


@pytest.mark.parametrize("wire", [bytes.fromhex("784000"), bytes.fromhex("78ff")])
def test_malformed_ack_vectors(wire: bytes) -> None:
    with pytest.raises(FragmentError):
        FragmentSender(payload=b"x", rule_id=1, tile_size=1, window_size=0)
    with pytest.raises(FragmentError):
        FragmentSender(payload=bytes(1282), rule_id=1, tile_size=10, window_size=7)
