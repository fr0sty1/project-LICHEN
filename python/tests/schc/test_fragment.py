# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SCHC fragmentation — sender side (RFC 8724 section 8).

Oracles: the canonical CRC-32 check value (crc32(b"123456789") = 0xCBF43926)
for the MIC, and a hand-traced window/FCN schedule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.schc.fragment import (
    ALL_1,
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


def test_single_fragment_datagram() -> None:
    sender = FragmentSender(payload=b"hi", rule_id=20, tile_size=10)
    frags = sender.all_fragments()
    assert len(frags) == 1
    assert frags[0].is_all_1
    assert frags[0].payload == b"hi"


def test_window_count_and_fragments_in_window() -> None:
    sender = FragmentSender(payload=bytes(7), rule_id=20, tile_size=1, window_size=3)
    assert sender.window_count == 3
    assert len(sender.fragments_in_window(0)) == 3
    assert len(sender.fragments_in_window(2)) == 1


def test_retransmit_missing_from_bitmap() -> None:
    sender = FragmentSender(payload=bytes(range(6)), rule_id=20, tile_size=1, window_size=3)
    # Window 0 has 3 fragments; bitmap says positions 0 and 2 received, 1 missing.
    missing = sender.retransmit(0, [True, False, True])
    assert len(missing) == 1
    assert missing[0].fcn == 1  # position 1 -> FCN window_size-1-1 = 1


def test_retransmit_treats_short_bitmap_as_missing() -> None:
    sender = FragmentSender(payload=bytes(range(3)), rule_id=20, tile_size=1, window_size=3)
    missing = sender.retransmit(0, [True])  # only position 0 acked
    # Position 1 -> FCN 1; position 2 is the datagram's last tile -> All-1 (63).
    assert [f.fcn for f in missing] == [1, ALL_1]


def test_ack_round_trip() -> None:
    ack = Ack(rule_id=20, window=1, bitmap=(True, False, True, True, False), complete=False)
    restored = Ack.from_bytes(ack.to_bytes())
    assert restored == ack


def test_ack_complete_flag() -> None:
    ack = Ack(rule_id=20, window=0, bitmap=(True,), complete=True)
    restored = Ack.from_bytes(ack.to_bytes())
    assert restored.complete is True


def test_invalid_sender_parameters() -> None:
    with pytest.raises(FragmentError):
        FragmentSender(payload=b"x", rule_id=1, tile_size=0)
    with pytest.raises(FragmentError):
        FragmentSender(payload=b"x", rule_id=1, tile_size=1, window_size=0)
