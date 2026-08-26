# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Focused fixed-profile SCHC ACK conformance tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict, cast

import pytest

from lichen.constants import SCHC_FRAGMENT_T
from lichen.schc.fragment import WINDOW_SIZE, Ack, FragmentError

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


class _AckVector(TypedDict, total=False):
    name: str
    category: str
    rule_id: int
    window: int
    c_bit: int
    bitmap: None
    received_bitmap_bits: str
    unassigned_zero_bits: int
    final_all_1_received: bool
    received_bitmap_prefix_bits: str
    trailing_received_bits: int
    assigned_fcns: list[int]
    wire: str


def _ack_bitmap_vectors() -> list[object]:
    document = cast(
        dict[str, object],
        json.loads((VECTORS_DIR / "schc_adaptation.json").read_text()),
    )
    raw_vectors = document["vectors"]
    if not isinstance(raw_vectors, list):
        raise AssertionError("schc_adaptation vectors must be a list")
    vectors: list[object] = []
    for raw_vector in raw_vectors:
        if not isinstance(raw_vector, dict):
            raise AssertionError("SCHC ACK vector must be an object")
        vector = cast(_AckVector, raw_vector)
        if vector.get("category") == "ack_bitmap":
            vectors.append(pytest.param(vector, id=vector["name"]))
    return vectors


def _expected_bitmap(vector: _AckVector) -> tuple[bool, ...]:
    if "received_bitmap_bits" in vector:
        bit_string = vector["received_bitmap_bits"]
        bit_string += "0" * vector["unassigned_zero_bits"]
        bit_string += "1" if vector["final_all_1_received"] is True else "0"
    else:
        bit_string = vector["received_bitmap_prefix_bits"]
        bit_string += "1" * vector["trailing_received_bits"]
    assert len(bit_string) == WINDOW_SIZE
    return tuple(bit == "1" for bit in bit_string)


@pytest.mark.parametrize("vector", _ack_bitmap_vectors())
def test_canonical_ack_bitmap_vectors(vector: _AckVector) -> None:
    """The Python codec consumes every canonical shared ACK bitmap vector."""
    wire = bytes.fromhex(vector["wire"])
    rule_id = vector["rule_id"]
    window = vector["window"]

    if vector["c_bit"] == 1:
        expected = Ack(rule_id, window, complete=True)
        assert vector["bitmap"] is None
    else:
        expected = Ack(rule_id, window, _expected_bitmap(vector))

    assert expected.to_bytes() == wire
    assert Ack.from_bytes(wire) == expected
    assigned_fcns = vector.get("assigned_fcns")
    if assigned_fcns is not None:
        assert Ack.from_bytes(wire, assigned_fcns=assigned_fcns) == expected


@pytest.mark.parametrize(
    ("bitmap", "wire"),
    [
        ((False,) * WINDOW_SIZE, "78000000000000000000"),
        ((True,) * WINDOW_SIZE, "783f"),
    ],
)
def test_c0_all_zero_and_all_one_bitmaps(
    bitmap: tuple[bool, ...],
    wire: str,
) -> None:
    ack = Ack(0x78, 0, bitmap)
    assert ack.to_bytes() == bytes.fromhex(wire)
    assert Ack.from_bytes(bytes.fromhex(wire)) == ack


@pytest.mark.parametrize("window", [0, 1])
@pytest.mark.parametrize("trailing_ones", range(WINDOW_SIZE + 1))
def test_every_trailing_one_boundary_has_exact_canonical_length(
    window: int,
    trailing_ones: int,
) -> None:
    if trailing_ones == WINDOW_SIZE:
        bitmap = (True,) * WINDOW_SIZE
    else:
        bitmap = (
            (True,) * (WINDOW_SIZE - trailing_ones - 1)
            + (False,)
            + (True,) * trailing_ones
        )
    ack = Ack(0x78, window, bitmap)
    wire = ack.to_bytes()
    retained_bits = WINDOW_SIZE - trailing_ones
    expected_length = 1 + (2 + retained_bits + 7) // 8

    assert len(wire) == expected_length
    assert wire[1] >> 7 == window
    assert Ack.from_bytes(wire) == ack


def test_empty_bitmap_is_only_valid_for_complete_ack() -> None:
    with pytest.raises(FragmentError, match="requires a 63-bit bitmap"):
        Ack(0x78, 0).to_bytes()

    assert Ack(0x78, 0, complete=True).to_bytes() == bytes.fromhex("7840")
    assert Ack(0x78, 1, complete=True).to_bytes() == bytes.fromhex("78c0")


def test_trailing_one_compression_is_canonical() -> None:
    bitmap = (True, True, False, True, False) + (True,) * 58
    ack = Ack(0x78, 0, bitmap)

    assert ack.to_bytes() == bytes.fromhex("7835")
    assert Ack.from_bytes(bytes.fromhex("7835")) == ack
    with pytest.raises(FragmentError, match="non-canonical compressed ACK"):
        Ack.from_bytes(bytes.fromhex("7835ffffffffffffff80"))


@pytest.mark.parametrize(
    ("wire", "message"),
    [
        (b"\x78", "too short"),
        (bytes.fromhex("784000"), "malformed C=1"),
        (bytes.fromhex("78000000000000000001"), "invalid ACK padding"),
        (bytes.fromhex("7800") + b"\x00" * 10, "bitmap size exceeds"),
    ],
)
def test_ack_rejects_invalid_sizes_and_padding(wire: bytes, message: str) -> None:
    with pytest.raises(FragmentError, match=message):
        Ack.from_bytes(wire)


def test_profile_has_no_dtag_field() -> None:
    """T=0 makes the rule/peer session key the sole datagram discriminator."""
    assert SCHC_FRAGMENT_T == 0
    assert Ack(0x78, 0, complete=True).to_bytes() == bytes.fromhex("7840")
    assert Ack(0x78, 1, complete=True).to_bytes() == bytes.fromhex("78c0")
