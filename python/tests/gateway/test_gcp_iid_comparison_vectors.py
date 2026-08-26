# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: GCP IID comparison vs shared vectors.

Drives ``lichen.link.slot_coordination.compare_iid`` against
``test/vectors/gcp_iid_comparison.json`` (spec 08-gateway-coordination.md
Section 6.3): IIDs are compared as memcmp / unsigned big-endian 64-bit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.slot_coordination import compare_iid

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "gcp_iid_comparison.json"

_WINNER_TO_SIGN = {"iid_a": -1, "tie": 0, "iid_b": 1}


@pytest.fixture(scope="module")
def vectors() -> list[dict]:
    with open(_VECTORS_PATH) as f:
        return json.load(f)["vectors"]


@pytest.mark.parametrize(
    "case", json.loads(_VECTORS_PATH.read_text())["vectors"], ids=lambda v: v["name"]
)
def test_iid_comparison(case: dict) -> None:
    iid_a = bytes.fromhex(case["iid_a"])
    iid_b = bytes.fromhex(case["iid_b"])
    winner = case["expected"]["winner"]

    result = compare_iid(iid_a, iid_b)

    assert result == _WINNER_TO_SIGN[winner], (
        f"{case['name']}: compare_iid returned {result}, expected {winner} "
        f"({case['expected']['reason']})"
    )


def test_rejects_non_eui64_lengths(vectors: list[dict]) -> None:
    """compare_iid guards its 8-byte contract even though vectors are valid."""
    with pytest.raises(ValueError):
        compare_iid(b"\x00" * 7, b"\x00" * 8)
    with pytest.raises(ValueError):
        compare_iid(b"\x00" * 8, b"\x00" * 9)
    del vectors
