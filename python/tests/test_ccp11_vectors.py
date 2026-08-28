# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Drive Python CCP-11 Dynamic Channel Selection from shared cross-language vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.ccp import hash_32, select_channel

_VECTOR_PATH = Path(__file__).parents[2] / "test" / "vectors" / "ccp11.json"
_DOC: dict[str, Any] = json.loads(_VECTOR_PATH.read_text())
_VECTORS: list[dict[str, Any]] = _DOC["vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_ccp11_dynamic_channel_selection(vector: dict[str, Any]) -> None:
    """Validate select_channel against CCP-11 dynamic channel selection vectors."""
    inputs = vector["input"]
    expected = vector["expected"]

    eui64 = bytes.fromhex(inputs["eui64_hex"].lower())
    epoch = inputs["epoch"]
    density = inputs["density"]
    n_channels = inputs["n_channels"]

    # Verify hash intermediate
    hash_input = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
    computed_hash = hash_32(hash_input)
    expected_hash = int(expected["hash_32"], 16)
    assert computed_hash == expected_hash, (
        f"hash_32 mismatch: got {computed_hash:08x}, expected {expected['hash_32']}"
    )

    # Verify channel selection
    channel = select_channel(eui64, epoch, density, n_channels)
    assert channel == expected["channel"], (
        f"channel mismatch: got {channel}, expected {expected['channel']}"
    )


def test_ccp11_density_boundary_coverage() -> None:
    """Verify CCP-11 vectors cover the critical density=8 boundary."""
    names = {v["name"] for v in _VECTORS}
    densities = {v["input"]["density"] for v in _VECTORS}

    # Critical boundary tests must exist
    assert "density_8_boundary_no_fallback" in names
    assert "density_9_triggers_ch0_fallback" in names

    # Must have both sides of the boundary
    assert 8 in densities, "Missing density=8 boundary test"
    assert 9 in densities, "Missing density=9 (first fallback) test"


def test_ccp11_ch0_fallback_vectors_correct() -> None:
    """Verify CH0 fallback vectors return channel 0."""
    fallback_vectors = [v for v in _VECTORS if v["input"]["density"] > 8]
    assert len(fallback_vectors) >= 2, "Need at least 2 CH0 fallback test cases"

    for v in fallback_vectors:
        assert v["expected"]["channel"] == 0, (
            f"{v['name']}: density {v['input']['density']} > 8 should return CH0"
        )


def test_ccp11_non_fallback_vectors_nonzero() -> None:
    """Verify non-fallback vectors return configured data channels."""
    normal_vectors = [
        v
        for v in _VECTORS
        if v["input"]["density"] <= 8 and v["input"]["n_channels"] > 1
    ]
    assert len(normal_vectors) >= 5, "Need at least 5 normal selection test cases"

    for v in normal_vectors:
        n_channels = v["input"]["n_channels"]
        expected_ch = v["expected"]["channel"]
        assert 1 <= expected_ch < n_channels, (
            f"{v['name']}: channel {expected_ch} not in [1, {n_channels})"
        )
