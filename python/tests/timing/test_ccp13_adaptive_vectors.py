# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume CCP-13 adaptive duty cycle vectors (spec 02a.9)."""

from __future__ import annotations

import json
import zlib
from pathlib import Path
from typing import Any

import pytest

from lichen.timing.duty_cycle import adaptive_duty_permille

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "ccp13.json"


def _load_adaptive_vectors() -> list[dict[str, Any]]:
    """Load adaptive duty vectors that have expected_duty_permille field."""
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert document["format_version"] == 2
    return [v for v in document["vectors"] if "expected_duty_permille" in v]


def _compute_crc32(density: int, region: int) -> str:
    """Compute the input CRC32 oracle for vector integrity check."""
    payload = f"density={density},region={region}".encode("ascii")
    return f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"


@pytest.mark.parametrize(
    "vector",
    _load_adaptive_vectors(),
    ids=lambda v: v["name"],
)
def test_adaptive_duty_permille_matches_vector(vector: dict[str, Any]) -> None:
    """Python adaptive_duty_permille matches canonical CCP-13 vectors."""
    density = vector["density"]
    region = vector["region"]
    expected = vector["expected_duty_permille"]

    # Verify input CRC32 oracle (catches accidental vector edits)
    if "input_crc32" in vector:
        computed_crc = _compute_crc32(density, region)
        assert computed_crc == vector["input_crc32"], (
            f"input CRC mismatch: computed {computed_crc}, "
            f"expected {vector['input_crc32']}"
        )

    # Test the implementation
    result = adaptive_duty_permille(density, region)
    assert result == expected, (
        f"adaptive_duty_permille({density}, {region}) = {result}, "
        f"expected {expected}"
    )


def test_adaptive_vectors_exist() -> None:
    """Ensure the adaptive duty vectors are present in ccp13.json."""
    vectors = _load_adaptive_vectors()
    assert len(vectors) >= 10, "Expected at least 10 adaptive duty vectors"


def test_all_density_boundaries_covered() -> None:
    """Ensure vectors cover sparse/moderate/dense boundaries for both regions."""
    vectors = _load_adaptive_vectors()
    names = {v["name"] for v in vectors}

    # Check that key boundaries are tested
    required = [
        "sparse_region0",
        "sparse_boundary_region0",
        "moderate_start_region0",
        "moderate_end_region0",
        "dense_start_region0",
        "sparse_region1",
        "moderate_region1",
        "dense_start_region1",
    ]
    for name in required:
        assert name in names, f"Missing required vector: {name}"
