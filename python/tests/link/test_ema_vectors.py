# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test EMA (Exponential Moving Average) computation against cross-language vectors.

Validates the Python ema_update implementation against ccp_ema_update_integer.json
test vectors. The EMA formula is: new_avg = avg + ((sample - avg) >> 2) with alpha=1/4.

Cross-language oracle: Python uses float arithmetic (diff * 0.25) while Rust uses
Q16.16 fixed-point with arithmetic right shift (diff >> 2). For integer inputs,
both produce identical EMA update results.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.adaptive_sf import ema_update

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load_vectors() -> dict:
    """Load the EMA test vectors."""
    return json.loads((VECTORS_DIR / "ccp_ema_update_integer.json").read_text())


def _single_update_cases():
    """Generate test cases for single EMA updates."""
    doc = _load_vectors()
    assert doc["format_version"] == 2
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v.get("type") != "sequence"
    ]


def _sequence_cases():
    """Generate test cases for sequence EMA updates."""
    doc = _load_vectors()
    assert doc["format_version"] == 2
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v.get("type") == "sequence"
    ]


@pytest.mark.parametrize("name,vector", _single_update_cases())
def test_ema_single_update(name: str, vector: dict) -> None:
    """Validate single EMA update against test vector.

    Tests that ema_update(avg, sample) produces the expected floating-point
    result matching the Q16.16 fixed-point computation.
    """
    inp = vector["input"]
    out = vector["output"]

    avg = float(inp["avg"])
    sample = inp["sample"]

    # Python ema_update uses float arithmetic
    result = ema_update(avg, sample)

    # Verify the result matches the expected float value
    # Allow small tolerance for floating-point precision
    expected_float = out["new_avg_float"]
    assert abs(result - expected_float) < 1e-10, (
        f"{name}: ema_update({avg}, {sample}) = {result}, expected {expected_float}"
    )

    # Verify diff computation is correct
    diff = sample - inp["avg"]
    assert diff == out["diff"], f"{name}: diff mismatch"


@pytest.mark.parametrize("name,vector", _sequence_cases())
def test_ema_sequence_update(name: str, vector: dict) -> None:
    """Validate EMA update sequence against test vector.

    Tests that applying a sequence of samples produces the expected
    final average value.
    """
    inp = vector["input"]
    out = vector["output"]

    avg = float(inp["initial_avg"])
    samples = inp["samples"]

    # Apply each sample in sequence
    for sample in samples:
        avg = ema_update(avg, sample)

    # Verify final result matches expected
    expected_float = out["final_avg_float"]
    assert abs(avg - expected_float) < 1e-10, (
        f"{name}: final avg = {avg}, expected {expected_float}"
    )


def test_ema_vector_file_integrity() -> None:
    """Verify the vector file structure and coverage."""
    doc = _load_vectors()
    assert doc["format_version"] == 2
    assert doc["vector_type"] == "ccp_ema_update"
    assert "EMA" in doc["description"]

    vectors = doc["vectors"]
    names = {v["name"] for v in vectors}

    # Verify required coverage categories
    assert "basic_positive_diff_divisible_by_4" in names
    assert "negative_diff_divisible_by_4" in names
    assert "small_diff_not_divisible_by_4" in names
    assert "negative_diff_not_divisible_by_4" in names
    assert "boundary_sf12_snr_critical" in names
    assert "convergence_sequence_positive" in names

    # Verify all vectors have required fields
    for v in vectors:
        assert "name" in v
        assert "description" in v
        assert "input" in v
        assert "output" in v
        if v.get("type") == "sequence":
            assert "initial_avg" in v["input"]
            assert "samples" in v["input"]
            assert "final_avg_float" in v["output"]
            assert "intermediate_avg_fp" in v["output"]
        else:
            assert "avg" in v["input"]
            assert "sample" in v["input"]
            assert "new_avg_float" in v["output"]
            assert "new_avg_fp" in v["output"]


def test_ema_integer_rounding_awareness() -> None:
    """Document the integer rounding divergence between Python and Rust.

    This test documents the known divergence: Python's int() truncates
    towards zero while Rust's avg() method uses round-half-up.

    For the EMA update itself, both implementations produce identical
    results. The divergence only manifests when converting to integer
    for SF threshold comparisons.
    """
    doc = _load_vectors()

    divergent_cases = []
    for v in doc["vectors"]:
        if v.get("type") == "sequence":
            continue
        out = v["output"]
        round_half_up = out["new_avg_int_round_half_up"]
        truncate = out["new_avg_int_truncate"]
        if round_half_up != truncate:
            divergent_cases.append(v["name"])

    # These cases are expected to diverge on integer conversion
    expected_divergent = {
        "small_diff_not_divisible_by_4",
        "negative_diff_not_divisible_by_4",
        "diff_minus_7_shows_rounding_divergence",
        "boundary_sf9_snr_good",
        "i8_boundary_max",
    }

    assert set(divergent_cases) == expected_divergent, (
        f"Unexpected divergent cases: {set(divergent_cases) ^ expected_divergent}"
    )
