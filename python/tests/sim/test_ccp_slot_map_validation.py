# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test CCP slot_map validation against test vectors.

Validates slot_map CBOR array per spec/02a-coordinated-capacity.md:80:
- Each entry must be < num_slots
- Array must be sorted ascending
- Duplicates are rejected (sorted-unique invariant)
- Empty array is valid (no TX slots)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "ccp_slot_map_validation.json"


def validate_slot_map(slot_map: list[int], num_slots: int) -> tuple[bool, str | None]:
    """Validate a slot_map array per CCP spec.

    Args:
        slot_map: List of u8 slot indices
        num_slots: Maximum number of slots (entries must be < num_slots)

    Returns:
        Tuple of (is_valid, error_type or None)
    """
    if not slot_map:
        return (True, None)

    prev = -1
    for slot in slot_map:
        if slot >= num_slots:
            return (False, "slot_out_of_bounds")
        if slot < prev:
            return (False, "unsorted")
        if slot == prev:
            return (False, "duplicate")
        prev = slot

    return (True, None)


def load_vectors():
    """Load test vectors from JSON file."""
    with open(VECTORS_PATH) as f:
        doc = json.load(f)
    return doc["vectors"]


@pytest.fixture(scope="module")
def vectors():
    return load_vectors()


def test_vectors_file_exists():
    """Ensure the test vectors file exists and is valid JSON."""
    assert VECTORS_PATH.is_file(), f"missing {VECTORS_PATH}"
    doc = json.loads(VECTORS_PATH.read_text())
    assert "vectors" in doc
    assert len(doc["vectors"]) > 0


@pytest.mark.parametrize(
    "vector",
    load_vectors(),
    ids=lambda v: v["name"],
)
def test_slot_map_validation(vector):
    """Test slot_map validation against each vector."""
    slot_map = vector["slot_map"]
    num_slots = vector["num_slots"]
    expected_valid = vector["expected_valid"]
    expected_error = vector["expected_error"]

    is_valid, error = validate_slot_map(slot_map, num_slots)

    assert is_valid == expected_valid, (
        f"{vector['name']}: expected valid={expected_valid}, got {is_valid}"
    )

    if not expected_valid:
        assert error == expected_error, (
            f"{vector['name']}: expected error={expected_error}, got {error}"
        )


def test_slot_out_of_bounds_specific():
    """Direct test for out-of-bounds slot detection."""
    is_valid, error = validate_slot_map([0, 3, 8, 12], 8)
    assert not is_valid
    assert error == "slot_out_of_bounds"


def test_slot_unsorted_specific():
    """Direct test for unsorted array detection."""
    is_valid, error = validate_slot_map([3, 1, 5, 2], 16)
    assert not is_valid
    assert error == "unsorted"


def test_slot_duplicate_specific():
    """Direct test for duplicate detection."""
    is_valid, error = validate_slot_map([1, 1, 3], 8)
    assert not is_valid
    assert error == "duplicate"


def test_slot_empty_valid():
    """Empty slot_map is always valid."""
    is_valid, error = validate_slot_map([], 8)
    assert is_valid
    assert error is None


def test_slot_boundary_max():
    """Slot at num_slots-1 is valid, slot at num_slots is not."""
    is_valid, _ = validate_slot_map([7], 8)
    assert is_valid

    is_valid, error = validate_slot_map([8], 8)
    assert not is_valid
    assert error == "slot_out_of_bounds"


def test_all_vectors_have_required_fields():
    """Ensure all vectors have the required fields."""
    vectors = load_vectors()
    required_fields = {"name", "num_slots", "slot_map", "expected_valid", "expected_error"}

    for v in vectors:
        missing = required_fields - set(v.keys())
        assert not missing, f"Vector {v.get('name', '?')} missing fields: {missing}"
