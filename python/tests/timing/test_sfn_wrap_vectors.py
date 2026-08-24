# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Vector-driven tests for SFN wrap and slot_for (spec section 14.7).

Loads test vectors from test/vectors/ccp_sfn_wrap_slot_hash.json and validates
Python implementation against known-good values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.timing.sfn import hash_32, sfn_delta, slot_for

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "ccp_sfn_wrap_slot_hash.json"


@pytest.fixture(scope="module")
def vectors() -> list[dict[str, Any]]:
    """Load test vectors from JSON file."""
    with open(VECTORS_PATH) as f:
        data = json.load(f)
    assert data["format_version"] == 2
    return data["vectors"]


def _parse_hex(value: str) -> int:
    """Parse hex string (with or without 0x prefix) to int."""
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)


class TestHash32Vectors:
    """Test hash_32 against reference vectors."""

    def test_hash_reference(self, vectors: list[dict[str, Any]]) -> None:
        """Verify hash_32 produces expected reference value."""
        vec = next(v for v in vectors if v["name"] == "hash_32_reference")
        eui = bytes.fromhex(vec["eui64_hex"])
        expected = _parse_hex(vec["expected_hash_32"])
        result = hash_32(eui)
        assert result == expected, f"hash_32 mismatch: got {hex(result)}, expected {hex(expected)}"

    def test_zeros_eui_hash(self, vectors: list[dict[str, Any]]) -> None:
        """Verify hash_32 for all-zeros EUI."""
        vec = next(v for v in vectors if v["name"] == "slot_for_zeros_eui")
        eui = bytes.fromhex(vec["eui64_hex"])
        expected = _parse_hex(vec["expected_hash_32"])
        result = hash_32(eui)
        assert result == expected

    def test_ones_eui_hash(self, vectors: list[dict[str, Any]]) -> None:
        """Verify hash_32 for all-ones EUI."""
        vec = next(v for v in vectors if v["name"] == "slot_for_ones_eui")
        eui = bytes.fromhex(vec["eui64_hex"])
        expected = _parse_hex(vec["expected_hash_32"])
        result = hash_32(eui)
        assert result == expected


class TestSlotForVectors:
    """Test slot_for against reference vectors."""

    @pytest.mark.parametrize(
        "vector_name",
        [
            "slot_for_sfn_zero",
            "slot_for_sfn_one",
            "slot_for_sfn_max",
            "slot_for_wrapping_sum_before_non_power_of_two_modulus",
            "slot_for_sfn_after_wrap",
            "slot_for_different_num_slots_8",
            "slot_for_different_num_slots_32",
            "slot_for_zeros_eui",
            "slot_for_ones_eui",
        ],
    )
    def test_slot_for_basic(self, vectors: list[dict[str, Any]], vector_name: str) -> None:
        """Test basic slot_for calculations."""
        vec = next(v for v in vectors if v["name"] == vector_name)
        eui = bytes.fromhex(vec["eui64_hex"])
        sfn = vec["sfn"]
        num_slots = vec["num_slots"]
        expected = vec["expected_slot"]
        result = slot_for(eui, sfn, num_slots)
        assert result == expected, (
            f"{vector_name}: slot_for({vec['eui64_hex']}, {sfn}, {num_slots}) = {result}, "
            f"expected {expected}"
        )

    def test_sfn_mask_to_32bit(self, vectors: list[dict[str, Any]]) -> None:
        """Test that large SFN values are masked to 32 bits."""
        vec = next(v for v in vectors if v["name"] == "sfn_mask_to_32bit")
        eui = bytes.fromhex(vec["eui64_hex"])
        sfn_large = vec["sfn_large"]
        num_slots = vec["num_slots"]
        expected = vec["expected_slot"]
        result = slot_for(eui, sfn_large, num_slots)
        assert result == expected, (
            f"Large SFN {hex(sfn_large)} should mask to 0 and produce slot {expected}, got {result}"
        )

    def test_sfn_mask_large_value(self, vectors: list[dict[str, Any]]) -> None:
        """Test that large SFN values mask correctly."""
        vec = next(v for v in vectors if v["name"] == "sfn_mask_large_value")
        eui = bytes.fromhex(vec["eui64_hex"])
        sfn_large = vec["sfn_large"]
        num_slots = vec["num_slots"]
        expected = vec["expected_slot"]
        result = slot_for(eui, sfn_large, num_slots)
        assert result == expected

    def test_full_wrap_sequence(self, vectors: list[dict[str, Any]]) -> None:
        """Test continuous slot rotation across SFN wrap boundary."""
        vec = next(v for v in vectors if v["name"] == "full_wrap_sequence")
        eui = bytes.fromhex(vec["eui64_hex"])
        num_slots = vec["num_slots"]
        for entry in vec["sequence"]:
            sfn = entry["sfn"]
            expected = entry["expected_slot"]
            result = slot_for(eui, sfn, num_slots)
            assert result == expected, (
                f"At SFN={sfn} ({entry['sfn_hex']}): got slot {result}, expected {expected}"
            )

    def test_sfn_wrap_continuity(self, vectors: list[dict[str, Any]]) -> None:
        """Test that slot rotation is continuous across SFN wrap."""
        vec = next(v for v in vectors if v["name"] == "sfn_wrap_continuity")
        eui = bytes.fromhex(vec["eui64_hex"])
        num_slots = vec["num_slots"]
        last_sfn = vec["last_sfn"]
        current_sfn = vec["current_sfn"]
        expected_delta = vec["expected_delta"]
        slot_at_last = slot_for(eui, last_sfn, num_slots)
        slot_at_current = slot_for(eui, current_sfn, num_slots)
        assert slot_at_last == vec["expected_slot_at_last"]
        assert slot_at_current == vec["expected_slot_at_current"]
        assert slot_at_current == (slot_at_last + expected_delta) % num_slots


class TestSfnDeltaVectors:
    """Test sfn_delta against reference vectors."""

    @pytest.mark.parametrize(
        "vector_name",
        [
            "sfn_delta_wrap_minimal",
            "sfn_delta_wrap_multi",
            "sfn_delta_wrap_near",
            "sfn_delta_no_wrap",
            "sfn_delta_zero",
            "sfn_delta_large_forward",
            "sfn_delta_apparent_backward",
        ],
    )
    def test_sfn_delta(self, vectors: list[dict[str, Any]], vector_name: str) -> None:
        """Test sfn_delta calculations."""
        vec = next(v for v in vectors if v["name"] == vector_name)
        current = vec["current_sfn"]
        last = vec["last_sfn"]
        expected = vec["expected_delta"]
        result = sfn_delta(current, last)
        assert result == expected, (
            f"{vector_name}: sfn_delta({current}, {last}) = {result}, expected {expected}"
        )


class TestSlotRotationProperty:
    """Property-based tests for slot rotation invariants."""

    def test_sfn_increment_rotates_slot(self, vectors: list[dict[str, Any]]) -> None:
        """Verify that SFN+1 always rotates slot by 1 (mod num_slots)."""
        vec = next(v for v in vectors if v["name"] == "slot_for_sfn_zero")
        eui = bytes.fromhex(vec["eui64_hex"])
        num_slots = vec["num_slots"]
        for sfn in [0, 1, 100, 0xFFFFFFFF - 1, 0xFFFFFFFF]:
            s0 = slot_for(eui, sfn, num_slots)
            s1 = slot_for(eui, (sfn + 1) & 0xFFFFFFFF, num_slots)
            expected = (s0 + 1) % num_slots
            assert s1 == expected, f"At SFN={sfn}: slot did not rotate by 1"

    def test_delta_equals_slot_difference(self, vectors: list[dict[str, Any]]) -> None:
        """Verify that sfn_delta equals the slot rotation distance."""
        vec = next(v for v in vectors if v["name"] == "slot_for_sfn_zero")
        eui = bytes.fromhex(vec["eui64_hex"])
        num_slots = vec["num_slots"]
        test_pairs = [
            (0, 5),
            (100, 150),
            (0xFFFFFFFF, 2),
            (0xFFFFFFFE, 5),
        ]
        for last, current in test_pairs:
            delta = sfn_delta(current, last)
            s_last = slot_for(eui, last, num_slots)
            s_current = slot_for(eui, current, num_slots)
            expected_slot = (s_last + delta) % num_slots
            assert s_current == expected_slot, (
                f"For SFN {last} -> {current}: "
                f"slot_for({current}) = {s_current}, "
                f"but (slot_for({last}) + delta) % {num_slots} = {expected_slot}"
            )
