# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test vectors for CCP beacon format and TDMA slot assignment divergence.

These vectors expose implementation differences between Python and Rust:
- Python slot_for: (hash_32(eui64) + sfn) % num_slots
- Rust TdmaScheduler::slot_for: lichen_hash_32(eui) % 16 (ignores SFN, hardcodes 16)

Cross-language oracle: vectors include expected values from both implementations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.timing.sfn import hash_32, slot_for

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "ccp_beacon_format.json"


def _load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def _slot_selection_cases():
    doc = _load_vectors()
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v.get("type") == "slot_selection"
    ]


def _hash_32_cases():
    doc = _load_vectors()
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v.get("type") == "hash_32"
    ]


def _ema_cases():
    doc = _load_vectors()
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v.get("type") == "ema"
    ]


def test_vectors_file_exists() -> None:
    assert VECTORS_PATH.is_file(), f"missing {VECTORS_PATH}"


def test_vectors_format_version() -> None:
    doc = _load_vectors()
    assert doc["format_version"] == 2


@pytest.mark.parametrize("name,vector", _slot_selection_cases())
def test_slot_selection_vector(name: str, vector: dict) -> None:
    """Validate Python slot_for against expected values.

    Note: These vectors document known divergence between Python and Rust.
    The 'slot_python' value is what Python produces; 'slot_rust_expected' is
    what Rust produces (or would produce with its current implementation).
    """
    inp = vector["input"]
    out = vector["output"]

    eui64 = bytes.fromhex(inp["eui64"])
    sfn = inp["sfn"]
    num_slots = inp["num_slots"]

    # Compute Python slot
    computed = slot_for(eui64, sfn, num_slots)
    expected_python = out["slot_python"]

    assert computed == expected_python, (
        f"{name}: Python slot mismatch: got {computed}, expected {expected_python}"
    )

    # Verify hash_32 if present
    if "hash_32" in out:
        h = hash_32(eui64)
        assert h == out["hash_32"], (
            f"{name}: hash_32 mismatch: got {h}, expected {out['hash_32']}"
        )


@pytest.mark.parametrize("name,vector", _slot_selection_cases())
def test_slot_selection_divergence_documented(name: str, vector: dict) -> None:
    """Verify that divergence between Python and Rust is correctly documented."""
    out = vector["output"]

    slot_python = out["slot_python"]
    slot_rust = out["slot_rust_expected"]
    diverges = out.get("diverges", False)

    if diverges:
        assert slot_python != slot_rust, (
            f"{name}: marked as diverging but slots match: {slot_python}"
        )
    else:
        assert slot_python == slot_rust, (
            f"{name}: not marked as diverging but slots differ: "
            f"Python={slot_python}, Rust={slot_rust}"
        )


@pytest.mark.parametrize("name,vector", _hash_32_cases())
def test_hash_32_vector(name: str, vector: dict) -> None:
    """Validate FNV-1a32 hash implementation against test vectors."""
    data = bytes.fromhex(vector["input"]["data_hex"])
    expected = vector["output"]["hash_32"]

    computed = hash_32(data)
    assert computed == expected, (
        f"{name}: hash_32 mismatch: got 0x{computed:08x}, expected 0x{expected:08x}"
    )


def test_hash_32_fnv1a_properties() -> None:
    """Cross-validate FNV-1a32 hash properties."""
    # Empty input returns offset basis
    assert hash_32(b"") == 0x811C9DC5

    # Single zero byte
    assert hash_32(b"\x00") == 0x050C5D1F

    # Deterministic
    data = b"\x00\x11\x22\x33\x44\x55\x66\x77"
    assert hash_32(data) == hash_32(data)

    # Different inputs produce different hashes (usually)
    assert hash_32(b"\x01") != hash_32(b"\x02")


def test_slot_for_sfn_rotation() -> None:
    """Verify that Python slot_for rotates with SFN as per spec.

    This is the expected behavior per spec section 14.7. The Rust
    implementation currently does not rotate with SFN, which is a bug.
    """
    eui = bytes.fromhex("0011223344556677")
    num_slots = 16

    # Slots should change as SFN increases
    slots = [slot_for(eui, sfn, num_slots) for sfn in range(num_slots)]

    # With 16 slots and num_slots=16, we should cycle through all slots
    # as SFN increases by 1 each time (since we add SFN to hash)
    # The sequence should be: 13, 14, 15, 0, 1, 2, ... (wrapping)
    base = slot_for(eui, 0, num_slots)
    expected = [(base + i) % num_slots for i in range(num_slots)]

    assert slots == expected, (
        f"Slot rotation mismatch:\n  got:      {slots}\n  expected: {expected}"
    )


def test_slot_for_num_slots_respected() -> None:
    """Verify that Python slot_for respects the num_slots parameter.

    The Rust implementation hardcodes num_slots=16, which is a bug.
    """
    eui = bytes.fromhex("aabbccddeeff0011")

    # With different num_slots, slots should be in correct range
    for num_slots in [4, 8, 12, 16, 32]:
        slot = slot_for(eui, 0, num_slots)
        assert 0 <= slot < num_slots, (
            f"slot {slot} out of range [0, {num_slots}) for num_slots={num_slots}"
        )


def test_slot_for_eui64_validation() -> None:
    """Verify EUI64 length validation."""
    with pytest.raises(ValueError, match="eui64 must be 8 bytes"):
        slot_for(b"\x00" * 7, 0, 16)

    with pytest.raises(ValueError, match="eui64 must be 8 bytes"):
        slot_for(b"\x00" * 9, 0, 16)


def test_slot_for_num_slots_validation() -> None:
    """Verify num_slots validation."""
    eui = bytes.fromhex("0011223344556677")

    with pytest.raises(ValueError, match="num_slots must be positive"):
        slot_for(eui, 0, 0)

    with pytest.raises(ValueError, match="num_slots must be positive"):
        slot_for(eui, 0, -1)
