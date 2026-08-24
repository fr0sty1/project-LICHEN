# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test canonical CCP beacon and TDMA slot vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.ccp import ema_update, ema_update_integer
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

    The expected slot is a language-neutral wire-profile oracle.
    """
    inp = vector["input"]
    out = vector["output"]

    eui64 = bytes.fromhex(inp["eui64"])
    sfn = inp["sfn"]
    num_slots = inp["num_slots"]

    computed = slot_for(eui64, sfn, num_slots)
    expected = out["slot"]

    assert computed == expected, (
        f"{name}: slot mismatch: got {computed}, expected {expected}"
    )

    # Verify hash_32 if present
    if "hash_32" in out:
        h = hash_32(eui64)
        assert h == out["hash_32"], (
            f"{name}: hash_32 mismatch: got {h}, expected {out['hash_32']}"
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

    This is the expected behavior per spec section 14.7.
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
    """Verify that Python slot_for respects the num_slots parameter."""
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


def test_beacon_header_layout_and_example_are_exact() -> None:
    vectors = {vector["name"]: vector for vector in _load_vectors()["vectors"]}
    layout = vectors["beacon_header_layout"]["expected_format"]
    assert layout == {
        "epoch_offset": 0,
        "epoch_size": 4,
        "num_slots_offset": 4,
        "num_slots_size": 1,
        "sfn_offset": 5,
        "sfn_size": 4,
        "timestamp_offset": 9,
        "timestamp_size": 4,
        "flags_offset": 13,
        "flags_size": 1,
        "rx_chains_offset": 14,
        "rx_chains_size": 1,
        "setup_window_offset": 15,
        "setup_window_size": 2,
        "occupied_time_offset": 17,
        "occupied_time_size": 2,
        "guard_offset": 19,
        "guard_size": 1,
        "channel_mask_offset": 20,
        "channel_mask_size": 4,
        "total_size": 24,
    }

    case = vectors["beacon_wire_example"]
    wire = bytes.fromhex(case["output"]["header_hex"])
    values = case["input"]
    assert len(wire) == layout["total_size"]
    assert int.from_bytes(wire[0:4], "big") == values["epoch"]
    assert wire[4] == values["num_slots"]
    assert int.from_bytes(wire[5:9], "big") == values["sfn"]
    assert int.from_bytes(wire[9:13], "big") == values["timestamp"]
    assert wire[13] == values["flags"]
    assert wire[14] == values["rx_chains"]
    assert int.from_bytes(wire[15:17], "big") == values["setup_window"]
    assert int.from_bytes(wire[17:19], "big") == values["occupied_time"]
    assert wire[19] == values["guard"] == 50
    assert int.from_bytes(wire[20:24], "big") == values["channel_mask"]


@pytest.mark.parametrize("name,vector", _ema_cases())
def test_ema_vectors_are_exact_and_match_production(name: str, vector: dict) -> None:
    """Check literal Q16.16 steps independently, then check both Python APIs."""
    inputs = vector["input"]
    expected = vector["output"]
    shift = inputs["alpha_shift"]

    oracle_avg = inputs["initial_avg_q16"]
    observed_steps: list[int] = []
    for sample in inputs["samples"]:
        sample_q16 = sample * 65536
        oracle_avg += (sample_q16 - oracle_avg) >> shift
        observed_steps.append(oracle_avg)
    assert observed_steps == expected["step_results_q16"], name
    assert oracle_avg == expected["final_result_q16"], name

    production_q16 = inputs["initial_avg_q16"]
    production_float = inputs["initial_avg_q16"] / 65536
    for sample in inputs["samples"]:
        production_q16 = ema_update_integer(production_q16, sample * 65536)
        production_float = ema_update(production_float, sample)
    assert production_q16 == expected["final_result_q16"], name
    assert production_float == expected["final_result_decimal"], name
