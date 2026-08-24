# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CCP oracle implementation against spec test vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.ccp import (
    adaptive_sf_select,
    ema_update,
    ema_update_integer,
    hash_32,
    now,
    select_channel,
    slot_hash,
    synchronized_hop,
)

VECTORS_DIR = Path(__file__).parent.parent.parent / "test" / "vectors"


def _load(name: str) -> dict:
    """Load a test vector file."""
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


# --- hash_32 tests ---


def test_hash_32_basis():
    """FNV-1a32 basis constant is correct."""
    # Empty input should return the basis
    # Actually FNV-1a processes each byte, so empty returns basis
    assert hash_32(b"") == 0x811C9DC5


def test_hash_32_known_values():
    """hash_32 matches known FNV-1a32 test vectors."""
    # Standard FNV-1a test vectors
    assert hash_32(b"") == 0x811C9DC5
    # Test with simple input
    assert hash_32(b"\x00") == 0x050C5D1F


# --- now() tests ---


def test_now_passthrough():
    """now() returns SFN masked to u32 range."""
    assert now(0) == 0
    assert now(1) == 1
    assert now(0xFFFFFFFF) == 0xFFFFFFFF
    # Overflow wraps
    assert now(0x100000000) == 0


def test_now_wrap_arithmetic():
    """now() handles u32 wrap correctly."""
    # Near-wrap value
    assert now(0xFFFFFFF0) == 0xFFFFFFF0
    # At wrap
    assert now(0xFFFFFFFF) == 0xFFFFFFFF


# --- select_channel tests ---


def _select_channel_cases():
    """Load select_channel endianness test vectors."""
    doc = _load("ccp_select_channel_endianness.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _select_channel_cases())
def test_select_channel_endianness(name: str, vector: dict) -> None:
    """Validate select_channel against endianness test vectors."""
    inp = vector["input"]
    out = vector["output"]
    inter = vector.get("intermediate", {})

    eui64_hex = inp["eui64_hex"]
    eui64 = bytes.fromhex(eui64_hex.lower())
    epoch = inp["epoch"]
    n_channels = inp["n_channels"]

    # Verify hash intermediate if present
    if "hash_32" in inter:
        data = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
        assert hash_32(data) == inter["hash_32"], f"{name}: hash_32 mismatch"

    # Test with density=0 (not > 8, so normal path)
    channel = select_channel(eui64, epoch, density=0, n_channels=n_channels)
    assert channel == out["channel"], f"{name}: channel mismatch"


def test_select_channel_density_fallback():
    """select_channel returns 0 when density > 8."""
    eui64 = bytes.fromhex("0011223344556677")
    # density > 8 should return CH0
    assert select_channel(eui64, epoch=0, density=9, n_channels=8) == 0
    assert select_channel(eui64, epoch=0, density=10, n_channels=8) == 0
    assert select_channel(eui64, epoch=0, density=100, n_channels=8) == 0


def test_select_channel_min_3_channels():
    """select_channel uses min 3 channels for modulo."""
    eui64 = bytes.fromhex("0011223344556677")
    # With n_channels=1, should still use max(1, 3) = 3
    ch = select_channel(eui64, epoch=0, density=0, n_channels=1)
    # Result should be in [1, 3]
    assert 1 <= ch <= 3


# --- adaptive_sf_select tests ---


def _ccp16_cases():
    """Load CCP16 test vectors."""
    doc = _load("ccp16.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_cases())
def test_adaptive_sf_select_ccp16(name: str, vector: dict) -> None:
    """Validate adaptive_sf_select against ccp16.json vectors."""
    inp = vector.get("input", vector)
    out = vector.get("output", vector)

    density = inp["density"]
    ema_snr = inp.get("snr_ema", inp.get("snr_db", 5.0))
    load_factor = inp.get("load_factor", 0.0)

    result = adaptive_sf_select(
        assigned_sf=None,
        density=density,
        ema_snr=ema_snr,
        ema_loss=0.0,
        utilization=0,
        load_factor=load_factor,
    )

    expected_sf = out.get("sf", 10)
    assert result.sf == expected_sf, (
        f"{name}: SF mismatch (got {result.sf}, expected {expected_sf})"
    )
    assert result.tx_allowed is True, f"{name}: tx_allowed should be True"


def _ccp16_utilization_cases():
    """Load CCP16 utilization test vectors."""
    doc = _load("ccp16_utilization.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_utilization_cases())
def test_adaptive_sf_select_utilization(name: str, vector: dict) -> None:
    """Validate adaptive_sf_select against utilization vectors."""
    inp = vector["input"]
    out = vector["output"]

    result = adaptive_sf_select(
        assigned_sf=inp.get("assigned_sf", 10),
        density=inp.get("density", 5),
        ema_snr=inp.get("ema_snr", 5.0),
        ema_loss=inp.get("ema_loss", 0.0),
        utilization=inp.get("utilization", 0),
        load_factor=0.0,
    )

    assert result.sf == out["sf"], f"{name}: SF mismatch (got {result.sf}, expected {out['sf']})"
    assert result.tx_allowed == out["tx_allowed"], f"{name}: tx_allowed mismatch"


def _ccp16_ema_loss_cases():
    """Load CCP16 EMA loss threshold test vectors."""
    doc = _load("ccp16_ema_loss_threshold.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_ema_loss_cases())
def test_adaptive_sf_select_ema_loss(name: str, vector: dict) -> None:
    """Validate adaptive_sf_select against EMA loss threshold vectors."""
    inp = vector["input"]
    out = vector["output"]

    result = adaptive_sf_select(
        assigned_sf=inp.get("assigned_sf", 10),
        density=inp.get("density", 5),
        ema_snr=inp.get("ema_snr", 5.0),
        ema_loss=inp.get("ema_loss", 0.0),
        utilization=inp.get("utilization", 0),
        load_factor=0.0,
    )

    assert result.sf == out["sf"], f"{name}: SF mismatch (got {result.sf}, expected {out['sf']})"


# --- ema_update tests ---


def test_ema_update_basic():
    """ema_update computes weighted average correctly."""
    # With alpha=0.25, new = 0.75 * old + 0.25 * sample
    assert ema_update(0.0, 4.0) == 1.0  # 0 + 0.25 * 4 = 1
    assert ema_update(4.0, 0.0) == 3.0  # 4 + 0.25 * -4 = 3
    assert ema_update(10.0, 10.0) == 10.0  # No change when equal


def test_ema_update_convergence():
    """ema_update converges toward sample over time."""
    avg = 0.0
    for _ in range(20):
        avg = ema_update(avg, 100.0)
    # After many iterations, should be close to 100
    assert 99.0 < avg < 100.0


def test_ema_update_integer():
    """ema_update_integer uses arithmetic right-shift."""
    # (sample - avg) >> 2 = (sample - avg) / 4 (rounded toward -inf)
    assert ema_update_integer(0, 4) == 1  # 0 + (4-0)>>2 = 0 + 1 = 1
    assert ema_update_integer(4, 0) == 3  # 4 + (0-4)>>2 = 4 + (-1) = 3
    assert ema_update_integer(10, 10) == 10  # No change


def test_ema_update_integer_negative():
    """ema_update_integer handles negative differences."""
    # Python's >> is arithmetic right-shift for negative numbers
    # -4 >> 2 = -1 (rounds toward -inf)
    assert ema_update_integer(100, 96) == 99  # 100 + (-4>>2) = 100 - 1 = 99


# --- synchronized_hop tests ---


def test_synchronized_hop_integration():
    """synchronized_hop combines channel and SF selection."""
    eui64 = bytes.fromhex("0011223344556677")
    channel, sf, tx_allowed = synchronized_hop(
        eui64=eui64,
        epoch=0,
        density=5,
        ema_snr=5.0,
        n_channels=8,
    )

    # Channel should be in valid range (not CH0 since density <= 8)
    assert 1 <= channel <= 8
    # SF should be default 10 with no conditions triggered
    assert sf == 10
    assert tx_allowed is True


def test_synchronized_hop_high_density():
    """synchronized_hop returns CH0 for high density."""
    eui64 = bytes.fromhex("0011223344556677")
    channel, sf, tx_allowed = synchronized_hop(
        eui64=eui64,
        epoch=0,
        density=25,
        ema_snr=5.0,
        n_channels=8,
    )

    # High density forces CH0 and SF 12
    assert channel == 0
    assert sf == 12
    assert tx_allowed is True


# --- slot_hash tests ---


def test_slot_hash_basic():
    """slot_hash computes TDMA slot correctly."""
    eui64 = bytes.fromhex("0011223344556677")
    slot = slot_hash(eui64, sfn=5, num_slots=8)
    # Slot should be in valid range
    assert 0 <= slot < 8


def test_slot_hash_wrap():
    """slot_hash handles SFN wrap correctly."""
    eui64 = bytes.fromhex("0011223344556677")
    # Near u32 wrap
    slot = slot_hash(eui64, sfn=0xFFFFFFFF, num_slots=8)
    assert 0 <= slot < 8


def test_slot_hash_wraps_u32_sum_before_non_power_of_two_modulus():
    """slot_hash applies wrapping-u32 addition before the slot modulus."""
    assert slot_hash(bytes.fromhex("0102030405060708"), 0xFFFFFFFF, 3) == 2


# --- Coverage tests ---


def test_ccp16_vector_coverage():
    """Verify ccp16.json covers required scenarios."""
    doc = _load("ccp16.json")
    names = {v["name"] for v in doc["vectors"]}

    # Essential test cases
    assert "synchronized_hop_channel_consistency" in names
    assert "select_channel_timing_test" in names
    assert "select_channel_sf12_high_density" in names


def test_utilization_vector_coverage():
    """Verify ccp16_utilization.json covers thresholds."""
    doc = _load("ccp16_utilization.json")
    names = {v["name"] for v in doc["vectors"]}

    assert "utilization_0_idle_channel" in names
    assert "utilization_150_threshold_1_boundary" in names
    assert "utilization_201_tx_blocked" in names


def test_ema_loss_vector_coverage():
    """Verify ccp16_ema_loss_threshold.json covers boundaries."""
    doc = _load("ccp16_ema_loss_threshold.json")
    names = {v["name"] for v in doc["vectors"]}

    assert "ema_loss_0.24_below_threshold" in names
    assert "ema_loss_0.25_at_threshold_exactly" in names
    assert "ema_loss_0.26_above_threshold" in names
