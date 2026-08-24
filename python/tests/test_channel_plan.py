# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CCP-4 Regional Channel Plans oracle.

Validates channel_plan.py against test vectors and spec requirements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.channel_plan import (
    AS923,
    AU915,
    EU868,
    REGIONAL_PLANS,
    US915,
    ChannelEntry,
    ChannelPlan,
    RegulatoryMode,
    UnknownPlanError,
    ch0_fallback_required,
    get_plan,
    get_plan_by_name,
    hash_32,
    select_channel,
    validate_plan_id,
)

# Path: tests/test_channel_plan.py -> python/tests -> python -> project-LICHEN
VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "test" / "vectors"


# Independent oracle per spec 02a §2a.3.1; cross-validates canonical vectors.
# Transcribed directly from the SelectChannel pseudocode in
# spec/02a-coordinated-capacity.md §2a.3.1 -- NOT derived from
# lichen/channel_plan.py nor test/vectors/generate.py -- so this file holds a
# second implementation of the same algorithm.

FNV1A32_BASIS = 0x811C9DC5
FNV1A32_PRIME = 0x01000193
U32_MODULUS = 1 << 32


def spec_reference_fnv1a32(data: bytes) -> int:
    """Reference FNV-1a 32-bit hash (spec §2a.3.1 step 3, basis 0x811c9dc5)."""
    value = FNV1A32_BASIS
    for byte in data:
        value = ((value ^ byte) * FNV1A32_PRIME) % U32_MODULUS
    return value


def spec_reference_select_channel(
    eui64: bytes, epoch: int, density: int, n_channels: int
) -> int:
    """Reference SelectChannel (spec §2a.3.1 steps 1-5).

    The epoch enters the hash as u32 little-endian; values >= 2^32 are
    truncated (& 0xFFFFFFFF), matching the C/Rust implementations.
    """
    if density > 8:
        return 0
    data = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
    n = max(n_channels, 3)
    return 1 + (spec_reference_fnv1a32(data) % n)


class TestHash32:
    """Tests for FNV-1a 32-bit hash function."""

    def test_empty_input(self) -> None:
        """hash_32(b'') = 0x811c9dc5 (basis value)."""
        assert hash_32(b"") == 0x811C9DC5

    def test_test_string(self) -> None:
        """hash_32(b'test') per test vector."""
        assert hash_32(b"test") == 0xAFD071E5

    def test_zero_pubkey(self) -> None:
        """hash_32(0x00*32) per test vector."""
        assert hash_32(b"\x00" * 32) == 0x0B2AE445

    def test_vectors_from_file(self) -> None:
        """Validate against hash_32.json test vectors.

        hash_32.json is committed canonical data; its absence is a hard
        failure, not a skip (a lost oracle must fail loudly).
        """
        vector_file = VECTORS_DIR / "hash_32.json"
        assert vector_file.is_file(), f"canonical vector file missing: {vector_file}"

        with open(vector_file) as f:
            data = json.load(f)

        assert data["vectors"], f"{vector_file.name} contains no vectors"

        for v in data["vectors"]:
            if "input_hex" in v:
                input_bytes = bytes.fromhex(v["input_hex"])
            else:
                input_bytes = v["input"].encode("utf-8")

            expected = int(v["output"], 16)
            assert hash_32(input_bytes) == expected, f"Failed for {v['name']}"


class TestChannelEntry:
    """Tests for ChannelEntry dataclass."""

    def test_defaults(self) -> None:
        """Default values match LoRa SF10/125kHz profile."""
        entry = ChannelEntry(frequency_hz=868_100_000)
        assert entry.bandwidth_hz == 125_000
        assert entry.spreading_factor == 10
        assert entry.coding_rate == 5
        assert entry.max_power_dbm == 14
        assert entry.regulatory_group == 0

    def test_custom_values(self) -> None:
        """Custom values are stored correctly."""
        entry = ChannelEntry(
            frequency_hz=915_000_000,
            bandwidth_hz=250_000,
            spreading_factor=7,
            coding_rate=8,
            max_power_dbm=22,
            regulatory_group=2,
        )
        assert entry.frequency_hz == 915_000_000
        assert entry.bandwidth_hz == 250_000
        assert entry.spreading_factor == 7
        assert entry.coding_rate == 8
        assert entry.max_power_dbm == 22
        assert entry.regulatory_group == 2

    def test_frozen(self) -> None:
        """ChannelEntry is immutable."""
        entry = ChannelEntry(frequency_hz=868_100_000)
        with pytest.raises(AttributeError):
            entry.frequency_hz = 900_000_000  # type: ignore[misc]


class TestChannelPlan:
    """Tests for ChannelPlan dataclass."""

    def test_num_channels(self) -> None:
        """num_channels returns correct count."""
        assert EU868.num_channels == 8
        assert US915.num_channels == 64
        assert AU915.num_channels == 64

    def test_frequency(self) -> None:
        """frequency() returns correct values."""
        assert EU868.frequency(0) == 868_100_000
        assert EU868.frequency(1) == 868_300_000
        assert US915.frequency(0) == 902_300_000

    def test_frequency_out_of_range(self) -> None:
        """frequency() raises for invalid index."""
        with pytest.raises(ValueError, match="out of range"):
            EU868.frequency(-1)
        with pytest.raises(ValueError, match="out of range"):
            EU868.frequency(100)

    def test_ch0_is_first(self) -> None:
        """CH0 (control channel) is at index 0."""
        for plan in REGIONAL_PLANS.values():
            assert plan.channels[0].frequency_hz > 0

    def test_regulatory_rules(self) -> None:
        """Plans have correct regulatory rules."""
        assert EU868.regulatory_rules.mode == RegulatoryMode.DUTY_CYCLE
        assert EU868.regulatory_rules.duty_cycle_percent == 1.0

        assert US915.regulatory_rules.mode == RegulatoryMode.DWELL_TIME
        assert US915.regulatory_rules.dwell_time_ms == 400

        assert AS923.regulatory_rules.mode == RegulatoryMode.LBT
        assert AS923.regulatory_rules.lbt_threshold_dbm == -80

    def test_validate_channel_mask(self) -> None:
        """validate_channel_mask computes intersection."""
        # EU868 has 8 channels, mask bits 0-7 valid
        assert EU868.validate_channel_mask(0xFF) == 0xFF
        assert EU868.validate_channel_mask(0xFFFF) == 0xFF
        assert EU868.validate_channel_mask(0x03) == 0x03

        # US915 has 64 channels
        assert US915.validate_channel_mask(0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF

    def test_is_valid_power(self) -> None:
        """is_valid_power checks against max_power_dbm."""
        assert EU868.is_valid_power(0, 14) is True
        assert EU868.is_valid_power(0, 10) is True
        assert EU868.is_valid_power(0, 15) is False

        assert US915.is_valid_power(0, 22) is True
        assert US915.is_valid_power(0, 30) is False

        # Invalid channel index
        assert EU868.is_valid_power(-1, 10) is False
        assert EU868.is_valid_power(100, 10) is False


class TestSelectChannel:
    """Tests for select_channel algorithm."""

    def test_density_above_8_returns_ch0(self) -> None:
        """density > 8 triggers CH0 fallback per spec."""
        eui64 = bytes.fromhex("0011223344556677")
        assert select_channel(eui64, epoch=0, density=9) == 0
        assert select_channel(eui64, epoch=0, density=10) == 0
        assert select_channel(eui64, epoch=0, density=100) == 0

    def test_density_8_or_below_uses_hash(self) -> None:
        """density <= 8 uses hash-based selection."""
        eui64 = bytes.fromhex("0011223344556677")
        ch = select_channel(eui64, epoch=0, density=8, plan=EU868)
        assert ch >= 1  # Never returns CH0 for density <= 8
        assert ch <= EU868.num_channels  # Spec CCP-16: channels are numbered 1..N

    def test_deterministic(self) -> None:
        """Same inputs produce same output."""
        eui64 = bytes.fromhex("0011223344556677")
        ch1 = select_channel(eui64, epoch=42, density=5)
        ch2 = select_channel(eui64, epoch=42, density=5)
        assert ch1 == ch2

    def test_different_epoch_different_channel(self) -> None:
        """Different epochs produce different channel sequences."""
        eui64 = bytes.fromhex("0011223344556677")
        channels = [select_channel(eui64, epoch=i, density=5) for i in range(100)]
        unique = set(channels)
        assert len(unique) > 1  # Should have variation

    def test_ccp16_vectors(self) -> None:
        """Validate select_channel against ccp16.json test vectors.

        ccp16.json was generated with NChannels=3 (the spec floor domain
        N = max(NChannels, 3), see ccp16_vectors in test/vectors/generate.py),
        so the vectors are exercised through a synthetic 3-channel plan.
        """
        with open(VECTORS_DIR / "ccp16.json") as f:
            data = json.load(f)

        vector_plan = ChannelPlan(
            plan_id=0xFF,
            version=1,
            name="CCP16VECTORS",
            channels=tuple(
                ChannelEntry(frequency_hz=868_100_000 + i * 200_000) for i in range(3)
            ),
        )

        for v in data["vectors"]:
            name = v["name"]
            inp = v["input"]
            out = v["output"]

            eui64 = bytes.fromhex(inp["eui64"])
            epoch = inp["epoch"]
            density = inp["density"]

            assert (
                hash_32(eui64 + epoch.to_bytes(4, "little")) == out["hash_32"]
            ), f"hash_32 mismatch for {name}"

            expected_ch = out["select_channel"]
            assert select_channel(eui64, epoch, density, vector_plan) == expected_ch, (
                f"select_channel mismatch for {name}"
            )
            assert vector_plan.select_channel(eui64, epoch, density) == expected_ch, (
                f"ChannelPlan.select_channel mismatch for {name}"
            )

    def test_ccp16_vectors_against_spec_oracle(self) -> None:
        """Every ccp16 vector: spec oracle == vector expectation == module.

        Triple equality per vector: the independent reference implementation
        above (written from spec §2a.3.1), the canonical expectation in
        ccp16.json, and lichen.channel_plan must all agree. ccp16.json was
        generated with NChannels=3, so n_channels comes from the synthetic
        3-channel plan encoding that context.
        """
        with open(VECTORS_DIR / "ccp16.json") as f:
            data = json.load(f)

        vector_plan = ChannelPlan(
            plan_id=0xFF,
            version=1,
            name="CCP16ORACLE",
            channels=tuple(
                ChannelEntry(frequency_hz=868_100_000 + i * 200_000) for i in range(3)
            ),
        )
        vector_n_channels = len(vector_plan.channels)

        for v in data["vectors"]:
            name = v["name"]
            inp = v["input"]
            expected_ch = v["output"]["select_channel"]

            eui64 = bytes.fromhex(inp["eui64"])
            epoch = inp["epoch"]
            density = inp["density"]

            assert (
                spec_reference_select_channel(eui64, epoch, density, vector_n_channels)
                == expected_ch
                == select_channel(eui64, epoch, density, vector_plan)
            ), f"spec oracle / vector / module disagreement for {name}"


class TestRegionalPlans:
    """Tests for regional plan definitions."""

    def test_all_plans_have_unique_ids(self) -> None:
        """Each plan has a unique plan_id."""
        ids = [p.plan_id for p in REGIONAL_PLANS.values()]
        assert len(ids) == len(set(ids))

    def test_all_plans_have_unique_names(self) -> None:
        """Each plan has a unique name."""
        names = [p.name for p in REGIONAL_PLANS.values()]
        assert len(names) == len(set(names))

    def test_plan_lookup_by_id(self) -> None:
        """get_plan returns correct plan by ID."""
        assert get_plan(0x01) is EU868
        assert get_plan(0x02) is US915
        assert get_plan(0x03) is AU915

    def test_plan_lookup_by_name(self) -> None:
        """get_plan_by_name returns correct plan."""
        assert get_plan_by_name("EU868") is EU868
        assert get_plan_by_name("US915") is US915
        assert get_plan_by_name("AU915") is AU915

    def test_unknown_plan_fails_closed(self) -> None:
        """Unknown plan_id/name raises UnknownPlanError (fail-closed)."""
        with pytest.raises(UnknownPlanError):
            get_plan(0xFF)
        with pytest.raises(UnknownPlanError):
            get_plan_by_name("UNKNOWN")

    def test_validate_plan_id(self) -> None:
        """validate_plan_id returns True for known plans."""
        assert validate_plan_id(0x01) is True
        assert validate_plan_id(0x02) is True
        assert validate_plan_id(0xFF) is False

    def test_ch0_fallback_required(self) -> None:
        """ch0_fallback_required for unknown plans/versions."""
        assert ch0_fallback_required(0xFF) is True
        assert ch0_fallback_required(0x01) is False
        assert ch0_fallback_required(0x01, version=1) is False
        assert ch0_fallback_required(0x01, version=999) is True


class TestUS915Compliance:
    """Tests for US915 FCC Part 15.247 compliance."""

    def test_channel_count(self) -> None:
        """US915 must have 50+ channels for FHSS compliance."""
        assert US915.num_channels >= 50

    def test_channel_spacing(self) -> None:
        """Channels are 200kHz apart."""
        for i in range(1, US915.num_channels):
            spacing = US915.channels[i].frequency_hz - US915.channels[i - 1].frequency_hz
            assert spacing == 200_000

    def test_dwell_time_limit(self) -> None:
        """Dwell time limit is 400ms."""
        assert US915.regulatory_rules.dwell_time_ms == 400


class TestEU868Compliance:
    """Tests for EU868 ETSI EN 300.220 compliance."""

    def test_duty_cycle(self) -> None:
        """Duty cycle is 1% per sub-band."""
        assert EU868.regulatory_rules.duty_cycle_percent == 1.0

    def test_max_power(self) -> None:
        """Max power is 14 dBm ERP."""
        for ch in EU868.channels:
            assert ch.max_power_dbm <= 14

    def test_regulatory_groups(self) -> None:
        """Channels are grouped by sub-band for duty cycle accounting."""
        groups = {ch.regulatory_group for ch in EU868.channels}
        assert len(groups) >= 1  # At least one group
