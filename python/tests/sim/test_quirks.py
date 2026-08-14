# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for hardware quirks model."""

import pytest
from lora_medium import (
    PRESETS,
    Medium,
    QuirkProfile,
    apply_rssi_noise,
    cad_with_quirks,
    frequency_offset_hz,
    pll_lock_fails,
)


class TestQuirkProfile:
    """Tests for QuirkProfile dataclass."""

    def test_default_is_ideal(self) -> None:
        """Default profile has no quirks."""
        profile = QuirkProfile()
        assert profile.warmup_ms == 0.0
        assert profile.pll_fail_rate == 0.0
        assert profile.crystal_ppm == 0.0
        assert profile.rssi_noise_db == 0.0
        assert profile.cad_false_positive_rate == 0.0
        assert profile.cad_false_negative_rate == 0.0
        assert profile.rx_deaf_us == 0

    def test_immutable(self) -> None:
        """QuirkProfile should be immutable (frozen)."""
        profile = QuirkProfile()
        with pytest.raises(AttributeError):
            profile.warmup_ms = 1.0  # type: ignore[misc]

    def test_custom_values(self) -> None:
        """Test creating profile with custom values."""
        profile = QuirkProfile(
            warmup_ms=3.0,
            pll_fail_rate=0.02,
            crystal_ppm=20.0,
            rssi_noise_db=3.0,
            cad_false_positive_rate=0.05,
            cad_false_negative_rate=0.03,
            rx_deaf_us=150,
        )
        assert profile.warmup_ms == 3.0
        assert profile.pll_fail_rate == 0.02
        assert profile.crystal_ppm == 20.0
        assert profile.rssi_noise_db == 3.0
        assert profile.cad_false_positive_rate == 0.05
        assert profile.cad_false_negative_rate == 0.03
        assert profile.rx_deaf_us == 150

    def test_negative_warmup_raises(self) -> None:
        """Negative warmup_ms is invalid."""
        with pytest.raises(ValueError, match="warmup_ms"):
            QuirkProfile(warmup_ms=-1.0)

    def test_pll_fail_rate_out_of_range_raises(self) -> None:
        """pll_fail_rate must be 0.0-1.0."""
        with pytest.raises(ValueError, match="pll_fail_rate"):
            QuirkProfile(pll_fail_rate=1.5)
        with pytest.raises(ValueError, match="pll_fail_rate"):
            QuirkProfile(pll_fail_rate=-0.1)

    def test_negative_rssi_noise_raises(self) -> None:
        """Negative rssi_noise_db is invalid."""
        with pytest.raises(ValueError, match="rssi_noise_db"):
            QuirkProfile(rssi_noise_db=-1.0)

    def test_cad_rates_out_of_range_raises(self) -> None:
        """CAD rates must be 0.0-1.0."""
        with pytest.raises(ValueError, match="cad_false_positive_rate"):
            QuirkProfile(cad_false_positive_rate=2.0)
        with pytest.raises(ValueError, match="cad_false_negative_rate"):
            QuirkProfile(cad_false_negative_rate=-0.1)

    def test_negative_rx_deaf_raises(self) -> None:
        """Negative rx_deaf_us is invalid."""
        with pytest.raises(ValueError, match="rx_deaf_us"):
            QuirkProfile(rx_deaf_us=-1)

    def test_with_overrides(self) -> None:
        """with_overrides creates new profile with specified changes."""
        base = PRESETS["moderate"]
        modified = base.with_overrides(warmup_ms=10.0)
        assert modified.warmup_ms == 10.0
        assert modified.pll_fail_rate == base.pll_fail_rate
        assert base.warmup_ms != 10.0  # original unchanged


class TestPresets:
    """Tests for named presets."""

    def test_ideal_preset_has_no_quirks(self) -> None:
        """Ideal preset should have all zeros."""
        ideal = PRESETS["ideal"]
        assert ideal.warmup_ms == 0.0
        assert ideal.pll_fail_rate == 0.0
        assert ideal.crystal_ppm == 0.0
        assert ideal.rssi_noise_db == 0.0
        assert ideal.cad_false_positive_rate == 0.0
        assert ideal.cad_false_negative_rate == 0.0
        assert ideal.rx_deaf_us == 0

    def test_moderate_preset(self) -> None:
        """Moderate preset should have typical real-world values."""
        mod = PRESETS["moderate"]
        assert mod.warmup_ms > 0
        assert mod.pll_fail_rate > 0
        assert mod.crystal_ppm > 0
        assert mod.rssi_noise_db > 0
        assert mod.cad_false_positive_rate > 0
        assert mod.cad_false_negative_rate > 0
        assert mod.rx_deaf_us > 0

    def test_sx1276_preset(self) -> None:
        """SX1276 preset exists and has reasonable values."""
        sx1276 = PRESETS["sx1276"]
        assert sx1276.warmup_ms > 0
        assert sx1276.pll_fail_rate < PRESETS["moderate"].pll_fail_rate

    def test_sx1262_preset(self) -> None:
        """SX1262 preset should be better than SX1276."""
        sx1262 = PRESETS["sx1262"]
        sx1276 = PRESETS["sx1276"]
        assert sx1262.warmup_ms <= sx1276.warmup_ms
        assert sx1262.pll_fail_rate <= sx1276.pll_fail_rate

    def test_garbage_preset(self) -> None:
        """Garbage preset should be worst-case."""
        garbage = PRESETS["garbage"]
        moderate = PRESETS["moderate"]
        assert garbage.warmup_ms > moderate.warmup_ms
        assert garbage.pll_fail_rate > moderate.pll_fail_rate
        assert garbage.crystal_ppm > moderate.crystal_ppm

    def test_all_expected_presets_exist(self) -> None:
        """All documented presets should exist."""
        assert "ideal" in PRESETS
        assert "moderate" in PRESETS
        assert "sx1276" in PRESETS
        assert "garbage" in PRESETS


class TestPllLockFails:
    """Tests for PLL lock failure function."""

    def test_zero_rate_never_fails(self) -> None:
        """Zero fail rate should never fail."""
        profile = QuirkProfile(pll_fail_rate=0.0)
        # Run many times to ensure statistical confidence
        for _ in range(100):
            assert pll_lock_fails(profile) is False

    def test_one_rate_always_fails(self) -> None:
        """100% fail rate should always fail."""
        profile = QuirkProfile(pll_fail_rate=1.0)
        for _ in range(100):
            assert pll_lock_fails(profile) is True

    def test_intermediate_rate_produces_failures(self) -> None:
        """50% rate should produce some failures over many trials."""
        profile = QuirkProfile(pll_fail_rate=0.5)
        failures = sum(1 for _ in range(1000) if pll_lock_fails(profile))
        # Should be roughly 500 with reasonable variance
        assert 300 < failures < 700


class TestApplyRssiNoise:
    """Tests for RSSI noise application."""

    def test_zero_noise_returns_exact(self) -> None:
        """Zero noise should return exact input."""
        profile = QuirkProfile(rssi_noise_db=0.0)
        assert apply_rssi_noise(-80.0, profile) == -80.0

    def test_noise_produces_variation(self) -> None:
        """Non-zero noise should produce variation."""
        profile = QuirkProfile(rssi_noise_db=3.0)
        results = [apply_rssi_noise(-80.0, profile) for _ in range(100)]
        # Should have variation
        assert min(results) != max(results)
        # Should be centered roughly on input
        mean = sum(results) / len(results)
        assert -83 < mean < -77

    def test_noise_bounded(self) -> None:
        """Noise should be bounded by ±rssi_noise_db."""
        profile = QuirkProfile(rssi_noise_db=3.0)
        for _ in range(100):
            result = apply_rssi_noise(-80.0, profile)
            # Triangular approximation goes to ±rssi_noise_db
            assert -83 <= result <= -77


class TestCadWithQuirks:
    """Tests for CAD with quirks."""

    def test_ideal_profile_exact(self) -> None:
        """Ideal profile should return exact activity state."""
        profile = PRESETS["ideal"]
        for _ in range(100):
            assert cad_with_quirks(True, profile) is True
            assert cad_with_quirks(False, profile) is False

    def test_high_false_positive_produces_positives(self) -> None:
        """High false positive rate should produce false positives."""
        profile = QuirkProfile(cad_false_positive_rate=0.5)
        false_positives = sum(
            1 for _ in range(1000) if cad_with_quirks(False, profile) is True
        )
        assert 300 < false_positives < 700

    def test_high_false_negative_produces_negatives(self) -> None:
        """High false negative rate should produce false negatives."""
        profile = QuirkProfile(cad_false_negative_rate=0.5)
        false_negatives = sum(
            1 for _ in range(1000) if cad_with_quirks(True, profile) is False
        )
        assert 300 < false_negatives < 700


class TestFrequencyOffset:
    """Tests for frequency offset calculation."""

    def test_zero_ppm_exact(self) -> None:
        """Zero crystal_ppm should return exact frequency."""
        profile = QuirkProfile(crystal_ppm=0.0)
        assert frequency_offset_hz(profile, 915_000_000) == 915_000_000

    def test_nonzero_ppm_produces_offset(self) -> None:
        """Non-zero ppm should produce frequency offset."""
        profile = QuirkProfile(crystal_ppm=30.0)
        results = [frequency_offset_hz(profile, 915_000_000) for _ in range(100)]
        # Should have variation
        assert min(results) != max(results)
        # Should be centered on nominal
        mean = sum(results) / len(results)
        assert abs(mean - 915_000_000) < 50_000  # Within reasonable bounds


class TestMediumQuirksAPI:
    """Tests for Medium class quirks API."""

    def test_default_is_ideal(self) -> None:
        """Default quirk profile should be ideal."""
        medium = Medium()
        profile = medium.get_quirks("any-node")
        assert profile == PRESETS["ideal"]

    def test_set_quirks_profile_by_name(self) -> None:
        """set_quirks_profile sets global default by name."""
        medium = Medium()
        medium.set_quirks_profile("moderate")
        profile = medium.get_quirks("any-node")
        assert profile == PRESETS["moderate"]

    def test_set_quirks_profile_invalid_raises(self) -> None:
        """set_quirks_profile with invalid name raises KeyError."""
        medium = Medium()
        with pytest.raises(KeyError, match="Unknown quirk profile"):
            medium.set_quirks_profile("nonexistent")

    def test_set_quirks_per_node_by_name(self) -> None:
        """set_quirks sets per-node profile by name."""
        medium = Medium()
        medium.set_quirks("node-1", "sx1276")
        assert medium.get_quirks("node-1") == PRESETS["sx1276"]
        # Other nodes use default
        assert medium.get_quirks("node-2") == PRESETS["ideal"]

    def test_set_quirks_per_node_by_instance(self) -> None:
        """set_quirks sets per-node profile by QuirkProfile instance."""
        medium = Medium()
        custom = QuirkProfile(warmup_ms=7.5, pll_fail_rate=0.1)
        medium.set_quirks("node-7", custom)
        assert medium.get_quirks("node-7") == custom

    def test_set_quirks_invalid_name_raises(self) -> None:
        """set_quirks with invalid preset name raises KeyError."""
        medium = Medium()
        with pytest.raises(KeyError, match="Unknown quirk profile"):
            medium.set_quirks("node-1", "invalid-preset")

    def test_per_node_overrides_global(self) -> None:
        """Per-node quirks override global default."""
        medium = Medium()
        medium.set_quirks_profile("garbage")
        medium.set_quirks("node-1", "ideal")
        assert medium.get_quirks("node-1") == PRESETS["ideal"]
        assert medium.get_quirks("node-2") == PRESETS["garbage"]

    def test_clear_quirks_single_node(self) -> None:
        """clear_quirks removes single node override."""
        medium = Medium()
        medium.set_quirks_profile("garbage")
        medium.set_quirks("node-1", "ideal")
        medium.clear_quirks("node-1")
        # Falls back to global
        assert medium.get_quirks("node-1") == PRESETS["garbage"]

    def test_clear_quirks_all_nodes(self) -> None:
        """clear_quirks(None) removes all node overrides."""
        medium = Medium()
        medium.set_quirks_profile("garbage")
        medium.set_quirks("node-1", "ideal")
        medium.set_quirks("node-2", "moderate")
        medium.clear_quirks()
        # All fall back to global
        assert medium.get_quirks("node-1") == PRESETS["garbage"]
        assert medium.get_quirks("node-2") == PRESETS["garbage"]
