# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LoRa propagation model."""

import math

import pytest

from lichen.sim.propagation import (
    CAPTURE_THRESHOLD_DB,
    PATH_LOSS_FREE_SPACE,
    PATH_LOSS_INDOOR,
    PATH_LOSS_URBAN,
    SENSITIVITY_SF7,
    SENSITIVITY_SF10,
    SENSITIVITY_SF12,
    PropagationModel,
    link_budget,
)


class TestPathLoss:
    """Test path loss calculations."""

    def test_path_loss_at_reference_distance(self) -> None:
        """Path loss at reference distance equals PL₀."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        assert model.path_loss(1.0) == 32.44

    def test_path_loss_at_10m_free_space(self) -> None:
        """Path loss at 10m with free space exponent (n=2.0).

        PL = 32.44 + 10*2.0*log10(10/1) = 32.44 + 20 = 52.44 dB
        """
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=PATH_LOSS_FREE_SPACE)
        assert model.path_loss(10.0) == pytest.approx(52.44, rel=1e-6)

    def test_path_loss_at_100m_urban(self) -> None:
        """Path loss at 100m with urban exponent (n=2.7).

        PL = 32.44 + 10*2.7*log10(100/1) = 32.44 + 54 = 86.44 dB
        """
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=PATH_LOSS_URBAN)
        assert model.path_loss(100.0) == pytest.approx(86.44, rel=1e-6)

    def test_path_loss_at_1000m_indoor(self) -> None:
        """Path loss at 1000m with indoor exponent (n=3.5).

        PL = 32.44 + 10*3.5*log10(1000/1) = 32.44 + 105 = 137.44 dB
        """
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=PATH_LOSS_INDOOR)
        assert model.path_loss(1000.0) == pytest.approx(137.44, rel=1e-6)

    def test_path_loss_below_reference_distance(self) -> None:
        """Path loss at distances < d₀ returns PL₀ (no negative path loss)."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        assert model.path_loss(0.5) == 32.44

    def test_path_loss_zero_distance_raises(self) -> None:
        """Path loss at zero distance raises ValueError."""
        model = PropagationModel()
        with pytest.raises(ValueError, match="Distance must be positive"):
            model.path_loss(0.0)

    def test_path_loss_negative_distance_raises(self) -> None:
        """Path loss at negative distance raises ValueError."""
        model = PropagationModel()
        with pytest.raises(ValueError, match="Distance must be positive"):
            model.path_loss(-10.0)


class TestReceivedPower:
    """Test received power calculations."""

    def test_received_power_at_1m(self) -> None:
        """Received power at 1m equals TX power minus PL₀."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        rx_power = model.received_power(tx_power_dbm=14.0, distance_m=1.0)
        assert rx_power == pytest.approx(-18.44, rel=1e-6)

    def test_received_power_at_100m(self) -> None:
        """Received power at 100m with 14 dBm TX.

        RX = 14 - 86.44 = -72.44 dBm (using urban n=2.7)
        """
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=PATH_LOSS_URBAN)
        rx_power = model.received_power(tx_power_dbm=14.0, distance_m=100.0)
        assert rx_power == pytest.approx(-72.44, rel=1e-6)

    def test_received_power_high_tx_power(self) -> None:
        """Higher TX power increases received power proportionally."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        rx_14dbm = model.received_power(tx_power_dbm=14.0, distance_m=100.0)
        rx_20dbm = model.received_power(tx_power_dbm=20.0, distance_m=100.0)
        assert rx_20dbm - rx_14dbm == pytest.approx(6.0, rel=1e-6)


class TestSNR:
    """Test signal-to-noise ratio calculations."""

    def test_snr_calculation(self) -> None:
        """SNR equals received power minus noise floor."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7, noise_floor_dbm=-120.0)
        # At 100m with 14 dBm TX: RX = -72.44 dBm
        # SNR = -72.44 - (-120) = 47.56 dB
        snr = model.snr(tx_power_dbm=14.0, distance_m=100.0)
        assert snr == pytest.approx(47.56, rel=1e-6)

    def test_snr_negative_when_below_noise(self) -> None:
        """SNR is negative when received power is below noise floor."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=3.5, noise_floor_dbm=-120.0)
        # At very long distance, signal drops below noise
        snr = model.snr(tx_power_dbm=14.0, distance_m=10000.0)
        assert snr < 0

    def test_snr_different_noise_floors(self) -> None:
        """Different noise floors produce different SNR values."""
        model_quiet = PropagationModel(noise_floor_dbm=-130.0)
        model_noisy = PropagationModel(noise_floor_dbm=-100.0)

        snr_quiet = model_quiet.snr(tx_power_dbm=14.0, distance_m=100.0)
        snr_noisy = model_noisy.snr(tx_power_dbm=14.0, distance_m=100.0)

        # Quieter environment has higher SNR
        assert snr_quiet > snr_noisy
        assert snr_quiet - snr_noisy == pytest.approx(30.0, rel=1e-6)


class TestCanDecode:
    """Test decode threshold checks."""

    def test_can_decode_strong_signal(self) -> None:
        """Strong signal can be decoded."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        # At 100m with 14 dBm: RX = -72.44 dBm > -132 dBm threshold
        assert model.can_decode(tx_power_dbm=14.0, distance_m=100.0) is True

    def test_can_decode_weak_signal(self) -> None:
        """Weak signal below threshold cannot be decoded."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=3.5)
        # Very long distance with indoor propagation
        assert model.can_decode(tx_power_dbm=14.0, distance_m=10000.0) is False

    def test_can_decode_at_sensitivity_edge(self) -> None:
        """Signal exactly at sensitivity threshold CAN be decoded (>= threshold)."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        # Find the distance where RX power equals sensitivity
        max_range = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)
        # At exactly max range, received power equals threshold - still decodable
        assert model.can_decode(tx_power_dbm=14.0, distance_m=max_range) is True
        # Slightly further, signal drops below threshold
        assert model.can_decode(tx_power_dbm=14.0, distance_m=max_range * 1.01) is False

    def test_can_decode_with_sf7_sensitivity(self) -> None:
        """SF7 has worse sensitivity than SF10."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        # Find a distance that works for SF10 but not SF7
        max_sf10 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)
        max_sf7 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF7)

        # SF10 has better sensitivity, so longer range
        assert max_sf10 > max_sf7

        # At a distance between the two ranges
        test_distance = (max_sf7 + max_sf10) / 2
        assert model.can_decode(14.0, test_distance, sensitivity_dbm=SENSITIVITY_SF10) is True
        assert model.can_decode(14.0, test_distance, sensitivity_dbm=SENSITIVITY_SF7) is False

    def test_can_decode_with_sf12_sensitivity(self) -> None:
        """SF12 has better sensitivity than SF10."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        max_sf12 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF12)
        max_sf10 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)

        # SF12 has better sensitivity, so longer range
        assert max_sf12 > max_sf10


class TestMaxRange:
    """Test maximum range calculations."""

    def test_max_range_calculation(self) -> None:
        """Max range produces received power equal to sensitivity."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        max_range = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)

        rx_power = model.received_power(tx_power_dbm=14.0, distance_m=max_range)
        assert rx_power == pytest.approx(SENSITIVITY_SF10, rel=1e-6)

    def test_max_range_higher_power_longer_range(self) -> None:
        """Higher TX power gives longer range."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        range_14dbm = model.max_range(tx_power_dbm=14.0)
        range_20dbm = model.max_range(tx_power_dbm=20.0)

        assert range_20dbm > range_14dbm

    def test_max_range_better_sensitivity_longer_range(self) -> None:
        """Better sensitivity gives longer range."""
        model = PropagationModel(pl0_dbm=32.44, d0_m=1.0, n=2.7)
        range_sf10 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)
        range_sf12 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF12)

        assert range_sf12 > range_sf10

    def test_max_range_free_space_vs_urban(self) -> None:
        """Free space propagation gives longer range than urban."""
        model_free = PropagationModel(pl0_dbm=32.44, n=PATH_LOSS_FREE_SPACE)
        model_urban = PropagationModel(pl0_dbm=32.44, n=PATH_LOSS_URBAN)

        range_free = model_free.max_range(tx_power_dbm=14.0)
        range_urban = model_urban.max_range(tx_power_dbm=14.0)

        assert range_free > range_urban


class TestConstants:
    """Test that constants are correctly defined."""

    def test_sensitivity_ordering(self) -> None:
        """Higher SF has better (more negative) sensitivity."""
        assert SENSITIVITY_SF7 > SENSITIVITY_SF10 > SENSITIVITY_SF12

    def test_capture_threshold(self) -> None:
        """Capture threshold is 6 dB per LoRaSim paper."""
        assert CAPTURE_THRESHOLD_DB == 6.0

    def test_path_loss_exponent_ordering(self) -> None:
        """Indoor has highest path loss exponent."""
        assert PATH_LOSS_FREE_SPACE < PATH_LOSS_URBAN < PATH_LOSS_INDOOR


class TestModelDefaults:
    """Test default model parameters."""

    def test_default_parameters(self) -> None:
        """Default parameters are set correctly."""
        model = PropagationModel()
        assert model.pl0_dbm == 32.44
        assert model.d0_m == 1.0
        assert model.n == 2.7
        assert model.noise_floor_dbm == -120.0

    def test_custom_parameters(self) -> None:
        """Custom parameters override defaults."""
        model = PropagationModel(pl0_dbm=40.0, d0_m=10.0, n=3.0, noise_floor_dbm=-110.0)
        assert model.pl0_dbm == 40.0
        assert model.d0_m == 10.0
        assert model.n == 3.0
        assert model.noise_floor_dbm == -110.0


class TestInitialization:
    """Test __post_init__ validation for PropagationModel."""

    def test_invalid_n_raises(self) -> None:
        """n <= 0 raises ValueError."""
        with pytest.raises(ValueError, match="Path loss exponent n must be positive"):
            PropagationModel(n=0.0)
        with pytest.raises(ValueError, match="Path loss exponent n must be positive"):
            PropagationModel(n=-0.5)

    def test_invalid_d0_m_raises(self) -> None:
        """d0_m <= 0 raises ValueError."""
        with pytest.raises(ValueError, match="Reference distance d0_m must be positive"):
            PropagationModel(d0_m=0.0)
        with pytest.raises(ValueError, match="Reference distance d0_m must be positive"):
            PropagationModel(d0_m=-1.0)

    def test_valid_parameters_succeed(self) -> None:
        """Valid positive values for n and d0_m are accepted."""
        model = PropagationModel(n=2.0, d0_m=5.0)
        assert model.n == 2.0
        assert model.d0_m == 5.0


class TestShadowing:
    """Test log-normal shadowing."""

    def test_shadowing_disabled_by_default(self) -> None:
        """Shadowing is disabled when shadow_std_db == 0."""
        model = PropagationModel()
        pl1 = model.path_loss(100.0)
        pl2 = model.path_loss(100.0)
        assert pl1 == pl2  # deterministic when disabled

    def test_shadowing_zero_std_is_deterministic(self) -> None:
        """Zero shadowing std produces deterministic output."""
        model = PropagationModel(shadow_std_db=0.0)
        pl_twice = [model.path_loss(100.0) for _ in range(5)]
        assert all(pl == pl_twice[0] for pl in pl_twice)

    def test_shadowing_negative_std_raises(self) -> None:
        """Negative shadow_std_db raises ValueError."""
        with pytest.raises(ValueError, match="Shadow standard deviation must be >= 0"):
            PropagationModel(shadow_std_db=-1.0)

    def test_shadowing_seed_override(self) -> None:
        """Seed override provides deterministic shadow offset."""
        model = PropagationModel(shadow_std_db=4.0, _seed=2.0)
        pl = model.path_loss(100.0)
        expected_base = 86.44
        assert pl == pytest.approx(expected_base + 8.0, rel=1e-6)


class TestFading:
    """Test small-scale fading."""

    def test_fading_disabled_by_default(self) -> None:
        """Fading is disabled when fading_std_db == 0."""
        model = PropagationModel()
        pl1 = model.path_loss(100.0)
        pl2 = model.path_loss(100.0)
        assert pl1 == pl2

    def test_fading_zero_std_is_deterministic(self) -> None:
        """Zero fading std produces deterministic output."""
        model = PropagationModel(fading_std_db=0.0)
        pl_twice = [model.path_loss(100.0) for _ in range(5)]
        assert all(pl == pl_twice[0] for pl in pl_twice)

    def test_fading_negative_std_raises(self) -> None:
        """Negative fading_std_db raises ValueError."""
        with pytest.raises(ValueError, match="Fading standard deviation must be >= 0"):
            PropagationModel(fading_std_db=-1.0)

    def test_fading_seed_override(self) -> None:
        """Seed override provides deterministic fading offset."""
        model = PropagationModel(fading_std_db=6.0, _seed=1.5)
        pl = model.path_loss(100.0)
        expected_base = 86.44
        assert pl == pytest.approx(expected_base + 9.0, rel=1e-6)

    def test_fading_invalid_type_raises(self) -> None:
        """Invalid fading_type raises ValueError."""
        with pytest.raises(ValueError, match="fading_type must be 'rayleigh' or 'ricean'"):
            PropagationModel(fading_type="unknown")

    def test_ricean_fading_nonnegative(self) -> None:
        """Ricean fading produces non-negative fading loss (abs)."""
        model = PropagationModel(fading_std_db=3.0, fading_type="ricean", _seed=-2.0)
        pl = model.path_loss(100.0)
        expected_base = 86.44 + 6.0  # abs(-2.0) * 3.0 = 6.0
        assert pl == pytest.approx(expected_base, rel=1e-6)


class TestSINR:
    """Test SINR calculations."""

    def test_sinr_no_interference(self) -> None:
        """SINR equals SNR when no interference."""
        model = PropagationModel(noise_floor_dbm=-120.0)
        sinr_val = model.sinr(tx_power_dbm=14.0, distance_m=100.0, interfering_powers_linear=[])
        snr_val = model.snr(tx_power_dbm=14.0, distance_m=100.0)
        assert sinr_val == pytest.approx(snr_val, rel=1e-6)

    def test_sinr_with_interference(self) -> None:
        """SINR is lower than SNR when interference present."""
        model = PropagationModel(noise_floor_dbm=-120.0)
        # One interferer at same power
        rx_power = model.received_power(14.0, 100.0)
        rx_linear = 10.0 ** (rx_power / 10.0)
        sinr_val = model.sinr(14.0, 100.0, interfering_powers_linear=[rx_linear])
        snr_val = model.snr(14.0, 100.0)
        assert sinr_val < snr_val

    def test_sinr_strong_signal_dominates(self) -> None:
        """SINR is high when desired signal is much stronger than interferers."""
        model = PropagationModel(noise_floor_dbm=-120.0)
        # Weak interferer at -90 dBm
        weak_interferer_linear = 10.0 ** (-90.0 / 10.0)
        # Strong signal at -60 dBm equivalent
        sinr_val = model.sinr(0.0, 1.0, interfering_powers_linear=[weak_interferer_linear])
        signal_linear = 10.0 ** (model.received_power(0.0, 1.0) / 10.0)
        noise_linear = 10.0 ** (-120.0 / 10.0)
        expected = 10.0 * math.log10(signal_linear / (noise_linear + weak_interferer_linear))
        assert sinr_val == pytest.approx(expected, rel=1e-6)

    def test_sinr_multiple_interferers(self) -> None:
        """SINR aggregates multiple interferers correctly."""
        model = PropagationModel(noise_floor_dbm=-120.0)
        signal_linear = 10.0 ** (-80.0 / 10.0)
        int1 = 10.0 ** (-90.0 / 10.0)
        int2 = 10.0 ** (-95.0 / 10.0)
        noise_linear = 10.0 ** (-120.0 / 10.0)
        total_noise = noise_linear + int1 + int2
        expected = 10.0 * math.log10(signal_linear / total_noise) if total_noise > 0 else float("inf")
        # We pass rssi directly via an overridden distance for the signal
        model2 = PropagationModel(pl0_dbm=0.0, d0_m=1.0, n=0.01, noise_floor_dbm=-120.0)
        sinr_val = model2.sinr(0.0, 1.0, interfering_powers_linear=[int1, int2])
        assert sinr_val == pytest.approx(expected, rel=0.5)


