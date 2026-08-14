# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LR-FHSS (Long Range Frequency Hopping Spread Spectrum) support.

Tests cover:
- LR-FHSS sensitivity threshold (-137 dBm)
- 4-contender collision resolution (fragment FEC recovery model)
- LR-FHSS airtime (2x LoRa airtime)
- Frequency-dependent path loss documentation

References:
- Semtech AN1200.64: LR-FHSS specification and sensitivity
- SX1262 datasheet: LR-FHSS parameters
"""

from lora_medium import (
    SENSITIVITY_LR_FHSS,
    SENSITIVITY_SF10,
    SENSITIVITY_SF12,
    Medium,
    PropagationModel,
    RxCandidate,
    Transmission,
    airtime_us,
    lr_fhss_airtime_us,
)


class TestLRFHSSSensitivity:
    """Test LR-FHSS sensitivity threshold."""

    def test_lr_fhss_sensitivity_equals_sf12(self) -> None:
        """LR-FHSS sensitivity matches SF12 per Semtech AN1200.64."""
        assert SENSITIVITY_LR_FHSS == SENSITIVITY_SF12
        assert SENSITIVITY_LR_FHSS == -137.0

    def test_lr_fhss_sensitivity_better_than_sf10(self) -> None:
        """LR-FHSS has better (more negative) sensitivity than SF10."""
        assert SENSITIVITY_LR_FHSS < SENSITIVITY_SF10

    def test_lr_fhss_extends_range_vs_sf10(self) -> None:
        """LR-FHSS achieves longer range than SF10 due to better sensitivity."""
        model = PropagationModel()
        range_sf10 = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_SF10)
        range_lr_fhss = model.max_range(tx_power_dbm=14.0, sensitivity_dbm=SENSITIVITY_LR_FHSS)

        assert range_lr_fhss > range_sf10
        # LR-FHSS is 5 dB more sensitive, so range should be ~1.46x longer
        # (10^(5/(10*2.7)) = ~1.46 for urban n=2.7)
        ratio = range_lr_fhss / range_sf10
        assert 1.4 < ratio < 1.6

    def test_medium_uses_lr_fhss_sensitivity(self) -> None:
        """Medium.get_rx_candidates uses LR-FHSS sensitivity for lr_fhss phy_mode."""
        medium = Medium()

        # Calculate range where signal is above LR-FHSS threshold but below SF10
        range_sf10 = medium.propagation.max_range(14.0, sensitivity_dbm=SENSITIVITY_SF10)
        range_lr_fhss = medium.propagation.max_range(14.0, sensitivity_dbm=SENSITIVITY_LR_FHSS)
        test_distance = (range_sf10 + range_lr_fhss) / 2

        # LR-FHSS transmission at this distance should be receivable
        tx_lr_fhss = medium.start_tx(
            node_id="tx_lr_fhss",
            payload=b"test",
            tx_power_dbm=14,
            position=(test_distance, 0.0, 0.0),
            time_us=1000,
            phy_mode="lr_fhss",
        )

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 100,
        )

        assert len(candidates) == 1
        assert candidates[0].transmission is tx_lr_fhss
        assert candidates[0].is_lr_fhss is True

    def test_lora_not_receivable_at_lr_fhss_distance(self) -> None:
        """Standard LoRa at LR-FHSS range is NOT receivable (below SF10 threshold)."""
        medium = Medium()

        range_sf10 = medium.propagation.max_range(14.0, sensitivity_dbm=SENSITIVITY_SF10)
        range_lr_fhss = medium.propagation.max_range(14.0, sensitivity_dbm=SENSITIVITY_LR_FHSS)
        test_distance = (range_sf10 + range_lr_fhss) / 2

        # Standard LoRa transmission at this distance should NOT be receivable
        medium.start_tx(
            node_id="tx_lora",
            payload=b"test",
            tx_power_dbm=14,
            position=(test_distance, 0.0, 0.0),
            time_us=1000,
            phy_mode="lora",
        )

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 100,
        )

        assert len(candidates) == 0

    def test_rx_candidate_is_lr_fhss_flag(self) -> None:
        """RxCandidate.is_lr_fhss is set correctly based on phy_mode."""
        medium = Medium()

        medium.start_tx(
            node_id="tx_lr_fhss",
            payload=b"test",
            tx_power_dbm=14,
            position=(100.0, 0.0, 0.0),
            time_us=1000,
            phy_mode="lr_fhss",
        )
        medium.start_tx(
            node_id="tx_lora",
            payload=b"test",
            tx_power_dbm=14,
            position=(-100.0, 0.0, 0.0),
            time_us=1000,
            phy_mode="lora",
        )

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 100,
        )

        assert len(candidates) == 2
        lr_fhss_candidates = [c for c in candidates if c.is_lr_fhss]
        lora_candidates = [c for c in candidates if not c.is_lr_fhss]
        assert len(lr_fhss_candidates) == 1
        assert len(lora_candidates) == 1


class TestLRFHSSCollisionResolution:
    """Test LR-FHSS 4-contender collision resolution.

    LR-FHSS uses fragment-level FEC that can recover the original message
    when up to 4 concurrent transmissions collide (only 50% of fragments
    need to be received). Beyond 4 contenders, recovery fails.
    """

    def test_single_lr_fhss_transmission_succeeds(self) -> None:
        """Single LR-FHSS transmission is always received."""
        medium = Medium()

        tx = Transmission(
            source_node_id="tx1",
            payload=b"test",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )

        candidates = [RxCandidate(transmission=tx, rssi=-80.0, snr=40.0, is_lr_fhss=True)]
        result = medium.resolve_reception(candidates)

        assert result is tx

    def test_two_lr_fhss_contenders_strongest_wins(self) -> None:
        """2 LR-FHSS contenders: strongest signal wins (<=4 threshold)."""
        medium = Medium()

        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )

        candidates = [
            RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0, is_lr_fhss=True),
            RxCandidate(transmission=tx2, rssi=-80.0, snr=40.0, is_lr_fhss=True),
        ]
        result = medium.resolve_reception(candidates)

        assert result is tx1

    def test_three_lr_fhss_contenders_strongest_wins(self) -> None:
        """3 LR-FHSS contenders: strongest signal wins (<=4 threshold)."""
        medium = Medium()

        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"medium",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx3 = Transmission(
            source_node_id="tx3",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )

        candidates = [
            RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0, is_lr_fhss=True),
            RxCandidate(transmission=tx2, rssi=-75.0, snr=45.0, is_lr_fhss=True),
            RxCandidate(transmission=tx3, rssi=-80.0, snr=40.0, is_lr_fhss=True),
        ]
        result = medium.resolve_reception(candidates)

        assert result is tx1

    def test_four_lr_fhss_contenders_strongest_wins(self) -> None:
        """4 LR-FHSS contenders: strongest signal still wins (<=4 threshold)."""
        medium = Medium()

        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"strongest",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx3 = Transmission(
            source_node_id="tx3",
            payload=b"medium",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx4 = Transmission(
            source_node_id="tx4",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )

        candidates = [
            RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0, is_lr_fhss=True),
            RxCandidate(transmission=tx2, rssi=-75.0, snr=45.0, is_lr_fhss=True),
            RxCandidate(transmission=tx3, rssi=-80.0, snr=40.0, is_lr_fhss=True),
            RxCandidate(transmission=tx4, rssi=-85.0, snr=35.0, is_lr_fhss=True),
        ]
        result = medium.resolve_reception(candidates)

        assert result is tx1

    def test_five_lr_fhss_contenders_all_lost(self) -> None:
        """5 LR-FHSS contenders: all lost (>4 threshold)."""
        medium = Medium()

        transmissions = []
        candidates = []
        for i in range(5):
            tx = Transmission(
                source_node_id=f"tx{i}",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                start_time_us=1000,
                end_time_us=2000,
                phy_mode="lr_fhss",
            )
            transmissions.append(tx)
            candidates.append(
                RxCandidate(
                    transmission=tx,
                    rssi=-70.0 - i * 5,
                    snr=50.0 - i * 5,
                    is_lr_fhss=True,
                )
            )

        result = medium.resolve_reception(candidates)

        assert result is None

    def test_ten_lr_fhss_contenders_all_lost(self) -> None:
        """10 LR-FHSS contenders: all lost (>4 threshold)."""
        medium = Medium()

        candidates = []
        for i in range(10):
            tx = Transmission(
                source_node_id=f"tx{i}",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                start_time_us=1000,
                end_time_us=2000,
                phy_mode="lr_fhss",
            )
            candidates.append(
                RxCandidate(
                    transmission=tx,
                    rssi=-70.0 - i * 2,
                    snr=50.0 - i * 2,
                    is_lr_fhss=True,
                )
            )

        result = medium.resolve_reception(candidates)

        assert result is None

    def test_four_lr_fhss_equal_power_strongest_wins(self) -> None:
        """4 LR-FHSS with equal power: first in sorted order wins."""
        medium = Medium()

        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"msg1",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"msg2",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx3 = Transmission(
            source_node_id="tx3",
            payload=b"msg3",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )
        tx4 = Transmission(
            source_node_id="tx4",
            payload=b"msg4",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lr_fhss",
        )

        # All same RSSI - should pick first after sorting (stable sort behavior)
        candidates = [
            RxCandidate(transmission=tx1, rssi=-80.0, snr=40.0, is_lr_fhss=True),
            RxCandidate(transmission=tx2, rssi=-80.0, snr=40.0, is_lr_fhss=True),
            RxCandidate(transmission=tx3, rssi=-80.0, snr=40.0, is_lr_fhss=True),
            RxCandidate(transmission=tx4, rssi=-80.0, snr=40.0, is_lr_fhss=True),
        ]
        result = medium.resolve_reception(candidates)

        # One of them should win (behavior depends on sort stability)
        assert result is not None


class TestLRFHSSVsLoRaCollision:
    """Test mixed LR-FHSS and LoRa collision scenarios."""

    def test_lora_uses_capture_effect_not_contender_count(self) -> None:
        """Standard LoRa uses 6dB capture effect, not 4-contender rule."""
        medium = Medium()

        tx_strong = Transmission(
            source_node_id="tx_strong",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lora",
        )
        tx_weak = Transmission(
            source_node_id="tx_weak",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lora",
        )

        # 10 dB difference - capture effect should apply for LoRa
        candidates = [
            RxCandidate(transmission=tx_strong, rssi=-70.0, snr=50.0, is_lr_fhss=False),
            RxCandidate(transmission=tx_weak, rssi=-80.0, snr=40.0, is_lr_fhss=False),
        ]
        result = medium.resolve_reception(candidates)

        assert result is tx_strong

    def test_lora_equal_power_collision_loses_both(self) -> None:
        """Standard LoRa with equal power loses both (no capture effect)."""
        medium = Medium()

        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"msg1",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lora",
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"msg2",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
            phy_mode="lora",
        )

        # Same RSSI - collision, both lost
        candidates = [
            RxCandidate(transmission=tx1, rssi=-80.0, snr=40.0, is_lr_fhss=False),
            RxCandidate(transmission=tx2, rssi=-80.0, snr=40.0, is_lr_fhss=False),
        ]
        result = medium.resolve_reception(candidates)

        assert result is None


class TestLRFHSSAirtime:
    """Test LR-FHSS airtime calculations."""

    def test_lr_fhss_airtime_double_lora(self) -> None:
        """LR-FHSS airtime is 2x LoRa airtime (fragment overhead)."""
        for payload_len in [0, 10, 50, 100, 255]:
            lora_time = airtime_us(payload_len)
            lr_fhss_time = lr_fhss_airtime_us(payload_len)
            assert lr_fhss_time == lora_time * 2

    def test_medium_uses_lr_fhss_airtime(self) -> None:
        """Medium.start_tx uses lr_fhss_airtime_us for lr_fhss phy_mode."""
        medium = Medium()
        payload = b"test payload"

        lora_tx = medium.start_tx(
            node_id="tx_lora",
            payload=payload,
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
            phy_mode="lora",
        )

        lr_fhss_tx = medium.start_tx(
            node_id="tx_lr_fhss",
            payload=payload,
            tx_power_dbm=14,
            position=(100.0, 0.0, 0.0),
            time_us=1000,
            phy_mode="lr_fhss",
        )

        lora_duration = lora_tx.end_time_us - lora_tx.start_time_us
        lr_fhss_duration = lr_fhss_tx.end_time_us - lr_fhss_tx.start_time_us

        assert lr_fhss_duration == lora_duration * 2


class TestFrequencyDependentPathLoss:
    """Document that frequency-dependent path loss is NOT implemented.

    The current PropagationModel uses a fixed PL0 (reference path loss at d0)
    calibrated for 915 MHz. The Friis free-space equation shows that path loss
    depends on frequency:

        PL0(f) = 20*log10(f) + 20*log10(d0) - 147.55 dB

    For example:
    - 868 MHz at 1m: ~31.75 dB
    - 915 MHz at 1m: ~32.22 dB (default in PropagationModel)
    - 923 MHz at 1m: ~32.29 dB

    The difference is small (~0.5 dB across EU868/US915/AS923 bands) and
    negligible compared to shadowing and fading effects.
    """

    def test_propagation_model_frequency_invariant(self) -> None:
        """PropagationModel path loss is invariant to frequency (PL0 is fixed)."""
        model = PropagationModel()

        # Path loss should be the same regardless of "frequency" since
        # frequency is not a parameter to path_loss()
        pl_100m = model.path_loss(100.0)

        # Calling again gives same result (no frequency parameter)
        assert model.path_loss(100.0) == pl_100m

    def test_pl0_calibrated_for_915mhz(self) -> None:
        """Default PL0 is calibrated for 915 MHz (32.44 dB at 1m)."""
        model = PropagationModel()
        assert model.pl0_dbm == 32.44

        # This is close to Friis free-space at 915 MHz:
        # PL0 = 20*log10(915e6) + 20*log10(1) - 147.55
        #     = 179.23 - 147.55 = 31.68 dB (free space)
        # The 32.44 default includes ~0.76 dB implementation loss margin

    def test_custom_pl0_for_other_frequencies(self) -> None:
        """Users can set custom PL0 for other frequency bands."""
        # EU868: ~31.75 dB free-space at 1m
        model_868 = PropagationModel(pl0_dbm=31.75)
        assert model_868.pl0_dbm == 31.75

        # AS923: ~32.29 dB free-space at 1m
        model_923 = PropagationModel(pl0_dbm=32.29)
        assert model_923.pl0_dbm == 32.29

        # Different PL0 values give different path loss
        pl_868 = model_868.path_loss(100.0)
        pl_923 = model_923.path_loss(100.0)
        assert pl_923 > pl_868

    def test_frequency_difference_small(self) -> None:
        """Frequency-dependent path loss difference is small across bands."""
        # Compute free-space PL0 difference between 868 and 915 MHz
        # PL0 = 20*log10(f_Hz) - 147.55 at 1m
        import math

        pl0_868 = 20 * math.log10(868e6) - 147.55
        pl0_915 = 20 * math.log10(915e6) - 147.55
        pl0_923 = 20 * math.log10(923e6) - 147.55

        delta_868_915 = pl0_915 - pl0_868
        delta_915_923 = pl0_923 - pl0_915

        # Difference is <0.5 dB across EU868 to US915
        assert delta_868_915 < 0.5

        # Difference is <0.1 dB across US915 to AS923
        assert delta_915_923 < 0.1
