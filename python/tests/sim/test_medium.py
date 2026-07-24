# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the radio medium simulation."""

import pytest

from lichen.sim.medium import Medium, RxCandidate
from lichen.sim.propagation import CAPTURE_THRESHOLD_DB, SENSITIVITY_SF10, PropagationModel
from lichen.sim.transmission import Transmission, airtime_us


class TestMediumBasics:
    """Test basic Medium functionality."""

    def test_default_propagation_model(self) -> None:
        """Medium uses default PropagationModel when none provided."""
        medium = Medium()
        assert medium.propagation is not None
        assert isinstance(medium.propagation, PropagationModel)

    def test_custom_propagation_model(self) -> None:
        """Medium uses custom propagation model when provided."""
        custom_model = PropagationModel(n=3.0)
        medium = Medium(propagation=custom_model)
        assert medium.propagation is custom_model

    def test_default_noise_floor(self) -> None:
        """Medium uses -120 dBm noise floor by default."""
        medium = Medium()
        assert medium.noise_floor_dbm == -120.0

    def test_custom_noise_floor(self) -> None:
        """Medium uses custom noise floor when provided."""
        medium = Medium(noise_floor_dbm=-110.0)
        assert medium.noise_floor_dbm == -110.0


class TestStartTx:
    """Test transmission creation."""

    def test_start_tx_creates_transmission(self) -> None:
        """start_tx creates a Transmission with correct parameters."""
        medium = Medium()
        payload = b"test payload"
        tx = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        assert isinstance(tx, Transmission)
        assert tx.source_node_id == "node1"
        assert tx.payload == payload
        assert tx.tx_power_dbm == 14
        assert tx.start_time_us == 1000

    def test_start_tx_calculates_end_time(self) -> None:
        """start_tx calculates correct end time from airtime."""
        medium = Medium()
        payload = b"test payload"
        start_time = 1000
        expected_duration = airtime_us(len(payload))

        tx = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=start_time,
        )

        assert tx.end_time_us == start_time + expected_duration

    def test_start_tx_adds_to_active_list(self) -> None:
        """start_tx adds transmission to active list."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        active = medium.get_active_transmissions(tx.start_time_us)
        assert tx in active


class TestEndTx:
    """Test transmission removal."""

    def test_end_tx_removes_transmission(self) -> None:
        """end_tx removes transmission from active list."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        medium.end_tx(tx.id)

        active = medium.get_active_transmissions(tx.start_time_us)
        assert tx not in active

    def test_end_tx_nonexistent_is_safe(self) -> None:
        """end_tx with nonexistent ID does not raise."""
        medium = Medium()
        medium.end_tx("nonexistent-id")  # Should not raise


class TestGetActiveTransmissions:
    """Test active transmission queries."""

    def test_get_active_transmissions_includes_ongoing(self) -> None:
        """get_active_transmissions includes transmissions in progress."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # During transmission
        mid_time = tx.start_time_us + (tx.end_time_us - tx.start_time_us) // 2
        active = medium.get_active_transmissions(mid_time)
        assert tx in active

    def test_get_active_transmissions_excludes_finished(self) -> None:
        """get_active_transmissions excludes completed transmissions."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # After transmission ends
        active = medium.get_active_transmissions(tx.end_time_us)
        assert tx not in active

    def test_get_active_transmissions_at_start_time(self) -> None:
        """Transmission is active at its start time."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        active = medium.get_active_transmissions(tx.start_time_us)
        assert tx in active

    def test_get_active_transmissions_before_start(self) -> None:
        """Transmission is not active before start time."""
        medium = Medium()
        tx = medium.start_tx(
            node_id="node1",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        active = medium.get_active_transmissions(tx.start_time_us - 1)
        assert tx not in active


class TestSingleTxDelivery:
    """Test single transmission delivery (no collision)."""

    def test_single_tx_delivered_to_nearby_receiver(self) -> None:
        """Single transmission is delivered to receiver in range."""
        medium = Medium()

        # Transmitter at origin
        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Receiver 100m away (well within range)
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
        )

        assert len(candidates) == 1
        assert candidates[0].transmission is tx
        assert candidates[0].rssi < 0  # Received power is negative dBm
        assert candidates[0].snr > 0  # SNR is positive

    def test_single_tx_resolves_successfully(self) -> None:
        """Single transmission resolves to successful reception."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
        )

        result = medium.resolve_reception(candidates)
        assert result is tx


class TestOutOfRange:
    """Test out-of-range scenarios (no candidates)."""

    def test_no_candidates_when_out_of_range(self) -> None:
        """No candidates when receiver is out of range."""
        medium = Medium()

        # Transmitter at origin
        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Calculate max range for this power level
        max_range = medium.propagation.max_range(14, sensitivity_dbm=SENSITIVITY_SF10)

        # Receiver far beyond max range
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(max_range * 2, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
        )

        assert len(candidates) == 0

    def test_resolve_returns_none_with_no_candidates(self) -> None:
        """resolve_reception returns None when no candidates."""
        medium = Medium()
        result = medium.resolve_reception([])
        assert result is None


class TestCollisionBothLost:
    """Test collision scenarios where both transmissions are lost."""

    def test_equal_power_collision_loses_both(self) -> None:
        """Equal power transmissions collide and both are lost."""
        medium = Medium()

        # Two transmitters equidistant from receiver
        medium.start_tx(
            node_id="tx1",
            payload=b"hello1",
            tx_power_dbm=14,
            position=(0.0, 100.0, 0.0),
            time_us=1000,
        )
        medium.start_tx(
            node_id="tx2",
            payload=b"hello2",
            tx_power_dbm=14,
            position=(0.0, -100.0, 0.0),
            time_us=1000,
        )

        # Receiver at origin (equidistant from both transmitters)
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 1000,
        )

        assert len(candidates) == 2

        # Both signals have same RSSI (equidistant)
        rssi_diff = abs(candidates[0].rssi - candidates[1].rssi)
        assert rssi_diff < 0.01  # Effectively equal

        # Collision: neither wins
        result = medium.resolve_reception(candidates)
        assert result is None

    def test_nearly_equal_power_collision(self) -> None:
        """Transmissions with <6dB difference collide."""
        medium = Medium()

        # Two transmitters at slightly different distances
        # 100m vs ~130m gives approximately 3dB difference (less than 6dB threshold)
        medium.start_tx(
            node_id="tx1",
            payload=b"hello1",
            tx_power_dbm=14,
            position=(100.0, 0.0, 0.0),
            time_us=1000,
        )
        medium.start_tx(
            node_id="tx2",
            payload=b"hello2",
            tx_power_dbm=14,
            position=(-130.0, 0.0, 0.0),
            time_us=1000,
        )

        # Receiver at origin
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 1000,
        )

        assert len(candidates) == 2

        # RSSI difference should be less than capture threshold
        sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)
        rssi_diff = sorted_candidates[0].rssi - sorted_candidates[1].rssi
        assert rssi_diff < CAPTURE_THRESHOLD_DB

        # Collision: neither wins
        result = medium.resolve_reception(candidates)
        assert result is None


class TestCaptureEffect:
    """Test capture effect (stronger signal wins)."""

    def test_capture_effect_stronger_wins(self) -> None:
        """Stronger signal wins when >= 6dB above weaker."""
        medium = Medium()

        # Close transmitter (strong signal)
        tx_strong = medium.start_tx(
            node_id="tx_strong",
            payload=b"strong signal",
            tx_power_dbm=14,
            position=(50.0, 0.0, 0.0),
            time_us=1000,
        )
        # Far transmitter (weak signal)
        # 50m vs 500m gives ~27dB difference (well above 6dB threshold)
        medium.start_tx(
            node_id="tx_weak",
            payload=b"weak signal",
            tx_power_dbm=14,
            position=(-500.0, 0.0, 0.0),
            time_us=1000,
        )

        # Receiver at origin
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(0.0, 0.0, 0.0),
            time_us=1000 + 1000,
        )

        assert len(candidates) == 2

        # RSSI difference should exceed capture threshold
        sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)
        rssi_diff = sorted_candidates[0].rssi - sorted_candidates[1].rssi
        assert rssi_diff >= CAPTURE_THRESHOLD_DB

        # Strong signal wins
        result = medium.resolve_reception(candidates)
        assert result is tx_strong

    def test_capture_effect_exactly_at_threshold(self) -> None:
        """Signal exactly at 6dB threshold wins."""
        # Create RxCandidates manually to test exact threshold
        medium = Medium()
        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
        )

        # Exactly 6dB difference
        candidates = [
            RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0),
            RxCandidate(transmission=tx2, rssi=-76.0, snr=44.0),
        ]

        result = medium.resolve_reception(candidates)
        assert result is tx1

    def test_capture_effect_just_below_threshold(self) -> None:
        """Signal just below 6dB threshold causes collision."""
        medium = Medium()
        tx1 = Transmission(
            source_node_id="tx1",
            payload=b"strong",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
        )
        tx2 = Transmission(
            source_node_id="tx2",
            payload=b"weak",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
        )

        # Just under 6dB difference (5.99 dB)
        candidates = [
            RxCandidate(transmission=tx1, rssi=-70.0, snr=50.0),
            RxCandidate(transmission=tx2, rssi=-75.99, snr=44.01),
        ]

        result = medium.resolve_reception(candidates)
        assert result is None


class TestFrequencyFilter:
    """Test frequency filtering for LR-FHSS support."""

    def test_frequency_filter_matches(self) -> None:
        """rx_frequency_hz filter includes transmission on matching frequency."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Override the default frequency
        tx.frequency_hz = 920_000_000

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
            rx_frequency_hz=920_000_000,
        )

        assert len(candidates) == 1
        assert candidates[0].transmission is tx

    def test_frequency_filter_excludes_nonmatching(self) -> None:
        """rx_frequency_hz filter excludes transmission on different frequency."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Override the default frequency
        tx.frequency_hz = 920_000_000

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
            rx_frequency_hz=915_000_000,
        )

        assert len(candidates) == 0

    def test_frequency_filter_combined_with_channel(self) -> None:
        """rx_frequency_hz filter works alongside channel filter."""
        medium = Medium()

        # Same channel but different frequency
        tx1 = medium.start_tx(
            node_id="tx1",
            payload=b"hello1",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
            channel=1,
        )
        tx1.frequency_hz = 920_000_000

        tx2 = medium.start_tx(
            node_id="tx2",
            payload=b"hello2",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
            channel=1,
        )
        tx2.frequency_hz = 915_000_000

        # Should only match tx1 by frequency
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=1000 + 1000,
            channel=1,
            rx_frequency_hz=920_000_000,
        )

        assert len(candidates) == 1
        assert candidates[0].transmission is tx1

    def test_detect_activity_frequency_filter(self) -> None:
        """detect_activity respects rx_frequency_hz filter."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )
        tx.frequency_hz = 920_000_000

        # Matching frequency
        assert medium.detect_activity(
            position=(100.0, 0.0, 0.0),
            time_us=1000 + 1000,
            rx_frequency_hz=920_000_000,
        )

        # Non-matching frequency
        assert not medium.detect_activity(
            position=(100.0, 0.0, 0.0),
            time_us=1000 + 1000,
            rx_frequency_hz=915_000_000,
        )

    def test_frequency_filter_nonexcluded(self) -> None:
        """No frequency filter passes all transmissions regardless of frequency."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )
        tx.frequency_hz = 920_000_000

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
        )

        assert len(candidates) == 1
        assert candidates[0].transmission is tx


class TestSelfTransmission:
    """Test that nodes don't receive their own transmissions."""

    def test_excludes_self_transmission(self) -> None:
        """Node does not receive its own transmission."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="node1",
            payload=b"hello",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Same node as receiver
        candidates = medium.get_rx_candidates(
            rx_node_id="node1",
            rx_position=(0.0, 0.0, 0.0),
            time_us=tx.start_time_us + 1000,
        )

        assert len(candidates) == 0


class TestRSSIAndSNRCalculations:
    """Test RSSI and SNR calculations."""

    def test_rssi_decreases_with_distance(self) -> None:
        """RSSI decreases as distance increases."""
        medium = Medium()

        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Close receiver
        candidates_close = medium.get_rx_candidates(
            rx_node_id="rx1",
            rx_position=(50.0, 0.0, 0.0),
            time_us=1000 + 100,
        )

        # Start new transmission for second test
        medium.end_tx(tx.id)
        medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=2000,
        )

        # Far receiver
        candidates_far = medium.get_rx_candidates(
            rx_node_id="rx2",
            rx_position=(200.0, 0.0, 0.0),
            time_us=2000 + 100,
        )

        assert len(candidates_close) == 1
        assert len(candidates_far) == 1
        assert candidates_close[0].rssi > candidates_far[0].rssi

    def test_snr_equals_rssi_minus_noise_floor(self) -> None:
        """SNR equals RSSI minus noise floor."""
        noise_floor = -115.0
        medium = Medium(noise_floor_dbm=noise_floor)

        medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(100.0, 0.0, 0.0),
            time_us=1000 + 100,
        )

        assert len(candidates) == 1
        expected_snr = candidates[0].rssi - noise_floor
        assert candidates[0].snr == pytest.approx(expected_snr, rel=1e-6)


class TestThreeDimensionalDistance:
    """Test 3D distance calculations."""

    def test_3d_distance_calculation(self) -> None:
        """Distance is calculated correctly in 3D."""
        medium = Medium()

        # Transmitter at origin
        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Receiver at (30, 40, 0) -> distance = 50m (3-4-5 triangle)
        candidates_2d = medium.get_rx_candidates(
            rx_node_id="rx1",
            rx_position=(30.0, 40.0, 0.0),
            time_us=1000 + 100,
        )

        medium.end_tx(tx.id)
        medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=2000,
        )

        # Receiver at (0, 0, 50) -> distance = 50m (pure Z)
        candidates_z = medium.get_rx_candidates(
            rx_node_id="rx2",
            rx_position=(0.0, 0.0, 50.0),
            time_us=2000 + 100,
        )

        # Both should have same distance (50m), so same RSSI
        assert len(candidates_2d) == 1
        assert len(candidates_z) == 1
        assert candidates_2d[0].rssi == pytest.approx(candidates_z[0].rssi, rel=1e-6)

    def test_full_3d_distance(self) -> None:
        """Full 3D distance sqrt(x^2 + y^2 + z^2) is used."""
        medium = Medium()

        medium.start_tx(
            node_id="tx_node",
            payload=b"test",
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=1000,
        )

        # Receiver at (30, 40, 50) -> distance = sqrt(900+1600+2500) = sqrt(5000) ~ 70.7m
        candidates = medium.get_rx_candidates(
            rx_node_id="rx_node",
            rx_position=(30.0, 40.0, 50.0),
            time_us=1000 + 100,
        )

        assert len(candidates) == 1
        # Verify RSSI corresponds to ~70.7m distance
        import math

        expected_distance = math.sqrt(30**2 + 40**2 + 50**2)
        expected_rssi = medium.propagation.received_power(14, expected_distance)
        assert candidates[0].rssi == pytest.approx(expected_rssi, rel=1e-6)
