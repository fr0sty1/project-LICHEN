# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the local radio medium (:mod:`lichen.sim.medium`).

Expected RSSI values are hand-computed from the log-distance model with the
default PropagationModel parameters (PL0 = 32.44 dB at 1 m, n = 2.7, no
shadowing or fading):

    PL(d) = 32.44 + 27 * log10(d)        RSSI = tx_power - PL(d)

    d = 10 m     -> PL =  59.44 dB   -> RSSI(14 dBm) =  -45.44 dBm
    d = 100 m    -> PL =  86.44 dB   -> RSSI(14 dBm) =  -72.44 dBm
    d = 1000 m   -> PL = 113.44 dB   -> RSSI(14 dBm) =  -99.44 dBm
    d = 100 km   -> PL = 167.44 dB   -> RSSI(14 dBm) = -153.44 dBm

Airtime for a 10-byte payload at SF10/125kHz/CR4-5, derived independently
from the LoRa airtime formula: n_payload = ceil((8*10 - 40 + 28 + 16)/40)*5
= 15 symbols, total = 8 + 4.25 + 8 + 15 = 35.25 symbols at 8192 us/symbol
= 288768 us. The pinned dependency's airtime_us truncates its float product
to int(), landing 1 us low, so window assertions allow that tolerance.
"""

import pytest

from lichen.sim.medium import Medium

AIRTIME_10B_US = 288_768
MID_AIRTIME_US = AIRTIME_10B_US // 2
PAYLOAD = b"0123456789"


class TestSingleTxDelivery:
    """A lone transmission is delivered to an in-range receiver."""

    def test_single_tx_delivery(self) -> None:
        """One active TX yields a single candidate and is received."""
        medium = Medium()
        tx = medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_b", (100.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(candidates) == 1
        candidate_tx, rssi, snr = candidates[0]
        assert candidate_tx is tx
        assert rssi == pytest.approx(-72.44)
        assert snr == pytest.approx(rssi - (-120.0))
        assert medium.resolve_reception(candidates) is tx

    def test_no_delivery_after_airtime(self) -> None:
        """Nothing is received once the transmission has ended."""
        medium = Medium()
        medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_b", (100.0, 0.0, 0.0), AIRTIME_10B_US)

        assert candidates == []
        assert medium.resolve_reception(candidates) is None

    def test_own_transmission_not_candidate(self) -> None:
        """A node does not receive its own transmission."""
        medium = Medium()
        medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_a", (100.0, 0.0, 0.0), MID_AIRTIME_US)

        assert candidates == []


class TestCollisionBothLost:
    """Overlapping transmissions of similar strength destroy each other."""

    def test_collision_both_lost(self) -> None:
        """Two simultaneous TXs with equal RSSI at the receiver are both lost."""
        medium = Medium()
        medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)
        medium.start_tx("node_b", PAYLOAD, 14, (200.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_c", (100.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(candidates) == 2
        assert candidates[0][1] == pytest.approx(candidates[1][1])
        assert medium.resolve_reception(candidates) is None


class TestCaptureEffect:
    """A sufficiently stronger signal captures the receiver."""

    def test_capture_effect_winner(self) -> None:
        """The strongest TX wins when it is 6+ dB above the second strongest."""
        medium = Medium()
        strong = medium.start_tx("node_a", PAYLOAD, 14, (10.0, 0.0, 0.0), 0)
        medium.start_tx("node_b", PAYLOAD, 14, (1000.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_c", (0.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(candidates) == 2
        assert medium.resolve_reception(candidates) is strong

    def test_capture_at_exact_threshold(self) -> None:
        """A delta of exactly 6 dB still captures (threshold is inclusive)."""
        medium = Medium()
        strong = medium.start_tx("node_a", PAYLOAD, 14, (100.0, 0.0, 0.0), 0)
        medium.start_tx("node_b", PAYLOAD, 8, (100.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_c", (0.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(candidates) == 2
        assert candidates[0][1] - candidates[1][1] == pytest.approx(6.0)
        assert medium.resolve_reception(candidates) is strong

    def test_below_threshold_both_lost(self) -> None:
        """A delta of 5 dB is below the threshold, so both are lost."""
        medium = Medium()
        medium.start_tx("node_a", PAYLOAD, 14, (100.0, 0.0, 0.0), 0)
        medium.start_tx("node_b", PAYLOAD, 9, (100.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_c", (0.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(candidates) == 2
        assert medium.resolve_reception(candidates) is None


class TestNoiseFloor:
    """Signals at or below the noise floor are never candidates."""

    def test_below_default_noise_floor_excluded(self) -> None:
        """A signal at -153.44 dBm is below the -120 dBm default floor."""
        medium = Medium()
        medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        candidates = medium.get_rx_candidates("node_b", (100_000.0, 0.0, 0.0), MID_AIRTIME_US)

        assert candidates == []

    def test_custom_noise_floor(self) -> None:
        """Raising the noise floor drops previously audible signals."""
        audible = Medium()
        audible.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)
        quiet = Medium(noise_floor_dbm=-90.0)
        quiet.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        audible_candidates = audible.get_rx_candidates("node_b", (1000.0, 0.0, 0.0), MID_AIRTIME_US)
        quiet_candidates = quiet.get_rx_candidates("node_b", (1000.0, 0.0, 0.0), MID_AIRTIME_US)

        assert len(audible_candidates) == 1
        assert quiet_candidates == []


class TestTransmissionTracking:
    """The medium tracks the lifecycle of active transmissions."""

    def test_active_window(self) -> None:
        """A TX is active from its start time until its airtime elapses."""
        medium = Medium()
        tx = medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 1000)

        assert tx.start_time_us == 1000
        assert tx.end_time_us == pytest.approx(1000 + AIRTIME_10B_US, abs=1)
        assert medium.get_active_transmissions(1000) == [tx]
        assert medium.get_active_transmissions(1000 + AIRTIME_10B_US) == []

    def test_end_tx_removes_transmission(self) -> None:
        """end_tx removes a transmission before its airtime elapses."""
        medium = Medium()
        tx = medium.start_tx("node_a", PAYLOAD, 14, (0.0, 0.0, 0.0), 0)

        medium.end_tx(tx.id)

        assert medium.get_active_transmissions(MID_AIRTIME_US) == []
