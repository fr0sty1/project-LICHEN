# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio medium simulation for the LICHEN simulator.

This module provides the Medium class that tracks active transmissions and
handles radio propagation, including collision detection with capture effect
and SINR-based interference resolution.

LoRa BER (bit error rate) as a function of SNR for a given SF and CR is
modelled using the closed-form approximation from:
    Croce, D. et al. (2017). "Impact of LoRa Imperfect Orthogonality:
    Analysis of Link-level Performance."
    IEEE Communications Letters, 21(4), 796-799.

The BER model uses SF-dependent SNR thresholds for 50% PER:

    SNR_th(SF) = sensitivity(SF) - noise_floor

At a given SINR, the packet error probability is:
    PER = 1 - (1 - BER(SINR, SF))^(num_bits)

See spec/02a-physical-layer.md for link budget analysis and fade margin.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from lichen.sim.propagation import (
    CAPTURE_THRESHOLD_DB,
    SENSITIVITY_DEFAULT,
    SENSITIVITY_LR_FHSS,
    SENSITIVITY_SF10,
    SENSITIVITY_SF7,
    SENSITIVITY_SF8,
    SENSITIVITY_SF9,
    SENSITIVITY_SF11,
    SENSITIVITY_SF12,
    PropagationModel,
)
from lichen.sim.transmission import Transmission, airtime_us, lr_fhss_airtime_us


# LoRa SNR thresholds (dB) for reliable decoding at each SF (Croce et al. 2017)
# These are the SNR (not absolute RSSI) required for ~50% PER with CR=4/5.
SNR_THRESHOLD_SF7 = SENSITIVITY_SF7 - (-120.0)  # -3.0 dB at NF=-120
SNR_THRESHOLD_SF8 = SENSITIVITY_SF8 - (-120.0)  # -6.0 dB
SNR_THRESHOLD_SF9 = SENSITIVITY_SF9 - (-120.0)  # -9.0 dB
SNR_THRESHOLD_SF10 = SENSITIVITY_SF10 - (-120.0)  # -12.0 dB
SNR_THRESHOLD_SF11 = SENSITIVITY_SF11 - (-120.0)  # -14.5 dB
SNR_THRESHOLD_SF12 = SENSITIVITY_SF12 - (-120.0)  # -17.0 dB


@dataclass
class RxCandidate:
    """A candidate transmission that a receiver might decode.

    Attributes:
        transmission: The transmission being received.
        rssi: Received signal strength indicator in dBm.
        snr: Signal-to-noise ratio in dB (before interference).
        added_latency_us: Extra delivery delay in microseconds (set by LatencyRule).
    """

    transmission: Transmission
    rssi: float
    snr: float
    added_latency_us: int = 0
    is_lr_fhss: bool = False


class Medium:
    """Radio medium that tracks transmissions and handles propagation.

    Supports multi-channel operation with independent collision/propagation
    oracles per channel. For CCP-12 rendezvous, get_rx_candidates,
    detect_activity, and start_tx use hop channel computed from SFN/EUI
    (via node's hop_schedule or synchronized_hop_channel helper). Keeps
    LR-FHSS support via rx_frequency_hz filter.

    Attributes:
        propagation: The propagation model used for path loss calculations.
        noise_floor_dbm: Receiver noise floor in dBm.
    """

    def __init__(
        self,
        propagation: PropagationModel | None = None,
        noise_floor_dbm: float = -120.0,
    ) -> None:
        """Initialize the radio medium.

        Args:
            propagation: Propagation model for path loss calculations.
                Uses default PropagationModel if not provided.
            noise_floor_dbm: Receiver noise floor in dBm. Default is -120.0.
        """
        self.propagation = propagation if propagation is not None else PropagationModel()
        self.noise_floor_dbm = noise_floor_dbm
        self.density_estimate = 0.0
        self._active_transmissions: list[Transmission] = []
        self._tx_positions: dict[str, tuple[float, float, float]] = {}

    def start_tx(
        self,
        node_id: str,
        payload: bytes,
        tx_power_dbm: int,
        position: tuple[float, float, float],
        time_us: int,
        channel: int = 0,
        phy_mode: str = "lora",
    ) -> Transmission:
        """Tag transmission with hop channel computed from SFN/EUI (via
        hop_schedule or helper per CCP-12). Keeps LR-FHSS airtime support.
        """
        if phy_mode == "lr_fhss":
            duration_us = lr_fhss_airtime_us(len(payload))
        else:
            duration_us = airtime_us(len(payload))
        tx = Transmission(
            source_node_id=node_id,
            payload=payload,
            tx_power_dbm=tx_power_dbm,
            start_time_us=time_us,
            end_time_us=time_us + duration_us,
            channel=channel,
            phy_mode=phy_mode,
        )
        self._active_transmissions.append(tx)
        self._tx_positions[tx.id] = position
        self.density_estimate = len(self._active_transmissions) / 10.0
        return tx

    def end_tx(self, transmission_id: str) -> None:
        """Remove a transmission from the active list.

        Args:
            transmission_id: ID of the transmission to remove.
        """
        self._active_transmissions = [
            tx for tx in self._active_transmissions if tx.id != transmission_id
        ]
        self._tx_positions.pop(transmission_id, None)

    def get_active_transmissions(self, time_us: int) -> list[Transmission]:
        """Get all transmissions active at a given time.

        A transmission is active if start_time <= time_us < end_time.

        Args:
            time_us: Simulation time in microseconds.

        Returns:
            List of active Transmission objects.
        """
        return [
            tx
            for tx in self._active_transmissions
            if tx.start_time_us <= time_us < tx.end_time_us
        ]

    def get_rx_candidates(
        self,
        rx_node_id: str,
        rx_position: tuple[float, float, float],
        time_us: int,
        channel: int = 0,
        rx_frequency_hz: int | None = None,
    ) -> list[RxCandidate]:
        """Get all decodable transmissions for a receiver on given channel.

        Uses hop channel computed from SFN/EUI via node's hop_schedule or
        synchronized_hop_channel helper per CCP-12. Only considers TX on
        matching channel. Independent oracle per channel. Supports LR-FHSS
        via optional rx_frequency_hz filter.

        For each active transmission on matching channel (excluding self),
        calculates distance, RSSI, and SNR. Only includes decodable ones.

        Args:
            rx_node_id: ID of the receiving node.
            rx_position: (x, y, z) position of the receiver in meters.
            time_us: Current simulation time in microseconds.
            channel: Hop channel from SFN/EUI (default 0).
            rx_frequency_hz: Optional frequency filter for LR-FHSS hops.

        Returns:
            List of RxCandidate objects for decodable transmissions.
        """
        candidates: list[RxCandidate] = []
        active = [
            tx
            for tx in self.get_active_transmissions(time_us)
            if tx.channel == channel
        ]

        for tx in active:
            if tx.source_node_id == rx_node_id:
                continue
            if rx_frequency_hz is not None and tx.frequency_hz != rx_frequency_hz:
                continue

            tx_pos = self._tx_positions.get(tx.id)
            if tx_pos is None:
                continue

            distance = math.sqrt(
                (rx_position[0] - tx_pos[0]) ** 2
                + (rx_position[1] - tx_pos[1]) ** 2
                + (rx_position[2] - tx_pos[2]) ** 2
            )

            if distance <= 0:
                distance = 0.001

            rssi = self.propagation.received_power(tx.tx_power_dbm, distance)
            snr = rssi - self.noise_floor_dbm
            is_lr_fhss = tx.phy_mode == "lr_fhss"
            sensitivity = SENSITIVITY_LR_FHSS if is_lr_fhss else SENSITIVITY_SF10
            if self.propagation.can_decode(
                tx.tx_power_dbm, distance, sensitivity_dbm=sensitivity
            ):
                candidates.append(
                    RxCandidate(
                        transmission=tx, rssi=rssi, snr=snr, is_lr_fhss=is_lr_fhss
                    )
                )


        return candidates

    def _sf_from_phy_mode(self, phy_mode: str) -> int | None:
        """Infer SF from phy_mode string (e.g. 'lora_sf7', 'lora_sf12', 'lora')."""
        if phy_mode.startswith("lora"):
            parts = phy_mode.split("_")
            if len(parts) >= 2 and parts[1].startswith("sf"):
                try:
                    return int(parts[1][2:])
                except (ValueError, IndexError):
                    return None
            return 10
        return None

    def _snr_threshold(self, sf: int | None) -> float:
        """Return the SNR threshold (dB) for a given SF."""
        thresholds = {
            7: SNR_THRESHOLD_SF7,
            8: SNR_THRESHOLD_SF8,
            9: SNR_THRESHOLD_SF9,
            10: SNR_THRESHOLD_SF10,
            11: SNR_THRESHOLD_SF11,
            12: SNR_THRESHOLD_SF12,
        }
        return thresholds.get(sf, SNR_THRESHOLD_SF10)

    def _packet_error_probability(self, sinr_db: float, sf: int | None, num_bits: int) -> float:
        """Estimate packet error probability from SINR.

        Uses a simplified BER model based on Croce et al. 2017, adapted
        for co-channel interference. For same-SF co-channel collisions,
        the required SINR for reliable decoding is approximately the
        Ec/N0 threshold (≈ 5-10 dB depending on SF), not the far lower
        SNR sensitivity threshold.

        The reference threshold is set at SINR_th = max(SNR_th(SF), 2.0 dB),
        ensuring that co-channel interference (which directly reduces SINR)
        produces meaningful PER estimates:
          - SINR >= SINR_th + 2.0: near-zero PER
          - SINR <= SINR_th - 10.0: near-certain loss
          - Exponential transition in between

        Args:
            sinr_db: Signal-to-interference-plus-noise ratio (dB).
            sf: Spreading factor (7-12).
            num_bits: Number of bits in the packet payload + header.

        Returns:
            Packet error probability (0.0 to 1.0).
        """
        snr_sens = self._snr_threshold(sf)
        sinr_th = max(snr_sens, 2.0)

        if sinr_db >= sinr_th + 2.0:
            return 0.0

        if sinr_db <= sinr_th - 10.0:
            return 1.0

        alpha = 0.5 if sf and sf >= 11 else 0.7
        ber = 0.5 * math.exp(-alpha * (sinr_db - sinr_th))
        ber = max(0.0, min(1.0, ber))
        per = 1.0 - (1.0 - ber) ** num_bits
        return min(1.0, max(0.0, per))

    def resolve_reception(
        self,
        candidates: list[RxCandidate],
        *,
        use_sinr: bool = False,
    ) -> Transmission | None:
        """Resolve which transmission is received given collision candidates.

        Two resolution modes:
          - Standard (use_sinr=False): legacy capture-effect model. Single
            candidate always succeeds. Multiple candidates with >=6 dB delta
            = strongest wins; otherwise total loss. LR-FHSS wins with up to 4
            concurrent transmissions.
          - SINR-based (use_sinr=True): computes signal-to-interference-plus-
            noise ratio for each candidate (treating all other candidates as
            interference). Uses BER/PER model to probabilistically decide
            reception. Candidate with lowest PER (if below threshold) wins.

        Args:
            candidates: List of RxCandidate objects to resolve.
            use_sinr: If True, use SINR-based probabilistic resolution.

        Returns:
            The successfully received Transmission, or None if collision
            or no signal.
        """
        if len(candidates) == 0:
            return None

        if len(candidates) == 1:
            return candidates[0].transmission

        if use_sinr:
            noise_linear = 10.0 ** (self.noise_floor_dbm / 10.0)

            best_per = 1.0
            best_candidate: RxCandidate | None = None

            for c in candidates:
                desired_linear = 10.0 ** (c.rssi / 10.0)

                interference_linear = noise_linear
                for other in candidates:
                    if other is c:
                        continue
                    interference_linear += 10.0 ** (other.rssi / 10.0)

                sinr_linear = desired_linear / max(interference_linear, 1e-30)
                sinr_db = 10.0 * math.log10(max(sinr_linear, 1e-30))

                sf = self._sf_from_phy_mode(c.transmission.phy_mode)
                num_bits = (len(c.transmission.payload) * 8) + 48
                per = self._packet_error_probability(sinr_db, sf, num_bits)

                if per < best_per:
                    best_per = per
                    best_candidate = c

            if best_candidate is not None and best_per < 0.5:
                return best_candidate.transmission
            return None

        sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)

        strongest = sorted_candidates[0]
        if strongest.transmission.phy_mode == "lr_fhss":
            if len(sorted_candidates) <= 4:
                return strongest.transmission
            return None
        if len(sorted_candidates) < 2:
            return strongest.transmission
        second = sorted_candidates[1]
        if strongest.rssi - second.rssi >= CAPTURE_THRESHOLD_DB:
            return strongest.transmission
        return None

    def detect_activity(
        self,
        position: tuple[float, float, float],
        time_us: int,
        sensitivity_dbm: float = SENSITIVITY_DEFAULT,
        channel: int = 0,
        rx_frequency_hz: int | None = None,
    ) -> bool:
        """Detect if any transmission is active and detectable at a position
        on the specified channel.

        Uses hop channel from SFN/EUI via node's hop_schedule or helper per
        CCP-12 for rendezvous. Supports LR-FHSS via rx_frequency_hz.
        Independent per-channel oracle.

        Args:
            position: (x, y, z) position of the detector in meters.
            time_us: Current simulation time in microseconds.
            sensitivity_dbm: Receiver sensitivity threshold in dBm.
                Defaults to SF10 sensitivity (-132 dBm).
            channel: Hop channel computed from SFN/EUI (default 0).
            rx_frequency_hz: Optional frequency filter for LR-FHSS hops.

        Returns:
            True if channel activity is detected, False otherwise.
        """
        active = [
            tx
            for tx in self.get_active_transmissions(time_us)
            if tx.channel == channel
        ]

        for tx in active:
            if rx_frequency_hz is not None and tx.frequency_hz != rx_frequency_hz:
                continue
            tx_pos = self._tx_positions.get(tx.id)
            if tx_pos is None:
                continue

            distance = math.sqrt(
                (position[0] - tx_pos[0]) ** 2
                + (position[1] - tx_pos[1]) ** 2
                + (position[2] - tx_pos[2]) ** 2
            )

            if distance <= 0:
                distance = 0.001

            rx_power = self.propagation.received_power(tx.tx_power_dbm, distance)

            if rx_power >= sensitivity_dbm:
                return True

        return False
