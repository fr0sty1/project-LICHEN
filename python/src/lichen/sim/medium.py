# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio medium simulation for the LICHEN simulator.

This module provides the Medium class that tracks active transmissions and
handles radio propagation, including collision detection with capture effect.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from lichen.sim.propagation import (
    CAPTURE_THRESHOLD_DB,
    SENSITIVITY_DEFAULT,
    SENSITIVITY_LR_FHSS,
    SENSITIVITY_SF10,
    PropagationModel,
)
from lichen.sim.transmission import Transmission, airtime_us, lr_fhss_airtime_us


_LINEAR_EPSILON = 1e-15


def _db_to_linear(dbm: float) -> float:
    return 10.0 ** (dbm / 10.0)


def _linear_to_db(linear: float) -> float:
    if linear <= _LINEAR_EPSILON:
        return -float("inf")
    return 10.0 * math.log10(linear)


@dataclass
class RxCandidate:
    """A candidate transmission that a receiver might decode.

    Attributes:
        transmission: The transmission being received.
        rssi: Received signal strength indicator in dBm.
        snr: Signal-to-noise ratio in dB.
        added_latency_us: Extra delivery delay in microseconds (set by LatencyRule).
        sinr_db: Signal-to-interference-plus-noise ratio in dB. Set during
            resolve_reception when multiple candidates present.
    """

    transmission: Transmission
    rssi: float
    snr: float
    added_latency_us: int = 0
    is_lr_fhss: bool = False
    sinr_db: float | None = None


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

    def resolve_reception(self, candidates: list[RxCandidate]) -> Transmission | None:
        """Resolve which transmission is received given collision candidates.

        Supports both standard LoRa (packet-level) and LR-FHSS (fragment-level).

        Resolution logic:
        - 0 candidates: None
        - 1 candidate: success
        - Multiple: sort by RSSI descending, compute SINR for each.
          - If strongest.is_lr_fhss: strongest wins when <= 4 contenders
            (fragment FEC recovery model); else total loss.
          - Standard capture: strongest wins if RSSI delta >= 6 dB
            (capture effect). Otherwise total collision loss (both lost).

        The SINR of each candidate is computed from interference contributed
        by all other candidates and stored in candidate.sinr_db.

        Args:
            candidates: List of RxCandidate objects to resolve.

        Returns:
            The successfully received Transmission, or None if collision
            or no signal.
        """
        if len(candidates) == 0:
            return None

        if len(candidates) == 1:
            candidates[0].sinr_db = candidates[0].snr
            return candidates[0].transmission

        # Sort by RSSI descending (strongest first)
        sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)

        # Compute SINR for each candidate
        for c in sorted_candidates:
            interferers = [
                _db_to_linear(o.rssi) for o in sorted_candidates if o is not c
            ]
            c.sinr_db = self.propagation.sinr(
                # Reconstruct tx power from RSSI + path loss for SINR calc.
                # For the SINR we use the candidate's RSSI directly as the
                # received signal power (linear), and sum interferers.
                tx_power_dbm=0.0,  # unused in sinr (we pass rssi via below)
                distance_m=1.0,  # unused in sinr
                interfering_powers_linear=interferers,
            )
            # Override sinr with true SINR using signal RSSI
            signal_linear = _db_to_linear(c.rssi)
            noise_linear = _db_to_linear(self.noise_floor_dbm)
            total_interference = sum(interferers)
            total_noise = noise_linear + total_interference
            if total_noise > 0:
                c.sinr_db = _linear_to_db(signal_linear / total_noise)
            else:
                c.sinr_db = float("inf")

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
