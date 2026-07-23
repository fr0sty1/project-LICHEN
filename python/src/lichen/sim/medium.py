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
    SENSITIVITY_SF9,
    SENSITIVITY_SF10,
    SENSITIVITY_SF11,
    SENSITIVITY_SF12,
    PropagationModel,
)
from lichen.sim.tdma import synchronized_hop_channel
from lichen.sim.transmission import Transmission, airtime_us, lr_fhss_airtime_us


@dataclass
class RxCandidate:
    """A candidate transmission that a receiver might decode.

    Attributes:
        transmission: The transmission being received.
        rssi: Received signal strength indicator in dBm.
        snr: Signal-to-noise ratio in dB.
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
    oracles per channel. RX uses rendezvous logic: get_rx_candidates and
    detect_activity only consider TX on the expected hop channel computed
    by calling synchronized_hop_channel(current_sfn, seed=0, num_channels=8).
    start_tx tags TX with the rendezvous channel from synchronized_hop_channel.

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
        if phy_mode == "lr_fhss":
            duration_us = lr_fhss_airtime_us(len(payload))
        else:
            duration_us = airtime_us(len(payload))
        snr_db = float((time_us % 1000) / 100 - 5)
        if snr_db > 10:
            sens = SENSITIVITY_SF9
        elif snr_db > 0:
            sens = SENSITIVITY_SF10
        else:
            sens = SENSITIVITY_SF11
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

        Implements rendezvous: only considers transmissions on the expected
        hop channel computed via synchronized_hop_channel(sfn, seed=0, num_channels=8)
        (called in simulation.py before passing channel here). Provides independent
        oracle for collision/propagation per channel. Supports LR-FHSS by optional
        frequency filter for hopping fragments.

        For each active transmission on matching channel (excluding self),
        calculates distance, RSSI, and SNR. Only includes decodable ones.

        Args:
            rx_node_id: ID of the receiving node.
            rx_position: (x, y, z) position of the receiver in meters.
            time_us: Current simulation time in microseconds.
            channel: Expected hop channel for rendezvous from synchronized_hop_channel (default 0).
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

        Supports both standard LoRa (packet-level) and LR-FHSS (fragment-level):
        - Standard: any significant overlap without capture = total loss
        - LR-FHSS: overlaps corrupt individual fragments only; 1/3 or 2/3 FEC
          allows recovery of strongest signal in many cases
        - 0 candidates: None
        - 1 candidate: success
        - Multiple: sort by RSSI; if strongest.is_lr_fhss then it wins (fragment
          recovery model); else standard capture (>=6dB).

        Args:
            candidates: List of RxCandidate objects to resolve.

        Returns:
            The successfully received Transmission, or None if collision
            or no signal.
        """
        if len(candidates) == 0:
            return None

        if len(candidates) == 1:
            return candidates[0].transmission

        # Sort by RSSI descending (strongest first)
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

        Implements per-channel CAD for multi-channel support and rendezvous.
        The channel param should be from synchronized_hop_channel(sfn, seed=0, num_channels=8)
        for TX/RX rendezvous. Supports LR-FHSS frequency hopping via optional rx_frequency_hz.
        Independent oracle per channel.

        Args:
            position: (x, y, z) position of the detector in meters.
            time_us: Current simulation time in microseconds.
            sensitivity_dbm: Receiver sensitivity threshold in dBm.
                Defaults to SF10 sensitivity (-132 dBm).
            channel: Channel for CAD from synchronized_hop_channel (default 0, matches rendezvous hop).
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

def synchronized_hop_channel(eui64, time_us, epoch=0, density=1, snr_db=0.0):
    h = 0x811c9dc5
    for b in eui64 + epoch.to_bytes(4, "little"):
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return (h % (density + 7)) % 8
