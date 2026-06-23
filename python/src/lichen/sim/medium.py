"""Radio medium simulation for the LICHEN simulator.

This module provides the Medium class that tracks active transmissions and
handles radio propagation, including collision detection with capture effect.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from lichen.sim.propagation import CAPTURE_THRESHOLD_DB, SENSITIVITY_SF10, PropagationModel
from lichen.sim.transmission import Transmission, airtime_us


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


class Medium:
    """Radio medium that tracks transmissions and handles propagation.

    The medium models the shared radio channel, tracking all active
    transmissions and computing received signal strengths based on
    distance and propagation characteristics. It handles collision
    detection with capture effect.

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
        self._active_transmissions: list[Transmission] = []
        self._tx_positions: dict[str, tuple[float, float, float]] = {}

    def start_tx(
        self,
        node_id: str,
        payload: bytes,
        tx_power_dbm: int,
        position: tuple[float, float, float],
        time_us: int,
    ) -> Transmission:
        """Start a new transmission.

        Creates a Transmission object with calculated end time based on
        payload length, adds it to the active transmissions list, and
        stores the transmitter position.

        Args:
            node_id: ID of the transmitting node.
            payload: Raw bytes being transmitted.
            tx_power_dbm: Transmit power in dBm.
            position: (x, y, z) position of the transmitter in meters.
            time_us: Current simulation time in microseconds.

        Returns:
            The created Transmission object.
        """
        duration_us = airtime_us(len(payload))
        tx = Transmission(
            source_node_id=node_id,
            payload=payload,
            tx_power_dbm=tx_power_dbm,
            start_time_us=time_us,
            end_time_us=time_us + duration_us,
        )
        self._active_transmissions.append(tx)
        self._tx_positions[tx.id] = position
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
    ) -> list[RxCandidate]:
        """Get all decodable transmissions for a receiver.

        For each active transmission (excluding transmissions from the
        receiver itself), calculates distance, RSSI, and SNR. Only
        includes transmissions that can be decoded based on sensitivity.

        Args:
            rx_node_id: ID of the receiving node.
            rx_position: (x, y, z) position of the receiver in meters.
            time_us: Current simulation time in microseconds.

        Returns:
            List of RxCandidate objects for decodable transmissions.
        """
        candidates: list[RxCandidate] = []
        active = self.get_active_transmissions(time_us)

        for tx in active:
            # Skip self-transmission
            if tx.source_node_id == rx_node_id:
                continue

            # Get transmitter position
            tx_pos = self._tx_positions.get(tx.id)
            if tx_pos is None:
                continue

            # Calculate 3D distance
            distance = math.sqrt(
                (rx_position[0] - tx_pos[0]) ** 2
                + (rx_position[1] - tx_pos[1]) ** 2
                + (rx_position[2] - tx_pos[2]) ** 2
            )

            # Avoid division by zero for co-located nodes
            if distance <= 0:
                distance = 0.001  # 1mm minimum

            # Calculate RSSI and SNR
            rssi = self.propagation.received_power(tx.tx_power_dbm, distance)
            snr = rssi - self.noise_floor_dbm

            # Check if signal can be decoded
            if self.propagation.can_decode(
                tx.tx_power_dbm, distance, sensitivity_dbm=SENSITIVITY_SF10
            ):
                candidates.append(RxCandidate(transmission=tx, rssi=rssi, snr=snr))

        return candidates

    def resolve_reception(self, candidates: list[RxCandidate]) -> Transmission | None:
        """Resolve which transmission is received given collision candidates.

        Implements collision detection with capture effect:
        - If 0 candidates: return None (nothing to receive)
        - If 1 candidate: return its transmission (clean reception)
        - If multiple candidates: apply capture effect
            - Sort by RSSI descending
            - If strongest >= CAPTURE_THRESHOLD_DB above second: strongest wins
            - Otherwise: collision, return None

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
        second = sorted_candidates[1]

        # Check capture effect: strongest must be >= 6 dB above second
        if strongest.rssi - second.rssi >= CAPTURE_THRESHOLD_DB:
            return strongest.transmission

        # Collision: neither can be decoded
        return None
