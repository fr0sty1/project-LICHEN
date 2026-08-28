# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio medium with transmission tracking, collision detection, and capture effect.

This module provides a focused radio medium for the LICHEN simulator. It
tracks active transmissions, computes per-receiver reception candidates
through :class:`lora_medium.PropagationModel`, and resolves collisions with
the LoRa capture effect: when two or more transmissions overlap in time, the
strongest wins only if its RSSI is at least
:data:`lora_medium.CAPTURE_THRESHOLD_DB` (6 dB) above the second strongest;
otherwise every colliding packet is lost.

Signals at or below the configurable noise floor (default -120 dBm) are
never reported as reception candidates.

This is a deliberately minimal medium. Regulatory duty-cycle enforcement,
hardware quirks, rendezvous channels, TDMA coordination, and LR-FHSS
handling live in the pinned ``lora-medium`` package's fuller ``Medium``.

Example:
    >>> medium = Medium()
    >>> tx = medium.start_tx("node_a", b"hello", 14, (0.0, 0.0, 0.0), 0)
    >>> candidates = medium.get_rx_candidates("node_b", (100.0, 0.0, 0.0), 1000)
    >>> received = medium.resolve_reception(candidates)
"""

from __future__ import annotations

import math

from lora_medium import CAPTURE_THRESHOLD_DB, PropagationModel, Transmission, airtime_us

Position = tuple[float, float, float]


class Medium:
    """Radio medium that tracks transmissions and resolves reception.

    Attributes:
        propagation: Propagation model used for path loss calculations.
        noise_floor_dbm: Receiver noise floor in dBm. Signals received at or
            below this level are not reported as reception candidates.
    """

    def __init__(
        self,
        propagation: PropagationModel | None = None,
        noise_floor_dbm: float = -120.0,
    ) -> None:
        """Initialize the radio medium.

        Args:
            propagation: Propagation model for path loss calculations.
                Uses a default PropagationModel if not provided.
            noise_floor_dbm: Receiver noise floor in dBm. Default is -120.0.
        """
        self.propagation = propagation if propagation is not None else PropagationModel()
        self.noise_floor_dbm = noise_floor_dbm
        self._transmissions: list[Transmission] = []
        self._tx_positions: dict[str, Position] = {}

    def start_tx(
        self,
        node_id: str,
        payload: bytes,
        tx_power: int,
        position: Position,
        time_us: int,
    ) -> Transmission:
        """Create a transmission and add it to the active set.

        Args:
            node_id: ID of the transmitting node.
            payload: Raw bytes being transmitted.
            tx_power: Transmit power in dBm.
            position: (x, y, z) position of the transmitter in meters.
            time_us: Simulation time when the transmission starts, in
                microseconds.

        Returns:
            The new Transmission, active for the LoRa airtime of the payload.
        """
        duration_us = airtime_us(len(payload))
        tx = Transmission(
            source_node_id=node_id,
            payload=payload,
            tx_power_dbm=tx_power,
            start_time_us=time_us,
            end_time_us=time_us + duration_us,
        )
        self._transmissions.append(tx)
        self._tx_positions[tx.id] = position
        return tx

    def end_tx(self, transmission_id: str) -> None:
        """Remove a transmission from the active set.

        Args:
            transmission_id: ID of the transmission to remove.
        """
        self._transmissions = [tx for tx in self._transmissions if tx.id != transmission_id]
        self._tx_positions.pop(transmission_id, None)

    def get_active_transmissions(self, time_us: int) -> list[Transmission]:
        """Return every transmission overlapping the given instant.

        A transmission is active while start_time_us <= time_us < end_time_us.

        Args:
            time_us: Simulation time in microseconds.

        Returns:
            List of active Transmission objects.
        """
        return [tx for tx in self._transmissions if tx.start_time_us <= time_us < tx.end_time_us]

    def get_rx_candidates(
        self,
        node_id: str,
        position: Position,
        time_us: int,
    ) -> list[tuple[Transmission, float, float]]:
        """Return the signals node_id can hear at a given instant.

        Only transmissions that are active at time_us, sent by another node,
        and received above the noise floor are returned. Each candidate is a
        (transmission, rssi, snr) tuple, where RSSI comes from the
        propagation model and SNR is RSSI minus the noise floor.

        Args:
            node_id: ID of the receiving node.
            position: (x, y, z) position of the receiver in meters.
            time_us: Simulation time in microseconds.

        Returns:
            List of (Transmission, rssi, snr) tuples for audible signals.
        """
        candidates: list[tuple[Transmission, float, float]] = []
        for tx in self.get_active_transmissions(time_us):
            if tx.source_node_id == node_id:
                continue
            tx_position = self._tx_positions.get(tx.id)
            if tx_position is None:
                continue
            distance = math.dist(position, tx_position)
            if distance <= 0:
                distance = 0.001
            rssi = self.propagation.received_power(tx.tx_power_dbm, distance)
            if rssi <= self.noise_floor_dbm:
                continue
            candidates.append((tx, rssi, rssi - self.noise_floor_dbm))
        return candidates

    def resolve_reception(
        self,
        candidates: list[tuple[Transmission, float, float]],
    ) -> Transmission | None:
        """Resolve overlapping candidates with the capture effect.

        Zero or one candidate is trivially resolved. For two or more, the
        strongest wins only when its RSSI is at least CAPTURE_THRESHOLD_DB
        above the second strongest; otherwise the collision is a total loss.

        Args:
            candidates: Candidates from get_rx_candidates.

        Returns:
            The successfully received Transmission, or None if the channel
            collided or no candidate was given.
        """
        if not candidates:
            return None
        ordered = sorted(candidates, key=lambda candidate: candidate[1], reverse=True)
        if len(ordered) == 1:
            return ordered[0][0]
        strongest_rssi = ordered[0][1]
        second_rssi = ordered[1][1]
        if strongest_rssi - second_rssi >= CAPTURE_THRESHOLD_DB:
            return ordered[0][0]
        return None
