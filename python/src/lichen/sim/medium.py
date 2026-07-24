# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio medium simulation for the LICHEN simulator.

This module provides the Medium class that tracks active transmissions and
handles radio propagation, including collision detection with capture effect.
Channel rendezvous uses hop channels computed from SFN/EUI (CCP-12).

CCP Rendezvous Priority (per spec/02a-tdma.md):
    1. SCHEDULED: gateway-assigned slot from beacon/DIO
    2. HASH_BASED: slot = hash_32(EUI64, SFN) % n_slots
    3. ANNOUNCE_DRIVEN: rx_channel from Announce (CCP-9)
    4. FALLBACK: CH0 contention

Load balancing uses per-channel utilization tracking. TDMA vector support
manages slot assignments for the superframe.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, auto

from lichen.sim.propagation import (
    CAPTURE_THRESHOLD_DB,
    SENSITIVITY_DEFAULT,
    SENSITIVITY_LR_FHSS,
    SENSITIVITY_SF10,
    PropagationModel,
)
from lichen.sim.tdma import hash_32, synchronized_hop_channel
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


class RendezvousMechanism(Enum):
    """CCP rendezvous mechanism priority order (spec/02a-tdma.md)."""

    SCHEDULED = auto()
    HASH_BASED = auto()
    ANNOUNCE_DRIVEN = auto()
    FALLBACK = auto()


@dataclass
class RendezvousInfo:
    """Result of a CCP rendezvous channel selection.

    Attributes:
        channel: Selected channel number (0 = CH0 control/fallback).
        mechanism: The rendezvous mechanism used.
        confidence: Selection confidence (0.0-1.0).
        slot: TDMA slot if SCHEDULED, else -1.
        valid_until_sfn: SFN until which this rendezvous is valid (SCHEDULED only).
    """

    channel: int
    mechanism: RendezvousMechanism
    confidence: float = 1.0
    slot: int = -1
    valid_until_sfn: int | None = None


@dataclass
class ChannelLoad:
    """Per-channel utilization metrics for load balancing.

    Attributes:
        channel_id: Channel index.
        utilization: Fraction of time channel is active (0.0-1.0).
        tx_count: Number of transmissions observed on this channel.
        active_tx_count: Current number of active transmissions.
    """

    channel_id: int
    utilization: float = 0.0
    tx_count: int = 0
    active_tx_count: int = 0


@dataclass
class TDMASlot:
    """A single TDMA slot in the superframe.

    Attributes:
        slot_id: Slot index within the superframe.
        assigned_node: EUI64 hex string of the assigned node, or '' for unassigned.
        channel: Channel for this slot.
        start_time_us: Slot start time in microseconds.
        end_time_us: Slot end time in microseconds.
        utilization: Fraction of slot capacity used (0.0-1.0).
    """

    slot_id: int
    assigned_node: str = ''
    channel: int = 0
    start_time_us: int = 0
    end_time_us: int = 0
    utilization: float = 0.0


@dataclass
class TDMAVector:
    """TDMA superframe slot assignment vector.

    Attributes:
        num_slots: Number of slots in the superframe.
        slot_duration_us: Duration of each slot in microseconds.
        guard_us: Guard time in microseconds.
        slots: List of TDMASlot assignments.
        epoch: Network epoch for slot computation.
        sfn: Current superframe number.
    """

    num_slots: int = 8
    slot_duration_us: int = 250000
    guard_us: int = 100000
    slots: list[TDMASlot] = field(default_factory=list)
    epoch: int = 0
    sfn: int = 0


class Medium:
    """Radio medium that tracks transmissions and handles propagation.

    Supports multi-channel operation with independent collision/propagation
    oracles per channel. Channel selection uses CCP-12 SFN/EUI-based hop
    channels computed by the caller.

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
        self._channel_utilization: dict[int, list[int]] = {}
        self._tdma_vector: TDMAVector | None = None
        self._announce_channels: dict[str, int] = {}
        self._known_peers: set[str] = set()

    def select_rendezvous_channel(
        self,
        peer_eui64: str | None = None,
        sfn: int | None = None,
        num_channels: int = 8,
        seed: int = 0,
        density: int = 0,
    ) -> RendezvousInfo:
        """Select a rendezvous channel using CCP priority (spec/02a-tdma.md).

        Priority order:
        1. SCHEDULED: gateway-assigned slot from beacon/DIO
        2. HASH_BASED: hash_32(EUI64, SFN) % n_slots
        3. ANNOUNCE_DRIVEN: rx_channel from Announce (CCP-9)
        4. FALLBACK: CH0 contention

        Args:
            peer_eui64: EUI64 hex string of the peer node.
            sfn: Superframe number for hash computation.
            num_channels: Number of channels in the plan.
            seed: Seed for hash-based hop calculation.
            density: Network density for density-aware fallback.

        Returns:
            RendezvousInfo with selected channel and mechanism.
        """
        channel = 0
        mechanism = RendezvousMechanism.FALLBACK
        confidence = 0.5
        slot_idx = -1

        if self._tdma_vector is not None and peer_eui64 is not None:
            for tdma_slot in self._tdma_vector.slots:
                if tdma_slot.assigned_node == peer_eui64:
                    channel = tdma_slot.channel
                    slot_idx = tdma_slot.slot_id
                    mechanism = RendezvousMechanism.SCHEDULED
                    confidence = 1.0
                    valid_until = self._tdma_vector.sfn + 1 if self._tdma_vector.sfn else None
                    return RendezvousInfo(
                        channel=channel,
                        mechanism=mechanism,
                        confidence=confidence,
                        slot=slot_idx,
                        valid_until_sfn=valid_until,
                    )

        if peer_eui64 is not None and peer_eui64 in self._known_peers:
            if sfn is not None:
                channel = synchronized_hop_channel(sfn, seed, num_channels)
                mechanism = RendezvousMechanism.HASH_BASED
                confidence = 0.8
                return RendezvousInfo(
                    channel=channel,
                    mechanism=mechanism,
                    confidence=confidence,
                )

        if peer_eui64 is not None and peer_eui64 in self._announce_channels:
            channel = self._announce_channels[peer_eui64]
            mechanism = RendezvousMechanism.ANNOUNCE_DRIVEN
            confidence = 0.6
            return RendezvousInfo(
                channel=channel,
                mechanism=mechanism,
                confidence=confidence,
            )

        return RendezvousInfo(
            channel=0,
            mechanism=RendezvousMechanism.FALLBACK,
            confidence=0.3,
        )

    def set_announce_channel(self, peer_eui64: str, channel: int) -> None:
        """Record an announce rx_channel for CCP-9 rendezvous.

        Args:
            peer_eui64: EUI64 hex string of the peer node.
            channel: Announced receive channel.
        """
        self._announce_channels[peer_eui64] = channel

    def mark_peer_known(self, peer_eui64: str) -> None:
        """Mark a peer as known for hash-based rendezvous.

        Args:
            peer_eui64: EUI64 hex string of the peer node.
        """
        self._known_peers.add(peer_eui64)

    def set_tdma_vector(self, vector: TDMAVector) -> None:
        """Install a TDMA vector for slot-based operation.

        Args:
            vector: TDMAVector with slot assignments.
        """
        self._tdma_vector = vector

    def get_tdma_vector(self) -> TDMAVector | None:
        """Get the current TDMA vector.

        Returns:
            Current TDMAVector or None if not set.
        """
        return self._tdma_vector

    def get_slot_for_node(self, node_eui64: str) -> TDMASlot | None:
        """Get the TDMA slot assigned to a specific node.

        Args:
            node_eui64: EUI64 hex string of the node.

        Returns:
            TDMASlot if the node has an assigned slot, None otherwise.
        """
        if self._tdma_vector is None:
            return None
        for slot in self._tdma_vector.slots:
            if slot.assigned_node == node_eui64:
                return slot
        return None

    def get_channel_loads(self, time_us: int, num_channels: int = 8) -> list[ChannelLoad]:
        """Get utilization metrics for all channels.

        Computes load from active transmissions on each channel.

        Args:
            time_us: Current simulation time in microseconds.
            num_channels: Number of channels to report.

        Returns:
            List of ChannelLoad, one per channel.
        """
        active = self.get_active_transmissions(time_us)
        per_channel_tx: dict[int, list[Transmission]] = {}
        for tx in active:
            ch = tx.channel
            if ch not in per_channel_tx:
                per_channel_tx[ch] = []
            per_channel_tx[ch].append(tx)

        loads: list[ChannelLoad] = []
        for ch in range(num_channels):
            txs = per_channel_tx.get(ch, [])
            total_airtime = sum(t.end_time_us - t.start_time_us for t in txs)
            window = max((t.end_time_us for t in txs), default=1)
            window = max(window - min((t.start_time_us for t in txs), default=0), 1)
            utilization = min(total_airtime / window, 1.0)
            if ch in self._channel_utilization:
                self._channel_utilization[ch].append(int(total_airtime))
            else:
                self._channel_utilization[ch] = [int(total_airtime)]
            loads.append(
                ChannelLoad(
                    channel_id=ch,
                    utilization=utilization,
                    tx_count=len(txs),
                    active_tx_count=len(txs),
                )
            )
        return loads

    def get_least_loaded_channel(
        self, time_us: int, num_channels: int = 8, exclude_channels: set[int] | None = None
    ) -> int:
        """Select the least loaded channel for load balancing.

        Args:
            time_us: Current simulation time in microseconds.
            num_channels: Number of channels available.
            exclude_channels: Set of channels to exclude (e.g. CH0 for data).

        Returns:
            Channel index with the lowest utilization.
        """
        loads = self.get_channel_loads(time_us, num_channels)
        candidates = [l for l in loads if exclude_channels is None or l.channel_id not in exclude_channels]
        if not candidates:
            return 0
        candidates.sort(key=lambda l: l.utilization)
        return candidates[0].channel_id

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
        """Create a transmission and add it to the active set.

        Channel is the caller-computed CCP-12 hop channel from SFN/EUI.
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
            tx for tx in self._active_transmissions if tx.start_time_us <= time_us < tx.end_time_us
        ]

    def get_rx_candidates(
        self,
        rx_node_id: str,
        rx_position: tuple[float, float, float],
        time_us: int,
        channel: int = 0,
    ) -> list[RxCandidate]:
        """Get all decodable transmissions for a receiver on given channel.

        Only considers active transmissions on the matching channel (excluding
        self). For each, calculates distance, RSSI, and SNR. Only includes
        those above the sensitivity threshold.

        Args:
            rx_node_id: ID of the receiving node.
            rx_position: (x, y, z) position of the receiver in meters.
            time_us: Current simulation time in microseconds.
            channel: CCP-12 hop channel from SFN/EUI (default 0).

        Returns:
            List of RxCandidate objects for decodable transmissions.
        """
        candidates: list[RxCandidate] = []
        active = [tx for tx in self.get_active_transmissions(time_us) if tx.channel == channel]

        for tx in active:
            if tx.source_node_id == rx_node_id:
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
            if self.propagation.can_decode(tx.tx_power_dbm, distance, sensitivity_dbm=sensitivity):
                candidates.append(
                    RxCandidate(transmission=tx, rssi=rssi, snr=snr, is_lr_fhss=is_lr_fhss)
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
    ) -> bool:
        """Detect if any transmission is active and detectable at a position
        on the specified channel.

        Args:
            position: (x, y, z) position of the detector in meters.
            time_us: Current simulation time in microseconds.
            sensitivity_dbm: Receiver sensitivity threshold in dBm.
                Defaults to SF10 sensitivity (-132 dBm).
            channel: CCP-12 hop channel from SFN/EUI (default 0).

        Returns:
            True if channel activity is detected, False otherwise.
        """
        active = [tx for tx in self.get_active_transmissions(time_us) if tx.channel == channel]

        for tx in active:
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
