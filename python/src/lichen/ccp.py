# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Coordinated Capacity Protocol (CCP) oracle implementation.

This module provides reference implementations for CCP-16 channel agility and
adaptive spreading factor selection per spec/02a-coordinated-capacity.md.

All functions in this module are deterministic oracles that MUST produce
identical output to test vectors in:
- test/vectors/ccp16.json
- test/vectors/ccp_load_balancing.json
- test/vectors/ccp16_utilization.json
- test/vectors/ccp16_ema_loss_threshold.json
- test/vectors/ccp_select_channel_endianness.json
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from lichen.timing.sfn import slot_for

# FNV-1a32 hash constants per spec/02a-coordinated-capacity.md:123
FNV1A32_BASIS = 0x811C9DC5
FNV1A32_PRIME = 0x01000193


def hash_32(data: bytes) -> int:
    """Compute FNV-1a32 hash.

    This is the canonical hash function for CCP slot and channel selection.
    The basis is 0x811c9dc5 per spec/02a-coordinated-capacity.md:123.

    Args:
        data: Input bytes to hash.

    Returns:
        32-bit unsigned hash value.
    """
    h = FNV1A32_BASIS
    for b in data:
        h = ((h ^ b) * FNV1A32_PRIME) & 0xFFFFFFFF
    return h


def now(sfn: int) -> int:
    """Return the current superframe number (SFN).

    Per spec/02a-coordinated-capacity.md section 2a.3.1:
    - All subtractions, comparisons, and MOD operations MUST use unsigned
      32-bit modular arithmetic (modulo 2^32) to handle wraparound.

    Args:
        sfn: Current SFN value (u32).

    Returns:
        The SFN value, masked to u32 range.
    """
    return sfn & 0xFFFFFFFF


def select_channel(
    eui64: bytes,
    epoch: int,
    density: int,
    n_channels: int = 8,
) -> int:
    """Select data channel using deterministic hash.

    Per spec/02a-coordinated-capacity.md section 2a.3.1 SelectChannel pseudocode:
    1. IF Density > 8 THEN RETURN 0 (CH0 fallback for high density)
    2. Data = CONCAT(EUI64 as BE bytes, Epoch as LE u32 bytes)
    3. Hash = FNV1A32(Data)
    4. N = MAX(NChannels, 3)
    5. RETURN 1 + (Hash MOD N)

    Args:
        eui64: 8-byte EUI-64 identifier (big-endian).
        epoch: Current epoch value (u32, encoded little-endian for hash).
        density: Network density estimate.
        n_channels: Number of available channels (default 8).

    Returns:
        Selected channel index. 0 for CH0 (control), 1-N for data channels.
    """
    # Step 1: High density forces CH0 fallback
    if density > 8:
        return 0

    # Step 2: Concatenate EUI64 (BE) with epoch (LE u32)
    data = eui64 + (epoch & 0xFFFFFFFF).to_bytes(4, "little")

    # Step 3: Compute hash
    h = hash_32(data)

    # Step 4-5: Select channel (output range [1, n_channels])
    n = max(n_channels, 3)
    return 1 + (h % n)


class SFResult(NamedTuple):
    """Result of adaptive SF selection.

    Attributes:
        sf: Selected spreading factor (7-12).
        tx_allowed: Whether transmission is permitted.
    """

    sf: int
    tx_allowed: bool


@dataclass
class NeighborMetrics:
    """Per-neighbor RF metrics with EMA smoothing.

    Attributes:
        ema_snr: Exponentially smoothed SNR (dB).
        ema_loss: Exponentially smoothed packet loss ratio (0.0-1.0).
    """

    ema_snr: float = 5.0
    ema_loss: float = 0.0


def ema_update(avg: float, sample: float, alpha: float = 0.25) -> float:
    """Update exponential moving average.

    Per spec/02a-coordinated-capacity.md section 2a.7:
    EMA_Update(Avg, Sample) = Avg + ((Sample - Avg) right-shift 2)

    For floating point, this is equivalent to:
    new_avg = avg + alpha * (sample - avg)
            = (1 - alpha) * avg + alpha * sample

    With alpha = 1/4 = 0.25 (spec default).

    Args:
        avg: Current average value.
        sample: New sample value.
        alpha: Smoothing factor (default 0.25 = 1/4).

    Returns:
        Updated average.
    """
    return avg + alpha * (sample - avg)


def ema_update_integer(avg: int, sample: int) -> int:
    """Integer EMA update using right-shift.

    Per spec/02a-coordinated-capacity.md section 2a.7:
    EMA_Update(Avg, Sample) = Avg + ((Sample - Avg) right-shift 2)

    Uses arithmetic right-shift to preserve sign for negative differences.

    Args:
        avg: Current integer average.
        sample: New integer sample.

    Returns:
        Updated integer average.
    """
    diff = sample - avg
    # Python's >> on negative integers is arithmetic right-shift
    return avg + (diff >> 2)


def adaptive_sf_select(
    assigned_sf: int | None,
    density: int,
    ema_snr: float,
    ema_loss: float = 0.0,
    utilization: int = 0,
    load_factor: float = 0.0,
) -> SFResult:
    """Select spreading factor based on network conditions.

    Implements the AdaptiveSFSelect procedure from spec/02a-coordinated-capacity.md
    section 2a.7, combined with the threshold table rules.

    Pseudocode:
    1. SF = AssignedSF
    2. IF SF absent THEN SF = 10
    3. IF (Density > 10) OR (Utilization > 150) THEN SF = MIN(12, SF + 2)
    4. IF (Neighbor.EMA_SNR > 8) AND (Density < 5) THEN SF = MAX(7, SF - 1)
    5a. IF Neighbor.EMA_Loss > 0.25 THEN SF = MIN(12, SF + 1)
    5b. IF Utilization > 200 THEN RETURN (12, false)
    6. RETURN (SF, true)

    Step 5b returns the fixed maximum SF=12 whenever Utilization > 200,
    independent of AssignedSF. This matches the normative select_tx_sf()
    pseudocode in spec/02-physical-link.md section 3.5 and the oracle
    vector test/vectors/ccp16_utilization.json
    ("utilization_high_with_sf7_baseline": AssignedSF=7 -> SF=12).

    Additional threshold table rules (applied after pseudocode):
    - SNR < -5 -> SF 12 (maximum range needed)
    - SNR < 0 -> at least SF 11
    - Density > 8 -> at least SF 11
    - Load factor > 0.8 -> at least SF 11

    Args:
        assigned_sf: Assigned spreading factor (7-12), or None for default.
        density: Network density estimate.
        ema_snr: Smoothed SNR in dB.
        ema_loss: Smoothed packet loss ratio (0.0-1.0).
        utilization: Channel utilization (0-255, where 255 = 100%).
        load_factor: Gateway load factor (0.0-1.0).

    Returns:
        SFResult with selected SF and tx_allowed flag.
    """
    # Step 1-2: Start with assigned SF or default of 10
    sf = assigned_sf if assigned_sf is not None else 10

    # Step 3: High density or high utilization triggers SF +2
    if density > 10 or utilization > 150:
        sf = min(12, sf + 2)

    # Step 4: Good SNR and low density allows SF -1 upgrade
    if ema_snr > 8 and density < 5:
        sf = max(7, sf - 1)

    # Step 5: High loss OR very high utilization triggers SF +1
    if ema_loss > 0.25 or utilization > 200:
        sf = min(12, sf + 1)
        if utilization > 200:
            # Per spec: utilization > 200 forces SF=12 and blocks tx
            return SFResult(12, False)

    # Threshold table rules (applied after pseudocode)
    # These ensure minimum SF for poor conditions

    # SNR < -5 -> SF 12 (maximum range needed)
    if ema_snr < -5:
        sf = 12
    # SNR < 0 -> at least SF 11
    elif ema_snr < 0:
        sf = max(11, sf)

    # Density > 8 -> at least SF 11 (from threshold table)
    if density > 8:
        sf = max(11, sf)

    # Load factor > 0.8 -> at least SF 11
    if load_factor > 0.8:
        sf = max(11, sf)

    return SFResult(sf, True)


def synchronized_hop(
    eui64: bytes,
    epoch: int,
    density: int,
    ema_snr: float,
    ema_loss: float = 0.0,
    utilization: int = 0,
    load_factor: float = 0.0,
    n_channels: int = 8,
    assigned_sf: int | None = None,
) -> tuple[int, int, bool]:
    """Compute channel and SF for synchronized hopping.

    Combines select_channel and adaptive_sf_select for a single operation.

    Args:
        eui64: 8-byte EUI-64 identifier.
        epoch: Current epoch value.
        density: Network density estimate.
        ema_snr: Smoothed SNR in dB.
        ema_loss: Smoothed packet loss ratio.
        utilization: Channel utilization (0-255).
        load_factor: Gateway load factor.
        n_channels: Number of available channels.
        assigned_sf: Assigned spreading factor, or None for default.

    Returns:
        Tuple of (channel, sf, tx_allowed).
    """
    channel = select_channel(eui64, epoch, density, n_channels)
    sf_result = adaptive_sf_select(
        assigned_sf, density, ema_snr, ema_loss, utilization, load_factor
    )
    return (channel, sf_result.sf, sf_result.tx_allowed)


def slot_hash(eui64: bytes, sfn: int, num_slots: int = 8) -> int:
    """Compute TDMA slot assignment from EUI-64 and SFN.

    Per spec/09-packets-timing.md section 14.7 and
    test/vectors/ccp_sfn_wrap_slot_hash.json:
    Slot ID = u32(hash_32(EUI64) + u32(SFN)) % num_slots

    Args:
        eui64: 8-byte EUI-64 identifier (big-endian).
        sfn: Superframe number (masked to u32).
        num_slots: Number of TDMA slots (default 8).

    Returns:
        Assigned slot index (0 to num_slots-1).

    Raises:
        ValueError: If num_slots is less than 1.
    """
    return slot_for(eui64, sfn, num_slots)
