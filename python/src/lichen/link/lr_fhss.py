# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LR-FHSS optional mode oracle (spec 02-physical-link.md §3.7).

SX1262-only.  Gateway advertises LR_FHSS_SUPPORTED in DIO (reserved bit);
nodes advertise LR_FHSS_CAPABLE in Announce app_data.  Nodes MAY select LR-FHSS
for uplink if gateway advertises support.  Gateway MUST implement dual-mode RX.
Downlink matches mode of node's most recent uplink. Node-to-node defaults to
standard LoRa; LR-FHSS only if both peers capable and negotiated.

For the Python oracle we model the capability flags as single-bit fields
packed into a DIO flags byte (reserved bit) and an Announce app_data byte.

Tradeoffs: ~2x airtime vs standard LoRa, 10x+ collision resilience via fragment FEC.
Uses LoRaWAN LR-FHSS DR8-DR11, OCW 137/336 kHz, CR 1/3 or 2/3, hopping per Semtech
AN1200.62 (see 02 §3.7).

See also: lora_medium Transmission.phy_mode for airtime/ sensitivity modeling.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# Bit positions (chosen to avoid collision with existing flags; MUST use reserved bit per spec)
DIO_LR_FHSS_SUPPORTED_BIT = 7  # DIO reserved bit for LR_FHSS_SUPPORTED
ANNOUNCE_LR_FHSS_CAPABLE_BIT = 0  # bit 0 of first app_data byte for LR_FHSS_CAPABLE


class PhyMode(IntEnum):
    """Physical layer mode for a transmission."""

    LORA = 0
    LR_FHSS = 1


@dataclass(frozen=True)
class DioLrFhssFlags:
    """DIO LR_FHSS advertisement (gateway -> nodes)."""

    lr_fhss_supported: bool = False

    def encode(self) -> int:
        return (1 << DIO_LR_FHSS_SUPPORTED_BIT) if self.lr_fhss_supported else 0

    @classmethod
    def decode(cls, flags: int) -> DioLrFhssFlags:
        return cls(lr_fhss_supported=bool(flags & (1 << DIO_LR_FHSS_SUPPORTED_BIT)))


@dataclass(frozen=True)
class AnnounceLrFhssFlags:
    """Announce LR_FHSS capability (node -> gateway/peers)."""

    lr_fhss_capable: bool = False

    def encode(self) -> int:
        return (1 << ANNOUNCE_LR_FHSS_CAPABLE_BIT) if self.lr_fhss_capable else 0

    @classmethod
    def decode(cls, byte: int) -> AnnounceLrFhssFlags:
        return cls(lr_fhss_capable=bool(byte & (1 << ANNOUNCE_LR_FHSS_CAPABLE_BIT)))


def negotiate_uplink_mode(
    *,
    node_capable: bool,
    gateway_supported: bool,
    node_prefers_lr_fhss: bool = False,
    gateway_dual_mode: bool = True,
) -> PhyMode:
    """Determine uplink PHY mode per spec §3.7 negotiation.

    - SX127x nodes ignore flags and use standard LoRa exclusively.
    - SX1262 nodes MAY select LR-FHSS for uplink if gateway advertises support.
    - Gateway MUST implement dual-mode RX (gateway_dual_mode flag).

    Args:
        node_capable: Whether node hardware is SX1262 and LR_FHSS capable.
        gateway_supported: Whether gateway DIO advertises LR_FHSS_SUPPORTED.
        node_prefers_lr_fhss: Whether node chooses LR-FHSS (density/collision heuristic).
        gateway_dual_mode: Whether gateway implements dual-mode RX (MUST be True per spec).

    Returns:
        PhyMode.LR_FHSS if negotiation succeeds, else PhyMode.LORA.
    """
    if not gateway_dual_mode:
        # Spec says gateway MUST implement dual-mode; if not, force LORA for safety
        return PhyMode.LORA
    if node_capable and gateway_supported and node_prefers_lr_fhss:
        return PhyMode.LR_FHSS
    return PhyMode.LORA


def downlink_mode_for_node(last_uplink_mode: PhyMode) -> PhyMode:
    """Downlink MUST match mode of node's most recent uplink."""
    return last_uplink_mode


def peer_to_peer_mode(
    *,
    a_capable: bool,
    b_capable: bool,
    negotiated: bool = False,
) -> PhyMode:
    """Node-to-node defaults to standard LoRa; LR-FHSS only if both capable and negotiated."""
    if negotiated and a_capable and b_capable:
        return PhyMode.LR_FHSS
    return PhyMode.LORA


__all__ = [
    "ANNOUNCE_LR_FHSS_CAPABLE_BIT",
    "AnnounceLrFhssFlags",
    "DIO_LR_FHSS_SUPPORTED_BIT",
    "DioLrFhssFlags",
    "PhyMode",
    "downlink_mode_for_node",
    "negotiate_uplink_mode",
    "peer_to_peer_mode",
]
