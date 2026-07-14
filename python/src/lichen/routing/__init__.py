# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN hybrid routing (spec section 7).

Three-tier routing architecture:
1. RPL: Border router traffic (upward/downward tree)
2. Announce: Peer-to-peer with active nodes (proactive gradient)
3. LOADng: Peer-to-peer fallback (reactive discovery)

The Router class decides which tier to use based on address classification.
"""

from lichen.routing.router import (
    MAX_FORWARDING_SOURCES,
    MAX_PACKETS_PER_SOURCE,
    AddressClass,
    ForwardingBuffer,
    ForwardingEntry,
    ForwardingResult,
    PendingPacket,
    RouteDecision,
    Router,
    RoutingError,
)

__all__ = [
    "AddressClass",
    "ForwardingBuffer",
    "ForwardingEntry",
    "ForwardingResult",
    "MAX_FORWARDING_SOURCES",
    "MAX_PACKETS_PER_SOURCE",
    "PendingPacket",
    "RouteDecision",
    "Router",
    "RoutingError",
]
