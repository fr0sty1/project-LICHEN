# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Authenticated L2 inner-payload dispatch helpers."""

from __future__ import annotations

from enum import Enum

from lichen.constants import L2_DISPATCH_ROUTING, L2_DISPATCH_SCHC

L2_ROUTING_TYPE_ANNOUNCE = 0x01


class L2PayloadKind(Enum):
    SCHC = "schc"
    ROUTING = "routing"
    UNKNOWN = "unknown"


def classify_l2_payload(payload: bytes) -> L2PayloadKind:
    """Classify an authenticated link inner payload by dispatch byte."""
    if not payload:
        return L2PayloadKind.UNKNOWN
    if payload[0] == L2_DISPATCH_SCHC:
        return L2PayloadKind.SCHC
    if payload[0] == L2_DISPATCH_ROUTING:
        return L2PayloadKind.ROUTING
    return L2PayloadKind.UNKNOWN


def l2_payload_body(payload: bytes) -> bytes:
    """Return bytes after the dispatch byte, or empty bytes for empty input."""
    return payload[1:] if payload else b""


def wrap_schc_payload(schc_payload: bytes) -> bytes:
    return bytes([L2_DISPATCH_SCHC]) + schc_payload


def wrap_routing_payload(routing_payload: bytes) -> bytes:
    return bytes([L2_DISPATCH_ROUTING]) + routing_payload
