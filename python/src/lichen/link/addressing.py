# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link-layer addressing modes (spec section 4.3).

Four destination addressing modes are defined in LLSec bits 0-1:

- NONE (0): Broadcast, 0 bytes, delivered to all neighbors.
- SHORT (1): 16-bit short address, 2 bytes, assigned by coordinator via DAD.
- EXTENDED (2): 64-bit EUI-64, 8 bytes, stable hardware identifier.
- ELIDED (3): 0 bytes, destination derived from SCHC payload context
  (the IPv6 destination address in the decompressed packet).

NONE and ELIDED both carry 0 bytes on wire but have different semantics:
NONE is broadcast (received by all), ELIDED is unicast to the IPv6 destination
recovered from the SCHC payload. Receivers MUST distinguish them via the
AddrMode field, not by address length alone.

This module provides the addressing oracle and the elided context-derivation
helper. It re-exports AddrMode for convenient import and implements
``derive_elided_destination`` which extracts the IPv6 destination from an
SCHC-compressed payload per draft-lichen-link-01 section 3.3.
"""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header

from .frame import AddrMode
from .short_addr import SHORT_ADDR_RESERVED

__all__ = [
    "AddrMode",
    "derive_elided_destination",
    "resolve_destination",
    "addressing_mode_for_destination",
]


def derive_elided_destination(schc_payload: bytes) -> IPv6Address:
    """Derive the destination address for ELIDED mode from SCHC payload.

    In elided mode the destination is not carried in the link-layer header;
    it is recovered from the IPv6 destination address inside the SCHC payload.
    The payload begins with a dispatch byte (0x14 for SCHC, 0x15 for
    routing/control). For SCHC payloads the residue is decompressed to obtain
    the full IPv6 packet; for raw IPv6 payloads (uncompressed rule 255) the
    header is parsed directly.

    Args:
        schc_payload: The frame payload bytes (dispatch + SCHC residue or
            routing message). For dispatch 0x14 the first byte after dispatch
            is the SCHC rule ID.

    Returns:
        The IPv6 destination address that the elided frame targets.

    Raises:
        ValueError: If the payload is empty, has an unknown dispatch, or
            cannot be parsed as an IPv6 packet.
    """
    if not schc_payload:
        raise ValueError("empty payload: cannot derive elided destination")

    dispatch = schc_payload[0]

    if dispatch == 0x14:
        # SCHC-compressed IPv6 datagram: decompress to get IPv6 header.
        # The SCHC packet is the bytes after the dispatch.
        from lichen.schc.headers import decompress_packet

        schc_packet = schc_payload[1:]
        if not schc_packet:
            raise ValueError("SCHC payload missing rule ID")
        raw = decompress_packet(schc_packet)
        if len(raw) < HEADER_LENGTH:
            raise ValueError(f"decompressed packet too short: {len(raw)} bytes")
        header = IPv6Header.from_bytes(raw[:HEADER_LENGTH])
        return header.dst_addr

    if dispatch == 0x15:
        raise ValueError("routing/control dispatch (0x15) has no IPv6 destination")

    # Attempt to treat as raw IPv6 header (uncompressed fallback).
    if len(schc_payload) >= HEADER_LENGTH:
        try:
            header = IPv6Header.from_bytes(schc_payload[:HEADER_LENGTH])
            if header.version == 6:
                return header.dst_addr
        except Exception:
            pass

    raise ValueError(f"unknown dispatch 0x{dispatch:02x}: cannot derive destination")


def resolve_destination(
    addr_mode: AddrMode,
    dst_addr: bytes,
    schc_payload: bytes | None = None,
) -> IPv6Address | None:
    """Resolve the logical destination for a received frame.

    Args:
        addr_mode: The addressing mode from the LLSec byte.
        dst_addr: The destination address bytes from the frame (0, 2, or 8 bytes).
        schc_payload: The frame payload, required when addr_mode is ELIDED.

    Returns:
        The destination as IPv6Address for unicast (SHORT/EXTENDED/ELIDED),
        or None for broadcast (NONE). For SHORT the address is the IID-derived
        form; for EXTENDED the EUI-64-derived link-local form.

    Raises:
        ValueError: If addr_mode is ELIDED but no payload is provided, or the
            payload cannot yield a destination.
    """
    if addr_mode == AddrMode.NONE:
        return None  # broadcast
    if addr_mode == AddrMode.SHORT:
        if len(dst_addr) != 2:
            raise ValueError(f"SHORT mode requires 2-byte address, got {len(dst_addr)}")
        short = int.from_bytes(dst_addr, "big")
        # SECURITY: Reject reserved short addresses (0x0000, 0xFFFE, 0xFFFF)
        # per spec 02-physical-link.md 4.5 and 802.15.4 conventions.
        if short in SHORT_ADDR_RESERVED:
            raise ValueError(f"reserved short address 0x{short:04x} cannot be used as destination")
        # Short address maps to IID 0000:00FF:FE00:XXXX
        iid = (0x0000_00FF_FE00_0000 | short).to_bytes(8, "big")
        from lichen.ipv6.addr import make_link_local

        return make_link_local(iid)
    if addr_mode == AddrMode.EXTENDED:
        if len(dst_addr) != 8:
            raise ValueError(f"EXTENDED mode requires 8-byte EUI-64, got {len(dst_addr)}")
        from lichen.ipv6.addr import eui64_to_iid, make_link_local

        iid = eui64_to_iid(dst_addr)
        return make_link_local(iid)
    if addr_mode == AddrMode.ELIDED:
        if schc_payload is None:
            raise ValueError("ELIDED mode requires payload for context derivation")
        return derive_elided_destination(schc_payload)
    raise ValueError(f"unknown AddrMode: {addr_mode}")


def addressing_mode_for_destination(
    dst: IPv6Address | None,
    use_elided: bool = False,
) -> AddrMode:
    """Select the appropriate addressing mode for a destination.

    Args:
        dst: The IPv6 destination, or None for broadcast.
        use_elided: If True and dst is not None, select ELIDED (destination
            will be derived from payload context). Otherwise select SHORT or
            EXTENDED based on address scope.

    Returns:
        The AddrMode that should be used on the wire.
    """
    if dst is None:
        return AddrMode.NONE
    if use_elided:
        return AddrMode.ELIDED
    # For non-elided unicast, choose based on whether we have a short address
    # mapping. Default to EXTENDED (full EUI-64) for determinism.
    return AddrMode.EXTENDED
