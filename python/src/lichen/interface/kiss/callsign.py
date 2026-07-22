# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
IID ↔ callsign mapping for KISS TNC app compatibility.

Maps LICHEN Interface Identifiers (8-byte IIDs derived from public keys)
to AX.25-style callsigns for display in TNC apps.
"""

from __future__ import annotations

from typing import Protocol

# Base-36 alphabet (0-9, A-Z)
B36_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Prefix for LICHEN-derived callsigns (1 char to fit 6-char limit)
LICHEN_PREFIX = "L"

# Broadcast callsign
BROADCAST_CALL = "CQ"


class PeerLookup(Protocol):
    """Protocol for looking up peers by IID suffix."""

    def lookup_by_suffix(self, suffix: int) -> bytes | None:
        """Find IID with given 24-bit suffix. Returns None if not found."""
        ...

    def all_iids(self) -> list[bytes]:
        """Return all known IIDs."""
        ...


def _encode_base36(value: int, width: int = 5) -> str:
    """Encode integer as base-36 string.

    Args:
        value: Non-negative integer
        width: Minimum output width (zero-padded)

    Returns:
        Base-36 string (uppercase)
    """
    if value == 0:
        return "0" * width

    result = []
    while value > 0:
        result.append(B36_ALPHABET[value % 36])
        value //= 36

    # Pad to width
    while len(result) < width:
        result.append("0")

    return "".join(reversed(result))


def _decode_base36(s: str) -> int:
    """Decode base-36 string to integer.

    Args:
        s: Base-36 string (case-insensitive)

    Returns:
        Decoded integer

    Raises:
        ValueError: If input contains characters outside 0-9, A-Z
    """
    s = s.upper()
    result = 0
    for c in s:
        idx = B36_ALPHABET.find(c)
        if idx < 0:
            raise ValueError(f"Invalid base-36 character: {c!r}")
        result = result * 36 + idx
    return result


def iid_to_callsign(iid: bytes, ssid: int = 0) -> str:
    """Convert 8-byte IID to callsign.

    Takes last 3 bytes (24 bits) as base-36 (5 chars), prefixes with LICHEN_PREFIX ("L").

    Args:
        iid: 8-byte Interface Identifier
        ssid: SSID suffix 0-15 (default 0, omitted in output)

    Returns:
        Callsign like "LABCDE" or "LABCDE-5"
    """
    if len(iid) != 8:
        raise ValueError(f"IID must be 8 bytes, got {len(iid)}")

    # Last 3 bytes as 24-bit value
    suffix = (iid[5] << 16) | (iid[6] << 8) | iid[7]

    encoded = _encode_base36(suffix, width=5)

    call = LICHEN_PREFIX + encoded

    if ssid == 0:
        return call
    return f"{call}-{ssid}"


def callsign_to_suffix(callsign: str) -> int | None:
    """Extract IID suffix from LICHEN callsign.

    Args:
        callsign: Callsign like "LABCDE" or "LABCDE-5"

    Returns:
        24-bit suffix value, or None if not a LICHEN callsign
    """
    # Strip SSID if present
    if "-" in callsign:
        call, _ = callsign.rsplit("-", 1)
    else:
        call = callsign

    call = call.upper()

    # Check for LICHEN prefix
    if not call.startswith(LICHEN_PREFIX):
        return None

    encoded = call[len(LICHEN_PREFIX):]

    if not encoded:
        return None

    # Validate characters
    for c in encoded:
        if c not in B36_ALPHABET:
            return None

    return _decode_base36(encoded)


def callsign_to_iid(callsign: str, peers: PeerLookup) -> bytes | None:
    """Look up full IID from callsign.

    Args:
        callsign: Callsign like "LABCDE"
        peers: Peer lookup for suffix → IID mapping

    Returns:
        8-byte IID if found, None otherwise
    """
    suffix = callsign_to_suffix(callsign)
    if suffix is None:
        return None

    return peers.lookup_by_suffix(suffix)


def is_broadcast_callsign(callsign: str) -> bool:
    """Check if callsign represents broadcast address."""
    call = callsign.upper()
    if "-" in call:
        call, _ = call.rsplit("-", 1)
    return call in (BROADCAST_CALL, "BEACON", "ALL")


def broadcast_iid() -> bytes:
    """Return the broadcast IID (all-nodes multicast suffix)."""
    # ff02::1 → IID portion is last 8 bytes
    # For link-local multicast, we use a conventional value
    return bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01])


class SimplePeerLookup:
    """Simple in-memory peer lookup for testing."""

    def __init__(self) -> None:
        self._peers: dict[int, bytes] = {}  # suffix → IID

    def add(self, iid: bytes) -> None:
        """Add a peer IID."""
        if len(iid) != 8:
            raise ValueError("IID must be 8 bytes")
        suffix = (iid[5] << 16) | (iid[6] << 8) | iid[7]
        self._peers[suffix] = iid

    def lookup_by_suffix(self, suffix: int) -> bytes | None:
        return self._peers.get(suffix)

    def all_iids(self) -> list[bytes]:
        return list(self._peers.values())
