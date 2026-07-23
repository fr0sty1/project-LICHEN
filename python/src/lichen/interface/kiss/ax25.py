# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
Minimal AX.25 framing for KISS TNC app compatibility.

Only implements UI frames (unnumbered information) - enough for
TNC apps to display source/destination and payload text.
"""

from __future__ import annotations

from dataclasses import dataclass

# AX.25 constants
CONTROL_UI = 0x03  # Unnumbered Information frame
PID_NO_L3 = 0xF0  # No layer 3 protocol


@dataclass
class Ax25Frame:
    """Decoded AX.25 UI frame."""

    src: str  # Source callsign with SSID (e.g., "LI3A7F-5")
    dst: str  # Destination callsign with SSID
    payload: bytes


class Ax25Error(Exception):
    """AX.25 framing error."""


def callsign_to_bytes(callsign: str, is_last: bool = False) -> bytes:
    """Encode callsign to 7-byte AX.25 address field.

    Args:
        callsign: Callsign with optional SSID (e.g., "W1AW-5" or "W1AW")
        is_last: True if this is the last address (source), sets bit 0

    Returns:
        7 bytes: 6 shifted chars + SSID byte
    """
    # Split callsign and SSID
    if "-" in callsign:
        call, ssid_str = callsign.rsplit("-", 1)
        try:
            ssid = int(ssid_str)
        except ValueError:
            ssid = 0
    else:
        call = callsign
        ssid = 0

    ssid = max(0, min(15, ssid))  # Clamp 0-15

    # Pad/truncate callsign to 6 chars
    call = call.upper()[:6].ljust(6)

    # Shift each char left 1 bit
    result = bytearray()
    for c in call:
        if c.isalnum() and ord(c) < 128:
            result.append(ord(c) << 1)
        else:
            result.append(ord(" ") << 1)

    # SSID byte: bits 1-4 = SSID, bit 0 = last address flag
    # Bits 5-6 are reserved (set to 1 per spec), bit 7 = 0
    ssid_byte = 0b01100000 | (ssid << 1) | (1 if is_last else 0)
    result.append(ssid_byte)

    return bytes(result)


def bytes_to_callsign(data: bytes) -> str:
    """Decode 7-byte AX.25 address to callsign string.

    Args:
        data: 7 bytes of AX.25 address field

    Returns:
        Callsign with SSID (e.g., "W1AW-5")
    """
    if len(data) != 7:
        raise Ax25Error(f"address must be 7 bytes, got {len(data)}")

    # Unshift characters
    call = ""
    for i in range(6):
        c = data[i] >> 1
        if 32 <= c <= 126:
            call += chr(c)
        else:
            call += " "
    call = call.rstrip()

    # Extract SSID from bits 1-4
    ssid = (data[6] >> 1) & 0x0F

    if ssid == 0:
        return call
    return f"{call}-{ssid}"


def ax25_encode(src: str, dst: str, payload: bytes) -> bytes:
    """Encode payload in minimal AX.25 UI frame.

    Args:
        src: Source callsign (e.g., "LI3A7F-0")
        dst: Destination callsign (e.g., "CQ-0")
        payload: Information field

    Returns:
        Complete AX.25 frame bytes
    """
    dst_bytes = callsign_to_bytes(dst, is_last=False)
    src_bytes = callsign_to_bytes(src, is_last=True)

    return dst_bytes + src_bytes + bytes([CONTROL_UI, PID_NO_L3]) + payload


def ax25_decode(frame: bytes) -> Ax25Frame:
    """Decode AX.25 UI frame.

    Args:
        frame: Complete AX.25 frame bytes

    Returns:
        Ax25Frame with src, dst, payload

    Raises:
        Ax25Error: If frame is malformed
    """
    # Minimum: 7 (dst) + 7 (src) + 1 (control) + 1 (PID) = 16 bytes
    if len(frame) < 16:
        raise Ax25Error(f"frame too short: {len(frame)} < 16")

    dst = bytes_to_callsign(frame[0:7])
    src = bytes_to_callsign(frame[7:14])

    control = frame[14]
    # ponytail: only UI frames supported, others rejected
    if control != CONTROL_UI:
        raise Ax25Error(f"unsupported control field: 0x{control:02X}, expected UI (0x03)")

    payload = frame[16:]

    return Ax25Frame(src=src, dst=dst, payload=payload)
