# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""App data encodings for announce messages (spec 9.7, 11.4).

Supports:
- Geographic coordinates (type 0x01): 9 bytes
- Congestion indicator (type 0x02): 2 bytes
"""

from __future__ import annotations

import struct

# App data type for geographic coordinates (spec 9.7)
APP_DATA_TYPE_COORDS = 0x01

# App data type for congestion indicator (spec 11.4)
APP_DATA_TYPE_CONGESTION = 0x02

# App data type for DTN expiry (spec 9.8)
APP_DATA_TYPE_DTN_EXPIRY = 0x03

# App data type for DTN pending destinations (spec 9.8)
APP_DATA_TYPE_DTN_PENDING = 0x04

# Header type for opportunistic forwarder list (spec 9.9)
HEADER_TYPE_OPPORTUNISTIC = 0x05

# Resolution: 1e-7 degrees per LSB, matching firmware/HAL e7 coordinates.
_SCALE = 10_000_000
_LAT_MIN = -90
_LAT_MAX = 90
_LON_MIN = -180
_LON_MAX = 180
_LAT_E7_MIN = _LAT_MIN * _SCALE
_LAT_E7_MAX = _LAT_MAX * _SCALE
_LON_E7_MIN = _LON_MIN * _SCALE
_LON_E7_MAX = _LON_MAX * _SCALE


def encode_coords(lat: float, lon: float) -> bytes:
    """Encode lat/lon to 9-byte app_data format.

    Args:
        lat: Latitude in degrees (-90 to +90).
        lon: Longitude in degrees (-180 to +180).

    Returns:
        9 bytes: type(1) + lat_e7(4) + lon_e7(4)

    Raises:
        ValueError: If coordinates out of range.
    """
    if not (_LAT_MIN <= lat <= _LAT_MAX):
        raise ValueError(f"latitude {lat} out of range (+/-90)")
    if not (_LON_MIN <= lon <= _LON_MAX):
        raise ValueError(f"longitude {lon} out of range (+/-180)")

    lat_raw = int(round(lat * _SCALE))
    lon_raw = int(round(lon * _SCALE))

    if not (_LAT_E7_MIN <= lat_raw <= _LAT_E7_MAX):
        raise ValueError(f"latitude {lat} out of range (+/-90)")
    if not (_LON_E7_MIN <= lon_raw <= _LON_E7_MAX):
        raise ValueError(f"longitude {lon} out of range (+/-180)")

    return bytes([APP_DATA_TYPE_COORDS]) + struct.pack(">ii", lat_raw, lon_raw)


def decode_coords(app_data: bytes) -> tuple[float, float] | None:
    """Decode coords from app_data if present. Scans for type in concatenated TLVs.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        (lat, lon) tuple in degrees, or None if no coords present.
    """
    if len(app_data) < 9:
        return None
    for i in range(len(app_data) - 8):
        if app_data[i] == APP_DATA_TYPE_COORDS:
            try:
                lat_raw, lon_raw = struct.unpack(">ii", app_data[i + 1 : i + 9])
                if not (_LAT_E7_MIN <= lat_raw <= _LAT_E7_MAX):
                    continue
                if not (_LON_E7_MIN <= lon_raw <= _LON_E7_MAX):
                    continue
                return (lat_raw / _SCALE, lon_raw / _SCALE)
            except struct.error:
                continue
    return None


# --- Congestion encoding (spec 11.4) ---


def encode_congestion(queue_depth: int) -> bytes:
    """Encode queue depth to 2-byte app_data format.

    Args:
        queue_depth: Current outbound queue depth (0-255).

    Returns:
        2 bytes: type(1) + queue_depth(1)

    Raises:
        ValueError: If queue_depth out of range.
    """
    if not (0 <= queue_depth <= 255):
        raise ValueError(f"queue_depth {queue_depth} out of range (0-255)")
    return bytes([APP_DATA_TYPE_CONGESTION, queue_depth])


def decode_congestion(app_data: bytes) -> int | None:
    """Decode congestion from app_data if present. Scans for type in concatenated TLVs.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        Queue depth (0-255), or None if no congestion indicator present.
    """
    if len(app_data) < 2:
        return None
    for i in range(len(app_data) - 1):
        if app_data[i] == APP_DATA_TYPE_CONGESTION:
            return app_data[i + 1]
    return None


# --- DTN encoding (spec 9.8) ---


def encode_dtn_expiry(expiry_unix: int) -> bytes:
    """Encode DTN absolute expiry to 5-byte app_data format.

    Args:
        expiry_unix: Unix timestamp (seconds since epoch) when message expires.

    Returns:
        5 bytes: type(1) + expiry(4)

    Raises:
        ValueError: If expiry out of 32-bit unsigned range.
    """
    if not (0 <= expiry_unix <= 0xFFFFFFFF):
        raise ValueError(f"expiry_unix {expiry_unix} out of range (0 to 2^32-1)")
    return bytes([APP_DATA_TYPE_DTN_EXPIRY]) + struct.pack(">I", expiry_unix)


def decode_dtn_expiry(app_data: bytes) -> int | None:
    """Decode DTN expiry from app_data if present. Scans for type in concatenated TLVs.

    Args:
        app_data: Raw app_data bytes from announce/message.

    Returns:
        Unix timestamp, or None if no DTN expiry present.
    """
    if len(app_data) < 5:
        return None
    for i in range(len(app_data) - 4):
        if app_data[i] == APP_DATA_TYPE_DTN_EXPIRY:
            try:
                expiry: int = struct.unpack(">I", app_data[i + 1 : i + 5])[0]
                return expiry
            except struct.error:
                continue
    return None


def encode_dtn_pending(iids: list[bytes]) -> bytes:
    """Encode DTN pending destination IIDs to app_data format.

    Args:
        iids: List of 8-byte Interface Identifiers with pending messages.

    Returns:
        Variable bytes: type(1) + count(1) + iids(8*count)

    Raises:
        ValueError: If any IID is not 8 bytes or count > 255.
    """
    if len(iids) > 255:
        raise ValueError(f"too many pending IIDs: {len(iids)} (max 255)")
    for i, iid in enumerate(iids):
        if len(iid) != 8:
            raise ValueError(f"IID {i} has length {len(iid)}, expected 8")
    return bytes([APP_DATA_TYPE_DTN_PENDING, len(iids)]) + b"".join(iids)


def decode_dtn_pending(app_data: bytes) -> list[bytes] | None:
    """Decode DTN pending IIDs from app_data if present. Scans for type in concatenated TLVs.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        List of 8-byte IIDs, or None if no pending list present.
    """
    if len(app_data) < 2:
        return None
    for i in range(len(app_data) - 1):
        if app_data[i] == APP_DATA_TYPE_DTN_PENDING:
            count = app_data[i + 1]
            expected_len = 2 + count * 8
            if len(app_data) - i >= expected_len:
                iids = []
                for j in range(count):
                    start = i + 2 + j * 8
                    iids.append(app_data[start : start + 8])
                return iids
    return None


# --- Opportunistic forwarding (spec 9.9) ---


MAX_OPPORTUNISTIC_CANDIDATES = 4
OPPORTUNISTIC_SLOT_TIME_MS = 100


def encode_opportunistic_forwarders(iids: list[bytes]) -> bytes:
    """Encode opportunistic forwarder candidate IIDs.

    Args:
        iids: List of 8-byte IIDs, ranked best-first (max 4).

    Returns:
        Variable bytes: type(1) + count(1) + iids(8*count)

    Raises:
        ValueError: If any IID is not 8 bytes or count > 4.
    """
    if len(iids) > MAX_OPPORTUNISTIC_CANDIDATES:
        raise ValueError(f"too many forwarders: {len(iids)} (max {MAX_OPPORTUNISTIC_CANDIDATES})")
    for i, iid in enumerate(iids):
        if len(iid) != 8:
            raise ValueError(f"IID {i} has length {len(iid)}, expected 8")
    return bytes([HEADER_TYPE_OPPORTUNISTIC, len(iids)]) + b"".join(iids)


def decode_opportunistic_forwarders(data: bytes) -> list[bytes] | None:
    """Decode opportunistic forwarder list from header. Scans for type in concatenated data.

    Args:
        data: Raw header bytes.

    Returns:
        List of 8-byte IIDs (ranked best-first), or None if not opportunistic.
    """
    i = 0
    while i + 2 <= len(data):
        if data[i] == HEADER_TYPE_OPPORTUNISTIC:
            count = data[i + 1]
            if count > MAX_OPPORTUNISTIC_CANDIDATES:
                return None
            expected_len = 2 + count * 8
            if len(data) < i + expected_len:
                return None
            iids = []
            for j in range(count):
                start = i + 2 + j * 8
                iids.append(data[start : start + 8])
            return iids
        i += 1
    return None


def opportunistic_wait_time_ms(rank: int) -> int:
    """Calculate wait time for opportunistic forwarding based on rank.

    Rank 0 forwards immediately. Higher ranks wait longer.

    Args:
        rank: Forwarder rank (0 = best).

    Returns:
        Wait time in milliseconds.
    """
    return rank * OPPORTUNISTIC_SLOT_TIME_MS
