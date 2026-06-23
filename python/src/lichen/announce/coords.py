"""App data encodings for announce messages (spec 9.7, 11.4).

Supports:
- Geographic coordinates (type 0x01): 7 bytes
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

# Resolution: 1e-5 degrees per LSB
_SCALE = 100_000

# Range: 24-bit signed = +/- 8388607 LSBs = +/- 83.88607 degrees
_MAX_RAW = (1 << 23) - 1  # 8388607


def encode_coords(lat: float, lon: float) -> bytes:
    """Encode lat/lon to 7-byte app_data format.

    Args:
        lat: Latitude in degrees (-83.88 to +83.88).
        lon: Longitude in degrees (-83.88 to +83.88).

    Returns:
        7 bytes: type(1) + lat(3) + lon(3)

    Raises:
        ValueError: If coordinates out of range.
    """
    lat_raw = int(round(lat * _SCALE))
    lon_raw = int(round(lon * _SCALE))

    if not (-_MAX_RAW <= lat_raw <= _MAX_RAW):
        raise ValueError(f"latitude {lat} out of range (+/-83.88)")
    if not (-_MAX_RAW <= lon_raw <= _MAX_RAW):
        raise ValueError(f"longitude {lon} out of range (+/-83.88)")

    # Pack as signed 24-bit (3 bytes each, big-endian)
    lat_bytes = _int24_to_bytes(lat_raw)
    lon_bytes = _int24_to_bytes(lon_raw)

    return bytes([APP_DATA_TYPE_COORDS]) + lat_bytes + lon_bytes


def decode_coords(app_data: bytes) -> tuple[float, float] | None:
    """Decode coords from app_data if present.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        (lat, lon) tuple in degrees, or None if no coords present.
    """
    if len(app_data) < 7:
        return None
    if app_data[0] != APP_DATA_TYPE_COORDS:
        return None

    lat_raw = _bytes_to_int24(app_data[1:4])
    lon_raw = _bytes_to_int24(app_data[4:7])

    return (lat_raw / _SCALE, lon_raw / _SCALE)


def _int24_to_bytes(value: int) -> bytes:
    """Convert signed int to 3 bytes big-endian."""
    if value < 0:
        value += 1 << 24  # two's complement
    return struct.pack(">I", value)[1:]  # drop high byte of 4-byte pack


def _bytes_to_int24(data: bytes) -> int:
    """Convert 3 bytes big-endian to signed int."""
    # Pad to 4 bytes, unpack as unsigned, then sign-extend
    value = struct.unpack(">I", b"\x00" + data)[0]
    if value >= (1 << 23):
        value -= 1 << 24  # sign extend
    return value


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
    """Decode congestion from app_data if present.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        Queue depth (0-255), or None if no congestion indicator present.
    """
    if len(app_data) < 2:
        return None
    if app_data[0] != APP_DATA_TYPE_CONGESTION:
        return None
    return app_data[1]


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
    """Decode DTN expiry from app_data if present.

    Args:
        app_data: Raw app_data bytes from announce/message.

    Returns:
        Unix timestamp, or None if no DTN expiry present.
    """
    if len(app_data) < 5:
        return None
    if app_data[0] != APP_DATA_TYPE_DTN_EXPIRY:
        return None
    return struct.unpack(">I", app_data[1:5])[0]


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
    """Decode DTN pending IIDs from app_data if present.

    Args:
        app_data: Raw app_data bytes from announce.

    Returns:
        List of 8-byte IIDs, or None if no pending list present.
    """
    if len(app_data) < 2:
        return None
    if app_data[0] != APP_DATA_TYPE_DTN_PENDING:
        return None
    count = app_data[1]
    expected_len = 2 + count * 8
    if len(app_data) < expected_len:
        return None
    iids = []
    for i in range(count):
        start = 2 + i * 8
        iids.append(app_data[start : start + 8])
    return iids


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
    """Decode opportunistic forwarder list from header.

    Args:
        data: Raw header bytes.

    Returns:
        List of 8-byte IIDs (ranked best-first), or None if not opportunistic.
    """
    if len(data) < 2:
        return None
    if data[0] != HEADER_TYPE_OPPORTUNISTIC:
        return None
    count = data[1]
    if count > MAX_OPPORTUNISTIC_CANDIDATES:
        return None
    expected_len = 2 + count * 8
    if len(data) < expected_len:
        return None
    iids = []
    for i in range(count):
        start = 2 + i * 8
        iids.append(data[start : start + 8])
    return iids


def opportunistic_wait_time_ms(rank: int) -> int:
    """Calculate wait time for opportunistic forwarding based on rank.

    Rank 0 (best candidate) forwards immediately.
    Higher ranks wait progressively longer.

    Args:
        rank: Forwarder rank (0 = best, higher = worse).

    Returns:
        Wait time in milliseconds.
    """
    return rank * OPPORTUNISTIC_SLOT_TIME_MS
