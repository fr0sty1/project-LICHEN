# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Wire protocol encoding/decoding for LICHEN simulator.

Binary protocol using little-endian byte order. Each message starts with
a 1-byte message type, followed by type-specific payload. The u8 channel
field in TX/RX_ENTER/CAD messages carries the channel from
synchronized_hop_channel(sfn, seed=0, num_channels=8) for TX/RX rendezvous
(CCP-12).

Message types:
    REGISTER (0x01): Node registration with position
    OK (0x00): Generic success response
    ERR (0xFF): Error response with code and message
    TX (0x10): Transmit with u8 channel after len
    TX_DONE (0x11): Transmit complete with airtime
    TX_FAIL (0x12): Transmit failed
    RX_ENTER (0x24): RX enter with timeout_us + u8 channel
    RX_EXIT (0x26): Renode -> Sim: leaving RX mode
    RX_PACKET (0x27): Sim -> Renode: packet arrived, unsolicited
    RX_TIMEOUT_PUSH (0x28): Sim -> Renode: RX timeout, unsolicited
    TIME (0x30): Time query request
    TIME_OK (0x31): Time query response
    CAD (0x40): CAD with timeout_ms + u8 channel
    CAD_RESULT (0x41): CAD result (detected/not detected)
"""

from __future__ import annotations

import struct
from typing import Final
from .tdma import hash_32

# Message type constants
MSG_OK: Final[int] = 0x00
MSG_REGISTER: Final[int] = 0x01
MSG_TX: Final[int] = 0x10
MSG_TX_DONE: Final[int] = 0x11
MSG_TX_FAIL: Final[int] = 0x12
MSG_RX_ENTER: Final[int] = 0x24
MSG_RX_EXIT: Final[int] = 0x26
MSG_RX_PACKET: Final[int] = 0x27
MSG_RX_TIMEOUT_PUSH: Final[int] = 0x28
MSG_TIME: Final[int] = 0x30
MSG_TIME_OK: Final[int] = 0x31
MSG_CAD: Final[int] = 0x40
MSG_CAD_RESULT: Final[int] = 0x41
MSG_ERR: Final[int] = 0xFF

# Maximum lengths for variable-length fields
MAX_ID_LENGTH: Final[int] = 255
MAX_PAYLOAD_LENGTH: Final[int] = 65535
MAX_ERR_MSG_LENGTH: Final[int] = 255

# Fixed-width integer field bounds
_UINT8_MAX: Final[int] = 0xFF
_UINT32_MAX: Final[int] = 0xFFFFFFFF
_INT16_MIN: Final[int] = -32768
_INT16_MAX: Final[int] = 32767


class ProtocolError(Exception):
    """Raised when protocol encoding/decoding fails."""


def _check_range(name: str, value: int, lo: int, hi: int) -> None:
    """Validate that an integer field fits its fixed-width packing range.

    Raises:
        ProtocolError: If value is outside [lo, hi].
    """
    if not lo <= value <= hi:
        raise ProtocolError(f"{name} out of range: {value} not in [{lo}, {hi}]")


def encode_register(
    sim_id: str, node_id: str, x: float, y: float, z: float
) -> bytes:
    """Encode a REGISTER message.

    Format:
        - 1 byte: message type (0x01)
        - 1 byte: sim_id length
        - N bytes: sim_id (UTF-8)
        - 1 byte: node_id length
        - N bytes: node_id (UTF-8)
        - 8 bytes: x position (double, little-endian)
        - 8 bytes: y position (double, little-endian)
        - 8 bytes: z position (double, little-endian)

    Args:
        sim_id: Simulation identifier string.
        node_id: Node identifier string.
        x: X coordinate in meters.
        y: Y coordinate in meters.
        z: Z coordinate in meters.

    Returns:
        Encoded message bytes.

    Raises:
        ProtocolError: If sim_id or node_id exceeds 255 bytes when encoded.
    """
    sim_id_bytes = sim_id.encode("utf-8")
    node_id_bytes = node_id.encode("utf-8")

    if len(sim_id_bytes) > MAX_ID_LENGTH:
        raise ProtocolError(f"sim_id too long: {len(sim_id_bytes)} > {MAX_ID_LENGTH}")
    if len(node_id_bytes) > MAX_ID_LENGTH:
        raise ProtocolError(f"node_id too long: {len(node_id_bytes)} > {MAX_ID_LENGTH}")

    return (
        struct.pack("<B", MSG_REGISTER)
        + struct.pack("<B", len(sim_id_bytes))
        + sim_id_bytes
        + struct.pack("<B", len(node_id_bytes))
        + node_id_bytes
        + struct.pack("<ddd", x, y, z)
    )


def decode_register(data: bytes) -> tuple[str, str, float, float, float]:
    """Decode a REGISTER message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        Tuple of (sim_id, node_id, x, y, z).

    Raises:
        ProtocolError: If data is malformed or too short.
    """
    if len(data) < 1:
        raise ProtocolError("REGISTER message too short")

    offset = 0

    # Read sim_id
    sim_id_len = data[offset]
    offset += 1
    if offset + sim_id_len > len(data):
        raise ProtocolError("REGISTER message truncated at sim_id")
    try:
        sim_id = data[offset : offset + sim_id_len].decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("Invalid UTF-8 in sim_id") from None
    offset += sim_id_len

    # Read node_id
    if offset >= len(data):
        raise ProtocolError("REGISTER message truncated before node_id length")
    node_id_len = data[offset]
    offset += 1
    if offset + node_id_len > len(data):
        raise ProtocolError("REGISTER message truncated at node_id")
    try:
        node_id = data[offset : offset + node_id_len].decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("Invalid UTF-8 in node_id") from None
    offset += node_id_len

    # Read coordinates
    if offset + 24 > len(data):
        raise ProtocolError("REGISTER message truncated at coordinates")
    x, y, z = struct.unpack_from("<ddd", data, offset)

    return (sim_id, node_id, x, y, z)


def encode_tx(payload: bytes, channel: int = 0) -> bytes:
    if len(payload) > MAX_PAYLOAD_LENGTH:
        raise ProtocolError(f"payload too long: {len(payload)} > {MAX_PAYLOAD_LENGTH}")
    _check_range("channel", channel, 0, _UINT8_MAX)
    return struct.pack("<BHB", MSG_TX, len(payload), channel) + payload


def decode_tx(data: bytes) -> tuple[bytes, int]:
    if len(data) < 2:
        raise ProtocolError("TX message too short")
    payload_len = struct.unpack_from("<H", data, 0)[0]
    if len(data) >= 3 + payload_len:
        channel = data[2]
        payload_start = 3
    else:
        channel = 0
        payload_start = 2
    if len(data) < payload_start + payload_len:
        raise ProtocolError("TX message truncated at payload")
    return data[payload_start:payload_start + payload_len], channel


def encode_tx_done(airtime_us: int) -> bytes:
    """Encode a TX_DONE message.

    Format:
        - 1 byte: message type (0x11)
        - 4 bytes: airtime in microseconds (uint32, little-endian)

    Args:
        airtime_us: Transmission airtime in microseconds.

    Returns:
        Encoded message bytes.

    Raises:
        ProtocolError: If airtime_us does not fit in a uint32.
    """
    _check_range("airtime_us", airtime_us, 0, _UINT32_MAX)
    return struct.pack("<BI", MSG_TX_DONE, airtime_us)


def decode_tx_done(data: bytes) -> int:
    """Decode a TX_DONE message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        Airtime in microseconds.

    Raises:
        ProtocolError: If data is too short.
    """
    if len(data) < 4:
        raise ProtocolError("TX_DONE message too short")

    (airtime_us,) = struct.unpack_from("<I", data, 0)
    return int(airtime_us)


def encode_tx_fail() -> bytes:
    """Encode a TX_FAIL message.

    Format:
        - 1 byte: message type (0x12)

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<B", MSG_TX_FAIL)


def encode_rx_enter(timeout_us: int, channel: int = 0) -> bytes:
    _check_range("timeout_us", timeout_us, 0, _UINT32_MAX)
    _check_range("channel", channel, 0, _UINT8_MAX)
    return struct.pack("<BIB", MSG_RX_ENTER, timeout_us, channel)


def decode_rx_enter(data: bytes) -> tuple[int, int]:
    if len(data) < 4:
        raise ProtocolError("RX_ENTER message too short")
    timeout_us = struct.unpack_from("<I", data, 0)[0]
    if len(data) >= 5:
        channel = data[4]
    else:
        channel = 0
    return timeout_us, channel


def encode_rx_exit() -> bytes:
    """Encode an RX_EXIT message (push-based RX mode exit).

    Format:
        - 1 byte: message type (0x26)

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<B", MSG_RX_EXIT)


def encode_rx_packet(payload: bytes, rssi: int, snr: int) -> bytes:
    """Encode an RX_PACKET message (push-based packet arrival).

    Format:
        - 1 byte: message type (0x27)
        - 2 bytes: payload length (uint16, little-endian)
        - N bytes: payload
        - 2 bytes: RSSI in dBm (int16, little-endian)
        - 2 bytes: SNR in dB * 10 (int16, little-endian)

    Args:
        payload: Received data.
        rssi: Received signal strength in dBm.
        snr: Signal-to-noise ratio in dB * 10 (e.g., -5.5 dB = -55).

    Returns:
        Encoded message bytes.

    Raises:
        ProtocolError: If payload exceeds 65535 bytes or rssi/snr do not fit
            in an int16.
    """
    if len(payload) > MAX_PAYLOAD_LENGTH:
        raise ProtocolError(
            f"payload too long: {len(payload)} > {MAX_PAYLOAD_LENGTH}"
        )
    _check_range("rssi", rssi, _INT16_MIN, _INT16_MAX)
    _check_range("snr", snr, _INT16_MIN, _INT16_MAX)

    return (
        struct.pack("<BH", MSG_RX_PACKET, len(payload))
        + payload
        + struct.pack("<hh", rssi, snr)
    )


def decode_rx_packet(data: bytes) -> tuple[bytes, int, int]:
    """Decode an RX_PACKET message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        Tuple of (payload, rssi, snr).

    Raises:
        ProtocolError: If data is malformed or too short.
    """
    if len(data) < 2:
        raise ProtocolError("RX_PACKET message too short")

    (payload_len,) = struct.unpack_from("<H", data, 0)

    if len(data) < 2 + payload_len + 4:
        raise ProtocolError("RX_PACKET message truncated")

    payload = data[2 : 2 + payload_len]
    rssi, snr = struct.unpack_from("<hh", data, 2 + payload_len)

    return (payload, rssi, snr)


def encode_rx_timeout_push() -> bytes:
    """Encode an RX_TIMEOUT_PUSH message (push-based RX timeout).

    Format:
        - 1 byte: message type (0x28)

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<B", MSG_RX_TIMEOUT_PUSH)


def encode_time() -> bytes:
    """Encode a TIME message.

    Format:
        - 1 byte: message type (0x30)

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<B", MSG_TIME)


def encode_time_ok(time_us: int) -> bytes:
    """Encode a TIME_OK message.

    Format:
        - 1 byte: message type (0x31)
        - 8 bytes: time in microseconds (uint64, little-endian)

    Args:
        time_us: Current simulation time in microseconds.

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<BQ", MSG_TIME_OK, time_us)


def decode_time_ok(data: bytes) -> int:
    """Decode a TIME_OK message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        Time in microseconds.

    Raises:
        ProtocolError: If data is too short.
    """
    if len(data) < 8:
        raise ProtocolError("TIME_OK message too short")

    (time_us,) = struct.unpack_from("<Q", data, 0)
    return int(time_us)


def encode_cad(timeout_ms: int, channel: int = 0) -> bytes:
    _check_range("timeout_ms", timeout_ms, 0, _UINT32_MAX)
    _check_range("channel", channel, 0, _UINT8_MAX)
    return struct.pack("<BIB", MSG_CAD, timeout_ms, channel)


def decode_cad(data: bytes) -> tuple[int, int]:
    if len(data) < 5:
        raise ProtocolError("CAD message too short")
    timeout_ms, channel = struct.unpack_from("<IB", data, 0)
    return timeout_ms, channel


def encode_cad_result(detected: bool) -> bytes:
    """Encode a CAD_RESULT message.

    Format:
        - 1 byte: message type (0x41)
        - 1 byte: detected (0 = no activity, 1 = activity detected)

    Args:
        detected: True if channel activity was detected, False otherwise.

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<BB", MSG_CAD_RESULT, 1 if detected else 0)


def decode_cad_result(data: bytes) -> bool:
    """Decode a CAD_RESULT message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        True if channel activity was detected, False otherwise.

    Raises:
        ProtocolError: If data is too short.
    """
    if len(data) < 1:
        raise ProtocolError("CAD_RESULT message too short")

    return data[0] != 0


def encode_ok() -> bytes:
    """Encode an OK message.

    Format:
        - 1 byte: message type (0x00)

    Returns:
        Encoded message bytes.
    """
    return struct.pack("<B", MSG_OK)


def encode_err(code: int, msg: str) -> bytes:
    """Encode an ERR message.

    Format:
        - 1 byte: message type (0xFF)
        - 1 byte: error code
        - 1 byte: message length
        - N bytes: message (UTF-8)

    Args:
        code: Error code (0-255).
        msg: Human-readable error message.

    Returns:
        Encoded message bytes.

    Raises:
        ProtocolError: If code is outside 0-255 or message exceeds 255 bytes
            when encoded.
    """
    _check_range("code", code, 0, _UINT8_MAX)
    msg_bytes = msg.encode("utf-8")

    if len(msg_bytes) > MAX_ERR_MSG_LENGTH:
        raise ProtocolError(
            f"error message too long: {len(msg_bytes)} > {MAX_ERR_MSG_LENGTH}"
        )

    return struct.pack("<BBB", MSG_ERR, code, len(msg_bytes)) + msg_bytes


def decode_err(data: bytes) -> tuple[int, str]:
    """Decode an ERR message payload.

    Args:
        data: Message bytes (excluding message type byte).

    Returns:
        Tuple of (error_code, message).

    Raises:
        ProtocolError: If data is malformed or too short.
    """
    if len(data) < 2:
        raise ProtocolError("ERR message too short")

    code = data[0]
    msg_len = data[1]

    if len(data) < 2 + msg_len:
        raise ProtocolError("ERR message truncated at message")

    try:
        msg = data[2 : 2 + msg_len].decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("Invalid UTF-8 in error message") from None

    return (code, msg)


def get_message_type(data: bytes) -> int:
    """Extract the message type from a message.

    Args:
        data: Complete message bytes.

    Returns:
        Message type byte.

    Raises:
        ProtocolError: If data is empty.
    """
    if not data:
        raise ProtocolError("Empty message")
    return data[0]


def get_message_payload(data: bytes) -> bytes:
    """Extract the payload from a message (everything after the type byte).

    Args:
        data: Complete message bytes.

    Returns:
        Message payload (excluding type byte).

    Raises:
        ProtocolError: If data is empty.
    """
    if not data:
        raise ProtocolError("Empty message")
    return data[1:]


def hop_channel(sfn: int, eui64: bytes, num_channels: int = 8, epoch: int = 0) -> int:
    """Deterministic synchronized hop per spec/02a-coordinated-capacity.md:120-125 using hash_32(test/vectors/generate.py:30) as oracle."""
    data = eui64 + ((sfn + epoch) & 0xffffffff).to_bytes(4, "little")
    h = hash_32(data)
    n = max(num_channels, 3)
    return 1 + (h % n)
