"""
LICHEN Native protocol framing.

Wire format:
    +--------+--------+--------+----------------+
    | START  | LEN_HI | LEN_LO | CBOR payload   |
    | 0xC1   |   (big-endian)  | (LEN bytes)    |
    +--------+--------+--------+----------------+

See spec/lichen-native/01-framing.md
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

START_BYTE = 0xC1
HEADER_SIZE = 3  # START + 2-byte length
MAX_PAYLOAD = 65535


class FramingError(Exception):
    """Framing protocol error."""


def frame(payload: bytes) -> bytes:
    """Wrap payload in LICHEN Native frame."""
    if len(payload) > MAX_PAYLOAD:
        raise FramingError(f"payload too large: {len(payload)} > {MAX_PAYLOAD}")
    return struct.pack(">BH", START_BYTE, len(payload)) + payload


def unframe(data: bytes) -> tuple[bytes, bytes]:
    """
    Extract one frame from data.

    Returns (payload, remaining_data).
    Raises FramingError if incomplete or invalid.
    """
    if len(data) < HEADER_SIZE:
        raise FramingError("incomplete header")

    if data[0] != START_BYTE:
        raise FramingError(f"invalid start byte: 0x{data[0]:02x}")

    length = struct.unpack(">H", data[1:3])[0]
    total = HEADER_SIZE + length

    if len(data) < total:
        raise FramingError(f"incomplete payload: need {total}, have {len(data)}")

    return data[HEADER_SIZE:total], data[total:]


@dataclass
class FrameReader:
    """
    Incremental frame reader for stream transports.

    Usage:
        reader = FrameReader()
        reader.feed(chunk)
        for payload in reader:
            process(payload)
    """

    buffer: bytearray
    max_size: int

    def __init__(self, max_size: int = MAX_PAYLOAD) -> None:
        self.buffer = bytearray()
        self.max_size = max_size

    def feed(self, data: bytes) -> None:
        """Add received data to buffer."""
        self.buffer.extend(data)

    def __iter__(self) -> Iterator[bytes]:
        """Yield complete frames from buffer."""
        while True:
            # Need at least header
            if len(self.buffer) < HEADER_SIZE:
                break

            # Sync to start byte
            if self.buffer[0] != START_BYTE:
                try:
                    idx = self.buffer.index(START_BYTE)
                    del self.buffer[:idx]
                except ValueError:
                    self.buffer.clear()
                    break
                continue

            # Parse length
            length = struct.unpack(">H", self.buffer[1:3])[0]

            # Sanity check
            if length > self.max_size:
                # Bad frame, skip start byte and resync
                del self.buffer[0]
                continue

            total = HEADER_SIZE + length
            if len(self.buffer) < total:
                break  # Need more data

            # Extract payload
            payload = bytes(self.buffer[HEADER_SIZE:total])
            del self.buffer[:total]
            yield payload

    def pending(self) -> int:
        """Bytes waiting in buffer."""
        return len(self.buffer)

    def clear(self) -> None:
        """Discard buffered data."""
        self.buffer.clear()


class FrameWriter:
    """
    Frame writer with optional MTU fragmentation for BLE.

    Usage:
        writer = FrameWriter(mtu=244)
        for chunk in writer.write(payload):
            send_to_ble(chunk)
    """

    mtu: int | None

    def __init__(self, mtu: int | None = None) -> None:
        """
        Create writer.

        Args:
            mtu: Max chunk size. None = no fragmentation.
        """
        self.mtu = mtu

    def write(self, payload: bytes) -> Iterator[bytes]:
        """Yield frame chunks (possibly fragmented)."""
        framed = frame(payload)
        if self.mtu is None:
            yield framed
        else:
            for i in range(0, len(framed), self.mtu):
                yield framed[i : i + self.mtu]
