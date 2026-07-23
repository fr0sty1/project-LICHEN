"""
KISS protocol framing (encode/decode).

KISS (Keep It Simple, Stupid) is a TNC interface standard from 1986.
LICHEN uses it for compatibility with ham radio apps (aprs.fi, APRSDroid).

Frame format: FEND | CMD | DATA... | FEND
Escaping: 0xC0 -> 0xDB 0xDC, 0xDB -> 0xDB 0xDD
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import IntEnum

# KISS special bytes
FEND = 0xC0  # Frame delimiter
FESC = 0xDB  # Escape prefix
TFEND = 0xDC  # Transposed FEND (after FESC)
TFESC = 0xDD  # Transposed FESC (after FESC)


class KissCommand(IntEnum):
    """KISS command types."""

    DATA = 0x00  # Data frame (bidirectional)
    TXDELAY = 0x01  # TX key-up delay (host->TNC)
    PERSISTENCE = 0x02  # CSMA p-value (host->TNC)
    SLOTTIME = 0x03  # CSMA slot interval (host->TNC)
    TXTAIL = 0x04  # TX tail time (host->TNC)
    FULLDUPLEX = 0x05  # Half/full duplex (host->TNC)
    # 0x06 = SetHardware (TNC-specific)
    RETURN = 0x0F  # Exit KISS mode (host->TNC)


@dataclass
class KissFrame:
    """Decoded KISS frame."""

    port: int  # 0-15
    command: int  # KissCommand value
    data: bytes


class KissError(Exception):
    """KISS protocol error."""

    pass


def kiss_escape(data: bytes) -> bytes:
    """Escape special bytes in payload.

    0xC0 (FEND) -> 0xDB 0xDC
    0xDB (FESC) -> 0xDB 0xDD
    """
    result = bytearray()
    for b in data:
        if b == FEND:
            result.extend([FESC, TFEND])
        elif b == FESC:
            result.extend([FESC, TFESC])
        else:
            result.append(b)
    return bytes(result)


def kiss_unescape(data: bytes) -> bytes:
    """Unescape payload data.

    0xDB 0xDC -> 0xC0 (FEND)
    0xDB 0xDD -> 0xDB (FESC)
    """
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == FESC:
            if i + 1 >= len(data):
                raise KissError("truncated escape sequence")
            next_byte = data[i + 1]
            if next_byte == TFEND:
                result.append(FEND)
            elif next_byte == TFESC:
                result.append(FESC)
            else:
                raise KissError(f"invalid escape sequence: 0xDB 0x{next_byte:02X}")
            i += 2
        else:
            result.append(data[i])
            i += 1
    return bytes(result)


def kiss_encode(port: int, command: int, data: bytes = b"") -> bytes:
    """Encode a KISS frame.

    Args:
        port: Port number 0-15
        command: Command type (KissCommand value)
        data: Payload data (will be escaped)

    Returns:
        Complete KISS frame: FEND | CMD | escaped_data | FEND
    """
    if not 0 <= port <= 15:
        raise ValueError(f"port must be 0-15, got {port}")
    if not 0 <= command <= 15:
        raise ValueError(f"command must be 0-15, got {command}")

    cmd_byte = (port << 4) | command
    # Escape the command byte along with the payload: (port=12, command=0)
    # makes cmd_byte == FEND (0xC0), which would corrupt the framing.
    escaped = kiss_escape(bytes([cmd_byte]) + data)
    return bytes([FEND]) + escaped + bytes([FEND])


def kiss_decode(frame: bytes) -> KissFrame:
    """Decode a KISS frame.

    Args:
        frame: Complete KISS frame (with FEND delimiters)

    Returns:
        KissFrame with port, command, and unescaped data

    Raises:
        KissError: If frame is malformed
    """
    if len(frame) < 3:
        raise KissError("frame too short")

    if frame[0] != FEND:
        raise KissError(f"frame must start with FEND (0xC0), got 0x{frame[0]:02X}")

    if frame[-1] != FEND:
        raise KissError(f"frame must end with FEND (0xC0), got 0x{frame[-1]:02X}")

    # Find actual end (skip consecutive FENDs at end)
    end = len(frame) - 1
    while end > 1 and frame[end - 1] == FEND:
        end -= 1

    if end < 2:
        raise KissError("empty frame")

    # Unescape the whole body first: the command byte is escaped on the
    # wire when its value collides with FEND/FESC (e.g. port=12, command=0).
    body = kiss_unescape(frame[1:end])
    if len(body) < 1:
        raise KissError("empty frame")

    cmd_byte = body[0]
    port = (cmd_byte >> 4) & 0x0F
    command = cmd_byte & 0x0F

    return KissFrame(port=port, command=command, data=bytes(body[1:]))


@dataclass
class KissReader:
    """Incremental KISS frame reader for stream transports.

    Feed bytes with feed(), iterate to get complete frames.

    Example:
        reader = KissReader()
        reader.feed(chunk1)
        reader.feed(chunk2)
        for frame in reader:
            handle(frame)
    """

    buffer: bytearray = field(default_factory=bytearray)
    max_frame_size: int = 2048  # Max escaped frame size
    _in_frame: bool = False
    _frame_start: int = 0

    def feed(self, data: bytes) -> None:
        """Add bytes to the buffer."""
        self.buffer.extend(data)

        # Limit buffer size to prevent memory exhaustion
        if len(self.buffer) > self.max_frame_size * 2:
            cut_point = -1
            for i in range(len(self.buffer) - 1):
                if self.buffer[i] == FEND and self.buffer[i + 1] != FEND:
                    cut_point = i
                    break
            if cut_point > 0:
                del self.buffer[:cut_point]
            elif cut_point == -1:
                self.buffer.clear()

    def __iter__(self) -> Iterator[KissFrame]:
        """Yield complete frames from buffer."""
        while True:
            frame = self._try_extract_frame()
            if frame is None:
                break
            yield frame

    def _try_extract_frame(self) -> KissFrame | None:
        """Try to extract one complete frame from buffer.

        Note: Port 12 with command 0 produces CMD byte 0xC0, which equals FEND.
        This is ambiguous with inter-frame padding and not supported. Use ports 0-11.
        """
        while True:
            # Skip leading non-FEND bytes (sync)
            while self.buffer and self.buffer[0] != FEND:
                del self.buffer[0]

            if len(self.buffer) < 3:
                return None

            # Skip inter-frame FEND padding to find frame content start.
            # After this loop, start points to the CMD byte (first non-FEND).
            # ponytail: port 12 cmd 0 = 0xC0 = FEND is unsupported, matches real TNCs
            start = 0
            while start < len(self.buffer) and self.buffer[start] == FEND:
                start += 1

            if start >= len(self.buffer):
                # Only FENDs in buffer
                return None

            # Find end FEND
            end = start
            while end < len(self.buffer) and self.buffer[end] != FEND:
                end += 1

            if end >= len(self.buffer):
                # No closing FEND yet
                return None

            # Extract frame: include start FEND and end FEND
            frame_bytes = bytes([FEND]) + bytes(self.buffer[start:end]) + bytes([FEND])

            # Remove from buffer (including trailing FEND)
            del self.buffer[: end + 1]

            try:
                return kiss_decode(frame_bytes)
            except KissError:
                # Invalid frame, skip and try next
                continue

    def clear(self) -> None:
        """Clear the buffer."""
        self.buffer.clear()
