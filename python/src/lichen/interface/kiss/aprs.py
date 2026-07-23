# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
APRS message format for APRSDroid compatibility.

Implements APRS message encoding/decoding so APRSDroid users see proper
messages in the Messages tab with delivery confirmations.

APRS message format (APRS101 spec chapter 14):
  :ADDRESSEE:message text{XXXXX

Where:
  - ADDRESSEE is exactly 9 characters (space-padded)
  - message text is the content
  - {XXXXX is optional message ID (1-5 chars) for ack tracking
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class AprsPacketType(Enum):
    """APRS packet types we handle."""
    MESSAGE = "message"
    ACK = "ack"
    REJ = "rej"
    POSITION = "position"  # Future
    UNKNOWN = "unknown"


@dataclass
class AprsMessage:
    """Parsed APRS message packet."""

    addressee: str  # 9-char destination (stripped)
    text: str  # Message content
    msg_id: str | None = None  # Message ID for acks (1-5 chars)

    def encode(self) -> bytes:
        """Encode to APRS message format."""
        # Pad addressee to 9 chars
        addr = self.addressee.upper()[:9].ljust(9)

        if self.msg_id:
            return f":{addr}:{self.text}{{{self.msg_id}".encode()
        return f":{addr}:{self.text}".encode()


@dataclass
class AprsAck:
    """APRS message acknowledgment."""

    addressee: str  # Who we're acking to
    msg_id: str  # Message ID being acked

    def encode(self) -> bytes:
        """Encode to APRS ack format."""
        addr = self.addressee.upper()[:9].ljust(9)
        return f":{addr}:ack{self.msg_id}".encode()


@dataclass
class AprsRej:
    """APRS message rejection."""

    addressee: str
    msg_id: str

    def encode(self) -> bytes:
        """Encode to APRS reject format."""
        addr = self.addressee.upper()[:9].ljust(9)
        return f":{addr}:rej{self.msg_id}".encode()


# Regex patterns for parsing
# Message: :ADDRESSEE:text{id or :ADDRESSEE:text
_MSG_PATTERN = re.compile(
    rb"^:(.{9}):(.+?)(?:\{([A-Za-z0-9]{1,5}))?$"
)
# Ack: :ADDRESSEE:ackXXXXX
_ACK_PATTERN = re.compile(
    rb"^:(.{9}):ack([A-Za-z0-9]{1,5})$"
)
# Reject: :ADDRESSEE:rejXXXXX
_REJ_PATTERN = re.compile(
    rb"^:(.{9}):rej([A-Za-z0-9]{1,5})$"
)


def parse_aprs_packet(data: bytes) -> AprsMessage | AprsAck | AprsRej | None:
    """Parse APRS packet from bytes.

    Args:
        data: Raw APRS packet bytes (info field, no AX.25 header)

    Returns:
        Parsed packet or None if not a recognized format.
    """
    # Try ack first (most specific)
    match = _ACK_PATTERN.match(data)
    if match:
        addressee = match.group(1).decode("utf-8", errors="replace").strip()
        msg_id = match.group(2).decode("utf-8", errors="replace")
        return AprsAck(addressee=addressee, msg_id=msg_id)

    # Try reject
    match = _REJ_PATTERN.match(data)
    if match:
        addressee = match.group(1).decode("utf-8", errors="replace").strip()
        msg_id = match.group(2).decode("utf-8", errors="replace")
        return AprsRej(addressee=addressee, msg_id=msg_id)

    # Try message
    match = _MSG_PATTERN.match(data)
    if match:
        addressee = match.group(1).decode("utf-8", errors="replace").strip()
        text = match.group(2).decode("utf-8", errors="replace")
        msg_id = None
        if match.group(3):
            msg_id = match.group(3).decode("utf-8", errors="replace")
        # Strip trailing { if text ends with it and no ID captured
        if text.endswith("{") and msg_id is None:
            text = text[:-1]
        return AprsMessage(addressee=addressee, text=text, msg_id=msg_id)

    return None


def get_packet_type(data: bytes) -> AprsPacketType:
    """Determine APRS packet type without full parsing."""
    if len(data) < 11:  # Minimum: :ADDRESSEE:x
        return AprsPacketType.UNKNOWN

    if data[0:1] != b":":
        # Not a message packet - could be position, status, etc.
        if data[0:1] in (b"!", b"=", b"/", b"@", b";", b")"):
            return AprsPacketType.POSITION
        return AprsPacketType.UNKNOWN

    # Check after the addressee
    if len(data) > 10:
        after = data[10:14]
        if after.startswith(b":ack"):
            return AprsPacketType.ACK
        if after.startswith(b":rej"):
            return AprsPacketType.REJ
        if after.startswith(b":"):
            return AprsPacketType.MESSAGE

    return AprsPacketType.UNKNOWN


@dataclass
class AprsMessageTracker:
    """Track pending messages for ack handling.

    Assigns message IDs, tracks pending acks, handles retries.
    """

    on_ack: Callable[[str, str], None] | None = None  # (addressee, msg_id)
    on_timeout: Callable[[str, str, str], None] | None = None  # (addressee, msg_id, text)
    retry_count: int = 3
    retry_interval_s: float = 30.0
    _next_id: int = field(default=1, repr=False)
    _pending: dict[str, tuple[str, str, float, int]] = field(
        default_factory=dict, repr=False
    )  # msg_id -> (addressee, text, send_time, retries_left)

    def next_msg_id(self) -> str:
        """Generate next message ID (1-5 alphanumeric)."""
        # Simple incrementing ID, wraps at 99999
        msg_id = str(self._next_id)
        self._next_id = (self._next_id % 99999) + 1
        return msg_id

    def track_message(self, addressee: str, text: str, msg_id: str) -> None:
        """Track an outgoing message for ack."""
        self._pending[msg_id] = (addressee, text, time.monotonic(), self.retry_count)

    def handle_ack(self, msg_id: str) -> bool:
        """Handle incoming ack. Returns True if matched pending message."""
        if msg_id in self._pending:
            addressee, _, _, _ = self._pending.pop(msg_id)
            if self.on_ack:
                self.on_ack(addressee, msg_id)
            return True
        return False

    def handle_rej(self, msg_id: str) -> bool:
        """Handle incoming reject. Returns True if matched pending message."""
        # Treat reject same as ack for tracking purposes
        return self.handle_ack(msg_id)

    def get_retries(self) -> list[tuple[str, str, str]]:
        now = time.monotonic()
        retries = []
        to_update = {}
        expired = []

        for msg_id, (addressee, text, send_time, retries_left) in list(self._pending.items()):
            if now - send_time >= self.retry_interval_s:
                if retries_left > 0:
                    retries.append((addressee, text, msg_id))
                    to_update[msg_id] = (addressee, text, now, retries_left - 1)
                else:
                    expired.append(msg_id)

        for msg_id, data in to_update.items():
            self._pending[msg_id] = data

        for msg_id in expired:
            if msg_id in self._pending:
                addressee, text, _, _ = self._pending.pop(msg_id)
                if self.on_timeout:
                    self.on_timeout(addressee, msg_id, text)

        return retries

    def pending_count(self) -> int:
        """Number of messages awaiting ack."""
        return len(self._pending)

    def clear(self) -> None:
        """Clear all pending messages."""
        self._pending.clear()


def create_message(addressee: str, text: str, msg_id: str | None = None) -> AprsMessage:
    """Create an APRS message.

    Args:
        addressee: Destination callsign (will be padded/truncated to 9 chars)
        text: Message text
        msg_id: Optional message ID for ack tracking

    Returns:
        AprsMessage ready to encode
    """
    return AprsMessage(addressee=addressee, text=text, msg_id=msg_id)


def create_ack(addressee: str, msg_id: str) -> AprsAck:
    """Create an APRS ack."""
    return AprsAck(addressee=addressee, msg_id=msg_id)
