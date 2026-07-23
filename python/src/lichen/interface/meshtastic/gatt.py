# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""BLE GATT service for Meshtastic app compatibility.

Implements the Meshtastic BLE interface allowing LICHEN nodes to appear
as Meshtastic devices to mobile apps. Mirrors the Rust implementation
in lichen-meshtastic/src/gatt.rs.

Service UUID: 6ba1b218-15a8-461f-9fa8-5dcae273eafd

Characteristics:
    ToRadio   (Write):      f75c76d2-129e-4dad-a1dd-7866124401e7
    FromRadio (Read):       2c55e69e-4993-11ed-b878-0242ac120002
    FromNum   (Read,Notify): ed9da18c-a800-4f66-a670-aa7547e34453

Wire format uses 4-byte length-prefix: [len_lo, len_hi, 0, 0] + protobuf.
"""

from __future__ import annotations

import logging
import struct
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic

from lichen.interface.meshtastic.proto import FromRadio, ToRadio

log = logging.getLogger(__name__)

# GATT Service UUIDs (canonical Meshtastic)
SERVICE_UUID = "6ba1b218-15a8-461f-9fa8-5dcae273eafd"
TORADIO_UUID = "f75c76d2-129e-4dad-a1dd-7866124401e7"
FROMRADIO_UUID = "2c55e69e-4993-11ed-b878-0242ac120002"
FROMNUM_UUID = "ed9da18c-a800-4f66-a670-aa7547e34453"

# MTU and queue limits
REQUESTED_MTU = 512
MAX_MESSAGE_SIZE = 512
MAX_QUEUE_DEPTH = 8
DEFAULT_DEADLINE_SECS = 60.0


class GattError(Exception):
    """Error during GATT operations."""


@dataclass
class QueueEntry:
    """A queued FromRadio message with expiration deadline."""

    data: bytes
    deadline: float  # monotonic timestamp

    def is_expired(self, now: float | None = None) -> bool:
        """Check if this entry has expired."""
        if now is None:
            now = monotonic()
        return now >= self.deadline


@dataclass
class MeshtasticGattService:
    """BLE GATT service state machine for Meshtastic protocol.

    Handles chunked writes, message queuing, and notification tracking.
    This is a stub providing the core logic; actual BLE registration
    requires platform-specific code (bleak/bless, Zephyr, etc.).

    Attributes:
        mtu: Negotiated MTU size.
        on_to_radio: Callback when a complete ToRadio message is received.
        on_notify: Callback to send FromNum notification.
    """

    mtu: int = REQUESTED_MTU
    on_to_radio: Callable[[ToRadio], None] | None = None
    on_notify: Callable[[int], None] | None = None

    # Internal state
    _write_buffer: bytearray = field(default_factory=bytearray)
    _write_expected_len: int | None = field(default=None)
    _from_radio_queue: deque[QueueEntry] = field(default_factory=deque)
    _from_num: int = field(default=0)
    _notifications_enabled: bool = field(default=False)
    _connected: bool = field(default=False)

    @property
    def from_num(self) -> int:
        """Current FromNum counter value."""
        return self._from_num

    @property
    def notifications_enabled(self) -> bool:
        """Whether notifications are enabled for FromNum."""
        return self._notifications_enabled

    @notifications_enabled.setter
    def notifications_enabled(self, value: bool) -> None:
        self._notifications_enabled = value

    @property
    def is_connected(self) -> bool:
        """Whether a client is connected."""
        return self._connected

    @property
    def pending_count(self) -> int:
        """Number of queued outbound messages."""
        return len(self._from_radio_queue)

    def on_connect(self, mtu: int = REQUESTED_MTU) -> None:
        """Called when a BLE client connects."""
        self._connected = True
        self.mtu = mtu
        self._write_buffer.clear()
        self._write_expected_len = None
        log.info("Meshtastic GATT client connected, MTU=%d", mtu)

    def on_disconnect(self) -> None:
        """Called when a BLE client disconnects."""
        self._connected = False
        self._notifications_enabled = False
        self._write_buffer.clear()
        self._write_expected_len = None
        self._from_radio_queue.clear()
        log.info("Meshtastic GATT client disconnected")

    def write_to_radio(self, chunk: bytes) -> ToRadio | None:
        """Handle a write to the ToRadio characteristic.

        Meshtastic BLE protocol uses chunked writes with a 4-byte header
        containing the message length. This method accumulates chunks until
        a complete message is received.

        Args:
            chunk: Raw bytes from BLE write.

        Returns:
            Parsed ToRadio when complete, None if still accumulating.
        """
        if not chunk:
            return None

        # If this is the start of a new message, parse the header
        if self._write_expected_len is None:
            buffered = len(self._write_buffer)
            if buffered > 0:
                # Partial header bytes buffered - accumulate
                header_bytes_needed = 4 - buffered
                if len(chunk) < header_bytes_needed:
                    self._write_buffer.extend(chunk)
                    return None
                self._write_buffer.extend(chunk[:header_bytes_needed])
                self._write_expected_len = struct.unpack(
                    "<H", self._write_buffer[:2]
                )[0]
                self._write_buffer.clear()
                if len(chunk) > header_bytes_needed:
                    self._write_buffer.extend(chunk[header_bytes_needed:])
            elif len(chunk) < 4:
                # Not enough for header
                self._write_buffer.extend(chunk)
                return None
            else:
                # Complete header
                self._write_expected_len = struct.unpack("<H", chunk[:2])[0]
                self._write_buffer.extend(chunk[4:])
        else:
            # Continue accumulating
            self._write_buffer.extend(chunk)

        # Check if complete
        if (
            self._write_expected_len is not None
            and len(self._write_buffer) >= self._write_expected_len
        ):
            data = bytes(self._write_buffer[: self._write_expected_len])
            # Preserve any trailing bytes that belong to the next message
            remaining = bytes(self._write_buffer[self._write_expected_len :])
            self._write_buffer.clear()
            self._write_buffer.extend(remaining)
            self._write_expected_len = None
            try:
                msg = ToRadio.from_bytes(data)
                if self.on_to_radio:
                    self.on_to_radio(msg)
                return msg
            except Exception as e:
                log.warning("Failed to parse ToRadio: %s", e)
                return None

        return None

    def queue_from_radio(
        self,
        msg: FromRadio,
        deadline_secs: float = DEFAULT_DEADLINE_SECS,
    ) -> int:
        """Queue an outbound FromRadio message.

        Args:
            msg: FromRadio message to queue.
            deadline_secs: Seconds until expiration (from now).

        Returns:
            New FromNum value.

        Raises:
            GattError: If queue is full.
        """
        if len(self._from_radio_queue) >= MAX_QUEUE_DEPTH:
            raise GattError("FromRadio queue full")

        data = msg.to_bytes()
        if len(data) > MAX_MESSAGE_SIZE:
            raise GattError(f"Message too large: {len(data)} > {MAX_MESSAGE_SIZE}")

        deadline = monotonic() + deadline_secs
        self._from_radio_queue.append(QueueEntry(data=data, deadline=deadline))
        self._from_num = (self._from_num + 1) & 0xFFFFFFFF

        if self._notifications_enabled and self.on_notify:
            self.on_notify(self._from_num)

        return self._from_num

    def _drain_expired(self) -> int:
        """Silently drop all expired entries (handles non-monotonic deadlines).

        Processes original queue length to remove expired entries anywhere
        in the queue by rotating non-expired entries to the back. Mirrors
        the Rust lichen-meshtastic implementation.
        """
        now = monotonic()
        dropped = 0
        original_len = len(self._from_radio_queue)
        for _ in range(original_len):
            if not self._from_radio_queue:
                break
            entry = self._from_radio_queue.popleft()
            if entry.is_expired(now):
                dropped += 1
            else:
                self._from_radio_queue.append(entry)
        return dropped

    def peek_from_radio(self) -> bytes | None:
        """Peek next non-expired FromRadio message (for characteristic read).

        Returns raw protobuf bytes, NOT including length header.
        """
        self._drain_expired()
        if self._from_radio_queue:
            return self._from_radio_queue[0].data
        return None

    def pop_from_radio(self) -> bytes | None:
        """Remove and return next non-expired FromRadio message.

        Returns raw protobuf bytes, NOT including length header.
        """
        self._drain_expired()
        if self._from_radio_queue:
            return self._from_radio_queue.popleft().data
        return None

    def read_from_radio_response(self) -> bytes | None:
        """Read next message formatted for BLE response (with length header).

        Returns 4-byte header + protobuf, or None if queue empty.
        """
        data = self.pop_from_radio()
        if data is None:
            return None
        return build_from_radio_response(data)


def build_from_radio_response(data: bytes) -> bytes:
    """Build a FromRadio response with 4-byte length header.

    Args:
        data: Raw protobuf bytes.

    Returns:
        4-byte header + data, suitable for BLE FromRadio characteristic.
    """
    if len(data) > 0xFFFF:
        raise GattError(f"Message too large for header: {len(data)}")
    header = struct.pack("<HBB", len(data), 0, 0)  # len_lo, len_hi, reserved, reserved
    return header + data


def parse_ble_message(data: bytes) -> tuple[bytes, int]:
    """Parse a BLE message with 4-byte length header.

    Args:
        data: Raw bytes including header.

    Returns:
        Tuple of (payload_bytes, total_consumed).

    Raises:
        GattError: If data is too short or truncated.
    """
    if len(data) < 4:
        raise GattError("Message too short for header")
    length = struct.unpack("<H", data[:2])[0]
    if len(data) < 4 + length:
        raise GattError(f"Message truncated: expected {length}, got {len(data) - 4}")
    return data[4 : 4 + length], 4 + length
