# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Meshtastic ↔ LICHEN message translation.

Translates MeshPacket payloads to/from LICHEN CoAP and announce messages.

Supported port numbers:
- TEXT_MESSAGE_APP (1): UTF-8 text → POST /msg
- POSITION_APP (3): Position protobuf ↔ announce with position payload
- NODEINFO_APP (4): User protobuf ↔ synthesized from peer identity

Position encoding uses Meshtastic's latitude_i/longitude_i format:
degrees * 1e7, stored as signed 32-bit integers.

This module uses manual protobuf encoding/decoding for the subset of
messages needed, avoiding the betterproto dependency for now.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.interface.meshtastic.address import AddressMapper


class PortNum(IntEnum):
    """Meshtastic port numbers (subset)."""

    UNKNOWN_APP = 0
    TEXT_MESSAGE_APP = 1
    POSITION_APP = 3
    NODEINFO_APP = 4
    TELEMETRY_APP = 67


class TranslationError(Exception):
    """Raised when message translation fails."""


# Position protobuf field tags (wire type 5 = fixed32, wire type 0 = varint)
_POS_LATITUDE_I = 1  # sfixed32
_POS_LONGITUDE_I = 2  # sfixed32
_POS_ALTITUDE = 3  # int32 (varint)
_POS_TIME = 4  # fixed32

# User protobuf field tags (wire type 2 = length-delimited)
_USER_ID = 1  # string
_USER_LONG_NAME = 2  # string
_USER_SHORT_NAME = 3  # string
_USER_HW_MODEL = 5  # enum (varint)

# HardwareModel.PRIVATE_HW = 255
_HW_MODEL_PRIVATE = 255


@dataclass
class Position:
    """GPS position from Meshtastic Position message."""

    latitude_i: int | None = None  # degrees * 1e7
    longitude_i: int | None = None  # degrees * 1e7
    altitude: int | None = None  # meters
    time: int | None = None  # unix timestamp

    @property
    def latitude(self) -> float | None:
        """Latitude in degrees."""
        if self.latitude_i is None:
            return None
        return self.latitude_i / 1e7

    @property
    def longitude(self) -> float | None:
        """Longitude in degrees."""
        if self.longitude_i is None:
            return None
        return self.longitude_i / 1e7

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.latitude_i is not None:
            parts.append(bytes([(_POS_LATITUDE_I << 3) | 5]))  # wire type 5 = fixed32
            parts.append(struct.pack("<i", self.latitude_i))
        if self.longitude_i is not None:
            parts.append(bytes([(_POS_LONGITUDE_I << 3) | 5]))
            parts.append(struct.pack("<i", self.longitude_i))
        if self.altitude is not None:
            parts.append(bytes([(_POS_ALTITUDE << 3) | 0]))  # wire type 0 = varint
            parts.append(_encode_varint(self.altitude))
        if self.time is not None:
            parts.append(bytes([(_POS_TIME << 3) | 5]))
            parts.append(struct.pack("<I", self.time))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> Position:
        """Decode from protobuf."""
        pos = cls()
        i = 0
        while i < len(data):
            if i >= len(data):
                break
            tag_byte = data[i]
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x07
            i += 1

            if wire_type == 5:  # fixed32
                if i + 4 > len(data):
                    break
                if field_num == _POS_LATITUDE_I:
                    pos.latitude_i = struct.unpack("<i", data[i : i + 4])[0]
                elif field_num == _POS_LONGITUDE_I:
                    pos.longitude_i = struct.unpack("<i", data[i : i + 4])[0]
                elif field_num == _POS_TIME:
                    pos.time = struct.unpack("<I", data[i : i + 4])[0]
                i += 4
            elif wire_type == 0:  # varint
                val, consumed = _decode_varint(data[i:])
                if field_num == _POS_ALTITUDE:
                    pos.altitude = val
                i += consumed
            elif wire_type == 2:  # length-delimited (skip)
                if i >= len(data):
                    break
                length, consumed = _decode_varint(data[i:])
                i += consumed + length
            else:
                # Unknown wire type, can't skip safely
                break

        return pos


@dataclass
class User:
    """User identity from Meshtastic User message."""

    id: str = ""
    long_name: str = ""
    short_name: str = ""
    hw_model: int = _HW_MODEL_PRIVATE

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.id:
            parts.append(bytes([(_USER_ID << 3) | 2]))
            id_bytes = self.id.encode("utf-8")
            parts.append(_encode_varint(len(id_bytes)))
            parts.append(id_bytes)
        if self.long_name:
            parts.append(bytes([(_USER_LONG_NAME << 3) | 2]))
            name_bytes = self.long_name.encode("utf-8")
            parts.append(_encode_varint(len(name_bytes)))
            parts.append(name_bytes)
        if self.short_name:
            parts.append(bytes([(_USER_SHORT_NAME << 3) | 2]))
            name_bytes = self.short_name.encode("utf-8")
            parts.append(_encode_varint(len(name_bytes)))
            parts.append(name_bytes)
        parts.append(bytes([(_USER_HW_MODEL << 3) | 0]))
        parts.append(_encode_varint(self.hw_model))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> User:
        """Decode from protobuf."""
        user = cls()
        i = 0
        while i < len(data):
            if i >= len(data):
                break
            tag_byte = data[i]
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x07
            i += 1

            if wire_type == 2:  # length-delimited
                if i >= len(data):
                    break
                length, consumed = _decode_varint(data[i:])
                i += consumed
                if i + length > len(data):
                    break
                value = data[i : i + length]
                if field_num == _USER_ID:
                    user.id = value.decode("utf-8", errors="replace")
                elif field_num == _USER_LONG_NAME:
                    user.long_name = value.decode("utf-8", errors="replace")
                elif field_num == _USER_SHORT_NAME:
                    user.short_name = value.decode("utf-8", errors="replace")
                i += length
            elif wire_type == 0:  # varint
                val, consumed = _decode_varint(data[i:])
                if field_num == _USER_HW_MODEL:
                    user.hw_model = val
                i += consumed
            elif wire_type == 5:  # fixed32 (skip)
                i += 4
            elif wire_type == 1:  # fixed64 (skip)
                i += 8
            else:
                break

        return user


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    if value < 0:
        # Negative values use zigzag for signed types, or full 64-bit for int32
        # For simplicity, treat as unsigned (works for small negative values)
        value = value & 0xFFFFFFFF
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value)
    return bytes(parts) if parts else b"\x00"


def _decode_varint(data: bytes) -> tuple[int, int]:
    """Decode a protobuf varint, return (value, bytes_consumed)."""
    value = 0
    shift = 0
    for i, byte in enumerate(data):
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, i + 1
        shift += 7
        if shift > 63:
            raise TranslationError("varint too long")
    raise TranslationError("truncated varint")


@dataclass
class Translator:
    """Translates between Meshtastic and LICHEN messages.

    Handles:
    - Text messages (portnum 1) ↔ CoAP POST /msg
    - Position (portnum 3) ↔ announce with position payload
    - NodeInfo (portnum 4) ↔ synthesized from IID

    The Translator uses an AddressMapper to resolve node_num ↔ IID.
    """

    mapper: AddressMapper

    # --- Text Messages (portnum 1) ---

    def text_to_coap_payload(self, payload: bytes) -> bytes:
        """Extract text payload for CoAP POST /msg.

        Text messages are raw UTF-8 in the Meshtastic payload.

        Args:
            payload: Raw bytes from MeshPacket.decoded.payload

        Returns:
            UTF-8 bytes to POST to /msg
        """
        # Meshtastic text is already UTF-8
        return payload

    def coap_to_text_payload(self, payload: bytes) -> bytes:
        """Convert CoAP /msg response to Meshtastic text payload.

        Args:
            payload: Bytes received from /msg resource

        Returns:
            Raw bytes for MeshPacket.decoded.payload
        """
        return payload

    # --- Position (portnum 3) ---

    def position_to_announce_payload(self, payload: bytes) -> bytes:
        """Convert Meshtastic Position to LICHEN announce payload.

        The announce app_data format is CBOR:
        {"lat": float, "lon": float, "alt": int}

        Args:
            payload: Protobuf-encoded Position

        Returns:
            CBOR-encoded position for announce app_data
        """
        import cbor2

        pos = Position.from_bytes(payload)
        data: dict[str, int | float] = {}
        if pos.latitude is not None:
            data["lat"] = pos.latitude
        if pos.longitude is not None:
            data["lon"] = pos.longitude
        if pos.altitude is not None:
            data["alt"] = pos.altitude
        return cbor2.dumps(data)

    def announce_to_position_payload(self, app_data: bytes) -> bytes:
        """Convert LICHEN announce payload to Meshtastic Position.

        Args:
            app_data: CBOR-encoded position from announce

        Returns:
            Protobuf-encoded Position
        """
        import cbor2

        data = cbor2.loads(app_data)
        pos = Position()
        if "lat" in data:
            pos.latitude_i = int(data["lat"] * 1e7)
        if "lon" in data:
            pos.longitude_i = int(data["lon"] * 1e7)
        if "alt" in data:
            pos.altitude = int(data["alt"])
        return pos.to_bytes()

    # --- NodeInfo (portnum 4) ---

    def iid_to_user_payload(self, iid: bytes) -> bytes:
        """Synthesize Meshtastic User from LICHEN IID.

        Creates a User with:
        - id: "!XXXXXXXX" format from low 32 bits
        - long_name: hex of full IID
        - short_name: last 4 chars of hex IID
        - hw_model: PRIVATE_HW (255)

        Args:
            iid: 8-byte Interface Identifier

        Returns:
            Protobuf-encoded User
        """
        from lichen.interface.meshtastic.address import iid_to_user_id

        user = User(
            id=iid_to_user_id(iid),
            long_name=iid.hex(),
            short_name=iid.hex()[-4:].upper(),
            hw_model=_HW_MODEL_PRIVATE,
        )
        return user.to_bytes()

    def user_payload_to_names(self, payload: bytes) -> tuple[str, str]:
        """Extract names from Meshtastic User payload.

        Args:
            payload: Protobuf-encoded User

        Returns:
            Tuple of (long_name, short_name)
        """
        user = User.from_bytes(payload)
        return user.long_name, user.short_name
