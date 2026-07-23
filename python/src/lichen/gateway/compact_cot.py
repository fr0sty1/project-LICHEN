# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Compact CoT decoder and XML expander for ATAK interoperability.

Implements spec/07-transport-app.md Section 10.1.1:
- Decodes compact binary CoT from LICHEN mesh (port 5681)
- Expands to full CoT XML for ATAK/TAK servers (TCP 8087)

Wire formats:
  PLI (17 bytes): subtype(1) + lat(4) + lon(4) + alt(2) + course(2) + speed(2) + team(1) + role(1)
  Chat (variable): subtype(1) + dest_type(1) + dest_id(0/1/8) + len(1) + text(N)
"""

from __future__ import annotations

import hashlib
import math
import struct
import uuid
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from xml.etree.ElementTree import Element, SubElement, tostring

# -- Constants --

PLI_PAYLOAD_SIZE = 16  # Excluding subtype byte
PLI_TOTAL_SIZE = 17  # Including subtype byte

# int16 range for altitude in decimeters (-3276.8m to +3276.7m)
INT16_MIN = -32768
INT16_MAX = 32767
UINT16_MAX = 65535  # Max speed cm/s (655.35 m/s); 0xFFFF often invalid sentinel
MAX_PLAUSIBLE_SPEED_M_S = 100.0  # ~360km/h; implausible for ground units


# -- Enums --


class CompactCotType(IntEnum):
    """Compact CoT message subtype byte."""

    CHAT = 0x01
    FRIENDLY_PLI = 0x02
    HOSTILE_PLI = 0x03
    NEUTRAL_PLI = 0x04
    UNKNOWN_PLI = 0x05
    MARKER = 0x10
    ALERT = 0x20

    def is_pli(self) -> bool:
        """Return True if this is a PLI subtype."""
        return self in (
            CompactCotType.FRIENDLY_PLI,
            CompactCotType.HOSTILE_PLI,
            CompactCotType.NEUTRAL_PLI,
            CompactCotType.UNKNOWN_PLI,
        )

    def to_cot_type(self) -> str:
        """Convert to CoT type string."""
        mapping = {
            CompactCotType.CHAT: "b-t-f",
            CompactCotType.FRIENDLY_PLI: "a-f-G-U-C",
            CompactCotType.HOSTILE_PLI: "a-h-G-U-C",
            CompactCotType.NEUTRAL_PLI: "a-n-G-U-C",
            CompactCotType.UNKNOWN_PLI: "a-u-G-U-C",
            CompactCotType.MARKER: "b-m-p-w",
            CompactCotType.ALERT: "b-a-o-tbl",
        }
        return mapping[self]


class DestType(IntEnum):
    """Chat destination type."""

    BROADCAST = 0x00
    TEAM = 0x01
    DIRECT = 0x02

    def dest_id_size(self) -> int:
        """Return size of dest_id field for this destination type."""
        if self == DestType.BROADCAST:
            return 0
        elif self == DestType.TEAM:
            return 1
        else:  # DIRECT
            return 8


class Team(IntEnum):
    """Team enumeration matching ATAK team colors."""

    BLUE = 0x01
    RED = 0x02
    GREEN = 0x03
    ORANGE = 0x04
    MAGENTA = 0x05
    MAROON = 0x06
    PURPLE = 0x07
    TEAL = 0x08
    WHITE = 0x09
    YELLOW = 0x0A

    def to_name(self) -> str:
        """Return ATAK team name."""
        return self.name.capitalize()

    @classmethod
    def from_byte(cls, b: int) -> Team | None:
        """Parse team from byte, returns None if invalid."""
        try:
            return cls(b)
        except ValueError:
            return None


# -- Role mapping (ATAK role strings) --

ROLE_NAMES = {
    0x01: "Team Member",
    0x02: "Team Lead",
    0x03: "HQ",
    0x04: "Sniper",
    0x05: "Medic",
    0x06: "Forward Observer",
    0x07: "RTO",
    0x08: "K9",
}


def role_to_name(role: int) -> str:
    """Convert role byte to ATAK role name."""
    return ROLE_NAMES.get(role, "Team Member")


# -- Deterministic UID generation --


def _derive_uid(namespace: str, *parts: str | bytes) -> str:
    """Derive a deterministic UUID-style UID from content parts.

    Uses SHA-256 hash truncated to UUID format for deterministic,
    content-based UID generation. This enables idempotent expansion
    and proper message deduplication.

    Args:
        namespace: Namespace prefix for the hash (e.g., "sender", "message")
        parts: Content parts to hash (strings or bytes)

    Returns:
        UUID-formatted string derived from content hash
    """
    h = hashlib.sha256()
    h.update(namespace.encode("utf-8"))
    for part in parts:
        if isinstance(part, str):
            h.update(part.encode("utf-8"))
        else:
            h.update(part)
    # Take first 16 bytes and format as UUID
    digest = h.digest()[:16]
    return str(uuid.UUID(bytes=digest))


def _derive_uid_from_cot(cot: CompactCot) -> str:
    """Derive deterministic UID from CompactCot content.

    Uses message content to generate a stable UID that remains
    the same across multiple expansions of the same message.
    """
    parts: list[str | bytes] = [str(cot.subtype.value)]
    if isinstance(cot.payload, PliPayload):
        pli = cot.payload
        parts.extend(
            [
                str(pli.lat_microdeg),
                str(pli.lon_microdeg),
                str(pli.alt_dm),
                str(pli.course_cdeg),
                str(pli.speed_cm_s),
                str(pli.team),
                str(pli.role),
            ]
        )
    elif isinstance(cot.payload, ChatPayload):
        chat = cot.payload
        parts.append(str(chat.dest_type.value))
        if chat.dest_team is not None:
            parts.append(str(chat.dest_team))
        if chat.dest_iid is not None:
            parts.append(chat.dest_iid)
        parts.append(chat.message)
    return _derive_uid("sender", *parts)


# -- Data classes --


@dataclass
class PliPayload:
    """Position Location Information payload."""

    lat_microdeg: int  # int32 microdegrees
    lon_microdeg: int  # int32 microdegrees
    alt_dm: int  # int16 decimeters
    course_cdeg: int  # uint16 centidegrees (0-35999)
    speed_cm_s: int  # uint16 cm/s; 0xFFFF may indicate sensor invalid/no-fix
    team: int  # uint8
    role: int  # uint8

    @property
    def lat_deg(self) -> float:
        """Latitude in degrees."""
        return self.lat_microdeg / 1_000_000.0

    @property
    def lon_deg(self) -> float:
        """Longitude in degrees."""
        return self.lon_microdeg / 1_000_000.0

    @property
    def alt_m(self) -> float:
        """Altitude in meters (HAE)."""
        return self.alt_dm / 10.0

    @property
    def course_deg(self) -> float:
        """Course in degrees."""
        return self.course_cdeg / 100.0

    @property
    def speed_m_s(self) -> float:
        """Speed in m/s. 0xFFFF sentinel treated as 0 (no valid fix)."""
        if self.speed_cm_s == UINT16_MAX:
            return 0.0
        return self.speed_cm_s / 100.0

    @property
    def team_name(self) -> str:
        """Team name string."""
        t = Team.from_byte(self.team)
        return t.to_name() if t else "White"

    @property
    def role_name(self) -> str:
        """Role name string."""
        return role_to_name(self.role)


@dataclass
class ChatPayload:
    """Chat message payload."""

    dest_type: DestType
    dest_team: int | None  # Only if dest_type == TEAM
    dest_iid: bytes | None  # Only if dest_type == DIRECT (8 bytes)
    message: str  # UTF-8 text


@dataclass
class CompactCot:
    """Decoded compact CoT message."""

    subtype: CompactCotType
    payload: PliPayload | ChatPayload | None


# -- Decoder --


class DecodeError(Exception):
    """Compact CoT decoding error."""

    pass


def decode_compact_cot(data: bytes) -> CompactCot:
    """Decode compact CoT from binary.

    Args:
        data: Raw compact CoT bytes from mesh.

    Returns:
        Decoded CompactCot message.

    Raises:
        DecodeError: If data is malformed.
    """
    if len(data) < 1:
        raise DecodeError("Empty buffer")

    try:
        subtype = CompactCotType(data[0])
    except ValueError as exc:
        raise DecodeError(f"Unknown subtype: 0x{data[0]:02x}") from exc

    if subtype.is_pli():
        return _decode_pli(subtype, data)
    elif subtype == CompactCotType.CHAT:
        return _decode_chat(data)
    elif subtype in (CompactCotType.MARKER, CompactCotType.ALERT):
        # Marker and Alert have no payload defined yet per spec
        return CompactCot(subtype=subtype, payload=None)
    else:
        raise DecodeError(f"Unhandled subtype: {subtype}")


def _decode_pli(subtype: CompactCotType, data: bytes) -> CompactCot:
    """Decode PLI message."""
    if len(data) < PLI_TOTAL_SIZE:
        raise DecodeError(f"PLI too short: {len(data)} < {PLI_TOTAL_SIZE}")
    if len(data) > PLI_TOTAL_SIZE:
        warnings.warn(f"PLI has {len(data) - PLI_TOTAL_SIZE} trailing bytes", stacklevel=2)

    # Parse fields (big-endian)
    lat = struct.unpack(">i", data[1:5])[0]
    lon = struct.unpack(">i", data[5:9])[0]
    alt = struct.unpack(">h", data[9:11])[0]
    course = struct.unpack(">H", data[11:13])[0]
    speed = struct.unpack(">H", data[13:15])[0]
    team = data[15]
    role = data[16]

    # Validate geographic coordinate ranges (microdegrees)
    if not (-90_000_000 <= lat <= 90_000_000):
        raise DecodeError(f"Latitude {lat} out of range [-90000000, 90000000]")
    if not (-180_000_000 <= lon <= 180_000_000):
        raise DecodeError(f"Longitude {lon} out of range [-180000000, 180000000]")

    # Course 0-359.99deg; speed 0xFFFF commonly signals invalid sensor reading
    if not (0 <= course <= 35999):
        raise DecodeError(f"Course {course} out of range [0, 35999]")
    if speed > int(MAX_PLAUSIBLE_SPEED_M_S * 100):
        warnings.warn(
            f"Implausible speed {speed}cm/s ({speed/100.0:.1f}m/s) in PLI "
            f"from mesh (0xFFFF may indicate sensor error/no GPS fix)",
            stacklevel=2,
        )

    payload = PliPayload(
        lat_microdeg=lat,
        lon_microdeg=lon,
        alt_dm=alt,
        course_cdeg=course,
        speed_cm_s=speed,
        team=team,
        role=role,
    )
    return CompactCot(subtype=subtype, payload=payload)


def _decode_chat(data: bytes) -> CompactCot:
    """Decode chat message."""
    if len(data) < 3:
        raise DecodeError(f"Chat too short: {len(data)} < 3")

    try:
        dest_type = DestType(data[1])
    except ValueError as exc:
        raise DecodeError(f"Invalid dest_type: 0x{data[1]:02x}") from exc

    dest_id_size = dest_type.dest_id_size()
    header_size = 2 + dest_id_size + 1  # subtype + dest_type + dest_id + length

    if len(data) < header_size:
        raise DecodeError(f"Chat header too short: {len(data)} < {header_size}")

    dest_team = None
    dest_iid = None

    if dest_type == DestType.TEAM:
        dest_team = data[2]
    elif dest_type == DestType.DIRECT:
        dest_iid = bytes(data[2:10])

    len_pos = 2 + dest_id_size
    msg_len = data[len_pos]
    total_size = header_size + msg_len

    if len(data) < total_size:
        raise DecodeError(f"Chat message truncated: {len(data)} < {total_size}")
    if len(data) > total_size:
        warnings.warn(f"Chat message has {len(data) - total_size} trailing bytes", stacklevel=2)

    msg_start = len_pos + 1
    msg_bytes = data[msg_start : msg_start + msg_len]

    try:
        message = msg_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"Invalid UTF-8 in message: {exc}") from exc

    payload = ChatPayload(
        dest_type=dest_type,
        dest_team=dest_team,
        dest_iid=dest_iid,
        message=message,
    )
    return CompactCot(subtype=CompactCotType.CHAT, payload=payload)


# -- XML Expander --


def expand_cot_to_xml(
    cot: CompactCot,
    sender_uid: str | None = None,
    sender_callsign: str | None = None,
    now: datetime | None = None,
    stale_seconds: int = 120,
) -> str:
    """Expand compact CoT to full ATAK-compatible XML.

    Args:
        cot: Decoded compact CoT message.
        sender_uid: Sender UID (e.g., IID as hex). If None, generates UUID.
        sender_callsign: Sender callsign for chat messages.
        now: Current timestamp. If None, uses datetime.now(UTC).
        stale_seconds: Seconds until event goes stale (default 120).

    Returns:
        CoT XML string.

    Raises:
        ValueError: If unknown subtype cannot be expanded.

    MARKER and ALERT return minimal placeholder XML (0,0,0 coords,
    generic detail) as compact format has no payload for them yet.
    """
    if now is None:
        now = datetime.now(UTC)

    if sender_uid is None:
        # Derive deterministic UID from message content for idempotent expansion
        sender_uid = _derive_uid_from_cot(cot)

    stale = now + timedelta(seconds=stale_seconds)

    # Format timestamps as ISO 8601 with Z suffix
    time_str = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    stale_str = stale.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stale.microsecond // 1000:03d}Z"

    if cot.subtype.is_pli():
        return _expand_pli_to_xml(cot, sender_uid, time_str, stale_str)
    elif cot.subtype == CompactCotType.CHAT:
        return _expand_chat_to_xml(
            cot, sender_uid, sender_callsign or sender_uid, time_str, stale_str
        )
    elif cot.subtype == CompactCotType.MARKER:
        return _expand_marker_to_xml(cot, sender_uid, time_str, stale_str)
    elif cot.subtype == CompactCotType.ALERT:
        return _expand_alert_to_xml(cot, sender_uid, time_str, stale_str)
    else:
        raise ValueError(f"Cannot expand subtype: {cot.subtype}")


def _expand_pli_to_xml(
    cot: CompactCot,
    uid: str,
    time_str: str,
    stale_str: str,
) -> str:
    """Expand PLI to CoT XML."""
    if not isinstance(cot.payload, PliPayload):
        raise TypeError(f"Expected PliPayload, got {type(cot.payload).__name__}")
    pli = cot.payload

    event = Element("event")
    event.set("version", "2.0")
    event.set("type", cot.subtype.to_cot_type())
    event.set("uid", uid)
    event.set("how", "m-g")
    event.set("time", time_str)
    event.set("start", time_str)
    event.set("stale", stale_str)

    point = SubElement(event, "point")
    point.set("lat", f"{pli.lat_deg:.6f}")
    point.set("lon", f"{pli.lon_deg:.6f}")
    point.set("hae", f"{pli.alt_m:.1f}")
    point.set("ce", "9999999")
    point.set("le", "9999999")

    detail = SubElement(event, "detail")

    contact = SubElement(detail, "contact")
    contact.set("callsign", uid)

    group = SubElement(detail, "__group")
    group.set("name", pli.team_name)
    group.set("role", pli.role_name)

    track = SubElement(detail, "track")
    track.set("course", f"{pli.course_deg:.2f}")
    track.set("speed", f"{pli.speed_m_s:.2f}")

    prec = SubElement(detail, "precisionlocation")
    prec.set("altsrc", "DTED0")
    prec.set("geopointsrc", "GPS")

    return _xml_to_string(event)


def _expand_chat_to_xml(
    cot: CompactCot,
    sender_uid: str,
    sender_callsign: str,
    time_str: str,
    stale_str: str,
) -> str:
    """Expand chat to GeoChat CoT XML."""
    if not isinstance(cot.payload, ChatPayload):
        raise TypeError(f"Expected ChatPayload, got {type(cot.payload).__name__}")
    chat = cot.payload

    # Derive deterministic message ID from sender + timestamp + content
    # This enables idempotent expansion and proper deduplication
    message_id = _derive_uid("message", sender_uid, time_str, chat.message)

    # Build event element
    event = Element("event")
    event.set("version", "2.0")
    event.set("type", "b-t-f")
    event.set("uid", f"GeoChat.{sender_uid}.{message_id}")
    event.set("how", "h-g-i-g-o")  # human-generated
    event.set("time", time_str)
    event.set("start", time_str)
    event.set("stale", stale_str)

    detail = SubElement(event, "detail")

    # __chat element
    chat_elem = SubElement(detail, "__chat")
    chat_elem.set("senderCallsign", sender_callsign)
    chat_elem.set("messageId", message_id)

    # Set chatroom based on destination
    if chat.dest_type == DestType.BROADCAST:
        chat_elem.set("chatroom", "All Chat Rooms")
        chat_elem.set("id", "All Chat Rooms")
    elif chat.dest_type == DestType.TEAM:
        team = Team.from_byte(chat.dest_team or 0)
        team_name = team.to_name() if team else "Unknown"
        chat_elem.set("chatroom", f"Team {team_name}")
        chat_elem.set("id", f"Team {team_name}")
        chat_elem.set("groupOwner", "true")
    elif chat.dest_type == DestType.DIRECT:
        dest_uid = chat.dest_iid.hex() if chat.dest_iid else "unknown"
        chat_elem.set("chatroom", dest_uid)
        chat_elem.set("id", dest_uid)

    # chatgrp element
    chatgrp = SubElement(chat_elem, "chatgrp")
    chatgrp.set("uid0", sender_uid)
    chatgrp.set("uid1", _get_dest_uid(chat))

    # link element
    link = SubElement(detail, "link")
    link.set("uid", sender_uid)
    link.set("type", "a-f-G-U-C")
    link.set("relation", "p-p")

    # remarks element with message text
    remarks = SubElement(detail, "remarks")
    remarks.set("source", "BAO.F.ATAK." + sender_uid)
    remarks.set("to", _get_dest_uid(chat))
    remarks.set("time", time_str)
    remarks.text = chat.message

    # __serverdestination for routing
    serverdest = SubElement(detail, "__serverdestination")
    serverdest.set("destinations", _get_dest_uid(chat))

    return _xml_to_string(event)


def _expand_marker_to_xml(
    cot: CompactCot,
    uid: str,
    time_str: str,
    stale_str: str,
) -> str:
    """Expand marker to CoT XML (minimal, no location data in compact format)."""
    event = Element("event")
    event.set("version", "2.0")
    event.set("type", "b-m-p-w")
    event.set("uid", uid)
    event.set("how", "m-g")
    event.set("time", time_str)
    event.set("start", time_str)
    event.set("stale", stale_str)

    detail = SubElement(event, "detail")
    contact = SubElement(detail, "contact")
    contact.set("callsign", uid)

    return _xml_to_string(event)


def _expand_alert_to_xml(
    cot: CompactCot,
    uid: str,
    time_str: str,
    stale_str: str,
) -> str:
    """Expand alert to CoT XML (minimal, no payload data in compact format)."""
    event = Element("event")
    event.set("version", "2.0")
    event.set("type", "b-a-o-tbl")  # alert
    event.set("uid", uid)
    event.set("how", "m-g")
    event.set("time", time_str)
    event.set("start", time_str)
    event.set("stale", stale_str)

    detail = SubElement(event, "detail")
    contact = SubElement(detail, "contact")
    contact.set("callsign", uid)

    return _xml_to_string(event)


def _get_dest_uid(chat: ChatPayload) -> str:
    """Get destination UID string from chat payload."""
    if chat.dest_type == DestType.BROADCAST:
        return "All Chat Rooms"
    elif chat.dest_type == DestType.TEAM:
        team = Team.from_byte(chat.dest_team or 0)
        return f"Team {team.to_name()}" if team else "Team Unknown"
    elif chat.dest_type == DestType.DIRECT:
        return chat.dest_iid.hex() if chat.dest_iid else "unknown"
    return "unknown"


def _xml_to_string(elem: Element) -> str:
    """Convert Element to XML string."""
    # Use xml declaration per ATAK spec
    xml_bytes = tostring(elem, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>' + xml_bytes


# -- Encoder --


def encode_compact_cot(cot: CompactCot) -> bytes:
    """Encode CompactCot to binary.

    Args:
        cot: CompactCot message to encode.

    Returns:
        Encoded binary bytes.

    Raises:
        ValueError: If message cannot be encoded.
    """
    if cot.subtype.is_pli():
        if not isinstance(cot.payload, PliPayload):
            raise ValueError("PLI subtype requires PliPayload")
        return _encode_pli(cot.subtype, cot.payload)
    elif cot.subtype == CompactCotType.CHAT:
        if not isinstance(cot.payload, ChatPayload):
            raise ValueError("CHAT subtype requires ChatPayload")
        return _encode_chat(cot.payload)
    elif cot.subtype in (CompactCotType.MARKER, CompactCotType.ALERT):
        return bytes([cot.subtype])
    else:
        raise ValueError(f"Cannot encode subtype: {cot.subtype}")


def _encode_pli(subtype: CompactCotType, pli: PliPayload) -> bytes:
    """Encode PLI to binary."""
    return (
        bytes([subtype])
        + struct.pack(">i", pli.lat_microdeg)
        + struct.pack(">i", pli.lon_microdeg)
        + struct.pack(">h", pli.alt_dm)
        + struct.pack(">H", pli.course_cdeg)
        + struct.pack(">H", pli.speed_cm_s)
        + bytes([pli.team, pli.role])
    )


def _encode_chat(chat: ChatPayload) -> bytes:
    """Encode chat to binary."""
    msg_bytes = chat.message.encode("utf-8")
    if len(msg_bytes) > 255:
        raise ValueError("Chat message exceeds 255 bytes")

    parts = [bytes([CompactCotType.CHAT, chat.dest_type])]

    if chat.dest_type == DestType.TEAM:
        if chat.dest_team is None:
            raise ValueError("dest_team required when dest_type is TEAM")
        parts.append(bytes([chat.dest_team]))
    elif chat.dest_type == DestType.DIRECT:
        if chat.dest_iid is None:
            raise ValueError("dest_iid required when dest_type is DIRECT")
        if len(chat.dest_iid) != 8:
            raise ValueError("dest_iid must be exactly 8 bytes")
        parts.append(chat.dest_iid)

    parts.append(bytes([len(msg_bytes)]))
    parts.append(msg_bytes)

    return b"".join(parts)


# -- XML Parser (Compressor) --


# Team name to enum mapping (case-insensitive)
TEAM_BY_NAME: dict[str, Team] = {t.name.lower(): t for t in Team}

# Role name to byte mapping (case-insensitive)
ROLE_BY_NAME: dict[str, int] = {v.lower(): k for k, v in ROLE_NAMES.items()}


def parse_cot_xml(xml_data: str | bytes) -> CompactCot:
    """Parse CoT XML and convert to CompactCot.

    This is the gateway entry point for compressing CoT XML from ATAK
    into compact binary format for mesh transmission.

    Expected XML structure:
        <event type="a-f-G-U-C" uid="..." time="..." stale="...">
          <point lat="47.606" lon="-122.332" hae="158"/>
          <detail>
            <__group name="Blue" role="Team Lead"/>
            <track course="270" speed="1.2"/>
            <remarks>Chat message text</remarks>
          </detail>
        </event>

    Args:
        xml_data: CoT XML string or bytes.

    Returns:
        CompactCot message ready for encoding.

    Raises:
        ValueError: If XML cannot be parsed or required elements are missing.
    """
    # SECURITY: Use defusedxml to prevent XML entity expansion attacks
    # (Billion Laughs, Quadratic Blowup) from untrusted ATAK sources
    from defusedxml.ElementTree import fromstring

    if isinstance(xml_data, bytes):
        xml_data = xml_data.decode("utf-8")

    root = fromstring(xml_data)
    if root.tag != "event":
        raise ValueError(f"Expected <event> root element, got <{root.tag}>")

    cot_type = root.get("type")
    if not cot_type:
        raise ValueError("Missing 'type' attribute on <event>")

    subtype = _cot_type_to_subtype(cot_type)

    if subtype == CompactCotType.CHAT:
        return _parse_xml_chat(root, subtype)

    if subtype.is_pli():
        return _parse_xml_pli(root, subtype)

    # Marker and Alert don't have payloads defined yet
    return CompactCot(subtype=subtype, payload=None)


def _cot_type_to_subtype(cot_type: str) -> CompactCotType:
    """Map CoT event type string to compact subtype.

    CoT type format: "a-f-G-..." where:
        - First letter: a=atom, b=bits
        - Second letter: f=friend, h=hostile, n=neutral, u=unknown
        - Third letter: G=ground, A=air, S=sea, etc.
    """
    if cot_type.startswith("b-t-f"):
        return CompactCotType.CHAT
    if cot_type.startswith("b-a"):
        return CompactCotType.ALERT
    if cot_type.startswith("b-m-p"):
        return CompactCotType.MARKER

    # Atom types (a-X-G-*) for ground positions
    parts = cot_type.split("-")
    if len(parts) >= 3 and parts[0] == "a" and parts[2] == "G":
        affiliation = parts[1]
        if affiliation == "f":
            return CompactCotType.FRIENDLY_PLI
        if affiliation == "h":
            return CompactCotType.HOSTILE_PLI
        if affiliation == "n":
            return CompactCotType.NEUTRAL_PLI
        if affiliation == "u":
            return CompactCotType.UNKNOWN_PLI

    raise ValueError(f"Cannot map CoT type to compact subtype: {cot_type}")


def _parse_xml_pli(root: Element, subtype: CompactCotType) -> CompactCot:
    """Parse PLI from XML event element."""
    point = root.find("point")
    if point is None:
        raise ValueError("Missing <point> element for PLI")

    lat_str = point.get("lat")
    lon_str = point.get("lon")
    if lat_str is None or lon_str is None:
        raise ValueError("Missing lat/lon attributes on <point>")

    lat = float(lat_str)
    lon = float(lon_str)
    if math.isnan(lat) or math.isinf(lat) or math.isnan(lon) or math.isinf(lon):
        raise ValueError("NaN/Inf in CoT coordinates")
    if not (-90.0 <= lat <= 90.0):
        raise ValueError(f"Latitude {lat} out of range [-90, 90]")
    if not (-180.0 <= lon <= 180.0):
        raise ValueError(f"Longitude {lon} out of range [-180, 180]")

    # hae = height above ellipsoid (altitude in meters)
    hae_str = point.get("hae")
    alt_m = float(hae_str) if hae_str else 0.0
    if not math.isfinite(alt_m):
        raise ValueError(f"Altitude value {alt_m} is not a finite number")

    course_deg = 0.0
    speed_m_s = 0.0
    detail = root.find("detail")
    if detail is not None:
        track = detail.find("track")
        if track is not None:
            course_str = track.get("course")
            speed_str = track.get("speed")
            if course_str:
                course_deg = float(course_str)
                if not math.isfinite(course_deg):
                    raise ValueError(f"Course value {course_deg} is not a finite number")
                course_deg = course_deg % 360.0
            if speed_str:
                speed_m_s = float(speed_str)
                if not math.isfinite(speed_m_s):
                    raise ValueError(f"Speed value {speed_m_s} is not a finite number")
                if speed_m_s < 0:
                    raise ValueError(f"Speed {speed_m_s} cannot be negative")
                if speed_m_s > MAX_PLAUSIBLE_SPEED_M_S:
                    warnings.warn(
                        f"Implausible speed {speed_m_s:.1f} m/s from CoT XML "
                        f"(clamped; 0xFFFF sentinel may indicate sensor error)",
                        stacklevel=3,
                    )
                    speed_m_s = MAX_PLAUSIBLE_SPEED_M_S

    # Extract team/role from <__group> element
    team_val = Team.BLUE
    role_val = 1
    if detail is not None:
        group = detail.find("__group")
        if group is not None:
            team_name = group.get("name")
            if team_name:
                team_val = TEAM_BY_NAME.get(team_name.lower(), Team.BLUE)
            role_str = group.get("role")
            if role_str:
                role_val = ROLE_BY_NAME.get(role_str.lower(), 1)

    # Clamp altitude to int16 range (-3276.8m to +3276.7m)
    alt_dm = max(INT16_MIN, min(INT16_MAX, int(alt_m * 10)))
    # Clamp speed to uint16 range (0-65535 cm/s). Implausible values (>100m/s)
    # warned and clamped above per project-LICHEN-z4zm (0xFFFF sentinel).
    speed_cm_s = min(UINT16_MAX, max(0, int(speed_m_s * 100)))

    pli = PliPayload(
        lat_microdeg=int(lat * 1_000_000),
        lon_microdeg=int(lon * 1_000_000),
        alt_dm=alt_dm,
        course_cdeg=int(course_deg * 100),
        speed_cm_s=speed_cm_s,
        team=team_val,
        role=role_val,
    )

    return CompactCot(subtype=subtype, payload=pli)


def _parse_xml_chat(root: Element, subtype: CompactCotType) -> CompactCot:
    """Parse chat message from XML event element."""
    detail = root.find("detail")
    if detail is None:
        raise ValueError("Missing <detail> element for chat")

    # Chat message is in <remarks> element
    remarks = detail.find("remarks")
    message = remarks.text if remarks is not None and remarks.text else ""

    # Determine destination
    dest_type = DestType.BROADCAST
    dest_team = None
    dest_iid = None

    # Check for team destination in __chat element
    chat_elem = detail.find("__chat")
    if chat_elem is not None:
        chat_group = chat_elem.get("chatroom")
        if chat_group:
            # Check team names first to avoid ambiguity with 16-char hex names
            # Handle both "Blue" and "Team Blue" formats (roundtrip)
            team_name = chat_group.lower()
            if team_name.startswith("team "):
                team_name = team_name[5:]
            team = TEAM_BY_NAME.get(team_name)
            if team:
                dest_type = DestType.TEAM
                dest_team = team
            elif len(chat_group) == 16:
                # Direct message: hex IID = 16 hex chars = 8 bytes
                try:
                    dest_iid = bytes.fromhex(chat_group)
                    dest_type = DestType.DIRECT
                except ValueError:
                    pass  # Not valid hex, leave as broadcast

    chat = ChatPayload(
        dest_type=dest_type,
        dest_team=dest_team,
        dest_iid=dest_iid,
        message=message,
    )

    return CompactCot(subtype=subtype, payload=chat)


# -- High-level Gateway Functions --


def compress_cot_xml(xml_data: str | bytes) -> bytes:
    """Compress CoT XML to compact binary format.

    This is the main gateway entry point for compressing CoT messages
    from ATAK for mesh transmission.

    Args:
        xml_data: CoT XML string or bytes from ATAK.

    Returns:
        Compact binary encoding ready for mesh transmission.

    Raises:
        ValueError: If XML cannot be parsed.
    """
    cot = parse_cot_xml(xml_data)
    return encode_compact_cot(cot)
