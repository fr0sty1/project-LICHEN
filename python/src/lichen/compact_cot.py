# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Compact Cursor on Target (CoT) binary encoding.

Implements the compact CoT format defined in LICHEN spec Section 10.1.1.
This provides a minimal binary encoding of tactical messages for LoRa mesh
transport, reducing typical CoT XML from 400+ bytes to 17-20 bytes.

Wire Format:
    PLI (Position Location Information) encoding (17 bytes):
        subtype(1) + lat(4) + lon(4) + alt(2) + course(2) + speed(2) + team(1) + role(1)

    Chat encoding (variable length):
        subtype(1) + dest_type(1) + dest_id(0/1/8) + length(1) + UTF-8 text

All multi-byte integers are big-endian (network byte order).
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import IntEnum


class CotSubtype(IntEnum):
    """Compact CoT message subtype."""

    CHAT = 0x01  # b-t-f
    FRIENDLY_PLI = 0x02  # a-f-G-*
    HOSTILE_PLI = 0x03  # a-h-G-*
    NEUTRAL_PLI = 0x04  # a-n-G-*
    UNKNOWN_PLI = 0x05  # a-u-G-*
    MARKER = 0x10  # b-m-p-*
    ALERT = 0x20  # b-a-*


class DestType(IntEnum):
    """Chat destination type."""

    BROADCAST = 0x00
    TEAM = 0x01
    DIRECT = 0x02


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


# Team name to enum mapping (case-insensitive)
TEAM_BY_NAME: dict[str, Team] = {t.name.lower(): t for t in Team}


# PLI struct format: lat(i4) + lon(i4) + alt(i2) + course(u2) + speed(u2) + team(u1) + role(u1)
PLI_PAYLOAD_FORMAT = ">iihHHBB"  # Note: alt is signed, course/speed unsigned
PLI_PAYLOAD_SIZE = struct.calcsize(PLI_PAYLOAD_FORMAT)  # 16 bytes
PLI_TOTAL_SIZE = 1 + PLI_PAYLOAD_SIZE  # 17 bytes with subtype

# int16 range for altitude in decimeters (-3276.8m to +3276.7m)
INT16_MIN = -32768
INT16_MAX = 32767
UINT16_MAX = 65535


@dataclass(frozen=True)
class PliPayload:
    """Position Location Information payload.

    Attributes:
        lat_microdeg: Latitude in microdegrees (int32).
        lon_microdeg: Longitude in microdegrees (int32).
        alt_dm: Altitude in decimeters (int16).
        course_cdeg: Course in centidegrees (uint16, 0-35999).
        speed_cm_s: Speed in cm/s (uint16).
        team: Team identifier (uint8).
        role: Role identifier (uint8).
    """

    lat_microdeg: int
    lon_microdeg: int
    alt_dm: int
    course_cdeg: int
    speed_cm_s: int
    team: int
    role: int

    @classmethod
    def from_degrees(
        cls,
        lat: float,
        lon: float,
        alt_m: float = 0.0,
        course_deg: float = 0.0,
        speed_m_s: float = 0.0,
        team: int = Team.BLUE,
        role: int = 1,
    ) -> PliPayload:
        """Create PLI from human-readable units.

        Args:
            lat: Latitude in degrees (-90 to +90).
            lon: Longitude in degrees (-180 to +180).
            alt_m: Altitude in meters.
            course_deg: Course in degrees (0 to 359.99).
            speed_m_s: Speed in meters per second.
            team: Team identifier.
            role: Role identifier.
        """
        # Clamp altitude to int16 range (-3276.8m to +3276.7m)
        alt_dm = max(INT16_MIN, min(INT16_MAX, int(alt_m * 10)))
        # Clamp speed to uint16 range (0 to 655.35 m/s)
        speed_cm_s = min(UINT16_MAX, max(0, int(speed_m_s * 100)))

        return cls(
            lat_microdeg=int(lat * 1_000_000),
            lon_microdeg=int(lon * 1_000_000),
            alt_dm=alt_dm,
            course_cdeg=int(course_deg * 100),
            speed_cm_s=speed_cm_s,
            team=team,
            role=role,
        )

    def to_degrees(
        self,
    ) -> tuple[float, float, float, float, float]:
        """Convert to human-readable units.

        Returns:
            Tuple of (lat_deg, lon_deg, alt_m, course_deg, speed_m_s).
        """
        return (
            self.lat_microdeg / 1_000_000,
            self.lon_microdeg / 1_000_000,
            self.alt_dm / 10,
            self.course_cdeg / 100,
            self.speed_cm_s / 100,
        )


@dataclass(frozen=True)
class ChatDest:
    """Chat destination."""

    dest_type: DestType
    team: int | None = None
    iid: bytes | None = None

    @classmethod
    def broadcast(cls) -> ChatDest:
        """Create broadcast destination."""
        return cls(dest_type=DestType.BROADCAST)

    @classmethod
    def to_team(cls, team: int) -> ChatDest:
        """Create team destination."""
        return cls(dest_type=DestType.TEAM, team=team)

    @classmethod
    def direct(cls, iid: bytes) -> ChatDest:
        """Create direct message destination."""
        if len(iid) != 8:
            raise ValueError("IID must be exactly 8 bytes")
        return cls(dest_type=DestType.DIRECT, iid=iid)


@dataclass(frozen=True)
class ChatPayload:
    """Chat message payload.

    Attributes:
        dest: Destination (broadcast, team, or direct).
        message: UTF-8 message text (max 255 bytes).
    """

    dest: ChatDest
    message: bytes

    def __post_init__(self) -> None:
        if len(self.message) > 255:
            raise ValueError("Chat message cannot exceed 255 bytes")


# Union type for all compact CoT message types
CompactCot = (
    tuple[CotSubtype, PliPayload]
    | tuple[CotSubtype, ChatPayload]
    | tuple[CotSubtype, None]  # For Marker/Alert
)


class DecodeError(Exception):
    """Error decoding compact CoT message."""


class EncodeError(Exception):
    """Error encoding compact CoT message."""


def encode_pli(subtype: CotSubtype, pli: PliPayload) -> bytes:
    """Encode a PLI message.

    Args:
        subtype: PLI subtype (FRIENDLY_PLI, HOSTILE_PLI, NEUTRAL_PLI, UNKNOWN_PLI).
        pli: PLI payload data.

    Returns:
        Encoded bytes (17 bytes).
    """
    payload = struct.pack(
        PLI_PAYLOAD_FORMAT,
        pli.lat_microdeg,
        pli.lon_microdeg,
        pli.alt_dm,
        pli.course_cdeg,
        pli.speed_cm_s,
        pli.team,
        pli.role,
    )
    return bytes([subtype]) + payload


def decode_pli(data: bytes) -> tuple[CotSubtype, PliPayload]:
    """Decode a PLI message.

    Args:
        data: Raw bytes (at least 17 bytes).

    Returns:
        Tuple of (subtype, PliPayload).

    Raises:
        DecodeError: If data is too short or invalid.
    """
    if len(data) < PLI_TOTAL_SIZE:
        raise DecodeError(f"PLI requires {PLI_TOTAL_SIZE} bytes, got {len(data)}")

    subtype_byte = data[0]
    try:
        subtype = CotSubtype(subtype_byte)
    except ValueError as e:
        raise DecodeError(f"Unknown subtype: 0x{subtype_byte:02x}") from e

    if subtype not in (
        CotSubtype.FRIENDLY_PLI,
        CotSubtype.HOSTILE_PLI,
        CotSubtype.NEUTRAL_PLI,
        CotSubtype.UNKNOWN_PLI,
    ):
        raise DecodeError(f"Expected PLI subtype, got {subtype.name}")

    lat, lon, alt, course, speed, team, role = struct.unpack(
        PLI_PAYLOAD_FORMAT, data[1:PLI_TOTAL_SIZE]
    )

    return subtype, PliPayload(
        lat_microdeg=lat,
        lon_microdeg=lon,
        alt_dm=alt,
        course_cdeg=course,
        speed_cm_s=speed,
        team=team,
        role=role,
    )


def encode_chat(chat: ChatPayload) -> bytes:
    """Encode a chat message.

    Args:
        chat: Chat payload.

    Returns:
        Encoded bytes.
    """
    parts = [bytes([CotSubtype.CHAT, chat.dest.dest_type])]

    if chat.dest.dest_type == DestType.TEAM:
        parts.append(bytes([chat.dest.team or 0]))
    elif chat.dest.dest_type == DestType.DIRECT:
        parts.append(chat.dest.iid or bytes(8))

    parts.append(bytes([len(chat.message)]))
    parts.append(chat.message)

    return b"".join(parts)


def decode_chat(data: bytes) -> ChatPayload:
    """Decode a chat message.

    Args:
        data: Raw bytes (including subtype byte).

    Returns:
        ChatPayload.

    Raises:
        DecodeError: If data is invalid.
    """
    if len(data) < 3:
        raise DecodeError(f"Chat requires at least 3 bytes, got {len(data)}")

    if data[0] != CotSubtype.CHAT:
        raise DecodeError(f"Expected CHAT subtype (0x01), got 0x{data[0]:02x}")

    try:
        dest_type = DestType(data[1])
    except ValueError as e:
        raise DecodeError(f"Unknown destination type: 0x{data[1]:02x}") from e

    pos = 2
    if dest_type == DestType.BROADCAST:
        dest = ChatDest.broadcast()
    elif dest_type == DestType.TEAM:
        if len(data) < pos + 1:
            raise DecodeError("Chat team destination truncated")
        dest = ChatDest.to_team(data[pos])
        pos += 1
    elif dest_type == DestType.DIRECT:
        if len(data) < pos + 8:
            raise DecodeError("Chat direct destination truncated")
        dest = ChatDest.direct(bytes(data[pos : pos + 8]))
        pos += 8
    else:
        raise DecodeError(f"Unsupported destination type: {dest_type}")

    if len(data) < pos + 1:
        raise DecodeError("Chat message length byte missing")

    msg_len = data[pos]
    pos += 1

    if len(data) < pos + msg_len:
        raise DecodeError(
            f"Chat message truncated: expected {msg_len} bytes, got {len(data) - pos}"
        )

    message = bytes(data[pos : pos + msg_len])
    return ChatPayload(dest=dest, message=message)


def encode(cot: CompactCot) -> bytes:
    """Encode a compact CoT message.

    Args:
        cot: Tuple of (subtype, payload) where payload is PliPayload, ChatPayload, or None.

    Returns:
        Encoded bytes.
    """
    subtype, payload = cot

    if subtype == CotSubtype.CHAT:
        if not isinstance(payload, ChatPayload):
            raise EncodeError("CHAT subtype requires ChatPayload")
        return encode_chat(payload)

    if subtype in (
        CotSubtype.FRIENDLY_PLI,
        CotSubtype.HOSTILE_PLI,
        CotSubtype.NEUTRAL_PLI,
        CotSubtype.UNKNOWN_PLI,
    ):
        if not isinstance(payload, PliPayload):
            raise EncodeError(f"{subtype.name} requires PliPayload")
        return encode_pli(subtype, payload)

    if subtype in (CotSubtype.MARKER, CotSubtype.ALERT):
        return bytes([subtype])

    raise EncodeError(f"Unknown subtype: {subtype}")


def decode(data: bytes) -> CompactCot:
    """Decode a compact CoT message.

    Args:
        data: Raw bytes.

    Returns:
        Tuple of (subtype, payload).

    Raises:
        DecodeError: If data is invalid.
    """
    if not data:
        raise DecodeError("Empty data")

    subtype_byte = data[0]
    try:
        subtype = CotSubtype(subtype_byte)
    except ValueError as e:
        raise DecodeError(f"Unknown subtype: 0x{subtype_byte:02x}") from e

    if subtype == CotSubtype.CHAT:
        return (subtype, decode_chat(data))

    if subtype in (
        CotSubtype.FRIENDLY_PLI,
        CotSubtype.HOSTILE_PLI,
        CotSubtype.NEUTRAL_PLI,
        CotSubtype.UNKNOWN_PLI,
    ):
        _, pli = decode_pli(data)
        return (subtype, pli)

    if subtype == CotSubtype.MARKER:
        return (CotSubtype.MARKER, None)

    if subtype == CotSubtype.ALERT:
        return (CotSubtype.ALERT, None)

    raise DecodeError(f"Unknown subtype: 0x{subtype_byte:02x}")


# ============================================================================
# XML CoT Parsing (Gateway functionality)
# ============================================================================


def cot_type_to_subtype(cot_type: str) -> CotSubtype:
    """Map CoT event type string to compact subtype.

    CoT type format: "a-f-G-..." where:
        - First letter: a=atom, b=bits
        - Second letter: f=friend, h=hostile, n=neutral, u=unknown
        - Third letter: G=ground, A=air, S=sea, etc.

    Args:
        cot_type: CoT event type string (e.g., "a-f-G-U-C").

    Returns:
        Corresponding CotSubtype.

    Raises:
        ValueError: If type cannot be mapped.
    """
    if cot_type.startswith("b-t-f"):
        return CotSubtype.CHAT
    if cot_type.startswith("b-a"):
        return CotSubtype.ALERT
    if cot_type.startswith("b-m-p"):
        return CotSubtype.MARKER

    # Atom types (a-X-G-*) for ground positions
    parts = cot_type.split("-")
    if len(parts) >= 3 and parts[0] == "a" and parts[2] == "G":
        affiliation = parts[1]
        if affiliation == "f":
            return CotSubtype.FRIENDLY_PLI
        if affiliation == "h":
            return CotSubtype.HOSTILE_PLI
        if affiliation == "n":
            return CotSubtype.NEUTRAL_PLI
        if affiliation == "u":
            return CotSubtype.UNKNOWN_PLI

    raise ValueError(f"Cannot map CoT type to compact subtype: {cot_type}")


def subtype_to_cot_type(subtype: CotSubtype) -> str:
    """Map compact subtype to CoT event type string.

    Args:
        subtype: Compact CoT subtype.

    Returns:
        CoT event type string.
    """
    mapping = {
        CotSubtype.CHAT: "b-t-f",
        CotSubtype.FRIENDLY_PLI: "a-f-G-U-C",
        CotSubtype.HOSTILE_PLI: "a-h-G-U-C",
        CotSubtype.NEUTRAL_PLI: "a-n-G-U-C",
        CotSubtype.UNKNOWN_PLI: "a-u-G-U-C",
        CotSubtype.MARKER: "b-m-p-w-GOTO",
        CotSubtype.ALERT: "b-a-o-tbl",
    }
    return mapping[subtype]


def parse_xml_cot(xml_data: str | bytes) -> CompactCot:
    """Parse CoT XML and convert to compact binary format.

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
        Tuple of (subtype, payload) ready for encoding.

    Raises:
        ValueError: If XML cannot be parsed or required elements are missing.
    """
    if isinstance(xml_data, bytes):
        xml_data = xml_data.decode("utf-8")

    root = ET.fromstring(xml_data)
    if root.tag != "event":
        raise ValueError(f"Expected <event> root element, got <{root.tag}>")

    cot_type = root.get("type")
    if not cot_type:
        raise ValueError("Missing 'type' attribute on <event>")

    subtype = cot_type_to_subtype(cot_type)

    # Handle chat messages
    if subtype == CotSubtype.CHAT:
        return _parse_xml_chat(root)

    # Handle PLI
    if subtype in (
        CotSubtype.FRIENDLY_PLI,
        CotSubtype.HOSTILE_PLI,
        CotSubtype.NEUTRAL_PLI,
        CotSubtype.UNKNOWN_PLI,
    ):
        return _parse_xml_pli(root, subtype)

    # Marker and Alert don't have payloads defined yet
    return (subtype, None)


def _parse_xml_pli(root: ET.Element, subtype: CotSubtype) -> CompactCot:
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

    # hae = height above ellipsoid (altitude in meters)
    hae_str = point.get("hae")
    alt_m = float(hae_str) if hae_str else 0.0

    # Extract course/speed from <track> element
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
            if speed_str:
                speed_m_s = float(speed_str)

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
                # Role is just an identifier; map common roles
                role_val = _parse_role(role_str)

    pli = PliPayload.from_degrees(
        lat=lat,
        lon=lon,
        alt_m=alt_m,
        course_deg=course_deg,
        speed_m_s=speed_m_s,
        team=team_val,
        role=role_val,
    )

    return (subtype, pli)


def _parse_role(role_str: str) -> int:
    """Parse role string to role byte.

    Standard ATAK roles map to integer values.
    """
    role_map = {
        "team member": 1,
        "team lead": 2,
        "hq": 3,
        "sniper": 4,
        "medic": 5,
        "forward observer": 6,
        "rto": 7,
        "k9": 8,
    }
    return role_map.get(role_str.lower(), 1)


def _parse_xml_chat(root: ET.Element) -> CompactCot:
    """Parse chat message from XML event element."""
    detail = root.find("detail")
    if detail is None:
        raise ValueError("Missing <detail> element for chat")

    # Chat message is in <remarks> element
    remarks = detail.find("remarks")
    message = remarks.text.encode("utf-8") if remarks is not None and remarks.text else b""

    # For now, assume broadcast. Proper chat routing uses
    # <marti><dest callsign="..."/></marti> which we could parse later.
    dest = ChatDest.broadcast()

    # Check for team or direct destination in __chat element
    chat_elem = detail.find("__chat")
    if chat_elem is not None:
        chat_group = chat_elem.get("chatroom")
        if chat_group:
            # Check if it's a direct message (hex IID = 16 hex chars = 8 bytes)
            if len(chat_group) == 16:
                try:
                    iid = bytes.fromhex(chat_group)
                    dest = ChatDest.direct(iid)
                except ValueError:
                    pass  # Not valid hex, fall through to team lookup
            if dest.dest_type == DestType.BROADCAST:
                # Not a direct message, check for team destination
                # Handle both "Blue" and "Team Blue" formats (roundtrip)
                team_name = chat_group.lower()
                if team_name.startswith("team "):
                    team_name = team_name[5:]
                team = TEAM_BY_NAME.get(team_name)
                if team:
                    dest = ChatDest.to_team(team)

    return (CotSubtype.CHAT, ChatPayload(dest=dest, message=message))


def xml_to_compact(xml_data: str | bytes) -> bytes:
    """Convert CoT XML to compact binary format.

    This is the main gateway entry point for compressing CoT messages.

    Args:
        xml_data: CoT XML string or bytes.

    Returns:
        Compact binary encoding ready for mesh transmission.

    Raises:
        ValueError: If XML cannot be parsed.
        EncodeError: If encoding fails.
    """
    cot = parse_xml_cot(xml_data)
    return encode(cot)


def compact_to_xml(data: bytes, uid: str = "LICHEN-1") -> str:
    """Convert compact binary to CoT XML format.

    This is the gateway entry point for expanding compact messages for ATAK.

    Args:
        data: Compact binary data.
        uid: UID to use in the CoT event (default: "LICHEN-1").

    Returns:
        CoT XML string.

    Raises:
        DecodeError: If decoding fails.
    """
    subtype, payload = decode(data)

    cot_type = subtype_to_cot_type(subtype)

    # Build XML event
    event = ET.Element("event")
    event.set("type", cot_type)
    event.set("uid", uid)

    if isinstance(payload, PliPayload):
        lat, lon, alt_m, course_deg, speed_m_s = payload.to_degrees()

        # <point>
        point = ET.SubElement(event, "point")
        point.set("lat", f"{lat:.6f}")
        point.set("lon", f"{lon:.6f}")
        point.set("hae", f"{alt_m:.1f}")

        # <detail>
        detail = ET.SubElement(event, "detail")

        # <__group>
        group = ET.SubElement(detail, "__group")
        try:
            team_enum = Team(payload.team)
            group.set("name", team_enum.name.title())
        except ValueError:
            group.set("name", f"Team{payload.team}")
        group.set("role", _role_to_string(payload.role))

        # <track>
        track = ET.SubElement(detail, "track")
        track.set("course", f"{course_deg:.1f}")
        track.set("speed", f"{speed_m_s:.2f}")

    elif isinstance(payload, ChatPayload):
        # Add empty point (required by CoT schema)
        point = ET.SubElement(event, "point")
        point.set("lat", "0.0")
        point.set("lon", "0.0")
        point.set("hae", "0.0")

        detail = ET.SubElement(event, "detail")
        remarks = ET.SubElement(detail, "remarks")
        remarks.text = payload.message.decode("utf-8", errors="replace")

    else:
        # Marker/Alert - minimal structure
        point = ET.SubElement(event, "point")
        point.set("lat", "0.0")
        point.set("lon", "0.0")
        point.set("hae", "0.0")
        ET.SubElement(event, "detail")

    return ET.tostring(event, encoding="unicode")


def _role_to_string(role: int) -> str:
    """Convert role byte to string."""
    role_map = {
        1: "Team Member",
        2: "Team Lead",
        3: "HQ",
        4: "Sniper",
        5: "Medic",
        6: "Forward Observer",
        7: "RTO",
        8: "K9",
    }
    return role_map.get(role, "Team Member")
