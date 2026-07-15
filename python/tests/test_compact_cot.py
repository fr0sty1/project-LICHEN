# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for compact CoT encoding/decoding."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.compact_cot import (
    ChatDest,
    ChatPayload,
    CotSubtype,
    DecodeError,
    DestType,
    PliPayload,
    Team,
    compact_to_xml,
    cot_type_to_subtype,
    decode,
    decode_chat,
    decode_pli,
    encode,
    parse_xml_cot,
    xml_to_compact,
)

# Path to test vectors
VECTORS_PATH = Path(__file__).parent.parent.parent / "test" / "vectors" / "compact_cot.json"


def load_vectors() -> list[dict]:
    """Load test vectors from JSON file."""
    with open(VECTORS_PATH) as f:
        data = json.load(f)
    return data["vectors"]


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


# ============================================================================
# Test vectors from compact_cot.json
# ============================================================================


class TestPliVectors:
    """Test PLI encoding/decoding against test vectors."""

    @pytest.fixture
    def pli_vectors(self) -> list[dict]:
        """Get only PLI test vectors."""
        return [v for v in load_vectors() if v["name"].startswith("pli_")]

    def test_encode_decode_roundtrip(self, pli_vectors: list[dict]) -> None:
        """Verify all PLI vectors encode correctly."""
        for vec in pli_vectors:
            fields = vec["decoded_fields"]
            expected_hex = vec["binary_hex"]

            subtype = CotSubtype(fields["subtype"])
            pli = PliPayload(
                lat_microdeg=fields["latitude_microdegrees"],
                lon_microdeg=fields["longitude_microdegrees"],
                alt_dm=fields["altitude_decimeters"],
                course_cdeg=fields["course_centidegrees"],
                speed_cm_s=fields["speed_cm_s"],
                team=fields["team"],
                role=fields["role"],
            )

            # Encode
            encoded = encode((subtype, pli))
            assert bytes_to_hex(encoded) == expected_hex, f"Failed: {vec['name']}"

            # Decode
            decoded_subtype, decoded_pli = decode(hex_to_bytes(expected_hex))
            assert decoded_subtype == subtype, f"Subtype mismatch: {vec['name']}"
            assert decoded_pli == pli, f"Payload mismatch: {vec['name']}"


class TestChatVectors:
    """Test chat encoding/decoding against test vectors."""

    @pytest.fixture
    def chat_vectors(self) -> list[dict]:
        """Get only chat test vectors."""
        return [v for v in load_vectors() if v["name"].startswith("chat_")]

    def test_encode_decode_roundtrip(self, chat_vectors: list[dict]) -> None:
        """Verify all chat vectors encode correctly."""
        for vec in chat_vectors:
            fields = vec["decoded_fields"]
            expected_hex = vec["binary_hex"]

            dest_type = DestType(fields["dest_type"])
            if dest_type == DestType.BROADCAST:
                dest = ChatDest.broadcast()
            elif dest_type == DestType.TEAM:
                dest = ChatDest.to_team(fields["dest_team"])
            elif dest_type == DestType.DIRECT:
                iid = hex_to_bytes(fields["dest_iid_hex"])
                dest = ChatDest.direct(iid)
            else:
                pytest.fail(f"Unknown dest_type in vector: {vec['name']}")

            message = fields["message_utf8"].encode("utf-8")
            chat = ChatPayload(dest=dest, message=message)

            # Encode
            encoded = encode((CotSubtype.CHAT, chat))
            assert bytes_to_hex(encoded) == expected_hex, f"Failed: {vec['name']}"

            # Decode
            decoded_subtype, decoded_chat = decode(hex_to_bytes(expected_hex))
            assert decoded_subtype == CotSubtype.CHAT, f"Subtype mismatch: {vec['name']}"
            assert decoded_chat.dest == chat.dest, f"Dest mismatch: {vec['name']}"
            assert decoded_chat.message == chat.message, f"Message mismatch: {vec['name']}"


class TestMarkerAlertVectors:
    """Test marker and alert encoding/decoding."""

    def test_marker(self) -> None:
        """Test marker encoding."""
        encoded = encode((CotSubtype.MARKER, None))
        assert encoded == b"\x10"

        decoded_subtype, decoded_payload = decode(b"\x10")
        assert decoded_subtype == CotSubtype.MARKER
        assert decoded_payload is None

    def test_alert(self) -> None:
        """Test alert encoding."""
        encoded = encode((CotSubtype.ALERT, None))
        assert encoded == b"\x20"

        decoded_subtype, decoded_payload = decode(b"\x20")
        assert decoded_subtype == CotSubtype.ALERT
        assert decoded_payload is None


# ============================================================================
# Unit tests
# ============================================================================


class TestPliPayload:
    """Test PliPayload dataclass."""

    def test_from_degrees(self) -> None:
        """Test creating PLI from human-readable units."""
        pli = PliPayload.from_degrees(
            lat=47.606,
            lon=-122.332,
            alt_m=158.0,
            course_deg=270.0,
            speed_m_s=1.2,
            team=Team.BLUE,
            role=2,
        )
        assert pli.lat_microdeg == 47606000
        assert pli.lon_microdeg == -122332000
        assert pli.alt_dm == 1580
        assert pli.course_cdeg == 27000
        assert pli.speed_cm_s == 120
        assert pli.team == Team.BLUE
        assert pli.role == 2

    def test_to_degrees(self) -> None:
        """Test converting PLI to human-readable units."""
        pli = PliPayload(
            lat_microdeg=47606000,
            lon_microdeg=-122332000,
            alt_dm=1580,
            course_cdeg=27000,
            speed_cm_s=120,
            team=1,
            role=1,
        )
        lat, lon, alt, course, speed = pli.to_degrees()
        assert lat == pytest.approx(47.606, rel=1e-6)
        assert lon == pytest.approx(-122.332, rel=1e-6)
        assert alt == pytest.approx(158.0, rel=1e-6)
        assert course == pytest.approx(270.0, rel=1e-6)
        assert speed == pytest.approx(1.2, rel=1e-6)


class TestChatDest:
    """Test ChatDest dataclass."""

    def test_broadcast(self) -> None:
        """Test broadcast destination."""
        dest = ChatDest.broadcast()
        assert dest.dest_type == DestType.BROADCAST
        assert dest.team is None
        assert dest.iid is None

    def test_team(self) -> None:
        """Test team destination."""
        dest = ChatDest.to_team(Team.RED)
        assert dest.dest_type == DestType.TEAM
        assert dest.team == Team.RED
        assert dest.iid is None

    def test_direct(self) -> None:
        """Test direct destination."""
        iid = bytes(8)
        dest = ChatDest.direct(iid)
        assert dest.dest_type == DestType.DIRECT
        assert dest.iid == iid

    def test_direct_invalid_iid(self) -> None:
        """Test direct destination with invalid IID length."""
        with pytest.raises(ValueError, match="exactly 8 bytes"):
            ChatDest.direct(bytes(7))


class TestChatPayload:
    """Test ChatPayload dataclass."""

    def test_message_too_long(self) -> None:
        """Test that messages over 255 bytes are rejected."""
        with pytest.raises(ValueError, match="cannot exceed 255 bytes"):
            ChatPayload(dest=ChatDest.broadcast(), message=bytes(256))


class TestDecodeErrors:
    """Test error handling during decoding."""

    def test_empty_data(self) -> None:
        """Test decoding empty data."""
        with pytest.raises(DecodeError, match="Empty data"):
            decode(b"")

    def test_unknown_subtype(self) -> None:
        """Test decoding unknown subtype."""
        with pytest.raises(DecodeError, match="Unknown subtype"):
            decode(b"\xff")

    def test_pli_too_short(self) -> None:
        """Test decoding truncated PLI."""
        with pytest.raises(DecodeError, match="requires 17 bytes"):
            decode_pli(b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_pli_latitude_out_of_range(self) -> None:
        """Test decoding PLI with latitude outside [-90, 90] degrees."""
        import struct

        # Build a 17-byte PLI with lat=100_000_000 (out of range)
        data = (
            b"\x02"  # subtype: friendly ground
            + struct.pack(">i", 100_000_000)  # lat: out of range
            + struct.pack(">i", 0)  # lon: valid
            + struct.pack(">h", 0)  # alt
            + struct.pack(">H", 0)  # course
            + struct.pack(">H", 0)  # speed
            + b"\x00\x00"  # team, role
        )
        with pytest.raises(DecodeError, match="Latitude .* out of range"):
            decode_pli(data)

    def test_pli_longitude_out_of_range(self) -> None:
        """Test decoding PLI with longitude outside [-180, 180] degrees."""
        import struct

        # Build a 17-byte PLI with lon=200_000_000 (out of range)
        data = (
            b"\x02"  # subtype: friendly ground
            + struct.pack(">i", 0)  # lat: valid
            + struct.pack(">i", 200_000_000)  # lon: out of range
            + struct.pack(">h", 0)  # alt
            + struct.pack(">H", 0)  # course
            + struct.pack(">H", 0)  # speed
            + b"\x00\x00"  # team, role
        )
        with pytest.raises(DecodeError, match="Longitude .* out of range"):
            decode_pli(data)

    def test_chat_too_short(self) -> None:
        """Test decoding truncated chat."""
        with pytest.raises(DecodeError, match="requires at least 3 bytes"):
            decode_chat(b"\x01\x00")

    def test_chat_message_truncated(self) -> None:
        """Test decoding chat with truncated message."""
        # Says 10 bytes of message but only has 5
        with pytest.raises(DecodeError, match="truncated"):
            decode_chat(b"\x01\x00\x0aHello")


# ============================================================================
# XML parsing tests
# ============================================================================


class TestXmlParsing:
    """Test XML CoT parsing."""

    def test_parse_friendly_pli(self) -> None:
        """Test parsing friendly ground PLI from XML."""
        xml = """<event type="a-f-G-U-C" uid="ALPHA-1">
          <point lat="47.606" lon="-122.332" hae="158"/>
          <detail>
            <__group name="Blue" role="Team Lead"/>
            <track course="270" speed="1.2"/>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.FRIENDLY_PLI
        assert isinstance(payload, PliPayload)
        assert payload.lat_microdeg == 47606000
        assert payload.lon_microdeg == -122332000
        assert payload.alt_dm == 1580
        assert payload.course_cdeg == 27000
        assert payload.speed_cm_s == 120
        assert payload.team == Team.BLUE
        assert payload.role == 2  # Team Lead

    def test_parse_hostile_pli(self) -> None:
        """Test parsing hostile ground PLI from XML."""
        xml = """<event type="a-h-G-U-C" uid="HOSTILE-1">
          <point lat="35.6762" lon="139.6503" hae="40"/>
          <detail>
            <__group name="Red" role="Team Member"/>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.HOSTILE_PLI
        assert isinstance(payload, PliPayload)
        assert payload.team == Team.RED

    def test_parse_chat_broadcast(self) -> None:
        """Test parsing broadcast chat from XML."""
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Hello world</remarks>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.CHAT
        assert isinstance(payload, ChatPayload)
        assert payload.message == b"Hello world"
        assert payload.dest.dest_type == DestType.BROADCAST

    def test_parse_chat_direct(self) -> None:
        """Test parsing direct message chat from XML.

        Direct messages use a 16-char hex IID as the chatroom.
        """
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Private message</remarks>
            <__chat chatroom="aabbccdd00112233"/>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.CHAT
        assert isinstance(payload, ChatPayload)
        assert payload.message == b"Private message"
        assert payload.dest.dest_type == DestType.DIRECT
        assert payload.dest.iid == bytes.fromhex("aabbccdd00112233")

    def test_parse_chat_team(self) -> None:
        """Test parsing team chat from XML."""
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Team message</remarks>
            <__chat chatroom="Blue"/>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.CHAT
        assert isinstance(payload, ChatPayload)
        assert payload.message == b"Team message"
        assert payload.dest.dest_type == DestType.TEAM
        assert payload.dest.team == Team.BLUE

    def test_parse_missing_point(self) -> None:
        """Test error when point element is missing."""
        xml = """<event type="a-f-G-U-C" uid="ALPHA-1">
          <detail/>
        </event>"""

        with pytest.raises(ValueError, match="Missing <point>"):
            parse_xml_cot(xml)

    def test_parse_missing_type(self) -> None:
        """Test error when type attribute is missing."""
        xml = """<event uid="ALPHA-1">
          <point lat="0" lon="0" hae="0"/>
        </event>"""

        with pytest.raises(ValueError, match="Missing 'type'"):
            parse_xml_cot(xml)


class TestCotTypeMapping:
    """Test CoT type to subtype mapping."""

    def test_friendly_ground(self) -> None:
        """Test friendly ground types."""
        assert cot_type_to_subtype("a-f-G") == CotSubtype.FRIENDLY_PLI
        assert cot_type_to_subtype("a-f-G-U") == CotSubtype.FRIENDLY_PLI
        assert cot_type_to_subtype("a-f-G-U-C") == CotSubtype.FRIENDLY_PLI

    def test_hostile_ground(self) -> None:
        """Test hostile ground types."""
        assert cot_type_to_subtype("a-h-G") == CotSubtype.HOSTILE_PLI
        assert cot_type_to_subtype("a-h-G-E-V") == CotSubtype.HOSTILE_PLI

    def test_neutral_ground(self) -> None:
        """Test neutral ground types."""
        assert cot_type_to_subtype("a-n-G") == CotSubtype.NEUTRAL_PLI

    def test_unknown_ground(self) -> None:
        """Test unknown ground types."""
        assert cot_type_to_subtype("a-u-G") == CotSubtype.UNKNOWN_PLI

    def test_chat(self) -> None:
        """Test chat type."""
        assert cot_type_to_subtype("b-t-f") == CotSubtype.CHAT

    def test_alert(self) -> None:
        """Test alert type."""
        assert cot_type_to_subtype("b-a") == CotSubtype.ALERT
        assert cot_type_to_subtype("b-a-o-tbl") == CotSubtype.ALERT

    def test_marker(self) -> None:
        """Test marker type."""
        assert cot_type_to_subtype("b-m-p-w") == CotSubtype.MARKER

    def test_unknown_type(self) -> None:
        """Test unknown type raises error."""
        with pytest.raises(ValueError, match="Cannot map"):
            cot_type_to_subtype("x-y-z")


class TestXmlRoundtrip:
    """Test XML to compact and back."""

    def test_pli_roundtrip(self) -> None:
        """Test PLI survives XML -> compact -> XML roundtrip."""
        original_xml = """<event type="a-f-G-U-C" uid="TEST-1">
          <point lat="51.5074" lon="-0.1278" hae="11"/>
          <detail>
            <__group name="Green" role="Medic"/>
            <track course="45" speed="1.5"/>
          </detail>
        </event>"""

        # Convert to compact
        compact = xml_to_compact(original_xml)

        # Should be 17 bytes for PLI
        assert len(compact) == 17
        assert compact[0] == CotSubtype.FRIENDLY_PLI

        # Convert back to XML
        result_xml = compact_to_xml(compact, uid="TEST-1")

        # Parse both and compare values
        _, orig_pli = parse_xml_cot(original_xml)
        _, result_pli = parse_xml_cot(result_xml)

        assert orig_pli == result_pli

    def test_chat_roundtrip(self) -> None:
        """Test chat survives XML -> compact -> XML roundtrip."""
        original_xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Test message</remarks>
          </detail>
        </event>"""

        compact = xml_to_compact(original_xml)
        result_xml = compact_to_xml(compact)

        _, orig_chat = parse_xml_cot(original_xml)
        _, result_chat = parse_xml_cot(result_xml)

        assert orig_chat.message == result_chat.message


class TestXmlToCompactIntegration:
    """Integration tests for gateway XML compression."""

    def test_typical_atak_pli(self) -> None:
        """Test compressing typical ATAK PLI message."""
        # This is a realistic ATAK PLI message
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

        compact = xml_to_compact(xml)

        # Should produce 17-byte PLI
        assert len(compact) == 17

        # Verify contents
        subtype, pli = decode(compact)
        assert subtype == CotSubtype.FRIENDLY_PLI
        assert isinstance(pli, PliPayload)

        lat, lon, alt, course, speed = pli.to_degrees()
        assert lat == pytest.approx(47.606209, rel=1e-5)
        assert lon == pytest.approx(-122.332071, rel=1e-5)
        assert alt == pytest.approx(158.5, rel=0.1)
        assert course == pytest.approx(270.5, rel=0.1)
        assert speed == pytest.approx(1.23, rel=0.01)
        assert pli.team == Team.BLUE

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

        compact = xml_to_compact(xml)

        xml_size = len(xml.encode("utf-8"))
        compact_size = len(compact)

        # Should achieve ~20x compression
        ratio = xml_size / compact_size
        assert ratio > 15, f"Compression ratio {ratio:.1f}x is too low"
