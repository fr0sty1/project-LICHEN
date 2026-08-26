# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for compact CoT encoding/decoding."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.compact_cot import (
    ChatDest,
    ChatPayload,
    CotSubtype,
    DecodeError,
    DestType,
    EncodeError,
    PliPayload,
    Team,
    compact_to_xml,
    cot_type_to_subtype,
    decode,
    decode_chat,
    decode_pli,
    encode,
    encode_pli,
    parse_xml_cot,
    xml_to_compact,
)

# Path to test vectors
VECTORS_PATH = Path(__file__).parent.parent.parent / "test" / "vectors" / "compact_cot.json"
SCHEMA_PATH = VECTORS_PATH.with_name("schema.json")
JsonObject = dict[str, Any]

PLI_POSITIVE_VECTOR_NAMES = {
    "pli_friendly_ground_origin",
    "pli_hostile_ground_negative_coords",
    "pli_neutral_ground_london",
    "pli_unknown_ground_tokyo",
    "pli_friendly_max_positive_coords",
    "pli_friendly_max_negative_coords",
    "pli_friendly_zero_altitude",
    "pli_friendly_max_speed",
}
PLI_INVALID_VECTOR_NAMES = {
    "pli_invalid_truncated",
    "pli_invalid_trailing_byte",
    "pli_invalid_latitude",
    "pli_invalid_latitude_below_minimum",
    "pli_invalid_longitude",
    "pli_invalid_longitude_below_minimum",
    "pli_invalid_course",
    "pli_invalid_unknown_subtype",
    "pli_invalid_non_pli_subtype",
}
CHAT_POSITIVE_VECTOR_NAMES = {
    "chat_broadcast_hello",
    "chat_team_blue_move",
    "chat_team_red_hold",
    "chat_direct_ack",
    "chat_broadcast_empty",
    "chat_team_yellow",
    "chat_broadcast_utf8",
    "chat_broadcast_max_message",
    "chat_direct_high_native_address",
}
CHAT_INVALID_VECTOR_NAMES = {
    "chat_invalid_dest_type",
    "chat_invalid_team_zero",
    "chat_invalid_team_above_range",
    "chat_invalid_direct_truncated",
    "chat_invalid_message_truncated",
    "chat_invalid_trailing_byte",
    "chat_invalid_utf8",
}


def load_vectors() -> list[JsonObject]:
    """Load test vectors from JSON file."""
    with open(VECTORS_PATH) as f:
        data: object = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("vectors"), list):
        raise ValueError("compact CoT vectors must contain a vectors array")
    return cast(list[JsonObject], data["vectors"])


def xml_vector_input(fields: JsonObject) -> str | bytes:
    """Build the exact XML input represented by a canonical vector."""
    if "xml_input" in fields:
        return cast(str, fields["xml_input"])
    return bytes.fromhex(cast(str, fields["xml_input_utf8_hex"]))


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def test_compact_cot_vector_document_matches_schema() -> None:
    """Keep the canonical Compact CoT document valid against the shared schema."""
    schema = json.loads(SCHEMA_PATH.read_text())
    document = json.loads(VECTORS_PATH.read_text())
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


def pli_from_degrees_with_override(field: str, value: float) -> PliPayload:
    """Construct a human-unit PLI with one field overridden for validation tests."""
    fields = {
        "lat": 0.0,
        "lon": 0.0,
        "alt_m": 0.0,
        "course_deg": 0.0,
        "speed_m_s": 0.0,
    }
    if field not in fields:
        raise ValueError(f"unknown PLI human-unit field: {field}")
    fields[field] = value
    return PliPayload.from_degrees(
        lat=fields["lat"],
        lon=fields["lon"],
        alt_m=fields["alt_m"],
        course_deg=fields["course_deg"],
        speed_m_s=fields["speed_m_s"],
    )


# ============================================================================
# Test vectors from compact_cot.json
# ============================================================================


class TestPliVectors:
    """Test PLI encoding/decoding against test vectors."""

    @pytest.fixture
    def pli_vectors(self) -> list[JsonObject]:
        """Get only PLI test vectors."""
        return [
            v
            for v in load_vectors()
            if v["name"].startswith("pli_") and "expect_error" not in v["decoded_fields"]
        ]

    @pytest.fixture
    def invalid_pli_vectors(self) -> list[JsonObject]:
        """Get malformed PLI wire vectors."""
        return [
            v
            for v in load_vectors()
            if v["name"].startswith("pli_") and "expect_error" in v["decoded_fields"]
        ]

    def test_encode_decode_roundtrip(self, pli_vectors: list[JsonObject]) -> None:
        """Verify all PLI vectors encode correctly."""
        assert {str(vec["name"]) for vec in pli_vectors} == PLI_POSITIVE_VECTOR_NAMES
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

    def test_malformed_vectors_rejected(self, invalid_pli_vectors: list[JsonObject]) -> None:
        """Reject every canonical negative PLI vector with its expected error category."""
        assert {str(vec["name"]) for vec in invalid_pli_vectors} == PLI_INVALID_VECTOR_NAMES
        for vec in invalid_pli_vectors:
            expected_error = vec["decoded_fields"]["expect_error"]
            with pytest.raises(DecodeError, match=expected_error):
                decode_pli(hex_to_bytes(vec["binary_hex"]))


class TestChatVectors:
    """Test chat encoding/decoding against test vectors."""

    @pytest.fixture
    def chat_vectors(self) -> list[JsonObject]:
        """Get only chat test vectors."""
        return [
            v
            for v in load_vectors()
            if v["name"].startswith("chat_") and "expect_error" not in v["decoded_fields"]
        ]

    @pytest.fixture
    def invalid_chat_vectors(self) -> list[JsonObject]:
        """Get malformed chat destination/wire vectors."""
        return [
            v
            for v in load_vectors()
            if v["name"].startswith("chat_") and "expect_error" in v["decoded_fields"]
        ]

    def test_encode_decode_roundtrip(self, chat_vectors: list[JsonObject]) -> None:
        """Verify all chat vectors encode correctly."""
        assert {str(vec["name"]) for vec in chat_vectors} == CHAT_POSITIVE_VECTOR_NAMES
        for vec in chat_vectors:
            fields = vec["decoded_fields"]
            expected_hex = vec["binary_hex"]

            dest_type = DestType(fields["dest_type"])
            if dest_type == DestType.BROADCAST:
                dest = ChatDest.broadcast()
            elif dest_type == DestType.TEAM:
                dest = ChatDest.to_team(fields["dest_team"])
            elif dest_type == DestType.DIRECT:
                address = hex_to_bytes(fields["dest_address_hex"])
                dest = ChatDest.direct(address)
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
            assert isinstance(decoded_chat, ChatPayload)
            assert decoded_chat.dest == chat.dest, f"Dest mismatch: {vec['name']}"
            assert decoded_chat.message == chat.message, f"Message mismatch: {vec['name']}"

    def test_malformed_vectors_rejected(self, invalid_chat_vectors: list[JsonObject]) -> None:
        """Reject all canonical invalid destination and length encodings."""
        assert {str(vec["name"]) for vec in invalid_chat_vectors} == CHAT_INVALID_VECTOR_NAMES
        for vec in invalid_chat_vectors:
            with pytest.raises(DecodeError, match=vec["decoded_fields"]["expect_error"]):
                decode_chat(hex_to_bytes(vec["binary_hex"]))


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

    @pytest.mark.parametrize(
        ("field", "value", "error"),
        [
            ("lat_microdeg", -90_000_001, "Latitude"),
            ("lat_microdeg", 90_000_001, "Latitude"),
            ("lon_microdeg", -180_000_001, "Longitude"),
            ("lon_microdeg", 180_000_001, "Longitude"),
            ("alt_dm", -32_769, "Altitude"),
            ("alt_dm", 32_768, "Altitude"),
            ("course_cdeg", -1, "Course"),
            ("course_cdeg", 36_000, "Course"),
            ("speed_cm_s", -1, "Speed"),
            ("speed_cm_s", 65_536, "Speed"),
            ("team", -1, "Team"),
            ("team", 256, "Team"),
            ("role", -1, "Role"),
            ("role", 256, "Role"),
        ],
    )
    def test_integer_field_bounds(self, field: str, value: int, error: str) -> None:
        """Direct payload construction rejects every out-of-range wire field."""
        fields = {
            "lat_microdeg": 0,
            "lon_microdeg": 0,
            "alt_dm": 0,
            "course_cdeg": 0,
            "speed_cm_s": 0,
            "team": 1,
            "role": 1,
        }
        fields[field] = value
        with pytest.raises(ValueError, match=error):
            PliPayload(**fields)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("lat", float("nan")),
            ("lat", float("inf")),
            ("lon", float("-inf")),
            ("alt_m", float("nan")),
            ("course_deg", float("inf")),
            ("speed_m_s", float("nan")),
        ],
    )
    def test_from_degrees_rejects_non_finite(self, field: str, value: float) -> None:
        """Human-unit conversion rejects NaN and infinities before quantization."""
        with pytest.raises(ValueError, match="must be finite"):
            pli_from_degrees_with_override(field, value)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("lat", 90.000001),
            ("lon", -180.000001),
            ("alt_m", 3276.8),
            ("course_deg", 360.0),
            ("speed_m_s", -0.01),
            ("speed_m_s", 655.36),
        ],
    )
    def test_from_degrees_rejects_out_of_range(self, field: str, value: float) -> None:
        """Human-unit conversion rejects values that cannot be represented canonically."""
        with pytest.raises(ValueError, match="out of range"):
            pli_from_degrees_with_override(field, value)

    def test_encode_pli_rejects_non_pli_subtype(self) -> None:
        """The PLI encoder never serializes a payload under another subtype."""
        pli = PliPayload(0, 0, 0, 0, 0, Team.BLUE, 1)
        with pytest.raises(EncodeError, match="Expected PLI subtype"):
            encode_pli(CotSubtype.CHAT, pli)

    def test_from_degrees_accepts_exact_bounds(self) -> None:
        """Every human-unit boundary converts to its exact fixed-point endpoint."""
        pli = PliPayload.from_degrees(
            lat=-90.0,
            lon=180.0,
            alt_m=-3276.8,
            course_deg=359.99,
            speed_m_s=655.35,
            team=255,
            role=255,
        )
        assert pli == PliPayload(-90_000_000, 180_000_000, -32_768, 35_999, 65_535, 255, 255)


class TestChatDest:
    """Test ChatDest dataclass."""

    def test_broadcast(self) -> None:
        """Test broadcast destination."""
        dest = ChatDest.broadcast()
        assert dest.dest_type == DestType.BROADCAST
        assert dest.team is None
        assert dest.address is None

    def test_team(self) -> None:
        """Test team destination."""
        dest = ChatDest.to_team(Team.RED)
        assert dest.dest_type == DestType.TEAM
        assert dest.team == Team.RED
        assert dest.address is None

    def test_direct(self) -> None:
        """Test direct destination."""
        address = bytes(16)
        dest = ChatDest.direct(address)
        assert dest.dest_type == DestType.DIRECT
        assert dest.address == address

    def test_direct_invalid_address(self) -> None:
        """Test direct destination with invalid IPv6 address length."""
        with pytest.raises(ValueError, match="exactly 16 address bytes"):
            ChatDest.direct(bytes(15))

    @pytest.mark.parametrize(
        ("dest_type", "team", "address"),
        [
            (DestType.BROADCAST, Team.BLUE, None),
            (DestType.BROADCAST, None, bytes(16)),
            (DestType.TEAM, None, None),
            (DestType.TEAM, Team.BLUE, bytes(16)),
            (DestType.TEAM, 0, None),
            (DestType.TEAM, 11, None),
            (DestType.TEAM, True, None),
            (DestType.DIRECT, Team.BLUE, bytes(16)),
            (DestType.DIRECT, None, None),
        ],
    )
    def test_rejects_inconsistent_fields(
        self, dest_type: DestType, team: int | None, address: bytes | None
    ) -> None:
        """Destination payload must agree with its discriminator."""
        with pytest.raises(ValueError):
            ChatDest(dest_type=dest_type, team=team, address=address)


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

    def test_pli_trailing_data(self) -> None:
        """PLI decoding requires the canonical exact length."""
        valid = bytes.fromhex("0200000000000000000000000000000101")
        with pytest.raises(DecodeError, match="requires 17 bytes exactly"):
            decode_pli(valid + b"\x00")

    def test_pli_wrong_known_subtype(self) -> None:
        """A known non-PLI subtype cannot be decoded through the PLI entry point."""
        with pytest.raises(DecodeError, match="Expected PLI subtype"):
            decode_pli(b"\x01" + bytes(16))

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

        Direct messages use a 32-character native IPv6 address as the chatroom.
        """
        xml = """<event type="b-t-f" uid="CHAT-1">
          <point lat="0" lon="0" hae="0"/>
          <detail>
            <remarks>Private message</remarks>
            <__chat chatroom="0200000000000000aabbccdd00112233"/>
          </detail>
        </event>"""

        subtype, payload = parse_xml_cot(xml)
        assert subtype == CotSubtype.CHAT
        assert isinstance(payload, ChatPayload)
        assert payload.message == b"Private message"
        assert payload.dest.dest_type == DestType.DIRECT
        assert payload.dest.address == bytes.fromhex("0200000000000000aabbccdd00112233")

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

        assert isinstance(orig_chat, ChatPayload)
        assert isinstance(result_chat, ChatPayload)
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


class TestCanonicalXmlVectors:
    """Exercise canonical XML vectors through the production XML bridge."""

    def test_positive_vectors_round_trip_byte_exact(self) -> None:
        count = 0
        for vector in load_vectors():
            name = cast(str, vector["name"])
            fields = cast(JsonObject, vector["decoded_fields"])
            if not name.startswith("xml_") or "xml_expect_error" in fields:
                continue

            expected = bytes.fromhex(cast(str, vector["binary_hex"]))
            assert xml_to_compact(xml_vector_input(fields)) == expected, name

            canonical = compact_to_xml(expected, uid=cast(str, fields["xml_uid"]))
            assert canonical == fields["canonical_core_xml"], name
            assert xml_to_compact(canonical) == expected, name
            count += 1

        assert count == 4

    def test_invalid_vectors_are_rejected(self) -> None:
        count = 0
        for vector in load_vectors():
            name = cast(str, vector["name"])
            fields = cast(JsonObject, vector["decoded_fields"])
            if not name.startswith("xml_") or "xml_expect_error" not in fields:
                continue

            with pytest.raises(
                (ValueError, UnicodeDecodeError, ET.ParseError),
                match=cast(str, fields["xml_expect_error"]),
            ):
                xml_to_compact(xml_vector_input(fields))
            count += 1

        assert count == 8
