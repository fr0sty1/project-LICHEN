# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Meshtastic message translation."""

import pytest

from lichen.announce.coords import encode_coords
from lichen.interface.meshtastic.address import AddressMapper
from lichen.interface.meshtastic.translate import (
    PortNum,
    Position,
    Translator,
    User,
)


class TestPortNum:
    """Tests for PortNum enum."""

    def test_values(self) -> None:
        assert PortNum.TEXT_MESSAGE_APP == 1
        assert PortNum.POSITION_APP == 3
        assert PortNum.NODEINFO_APP == 4
        assert PortNum.TELEMETRY_APP == 67


class TestPosition:
    """Tests for Position protobuf encoding/decoding."""

    def test_empty_position(self) -> None:
        pos = Position()
        assert pos.latitude_i is None
        assert pos.longitude_i is None
        assert pos.latitude is None
        assert pos.longitude is None

    def test_coordinate_conversion(self) -> None:
        # Seattle: 47.6062, -122.3321
        pos = Position(latitude_i=476062000, longitude_i=-1223321000)
        assert pos.latitude is not None
        assert pos.longitude is not None
        assert abs(pos.latitude - 47.6062) < 1e-6
        assert abs(pos.longitude - (-122.3321)) < 1e-6

    def test_roundtrip(self) -> None:
        original = Position(
            latitude_i=476062000,
            longitude_i=-1223321000,
            altitude=100,
            time=1700000000,
        )
        data = original.to_bytes()
        decoded = Position.from_bytes(data)

        assert decoded.latitude_i == original.latitude_i
        assert decoded.longitude_i == original.longitude_i
        assert decoded.altitude == original.altitude
        assert decoded.time == original.time

    def test_partial_position(self) -> None:
        """Test encoding/decoding with only some fields set."""
        original = Position(latitude_i=123456789)
        data = original.to_bytes()
        decoded = Position.from_bytes(data)

        assert decoded.latitude_i == original.latitude_i
        assert decoded.longitude_i is None
        assert decoded.altitude is None

    def test_empty_bytes(self) -> None:
        """Empty bytes should produce empty position."""
        pos = Position.from_bytes(b"")
        assert pos.latitude_i is None


class TestUser:
    """Tests for User protobuf encoding/decoding."""

    def test_roundtrip(self) -> None:
        original = User(
            id="!deadbeef",
            long_name="Test Node",
            short_name="TEST",
            hw_model=255,
        )
        data = original.to_bytes()
        decoded = User.from_bytes(data)

        assert decoded.id == original.id
        assert decoded.long_name == original.long_name
        assert decoded.short_name == original.short_name
        assert decoded.hw_model == original.hw_model

    def test_empty_user(self) -> None:
        user = User()
        data = user.to_bytes()
        decoded = User.from_bytes(data)
        assert decoded.hw_model == 255  # Default is PRIVATE_HW

    def test_unicode_names(self) -> None:
        original = User(long_name="Node 🌐", short_name="N🌐")
        data = original.to_bytes()
        decoded = User.from_bytes(data)
        assert decoded.long_name == original.long_name
        assert decoded.short_name == original.short_name


class TestTranslatorText:
    """Tests for text message translation."""

    @pytest.fixture
    def translator(self) -> Translator:
        return Translator(mapper=AddressMapper())

    def test_text_passthrough(self, translator: Translator) -> None:
        """Text messages are passed through unchanged."""
        payload = b"Hello, world!"
        assert translator.text_to_coap_payload(payload) == payload

    def test_coap_to_text_passthrough(self, translator: Translator) -> None:
        payload = b"Reply message"
        assert translator.coap_to_text_payload(payload) == payload

    def test_utf8_preserved(self, translator: Translator) -> None:
        payload = "Hello 世界 🌍".encode()
        assert translator.text_to_coap_payload(payload) == payload


class TestTranslatorPosition:
    """Tests for position message translation."""

    @pytest.fixture
    def translator(self) -> Translator:
        return Translator(mapper=AddressMapper())

    def test_position_to_announce(self, translator: Translator) -> None:
        # Seattle coordinates
        pos = Position(
            latitude_i=476062000,
            longitude_i=-1223321000,
            altitude=100,
        )
        payload = pos.to_bytes()
        result = translator.position_to_announce_payload(payload)

        assert result == encode_coords(47.6062, -122.3321)

    def test_announce_to_position(self, translator: Translator) -> None:
        announce_data = encode_coords(47.6062, -122.3321)
        result = translator.announce_to_position_payload(announce_data)

        pos = Position.from_bytes(result)
        assert pos.latitude_i == 476062000
        assert pos.longitude_i == -1223321000
        assert pos.altitude is None

    def test_position_roundtrip(self, translator: Translator) -> None:
        """Position survives mesh→announce→mesh translation."""
        original = Position(
            latitude_i=476062000,
            longitude_i=-1223321000,
            altitude=100,
        )
        payload = original.to_bytes()

        # Mesh → announce → mesh
        announce = translator.position_to_announce_payload(payload)
        result = translator.announce_to_position_payload(announce)
        decoded = Position.from_bytes(result)

        assert decoded.latitude_i == original.latitude_i
        assert decoded.longitude_i == original.longitude_i
        assert decoded.altitude is None


class TestTranslatorNodeInfo:
    """Tests for nodeinfo message translation."""

    @pytest.fixture
    def translator(self) -> Translator:
        return Translator(mapper=AddressMapper())

    def test_iid_to_user(self, translator: Translator) -> None:
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])
        payload = translator.iid_to_user_payload(iid)

        user = User.from_bytes(payload)
        assert user.id == "!deadbeef"
        assert user.long_name == "01020304deadbeef"
        assert user.short_name == "BEEF"
        assert user.hw_model == 255

    def test_user_payload_to_names(self, translator: Translator) -> None:
        user = User(long_name="Test Node", short_name="TST")
        payload = user.to_bytes()

        long_name, short_name = translator.user_payload_to_names(payload)
        assert long_name == "Test Node"
        assert short_name == "TST"
