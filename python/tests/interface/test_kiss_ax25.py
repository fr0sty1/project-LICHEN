"""Tests for AX.25 minimal framing."""

import pytest

from lichen.interface.kiss.ax25 import (
    Ax25Error,
    ax25_decode,
    ax25_encode,
    bytes_to_callsign,
    callsign_to_bytes,
)


class TestCallsignToBytes:
    def test_simple_callsign(self):
        result = callsign_to_bytes("W1AW")
        assert len(result) == 7
        # W=0x57, shifted = 0xAE
        assert result[0] == ord("W") << 1

    def test_callsign_with_ssid(self):
        result = callsign_to_bytes("W1AW-5")
        ssid_byte = result[6]
        ssid = (ssid_byte >> 1) & 0x0F
        assert ssid == 5

    def test_short_callsign_padded(self):
        result = callsign_to_bytes("N1A")
        # Should be padded to 6 chars
        # Char 4, 5, 6 should be space (0x20 << 1 = 0x40)
        assert result[3] == 0x40  # space shifted
        assert result[4] == 0x40
        assert result[5] == 0x40

    def test_long_callsign_truncated(self):
        result = callsign_to_bytes("ABCDEFGHIJ-1")
        # Only first 6 chars kept
        call = bytes_to_callsign(result)
        assert call == "ABCDEF-1"

    def test_is_last_flag(self):
        not_last = callsign_to_bytes("W1AW", is_last=False)
        is_last = callsign_to_bytes("W1AW", is_last=True)
        # Bit 0 of SSID byte
        assert (not_last[6] & 0x01) == 0
        assert (is_last[6] & 0x01) == 1

    def test_ssid_clamped(self):
        result = callsign_to_bytes("W1AW-99")
        ssid = (result[6] >> 1) & 0x0F
        assert ssid == 15  # Clamped to max

    def test_invalid_ssid_becomes_zero(self):
        result = callsign_to_bytes("W1AW-abc")
        ssid = (result[6] >> 1) & 0x0F
        assert ssid == 0

    def test_lowercase_uppercased(self):
        result = callsign_to_bytes("w1aw-3")
        call = bytes_to_callsign(result)
        assert call == "W1AW-3"


class TestBytesToCallsign:
    def test_simple_decode(self):
        # Encode then decode
        encoded = callsign_to_bytes("N0CALL-7")
        decoded = bytes_to_callsign(encoded)
        assert decoded == "N0CALL-7"

    def test_no_ssid(self):
        encoded = callsign_to_bytes("W1AW-0")
        decoded = bytes_to_callsign(encoded)
        assert decoded == "W1AW"  # SSID 0 omitted

    def test_wrong_length_raises(self):
        with pytest.raises(Ax25Error, match="7 bytes"):
            bytes_to_callsign(b"short")

    def test_strips_padding(self):
        encoded = callsign_to_bytes("AB")
        decoded = bytes_to_callsign(encoded)
        assert decoded == "AB"


class TestAx25Encode:
    def test_basic_encode(self):
        frame = ax25_encode("W1AW-1", "CQ", b"Hello")
        assert len(frame) == 16 + 5  # header + payload

    def test_frame_structure(self):
        frame = ax25_encode("SRC-1", "DST-2", b"test")
        # First 7 bytes: destination
        dst = bytes_to_callsign(frame[0:7])
        assert dst == "DST-2"
        # Next 7 bytes: source
        src = bytes_to_callsign(frame[7:14])
        assert src == "SRC-1"
        # Control byte
        assert frame[14] == 0x03  # UI
        # PID
        assert frame[15] == 0xF0  # No L3
        # Payload
        assert frame[16:] == b"test"

    def test_empty_payload(self):
        frame = ax25_encode("A", "B", b"")
        assert len(frame) == 16


class TestAx25Decode:
    def test_basic_decode(self):
        frame = ax25_encode("SRC-5", "DST-0", b"Hello World")
        result = ax25_decode(frame)
        assert result.src == "SRC-5"
        assert result.dst == "DST"
        assert result.payload == b"Hello World"

    def test_too_short_raises(self):
        with pytest.raises(Ax25Error, match="too short"):
            ax25_decode(b"short")

    def test_non_ui_rejected(self):
        frame = ax25_encode("A", "B", b"x")
        # Corrupt control byte
        bad = frame[:14] + bytes([0x00]) + frame[15:]
        with pytest.raises(Ax25Error, match="unsupported control"):
            ax25_decode(bad)


class TestRoundtrip:
    def test_roundtrip(self):
        for src, dst, payload in [
            ("W1AW-5", "CQ-0", b"test"),
            ("LI3A7F-0", "LI9B2C-1", b"LICHEN message"),
            ("N0CALL", "BEACON", b""),
            ("A-15", "B-0", bytes(range(256))),
        ]:
            frame = ax25_encode(src, dst, payload)
            result = ax25_decode(frame)
            # Normalize SSIDs for comparison
            expected_src = src if "-" in src and not src.endswith("-0") else src.replace("-0", "")
            assert result.src == expected_src or result.src == src.split("-")[0]
            assert result.payload == payload


class TestLichenCallsigns:
    """Test LICHEN-style callsigns."""

    def test_lichen_prefix(self):
        frame = ax25_encode("LI3A7F-0", "LIFFFF-0", b"mesh")
        result = ax25_decode(frame)
        assert result.src == "LI3A7F"
        assert result.dst == "LIFFFF"

    def test_broadcast_cq(self):
        frame = ax25_encode("LI1234-0", "CQ", b"broadcast")
        result = ax25_decode(frame)
        assert result.dst == "CQ"
