"""Tests for KISS protocol framing."""

import pytest

from lichen.interface.kiss import (
    FEND,
    FESC,
    TFEND,
    TFESC,
    KissCommand,
    KissError,
    KissReader,
    kiss_decode,
    kiss_encode,
    kiss_escape,
    kiss_unescape,
)


class TestConstants:
    def test_fend_value(self):
        assert FEND == 0xC0

    def test_fesc_value(self):
        assert FESC == 0xDB

    def test_tfend_value(self):
        assert TFEND == 0xDC

    def test_tfesc_value(self):
        assert TFESC == 0xDD


class TestKissCommand:
    def test_data_command(self):
        assert KissCommand.DATA == 0x00

    def test_txdelay_command(self):
        assert KissCommand.TXDELAY == 0x01

    def test_return_command(self):
        assert KissCommand.RETURN == 0x0F


class TestKissEscape:
    def test_no_special_bytes(self):
        data = b"hello world"
        assert kiss_escape(data) == data

    def test_escape_fend(self):
        data = bytes([0xC0])
        assert kiss_escape(data) == bytes([0xDB, 0xDC])

    def test_escape_fesc(self):
        data = bytes([0xDB])
        assert kiss_escape(data) == bytes([0xDB, 0xDD])

    def test_escape_multiple(self):
        # [0xC0, 0x41, 0xDB] -> [0xDB, 0xDC, 0x41, 0xDB, 0xDD]
        data = bytes([0xC0, 0x41, 0xDB])
        expected = bytes([0xDB, 0xDC, 0x41, 0xDB, 0xDD])
        assert kiss_escape(data) == expected

    def test_escape_empty(self):
        assert kiss_escape(b"") == b""

    def test_escape_all_fend(self):
        data = bytes([0xC0, 0xC0, 0xC0])
        expected = bytes([0xDB, 0xDC, 0xDB, 0xDC, 0xDB, 0xDC])
        assert kiss_escape(data) == expected


class TestKissUnescape:
    def test_no_escapes(self):
        data = b"hello world"
        assert kiss_unescape(data) == data

    def test_unescape_fend(self):
        data = bytes([0xDB, 0xDC])
        assert kiss_unescape(data) == bytes([0xC0])

    def test_unescape_fesc(self):
        data = bytes([0xDB, 0xDD])
        assert kiss_unescape(data) == bytes([0xDB])

    def test_unescape_multiple(self):
        data = bytes([0xDB, 0xDC, 0x41, 0xDB, 0xDD])
        expected = bytes([0xC0, 0x41, 0xDB])
        assert kiss_unescape(data) == expected

    def test_unescape_empty(self):
        assert kiss_unescape(b"") == b""

    def test_truncated_escape_raises(self):
        data = bytes([0x41, 0xDB])  # FESC at end with no following byte
        with pytest.raises(KissError, match="truncated"):
            kiss_unescape(data)

    def test_invalid_escape_raises(self):
        data = bytes([0xDB, 0x00])  # FESC followed by invalid byte
        with pytest.raises(KissError, match="invalid escape"):
            kiss_unescape(data)


class TestRoundtrip:
    def test_escape_unescape_roundtrip(self):
        """Escape then unescape should return original."""
        for data in [
            b"",
            b"hello",
            bytes([0xC0]),
            bytes([0xDB]),
            bytes([0xC0, 0xDB, 0xC0]),
            bytes(range(256)),
        ]:
            assert kiss_unescape(kiss_escape(data)) == data


class TestKissEncode:
    def test_simple_data_frame(self):
        frame = kiss_encode(0, KissCommand.DATA, b"test")
        assert frame[0] == FEND
        assert frame[1] == 0x00  # port 0, cmd 0
        assert frame[-1] == FEND
        assert b"test" in frame

    def test_port_in_command_byte(self):
        frame = kiss_encode(5, KissCommand.DATA, b"x")
        assert frame[1] == 0x50  # port 5 << 4 | cmd 0

    def test_command_in_byte(self):
        frame = kiss_encode(0, KissCommand.TXDELAY, bytes([50]))
        assert frame[1] == 0x01  # port 0 | cmd 1

    def test_escaping_in_encode(self):
        frame = kiss_encode(0, 0, bytes([0xC0, 0xDB]))
        # Data should be escaped
        assert bytes([0xDB, 0xDC, 0xDB, 0xDD]) in frame

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError, match="port"):
            kiss_encode(16, 0, b"")

    def test_invalid_command_raises(self):
        with pytest.raises(ValueError, match="command"):
            kiss_encode(0, 16, b"")

    def test_empty_data(self):
        frame = kiss_encode(0, 0, b"")
        assert frame == bytes([FEND, 0x00, FEND])


class TestKissDecode:
    def test_simple_frame(self):
        frame = bytes([FEND, 0x00, 0x41, 0x42, FEND])
        result = kiss_decode(frame)
        assert result.port == 0
        assert result.command == 0
        assert result.data == b"AB"

    def test_decode_port(self):
        frame = bytes([FEND, 0x70, 0x41, FEND])  # port 7
        result = kiss_decode(frame)
        assert result.port == 7
        assert result.command == 0

    def test_decode_command(self):
        frame = bytes([FEND, 0x01, 0x32, FEND])  # TXDELAY = 50
        result = kiss_decode(frame)
        assert result.port == 0
        assert result.command == KissCommand.TXDELAY
        assert result.data == bytes([0x32])

    def test_decode_with_escapes(self):
        # Escaped data: 0xDB 0xDC -> 0xC0
        frame = bytes([FEND, 0x00, 0xDB, 0xDC, FEND])
        result = kiss_decode(frame)
        assert result.data == bytes([0xC0])

    def test_too_short_raises(self):
        with pytest.raises(KissError, match="too short"):
            kiss_decode(bytes([FEND, FEND]))

    def test_no_start_fend_raises(self):
        with pytest.raises(KissError, match="start with FEND"):
            kiss_decode(bytes([0x00, 0x41, FEND]))

    def test_no_end_fend_raises(self):
        with pytest.raises(KissError, match="end with FEND"):
            kiss_decode(bytes([FEND, 0x00, 0x41]))

    def test_multiple_trailing_fends(self):
        # Should handle consecutive FENDs at end
        frame = bytes([FEND, 0x00, 0x41, FEND, FEND, FEND])
        result = kiss_decode(frame)
        assert result.data == b"A"


class TestEncodeDecodeRoundtrip:
    def test_roundtrip(self):
        for port in [0, 7, 15]:
            for cmd in [0, 1, 15]:
                for data in [b"", b"test", bytes([0xC0, 0xDB, 0xFF])]:
                    frame = kiss_encode(port, cmd, data)
                    result = kiss_decode(frame)
                    assert result.port == port
                    assert result.command == cmd
                    assert result.data == data

    def test_cmd_byte_colliding_with_delimiters_is_escaped(self):
        # (port=12, cmd=0) -> cmd byte 0xC0 == FEND; (port=13, cmd=11) ->
        # 0xDB == FESC. Both must be escaped on the wire and round-trip.
        for port, cmd in [(12, 0), (13, 11)]:
            for data in [b"", b"Hi"]:
                frame = kiss_encode(port, cmd, data)
                assert frame[1] == 0xDB  # FESC: cmd byte is escaped
                result = kiss_decode(frame)
                assert result.port == port
                assert result.command == cmd
                assert result.data == data


class TestKissReader:
    def test_single_frame(self):
        reader = KissReader()
        reader.feed(bytes([FEND, 0x00, 0x41, 0x42, FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].data == b"AB"

    def test_multiple_frames(self):
        reader = KissReader()
        reader.feed(bytes([FEND, 0x00, 0x41, FEND, FEND, 0x00, 0x42, FEND]))
        frames = list(reader)
        assert len(frames) == 2
        assert frames[0].data == b"A"
        assert frames[1].data == b"B"

    def test_incremental_feed(self):
        reader = KissReader()
        reader.feed(bytes([FEND, 0x00]))
        assert list(reader) == []  # Not complete

        reader.feed(bytes([0x41, 0x42]))
        assert list(reader) == []  # Still not complete

        reader.feed(bytes([FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].data == b"AB"

    def test_skips_garbage_before_fend(self):
        reader = KissReader()
        reader.feed(bytes([0x00, 0x01, 0x02, FEND, 0x00, 0x41, FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].data == b"A"

    def test_handles_consecutive_fends(self):
        reader = KissReader()
        reader.feed(bytes([FEND, FEND, FEND, 0x00, 0x41, FEND]))
        frames = list(reader)
        assert len(frames) == 1

    def test_buffer_overflow_protection(self):
        reader = KissReader(max_frame_size=100)
        # Feed more than max_frame_size * 2
        reader.feed(bytes([0x41] * 300))
        # Buffer should be trimmed
        assert len(reader.buffer) < 300

    def test_clear(self):
        reader = KissReader()
        reader.feed(bytes([FEND, 0x00, 0x41]))
        reader.clear()
        assert len(reader.buffer) == 0

    def test_escaped_data(self):
        reader = KissReader()
        # Frame with escaped FEND
        reader.feed(bytes([FEND, 0x00, 0xDB, 0xDC, FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].data == bytes([0xC0])

    def test_invalid_frame_skipped(self):
        reader = KissReader()
        # Invalid escape followed by valid frame
        reader.feed(bytes([FEND, 0x00, 0xDB, 0x00, FEND, FEND, 0x00, 0x41, FEND]))
        frames = list(reader)
        # First frame invalid (bad escape), second valid
        assert len(frames) == 1
        assert frames[0].data == b"A"

    def test_minimal_frame_no_payload(self):
        """Minimal valid frame: FEND|CMD|FEND (command byte, no payload data)."""
        reader = KissReader()
        reader.feed(bytes([FEND, 0x00, FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].port == 0
        assert frames[0].command == 0
        assert frames[0].data == b""

    def test_minimal_frame_with_leading_fends(self):
        """Minimal frame with multiple leading FENDs (inter-frame padding)."""
        reader = KissReader()
        reader.feed(bytes([FEND, FEND, FEND, 0x00, FEND]))
        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].port == 0
        assert frames[0].command == 0
        assert frames[0].data == b""

    def test_consecutive_minimal_frames(self):
        """Multiple consecutive minimal frames with various commands."""
        reader = KissReader()
        # Three minimal frames: DATA (0x00), TXDELAY (0x01), RETURN (0x0F)
        reader.feed(bytes([FEND, 0x00, FEND, FEND, 0x01, FEND, FEND, 0x0F, FEND]))
        frames = list(reader)
        assert len(frames) == 3
        assert frames[0].command == 0x00
        assert frames[1].command == 0x01
        assert frames[2].command == 0x0F
