"""Tests for LICHEN Native protocol framing."""

import pytest

from lichen.interface.framing import (
    START_BYTE,
    FrameReader,
    FrameWriter,
    FramingError,
    frame,
    unframe,
)


class TestFrame:
    def test_frame_empty(self):
        result = frame(b"")
        assert result == bytes([START_BYTE, 0x00, 0x00])

    def test_frame_small(self):
        result = frame(b"\x01\x02\x03")
        assert result == bytes([START_BYTE, 0x00, 0x03, 0x01, 0x02, 0x03])

    def test_frame_256_bytes(self):
        payload = bytes(range(256))
        result = frame(payload)
        assert result[0] == START_BYTE
        assert result[1:3] == b"\x01\x00"  # 256 in big-endian
        assert result[3:] == payload

    def test_frame_too_large(self):
        with pytest.raises(FramingError, match="too large"):
            frame(b"x" * 65536)


class TestUnframe:
    def test_unframe_simple(self):
        data = bytes([START_BYTE, 0x00, 0x03, 0x01, 0x02, 0x03])
        payload, remaining = unframe(data)
        assert payload == b"\x01\x02\x03"
        assert remaining == b""

    def test_unframe_with_remaining(self):
        data = bytes([START_BYTE, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD])
        payload, remaining = unframe(data)
        assert payload == b"\xAA\xBB"
        assert remaining == b"\xCC\xDD"

    def test_unframe_incomplete_header(self):
        with pytest.raises(FramingError, match="incomplete header"):
            unframe(bytes([START_BYTE, 0x00]))

    def test_unframe_incomplete_payload(self):
        with pytest.raises(FramingError, match="incomplete payload"):
            unframe(bytes([START_BYTE, 0x00, 0x10, 0x01, 0x02]))

    def test_unframe_bad_start(self):
        with pytest.raises(FramingError, match="invalid start byte"):
            unframe(bytes([0x00, 0x00, 0x01, 0xFF]))


class TestFrameReader:
    def test_empty(self):
        reader = FrameReader()
        assert list(reader) == []

    def test_single_frame(self):
        reader = FrameReader()
        reader.feed(bytes([START_BYTE, 0x00, 0x02, 0xAA, 0xBB]))
        frames = list(reader)
        assert frames == [b"\xAA\xBB"]
        assert reader.pending() == 0

    def test_multiple_frames(self):
        reader = FrameReader()
        # Two frames back to back
        data = (
            bytes([START_BYTE, 0x00, 0x01, 0x11])
            + bytes([START_BYTE, 0x00, 0x01, 0x22])
        )
        reader.feed(data)
        frames = list(reader)
        assert frames == [b"\x11", b"\x22"]

    def test_incremental_feed(self):
        reader = FrameReader()
        # Feed header only
        reader.feed(bytes([START_BYTE, 0x00, 0x03]))
        assert list(reader) == []
        assert reader.pending() == 3

        # Feed partial payload
        reader.feed(bytes([0x01, 0x02]))
        assert list(reader) == []
        assert reader.pending() == 5

        # Feed rest
        reader.feed(bytes([0x03]))
        frames = list(reader)
        assert frames == [b"\x01\x02\x03"]
        assert reader.pending() == 0

    def test_resync_on_garbage(self):
        reader = FrameReader()
        # Garbage then valid frame
        reader.feed(bytes([0xFF, 0xFE, START_BYTE, 0x00, 0x01, 0x42]))
        frames = list(reader)
        assert frames == [b"\x42"]

    def test_resync_on_bad_length(self):
        reader = FrameReader(max_size=100)
        # Frame with length > max_size should be skipped
        reader.feed(bytes([START_BYTE, 0xFF, 0xFF]))  # length 65535
        reader.feed(bytes([START_BYTE, 0x00, 0x01, 0x99]))  # valid frame
        frames = list(reader)
        assert frames == [b"\x99"]

    def test_clear(self):
        reader = FrameReader()
        reader.feed(bytes([START_BYTE, 0x00, 0x10]))
        assert reader.pending() > 0
        reader.clear()
        assert reader.pending() == 0


class TestFrameWriter:
    def test_no_fragmentation(self):
        writer = FrameWriter()
        chunks = list(writer.write(b"\x01\x02"))
        assert len(chunks) == 1
        assert chunks[0] == bytes([START_BYTE, 0x00, 0x02, 0x01, 0x02])

    def test_fragmentation(self):
        writer = FrameWriter(mtu=4)
        # Frame: C1 00 03 AA BB CC = 6 bytes, MTU=4
        chunks = list(writer.write(b"\xAA\xBB\xCC"))
        assert len(chunks) == 2
        assert chunks[0] == bytes([START_BYTE, 0x00, 0x03, 0xAA])
        assert chunks[1] == bytes([0xBB, 0xCC])

    def test_roundtrip_fragmented(self):
        writer = FrameWriter(mtu=5)
        reader = FrameReader()

        payload = b"hello world"
        for chunk in writer.write(payload):
            reader.feed(chunk)

        frames = list(reader)
        assert frames == [payload]
