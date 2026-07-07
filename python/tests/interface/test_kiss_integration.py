"""Integration tests for KISS mode.

Tests end-to-end flows and edge cases across framing/handler/serial.
"""

import random
from unittest.mock import patch

import pytest

from lichen.interface.kiss import (
    FEND,
    FESC,
    TFEND,
    TFESC,
    KissCommand,
    KissHandler,
    KissReader,
    KissSerialConnection,
    kiss_decode,
    kiss_encode,
    kiss_escape,
    kiss_unescape,
)


class TestEscapeRoundtrip:
    """Roundtrip tests for escape/unescape with pathological inputs."""

    def test_all_byte_values(self):
        """Every byte value survives roundtrip."""
        data = bytes(range(256))
        assert kiss_unescape(kiss_escape(data)) == data

    def test_repeated_special_bytes(self):
        """Long runs of FEND/FESC."""
        for special in [FEND, FESC]:
            data = bytes([special] * 100)
            assert kiss_unescape(kiss_escape(data)) == data

    def test_alternating_specials(self):
        """Alternating FEND and FESC."""
        data = bytes([FEND, FESC] * 50)
        assert kiss_unescape(kiss_escape(data)) == data

    def test_escape_sequences_in_data(self):
        """Data that looks like escape sequences."""
        # FESC TFEND should become FEND, but raw TFEND alone is just TFEND
        data = bytes([TFEND, TFESC, FESC, FEND])
        assert kiss_unescape(kiss_escape(data)) == data


class TestFrameRoundtrip:
    """Roundtrip tests for encode/decode."""

    def test_all_ports(self):
        for port in range(16):
            frame = kiss_encode(port, KissCommand.DATA, b"test")
            result = kiss_decode(frame)
            assert result.port == port
            assert result.data == b"test"

    def test_all_commands(self):
        for cmd in [0, 1, 2, 3, 4, 5, 15]:
            frame = kiss_encode(0, cmd, b"x")
            result = kiss_decode(frame)
            assert result.command == cmd

    def test_binary_payloads(self):
        """Binary payloads with all byte values."""
        payload = bytes(range(256))
        frame = kiss_encode(0, KissCommand.DATA, payload)
        result = kiss_decode(frame)
        assert result.data == payload


class TestReaderEdgeCases:
    """Edge cases for KissReader frame reassembly."""

    def test_byte_at_a_time(self):
        """Feed one byte at a time."""
        reader = KissReader()
        frame = kiss_encode(0, KissCommand.DATA, b"hello")

        frames = []
        for b in frame:
            reader.feed(bytes([b]))
            frames.extend(list(reader))

        assert len(frames) == 1
        assert frames[0].data == b"hello"

    def test_garbage_recovery(self):
        """Recover from garbage between frames."""
        reader = KissReader()

        # Garbage, valid frame, garbage, valid frame
        reader.feed(b"\x00\x01\x02")  # garbage
        reader.feed(kiss_encode(0, 0, b"a"))
        reader.feed(b"\xff\xfe\xfd")  # garbage
        reader.feed(kiss_encode(0, 0, b"b"))

        frames = list(reader)
        assert len(frames) == 2
        assert frames[0].data == b"a"
        assert frames[1].data == b"b"

    def test_many_fends(self):
        """Multiple FEND delimiters."""
        reader = KissReader()

        # Many FENDs, then frame, then many FENDs
        reader.feed(bytes([FEND] * 10))
        reader.feed(bytes([0x00, 0x41]))  # cmd + data
        reader.feed(bytes([FEND] * 10))

        frames = list(reader)
        assert len(frames) == 1
        assert frames[0].data == b"A"

    def test_empty_frames(self):
        """Frames with no payload."""
        reader = KissReader()
        reader.feed(kiss_encode(0, 0, b""))
        reader.feed(kiss_encode(0, 1, b""))
        reader.feed(kiss_encode(0, 15, b""))

        frames = list(reader)
        assert len(frames) == 3
        for f in frames:
            assert f.data == b""


class TestHandlerIntegration:
    """Handler with reader integration."""

    def test_reader_to_handler_flow(self):
        """Frames from reader go to handler."""
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append(data))
        reader = KissReader()

        # Feed multiple frames
        reader.feed(kiss_encode(0, KissCommand.DATA, b"one"))
        reader.feed(kiss_encode(0, KissCommand.DATA, b"two"))
        reader.feed(kiss_encode(0, KissCommand.TXDELAY, bytes([50])))
        reader.feed(kiss_encode(0, KissCommand.DATA, b"three"))

        for frame in reader:
            handler.handle(frame)

        assert received == [b"one", b"two", b"three"]
        assert handler.config.txdelay_ms == 50

    def test_return_stops_processing(self):
        """RETURN command stops further processing."""
        received = []
        handler = KissHandler(on_tx_frame=lambda port, data: received.append(data))
        reader = KissReader()

        reader.feed(kiss_encode(0, KissCommand.DATA, b"before"))
        reader.feed(kiss_encode(0, KissCommand.RETURN, b""))
        reader.feed(kiss_encode(0, KissCommand.DATA, b"after"))

        for frame in reader:
            handler.handle(frame)

        assert received == [b"before"]
        assert handler.exited


class TestFuzz:
    """Fuzz tests with random data."""

    def test_random_bytes_no_crash(self):
        """Random bytes don't crash the reader."""
        rng = random.Random(42)
        reader = KissReader()

        for _ in range(100):
            chunk = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 500)))
            reader.feed(chunk)
            # Just iterate - shouldn't crash
            list(reader)

    def test_random_bytes_interspersed_with_valid(self):
        """Valid frames survive random garbage (that avoids FEND)."""
        rng = random.Random(43)
        reader = KissReader()

        expected = []
        for i in range(10):
            # Garbage that avoids FEND (0xC0) - realistic for line noise
            # ponytail: KISS has no checksum, garbage with FEND creates spurious frames
            garbage = bytes(
                rng.choice([b for b in range(256) if b != FEND])
                for _ in range(rng.randint(0, 100))
            )
            reader.feed(garbage)

            # Valid frame
            payload = f"frame{i}".encode()
            expected.append(payload)
            reader.feed(kiss_encode(0, KissCommand.DATA, payload))

        frames = list(reader)
        actual = [f.data for f in frames]

        # Should get all valid frames (order preserved)
        assert actual == expected

    def test_random_valid_frames(self):
        """Randomly generated valid frames roundtrip via encode/decode."""
        # ponytail: test encode/decode directly, reader tested separately
        rng = random.Random(44)

        for _ in range(50):
            port = rng.randint(0, 15)
            payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 200)))

            frame_bytes = kiss_encode(port, KissCommand.DATA, payload)
            result = kiss_decode(frame_bytes)

            assert result.port == port
            assert result.data == payload

    def test_random_frames_through_reader(self):
        """Random frames survive reader when properly delimited."""
        rng = random.Random(46)
        reader = KissReader()

        expected = []
        for _ in range(20):
            # ponytail: avoid port 12 with cmd 0 (0xC0 = FEND, ambiguous)
            port = rng.randint(0, 11)
            # Keep payloads small to avoid buffer issues
            payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 50)))
            expected.append((port, payload))
            reader.feed(kiss_encode(port, KissCommand.DATA, payload))

        frames = list(reader)

        assert len(frames) == len(expected)
        for frame, (exp_port, exp_data) in zip(frames, expected, strict=True):
            assert frame.port == exp_port
            assert frame.data == exp_data

    def test_escape_fuzz(self):
        """Random payloads survive escape/unescape."""
        rng = random.Random(45)

        for _ in range(100):
            data = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 500)))
            assert kiss_unescape(kiss_escape(data)) == data


class MockSerial:
    """Mock serial for integration tests."""

    def __init__(self):
        self.rx_buffer = bytearray()
        self.tx_buffer = bytearray()
        self.is_open = True

    @property
    def in_waiting(self):
        return len(self.rx_buffer)

    def read(self, size):
        data = bytes(self.rx_buffer[:size])
        del self.rx_buffer[:size]
        return data

    def write(self, data):
        self.tx_buffer.extend(data)

    def flush(self):
        pass

    def close(self):
        self.is_open = False

    def inject(self, data):
        self.rx_buffer.extend(data)


class TestSerialIntegration:
    """End-to-end serial tests."""

    @pytest.mark.asyncio
    async def test_bidirectional_flow(self):
        """Frames flow both directions."""
        mock = MockSerial()
        received = []

        with patch("serial.Serial", return_value=mock):
            conn = KissSerialConnection(
                port="/dev/test",
                on_frame=lambda port, data: received.append(data),
            )
            await conn.open()

            # Host -> Device (TX)
            mock.inject(kiss_encode(0, KissCommand.DATA, b"to_radio"))
            await conn.recv()
            assert received == [b"to_radio"]

            # Device -> Host (RX)
            await conn.send_frame(b"from_radio")
            frame = kiss_decode(bytes(mock.tx_buffer))
            assert frame.data == b"from_radio"

            await conn.close()

    @pytest.mark.asyncio
    async def test_config_and_data_mixed(self):
        """Config commands interleaved with data."""
        mock = MockSerial()
        received = []

        with patch("serial.Serial", return_value=mock):
            conn = KissSerialConnection(
                port="/dev/test",
                on_frame=lambda port, data: received.append(data),
            )
            await conn.open()

            # Mix of commands
            mock.inject(kiss_encode(0, KissCommand.TXDELAY, bytes([100])))
            mock.inject(kiss_encode(0, KissCommand.DATA, b"a"))
            mock.inject(kiss_encode(0, KissCommand.PERSISTENCE, bytes([200])))
            mock.inject(kiss_encode(0, KissCommand.DATA, b"b"))
            mock.inject(kiss_encode(0, KissCommand.FULLDUPLEX, bytes([1])))
            mock.inject(kiss_encode(0, KissCommand.DATA, b"c"))

            while mock.in_waiting:
                await conn.recv()

            assert received == [b"a", b"b", b"c"]
            assert conn.handler.config.txdelay_ms == 100
            assert conn.handler.config.persistence == 200
            assert conn.handler.config.fullduplex is True

            await conn.close()
