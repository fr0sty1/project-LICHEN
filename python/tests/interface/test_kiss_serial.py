"""Tests for KISS serial transport."""

from unittest.mock import patch

import pytest

from lichen.interface.kiss import (
    FEND,
    KissCommand,
    KissSerialConnection,
    kiss_encode,
)


class MockSerial:
    """Mock serial port for testing."""

    def __init__(self):
        self.rx_buffer = bytearray()
        self.tx_buffer = bytearray()
        self.is_open = True
        self._waiting = 0

    @property
    def in_waiting(self):
        return len(self.rx_buffer)

    def read(self, size):
        if not self.rx_buffer:
            return b""
        data = bytes(self.rx_buffer[:size])
        del self.rx_buffer[:size]
        return data

    def write(self, data):
        self.tx_buffer.extend(data)

    def flush(self):
        pass

    def close(self):
        self.is_open = False

    def inject(self, data: bytes):
        """Inject data as if received from device."""
        self.rx_buffer.extend(data)


@pytest.fixture
def mock_serial():
    return MockSerial()


class TestKissSerialConnection:
    @pytest.mark.asyncio
    async def test_open_close(self, mock_serial):
        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test")
            await conn.open()
            assert conn.is_open
            await conn.close()
            assert conn.closed

    @pytest.mark.asyncio
    async def test_recv_data_frame(self, mock_serial):
        received = []

        def on_frame(port, payload):
            received.append((port, payload))

        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test", on_frame=on_frame)
            await conn.open()

            # Inject a KISS data frame
            frame = kiss_encode(0, KissCommand.DATA, b"hello")
            mock_serial.inject(frame)

            # Process it
            await conn.recv()

            assert received == [(0, b"hello")]
            await conn.close()

    @pytest.mark.asyncio
    async def test_recv_multiple_frames(self, mock_serial):
        received = []

        def on_frame(port, payload):
            received.append((port, payload))

        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test", on_frame=on_frame)
            await conn.open()

            # Inject multiple frames
            mock_serial.inject(kiss_encode(0, KissCommand.DATA, b"one"))
            mock_serial.inject(kiss_encode(0, KissCommand.DATA, b"two"))

            await conn.recv()

            assert received == [(0, b"one"), (0, b"two")]
            await conn.close()

    @pytest.mark.asyncio
    async def test_recv_return_stops(self, mock_serial):
        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test")
            await conn.open()

            # Inject RETURN command
            mock_serial.inject(kiss_encode(0, KissCommand.RETURN, b""))

            result = await conn.recv()

            assert result is False
            assert conn.handler.exited
            await conn.close()

    @pytest.mark.asyncio
    async def test_send_frame(self, mock_serial):
        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test")
            await conn.open()

            await conn.send_frame(b"test", port=0)

            # Check what was written
            assert len(mock_serial.tx_buffer) > 0
            assert mock_serial.tx_buffer[0] == FEND
            assert mock_serial.tx_buffer[-1] == FEND
            assert b"test" in mock_serial.tx_buffer
            await conn.close()

    @pytest.mark.asyncio
    async def test_config_commands(self, mock_serial):
        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test")
            await conn.open()

            # Inject config commands
            mock_serial.inject(kiss_encode(0, KissCommand.TXDELAY, bytes([100])))
            mock_serial.inject(kiss_encode(0, KissCommand.PERSISTENCE, bytes([200])))

            await conn.recv()

            assert conn.handler.config.txdelay_ms == 100
            assert conn.handler.config.persistence == 200
            await conn.close()

    @pytest.mark.asyncio
    async def test_incremental_receive(self, mock_serial):
        """Test frame reassembly across multiple reads."""
        received = []

        def on_frame(port, payload):
            received.append((port, payload))

        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test", on_frame=on_frame)
            await conn.open()

            # Build a frame and split it
            frame = kiss_encode(0, KissCommand.DATA, b"split")
            mid = len(frame) // 2

            # First half
            mock_serial.inject(frame[:mid])
            await conn.recv()
            assert received == []  # Not complete yet

            # Second half
            mock_serial.inject(frame[mid:])
            await conn.recv()
            assert received == [(0, b"split")]

            await conn.close()

    @pytest.mark.asyncio
    async def test_closed_raises_on_send(self, mock_serial):
        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test")
            await conn.open()
            await conn.close()

            with pytest.raises(ConnectionError):
                await conn.send_frame(b"test")

    @pytest.mark.asyncio
    async def test_on_frame_wired_to_handler(self, mock_serial):
        """Verify on_frame callback is connected to handler."""
        received = []

        def on_frame(port, payload):
            received.append((port, payload))

        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test", on_frame=on_frame)

            # Handler's on_tx_frame should be set
            assert conn.handler.on_tx_frame is on_frame


class TestKissSerialRun:
    @pytest.mark.asyncio
    async def test_run_until_return(self, mock_serial):
        frames = []

        def on_frame(port, payload):
            frames.append((port, payload))

        with patch("serial.Serial", return_value=mock_serial):
            conn = KissSerialConnection(port="/dev/test", on_frame=on_frame)
            await conn.open()

            # Inject some frames then RETURN
            mock_serial.inject(kiss_encode(0, KissCommand.DATA, b"a"))
            mock_serial.inject(kiss_encode(0, KissCommand.DATA, b"b"))
            mock_serial.inject(kiss_encode(0, KissCommand.RETURN, b""))

            await conn.run()

            assert frames == [(0, b"a"), (0, b"b")]
            assert conn.closed
