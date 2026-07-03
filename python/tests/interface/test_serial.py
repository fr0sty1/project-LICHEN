"""Tests for LICHEN Native serial transport."""

import asyncio
import contextlib
from unittest.mock import MagicMock, patch

import pytest

from lichen.interface.messages import ConfigGet, ConfigResult, Hello, ResultCode
from lichen.interface.serial import SerialConnection, list_serial_ports, open_serial


class TestListPorts:
    def test_list_serial_ports(self):
        """list_serial_ports returns a list."""
        ports = list_serial_ports()
        assert isinstance(ports, list)


class TestSerialConnection:
    @pytest.mark.asyncio
    async def test_open_close(self):
        """Test open and close with mock serial."""
        mock_serial = MagicMock()
        mock_serial.is_open = True

        with patch("serial.Serial", return_value=mock_serial):
            conn = SerialConnection(port="/dev/ttyTEST")
            await conn.open()

            assert conn.is_open
            assert not conn.closed

            await conn.close()
            assert conn.closed
            mock_serial.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_send(self):
        """Test sending a message."""
        mock_serial = MagicMock()
        mock_serial.is_open = True

        with patch("serial.Serial", return_value=mock_serial):
            conn = SerialConnection(port="/dev/ttyTEST")
            await conn.open()

            try:
                msg = Hello(version=1, firmware="test")
                await conn.send(msg)

                # Verify write was called
                mock_serial.write.assert_called_once()
                mock_serial.flush.assert_called_once()

                # Check frame format (starts with 0xC1)
                written = mock_serial.write.call_args[0][0]
                assert written[0] == 0xC1
            finally:
                await conn.close()

    @pytest.mark.asyncio
    async def test_recv(self):
        """Test receiving a message."""
        # Create a framed Hello message
        from lichen.interface.framing import frame
        from lichen.interface.messages import encode_message

        hello = Hello(version=1, firmware="device")
        framed = frame(encode_message(hello))

        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.in_waiting = len(framed)
        mock_serial.read.return_value = framed

        with patch("serial.Serial", return_value=mock_serial):
            conn = SerialConnection(port="/dev/ttyTEST")
            await conn.open()

            try:
                msg = await conn.recv()
                assert isinstance(msg, Hello)
                assert msg.firmware == "device"
            finally:
                await conn.close()

    @pytest.mark.asyncio
    async def test_send_when_closed(self):
        """Sending on closed connection raises error."""
        conn = SerialConnection(port="/dev/ttyTEST")
        conn._closed = True

        with pytest.raises(ConnectionError):
            await conn.send(Hello())

    @pytest.mark.asyncio
    async def test_handler_callback(self):
        """Test run() loop with handler."""
        from lichen.interface.framing import frame
        from lichen.interface.messages import encode_message

        # Prepare messages: ConfigGet, then close
        config_get = ConfigGet()
        framed = frame(encode_message(config_get))

        read_count = 0

        def mock_read(size=1):
            nonlocal read_count
            read_count += 1
            if read_count == 1:
                return framed
            # Return empty to trigger close
            return b""

        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.in_waiting = len(framed)
        mock_serial.read.side_effect = mock_read

        received = []

        async def handler(msg):
            received.append(msg)
            return ConfigResult(result=ResultCode.OK)

        with patch("serial.Serial", return_value=mock_serial):
            conn = SerialConnection(port="/dev/ttyTEST", handler=handler)
            await conn.open()

            # Run with timeout
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(conn.run(), timeout=0.5)

            assert len(received) >= 1
            assert isinstance(received[0], ConfigGet)


class TestOpenSerial:
    @pytest.mark.asyncio
    async def test_open_serial(self):
        """Test open_serial convenience function."""
        mock_serial = MagicMock()
        mock_serial.is_open = True

        with patch("serial.Serial", return_value=mock_serial):
            conn = await open_serial("/dev/ttyTEST", baudrate=9600)
            try:
                assert conn.is_open
                assert conn.baudrate == 9600
            finally:
                await conn.close()
