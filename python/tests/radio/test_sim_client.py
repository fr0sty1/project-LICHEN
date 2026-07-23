# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SimRadio client."""

from __future__ import annotations

import asyncio
import struct

import anyio
import pytest

from lichen.radio.sim_client import MAX_MESSAGE_LENGTH, SimRadio, SimRadioError
from lichen.sim.protocol import (
    MSG_REGISTER,
    MSG_RX_ENTER,
    MSG_TIME,
    MSG_TX,
    ProtocolError,
    decode_register,
    decode_rx_enter,
    decode_tx,
    encode_err,
    encode_ok,
    encode_rx_packet,
    encode_rx_timeout_push,
    encode_time_ok,
    encode_tx_done,
    encode_tx_fail,
    get_message_type,
)


class MockServer:
    """Mock TCP server for testing SimRadio client."""

    def __init__(self) -> None:
        self.received_messages: list[bytes] = []
        self.responses: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._port: int = 0
        self._handler_done: asyncio.Event = asyncio.Event()

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> None:
        """Start the mock server on a random port."""
        self._server = await asyncio.start_server(
            self._handle_client, host="127.0.0.1", port=0
        )
        # Get the assigned port
        addr = self._server.sockets[0].getsockname()
        self._port = addr[1]

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single client connection."""
        try:
            for response in self.responses:
                # Read incoming message
                msg = await self._read_message(reader)
                self.received_messages.append(msg)
                # Send response
                await self._send_message(writer, response)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            self._handler_done.set()

    async def _read_message(self, reader: asyncio.StreamReader) -> bytes:
        """Read a length-prefixed message."""
        length_data = await reader.readexactly(4)
        (msg_len,) = struct.unpack("<I", length_data)
        return await reader.readexactly(msg_len)

    async def _send_message(
        self, writer: asyncio.StreamWriter, data: bytes
    ) -> None:
        """Send a length-prefixed message."""
        frame = struct.pack("<I", len(data)) + data
        writer.write(frame)
        await writer.drain()

    async def wait_for_handler(self) -> None:
        """Wait for the client handler to complete."""
        await self._handler_done.wait()

    async def close(self) -> None:
        """Close the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def mock_server():
    """Create and start a mock server."""
    server = MockServer()
    await server.start()
    yield server
    await server.close()


async def test_connect_success(mock_server: MockServer) -> None:
    """Test successful connection and registration."""
    mock_server.responses = [encode_ok()]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (1.0, 2.0, 3.0))

    await radio.connect()
    await radio.close()
    await mock_server.wait_for_handler()

    # Verify REGISTER message was sent
    assert len(mock_server.received_messages) == 1
    msg = mock_server.received_messages[0]
    assert get_message_type(msg) == MSG_REGISTER
    sim_id, node_id, x, y, z = decode_register(msg[1:])
    assert sim_id == "sim1"
    assert node_id == "node1"
    assert (x, y, z) == (1.0, 2.0, 3.0)


async def test_connect_error(mock_server: MockServer) -> None:
    """Test connection failure due to server error."""
    mock_server.responses = [encode_err(1, "Simulation not found")]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    with pytest.raises(SimRadioError, match="Registration failed"):
        await radio.connect()


async def test_transmit_success(mock_server: MockServer) -> None:
    """Test successful transmission."""
    mock_server.responses = [
        encode_ok(),  # REGISTER response
        encode_tx_done(1000),  # TX response
    ]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    await radio.connect()
    result = await radio.transmit(b"hello world")
    await radio.close()
    await mock_server.wait_for_handler()

    assert result is True
    assert len(mock_server.received_messages) == 2
    tx_msg = mock_server.received_messages[1]
    assert get_message_type(tx_msg) == MSG_TX
    payload, channel = decode_tx(tx_msg[1:])
    assert payload == b"hello world"
    assert channel == 0


async def test_transmit_failure(mock_server: MockServer) -> None:
    """Test transmission failure."""
    mock_server.responses = [
        encode_ok(),  # REGISTER response
        encode_tx_fail(),  # TX response
    ]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    await radio.connect()
    result = await radio.transmit(b"test")
    await radio.close()
    await mock_server.wait_for_handler()

    assert result is False


async def test_receive_success(mock_server: MockServer) -> None:
    """Test successful reception using push-based RX_ENTER/RX_PACKET."""
    mock_server.responses = [
        encode_ok(),  # REGISTER response
        encode_rx_packet(b"received data", -80, 100),  # RX_PACKET response (snr in dB * 10)
    ]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    await radio.connect()
    result = await radio.receive(5000)
    await radio.close()
    await mock_server.wait_for_handler()

    assert result is not None
    payload, rssi, snr = result
    assert payload == b"received data"
    assert rssi == -80
    assert snr == 100

    # Verify RX_ENTER request (timeout in microseconds: ms -> us)
    rx_msg = mock_server.received_messages[1]
    assert get_message_type(rx_msg) == MSG_RX_ENTER
    timeout_us, channel = decode_rx_enter(rx_msg[1:])
    assert timeout_us == 5000 * 1000
    assert channel == 0


async def test_receive_timeout(mock_server: MockServer) -> None:
    """Test receive timeout using push-based RX_TIMEOUT_PUSH."""
    mock_server.responses = [
        encode_ok(),  # REGISTER response
        encode_rx_timeout_push(),  # RX_TIMEOUT_PUSH response
    ]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    await radio.connect()
    result = await radio.receive(1000)
    await radio.close()
    await mock_server.wait_for_handler()

    assert result is None


async def test_get_time(mock_server: MockServer) -> None:
    """Test time query."""
    mock_server.responses = [
        encode_ok(),  # REGISTER response
        encode_time_ok(123456789),  # TIME response
    ]

    radio = SimRadio("127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0))

    await radio.connect()
    time_us = await radio.get_time()
    await radio.close()
    await mock_server.wait_for_handler()

    assert time_us == 123456789

    # Verify TIME request
    time_msg = mock_server.received_messages[1]
    assert get_message_type(time_msg) == MSG_TIME


async def test_configure() -> None:
    """Test configure method stores values locally."""
    radio = SimRadio("localhost", 5555, "sim1", "node1", (0, 0, 0))

    # Check defaults
    assert radio.freq_hz == 915_000_000
    assert radio.tx_power_dbm == 14

    # Configure new values
    radio.configure(868_000_000, 20)

    assert radio.freq_hz == 868_000_000
    assert radio.tx_power_dbm == 20


async def test_context_manager(mock_server: MockServer) -> None:
    """Test async context manager."""
    mock_server.responses = [encode_ok()]

    async with SimRadio(
        "127.0.0.1", mock_server.port, "sim1", "node1", (0, 0, 0)
    ) as radio:
        # Should be connected
        assert radio._stream is not None

    # Should be disconnected after exiting context
    assert radio._stream is None
    await mock_server.wait_for_handler()


async def test_not_connected_error() -> None:
    """Test operations fail when not connected."""
    radio = SimRadio("localhost", 5555, "sim1", "node1", (0, 0, 0))

    with pytest.raises(SimRadioError, match="Not connected"):
        await radio.transmit(b"test")

    with pytest.raises(SimRadioError, match="Not connected"):
        await radio.receive(1000)

    with pytest.raises(SimRadioError, match="Not connected"):
        await radio.get_time()


async def test_connect_to_invalid_host() -> None:
    """Test connection to invalid host fails gracefully."""
    radio = SimRadio("invalid.host.that.does.not.exist", 5555, "sim1", "node1", (0, 0, 0))

    with pytest.raises(SimRadioError, match="Failed to connect"):
        await radio.connect()


async def test_close_when_not_connected() -> None:
    """Test close() is safe to call when not connected."""
    radio = SimRadio("localhost", 5555, "sim1", "node1", (0, 0, 0))
    # Should not raise
    await radio.close()


async def test_recv_rejects_oversized_message() -> None:
    """A forged length prefix above MAX_MESSAGE_LENGTH is rejected before alloc.

    The server replies with only a 4-byte length prefix claiming an enormous
    body and never sends the body. A correct client rejects it based on the
    prefix alone; a missing bound would instead block reading bytes that never
    arrive (so this test would hang rather than pass).
    """

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Consume the REGISTER frame the client sends on connect.
        (n,) = struct.unpack("<I", await reader.readexactly(4))
        await reader.readexactly(n)
        # Reply with a frame claiming a body larger than the allowed maximum.
        writer.write(struct.pack("<I", MAX_MESSAGE_LENGTH + 1))
        await writer.drain()
        await reader.read()  # hold the connection open until the client closes
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        radio = SimRadio("127.0.0.1", port, "sim1", "node1", (0, 0, 0))
        with pytest.raises(ProtocolError, match="exceeds maximum"):
            await radio.connect()
        await radio.close()


class _RecordingStream:
    """In-memory SocketStream stand-in that records operation order.

    Each ``send`` records a "send" event, queues the matching response frame,
    then yields control so a concurrent task may run. Each ``receive`` records
    a "recv" event. A test inspects ``events`` to verify that one operation's
    send->recv exchange is not interleaved with another's.
    """

    def __init__(self, response_for) -> None:
        self._response_for = response_for
        self._inbox = b""
        self.events: list[str] = []

    async def send(self, data: bytes) -> None:
        message = data[4:]  # strip the 4-byte length prefix
        self.events.append("send")
        response = self._response_for(message)
        self._inbox += struct.pack("<I", len(response)) + response
        # Yield here: an unsynchronized concurrent op would interleave its send.
        await anyio.lowlevel.checkpoint()

    async def receive(self, max_bytes: int) -> bytes:
        await anyio.lowlevel.checkpoint()
        if not self._inbox:
            raise AssertionError("receive() called with no buffered data")
        chunk, self._inbox = self._inbox[:max_bytes], self._inbox[max_bytes:]
        self.events.append("recv")
        return chunk

    async def aclose(self) -> None:
        pass


async def test_concurrent_operations_are_serialized() -> None:
    """Concurrent operations must not interleave their send/recv exchanges.

    The recording stream yields control at each send, so without serialization
    the two operations would both send before either reads (events would start
    with two "send"s). The lock forces each send to be immediately followed by
    its own recv; this assertion fails if the lock is removed.
    """

    def response_for(message: bytes) -> bytes:
        mtype = message[0]
        if mtype == MSG_TX:
            return encode_tx_done(1234)
        if mtype == MSG_TIME:
            return encode_time_ok(5678)
        raise AssertionError(f"unexpected request type 0x{mtype:02x}")

    stream = _RecordingStream(response_for)
    radio = SimRadio("h", 1, "sim", "node", (0.0, 0.0, 0.0))
    radio._stream = stream  # type: ignore[assignment]  # inject a connected stream

    results: dict[str, object] = {}

    async def run_tx() -> None:
        results["tx"] = await radio.transmit(b"hello")

    async def run_time() -> None:
        results["time"] = await radio.get_time()

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_tx)
        tg.start_soon(run_time)

    # Both exchanges completed with their correct, matched responses.
    assert results["tx"] is True
    assert results["time"] == 5678

    # Each send is immediately followed by a recv from the same exchange;
    # no two sends are adjacent.
    assert stream.events.count("send") == 2
    for i, kind in enumerate(stream.events):
        if kind == "send":
            assert stream.events[i + 1] == "recv", (
                f"send not immediately followed by recv: {stream.events}"
            )
