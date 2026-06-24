# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SimRadio client for the LICHEN simulator.

This module provides a Radio implementation that connects to the simulator
server over TCP, enabling simulated radio operations for testing and development.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import anyio

from lichen.sim.protocol import (
    MSG_CAD_RESULT,
    MSG_ERR,
    MSG_OK,
    MSG_RX_OK,
    MSG_RX_TIMEOUT,
    MSG_TIME_OK,
    MSG_TX_DONE,
    MSG_TX_FAIL,
    ProtocolError,
    decode_cad_result,
    decode_err,
    decode_rx_ok,
    decode_time_ok,
    encode_cad,
    encode_register,
    encode_rx,
    encode_time,
    encode_tx,
    get_message_type,
)

if TYPE_CHECKING:
    from anyio.abc import SocketStream

# Upper bound on an incoming framed message, to prevent a malicious or buggy
# server from triggering a huge allocation via the 4-byte length prefix.
# The largest legitimate message is an RX_OK carrying a max-size payload
# (1 type + 2 length + 65535 payload + 4 rssi/snr); 1 MiB leaves generous
# headroom while bounding memory use.
MAX_MESSAGE_LENGTH = 1 << 20


class SimRadioError(Exception):
    """Raised when SimRadio operations fail."""


class SimRadio:
    """Radio implementation that connects to the LICHEN simulator server.

    This class implements the Radio protocol by communicating with a simulator
    server over TCP. Each operation sends a request message and waits for
    the corresponding response.

    Usage:
        async with SimRadio("localhost", 5555, "sim1", "node1", (0, 0, 0)) as radio:
            radio.configure(915_000_000, 14)
            await radio.transmit(b"hello")
    """

    def __init__(
        self,
        host: str,
        port: int,
        sim_id: str,
        node_id: str,
        position: tuple[float, float, float],
    ) -> None:
        """Initialize a SimRadio instance.

        Args:
            host: Simulator server hostname or IP address.
            port: Simulator server TCP port.
            sim_id: Simulation identifier to join.
            node_id: Unique identifier for this node.
            position: Node position as (x, y, z) coordinates in meters.
        """
        self._host = host
        self._port = port
        self._sim_id = sim_id
        self._node_id = node_id
        self._position = position
        self._stream: SocketStream | None = None
        self._freq_hz: int = 915_000_000
        self._tx_power_dbm: int = 14
        # Serializes each request/response exchange. Without it, concurrent
        # operations could interleave their _send/_recv calls and mismatch
        # responses to requests (or corrupt frame framing on the shared stream).
        self._lock = anyio.Lock()

    @property
    def freq_hz(self) -> int:
        """Current configured frequency in Hz."""
        return self._freq_hz

    @property
    def tx_power_dbm(self) -> int:
        """Current configured transmit power in dBm."""
        return self._tx_power_dbm

    async def connect(self) -> None:
        """Open TCP connection to the simulator and register this node.

        Sends a REGISTER message and waits for an OK response.

        Raises:
            SimRadioError: If connection fails or registration is rejected.
        """
        try:
            self._stream = await anyio.connect_tcp(self._host, self._port)
        except OSError as e:
            raise SimRadioError(f"Failed to connect to {self._host}:{self._port}: {e}") from e

        # Send REGISTER message
        x, y, z = self._position
        msg = encode_register(self._sim_id, self._node_id, x, y, z)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = get_message_type(response)

        if msg_type == MSG_OK:
            return
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"Registration failed (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to REGISTER: 0x{msg_type:02x}")

    async def transmit(self, payload: bytes) -> bool:
        """Transmit a payload over the simulated radio.

        Args:
            payload: The raw bytes to transmit.

        Returns:
            True if transmission succeeded (TX_DONE), False if it failed (TX_FAIL).

        Raises:
            SimRadioError: If not connected or protocol error occurs.
        """
        self._ensure_connected()

        msg = encode_tx(payload)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = get_message_type(response)

        if msg_type == MSG_TX_DONE:
            return True
        elif msg_type == MSG_TX_FAIL:
            return False
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"TX error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to TX: 0x{msg_type:02x}")

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Receive a payload from the simulated radio.

        Blocks until a packet is received or timeout expires.

        Args:
            timeout_ms: Maximum time to wait for a packet, in milliseconds.

        Returns:
            A tuple of (payload, rssi_dbm, snr_db) if a packet was received,
            or None if the timeout expired without receiving a packet.

        Raises:
            SimRadioError: If not connected or protocol error occurs.
        """
        self._ensure_connected()

        msg = encode_rx(timeout_ms)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = get_message_type(response)

        if msg_type == MSG_RX_OK:
            payload, rssi, snr = decode_rx_ok(response[1:])
            return (payload, rssi, snr)
        elif msg_type == MSG_RX_TIMEOUT:
            return None
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"RX error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to RX: 0x{msg_type:02x}")

    async def get_time(self) -> int:
        """Get the current simulation time.

        Returns:
            Current simulation time in microseconds.

        Raises:
            SimRadioError: If not connected or protocol error occurs.
        """
        self._ensure_connected()

        msg = encode_time()
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = get_message_type(response)

        if msg_type == MSG_TIME_OK:
            return decode_time_ok(response[1:])
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"TIME error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to TIME: 0x{msg_type:02x}")

    async def cad(self, timeout_ms: int) -> bool:
        """Perform Channel Activity Detection (CAD).

        CAD is a quick check for LoRa preamble activity on the channel,
        used for listen-before-talk and low-power wake-up detection.

        Args:
            timeout_ms: Maximum time to wait for CAD completion, in milliseconds.

        Returns:
            True if channel activity (LoRa preamble) was detected, False otherwise.

        Raises:
            SimRadioError: If not connected or protocol error occurs.
        """
        self._ensure_connected()

        msg = encode_cad(timeout_ms)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = get_message_type(response)

        if msg_type == MSG_CAD_RESULT:
            return decode_cad_result(response[1:])
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"CAD error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to CAD: 0x{msg_type:02x}")

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """Configure the radio parameters.

        These values are stored locally only and exposed via the ``freq_hz`` and
        ``tx_power_dbm`` properties. The current wire protocol's TX message
        carries only the payload, so the simulator does not receive or act on
        these settings; sending them would require a new protocol message.

        Args:
            freq_hz: Center frequency in Hz (e.g., 915_000_000 for 915 MHz).
            tx_power_dbm: Transmit power in dBm (e.g., 14 for 14 dBm / 25 mW).
        """
        self._freq_hz = freq_hz
        self._tx_power_dbm = tx_power_dbm

    async def close(self) -> None:
        """Close the TCP connection to the simulator."""
        if self._stream is not None:
            await self._stream.aclose()
            self._stream = None

    async def __aenter__(self) -> SimRadio:
        """Enter async context manager, connecting to the simulator."""
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager, closing the connection."""
        await self.close()

    def _ensure_connected(self) -> SocketStream:
        """Verify that we have an active connection and return the stream.

        Returns:
            The active socket stream.

        Raises:
            SimRadioError: If not connected.
        """
        if self._stream is None:
            raise SimRadioError("Not connected to simulator")
        return self._stream

    async def _send(self, data: bytes) -> None:
        """Send data over the TCP connection.

        Uses length-prefixed framing: 4-byte little-endian length followed by data.

        Args:
            data: The message bytes to send.

        Raises:
            SimRadioError: If send fails.
        """
        stream = self._ensure_connected()
        frame = struct.pack("<I", len(data)) + data
        try:
            await stream.send(frame)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as e:
            self._stream = None
            raise SimRadioError(f"Connection lost during send: {e}") from e

    async def _recv(self) -> bytes:
        """Receive a complete message from the TCP connection.

        Reads the length-prefixed frame and returns the message payload.

        Returns:
            The message bytes (including message type).

        Raises:
            SimRadioError: If receive fails or connection is closed.
            ProtocolError: If the message is malformed.
        """
        self._ensure_connected()

        try:
            # Read 4-byte length prefix
            length_data = await self._recv_exact(4)
            (msg_len,) = struct.unpack("<I", length_data)

            if msg_len == 0:
                raise ProtocolError("Received zero-length message")
            if msg_len > MAX_MESSAGE_LENGTH:
                raise ProtocolError(
                    f"Message length {msg_len} exceeds maximum {MAX_MESSAGE_LENGTH}"
                )

            # Read the message body
            return await self._recv_exact(msg_len)

        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as e:
            self._stream = None
            raise SimRadioError(f"Connection lost during receive: {e}") from e

    async def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes from the TCP connection.

        Args:
            n: Number of bytes to receive.

        Returns:
            Exactly n bytes of data.

        Raises:
            SimRadioError: If connection closes before all bytes are received.
        """
        stream = self._ensure_connected()
        chunks: list[bytes] = []
        remaining = n

        while remaining > 0:
            chunk = await stream.receive(remaining)
            if not chunk:
                raise SimRadioError(
                    f"Connection closed: expected {n} bytes, got {n - remaining}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)
