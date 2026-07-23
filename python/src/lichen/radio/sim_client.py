# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SimRadio client for the LICHEN simulator.

This module provides a Radio implementation that connects to the simulator
server over TCP, enabling simulated radio operations for testing and development.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import TYPE_CHECKING

import anyio
import structlog

from lichen.radio.base import MAX_LORA_PAYLOAD
from lichen.sim.protocol import (
    MAX_ID_LENGTH,
    MSG_CAD_RESULT,
    MSG_ERR,
    MSG_OK,
    MSG_RX_PACKET,
    MSG_RX_TIMEOUT_PUSH,
    MSG_TIME_OK,
    MSG_TX_DONE,
    MSG_TX_FAIL,
    ProtocolError,
    decode_cad_result,
    decode_err,
    decode_rx_packet,
    decode_time_ok,
    encode_cad,
    encode_register,
    encode_rx_enter,
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
MAX_TIMEOUT_MS = 4_294_967

logger = structlog.get_logger()


class SimRadioError(Exception):
    """Raised when SimRadio operations fail."""


class SimRadio:
    """Radio implementation that connects to the LICHEN simulator server.

    This class implements the Radio protocol by communicating with a simulator
    server over TCP. Each operation sends a request message and waits for
    the corresponding response.

    On connection loss, call ``reconnect()`` to recover (see reconnect() for
    details). The context manager does not auto-reconnect.

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
        for coord in position:
            if not math.isfinite(coord):
                msg = f"Position coordinates must be finite, got {position}"
                raise ValueError(msg)
        if not (1 <= port <= 65535):
            raise ValueError(f"port must be in range 1-65535, got {port}")
        if not sim_id or not node_id:
            raise ValueError("sim_id and node_id cannot be empty")
        sim_id_bytes = sim_id.encode("utf-8")
        if len(sim_id_bytes) > MAX_ID_LENGTH:
            raise ValueError(
                f"sim_id too long: {len(sim_id_bytes)} > {MAX_ID_LENGTH} bytes"
            )
        node_id_bytes = node_id.encode("utf-8")
        if len(node_id_bytes) > MAX_ID_LENGTH:
            raise ValueError(
                f"node_id too long: {len(node_id_bytes)} > {MAX_ID_LENGTH} bytes"
            )
        self._host = host
        self._port = port
        self._sim_id = sim_id
        self._node_id = node_id
        self._position = position
        self._stream: SocketStream | None = None
        self._freq_hz: int = 915_000_000
        self._tx_power_dbm: int = 14
        self._lock = anyio.Lock()
        self._connect_lock = anyio.Lock()

    @property
    def freq_hz(self) -> int:
        """Current configured frequency in Hz."""
        return self._freq_hz

    @property
    def tx_power_dbm(self) -> int:
        """Current configured transmit power in dBm."""
        return self._tx_power_dbm

    def _validate_response(self, response: bytes) -> int:
        if not response:
            raise SimRadioError("Empty simulator response")
        msg_type = get_message_type(response)
        if len(response) < 2 and msg_type in (MSG_ERR, MSG_RX_PACKET, MSG_TIME_OK):
            raise SimRadioError(
                f"Simulator response type 0x{msg_type:02x} too short for payload"
            )
        return msg_type


    async def connect(self) -> None:
        """Open TCP connection to the simulator and register this node.

        Sends a REGISTER message and waits for an OK response.

        This method is safe to call concurrently; only one connection will be
        established and subsequent calls will return immediately if already
        connected.

        Raises:
            SimRadioError: If connection fails or registration is rejected.
        """
        async with self._connect_lock:
            # Already connected - nothing to do
            if self._stream is not None:
                return

            try:
                self._stream = await anyio.connect_tcp(self._host, self._port)
            except OSError as e:
                raise SimRadioError(f"Failed to connect to {self._host}:{self._port}: {e}") from e

            # Send REGISTER message
            try:
                x, y, z = self._position
                msg = encode_register(self._sim_id, self._node_id, x, y, z)
                async with self._lock:
                    await self._send(msg)
                    response = await self._recv()
                msg_type = self._validate_response(response)

                if msg_type == MSG_OK:
                    return
                elif msg_type == MSG_ERR:
                    code, err_msg = decode_err(response[1:])
                    raise SimRadioError(f"Registration failed (code {code}): {err_msg}")
                else:
                    raise SimRadioError(f"Unexpected response to REGISTER: 0x{msg_type:02x}")
            except BaseException:
                async with self._lock:
                    if self._stream is not None:
                        await self._stream.aclose()
                        self._stream = None
                raise

    async def reconnect(self) -> None:
        """Close any existing connection and establish a fresh one.

        Call after SimRadioError from connection loss (BrokenResourceError
        or ClosedResourceError) to restore usability. Context-manager users
        must re-enter the context after reconnect.
        """
        await self.close()
        await self.connect()

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        self._ensure_connected()
        if len(payload) > MAX_LORA_PAYLOAD:
            raise ValueError(
                f"payload length {len(payload)} exceeds LoRa MTU ({MAX_LORA_PAYLOAD} bytes)"
            )
        msg = encode_tx(payload, channel)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = self._validate_response(response)
        if msg_type == MSG_TX_DONE:
            packet_hash = hashlib.sha256(payload).digest()[:16].hex()
            logger.info("tx",node_id=self._node_id,len=len(payload),packet_hash=packet_hash)
            return True
        elif msg_type == MSG_TX_FAIL:
            packet_hash = hashlib.sha256(payload).digest()[:16].hex()
            logger.warning("tx_fail",node_id=self._node_id,len=len(payload),packet_hash=packet_hash)
            return False
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"TX error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to TX: 0x{msg_type:02x}")

    async def receive(self, timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        self._ensure_connected()
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be non-negative")
        if not (0 <= timeout_ms <= MAX_TIMEOUT_MS):
            raise ValueError(
                f"timeout_ms must be <= {MAX_TIMEOUT_MS} (~71 minutes), got {timeout_ms}"
            )
        timeout_us = timeout_ms * 1000
        msg = encode_rx_enter(timeout_us, channel)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = self._validate_response(response)
        if msg_type == MSG_RX_PACKET:
            payload, rssi, snr = decode_rx_packet(response[1:])
            packet_hash = hashlib.sha256(payload).digest()[:16].hex()
            logger.info("rx",node_id=self._node_id,len=len(payload),rssi=rssi,snr=snr,packet_hash=packet_hash)
            return (payload, rssi, snr)
        elif msg_type == MSG_RX_TIMEOUT_PUSH:
            return None
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"RX error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to RX_ENTER: 0x{msg_type:02x}")

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
        msg_type = self._validate_response(response)

        if msg_type == MSG_TIME_OK:
            return decode_time_ok(response[1:])
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"TIME error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to TIME: 0x{msg_type:02x}")

    async def cad(self, timeout_ms: int, channel: int = 0) -> bool:
        self._ensure_connected()
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be non-negative")
        msg = encode_cad(timeout_ms, channel)
        async with self._lock:
            await self._send(msg)
            response = await self._recv()
        msg_type = self._validate_response(response)
        if msg_type == MSG_CAD_RESULT:
            return decode_cad_result(response[1:])
        elif msg_type == MSG_ERR:
            code, err_msg = decode_err(response[1:])
            raise SimRadioError(f"CAD error (code {code}): {err_msg}")
        else:
            raise SimRadioError(f"Unexpected response to CAD: 0x{msg_type:02x}")

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """Configure the radio parameters.

        See Radio.configure() in base.py for contract. Values are stored
        locally for the properties; no wire protocol message is sent (TX
        carries only payload and channel). Simulator propagation uses
        defaults until CONFIGURE support is added.

        Args:
            freq_hz: Center frequency in Hz (e.g., 915_000_000 for 915 MHz).
            tx_power_dbm: Transmit power in dBm (e.g., 14 for 14 dBm / 25 mW).
        """
        self._freq_hz = freq_hz
        self._tx_power_dbm = tx_power_dbm

    async def close(self) -> None:
        """Close the TCP connection to the simulator.

        Acquires the operation lock to ensure no in-flight operations
        are using the stream, preventing BrokenResourceError races.
        """
        async with self._lock:
            stream = self._stream
            if stream is not None:
                self._stream = None
                await stream.aclose()

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
        try:
            await self.close()
        except Exception:
            if exc_type is None:
                raise

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
                try:
                    if self._stream is not None:
                        await self._stream.aclose()
                finally:
                    self._stream = None
                raise ProtocolError("Received zero-length message")
            if msg_len > MAX_MESSAGE_LENGTH:
                try:
                    if self._stream is not None:
                        await self._stream.aclose()
                finally:
                    self._stream = None
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
                received = n - remaining
                raise SimRadioError(
                    f"Connection closed unexpectedly: received {received}/{n} bytes"
                )
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)
