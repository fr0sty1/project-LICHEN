# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TCP server for Renode SubGHz peripheral bridge.

Accepts a single connection from a Renode C# peripheral and translates
simple commands to simulation TX/RX operations. No REGISTER handshake -
node_id is fixed at server creation.

Protocol (length-prefixed, 4-byte LE):
    TX (0x10): 2-byte len + payload -> TX_DONE (0x11) with 4-byte airtime_us
    RX_ENTER (0x24): Enter RX mode with timeout -> RX_PACKET (0x27) or RX_TIMEOUT_PUSH (0x28)
    RX_EXIT (0x26): Exit RX mode
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from lichen.sim.protocol import (
    MAX_PAYLOAD_LENGTH,
    MSG_RX_ENTER,
    MSG_RX_EXIT,
    MSG_TX,
    decode_rx_enter,
    decode_tx,
    encode_rx_packet,
    encode_rx_timeout_push,
    encode_tx_done,
    encode_tx_fail,
    get_message_payload,
    get_message_type,
)
from lichen.sim.transmission import airtime_us

if TYPE_CHECKING:
    from collections.abc import Coroutine
    from lichen.sim.simulation import Simulation

logger = logging.getLogger(__name__)


async def _read_message(reader: asyncio.StreamReader) -> bytes | None:
    """Read length-prefixed message."""
    try:
        length_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack("<I", length_bytes)
    if length == 0:
        return b""
    # SECURITY: Reject oversized lengths to prevent memory exhaustion attacks.
    if length > MAX_PAYLOAD_LENGTH:
        return None
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None


async def _write_message(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Write length-prefixed message."""
    writer.write(struct.pack("<I", len(data)) + data)
    await writer.drain()


class RenodeServer:
    """TCP server bridging one Renode node to lichen-sim.

    Each RenodeServer handles exactly one node. Create multiple servers
    on different ports for multiple Renode instances.

    The server runs a background simulation driver task that periodically
    calls deliver_pending_packets() and maybe_advance_time(). This allows
    BARRIER_SYNC mode to work correctly even when multiple RenodeServers
    are operating concurrently.
    """

    def __init__(
        self,
        simulation: Simulation,
        node_id: str,
        position: tuple[float, float, float] = (0.0, 0.0, 0.0),
        tx_power_dbm: int = 22,
    ) -> None:
        self._simulation = simulation
        self._node_id = node_id
        self._position = position
        self._tx_power_dbm = tx_power_dbm
        self._server: asyncio.Server | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._stopping = False
        self._connected = False
        self._sim_driver_task: asyncio.Task[None] | None = None
        self._pending_tasks: set[asyncio.Task[None]] = set()
        self._connection_tasks: set[asyncio.Task[None]] = set()

    async def start(self, host: str = "127.0.0.1", port: int = 5555) -> int:
        """Start server and add node to simulation. Returns actual port."""
        self._stopping = False
        # Add node to simulation
        node = self._simulation.add_node(
            self._node_id,
            self._position[0],
            self._position[1],
            self._position[2],
        )
        node.tx_power_dbm = self._tx_power_dbm

        self._server = await asyncio.start_server(self._accept_connection, host, port)
        actual_port = int(self._server.sockets[0].getsockname()[1])
        logger.info(
            "Renode server for %s listening on %s:%d",
            self._node_id, host, actual_port
        )

        # Start simulation driver task
        self._sim_driver_task = asyncio.create_task(self._simulation_driver())

        return actual_port

    async def stop(self) -> None:
        """Stop server."""
        import contextlib

        self._stopping = True
        listener = self._server
        self._server = None
        if listener is not None:
            listener.close()

        if self._writer is not None:
            self._simulation.exit_rx_mode(self._node_id)
            self._writer.close()
            with contextlib.suppress(ConnectionError):
                await self._writer.wait_closed()

        if self._connection_tasks:
            await asyncio.gather(*self._connection_tasks, return_exceptions=True)

        if listener is not None:
            await listener.wait_closed()

        # Cancel simulation driver
        if self._sim_driver_task is not None:
            self._sim_driver_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sim_driver_task
            self._sim_driver_task = None

        # Cancel pending background tasks
        for task in list(self._pending_tasks):
            task.cancel()
        if self._pending_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*self._pending_tasks, return_exceptions=True)
        self._pending_tasks.clear()

        self._writer = None
        self._connected = False

    def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Start and track one connection handler."""
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._connection_tasks.add(task)
        task.add_done_callback(self._connection_tasks.discard)

    async def _simulation_driver(self) -> None:
        """Background task that drives the simulation.

        Periodically calls deliver_pending_packets() and maybe_advance_time()
        to ensure BARRIER_SYNC mode advances time and delivers packets.
        """
        try:
            while True:
                self._simulation.deliver_pending_packets()
                self._simulation.maybe_advance_time()
                await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Simulation driver error")
            raise

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle Renode connection."""
        if self._stopping or self._writer is not None:
            writer.close()
            await writer.wait_closed()
            return

        peer = writer.get_extra_info("peername")
        logger.info("Renode connected from %s for node %s", peer, self._node_id)
        self._connected = True
        self._writer = writer

        try:
            while True:
                data = await _read_message(reader)
                if data is None:
                    break

                msg_type = get_message_type(data)

                if msg_type == MSG_TX:
                    await self._handle_tx(data, writer)
                elif msg_type == MSG_RX_ENTER:
                    self._handle_rx_enter(data, writer)
                elif msg_type == MSG_RX_EXIT:
                    self._handle_rx_exit()
                else:
                    logger.warning("Unknown message 0x%02x from Renode", msg_type)

        except Exception:
            logger.exception("Error in Renode connection")
        finally:
            if self._writer is writer:
                self._simulation.exit_rx_mode(self._node_id)
                self._connected = False
                self._writer = None
            writer.close()

    async def _handle_tx(self, data: bytes, writer: asyncio.StreamWriter) -> None:
        try:
            tx_payload, ch = decode_tx(get_message_payload(data))
        except Exception as e:
            logger.error("Bad TX message: %s", e)
            await _write_message(writer, encode_tx_fail())
            return

        try:
            self._simulation.start_transmission(
                self._node_id, tx_payload, channel=ch
            )
        except ValueError as e:
            logger.error("TX failed: %s", e)
            await _write_message(writer, encode_tx_fail())
            return

        tx_airtime = airtime_us(len(tx_payload))
        logger.debug(
            "Renode TX: %d bytes, airtime %d us, ch=%d", len(tx_payload), tx_airtime, ch
        )
        await _write_message(writer, encode_tx_done(tx_airtime))

    def _handle_rx_enter(self, data: bytes, writer: asyncio.StreamWriter) -> None:
        timeout_us, ch = decode_rx_enter(get_message_payload(data))
        logger.debug(
            "Renode RX_ENTER: node=%s timeout_us=%d ch=%d",
            self._node_id,
            timeout_us,
            ch,
        )
        self._simulation.enter_rx_mode(
            self._node_id,
            timeout_us,
            lambda payload, rssi, snr: self._on_rx_packet(
                writer, payload, rssi, snr
            ),
            lambda: self._on_rx_timeout(writer),
            channel=ch,
        )

    def _handle_rx_exit(self) -> None:
        """Handle RX_EXIT - exit push-based RX mode."""
        logger.debug("Renode RX_EXIT: node=%s", self._node_id)
        self._simulation.exit_rx_mode(self._node_id)

    async def push_to_renode(self, data: bytes) -> None:
        """Push unsolicited message to Renode.

        Args:
            data: Protocol message to send (already encoded).

        Raises:
            RuntimeError: If no Renode client is connected.
        """
        if self._writer is None:
            raise RuntimeError("No Renode client connected")
        await _write_message(self._writer, data)

    async def _push_to_writer(
        self, writer: asyncio.StreamWriter, data: bytes
    ) -> None:
        """Push data only if writer still owns the active connection."""
        if self._writer is writer:
            await _write_message(writer, data)

    def _create_background_task(self, coro: Coroutine[None, None, None]) -> None:
        """Create a tracked background task with exception handling.

        The task is added to _pending_tasks and automatically removed when done.
        Exceptions are logged rather than left unhandled.
        """
        task = asyncio.create_task(coro)
        self._pending_tasks.add(task)

        def on_done(t: asyncio.Task[None]) -> None:
            self._pending_tasks.discard(t)
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                logger.debug(
                    "Background task failed for %s: %s", self._node_id, exc
                )

        task.add_done_callback(on_done)

    def _on_rx_packet(
        self, writer: asyncio.StreamWriter, payload: bytes, rssi: int, snr: int
    ) -> None:
        """Callback for push-based packet arrival.

        Schedules an unsolicited RX_PACKET message to Renode.

        Args:
            payload: Received packet data.
            rssi: Received signal strength in dBm.
            snr: Signal-to-noise ratio in dB * 10.
        """
        if self._writer is not writer:
            logger.warning("RX packet but no Renode connected for %s", self._node_id)
            return
        msg = encode_rx_packet(payload, rssi, snr)
        self._create_background_task(self._push_to_writer(writer, msg))

    def _on_rx_timeout(self, writer: asyncio.StreamWriter) -> None:
        """Callback for push-based RX timeout.

        Schedules an unsolicited RX_TIMEOUT_PUSH message to Renode.
        """
        if self._writer is not writer:
            logger.warning("RX timeout but no Renode connected for %s", self._node_id)
            return
        msg = encode_rx_timeout_push()
        self._create_background_task(self._push_to_writer(writer, msg))


async def start_renode_server(
    simulation: Simulation,
    node_id: str,
    host: str = "127.0.0.1",
    port: int = 0,  # 0 = auto-assign
    position: tuple[float, float, float] = (0.0, 0.0, 0.0),
    tx_power_dbm: int = 22,
) -> tuple[RenodeServer, int]:
    """Start a Renode bridge server for a single node.

    Returns (server, port) tuple.
    """
    server = RenodeServer(simulation, node_id, position, tx_power_dbm)
    actual_port = await server.start(host, port)
    return server, actual_port
