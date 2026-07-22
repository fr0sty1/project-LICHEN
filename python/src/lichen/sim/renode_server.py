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
        self._connected = False
        self._sim_driver_task: asyncio.Task[None] | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 5555) -> int:
        """Start server and add node to simulation. Returns actual port."""
        # Add node to simulation
        node = self._simulation.add_node(
            self._node_id,
            self._position[0],
            self._position[1],
            self._position[2],
        )
        node.tx_power_dbm = self._tx_power_dbm

        self._server = await asyncio.start_server(
            self._handle_connection, host, port
        )
        actual_port = self._server.sockets[0].getsockname()[1]
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

        # Cancel simulation driver
        if self._sim_driver_task is not None:
            self._sim_driver_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sim_driver_task
            self._sim_driver_task = None

        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _simulation_driver(self) -> None:
        """Background task that drives the simulation.

        Periodically calls deliver_pending_packets() and maybe_advance_time()
        to ensure BARRIER_SYNC mode advances time and delivers packets.
        """
        try:
            while True:
                # Deliver packets to nodes in callback-based RX mode
                self._simulation.deliver_pending_packets()
                # Advance time (fires TxEndEvent, RxTimeoutEvent)
                self._simulation.maybe_advance_time()
                # Brief delay to avoid busy loop
                await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            if not isinstance(exc, (KeyboardInterrupt, SystemExit)):
                logger.exception("Error in simulation driver")
            raise

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle Renode connection."""
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
                    self._handle_rx_enter(data)
                elif msg_type == MSG_RX_EXIT:
                    self._handle_rx_exit()
                else:
                    logger.warning("Unknown message 0x%02x from Renode", msg_type)

        except Exception:
            logger.exception("Error in Renode connection")
        finally:
            self._connected = False
            self._writer = None
            writer.close()

    async def _handle_tx(self, data: bytes, writer: asyncio.StreamWriter) -> None:
        """Handle TX request from Renode."""
        try:
            payload = decode_tx(get_message_payload(data))
        except Exception as e:
            logger.error("Bad TX message: %s", e)
            await _write_message(writer, encode_tx_fail())
            return

        try:
            self._simulation.start_transmission(self._node_id, payload)
        except ValueError as e:
            logger.error("TX failed: %s", e)
            await _write_message(writer, encode_tx_fail())
            return

        tx_airtime = airtime_us(len(payload))
        logger.debug("Renode TX: %d bytes, airtime %d us", len(payload), tx_airtime)
        await _write_message(writer, encode_tx_done(tx_airtime))

    def _handle_rx_enter(self, data: bytes) -> None:
        """Handle RX_ENTER - enter push-based RX mode.

        Enters RX mode with callbacks. The background simulation driver task
        handles time advancement and packet delivery.

        Args:
            data: Complete message bytes including type byte.
        """
        timeout_us = decode_rx_enter(get_message_payload(data))
        logger.debug(
            "Renode RX_ENTER: node=%s timeout_us=%d", self._node_id, timeout_us
        )
        self._simulation.enter_rx_mode(
            self._node_id,
            timeout_us,
            self._on_rx_packet,
            self._on_rx_timeout,
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

    def _on_rx_packet(self, payload: bytes, rssi: int, snr: int) -> None:
        """Callback for push-based packet arrival.

        Schedules an unsolicited RX_PACKET message to Renode.

        Args:
            payload: Received packet data.
            rssi: Received signal strength in dBm.
            snr: Signal-to-noise ratio in dB * 10.
        """
        if self._writer is None:
            logger.warning("RX packet but no Renode connected for %s", self._node_id)
            return
        msg = encode_rx_packet(payload, rssi, snr)
        asyncio.create_task(self.push_to_renode(msg))

    def _on_rx_timeout(self) -> None:
        """Callback for push-based RX timeout.

        Schedules an unsolicited RX_TIMEOUT_PUSH message to Renode.
        """
        if self._writer is None:
            logger.warning("RX timeout but no Renode connected for %s", self._node_id)
            return
        msg = encode_rx_timeout_push()
        asyncio.create_task(self.push_to_renode(msg))


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
