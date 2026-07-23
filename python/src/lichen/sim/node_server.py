# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TCP node server for LICHEN simulator.

This module provides a TCP server that accepts connections from SimRadio clients
and translates wire protocol messages into Simulation calls. Each client
connection represents a single simulated node.

Push-based RX (RX_ENTER/RX_EXIT) uses a background simulation driver task and
does not poll. The legacy poll-based MSG_RX handler still uses a 1ms polling
loop but is deprecated - SimRadio already uses push-based RX.

Long-term, this module should be unified with or replaced by RenodeServer.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from typing import TYPE_CHECKING

from lichen.sim.duty_cycle import DutyCycleTracker
from lichen.sim.protocol import (
    MAX_PAYLOAD_LENGTH,
    MSG_CAD,
    MSG_REGISTER,
    MSG_RX,
    MSG_RX_ENTER,
    MSG_RX_EXIT,
    MSG_TIME,
    MSG_TX,
    ProtocolError,
    decode_cad,
    decode_register,
    decode_rx,
    decode_rx_enter,
    decode_tx,
    encode_cad_result,
    encode_err,
    encode_ok,
    encode_rx_ok,
    encode_rx_packet,
    encode_rx_timeout,
    encode_rx_timeout_push,
    encode_time_ok,
    encode_tx_done,
    encode_tx_fail,
    get_message_payload,
    get_message_type,
)
from lichen.sim.transmission import airtime_us

if TYPE_CHECKING:
    from lichen.sim.pcap import PcapngWriter
    from lichen.sim.simulation import Simulation

logger = logging.getLogger(__name__)


async def read_message(reader: asyncio.StreamReader) -> bytes | None:
    """Read a length-prefixed message from the stream.

    Messages are framed with a 4-byte little-endian length prefix.

    Args:
        reader: The stream reader.

    Returns:
        The message bytes (without length prefix), or None on EOF.
    """
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


async def write_message(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Write a length-prefixed message to the stream.

    Args:
        writer: The stream writer.
        data: The message bytes to write.
    """
    writer.write(struct.pack("<I", len(data)) + data)
    await writer.drain()


class NodeServer:
    """TCP server that handles SimRadio client connections.

    Each client connection represents a simulated node. The server
    translates wire protocol messages into Simulation calls and
    manages duty cycle tracking and packet capture.

    Attributes:
        simulation: The Simulation instance to use.
        pcap_writer: Optional PcapngWriter for packet capture.
        duty_cycle_limit: Duty cycle limit percentage (default 1.0%).
    """

    def __init__(
        self,
        simulation: Simulation,
        pcap_writer: PcapngWriter | None = None,
        duty_cycle_limit: float = 1.0,
    ) -> None:
        """Initialize the node server.

        Args:
            simulation: The Simulation instance to use for all nodes.
            pcap_writer: Optional PcapngWriter for packet capture.
            duty_cycle_limit: Maximum duty cycle as percentage (e.g., 1.0 for 1%).
        """
        self._simulation = simulation
        self._pcap_writer = pcap_writer
        self._duty_cycle_limit = duty_cycle_limit
        self._duty_trackers: dict[str, DutyCycleTracker] = {}
        self._connections: dict[str, asyncio.StreamWriter] = {}
        self._sim_driver_task: asyncio.Task[None] | None = None

    async def _simulation_driver(self) -> None:
        """Background task that drives the simulation.

        Periodically calls deliver_pending_packets() and maybe_advance_time()
        to ensure push-based RX mode works without polling in handlers.
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

    def _ensure_simulation_driver(self) -> None:
        """Start the simulation driver task if not already running."""
        if self._sim_driver_task is None or self._sim_driver_task.done():
            self._sim_driver_task = asyncio.create_task(self._simulation_driver())

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection.

        Reads messages until the connection closes. The first message
        must be REGISTER to associate the connection with a node.

        Args:
            reader: The stream reader.
            writer: The stream writer.
        """
        peer = writer.get_extra_info("peername")
        logger.info("New connection from %s", peer)

        node_id: str | None = None

        try:
            # First message must be REGISTER
            data = await read_message(reader)
            if data is None:
                logger.warning("Connection from %s closed before REGISTER", peer)
                return

            try:
                msg_type = get_message_type(data)
            except ProtocolError as e:
                logger.error("Invalid message from %s: %s", peer, e)
                await write_message(writer, encode_err(1, str(e)))
                return

            if msg_type != MSG_REGISTER:
                logger.error(
                    "First message from %s must be REGISTER, got 0x%02x",
                    peer,
                    msg_type,
                )
                await write_message(
                    writer, encode_err(2, "First message must be REGISTER")
                )
                return

            node_id = await self._handle_register(data, writer)
            if node_id is None:
                return

            # Main message loop
            while True:
                data = await read_message(reader)
                if data is None:
                    logger.info("Connection closed for node %s", node_id)
                    break

                try:
                    msg_type = get_message_type(data)
                except ProtocolError as e:
                    logger.error("Invalid message from node %s: %s", node_id, e)
                    await write_message(writer, encode_err(1, str(e)))
                    continue

                if msg_type == MSG_TX:
                    await self._handle_tx(node_id, data, writer)
                elif msg_type == MSG_RX:
                    await self._handle_rx(node_id, data, writer)
                elif msg_type == MSG_RX_ENTER:
                    await self._handle_rx_enter(node_id, data, writer)
                elif msg_type == MSG_RX_EXIT:
                    self._handle_rx_exit(node_id)
                elif msg_type == MSG_TIME:
                    await self._handle_time(writer)
                elif msg_type == MSG_CAD:
                    await self._handle_cad(node_id, data, writer)
                else:
                    logger.warning(
                        "Unknown message type 0x%02x from node %s", msg_type, node_id
                    )
                    await write_message(
                        writer, encode_err(3, f"Unknown message type: 0x{msg_type:02x}")
                    )

        except ConnectionResetError:
            logger.info("Connection reset for node %s", node_id or peer)
        except Exception:
            logger.exception("Error handling connection for node %s", node_id or peer)
        finally:
            if node_id is not None:
                self._cleanup_node(node_id)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle_register(
        self,
        data: bytes,
        writer: asyncio.StreamWriter,
    ) -> str | None:
        """Handle a REGISTER message.

        Decodes the message, validates the simulation ID, adds the node
        to the simulation, and creates a duty cycle tracker.

        Args:
            data: The complete message bytes (including type byte).
            writer: The stream writer for responses.

        Returns:
            The node_id on success, None on error.
        """
        try:
            payload = get_message_payload(data)
            sim_id, node_id, x, y, z = decode_register(payload)
        except ProtocolError as e:
            logger.error("Failed to decode REGISTER: %s", e)
            await write_message(writer, encode_err(1, f"Invalid REGISTER: {e}"))
            return None

        # Validate simulation ID
        if sim_id != self._simulation.id:
            logger.error(
                "Simulation ID mismatch: expected %s, got %s",
                self._simulation.id,
                sim_id,
            )
            await write_message(
                writer,
                encode_err(4, f"Unknown simulation: {sim_id}"),
            )
            return None

        # Add node to simulation
        try:
            self._simulation.add_node(node_id, x, y, z)
        except ValueError as e:
            logger.error("Failed to add node %s: %s", node_id, e)
            await write_message(writer, encode_err(5, str(e)))
            return None

        # Create duty cycle tracker
        self._duty_trackers[node_id] = DutyCycleTracker(
            limit_percent=self._duty_cycle_limit
        )

        # Track connection
        self._connections[node_id] = writer

        # Ensure simulation driver is running for push-based RX
        self._ensure_simulation_driver()

        logger.info("Registered node %s at (%.1f, %.1f, %.1f)", node_id, x, y, z)
        await write_message(writer, encode_ok())
        return node_id

    async def _handle_tx(self,node_id: str,data: bytes,writer: asyncio.StreamWriter,) -> None:
        try:
            payload = get_message_payload(data)
            tx_payload, ch = decode_tx(payload)
        except ProtocolError as e:
            logger.error("Failed to decode TX from %s: %s", node_id, e)
            await write_message(writer, encode_err(1, f"Invalid TX: {e}"))
            return
        tx_airtime_us = airtime_us(len(tx_payload))
        current_time_us = self._simulation.current_time_us
        tracker = self._duty_trackers.get(node_id)
        if tracker is not None and not tracker.can_transmit(tx_airtime_us, current_time_us):
            logger.warning("Duty cycle exceeded for node %s", node_id)
            await write_message(writer, encode_tx_fail())
            return
        try:
            self._simulation.start_transmission(node_id, tx_payload, channel=ch)
        except ValueError as e:
            logger.error("Failed to start TX for %s: %s", node_id, e)
            await write_message(writer, encode_err(6, str(e)))
            return
        if tracker is not None:
            tracker.record_tx(tx_airtime_us, current_time_us)
        if self._pcap_writer is not None:
            self._pcap_writer.write_packet(timestamp_us=current_time_us,data=tx_payload,src_node=node_id)
        logger.debug("TX from %s: %d bytes, airtime %d us", node_id, len(tx_payload), tx_airtime_us)
        await write_message(writer, encode_tx_done(tx_airtime_us))

    async def _handle_rx(
        self,
        node_id: str,
        data: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an RX message (poll-based, deprecated).

        .. deprecated::
            This method uses a polling loop. New clients should use RX_ENTER
            (push-based) instead. SimRadio already uses RX_ENTER.

        Starts a receive operation in the simulation and waits for
        either a packet or timeout.

        Args:
            node_id: The receiving node's ID.
            data: The complete message bytes (including type byte).
            writer: The stream writer for responses.
        """
        try:
            payload = get_message_payload(data)
            timeout_ms = decode_rx(payload)
        except ProtocolError as e:
            logger.error("Failed to decode RX from %s: %s", node_id, e)
            await write_message(writer, encode_err(1, f"Invalid RX: {e}"))
            return

        # Start receive in simulation
        try:
            self._simulation.start_receive(node_id, timeout_ms)
        except ValueError as e:
            logger.error("Failed to start RX for %s: %s", node_id, e)
            await write_message(writer, encode_err(7, str(e)))
            return

        result = await self._await_rx_result(node_id, timeout_ms * 1000)

        # Clean up RX state and cancel pending timeout event
        self._simulation.exit_rx_mode(node_id)

        if result is not None:
            rx_payload, rssi, snr = result
            logger.debug(
                "RX at %s: %d bytes, RSSI %d, SNR %d",
                node_id,
                len(rx_payload),
                rssi,
                snr,
            )
            await write_message(writer, encode_rx_ok(rx_payload, rssi, snr))
        else:
            logger.debug("RX timeout at %s after %d ms", node_id, timeout_ms)
            await write_message(writer, encode_rx_timeout())

    async def _await_rx_result(
        self,
        node_id: str,
        timeout_us: int,
    ) -> tuple[bytes, int, int] | None:
        """Wait for a packet or timeout on a node already in RX_WAIT.

        .. deprecated::
            This method uses a 1ms polling loop. It is used by the deprecated
            MSG_RX handler. New code should use RX_ENTER with callbacks.

        Checks for a deliverable packet before advancing time so advancing
        can never skip an in-range reception (see maybe_advance_time).

        Args:
            node_id: The receiving node's ID.
            timeout_us: Receive timeout in microseconds.

        Returns:
            Tuple of (payload, rssi, snr), or None on timeout.
        """
        start_time_us = self._simulation.current_time_us
        while True:
            # Check for received packet
            result = self._simulation.get_rx_result(node_id)
            if result is not None:
                return result

            self._simulation.maybe_advance_time()

            # Check if we've timed out
            elapsed_us = self._simulation.current_time_us - start_time_us
            if elapsed_us >= timeout_us:
                return None

            # Brief delay before next check to avoid busy loop
            await asyncio.sleep(0.001)  # 1ms polling interval

    async def _handle_rx_enter(self,node_id: str,data: bytes,writer: asyncio.StreamWriter,) -> None:
        try:
            payload = get_message_payload(data)
            timeout_us, ch = decode_rx_enter(payload)
        except ProtocolError as e:
            logger.error("Failed to decode RX_ENTER from %s: %s", node_id, e)
            await write_message(writer, encode_err(1, f"Invalid RX_ENTER: {e}"))
            return
        rx_result: list[tuple[bytes, int, int] | None] = [None]
        rx_done = asyncio.Event()
        def on_packet(pkt_payload: bytes, rssi: int, snr: int) -> None:
            rx_result[0] = (pkt_payload, rssi, snr)
            rx_done.set()
        def on_timeout() -> None:
            rx_done.set()
        entered = False
        try:
            self._simulation.enter_rx_mode(
                node_id, timeout_us, on_packet, on_timeout, channel=ch
            )
            entered = True
        except ValueError as e:
            logger.error("Failed to enter RX mode for %s: %s", node_id, e)
            await write_message(writer, encode_err(7, str(e)))
            return
        try:
            await rx_done.wait()
            if rx_result[0] is not None:
                pkt_payload, rssi, snr = rx_result[0]
                logger.debug(
                    "RX_ENTER at %s: %d bytes, RSSI %d, SNR %d",
                    node_id,
                    len(pkt_payload),
                    rssi,
                    snr,
                )
                await write_message(writer, encode_rx_packet(pkt_payload, rssi, snr))
            else:
                logger.debug("RX_ENTER timeout at %s after %d us", node_id, timeout_us)
                await write_message(writer, encode_rx_timeout_push())
        finally:
            if entered:
                self._simulation.exit_rx_mode(node_id)

    def _handle_rx_exit(self, node_id: str) -> None:
        """Handle an RX_EXIT message.

        Exits push-based RX mode for the node.

        Args:
            node_id: The node ID to exit RX mode.
        """
        logger.debug("RX_EXIT from %s", node_id)
        self._simulation.exit_rx_mode(node_id)

    async def _handle_time(
        self,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a TIME message.

        Returns the current simulation time.

        Args:
            writer: The stream writer for responses.
        """
        time_us = self._simulation.current_time_us
        logger.debug("TIME query: %d us", time_us)
        await write_message(writer, encode_time_ok(time_us))

    async def _handle_cad(self,node_id: str,data: bytes,writer: asyncio.StreamWriter,) -> None:
        try:
            payload = get_message_payload(data)
            _, ch = decode_cad(payload)
        except ProtocolError as e:
            logger.error("Failed to decode CAD from %s: %s", node_id, e)
            await write_message(writer, encode_err(1, f"Invalid CAD: {e}"))
            return
        node = self._simulation.get_node(node_id)
        if node is None:
            logger.error("Node %s not found for CAD", node_id)
            await write_message(writer, encode_err(8, f"Node not found: {node_id}"))
            return
        current_time_us = self._simulation.current_time_us
        detected = self._simulation.medium.detect_activity(
            position=node.position, time_us=current_time_us, channel=ch
        )
        logger.debug("CAD at %s: detected=%s", node_id, detected)
        await write_message(writer, encode_cad_result(detected))

    def _cleanup_node(self, node_id: str) -> None:
        """Clean up resources for a disconnected node.

        Marks the node as disconnected and removes tracking data.

        Args:
            node_id: The node ID to clean up.
        """
        # Mark node disconnected in simulation
        node = self._simulation.get_node(node_id)
        if node is not None:
            node.disconnect()

        # Remove duty cycle tracker
        self._duty_trackers.pop(node_id, None)

        # Remove connection tracking
        self._connections.pop(node_id, None)

        logger.info("Cleaned up node %s", node_id)


async def start_node_server(
    simulation: Simulation,
    host: str = "127.0.0.1",
    port: int = 4444,
    pcap_writer: PcapngWriter | None = None,
    duty_cycle_limit: float = 1.0,
) -> asyncio.Server:
    """Start a TCP server for SimRadio client connections.

    Creates a NodeServer instance and starts an asyncio TCP server
    that routes connections to the NodeServer.

    Args:
        simulation: The Simulation instance to use.
        host: Host address to bind to. Defaults to "127.0.0.1".
        port: Port number to bind to. Defaults to 4444.
        pcap_writer: Optional PcapngWriter for packet capture.
        duty_cycle_limit: Maximum duty cycle as percentage (e.g., 1.0 for 1%).

    Returns:
        The asyncio.Server instance. Use `server.close()` and
        `await server.wait_closed()` to shut down.

    Example:
        >>> sim = Simulation("test-sim")
        >>> server = await start_node_server(sim, port=4445)
        >>> # ... run simulation ...
        >>> server.close()
        >>> await server.wait_closed()
    """
    node_server = NodeServer(
        simulation, pcap_writer=pcap_writer, duty_cycle_limit=duty_cycle_limit
    )

    server = await asyncio.start_server(
        node_server.handle_connection,
        host,
        port,
    )

    logger.info("Node server listening on %s:%d", host, port)
    return server
