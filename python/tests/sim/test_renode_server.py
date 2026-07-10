# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Renode bridge server."""

import asyncio
import struct

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation


async def _send_message(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Send length-prefixed message."""
    writer.write(struct.pack("<I", len(data)) + data)
    await writer.drain()


async def _read_message(reader: asyncio.StreamReader) -> bytes:
    """Read length-prefixed message."""
    length_bytes = await reader.readexactly(4)
    (length,) = struct.unpack("<I", length_bytes)
    if length == 0:
        return b""
    return await reader.readexactly(length)


@pytest.mark.asyncio
async def test_renode_tx_basic() -> None:
    """Test TX from mock Renode client."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send TX: type(0x10) + len(2) + payload
        payload = b"hello from renode"
        tx_msg = bytes([0x10]) + struct.pack("<H", len(payload)) + payload
        await _send_message(writer, tx_msg)

        # Read TX_DONE response
        resp = await _read_message(reader)
        assert resp[0] == 0x11  # TX_DONE
        airtime = struct.unpack("<I", resp[1:5])[0]
        assert airtime > 0

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_rx_poll_empty() -> None:
    """Test RX poll returns empty when no packets."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send RX_POLL: type(0x20)
        await _send_message(writer, bytes([0x20]))

        # Read RX_EMPTY response
        resp = await _read_message(reader)
        assert resp[0] == 0x23  # RX_EMPTY

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_push_to_renode() -> None:
    """Test pushing unsolicited messages to Renode."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Wait briefly for connection to be established
        await asyncio.sleep(0.01)

        # Push a message to Renode
        test_data = bytes([0x99, 0x01, 0x02, 0x03])
        await server.push_to_renode(test_data)

        # Client should receive it
        resp = await _read_message(reader)
        assert resp == test_data

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_push_no_client_raises() -> None:
    """Test that push_to_renode raises when no client connected."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        # No client connected - should raise
        with pytest.raises(RuntimeError, match="No Renode client connected"):
            await server.push_to_renode(b"test")
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_on_rx_packet_callback() -> None:
    """Test _on_rx_packet callback sends RX_PACKET to client."""
    from lichen.sim.protocol import MSG_RX_PACKET, decode_rx_packet

    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Trigger the callback
        server._on_rx_packet(b"test payload", -80, 100)

        # Client should receive RX_PACKET
        resp = await _read_message(reader)
        assert resp[0] == MSG_RX_PACKET
        payload, rssi, snr = decode_rx_packet(resp[1:])
        assert payload == b"test payload"
        assert rssi == -80
        assert snr == 100

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_on_rx_timeout_callback() -> None:
    """Test _on_rx_timeout callback sends RX_TIMEOUT_PUSH to client."""
    from lichen.sim.protocol import MSG_RX_TIMEOUT_PUSH

    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Trigger the callback
        server._on_rx_timeout()

        # Client should receive RX_TIMEOUT_PUSH
        resp = await _read_message(reader)
        assert resp[0] == MSG_RX_TIMEOUT_PUSH
        assert len(resp) == 1  # Just the type byte

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_callbacks_no_client_logged() -> None:
    """Test callbacks log warning when no client connected."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        # No client connected - callbacks should not raise, just log
        server._on_rx_packet(b"test", -80, 100)
        server._on_rx_timeout()
        # No exception = success
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_rx_enter_exit() -> None:
    """Test RX_ENTER and RX_EXIT message handling."""
    from lichen.sim.node import NodeState
    from lichen.sim.protocol import encode_rx_enter, encode_rx_exit

    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Verify node starts IDLE
        node = sim.get_node("renode-node")
        assert node is not None
        assert node.state == NodeState.IDLE

        # Send RX_ENTER with 1 second timeout (1_000_000 us)
        rx_enter_msg = encode_rx_enter(1_000_000)
        await _send_message(writer, rx_enter_msg)
        await asyncio.sleep(0.01)

        # Verify node enters RX_WAIT state
        assert node.state == NodeState.RX_WAIT

        # Send RX_EXIT
        rx_exit_msg = encode_rx_exit()
        await _send_message(writer, rx_exit_msg)
        await asyncio.sleep(0.01)

        # Verify node returns to IDLE
        assert node.state == NodeState.IDLE

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_rx_enter_sets_callbacks() -> None:
    """Test that RX_ENTER properly registers callbacks with simulation."""
    from lichen.sim.node import NodeState
    from lichen.sim.protocol import encode_rx_enter

    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Enter RX mode
        rx_enter_msg = encode_rx_enter(1_000_000)
        await _send_message(writer, rx_enter_msg)
        await asyncio.sleep(0.01)

        # Verify node is in RX_WAIT and callbacks are set
        node = sim.get_node("renode-node")
        assert node is not None
        assert node.state == NodeState.RX_WAIT
        assert node.rx_callbacks is not None
        # Callbacks should be the server's methods
        assert node.rx_callbacks[0] == server._on_rx_packet
        assert node.rx_callbacks[1] == server._on_rx_timeout

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()
