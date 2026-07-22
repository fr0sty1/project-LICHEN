# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Renode bridge server."""

import asyncio
import struct
from collections.abc import Callable

import pytest

from lichen.sim.node import NodeState
from lichen.sim.renode_server import RenodeServer, start_renode_server
from lichen.sim.simulation import Simulation, TimeMode


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


async def _enter_rx_and_get_callbacks(
    sim: Simulation, writer: asyncio.StreamWriter
) -> tuple[Callable[..., None], Callable[[], None]]:
    """Enter RX and return the callbacks registered by the server."""
    from lichen.sim.protocol import encode_rx_enter

    await _send_message(writer, encode_rx_enter(0xFFFFFFFF))
    for _ in range(100):
        node = sim.get_node("renode-node")
        if node is not None and node.rx_callbacks is not None:
            return node.rx_callbacks
        await asyncio.sleep(0.001)
    raise AssertionError("RX callbacks were not registered")


async def _wait_for_disconnect(server: RenodeServer) -> None:
    """Wait until a RenodeServer releases its active writer."""
    for _ in range(100):
        if server._writer is None:
            return
        await asyncio.sleep(0.001)
    raise AssertionError("server did not release disconnected client")


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
async def test_stop_closes_active_client() -> None:
    """Stopping the server closes an active Renode connection."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    payload = b"connected"
    await _send_message(writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload)
    assert (await _read_message(reader))[0] == 0x11
    await _enter_rx_and_get_callbacks(sim, writer)
    node = sim.get_node("renode-node")
    assert node is not None
    assert node.rx_callbacks is not None

    await asyncio.wait_for(server.stop(), timeout=1)
    await asyncio.wait_for(server.stop(), timeout=1)

    assert node.state == NodeState.IDLE
    assert node.rx_callbacks is None
    assert not server._connection_tasks
    assert await asyncio.wait_for(reader.read(), timeout=1) == b""
    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_rejects_overlapping_client() -> None:
    """A second client cannot replace the active Renode connection."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)
    first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
    payload = b"first"
    await _send_message(
        first_writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload
    )
    assert (await _read_message(first_reader))[0] == 0x11

    second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
    assert await asyncio.wait_for(second_reader.read(), timeout=1) == b""

    await asyncio.wait_for(server.stop(), timeout=1)
    first_writer.close()
    second_writer.close()
    await first_writer.wait_closed()
    await second_writer.wait_closed()


@pytest.mark.asyncio
async def test_stale_rx_callback_does_not_reach_reconnected_client() -> None:
    """A callback from a disconnected client cannot target its replacement."""
    sim = Simulation("test", time_mode=TimeMode.REALTIME)
    server, port = await start_renode_server(sim, "renode-node", port=0)
    first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
    payload = b"first"
    await _send_message(
        first_writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload
    )
    assert (await _read_message(first_reader))[0] == 0x11
    _, stale_timeout = await _enter_rx_and_get_callbacks(sim, first_writer)
    first_writer.close()
    await first_writer.wait_closed()
    await _wait_for_disconnect(server)

    second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
    payload = b"second"
    await _send_message(
        second_writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload
    )
    assert (await _read_message(second_reader))[0] == 0x11

    stale_timeout()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(second_reader.read(1), timeout=0.05)

    await server.stop()
    second_writer.close()
    await second_writer.wait_closed()


@pytest.mark.asyncio
async def test_renode_on_rx_packet_callback() -> None:
    """Test _on_rx_packet callback sends RX_PACKET to client."""
    from lichen.sim.protocol import MSG_RX_PACKET, decode_rx_packet

    sim = Simulation("test", time_mode=TimeMode.REALTIME)
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        payload = b"connected"
        await _send_message(
            writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload
        )
        assert (await _read_message(reader))[0] == 0x11

        on_packet, _ = await _enter_rx_and_get_callbacks(sim, writer)
        on_packet(b"test payload", -80, 100)

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

    sim = Simulation("test", time_mode=TimeMode.REALTIME)
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        payload = b"connected"
        await _send_message(
            writer, bytes([0x10]) + struct.pack("<H", len(payload)) + payload
        )
        assert (await _read_message(reader))[0] == 0x11

        _, on_timeout = await _enter_rx_and_get_callbacks(sim, writer)
        on_timeout()

        # Client should receive RX_TIMEOUT_PUSH
        resp = await _read_message(reader)
        assert resp[0] == MSG_RX_TIMEOUT_PUSH
        assert len(resp) == 1  # Just the type byte

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_stale_callbacks_without_client_do_not_raise() -> None:
    """Stale callbacks are harmless after their client disconnects."""
    sim = Simulation("test", time_mode=TimeMode.REALTIME)
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        on_packet, on_timeout = await _enter_rx_and_get_callbacks(sim, writer)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.01)

        # Stale callbacks should not raise or target a later client.
        on_packet(b"test", -80, 100)
        on_timeout()
        # No exception = success
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_rx_enter_exit() -> None:
    """Test RX_ENTER and RX_EXIT message handling."""
    from lichen.sim.node import NodeState
    from lichen.sim.protocol import encode_rx_enter, encode_rx_exit
    from lichen.sim.simulation import TimeMode

    # Use REALTIME mode so background driver doesn't advance time instantly
    sim = Simulation("test", time_mode=TimeMode.REALTIME)
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
    from lichen.sim.protocol import encode_rx_enter, encode_rx_exit
    from lichen.sim.simulation import TimeMode

    # Use REALTIME mode so background driver doesn't advance time instantly
    sim = Simulation("test", time_mode=TimeMode.REALTIME)
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Enter RX mode
        rx_enter_msg = encode_rx_enter(10_000_000)  # 10 second timeout
        await _send_message(writer, rx_enter_msg)
        await asyncio.sleep(0.01)

        # Verify node is in RX_WAIT and callbacks are set
        node = sim.get_node("renode-node")
        assert node is not None
        assert node.state == NodeState.RX_WAIT
        assert node.rx_callbacks is not None
        assert callable(node.rx_callbacks[0])
        assert callable(node.rx_callbacks[1])

        # Exit RX mode to clean up
        await _send_message(writer, encode_rx_exit())
        await asyncio.sleep(0.01)

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_barrier_sync_packet_delivery() -> None:
    """Test BARRIER_SYNC mode: TX from one node delivers exactly once to RX node.

    In BARRIER_SYNC mode, time only advances when a node is in RX_WAIT.
    The test sequence is:
    1. TX node transmits (creates TxEndEvent)
    2. RX node enters RX mode
    3. Simulation advances time to TxEndEvent, then delivers packet
    """
    from lichen.sim.protocol import (
        MSG_RX_PACKET,
        decode_rx_packet,
        encode_rx_enter,
    )
    from lichen.sim.simulation import TimeMode

    # BARRIER_SYNC mode is the default, but be explicit
    sim = Simulation("test", time_mode=TimeMode.BARRIER_SYNC)

    # Create two Renode servers at different positions (close enough to receive)
    rx_server, rx_port = await start_renode_server(
        sim, "rx-node", port=0, position=(0.0, 0.0, 0.0)
    )
    tx_server, tx_port = await start_renode_server(
        sim, "tx-node", port=0, position=(100.0, 0.0, 0.0)  # 100m away
    )

    received_packets: list[tuple[bytes, int, int]] = []

    try:
        # Connect both clients
        rx_reader, rx_writer = await asyncio.open_connection("127.0.0.1", rx_port)
        tx_reader, tx_writer = await asyncio.open_connection("127.0.0.1", tx_port)
        await asyncio.sleep(0.01)

        # TX node transmits FIRST - this creates TxEndEvent in the queue
        # Time won't advance until an RX node enters RX_WAIT
        payload = b"test packet for barrier sync"
        tx_msg = bytes([0x10]) + struct.pack("<H", len(payload)) + payload
        await _send_message(tx_writer, tx_msg)

        # Read TX_DONE response
        tx_resp = await _read_message(tx_reader)
        assert tx_resp[0] == 0x11  # TX_DONE

        # Now RX node enters receive mode
        # The simulation driver will advance time to TxEndEvent, then deliver packet
        rx_enter_msg = encode_rx_enter(5_000_000)  # 5 second timeout
        await _send_message(rx_writer, rx_enter_msg)

        # Wait for RX_PACKET to arrive at the receiver
        try:
            rx_resp = await asyncio.wait_for(_read_message(rx_reader), timeout=2.0)
            assert rx_resp[0] == MSG_RX_PACKET
            pkt_payload, rssi, snr = decode_rx_packet(rx_resp[1:])
            received_packets.append((pkt_payload, rssi, snr))
        except TimeoutError:
            pytest.fail("RX_PACKET not received within timeout")

        # Verify exactly one packet received
        assert len(received_packets) == 1
        assert received_packets[0][0] == payload
        # RSSI should be negative (signal strength in dBm)
        assert received_packets[0][1] < 0
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(_read_message(rx_reader), timeout=0.05)

        tx_writer.close()
        rx_writer.close()
        await tx_writer.wait_closed()
        await rx_writer.wait_closed()
    finally:
        await tx_server.stop()
        await rx_server.stop()


@pytest.mark.asyncio
async def test_renode_rx_timeout_delivered() -> None:
    """Test that RX timeout fires and delivers RX_TIMEOUT_PUSH."""
    from lichen.sim.protocol import MSG_RX_TIMEOUT_PUSH, encode_rx_enter
    from lichen.sim.simulation import TimeMode

    sim = Simulation("test", time_mode=TimeMode.BARRIER_SYNC)
    server, port = await start_renode_server(sim, "rx-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.01)

        # Enter RX mode with a very short timeout (100us)
        rx_enter_msg = encode_rx_enter(100)
        await _send_message(writer, rx_enter_msg)

        # Wait for RX_TIMEOUT_PUSH - the simulation loop should fire the timeout
        try:
            resp = await asyncio.wait_for(_read_message(reader), timeout=2.0)
            assert resp[0] == MSG_RX_TIMEOUT_PUSH
        except TimeoutError:
            pytest.fail("RX_TIMEOUT_PUSH not received within timeout")

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()
