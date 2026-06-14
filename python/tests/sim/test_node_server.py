"""Tests for the NodeServer TCP server."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from lichen.sim.node_server import (
    read_message,
    start_node_server,
    write_message,
)
from lichen.sim.pcap import PcapngWriter
from lichen.sim.protocol import (
    MSG_ERR,
    MSG_OK,
    MSG_RX_OK,
    MSG_RX_TIMEOUT,
    MSG_TIME_OK,
    MSG_TX_DONE,
    MSG_TX_FAIL,
    decode_err,
    decode_rx_ok,
    decode_time_ok,
    decode_tx_done,
    encode_register,
    encode_rx,
    encode_time,
    encode_tx,
    get_message_payload,
    get_message_type,
)
from lichen.sim.simulation import Simulation
from lichen.sim.transmission import airtime_us


async def send_and_receive(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    data: bytes,
) -> bytes:
    """Send a message and read the response."""
    await write_message(writer, data)
    response = await read_message(reader)
    assert response is not None
    return response


class TestMessageFraming:
    """Test length-prefixed message framing."""

    @pytest.mark.asyncio
    async def test_read_write_message(self) -> None:
        """Messages can be written and read back with framing."""
        # Use a simple echo server to test framing
        test_data = b"hello world"
        received_data: list[bytes] = []

        async def echo_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await read_message(reader)
            if data is not None:
                received_data.append(data)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])
            await write_message(writer, test_data)
            writer.close()
            await writer.wait_closed()

            # Give server time to process
            await asyncio.sleep(0.05)

            assert len(received_data) == 1
            assert received_data[0] == test_data
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_read_empty_message(self) -> None:
        """Empty messages can be sent and received."""
        received_data: list[bytes] = []

        async def echo_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            data = await read_message(reader)
            if data is not None:
                received_data.append(data)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])
            await write_message(writer, b"")
            writer.close()
            await writer.wait_closed()

            # Give server time to process
            await asyncio.sleep(0.05)

            assert len(received_data) == 1
            assert received_data[0] == b""
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_read_message_eof(self) -> None:
        """read_message returns None on EOF."""
        # Create a StreamReader and feed it no data
        reader = asyncio.StreamReader()
        reader.feed_eof()

        received = await read_message(reader)
        assert received is None


class TestNodeServerRegister:
    """Test REGISTER message handling."""

    @pytest.mark.asyncio
    async def test_register_success(self) -> None:
        """Node can register successfully."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Send REGISTER
            register_msg = encode_register("test-sim", "node1", 10.0, 20.0, 5.0)
            response = await send_and_receive(reader, writer, register_msg)

            # Should get OK
            assert get_message_type(response) == MSG_OK

            # Node should be in simulation
            node = sim.get_node("node1")
            assert node is not None
            assert node.position == (10.0, 20.0, 5.0)
            assert node.connected is True

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_register_wrong_simulation_id(self) -> None:
        """REGISTER with wrong simulation ID returns error."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Send REGISTER with wrong sim_id
            register_msg = encode_register("wrong-sim", "node1", 0.0, 0.0, 0.0)
            response = await send_and_receive(reader, writer, register_msg)

            # Should get ERR
            assert get_message_type(response) == MSG_ERR
            code, msg = decode_err(get_message_payload(response))
            assert code == 4
            assert "wrong-sim" in msg

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_register_duplicate_node_id(self) -> None:
        """REGISTER with duplicate node ID returns error."""
        sim = Simulation("test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)  # Pre-existing node

        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            response = await send_and_receive(reader, writer, register_msg)

            assert get_message_type(response) == MSG_ERR
            code, msg = decode_err(get_message_payload(response))
            assert code == 5
            assert "already exists" in msg

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_first_message_must_be_register(self) -> None:
        """First message must be REGISTER."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Send TX without registering first
            tx_msg = encode_tx(b"hello")
            response = await send_and_receive(reader, writer, tx_msg)

            assert get_message_type(response) == MSG_ERR
            code, msg = decode_err(get_message_payload(response))
            assert code == 2
            assert "REGISTER" in msg

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


class TestNodeServerTx:
    """Test TX message handling."""

    @pytest.mark.asyncio
    async def test_tx_success(self) -> None:
        """TX message succeeds and returns airtime."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Register first
            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await send_and_receive(reader, writer, register_msg)

            # Send TX
            payload = b"test payload"
            expected_airtime = airtime_us(len(payload))
            tx_msg = encode_tx(payload)
            response = await send_and_receive(reader, writer, tx_msg)

            assert get_message_type(response) == MSG_TX_DONE
            actual_airtime = decode_tx_done(get_message_payload(response))
            assert actual_airtime == expected_airtime

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tx_duty_cycle_exceeded(self) -> None:
        """TX fails when duty cycle is exceeded."""
        sim = Simulation("test-sim")
        # Set very low duty cycle limit (0.001%) so any TX exceeds it
        server = await start_node_server(sim, port=0, duty_cycle_limit=0.0001)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Register
            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await send_and_receive(reader, writer, register_msg)

            # First TX - may or may not succeed depending on timing
            tx_msg = encode_tx(b"first")
            await send_and_receive(reader, writer, tx_msg)

            # Second TX should exceed duty cycle
            tx_msg = encode_tx(b"second packet with longer payload")
            response = await send_and_receive(reader, writer, tx_msg)

            # Either TX_DONE or TX_FAIL depending on first TX
            # With 0.0001% limit and 3600s window, max airtime is ~36us
            # LoRa SF10 airtime is much larger, so second should fail
            assert get_message_type(response) == MSG_TX_FAIL

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tx_with_pcap_writer(self) -> None:
        """TX writes packet to pcap file."""
        sim = Simulation("test-sim")

        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            pcap_path = Path(f.name)

        try:
            with PcapngWriter(pcap_path) as pcap:
                server = await start_node_server(sim, port=0, pcap_writer=pcap)
                addr = server.sockets[0].getsockname()

                reader, writer = await asyncio.open_connection(addr[0], addr[1])

                # Register and TX
                register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
                await send_and_receive(reader, writer, register_msg)

                tx_msg = encode_tx(b"captured packet")
                await send_and_receive(reader, writer, tx_msg)

                writer.close()
                await writer.wait_closed()

                server.close()
                await server.wait_closed()

            # Verify pcap file was written
            assert pcap_path.stat().st_size > 0
        finally:
            pcap_path.unlink(missing_ok=True)


class TestNodeServerRx:
    """Test RX message handling."""

    @pytest.mark.asyncio
    async def test_rx_timeout(self) -> None:
        """RX times out when no transmission."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Register
            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await send_and_receive(reader, writer, register_msg)

            # RX with timeout
            rx_msg = encode_rx(100)  # 100ms timeout
            response = await send_and_receive(reader, writer, rx_msg)

            assert get_message_type(response) == MSG_RX_TIMEOUT

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_rx_receives_packet(self) -> None:
        """RX receives a transmitted packet."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            # Connect two nodes
            reader1, writer1 = await asyncio.open_connection(addr[0], addr[1])
            reader2, writer2 = await asyncio.open_connection(addr[0], addr[1])

            # Register both nodes at different positions
            reg1 = encode_register("test-sim", "tx_node", 0.0, 0.0, 0.0)
            reg2 = encode_register("test-sim", "rx_node", 100.0, 0.0, 0.0)
            await send_and_receive(reader1, writer1, reg1)
            await send_and_receive(reader2, writer2, reg2)

            # TX node transmits
            payload = b"hello from tx"
            tx_msg = encode_tx(payload)
            await send_and_receive(reader1, writer1, tx_msg)

            # RX node receives
            rx_msg = encode_rx(1000)  # 1s timeout
            response = await send_and_receive(reader2, writer2, rx_msg)

            assert get_message_type(response) == MSG_RX_OK
            rx_payload, rssi, snr = decode_rx_ok(get_message_payload(response))
            assert rx_payload == payload
            assert rssi < 0  # RSSI is negative dBm
            assert snr > 0  # SNR is positive

            writer1.close()
            writer2.close()
            await writer1.wait_closed()
            await writer2.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


class TestNodeServerTime:
    """Test TIME message handling."""

    @pytest.mark.asyncio
    async def test_time_query(self) -> None:
        """TIME query returns current simulation time."""
        sim = Simulation("test-sim")
        sim.advance_to(1_000_000)  # 1 second

        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Register
            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await send_and_receive(reader, writer, register_msg)

            # Query time
            time_msg = encode_time()
            response = await send_and_receive(reader, writer, time_msg)

            assert get_message_type(response) == MSG_TIME_OK
            time_us = decode_time_ok(get_message_payload(response))
            assert time_us == 1_000_000

            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


class TestNodeServerCleanup:
    """Test connection cleanup behavior."""

    @pytest.mark.asyncio
    async def test_disconnect_cleanup(self) -> None:
        """Node is marked disconnected when connection closes."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            reader, writer = await asyncio.open_connection(addr[0], addr[1])

            # Register
            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await send_and_receive(reader, writer, register_msg)

            node = sim.get_node("node1")
            assert node is not None
            assert node.connected is True

            # Close connection
            writer.close()
            await writer.wait_closed()

            # Give server time to clean up
            await asyncio.sleep(0.1)

            # Node should be disconnected
            assert node.connected is False

        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_multiple_connections(self) -> None:
        """Server handles multiple simultaneous connections."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)
        addr = server.sockets[0].getsockname()

        try:
            # Connect multiple nodes
            connections = []
            for i in range(3):
                reader, writer = await asyncio.open_connection(addr[0], addr[1])
                connections.append((reader, writer))

                register_msg = encode_register("test-sim", f"node{i}", float(i * 10), 0.0, 0.0)
                await send_and_receive(reader, writer, register_msg)

            # All nodes should be registered
            assert sim.get_connected_node_count() == 3

            # Clean up
            for _reader, writer in connections:
                writer.close()
                await writer.wait_closed()

        finally:
            server.close()
            await server.wait_closed()


class TestStartNodeServer:
    """Test the start_node_server helper function."""

    @pytest.mark.asyncio
    async def test_start_server_default_address(self) -> None:
        """Server starts with default address."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, port=0)

        try:
            addr = server.sockets[0].getsockname()
            assert addr[0] == "127.0.0.1"
            assert addr[1] > 0  # Assigned port
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_start_server_custom_address(self) -> None:
        """Server starts with custom address."""
        sim = Simulation("test-sim")
        server = await start_node_server(sim, host="127.0.0.1", port=0)

        try:
            addr = server.sockets[0].getsockname()
            assert addr[0] == "127.0.0.1"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_unknown_kwarg_rejected(self) -> None:
        """Unknown keyword args are now a TypeError, not silently dropped."""
        sim = Simulation("test-sim")
        with pytest.raises(TypeError):
            await start_node_server(sim, port=0, bogus_option=123)
