"""Tests for LICHEN Native TCP transport."""

import asyncio
import contextlib

import pytest

from lichen.interface.messages import (
    ConfigGet,
    ConfigResult,
    Hello,
    MessageType,
    ResultCode,
)
from lichen.interface.tcp import TcpServer, connect, serve


@pytest.fixture
async def echo_server():
    """Server that echoes messages back."""

    async def handler(msg):
        return msg

    server = await serve("127.0.0.1", 0, handler)
    yield server
    await server.close()


@pytest.fixture
async def hello_server():
    """Server that responds to Hello with Hello."""

    async def handler(msg):
        if isinstance(msg, Hello):
            return Hello(
                version=1,
                supported=[MessageType.HELLO],
                firmware="test-server",
                iid=b"\x00" * 8,
            )
        return None

    server = await serve("127.0.0.1", 0, handler)
    yield server
    await server.close()


class TestTcpConnection:
    @pytest.mark.asyncio
    async def test_connect_send_recv(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            # Send a message
            msg = Hello(version=1, firmware="test-client")
            await conn.send(msg)

            # Receive echo
            response = await conn.recv()
            assert isinstance(response, Hello)
            assert response.firmware == "test-client"
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_multiple_messages(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            for i in range(5):
                msg = Hello(version=1, firmware=f"client-{i}")
                await conn.send(msg)
                response = await conn.recv()
                assert isinstance(response, Hello)
                assert response.firmware == f"client-{i}"
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_close(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        assert not conn.closed

        await conn.close()
        assert conn.closed

        # Double close is safe
        await conn.close()

    @pytest.mark.asyncio
    async def test_send_after_close(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        await conn.close()

        with pytest.raises(ConnectionError):
            await conn.send(Hello())

    @pytest.mark.asyncio
    async def test_peername(self, echo_server: TcpServer):
        """Connection reports peer address."""
        addr = echo_server.address
        assert addr is not None

        conn = await connect(addr[0], addr[1])
        try:
            peer = conn.peername
            assert peer is not None
            assert peer[0] == "127.0.0.1"
        finally:
            await conn.close()


class TestTcpServer:
    @pytest.mark.asyncio
    async def test_server_address(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None
        assert addr[0] == "127.0.0.1"
        assert addr[1] > 0

    @pytest.mark.asyncio
    async def test_multiple_clients(self, echo_server: TcpServer):
        addr = echo_server.address
        assert addr is not None

        # Connect multiple clients
        clients = []
        for _ in range(3):
            conn = await connect(addr[0], addr[1])
            clients.append(conn)

        try:
            # Each sends and receives
            for i, conn in enumerate(clients):
                msg = Hello(firmware=f"client-{i}")
                await conn.send(msg)
                response = await conn.recv()
                assert isinstance(response, Hello)
                assert response.firmware == f"client-{i}"
        finally:
            for conn in clients:
                await conn.close()

    @pytest.mark.asyncio
    async def test_server_close(self):
        async def handler(msg):
            return msg

        server = await serve("127.0.0.1", 0, handler)
        addr = server.address
        assert addr is not None

        # Connect a client
        conn = await connect(addr[0], addr[1])
        await asyncio.sleep(0.01)  # Let connection establish

        # Close server
        await server.close()

        # Client should detect close
        await asyncio.sleep(0.01)
        await conn.close()


class TestHandlerProtocol:
    @pytest.mark.asyncio
    async def test_handler_receives_correct_type(self):
        received = []

        async def handler(msg):
            received.append(msg)
            if isinstance(msg, ConfigGet):
                return ConfigResult(result=ResultCode.OK, values={1: 22})
            return None

        server = await serve("127.0.0.1", 0, handler)
        try:
            addr = server.address
            assert addr is not None

            conn = await connect(addr[0], addr[1])
            try:
                # Send ConfigGet
                await conn.send(ConfigGet())
                response = await conn.recv()

                assert len(received) == 1
                assert isinstance(received[0], ConfigGet)
                assert isinstance(response, ConfigResult)
                assert response.result == ResultCode.OK
            finally:
                await conn.close()
        finally:
            await server.close()

    @pytest.mark.asyncio
    async def test_handler_returns_none(self):
        """Handler returning None sends no response."""

        async def handler(msg):
            return None  # No response

        server = await serve("127.0.0.1", 0, handler)
        try:
            addr = server.address
            assert addr is not None

            conn = await connect(addr[0], addr[1])
            try:
                await conn.send(Hello())
                # No response expected, but connection stays open

                # Send another and close
                await conn.send(Hello())
            finally:
                await conn.close()
        finally:
            await server.close()


class TestConnectionRun:
    @pytest.mark.asyncio
    async def test_client_run_loop(self, hello_server: TcpServer):
        """Test client-side run() loop."""
        addr = hello_server.address
        assert addr is not None

        responses = []

        async def handler(msg):
            responses.append(msg)
            return None

        conn = await connect(addr[0], addr[1], handler=handler)

        # Send initial hello
        await conn.send(Hello(firmware="run-test"))

        # Run for a short time
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(conn.run(), timeout=0.1)

        await conn.close()

        # Should have received server's hello response
        assert len(responses) == 1
        assert isinstance(responses[0], Hello)
        assert responses[0].firmware == "test-server"
