"""
TCP transport for the legacy LICHEN Native CBOR protocol.

Current LCI sessions use IPv6 + CoAP from spec/11-lci.md. This module preserves
the historical spec/lichen-native TCP framing for simulator compatibility.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from lichen.interface.framing import FrameReader, frame
from lichen.interface.messages import Message, decode_message, encode_message

log = logging.getLogger(__name__)

# Type alias for message handler
MessageHandler = Callable[[Message], Awaitable[Message | None]]


@dataclass
class TcpConnection:
    """
    A single TCP connection using legacy LICHEN Native CBOR framing.

    Can be used as client or server-side connection.
    """

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    handler: MessageHandler | None = None
    _frame_reader: FrameReader = field(default_factory=FrameReader)
    _closed: bool = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def peername(self) -> tuple[str, int] | None:
        try:
            return self.writer.get_extra_info("peername")
        except Exception:
            return None

    async def send(self, msg: Message) -> None:
        """Send a message."""
        if self._closed:
            raise ConnectionError("connection closed")
        data = frame(encode_message(msg))
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self) -> Message | None:
        """
        Receive one message.

        Returns None on clean close.
        Raises ConnectionError on error.
        """
        while not self._closed:
            # Check buffer first
            for payload in self._frame_reader:
                return decode_message(payload)

            # Read more data
            try:
                chunk = await self.reader.read(4096)
            except (ConnectionError, asyncio.CancelledError):
                self._closed = True
                raise

            if not chunk:
                # Clean close
                self._closed = True
                return None

            self._frame_reader.feed(chunk)

        return None

    async def run(self) -> None:
        """
        Run receive loop, dispatching to handler.

        Stops on close or error.
        """
        if self.handler is None:
            raise ValueError("no handler set")

        try:
            while not self._closed:
                msg = await self.recv()
                if msg is None:
                    break

                response = await self.handler(msg)
                if response is not None:
                    await self.send(response)
        except ConnectionError:
            pass
        finally:
            await self.close()

    async def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


async def connect(
    host: str,
    port: int,
    handler: MessageHandler | None = None,
) -> TcpConnection:
    """
    Connect to a LICHEN Native TCP server.

    Args:
        host: Server hostname or IP
        port: Server port
        handler: Optional message handler for run() loop

    Returns:
        Connected TcpConnection
    """
    reader, writer = await asyncio.open_connection(host, port)
    return TcpConnection(reader=reader, writer=writer, handler=handler)


@dataclass
class TcpServer:
    """
    TCP server accepting LICHEN Native connections.

    Usage:
        async def handle(msg):
            return SomeResponse(...)

        server = await serve("localhost", 5684, handle)
        await server.wait_closed()
    """

    server: asyncio.Server
    handler: MessageHandler
    connections: list[TcpConnection] = field(default_factory=list)

    @property
    def address(self) -> tuple[str, int] | None:
        """Server's bound address."""
        sockets = self.server.sockets
        if sockets:
            return sockets[0].getsockname()[:2]
        return None

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new client connection."""
        conn = TcpConnection(reader=reader, writer=writer, handler=self.handler)
        self.connections.append(conn)
        peer = conn.peername
        log.debug("client connected: %s", peer)

        try:
            await conn.run()
        finally:
            if conn in self.connections:
                self.connections.remove(conn)
            log.debug("client disconnected: %s", peer)

    async def close(self) -> None:
        """Close server and all connections."""
        # Close all client connections
        for conn in list(self.connections):
            await conn.close()
        self.connections.clear()

        # Close server
        self.server.close()
        await self.server.wait_closed()

    async def wait_closed(self) -> None:
        """Wait for server to close."""
        await self.server.wait_closed()


async def serve(
    host: str,
    port: int,
    handler: MessageHandler,
) -> TcpServer:
    """
    Start a LICHEN Native TCP server.

    Args:
        host: Bind address (use "" or "0.0.0.0" for all interfaces)
        port: Port to listen on (0 for random)
        handler: Async function called for each message

    Returns:
        Running TcpServer
    """
    tcp_server = TcpServer(server=None, handler=handler)  # type: ignore

    server = await asyncio.start_server(
        tcp_server._handle_client,
        host,
        port,
    )
    tcp_server.server = server

    addr = tcp_server.address
    log.info(
        "LICHEN Native server listening on %s:%d",
        addr[0] if addr else "?",
        addr[1] if addr else 0,
    )

    return tcp_server
