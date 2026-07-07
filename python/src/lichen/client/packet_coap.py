# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""ResourceTransport adapter for CoAP over packet LCI links."""

from __future__ import annotations

import asyncio
import contextvars
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv6Address
from typing import Any, TypeVar

from lichen.client.ip_coap import AiocoapResourceTransport, CoapTransportError, IpCoapConfig
from lichen.client.lci import ResourceSubscription, ResourceTransport
from lichen.client.model import CoapResult
from lichen.client.transport import PacketTransport
from lichen.coap.schc_channel import DEFAULT_COAP_PORT, unwrap_coap, wrap_coap
from lichen.coap.transport import DatagramChannel, ReceiveCallback, create_lichen_context
from lichen.ipv6.packet import IPv6Packet, NextHeader
from lichen.ipv6.udp import UdpDatagram, udp_checksum

logger = logging.getLogger(__name__)
_SEND_SCOPE: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "packet_coap_send_scope",
    default=None,
)
_T = TypeVar("_T")


@dataclass(frozen=True)
class PacketCoapConfig:
    """Connection settings for packet-backed local CoAP LCI."""

    local_host: str = "fe80::2"
    peer_host: str = "fe80::1"
    timeout_s: float = 10.0
    src_port: int = DEFAULT_COAP_PORT
    dst_port: int = DEFAULT_COAP_PORT

    @property
    def base_uri(self) -> str:
        """Return the peer CoAP URI used by the shared LCI client."""
        return f"coap://[{self.peer_host}]"


class PacketCoapResourceTransport(ResourceTransport):
    """Run LCI ResourceTransport requests over a packet transport.

    The underlying packet transport carries IPv6 packets, as exposed by BLE
    SLIP-over-GATT. This adapter frames aiocoap datagrams as IPv6/UDP packets
    and delegates request/observe behavior to the same aiocoap-backed client
    path used for direct IP transports.
    """

    def __init__(
        self,
        packet_transport: PacketTransport,
        *,
        config: PacketCoapConfig | None = None,
    ) -> None:
        self.packet_transport = packet_transport
        self.config = config or PacketCoapConfig()
        self._channel: PacketDatagramChannel | None = None
        self._resource_transport: AiocoapResourceTransport | None = None

    async def connect(self) -> None:
        """Open the packet link and construct an aiocoap context over it."""
        if self._resource_transport is not None:
            return
        await self.packet_transport.connect()
        channel = PacketDatagramChannel(
            self.packet_transport,
            self.config.local_host,
            src_port=self.config.src_port,
            dst_port=self.config.dst_port,
        )
        channel.start()
        self._channel = channel
        self._resource_transport = AiocoapResourceTransport(
            config=IpCoapConfig(base_uri=self.config.base_uri, timeout_s=self.config.timeout_s),
            context_factory=lambda: create_lichen_context(channel, self.config.local_host),
        )
        try:
            await self._resource_transport.connect()
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Close the CoAP context and underlying packet transport."""
        transport = self._resource_transport
        self._resource_transport = None
        if transport is not None:
            with suppress(Exception):
                await transport.close()
        channel = self._channel
        self._channel = None
        if channel is not None:
            await channel.aclose()
        else:
            with suppress(Exception):
                await self.packet_transport.close()

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        """Perform one CoAP request over the packet link."""
        return await self._run_with_send_scope(
            self._require_transport().request(
                method,
                path,
                payload=payload,
                content_format=content_format,
                observe=observe,
            )
        )

    async def observe(self, path: str, *, method: str = "GET") -> ResourceSubscription:
        """Start an Observe subscription over the packet link."""
        channel = self._require_channel()
        scope = PacketSendScope(channel)
        with scope:
            observe_task = asyncio.create_task(
                self._require_transport().observe(path, method=method)
            )
        subscription = await self._race_send_failure(observe_task, scope)
        return PacketCoapResourceSubscription(
            subscription,
            channel,
            scope,
            on_send_failure=self.close,
        )

    def _require_transport(self) -> AiocoapResourceTransport:
        if self._resource_transport is None:
            raise CoapTransportError("packet CoAP transport is not connected")
        return self._resource_transport

    def _require_channel(self) -> PacketDatagramChannel:
        if self._channel is None:
            raise CoapTransportError("packet CoAP transport is not connected")
        return self._channel

    async def _run_with_send_scope(self, awaitable: Awaitable[_T]) -> _T:
        channel = self._require_channel()
        scope = PacketSendScope(channel)
        with scope:
            task = asyncio.ensure_future(awaitable)
        return await self._race_send_failure(task, scope)

    async def _race_send_failure(
        self,
        task: asyncio.Future[_T],
        scope: PacketSendScope,
    ) -> _T:
        error_task = asyncio.create_task(scope.next_error())
        wait_set: set[asyncio.Future[Any]] = {task, error_task}
        done, pending = await asyncio.wait(
            wait_set,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for pending_task in pending:
            pending_task.cancel()
        if error_task in done:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            await self.close()
            raise CoapTransportError(f"packet CoAP send failed: {error_task.result()}")
        error_task.cancel()
        with suppress(asyncio.CancelledError):
            await error_task
        return task.result()


class PacketCoapResourceSubscription(ResourceSubscription):
    """Observe subscription that binds the initial packet send to first result."""

    def __init__(
        self,
        inner: ResourceSubscription,
        channel: PacketDatagramChannel,
        scope: PacketSendScope | None = None,
        on_send_failure: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._inner = inner
        self._channel = channel
        self._scope = scope or PacketSendScope(channel)
        self._on_send_failure = on_send_failure

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def close(self) -> None:
        await self._inner.close()

    async def _results(self) -> AsyncIterator[CoapResult]:
        iterator = self._inner.results()
        with self._scope:
            first_task = asyncio.ensure_future(anext(iterator))
        error_task = asyncio.create_task(self._scope.next_error())
        wait_set: set[asyncio.Future[Any]] = {first_task, error_task}
        done, pending = await asyncio.wait(
            wait_set,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for pending_task in pending:
            pending_task.cancel()
        if error_task in done:
            first_task.cancel()
            with suppress(asyncio.CancelledError):
                await first_task
            with suppress(Exception):
                await self._inner.close()
            if self._on_send_failure is not None:
                await self._on_send_failure()
            raise CoapTransportError(f"packet CoAP send failed: {error_task.result()}")
        error_task.cancel()
        with suppress(asyncio.CancelledError):
            await error_task
        yield first_task.result()
        async for result in iterator:
            yield result


class PacketSendScope:
    """Tracks packet send failures for one request/Observe operation."""

    def __init__(self, channel: PacketDatagramChannel) -> None:
        self._channel = channel
        self._token: contextvars.Token[PacketSendScope | None] | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._errors: asyncio.Queue[BaseException] = asyncio.Queue()

    def __enter__(self) -> PacketSendScope:
        self._token = _SEND_SCOPE.set(self)
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        if self._token is not None:
            _SEND_SCOPE.reset(self._token)
            self._token = None

    @property
    def channel(self) -> PacketDatagramChannel:
        return self._channel

    def track(self, task: asyncio.Task[None]) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._on_send_done)

    async def next_error(self) -> BaseException:
        return await self._errors.get()

    def _on_send_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        with suppress(asyncio.CancelledError):
            exc = task.exception()
            if exc is not None:
                self._errors.put_nowait(exc)
                logger.debug("packet CoAP send failed: %s", exc)


class PacketDatagramChannel(DatagramChannel):
    """DatagramChannel that sends CoAP datagrams inside IPv6 packet frames."""

    def __init__(
        self,
        packet_transport: PacketTransport,
        local_host: str,
        *,
        src_port: int = DEFAULT_COAP_PORT,
        dst_port: int = DEFAULT_COAP_PORT,
    ) -> None:
        self._packet_transport = packet_transport
        self._local = IPv6Address(local_host)
        self._src_port = src_port
        self._dst_port = dst_port
        self._receiver: ReceiveCallback | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._send_tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def start(self) -> None:
        """Start forwarding inbound packets to aiocoap."""
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_packets())

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self._receiver = receiver

    def send_datagram(self, data: bytes, dest: str) -> None:
        if self._closed:
            return
        packet = wrap_coap(
            self._local,
            IPv6Address(dest),
            data,
            src_port=self._src_port,
            dst_port=self._dst_port,
        )
        task = asyncio.create_task(self._packet_transport.send_packet(packet))
        self._send_tasks.add(task)
        task.add_done_callback(self._send_tasks.discard)
        scope = _SEND_SCOPE.get()
        if scope is not None and scope.channel is self:
            scope.track(task)
        else:
            task.add_done_callback(self._log_unscoped_send_done)

    def close(self) -> None:
        self._closed = True
        if self._reader_task is not None:
            self._reader_task.cancel()
        for task in tuple(self._send_tasks):
            task.cancel()

    def _log_unscoped_send_done(self, task: asyncio.Task[None]) -> None:
        with suppress(asyncio.CancelledError):
            exc = task.exception()
            if exc is not None:
                logger.debug("packet CoAP send failed: %s", exc)

    async def aclose(self) -> None:
        """Close the channel and packet transport."""
        self.close()
        if self._reader_task is not None:
            with suppress(asyncio.CancelledError):
                await self._reader_task
        for task in tuple(self._send_tasks):
            with suppress(asyncio.CancelledError):
                await task
        await self._packet_transport.close()

    async def _read_packets(self) -> None:
        async for packet in self._packet_transport.packets():
            self._handle_packet(packet)

    def _handle_packet(self, packet: bytes) -> None:
        receiver = self._receiver
        if receiver is None:
            return
        try:
            parsed = IPv6Packet.from_bytes(packet)
            if parsed.header.dst_addr != self._local:
                return
            if parsed.header.next_header != NextHeader.UDP:
                return
            udp = UdpDatagram.from_bytes(parsed.payload)
            if udp.dst_port != self._src_port or udp.src_port != self._dst_port:
                return
            if udp.checksum == 0:
                return
            if udp_checksum(parsed.header.src_addr, parsed.header.dst_addr, parsed.payload) != 0:
                return
            source = str(parsed.header.src_addr)
            coap = unwrap_coap(packet)
        except Exception:
            logger.debug("failed to parse packet", exc_info=True)
            return
        receiver(coap, source)
