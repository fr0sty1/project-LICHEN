# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""ResourceTransport adapter for CoAP over packet LCI links."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import math
import posixpath
import struct
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv6Address
from typing import Any, Self, TypeVar
from urllib.parse import unquote

from lichen.client.ble import BlePacketTransport, BleSecurityError, BleSecurityLevel
from lichen.client.ip_coap import AiocoapResourceTransport, CoapTransportError, IpCoapConfig
from lichen.client.lci import LciSecurityError, ResourceSubscription, ResourceTransport
from lichen.client.model import CoapResult
from lichen.client.transport import PacketTransport
from lichen.coap.params import CongestionError
from lichen.coap.schc_channel import DEFAULT_COAP_PORT, wrap_coap
from lichen.coap.transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    ReceiveCallback,
    create_lichen_context,
    parse_channel_endpoint,
    unscoped_ipv6,
)
from lichen.ipv6.packet import IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UdpDatagram, UdpError
from lichen.link.tx_queue import Priority

logger = logging.getLogger(__name__)
_SEND_SCOPE: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "packet_coap_send_scope",
    default=None,
)
# Safety: when asyncio.create_task / ensure_future is called inside a
# `with PacketSendScope(...)` block, the task captures a copy of the
# current context (including _SEND_SCOPE).  Each task's context is
# immutable from other tasks, so the scope is not lost even after the
# calling coroutine exits the `with` block, suspends, or a different
# task enters its own scope.
_T = TypeVar("_T")


@dataclass(frozen=True)
class PacketCoapConfig:
    """Connection settings for packet-backed local CoAP LCI."""

    local_host: str = "fe80::2"
    peer_host: str = "fe80::1"
    timeout_s: float = 10.0
    src_port: int = DEFAULT_COAP_PORT
    dst_port: int = DEFAULT_COAP_PORT

    def __post_init__(self) -> None:
        """Validate configuration values."""
        # Validate IPv6 address format early if the value looks like an IPv6 address.
        # Hostnames (no colon) are allowed and validated at connect time.
        for field, value in [("local_host", self.local_host), ("peer_host", self.peer_host)]:
            if value is None:
                raise ValueError(f"{field} must not be None")
            if not value:
                raise ValueError(f"{field} must not be empty")
            if ":" in value:  # Looks like IPv6, validate format now
                try:
                    IPv6Address(value.split("%")[0])  # Strip scope before parsing
                except ValueError as exc:
                    raise ValueError(f"{field} is not a valid IPv6 address: {exc}") from exc
        if not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError(f"timeout_s must be a positive finite number, got {self.timeout_s}")
        if not (1 <= self.src_port <= 65535):
            raise ValueError(f"src_port must be 1-65535, got {self.src_port}")
        if not (1 <= self.dst_port <= 65535):
            raise ValueError(f"dst_port must be 1-65535, got {self.dst_port}")

    @property
    def base_uri(self) -> str:
        """Return the peer CoAP URI used by the shared LCI client."""
        return parse_channel_endpoint(self.peer_host, default_port=self.dst_port).uri

    @property
    def local_endpoint(self) -> str:
        """Return the local endpoint identity presented to aiocoap."""
        return parse_channel_endpoint(self.local_host, default_port=self.src_port).authority


class PacketCoapResourceTransport(ResourceTransport):
    """Run LCI ResourceTransport requests over a packet transport.

    The underlying packet transport carries IPv6 packets, as exposed by BLE
    SLIP-over-GATT. This adapter frames aiocoap datagrams as IPv6/UDP packets
    and delegates request/observe behavior to the same aiocoap-backed client
    path used for direct IP transports.

    Thread Safety:
        This class is designed for single-threaded asyncio use. Callers MUST NOT
        call close() while request() or observe() operations are in flight. The
        lifecycle lock protects connect/close transitions but not the fast path
        used by request/observe to avoid lock overhead. Concurrent close during
        an active request may cause AttributeError or use-after-close.
    """

    def __init__(
        self,
        packet_transport: PacketTransport,
        *,
        config: PacketCoapConfig | None = None,
    ) -> None:
        if packet_transport is None:
            raise ValueError("packet_transport must not be None")
        self.packet_transport = packet_transport
        self.config = config or PacketCoapConfig()
        self._channel: PacketDatagramChannel | None = None
        self._resource_transport: AiocoapResourceTransport | None = None
        self._lifecycle_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None
        self._packet_closed = False
        self._active_ops = 0
        self._active_subscriptions = 0

    async def connect(self) -> None:
        """Open the packet link and construct an aiocoap context over it."""
        async with self._lifecycle_lock:
            if self._resource_transport is not None:
                return
            if self._close_task is not None:
                raise CoapTransportError("packet CoAP transport is closing")
            self._packet_closed = False
            channel: PacketDatagramChannel | None = None
            resource_transport: AiocoapResourceTransport | None = None
            try:
                await self.packet_transport.connect()
                channel = PacketDatagramChannel(
                    self.packet_transport,
                    self.config.local_host,
                    src_port=self.config.src_port,
                    dst_port=self.config.dst_port,
                )
                channel.start()
                await asyncio.sleep(0)
                if channel._reader_task is not None and channel._reader_task.done():
                    channel._reader_task.result()
                resource_transport = AiocoapResourceTransport(
                    config=IpCoapConfig(
                        base_uri=self.config.base_uri,
                        timeout_s=self.config.timeout_s,
                    ),
                    context_factory=lambda: create_lichen_context(
                        channel, self.config.local_endpoint
                    ),
                )
                await resource_transport.connect()
                await asyncio.sleep(0)
                if channel._reader_task is not None and channel._reader_task.done():
                    channel._reader_task.result()
            except BaseException as primary:
                if resource_transport is not None:
                    with suppress(BaseException):
                        await resource_transport.close()
                with suppress(BaseException):
                    if channel is not None:
                        await channel.aclose()
                    else:
                        await self.packet_transport.close()
                self._packet_closed = True
                raise primary
            self._channel = channel
            self._resource_transport = resource_transport

    async def close(self) -> None:
        """Close the CoAP context and underlying packet transport.

        Note: The warning logged when operations are in flight is advisory only.
        This class documents single-threaded asyncio use; callers MUST NOT call
        close() while request() or observe() operations are in flight. Concurrent
        close() during an active operation may cause use-after-close errors.
        """
        if self._active_ops > 0 or self._active_subscriptions > 0:
            logger.warning(
                "close() called with %d operation(s) in flight and %d active subscription(s); "
                "caller should await operations and close subscriptions before closing",
                self._active_ops,
                self._active_subscriptions,
            )
        async with self._lifecycle_lock:
            if self._close_task is None:
                self._close_task = asyncio.create_task(self._close_once())
            close_task = self._close_task
        await asyncio.shield(close_task)

    async def _close_once(self) -> None:
        """Internal close implementation, called at most once.

        Closes resource transport and channel/packet, propagating the first
        error encountered to all concurrent callers.
        """
        transport = self._resource_transport
        self._resource_transport = None
        channel = self._channel
        self._channel = None
        already_closed = self._packet_closed
        self._packet_closed = True
        error: BaseException | None = None
        if transport is not None:
            try:
                await transport.close()
            except BaseException as exc:
                error = exc
        if channel is not None:
            try:
                await channel.aclose()
            except BaseException as exc:
                if error is None:
                    error = exc
        elif not already_closed:
            try:
                await self.packet_transport.close()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

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
        if not method:
            raise ValueError("method must not be empty")
        self.check_security_for_path(path)
        self._active_ops += 1
        try:
            return await self._run_with_send_scope(
                self._require_transport().request(
                    method,
                    path,
                    payload=payload,
                    content_format=content_format,
                    observe=observe,
                )
            )
        finally:
            self._active_ops -= 1

    async def observe(self, path: str, *, method: str = "GET") -> ResourceSubscription:
        """Start an Observe subscription over the packet link.

        Note: _active_ops tracks only the setup phase (until subscription is returned).
        Active subscriptions are tracked separately via _active_subscriptions, which
        is incremented when the subscription is returned and decremented when it is
        closed. Callers must close the returned subscription before calling close()
        on this transport.
        """
        self.check_security_for_path(path)
        self._active_ops += 1
        try:
            channel = self._require_channel()
            scope = PacketSendScope(channel)
            with scope:
                observe_task = asyncio.create_task(
                    self._require_transport().observe(path, method=method)
                )
            subscription = await self._race_send_failure(observe_task, scope)
            self._active_subscriptions += 1
            return PacketCoapResourceSubscription(
                subscription,
                channel,
                scope,
                on_send_failure=self.close,
                on_close=self._unregister_subscription,
            )
        finally:
            self._active_ops -= 1

    def _unregister_subscription(self) -> None:
        """Decrement the active subscription count when a subscription closes."""
        if self._active_subscriptions > 0:
            self._active_subscriptions -= 1

    def check_security_for_path(self, path: str) -> None:
        """Check if security requirements are met for accessing a path.

        SECURITY: Per spec 17.5.4, BLE transports MUST require LE Secure
        Connections for /diag/raw/* resources.

        Raises:
            LciSecurityError: If BLE security requirements are not met.
            ValueError: If path is empty.
        """
        # Validate non-empty path for all transports
        if not path:
            raise ValueError("path must not be empty")

        # Only BLE transports require LESC check
        if not isinstance(self.packet_transport, BlePacketTransport):
            return  # Non-BLE transports (USB/serial) are trusted per spec 17.6.1

        # Normalize path for security check: iteratively URL-decode until stable,
        # resolve dot segments, and collapse leading double-slashes.
        # This is defense-in-depth; server canonicalizes and enforces per spec 17.5.4.
        # SECURITY: Iterative decoding prevents double-encoding bypass (%252F -> %2F -> /)
        normalized = path
        for _ in range(10):  # Defensive limit; unquote should converge quickly
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        else:
            # SECURITY: Did not converge - excessive encoding levels may indicate bypass attempt
            raise ValueError("path contains excessive URL encoding")
        # SECURITY: Reject null bytes to prevent truncation-based bypass in C servers.
        # We reject rather than strip because the C server may truncate at null,
        # leading to inconsistent paths between client security check and server routing.
        if '\x00' in normalized:
            raise ValueError("path contains null byte")
        if not normalized:
            raise ValueError("path must not be empty after sanitization")
        # SECURITY: Reject non-ASCII to prevent Unicode confusable bypass (e.g., U+FF0F
        # FULLWIDTH SOLIDUS or U+2215 DIVISION SLASH instead of U+002F SOLIDUS).
        # CoAP paths are ASCII; non-ASCII indicates potential bypass attempt.
        if any(ord(c) > 127 for c in normalized):
            raise ValueError("path contains non-ASCII characters")
        normalized = posixpath.normpath(normalized)
        # SECURITY: posixpath.normpath preserves leading // per POSIX; collapse it
        if normalized.startswith("//"):
            normalized = normalized[1:]
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        # SECURITY: Strip URI fragments before security check. Per RFC 7252, fragments are
        # client-side only, so '/diag/raw#foo' would bypass security checks but the CoAP
        # request is sent to '/diag/raw'. Strip fragment before query to handle '#' in query.
        if "#" in normalized:
            normalized = normalized.split("#", 1)[0]
        # SECURITY: Strip query strings before security check. A path like '/diag/raw?foo'
        # would bypass the equality/prefix checks below, but downstream CoAP libraries
        # may interpret '?' as a query separator and route to '/diag/raw'.
        if "?" in normalized:
            normalized = normalized.split("?", 1)[0]
        # SECURITY: Case-insensitive match prevents case variation bypass
        # Check both the collection path and paths under it
        normalized_lower = normalized.lower()
        if normalized_lower != "/diag/raw" and not normalized_lower.startswith("/diag/raw/"):
            return  # No special security required

        # SECURITY: BLE transports MUST require LESC for raw diagnostics
        try:
            self.packet_transport.assert_lesc_for_diagnostics()
        except BleSecurityError:
            # SECURITY: Do not expose actual_level to prevent security state enumeration.
            # Exception chain is intentionally broken to avoid leaking the actual level.
            raise LciSecurityError(
                "insufficient security level for this resource",
                path=path,
                required_level=BleSecurityLevel.LESC.name,
            ) from None

    def _require_transport(self) -> AiocoapResourceTransport:
        """Return the underlying transport, raising if not connected.

        API CONTRACT: The returned reference is not protected by a lock. Callers
        MUST NOT call close() while request/observe operations are in flight.
        Violating this contract may cause operations to proceed on a stale
        reference whose underlying channel is closing. The GIL prevents data
        races but a logical TOCTOU window exists if close() runs concurrently.
        """
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
            with suppress(BaseException):
                await task
            with suppress(BaseException):
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
        on_close: Callable[[], None] | None = None,
    ) -> None:
        if inner is None:
            raise ValueError("inner must not be None")
        self._inner = inner
        self._channel = channel
        self._scope = scope or PacketSendScope(channel)
        self._on_send_failure = on_send_failure
        self._on_close = on_close
        self._closed = False

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._inner.close()
        finally:
            if self._on_close is not None:
                self._on_close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: object, exc_val: object, exc_tb: object
    ) -> None:
        await self.close()

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
            with suppress(BaseException):
                await first_task
            # CancelledError is a BaseException since Python 3.8, not caught by Exception
            with suppress(Exception, asyncio.CancelledError):
                await self.close()
            if self._on_send_failure is not None:
                with suppress(BaseException):
                    await self._on_send_failure()
            raise CoapTransportError(f"packet CoAP send failed: {error_task.result()}")
        error_task.cancel()
        with suppress(asyncio.CancelledError):
            await error_task
        # PEP 479/525: StopAsyncIteration raised inside an async generator becomes
        # RuntimeError, so catch it explicitly. Empty iterator means no results.
        try:
            first_result = first_task.result()
        except StopAsyncIteration:
            return
        yield first_result
        async for result in iterator:
            yield result


class PacketSendScope:
    """Tracks packet send failures for one request/Observe operation."""

    _ERROR_QUEUE_MAXSIZE = 100
    _DROP_LOG_INTERVAL = 10  # Log warning every N dropped errors

    def __init__(self, channel: PacketDatagramChannel) -> None:
        if channel is None:
            raise ValueError("channel must not be None")
        self._channel = channel
        self._token: contextvars.Token[PacketSendScope | None] | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._errors: asyncio.Queue[BaseException] = asyncio.Queue(
            maxsize=self._ERROR_QUEUE_MAXSIZE
        )
        self._dropped_error_count = 0

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
                try:
                    self._errors.put_nowait(exc)
                except asyncio.QueueFull:
                    self._dropped_error_count += 1
                    if self._dropped_error_count % self._DROP_LOG_INTERVAL == 1:
                        logger.warning(
                            "packet CoAP error queue full, dropped %d errors (latest: %s)",
                            self._dropped_error_count,
                            exc,
                        )
                    return
                logger.debug("packet CoAP send failed: %s", exc)


class PacketDatagramChannel(DatagramChannel):
    """DatagramChannel that sends CoAP datagrams inside IPv6 packet frames."""

    _SEND_TASKS_WARNING_THRESHOLD = 100
    _SEND_TASKS_HARD_LIMIT = 1000

    def __init__(
        self,
        packet_transport: PacketTransport,
        local_host: str,
        *,
        src_port: int = DEFAULT_COAP_PORT,
        dst_port: int = DEFAULT_COAP_PORT,
    ) -> None:
        self._packet_transport = packet_transport
        local = parse_channel_endpoint(local_host, default_port=src_port)
        local_address = IPv6Address(local.host)
        if local_address.scope_id is not None and not local_address.is_link_local:
            raise ValueError("IPv6 scope is only supported for link-local endpoints")
        self._local_endpoint = local
        self._local = unscoped_ipv6(local.host)
        self._endpoint_policy = EndpointPolicy.owning_link_local(local.host)
        self._src_port = local.port
        self._dst_port = dst_port
        self._receiver: ReceiveCallback | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._send_tasks: set[asyncio.Task[None]] = set()
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._lifecycle_lock = asyncio.Lock()

    def start(self) -> None:
        """Start forwarding inbound packets to aiocoap.

        This method is synchronous and idempotent. The check-then-assign for
        _reader_task is atomic in single-threaded asyncio (no await between
        check and assignment). Do not call from multiple OS threads.
        """
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_packets())

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> bool:
        if self._receiver == receiver:
            self._receiver = None
            return True
        if self._receiver is not None:
            logger.debug(
                "clear_receiver called with mismatched receiver: expected %r, got %r",
                self._receiver,
                receiver,
            )
        return False

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._endpoint_policy

    def send_datagram(
        self,
        data: bytes,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        if dest is None:
            raise ValueError("dest must not be None")
        if data is None:
            raise ValueError("data must not be None")
        if self._closed:
            raise RuntimeError("channel is closed")
        if check_congestion:
            self.check_congestion_for(priority)
        # SECURITY: Enforce hard cap to prevent unbounded memory growth
        pending_count = len(self._send_tasks)
        if pending_count >= self._SEND_TASKS_HARD_LIMIT:
            raise CongestionError(
                self.congestion_level,
                priority,
                retry_after_ms=1000,
            )
        endpoint = self.normalize_endpoint(
            parse_channel_endpoint(dest, default_port=self._dst_port)
        )
        try:
            destination = IPv6Address(endpoint.host)
        except ValueError as exc:
            raise ValueError(f"dest must be a valid IPv6 address, got: {dest}") from exc
        wire_destination = unscoped_ipv6(destination)
        packet = wrap_coap(
            self._local,
            wire_destination,
            data,
            src_port=self._src_port,
            dst_port=endpoint.port,
        )
        task = asyncio.create_task(self._packet_transport.send_packet(packet))
        self._send_tasks.add(task)
        task.add_done_callback(self._send_tasks.discard)
        pending_count = len(self._send_tasks)
        if pending_count == self._SEND_TASKS_WARNING_THRESHOLD:
            logger.warning(
                "packet CoAP send queue reached %d pending tasks; "
                "consider backpressure or rate limiting",
                pending_count,
            )
        # Safe: the task calling us was created inside a with scope block,
        # so its context captured _SEND_SCOPE (see comment above).
        scope = _SEND_SCOPE.get()
        if scope is not None and scope.channel is self:
            scope.track(task)
        else:
            task.add_done_callback(self._log_unscoped_send_done)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._receiver = None
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
        async with self._lifecycle_lock:
            if self._close_task is None:
                self._close_task = asyncio.create_task(self._aclose_once())
            close_task = self._close_task
        await asyncio.shield(close_task)

    async def _aclose_once(self) -> None:
        self.close()
        reader = self._reader_task
        sends = tuple(self._send_tasks)
        tasks = (() if reader is None else (reader,)) + sends
        error: BaseException | None = None
        try:
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                failures = [
                    result
                    for result in results
                    if isinstance(result, BaseException)
                    and not isinstance(result, asyncio.CancelledError)
                ]
                if failures:
                    if (
                        reader is not None
                        and isinstance(results[0], BaseException)
                        and not isinstance(results[0], asyncio.CancelledError)
                    ):
                        error = results[0]
                    else:
                        def _safe_exc_key(exc: BaseException) -> tuple[str, str]:
                            try:
                                exc_str = str(exc)
                            except Exception:
                                exc_str = ""
                            return (
                                f"{type(exc).__module__}.{type(exc).__qualname__}",
                                exc_str,
                            )
                        error = min(failures, key=_safe_exc_key)
        finally:
            try:
                await self._packet_transport.close()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    async def _read_packets(self) -> None:
        try:
            async for packet in self._packet_transport.packets():
                try:
                    self._handle_packet(packet)
                except Exception:
                    logger.exception("unhandled error in _handle_packet")
        except Exception:
            logger.exception("packet reader failed")
            with suppress(Exception):
                self.close()
            raise

    def _handle_packet(self, packet: bytes) -> None:
        """Process an inbound IPv6 packet and forward CoAP payload to receiver.

        SECURITY: This method accepts packets from any IPv6 source address without
        validation, relying on transport-layer trust. Current transports (BLE/USB/serial)
        provide physical-layer authentication per spec 17.6.1. If a new transport type
        is added without physical-layer authentication, source address allowlisting
        should be implemented at the PacketTransport layer or in this method.
        """
        receiver = self._receiver
        if receiver is None:
            return
        try:
            parsed = IPv6Packet.from_bytes(packet)
            if parsed.header.dst_addr.packed != self._local.packed:
                return
            if parsed.header.next_header != NextHeader.UDP:
                return
            udp = UdpDatagram.from_bytes(parsed.payload)
            if udp.dst_port != self._src_port:
                return
            if not UdpDatagram.verify_checksum(
                parsed.header.src_addr, parsed.header.dst_addr, parsed.payload
            ):
                logger.debug("dropping packet: invalid UDP checksum")
                return
            source = self.normalize_endpoint(
                Endpoint(str(parsed.header.src_addr), udp.src_port)
            ).authority
            coap = udp.payload
        except (PacketError, UdpError, struct.error, ValueError, IndexError):
            logger.debug("failed to parse packet", exc_info=True)
            return
        receiver(coap, source)
