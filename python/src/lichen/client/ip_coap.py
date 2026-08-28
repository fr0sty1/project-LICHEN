# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IP/CoAP ResourceTransport for native LCI clients."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol, Self
from urllib.parse import urlsplit

import aiocoap
import cbor2
from aiocoap import Message
from aiocoap.numbers import ContentFormat

from lichen.client.addressing import STATIC_NODE_ADDRESS
from lichen.client.lci import ResourceSubscription, ResourceTransport
from lichen.client.model import CoapResult

CBOR_CONTENT_FORMAT = int(ContentFormat.CBOR)
DEFAULT_503_BACKOFF_S = 60  # Default backoff when no Max-Age/retry_after provided


class CoapTransportError(RuntimeError):
    """IP/CoAP transport setup, timeout, or payload decoding failure."""


class ServiceUnavailableError(CoapTransportError):
    """5.03 Service Unavailable response requiring backoff (spec 07 section 10.2.3).

    Per spec: "Senders receiving 5.03 MUST back off for the indicated duration."

    Attributes:
        retry_after_s: Backoff duration in seconds from Max-Age or payload.
        reason: Optional reason from the CBOR payload (e.g., "duty_cycle").
        level: Optional congestion level from the CBOR payload.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after_s: int | None = None,
        reason: str | None = None,
        level: str | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s
        self.reason = reason
        self.level = level


class RequestHandleLike(Protocol):
    """Subset of aiocoap request handles used by this transport."""

    response: Any
    observation: Any


class ContextLike(Protocol):
    """Subset of aiocoap Context used by this transport."""

    def request(self, request: Message) -> RequestHandleLike:
        """Start one CoAP request."""

    async def shutdown(self) -> None:
        """Shutdown the context."""


@dataclass(frozen=True)
class IpCoapConfig:
    """Connection settings for a local LCI CoAP endpoint."""

    base_uri: str = f"coap://[{STATIC_NODE_ADDRESS}]"
    timeout_s: float = 10.0
    enforce_503_backoff: bool = True  # Enforce 5.03 backoff (spec 07 section 10.2.3)


ContextFactory = Callable[[], Awaitable[ContextLike]]


class AiocoapResourceTransport(ResourceTransport):
    """ResourceTransport implementation for direct IPv6 + CoAP LCI access.

    Implements 5.03 Service Unavailable backoff per spec 07 section 10.2.3:
    "Senders receiving 5.03 MUST back off for the indicated duration."

    The transport tracks peer backoff state and refuses new requests to peers
    that are in backoff. Backoff duration comes from Max-Age option or
    retry_after field in CBOR payload.
    """

    def __init__(
        self,
        *,
        config: IpCoapConfig | None = None,
        context: ContextLike | None = None,
        context_factory: ContextFactory | None = None,
    ) -> None:
        self.config = config or IpCoapConfig()
        self._context = context
        self._owns_context = context is None
        self._context_factory = context_factory
        self._lock = asyncio.Lock()
        # Track peer backoff state: peer -> (expires_at_monotonic, reason)
        self._peer_backoffs: dict[str, tuple[float, str | None]] = {}

    async def connect(self) -> None:
        """Create an aiocoap client context when one was not injected."""
        async with self._lock:
            if self._context is not None:
                return
            try:
                if self._context_factory is not None:
                    self._context = await self._context_factory()
                else:
                    self._context = await aiocoap.Context.create_client_context()
            except BaseException:
                self._context = None
                raise
            self._owns_context = True

    async def close(self) -> None:
        """Shutdown an owned aiocoap context."""
        async with self._lock:
            if self._context is None:
                return
            ctx = self._context
            owns = self._owns_context
            self._context = None
            self._owns_context = False
            if owns:
                await ctx.shutdown()

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        """Perform one CoAP resource request.

        Per spec 07 section 10.2.3, if a 5.03 Service Unavailable response is
        received, this method records the backoff duration and raises
        ServiceUnavailableError. Subsequent requests during backoff also raise.

        Raises:
            ServiceUnavailableError: If peer is backed off or 5.03 received.
            CoapTransportError: For transport-level failures.
        """
        uri = self._uri_for_path(path)
        peer = _uri_origin(uri, fallback=self.config.base_uri)
        # SECURITY: Block requests to peers in backoff per spec 07 section 10.2.3.
        # The spec MUST requirement ("Senders receiving 5.03 MUST back off for the
        # indicated duration") protects peers from traffic they've explicitly asked
        # to stop receiving. Ignoring backoff would contribute to duty cycle exhaustion
        # across the mesh and is considered network abuse.
        if self.config.enforce_503_backoff:
            backoff_entry = self._peer_backoffs.get(peer)
            if backoff_entry is not None:
                expires_at, reason = backoff_entry
                remaining = expires_at - time.monotonic()
                if remaining > 0:
                    raise ServiceUnavailableError(
                        f"{method} {path} blocked: backed off for {remaining:.1f}s",
                        retry_after_s=int(remaining) + 1,
                        reason=reason,
                    )
                else:
                    # Backoff expired, clear it (use pop to avoid race with concurrent requests)
                    self._peer_backoffs.pop(peer, None)

        context = self._require_context()
        try:
            message = _build_message(
                method,
                uri,
                payload=payload,
                content_format=content_format,
                observe=observe,
            )
            handle = context.request(message)
            response = await asyncio.wait_for(handle.response, timeout=self.config.timeout_s)
        except Exception as exc:
            raise CoapTransportError(f"{method} {path} failed: {exc}") from exc

        result = _coap_result(response)

        # Handle 5.03 Service Unavailable (spec 07 section 10.2.3)
        if result.is_service_unavailable and self.config.enforce_503_backoff:
            # retry_after_s is already capped at MAX_BACKOFF_S; use it or default
            retry_after = (
                result.retry_after_s if result.retry_after_s is not None else DEFAULT_503_BACKOFF_S
            )
            reason = None
            level = None
            if isinstance(result.payload, dict):
                reason = result.payload.get("reason")
                level = result.payload.get("level")
                reason = reason if isinstance(reason, str) else None
                level = level if isinstance(level, str) else None
            # Record backoff
            self._peer_backoffs[peer] = (time.monotonic() + retry_after, reason)
            raise ServiceUnavailableError(
                f"{method} {path} returned 5.03: back off for {retry_after}s",
                retry_after_s=retry_after,
                reason=reason,
                level=level,
            )

        return result

    def clear_backoff(self) -> None:
        """Clear all backoff state (for testing or explicit reset)."""
        self._peer_backoffs.clear()

    async def observe(self, path: str, *, method: str = "GET") -> ResourceSubscription:
        """Start a CoAP Observe relationship.

        Per spec 07 section 10.2.3, if the peer is backed off (due to a prior
        5.03 response), this method raises ServiceUnavailableError without
        sending a request.

        Raises:
            ServiceUnavailableError: If peer is backed off.
            CoapTransportError: For transport-level failures.
        """
        uri = self._uri_for_path(path)
        peer = _uri_origin(uri, fallback=self.config.base_uri)
        # SECURITY: Block observe requests to peers in backoff (same rationale as request()).
        if self.config.enforce_503_backoff:
            backoff_entry = self._peer_backoffs.get(peer)
            if backoff_entry is not None:
                expires_at, reason = backoff_entry
                remaining = expires_at - time.monotonic()
                if remaining > 0:
                    raise ServiceUnavailableError(
                        f"{method} {path} observe blocked: backed off for {remaining:.1f}s",
                        retry_after_s=int(remaining) + 1,
                        reason=reason,
                    )
                else:
                    # Backoff expired, clear it (use pop to avoid race with concurrent requests)
                    self._peer_backoffs.pop(peer, None)

        context = self._require_context()
        try:
            message = _build_message(method, uri, observe=True)
            handle = context.request(message)
        except Exception as exc:
            raise CoapTransportError(f"{method} {path} observe failed: {exc}") from exc
        return AiocoapResourceSubscription(
            handle,
            method=method,
            path=path,
            timeout_s=self.config.timeout_s,
        )

    def check_security_for_path(self, path: str) -> None:
        """Security check is not applicable for direct IP/CoAP transport.

        SECURITY: Direct IP/CoAP transport is used for trusted local connections
        (e.g., localhost or wired network). BLE-specific LESC requirements per
        spec 17.5.4 do not apply. This transport relies on network-layer access
        control (firewall, bind address) rather than link-layer authentication.
        """
        # Intentional no-op: IP/CoAP is a trusted local transport per spec 17.6.1

    def _require_context(self) -> ContextLike:
        if self._context is None:
            raise CoapTransportError("IP/CoAP transport is not connected")
        return self._context

    def _uri_for_path(self, path: str) -> str:
        if path.startswith(("coap://", "coaps://")):
            return path
        base = self.config.base_uri.rstrip("/")
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{base}{suffix}"


def _uri_origin(uri: str, *, fallback: str) -> str:
    """Return the scheme and authority used for per-peer backoff state."""
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return fallback
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return fallback


class AiocoapResourceSubscription(ResourceSubscription):
    """ResourceSubscription backed by aiocoap Observe notifications."""

    def __init__(
        self,
        handle: RequestHandleLike,
        *,
        method: str,
        path: str,
        timeout_s: float,
    ) -> None:
        self._handle = handle
        self._method = method
        self._path = path
        self._timeout_s = timeout_s
        self._closed = False
        self._closed_event = asyncio.Event()
        self._last_seq: int | None = None

    def results(self) -> AsyncIterator[CoapResult]:
        """Yield decoded Observe notifications."""
        return self._results()

    async def close(self) -> None:
        """Cancel the Observe relationship when aiocoap exposes a handle."""
        if self._closed:
            return
        self._closed = True
        self._closed_event.set()
        cancel = getattr(self._handle.observation, "cancel", None)
        if cancel is not None:
            with suppress(AssertionError):
                cancel()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        await self.close()

    def _should_accept(self, msg: Message) -> bool:
        seq = msg.opt.observe
        if seq is None:
            return True
        if self._last_seq is None:
            self._last_seq = seq
            return True
        diff = (seq - self._last_seq) & 0xFFFFFF
        if 0 < diff < 0x800000:
            self._last_seq = seq
            return True
        return False

    async def _results(self) -> AsyncIterator[CoapResult]:
        try:
            first = await asyncio.wait_for(self._handle.response, timeout=self._timeout_s)
            if self._should_accept(first):
                yield _coap_result(first)
            iterator = self._handle.observation.__aiter__()
            while not self._closed:
                response = await self._next_observation_or_close(iterator)
                if response is None:
                    return
                if self._should_accept(response):
                    yield _coap_result(response)
        except Exception as exc:
            # CancelledError is a BaseException since Python 3.8, not caught by Exception
            with suppress(Exception, asyncio.CancelledError):
                await self.close()
            raise CoapTransportError(f"{self._method} {self._path} observe failed: {exc}") from exc

    async def _next_observation_or_close(self, iterator: Any) -> Message | None:
        next_task = asyncio.create_task(iterator.__anext__())
        close_task = asyncio.create_task(self._closed_event.wait())
        done, pending = await asyncio.wait(
            {next_task, close_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if close_task in done:
            next_task.cancel()
            with suppress(asyncio.CancelledError):
                await next_task
            return None
        with suppress(asyncio.CancelledError):
            await close_task
        try:
            return next_task.result()
        except StopAsyncIteration:
            return None


def _build_message(
    method: str,
    uri: str,
    *,
    payload: bytes = b"",
    content_format: int | None = None,
    observe: bool = False,
) -> Message:
    code = _method_code(method)
    message = Message(code=code, uri=uri, payload=payload)
    if content_format is not None:
        message.opt.content_format = content_format
    if observe:
        message.opt.observe = 0
    return message


def _method_code(method: str) -> aiocoap.Code:
    m = method.upper()
    if m == "GET":
        return aiocoap.GET
    elif m == "POST":
        return aiocoap.POST
    elif m == "PUT":
        return aiocoap.PUT
    elif m == "DELETE":
        return aiocoap.DELETE
    else:
        raise CoapTransportError(f"unsupported CoAP method: {method}")


def _coap_result(message: Message) -> CoapResult:
    return CoapResult(
        code=message.code.dotted,
        payload=_decode_payload(message),
        location_path=tuple(message.opt.location_path or ()),
        content_format=_int_or_none(message.opt.content_format),
        raw_payload=message.payload,
        max_age=_uint_or_none(message.opt.max_age),
    )


def _decode_payload(message: Message) -> Any | None:
    if not message.payload:
        return None
    content_format = _int_or_none(message.opt.content_format)
    if content_format == CBOR_CONTENT_FORMAT:
        try:
            return cbor2.loads(message.payload)
        except Exception as exc:
            raise CoapTransportError("invalid CBOR response payload") from exc
    try:
        return message.payload.decode()
    except UnicodeDecodeError:
        return message.payload


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        # OverflowError: Decimal('inf') or Decimal('-inf') cannot convert to int
        # ValueError: float('nan') or Decimal('nan') cannot convert to int
        # TypeError: incompatible type
        return None


def _uint_or_none(value: Any) -> int | None:
    """Convert to unsigned int or return None for invalid/negative values.

    CoAP options like Max-Age and Content-Format are defined as unsigned
    integers (RFC 7252). Negative values are invalid and should be treated
    as if the option was absent.
    """
    result = _int_or_none(value)
    if result is not None and result < 0:
        return None
    return result
