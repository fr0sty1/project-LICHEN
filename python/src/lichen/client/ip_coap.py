# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IP/CoAP ResourceTransport for native LCI clients."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol

import aiocoap
import cbor2
from aiocoap import Message
from aiocoap.numbers import ContentFormat

from lichen.client.lci import ResourceSubscription, ResourceTransport
from lichen.client.model import CoapResult

CBOR_CONTENT_FORMAT = int(ContentFormat.CBOR)


class CoapTransportError(RuntimeError):
    """IP/CoAP transport setup, timeout, or payload decoding failure."""


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

    base_uri: str = "coap://[fe80::1]"
    timeout_s: float = 10.0


ContextFactory = Callable[[], Awaitable[ContextLike]]


class AiocoapResourceTransport(ResourceTransport):
    """ResourceTransport implementation for direct IPv6 + CoAP LCI access."""

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

    async def connect(self) -> None:
        """Create an aiocoap client context when one was not injected."""
        async with self._lock:
            if self._context is not None:
                return
            if self._context_factory is not None:
                self._context = await self._context_factory()
            else:
                self._context = await aiocoap.Context.create_client_context()
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
        """Perform one CoAP resource request."""
        context = self._require_context()
        try:
            message = _build_message(
                method,
                self._uri_for_path(path),
                payload=payload,
                content_format=content_format,
                observe=observe,
            )
            handle = context.request(message)
            response = await asyncio.wait_for(handle.response, timeout=self.config.timeout_s)
        except Exception as exc:
            raise CoapTransportError(f"{method} {path} failed: {exc}") from exc
        return _coap_result(response)

    async def observe(self, path: str, *, method: str = "GET") -> ResourceSubscription:
        """Start a CoAP Observe relationship."""
        context = self._require_context()
        try:
            message = _build_message(method, self._uri_for_path(path), observe=True)
            handle = context.request(message)
        except Exception as exc:
            raise CoapTransportError(f"{method} {path} observe failed: {exc}") from exc
        return AiocoapResourceSubscription(
            handle,
            method=method,
            path=path,
            timeout_s=self.config.timeout_s,
        )

    def _require_context(self) -> ContextLike:
        if self._context is None:
            raise CoapTransportError("IP/CoAP transport is not connected")
        return self._context

    def _uri_for_path(self, path: str) -> str:
        base = self.config.base_uri.rstrip("/")
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{base}{suffix}"


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

    def _should_accept(self, msg: Message) -> bool:
        seq = msg.opt.observe
        if seq is None:
            return True
        if self._last_seq is None:
            self._last_seq = seq
            return True
        diff = (seq - self._last_seq) & 0xffffff
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
            with suppress(Exception):
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
    except (TypeError, ValueError):
        return None
