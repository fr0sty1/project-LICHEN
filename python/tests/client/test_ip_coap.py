# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for IP/CoAP LCI ResourceTransport."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import aiocoap  # type: ignore[import-untyped]
import cbor2
import pytest
from aiocoap import Message

from lichen.client.ip_coap import (
    CBOR_CONTENT_FORMAT,
    AiocoapResourceTransport,
    CoapTransportError,
    IpCoapConfig,
)
from lichen.client.lci import LciClient
from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


class FakeObservation:
    def __init__(self, messages: list[Message]) -> None:
        self._messages = messages
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    async def __aiter__(self) -> AsyncIterator[Message]:
        for message in self._messages:
            yield message


class PendingObservation:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def __aiter__(self) -> PendingObservation:
        return self

    async def __anext__(self) -> Message:
        await asyncio.Event().wait()
        raise StopAsyncIteration


class FakeRequestHandle:
    def __init__(
        self,
        response: Message | Exception,
        observation: Any | None = None,
    ) -> None:
        self.response = self._response(response)
        self.observation = observation or FakeObservation([])

    async def _response(self, response: Message | Exception) -> Message:
        if isinstance(response, Exception):
            raise response
        return response


class FakeContext:
    def __init__(self) -> None:
        self.requests: list[Message] = []
        self.responses: list[Message | Exception] = []
        self.observations: list[FakeObservation] = []
        self.shutdown_called = False

    def request(self, request: Message) -> FakeRequestHandle:
        self.requests.append(request)
        response = self.responses.pop(0)
        observation = self.observations.pop(0) if self.observations else None
        return FakeRequestHandle(response, observation)

    async def shutdown(self) -> None:
        self.shutdown_called = True


def _cbor_response(value: Any, *, code: aiocoap.Code = aiocoap.CONTENT) -> Message:
    message = Message(code=code, payload=cbor2.dumps(value))
    message.opt.content_format = CBOR_CONTENT_FORMAT
    return message


async def test_request_decodes_cbor_and_preserves_response_details() -> None:
    context = FakeContext()
    response = _cbor_response({"uptime_s": 42})
    response.opt.location_path = ("msg", "outbox", "1")
    context.responses.append(response)
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://[fe80::1]", timeout_s=0.5),
        context=context,
    )

    result = await transport.request("GET", "/status")

    assert result.code == "2.05"
    assert result.payload == {"uptime_s": 42}
    assert result.location_path == ("msg", "outbox", "1")
    assert result.content_format == CBOR_CONTENT_FORMAT
    assert result.raw_payload == response.payload
    assert context.requests[0].get_request_uri() == "coap://[fe80::1]/status"


async def test_request_sends_cbor_payload_and_content_format() -> None:
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.CHANGED))
    transport = AiocoapResourceTransport(context=context)
    payload = cbor2.dumps({"name": "node"})

    result = await transport.request(
        "PUT",
        "config",
        payload=payload,
        content_format=CBOR_CONTENT_FORMAT,
    )

    assert result.code == "2.04"
    assert context.requests[0].payload == payload
    assert context.requests[0].opt.content_format == CBOR_CONTENT_FORMAT


async def test_request_preserves_unsupported_resource_code() -> None:
    context = FakeContext()
    context.responses.append(Message(code=aiocoap.NOT_FOUND, payload=b"missing"))
    transport = AiocoapResourceTransport(context=context)

    result = await transport.request("GET", "/nope")

    assert result.code == "4.04"
    assert result.payload == "missing"


async def test_request_wraps_timeouts() -> None:
    context = FakeContext()
    context.responses.append(TimeoutError("slow"))
    transport = AiocoapResourceTransport(context=context, config=IpCoapConfig(timeout_s=0.01))

    with pytest.raises(CoapTransportError, match="GET /status failed"):
        await transport.request("GET", "/status")


async def test_request_rejects_invalid_cbor() -> None:
    context = FakeContext()
    message = Message(code=aiocoap.CONTENT, payload=b"not-cbor")
    message.opt.content_format = CBOR_CONTENT_FORMAT
    context.responses.append(message)
    transport = AiocoapResourceTransport(context=context)

    with pytest.raises(CoapTransportError, match="invalid CBOR"):
        await transport.request("GET", "/status")


async def test_request_rejects_unsupported_method() -> None:
    transport = AiocoapResourceTransport(context=FakeContext())

    with pytest.raises(CoapTransportError, match="unsupported CoAP method"):
        await transport.request("PATCH", "/config")


async def test_request_wraps_message_construction_errors() -> None:
    transport = AiocoapResourceTransport(
        context=FakeContext(),
        config=IpCoapConfig(base_uri="not a uri"),
    )

    with pytest.raises(CoapTransportError, match="GET /status failed"):
        await transport.request("GET", "/status")


async def test_observe_yields_initial_and_later_notifications() -> None:
    context = FakeContext()
    context.responses.append(_cbor_response({"messages": []}))
    observation = FakeObservation([_cbor_response({"messages": [{"id": 1}]})])
    context.observations.append(observation)
    transport = AiocoapResourceTransport(context=context)

    subscription = await transport.observe("/msg/inbox")
    results = []
    async for result in subscription.results():
        results.append(result.payload)
        if len(results) == 2:
            break

    assert results == [{"messages": []}, {"messages": [{"id": 1}]}]
    assert context.requests[0].opt.observe == 0
    await subscription.close()
    assert observation.cancelled
    await subscription.close()
    assert observation.cancelled


async def test_observe_initial_response_timeout_is_wrapped() -> None:
    context = FakeContext()
    context.responses.append(TimeoutError("slow observe"))
    transport = AiocoapResourceTransport(context=context, config=IpCoapConfig(timeout_s=0.01))

    subscription = await transport.observe("/msg/inbox")

    with pytest.raises(CoapTransportError, match="GET /msg/inbox observe failed"):
        async for _result in subscription.results():
            pass


async def test_observe_close_wakes_pending_notification_reader() -> None:
    context = FakeContext()
    context.responses.append(_cbor_response({"messages": []}))
    observation = PendingObservation()
    context.observations.append(observation)  # type: ignore[arg-type]
    transport = AiocoapResourceTransport(context=context)
    subscription = await transport.observe("/msg/inbox")
    iterator = subscription.results()

    assert (await anext(iterator)).payload == {"messages": []}
    pending: asyncio.Future[Any] = asyncio.ensure_future(anext(iterator))
    await asyncio.sleep(0)
    await subscription.close()

    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(pending, timeout=1.0)
    assert observation.cancelled


async def test_close_does_not_shut_down_injected_context() -> None:
    context = FakeContext()
    transport = AiocoapResourceTransport(context=context)

    await transport.close()

    assert not context.shutdown_called


async def test_reconnect_after_injected_context_owns_created_context() -> None:
    injected_context = FakeContext()
    created_context = FakeContext()

    async def factory() -> FakeContext:
        return created_context

    transport = AiocoapResourceTransport(context=injected_context, context_factory=factory)

    await transport.close()
    assert not injected_context.shutdown_called
    await transport.connect()
    await transport.close()

    assert created_context.shutdown_called


async def test_lci_client_get_status_over_in_memory_aiocoap_context() -> None:
    net = InMemoryNetwork()
    site = build_site(StaticNodeInfo(status={"uptime_s": 123, "battery_pct": 91}))
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client_context = await create_lichen_context(net.channel("cli"), "cli")
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://srv", timeout_s=1.0),
        context=client_context,
    )
    client = LciClient(transport)

    try:
        status = await client.get_status()
    finally:
        await client_context.shutdown()
        await server.shutdown()

    assert status.uptime_s == 123
    assert status.battery_pct == 91
