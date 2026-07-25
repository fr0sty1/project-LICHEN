# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC initiator/client-side behavior."""

from __future__ import annotations

import asyncio

import aiocoap
import pytest

from lichen.coap.secure import SecureDatagramChannel
from lichen.coap.transport import InMemoryNetwork
from lichen.crypto.identity import Identity


class _CapturedRequest:
    def __init__(self, response: aiocoap.Message) -> None:
        loop = asyncio.get_running_loop()
        self.response: asyncio.Future[aiocoap.Message] = loop.create_future()
        self.response.set_result(response)


class _CapturingContext:
    def __init__(self) -> None:
        self.message: aiocoap.Message | None = None

    def request(self, message: aiocoap.Message) -> _CapturedRequest:
        self.message = message
        return _CapturedRequest(aiocoap.Message(code=aiocoap.CHANGED, payload=b"response"))


@pytest.mark.asyncio
async def test_secure_edhoc_uses_canonical_ipv6_endpoint_uri(monkeypatch) -> None:
    channel = SecureDatagramChannel(
        InMemoryNetwork().channel("[2001:db8::2]:61617"),
        Identity.generate(),
        local_host="[2001:db8::2]:61617",
    )
    context = _CapturingContext()

    async def get_context() -> _CapturingContext:
        return context

    monkeypatch.setattr(channel, "_get_edhoc_context", get_context)

    response = await channel._edhoc_exchange("[2001:db8::1]:61616", b"message-1")

    assert response == b"response"
    assert context.message is not None
    assert context.message.get_request_uri() == ("coap://[2001:db8::1]:61616/.well-known/edhoc")
