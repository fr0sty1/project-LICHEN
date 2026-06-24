# SPDX-License-Identifier: GPL-3.0-or-later
"""Test UDP CoAP server binding."""

import pytest
import aiocoap

from lichen.coap.udp_server import bind_coap_udp
from lichen.crypto.identity import Identity
from lichen.node import Node
from lichen.radio.base import Radio

# ponytail: use fixed high port to avoid conflicts
TEST_PORT = 15683


class DummyRadio(Radio):
    """Minimal radio for testing."""

    async def transmit(self, data: bytes) -> bool:
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, float] | None:
        return None


@pytest.fixture
def node():
    identity = Identity.generate()
    radio = DummyRadio()
    return Node(identity=identity, radio=radio)


@pytest.mark.asyncio
async def test_bind_coap_udp_status(node):
    """Test that /status is queryable via real UDP."""
    ctx = await bind_coap_udp(node, port=TEST_PORT)
    try:
        client = await aiocoap.Context.create_client_context()
        try:
            request = aiocoap.Message(code=aiocoap.GET, uri=f"coap://[::1]:{TEST_PORT}/status")
            response = await client.request(request).response
            assert response.code.is_successful()
        finally:
            await client.shutdown()
    finally:
        await ctx.shutdown()


@pytest.mark.asyncio
async def test_bind_coap_udp_neighbors(node):
    """Test that /neighbors is queryable via real UDP."""
    ctx = await bind_coap_udp(node, port=TEST_PORT + 1)
    try:
        client = await aiocoap.Context.create_client_context()
        try:
            request = aiocoap.Message(code=aiocoap.GET, uri=f"coap://[::1]:{TEST_PORT + 1}/neighbors")
            response = await client.request(request).response
            assert response.code.is_successful()
        finally:
            await client.shutdown()
    finally:
        await ctx.shutdown()
