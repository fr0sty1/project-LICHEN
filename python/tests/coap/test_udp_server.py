# SPDX-License-Identifier: GPL-3.0-or-later
"""Test UDP CoAP server binding."""

import aiocoap
import pytest

from lichen.coap.udp_server import bind_coap_udp
from lichen.crypto.identity import Identity
from lichen.node import Node
from lichen.radio.base import Radio

# ponytail: use fixed high port to avoid conflicts
TEST_PORT = 15683

# IPv4 loopback, not the "::1" default: aiocoap resolves with AI_ADDRCONFIG,
# which rejects ::1 on hosts with no global IPv6 address (e.g. GitHub-hosted
# CI runners). The binding machinery under test is address-family agnostic.
TEST_BIND = "127.0.0.1"


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
    ctx = await bind_coap_udp(node, port=TEST_PORT, bind=TEST_BIND)
    try:
        client = await aiocoap.Context.create_client_context()
        try:
            request = aiocoap.Message(
                code=aiocoap.GET, uri=f"coap://{TEST_BIND}:{TEST_PORT}/status"
            )
            response = await client.request(request).response
            assert response.code.is_successful()
        finally:
            await client.shutdown()
    finally:
        await ctx.shutdown()


@pytest.mark.asyncio
async def test_bind_coap_udp_neighbors(node):
    """Test that /neighbors is queryable via real UDP."""
    ctx = await bind_coap_udp(node, port=TEST_PORT + 1, bind=TEST_BIND)
    try:
        client = await aiocoap.Context.create_client_context()
        try:
            request = aiocoap.Message(
                code=aiocoap.GET,
                uri=f"coap://{TEST_BIND}:{TEST_PORT + 1}/neighbors",
            )
            response = await client.request(request).response
            assert response.code.is_successful()
        finally:
            await client.shutdown()
    finally:
        await ctx.shutdown()
