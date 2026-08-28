# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CoAP handoff resource (GCP-7)."""

from __future__ import annotations

import time
from ipaddress import IPv6Address
from unittest.mock import MagicMock

import pytest
from aiocoap import CHANGED, UNAUTHORIZED, Message
from aiocoap.numbers import ContentFormat

from lichen.coap.resources.handoff import HandoffResource
from lichen.gateway.handoff import (
    HandoffRejectReason,
    HandoffRequest,
    HandoffResponse,
    NodeRegistry,
    OscoreState,
)


@pytest.fixture
def registry() -> NodeRegistry:
    return NodeRegistry()


@pytest.fixture
def resource(registry: NodeRegistry) -> HandoffResource:
    return HandoffResource(registry, require_oscore=False)


@pytest.fixture
def protected_resource(registry: NodeRegistry) -> HandoffResource:
    return HandoffResource(registry, require_oscore=True)


@pytest.fixture
def node_address() -> IPv6Address:
    return IPv6Address("fe80::1234:5678:9abc:def0")


@pytest.fixture
def oscore_state() -> OscoreState:
    return OscoreState(
        master_secret=b"\x01" * 16,
        master_salt=b"\x02" * 8,
        sender_id=b"\x00",
        recipient_id=b"\x01",
        algorithm=10,
        hashfun="SHA-256",
        window_size=32,
        id_context=None,
        sender_sequence=100,
        replay_index=50,
        replay_bitfield=0,
    )


def _make_request(payload: bytes | None = None, oscore_protected: bool = False) -> Message:
    """Create a mock POST request."""
    msg = MagicMock(spec=Message)
    msg.payload = payload
    msg.opt = MagicMock()
    msg.opt.object_security = b"oscore_data" if oscore_protected else None
    return msg


class TestHandoffResource:
    """Tests for HandoffResource."""

    @pytest.mark.asyncio
    async def test_successful_handoff(
        self,
        resource: HandoffResource,
        registry: NodeRegistry,
        node_address: IPv6Address,
        oscore_state: OscoreState,
    ) -> None:
        """Successful handoff returns state and CHANGED status."""
        # Setup: register node
        registry.register(
            node_address,
            dao_sequence=42,
            path_sequence=10,
            oscore_state=oscore_state,
        )

        # Send handoff request
        request_payload = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        ).encode()
        request = _make_request(request_payload)

        response = await resource.render_post(request)

        assert response.code == CHANGED
        assert response.opt.content_format == ContentFormat.CBOR

        # Parse response
        handoff_response = HandoffResponse.decode(response.payload)
        assert handoff_response.status == HandoffRejectReason.SUCCESS
        assert handoff_response.dao_sequence == 42
        assert handoff_response.path_sequence == 10
        assert handoff_response.oscore_state == oscore_state

        # Two-phase commit: node stays in registry with pending_handoff=True.
        # This prevents orphaning if the response is lost in transit.
        # Caller must explicitly call finalize_handoff() after confirmation.
        assert node_address in registry
        entry = registry.get(node_address)
        assert entry is not None
        assert entry.pending_handoff is True

    @pytest.mark.asyncio
    async def test_node_not_found(
        self, resource: HandoffResource, node_address: IPv6Address
    ) -> None:
        """Handoff for unknown node returns NODE_NOT_FOUND."""
        request_payload = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        ).encode()
        request = _make_request(request_payload)

        response = await resource.render_post(request)

        assert response.code == CHANGED  # Still CHANGED, error is in payload
        handoff_response = HandoffResponse.decode(response.payload)
        assert handoff_response.status == HandoffRejectReason.NODE_NOT_FOUND

    @pytest.mark.asyncio
    async def test_empty_payload(self, resource: HandoffResource) -> None:
        """Empty payload returns MALFORMED_REQUEST."""
        request = _make_request(b"")

        response = await resource.render_post(request)

        assert response.code == CHANGED
        handoff_response = HandoffResponse.decode(response.payload)
        assert handoff_response.status == HandoffRejectReason.MALFORMED_REQUEST
        assert "empty" in handoff_response.message.lower()

    @pytest.mark.asyncio
    async def test_invalid_cbor_payload(self, resource: HandoffResource) -> None:
        """Invalid CBOR returns MALFORMED_REQUEST."""
        request = _make_request(b"\x85\x01")  # Truncated CBOR

        response = await resource.render_post(request)

        assert response.code == CHANGED
        handoff_response = HandoffResponse.decode(response.payload)
        assert handoff_response.status == HandoffRejectReason.MALFORMED_REQUEST

    @pytest.mark.asyncio
    async def test_requires_oscore_protection(
        self,
        protected_resource: HandoffResource,
        registry: NodeRegistry,
        node_address: IPv6Address,
    ) -> None:
        """Protected resource rejects unprotected requests."""
        registry.register(node_address)

        request_payload = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        ).encode()

        # Unprotected request
        request = _make_request(request_payload, oscore_protected=False)
        response = await protected_resource.render_post(request)
        assert response.code == UNAUTHORIZED

        # Node should still be in registry (not processed)
        assert node_address in registry

    @pytest.mark.asyncio
    async def test_accepts_oscore_protected(
        self,
        protected_resource: HandoffResource,
        registry: NodeRegistry,
        node_address: IPv6Address,
    ) -> None:
        """Protected resource accepts OSCORE-protected requests."""
        registry.register(
            node_address,
            dao_sequence=100,
            path_sequence=50,
        )

        request_payload = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        ).encode()

        # Protected request
        request = _make_request(request_payload, oscore_protected=True)
        response = await protected_resource.render_post(request)

        assert response.code == CHANGED
        handoff_response = HandoffResponse.decode(response.payload)
        assert handoff_response.status == HandoffRejectReason.SUCCESS

    def test_link_description(self, resource: HandoffResource) -> None:
        """Link description includes resource type and content format."""
        desc = resource.get_link_description()
        assert desc["rt"] == "lichen-gw.handoff"
        assert desc["ct"] == str(int(ContentFormat.CBOR))
