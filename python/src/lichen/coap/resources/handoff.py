# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resource for node handoff (GCP-7).

Exposes POST /.well-known/lichen-gw/handoff for gateway-to-gateway
node handoff requests per spec section 08-gateway-coordination.md.

SECURITY: This resource MUST be protected by OSCORE. Unauthenticated
handoff requests enable node hijacking attacks where an attacker could:
- Steal security contexts (enabling impersonation)
- Disrupt routing (removing nodes from legitimate gateways)
- Cause denial of service (forcing constant handoff churn)

The resource validates OSCORE protection and rejects unprotected requests
with 4.01 Unauthorized.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiocoap import CHANGED, UNAUTHORIZED, Message, resource
from aiocoap.numbers import ContentFormat

from lichen.gateway.handoff import (
    HandoffError,
    HandoffRejectReason,
    HandoffRequest,
    HandoffResponse,
)

if TYPE_CHECKING:
    from lichen.gateway.handoff import NodeRegistry

CBOR = ContentFormat.CBOR


class HandoffResource(resource.Resource):
    """POST /.well-known/lichen-gw/handoff resource for node handoff.

    Handles incoming handoff requests from peer gateways. The source
    gateway POSTs a HandoffRequest; this resource validates it,
    extracts node state, removes the node from the registry, and
    returns a HandoffResponse with the transferred state.

    SECURITY: By default, requires OSCORE protection (detected via
    request.opt.object_security). For testing without OSCORE, set
    require_oscore=False (NOT for production).

    Usage:
        registry = NodeRegistry()
        resource = HandoffResource(registry)
        site.add_resource([".well-known", "lichen-gw", "handoff"], resource)
    """

    def __init__(
        self,
        registry: NodeRegistry,
        *,
        require_oscore: bool = True,
    ) -> None:
        """Create a handoff resource.

        Args:
            registry: The node registry to extract state from.
            require_oscore: If True (default), reject requests without
                OSCORE protection. Set False ONLY for testing.
        """
        super().__init__()
        self._registry = registry
        self._require_oscore = require_oscore

    async def render_post(self, request: Message) -> Message:
        """Handle POST /handoff request.

        Returns:
            CBOR-encoded HandoffResponse.
        """
        # SECURITY: Verify OSCORE protection. The object_security option
        # is set by aiocoap when the message was successfully unprotected.
        if self._require_oscore and not getattr(request.opt, "object_security", None):
            return Message(code=UNAUTHORIZED)

        if not request.payload:
            response = HandoffResponse.error(
                HandoffRejectReason.MALFORMED_REQUEST,
                "empty payload",
            )
            return self._cbor_response(response.encode())

        try:
            handoff_request = HandoffRequest.decode(request.payload)
        except HandoffError as e:
            response = HandoffResponse.error(
                HandoffRejectReason.MALFORMED_REQUEST,
                str(e),
            )
            return self._cbor_response(response.encode())

        # Process the handoff request
        handoff_response = self._registry.handle_handoff_request(handoff_request)

        # Use CHANGED (2.04) for successful state transfer, or for errors
        # that still return a valid response. Only use BAD_REQUEST for
        # malformed payloads that couldn't be parsed at all.
        return self._cbor_response(handoff_response.encode())

    def _cbor_response(self, payload: bytes) -> Message:
        """Create a CBOR response message."""
        msg = Message(code=CHANGED, payload=payload)
        msg.opt.content_format = CBOR
        return msg

    def get_link_description(self) -> dict[str, str]:
        """Link-format description for /.well-known/core."""
        return {"rt": "lichen-gw.handoff", "ct": str(int(CBOR))}
