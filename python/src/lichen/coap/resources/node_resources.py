# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node status resources: /status, /neighbors, /config."""

from __future__ import annotations

from aiocoap import BAD_REQUEST, CHANGED, UNAUTHORIZED, Message

from lichen.coap.resources.base import NodeInfo, _cbor_response, _ReadResource
from lichen.coap.resources.cbor_validation import _decode_single_cbor


class StatusResource(_ReadResource):
    """``/status`` — node status (uptime, rank, parent, battery, ...)."""

    rt = "status"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_status())


class NeighborsResource(_ReadResource):
    """``/neighbors`` — the neighbour table."""

    rt = "status"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_neighbors())


class ConfigResource(_ReadResource):
    """``/config`` — node configuration (GET to read, PUT to update).

    SECURITY: Config writes can reconfigure security features, routing
    parameters, or redirect traffic. By default, PUT is rejected with
    4.01 Unauthorized unless ``allow_writes=True``.

    In production, use OSCORE-protected transport (spec section 8.7) and
    set ``allow_writes=True`` only when the transport layer enforces
    authentication. For testing without OSCORE, explicitly enable writes.
    """

    rt = "config"

    def __init__(self, node_info: NodeInfo, *, allow_writes: bool = False) -> None:
        """Create a config resource.

        Args:
            node_info: Data source for configuration.
            allow_writes: If True, allow PUT to modify configuration.
                SECURITY: Only set True when transport-layer authentication
                (OSCORE) is enforced. Defaults to False (read-only).
        """
        super().__init__(node_info)
        self._allow_writes = allow_writes

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_config())

    async def render_put(self, request: Message) -> Message:
        # SECURITY: Reject unauthenticated writes. Config changes can disable
        # security features, alter routing, or redirect traffic (spec 8).
        if not self._allow_writes:
            return Message(code=UNAUTHORIZED)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            updates = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if not isinstance(updates, dict):
            return Message(code=BAD_REQUEST)
        try:
            self.node_info.set_config(updates)
        except (TypeError, ValueError, OverflowError):
            return Message(code=BAD_REQUEST)
        return Message(code=CHANGED)
