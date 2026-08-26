# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node status resources: /status, /status/neighbors, /status/routes, /config."""

from __future__ import annotations

from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, UNAUTHORIZED, Message, resource

from lichen.coap.resources.base import CBOR, NodeInfo, _cbor_response, _ReadResource
from lichen.coap.resources.cbor_validation import _decode_single_cbor


class StatusResource(resource.ObservableResource):
    """``/status`` — node status (uptime, rank, parent, battery, ...).

    Observable per spec/11-lci.md 17.5.3 (``obs`` on ``</status>``). Call
    :meth:`notify_changed` when status fields change.
    """

    rt = "status"

    def __init__(self, node_info: NodeInfo) -> None:
        super().__init__()
        self.node_info = node_info

    def notify_changed(self) -> None:
        """Notify RFC 7641 observers that status has changed."""
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_status())

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR)), "obs": None}


class NeighborsResource(resource.ObservableResource):
    """``/status/neighbors`` — observable neighbour table (spec 17.5.3).

    Supports CoAP Observe (RFC 7641). Call :meth:`notify_changed` when the
    neighbour table changes to push notifications to all registered observers.

    Example::

        neighbors = NeighborsResource(node_info)
        site = build_site(node_info, neighbors_resource=neighbors)
        # ... later, when neighbours change:
        neighbors.notify_changed()
    """

    rt = "status"

    def __init__(self, node_info: NodeInfo) -> None:
        super().__init__()
        self.node_info = node_info

    def notify_changed(self) -> None:
        """Notify all observers that the neighbour table has changed.

        Call this whenever neighbours are added, removed, or updated.
        """
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_neighbors())

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {"rt": self.rt, "ct": str(int(CBOR)), "obs": None}


class RoutesResource(_ReadResource):
    """``/status/routes`` — the routing table (spec 17.5.3).

    Returns: {routes: [{prefix, via, metric, lifetime_s}, ...], default_route}
    """

    rt = "status"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_routes())


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


class RadioConfigResource(_ReadResource):
    """``/config/radio`` — radio configuration (GET to read, PUT to update).

    Per spec 17.5.2, exposes: freq_mhz, bw_khz, sf, cr, tx_power_dbm, sync_word.

    SECURITY: Radio config writes can alter channel parameters, affecting
    mesh connectivity. By default, PUT is rejected with 4.01 Unauthorized
    unless ``allow_writes=True``.
    """

    rt = "config"

    def __init__(self, node_info: NodeInfo, *, allow_writes: bool = False) -> None:
        """Create a radio config resource.

        Args:
            node_info: Data source for radio configuration.
            allow_writes: If True, allow PUT to modify radio configuration.
                SECURITY: Only set True when transport-layer authentication
                (OSCORE) is enforced. Defaults to False (read-only).
        """
        super().__init__(node_info)
        self._allow_writes = allow_writes

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_radio_config())

    async def render_put(self, request: Message) -> Message:
        # SECURITY: Reject unauthenticated writes. Radio config changes can
        # disrupt mesh connectivity by altering channel parameters.
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
            self.node_info.set_radio_config(updates)
        except (TypeError, ValueError, OverflowError):
            return Message(code=BAD_REQUEST)
        return Message(code=CHANGED)


class IdentityConfigResource(_ReadResource):
    """``/config/identity`` — node identity (GET only, read-only).

    Per spec 17.5.2, exposes: eui64, pubkey, pubkey_fingerprint, addrs.
    This resource is intentionally read-only; identity is provisioned
    out-of-band and cannot be modified at runtime.
    """

    rt = "config"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_identity())
