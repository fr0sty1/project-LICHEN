# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``/diag`` and ``/diag/raw/rx`` (spec/11-lci.md 17.5.4)."""

from __future__ import annotations

from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, Message, resource

from lichen.coap.raw_diag import CODE_BAD_REQUEST, MAX_TTL_S, RawDiagTTL
from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor

SPEC_MAX_FRAME_LEN = 255


class DiagResource(resource.Resource):
    """``GET /diag`` diagnostics summary."""

    rt = "diag"

    async def render_get(self, request: Message) -> Message:
        del request
        return _cbor_response(diag_summary())

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}


class RawRxResource(resource.Resource):
    """GET/PUT ``/diag/raw/rx`` arming status (spec 17.5.4)."""

    rt = "diag.raw.rx"

    def __init__(self, ttl: RawDiagTTL | None = None) -> None:
        super().__init__()
        self.ttl = ttl if ttl is not None else RawDiagTTL()
        self.include_payload = False

    async def render_get(self, request: Message) -> Message:
        del request
        return _cbor_response(self.status_map())

    async def render_put(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        enabled = body.get("enabled")
        if type(enabled) is not bool:
            return Message(code=BAD_REQUEST)
        ttl_s = body.get("ttl_s")
        include_payload = body.get("include_payload", False)
        if include_payload is not False and type(include_payload) is not bool:
            return Message(code=BAD_REQUEST)
        ok, code = self.ttl.arm(enabled=enabled, ttl_s=ttl_s)
        if not ok or code == CODE_BAD_REQUEST:
            return Message(code=BAD_REQUEST)
        self.include_payload = bool(include_payload) if enabled else False
        return Message(code=CHANGED)

    def status_map(self) -> dict[str, Any]:
        return {
            "enabled": self.ttl.enabled,
            "remaining_s": self.ttl.remaining_s(),
            "max_ttl_s": self.ttl.max_ttl_s,
        }

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}


class RawRxEventsResource(resource.ObservableResource):
    """``GET /diag/raw/rx/events`` Observe stream (spec 17.5.4)."""

    rt = "diag.raw.rx.events"

    def __init__(self) -> None:
        super().__init__()
        self._last: dict[str, Any] = {}

    def publish(self, event: dict[str, Any]) -> None:
        if type(event) is not dict:
            raise TypeError("event must be a dict")
        self._last = dict(event)
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        del request
        return _cbor_response(dict(self._last))

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR)), "obs": None}


def diag_summary() -> dict[str, Any]:
    """Spec diagnostics summary document."""
    return {
        "available": True,
        "raw": {
            "available": True,
            "rx": "/diag/raw/rx",
            "rx_events": "/diag/raw/rx/events",
            "tx": "/diag/raw/tx",
            "max_frame_len": SPEC_MAX_FRAME_LEN,
        },
    }


def default_disabled_status() -> dict[str, Any]:
    """Spec example for a disarmed raw-RX resource."""
    return {"enabled": False, "remaining_s": 0, "max_ttl_s": MAX_TTL_S}
