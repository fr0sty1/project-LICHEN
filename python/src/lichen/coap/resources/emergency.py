# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Emergency resources: /sos and /rollcall."""

from __future__ import annotations

import math
import time
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor


class SosResource(resource.ObservableResource):
    """Observable ``/sos`` — emergency (POST per spec/12-apps.md 18.4).

    State is a CBOR map::

        {"active": true, "from": "<hex-eui64>", "t": <float>}  # active
        {"active": false, "from": null, "t": null}              # idle

    **POST** activates with ``{"type":"sos", "node":..., "ts":...}`` (or legacy {"from","t"}).
    **DELETE** cancels.  **GET** and **Observe** expose the current state to all
    subscribers so neighbouring nodes can relay/escalate the alert.

    The repeating-beacon behaviour (every 30 s) is the responsibility of the
    application layer driving :meth:`retrigger`; the resource itself only
    tracks state and notifies on changes.
    """

    def __init__(self) -> None:
        super().__init__()
        self._active = False
        self._from: str | None = None
        self._t: float | None = None

    def _state_payload(self) -> bytes:
        return cbor2.dumps({"active": self._active, "from": self._from, "t": self._t})

    def activate(self, from_eui64: bytes, t: float) -> None:
        """Activate SOS from *from_eui64* at time *t* and notify observers."""
        self._active = True
        self._from = from_eui64.hex()
        self._t = t
        self.updated_state()

    def cancel(self) -> None:
        """Cancel an active SOS and notify observers.  No-op if already idle."""
        if self._active:
            self._active = False
            self._from = None
            self._t = None
            self.updated_state()

    def retrigger(self) -> None:
        """Re-notify observers without changing state (periodic beacon pulse)."""
        if self._active:
            self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._state_payload())
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except (ValueError, cbor2.CBORDecodeError):
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        from_hex = body.get("from") or body.get("node")
        timestamp = body.get("t") or body.get("ts")
        if "type" in body and body["type"] != "sos":
            pass  # support other types per spec in future
        if from_hex is None or timestamp is None:
            return Message(code=aiocoap.BAD_REQUEST)
        if (
            not isinstance(from_hex, str)
            or len(from_hex) != 16
            or any(char not in "0123456789abcdefABCDEF" for char in from_hex)
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or (isinstance(timestamp, float) and not math.isfinite(timestamp))
            or timestamp < 0
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        self.activate(bytes.fromhex(from_hex), timestamp)
        return Message(code=CREATED)

    async def render_delete(self, request: Message) -> Message:
        self.cancel()
        return Message(code=aiocoap.DELETED)


class RollcallResource(resource.ObservableResource):
    """Demo CoAP resource for conference rollcall use case per spec/12-apps.md 18.6.
    Supports POST to initiate, observable GET for status with SenML position data.
    Used by LCI-based conference demo application.
    """

    def __init__(self) -> None:
        super().__init__()
        self._rollcalls: dict[str, dict[str, Any]] = {}

    def update(
        self,
        roll_id: str,
        responded: list[dict[str, Any]] | None = None,
        missing: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update rollcall state and notify observers (for demo position beacons)."""
        if roll_id not in self._rollcalls:
            self._rollcalls[roll_id] = {
                "id": roll_id,
                "started": int(time.time()),
                "timeout_s": 60,
                "responded": [],
                "missing": [],
            }
        if responded is not None:
            self._rollcalls[roll_id]["responded"] = responded
        if missing is not None:
            self._rollcalls[roll_id]["missing"] = missing
        self.updated_state()

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "rollcall", "ct": str(int(CBOR)), "obs": None}

    async def render_post(self, request: Message) -> Message:
        """POST /rollcall to initiate a roll call (spec/12-apps.md:18.6)."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            data = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(data, dict) or "id" not in data:
            return Message(code=aiocoap.BAD_REQUEST)
        roll_id = str(data["id"])
        self._rollcalls[roll_id] = {
            "id": roll_id,
            "started": data.get("ts", int(time.time())),
            "timeout_s": data.get("timeout_s", 60),
            "responded": [],
            "missing": [],
        }
        self.updated_state()
        return Message(code=CREATED)

    async def render_get(self, request: Message) -> Message:
        """GET /rollcall/{id} or /rollcall returns status. Uses SenML via profiles for position."""
        roll_id = None
        if request.opt.uri_path and len(request.opt.uri_path) > 1:
            roll_id = request.opt.uri_path[-1]
        if roll_id and roll_id in self._rollcalls:
            data = dict(self._rollcalls[roll_id])
            payload = cbor2.dumps(data)
        else:
            payload = cbor2.dumps({"rollcalls": list(self._rollcalls.values())})
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = CBOR
        return msg
