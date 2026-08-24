# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Emergency resources: /sos, /rollcall, and /checkin."""

from __future__ import annotations

import math
import time
from typing import Any

import aiocoap
import cbor2
from aiocoap import CHANGED, CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor

MAX_ROLLCALLS = 256
MAX_ROLLCALL_TIMEOUT_S = 7 * 86400
MAX_CHECKINS = 256  # Maximum stored check-ins

# SOS rate limiting per spec (per-source limits)
SOS_COOLDOWN_S = 600  # 10-minute minimum between requests from same source
SOS_HOURLY_MAX = 3  # Maximum 3 requests per hour from same source

# Valid check-in status values per spec 18.6.1
CHECKIN_STATUS_VALUES = frozenset({"ok", "help", "delayed"})


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

    Rate limiting: each source node is limited to 3 requests per hour with a
    minimum 10-minute cooldown between requests. This prevents SOS flooding
    while allowing legitimate emergency use.
    """

    def __init__(self, time_func: Any = None) -> None:
        """Initialize SOS resource.

        Args:
            time_func: Optional callable returning current time (for testing).
                       Defaults to time.time.
        """
        super().__init__()
        self._active = False
        self._from: str | None = None
        self._t: float | None = None
        self._time_func = time_func if time_func is not None else time.time
        # Per-source rate limiting: maps source hex -> list of request timestamps
        self._request_times: dict[str, list[float]] = {}

    def _prune_old_requests(self, source_hex: str) -> None:
        """Remove request timestamps older than 1 hour for the given source."""
        if source_hex not in self._request_times:
            return
        now = self._time_func()
        cutoff = now - 3600  # 1 hour
        self._request_times[source_hex] = [
            ts for ts in self._request_times[source_hex] if ts > cutoff
        ]
        if not self._request_times[source_hex]:
            del self._request_times[source_hex]

    def check_rate_limit(self, source_hex: str) -> bool:
        """Check if source is within rate limits.

        Returns True if request is allowed, False if rate-limited.

        Rate limits:
        - 10-minute cooldown between requests from same source
        - Maximum 3 requests per hour from same source
        """
        self._prune_old_requests(source_hex)
        if source_hex not in self._request_times:
            return True
        timestamps = self._request_times[source_hex]
        now = self._time_func()
        # Check cooldown: most recent request must be > 10 min ago
        if timestamps and (now - timestamps[-1]) < SOS_COOLDOWN_S:
            return False
        # Check hourly max: must have fewer than 3 requests in last hour
        return len(timestamps) < SOS_HOURLY_MAX

    def _record_request(self, source_hex: str) -> None:
        """Record a successful request timestamp for rate limiting."""
        now = self._time_func()
        if source_hex not in self._request_times:
            self._request_times[source_hex] = []
        self._request_times[source_hex].append(now)

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
        except (ValueError, OverflowError, cbor2.CBORDecodeError):
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        from_hex = body["from"] if "from" in body else body.get("node")
        timestamp = body["t"] if "t" in body else body.get("ts")
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
        # Check rate limit before activating
        if not self.check_rate_limit(from_hex):
            return Message(code=aiocoap.TOO_MANY_REQUESTS)
        self._record_request(from_hex)
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

    def _prune_expired(self) -> None:
        now = int(time.time())
        expired = [
            roll_id
            for roll_id, entry in self._rollcalls.items()
            if now - entry["started"] > entry["timeout_s"]
        ]
        for roll_id in expired:
            del self._rollcalls[roll_id]

    def update(
        self,
        roll_id: str,
        responded: list[dict[str, Any]] | None = None,
        missing: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update rollcall state and notify observers (for demo position beacons)."""
        if roll_id not in self._rollcalls:
            self._prune_expired()
            if len(self._rollcalls) >= MAX_ROLLCALLS:
                return
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
        started = data.get("ts", int(time.time()))
        timeout_s = data.get("timeout_s", 60)
        for value in (started, timeout_s):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or (isinstance(value, float) and not math.isfinite(value))
            ):
                return Message(code=aiocoap.BAD_REQUEST)
        if started < 0 or not 0 < timeout_s <= MAX_ROLLCALL_TIMEOUT_S:
            return Message(code=aiocoap.BAD_REQUEST)
        roll_id = str(data["id"])
        self._prune_expired()
        if roll_id not in self._rollcalls and len(self._rollcalls) >= MAX_ROLLCALLS:
            return Message(code=aiocoap.SERVICE_UNAVAILABLE)
        self._rollcalls[roll_id] = {
            "id": roll_id,
            "started": started,
            "timeout_s": timeout_s,
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


class CheckInResource(resource.Resource):
    """Check-in resource ``/checkin`` per spec 18.6.1.

    Individual nodes check in with a group leader by POSTing:

        {
          "node": "0200:...:1111",
          "ts": 1716742800,
          "lat": 37.77,            # optional
          "lon": -122.42,          # optional
          "status": "ok",          # "ok", "help", "delayed"
          "msg": "At checkpoint 2" # optional
        }

    Response: 2.04 Changed

    Stores recent check-ins for retrieval via GET. Oldest entries are
    pruned when storage limit is reached.
    """

    def __init__(self) -> None:
        super().__init__()
        self._checkins: dict[str, dict[str, Any]] = {}

    def _prune_oldest(self) -> None:
        """Remove oldest check-in if at capacity."""
        if len(self._checkins) >= MAX_CHECKINS:
            oldest_node = min(
                self._checkins,
                key=lambda n: self._checkins[n].get("ts", 0),
            )
            del self._checkins[oldest_node]

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "checkin", "ct": str(int(CBOR))}

    async def render_post(self, request: Message) -> Message:
        """POST /checkin to record a check-in (spec 18.6.1)."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            data = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(data, dict):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate required field: node
        node = data.get("node")
        if node is None:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(node, str) or not node:
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate required field: ts
        ts = data.get("ts")
        if ts is None:
            return Message(code=aiocoap.BAD_REQUEST)
        if (
            isinstance(ts, bool)
            or not isinstance(ts, (int, float))
            or (isinstance(ts, float) and not math.isfinite(ts))
            or ts < 0
        ):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate required field: status
        status = data.get("status")
        if status is None:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(status, str) or status not in CHECKIN_STATUS_VALUES:
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate optional fields: lat/lon
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is not None and (
            isinstance(lat, bool)
            or not isinstance(lat, (int, float))
            or (isinstance(lat, float) and not math.isfinite(lat))
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        if lon is not None and (
            isinstance(lon, bool)
            or not isinstance(lon, (int, float))
            or (isinstance(lon, float) and not math.isfinite(lon))
        ):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate optional field: msg
        msg = data.get("msg")
        if msg is not None and not isinstance(msg, str):
            return Message(code=aiocoap.BAD_REQUEST)

        # Store the check-in
        self._prune_oldest()
        entry: dict[str, Any] = {
            "node": node,
            "ts": ts,
            "status": status,
        }
        if lat is not None:
            entry["lat"] = lat
        if lon is not None:
            entry["lon"] = lon
        if msg is not None:
            entry["msg"] = msg

        self._checkins[node] = entry
        return Message(code=CHANGED)

    async def render_get(self, request: Message) -> Message:
        """GET /checkin returns all stored check-ins."""
        payload = cbor2.dumps({"checkins": list(self._checkins.values())})
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = CBOR
        return msg
