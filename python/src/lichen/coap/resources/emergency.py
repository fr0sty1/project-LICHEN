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
from lichen.coap.sos_origin import (
    OriginSequenceTracker,
    SosOriginSignature,
    canonicalize_sos_payload,
    verify_sos_origin,
)
from lichen.crypto.identity import _pubkey_to_iid
from lichen.crypto.trust import TrustError

MAX_ROLLCALLS = 256
MAX_ROLLCALL_TIMEOUT_S = 7 * 86400
MAX_CHECKINS = 256  # Maximum stored check-ins

# SOS rate limiting per spec (per-source limits)
SOS_COOLDOWN_S = 600  # 10-minute cooldown period per source
SOS_HOURLY_MAX = 3  # Maximum 3 requests per hour from same source
SOS_BURST_MAX = 2  # Max messages per cooldown period ("Burst allowance: 2")

# Fields carrying the origin-signature envelope; excluded from the signed
# core alert dict (spec 18.4.1 signs only the alert payload).
_SOS_ENVELOPE_FIELDS = frozenset({"pubkey", "sig"})

# Valid check-in status values per spec 18.6.1
CHECKIN_STATUS_VALUES = frozenset({"ok", "help", "delayed"})


class SosResource(resource.ObservableResource):
    """Observable ``/sos`` — emergency (POST per spec/12-apps.md 18.4).

    State is a CBOR map::

        {"active": true, "from": "<hex-eui64>", "t": <float>}  # active
        {"active": false, "from": null, "t": null}              # idle

    **POST** activates with ``{"type":"sos", "node":..., "ts":...}`` plus the
    origin-signature envelope ``{"pubkey": <32B>, "sig": <56B>}`` (or legacy
    {"from","t"} core fields).  Per spec 18.4.1 the origin signature is
    REQUIRED: the pubkey must derive to the claimed node IID, the Schnorr48
    signature must verify over the canonical CBOR of the core alert dict,
    and the origin sequence must strictly advance; anything else is dropped
    with 4.01.
    **DELETE** cancels.  **GET** and **Observe** expose the current state to all
    subscribers so neighbouring nodes can relay/escalate the alert.

    The repeating-beacon behaviour (every 30 s) is the responsibility of the
    application layer driving :meth:`retrigger`; the resource itself only
    tracks state and notifies on changes.

    Rate limiting (spec 18.4.1, over monotonic uptime): each source gets at
    most SOS_HOURLY_MAX messages per rolling hour; a new cooldown period
    starts whenever a message arrives at or after ``period_start +
    SOS_COOLDOWN_S``; within an open period at most SOS_BURST_MAX messages
    are allowed ("burst allowance"). Excess requests get 4.29 with a CBOR
    ``{"retry_after": N}`` payload.
    """

    def __init__(
        self,
        time_func: Any = None,
        trust_store: Any = None,
    ) -> None:
        """Initialize SOS resource.

        Args:
            time_func: Optional callable returning current monotonic time
                       (for testing). Defaults to time.monotonic per spec
                       18.4.1 ("rate limiting uses monotonic uptime").
            trust_store: Optional TrustStore for TOFU pinning of verified
                         origin pubkeys. When None, only cryptographic
                         verification (key-to-IID binding + signature) is
                         enforced.
        """
        super().__init__()
        self._active = False
        self._from: str | None = None
        self._t: float | None = None
        self._time_func = time_func if time_func is not None else time.monotonic
        self._trust_store = trust_store
        # Per-source rate limiting: maps source hex -> list of request timestamps
        self._request_times: dict[str, list[float]] = {}
        # Cooldown period anchor per source (burst budget resets each period)
        self._period_start: dict[str, float] = {}
        # Monotonic origin-sequence gate for signed POSTs
        self._sequences = OriginSequenceTracker()

    def _prune_old_requests(self, source_hex: str) -> None:
        """Remove request timestamps older than 1 hour for the given source."""
        if source_hex not in self._request_times:
            return
        now = self._time_func()
        cutoff = now - 3600  # 1 hour
        self._request_times[source_hex] = [
            ts for ts in self._request_times[source_hex] if ts >= cutoff
        ]
        timestamps = self._request_times[source_hex]
        if not timestamps:
            del self._request_times[source_hex]
            self._period_start.pop(source_hex, None)
        else:
            # Keep the period anchor inside the retained window; if the old
            # anchor was pruned, the oldest retained entry starts the period.
            anchor = self._period_start.get(source_hex)
            if anchor is None or anchor < timestamps[0]:
                self._period_start[source_hex] = timestamps[0]

    def evaluate_rate_limit(self, source_hex: str) -> tuple[bool, int, str]:
        """Evaluate rate limits for *source_hex*.

        Returns:
            ``(allowed, retry_after_s, reason)`` where *reason* is one of
            ``first_sos``, ``cooldown_elapsed``, ``within_burst``,
            ``cooldown_active``, or ``hourly_limit_exceeded``.

        Semantics (spec 18.4.1 rate table):
        - hourly gate first: >= SOS_HOURLY_MAX requests in the past hour -> deny
        - at/after ``period_start + SOS_COOLDOWN_S`` a new period begins -> allow
        - within an open period: allowed while fewer than SOS_BURST_MAX
          messages have been sent since ``period_start``
        - otherwise denied until the current period's cooldown expires
        """
        self._prune_old_requests(source_hex)
        now = self._time_func()
        timestamps = self._request_times.get(source_hex)
        if not timestamps:
            return True, 0, "first_sos"
        if len(timestamps) >= SOS_HOURLY_MAX:
            retry_after = math.ceil(3600 - (now - timestamps[0]))
            return False, max(1, int(retry_after)), "hourly_limit_exceeded"
        period_start = self._period_start.get(source_hex, timestamps[0])
        if now - period_start >= SOS_COOLDOWN_S:
            return True, 0, "cooldown_elapsed"
        period_count = sum(1 for ts in timestamps if ts >= period_start)
        if period_count < SOS_BURST_MAX:
            return True, 0, "within_burst"
        retry_after = math.ceil(period_start + SOS_COOLDOWN_S - now)
        return False, max(1, int(retry_after)), "cooldown_active"

    def check_rate_limit(self, source_hex: str) -> bool:
        """Check if source is within rate limits.

        Returns True if request is allowed, False if rate-limited.

        See :meth:`evaluate_rate_limit` for the full semantics and the
        retry-after value carried on 4.29 responses.
        """
        allowed, _retry_after, _reason = self.evaluate_rate_limit(source_hex)
        return allowed

    def _record_request(self, source_hex: str) -> None:
        """Record a successful request timestamp for rate limiting."""
        now = self._time_func()
        timestamps = self._request_times.setdefault(source_hex, [])
        anchor = self._period_start.get(source_hex)
        if not timestamps or anchor is None or now - anchor >= SOS_COOLDOWN_S:
            self._period_start[source_hex] = now
        timestamps.append(now)

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
        # Spec 18.4.1: SOS MUST carry a valid origin signature; unsigned or
        # invalid messages are dropped. The envelope carries the signer's
        # pubkey (32 B) and the wire origin signature (8 B seq + 48 B sig).
        pubkey = body.get("pubkey")
        sig_blob = body.get("sig")
        if (
            not isinstance(pubkey, bytes)
            or len(pubkey) != 32
            or not isinstance(sig_blob, bytes)
        ):
            return Message(code=aiocoap.UNAUTHORIZED)
        try:
            origin_sig = SosOriginSignature.from_bytes(sig_blob)
        except ValueError:
            return Message(code=aiocoap.UNAUTHORIZED)
        iid = bytes.fromhex(from_hex.lower())
        if _pubkey_to_iid(pubkey) != iid:
            return Message(code=aiocoap.UNAUTHORIZED)
        core_alert = {k: v for k, v in body.items() if k not in _SOS_ENVELOPE_FIELDS}
        origin_addr = b"\x02\x00" + b"\x00" * 6 + iid
        if not verify_sos_origin(
            pubkey, origin_addr, canonicalize_sos_payload(core_alert), origin_sig
        ):
            return Message(code=aiocoap.UNAUTHORIZED)
        if self._trust_store is not None:
            try:
                self._trust_store.verify_or_pin(pubkey, iid)
            except TrustError:
                return Message(code=aiocoap.UNAUTHORIZED)
        # Replay gate: only strictly advancing sequences may activate.
        source_key = from_hex.lower()
        last_seq = self._sequences.last_seen(source_key)
        if last_seq is not None and origin_sig.origin_sequence <= last_seq:
            return Message(code=aiocoap.UNAUTHORIZED)
        # Check rate limit before activating
        allowed, retry_after, _reason = self.evaluate_rate_limit(source_key)
        if not allowed:
            msg = Message(code=aiocoap.TOO_MANY_REQUESTS)
            msg.payload = cbor2.dumps({"retry_after": retry_after})
            msg.opt.content_format = CBOR
            return msg
        self._sequences.accept(source_key, origin_sig.origin_sequence)
        self._record_request(source_key)
        self.activate(bytes.fromhex(from_hex), timestamp)
        return Message(code=CREATED)

    async def render_delete(self, request: Message) -> Message:
        """DELETE /sos cancels an active alert. Requires origin authentication.

        Only the originator of the active alert may cancel it. The request must
        carry a valid origin-signature envelope (pubkey + sig) and the pubkey
        must derive to the IID of the active SOS originator.
        """
        # SECURITY: Require active alert to cancel
        if not self._active or self._from is None:
            return Message(code=aiocoap.NOT_FOUND)
        # SECURITY: Require signed payload for authentication
        if not request.payload:
            return Message(code=aiocoap.UNAUTHORIZED)
        try:
            body = _decode_single_cbor(request.payload)
        except (ValueError, OverflowError, cbor2.CBORDecodeError):
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        # SECURITY: Require origin-signature envelope
        pubkey = body.get("pubkey")
        sig_blob = body.get("sig")
        if (
            not isinstance(pubkey, bytes)
            or len(pubkey) != 32
            or not isinstance(sig_blob, bytes)
        ):
            return Message(code=aiocoap.UNAUTHORIZED)
        try:
            origin_sig = SosOriginSignature.from_bytes(sig_blob)
        except ValueError:
            return Message(code=aiocoap.UNAUTHORIZED)
        # SECURITY: Verify requester is the originator of the active alert
        active_iid = bytes.fromhex(self._from.lower())
        if _pubkey_to_iid(pubkey) != active_iid:
            return Message(code=aiocoap.UNAUTHORIZED)
        # SECURITY: Verify signature over canonical cancel payload
        core_cancel = {k: v for k, v in body.items() if k not in _SOS_ENVELOPE_FIELDS}
        origin_addr = b"\x02\x00" + b"\x00" * 6 + active_iid
        if not verify_sos_origin(
            pubkey, origin_addr, canonicalize_sos_payload(core_cancel), origin_sig
        ):
            return Message(code=aiocoap.UNAUTHORIZED)
        # SECURITY: Replay gate for cancel requests
        source_key = self._from.lower()
        last_seq = self._sequences.last_seen(source_key)
        if last_seq is not None and origin_sig.origin_sequence <= last_seq:
            return Message(code=aiocoap.UNAUTHORIZED)
        self._sequences.accept(source_key, origin_sig.origin_sequence)
        self.cancel()
        return Message(code=aiocoap.DELETED)


class RollcallResource(resource.ObservableResource):
    """Demo CoAP resource for conference rollcall use case per spec/12-apps.md 18.6.
    Supports POST to initiate, observable GET for status with SenML position data.
    Used by LCI-based conference demo application.
    """

    def __init__(self, time_func: Any = None) -> None:
        """Initialize Rollcall resource.

        Args:
            time_func: Optional callable returning current time (for testing).
                       Defaults to time.monotonic per spec 18.6.
        """
        super().__init__()
        self._time_func = time_func if time_func is not None else time.monotonic
        self._rollcalls: dict[str, dict[str, Any]] = {}

    def _prune_expired(self) -> None:
        now = int(self._time_func())
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
                "started": int(self._time_func()),
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
        started = data.get("ts", int(self._time_func()))
        timeout_s = data.get("timeout_s", 60)
        for value in (started, timeout_s):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or (isinstance(value, float) and not math.isfinite(value))
            ):
                return Message(code=aiocoap.BAD_REQUEST)
        now = int(self._time_func())
        # Reject far-future timestamps that would never expire; allow 60s clock skew
        if started < 0 or started > now + 60 or not 0 < timeout_s <= MAX_ROLLCALL_TIMEOUT_S:
            return Message(code=aiocoap.BAD_REQUEST)
        # Validate id type: only str or int allowed (null/bytes/list/dict rejected)
        raw_id = data["id"]
        if raw_id is None or isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
            return Message(code=aiocoap.BAD_REQUEST)
        roll_id = str(raw_id)
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
        self._prune_expired()
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

    async def render_delete(self, request: Message) -> Message:
        """DELETE /rollcall/{id} removes a rollcall entry."""
        self._prune_expired()
        roll_id = None
        if request.opt.uri_path and len(request.opt.uri_path) > 1:
            roll_id = request.opt.uri_path[-1]
        if not roll_id or roll_id not in self._rollcalls:
            return Message(code=aiocoap.NOT_FOUND)
        del self._rollcalls[roll_id]
        self.updated_state()
        return Message(code=aiocoap.DELETED)


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

        # Validate optional fields: lat/lon per the SOS/checkin coordinate
        # contract (spec 18.4.2, mirrored from lichen/subsys/lichen/coap/
        # sos_alert.c): latitude [-90, 90] and longitude [-180, 180]
        # INCLUSIVE; non-finite values are rejected the same way. Values
        # that were previously accepted stay accepted (pairs within the
        # documented ranges, integer coordinates, -0.0). Location is
        # all-or-none: exactly one half of the pair is invalid input.
        lat = data.get("lat")
        lon = data.get("lon")
        for value, limit in ((lat, 90), (lon, 180)):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return Message(code=aiocoap.BAD_REQUEST)
            if isinstance(value, float) and not math.isfinite(value):
                return Message(code=aiocoap.BAD_REQUEST)
            if value < -limit or value > limit:
                return Message(code=aiocoap.BAD_REQUEST)
        if (lat is None) != (lon is None):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate optional field: msg
        msg = data.get("msg")
        if msg is not None and not isinstance(msg, str):
            return Message(code=aiocoap.BAD_REQUEST)

        # Store the check-in (only prune if this is a new node)
        if node not in self._checkins:
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
