# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Confessions resource: anonymous ephemeral messaging board (spec 18.10).

RAM-only storage, no-log guarantee, observable feed with SenML+CBOR payloads.
"""

from __future__ import annotations

import hashlib
import math
import time
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import CBOR, SENML_CBOR
from lichen.senml.codec import SenmlRecord, unpack

# Rate limiting per spec 18.10.3
CONFESSION_COOLDOWN_S = 30  # 1 POST per 30s per node
CONFESSION_HOURLY_MAX = 12  # Max 12 POSTs per hour per node

# Storage limits per spec 18.10.3
CONFESSION_MAX_SIZE = 768  # Max confession payload size in bytes
CONFESSION_STORAGE_LEAF = 2 * 1024  # 2 KB for leaf nodes
CONFESSION_STORAGE_BR = 8 * 1024  # 8 KB for border routers

# TTL per spec 18.10.3
CONFESSION_DEFAULT_TTL = 12 * 3600  # 12 hours default
CONFESSION_MAX_TTL = 48 * 3600  # 48 hours max


def _generate_id(content: str, timestamp: float) -> str:
    """Generate a short hex ID from content hash."""
    data = f"{content}:{timestamp}".encode()
    return hashlib.sha256(data).hexdigest()[:6]


class ConfessionsResource(resource.ObservableResource, resource.PathCapable):
    """Observable ``/confessions`` -- anonymous ephemeral message board.

    **RAM-only storage**: All confessions are held in memory only. No flash
    writes, no NVS, no filesystem persistence. Cleared on any reboot.

    **Rate limiting**: 1 POST per 30s per node, max 12 per hour.

    **Storage**: FIFO eviction when storage limit reached. Oldest confessions
    silently evicted (no back-pressure signaling).

    **SenML+CBOR**: Payloads use SenML format (Content-Format 112) per spec.

    Example POST payload::

        [
          {"bn": "urn:dev:mac:0011223344556677:", "bt": 1721654321},
          {"n": "type", "vs": "confession"},
          {"n": "content", "vs": "The message content here."},
          {"n": "anonymous", "v": 1},
          {"n": "ttl", "v": 43200}
        ]

    GET returns array of confessions with metadata.
    """

    def __init__(
        self,
        *,
        is_border_router: bool = False,
        time_func: Any = None,
    ) -> None:
        """Initialize confessions resource.

        Args:
            is_border_router: If True, use larger 8KB storage; else 2KB.
            time_func: Optional callable returning current time (for testing).
        """
        super().__init__()
        self._is_border_router = is_border_router
        self._storage_limit = CONFESSION_STORAGE_BR if is_border_router else CONFESSION_STORAGE_LEAF
        self._time_func = time_func if time_func is not None else time.time
        # Confessions storage: list of (id, content_dict, size_bytes, expire_time)
        self._confessions: list[dict[str, Any]] = []
        self._total_size = 0
        # Rate limiting: maps source hex -> list of request timestamps (monotonic)
        self._request_times: dict[str, list[float]] = {}

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {
            "rt": "confessions",
            "ct": str(int(SENML_CBOR)),
            "obs": None,
        }

    def _prune_expired(self) -> None:
        """Remove expired confessions."""
        now = self._time_func()
        expired = [c for c in self._confessions if c["expire_time"] <= now]
        for conf in expired:
            self._total_size -= conf["size"]
            self._confessions.remove(conf)

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

    def check_rate_limit(self, source_hex: str) -> tuple[bool, int]:
        """Check if source is within rate limits.

        Returns:
            Tuple of (allowed, retry_after_seconds).
            allowed is True if request is permitted, False if rate-limited.
            retry_after_seconds is the time until next request is allowed.
        """
        self._prune_old_requests(source_hex)
        now = self._time_func()

        if source_hex not in self._request_times:
            return (True, 0)

        timestamps = self._request_times[source_hex]

        # Check cooldown: most recent request must be > 30s ago
        if timestamps:
            time_since_last = now - timestamps[-1]
            if time_since_last < CONFESSION_COOLDOWN_S:
                return (False, math.ceil(CONFESSION_COOLDOWN_S - time_since_last))

        # Check hourly max: must have fewer than 12 requests in last hour
        if len(timestamps) >= CONFESSION_HOURLY_MAX:
            oldest_in_window = timestamps[0]
            retry_after = math.ceil(3600 - (now - oldest_in_window))
            return (False, retry_after)

        return (True, 0)

    def _record_request(self, source_hex: str) -> None:
        """Record a successful request timestamp for rate limiting."""
        now = self._time_func()
        if source_hex not in self._request_times:
            self._request_times[source_hex] = []
        self._request_times[source_hex].append(now)

    def _evict_oldest(self, needed_space: int) -> None:
        """Evict oldest confessions until enough space is available."""
        while self._confessions and self._total_size + needed_space > self._storage_limit:
            oldest = self._confessions.pop(0)
            self._total_size -= oldest["size"]

    def _extract_source_iid(self, records: list[SenmlRecord]) -> str | None:
        """Extract source node IID from SenML base name."""
        for rec in records:
            if rec.bn and rec.bn.startswith("urn:dev:mac:"):
                # Extract hex IID from "urn:dev:mac:XXXX:"
                parts = rec.bn.split(":")
                if len(parts) >= 4:
                    return parts[3].lower()
        return None

    def _extract_field(
        self, records: list[SenmlRecord], name: str, value_type: str = "vs"
    ) -> Any:
        """Extract a field value from SenML records by name."""
        for rec in records:
            if rec.n == name:
                return getattr(rec, value_type, None)
        return None

    def rate_info(self, source_hex: str) -> dict[str, int]:
        """Return rate limit info for a source."""
        self._prune_old_requests(source_hex)
        timestamps = self._request_times.get(source_hex, [])
        remaining = CONFESSION_HOURLY_MAX - len(timestamps)
        now = self._time_func()

        if not timestamps:
            reset_s = 3600
        else:
            oldest_in_window = timestamps[0]
            reset_s = max(0, int(3600 - (now - oldest_in_window)))

        return {"rate_remaining": remaining, "rate_reset_s": reset_s}

    def storage_info(self) -> dict[str, float]:
        """Return storage usage info."""
        return {
            "storage_used_kb": self._total_size / 1024,
            "storage_max_kb": self._storage_limit / 1024,
        }

    def confessions(self) -> list[dict[str, Any]]:
        """Return current confessions list (for testing/inspection)."""
        self._prune_expired()
        return [dict(c) for c in self._confessions]

    def clear(self) -> None:
        """Clear all confessions (simulates reboot)."""
        self._confessions.clear()
        self._total_size = 0
        self._request_times.clear()
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        """GET /confessions or /confessions/{id}."""
        self._prune_expired()

        # Check for specific confession ID in path
        uri_path = request.opt.uri_path or ()
        if len(uri_path) > 1:
            # GET /confessions/{id}
            conf_id = uri_path[-1]
            for conf in self._confessions:
                if conf["id"] == conf_id:
                    now = self._time_func()
                    response_data = {
                        "id": conf["id"],
                        "content": conf["content"],
                        "ts": conf["ts"],
                        "age_s": int(now - conf["ts"]),
                        "anonymous": conf.get("anonymous", True),
                    }
                    if conf.get("lat") is not None:
                        response_data["lat"] = conf["lat"]
                    if conf.get("lon") is not None:
                        response_data["lon"] = conf["lon"]
                    msg = Message(code=CONTENT, payload=cbor2.dumps(response_data))
                    msg.opt.content_format = CBOR
                    max_age = int(conf["expire_time"] - now)
                    if max_age > 0:
                        msg.opt.max_age = max_age
                    return msg
            return Message(code=aiocoap.NOT_FOUND)

        # GET /confessions - return all
        # Parse query params
        query = {}
        if request.opt.uri_query:
            for q in request.opt.uri_query:
                if "=" in q:
                    k, v = q.split("=", 1)
                    query[k] = v

        count_limit = int(query.get("count", "100"))
        since_ts = float(query.get("since", "0"))

        now = self._time_func()
        confessions_list = []
        for conf in self._confessions:
            if conf["ts"] < since_ts:
                continue
            entry = {
                "id": conf["id"],
                "content": conf["content"],
                "ts": conf["ts"],
                "age_s": int(now - conf["ts"]),
            }
            if conf.get("lat") is not None:
                entry["lat"] = conf["lat"]
            if conf.get("lon") is not None:
                entry["lon"] = conf["lon"]
            confessions_list.append(entry)
            if len(confessions_list) >= count_limit:
                break

        response_data = {
            "count": len(confessions_list),
            "confessions": confessions_list,
            **self.storage_info(),
        }

        msg = Message(code=CONTENT, payload=cbor2.dumps(response_data))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        """POST /confessions -- submit a new confession."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)

        # Check payload size
        if len(request.payload) > CONFESSION_MAX_SIZE:
            return Message(code=aiocoap.REQUEST_ENTITY_TOO_LARGE)

        # Parse SenML payload
        try:
            records = unpack(request.payload)
        except (ValueError, cbor2.CBORDecodeError):
            return Message(code=aiocoap.BAD_REQUEST)

        if not records:
            return Message(code=aiocoap.BAD_REQUEST)

        # Extract source IID for rate limiting
        source_iid = self._extract_source_iid(records)
        if source_iid is None:
            return Message(code=aiocoap.BAD_REQUEST)

        # Check rate limit
        allowed, retry_after = self.check_rate_limit(source_iid)
        if not allowed:
            msg = Message(code=aiocoap.TOO_MANY_REQUESTS)
            # aiocoap doesn't have direct Retry-After support, encode in payload
            msg.payload = cbor2.dumps({"retry_after": retry_after})
            msg.opt.content_format = CBOR
            return msg

        # Extract confession data
        confession_type = self._extract_field(records, "type", "vs")
        if confession_type is not None and confession_type != "confession":
            return Message(code=aiocoap.BAD_REQUEST)

        content = self._extract_field(records, "content", "vs")
        if content is None or not isinstance(content, str):
            return Message(code=aiocoap.BAD_REQUEST)

        # Extract optional fields
        anonymous_val = self._extract_field(records, "anonymous", "v")
        anonymous = anonymous_val != 0 if anonymous_val is not None else True

        ttl_val = self._extract_field(records, "ttl", "v")
        if ttl_val is not None:
            if not isinstance(ttl_val, (int, float)) or ttl_val <= 0:
                return Message(code=aiocoap.BAD_REQUEST)
            ttl = min(int(ttl_val), CONFESSION_MAX_TTL)
        else:
            ttl = CONFESSION_DEFAULT_TTL

        lat = self._extract_field(records, "lat", "v")
        lon = self._extract_field(records, "lon", "v")

        # Extract base time
        base_time = None
        for rec in records:
            if rec.bt is not None:
                base_time = float(rec.bt)
                break
        if base_time is None:
            base_time = self._time_func()

        # Generate confession ID
        conf_id = _generate_id(content, base_time)

        # Calculate size (approximate: content + overhead)
        conf_size = len(content.encode()) + 64  # overhead for metadata

        # Prune expired and evict if needed
        self._prune_expired()
        self._evict_oldest(conf_size)

        # Store confession
        now = self._time_func()
        confession = {
            "id": conf_id,
            "content": content,
            "ts": base_time,
            "expire_time": now + ttl,
            "size": conf_size,
            "anonymous": anonymous,
            "source": None if anonymous else source_iid,
        }
        if lat is not None:
            confession["lat"] = lat
        if lon is not None:
            confession["lon"] = lon

        self._confessions.append(confession)
        self._total_size += conf_size

        # Record request for rate limiting
        self._record_request(source_iid)

        # Notify observers
        self.updated_state()

        # Build response
        msg = Message(code=CREATED)
        msg.opt.location_path = ("confessions", conf_id)
        msg.opt.max_age = ttl
        return msg
