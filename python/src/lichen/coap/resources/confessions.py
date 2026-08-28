# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Confessions resource: anonymous ephemeral messaging board (spec 18.10).

RAM-only storage, no-log guarantee, observable feed. POST is SenML+CBOR
(Content-Format 112). Collection GET is the 18.10.7 CBOR query/display map.
"""

from __future__ import annotations

import math
import secrets
import time
from ipaddress import IPv6Address
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.senml.codec import SenmlRecord, unpack

# Shared quota when the request has no IPv6 source IID and no OSCORE identity.
# SECURITY: never key a bucket on client-supplied SenML ``bn``.
_UNAUTHENTICATED_RATE_KEY = "unauthenticated"

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

_ID_BYTES = 3  # 6 hex chars (e.g. "8a4f2b")
_HEX_LOWER = frozenset("0123456789abcdef")
_DEFAULT_GET_COUNT = 100


def _generate_id() -> str:
    """Generate a 6-character lowercase hex confession ID.

    SECURITY: CSPRNG only. Do not hash content or timestamps; a content
    fingerprint lets an observer verify a guessed confession without
    reading the body, and makes Location-Path predictable.
    """
    return secrets.token_hex(_ID_BYTES)


def _is_confession_id(value: str) -> bool:
    """Return True if value is a canonical 6-char lowercase hex id."""
    return len(value) == _ID_BYTES * 2 and all(c in _HEX_LOWER for c in value)


def _parse_query(request: Message) -> dict[str, str]:
    query: dict[str, str] = {}
    for item in request.opt.uri_query or ():
        if "=" in item:
            key, value = item.split("=", 1)
            query[key] = value
    return query


def _extract_claimed_iid(records: list[SenmlRecord]) -> str | None:
    """Extract the client-claimed IID from SenML ``bn`` ``urn:dev:mac:<hex>:``.

    SECURITY: this value is attacker-controlled. It MUST NOT key rate
    limits or be stored as ``sender`` unless it matches an authenticated
    IPv6 source IID.
    """
    for rec in records:
        if rec.bn and rec.bn.startswith("urn:dev:mac:"):
            parts = rec.bn.split(":")
            if len(parts) >= 4 and parts[3]:
                return parts[3].lower()
    return None


def _host_from_hostinfo(hostinfo: str) -> str:
    """Return the host portion of an aiocoap ``hostinfo`` string."""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        end = hostinfo.find("]")
        if end > 0:
            return hostinfo[1:end]
        return hostinfo
    # hostname:port or IPv4:port. Unbracketed IPv6 cannot carry a port.
    if hostinfo.count(":") == 1:
        return hostinfo.rsplit(":", 1)[0]
    return hostinfo


def _ipv6_source_iid(request: Message) -> str | None:
    """Return the 16-hex IPv6 source IID from ``request.remote``, or None.

    Link-local ``fe80::/10`` and native ``0200::/8`` both carry the
    key-derived IID in the low 64 bits (spec 6.1). Multicast, unspecified,
    and IPv4-mapped addresses are not node IIDs.
    """
    remote = getattr(request, "remote", None)
    hostinfo = getattr(remote, "hostinfo", None)
    if not isinstance(hostinfo, str) or not hostinfo:
        return None
    host = _host_from_hostinfo(hostinfo)
    try:
        addr = IPv6Address(host)
    except ValueError:
        return None
    if addr.is_multicast or addr.is_unspecified or addr.ipv4_mapped is not None:
        return None
    return addr.packed[8:16].hex()


def _oscore_identity(request: Message) -> str | None:
    """Return an OSCORE identity when the request was OSCORE-protected, or None.

    Pairwise OSCORE reveals a sender identity. Group contexts are still an
    authenticated bucket (shared among group members) when no IPv6 source
    IID is available. Spec 18.10.3 prefers per-node IID over OSCORE.
    """
    oscore_context = getattr(request, "oscore_context", None)
    if isinstance(oscore_context, str) and oscore_context:
        return oscore_context
    if oscore_context is not None:
        identity = getattr(oscore_context, "recipient_id", None) or getattr(
            oscore_context, "kid", None
        )
        if isinstance(identity, (bytes, bytearray)) and identity:
            return bytes(identity).hex()
        if isinstance(identity, str) and identity:
            return identity
        rendered = str(oscore_context)
        if rendered:
            return rendered
    context_id = getattr(request, "oscore_context_id", None)
    if isinstance(context_id, str) and context_id:
        return context_id
    if getattr(request, "oscore_protected", False):
        return "default"
    if getattr(request.opt, "oscore", None) is not None:
        return "default"
    return None


def _authenticated_rate_key(request: Message) -> str:
    """Return the rate-limit key for *request*.

    Preference (spec 18.10.3: per-node IID, not OSCORE context):
    1. IPv6 source IID from ``request.remote``
    2. OSCORE identity when present (no IPv6 source)
    3. A single unauthenticated bucket -- never a client-supplied ``bn``
    """
    iid = _ipv6_source_iid(request)
    if iid is not None:
        return iid
    oscore = _oscore_identity(request)
    if oscore is not None:
        return f"oscore:{oscore}"
    return _UNAUTHENTICATED_RATE_KEY


def _displayed_sender(*, claimed_iid: str | None, authenticated_iid: str | None) -> str | None:
    """Return the stored sender IID for a non-anonymous confession.

    SECURITY: client-supplied ``bn`` is displayed only when it equals the
    authenticated IPv6 source IID. Mismatches and missing authentication
    omit sender rather than impersonate another node.
    """
    if authenticated_iid is None or claimed_iid is None:
        return None
    if claimed_iid != authenticated_iid:
        return None
    return authenticated_iid


def _extract_field(records: list[SenmlRecord], name: str, value_type: str = "vs") -> Any:
    """Extract a field value from SenML records by name."""
    for rec in records:
        if rec.n == name:
            return getattr(rec, value_type, None)
    return None


def _extract_anonymous(records: list[SenmlRecord]) -> bool:
    """Return the anonymous flag; default True per spec 18.10.1."""
    for rec in records:
        if rec.n != "anonymous":
            continue
        if rec.vb is not None:
            return bool(rec.vb)
        if rec.v is not None:
            return rec.v != 0
    return True


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


class ConfessionsResource(resource.ObservableResource):
    """Observable ``/confessions`` -- anonymous ephemeral message board.

    **RAM-only storage**: All confessions are held in memory only. No flash
    writes, no NVS, no filesystem persistence. Cleared on any reboot.

    **Rate limiting**: 1 POST per 30s per authenticated node IID (IPv6
    source IID, or OSCORE identity when no IPv6 source is available),
    max 12 per hour, using monotonic uptime (spec 18.10.3). Client-supplied
    SenML ``bn`` is not a quota key.

    **Storage**: FIFO eviction when the storage limit is reached. Oldest
    confessions silently vanish (no back-pressure).

    **OSCORE**: Optional on POST. GET is public. OSCORE context is never
    stored with confession content.
    """

    def __init__(
        self,
        *,
        is_border_router: bool = False,
        storage_limit: int | None = None,
        time_func: Any = None,
        node_iid: str | None = None,
        persist: bool = False,
    ) -> None:
        """Initialize confessions resource.

        Args:
            is_border_router: If True, use 8KB storage; else 2KB.
            storage_limit: Optional explicit byte budget (overrides BR/leaf).
            time_func: Optional callable returning current time (for testing).
                Defaults to ``time.monotonic`` so rate limits cannot be
                bypassed by wall-clock spoofing.
            node_iid: Optional local node IID used for GET rate-remaining.
            persist: Operator override that voids the no-log guarantee.
                Storage remains RAM in this oracle; GET surfaces ``logging``.
        """
        super().__init__()
        if storage_limit is None:
            storage_limit = CONFESSION_STORAGE_BR if is_border_router else CONFESSION_STORAGE_LEAF
        if (
            isinstance(storage_limit, bool)
            or not isinstance(storage_limit, int)
            or storage_limit <= 0
        ):
            raise ValueError("storage_limit must be a positive integer")
        self._is_border_router = is_border_router
        self._storage_limit = storage_limit
        self._time_func = time_func if time_func is not None else time.monotonic
        self._node_iid = node_iid.lower() if node_iid else None
        self._persist = bool(persist)
        # Oldest-first RAM store. Never written to flash/NVS/filesystem.
        self._confessions: list[dict[str, Any]] = []
        self._total_size = 0
        # Rate limiting: authenticated identity -> request timestamps
        # (same clock as time_func). Keys are IPv6 IIDs, ``oscore:*``, or
        # ``unauthenticated`` -- never client-supplied SenML ``bn``.
        self._request_times: dict[str, list[float]] = {}

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {
            "rt": "confessions",
            "ct": str(int(CBOR)),
            "obs": None,
        }

    def _prune_expired(self) -> None:
        """Remove expired confessions (TTL measured from receive time)."""
        now = self._time_func()
        kept: list[dict[str, Any]] = []
        size = 0
        for conf in self._confessions:
            if conf["expire_time"] > now:
                kept.append(conf)
                size += conf["size"]
        self._confessions = kept
        self._total_size = size

    def _reap_stale_rate_buckets(self) -> None:
        """Drop timestamps older than 1 hour from every rate bucket.

        SECURITY: reaping is global. Abandoned keys (including spoofed
        ones from older code) must not wait for that key to return.
        """
        now = self._time_func()
        cutoff = now - 3600  # 1 hour
        stale: list[str] = []
        for key, timestamps in self._request_times.items():
            kept = [ts for ts in timestamps if ts > cutoff]
            if kept:
                self._request_times[key] = kept
            else:
                stale.append(key)
        for key in stale:
            del self._request_times[key]

    def _prune_old_requests(self, source_hex: str) -> None:
        """Remove request timestamps older than 1 hour.

        *source_hex* is kept for call-site compatibility; every bucket is
        reaped so stale identities do not accumulate.
        """
        del source_hex
        self._reap_stale_rate_buckets()

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

        # 30s cooldown is the tighter limit and is checked first (18.10.3).
        if timestamps:
            time_since_last = now - timestamps[-1]
            if time_since_last < CONFESSION_COOLDOWN_S:
                return (False, math.ceil(CONFESSION_COOLDOWN_S - time_since_last))

        if len(timestamps) >= CONFESSION_HOURLY_MAX:
            oldest_in_window = timestamps[0]
            retry_after = math.ceil(3600 - (now - oldest_in_window))
            return (False, retry_after)

        return (True, 0)

    def _record_request(self, source_hex: str) -> None:
        """Record a successful request timestamp for rate limiting."""
        self._reap_stale_rate_buckets()
        now = self._time_func()
        if source_hex not in self._request_times:
            self._request_times[source_hex] = []
        self._request_times[source_hex].append(now)

    def _evict_oldest(self, needed_space: int) -> None:
        """Evict oldest confessions until enough space is available."""
        while self._confessions and self._total_size + needed_space > self._storage_limit:
            oldest = self._confessions.pop(0)
            self._total_size -= oldest["size"]

    def _existing_ids(self) -> set[str]:
        return {conf["id"] for conf in self._confessions}

    def _unique_id(self) -> str:
        taken = self._existing_ids()
        conf_id = _generate_id()
        while conf_id in taken:
            conf_id = _generate_id()
        return conf_id

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

    def confession(self, conf_id: str) -> dict[str, Any] | None:
        """Return one live confession dict, or None if missing/expired."""
        self._prune_expired()
        if not _is_confession_id(conf_id):
            return None
        for conf in self._confessions:
            if conf["id"] == conf_id:
                return dict(conf)
        return None

    def clear(self) -> None:
        """Clear all confessions (simulates reboot). Rate table is RAM-only too."""
        self._confessions.clear()
        self._total_size = 0
        self._request_times.clear()
        self.updated_state()

    def add_confession(
        self,
        content: str,
        *,
        confession_id: str | None = None,
        ts: float | None = None,
        ttl: int | None = None,
        size: int | None = None,
        anonymous: bool = True,
        source: str | None = None,
        lat: float | None = None,
        lon: float | None = None,
        confession_type: str = "confession",
    ) -> str:
        """Insert a confession directly (tests, mesh delivery, reboot seeds).

        Does not consume the POST rate budget. Evicts oldest entries if needed.
        """
        now = self._time_func()
        if ts is None:
            ts = now
        if ttl is None:
            ttl = CONFESSION_DEFAULT_TTL
        ttl = min(max(int(ttl), 0), CONFESSION_MAX_TTL)
        if ttl <= 0:
            ttl = CONFESSION_DEFAULT_TTL
        if size is None:
            size = len(content.encode()) + 64
        if size < 0:
            raise ValueError("size must be non-negative")
        self._prune_expired()
        self._evict_oldest(size)
        if confession_id is None:
            confession_id = self._unique_id()
        elif confession_id in self._existing_ids() or not _is_confession_id(confession_id):
            raise ValueError("confession_id must be a unique 6-char lowercase hex id")
        stored = {
            "id": confession_id,
            "content": content,
            "type": confession_type,
            "ts": ts,
            "received_at": now,
            "expire_time": now + ttl,
            "size": size,
            "anonymous": anonymous,
            # SECURITY: never store OSCORE context / key id with content.
            "source": None if anonymous else source,
        }
        if lat is not None:
            stored["lat"] = lat
        if lon is not None:
            stored["lon"] = lon
        self._confessions.append(stored)
        self._total_size += size
        self.updated_state()
        return confession_id

    def _entry_public(self, conf: dict[str, Any], now: float, *, detail: bool) -> dict[str, Any]:
        age_s = max(0, int(now - conf["received_at"]))
        entry: dict[str, Any] = {
            "id": conf["id"],
            "content": conf["content"],
            "ts": conf["ts"],
            "age_s": age_s,
        }
        if conf.get("lat") is not None:
            entry["lat"] = conf["lat"]
        if conf.get("lon") is not None:
            entry["lon"] = conf["lon"]
        if detail:
            entry["anonymous"] = conf.get("anonymous", True)
            if not entry["anonymous"] and conf.get("source"):
                entry["sender"] = conf["source"]
        return entry

    def _collection_body(
        self,
        *,
        count_limit: int,
        since_ts: float | None,
        after_ts: float | None,
        type_filter: str | None,
        rate_key: str | None,
    ) -> dict[str, Any]:
        self._prune_expired()
        self._reap_stale_rate_buckets()
        now = self._time_func()
        selected: list[dict[str, Any]] = []
        for conf in self._confessions:
            if since_ts is not None and conf["ts"] < since_ts:
                continue
            if after_ts is not None and conf["ts"] <= after_ts:
                continue
            if type_filter is not None and conf.get("type", "confession") != type_filter:
                continue
            selected.append(conf)
        selected.reverse()  # newest first (18.10.7 listing)
        selected = selected[:count_limit]
        entries = [self._entry_public(conf, now, detail=False) for conf in selected]
        body: dict[str, Any] = {
            "count": len(entries),
            "confessions": entries,
            **self.storage_info(),
        }
        # Rate info is for the requesting client, not the host. Omit if the
        # requester cannot be authenticated (spec 18.10.7 acceptance criteria).
        if rate_key is not None and rate_key != _UNAUTHENTICATED_RATE_KEY:
            body.update(self.rate_info(rate_key))
        if self._persist:
            body["logging"] = True
        return body

    def render_one(self, conf_id: str) -> Message:
        """GET /confessions/{id} body (used by the PathCapable details resource)."""
        conf = self.confession(conf_id)
        if conf is None:
            return Message(code=aiocoap.NOT_FOUND)
        now = self._time_func()
        payload = self._entry_public(conf, now, detail=True)
        msg = Message(code=CONTENT, payload=cbor2.dumps(payload))
        msg.opt.content_format = CBOR
        max_age = int(conf["expire_time"] - now)
        if max_age > 0:
            msg.opt.max_age = max_age
        return msg

    async def render_get(self, request: Message) -> Message:
        """GET /confessions or /confessions/{id}."""
        uri_path = request.opt.uri_path or ()
        if len(uri_path) == 1 and _is_confession_id(uri_path[0]):
            return self.render_one(uri_path[0])
        if len(uri_path) > 1:
            return self.render_one(uri_path[-1])

        query = _parse_query(request)
        try:
            count_limit = int(query["count"]) if "count" in query else _DEFAULT_GET_COUNT
        except (TypeError, ValueError):
            return Message(code=aiocoap.BAD_REQUEST)
        if isinstance(count_limit, bool) or count_limit < 0:
            return Message(code=aiocoap.BAD_REQUEST)

        since_ts: float | None = None
        after_ts: float | None = None
        if "since" in query:
            try:
                since_ts = float(query["since"])
            except ValueError:
                return Message(code=aiocoap.BAD_REQUEST)
            if not math.isfinite(since_ts):
                return Message(code=aiocoap.BAD_REQUEST)
        if "after" in query:
            try:
                after_ts = float(query["after"])
            except ValueError:
                return Message(code=aiocoap.BAD_REQUEST)
            if not math.isfinite(after_ts):
                return Message(code=aiocoap.BAD_REQUEST)

        type_filter = query.get("type") or None
        rate_key = _authenticated_rate_key(request)
        body = self._collection_body(
            count_limit=count_limit,
            since_ts=since_ts,
            after_ts=after_ts,
            type_filter=type_filter,
            rate_key=rate_key,
        )
        msg = Message(code=CONTENT, payload=cbor2.dumps(body))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        """POST /confessions -- submit a new confession."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)

        if len(request.payload) > CONFESSION_MAX_SIZE:
            return Message(code=aiocoap.REQUEST_ENTITY_TOO_LARGE)

        try:
            _decode_single_cbor(request.payload)
            records = unpack(request.payload)
        except (ValueError, TypeError):
            return Message(code=aiocoap.BAD_REQUEST)

        if not records:
            return Message(code=aiocoap.BAD_REQUEST)

        claimed_iid = _extract_claimed_iid(records)
        if claimed_iid is None:
            return Message(code=aiocoap.BAD_REQUEST)

        # SECURITY: quota is keyed on authenticated identity, never SenML bn.
        rate_key = _authenticated_rate_key(request)
        allowed, retry_after = self.check_rate_limit(rate_key)
        if not allowed:
            msg = Message(code=aiocoap.TOO_MANY_REQUESTS)
            msg.payload = cbor2.dumps({"retry_after": retry_after})
            msg.opt.content_format = CBOR
            msg.opt.max_age = retry_after
            return msg

        confession_type = _extract_field(records, "type", "vs")
        if confession_type is not None and confession_type != "confession":
            return Message(code=aiocoap.BAD_REQUEST)

        content = _extract_field(records, "content", "vs")
        if content is None or not isinstance(content, str) or content == "":
            return Message(code=aiocoap.BAD_REQUEST)

        anonymous = _extract_anonymous(records)
        authenticated_iid = _ipv6_source_iid(request)
        stored_source = (
            None
            if anonymous
            else _displayed_sender(claimed_iid=claimed_iid, authenticated_iid=authenticated_iid)
        )

        ttl_val = _extract_field(records, "ttl", "v")
        if ttl_val is not None:
            if not _finite_number(ttl_val) or ttl_val <= 0:
                return Message(code=aiocoap.BAD_REQUEST)
            ttl = min(int(ttl_val), CONFESSION_MAX_TTL)
        else:
            ttl = CONFESSION_DEFAULT_TTL

        lat = _extract_field(records, "lat", "v")
        lon = _extract_field(records, "lon", "v")
        if lat is not None and not _finite_number(lat):
            return Message(code=aiocoap.BAD_REQUEST)
        if lon is not None and not _finite_number(lon):
            return Message(code=aiocoap.BAD_REQUEST)

        base_time = None
        for rec in records:
            if rec.bt is not None:
                base_time = float(rec.bt)
                break
        now = self._time_func()
        if base_time is None:
            base_time = now

        conf_size = len(request.payload)
        self._prune_expired()
        self._evict_oldest(conf_size)

        conf_id = self._unique_id()
        stored = {
            "id": conf_id,
            "content": content,
            "type": confession_type or "confession",
            "ts": base_time,
            "received_at": now,
            "expire_time": now + ttl,
            "size": conf_size,
            "anonymous": anonymous,
            # SECURITY: OSCORE context is not persisted with confession content.
            # SECURITY: ``source`` is the authenticated IPv6 IID only when the
            # claimed SenML ``bn`` matches it; spoofed bn is never stored.
            "source": stored_source,
        }
        if lat is not None:
            stored["lat"] = lat
        if lon is not None:
            stored["lon"] = lon

        self._confessions.append(stored)
        self._total_size += conf_size
        self._record_request(rate_key)
        self.updated_state()

        msg = Message(code=CREATED)
        msg.opt.location_path = ("confessions", conf_id)
        msg.opt.max_age = ttl
        return msg


class ConfessionsDetailsResource(resource.Resource, resource.PathCapable):
    """Dynamic router for ``/confessions/{id}`` (spec 18.10.2)."""

    def __init__(self, board: ConfessionsResource) -> None:
        super().__init__()
        self._board = board

    async def render_get(self, request: Message) -> Message:
        uri_path = request.opt.uri_path or ()
        if len(uri_path) != 1:
            return Message(code=aiocoap.NOT_FOUND)
        conf_id = uri_path[0]
        if not _is_confession_id(conf_id):
            return Message(code=aiocoap.NOT_FOUND)
        return self._board.render_one(conf_id)
