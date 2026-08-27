# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Dead Drop resource: /deaddrop and /deaddrop/{id} (spec 18.9).

Asynchronous, rate-limited data drops for store-and-forward style communication
without direct addressing. Nodes POST SenML-formatted payloads to /deaddrop;
others retrieve via GET (with optional Observe).
"""

from __future__ import annotations

import math
import secrets
import time
from contextlib import suppress
from dataclasses import replace
from decimal import Decimal
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import CBOR, SENML_CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.senml.codec import SenmlRecord, label_for_field, pack

# Rate limits per spec 18.9
DEADDROP_POSTS_PER_HOUR = 6  # POSTs per hour per context
DEADDROP_MAX_DROP_SIZE = 1536  # Max drop size in bytes
DEADDROP_STORAGE_LEAF = 8 * 1024  # 8KB for leaf nodes
DEADDROP_STORAGE_BR = 32 * 1024  # 32KB for border routers
DEADDROP_DEFAULT_TTL = 24 * 3600  # 24 hours default retention
DEADDROP_MAX_TTL = 7 * 24 * 3600  # 7 days maximum retention

_DROP_ID_BYTES = 3  # 6 hex chars (e.g., "7f3a9c")
_HEX_LOWER = frozenset("0123456789abcdef")
_PRIVACY_RESTRICTED = frozenset({"private", "group"})


def _generate_drop_id() -> str:
    """Generate a 6-character lowercase hex drop ID."""
    return secrets.token_hex(_DROP_ID_BYTES)


def _is_drop_id(value: str) -> bool:
    """Return True if value is a canonical 6-char lowercase hex drop ID."""
    return len(value) == _DROP_ID_BYTES * 2 and all(c in _HEX_LOWER for c in value)


def _parse_query(request: Message) -> dict[str, str]:
    query: dict[str, str] = {}
    for item in request.opt.uri_query or ():
        if "=" in item:
            key, value = item.split("=", 1)
            query[key] = value
    return query


def _scalar_oscore_identity(value: object) -> str | None:
    """Return a non-empty scalar identity without stringifying objects."""
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value).hex()
    return None


def _bound_oscore_peer_identity(value: object) -> str | None:
    """Return the authenticated peer ID carried by an OSCORE context."""
    for attribute in ("recipient_id", "kid"):
        try:
            peer = _scalar_oscore_identity(getattr(value, attribute, None))
        except Exception:
            return None
        if peer is not None:
            return f"oscore-peer:{peer}"
    return None


def _bound_oscore_identity(value: object) -> str | None:
    """Return a distinct OSCORE identity from a post-unprotect binding, or None.

    SECURITY: Only identities attached after successful unprotect count.
    Strings and non-empty byte strings are accepted; context objects may
    expose ``durable_context_id()``. Arbitrary objects are not stringified
    into a shared bucket, and CoAP option values are never consulted.
    """
    scalar = _scalar_oscore_identity(value)
    if scalar is not None:
        return scalar

    # On a live aiocoap server this is the unprotecting context. Its
    # recipient ID is the authenticated request sender (our peer), while its
    # sender ID is local and therefore MUST NOT key peer ACL or quota state.
    peer = _bound_oscore_peer_identity(value)
    if peer is not None:
        return peer

    try:
        durable = getattr(value, "durable_context_id", None)
    except Exception:
        return None
    if callable(durable):
        try:
            context_id = _scalar_oscore_identity(durable())
        except Exception:
            return None
        if context_id is not None:
            return context_id
    return None


def _request_context_id(request: Message) -> str | None:
    """Return the OSCORE context identifier bound after successful unprotect.

    SECURITY: Writes MUST be OSCORE-protected (spec 18.9). Presence of the
    CoAP OSCORE option (``opt.oscore`` / ``object_security``) is not
    authentication: unprotect reconstructs an inner request without that
    option, and an unprotected client can attach option 9 to plaintext.
    A boolean ``oscore_protected`` flag without a distinct identity would
    collapse every writer onto a shared ``default`` rate-limit and ACL
    bucket. Only a non-empty identity bound on the request (or its remote)
    after unprotect is accepted.
    """
    remote = getattr(request, "remote", None)
    if remote is not None:
        missing = object()
        try:
            live_context = getattr(remote, "security_context", missing)
        except Exception:
            return None
        if live_context is not missing:
            # SECURITY: OSCOREAddress is proof that aiocoap unprotected this
            # request. If its context cannot identify the authenticated peer,
            # fail closed instead of falling back to a request attribute that
            # middleware or a test double could have supplied.
            return _bound_oscore_peer_identity(live_context)

    for holder in (request, remote):
        if holder is None:
            continue
        ident = _bound_oscore_identity(getattr(holder, "oscore_context", None))
        if ident is not None:
            return ident
        ident = _bound_oscore_identity(getattr(holder, "oscore_context_id", None))
        if ident is not None:
            return ident
    return None


def _record_from_map(m: dict[Any, Any]) -> SenmlRecord:
    """Build a SenML record from RFC 8428 integer labels or JSON-style names."""
    labels: dict[int, Any] = {}
    for key, val in m.items():
        if type(key) is int:
            labels[key] = val
            continue
        if isinstance(key, str):
            label = label_for_field(key)
            if label is not None:
                labels[label] = val
            elif key.endswith("_"):
                raise ValueError(f"unknown mandatory SenML label '{key}'")
            continue
        raise ValueError(f"SenML label must be an integer or string, got {type(key).__name__}")
    return SenmlRecord.from_cbor_map(labels)


def _coerce_records(payload: list[Any]) -> list[SenmlRecord] | None:
    """Return SenML records from a decoded pack, or None if the pack is invalid."""
    if not isinstance(payload, list):
        return None
    records: list[SenmlRecord] = []
    for item in payload:
        if isinstance(item, SenmlRecord):
            records.append(item)
            continue
        if not isinstance(item, dict):
            return None
        try:
            records.append(_record_from_map(item))
        except (TypeError, ValueError):
            return None
    return records


def _senml_text(records: list[SenmlRecord], name: str) -> str | None:
    for record in records:
        if record.n == name and isinstance(record.vs, str):
            return record.vs
    return None


def _copy_payload(records: list[SenmlRecord]) -> list[SenmlRecord]:
    return [replace(record) for record in records]


def _numeric_value(record: SenmlRecord) -> float | None:
    """Return a float-safe numeric value from *record*, or ``None``.

    Accepts the codec's numeric types: ints and floats, plus finite
    ``Decimal``s (which ``_validate_field_type`` admits). Bools, non-numerics,
    and non-finite Decimals are rejected as ``None``. Ints and Decimals beyond
    float range clamp to +/-infinity instead of raising ``OverflowError``, so
    callers can treat the result as an ordinary finite-or-infinite float;
    native floats pass through unchanged, preserving their historical
    NaN/inf handling downstream.
    """
    value = record.v
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    if isinstance(value, Decimal) and not value.is_finite():
        return None
    try:
        converted = float(value)
    except OverflowError:
        return math.inf if value > 0 else -math.inf
    return converted


def _extract_ttl(records: list[SenmlRecord], now: float) -> int:
    """Return clamped retention seconds from SenML ``ttl`` or unix ``expires``.

    Retention policy: a sender-provided ``ttl`` of zero or less is honored as
    immediate expiry (zero retention), consistent with the strict handling of
    an ``expires`` already past the clock (which returns 0). Neither field
    ever resurrects a drop at the default TTL; only records carrying neither
    fall back to it.

    Values that survive :func:`_numeric_value` as infinities -- ints or
    finite Decimals beyond float range -- clamp at the boundary like their
    finite neighbors: ``+inf`` yields ``DEADDROP_MAX_TTL``, ``-inf`` zero
    retention; NaN likewise means zero retention.
    """
    ttl: int | None = None
    expires: float | None = None
    for record in records:
        value = _numeric_value(record)
        if value is None:
            continue
        if record.n == "ttl":
            if math.isfinite(value):
                ttl = max(min(int(value), DEADDROP_MAX_TTL), 0)
            else:
                ttl = DEADDROP_MAX_TTL if value > 0 else 0
        elif record.n == "expires":
            expires = value
    if ttl is not None:
        return ttl
    if expires is not None:
        remaining = expires - now
        if remaining > 0:
            with suppress(OverflowError, ValueError):
                return min(int(remaining), DEADDROP_MAX_TTL)
            return DEADDROP_MAX_TTL
        return 0
    return DEADDROP_DEFAULT_TTL


def _available_kb(available_bytes: int) -> int | float:
    kb = available_bytes / 1024
    as_int = int(kb)
    return as_int if kb == as_int else kb


def _wrap_drop_senml(drop: dict[str, Any]) -> list[SenmlRecord]:
    """Wrap one drop's SenML records with collection metadata (spec 18.9 GET)."""
    wrapped: list[SenmlRecord] = [
        SenmlRecord(n="id", vs=drop["id"]),
        SenmlRecord(n="age_s", u="s", v=drop["age_s"]),
        SenmlRecord(n="ttl", u="s", v=drop["ttl"]),
        SenmlRecord(n="size", u="B", v=drop["size"]),
    ]
    payload = drop["payload"]
    if isinstance(payload, list):
        wrapped.extend(item for item in payload if isinstance(item, SenmlRecord))
    return wrapped


class DeadDropResource(resource.ObservableResource):
    """Observable ``/deaddrop`` - rate-limited store-forward drops (spec 18.9).

    **GET** returns current drops as SenML+CBOR, each wrapped with metadata.
    Query parameters ``type``, ``after``, and ``node`` filter the collection.
    **POST** creates a new drop (MUST be OSCORE protected).

    Rate limits:
    - 6 POSTs per hour per OSCORE context
    - Max 1536 bytes per drop
    - Total storage: 8KB (leaf) or 32KB (BR)
    - Default TTL: 24 hours (max 7 days)

    OSCORE:
    - Writes (POST): MUST be protected; unprotected (including a spoofed
      OSCORE option on plaintext) -> 4.01 ``{"error": "oscore_required"}``.
      Rate limits and private/group ACL keys are the identity bound after
      successful unprotect, never a shared ``default`` bucket.
    - Reads (GET): public drops are visible without OSCORE; private/group
      drops require a matching bound OSCORE context or return 4.03 Forbidden.
    """

    def __init__(
        self,
        *,
        storage_limit: int = DEADDROP_STORAGE_LEAF,
        time_func: Any = None,
    ) -> None:
        """Initialize Dead Drop resource.

        Args:
            storage_limit: Maximum storage in bytes (default 8KB leaf).
            time_func: Optional callable returning current time (for testing).
                When omitted, drop timestamps use ``time.time`` (unix seconds,
                spec 18.9 / LCI 17.5.8) while the rate-limit window uses
                ``time.monotonic``.
        """
        super().__init__()
        if (
            isinstance(storage_limit, bool)
            or not isinstance(storage_limit, int)
            or storage_limit <= 0
        ):
            raise ValueError("storage_limit must be a positive integer")
        self._storage_limit = storage_limit
        self._time_func = time_func if time_func is not None else time.time
        self._rate_time_func = self._time_func if time_func is not None else time.monotonic
        # drops: dict[drop_id -> {payload, created, ttl, context, size, privacy, recipient}]
        self._drops: dict[str, dict[str, Any]] = {}
        self._drop_order: list[str] = []  # oldest first for FIFO
        self._current_storage: int = 0
        # Per-context rate limiting: context_id -> list of POST timestamps
        self._request_times: dict[str, list[float]] = {}

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "deaddrop", "ct": str(int(SENML_CBOR)), "obs": None}

    def _prune_old_requests(self, context_id: str) -> None:
        """Remove request timestamps older than 1 hour for rate limiting."""
        if context_id not in self._request_times:
            return
        now = self._rate_time_func()
        cutoff = now - 3600  # 1 hour
        self._request_times[context_id] = [
            ts for ts in self._request_times[context_id] if ts > cutoff
        ]
        if not self._request_times[context_id]:
            del self._request_times[context_id]

    def check_rate_limit(self, context_id: str) -> tuple[bool, int]:
        """Check if context is within rate limits.

        Returns:
            (allowed, retry_after_seconds)
            allowed=True if request is permitted, False if rate-limited.
            retry_after_seconds is hint for Retry-After.
        """
        self._prune_old_requests(context_id)
        if context_id not in self._request_times:
            return True, 0
        timestamps = self._request_times[context_id]
        if len(timestamps) >= DEADDROP_POSTS_PER_HOUR:
            oldest = min(timestamps)
            now = self._rate_time_func()
            retry_after = max(1, int(math.ceil(3600 - (now - oldest))))
            return False, retry_after
        return True, 0

    def _record_request(self, context_id: str) -> None:
        """Record a successful POST for rate limiting."""
        now = self._rate_time_func()
        if context_id not in self._request_times:
            self._request_times[context_id] = []
        self._request_times[context_id].append(now)

    def _prune_expired_drops(self) -> None:
        """Remove all expired drops."""
        now = self._time_func()
        expired = [
            drop_id for drop_id, drop in self._drops.items() if now - drop["created"] >= drop["ttl"]
        ]
        for drop_id in expired:
            self._remove_drop(drop_id)

    def _remove_drop(self, drop_id: str) -> None:
        """Remove a drop by ID."""
        if drop_id in self._drops:
            self._current_storage -= self._drops[drop_id]["size"]
            del self._drops[drop_id]
        if drop_id in self._drop_order:
            self._drop_order.remove(drop_id)

    def _evict_for_space(self, needed: int) -> bool:
        """Evict expired then oldest drops to make space. True if space available."""
        if needed > self._storage_limit:
            return False
        self._prune_expired_drops()
        while self._current_storage + needed > self._storage_limit and self._drop_order:
            self._remove_drop(self._drop_order[0])
        return self._current_storage + needed <= self._storage_limit

    def _drop_visible(self, drop: dict[str, Any], context_id: str | None) -> bool:
        privacy = drop.get("privacy", "public")
        if privacy == "public":
            return True
        # SECURITY: fail-closed for unknown privacy values per spec 18.9
        if privacy not in _PRIVACY_RESTRICTED:
            return False
        if context_id is None:
            return False
        # "private": only creator can see
        if context_id == drop.get("context"):
            return True
        # "group": creator OR designated recipient can see
        if privacy == "group" and context_id == drop.get("recipient"):
            return True
        return False

    def _public_view(self, drop_id: str, drop: dict[str, Any]) -> dict[str, Any]:
        now = self._time_func()
        return {
            "id": drop_id,
            "payload": drop["payload"],
            "created": drop["created"],
            "ttl": drop["ttl"],
            "age_s": int(now - drop["created"]),
            "size": drop["size"],
            "privacy": drop.get("privacy", "public"),
            "recipient": drop.get("recipient"),
            "context": drop.get("context"),
        }

    def drops(
        self,
        *,
        context_id: str | None = None,
        drop_type: str | None = None,
        after: float | None = None,
        node: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return current drops visible to *context_id*, with optional filters."""
        self._prune_expired_drops()
        result: list[dict[str, Any]] = []
        for drop_id in self._drop_order:
            drop = self._drops.get(drop_id)
            if drop is None or not self._drop_visible(drop, context_id):
                continue
            if after is not None and drop["created"] <= after:
                continue
            if drop_type is not None and _senml_text(drop["payload"], "type") != drop_type:
                continue
            if node is not None:
                recipient = drop.get("recipient") or _senml_text(drop["payload"], "recipient")
                node_field = _senml_text(drop["payload"], "node")
                if node not in (recipient, node_field):
                    continue
            result.append(self._public_view(drop_id, drop))
        return result

    def drop(self, drop_id: str) -> dict[str, Any] | None:
        """Return a single drop by ID, or None if not found/expired."""
        self._prune_expired_drops()
        stored = self._drops.get(drop_id)
        if stored is None:
            return None
        return self._public_view(drop_id, stored)

    def add_drop(
        self,
        payload: list[Any],
        *,
        context_id: str,
        ttl: int | None = None,
        drop_id: str | None = None,
        privacy: str = "public",
        recipient: str | None = None,
    ) -> str | None:
        """Add a drop directly (for testing or mesh delivery).

        Returns the drop ID, or None if storage full / invalid.
        ``payload`` is a SenML pack: ``SenmlRecord`` objects or CBOR maps
        with RFC 8428 integer labels (JSON-style names are also accepted).
        An explicit ``ttl`` of zero or less is honored as immediate expiry
        (zero retention), not the default TTL.
        """
        records = _coerce_records(payload)
        if records is None:
            return None
        if ttl is None:
            ttl = _extract_ttl(records, self._time_func())
        else:
            ttl = min(max(int(ttl), 0), DEADDROP_MAX_TTL)
        try:
            encoded = pack(records)
        except (TypeError, ValueError):
            return None
        size = len(encoded)
        if size > DEADDROP_MAX_DROP_SIZE:
            return None
        if not self._evict_for_space(size):
            return None
        if drop_id is None:
            drop_id = _generate_drop_id()
            while drop_id in self._drops:
                drop_id = _generate_drop_id()
        elif not _is_drop_id(drop_id) or drop_id in self._drops:
            return None
        if recipient is None:
            recipient = _senml_text(records, "recipient") or _senml_text(records, "node")
        # SECURITY: Unknown privacy values MUST NOT fail-open to caller-provided
        # default (spec 18.9). Reject invalid values; only canonical tokens accepted.
        privacy_field = _senml_text(records, "privacy")
        if privacy_field is None:
            pass  # use caller-provided privacy parameter
        elif privacy_field in {"public", "private", "group"}:
            privacy = privacy_field
        else:
            return None
        now = self._time_func()
        self._drops[drop_id] = {
            "payload": _copy_payload(records),
            "created": now,
            "ttl": ttl,
            "context": context_id,
            "size": size,
            "privacy": privacy,
            "recipient": recipient,
        }
        self._drop_order.append(drop_id)
        self._current_storage += size
        self.updated_state()
        return drop_id

    def storage_info(self) -> dict[str, Any]:
        """Return current storage usage info."""
        self._prune_expired_drops()
        return {
            "used_bytes": self._current_storage,
            "limit_bytes": self._storage_limit,
            "available_bytes": self._storage_limit - self._current_storage,
            "drop_count": len(self._drops),
        }

    async def render_get(self, request: Message) -> Message:
        """Return visible drops as SenML+CBOR, each wrapped with metadata."""
        query = _parse_query(request)
        after: float | None = None
        if "after" in query:
            try:
                after = float(query["after"])
            except ValueError:
                return Message(code=aiocoap.BAD_REQUEST)
            if not math.isfinite(after):
                return Message(code=aiocoap.BAD_REQUEST)
        drop_type = query.get("type") or None
        node = query.get("node") or None
        context_id = _request_context_id(request)
        all_records: list[SenmlRecord] = []
        for drop_info in self.drops(
            context_id=context_id,
            drop_type=drop_type,
            after=after,
            node=node,
        ):
            all_records.extend(_wrap_drop_senml(drop_info))
        msg = Message(code=CONTENT, payload=pack(all_records))
        msg.opt.content_format = SENML_CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        """Create a new drop. Requires OSCORE protection."""
        # SECURITY: Writes MUST be OSCORE-protected (spec 18.9).
        context_id = _request_context_id(request)
        if context_id is None:
            msg = Message(code=aiocoap.UNAUTHORIZED)
            msg.opt.content_format = CBOR
            msg.payload = cbor2.dumps({"error": "oscore_required"})
            return msg
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        if len(request.payload) > DEADDROP_MAX_DROP_SIZE:
            return Message(code=aiocoap.REQUEST_ENTITY_TOO_LARGE)
        try:
            decoded = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(decoded, list):
            return Message(code=aiocoap.BAD_REQUEST)
        records = _coerce_records(decoded)
        if records is None:
            return Message(code=aiocoap.BAD_REQUEST)
        allowed, retry_after = self.check_rate_limit(context_id)
        if not allowed:
            msg = Message(code=aiocoap.TOO_MANY_REQUESTS)
            msg.opt.content_format = CBOR
            msg.payload = cbor2.dumps({"retry_after": retry_after})
            msg.opt.max_age = retry_after
            return msg
        now = self._time_func()
        ttl = _extract_ttl(records, now)
        encoded_size = len(request.payload)
        if not self._evict_for_space(encoded_size):
            msg = Message(code=aiocoap.SERVICE_UNAVAILABLE)
            msg.opt.content_format = CBOR
            info = self.storage_info()
            msg.payload = cbor2.dumps(
                {
                    "reason": "storage_full",
                    "retry_after": 3600,
                    "available_kb": _available_kb(info["available_bytes"]),
                }
            )
            return msg
        drop_id = _generate_drop_id()
        while drop_id in self._drops:
            drop_id = _generate_drop_id()
        # SECURITY: Unknown privacy values MUST NOT fail-open to public (spec 18.9).
        # Reject invalid values with 4.00; only canonical tokens are accepted.
        privacy_raw = _senml_text(records, "privacy")
        if privacy_raw is None:
            privacy = "public"
        elif privacy_raw in {"public", "private", "group"}:
            privacy = privacy_raw
        else:
            msg = Message(code=aiocoap.BAD_REQUEST)
            msg.opt.content_format = CBOR
            msg.payload = cbor2.dumps({"error": "invalid_privacy_value"})
            return msg
        recipient = _senml_text(records, "recipient") or _senml_text(records, "node")
        self._drops[drop_id] = {
            "payload": _copy_payload(records),
            "created": now,
            "ttl": ttl,
            "context": context_id,
            "size": encoded_size,
            "privacy": privacy,
            "recipient": recipient,
        }
        self._drop_order.append(drop_id)
        self._current_storage += encoded_size
        self._record_request(context_id)
        self.updated_state()
        msg = Message(code=CREATED)
        msg.opt.location_path = ("deaddrop", drop_id)
        msg.opt.max_age = ttl
        return msg


class DeadDropDetailsResource(resource.Resource, resource.PathCapable):
    """Dynamic router for ``/deaddrop/{id}`` (spec 18.9).

    **GET** returns a single drop's SenML payload.
    Private/group drops without a matching OSCORE context return 4.03.
    """

    def __init__(self, deaddrop: DeadDropResource) -> None:
        super().__init__()
        self._deaddrop = deaddrop

    def _extract_id(self, request: Message) -> str | None:
        """Extract drop ID from URI path."""
        if len(request.opt.uri_path) != 1:
            return None
        drop_id = request.opt.uri_path[0]
        if not isinstance(drop_id, str) or not _is_drop_id(drop_id):
            return None
        return drop_id

    async def render_get(self, request: Message) -> Message:
        """Return a single drop's SenML payload."""
        drop_id = self._extract_id(request)
        if drop_id is None:
            return Message(code=aiocoap.NOT_FOUND)
        drop_info = self._deaddrop.drop(drop_id)
        if drop_info is None:
            return Message(code=aiocoap.NOT_FOUND)
        context_id = _request_context_id(request)
        if not self._deaddrop._drop_visible(drop_info, context_id):
            # SECURITY: private drops return 404 to hide existence; group drops
            # return 403 to signal recipient should authenticate.
            privacy = drop_info.get("privacy", "public")
            if privacy == "private":
                return Message(code=aiocoap.NOT_FOUND)
            return Message(code=aiocoap.FORBIDDEN)
        payload = drop_info["payload"]
        if not isinstance(payload, list) or any(
            not isinstance(item, SenmlRecord) for item in payload
        ):
            return Message(code=aiocoap.INTERNAL_SERVER_ERROR)
        try:
            body = pack(payload)
        except (TypeError, ValueError):
            return Message(code=aiocoap.INTERNAL_SERVER_ERROR)
        msg = Message(code=CONTENT, payload=body)
        msg.opt.content_format = SENML_CBOR
        remaining_ttl = drop_info["ttl"] - drop_info["age_s"]
        if remaining_ttl > 0:
            msg.opt.max_age = remaining_ttl
        return msg

    def get_resources_as_linkheader(self) -> Any:
        # SECURITY: aiocoap's discovery hook has no request or authenticated
        # OSCORE context, so it cannot apply the private/group ACL used by
        # render_get(). Advertising only public IDs would also make a cached
        # link-format response stale if a drop's policy changes. Keep dynamic
        # IDs undiscoverable; the parent /deaddrop collection remains in WKC.
        return resource.LinkFormat([])
