# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Dead Drop resource: /deaddrop and /deaddrop/{id} (spec 18.9).

Asynchronous, rate-limited data drops for store-and-forward style communication
without direct addressing. Nodes POST SenML-formatted payloads to /deaddrop;
others retrieve via GET (with optional Observe).
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, CREATED, Message, resource

from lichen.coap.resources.base import SENML_CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor

# Rate limits per spec 18.9
DEADDROP_POSTS_PER_HOUR = 6  # POSTs per hour per context
DEADDROP_MAX_DROP_SIZE = 1536  # Max drop size in bytes
DEADDROP_STORAGE_LEAF = 8 * 1024  # 8KB for leaf nodes
DEADDROP_STORAGE_BR = 32 * 1024  # 32KB for border routers
DEADDROP_DEFAULT_TTL = 24 * 3600  # 24 hours default retention
DEADDROP_MAX_TTL = 7 * 24 * 3600  # 7 days maximum retention

# ID generation
_DROP_ID_BYTES = 3  # 6 hex chars (e.g., "7f3a9c")


def _generate_drop_id() -> str:
    """Generate a 6-character hex drop ID."""
    return secrets.token_hex(_DROP_ID_BYTES)


class DeadDropResource(resource.ObservableResource):
    """Observable ``/deaddrop`` - rate-limited store-forward drops (spec 18.9).

    **GET** returns all current drops (SenML+CBOR array).
    **POST** creates a new drop (requires OSCORE protection).

    Drop format is SenML+CBOR (Content-Format 112). Each drop is stored with
    metadata including ID, creation time, TTL, and OSCORE context.

    Rate limits:
    - 6 POSTs per hour per OSCORE context
    - Max 1536 bytes per drop
    - Total storage: 8KB (leaf) or 32KB (BR)
    - Default TTL: 24 hours

    OSCORE Requirements:
    - Writes (POST): MUST be protected with OSCORE
    - Reads (GET): Public drops allowed without protection

    Eviction: expired first, then oldest (FIFO).
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
        # drops: dict[drop_id -> {payload, created, ttl, context, size}]
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
        now = self._time_func()
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
            retry_after_seconds is hint for Retry-After header.
        """
        self._prune_old_requests(context_id)
        if context_id not in self._request_times:
            return True, 0
        timestamps = self._request_times[context_id]
        if len(timestamps) >= DEADDROP_POSTS_PER_HOUR:
            # Calculate when oldest request will expire
            oldest = min(timestamps)
            now = self._time_func()
            retry_after = max(1, int(3600 - (now - oldest)))
            return False, retry_after
        return True, 0

    def _record_request(self, context_id: str) -> None:
        """Record a successful POST for rate limiting."""
        now = self._time_func()
        if context_id not in self._request_times:
            self._request_times[context_id] = []
        self._request_times[context_id].append(now)

    def _prune_expired_drops(self) -> None:
        """Remove all expired drops."""
        now = self._time_func()
        expired = [
            drop_id
            for drop_id, drop in self._drops.items()
            if now - drop["created"] > drop["ttl"]
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
        """Evict drops to make space. Returns True if space available."""
        self._prune_expired_drops()
        # Evict oldest until we have space
        while (
            self._current_storage + needed > self._storage_limit
            and self._drop_order
        ):
            oldest_id = self._drop_order[0]
            self._remove_drop(oldest_id)
        return self._current_storage + needed <= self._storage_limit

    def drops(self) -> list[dict[str, Any]]:
        """Return all current drops with metadata."""
        self._prune_expired_drops()
        now = self._time_func()
        result = []
        for drop_id in self._drop_order:
            if drop_id in self._drops:
                drop = self._drops[drop_id]
                result.append({
                    "id": drop_id,
                    "payload": drop["payload"],
                    "created": drop["created"],
                    "ttl": drop["ttl"],
                    "age_s": int(now - drop["created"]),
                    "size": drop["size"],
                })
        return result

    def drop(self, drop_id: str) -> dict[str, Any] | None:
        """Return a single drop by ID, or None if not found/expired."""
        self._prune_expired_drops()
        if drop_id not in self._drops:
            return None
        now = self._time_func()
        drop = self._drops[drop_id]
        return {
            "id": drop_id,
            "payload": drop["payload"],
            "created": drop["created"],
            "ttl": drop["ttl"],
            "age_s": int(now - drop["created"]),
            "size": drop["size"],
        }

    def add_drop(
        self,
        payload: list[Any],
        *,
        context_id: str,
        ttl: int | None = None,
    ) -> str | None:
        """Add a drop directly (for testing or mesh delivery).

        Returns the drop ID, or None if storage full.
        """
        if ttl is None:
            ttl = DEADDROP_DEFAULT_TTL
        ttl = min(ttl, DEADDROP_MAX_TTL)
        encoded = cbor2.dumps(payload)
        size = len(encoded)
        if size > DEADDROP_MAX_DROP_SIZE:
            return None
        if not self._evict_for_space(size):
            return None
        drop_id = _generate_drop_id()
        while drop_id in self._drops:
            drop_id = _generate_drop_id()
        now = self._time_func()
        self._drops[drop_id] = {
            "payload": payload,
            "created": now,
            "ttl": ttl,
            "context": context_id,
            "size": size,
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
        """Return all current drops as SenML+CBOR array."""
        self._prune_expired_drops()
        # Collect all drop payloads into single SenML array
        all_records: list[Any] = []
        for drop_info in self.drops():
            all_records.extend(drop_info["payload"])
        msg = Message(code=CONTENT, payload=cbor2.dumps(all_records))
        msg.opt.content_format = SENML_CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        """Create a new drop. Requires OSCORE protection."""
        # SECURITY: OSCORE enforcement for writes
        # In a real implementation, OSCORE protection is checked via request options.
        # For the Python simulator, we check for oscore_context attribute or flag.
        oscore_context = getattr(request, "oscore_context", None)
        oscore_protected = getattr(request, "oscore_protected", False)
        if oscore_context is None and not oscore_protected:
            # Check for explicit test flag or remote address-based context
            context_id = getattr(request, "oscore_context_id", None)
            if context_id is None:
                msg = Message(code=aiocoap.UNAUTHORIZED)
                msg.opt.content_format = SENML_CBOR
                # Return error details per spec
                msg.payload = cbor2.dumps({"error": "oscore_required"})
                return msg
        else:
            context_id = (
                oscore_context
                if isinstance(oscore_context, str)
                else str(oscore_context) if oscore_context else "default"
            )
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        # Check payload size before decoding
        if len(request.payload) > DEADDROP_MAX_DROP_SIZE:
            return Message(code=aiocoap.REQUEST_ENTITY_TOO_LARGE)
        try:
            payload = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        # SenML must be an array
        if not isinstance(payload, list):
            return Message(code=aiocoap.BAD_REQUEST)
        # Check rate limit
        allowed, retry_after = self.check_rate_limit(context_id)
        if not allowed:
            msg = Message(code=aiocoap.TOO_MANY_REQUESTS)
            msg.opt.max_age = retry_after
            return msg
        # Extract TTL from SenML if present (look for "n": "ttl" record)
        ttl = DEADDROP_DEFAULT_TTL
        for record in payload:
            if isinstance(record, dict) and record.get("n") == "ttl":
                ttl_val = record.get("v")
                if isinstance(ttl_val, (int, float)) and not isinstance(ttl_val, bool):
                    ttl = min(int(ttl_val), DEADDROP_MAX_TTL)
                break
        # Check storage availability
        encoded_size = len(request.payload)
        if not self._evict_for_space(encoded_size):
            msg = Message(code=aiocoap.SERVICE_UNAVAILABLE)
            msg.opt.content_format = SENML_CBOR
            info = self.storage_info()
            msg.payload = cbor2.dumps({
                "reason": "storage_full",
                "retry_after": 3600,
                "available_kb": info["available_bytes"] / 1024,
            })
            return msg
        # Create the drop
        drop_id = _generate_drop_id()
        while drop_id in self._drops:
            drop_id = _generate_drop_id()
        now = self._time_func()
        self._drops[drop_id] = {
            "payload": payload,
            "created": now,
            "ttl": ttl,
            "context": context_id,
            "size": encoded_size,
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
    """

    def __init__(self, deaddrop: DeadDropResource) -> None:
        super().__init__()
        self._deaddrop = deaddrop

    def _extract_id(self, request: Message) -> str | None:
        """Extract drop ID from URI path."""
        if len(request.opt.uri_path) != 1:
            return None
        drop_id = request.opt.uri_path[0]
        if not drop_id or not drop_id.isascii():
            return None
        # Validate hex format (6 chars)
        if len(drop_id) != _DROP_ID_BYTES * 2:
            return None
        try:
            int(drop_id, 16)
        except ValueError:
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
        msg = Message(code=CONTENT, payload=cbor2.dumps(drop_info["payload"]))
        msg.opt.content_format = SENML_CBOR
        # Set Max-Age to remaining TTL
        remaining_ttl = drop_info["ttl"] - drop_info["age_s"]
        if remaining_ttl > 0:
            msg.opt.max_age = remaining_ttl
        return msg

    def get_resources_as_linkheader(self) -> Any:
        return resource.LinkFormat([
            resource.Link(f"/{drop_id}", ct=str(int(SENML_CBOR)))
            for drop_id in self._deaddrop._drop_order
        ])
