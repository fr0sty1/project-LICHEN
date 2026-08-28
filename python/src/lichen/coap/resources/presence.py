# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Observable presence resources (spec 18.5).

``/presence`` is the node's own status (GET/PUT/Observe).
``/presence/cache`` is the table of recently-heard peer presence.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections.abc import Callable
from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, CONTENT, UNAUTHORIZED, Message, resource
from aiocoap.numbers import ContentFormat

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.messaging import _peer_is_local_admin
from lichen.presence import (
    LOW_BATTERY_PCT,
    Presence,
    PresenceCache,
    PresenceCacheEntry,
    PresenceError,
    age_s_at,
    apply_automatic_status,
)

_PRESENCE_CACHE_MAX = 100  # maximum entries in the presence cache


def _finite_non_negative(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
        or value < 0
    ):
        raise ValueError(f"{name} must be a non-negative finite number")
    return float(value)


def _canonical_ipv6(addr: str) -> str:
    """Parse and return the canonical form of an IPv6 address.

    Raises ValueError if addr is not a valid IPv6 address.
    """
    if not isinstance(addr, str):
        raise ValueError("addr must be a string")
    try:
        return str(ipaddress.IPv6Address(addr))
    except ipaddress.AddressValueError as e:
        raise ValueError(f"addr must be a valid IPv6 address: {e}") from e


class PresenceResource(resource.ObservableResource):
    """Observable ``/presence`` — own presence GET/PUT (spec 18.5.1-18.5.3).

    GET returns the local presence CBOR map. PUT replaces it (status required;
    omitted ``ts`` is filled with the current time) then applies automatic
    status (spec 18.5.3). Observe notifies on change.

    SECURITY: PUT is set-own-presence (spec 18.5.2). Peer operations are
    GET/Observe. Unauthenticated writes are rejected with 4.01 Unauthorized
    unless ``allow_writes=True`` or the request peer is a local-admin
    loopback (LCI). A mesh peer must not overwrite another node's advertised
    status, including ``emergency`` (spec 18.4.1 origin-signature path).

    Automatic status (spec 18.5.3) is applied via :meth:`note_gps`,
    :meth:`note_interaction`, :meth:`note_sos`, :meth:`note_battery`,
    :meth:`tick`, and PUT.
    """

    def __init__(
        self,
        time_source: Callable[[], float] | None = None,
        *,
        allow_writes: bool = False,
    ) -> None:
        """Create the local presence resource.

        Args:
            time_source: Optional callable returning current Unix time.
            allow_writes: If True, allow PUT from any client. SECURITY: set
                True only when the transport layer already enforces
                authentication (OSCORE or LCI). Defaults to False.
        """
        super().__init__()
        self._time_source = time_source if time_source is not None else time.time
        self._allow_writes = allow_writes
        now = _finite_non_negative(self._time_source(), "time_source")
        self._presence = Presence(status="available", ts=int(now))
        self._moving: bool | None = None
        self._last_motion_at: float | None = None
        self._last_interaction_at: float = float(now)
        self._sos_active = False
        self._pre_sos: Presence | None = None

    def get_presence(self) -> Presence:
        """Return the current local presence."""
        return self._presence

    def set_presence(self, presence: Presence) -> None:
        """Replace local presence and notify observers if it changed."""
        if not isinstance(presence, Presence):
            raise PresenceError("presence must be a Presence")
        presence = Presence.from_mapping(presence.to_map())
        if presence == self._presence:
            return
        self._presence = presence
        self.updated_state()

    def note_gps(self, moving: bool, now: float | None = None) -> None:
        """Record a GPS motion sample and apply automatic status."""
        if type(moving) is not bool:
            raise ValueError("moving must be a boolean")
        stamp = self._time_source() if now is None else now
        stamp = _finite_non_negative(stamp, "now")
        self._moving = moving
        if moving or self._last_motion_at is None:
            self._last_motion_at = stamp
        self._apply_auto(stamp)

    def note_interaction(self, now: float | None = None) -> None:
        """Record user interaction and apply automatic status."""
        stamp = self._time_source() if now is None else now
        stamp = _finite_non_negative(stamp, "now")
        self._last_interaction_at = stamp
        self._apply_auto(stamp)

    def note_sos(self, active: bool, now: float | None = None) -> None:
        """Record SOS active/clear and apply automatic status."""
        if type(active) is not bool:
            raise ValueError("active must be a boolean")
        stamp = self._time_source() if now is None else now
        stamp = _finite_non_negative(stamp, "now")
        current = self._presence
        if active and not self._sos_active:
            self._pre_sos = current
        elif not active and self._sos_active and self._pre_sos is not None:
            current = self._pre_sos
            self._pre_sos = None
        self._sos_active = active
        self._apply_auto(stamp, current=current)

    def note_battery(self, percent: int, now: float | None = None) -> None:
        """Record battery percentage and apply automatic status."""
        if type(percent) is not int or percent < 0 or percent > 100:
            raise ValueError("battery must be an integer 0..100")
        stamp = self._time_source() if now is None else now
        stamp = _finite_non_negative(stamp, "now")
        current = self._presence
        # Spec 18.5.3: low_battery must be True iff battery < LOW_BATTERY_PCT
        low_battery = True if percent < LOW_BATTERY_PCT else None
        pending = Presence(
            status=current.status,
            ts=current.ts,
            activity=current.activity,
            msg=current.msg,
            battery=percent,
            low_battery=low_battery,
        )
        self._apply_auto(stamp, current=pending)

    def tick(self, now: float | None = None) -> None:
        """Re-evaluate time-based automatic status (inactivity, stationary)."""
        stamp = self._time_source() if now is None else now
        self._apply_auto(_finite_non_negative(stamp, "now"))

    def _apply_auto(self, now: float, current: Presence | None = None) -> None:
        updated = apply_automatic_status(
            self._presence if current is None else current,
            now,
            moving=self._moving,
            last_motion_at=self._last_motion_at,
            last_interaction_at=self._last_interaction_at,
            sos_active=self._sos_active,
        )
        self.set_presence(updated)

    async def render_get(self, request: Message) -> Message:  # noqa: ARG002
        msg = Message(code=CONTENT, payload=self._presence.to_cbor())
        msg.opt.content_format = CBOR
        return msg

    async def render_put(self, request: Message) -> Message:
        # SECURITY: Reject unauthenticated writes before parsing. Presence
        # documents are observed by peers; an attacker PUT would overwrite
        # status/msg/battery and can advertise emergency without SOS origin
        # signatures (spec 18.4.1, 18.5.2).
        if not self._allow_writes and not _peer_is_local_admin(getattr(request, "remote", None)):
            return Message(code=UNAUTHORIZED)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        if (
            request.opt.content_format is not None
            and request.opt.content_format != ContentFormat.CBOR
        ):
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        if "status" not in body:
            return Message(code=BAD_REQUEST)
        try:
            stamp = _finite_non_negative(self._time_source(), "time_source")
            document = dict(body)
            if "ts" not in document:
                document["ts"] = int(stamp)
            presence = Presence.from_mapping(document)
        except (PresenceError, TypeError, ValueError):
            return Message(code=BAD_REQUEST)
        self._last_interaction_at = stamp
        if self._sos_active:
            self._pre_sos = presence
        self._apply_auto(stamp, current=presence)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {
            "rt": "lichen.presence",
            "ct": str(int(CBOR)),
            "obs": None,
        }


class PresenceCacheResource(resource.ObservableResource):
    """Observable ``/presence/cache`` — all known node presence (spec 18.5.2).

    Returns::

        {
          "nodes": [
            {"addr": "0200::1111", "status": "available", "battery": 87, "age_s": 30}
          ]
        }

    ``age_s`` is computed at GET time as ``max(0, int(now - ts))``.

    The cache is bounded to :data:`_PRESENCE_CACHE_MAX` entries (default 100).
    When the limit is exceeded, the oldest entries by timestamp are evicted.
    """

    def __init__(
        self,
        time_source: Callable[[], float] | None = None,
        *,
        max_entries: int = _PRESENCE_CACHE_MAX,
    ) -> None:
        super().__init__()
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        self._time_source = time_source if time_source is not None else time.time
        self._max_entries = max_entries
        self._nodes: dict[str, dict[str, Any]] = {}

    def record(
        self,
        addr: str,
        status: str,
        ts: float,
        battery: int | None = None,
    ) -> None:
        """Record or refresh a peer's presence and notify observers.

        SECURITY: ts is capped to the current time. A future timestamp would
        report age_s=0 indefinitely and survive TTL-based purges (spec 18.5.2).

        addr must be a valid IPv6 address; it is canonicalized so that
        equivalent spellings (e.g., "0200::1111" vs "0200:0:0:0:0:0:0:1111")
        occupy the same cache slot.
        """
        canonical_addr = _canonical_ipv6(addr)
        stamp = _finite_non_negative(ts, "ts")
        now = _finite_non_negative(self._time_source(), "time_source")
        # Cap ts to now: future timestamps would dodge purge and report age_s=0
        stamp = min(stamp, now)
        entry_map: dict[str, Any] = {"addr": canonical_addr, "status": status, "age_s": 0}
        if battery is not None:
            entry_map["battery"] = battery
        entry = PresenceCacheEntry.from_mapping(entry_map)
        stored: dict[str, Any] = {
            "addr": entry.addr,
            "status": entry.status,
            "ts": stamp,
        }
        if entry.battery is not None:
            stored["battery"] = entry.battery
        existing = self._nodes.get(entry.addr)
        if existing == stored:
            return
        # SECURITY: Reject stale data - replayed old announcements must not
        # overwrite newer entries or manipulate eviction ordering.
        if existing is not None and existing["ts"] > stamp:
            return
        self._nodes[entry.addr] = stored
        self._enforce_max()
        self.updated_state()

    def _enforce_max(self) -> None:
        """Evict oldest entries (by timestamp) if cache exceeds max_entries."""
        if len(self._nodes) <= self._max_entries:
            return
        # Sort by timestamp ascending (oldest first), evict excess
        sorted_addrs = sorted(self._nodes.keys(), key=lambda k: self._nodes[k]["ts"])
        excess = len(self._nodes) - self._max_entries
        for addr in sorted_addrs[:excess]:
            self._nodes.pop(addr, None)

    def evict(self, addr: str) -> None:
        """Remove a peer from the cache and notify observers.

        addr must be a valid IPv6 address; it is canonicalized so that any
        valid spelling of the address will hit the cached entry. No-op if
        the peer is not in the cache.
        """
        canonical_addr = _canonical_ipv6(addr)
        if self._nodes.pop(canonical_addr, None) is not None:
            self.updated_state()

    def purge_older_than(self, cutoff_ts: float) -> int:
        """Remove entries with ``ts < cutoff_ts`` and notify if any were removed.

        Returns the number of entries evicted.
        """
        cutoff = _finite_non_negative(cutoff_ts, "cutoff timestamp")
        stale = [k for k, v in list(self._nodes.items()) if v["ts"] < cutoff]
        for key in stale:
            self._nodes.pop(key, None)
        if stale:
            self.updated_state()
        return len(stale)

    def snapshot(self, now: float | None = None) -> PresenceCache:
        """Return the cache envelope with ``age_s`` computed at ``now``."""
        stamp = self._time_source() if now is None else now
        stamp = _finite_non_negative(stamp, "now")
        nodes: list[PresenceCacheEntry] = []
        for stored in self._nodes.values():
            entry_map: dict[str, Any] = {
                "addr": stored["addr"],
                "status": stored["status"],
                "age_s": age_s_at(stamp, stored["ts"]),
            }
            if "battery" in stored:
                entry_map["battery"] = stored["battery"]
            nodes.append(PresenceCacheEntry.from_mapping(entry_map))
        return PresenceCache(nodes=tuple(nodes))

    async def render_get(self, request: Message) -> Message:  # noqa: ARG002
        msg = Message(code=CONTENT, payload=self.snapshot().to_cbor())
        msg.opt.content_format = CBOR
        return msg

    def get_link_description(self) -> dict[str, Any]:
        return {
            "rt": "lichen.presence.cache",
            "ct": str(int(CBOR)),
            "obs": None,
        }
