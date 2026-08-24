# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Position cache resource for peer position tracking (spec 18.2).

Stores positions received from position beacons and provides GET access
to the cache with age tracking.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from typing import Any

import cbor2
from aiocoap import CONTENT, Message, resource

from lichen.coap.resources.base import CBOR


class PositionCacheResource(resource.ObservableResource):
    """Observable ``/pos/cache`` — CBOR map of cached peer positions.

    Per spec 18.2.1, returns::

        {
          "positions": [
            {
              "node": "0200:...:1111",
              "lat": 37.774929,
              "lon": -122.419416,
              "alt": 10.5,
              "ts": 1716742800,
              "age_s": 45
            }
          ]
        }

    The ``age_s`` field is computed at response time as ``now - ts``.

    Example::

        cache = PositionCacheResource()
        site = build_site(info, position_cache_resource=cache)
        # When a position beacon arrives:
        cache.record_position("0200::1111", lat=37.77, lon=-122.42, ts=1716742800)
    """

    def __init__(self, time_source: Callable[[], float] | None = None) -> None:
        """Initialize the position cache.

        Args:
            time_source: Optional callable returning current Unix time.
                Defaults to time.time. Useful for testing.
        """
        super().__init__()
        self._positions: dict[str, dict[str, Any]] = {}
        self._time_source = time_source if time_source is not None else time.time

    def record_position(
        self,
        node: str,
        lat: float,
        lon: float,
        ts: float,
        alt: float | None = None,
    ) -> None:
        """Record or update a peer's position and notify observers.

        Args:
            node: IPv6 address of the peer (e.g., "0200::1111").
            lat: Latitude in decimal degrees (WGS-84).
            lon: Longitude in decimal degrees (WGS-84).
            ts: Unix timestamp when position was recorded (>= 0).
            alt: Altitude in metres above WGS-84 ellipsoid, or None to omit.

        Raises:
            ValueError: If ts is not a non-negative finite number.
            ValueError: If lat or lon is not a finite number.
        """
        if (
            isinstance(ts, bool)
            or not isinstance(ts, (int, float))
            or (isinstance(ts, float) and not math.isfinite(ts))
            or ts < 0
        ):
            raise ValueError("timestamp must be non-negative finite number")
        if (
            isinstance(lat, bool)
            or not isinstance(lat, (int, float))
            or (isinstance(lat, float) and not math.isfinite(lat))
        ):
            raise ValueError("latitude must be finite number")
        if (
            isinstance(lon, bool)
            or not isinstance(lon, (int, float))
            or (isinstance(lon, float) and not math.isfinite(lon))
        ):
            raise ValueError("longitude must be finite number")
        if alt is not None and (
            isinstance(alt, bool)
            or not isinstance(alt, (int, float))
            or (isinstance(alt, float) and not math.isfinite(alt))
        ):
            raise ValueError("altitude must be finite number or None")

        entry: dict[str, Any] = {
            "node": node,
            "lat": lat,
            "lon": lon,
            "ts": ts,
        }
        if alt is not None:
            entry["alt"] = alt
        self._positions[node] = entry
        self.updated_state()

    def evict(self, node: str) -> None:
        """Remove a peer's position from the cache and notify observers.

        No-op if the peer is not in the cache.
        """
        if self._positions.pop(node, None) is not None:
            self.updated_state()

    def purge_older_than(self, cutoff_ts: float) -> int:
        """Remove positions with ``ts < cutoff_ts`` and notify if any were removed.

        Args:
            cutoff_ts: Unix timestamp cutoff (must be non-negative).

        Returns:
            The number of entries evicted.

        Raises:
            ValueError: If cutoff_ts is not a non-negative finite number.
        """
        if (
            isinstance(cutoff_ts, bool)
            or not isinstance(cutoff_ts, (int, float))
            or (isinstance(cutoff_ts, float) and not math.isfinite(cutoff_ts))
            or cutoff_ts < 0
        ):
            raise ValueError("cutoff timestamp must be non-negative finite number")
        positions = dict(self._positions)
        stale = [k for k, v in positions.items() if v["ts"] < cutoff_ts]
        for k in stale:
            self._positions.pop(k, None)
        if stale:
            self.updated_state()
        return len(stale)

    async def render_get(self, request: Message) -> Message:  # noqa: ARG002
        """Return all cached positions with computed age_s."""
        now = self._time_source()
        positions = []
        for entry in self._positions.values():
            pos = dict(entry)
            pos["age_s"] = int(now - entry["ts"])
            positions.append(pos)
        payload = cbor2.dumps({"positions": positions})
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = CBOR
        return msg

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {
            "rt": "lichen.pos.cache",
            "ct": str(int(CBOR)),
            "obs": None,
        }
