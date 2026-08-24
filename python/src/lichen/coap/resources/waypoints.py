# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Waypoint resources: /waypoints and /waypoints/{id} (spec 18.3)."""

from __future__ import annotations

import time
from typing import Any

import aiocoap
from aiocoap import Message, resource

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor

_WAYPOINTS_MAX = 100  # maximum stored waypoints


def _is_valid_tstr(value: Any) -> bool:
    """Check if value is a valid text string."""
    return isinstance(value, str) and len(value) > 0


def _is_valid_float(value: Any) -> bool:
    """Check if value is a valid float or int (coercible to float)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_valid_uint(value: Any) -> bool:
    """Check if value is a valid unsigned integer."""
    return type(value) is int and value >= 0


class WaypointsResource(resource.Resource):
    """``/waypoints`` collection for shared waypoints (spec 18.3).

    **GET** returns all waypoints.
    **POST** creates a new waypoint (returns 2.01 Created with Location-Path).

    Waypoint format::

        {
            "id": "wpt-001",              ; unique ID (tstr)
            "name": "Rally Point Alpha",  ; human-readable name (tstr)
            "lat": 37.774929,             ; WGS84 latitude (float)
            "lon": -122.419416,           ; WGS84 longitude (float)
            "alt": 10.5,                  ; altitude meters (float, optional)
            "icon": "flag",               ; icon hint (tstr, optional)
            "color": "#FF0000",           ; color hint (tstr, optional)
            "notes": "Meet here at 1400", ; description (tstr, optional)
            "created": 1716742800,        ; creation time (uint)
            "creator": "0200:...:1111",   ; creator node (tstr)
            "expires": 1716829200         ; expiration time (uint, optional)
        }
    """

    def __init__(
        self,
        *,
        creator_id: str = "unknown",
        max_waypoints: int = _WAYPOINTS_MAX,
    ) -> None:
        super().__init__()
        if (
            isinstance(max_waypoints, bool)
            or not isinstance(max_waypoints, int)
            or max_waypoints <= 0
        ):
            raise ValueError("max_waypoints must be a positive integer")
        self._creator_id = creator_id
        self._max_waypoints = max_waypoints
        self._waypoints: dict[str, dict[str, Any]] = {}
        self._waypoint_order: list[str] = []
        self._next_id = 1

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "waypoints", "ct": str(int(CBOR))}

    def waypoints(self) -> list[dict[str, Any]]:
        """Return all waypoints in creation order."""
        return [dict(self._waypoints[wpt_id]) for wpt_id in self._waypoint_order]

    def waypoint(self, wpt_id: str) -> dict[str, Any] | None:
        """Return a single waypoint by ID."""
        wpt = self._waypoints.get(wpt_id)
        return dict(wpt) if wpt is not None else None

    def add_waypoint(self, waypoint: dict[str, Any]) -> str:
        """Add a waypoint directly (for testing or mesh delivery).

        Returns the waypoint ID.
        """
        wpt_id = waypoint["id"]
        self._waypoints[wpt_id] = dict(waypoint)
        if wpt_id not in self._waypoint_order:
            self._waypoint_order.append(wpt_id)
        self._enforce_max()
        return wpt_id

    def update_waypoint(self, wpt_id: str, updates: dict[str, Any]) -> bool:
        """Update a waypoint by ID. Returns True if found and updated."""
        if wpt_id not in self._waypoints:
            return False
        wpt = self._waypoints[wpt_id]
        # Only update allowed fields (not id, created, creator)
        for key in ("name", "lat", "lon", "alt", "icon", "color", "notes", "expires"):
            if key in updates:
                wpt[key] = updates[key]
        return True

    def delete_waypoint(self, wpt_id: str) -> bool:
        """Delete a waypoint by ID. Returns True if found and deleted."""
        if wpt_id not in self._waypoints:
            return False
        del self._waypoints[wpt_id]
        self._waypoint_order.remove(wpt_id)
        return True

    def _enforce_max(self) -> None:
        """Ensure we don't exceed max_waypoints."""
        if len(self._waypoint_order) > self._max_waypoints:
            oldest = self._waypoint_order[: len(self._waypoint_order) - self._max_waypoints]
            self._waypoint_order = self._waypoint_order[-self._max_waypoints:]
            for old_id in oldest:
                self._waypoints.pop(old_id, None)

    def _generate_id(self) -> str:
        """Generate a unique waypoint ID."""
        wpt_id = f"wpt-{self._next_id:03d}"
        self._next_id += 1
        return wpt_id

    async def render_get(self, request: Message) -> Message:
        """Return all waypoints."""
        return _cbor_response({"waypoints": self.waypoints()})

    async def render_post(self, request: Message) -> Message:
        """Create a new waypoint."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate required fields
        if not _is_valid_tstr(body.get("name")):
            return Message(code=aiocoap.BAD_REQUEST)
        if not _is_valid_float(body.get("lat")):
            return Message(code=aiocoap.BAD_REQUEST)
        if not _is_valid_float(body.get("lon")):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate optional fields if present
        if "alt" in body and not _is_valid_float(body["alt"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "icon" in body and not _is_valid_tstr(body["icon"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "color" in body and not _is_valid_tstr(body["color"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "notes" in body and not _is_valid_tstr(body["notes"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "expires" in body and not _is_valid_uint(body["expires"]):
            return Message(code=aiocoap.BAD_REQUEST)

        # Build waypoint with auto-generated fields
        wpt_id = body.get("id")
        if wpt_id is None:
            wpt_id = self._generate_id()
        elif not _is_valid_tstr(wpt_id):
            return Message(code=aiocoap.BAD_REQUEST)

        waypoint: dict[str, Any] = {
            "id": wpt_id,
            "name": body["name"],
            "lat": float(body["lat"]),
            "lon": float(body["lon"]),
            "created": body.get("created", int(time.time())),
            "creator": body.get("creator", self._creator_id),
        }

        # Add optional fields
        if "alt" in body:
            waypoint["alt"] = float(body["alt"])
        if "icon" in body:
            waypoint["icon"] = body["icon"]
        if "color" in body:
            waypoint["color"] = body["color"]
        if "notes" in body:
            waypoint["notes"] = body["notes"]
        if "expires" in body:
            waypoint["expires"] = body["expires"]

        self.add_waypoint(waypoint)

        msg = Message(code=aiocoap.CREATED)
        msg.opt.location_path = ("waypoints", wpt_id)
        return msg


class WaypointDetailsResource(resource.Resource, resource.PathCapable):
    """Dynamic router for ``/waypoints/{id}`` (spec 18.3).

    **GET** returns a single waypoint.
    **PUT** updates a waypoint.
    **DELETE** removes a waypoint.
    """

    def __init__(self, waypoints: WaypointsResource) -> None:
        super().__init__()
        self._waypoints = waypoints

    def _extract_id(self, request: Message) -> str | None:
        """Extract waypoint ID from URI path."""
        if len(request.opt.uri_path) != 1:
            return None
        wpt_id = request.opt.uri_path[0]
        if not wpt_id or not wpt_id.isascii():
            return None
        return wpt_id

    async def render_get(self, request: Message) -> Message:
        """Return a single waypoint."""
        wpt_id = self._extract_id(request)
        if wpt_id is None:
            return Message(code=aiocoap.NOT_FOUND)
        waypoint = self._waypoints.waypoint(wpt_id)
        if waypoint is None:
            return Message(code=aiocoap.NOT_FOUND)
        return _cbor_response(waypoint)

    async def render_put(self, request: Message) -> Message:
        """Update a waypoint."""
        wpt_id = self._extract_id(request)
        if wpt_id is None:
            return Message(code=aiocoap.NOT_FOUND)
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)

        # Validate optional fields if present
        if "name" in body and not _is_valid_tstr(body["name"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "lat" in body and not _is_valid_float(body["lat"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "lon" in body and not _is_valid_float(body["lon"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "alt" in body and not _is_valid_float(body["alt"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "icon" in body and not _is_valid_tstr(body["icon"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "color" in body and not _is_valid_tstr(body["color"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "notes" in body and not _is_valid_tstr(body["notes"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "expires" in body and not _is_valid_uint(body["expires"]):
            return Message(code=aiocoap.BAD_REQUEST)

        if not self._waypoints.update_waypoint(wpt_id, body):
            return Message(code=aiocoap.NOT_FOUND)

        return Message(code=aiocoap.CHANGED)

    async def render_delete(self, request: Message) -> Message:
        """Delete a waypoint."""
        wpt_id = self._extract_id(request)
        if wpt_id is None:
            return Message(code=aiocoap.NOT_FOUND)
        if not self._waypoints.delete_waypoint(wpt_id):
            return Message(code=aiocoap.NOT_FOUND)
        return Message(code=aiocoap.DELETED)

    def get_resources_as_linkheader(self) -> Any:
        return resource.LinkFormat([
            resource.Link(f"/{wpt_id}", ct=str(int(CBOR)))
            for wpt_id in self._waypoints._waypoint_order
        ])
