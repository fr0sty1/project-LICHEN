# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SenML+CBOR observable resources for sensors, location, and metrics."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aiocoap import CONTENT, Message, resource

from lichen.coap.resources.base import SENML_CBOR


class SenMLSensorsResource(resource.ObservableResource):
    """Observable ``/sensors`` — SenML+CBOR pack of all current readings.

    Callers push new readings by calling :meth:`update`; all registered CoAP
    observers receive a notification automatically (RFC 7641).

    Example::

        sensors = SenMLSensorsResource()
        site = build_site(info, sensors_resource=sensors)
        # ... later, when readings change:
        sensors.update([temperature(23.4), humidity(61.0)])
    """

    def __init__(self) -> None:
        super().__init__()
        from lichen.senml.codec import pack  # noqa: PLC0415

        self._records: list[Any] = []
        self._payload: bytes = pack([])

    def update(self, records: list[Any]) -> None:
        """Replace the current readings and notify all observers.

        Args:
            records: List of :class:`~lichen.senml.codec.SenmlRecord`.
        """
        from lichen.senml.codec import pack

        self._records = records
        self._payload = pack(records)
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg


class SenMLLocationResource(resource.ObservableResource):
    """Observable ``/sensors/location`` — current position as SenML+CBOR.

    Callers push position fixes by calling :meth:`update`.  ``build_site`` also
    mounts the resource at the historical ``/location`` path for compatibility.

    Example::

        loc = SenMLLocationResource()
        site = build_site(info, location_resource=loc)
        loc.update(lat=48.2049, lon=16.3710, alt=158.0)
    """

    def __init__(self) -> None:
        super().__init__()
        from lichen.senml.codec import pack  # noqa: PLC0415

        self._payload: bytes = pack([])

    def update(
        self,
        lat: float,
        lon: float,
        alt: float | None = None,
        speed: float | None = None,
        heading: float | None = None,
        hacc: float | None = None,
        vacc: float | None = None,
    ) -> None:
        """Set the current position and notify all observers.

        Args:
            lat: Latitude in decimal degrees (WGS-84).
            lon: Longitude in decimal degrees (WGS-84).
            alt: Altitude in metres above WGS-84 ellipsoid, or None to omit.
            speed: Ground speed in metres per second, or None to omit.
            heading: Heading in degrees, or None to omit.
            hacc: Horizontal accuracy in metres, or None to omit.
            vacc: Vertical accuracy in metres, or None to omit.
        """
        from lichen.senml.codec import pack
        from lichen.senml.profiles import location

        self._payload = pack(
            location(
                lat=lat,
                lon=lon,
                alt=alt,
                speed=speed,
                heading=heading,
                hacc=hacc,
                vacc=vacc,
            )
        )
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg

    def get_link_description(self) -> dict[str, Any]:
        """Describe the observable location sensor for CoRE discovery."""
        return {
            "rt": "senml",
            "if": "sensor",
            "ct": str(int(SENML_CBOR)),
            "obs": None,
            "geo": "*",
        }


class PositionBeaconResource(resource.ObservableResource):
    """Writable ``/pos`` — position beacon receiver (SenML+CBOR).

    Remote nodes PUT their position to this resource. The coordinator stores
    positions keyed by sender identity (extracted from SenML base name ``bn``
    or CoAP source address) and notifies observers.

    Example::

        pos = PositionBeaconResource(on_position=my_callback)
        site = build_site(info, position_beacon_resource=pos)
        # Remote node PUTs position -> on_position callback fires

    On GET, returns all stored positions as a CBOR map:
    ``{sender_id: {lat, lon, alt?, speed?, heading?, ts}, ...}``
    """

    # Required position fields
    _REQUIRED = frozenset({"lat", "lon"})
    # All valid position fields from profiles.location
    _VALID_FIELDS = frozenset({"lat", "lon", "alt", "speed", "heading", "hacc", "vacc"})

    def __init__(
        self,
        *,
        on_position: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        """Create a position beacon resource.

        Args:
            on_position: Optional callback invoked on each valid position update.
                Called with (sender_id, position_dict) where position_dict
                contains lat, lon, and optional alt, speed, heading, hacc, vacc, ts.
        """
        super().__init__()
        self._positions: dict[str, dict[str, Any]] = {}
        self._on_position = on_position

    def _extract_position(self, records: list[Any]) -> tuple[str | None, dict[str, Any]]:
        """Extract sender ID and position from SenML records.

        Returns:
            Tuple of (sender_id_or_None, position_dict). sender_id is None if
            no base name was provided. position_dict has lat, lon, and optional
            fields.

        Raises:
            ValueError: If required fields (lat, lon) are missing.
        """
        sender_id: str | None = None
        position: dict[str, Any] = {}

        for rec in records:
            # Extract base name as sender ID
            if rec.bn is not None:
                sender_id = rec.bn
            # Extract position fields
            if rec.n in self._VALID_FIELDS and rec.v is not None:
                position[rec.n] = rec.v

        missing = self._REQUIRED - set(position.keys())
        if missing:
            raise ValueError(f"Missing required position fields: {sorted(missing)}")

        return sender_id, position

    async def render_put(self, request: Message) -> Message:
        """Handle PUT /pos — receive position beacon from remote node."""
        import time

        from aiocoap import BAD_REQUEST, CHANGED

        from lichen.senml.codec import unpack

        if not request.payload:
            return Message(code=BAD_REQUEST)

        # Validate content format
        if request.opt.content_format is not None and request.opt.content_format != SENML_CBOR:
            return Message(code=BAD_REQUEST)

        try:
            records = unpack(request.payload)
        except ValueError:
            return Message(code=BAD_REQUEST)

        try:
            sender_id, position = self._extract_position(records)
        except ValueError:
            return Message(code=BAD_REQUEST)

        # Use sender_id from bn, or fall back to remote address
        if sender_id is None:
            remote = getattr(request, "remote", None)
            sender_id = str(remote.hostinfo) if remote is not None else "unknown"

        # Add timestamp
        position["ts"] = time.time()

        # Store position
        self._positions[sender_id] = position
        self.updated_state()

        # Invoke callback if provided
        if self._on_position is not None:
            self._on_position(sender_id, position)

        return Message(code=CHANGED)

    async def render_get(self, request: Message) -> Message:
        """Handle GET /pos — return all stored positions."""
        import cbor2

        from lichen.coap.resources.base import CBOR

        msg = Message(code=CONTENT, payload=cbor2.dumps(self._positions))
        msg.opt.content_format = CBOR
        return msg

    def get_position(self, sender_id: str) -> dict[str, Any] | None:
        """Get the last known position for a sender.

        Args:
            sender_id: The sender's base name or address.

        Returns:
            Position dict or None if not found.
        """
        return self._positions.get(sender_id)

    def get_all_positions(self) -> dict[str, dict[str, Any]]:
        """Get all stored positions.

        Returns:
            Dict mapping sender_id to position dict.
        """
        return dict(self._positions)

    def clear(self) -> None:
        """Clear all stored positions."""
        self._positions.clear()
        self.updated_state()

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        from lichen.coap.resources.base import CBOR

        return {
            "rt": "position",
            "if": "sensor",
            "ct": str(int(CBOR)),
            "obs": None,
        }


class SenMLMetricsResource(resource.ObservableResource):
    """Basic observable ``/metrics`` CoAP resource — SenML+CBOR (112)
    telemetry+battery profile (RSSI, nodecount, pps, battery, collision-rate).

    Updated via :meth:`update(**kwargs)` where kwargs match
    :func:`~lichen.senml.profiles.metrics`. Supports GET, Observe.
    """

    def __init__(self) -> None:
        """Initialize with empty SenML pack."""
        super().__init__()
        from lichen.senml.codec import pack  # noqa: PLC0415

        self._payload: bytes = pack([])

    def update(
        self,
        rssi: int | None = None,
        nodecount: int | None = None,
        packets_per_sec: float | None = None,
        battery: float | None = None,
        collision_rate: float | None = None,
    ) -> None:
        """Update telemetry+battery readings and notify all observers."""
        from lichen.senml.codec import pack  # noqa: PLC0415
        from lichen.senml.profiles import metrics  # noqa: PLC0415

        self._payload = pack(
            metrics(
                rssi=rssi,
                nodecount=nodecount,
                packets_per_sec=packets_per_sec,
                battery=battery,
                collision_rate=collision_rate,
            ),
        )
        self.updated_state()

    async def render_get(self, request: Message) -> Message:  # noqa: D102,ARG002
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {
            "rt": "senml",
            "if": "sensor",
            "ct": str(int(SENML_CBOR)),
            "obs": None,
        }
