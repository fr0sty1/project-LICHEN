# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SenML+CBOR observable resources for sensors, location, and metrics."""

from __future__ import annotations

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
    """Observable ``/location`` — SenML+CBOR lat/lon(/alt) pack.

    Callers push position fixes by calling :meth:`update`.

    Example::

        loc = SenMLLocationResource()
        site = build_site(info, location_resource=loc)
        loc.update(lat=48.2049, lon=16.3710, alt=158.0)
    """

    def __init__(self) -> None:
        super().__init__()
        from lichen.senml.codec import pack  # noqa: PLC0415
        self._payload: bytes = pack([])

    def update(self, lat: float, lon: float, alt: float | None = None) -> None:
        """Set the current position and notify all observers.

        Args:
            lat: Latitude in decimal degrees (WGS-84).
            lon: Longitude in decimal degrees (WGS-84).
            alt: Altitude in metres above WGS-84 ellipsoid, or None to omit.
        """
        from lichen.senml.codec import pack
        from lichen.senml.profiles import location

        self._payload = pack(location(lat, lon, alt))
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg


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
