# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Range Testing resources: /diag/rangetest and /diag/traceroute (spec 18.7)."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import aiocoap
import cbor2
from aiocoap import CONTENT, Message, resource

from lichen.coap.resources.base import CBOR, SENML_CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.senml.codec import SenmlRecord, pack

# Limits per spec
MAX_PAYLOAD_LEN = 255  # Maximum test payload size
MAX_COUNT = 100  # Maximum response count
DEFAULT_INTERVAL_MS = 5000  # Default continuous test interval


@dataclass
class RadioMetrics:
    """Radio link quality metrics for range testing."""

    rssi: float = -85.0  # dBm
    snr: float = 7.5  # dB
    sf: int = 9  # Spreading factor
    freq: float = 906.875  # MHz


@dataclass
class TracerouteHop:
    """A single hop in a traceroute."""

    addr: str  # IPv6 address
    rssi: float  # dBm
    rtt_ms: float  # Round-trip time in ms


@dataclass
class RadioMetricsProvider:
    """Provider for radio metrics (injectable for testing).

    In a real implementation, this would read from the radio driver.
    """

    metrics: RadioMetrics = field(default_factory=RadioMetrics)
    hops: list[TracerouteHop] = field(default_factory=list)
    node_eui64: str = "0102030405060708"

    def get_metrics(self) -> RadioMetrics:
        """Return current radio metrics."""
        return self.metrics

    def get_traceroute(self) -> list[TracerouteHop]:
        """Return traceroute hops to this node."""
        return self.hops


def _rangetest_senml(
    node_eui64: str,
    seq: int,
    metrics: RadioMetrics,
    timestamp: float | None = None,
) -> list[SenmlRecord]:
    """Build SenML pack for range test response per spec 18.7.2.

    Returns:
        List of SenML records with bn, bt, seq, rssi, snr, sf, freq.
    """
    bt = timestamp if timestamp is not None else time.time()
    return [
        SenmlRecord(bn=f"urn:dev:mac:{node_eui64}:", bt=bt),
        SenmlRecord(n="seq", v=seq),
        SenmlRecord(n="rssi", u="dBm", v=metrics.rssi),
        SenmlRecord(n="snr", u="dB", v=metrics.snr),
        SenmlRecord(n="sf", v=metrics.sf),
        SenmlRecord(n="freq", u="MHz", v=metrics.freq),
    ]


class RangeTestResource(resource.ObservableResource):
    """Observable ``/diag/rangetest`` — range testing (spec 18.7.2/18.7.3).

    **POST** (Extended Range Test): Returns SenML+CBOR with radio metrics.
    Request body (optional)::

        {"seq": 1, "payload_len": 32, "count": 5}

    Response::

        [
          {"bn": "urn:dev:mac:...", "bt": 1716742800},
          {"n": "seq", "v": 1},
          {"n": "rssi", "u": "dBm", "v": -85},
          {"n": "snr", "u": "dB", "v": 7.5},
          {"n": "sf", "v": 9},
          {"n": "freq", "u": "MHz", "v": 906.875}
        ]

    **GET** (Continuous Range Test): Returns current metrics or subscribes
    via Observe (RFC 7641) for periodic updates.

    The resource maintains internal state that can be updated via :meth:`update`
    to push new readings to observers.
    """

    def __init__(
        self,
        provider: RadioMetricsProvider | None = None,
        time_func: Any = None,
    ) -> None:
        """Initialize RangeTest resource.

        Args:
            provider: Radio metrics provider (defaults to static metrics).
            time_func: Optional callable returning current time (for testing).
        """
        super().__init__()
        self._provider = provider if provider is not None else RadioMetricsProvider()
        self._time_func = time_func if time_func is not None else time.time
        self._seq = 0
        self._interval_ms = DEFAULT_INTERVAL_MS
        # Pre-compute initial payload
        self._update_payload()

    def _update_payload(self) -> None:
        """Update the cached SenML payload."""
        metrics = self._provider.get_metrics()
        records = _rangetest_senml(
            self._provider.node_eui64,
            self._seq,
            metrics,
            self._time_func(),
        )
        self._payload = pack(records)

    def update(self, metrics: RadioMetrics | None = None) -> None:
        """Update metrics and notify observers.

        Args:
            metrics: New radio metrics. If None, re-reads from provider.
        """
        if metrics is not None:
            self._provider.metrics = metrics
        self._seq += 1
        self._update_payload()
        self.updated_state()

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core."""
        return {
            "rt": "rangetest",
            "ct": str(int(SENML_CBOR)),
            "obs": None,
        }

    async def render_get(self, request: Message) -> Message:
        """GET /diag/rangetest — return current metrics (spec 18.7.3)."""
        # Check for interval parameter in payload
        if request.payload:
            try:
                body = _decode_single_cbor(request.payload)
            except (ValueError, OverflowError, cbor2.CBORDecodeError):
                return Message(code=aiocoap.BAD_REQUEST)
            # Match POST strictness: only a map may carry options (spec 18.7.3).
            if not isinstance(body, dict):
                return Message(code=aiocoap.BAD_REQUEST)
            if "interval_ms" in body:
                interval = body["interval_ms"]
                if (
                    isinstance(interval, bool)
                    or not isinstance(interval, (int, float))
                    or (isinstance(interval, float) and not math.isfinite(interval))
                    or interval <= 0
                ):
                    return Message(code=aiocoap.BAD_REQUEST)
                self._interval_ms = int(interval)

        # Update and return current metrics
        self._update_payload()
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        """POST /diag/rangetest — extended range test (spec 18.7.2)."""
        seq = 0
        # payload_len and count are validated but behavior is out of scope
        # for this oracle; real implementation would pad request/send multiple responses
        _payload_len = 0
        _count = 1

        # Parse optional request body
        if request.payload:
            try:
                body = _decode_single_cbor(request.payload)
            except (ValueError, OverflowError, cbor2.CBORDecodeError):
                return Message(code=aiocoap.BAD_REQUEST)

            if not isinstance(body, dict):
                return Message(code=aiocoap.BAD_REQUEST)

            # Validate seq
            if "seq" in body:
                seq_val = body["seq"]
                if isinstance(seq_val, bool) or not isinstance(seq_val, int) or seq_val < 0:
                    return Message(code=aiocoap.BAD_REQUEST)
                seq = seq_val

            # Validate payload_len
            if "payload_len" in body:
                plen = body["payload_len"]
                if (
                    isinstance(plen, bool)
                    or not isinstance(plen, int)
                    or plen < 0
                    or plen > MAX_PAYLOAD_LEN
                ):
                    return Message(code=aiocoap.BAD_REQUEST)
                _payload_len = plen  # noqa: F841

            # Validate count
            if "count" in body:
                cnt = body["count"]
                if isinstance(cnt, bool) or not isinstance(cnt, int) or cnt < 1 or cnt > MAX_COUNT:
                    return Message(code=aiocoap.BAD_REQUEST)
                _count = cnt  # noqa: F841

        # Get current metrics from provider
        metrics = self._provider.get_metrics()

        # Build SenML response
        records = _rangetest_senml(
            self._provider.node_eui64,
            seq,
            metrics,
            self._time_func(),
        )

        # For count > 1, the caller would receive multiple responses
        # (out of scope for this oracle; just return single response)
        # The payload_len parameter is for testing with specific sizes
        # (would affect the request padding, not the response)

        payload = pack(records)
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = SENML_CBOR
        return msg


class TracerouteResource(resource.Resource):
    """``/diag/traceroute`` — mesh path discovery (spec 18.7.4).

    **GET** returns the hop-by-hop path through the mesh::

        {
          "hops": [
            {"addr": "fe80::1111", "rssi": -65, "rtt_ms": 120},
            {"addr": "fe80::2222", "rssi": -78, "rtt_ms": 340}
          ],
          "total_hops": 2,
          "total_rtt_ms": 340
        }

    Implementation uses RPL source routing information or hop-by-hop probing.
    """

    def __init__(self, provider: RadioMetricsProvider | None = None) -> None:
        """Initialize Traceroute resource.

        Args:
            provider: Radio metrics provider with hop information.
        """
        super().__init__()
        self._provider = provider if provider is not None else RadioMetricsProvider()

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core."""
        return {
            "rt": "traceroute",
            "ct": str(int(CBOR)),
        }

    async def render_get(self, request: Message) -> Message:
        """GET /diag/traceroute — return mesh path (spec 18.7.4)."""
        hops = self._provider.get_traceroute()

        # Build response
        hops_data = [{"addr": hop.addr, "rssi": hop.rssi, "rtt_ms": hop.rtt_ms} for hop in hops]

        total_hops = len(hops)
        # Float-typed even when empty so the CBOR value type never flips
        # with hop count (cross-implementation conformance).
        total_rtt_ms = hops[-1].rtt_ms if hops else 0.0

        response = {
            "hops": hops_data,
            "total_hops": total_hops,
            "total_rtt_ms": total_rtt_ms,
        }

        msg = Message(code=CONTENT, payload=cbor2.dumps(response))
        msg.opt.content_format = CBOR
        return msg
