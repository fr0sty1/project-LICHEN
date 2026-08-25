# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the LCI status-side CBOR vector families by driving real code.

Files consumed (previously had zero machine consumers):

- ``test/vectors/lci_status.json``        -> ``StatusResource.render_get`` over
  ``StaticNodeInfo`` (spec 17.5.3 status document)
- ``test/vectors/lci_routing_table.json`` -> ``RoutesResource.render_get`` over
  ``StaticNodeInfo`` (spec 17.5.3 routing table document)
- ``test/vectors/lci_raw_diag.json``      -> ``LciClient.send_raw_tx`` /
  ``arm_raw_rx`` request encoders, the client-side ttl_s rejection, and
  ``normalize_raw_rx_status`` / ``normalize_raw_rx_event`` decoders
- ``test/vectors/position_cache.json``    -> ``PositionCacheResource.render_get``
  with an injected fixed clock, plus record_position validation rejections
- ``test/vectors/position_observe.json``  -> SenML+CBOR observe notification
  payloads from ``SenMLLocationResource`` pushed through a full
  ``InMemoryNetwork`` client/server stack (spec 18.2.3)

Byte oracle follows the ``neighbors_cbor.json`` precedent: for producer-backed
families the resource/client emits the pinned bytes; for rx_status/rx_event
payloads no Python producer exists (firmware-side), so bytes are pinned by the
reference CBOR codec oracle (``cbor2.dumps`` of the spec-shaped input) and the
real client decoders are driven against them.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import cbor2
import pytest
from aiocoap import GET, Message

from lichen.client import CoapResult, LciClient, RawDiagnosticState
from lichen.client.lci import normalize_raw_rx_event, normalize_raw_rx_status
from lichen.coap.resources import (
    PositionCacheResource,
    RoutesResource,
    SenMLLocationResource,
    StaticNodeInfo,
    StatusResource,
)
from lichen.coap.resources.site import build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.senml.codec import unpack

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"

LCI_STATUS = json.loads((VECTORS_DIR / "lci_status.json").read_text())
LCI_ROUTING_TABLE = json.loads((VECTORS_DIR / "lci_routing_table.json").read_text())
LCI_RAW_DIAG = json.loads((VECTORS_DIR / "lci_raw_diag.json").read_text())
POSITION_CACHE = json.loads((VECTORS_DIR / "position_cache.json").read_text())
POSITION_OBSERVE = json.loads((VECTORS_DIR / "position_observe.json").read_text())


def _vec(doc: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [v for v in doc["vectors"] if v["name"] == name]
    assert len(matches) == 1, f"vector {name!r} not unique in {doc['name']}"
    return matches[0]


def _cases(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(v["name"], v) for v in doc["vectors"]]


# ---------------------------------------------------------------------------
# Shared test doubles
# ---------------------------------------------------------------------------


class RecordingTransport:
    """ResourceTransport double that records emitted requests verbatim."""

    def __init__(self, response: CoapResult | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self._response = response

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        del observe
        self.requests.append(
            {
                "method": method,
                "path": path,
                "payload": bytes(payload),
                "content_format": content_format,
            }
        )
        assert self._response is not None, "unexpected request without scripted response"
        return self._response

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def observe(self, path: str, *, method: str = "GET") -> AsyncIterator[CoapResult]:
        del path, method
        raise NotImplementedError


# ---------------------------------------------------------------------------
# lci_status.json — GET /status payload (spec 17.5.3)
# ---------------------------------------------------------------------------


class TestLciStatusVectors:
    @pytest.mark.parametrize("name,vector", _cases(LCI_STATUS))
    async def test_status_resource_emits_pinned_bytes(self, name: str, vector: dict) -> None:
        info = StaticNodeInfo(status=vector["input"]["status"])
        response = await StatusResource(info).render_get(Message(code=GET))
        assert int(response.opt.content_format) == 60, name
        assert response.payload.hex() == vector["encoded_hex"], f"encode drift: {name}"

    @pytest.mark.parametrize("name,vector", _cases(LCI_STATUS))
    async def test_status_payload_round_trips(self, name: str, vector: dict) -> None:
        wire = bytes.fromhex(vector["encoded_hex"])
        decoded = cbor2.loads(wire)
        assert decoded == vector["input"]["status"], name
        # Canonical re-encode of the pinned input reproduces the committed hex.
        assert cbor2.dumps(vector["input"]["status"]) == wire, f"re-encode drift: {name}"


# ---------------------------------------------------------------------------
# lci_routing_table.json — GET /status/routes payload (spec 17.5.3)
# ---------------------------------------------------------------------------


class TestRoutingTableVectors:
    @pytest.mark.parametrize("name,vector", _cases(LCI_ROUTING_TABLE))
    async def test_routes_resource_emits_pinned_bytes(self, name: str, vector: dict) -> None:
        info = StaticNodeInfo(routes=vector["input"])
        response = await RoutesResource(info).render_get(Message(code=GET))
        assert int(response.opt.content_format) == 60, name
        assert response.payload.hex() == vector["encoded_hex"], f"encode drift: {name}"
        assert cbor2.loads(response.payload) == vector["input"], name

    @pytest.mark.parametrize("name,vector", _cases(LCI_ROUTING_TABLE))
    def test_route_entries_carry_required_fields(self, name: str, vector: dict) -> None:
        for route in vector["input"]["routes"]:
            assert set(route) == {"prefix", "via", "metric", "lifetime_s"}, name
            assert route["prefix"].endswith("/64"), name
            assert route["via"].startswith("fe80::"), name


# ---------------------------------------------------------------------------
# lci_raw_diag.json — raw diagnostics commands and payloads (spec 17.5.4)
# ---------------------------------------------------------------------------


class TestRawDiagVectors:
    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(LCI_RAW_DIAG) if c[1]["kind"] == "tx_command"],
    )
    async def test_send_raw_tx_encodes_pinned_request(self, name: str, vector: dict) -> None:
        transport = RecordingTransport(response=CoapResult(code="2.04"))
        client = LciClient(transport)
        result = await client.send_raw_tx(
            bytes.fromhex(vector["input"]["frame_hex"]), wait=vector["input"]["wait"]
        )
        assert result.state is RawDiagnosticState.OK, name
        assert result.coap_code == "2.04"
        assert len(transport.requests) == 1, name
        sent = transport.requests[0]
        assert sent["method"] == vector["request"]["method"]
        assert sent["path"] == vector["request"]["path"]
        assert sent["content_format"] == vector["request"]["content_format"]
        assert sent["payload"].hex() == vector["request_cbor_hex"], f"encode drift: {name}"
        body = cbor2.loads(sent["payload"])
        assert body == {
            "frame": bytes.fromhex(vector["input"]["frame_hex"]),
            "wait": vector["input"]["wait"],
        }, name

    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(LCI_RAW_DIAG) if c[1]["kind"] == "arm_command"],
    )
    async def test_arm_raw_rx_encodes_pinned_request(self, name: str, vector: dict) -> None:
        transport = RecordingTransport(response=CoapResult(code="2.04"))
        client = LciClient(transport)
        result = await client.arm_raw_rx(
            ttl_s=vector["input"]["ttl_s"],
            include_payload=vector["input"]["include_payload"],
            enabled=vector["input"]["enabled"],
        )
        assert result.state is RawDiagnosticState.OK, name
        assert len(transport.requests) == 1, name
        sent = transport.requests[0]
        assert sent["method"] == vector["request"]["method"]
        assert sent["path"] == vector["request"]["path"]
        assert sent["content_format"] == vector["request"]["content_format"]
        assert sent["payload"].hex() == vector["request_cbor_hex"], f"encode drift: {name}"
        assert cbor2.loads(sent["payload"]) == vector["input"], name

    async def test_arm_raw_rx_rejects_nonpositive_ttl_without_wire_request(self) -> None:
        vec = _vec(LCI_RAW_DIAG, "rx_arm_reject_ttl_zero")
        transport = RecordingTransport()
        client = LciClient(transport)
        result = await client.arm_raw_rx(ttl_s=vec["input"]["ttl_s"])
        assert result.state.value == vec["expected"]["state"]
        assert result.detail == vec["expected"]["detail"]
        assert len(transport.requests) == vec["expected"]["wire_requests"]

    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(LCI_RAW_DIAG) if c[1]["kind"] == "rx_status"],
    )
    async def test_rx_status_decodes_through_lci_client(self, name: str, vector: dict) -> None:
        wire = bytes.fromhex(vector["encoded_hex"])
        # Reference-codec oracle: canonical encoding of the pinned input map.
        assert cbor2.dumps(vector["input"]) == wire, f"re-encode drift: {name}"
        transport = RecordingTransport(response=CoapResult(code="2.05", payload=vector["input"]))
        client = LciClient(transport)
        status = await client.get_raw_rx_status()
        normalized = vector["normalized"]
        assert status.state is RawDiagnosticState(normalized["state"])
        assert status.enabled is normalized["enabled"]
        assert status.remaining_s == normalized["remaining_s"]
        assert status.max_ttl_s == normalized["max_ttl_s"]
        assert transport.requests[0]["path"] == "/diag/raw/rx"

    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(LCI_RAW_DIAG) if c[1]["kind"] == "rx_event"],
    )
    def test_rx_event_normalizes_spec_fields(self, name: str, vector: dict) -> None:
        wire = bytes.fromhex(vector["encoded_hex"])
        # Canonical wire map: frame is raw bytes on the wire, hex in the JSON,
        # and keyed first to match the producer's insertion order.
        wire_map = {"frame": bytes.fromhex(vector["input"]["frame_hex"])}
        wire_map.update({k: v for k, v in vector["input"].items() if k != "frame_hex"})
        assert cbor2.dumps(wire_map) == wire, f"re-encode drift: {name}"
        event = normalize_raw_rx_event(cbor2.loads(wire))
        normalized = vector["normalized"]
        assert event.state is RawDiagnosticState(normalized["state"])
        assert event.frame == bytes.fromhex(normalized["frame_hex"])
        assert event.rssi_dbm == normalized["rssi_dbm"]
        assert event.snr_db == normalized["snr_db"]
        for optional in ("uptime_ms", "freq_hz", "crc_ok"):
            if optional in normalized:
                assert getattr(event, optional) == normalized[optional], name

    async def test_rx_status_not_a_map_rejected(self) -> None:
        vec = _vec(LCI_RAW_DIAG, "rx_status_not_a_map")
        payload = cbor2.loads(bytes.fromhex(vec["encoded_hex"]))
        status = normalize_raw_rx_status(payload)
        assert status.state is RawDiagnosticState(vec["expected"]["state"])
        assert status.detail == vec["expected"]["detail"]
        assert status.enabled is None and status.remaining_s is None

    async def test_rx_event_not_a_map_rejected(self) -> None:
        vec = _vec(LCI_RAW_DIAG, "rx_event_not_a_map")
        payload = cbor2.loads(bytes.fromhex(vec["encoded_hex"]))
        event = normalize_raw_rx_event(payload)
        assert event.state is RawDiagnosticState(vec["expected"]["state"])
        assert event.detail == vec["expected"]["detail"]
        assert event.frame is None


# ---------------------------------------------------------------------------
# position_cache.json — GET /pos/cache responses (spec 18.2.1)
# ---------------------------------------------------------------------------


class TestPositionCacheVectors:
    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(POSITION_CACHE) if c[1].get("kind") != "reject"],
    )
    async def test_cache_response_matches_pinned_bytes(self, name: str, vector: dict) -> None:
        cache = PositionCacheResource(time_source=lambda: vector["input"]["now"])
        for record in vector["input"]["record"]:
            cache.record_position(**dict(record))
        response = await cache.render_get(Message(code=GET))
        assert int(response.opt.content_format) == 60, name
        assert response.payload.hex() == vector["encoded_hex"], f"encode drift: {name}"
        decoded = cbor2.loads(response.payload)
        assert {p["node"] for p in decoded["positions"]} == {
            r["node"] for r in vector["input"]["record"]
        }
        for entry in decoded["positions"]:
            expected_age = int(vector["input"]["now"] - entry["ts"])
            assert entry["age_s"] == expected_age, name

    @pytest.mark.parametrize(
        "name,vector",
        [c for c in _cases(POSITION_CACHE) if c[1].get("kind") == "reject"],
    )
    async def test_cache_record_rejections(self, name: str, vector: dict) -> None:
        cache = PositionCacheResource()
        kwargs = dict(vector["input"])
        if kwargs.get("lat") == "NaN":
            kwargs["lat"] = float("nan")
        with pytest.raises(ValueError, match=vector["expected_error"]):
            cache.record_position(**kwargs)
        # Rejected records must not mutate the cache.
        response = await cache.render_get(Message(code=GET))
        assert cbor2.loads(response.payload) == {"positions": []}, name


# ---------------------------------------------------------------------------
# position_observe.json — SenML observe notification sequences (spec 18.2.3)
# ---------------------------------------------------------------------------


async def _observe_location_session(
    updates: list[dict[str, Any]],
) -> tuple[bytes, list[bytes]]:
    net = InMemoryNetwork()
    location = SenMLLocationResource()
    site = build_site(StaticNodeInfo(status={"rank": 256}), location_resource=location)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    try:
        request = client.request(Message(code=GET, observe=0, uri="coap://srv/location"))
        initial = await request.response
        notifications: list[bytes] = []
        observer = request.observation.__aiter__()
        for fix in updates:
            location.update(**fix)
            note = await asyncio.wait_for(observer.__anext__(), timeout=5.0)
            notifications.append(bytes(note.payload))
        return bytes(initial.payload), notifications
    finally:
        await client.shutdown()
        await server.shutdown()


class TestPositionObserveVectors:
    @pytest.mark.parametrize("name,vector", _cases(POSITION_OBSERVE))
    async def test_notification_sequence_matches_pins(self, name: str, vector: dict) -> None:
        initial, notifications = await _observe_location_session(vector["input"]["updates"])
        if "initial_response_hex" in vector:
            assert initial.hex() == vector["initial_response_hex"], name
        assert len(notifications) == len(vector["notification_payloads_hex"]), name
        for index, (actual, expected_hex) in enumerate(
            zip(notifications, vector["notification_payloads_hex"], strict=True)
        ):
            assert actual.hex() == expected_hex, f"{name}: notification {index + 1} drift"
            records = unpack(actual)
            assert isinstance(records, list) and records, name
            # Every pack carries lat/lon records; alt present iff update had it.
            names = {record.n for record in records}
            fix = vector["input"]["updates"][index]
            assert {"lat", "lon"} <= names, name
            assert ("alt" in names) is ("alt" in fix), name


# ---------------------------------------------------------------------------
# Guard: every vector in each file is accounted for by this module
# ---------------------------------------------------------------------------


class TestAllStatusSideVectorsAccountedFor:
    EXPECTED_COUNTS = {
        "lci_status": 4,
        "lci_routing_table": 3,
        "lci_raw_diag": 11,
        "position_cache": 7,
        "position_observe": 2,
    }

    @pytest.mark.parametrize(
        "doc",
        [LCI_STATUS, LCI_ROUTING_TABLE, LCI_RAW_DIAG, POSITION_CACHE, POSITION_OBSERVE],
    )
    def test_vector_count_matches_expectation(self, doc: dict[str, Any]) -> None:
        assert doc["format_version"] == 2
        assert len(doc["vectors"]) == self.EXPECTED_COUNTS[doc["name"]]
