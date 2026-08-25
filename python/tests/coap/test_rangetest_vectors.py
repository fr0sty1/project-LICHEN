# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: range-testing CoAP resources vs shared vectors.

Drives the real ``RangeTestResource`` / ``TracerouteResource`` implementations
(spec 18.7) against the hand-derived oracle vectors in
``test/vectors/rangetest.json``. Expected payloads were encoded independently
from RFC 8428 Table 4 with raw cbor2; the implementation MUST reproduce them
byte-for-byte.
"""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Code, Message

from lichen.coap.resources.rangetest import (
    RadioMetrics,
    RadioMetricsProvider,
    RangeTestResource,
    TracerouteHop,
    TracerouteResource,
)

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "rangetest.json"

_CODE_BY_NAME = {
    "2.05": Code.CONTENT,
    "4.00": Code.BAD_REQUEST,
}


def _load_vectors() -> list[dict]:
    with open(_VECTORS_PATH) as f:
        return json.load(f)["vectors"]


@pytest.fixture(scope="module")
def vectors() -> list[dict]:
    return _load_vectors()


def _provider_from(vector: dict) -> RadioMetricsProvider:
    p = vector["provider"]
    return RadioMetricsProvider(
        metrics=RadioMetrics(rssi=p["rssi"], snr=p["snr"], sf=p["sf"], freq=p["freq"]),
        hops=[TracerouteHop(**h) for h in p.get("hops", [])],
        node_eui64=p["node_eui64"],
    )


def _request(vector: dict) -> Message:
    req = vector["request"]
    payload = b""
    if "body_hex" in req:
        payload = bytes.fromhex(req["body_hex"])
    method = Code.POST if req["method"] == "POST" else Code.GET
    return Message(code=method, payload=payload)


async def _render(vector: dict) -> Message:
    resource: object
    if vector["type"] == "traceroute":
        resource = TracerouteResource(provider=_provider_from(vector))
        return await resource.render_get(_request(vector))  # type: ignore[attr-defined]
    resource = RangeTestResource(
        provider=_provider_from(vector),
        time_func=lambda now=vector["now"]: now,
    )
    request = _request(vector)
    if request.code == Code.POST:
        return await resource.render_post(request)  # type: ignore[attr-defined]
    return await resource.render_get(request)  # type: ignore[attr-defined]


def _numeric_labels(records: list[dict]) -> list[dict]:
    """JSON cannot carry integer map keys; vectors store labels as strings."""
    return [{int(k): v for k, v in record.items()} for record in records]


class TestRangeTestVectors:
    @pytest.mark.parametrize("case", _load_vectors(), ids=lambda v: v["name"])
    async def test_vector(self, case: dict) -> None:
        response = await _render(case)
        expected = case["expected"]

        assert response.code == _CODE_BY_NAME[expected["code"]], (
            f"{case['name']}: got {response.code}, want {expected['code']}"
        )

        if "content_format" in expected:
            want_cf = (
                None
                if expected["content_format"] is None
                else aiocoap.ContentFormat(expected["content_format"])
            )
            assert response.opt.content_format == want_cf

        if "payload_hex" in expected:
            assert response.payload.hex() == expected["payload_hex"], (
                f"{case['name']}: payload mismatch"
            )

        if "records" in expected:
            decoded = cbor2.loads(response.payload)
            if case["type"] == "traceroute":
                assert decoded == expected["records"], f"{case['name']}: record mismatch"
            else:
                actual = [{int(k): v for k, v in record.items()} for record in decoded]
                assert actual == _numeric_labels(expected["records"]), (
                    f"{case['name']}: record mismatch"
                )
