# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume ``test/vectors/core_link_format.json`` (RFC 6690 discovery).

Parse vectors drive :func:`lichen.client.lci.parse_link_format`, the real LCI
discovery decoder. The ``node_emitted`` vector pins the exact link entries the
Python node's default ``build_site()`` emits from GET /.well-known/core and is
verified against a live InMemoryNetwork stack (aiocoap appends one
version-pinned ``rel="impl-info"`` entry that the vector intentionally omits).
Error vectors reflect verified behavior: unclosed quotes raise
:class:`lichen.client.LciClientError`; bracket-less targets are skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from aiocoap import GET, Message

from lichen.client.lci import parse_link_format
from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
DOC: dict[str, Any] = json.loads((VECTORS_DIR / "core_link_format.json").read_text())
VECTORS = DOC["vectors"]

PARSE_VECTORS = [v for v in VECTORS if v["kind"] == "parse"]
ERROR_VECTORS = [v for v in VECTORS if v["kind"] == "error"]
NODE_VECTORS = [v for v in VECTORS if v["kind"] == "node_emitted"]

EXPECTED_COUNTS = {"parse": 9, "error": 2, "node_emitted": 1}


def _assert_capabilities(caps: Any, expected: dict[str, Any]) -> None:
    assert sorted(caps.resources) == expected["resources"]
    assert sorted(caps.observable) == expected["observable"]
    actual_types = {path: list(types) for path, types in caps.resource_types.items()}
    assert actual_types == expected["resource_types"]


@pytest.mark.parametrize("vector", PARSE_VECTORS, ids=lambda v: v["name"])
def test_parse_link_format(vector: dict[str, Any]) -> None:
    _assert_capabilities(parse_link_format(vector["body"]), vector["expected"])


@pytest.mark.parametrize("vector", ERROR_VECTORS, ids=lambda v: v["name"])
def test_error_cases_match_real_behavior(vector: dict[str, Any]) -> None:
    if vector["name"] == "error_unclosed_quote_raises":
        from lichen.client import LciClientError

        with pytest.raises(LciClientError, match="unclosed quote"):
            parse_link_format(vector["body"])
    else:
        # Lenient skip is the documented real behavior; pinned as such.
        _assert_capabilities(parse_link_format(vector["body"]), vector["expected"])


@pytest.mark.asyncio
async def test_node_emitted_default_site_wkc() -> None:
    vec = NODE_VECTORS[0]
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=build_site(StaticNodeInfo())
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server/.well-known/core")
        ).response
        body = response.payload.decode()
    finally:
        await client.shutdown()
        await server.shutdown()

    assert int(response.opt.content_format) == vec["expected"]["content_format"] == 40

    # Every pinned entry appears in emission order (impl-info may trail).
    cursor = -1
    for link in vec["links"]:
        index = body.find(link)
        assert index > cursor, f"{link!r} missing or out of order in {body!r}"
        cursor = index

    capabilities = parse_link_format(body)
    assert set(vec["expected"]["resources"]) <= set(capabilities.resources)
    assert set(vec["expected"]["observable"]) <= set(capabilities.observable)
    for path, types in vec["expected"]["resource_types"].items():
        if types:
            assert list(capabilities.resource_types[path]) == types


class TestAllVectorsAccountedFor:
    def test_vector_count_matches_expectation(self) -> None:
        counts = {
            "parse": len(PARSE_VECTORS),
            "error": len(ERROR_VECTORS),
            "node_emitted": len(NODE_VECTORS),
        }
        assert counts == EXPECTED_COUNTS
        assert sum(counts.values()) == len(VECTORS)
