# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume ``test/vectors/lci_identity.json`` via the read-only /config/identity.

GET vectors pin the exact bytes emitted by
:class:`~lichen.coap.resources.node_resources.IdentityConfigResource` and are
additionally normalized through the real LCI client path
(:func:`lichen.client.lci.normalize_identity`). The full-identity vector's
addresses are cross-checked against genuine key derivation
(:func:`lichen.ipv6.addr.link_local_from_pubkey`,
:func:`lichen.ipv6.addr.native_address_from_pubkey`). Mutating methods have no
implementation surface by design, so PUT/DELETE yield 4.05 — that is the
pinned rejection behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest
from aiocoap import DELETE, GET, PUT, Message
from aiocoap.numbers import ContentFormat

from lichen.client.lci import normalize_identity
from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.resources.node_resources import IdentityConfigResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.ipv6.addr import link_local_from_pubkey, native_address_from_pubkey

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
DOC: dict[str, Any] = json.loads((VECTORS_DIR / "lci_identity.json").read_text())
VECTORS = DOC["vectors"]

GET_VECTORS = [v for v in VECTORS if v["op"] == "get"]
METHOD_VECTORS = [v for v in VECTORS if v["op"] in ("put", "delete")]

EXPECTED_COUNTS = {"get": 4, "method_not_allowed": 2}


@pytest.mark.parametrize("vector", GET_VECTORS, ids=lambda v: v["name"])
def test_get_reencodes_byte_exact(vector: dict[str, Any]) -> None:
    """Generator oracle: canonical re-encode of the pinned map is byte-identical."""
    assert cbor2.dumps(vector["input"]) == bytes.fromhex(vector["encoded_hex"])
    decoded = cbor2.loads(bytes.fromhex(vector["encoded_hex"]))
    assert decoded == vector["input"]


@pytest.mark.parametrize("vector", GET_VECTORS, ids=lambda v: v["name"])
async def test_get_resource_emits_pinned_bytes(vector: dict[str, Any]) -> None:
    resource = IdentityConfigResource(StaticNodeInfo(identity=dict(vector["input"])))
    response = await resource.render_get(Message())
    assert response.payload == bytes.fromhex(vector["encoded_hex"]), vector["name"]
    assert int(response.opt.content_format) == vector["content_format"] == 60


@pytest.mark.parametrize("vector", GET_VECTORS, ids=lambda v: v["name"])
async def test_get_normalizes_through_lci_client(vector: dict[str, Any]) -> None:
    """The committed wire bytes decode into typed client fields."""
    identity = normalize_identity(cbor2.loads(bytes.fromhex(vector["encoded_hex"])))
    expected = vector["input"]
    assert identity.eui64 == expected.get("eui64")
    assert identity.pubkey == expected.get("pubkey")
    assert identity.pubkey_fingerprint == expected.get("pubkey_fingerprint")
    assert identity.addrs == expected.get("addrs")


def test_full_identity_addresses_match_key_derivation() -> None:
    """Vector addresses must be genuinely derived from the pinned public key."""
    vec = next(v for v in VECTORS if v["name"] == "get_full_identity")
    pubkey = bytes.fromhex(vec["input"]["pubkey"])
    assert len(pubkey) == 32
    addrs = vec["input"]["addrs"]
    assert addrs["link_local"] == str(link_local_from_pubkey(pubkey))
    assert addrs["primary"] == str(native_address_from_pubkey(pubkey))
    assert addrs["primary"].startswith("2")  # inside the native 0200::/8 profile


async def _identity_stack(info: StaticNodeInfo) -> tuple[Any, Any]:
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=build_site(info))
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.parametrize("vector", METHOD_VECTORS, ids=lambda v: v["name"])
async def test_mutating_methods_are_method_not_allowed(vector: dict[str, Any]) -> None:
    info = StaticNodeInfo(identity={"eui64": "0x0011223344556677"})
    client, server = await _identity_stack(info)
    try:
        request = Message(
            code=PUT if vector["op"] == "put" else DELETE,
            uri=f"coap://server{vector['resource_path']}",
            payload=bytes.fromhex(vector["wire_hex"]),
        )
        if vector["op"] == "put":
            request.opt.content_format = ContentFormat.CBOR
        response = await client.request(request).response
        assert response.code.dotted == vector["expected"]["code"] == "4.05"

        current = await client.request(
            Message(code=GET, uri=f"coap://server{vector['resource_path']}")
        ).response
        assert cbor2.loads(current.payload) == info.identity  # untouched
    finally:
        await client.shutdown()
        await server.shutdown()


class TestAllVectorsAccountedFor:
    def test_vector_count_matches_expectation(self) -> None:
        counts = {
            "get": len(GET_VECTORS),
            "method_not_allowed": len(METHOD_VECTORS),
        }
        assert counts == EXPECTED_COUNTS
        assert sum(counts.values()) == len(VECTORS)
