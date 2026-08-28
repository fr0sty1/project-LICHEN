# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET/POST /groups (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from ipaddress import IPv6Address

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
    group_id_from_name,
    mcast_from_id,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

# RFC 7252 section 5.9.2.2 / 12.1: 4.01 Unauthorized = class 4, detail 1.
RFC7252_UNAUTHORIZED = 4 * 32 + 1
# spec/12-apps.md 18.8.2: group OSCORE master_secret is 32 bytes.
SPEC_MASTER_SECRET_LEN = 32
OWNER = "0200::1111"


def _create_request(*, encrypted: bool, context: str | None = OWNER) -> Message:
    request = Message(
        code=aiocoap.POST,
        payload=cbor2.dumps({"name": "Team Alpha", "encrypted": encrypted}),
    )
    if context is not None:
        request.oscore_context_id = context
    return request


def _assert_no_key_material(payload: bytes | None) -> None:
    """Independent oracle: plaintext CoAP must not carry group key bytes."""
    if not payload:
        return
    body = cbor2.loads(payload)
    if type(body) is dict:
        assert "master_secret" not in body
        assert "master_salt" not in body


@pytest.mark.asyncio
async def test_groups_create_and_list() -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    site = Site()
    site.add_resource(["groups"], resource)
    site.add_resource(["groups"], GroupsItemResource(resource))
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        empty = await client.request(Message(code=aiocoap.GET, uri="coap://server/groups")).response
        assert cbor2.loads(empty.payload) == {"groups": []}
        created = await resource.render_post(_create_request(encrypted=False))
        assert created.code == aiocoap.CREATED
        body = cbor2.loads(created.payload)
        expected_id = group_id_from_name("Team Alpha")
        assert body["id"] == expected_id
        # Independent RFC 3306 oracle: SHA-256 high 16 bits, owner 0200::1111 /64.
        gid = int.from_bytes(sha256(expected_id.encode("utf-8")).digest()[:2], "big")
        expected_mcast = IPv6Address(
            b"\xff\x35\x00\x40"
            + IPv6Address("0200::1111").packed[:8]
            + b"\x00\x00"
            + gid.to_bytes(2, "big")
        )
        assert IPv6Address(body["mcast"]) == expected_mcast
        _assert_no_key_material(created.payload)
        assert created.opt.location_path == ("groups", expected_id)
        listed = await client.request(
            Message(code=aiocoap.GET, uri="coap://server/groups")
        ).response
        rows = cbor2.loads(listed.payload)
        assert rows == {"groups": [{"id": expected_id, "name": "Team Alpha", "members": 1}]}
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_encrypted_create_unprotected_is_unauthorized() -> None:
    """spec 18.8.2: encrypted create is mesh-reachable and must not leak keys."""
    resource = GroupsCollectionResource(owner="0200::1111")
    site = Site()
    site.add_resource(["groups"], resource)
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        created = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups",
                payload=cbor2.dumps({"name": "Team Alpha", "encrypted": True}),
            )
        ).response
        assert int(created.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(created.payload)
        assert resource.groups == {}
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_encrypted_create_pairwise_oscore_returns_master_secret() -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    created = await resource.render_post(_create_request(encrypted=True))
    assert created.code == aiocoap.CREATED
    body = cbor2.loads(created.payload)
    assert type(body["master_secret"]) is bytes
    assert len(body["master_secret"]) == SPEC_MASTER_SECRET_LEN
    stored = resource.groups[body["id"]]
    assert stored["master_secret"] == body["master_secret"]
    assert stored["owner"] == OWNER
    assert stored["members"] == [OWNER]
    assert stored["admins"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("encrypted", (False, True))
async def test_create_without_pairwise_identity_is_unauthorized(encrypted: bool) -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    response = await resource.render_post(_create_request(encrypted=encrypted, context=None))
    assert int(response.code) == RFC7252_UNAUTHORIZED
    _assert_no_key_material(response.payload)
    assert resource.groups == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("encrypted", (False, True))
async def test_non_owner_pairwise_identity_is_forbidden(encrypted: bool) -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    response = await resource.render_post(
        _create_request(encrypted=encrypted, context="0200::9999")
    )
    assert response.code == aiocoap.FORBIDDEN
    _assert_no_key_material(response.payload)
    assert resource.groups == {}


@pytest.mark.asyncio
async def test_conflicting_pairwise_bindings_are_unauthorized() -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    request = _create_request(encrypted=True)
    request.remote = type("Remote", (), {"oscore_context_id": "0200::9999"})()
    response = await resource.render_post(request)
    assert int(response.code) == RFC7252_UNAUTHORIZED
    _assert_no_key_material(response.payload)
    assert resource.groups == {}


@pytest.mark.asyncio
async def test_spoofed_oscore_metadata_cannot_create() -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    flagged = _create_request(encrypted=True, context=None)
    flagged.oscore_protected = True
    option_only = _create_request(encrypted=True, context=None)
    option_only.opt.oscore = b"\x00"

    class _GroupContext:
        external_aad_is_group = True
        is_signing = True

        def durable_context_id(self) -> str:
            return OWNER

    group_context = _create_request(encrypted=True, context=None)
    group_context.oscore_context = _GroupContext()

    for request in (flagged, option_only, group_context):
        response = await resource.render_post(request)
        assert int(response.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(response.payload)
    assert resource.groups == {}


@pytest.mark.asyncio
async def test_create_entropy_failure_is_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = GroupsCollectionResource(owner=OWNER)
    calls = 0

    def failing_random(length: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("entropy unavailable")
        return bytes([length]) * length

    monkeypatch.setattr("lichen.coap.resources.groups_collection.os.urandom", failing_random)
    failed = await resource.render_post(_create_request(encrypted=True))
    assert failed.code == aiocoap.INTERNAL_SERVER_ERROR
    _assert_no_key_material(failed.payload)
    assert resource.groups == {}

    monkeypatch.setattr(
        "lichen.coap.resources.groups_collection.os.urandom",
        lambda length: bytes([length]) * length,
    )
    retried = await resource.render_post(_create_request(encrypted=True))
    assert retried.code == aiocoap.CREATED
    assert len(resource.groups) == 1


def test_concurrent_duplicate_creates_commit_once(monkeypatch: pytest.MonkeyPatch) -> None:
    resource = GroupsCollectionResource(owner=OWNER)

    def slow_random(length: int) -> bytes:
        time.sleep(0.01)
        return bytes([length]) * length

    def create() -> Message:
        return asyncio.run(resource.render_post(_create_request(encrypted=True)))

    monkeypatch.setattr("lichen.coap.resources.groups_collection.os.urandom", slow_random)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: create(), range(2)))

    assert sorted(int(response.code) for response in responses) == [
        int(aiocoap.CREATED),
        int(aiocoap.BAD_REQUEST),
    ]
    assert len(resource.groups) == 1


def test_mcast_from_id_sha256_high16_on_default_02xx_prefix() -> None:
    """Wrapper matches the RFC 3306 layout without using the IPv6 helper as oracle."""
    gid = int.from_bytes(sha256(b"team-alpha").digest()[:2], "big")
    expected = IPv6Address(
        b"\xff\x35\x00\x40" + b"\x02\x00" + b"\x00" * 6 + b"\x00\x00" + gid.to_bytes(2, "big")
    )
    assert IPv6Address(mcast_from_id("team-alpha")) == expected
    mesh = IPv6Address("0200:1234:5678:9abc::")
    expected_mesh = IPv6Address(
        b"\xff\x35\x00\x40" + mesh.packed[:8] + b"\x00\x00" + gid.to_bytes(2, "big")
    )
    assert IPv6Address(mcast_from_id("team-alpha", prefix=str(mesh))) == expected_mesh
