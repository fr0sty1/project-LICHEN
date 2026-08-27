# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET/PUT/DELETE /groups/{id} and POST /groups/{id}/key (spec 18.8)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import FORBIDDEN, Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
    group_id_from_name,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

OWNER = "0200::1111"
ADMIN = "0200::2222"
MEMBER = "0200::3333"
OUTSIDER = "0200::9999"
# RFC 7252 section 5.9.2.2 / 12.1: 4.01 Unauthorized = class 4, detail 1.
RFC7252_UNAUTHORIZED = 4 * 32 + 1
FORBIDDEN_CODE = 4 * 32 + 3
# spec/12-apps.md 18.8.2 key distribution fields.
SPEC_MASTER_SECRET_LEN = 32
SPEC_MASTER_SALT_LEN = 8
SPEC_GROUP_ALG = "AES-CCM-16-64-128"


class _GroupOscoreContext:
    external_aad_is_group = True
    is_signing = True

    def __init__(self, group_id: str, epoch: int = 1) -> None:
        self.id_context = bytes.fromhex(group_id) + epoch.to_bytes(4, "big")

    def durable_context_id(self) -> bytes:
        return self.id_context


def _assert_no_key_material(
    payload: bytes | None, *, secret: bytes = b"", salt: bytes = b""
) -> None:
    if secret:
        assert secret not in (payload or b"")
    if salt:
        assert salt not in (payload or b"")
    if not payload:
        return
    body = cbor2.loads(payload)
    if type(body) is dict:
        assert "master_secret" not in body
        assert "master_salt" not in body


def _pairwise_post(payload: dict, *, path: tuple[str, ...] = (), context: str = OWNER) -> Message:
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(payload))
    if path:
        request.opt.uri_path = path
    request.oscore_context_id = context
    return request


def _pairwise_request(
    code: int, path: tuple[str, ...], payload: dict | None = None, context: str | None = OWNER
) -> Message:
    request = Message(code=code, payload=cbor2.dumps(payload) if payload is not None else b"")
    request.opt.uri_path = path
    if context is not None:
        request.oscore_context_id = context
    return request


async def _stack(
    owner: str = "0200::1111",
) -> tuple[GroupsCollectionResource, aiocoap.Context, aiocoap.Context]:
    resource = GroupsCollectionResource(owner=owner, clock=lambda: 1716742800)
    site = Site()
    site.add_resource(["groups"], resource)
    site.add_resource(["groups"], GroupsItemResource(resource))
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    return resource, client, server


async def _create(
    collection: GroupsCollectionResource,
    *,
    encrypted: bool = True,
    name: str = "Team Alpha",
) -> str:
    request = Message(
        code=aiocoap.POST,
        payload=cbor2.dumps({"name": name, "encrypted": encrypted}),
    )
    request.oscore_context_id = OWNER
    created = await collection.render_post(request)
    assert created.code == aiocoap.CREATED
    group_id = cbor2.loads(created.payload)["id"]
    assert isinstance(group_id, str)
    return group_id


@pytest.mark.asyncio
async def test_group_item_get_put_delete() -> None:
    resource, client, server = await _stack()
    item = GroupsItemResource(resource)
    try:
        group_id = await _create(resource)
        assert group_id == group_id_from_name("Team Alpha")

        # spec 18.8.2 privacy: unprotected GET MUST NOT carry roster arrays.
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        body = cbor2.loads(got.payload)
        assert body["id"] == group_id
        assert body["name"] == "Team Alpha"
        assert body["owner"] == "0200::1111"
        assert body["created"] == 1716742800
        assert body["key_epoch"] == 1
        assert "master_secret" not in body
        assert "members" not in body
        assert "admins" not in body

        # Authorized viewer (owner pairwise) sees the full document.
        full = await item.render_get(_pairwise_request(aiocoap.GET, (group_id,), context=OWNER))
        full_body = cbor2.loads(full.payload)
        assert full_body["members"] == ["0200::1111"]
        assert full_body["admins"] == []

        # spec 18.8.2 membership sync: members endpoint is OSCORE-only.
        bare_members = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}/members")
        ).response
        assert int(bare_members.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(bare_members.payload)

        outsider_members = await item.render_get(
            _pairwise_request(aiocoap.GET, (group_id, "members"), context=OUTSIDER)
        )
        assert int(outsider_members.code) == FORBIDDEN_CODE
        assert outsider_members.code == FORBIDDEN

        member_body = cbor2.loads(
            (
                await item.render_get(
                    _pairwise_request(aiocoap.GET, (group_id, "members"), context=OWNER)
                )
            ).payload
        )
        assert member_body["owner"] == "0200::1111"
        assert member_body["admins"] == []
        assert member_body["members"] == ["0200::1111"]

        group_ctx_request = _pairwise_request(aiocoap.GET, (group_id, "members"), context=None)
        group_ctx_request.oscore_context = _GroupOscoreContext(group_id)
        ctx_members = await item.render_get(group_ctx_request)
        assert ctx_members.code == aiocoap.CONTENT
        assert cbor2.loads(ctx_members.payload)["members"] == ["0200::1111"]

        # spec 18.8.2: group id is derived from name hash; renaming would leave
        # a stale id. Names are immutable after creation (option a).
        put_payload = {"name": "Team Alpha Renamed"}
        unauthed_put = await client.request(
            Message(
                code=aiocoap.PUT,
                uri=f"coap://server/groups/{group_id}",
                payload=cbor2.dumps(put_payload),
            )
        ).response
        assert int(unauthed_put.code) == RFC7252_UNAUTHORIZED

        member_put = await item.render_put(
            _pairwise_request(aiocoap.PUT, (group_id,), put_payload, context=MEMBER)
        )
        assert int(member_put.code) == FORBIDDEN_CODE
        assert member_put.code == FORBIDDEN

        # Owner PUT with a different name is rejected (names are immutable).
        owner_put = await item.render_put(
            _pairwise_request(aiocoap.PUT, (group_id,), put_payload, context=OWNER)
        )
        assert owner_put.code == aiocoap.BAD_REQUEST
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert cbor2.loads(got.payload)["name"] == "Team Alpha"

        # Idempotent PUT with the same name succeeds.
        same_name_put = await item.render_put(
            _pairwise_request(aiocoap.PUT, (group_id,), {"name": "Team Alpha"}, context=OWNER)
        )
        assert same_name_put.code == aiocoap.CHANGED

        missing = await client.request(
            Message(code=aiocoap.GET, uri="coap://server/groups/no-such")
        ).response
        assert missing.code == aiocoap.NOT_FOUND

        unauthed_delete = await client.request(
            Message(code=aiocoap.DELETE, uri=f"coap://server/groups/{group_id}")
        ).response
        assert int(unauthed_delete.code) == RFC7252_UNAUTHORIZED

        member_delete = await item.render_delete(
            _pairwise_request(aiocoap.DELETE, (group_id,), context=MEMBER)
        )
        assert int(member_delete.code) == FORBIDDEN_CODE
        assert member_delete.code == FORBIDDEN

        deleted = await item.render_delete(
            _pairwise_request(aiocoap.DELETE, (group_id,), context=OWNER)
        )
        assert deleted.code == aiocoap.DELETED
        gone = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert gone.code == aiocoap.NOT_FOUND
        assert group_id not in resource.groups
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_group_context_is_bound_to_group_and_current_epoch() -> None:
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_a = await _create(resource, name="Group A")
    group_b = await _create(resource, name="Group B")

    def group_get(group_id: str, context: object, *, members: bool = True) -> Message:
        request = Message(code=aiocoap.GET)
        request.opt.uri_path = (group_id, "members") if members else (group_id,)
        request.oscore_context = context
        return request

    context_a = _GroupOscoreContext(group_a)
    own = await item.render_get(group_get(group_a, context_a))
    assert own.code == aiocoap.CONTENT

    swapped_members = await item.render_get(group_get(group_b, context_a))
    assert swapped_members.code == FORBIDDEN
    _assert_no_key_material(swapped_members.payload)
    assert not swapped_members.payload

    swapped_document = await item.render_get(group_get(group_b, context_a, members=False))
    assert swapped_document.code == FORBIDDEN
    assert not swapped_document.payload

    class _UnboundGroupContext:
        external_aad_is_group = True
        is_signing = True

    unbound = await item.render_get(group_get(group_a, _UnboundGroupContext()))
    assert unbound.code == FORBIDDEN

    assert resource.rekey(group_a) is not None
    stale = await item.render_get(group_get(group_a, context_a))
    assert stale.code == FORBIDDEN
    current = await item.render_get(group_get(group_a, _GroupOscoreContext(group_a, epoch=2)))
    assert current.code == aiocoap.CONTENT


@pytest.mark.asyncio
async def test_join_key_post_and_key_metadata() -> None:
    resource, client, server = await _stack()
    item = GroupsItemResource(resource)
    try:
        group_id = await _create(resource, encrypted=True)
        meta = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}/key")
        ).response
        meta_body = cbor2.loads(meta.payload)
        assert meta_body["algorithm"] == SPEC_GROUP_ALG
        assert "master_secret" not in meta_body

        # spec 18.8.2: key distribution requires a prior invitation and binds
        # body['node'] to the authenticated pairwise peer.
        assert resource.record_invitation(group_id, MEMBER) is True
        joined = await item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": MEMBER},
                path=(group_id, "key"),
                context=MEMBER,
            )
        )
        assert joined.code == aiocoap.CONTENT
        key = cbor2.loads(joined.payload)
        assert key["algorithm"] == SPEC_GROUP_ALG
        assert key["key_epoch"] == 1
        assert type(key["master_secret"]) is bytes
        assert type(key["master_salt"]) is bytes
        assert len(key["master_secret"]) == SPEC_MASTER_SECRET_LEN
        assert len(key["master_salt"]) == SPEC_MASTER_SALT_LEN
        stored = resource.groups[group_id]
        assert key["master_secret"] == stored["master_secret"]
        assert key["master_salt"] == stored["master_salt"]
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert "members" not in cbor2.loads(got.payload)

        # Claiming another node's address over your own context is rejected.
        spoofed = await item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": OUTSIDER},
                path=(group_id, "key"),
                context=MEMBER,
            )
        )
        assert spoofed.code == FORBIDDEN
        _assert_no_key_material(spoofed.payload)
        assert OUTSIDER not in stored["members"]

        bad = await item.render_post(
            _pairwise_post(
                {"request": "nope", "node": MEMBER},
                path=(group_id, "key"),
                context=MEMBER,
            )
        )
        assert bad.code == aiocoap.BAD_REQUEST
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_uninvited_and_expired_join_key_is_forbidden() -> None:
    """spec 18.8.2: only an unexpired prior invitation opens enrollment."""
    now = {"t": 1_716_742_800.0}
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: now["t"])
    item = GroupsItemResource(resource)
    request = Message(
        code=aiocoap.POST,
        payload=cbor2.dumps({"name": "Team Alpha", "encrypted": True}),
    )
    request.oscore_context_id = OWNER
    created = await resource.render_post(request)
    assert created.code == aiocoap.CREATED
    group_id = cbor2.loads(created.payload)["id"]
    stored = resource.groups[group_id]
    secret = bytes(stored["master_secret"])
    salt = bytes(stored["master_salt"])

    def _join(context: str, node: str) -> Message:
        return item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": node},
                path=(group_id, "key"),
                context=context,
            )
        )

    uninvited = await _join(OUTSIDER, OUTSIDER)
    assert uninvited.code == FORBIDDEN
    _assert_no_key_material(uninvited.payload, secret=secret, salt=salt)
    assert OUTSIDER not in stored["members"]

    # A stale timestamp is refused outright, before the ledger is touched.
    assert resource.record_invitation(group_id, MEMBER, expires=int(now["t"]) - 1) is False

    # A real invitation grants access until its own expiry only.
    assert resource.record_invitation(group_id, MEMBER, expires=int(now["t"]) + 600) is True
    granted = await _join(MEMBER, MEMBER)
    assert granted.code == aiocoap.CONTENT
    assert MEMBER in stored["members"]

    now["t"] += 601
    expired = await _join(MEMBER, MEMBER)
    assert expired.code == FORBIDDEN
    _assert_no_key_material(expired.payload, secret=secret, salt=salt)
    assert resource.invitation_valid(group_id, MEMBER) is False


@pytest.mark.asyncio
async def test_unprotected_join_key_is_unauthorized() -> None:
    """spec 18.8.2: join_key over plaintext CoAP is 4.01, keys stay off the wire."""
    resource, client, server = await _stack()
    try:
        group_id = await _create(resource, encrypted=True)
        stored = resource.groups[group_id]
        secret = bytes(stored["master_secret"])
        salt = bytes(stored["master_salt"])
        joined = await client.request(
            Message(
                code=aiocoap.POST,
                uri=f"coap://server/groups/{group_id}/key",
                payload=cbor2.dumps({"request": "join_key", "node": MEMBER}),
            )
        ).response
        assert int(joined.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(joined.payload, secret=secret, salt=salt)
        assert MEMBER not in stored["members"]
        spoofed = Message(
            code=aiocoap.POST,
            uri=f"coap://server/groups/{group_id}/key",
            payload=cbor2.dumps({"request": "join_key", "node": OUTSIDER}),
        )
        spoofed.opt.oscore = b"\x00"
        spoofed_resp = await client.request(spoofed).response
        assert int(spoofed_resp.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(spoofed_resp.payload, secret=secret, salt=salt)
        assert OUTSIDER not in stored["members"]
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_join_key_rejects_spoofed_and_group_oscore() -> None:
    resource = GroupsCollectionResource(owner="0200::1111", clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)
    stored = resource.groups[group_id]
    secret = bytes(stored["master_secret"])
    salt = bytes(stored["master_salt"])
    payload = cbor2.dumps({"request": "join_key", "node": MEMBER})

    async def _reject(request: Message) -> None:
        request.opt.uri_path = (group_id, "key")
        response = await item.render_post(request)
        assert int(response.code) == RFC7252_UNAUTHORIZED
        _assert_no_key_material(response.payload, secret=secret, salt=salt)
        assert MEMBER not in stored["members"]

    plain = Message(code=aiocoap.POST, payload=payload)
    await _reject(plain)

    flagged = Message(code=aiocoap.POST, payload=payload)
    flagged.oscore_protected = True
    await _reject(flagged)

    option = Message(code=aiocoap.POST, payload=payload)
    option.opt.oscore = b"\x00"
    await _reject(option)

    empty_id = Message(code=aiocoap.POST, payload=payload)
    empty_id.oscore_context_id = ""
    await _reject(empty_id)

    class _GroupCtx:
        external_aad_is_group = True
        is_signing = True

        def durable_context_id(self) -> str:
            return "group-ctx"

    group_ctx = Message(code=aiocoap.POST, payload=payload)
    group_ctx.oscore_context = _GroupCtx()
    await _reject(group_ctx)

    named_group = Message(code=aiocoap.POST, payload=payload)
    named_group.oscore_context = "group"
    await _reject(named_group)

    mixed = Message(code=aiocoap.POST, payload=payload)
    mixed.oscore_context = _GroupCtx()
    mixed.oscore_context_id = "edhoc-pairwise"
    await _reject(mixed)


@pytest.mark.asyncio
async def test_join_key_accepts_bound_context_object() -> None:
    """spec 18.8.2: context object proves authentication; IPv6 identity for roster."""

    class _PairwiseCtx:
        external_aad_is_group = False
        is_signing = False

        def durable_context_id(self) -> bytes:
            # Context ID bytes are for context correlation, not roster identity.
            return b"edhoc-context-id"

    # The peer identity is the IPv6 address, not hex(durable_context_id()).
    peer_identity = MEMBER
    resource = GroupsCollectionResource(owner="0200::1111", clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)
    stored = resource.groups[group_id]
    assert resource.record_invitation(group_id, peer_identity) is True
    request = Message(
        code=aiocoap.POST,
        payload=cbor2.dumps({"request": "join_key", "node": peer_identity}),
    )
    request.opt.uri_path = (group_id, "key")
    # Context object proves authentication happened; oscore_context_id carries identity.
    request.oscore_context = _PairwiseCtx()
    request.oscore_context_id = peer_identity
    joined = await item.render_post(request)
    assert joined.code == aiocoap.CONTENT
    key = cbor2.loads(joined.payload)
    assert len(key["master_secret"]) == SPEC_MASTER_SECRET_LEN
    assert len(key["master_salt"]) == SPEC_MASTER_SALT_LEN
    assert key["master_secret"] == stored["master_secret"]
    assert key["algorithm"] == SPEC_GROUP_ALG
    assert peer_identity in stored["members"]


@pytest.mark.asyncio
async def test_admin_cannot_put_or_delete_authoritative_group() -> None:
    """spec 18.8.2: admin may invite/remove members, not rename or delete."""
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)
    stored = resource.groups[group_id]
    stored["admins"] = [ADMIN]
    stored["members"] = [OWNER, ADMIN]
    assert resource.requester_role(group_id, ADMIN) == "admin"
    assert resource.requester_role(group_id, OWNER) == "owner"

    put = await item.render_put(
        _pairwise_request(aiocoap.PUT, (group_id,), {"name": "Hijacked"}, context=ADMIN)
    )
    assert int(put.code) == FORBIDDEN_CODE
    assert put.code == FORBIDDEN
    assert stored["name"] == "Team Alpha"

    delete = await item.render_delete(_pairwise_request(aiocoap.DELETE, (group_id,), context=ADMIN))
    assert int(delete.code) == FORBIDDEN_CODE
    assert delete.code == FORBIDDEN
    assert group_id in resource.groups


@pytest.mark.asyncio
async def test_join_key_requires_matching_peer_even_when_target_is_invited() -> None:
    """body.node is bound to the pairwise peer, not a claimed invitee address."""
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)
    stored = resource.groups[group_id]
    secret = bytes(stored["master_secret"])
    salt = bytes(stored["master_salt"])
    assert resource.record_invitation(group_id, OUTSIDER) is True
    assert resource.record_invitation(group_id, MEMBER) is True

    spoofed = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": OUTSIDER},
            path=(group_id, "key"),
            context=MEMBER,
        )
    )
    assert int(spoofed.code) == FORBIDDEN_CODE
    _assert_no_key_material(spoofed.payload, secret=secret, salt=salt)
    assert OUTSIDER not in stored["members"]
    assert MEMBER not in stored["members"]


@pytest.mark.asyncio
async def test_key_metadata_reports_advertised_key_expiry() -> None:
    """GET /groups/{id}/key advertises the 24h key lifetime (spec 18.8.2).

    ``expires`` is the only client-facing expiry contract of the live epoch:
    creation pins it to stamp+86400 and every rekey re-pins it to its own
    stamp+86400. Values below are hand-derived from those construction
    stamps, not echoed from state.
    """
    t0 = 1_716_742_800
    now = {"t": float(t0)}
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: now["t"])
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)

    meta = await item.render_get(_pairwise_request(aiocoap.GET, (group_id, "key"), context=None))
    assert meta.code == aiocoap.CONTENT
    body = cbor2.loads(meta.payload)
    # Full-document equality against the hand-built response shape.
    assert body == {
        "algorithm": SPEC_GROUP_ALG,
        "key_id": f"key-{group_id}-001",
        "expires": t0 + 86400,
    }
    # The metadata endpoint carries no key material on any transport.
    _assert_no_key_material(meta.payload)

    now["t"] = float(t0 + 100)
    assert resource.rekey(group_id) == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    rotated_meta = await item.render_get(
        _pairwise_request(aiocoap.GET, (group_id, "key"), context=None)
    )
    assert rotated_meta.code == aiocoap.CONTENT
    rotated_body = cbor2.loads(rotated_meta.payload)
    assert rotated_body == {
        "algorithm": SPEC_GROUP_ALG,
        "key_id": f"key-{group_id}-002",
        "expires": t0 + 100 + 86400,
    }
    _assert_no_key_material(rotated_meta.payload)


@pytest.mark.asyncio
async def test_join_key_admin_invitation_promotes_admin() -> None:
    """spec 18.8.2: an admin invitation installs the invitee as admin and member."""
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    group_id = await _create(resource, encrypted=True)
    assert resource.record_invitation(group_id, ADMIN, role="admin") is True
    assert resource.record_invitation(group_id, ADMIN, role="owner") is False

    joined = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": ADMIN},
            path=(group_id, "key"),
            context=ADMIN,
        )
    )
    assert joined.code == aiocoap.CONTENT
    stored = resource.groups[group_id]
    assert ADMIN in stored["members"]
    assert ADMIN in stored["admins"]
    assert resource.requester_role(group_id, ADMIN) == "admin"

    # Admin cannot PUT even with the same name (forbidden before name check).
    put = await item.render_put(
        _pairwise_request(aiocoap.PUT, (group_id,), {"name": "Team Alpha"}, context=ADMIN)
    )
    assert int(put.code) == FORBIDDEN_CODE
    assert stored["name"] == "Team Alpha"
