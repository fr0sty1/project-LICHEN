# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Role matrix for /groups/{id} mutations (spec/12-apps.md 18.8.2 roles table)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
)

OWNER = "0200::1111"
ADMIN = "0200::2222"
MEMBER = "0200::3333"
OUTSIDER = "0200::9999"
FIXED_CLOCK = 1716742800
UNAUTHORIZED_CODE = 4 * 32 + 1
FORBIDDEN_CODE = 4 * 32 + 3


def _request(code: int, path: tuple[str, ...], payload: dict | None, context: str | None):
    request = aiocoap.Message(code=code, payload=cbor2.dumps(payload) if payload else b"")
    request.opt.uri_path = path
    if context is not None:
        request.oscore_context_id = context
    return request


def _promote_admin(collection: GroupsCollectionResource, group_id: str) -> None:
    state = collection.groups[group_id]
    state["admins"].append(ADMIN)
    state["members"].append(ADMIN)


async def _provision(role: str | None) -> tuple[GroupsCollectionResource, GroupsItemResource, str]:
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    created = await collection.render_post(
        _request(aiocoap.POST, (), {"name": "Team Alpha", "encrypted": True}, OWNER)
    )
    assert created.code == aiocoap.CREATED
    group_id = cbor2.loads(created.payload)["id"]
    if role == ADMIN:
        # Admin Delegation promotion (spec 18.8.2): admins are always members.
        _promote_admin(collection, group_id)
    elif role == MEMBER:
        collection.groups[group_id]["members"].append(MEMBER)
    return collection, item, group_id


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [None, MEMBER, ADMIN, OUTSIDER, OWNER])
async def test_put_name_change_rejected_for_all_roles(role: str | None) -> None:
    """Name changes rejected: 4.01 unauth, 4.03 non-owner, 4.00 owner (18.8.2).

    Group id is derived from name hash; changing the name would leave a stale
    id that no longer matches. Names are immutable after creation (option a).
    """
    collection, item, group_id = await _provision(role if role in {ADMIN, MEMBER} else None)
    response = await item.render_put(
        _request(aiocoap.PUT, (group_id,), {"name": "Team Alpha Renamed"}, role)
    )
    # None=UNAUTHORIZED, non-owner=FORBIDDEN, owner=BAD_REQUEST (name immutable)
    expected = (
        UNAUTHORIZED_CODE
        if role is None
        else (aiocoap.BAD_REQUEST if role == OWNER else FORBIDDEN_CODE)
    )
    assert int(response.code) == int(expected), f"role={role}"
    document = cbor2.loads(
        (await item.render_get(_request(aiocoap.GET, (group_id,), None, OWNER))).payload
    )
    assert document["name"] == "Team Alpha"


@pytest.mark.asyncio
async def test_owner_idempotent_put_same_name_succeeds() -> None:
    """Owner PUT with the same name is idempotent and succeeds."""
    collection, item, group_id = await _provision(None)
    response = await item.render_put(
        _request(aiocoap.PUT, (group_id,), {"name": "Team Alpha"}, OWNER)
    )
    assert response.code == aiocoap.CHANGED
    document = cbor2.loads(
        (await item.render_get(_request(aiocoap.GET, (group_id,), None, OWNER))).payload
    )
    assert document["name"] == "Team Alpha"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [None, MEMBER, ADMIN, OUTSIDER, OWNER])
async def test_delete_follows_owner_only_role_table(role: str | None) -> None:
    """Delete is an owner capability on the authoritative record."""
    collection, item, group_id = await _provision(role if role in {ADMIN, MEMBER} else None)
    response = await item.render_delete(_request(aiocoap.DELETE, (group_id,), None, role))
    if role is None:
        assert int(response.code) == UNAUTHORIZED_CODE
    elif role == OWNER:
        assert response.code == aiocoap.DELETED
    else:
        assert int(response.code) == FORBIDDEN_CODE, f"role={role}"
    assert (group_id in collection.groups) == (role != OWNER)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "peer, invited, claimed, expected_code",
    [
        (None, False, OUTSIDER, UNAUTHORIZED_CODE),
        (OUTSIDER, False, OUTSIDER, FORBIDDEN_CODE),
        (OUTSIDER, True, OUTSIDER, aiocoap.CONTENT),
        (OUTSIDER, True, ADMIN, FORBIDDEN_CODE),
        (OWNER, False, OWNER, FORBIDDEN_CODE),
        (MEMBER, True, MEMBER, aiocoap.CONTENT),
        (ADMIN, True, ADMIN, aiocoap.CONTENT),
    ],
)
async def test_join_key_authorization_is_invitation_and_binding(
    peer: str | None, invited: bool, claimed: str, expected_code: int
) -> None:
    """Key fetch needs pairwise OSCORE, a live invitation, and self-binding."""
    collection, item, group_id = await _provision(None)
    if invited:
        assert collection.record_invitation(group_id, claimed) is True
    response = await item.render_post(
        _request(
            aiocoap.POST,
            (group_id, "key"),
            {"request": "join_key", "node": claimed},
            peer,
        )
    )
    assert int(response.code) == int(expected_code), f"peer={peer} claim={claimed}"
    body_bytes = response.payload or b""
    current_secret = bytes(collection.groups[group_id]["master_secret"])
    current_salt = bytes(collection.groups[group_id]["master_salt"])
    if expected_code == aiocoap.CONTENT:
        key = cbor2.loads(body_bytes)
        assert key["master_secret"] == current_secret
        assert key["master_salt"] == current_salt
        assert claimed in collection.groups[group_id]["members"]
    else:
        assert current_secret not in body_bytes
        assert current_salt not in body_bytes
