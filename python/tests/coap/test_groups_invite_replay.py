# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Invitation replay, consumption, and decline semantics (spec 18.8.2)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
)
from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.group_membership import invitation_preimage, parse_invitation

OWNER = "0200::1111"
MEMBER = "0200::4444"
LATER_MEMBER = "0200::5555"
FIXED_CLOCK = 1716742800
EXPIRES = FIXED_CLOCK + 600
FORBIDDEN_CODE = 4 * 32 + 3


def _pairwise_post(
    payload: dict, *, path: tuple[str, ...] = (), context: str = OWNER
) -> Message:
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(payload))
    if path:
        request.opt.uri_path = path
    request.oscore_context_id = context
    return request


def _plain_post(document: dict) -> Message:
    return Message(code=aiocoap.POST, payload=cbor2.dumps(document))


def _signed_document(
    group_id: str, owner_identity: Identity, *, expires: int = EXPIRES
) -> dict:
    """Genuine Schnorr-signed member invitation from the owner."""
    document = {
        "group_id": group_id,
        "group_name": "Team Alpha",
        "mcast": "ff35:0040::1",
        "inviter": OWNER,
        "role": "member",
        "expires": expires,
        "signature": b"\x00" * 48,
    }
    parsed = parse_invitation(document)
    signature = sign(
        owner_identity.privkey, owner_identity.pubkey, invitation_preimage(parsed)
    )
    return {**document, "signature": signature}


def _invite_resource(
    collection: GroupsCollectionResource, invitee: str, pubkey: bytes
) -> GroupsInviteResource:
    return GroupsInviteResource(
        pubkeys={OWNER: pubkey},
        collection=collection,
        invitee=invitee,
    )


async def _created_group(collection: GroupsCollectionResource) -> str:
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    assert created.code == aiocoap.CREATED
    return cbor2.loads(created.payload)["id"]


async def _join_key(item: GroupsItemResource, group_id: str, node: str) -> Message:
    return await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": node}, path=(group_id, "key"), context=node
        )
    )


@pytest.mark.asyncio
async def test_invitation_replay_lifecycle_is_rejected_at_every_stage() -> None:
    """The same signed document cannot be re-accepted after use or removal."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x06" * 32)
    document = _signed_document(group_id, owner_identity)
    invites = _invite_resource(collection, MEMBER, owner_identity.pubkey)

    # 1. First acceptance unlocks exactly one key fetch.
    first = await invites.render_post(_plain_post(document))
    assert first.code == aiocoap.CHANGED
    grant = await _join_key(item, group_id, MEMBER)
    assert grant.code == aiocoap.CONTENT
    state = collection.groups[group_id]
    assert state["members"] == [OWNER, MEMBER]

    # 2. Replay while enrolled: the consumption marker refuses re-recording.
    replay = await invites.render_post(_plain_post(document))
    assert int(replay.code) == FORBIDDEN_CODE
    assert len(invites.accepted) == 1
    assert collection.groups[group_id]["members"] == [OWNER, MEMBER]

    # 3. Forced removal revokes membership and burns the document identity.
    rotated = collection.rekey(group_id, removed_member=MEMBER)
    assert rotated is not None
    state = collection.groups[group_id]
    assert MEMBER not in state["members"]
    assert collection.invitation_valid(group_id, MEMBER) is False

    # 4. Replay after removal is refused although the ledger entry was popped,
    #    and join_key cannot resurrect the removed enrollment either.
    resurrected = await invites.render_post(_plain_post(document))
    assert int(resurrected.code) == FORBIDDEN_CODE
    assert collection.invitation_valid(group_id, MEMBER) is False
    denied = await _join_key(item, group_id, MEMBER)
    assert int(denied.code) == FORBIDDEN_CODE
    assert collection.groups[group_id]["members"] == [OWNER]


@pytest.mark.asyncio
async def test_unconsumed_invitation_is_burned_by_forced_removal() -> None:
    """A revoked-but-never-joined invitation cannot enroll later."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x07" * 32)
    document = _signed_document(group_id, owner_identity)
    invites = _invite_resource(collection, LATER_MEMBER, owner_identity.pubkey)

    accepted = await invites.render_post(_plain_post(document))
    assert accepted.code == aiocoap.CHANGED

    # The owner revokes before the invitee ever spent the invitation.
    rotated = collection.rekey(group_id, removed_member=LATER_MEMBER)
    assert rotated is not None
    assert collection.invitation_valid(group_id, LATER_MEMBER) is False

    replayed = await invites.render_post(_plain_post(document))
    assert int(replayed.code) == FORBIDDEN_CODE
    join = await _join_key(item, group_id, LATER_MEMBER)
    assert int(join.code) == FORBIDDEN_CODE
    assert LATER_MEMBER not in collection.groups[group_id]["members"]


@pytest.mark.asyncio
async def test_clock_skew_returns_declined_not_changed() -> None:
    """86w8: an expiry already past on the local clock declines immediately."""
    ahead = {"t": FIXED_CLOCK + 3600}
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: ahead["t"])
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x08" * 32)
    # Signed for an expiry that has already passed on the server clock.
    document = _signed_document(group_id, owner_identity, expires=FIXED_CLOCK + 600)
    invites = _invite_resource(collection, MEMBER, owner_identity.pubkey)

    declined = await invites.render_post(_plain_post(document))
    assert int(declined.code) == FORBIDDEN_CODE
    assert invites.accepted == []
    stored = collection.groups[group_id].get("invitations") or {}
    assert MEMBER not in stored
    denied = await _join_key(item, group_id, MEMBER)
    assert int(denied.code) == FORBIDDEN_CODE

    # Contrast case with an aligned clock: the same shape of document succeeds.
    aligned = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    aligned_group = await _created_group(aligned)
    aligned_invites = _invite_resource(aligned, MEMBER, owner_identity.pubkey)
    fresh = _signed_document(aligned_group, owner_identity)
    accepted = await aligned_invites.render_post(_plain_post(fresh))
    assert accepted.code == aiocoap.CHANGED


@pytest.mark.asyncio
async def test_unknown_group_document_returns_declined() -> None:
    """A well-formed, signed document naming no known group is declined."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    owner_identity = Identity.from_seed(b"\x09" * 32)
    document = {
        "group_id": "does-not-exist",
        "group_name": "Ghost",
        "mcast": "ff35:0040::9",
        "inviter": OWNER,
        "role": "member",
        "expires": EXPIRES,
        "signature": b"\x00" * 48,
    }
    parsed = parse_invitation(document)
    signature = sign(
        owner_identity.privkey, owner_identity.pubkey, invitation_preimage(parsed)
    )
    invites = _invite_resource(collection, MEMBER, owner_identity.pubkey)
    response = await invites.render_post(
        _plain_post({**document, "signature": signature})
    )
    assert int(response.code) == FORBIDDEN_CODE
    assert invites.accepted == []
