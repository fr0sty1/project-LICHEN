# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/remove (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import aiocoap
import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.groups_collection import GroupsCollectionResource
from lichen.coap.resources.groups_remove import GroupsRemoveResource
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.group_membership import GroupRoster, parse_removal, removal_preimage

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "groups_membership.json"

OWNER = "0200::1111"
MEMBER = "0200::3333"


def _document(*, group_id: str = "team-alpha", removed_by: str = OWNER) -> dict[str, Any]:
    return {
        "group_id": group_id,
        "removed_by": removed_by,
        "reason": "no longer on team",
    }


def _signed(identity: Identity, document: dict[str, Any]) -> dict[str, Any]:
    draft = parse_removal({**document, "signature": b"\x00" * 48})
    signature = sign(identity.privkey, identity.pubkey, removal_preimage(draft))
    return {**document, "signature": signature}


def _request(document: dict[str, Any]) -> Message:
    return Message(code=aiocoap.POST, payload=cbor2.dumps(document))


def _resource(
    identity: Identity | None,
    *,
    node_id: str = MEMBER,
    collection: GroupsCollectionResource | None = None,
) -> GroupsRemoveResource:
    return GroupsRemoveResource(
        roster=GroupRoster(owner=OWNER, members=frozenset({MEMBER})),
        pubkeys={} if identity is None else {OWNER: identity.pubkey},
        node_id=node_id,
        collection=collection,
    )


@pytest.mark.asyncio
async def test_vector_with_unpinned_remover_is_refused_without_mutation() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["kind"] == "removal")
    payload = dict(case["payload"])
    payload["signature"] = bytes.fromhex(payload.pop("signature_hex"))
    collection = Mock(spec=GroupsCollectionResource)
    resource = GroupsRemoveResource(
        roster=GroupRoster(
            owner=payload["removed_by"],
            members=frozenset({MEMBER}),
        ),
        node_id=MEMBER,
        collection=collection,
    )

    response = await resource.render_post(_request(payload))

    assert response.code == aiocoap.FORBIDDEN
    assert resource.accepted == []
    collection.rekey.assert_not_called()


@pytest.mark.asyncio
async def test_pinned_owner_with_valid_signature_removes_once() -> None:
    owner = Identity.from_seed(b"\x31" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(owner, collection=collection)
    document = _signed(owner, _document())

    response = await resource.render_post(_request(document))

    assert response.code == aiocoap.CHANGED
    assert len(resource.accepted) == 1
    assert resource.accepted[0].group_id == "team-alpha"
    collection.rekey.assert_called_once_with("team-alpha", removed_member=MEMBER)


@pytest.mark.asyncio
async def test_unknown_key_rejection_does_not_burn_later_authenticated_removal() -> None:
    owner = Identity.from_seed(b"\x32" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(None, collection=collection)
    document = _signed(owner, _document())

    denied = await resource.render_post(_request(document))
    assert denied.code == aiocoap.FORBIDDEN
    assert resource.accepted == []
    collection.rekey.assert_not_called()

    resource.pubkeys[OWNER] = owner.pubkey
    accepted = await resource.render_post(_request(document))
    assert accepted.code == aiocoap.CHANGED
    collection.rekey.assert_called_once_with("team-alpha", removed_member=MEMBER)


@pytest.mark.asyncio
async def test_mismatched_signature_fails_before_mutation_and_does_not_burn() -> None:
    owner = Identity.from_seed(b"\x33" * 32)
    impostor = Identity.from_seed(b"\x34" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(owner, collection=collection)

    denied = await resource.render_post(_request(_signed(impostor, _document())))
    assert denied.code == aiocoap.FORBIDDEN
    assert resource.accepted == []
    collection.rekey.assert_not_called()

    accepted = await resource.render_post(_request(_signed(owner, _document())))
    assert accepted.code == aiocoap.CHANGED
    collection.rekey.assert_called_once_with("team-alpha", removed_member=MEMBER)


@pytest.mark.asyncio
async def test_owner_cannot_be_removed_even_with_valid_owner_signature() -> None:
    owner = Identity.from_seed(b"\x35" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(owner, node_id=OWNER, collection=collection)

    response = await resource.render_post(_request(_signed(owner, _document())))

    assert response.code == aiocoap.FORBIDDEN
    assert resource.accepted == []
    collection.rekey.assert_not_called()


@pytest.mark.asyncio
async def test_authenticated_removal_document_is_one_use() -> None:
    owner = Identity.from_seed(b"\x36" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(owner, collection=collection)
    request = _request(_signed(owner, _document()))

    first = await resource.render_post(request)
    replay = await resource.render_post(request)

    assert first.code == aiocoap.CHANGED
    assert replay.code == aiocoap.FORBIDDEN
    assert len(resource.accepted) == 1
    collection.rekey.assert_called_once_with("team-alpha", removed_member=MEMBER)


@pytest.mark.asyncio
async def test_concurrent_duplicate_removal_rotates_only_once() -> None:
    owner = Identity.from_seed(b"\x37" * 32)
    collection = Mock(spec=GroupsCollectionResource)
    resource = _resource(owner, collection=collection)
    document = _signed(owner, _document())

    responses = await asyncio.gather(
        resource.render_post(_request(document)),
        resource.render_post(_request(document)),
    )

    codes = [response.code for response in responses]
    assert codes.count(aiocoap.CHANGED) == 1
    assert codes.count(aiocoap.FORBIDDEN) == 1
    assert len(resource.accepted) == 1
    collection.rekey.assert_called_once_with("team-alpha", removed_member=MEMBER)
