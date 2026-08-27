# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/invite (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
)
from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.group_membership import (
    GroupRoster,
    invitation_preimage,
    parse_invitation,
)

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "groups_membership.json"

OWNER = "0200::1111"
ADMIN = "0200::2222"
MEMBER = "0200::3333"
OTHER_INVITEE = "0200::4444"
FIXED_CLOCK = 1716742800
EXPIRES = FIXED_CLOCK + 600


def _pairwise_post(
    payload: dict, *, path: tuple[str, ...] = (), context: str = OWNER
) -> Message:
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(payload))
    if path:
        request.opt.uri_path = path
    request.oscore_context_id = context
    return request


def _sign(inviter_identity: Identity, document: dict) -> dict:
    """Return *document* carrying a genuine 48-byte Schnorr signature.

    Oracles are split asymmetrically on purpose: acceptance checks that a
    validly signed document is honored, rejection checks that foreign-key or
    mutated documents are refused without touching any state.
    """
    draft = parse_invitation({**document, "signature": b"\x00" * 48})
    signature = sign(
        inviter_identity.privkey, inviter_identity.pubkey, invitation_preimage(draft)
    )
    return {**document, "signature": signature}


def _document(group_id: str, inviter: str, role: str, *, expires: int = EXPIRES) -> dict:
    return {
        "group_id": group_id,
        "group_name": "Team Alpha",
        "mcast": "ff35:0040::1",
        "inviter": inviter,
        "role": role,
        "expires": expires,
    }


async def _created_group(collection: GroupsCollectionResource) -> str:
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    assert created.code == aiocoap.CREATED
    return cbor2.loads(created.payload)["id"]


@pytest.mark.asyncio
async def test_post_groups_invite_accepts_vector() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["name"] == "invite_member")
    payload = dict(case["payload"])
    payload["signature"] = bytes.fromhex(payload.pop("signature_hex"))
    # Local provisioning path: the local node authored the invitation itself
    # (node_id == inviter) and the client is an LCI loopback peer, so the
    # trusted-origin carve-out applies. The same document delivered from a
    # wire peer MUST be refused (fail closed, see security tests below).
    resource = GroupsInviteResource(node_id=payload["inviter"])
    site = Site()
    site.add_resource(["groups", "invite"], resource)
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    local = await create_lichen_context(net.channel("[::1]"), "[::1]")
    wire_client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await local.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps(payload),
            )
        ).response
        assert resp.code == aiocoap.CHANGED
        assert len(resource.accepted) == 1
        assert resource.accepted[0].group_id == "team-alpha"
        assert resource.accepted[0].role == "member"

        forged = await wire_client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps(payload),
            )
        ).response
        assert int(forged.code) == 4 * 32 + 3
        assert len(resource.accepted) == 1

        bad = await local.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps({"group_id": "x", "role": "owner"}),
            )
        ).response
        assert bad.code == aiocoap.BAD_REQUEST
    finally:
        await local.shutdown()
        await wire_client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_remote_invitation_without_known_pubkey_is_refused() -> None:
    """SECURITY: an unverifiable remote inviter cannot mint memberships."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = GroupsInviteResource(
        roster=GroupRoster(owner=OWNER),
        collection=collection,
        invitee=MEMBER,
    )
    response = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(
                # Well-formed including a signature-sized blob, but no trusted
                # pubkey exists for the inviter: refuse without recording.
                {**_document(group_id, OWNER, "member"), "signature": b"\x11" * 48}
            ),
        )
    )
    assert int(response.code) == 4 * 32 + 3
    assert invites.accepted == []
    assert collection.invitation_valid(group_id, MEMBER) is False


@pytest.mark.asyncio
async def test_signed_invitation_from_known_pubkey_records_usable_ledger() -> None:
    """A genuinely signed invitation from a trusted key is accepted end-to-end."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x06" * 32)
    invites = GroupsInviteResource(
        pubkeys={OWNER: owner_identity.pubkey},
        collection=collection,
        invitee=MEMBER,
    )
    invited = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(owner_identity, _document(group_id, OWNER, "member"))),
        )
    )
    assert invited.code == aiocoap.CHANGED
    assert len(invites.accepted) == 1
    assert collection.invitation_role(group_id, MEMBER) == "member"

    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": MEMBER}, path=(group_id, "key"), context=MEMBER
        )
    )
    assert grant.code == aiocoap.CONTENT
    assert MEMBER in collection.groups[group_id]["members"]


@pytest.mark.asyncio
async def test_forged_signature_and_wrong_key_are_rejected() -> None:
    """Forged signatures and foreign keys are refused without ledger effects."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x06" * 32)
    impostor = Identity.from_seed(b"\x07" * 32)
    invites = GroupsInviteResource(
        pubkeys={OWNER: owner_identity.pubkey},
        collection=collection,
        invitee=MEMBER,
    )

    # Signed by a key that is not trusted for the claimed inviter identity.
    foreign = _sign(impostor, _document(group_id, OWNER, "member"))
    forged = await invites.render_post(
        Message(code=aiocoap.POST, payload=cbor2.dumps(foreign))
    )
    assert int(forged.code) == 4 * 32 + 3

    # Valid signature over one document, attached to a mutated document.
    genuine = _sign(owner_identity, _document(group_id, OWNER, "member"))
    genuine["role"] = "admin"
    tampered = await invites.render_post(
        Message(code=aiocoap.POST, payload=cbor2.dumps(genuine))
    )
    assert int(tampered.code) == 4 * 32 + 3

    assert invites.accepted == []
    assert collection.invitation_valid(group_id, MEMBER) is False


@pytest.mark.asyncio
async def test_owner_minted_admin_invitation_joins_as_admin() -> None:
    """Owner promotion authority: an owner-minted admin invite promotes."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x06" * 32)
    invites = GroupsInviteResource(
        pubkeys={OWNER: owner_identity.pubkey},
        collection=collection,
        invitee=MEMBER,
    )
    invited = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(owner_identity, _document(group_id, OWNER, "admin"))),
        )
    )
    assert invited.code == aiocoap.CHANGED
    assert collection.invitation_role(group_id, MEMBER) == "admin"

    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": MEMBER}, path=(group_id, "key"), context=MEMBER
        )
    )
    assert grant.code == aiocoap.CONTENT
    assert MEMBER in collection.groups[group_id]["members"]
    assert MEMBER in collection.groups[group_id]["admins"]


@pytest.mark.asyncio
async def test_admin_may_only_mint_member_invitations() -> None:
    """spec 18.8.2 L1129-1143: promotion authority is reserved to the owner."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    owner_identity = Identity.from_seed(b"\x06" * 32)
    admin_identity = Identity.from_seed(b"\x07" * 32)
    invites = GroupsInviteResource(
        roster=GroupRoster(owner=OWNER, admins=frozenset({ADMIN})),
        pubkeys={OWNER: owner_identity.pubkey, ADMIN: admin_identity.pubkey},
        collection=collection,
        invitee=MEMBER,
    )

    escalated = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(admin_identity, _document(group_id, ADMIN, "admin"))),
        )
    )
    assert int(escalated.code) == 4 * 32 + 3
    assert invites.accepted == []
    assert collection.invitation_valid(group_id, MEMBER) is False

    # Positive control: an admin CAN mint a plain member-role invitation...
    delegated = GroupsInviteResource(
        roster=GroupRoster(owner=OWNER, admins=frozenset({ADMIN})),
        pubkeys={OWNER: owner_identity.pubkey, ADMIN: admin_identity.pubkey},
        collection=collection,
        invitee=OTHER_INVITEE,
    )
    member_doc = await delegated.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(admin_identity, _document(group_id, ADMIN, "member"))),
        )
    )
    assert member_doc.code == aiocoap.CHANGED
    assert collection.invitation_role(group_id, OTHER_INVITEE) == "member"

    # ...and the resulting role ledger joins the invitee as member only.
    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": OTHER_INVITEE},
            path=(group_id, "key"),
            context=OTHER_INVITEE,
        )
    )
    assert grant.code == aiocoap.CONTENT
    state = collection.groups[group_id]
    assert OTHER_INVITEE in state["members"]
    assert OTHER_INVITEE not in state["admins"]


@pytest.mark.asyncio
async def test_wire_forgery_claiming_local_node_leaks_no_secret() -> None:
    """SECURITY (worker6-0vhm): the live harness exploit chain is dead.

    Replica of shipped wiring -- GroupsInviteResource(node_id=owner), no
    roster, no pinned pubkeys -- receiving POST /groups/invite from a wire
    peer with inviter==node_id, role=admin, junk signature. The document
    must be refused AND the follow-up join_key over the attacker's own
    pairwise context must disclose nothing.
    """
    attacker = "0200::9999"
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    site = Site()
    site.add_resource(["groups"], collection)
    site.add_resource(["groups"], item)
    site.add_resource(["groups", "invite"], GroupsInviteResource(node_id=OWNER))
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    attacker_client = await create_lichen_context(net.channel("attacker"), "attacker")
    try:
        created = await collection.render_post(
            _pairwise_post({"name": "Team Alpha", "encrypted": True})
        )
        assert created.code == aiocoap.CREATED
        group_id = cbor2.loads(created.payload)["id"]

        forged = await attacker_client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps(
                    {**_document(group_id, OWNER, "admin"), "signature": b"\x11" * 48}
                ),
            )
        ).response
        assert int(forged.code) == 4 * 32 + 3

        # Key fetch over the attacker's own legitimate pairwise context.
        grant = await item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": attacker},
                path=(group_id, "key"),
                context=attacker,
            )
        )
        assert int(grant.code) == 4 * 32 + 3
        # Empty payload: zero bytes of key material were disclosed.
        assert not grant.payload
        assert attacker not in collection.groups[group_id]["members"]
        assert attacker not in collection.groups[group_id]["admins"]
        assert collection.invitation_role(group_id, attacker) is None
    finally:
        await attacker_client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_node_signed_wire_invitation_verifies_against_pinned_self_key() -> None:
    """A wire delivery claiming inviter==node_id verifies like foreign inviters.

    Constructing the resource with node_pubkey pins the node's own key into
    the same registry used for remote inviters: a genuinely signed document
    is honored end-to-end while impostor-signed promotion is refused.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    node_identity = Identity.from_seed(b"\x06" * 32)
    impostor = Identity.from_seed(b"\x07" * 32)
    invites = GroupsInviteResource(
        node_id=OWNER,
        node_pubkey=node_identity.pubkey,
        collection=collection,
        invitee=MEMBER,
    )
    # Registry mechanics: the self key is pinned under the node id exactly
    # like any provisioned peer entry.
    assert invites.pubkeys.get(OWNER) == node_identity.pubkey

    genuine = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(node_identity, _document(group_id, OWNER, "member"))),
        )
    )
    assert genuine.code == aiocoap.CHANGED
    assert len(invites.accepted) == 1

    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": MEMBER}, path=(group_id, "key"), context=MEMBER
        )
    )
    assert grant.code == aiocoap.CONTENT
    assert MEMBER in collection.groups[group_id]["members"]

    escalated = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps(_sign(impostor, _document(group_id, OWNER, "admin"))),
        )
    )
    assert int(escalated.code) == 4 * 32 + 3
    assert len(invites.accepted) == 1
