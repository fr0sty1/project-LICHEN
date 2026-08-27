# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Membership sequences and rekey-on-removal (spec 18.8.2)."""

from __future__ import annotations

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    REKEY_GRACE_S,
    GroupsCollectionResource,
    GroupsItemResource,
)
from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.coap.resources.groups_remove import GroupsRemoveResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.group_membership import (
    GroupRoster,
    invitation_preimage,
    parse_invitation,
    parse_removal,
    removal_preimage,
)

ROOT = Path(__file__).resolve().parents[3]
SEQ = ROOT / "test" / "vectors" / "groups_membership_sequences.json"
REKEY = ROOT / "test" / "vectors" / "groups_rekey.json"

OWNER = "0200::1111"
FORBIDDEN_CODE = 4 * 32 + 3


def _pairwise_post(
    payload: dict[str, object], *, path: tuple[str, ...] = (), context: str = OWNER
) -> Message:
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(payload))
    if path:
        request.opt.uri_path = path
    request.oscore_context_id = context
    return request


def _members_request(group_id: str, context: str | None = OWNER) -> Message:
    request = Message(code=aiocoap.GET)
    request.opt.uri_path = (group_id, "members")
    if context is not None:
        request.oscore_context_id = context
    return request


async def _client_server(site: Site) -> tuple[aiocoap.Context, aiocoap.Context]:
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.asyncio
async def test_membership_protocol_sequences() -> None:
    document = json.loads(SEQ.read_text(encoding="utf-8"))
    owner = OWNER
    for case in document["vectors"]:
        collection = GroupsCollectionResource(owner=owner, clock=lambda: 1716742800)
        item = GroupsItemResource(collection)
        site = Site()
        site.add_resource(["groups"], collection)
        site.add_resource(["groups"], item)
        # The local node is the owner authoring its own invitations, so the
        # provisioning carve-out applies only from a locally trusted origin:
        # the LCI client is bound to loopback (admin), while a wire peer with
        # the same junk-signature document must be refused.
        site.add_resource(["groups", "invite"], GroupsInviteResource(node_id=owner))
        net = InMemoryNetwork()
        server = await create_lichen_context(net.channel("server"), "server", site=site)
        client = await create_lichen_context(net.channel("[::1]"), "[::1]")
        group_id = ""
        try:
            for step in case["steps"]:
                if step["op"] == "create":
                    created = await collection.render_post(
                        _pairwise_post({"name": step["name"], "encrypted": step["encrypted"]})
                    )
                    assert created.code == aiocoap.CREATED
                    group_id = cbor2.loads(created.payload)["id"]
                elif step["op"] == "invite":
                    assert step["inviter_is_owner"] is True
                    assert step["role"] == "member"
                    invited = await client.request(
                        Message(
                            code=aiocoap.POST,
                            uri="coap://server/groups/invite",
                            payload=cbor2.dumps(
                                {
                                    "group_id": group_id,
                                    "group_name": "Team Alpha",
                                    "mcast": "ff35:0040::1",
                                    "inviter": owner,
                                    "role": "member",
                                    "expires": 1716829200,
                                    "signature": b"\x11",
                                }
                            ),
                        )
                    ).response
                    assert invited.code == aiocoap.CHANGED
                elif step["op"] == "join_key":
                    # spec 18.8.2: key fetch only after accepting an
                    # invitation, bound to the pairwise peer identity.
                    collection.record_invitation(group_id, step["node"])
                    resp = await item.render_post(
                        _pairwise_post(
                            {"request": "join_key", "node": step["node"]},
                            path=(group_id, "key"),
                            context=step["node"],
                        )
                    )
                    assert resp.code == aiocoap.CONTENT
                elif step["op"] == "members":
                    resp = await item.render_get(_members_request(group_id))
                    body = cbor2.loads(resp.payload)
                    expected = step["expected"]
                    if expected.get("owner_is_member"):
                        assert body["owner"] in body["members"]
                    if "admins" in expected:
                        assert body["admins"] == expected["admins"]
                    if "member_count" in expected:
                        assert len(body["members"]) == expected["member_count"]
                    if "contains" in expected:
                        assert expected["contains"] in body["members"]
        finally:
            await client.shutdown()
            await server.shutdown()


@pytest.mark.asyncio
async def test_members_endpoint_rejects_unaffiliated_and_bare_requests() -> None:
    """spec 18.8.2: roster sync requires OSCORE and affiliation."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(collection)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]

    bare = await item.render_get(_members_request(group_id, context=None))
    assert int(bare.code) == 4 * 32 + 1

    outsider = "0200::9999"
    refused = await item.render_get(_members_request(group_id, context=outsider))
    assert refused.code == FORBIDDEN_CODE

    # A legacy/persisted orphan admin entry must not restore authority: admins
    # are bound to membership in the current roster epoch.
    collection.groups[group_id]["admins"].append(outsider)
    stale_admin = await item.render_get(_members_request(group_id, context=outsider))
    assert stale_admin.code == FORBIDDEN_CODE

    collection.groups[group_id]["members"].append(outsider)
    admin_view = await item.render_get(_members_request(group_id, context=outsider))
    assert admin_view.code == aiocoap.CONTENT


@pytest.mark.asyncio
async def test_locally_authored_removal_requires_trusted_origin() -> None:
    """SECURITY: removed_by==node_id skips crypto only for a locally trusted origin.

    Split oracle against fixed code: an LCI loopback peer and this node's own
    pairwise identity are trusted authorship origins for owner-authored
    removals, while the identical unauthenticated wire delivery must be
    refused without any state mutation (forced removal is otherwise a
    repeatable de-enrollment/key-churn primitive).
    """
    async def _setup() -> tuple[GroupsCollectionResource, GroupsRemoveResource, str]:
        collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
        created = await collection.render_post(
            _pairwise_post({"name": "Team Alpha", "encrypted": True})
        )
        group_id = cbor2.loads(created.payload)["id"]
        remover = GroupsRemoveResource(node_id=OWNER, collection=collection)
        return collection, remover, group_id

    # LCI loopback admin: locally authored junk-signature removal is honored.
    collection, remover, group_id = await _setup()
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(_removal_document(group_id)))
    request.remote = SimpleNamespace(hostinfo="[::1]")
    response = await remover.render_post(request)
    assert response.code == aiocoap.CHANGED
    assert len(remover.accepted) == 1
    assert collection.groups[group_id]["key_epoch"] == 2

    # The node's own pairwise identity bound after unprotect: trusted too.
    collection, remover, group_id = await _setup()
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(_removal_document(group_id)))
    request.oscore_context_id = OWNER
    response = await remover.render_post(request)
    assert response.code == aiocoap.CHANGED
    assert len(remover.accepted) == 1

    # Unauthenticated wire delivery claiming local authorship: refused with
    # no membership or key state change (the exploit bead worker6-x8q9).
    collection, remover, group_id = await _setup()
    state_before = copy.deepcopy(collection.groups[group_id])
    request = Message(code=aiocoap.POST, payload=cbor2.dumps(_removal_document(group_id)))
    request.remote = SimpleNamespace(hostinfo="[fe80::2]")
    response = await remover.render_post(request)
    assert int(response.code) == FORBIDDEN_CODE
    assert remover.accepted == []
    assert collection.groups[group_id] == state_before


def _removal_document(group_id: str) -> dict[str, object]:
    return {
        "group_id": group_id,
        "removed_by": OWNER,
        "reason": "owner left",
        "signature": b"\x00" * 48,
    }


@pytest.mark.asyncio
async def test_rekey_retains_old_material_through_grace() -> None:
    """spec 18.8.2: retired keys stay unprotect-capable until the grace ends."""
    document = json.loads(REKEY.read_text(encoding="utf-8"))
    now = {"t": 1_716_742_800.0}
    owner = OWNER
    collection = GroupsCollectionResource(owner=owner, clock=lambda: now["t"])
    item = GroupsItemResource(collection)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    creation_body = cbor2.loads(created.payload)

    # Voluntary-join flow before any rotation.
    newcomer = "0200::4444"
    assert collection.record_invitation(group_id, newcomer) is True
    joined = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": newcomer}, path=(group_id, "key"), context=newcomer
        )
    )
    assert joined.code == aiocoap.CONTENT
    pre_rotated_secret = collection.groups[group_id]["master_secret"]
    assert creation_body["master_secret"] == pre_rotated_secret

    pre_rotation = {
        "epoch": collection.groups[group_id]["key_epoch"],
        "secret": bytes(pre_rotated_secret),
        "salt": bytes(collection.groups[group_id]["master_salt"]),
        "key_id": collection.groups[group_id]["key_id"],
    }
    rotated = collection.rekey(group_id)
    assert rotated == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    assert collection.epoch_accepted(group_id, pre_rotation["epoch"]) is True

    retained = collection.group_key_for_epoch(group_id, pre_rotation["epoch"])
    assert retained == {
        "key_epoch": pre_rotation["epoch"],
        "master_secret": pre_rotation["secret"],
        "master_salt": pre_rotation["salt"],
        "key_id": pre_rotation["key_id"],
    }

    # Unknown epochs never resolve.
    assert collection.group_key_for_epoch(group_id, 99) is None
    assert collection.epoch_accepted(group_id, 99) is False

    now["t"] += document["grace_s"]
    assert collection.epoch_accepted(group_id, pre_rotation["epoch"]) is False
    assert collection.group_key_for_epoch(group_id, pre_rotation["epoch"]) is None
    assert collection.groups[group_id]["retired_epochs"] == []
    # The live key was never touched by grace handling.
    assert collection.groups[group_id]["master_secret"] != pre_rotation["secret"]


@pytest.mark.asyncio
async def test_rekey_never_strips_owner() -> None:
    """spec 18.8.2: Owner is always a member."""
    now = {"t": 1_716_742_800.0}
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: now["t"])
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    rotated = collection.rekey(group_id, removed_member=OWNER)
    assert rotated is not None
    assert OWNER in collection.groups[group_id]["members"]
    assert collection.groups[group_id]["key_epoch"] == 2


@pytest.mark.asyncio
async def test_rekey_removes_admin_from_authoritative_roster() -> None:
    """A removed admin loses both membership and every roster read capability."""
    admin = "0200::2222"
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(collection)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    assert collection.record_invitation(group_id, admin, role="admin") is True
    joined = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": admin},
            path=(group_id, "key"),
            context=admin,
        )
    )
    assert joined.code == aiocoap.CONTENT
    assert collection.requester_role(group_id, admin) == "admin"

    rotated = collection.rekey(group_id, removed_member=admin)
    assert rotated is not None
    state = collection.groups[group_id]
    assert admin not in state["members"]
    assert admin not in state["admins"]
    assert OWNER in state["members"]
    assert collection.requester_role(group_id, admin) is None
    assert collection.invitation_valid(group_id, admin) is False

    refused = await item.render_get(_members_request(group_id, context=admin))
    assert refused.code == FORBIDDEN_CODE
    owner_view = await item.render_get(_members_request(group_id))
    assert owner_view.code == aiocoap.CONTENT
    assert cbor2.loads(owner_view.payload)["admins"] == []


@pytest.mark.asyncio
async def test_rekey_failure_is_atomic_and_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entropy failure cannot commit a roster removal without its new key."""
    admin = "0200::2222"
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    state = collection.groups[group_id]
    state["members"].append(admin)
    state["admins"].append(admin)
    before = copy.deepcopy(state)
    calls = 0

    def failing_random(length: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("entropy unavailable")
        return bytes([length]) * length

    monkeypatch.setattr("lichen.coap.resources.groups_collection.os.urandom", failing_random)
    with pytest.raises(OSError, match="entropy unavailable"):
        collection.rekey(group_id, removed_member=admin)
    assert state == before
    assert collection.requester_role(group_id, admin) == "admin"

    monkeypatch.setattr(
        "lichen.coap.resources.groups_collection.os.urandom",
        lambda length: bytes([length]) * length,
    )
    assert collection.rekey(group_id, removed_member=admin) is not None
    assert collection.requester_role(group_id, admin) is None


@pytest.mark.asyncio
async def test_concurrent_rekeys_serialize_epochs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two simultaneous rotations commit distinct monotonically increasing epochs."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]

    def slow_random(length: int) -> bytes:
        time.sleep(0.01)
        return bytes([length]) * length

    monkeypatch.setattr("lichen.coap.resources.groups_collection.os.urandom", slow_random)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: collection.rekey(group_id), range(2)))

    assert sorted(result["key_epoch"] for result in results if result is not None) == [2, 3]
    state = collection.groups[group_id]
    assert state["key_epoch"] == 3
    assert [entry["key_epoch"] for entry in state["retired_epochs"]] == [1, 2]
    assert OWNER in state["members"]


@pytest.mark.asyncio
async def test_invite_acceptance_records_usable_invitation() -> None:
    """spec 18.8.2: accepted signed invitations unlock bound key fetch.

    The invitation carries a genuine 48-byte Schnorr signature over the
    canonical preimage; the owner keypair is generated in-test and the
    signed bytes are handed to the resource unmodified.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(collection)
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]

    invitee = "0200::3333"
    owner_identity = Identity.from_seed(b"\x06" * 32)
    draft = parse_invitation(
        {
            "group_id": group_id,
            "group_name": "Team Alpha",
            "mcast": "ff35:0040::1",
            "inviter": OWNER,
            "role": "member",
            "expires": 1716742800 + 600,
            "signature": b"\x00" * 48,
        }
    )
    signature = sign(owner_identity.privkey, owner_identity.pubkey, invitation_preimage(draft))
    invites = GroupsInviteResource(
        roster=GroupRoster(owner=OWNER),
        pubkeys={OWNER: owner_identity.pubkey},
        collection=collection,
        invitee=invitee,
    )
    invited = await invites.render_post(
        Message(
            code=aiocoap.POST,
            payload=cbor2.dumps({**draft.to_map(), "signature": signature}),
        )
    )
    assert invited.code == aiocoap.CHANGED

    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": invitee}, path=(group_id, "key"), context=invitee
        )
    )
    assert grant.code == aiocoap.CONTENT
    assert invitee in collection.groups[group_id]["members"]


@pytest.mark.asyncio
async def test_rekey_on_member_removal() -> None:
    document = json.loads(REKEY.read_text(encoding="utf-8"))
    assert document["grace_s"] == REKEY_GRACE_S
    case = document["vectors"][0]
    now = {"t": 1_716_742_800.0}
    owner = OWNER
    removed = case["removed_member"]
    collection = GroupsCollectionResource(owner=owner, clock=lambda: now["t"])
    owner_identity = Identity.from_seed(b"\x38" * 32)
    site = Site()
    site.add_resource(["groups"], collection)
    site.add_resource(["groups"], GroupsItemResource(collection))
    roster = GroupRoster(owner=owner)
    remover = GroupsRemoveResource(
        roster=roster,
        pubkeys={owner: owner_identity.pubkey},
        node_id=removed,
        collection=collection,
    )
    site.add_resource(["groups", "remove"], remover)
    client, server = await _client_server(site)
    item = GroupsItemResource(collection)
    try:
        created = await collection.render_post(
            _pairwise_post({"name": "Team Alpha", "encrypted": True})
        )
        created_id = cbor2.loads(created.payload)["id"]
        creation_secret = cbor2.loads(created.payload)["master_secret"]

        # spec 18.8.2: the member being removed had accepted its invitation
        # and fetched the original key before the forced removal.
        assert collection.record_invitation(created_id, removed) is True
        pre_fetch = await item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": removed},
                path=(created_id, "key"),
                context=removed,
            )
        )
        assert pre_fetch.code == aiocoap.CONTENT

        state = collection.groups[created_id]
        assert state["key_epoch"] == case["initial_epoch"]
        old_epoch = state["key_epoch"]
        old_secret = state["master_secret"]
        old_salt = state["master_salt"]
        old_key_id = state["key_id"]
        # Independent oracle: the retained material is the very secret handed
        # out at creation time and during the pre-removal fetch.
        assert old_secret == creation_secret
        assert old_secret == cbor2.loads(pre_fetch.payload)["master_secret"]

        removal = parse_removal(
            {
                "group_id": created_id,
                "removed_by": owner,
                "reason": "no longer on team",
                "signature": b"\x00" * 48,
            }
        )
        removal_signature = sign(
            owner_identity.privkey,
            owner_identity.pubkey,
            removal_preimage(removal),
        )
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/remove",
                payload=cbor2.dumps(
                    {
                        **removal.to_map(),
                        "signature": removal_signature,
                    }
                ),
            )
        ).response
        assert resp.code == aiocoap.CHANGED

        state = collection.groups[created_id]
        assert state["key_epoch"] == case["after_removal_epoch"]
        assert state["master_secret"] != old_secret
        assert removed not in state["members"]
        assert owner in state["members"]
        # Forced removal revokes the removed node's invitation too.
        assert collection.invitation_valid(created_id, removed) is False

        assert (
            collection.epoch_accepted(created_id, old_epoch)
            is case["old_epoch_accepted_before_grace"]
        )
        retained = collection.group_key_for_epoch(created_id, old_epoch)
        assert retained == {
            "key_epoch": old_epoch,
            "master_secret": old_secret,
            "master_salt": old_salt,
            "key_id": old_key_id,
        }

        now["t"] += document["grace_s"]
        assert (
            collection.epoch_accepted(created_id, old_epoch)
            is case["old_epoch_accepted_after_grace"]
        )
        assert collection.group_key_for_epoch(created_id, old_epoch) is None
        assert state["retired_epochs"] == []
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_sequential_rekeys_stack_retired_epochs_with_prune_boundaries() -> None:
    """Three rotations stack grace entries; every step's stack is pinned exactly.

    Hand-derived timeline (t0 = 1716742800):

    - create@t0 -> epoch 1
    - rekey@t0: retires epoch 1, expires t0+3600; stack [1]
    - rekey@t0+100: retires epoch 2, expires t0+3700; stack [1, 2]
    - probe@t0+3600: epoch 1 exactly expired (strict ``<``) yet still present;
      epoch 2 still live. Prune-on-read drops only epoch 1 -> stack [2]
    - rekey@t0+3600: retires epoch 3, expires t0+7200; stack [2, 3]
    - probe@t0+7200: epochs 2 and 3 exactly expired; prune-on-read empties.

    Secrets/salts are captured from construction time like the other tests in
    this file; key ids and expiry stamps are computed offline from the known
    schedule.
    """
    t0 = 1_716_742_800
    now = {"t": float(t0)}
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: now["t"])
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    state = collection.groups[group_id]

    s1 = bytes(state["master_secret"])
    sa1 = bytes(state["master_salt"])
    k1 = f"key-{group_id}-001"
    # A freshly created encrypted group has no retired stack yet.
    assert state.get("retired_epochs", []) == []

    # Rekey #1 @ T.
    assert collection.rekey(group_id) == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    s2 = bytes(state["master_secret"])
    sa2 = bytes(state["master_salt"])

    # Rekey #2 @ t0+100 stacks behind the still-live epoch 1 entry.
    now["t"] = float(t0 + 100)
    assert collection.rekey(group_id) == {"key_id": f"key-{group_id}-003", "key_epoch": 3}
    s3 = bytes(state["master_secret"])
    sa3 = bytes(state["master_salt"])
    entry_one_expired_at = t0 + REKEY_GRACE_S
    entry_two_expired_at = t0 + 100 + REKEY_GRACE_S
    assert state["retired_epochs"] == [
        {
            "key_epoch": 1,
            "master_secret": s1,
            "master_salt": sa1,
            "key_id": k1,
            "expires": entry_one_expired_at,
        },
        {
            "key_epoch": 2,
            "master_secret": s2,
            "master_salt": sa2,
            "key_id": f"key-{group_id}-002",
            "expires": entry_two_expired_at,
        },
    ]

    # Boundary @ T+3600: acceptance is strict (< expires), so epoch 1 is dead
    # while still physically stacked; epochs 2 and 3 are accepted.
    now["t"] = float(t0 + REKEY_GRACE_S)
    assert collection.epoch_accepted(group_id, 1) is False
    assert collection.epoch_accepted(group_id, 2) is True

    # Prune-on-read trigger: live-clock lookup of a retired epoch mutates the
    # stack, dropping exactly the expired epoch 1.
    retained = collection.group_key_for_epoch(group_id, 2)
    assert retained == {
        "key_epoch": 2,
        "master_secret": s2,
        "master_salt": sa2,
        "key_id": f"key-{group_id}-002",
    }
    assert state["retired_epochs"] == [
        {
            "key_epoch": 2,
            "master_secret": s2,
            "master_salt": sa2,
            "key_id": f"key-{group_id}-002",
            "expires": entry_two_expired_at,
        }
    ]

    # Rekey #3 @ the same stamp keeps only live entries and appends epoch 3.
    assert collection.rekey(group_id) == {"key_id": f"key-{group_id}-004", "key_epoch": 4}
    s4 = bytes(state["master_secret"])
    sa4 = bytes(state["master_salt"])
    entry_three_expired_at = t0 + 2 * REKEY_GRACE_S
    assert state["retired_epochs"] == [
        {
            "key_epoch": 2,
            "master_secret": s2,
            "master_salt": sa2,
            "key_id": f"key-{group_id}-002",
            "expires": entry_two_expired_at,
        },
        {
            "key_epoch": 3,
            "master_secret": s3,
            "master_salt": sa3,
            "key_id": f"key-{group_id}-003",
            "expires": entry_three_expired_at,
        },
    ]

    # Final boundary @ T+7200: both stacked entries are exactly expired.
    now["t"] = float(entry_three_expired_at)
    assert collection.epoch_accepted(group_id, 2) is False
    assert collection.epoch_accepted(group_id, 3) is False
    # The mutating lookup of a retired epoch prunes both dead entries.
    assert collection.group_key_for_epoch(group_id, 3) is None
    assert state["retired_epochs"] == []
    # The live epoch was never touched by grace handling.
    current = collection.group_key_for_epoch(group_id, 4)
    assert current == {
        "key_epoch": 4,
        "master_secret": s4,
        "master_salt": sa4,
        "key_id": f"key-{group_id}-004",
    }


@pytest.mark.asyncio
async def test_double_prune_is_idempotent_and_concurrency_free() -> None:
    """A second read-time prune drops nothing (second call returns no drops).

    Two retired entries are stacked; at a stamp where only the first has
    expired, one pruning pass drops exactly one entry and leaves the survivor
    byte-identical; repeating the identical pass proves idempotency by deep
    equality against the post-first-pass snapshot. Rekey and prune mutate
    synchronously under the collection mutation lock, so sequential double
    invocation IS the concurrency-relevant interleaving contract under
    cooperative asyncio -- no fake async scaffolding is needed to evidence it.
    """
    t0 = 1_716_742_800
    now = {"t": float(t0)}
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: now["t"])
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    group_id = cbor2.loads(created.payload)["id"]
    state = collection.groups[group_id]

    s1 = bytes(state["master_secret"])
    sa1 = bytes(state["master_salt"])
    assert collection.rekey(group_id) == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    s2 = bytes(state["master_secret"])
    sa2 = bytes(state["master_salt"])
    now["t"] = float(t0 + 100)
    assert collection.rekey(group_id) == {"key_id": f"key-{group_id}-003", "key_epoch": 3}

    entry_one_expired_at = t0 + REKEY_GRACE_S
    entry_two_expired_at = t0 + 100 + REKEY_GRACE_S
    expected_initial = [
        {
            "key_epoch": 1,
            "master_secret": s1,
            "master_salt": sa1,
            "key_id": f"key-{group_id}-001",
            "expires": entry_one_expired_at,
        },
        {
            "key_epoch": 2,
            "master_secret": s2,
            "master_salt": sa2,
            "key_id": f"key-{group_id}-002",
            "expires": entry_two_expired_at,
        },
    ]
    assert copy.deepcopy(state["retired_epochs"]) == expected_initial

    now["t"] = float(entry_one_expired_at)
    pre_len = len(state["retired_epochs"])

    first_pass = collection.group_key_for_epoch(group_id, 2)
    after_first = copy.deepcopy(state["retired_epochs"])
    assert len(after_first) == pre_len - 1
    assert after_first == [
        {
            "key_epoch": 2,
            "master_secret": s2,
            "master_salt": sa2,
            "key_id": f"key-{group_id}-002",
            "expires": entry_two_expired_at,
        }
    ]

    # The identical second pass drops zero entries.
    second_pass = collection.group_key_for_epoch(group_id, 2)
    assert second_pass == first_pass
    assert copy.deepcopy(state["retired_epochs"]) == after_first
