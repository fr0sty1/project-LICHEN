# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Mutation-lock coverage for invitation, join, delete, and prune transitions
(spec 18.8.2).

``record_invitation``, ``consume_invitation``, and the ``_join_key``
roster transition mutate the same structures that ``rekey()`` snapshots
and rebuilds under ``_mutation_lock``. These tests pin that every
mutating path actually holds the lock: a non-reentrant
``acquire(blocking=False)`` probe inside the critical section must fail,
and cross-thread rekey interleavings must never drop a write. The lock
must also span the join's key-material read-back, the delete's
check-then-remove, and the grace-window prune in ``group_key_for_epoch``.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import aiocoap
import cbor2
import pytest

from lichen.coap.resources import groups_collection as groups_collection_module
from lichen.coap.resources.groups_collection import (
    OSCORE_GROUP_ALG,
    GroupsCollectionResource,
    GroupsItemResource,
    _invitation_identity,
)

OWNER = "0200::1111"
NEWCOMER = "0200::4444"
T0 = 1_716_742_800


def _pairwise_post(
    payload: dict[str, object], *, path: tuple[str, ...] = (), context: str = OWNER
) -> aiocoap.Message:
    request = aiocoap.Message(code=aiocoap.POST, payload=cbor2.dumps(payload))
    if path:
        request.opt.uri_path = path
    request.oscore_context_id = context
    return request


def _delete_request(group_id: str, *, context: str = OWNER) -> aiocoap.Message:
    request = aiocoap.Message(code=aiocoap.DELETE)
    request.opt.uri_path = (group_id,)
    request.oscore_context_id = context
    return request


async def _created_group(
    collection: GroupsCollectionResource,
) -> str:
    created = await collection.render_post(
        _pairwise_post({"name": "Team Alpha", "encrypted": True})
    )
    assert created.code == aiocoap.CREATED
    group_id: str = cbor2.loads(created.payload)["id"]
    return group_id


def _assert_lock_held(collection: GroupsCollectionResource) -> None:
    """Fail unless *collection*'s mutation lock is already held (same thread)."""
    lock = collection._mutation_lock
    acquired = lock.acquire(blocking=False)
    if acquired:
        lock.release()
    assert not acquired, "_mutation_lock not held inside mutating critical section"


@pytest.mark.asyncio
async def test_record_invitation_holds_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The burned-identity check and invitations write run under the lock."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)

    original = groups_collection_module._invitation_identity
    calls = 0

    def probing_identity(inviter: str, node: str, *, expires: int | None, role: str) -> str:
        nonlocal calls
        calls += 1
        _assert_lock_held(collection)
        return original(inviter, node, expires=expires, role=role)

    monkeypatch.setattr(groups_collection_module, "_invitation_identity", probing_identity)
    assert collection.record_invitation(group_id, NEWCOMER, inviter=OWNER) is True
    assert calls == 1

    # Outside the critical section the same probe acquires cleanly.
    assert collection._mutation_lock.acquire(blocking=False) is True
    collection._mutation_lock.release()


@pytest.mark.asyncio
async def test_consume_invitation_holds_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one-time enrollment marker is written under the lock."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER, inviter=OWNER) is True

    original = collection._invitation_entry
    calls = 0

    def probing_entry(group_id: str, node: str) -> dict[str, Any] | None:
        nonlocal calls
        calls += 1
        _assert_lock_held(collection)
        return original(group_id, node)

    monkeypatch.setattr(collection, "_invitation_entry", probing_entry)
    collection.consume_invitation(group_id, NEWCOMER)
    assert calls == 1

    identity = _invitation_identity(OWNER, NEWCOMER, expires=None, role="member")
    assert collection.groups[group_id]["consumed_invitations"] == {identity: True}


@pytest.mark.asyncio
async def test_join_key_holds_mutation_lock_through_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invitation check, roster append, and burn marker are one locked span.

    Completion under the real non-reentrant ``threading.Lock`` is also the
    deadlock regression: a nested acquisition (public ``consume_invitation``
    inside the locked span) would block the event loop forever.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER) is True

    original = collection.invitation_consumed
    calls = 0

    def probing_consumed(group_id: str, node: str) -> bool:
        nonlocal calls
        calls += 1
        _assert_lock_held(collection)
        return original(group_id, node)

    monkeypatch.setattr(collection, "invitation_consumed", probing_consumed)
    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": NEWCOMER},
            path=(group_id, "key"),
            context=NEWCOMER,
        )
    )
    assert grant.code == aiocoap.CONTENT
    assert calls == 1
    assert NEWCOMER in collection.groups[group_id]["members"]
    # No inviter -> no document identity -> no burn marker, but the entry
    # itself is marked spent.
    assert collection.groups[group_id].get("consumed_invitations", {}) == {}
    # Via the captured original: the patched probe only guards the locked span.
    assert original(group_id, NEWCOMER) is True


@pytest.mark.asyncio
async def test_consume_invitation_public_wrapper_actually_locks() -> None:
    """The public wrapper acquires; a background consumer blocks until release."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER) is True

    collection._mutation_lock.acquire()
    done = threading.Event()

    def worker() -> None:
        collection.consume_invitation(group_id, NEWCOMER)
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        # Held lock: the consumer must stay blocked (not silently no-op).
        assert done.wait(timeout=0.2) is False
    finally:
        collection._mutation_lock.release()
    assert done.wait(timeout=5.0) is True
    thread.join()
    assert collection.groups[group_id]["invitations"][NEWCOMER]["consumed"] is True


@pytest.mark.asyncio
async def test_rekey_and_invitation_records_do_not_lose_writes() -> None:
    """Rekey's snapshot/rebuild cannot clobber concurrent invitation records.

    The exact final state is identical for every thread interleaving (the
    lock makes the outcome interleaving-independent): both records survive,
    the removed member's invitation is popped and its identity burned, and
    no joiner identity is marked consumed.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)
    state = collection.groups[group_id]

    removed = "0200::2222"
    identity_removed = _invitation_identity(OWNER, removed, expires=None, role="member")
    state["members"].append(removed)
    state.setdefault("invitations", {})[removed] = {
        "expires": None,
        "role": "member",
        "identity": identity_removed,
    }

    joiners = ("0200::3333", "0200::4444")
    expires = T0 + 600

    with ThreadPoolExecutor(max_workers=3) as executor:
        rotation = executor.submit(collection.rekey, group_id, removed_member=removed)
        recorded = [
            executor.submit(
                collection.record_invitation,
                group_id,
                joiner,
                inviter=OWNER,
                expires=expires,
            ).result()
            for joiner in joiners
        ]
        rotated = rotation.result()

    assert rotated == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    assert recorded == [True, True]
    assert state["invitations"] == {
        joiner: {
            "expires": expires,
            "role": "member",
            "identity": _invitation_identity(OWNER, joiner, expires=expires, role="member"),
        }
        for joiner in joiners
    }
    assert state["consumed_invitations"] == {identity_removed: True}
    assert removed not in state["members"]
    assert OWNER in state["members"]
    assert state["key_epoch"] == 2


@pytest.mark.asyncio
async def test_rekey_rebuild_does_not_drop_concurrent_join_key_member() -> None:
    """A join racing a rotation still ends up on the roster (no lost append).

    Whatever the interleave, the lock orders the join's membership append
    against rekey's locked rebuild: the newcomer is present afterwards, the
    invitation is consumed exactly once, and the rotation still lands.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER) is True

    with ThreadPoolExecutor(max_workers=1) as executor:
        rotation = executor.submit(collection.rekey, group_id)
        grant = await item.render_post(
            _pairwise_post(
                {"request": "join_key", "node": NEWCOMER},
                path=(group_id, "key"),
                context=NEWCOMER,
            )
        )
        rotated = rotation.result()

    assert rotated == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    assert grant.code == aiocoap.CONTENT
    state = collection.groups[group_id]
    assert NEWCOMER in state["members"]
    assert OWNER in state["members"]
    assert collection.invitation_consumed(group_id, NEWCOMER) is True


@pytest.mark.asyncio
async def test_render_delete_holds_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existence check, owner check, and removal are one locked transition."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)

    original = collection.requester_role
    calls = 0

    def probing_role(group_id: str, peer: str | None) -> str | None:
        nonlocal calls
        calls += 1
        _assert_lock_held(collection)
        return original(group_id, peer)

    monkeypatch.setattr(collection, "requester_role", probing_role)
    deleted = await item.render_delete(_delete_request(group_id))
    assert deleted.code == aiocoap.DELETED
    assert calls == 1
    assert group_id not in collection.groups
    # Outside the critical section the same probe acquires cleanly.
    assert collection._mutation_lock.acquire(blocking=False) is True
    collection._mutation_lock.release()


@pytest.mark.asyncio
async def test_render_delete_waits_for_mutation_lock() -> None:
    """A delete arriving while the lock is held blocks instead of racing."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)

    collection._mutation_lock.acquire()
    done = threading.Event()

    def worker() -> None:
        deleted = asyncio.run(item.render_delete(_delete_request(group_id)))
        worker.result_code = deleted.code  # type: ignore[attr-defined]
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        # Held lock: the delete must stay blocked (not silently proceed).
        assert done.wait(timeout=0.2) is False
    finally:
        collection._mutation_lock.release()
    assert done.wait(timeout=5.0) is True
    thread.join()
    assert worker.result_code == aiocoap.DELETED  # type: ignore[attr-defined]
    assert group_id not in collection.groups


@pytest.mark.asyncio
async def test_delete_between_capture_and_join_returns_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delete committing after _join_key's capture yields 4.04, no key material.

    The decode hook lands exactly between the unlocked record capture and
    the locked span, simulating an owner DELETE that commits while the join
    request is in flight. Without the locked re-fetch the join would mutate
    the detached record and return CONTENT with its key material.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER) is True
    detached = collection.groups[group_id]

    original_decode = groups_collection_module._decode_single_cbor

    def decoding_then_delete(payload: bytes) -> dict[str, Any]:
        body = original_decode(payload)
        # The delete commits between the capture and the locked span.
        collection.groups.pop(group_id)
        return body  # type: ignore[no-any-return]

    monkeypatch.setattr(groups_collection_module, "_decode_single_cbor", decoding_then_delete)
    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": NEWCOMER},
            path=(group_id, "key"),
            context=NEWCOMER,
        )
    )
    assert grant.code == aiocoap.NOT_FOUND
    assert grant.payload == b""
    # The detached record was never mutated by the aborted join.
    assert NEWCOMER not in detached["members"]
    assert group_id not in collection.groups


@pytest.mark.asyncio
async def test_rekey_before_response_readback_yields_join_epoch_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The join response is the epoch tuple captured under the lock.

    The _cbor_response hook commits a rekey after the locked span but
    before the response is serialized. The grant must stay the
    self-consistent tuple from the epoch the enrollment happened in --
    never a torn mix of the old id and the rotated secret.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    assert collection.record_invitation(group_id, NEWCOMER) is True
    before = collection.groups[group_id]
    secret0 = before["master_secret"]
    salt0 = before["master_salt"]

    original_cbor = groups_collection_module._cbor_response

    def cbor_after_rekey(data: dict[str, Any]) -> aiocoap.Message:
        # Commits after the locked span, before the response is built out.
        collection.rekey(group_id)
        return original_cbor(data)

    monkeypatch.setattr(groups_collection_module, "_cbor_response", cbor_after_rekey)
    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": NEWCOMER},
            path=(group_id, "key"),
            context=NEWCOMER,
        )
    )
    assert grant.code == aiocoap.CONTENT
    grant_body = cbor2.loads(grant.payload)
    assert grant_body == {
        "key_id": f"key-{group_id}-001",
        "key_epoch": 1,
        "master_secret": secret0,
        "master_salt": salt0,
        "algorithm": OSCORE_GROUP_ALG,
    }
    # The rotation still landed, and the joiner is on the roster.
    assert collection.groups[group_id]["key_epoch"] == 2
    assert NEWCOMER in collection.groups[group_id]["members"]
    # The granted tuple matches the retained grace-window material.
    retained = collection.group_key_for_epoch(group_id, 1)
    assert retained == {
        "key_epoch": 1,
        "master_secret": secret0,
        "master_salt": salt0,
        "key_id": f"key-{group_id}-001",
    }


@pytest.mark.asyncio
async def test_group_key_for_epoch_holds_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The grace prune (read-and-write-back of retired_epochs) runs locked."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)
    assert collection.rekey(group_id) == {
        "key_id": f"key-{group_id}-002",
        "key_epoch": 2,
    }

    original = collection._live_retired
    calls = 0

    def probing_retired(
        item: dict[str, Any], stamp: int, *, mutate: bool = False
    ) -> list[dict[str, Any]]:
        nonlocal calls
        calls += 1
        _assert_lock_held(collection)
        return original(item, stamp, mutate=mutate)

    monkeypatch.setattr(collection, "_live_retired", probing_retired)
    retained = collection.group_key_for_epoch(group_id, 1)
    assert calls == 1
    assert retained is not None
    assert retained["key_epoch"] == 1
    # Outside the critical section the same probe acquires cleanly.
    assert collection._mutation_lock.acquire(blocking=False) is True
    collection._mutation_lock.release()


@pytest.mark.asyncio
async def test_prune_and_rekey_do_not_lose_retired_entry() -> None:
    """An unlocked prune cannot clobber a rekey's concurrently retired entry.

    Whatever the interleave, the epoch-1 grace material survives both the
    rotation and the prune: the post-state answer for epoch 1 is identical
    to whatever the racing call returned.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)

    with ThreadPoolExecutor(max_workers=2) as executor:
        rotation = executor.submit(collection.rekey, group_id)
        raced = executor.submit(collection.group_key_for_epoch, group_id, 1)
        rotated = rotation.result()
        got = raced.result()

    assert rotated == {"key_id": f"key-{group_id}-002", "key_epoch": 2}
    assert got is None or got["key_epoch"] == 1
    retained = collection.group_key_for_epoch(group_id, 1)
    assert retained is not None
    assert retained["key_epoch"] == 1
    assert retained == got


@pytest.mark.asyncio
async def test_legacy_scalar_invitation_burn_persists_normalization() -> None:
    """Consuming a legacy scalar entry persists the normalized dict.

    The consumed marker must land on the stored invitation, not on a
    synthesized throwaway, or the one-time spend is silently lost.
    """
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    group_id = await _created_group(collection)
    expires = T0 + 600
    collection.groups[group_id]["invitations"] = {NEWCOMER: expires}

    assert collection.invitation_valid(group_id, NEWCOMER) is True
    assert collection.invitation_role(group_id, NEWCOMER) == "member"
    collection.consume_invitation(group_id, NEWCOMER)

    stored = collection.groups[group_id]["invitations"][NEWCOMER]
    assert stored == {"expires": expires, "role": "member", "consumed": True}
    assert collection.invitation_consumed(group_id, NEWCOMER) is True
    # Expiry survived normalization: still valid as an invitation document,
    # but the spend marker is durable for the replay check.
    assert collection.invitation_valid(group_id, NEWCOMER) is True


@pytest.mark.asyncio
async def test_join_key_consumes_legacy_scalar_invitation_persistently() -> None:
    """The join path's burn also normalizes-and-persists scalar entries."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: T0)
    item = GroupsItemResource(collection)
    group_id = await _created_group(collection)
    collection.groups[group_id]["invitations"] = {NEWCOMER: T0 + 600}

    grant = await item.render_post(
        _pairwise_post(
            {"request": "join_key", "node": NEWCOMER},
            path=(group_id, "key"),
            context=NEWCOMER,
        )
    )
    assert grant.code == aiocoap.CONTENT
    stored = collection.groups[group_id]["invitations"][NEWCOMER]
    assert stored == {"expires": T0 + 600, "role": "member", "consumed": True}
    assert collection.invitation_consumed(group_id, NEWCOMER) is True
    assert NEWCOMER in collection.groups[group_id]["members"]
