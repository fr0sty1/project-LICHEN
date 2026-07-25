# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for InMemoryOscoreContextStore."""

from __future__ import annotations

import asyncio
import multiprocessing
from typing import Any, cast

import pytest

from lichen.coap.secure import (
    ForkSafetyError,
    InMemoryOscoreContextStore,
    PeerKeyConflictError,
)

from .conftest_context_store import SCOPED_POLICY, make_context


def _fork_memory_store_get(store: InMemoryOscoreContextStore, connection: object) -> None:
    async def run() -> str:
        try:
            await store.get("peer")
        except ForkSafetyError:
            return "fork-safe"
        return "unsafe"

    cast(Any, connection).send(asyncio.run(run()))
    cast(Any, connection).close()


@pytest.mark.asyncio
async def test_memory_case_aliases_have_one_canonical_record() -> None:
    """Verify case-insensitive aliases share a single canonical record."""
    store = InMemoryOscoreContextStore()
    await store.pin_peer("Peer", b"peer-key")
    await store.pin_peer("peer", b"peer-key")

    assert set(store._records) == {"peer"}
    with pytest.raises(PeerKeyConflictError):
        await store.pin_peer("PEER", b"different-key")
    assert set(store._records) == {"peer"}


@pytest.mark.asyncio
async def test_memory_queued_alias_pin_uses_migrated_normalizer() -> None:
    """Verify queued pin operations use the new normalizer after migration."""
    store = InMemoryOscoreContextStore()
    pin = asyncio.create_task(store.pin_peer("fe80::1", b"peer-key"))

    store.migrate_endpoint_keys(SCOPED_POLICY, {})
    await pin

    assert set(store._records) == {"[fe80::1%ble0]"}
    assert await store.get_peer_pubkey("fe80::1") == b"peer-key"


@pytest.mark.asyncio
async def test_in_memory_remove_preserves_pin_generation_and_ledgers() -> None:
    """Verify remove preserves pin, generation, and ledger state."""
    store = InMemoryOscoreContextStore()
    first = await store.put("peer", make_context(b"a" * 16), b"peer-key")
    assert (await store.reserve_sender_sequences("peer", first.generation, 4)).end == 4

    await store.remove("peer")
    assert await store.get("peer") is None
    assert await store.get_peer_pubkey("peer") == b"peer-key"
    assert await store.get_generation("peer") == 2
    from lichen.coap.secure import ContextGenerationError

    with pytest.raises(ContextGenerationError):
        await store.reserve_sender_sequences("peer", 1, 1)
    with pytest.raises(PeerKeyConflictError):
        await store.put("peer", make_context(b"a" * 16), b"different-key", expected_generation=2)

    restored_context = make_context(b"a" * 16)
    restored = await store.put("peer", restored_context, b"peer-key", expected_generation=2)
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 4


def test_fork_in_memory_store_fails_closed() -> None:
    """Verify forked processes cannot access in-memory store."""
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork start method unavailable")
    fork = multiprocessing.get_context("fork")
    store = InMemoryOscoreContextStore()
    asyncio.run(store.put("peer", make_context(), b"peer-key"))
    parent, child = fork.Pipe(duplex=False)
    process = fork.Process(target=_fork_memory_store_get, args=(store, child))
    process.start()
    child.close()
    assert parent.recv() == "fork-safe"
    process.join(timeout=10)
    assert process.exitcode == 0
