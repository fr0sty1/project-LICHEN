# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SqliteOscoreContextStore."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from aiocoap import Message
from aiocoap.oscore import Direction

from lichen.coap.secure import (
    ContextGenerationError,
    EndpointPolicyConflictError,
    PeerKeyConflictError,
    SecureDatagramChannel,
    SequenceReservationError,
    SqliteOscoreContextStore,
)
from lichen.coap.transport import EndpointPolicy, LichenRemote
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MAX_OSCORE_SEQUENCE_NUMBER

from .conftest_context_store import (
    SCOPED_POLICY,
    BlockBeforePin,
    BlockBeforeTransaction,
    BlockInTransaction,
    BlockMigrationInTransaction,
    FailAfterWrite,
    RecordingChannel,
    ReplayCasBarrier,
    duplicate_legacy_context,
    extract_partial_iv,
    incoming_protected,
    insert_legacy_pins,
    make_context,
    make_request,
    mark_sqlite_as_legacy,
    paired_contexts,
    protected_request,
    stored_host_keys,
)


def _fork_sqlite_channel_send(channel: SecureDatagramChannel, connection: object) -> None:
    async def run() -> int:
        await channel._send_protected(make_request(91), "Peer")
        inner = cast(RecordingChannel, channel._inner)
        return extract_partial_iv(inner.sent[-1][0])

    cast(Any, connection).send(asyncio.run(run()))
    cast(Any, connection).close()


@pytest.mark.asyncio
async def test_sqlite_legacy_identical_aliases_coalesce_on_first_operation(
    tmp_path: Path,
) -> None:
    """Verify identical legacy aliases coalesce to canonical form."""
    store = SqliteOscoreContextStore(tmp_path / "legacy-identical.sqlite3")
    insert_legacy_pins(store, [("Peer", b"peer-key"), ("peer", b"peer-key")])

    assert await store.get_peer_pubkey("PEER") == b"peer-key"
    await store.pin_peer("Peer", b"peer-key")

    assert stored_host_keys(store) == {"peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata == (EndpointPolicy().serialize(),)


@pytest.mark.asyncio
async def test_sqlite_legacy_conflicting_aliases_fail_without_mutation(
    tmp_path: Path,
) -> None:
    """Verify conflicting legacy aliases fail without mutating store."""
    store = SqliteOscoreContextStore(tmp_path / "legacy-conflict.sqlite3")
    insert_legacy_pins(store, [("Peer", b"key-a"), ("peer", b"key-b")])

    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.get_peer_pubkey("peer")
    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.pin_peer("peer", b"key-a")

    assert stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None


@pytest.mark.asyncio
async def test_sqlite_legacy_identical_context_aliases_coalesce(tmp_path: Path) -> None:
    """Verify identical legacy context aliases coalesce properly."""
    store = SqliteOscoreContextStore(tmp_path / "legacy-context.sqlite3")
    original = await store.put("peer", make_context(), b"peer-key")
    mark_sqlite_as_legacy(store)
    duplicate_legacy_context(store, "Peer")

    loaded = await store.get("PEER")

    assert loaded is not None
    assert loaded.generation == original.generation
    assert loaded.oscore.export_parameters() == original.oscore.export_parameters()
    assert stored_host_keys(store) == {"peer"}


@pytest.mark.asyncio
async def test_sqlite_legacy_context_generation_conflict_rolls_back(tmp_path: Path) -> None:
    """Verify generation conflicts during legacy coalescing roll back."""
    store = SqliteOscoreContextStore(tmp_path / "legacy-generation.sqlite3")
    await store.put("peer", make_context(), b"peer-key")
    mark_sqlite_as_legacy(store)
    duplicate_legacy_context(store, "Peer", generation=2)

    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.get("peer")

    assert stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None


@pytest.mark.asyncio
async def test_sqlite_legacy_two_handle_race_converges(tmp_path: Path) -> None:
    """Verify concurrent legacy migrations converge to same state."""
    path = tmp_path / "legacy-race.sqlite3"
    first = SqliteOscoreContextStore(path)
    second = SqliteOscoreContextStore(path)
    insert_legacy_pins(first, [("Peer", b"peer-key"), ("peer", b"peer-key")])

    loaded, pinned = await asyncio.gather(
        first.get_peer_pubkey("PEER"),
        second.pin_peer("peer", b"peer-key"),
    )

    assert loaded == b"peer-key"
    assert pinned is None
    assert stored_host_keys(first) == {"peer"}
    assert SqliteOscoreContextStore(path)._endpoint_policy == EndpointPolicy()


@pytest.mark.asyncio
async def test_sqlite_queued_alias_pin_uses_migrated_normalizer(tmp_path: Path) -> None:
    """Verify queued pin uses new normalizer after migration."""
    hooks = BlockBeforePin()
    store = SqliteOscoreContextStore(tmp_path / "queued-pin.sqlite3", hooks=hooks)
    pin = asyncio.create_task(store.pin_peer("fe80::1", b"peer-key"))
    await hooks.entered.wait()

    store.migrate_endpoint_keys(SCOPED_POLICY, {})
    hooks.release.set()
    await pin

    with sqlite3.connect(store._path) as connection:
        keys = [str(row[0]) for row in connection.execute("SELECT host FROM oscore_hosts")]
    assert keys == ["[fe80::1%ble0]"]
    assert await store.get_peer_pubkey("fe80::1") == b"peer-key"


@pytest.mark.asyncio
async def test_sqlite_queued_alias_put_uses_migrated_normalizer(tmp_path: Path) -> None:
    """Verify queued put uses new normalizer after migration."""
    hooks = BlockBeforeTransaction()
    hooks.enabled = True
    store = SqliteOscoreContextStore(tmp_path / "queued-put.sqlite3", hooks=hooks)
    put = asyncio.create_task(store.put("fe80::1", make_context(), b"peer-key"))
    await hooks.entered.wait()

    store.migrate_endpoint_keys(SCOPED_POLICY, {})
    hooks.release.set()
    published = await put

    assert stored_host_keys(store) == {"[fe80::1%ble0]"}
    assert set(store._cache) == {"[fe80::1%ble0]"}
    assert await store.get("fe80::1") is published


@pytest.mark.asyncio
async def test_sqlite_handles_share_persisted_endpoint_policy(tmp_path: Path) -> None:
    """Verify multiple handles share persisted endpoint policy."""
    path = tmp_path / "shared-policy.sqlite3"
    hooks = BlockBeforePin()
    first = SqliteOscoreContextStore(path)
    second = SqliteOscoreContextStore(path, hooks=hooks)
    original = await first.put("fe80::1", make_context(), b"context-key")
    assert await second.get("fe80::1") is not None
    mark_sqlite_as_legacy(first, second)
    queued_pin = asyncio.create_task(second.pin_peer("fe80::2", b"pin-key"))
    await hooks.entered.wait()

    first.migrate_endpoint_keys(SCOPED_POLICY, {})
    hooks.release.set()
    await queued_pin

    assert stored_host_keys(first) == {"[fe80::1%ble0]", "[fe80::2%ble0]"}
    migrated = await second.get("fe80::1")
    assert migrated is not None
    assert migrated.peer_pubkey == original.peer_pubkey
    assert set(second._cache) == {"[fe80::1%ble0]"}
    assert await second.get_peer_pubkey("fe80::2") == b"pin-key"
    with pytest.raises(PeerKeyConflictError):
        await second.pin_peer("fe80::2", b"different-key")

    incompatible = EndpointPolicy.owning_link_local("fe80::9%other")
    before = stored_host_keys(first)
    with pytest.raises(EndpointPolicyConflictError, match="incompatible"):
        second.migrate_endpoint_keys(incompatible, {"fe80::3": b"new-key"})
    assert stored_host_keys(first) == before
    assert await first.get_peer_pubkey("fe80::3") is None

    reopened = SqliteOscoreContextStore(path)
    assert reopened._endpoint_policy == SCOPED_POLICY
    assert await reopened.get("fe80::1") is not None
    await reopened.pin_peer("fe80::3", b"reopened-key")
    assert stored_host_keys(reopened) == {
        "[fe80::1%ble0]",
        "[fe80::2%ble0]",
        "[fe80::3%ble0]",
    }


def test_sqlite_compatible_policy_rebind_is_no_write(tmp_path: Path) -> None:
    """Verify compatible policy rebind doesn't write."""
    hooks = FailAfterWrite()
    store = SqliteOscoreContextStore(tmp_path / "idempotent-policy.sqlite3", hooks=hooks)
    store.migrate_endpoint_keys(SCOPED_POLICY, {})
    hooks.enabled = True

    store.migrate_endpoint_keys(SCOPED_POLICY, {})

    assert store._endpoint_policy == SCOPED_POLICY


@pytest.mark.asyncio
async def test_sqlite_unknown_policy_fails_closed_before_insert(tmp_path: Path) -> None:
    """Verify unknown policy version fails before inserting data."""
    store = SqliteOscoreContextStore(tmp_path / "unknown-policy.sqlite3")
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "INSERT INTO oscore_metadata (key, value) VALUES ('endpoint_policy', ?)",
            ('{"ipv6_only":true,"link_local_scope":null,"scope_mode":"owning","version":2}',),
        )

    with pytest.raises(ValueError, match="unsupported endpoint policy"):
        await store.pin_peer("fe80::1", b"peer-key")

    assert stored_host_keys(store) == set()


@pytest.mark.asyncio
async def test_sqlite_migration_write_failure_rolls_back(tmp_path: Path) -> None:
    """Verify migration write failure rolls back cleanly."""
    hooks = FailAfterWrite()
    store = SqliteOscoreContextStore(tmp_path / "migration-rollback.sqlite3", hooks=hooks)
    original = await store.put("fe80::1", make_context(), b"peer-key")
    mark_sqlite_as_legacy(store)
    hooks.enabled = True

    with pytest.raises(OSError, match="injected write failure"):
        store.migrate_endpoint_keys(SCOPED_POLICY, {})

    with sqlite3.connect(store._path) as connection:
        policy = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert policy is None
    hooks.enabled = False
    loaded = await store.get("fe80::1")
    assert loaded is not None
    assert loaded.oscore.export_parameters() == original.oscore.export_parameters()
    assert await store.get("[fe80::1%ble0]") is None
    assert await store.get_generation("fe80::1") == 1
    assert SqliteOscoreContextStore(store._path)._endpoint_policy == EndpointPolicy()


@pytest.mark.asyncio
async def test_sqlite_reopen_reconstructs_context(tmp_path: Path) -> None:
    """Verify reopened store reconstructs context correctly."""
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    original = make_context()
    published = await store.put("[fd00::1]", original, b"peer-key")
    assert published.generation == 1
    assert original.export_parameters().master_secret == b"s" * 16

    reopened = SqliteOscoreContextStore(path)
    loaded = await reopened.get("[fd00::1]")
    assert loaded is not None
    assert loaded.peer_pubkey == b"peer-key"
    assert loaded.generation == 1
    assert loaded.oscore.export_parameters() == original.export_parameters()
    assert loaded.oscore.sender_sequence_number == 0
    with pytest.raises(OverflowError, match="no durable"):
        loaded.oscore.new_sequence_number()


@pytest.mark.asyncio
async def test_sqlite_reads_legacy_string_algorithm_metadata(tmp_path: Path) -> None:
    """Verify store reads legacy string algorithm metadata."""
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    await store.put("peer", make_context(), b"peer-key")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE oscore_hosts SET algorithm_json = ? WHERE host = ?",
            ('"AES-CCM-16-64-128"', "peer"),
        )

    loaded = await SqliteOscoreContextStore(path).get("peer")

    assert loaded is not None
    assert loaded.oscore.export_parameters().algorithm == 10


@pytest.mark.asyncio
async def test_reg_name_case_aliases_collide_but_ports_do_not(tmp_path: Path) -> None:
    """Verify reg-name case aliases collide but ports don't."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("Peer", make_context(b"a" * 16), b"key-a")
    with pytest.raises(PeerKeyConflictError):
        await store.put("peer", make_context(b"b" * 16), b"key-b")
    await store.put("peer:61616", make_context(b"c" * 16), b"key-c")

    assert (await store.get_peer_pubkey("Peer")) == b"key-a"
    assert (await store.get_peer_pubkey("peer")) == b"key-a"
    assert (await store.get_peer_pubkey("peer:61616")) == b"key-c"


@pytest.mark.asyncio
async def test_partial_transaction_failure_preserves_old_record(tmp_path: Path) -> None:
    """Verify partial transaction failure preserves existing record."""
    hooks = FailAfterWrite()
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    await store.put("peer", make_context(b"a" * 16), b"peer-key")

    hooks.enabled = True
    with pytest.raises(OSError, match="injected write failure"):
        await store.put(
            "peer",
            make_context(b"b" * 16),
            b"peer-key",
            expected_generation=1,
        )

    loaded = await SqliteOscoreContextStore(path).get("peer")
    assert loaded is not None
    assert loaded.generation == 1
    assert loaded.oscore.export_parameters().master_secret == b"a" * 16


@pytest.mark.asyncio
async def test_cancellation_before_transaction_preserves_old_record(tmp_path: Path) -> None:
    """Verify cancellation before transaction preserves existing record."""
    hooks = BlockBeforeTransaction()
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    await store.put("peer", make_context(b"a" * 16), b"peer-key")

    hooks.enabled = True
    task = asyncio.create_task(
        store.put(
            "peer",
            make_context(b"b" * 16),
            b"peer-key",
            expected_generation=1,
        )
    )
    await hooks.entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    loaded = await SqliteOscoreContextStore(path).get("peer")
    assert loaded is not None
    assert loaded.generation == 1
    assert loaded.oscore.export_parameters().master_secret == b"a" * 16


@pytest.mark.asyncio
async def test_cancellation_after_transaction_start_returns_commit(tmp_path: Path) -> None:
    """Verify cancellation after transaction start returns committed result."""
    hooks = BlockInTransaction()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", make_context(), b"peer-key")

    hooks.enabled = True
    task = asyncio.create_task(store.reserve_sender_sequences("peer", 1, 4))
    assert await asyncio.to_thread(hooks.entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    hooks.release.set()
    reservation = await task
    assert (reservation.start, reservation.end) == (0, 4)
    assert task.cancelling() == 0

    reopened = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    loaded = await reopened.get("peer")
    assert loaded is not None
    assert loaded.oscore.sender_sequence_number == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get", "get_generation", "get_peer_pubkey"])
async def test_cancelled_sqlite_read_waits_for_legacy_migration_commit(
    method: str, tmp_path: Path
) -> None:
    """Verify cancelled read waits for legacy migration commit."""
    hooks = BlockMigrationInTransaction()
    path = tmp_path / f"cancel-{method}.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    original = await store.put("peer", make_context(), b"peer-key")
    mark_sqlite_as_legacy(store)
    duplicate_legacy_context(store, "Peer")
    other = SqliteOscoreContextStore(path)
    hooks.enabled = True

    task = asyncio.create_task(getattr(store, method)("PEER"))
    assert await asyncio.to_thread(hooks.entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    hooks.release.set()
    result = await task
    assert task.cancelling() == 0

    assert store._endpoint_policy == EndpointPolicy()
    assert stored_host_keys(store) == {"peer"}
    with sqlite3.connect(path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata == (EndpointPolicy().serialize(),)
    if method == "get":
        assert result is not None
        assert set(store._cache) == {"peer"}
        assert store._cache["peer"].oscore.export_parameters() == (
            original.oscore.export_parameters()
        )
    elif method == "get_generation":
        assert result == 1
    else:
        assert result == b"peer-key"
    assert await other.get_peer_pubkey("PEER") == b"peer-key"
    assert other._endpoint_policy == EndpointPolicy()


@pytest.mark.asyncio
async def test_cancelled_sqlite_read_waits_for_migration_rollback(tmp_path: Path) -> None:
    """Verify cancelled read waits for migration rollback."""
    hooks = BlockMigrationInTransaction()
    path = tmp_path / "cancel-rollback.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    original = await store.put("peer", make_context(), b"peer-key")
    mark_sqlite_as_legacy(store)
    duplicate_legacy_context(store, "Peer")
    hooks.enabled = True
    hooks.fail = True

    task = asyncio.create_task(store.get("PEER"))
    assert await asyncio.to_thread(hooks.entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    hooks.release.set()
    with pytest.raises(OSError, match="injected migration failure"):
        await task
    assert task.cancelling() == 0

    assert store._endpoint_policy is None
    assert store._cache == {"peer": original}
    assert stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None

    hooks.enabled = False
    store.migrate_endpoint_keys(EndpointPolicy(), {})
    assert stored_host_keys(store) == {"peer"}
    with pytest.raises(EndpointPolicyConflictError):
        store.migrate_endpoint_keys(SCOPED_POLICY, {})


@pytest.mark.asyncio
async def test_key_conflict_does_not_mutate_record(tmp_path: Path) -> None:
    """Verify key conflict doesn't mutate existing record."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("PEER", make_context(b"a" * 16), b"key-a")

    with pytest.raises(PeerKeyConflictError):
        await store.put(
            "PEER",
            make_context(b"b" * 16),
            b"key-b",
            expected_generation=1,
        )

    loaded = await store.get("PEER")
    assert loaded is not None
    assert loaded.peer_pubkey == b"key-a"
    assert loaded.oscore.export_parameters().master_secret == b"a" * 16


@pytest.mark.asyncio
async def test_context_replacement_rejects_stale_generation(tmp_path: Path) -> None:
    """Verify context replacement rejects stale generation."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", make_context(b"a" * 16), b"peer-key")
    replacement = await store.put("peer", make_context(b"b" * 16), b"peer-key", expected_generation=1)
    assert replacement.generation == 2

    with pytest.raises(ContextGenerationError):
        await store.put(
            "peer",
            make_context(b"c" * 16),
            b"peer-key",
            expected_generation=1,
        )

    loaded = await store.get("peer")
    assert loaded is not None
    assert loaded.generation == 2
    assert loaded.oscore.export_parameters().master_secret == b"b" * 16


@pytest.mark.asyncio
async def test_identical_material_replacement_preserves_high_water(tmp_path: Path) -> None:
    """Verify identical material replacement preserves high water mark."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", make_context(), b"peer-key")
    first = await store.reserve_sender_sequences("peer", 1, 4)
    assert (first.start, first.end) == (0, 4)

    replacement_context = make_context()
    replacement = await store.put("peer", replacement_context, b"peer-key", expected_generation=1)
    assert replacement.generation == 2
    assert replacement_context.sender_sequence_number == 4
    second = await store.reserve_sender_sequences("peer", 2, 4)
    assert (second.start, second.end) == (4, 8)


@pytest.mark.asyncio
async def test_concurrent_reservations_are_disjoint(tmp_path: Path) -> None:
    """Verify concurrent sequence reservations are disjoint."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", make_context(), b"peer-key")

    reservations = await asyncio.gather(
        *(store.reserve_sender_sequences("peer", 1, 4) for _ in range(3))
    )
    ranges = sorted((reservation.start, reservation.end) for reservation in reservations)
    assert ranges == [(0, 4), (4, 8), (8, 12)]


@pytest.mark.asyncio
async def test_crash_with_unused_block_skips_values_on_reopen(tmp_path: Path) -> None:
    """Verify crash with unused block skips values on reopen."""
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    await store.put("peer", make_context(), b"peer-key")
    context = await store.get("peer")
    assert context is not None
    first = await store.reserve_sender_sequences("peer", 1, 4)
    context.oscore.set_sender_sequence_reservation(first.start, first.end)
    assert context.oscore.new_sequence_number() == 0
    assert context.oscore.new_sequence_number() == 1

    reopened = SqliteOscoreContextStore(path)
    recovered = await reopened.get("peer")
    assert recovered is not None
    assert recovered.oscore.sender_sequence_number == 4
    second = await reopened.reserve_sender_sequences("peer", 1, 4)
    assert (second.start, second.end) == (4, 8)
    recovered.oscore.set_sender_sequence_reservation(second.start, second.end)
    assert recovered.oscore.new_sequence_number() == 4


@pytest.mark.asyncio
async def test_sequence_exhaustion_fails_before_nonce_return(tmp_path: Path) -> None:
    """Verify sequence exhaustion fails before returning nonce."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    context = make_context(starting_sequence=MAX_OSCORE_SEQUENCE_NUMBER)
    published = await store.put("peer", context, b"peer-key")
    reservation = await store.reserve_sender_sequences("peer", published.generation, 8)
    assert (reservation.start, reservation.end) == (
        MAX_OSCORE_SEQUENCE_NUMBER,
        MAX_OSCORE_SEQUENCE_NUMBER + 1,
    )
    context.set_sender_sequence_reservation(reservation.start, reservation.end)
    assert context.new_sequence_number() == MAX_OSCORE_SEQUENCE_NUMBER
    with pytest.raises(SequenceReservationError, match="exhausted"):
        await store.reserve_sender_sequences("peer", published.generation, 1)
    with pytest.raises(OverflowError, match="exhausted"):
        context.new_sequence_number()


@pytest.mark.asyncio
async def test_concurrent_sends_use_unique_committed_sequences(tmp_path: Path) -> None:
    """Verify concurrent sends use unique committed sequences."""
    inner = RecordingChannel()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    channel = SecureDatagramChannel(
        inner,
        Identity.generate(),
        context_store=store,
        sequence_reservation_size=3,
    )
    await channel.add_context("peer", make_context(), b"peer-key")

    await asyncio.gather(*(channel._send_protected(make_request(mid), "peer") for mid in range(20)))

    assert len(inner.sent) == 20
    assert [extract_partial_iv(datagram) for datagram, _ in inner.sent] == list(range(20))


@pytest.mark.asyncio
async def test_independent_channels_send_unique_sequences(tmp_path: Path) -> None:
    """Verify independent channels send unique sequences."""
    path = tmp_path / "contexts.sqlite3"
    await SqliteOscoreContextStore(path).put("peer", make_context(), b"peer-key")
    first_inner = RecordingChannel()
    second_inner = RecordingChannel()
    first = SecureDatagramChannel(
        first_inner,
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
        sequence_reservation_size=3,
    )
    second = SecureDatagramChannel(
        second_inner,
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
        sequence_reservation_size=3,
    )

    await asyncio.gather(
        *(first._send_protected(make_request(mid), "peer") for mid in range(10)),
        *(second._send_protected(make_request(mid), "peer") for mid in range(10, 20)),
    )

    partial_ivs = [extract_partial_iv(datagram) for datagram, _ in first_inner.sent + second_inner.sent]
    assert len(partial_ivs) == 20
    assert len(set(partial_ivs)) == 20


@pytest.mark.asyncio
async def test_sqlite_rotation_aba_resumes_permanent_sender_ledger(tmp_path: Path) -> None:
    """Verify rotation ABA pattern resumes permanent sender ledger."""
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    first_a = await store.put("peer", make_context(b"a" * 16), b"peer-key")
    first_range = await store.reserve_sender_sequences("peer", first_a.generation, 4)
    assert (first_range.start, first_range.end) == (0, 4)

    context_b = await store.put("peer", make_context(b"b" * 16), b"peer-key", expected_generation=1)
    b_range = await store.reserve_sender_sequences("peer", context_b.generation, 3)
    assert (b_range.start, b_range.end) == (0, 3)

    second_a_context = make_context(b"a" * 16, window_size=64)
    second_a = await store.put("peer", second_a_context, b"peer-key", expected_generation=2)
    assert second_a.generation == 3
    assert second_a_context.sender_sequence_number == 4
    second_range = await store.reserve_sender_sequences("peer", 3, 4)
    assert (second_range.start, second_range.end) == (4, 8)


@pytest.mark.asyncio
async def test_sqlite_remove_tombstone_rejects_stale_handle_and_aba(tmp_path: Path) -> None:
    """Verify remove tombstone rejects stale handle and ABA."""
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    first = await store.put("peer", make_context(), b"peer-key")
    await store.reserve_sender_sequences("peer", first.generation, 4)
    await store.remove("peer")

    assert await store.get("peer") is None
    assert await store.get_peer_pubkey("peer") == b"peer-key"
    assert await store.get_generation("peer") == 2
    with pytest.raises(ContextGenerationError):
        await store.reserve_sender_sequences("peer", first.generation, 1)
    with pytest.raises(ContextGenerationError):
        await store.put("peer", make_context(), b"peer-key", expected_generation=1)

    restored_context = make_context()
    restored = await store.put("peer", restored_context, b"peer-key", expected_generation=2)
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 4
    reopened = SqliteOscoreContextStore(path)
    assert await reopened.get_peer_pubkey("peer") == b"peer-key"


@pytest.mark.asyncio
async def test_exhausted_context_reopens_loaded_and_exhausted(tmp_path: Path) -> None:
    """Verify exhausted context reopens as loaded and exhausted."""
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    context = make_context(starting_sequence=MAX_OSCORE_SEQUENCE_NUMBER)
    published = await store.put("peer", context, b"peer-key")
    final_range = await store.reserve_sender_sequences("peer", published.generation, 2)
    context.set_sender_sequence_reservation(final_range.start, final_range.end)
    assert context.new_sequence_number() == MAX_OSCORE_SEQUENCE_NUMBER

    loaded = await SqliteOscoreContextStore(path).get("peer")
    assert loaded is not None
    assert loaded.oscore.sender_sequence_number == MAX_OSCORE_SEQUENCE_NUMBER + 1
    with pytest.raises(OverflowError, match="exhausted"):
        loaded.oscore.new_sequence_number()
    with pytest.raises(SequenceReservationError, match="exhausted"):
        await SqliteOscoreContextStore(path).reserve_sender_sequences("peer", loaded.generation, 1)


@pytest.mark.asyncio
async def test_replay_window_persists_across_reopen(tmp_path: Path) -> None:
    """Verify replay window persists across store reopen."""
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = paired_contexts()
    protected, wire = protected_request(sender)
    store = SqliteOscoreContextStore(path)
    await store.put("peer", recipient, b"peer-key")
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate(), context_store=store)

    assert await channel._unprotect(protected, "peer") is not None

    replay = Message.decode(wire, LichenRemote("peer"))
    replay.direction = Direction.INCOMING
    reopened_channel = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened_channel._unprotect(replay, "peer") is None


@pytest.mark.asyncio
async def test_replay_persistence_failure_drops_plaintext(tmp_path: Path) -> None:
    """Verify replay persistence failure drops plaintext."""
    hooks = FailAfterWrite()
    sender, recipient = paired_contexts()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", recipient, b"peer-key")
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate(), context_store=store)
    hooks.enabled = True

    protected, wire = protected_request(sender)
    assert await channel._unprotect(protected, "peer") is None
    hooks.enabled = False
    assert await channel._unprotect(incoming_protected(wire), "peer") is not None


@pytest.mark.asyncio
async def test_same_replay_packet_is_linearizable_across_stores(tmp_path: Path) -> None:
    """Verify same replay packet is linearizable across stores."""
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = paired_contexts()
    _, wire = protected_request(sender)
    await SqliteOscoreContextStore(path).put("peer", recipient, b"peer-key")
    barrier = ReplayCasBarrier()
    first = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path, hooks=barrier),
    )
    second = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path, hooks=barrier),
    )

    results = await asyncio.gather(
        first._unprotect(incoming_protected(wire), "peer"),
        second._unprotect(incoming_protected(wire), "peer"),
    )

    assert sum(result is not None for result in results) == 1
    reopened = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened._unprotect(incoming_protected(wire), "peer") is None


@pytest.mark.asyncio
async def test_different_replay_packets_conflict_without_erasure(tmp_path: Path) -> None:
    """Verify different replay packets conflict without erasure."""
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = paired_contexts()
    _, first_wire = protected_request(sender, mid=80, token=b"first")
    _, second_wire = protected_request(sender, mid=81, token=b"second")
    await SqliteOscoreContextStore(path).put("peer", recipient, b"peer-key")
    barrier = ReplayCasBarrier()
    channels = [
        SecureDatagramChannel(
            RecordingChannel(),
            Identity.generate(),
            context_store=SqliteOscoreContextStore(path, hooks=barrier),
        )
        for _ in range(2)
    ]

    results = await asyncio.gather(
        channels[0]._unprotect(incoming_protected(first_wire), "peer"),
        channels[1]._unprotect(incoming_protected(second_wire), "peer"),
    )
    assert sum(result is not None for result in results) == 1

    losing_index = 0 if results[0] is None else 1
    losing_wire = first_wire if losing_index == 0 else second_wire
    assert (
        await channels[losing_index]._unprotect(incoming_protected(losing_wire), "peer")
        is not None
    )

    reopened = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened._unprotect(incoming_protected(first_wire), "peer") is None
    assert await reopened._unprotect(incoming_protected(second_wire), "peer") is None


def test_sqlite_file_mode_owner_and_journal_security(tmp_path: Path) -> None:
    """Verify SQLite file mode and journal security."""
    path = tmp_path / "contexts.sqlite3"
    SqliteOscoreContextStore(path)
    assert path.stat().st_uid == os.geteuid()
    assert path.stat().st_mode & 0o777 == 0o600
    os.chmod(path, 0o644)

    SqliteOscoreContextStore(path)
    assert path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    assert not path.with_name(path.name + "-wal").exists()


def test_sqlite_rejects_insecure_parent(tmp_path: Path) -> None:
    """Verify SQLite rejects insecure parent directory."""
    insecure_parent = tmp_path / "shared"
    insecure_parent.mkdir(mode=0o700)
    os.chmod(insecure_parent, 0o777)

    with pytest.raises(PermissionError, match="group/other writable"):
        SqliteOscoreContextStore(insecure_parent / "contexts.sqlite3")


def test_sqlite_rejects_symlink_database_path(tmp_path: Path) -> None:
    """Verify SQLite rejects symlink database path."""
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = tmp_path / "contexts.sqlite3"
    symlink.symlink_to(target)

    with pytest.raises(ValueError, match="regular file"):
        SqliteOscoreContextStore(symlink)


def test_sqlite_accepts_secure_private_parent(tmp_path: Path) -> None:
    """Verify SQLite accepts secure private parent directory."""
    secure_parent = tmp_path / "private"
    secure_parent.mkdir(mode=0o700)

    store = SqliteOscoreContextStore(secure_parent / "contexts.sqlite3")

    assert store._path == str(secure_parent / "contexts.sqlite3")


@pytest.mark.asyncio
async def test_repeated_cancellation_returns_definitive_commit(tmp_path: Path) -> None:
    """Verify repeated cancellation returns definitive commit."""
    hooks = BlockInTransaction()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", make_context(), b"peer-key")
    hooks.enabled = True
    task = asyncio.create_task(store.reserve_sender_sequences("peer", 1, 4))
    assert await asyncio.to_thread(hooks.entered.wait, 5)
    for _ in range(5):
        task.cancel()
        await asyncio.sleep(0)
    hooks.release.set()

    reservation = await task
    assert (reservation.start, reservation.end) == (0, 4)
    assert task.cancelling() == 0
    loaded = await SqliteOscoreContextStore(tmp_path / "contexts.sqlite3").get("peer")
    assert loaded is not None
    assert loaded.oscore.sender_sequence_number == 4


def test_fork_sqlite_channel_discards_inherited_reservation(tmp_path: Path) -> None:
    """Verify forked process discards inherited reservation."""
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork start method unavailable")
    fork = multiprocessing.get_context("fork")
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    asyncio.run(store.put("Peer", make_context(), b"peer-key"))
    context = asyncio.run(store.get("Peer"))
    assert context is not None
    reservation = asyncio.run(store.reserve_sender_sequences("Peer", 1, 4))
    context.oscore.set_sender_sequence_reservation(reservation.start, reservation.end)
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate(), context_store=store)
    parent, child = fork.Pipe(duplex=False)
    process = fork.Process(target=_fork_sqlite_channel_send, args=(channel, child))
    process.start()
    child.close()
    assert parent.recv() == 4
    process.join(timeout=10)
    assert process.exitcode == 0
