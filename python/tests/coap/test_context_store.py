# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared and integration tests for OSCORE context-store and sender sequences."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from lichen.coap.secure import (
    ContextGenerationError,
    InMemoryOscoreContextStore,
    OscoreContextStore,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SecureDatagramChannel,
    SqliteOscoreContextStore,
    TofuPeerResolver,
    TransactionalOscoreContextStore,
    normalize_host,
    validate_endpoint_key,
)
from lichen.coap.transport import EndpointPolicy
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext

from .conftest_context_store import (
    SCOPED_POLICY,
    FailingReservationStore,
    IncompleteStore,
    RecordingChannel,
    RemoteInspectingContext,
    conforming_store,  # noqa: F401 - pytest fixture
    make_context,
    make_request,
    stored_host_keys,
)


def test_context_parameters_are_exact_reconstruction_inputs() -> None:
    """Verify context parameters match reconstruction inputs."""
    context = make_context()
    parameters = context.export_parameters()

    assert parameters.master_secret == b"s" * 16
    assert parameters.master_salt == b"salt1234"
    assert parameters.sender_id == b"\x01"
    assert parameters.recipient_id == b"\x02"
    assert parameters.algorithm == 10
    assert parameters.hashfun == "sha256"
    assert parameters.window_size == 17
    assert parameters.id_context == b"lichen-test"


@pytest.mark.asyncio
async def test_store_contract_conformance(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    """Verify store implementation conforms to interface contract."""
    store = conforming_store
    assert isinstance(store, TransactionalOscoreContextStore)
    await store.pin_peer("endpoint-a:61616", b"peer-key")
    await store.pin_peer("endpoint-a:61616", b"peer-key")
    context = make_context()
    published = await store.put("endpoint-a:61616", context, b"peer-key")
    assert published.generation == 1
    with pytest.raises(ContextGenerationError):
        await store.put("endpoint-a:61616", context, b"peer-key", expected_generation=0)
    idempotent = await store.put("endpoint-a:61616", context, b"peer-key", expected_generation=1)
    assert idempotent is published
    assert idempotent.generation == 1
    first = await store.reserve_sender_sequences("endpoint-a:61616", 1, 4)
    second = await store.reserve_sender_sequences("endpoint-a:61616", 1, 4)
    assert (first.start, first.end) == (0, 4)
    assert (second.start, second.end) == (4, 8)

    recipient_identity = published.oscore.recipient_cryptographic_identity()
    await store.compare_and_set_replay_window("endpoint-a:61616", 1, recipient_identity, 0, 0, 0, 1)
    with pytest.raises(ReplayWindowConflictError) as conflict:
        await store.compare_and_set_replay_window(
            "endpoint-a:61616", 1, recipient_identity, 0, 0, 0, 2
        )
    assert conflict.value.current_state == (0, 1)

    with pytest.raises(PeerKeyConflictError):
        await store.put(
            "endpoint-a:61616",
            make_context(b"b" * 16),
            b"other-key",
            expected_generation=1,
        )
    assert await store.get_peer_pubkey("endpoint-a:61616") == b"peer-key"
    assert await store.get_generation("endpoint-a:61616") == 1

    await store.remove("endpoint-a:61616")
    assert await store.get("endpoint-a:61616") is None
    assert await store.get_peer_pubkey("endpoint-a:61616") == b"peer-key"
    assert await store.get_generation("endpoint-a:61616") == 2
    restored_context = make_context()
    restored = await store.put(
        "endpoint-a:61616", restored_context, b"peer-key", expected_generation=2
    )
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 8


@pytest.mark.asyncio
async def test_batch_pin_late_conflict_is_atomic(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    """Verify batch pin with late conflict is atomic."""
    await conforming_store.pin_peer("existing", b"existing-key")

    with pytest.raises(PeerKeyConflictError):
        await conforming_store.pin_peers(
            {
                "new-peer": b"new-key",
                "existing": b"conflicting-key",
            }
        )

    assert await conforming_store.get_peer_pubkey("new-peer") is None
    assert await conforming_store.get_peer_pubkey("existing") == b"existing-key"


@pytest.mark.asyncio
async def test_context_alias_conflict_migration_rolls_back(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    """Verify context alias conflict during migration rolls back."""
    unscoped = await conforming_store.put("fe80::1", make_context(b"a" * 16), b"peer-key")
    scoped = await conforming_store.put("[fe80::1%ble0]", make_context(b"b" * 16), b"peer-key")
    if isinstance(conforming_store, SqliteOscoreContextStore):
        from .conftest_context_store import mark_sqlite_as_legacy

        mark_sqlite_as_legacy(conforming_store)

    with pytest.raises(PeerKeyConflictError, match="conflicting record"):
        conforming_store.migrate_endpoint_keys(SCOPED_POLICY, {})

    loaded_unscoped = await conforming_store.get("fe80::1")
    loaded_scoped = await conforming_store.get("[fe80::1%ble0]")
    if isinstance(conforming_store, InMemoryOscoreContextStore):
        assert loaded_unscoped is unscoped
        assert loaded_scoped is scoped
    else:
        assert loaded_unscoped is not None
        assert loaded_scoped is not None
        assert loaded_unscoped.oscore.export_parameters() == unscoped.oscore.export_parameters()
        assert loaded_scoped.oscore.export_parameters() == scoped.oscore.export_parameters()
    assert await conforming_store.get_generation("fe80::1") == 1
    assert await conforming_store.get_generation("[fe80::1%ble0]") == 1


@pytest.mark.asyncio
async def test_identical_context_aliases_coalesce_idempotently(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    """Verify identical context aliases coalesce idempotently."""
    await conforming_store.put("fe80::1", make_context(), b"peer-key")
    await conforming_store.put("[fe80::1%ble0]", make_context(), b"peer-key")
    if isinstance(conforming_store, SqliteOscoreContextStore):
        from .conftest_context_store import mark_sqlite_as_legacy

        mark_sqlite_as_legacy(conforming_store)

    conforming_store.migrate_endpoint_keys(SCOPED_POLICY, {})
    first = await conforming_store.get("[fe80::1%ble0]")
    conforming_store.migrate_endpoint_keys(SCOPED_POLICY, {})
    second = await conforming_store.get("[fe80::1%ble0]")

    assert await conforming_store.get("fe80::1") is first
    assert stored_host_keys(conforming_store) == {"[fe80::1%ble0]"}
    assert first is not None
    assert second is first
    assert second.generation == 1
    assert second.peer_pubkey == b"peer-key"


@pytest.mark.asyncio
async def test_malformed_scope_migration_preserves_store_state(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    """Verify malformed scope migration preserves store state."""
    store = conforming_store
    await store.pin_peer("pinned-peer", b"pin-key")
    published = await store.put("context-peer", make_context(), b"context-key")
    if isinstance(store, SqliteOscoreContextStore):
        assert await store.get("context-peer") is published
    original_hosts = stored_host_keys(store)
    original_policy = store._endpoint_policy

    for scope in (
        "",
        "bad@scope",
        "bad?scope",
        "bad#scope",
        "bad[scope",
        "bad]scope",
        "bad/scope",
        "bad scope",
        "bad\x00scope",
        "bad%scope",
        chr(0xD800),
    ):
        with pytest.raises(ValueError, match="scope"):
            store.migrate_endpoint_keys(
                EndpointPolicy(
                    scope_mode="owning",
                    link_local_scope=scope,
                    ipv6_only=True,
                ),
                {"new-pin": b"new-key"},
            )

        assert store._endpoint_policy == original_policy
        assert stored_host_keys(store) == original_hosts
        assert await store.get("context-peer") is published
        assert await store.get_generation("context-peer") == 1
        assert await store.get_peer_pubkey("pinned-peer") == b"pin-key"
        assert await store.get_peer_pubkey("new-pin") is None

    if isinstance(store, SqliteOscoreContextStore):
        import sqlite3

        with sqlite3.connect(store._path) as connection:
            metadata = connection.execute(
                "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
            ).fetchone()
        assert metadata == (EndpointPolicy().serialize(),)


@pytest.mark.asyncio
async def test_prebound_tofu_resolver_installs_legacy_default_policy(tmp_path: Path) -> None:
    """Verify prebound TOFU resolver installs legacy default policy."""
    store = SqliteOscoreContextStore(tmp_path / "legacy-resolver.sqlite3")
    from .conftest_context_store import insert_legacy_pins

    insert_legacy_pins(store, [("Peer", b"peer-key"), ("peer", b"peer-key")])
    resolver = TofuPeerResolver(store)

    assert await resolver.get_peer_pubkey("PEER") == b"peer-key"
    assert stored_host_keys(store) == {"peer"}
    assert SqliteOscoreContextStore(store._path)._endpoint_policy == EndpointPolicy()


def test_channel_rejects_incomplete_context_store() -> None:
    """Verify channel rejects incomplete context store."""
    with pytest.raises(TypeError, match="incomplete OSCORE context store"):
        SecureDatagramChannel(
            RecordingChannel(),
            Identity.generate(),
            context_store=cast(Any, IncompleteStore()),
        )


def test_public_oscore_context_store_is_concrete_memory_store() -> None:
    """Verify public OscoreContextStore is concrete memory store."""
    store = OscoreContextStore()

    assert isinstance(store, InMemoryOscoreContextStore)
    assert isinstance(store, TransactionalOscoreContextStore)


def test_endpoint_keys_are_canonical_authorities() -> None:
    """Verify endpoint keys are canonical authorities."""
    assert validate_endpoint_key("[FD00:0:0:0:0:0:0:1]") == "[fd00::1]"
    assert validate_endpoint_key("[fd00::1]:5683") == "[fd00::1]"
    assert validate_endpoint_key("[fd00::1]:61616") == "[fd00::1]:61616"
    assert validate_endpoint_key("fd00::1") == "[fd00::1]"
    assert validate_endpoint_key("Peer.Example.") == "peer.example."
    assert normalize_host("Case.Insensitive.") == "case.insensitive."
    for malformed in ("", "bad\x00endpoint", "ble://Adapter 0/Peer#1"):
        with pytest.raises(ValueError):
            validate_endpoint_key(malformed)


@pytest.mark.asyncio
async def test_oscore_context_ip_aliases_resolve_to_one_source_key() -> None:
    """Verify OSCORE context IP aliases resolve to one source key."""
    store = OscoreContextStore()
    published = await store.put(
        "[FD00:0:0:0:0:0:0:1]:61616",
        make_context(),
        b"peer-key",
    )

    loaded = await store.get("[fd00::1]:61616")

    assert loaded is published
    assert await store.get_generation("fd00::1") is None
    assert await store.get_generation("[fd00::1]:61616") == 1


@pytest.mark.asyncio
async def test_default_tofu_uses_context_store_binding() -> None:
    """Verify default TOFU uses context store binding."""
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate(), context_store=store)
    await channel.add_context("PEER", make_context(), b"peer-key")

    assert await channel._peer_resolver.get_peer_pubkey("PEER") == b"peer-key"
    assert await channel._peer_resolver.get_peer_pubkey("peer") == b"peer-key"


@pytest.mark.asyncio
async def test_sync_publication_rejects_after_async_store_use() -> None:
    """Verify sync publication rejects after async store use."""
    store = InMemoryOscoreContextStore()
    assert await store.get("peer") is None

    with pytest.raises(RuntimeError, match="before async store use"):
        store.put_sync("peer", make_context(), b"peer-key")


@pytest.mark.asyncio
async def test_failed_reservation_transmits_nothing() -> None:
    """Verify failed reservation transmits nothing."""
    inner = RecordingChannel()
    store = FailingReservationStore()
    channel = SecureDatagramChannel(inner, Identity.generate(), context_store=store)
    await channel.add_context("peer", make_context(), b"peer-key")

    await channel._send_protected(make_request(1), "peer")

    assert inner.sent == []


def test_sender_identity_ignores_replay_window_configuration() -> None:
    """Verify sender identity ignores replay window configuration."""
    first = make_context(window_size=17)
    second = make_context(window_size=64)

    assert first.sender_cryptographic_identity() == second.sender_cryptographic_identity()
    assert first.recipient_cryptographic_identity() == second.recipient_cryptographic_identity()

    without_context = MemorySecurityContext(
        b"s" * 16, b"salt1234", b"\x01", b"\x02", id_context=None
    )
    empty_context = MemorySecurityContext(b"s" * 16, b"salt1234", b"\x01", b"\x02", id_context=b"")
    assert (
        without_context.sender_cryptographic_identity()
        != empty_context.sender_cryptographic_identity()
    )


def test_ledger_identity_ignores_algorithm_implementation_metadata() -> None:
    """Verify ledger identity ignores algorithm implementation metadata."""
    original = make_context()
    renamed = make_context()
    equivalent_algorithm = type(
        "RenamedEquivalentAead",
        (),
        {"__module__": "replacement.crypto.backend", "value": 10},
    )()
    renamed.alg_aead = cast(Any, equivalent_algorithm)

    assert original.sender_cryptographic_identity() == renamed.sender_cryptographic_identity()
    assert original.recipient_cryptographic_identity() == renamed.recipient_cryptographic_identity()


@pytest.mark.asyncio
async def test_transport_canonicalizes_reg_name_destination(tmp_path: Path) -> None:
    """Verify transport canonicalizes reg-name destination."""
    inner = RecordingChannel()
    context = RemoteInspectingContext(
        master_secret=b"s" * 16,
        master_salt=b"salt1234",
        sender_id=b"\x01",
        recipient_id=b"\x02",
    )
    channel = SecureDatagramChannel(
        inner,
        Identity.generate(),
        context_store=SqliteOscoreContextStore(tmp_path / "contexts.sqlite3"),
    )
    await channel.add_context("Peer", context, b"peer-key")
    await channel._send_protected(make_request(1), "Peer")

    assert inner.sent[0][1] == "peer"
    assert context.protected_remote == "peer"


@pytest.mark.asyncio
async def test_send_datagram_rejects_invalid_host_synchronously() -> None:
    """Verify send_datagram rejects invalid host synchronously."""
    import asyncio

    channel = SecureDatagramChannel(RecordingChannel(), Identity.generate())

    with pytest.raises(ValueError, match="endpoint"):
        channel.send_datagram(make_request(1), "bad\x00host")
    await asyncio.sleep(0)


def test_empty_standalone_tofu_binds_to_channel_store() -> None:
    """Verify empty standalone TOFU binds to channel store."""
    store = InMemoryOscoreContextStore()
    resolver = TofuPeerResolver()
    channel = SecureDatagramChannel(
        RecordingChannel(), Identity.generate(), context_store=store, peer_resolver=resolver
    )

    assert channel._peer_resolver is resolver
    assert resolver._context_store is store
    assert resolver._pinned == {}


@pytest.mark.asyncio
async def test_prepopulated_standalone_tofu_migrates_transactionally() -> None:
    """Verify prepopulated standalone TOFU migrates transactionally."""
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Legacy", b"peer-key")
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )

    assert resolver._pinned == {}
    assert await channel._peer_resolver.get_peer_pubkey("Peer.Legacy") == b"peer-key"
    assert await store.get_peer_pubkey("Peer.Legacy") == b"peer-key"


@pytest.mark.asyncio
async def test_prepopulated_tofu_migrates_before_publication() -> None:
    """Verify prepopulated TOFU migrates before publication."""
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Publish", b"peer-key")
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(
        RecordingChannel(),
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )

    await channel.add_context("Peer.Publish", make_context(), b"peer-key")

    assert await store.get_peer_pubkey("Peer.Publish") == b"peer-key"
    assert await store.has_context("Peer.Publish")
    assert resolver._pinned == {}


@pytest.mark.asyncio
async def test_prepopulated_tofu_migration_conflict_fails_closed() -> None:
    """Verify prepopulated TOFU migration conflict fails closed."""
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Legacy", b"legacy-key")
    store = InMemoryOscoreContextStore()
    await store.pin_peer("Peer.Legacy", b"authoritative-key")
    with pytest.raises(PeerKeyConflictError):
        SecureDatagramChannel(
            RecordingChannel(),
            Identity.generate(),
            context_store=store,
            peer_resolver=resolver,
        )
    assert await store.get_peer_pubkey("Peer.Legacy") == b"authoritative-key"
    assert resolver._pinned == {"peer.legacy": b"legacy-key"}
    assert resolver._context_store is None
    assert resolver._endpoint_policy is None


def test_tofu_bound_to_different_store_is_incompatible() -> None:
    """Verify TOFU bound to different store is incompatible."""
    resolver = TofuPeerResolver(InMemoryOscoreContextStore())

    with pytest.raises(ValueError, match="different context store"):
        SecureDatagramChannel(
            RecordingChannel(),
            Identity.generate(),
            context_store=InMemoryOscoreContextStore(),
            peer_resolver=resolver,
        )
