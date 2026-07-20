# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Transactional OSCORE context-store and sender sequence tests."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from aiocoap import GET, Message
from aiocoap.numbers import types
from aiocoap.oscore import Direction

from lichen.coap.secure import (
    ContextGenerationError,
    EndpointPolicyConflictError,
    ForkSafetyError,
    InMemoryOscoreContextStore,
    OscoreContextStore,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SecureDatagramChannel,
    SequenceReservation,
    SequenceReservationError,
    SqliteOscoreContextStore,
    SqliteStoreHooks,
    TofuPeerResolver,
    TransactionalOscoreContextStore,
    normalize_host,
    validate_endpoint_key,
)
from lichen.coap.transport import (
    DatagramChannel,
    EndpointPolicy,
    LichenRemote,
    ReceiveCallback,
)
from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MAX_OSCORE_SEQUENCE_NUMBER, MemorySecurityContext


def _context(
    secret: bytes = b"s" * 16,
    *,
    starting_sequence: int = 0,
    window_size: int = 17,
) -> MemorySecurityContext:
    return MemorySecurityContext(
        master_secret=secret,
        master_salt=b"salt1234",
        sender_id=b"\x01",
        recipient_id=b"\x02",
        window_size=window_size,
        id_context=b"lichen-test",
        starting_sequence_number=starting_sequence,
    )


class _FailAfterWrite(SqliteStoreHooks):
    def __init__(self) -> None:
        self.enabled = False

    def transaction_step(self, operation: str, step: str) -> None:
        if (
            self.enabled
            and operation in {"put", "replay_cas", "migrate"}
            and step == "after_write"
        ):
            raise OSError("injected write failure")


class _BlockBeforeTransaction(SqliteStoreHooks):
    def __init__(self) -> None:
        self.enabled = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def before_transaction(self, operation: str, host: str) -> None:
        if self.enabled and operation == "put":
            self.entered.set()
            await self.release.wait()


class _BlockBeforePin(SqliteStoreHooks):
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def before_transaction(self, operation: str, host: str) -> None:
        if operation == "pin_batch":
            self.entered.set()
            await self.release.wait()


class _BlockInTransaction(SqliteStoreHooks):
    def __init__(self) -> None:
        self.enabled = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def transaction_step(self, operation: str, step: str) -> None:
        if self.enabled and operation == "reserve" and step == "after_write":
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("transaction test release timed out")


class _BlockMigrationInTransaction(SqliteStoreHooks):
    def __init__(self) -> None:
        self.enabled = False
        self.fail = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def transaction_step(self, operation: str, step: str) -> None:
        if self.enabled and operation == "migrate" and step == "after_write":
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("migration test release timed out")
            if self.fail:
                raise OSError("injected migration failure")


class _ReplayCasBarrier(SqliteStoreHooks):
    def __init__(self) -> None:
        self.arrivals = 0
        self.release = asyncio.Event()

    async def before_transaction(self, operation: str, host: str) -> None:
        if operation != "replay_cas" or self.arrivals >= 2:
            return
        self.arrivals += 1
        if self.arrivals == 2:
            self.release.set()
        await self.release.wait()


class _RecordingChannel(DatagramChannel):
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str]] = []

    def send_datagram(self, data: bytes, dest: str) -> None:
        self.sent.append((data, dest))

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self.receiver = receiver

    def close(self) -> None:
        pass


class _RemoteInspectingContext(MemorySecurityContext):
    protected_remote: str | None = None

    def protect(self, message: Any, request_id: Any = None) -> Any:
        self.protected_remote = message.remote.hostinfo
        return super().protect(message, request_id)


class _FailingReservationStore(InMemoryOscoreContextStore):
    async def reserve_sender_sequences(
        self, host: str, generation: int, count: int
    ) -> SequenceReservation:
        raise SequenceReservationError("injected reservation failure")


class _IncompleteStore:
    def check_process(self) -> None:
        pass


@pytest.fixture(params=("memory", "sqlite"))
def conforming_store(
    request: pytest.FixtureRequest, tmp_path: Path
) -> TransactionalOscoreContextStore:
    if request.param == "memory":
        return InMemoryOscoreContextStore()
    return SqliteOscoreContextStore(tmp_path / "conformance.sqlite3")


def _request(mid: int) -> bytes:
    message = Message(code=GET)
    message.token = mid.to_bytes(2, "big")
    message.mtype = types.NON
    message.mid = mid
    message.remote = LichenRemote("peer")
    message.direction = Direction.OUTGOING
    return cast(bytes, message.encode())


_SCOPED_POLICY = EndpointPolicy.owning_link_local("fe80::2%ble0")


def _stored_host_keys(store: TransactionalOscoreContextStore) -> set[str]:
    if isinstance(store, InMemoryOscoreContextStore):
        return set(store._records)
    sqlite_store = cast(SqliteOscoreContextStore, store)
    with sqlite3.connect(sqlite_store._path) as connection:
        return {str(row[0]) for row in connection.execute("SELECT host FROM oscore_hosts")}


def _insert_legacy_pins(
    store: SqliteOscoreContextStore, rows: list[tuple[str, bytes]]
) -> None:
    with sqlite3.connect(store._path) as connection:
        connection.executemany(
            "INSERT INTO oscore_hosts (host, peer_pubkey) VALUES (?, ?)", rows
        )


def _mark_sqlite_as_legacy(*stores: SqliteOscoreContextStore) -> None:
    if not stores:
        return
    with sqlite3.connect(stores[0]._path) as connection:
        connection.execute("DELETE FROM oscore_metadata WHERE key = 'endpoint_policy'")
    for store in stores:
        store._endpoint_policy = None


def _duplicate_legacy_context(
    store: SqliteOscoreContextStore, alias: str, *, generation: int | None = None
) -> None:
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "INSERT INTO oscore_hosts (host, peer_pubkey, master_secret, master_salt, "
            "sender_id, recipient_id, algorithm_json, hashfun, window_size, id_context, "
            "sender_identity, recipient_identity, generation) "
            "SELECT ?, peer_pubkey, master_secret, master_salt, sender_id, recipient_id, "
            "algorithm_json, hashfun, window_size, id_context, sender_identity, "
            "recipient_identity, COALESCE(?, generation) FROM oscore_hosts WHERE host = 'peer'",
            (alias, generation),
        )


def _partial_iv(datagram: bytes) -> int:
    protected = Message.decode(datagram, LichenRemote("peer"))
    option: bytes | None = protected.opt.oscore
    assert option is not None
    length = option[0] & 0x07
    assert length > 0
    return int.from_bytes(option[1 : 1 + length], "big")


def _paired_contexts() -> tuple[MemorySecurityContext, MemorySecurityContext]:
    initiator_identity = Identity.generate()
    responder_identity = Identity.generate()
    initiator = EdhocInitiator.create(initiator_identity, c_i=b"\x00")
    responder = EdhocResponder.create(responder_identity, c_r=b"\x01")
    message_1 = initiator.create_message_1()
    message_2 = responder.process_message_1(message_1, initiator_identity.pubkey)
    message_3 = initiator.process_message_2(message_2, responder_identity.pubkey)
    responder.process_message_3(message_3, initiator_identity.pubkey)
    return (
        MemorySecurityContext.from_edhoc(initiator.export_oscore()),
        MemorySecurityContext.from_edhoc(responder.export_oscore()),
    )


def _protected_request(
    sender: MemorySecurityContext,
    *,
    mid: int = 77,
    token: bytes = b"replay",
) -> tuple[Message, bytes]:
    plaintext = Message(code=GET)
    plaintext.mtype = types.NON
    plaintext.mid = mid
    plaintext.token = token
    plaintext.remote = LichenRemote("peer")
    plaintext.direction = Direction.OUTGOING
    protected, _ = sender.protect(plaintext)
    protected.mtype = plaintext.mtype
    protected.mid = plaintext.mid
    protected.remote = LichenRemote("peer")
    encoded = cast(bytes, protected.encode())
    incoming = Message.decode(encoded, LichenRemote("peer"))
    incoming.direction = Direction.INCOMING
    return incoming, encoded


def _incoming_protected(wire: bytes, endpoint: str = "peer") -> Message:
    message = Message.decode(wire, LichenRemote(endpoint))
    message.direction = Direction.INCOMING
    return message


def _fork_sqlite_channel_send(channel: SecureDatagramChannel, connection: object) -> None:
    async def run() -> int:
        await channel._send_protected(_request(91), "Peer")
        inner = cast(_RecordingChannel, channel._inner)
        return _partial_iv(inner.sent[-1][0])

    cast(Any, connection).send(asyncio.run(run()))
    cast(Any, connection).close()


def _fork_memory_store_get(store: InMemoryOscoreContextStore, connection: object) -> None:
    async def run() -> str:
        try:
            await store.get("peer")
        except ForkSafetyError:
            return "fork-safe"
        return "unsafe"

    cast(Any, connection).send(asyncio.run(run()))
    cast(Any, connection).close()


def test_context_parameters_are_exact_reconstruction_inputs() -> None:
    context = _context()
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
    store = conforming_store
    assert isinstance(store, TransactionalOscoreContextStore)
    await store.pin_peer("endpoint-a:61616", b"peer-key")
    await store.pin_peer("endpoint-a:61616", b"peer-key")
    context = _context()
    published = await store.put("endpoint-a:61616", context, b"peer-key")
    assert published.generation == 1
    with pytest.raises(ContextGenerationError):
        await store.put("endpoint-a:61616", context, b"peer-key", expected_generation=0)
    idempotent = await store.put(
        "endpoint-a:61616", context, b"peer-key", expected_generation=1
    )
    assert idempotent is published
    assert idempotent.generation == 1
    first = await store.reserve_sender_sequences("endpoint-a:61616", 1, 4)
    second = await store.reserve_sender_sequences("endpoint-a:61616", 1, 4)
    assert (first.start, first.end) == (0, 4)
    assert (second.start, second.end) == (4, 8)

    recipient_identity = published.oscore.recipient_cryptographic_identity()
    await store.compare_and_set_replay_window(
        "endpoint-a:61616", 1, recipient_identity, 0, 0, 0, 1
    )
    with pytest.raises(ReplayWindowConflictError) as conflict:
        await store.compare_and_set_replay_window(
            "endpoint-a:61616", 1, recipient_identity, 0, 0, 0, 2
        )
    assert conflict.value.current_state == (0, 1)

    with pytest.raises(PeerKeyConflictError):
        await store.put(
            "endpoint-a:61616",
            _context(b"b" * 16),
            b"other-key",
            expected_generation=1,
        )
    assert await store.get_peer_pubkey("endpoint-a:61616") == b"peer-key"
    assert await store.get_generation("endpoint-a:61616") == 1

    await store.remove("endpoint-a:61616")
    assert await store.get("endpoint-a:61616") is None
    assert await store.get_peer_pubkey("endpoint-a:61616") == b"peer-key"
    assert await store.get_generation("endpoint-a:61616") == 2
    restored_context = _context()
    restored = await store.put(
        "endpoint-a:61616", restored_context, b"peer-key", expected_generation=2
    )
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 8


@pytest.mark.asyncio
async def test_batch_pin_late_conflict_is_atomic(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
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
async def test_memory_case_aliases_have_one_canonical_record() -> None:
    store = InMemoryOscoreContextStore()
    await store.pin_peer("Peer", b"peer-key")
    await store.pin_peer("peer", b"peer-key")

    assert set(store._records) == {"peer"}
    with pytest.raises(PeerKeyConflictError):
        await store.pin_peer("PEER", b"different-key")
    assert set(store._records) == {"peer"}


@pytest.mark.asyncio
async def test_sqlite_legacy_identical_aliases_coalesce_on_first_operation(
    tmp_path: Path,
) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-identical.sqlite3")
    _insert_legacy_pins(store, [("Peer", b"peer-key"), ("peer", b"peer-key")])

    assert await store.get_peer_pubkey("PEER") == b"peer-key"
    await store.pin_peer("Peer", b"peer-key")

    assert _stored_host_keys(store) == {"peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata == (EndpointPolicy().serialize(),)


@pytest.mark.asyncio
async def test_sqlite_legacy_conflicting_aliases_fail_without_mutation(
    tmp_path: Path,
) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-conflict.sqlite3")
    _insert_legacy_pins(store, [("Peer", b"key-a"), ("peer", b"key-b")])

    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.get_peer_pubkey("peer")
    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.pin_peer("peer", b"key-a")

    assert _stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None


@pytest.mark.asyncio
async def test_sqlite_legacy_identical_context_aliases_coalesce(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-context.sqlite3")
    original = await store.put("peer", _context(), b"peer-key")
    _mark_sqlite_as_legacy(store)
    _duplicate_legacy_context(store, "Peer")

    loaded = await store.get("PEER")

    assert loaded is not None
    assert loaded.generation == original.generation
    assert loaded.oscore.export_parameters() == original.oscore.export_parameters()
    assert _stored_host_keys(store) == {"peer"}


@pytest.mark.asyncio
async def test_sqlite_legacy_context_generation_conflict_rolls_back(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-generation.sqlite3")
    await store.put("peer", _context(), b"peer-key")
    _mark_sqlite_as_legacy(store)
    _duplicate_legacy_context(store, "Peer", generation=2)

    with pytest.raises(PeerKeyConflictError, match="legacy endpoint aliases"):
        await store.get("peer")

    assert _stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(store._path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None


@pytest.mark.asyncio
async def test_prebound_tofu_resolver_installs_legacy_default_policy(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-resolver.sqlite3")
    _insert_legacy_pins(store, [("Peer", b"peer-key"), ("peer", b"peer-key")])
    resolver = TofuPeerResolver(store)

    assert await resolver.get_peer_pubkey("PEER") == b"peer-key"
    assert _stored_host_keys(store) == {"peer"}
    assert SqliteOscoreContextStore(store._path)._endpoint_policy == EndpointPolicy()


@pytest.mark.asyncio
async def test_sqlite_legacy_two_handle_race_converges(tmp_path: Path) -> None:
    path = tmp_path / "legacy-race.sqlite3"
    first = SqliteOscoreContextStore(path)
    second = SqliteOscoreContextStore(path)
    _insert_legacy_pins(first, [("Peer", b"peer-key"), ("peer", b"peer-key")])

    loaded, pinned = await asyncio.gather(
        first.get_peer_pubkey("PEER"),
        second.pin_peer("peer", b"peer-key"),
    )

    assert loaded == b"peer-key"
    assert pinned is None
    assert _stored_host_keys(first) == {"peer"}
    assert SqliteOscoreContextStore(path)._endpoint_policy == EndpointPolicy()


@pytest.mark.asyncio
async def test_context_alias_conflict_migration_rolls_back(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    unscoped = await conforming_store.put("fe80::1", _context(b"a" * 16), b"peer-key")
    scoped = await conforming_store.put(
        "[fe80::1%ble0]", _context(b"b" * 16), b"peer-key"
    )
    if isinstance(conforming_store, SqliteOscoreContextStore):
        _mark_sqlite_as_legacy(conforming_store)

    with pytest.raises(PeerKeyConflictError, match="conflicting record"):
        conforming_store.migrate_endpoint_keys(_SCOPED_POLICY, {})

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
    await conforming_store.put("fe80::1", _context(), b"peer-key")
    await conforming_store.put("[fe80::1%ble0]", _context(), b"peer-key")
    if isinstance(conforming_store, SqliteOscoreContextStore):
        _mark_sqlite_as_legacy(conforming_store)

    conforming_store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    first = await conforming_store.get("[fe80::1%ble0]")
    conforming_store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    second = await conforming_store.get("[fe80::1%ble0]")

    assert await conforming_store.get("fe80::1") is first
    assert _stored_host_keys(conforming_store) == {"[fe80::1%ble0]"}
    assert first is not None
    assert second is first
    assert second.generation == 1
    assert second.peer_pubkey == b"peer-key"


@pytest.mark.asyncio
async def test_memory_queued_alias_pin_uses_migrated_normalizer() -> None:
    store = InMemoryOscoreContextStore()
    pin = asyncio.create_task(store.pin_peer("fe80::1", b"peer-key"))

    store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    await pin

    assert set(store._records) == {"[fe80::1%ble0]"}
    assert await store.get_peer_pubkey("fe80::1") == b"peer-key"


@pytest.mark.asyncio
async def test_sqlite_queued_alias_pin_uses_migrated_normalizer(tmp_path: Path) -> None:
    hooks = _BlockBeforePin()
    store = SqliteOscoreContextStore(tmp_path / "queued-pin.sqlite3", hooks=hooks)
    pin = asyncio.create_task(store.pin_peer("fe80::1", b"peer-key"))
    await hooks.entered.wait()

    store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    hooks.release.set()
    await pin

    with sqlite3.connect(store._path) as connection:
        keys = [str(row[0]) for row in connection.execute("SELECT host FROM oscore_hosts")]
    assert keys == ["[fe80::1%ble0]"]
    assert await store.get_peer_pubkey("fe80::1") == b"peer-key"


@pytest.mark.asyncio
async def test_sqlite_queued_alias_put_uses_migrated_normalizer(tmp_path: Path) -> None:
    hooks = _BlockBeforeTransaction()
    hooks.enabled = True
    store = SqliteOscoreContextStore(tmp_path / "queued-put.sqlite3", hooks=hooks)
    put = asyncio.create_task(store.put("fe80::1", _context(), b"peer-key"))
    await hooks.entered.wait()

    store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    hooks.release.set()
    published = await put

    assert _stored_host_keys(store) == {"[fe80::1%ble0]"}
    assert set(store._cache) == {"[fe80::1%ble0]"}
    assert await store.get("fe80::1") is published


@pytest.mark.asyncio
async def test_sqlite_handles_share_persisted_endpoint_policy(tmp_path: Path) -> None:
    path = tmp_path / "shared-policy.sqlite3"
    hooks = _BlockBeforePin()
    first = SqliteOscoreContextStore(path)
    second = SqliteOscoreContextStore(path, hooks=hooks)
    original = await first.put("fe80::1", _context(), b"context-key")
    assert await second.get("fe80::1") is not None
    _mark_sqlite_as_legacy(first, second)
    queued_pin = asyncio.create_task(second.pin_peer("fe80::2", b"pin-key"))
    await hooks.entered.wait()

    first.migrate_endpoint_keys(_SCOPED_POLICY, {})
    hooks.release.set()
    await queued_pin

    assert _stored_host_keys(first) == {"[fe80::1%ble0]", "[fe80::2%ble0]"}
    migrated = await second.get("fe80::1")
    assert migrated is not None
    assert migrated.peer_pubkey == original.peer_pubkey
    assert set(second._cache) == {"[fe80::1%ble0]"}
    assert await second.get_peer_pubkey("fe80::2") == b"pin-key"
    with pytest.raises(PeerKeyConflictError):
        await second.pin_peer("fe80::2", b"different-key")

    incompatible = EndpointPolicy.owning_link_local("fe80::9%other")
    before = _stored_host_keys(first)
    with pytest.raises(EndpointPolicyConflictError, match="incompatible"):
        second.migrate_endpoint_keys(incompatible, {"fe80::3": b"new-key"})
    assert _stored_host_keys(first) == before
    assert await first.get_peer_pubkey("fe80::3") is None

    reopened = SqliteOscoreContextStore(path)
    assert reopened._endpoint_policy == _SCOPED_POLICY
    assert await reopened.get("fe80::1") is not None
    await reopened.pin_peer("fe80::3", b"reopened-key")
    assert _stored_host_keys(reopened) == {
        "[fe80::1%ble0]",
        "[fe80::2%ble0]",
        "[fe80::3%ble0]",
    }


def test_sqlite_compatible_policy_rebind_is_no_write(tmp_path: Path) -> None:
    hooks = _FailAfterWrite()
    store = SqliteOscoreContextStore(tmp_path / "idempotent-policy.sqlite3", hooks=hooks)
    store.migrate_endpoint_keys(_SCOPED_POLICY, {})
    hooks.enabled = True

    store.migrate_endpoint_keys(_SCOPED_POLICY, {})

    assert store._endpoint_policy == _SCOPED_POLICY


@pytest.mark.asyncio
async def test_sqlite_unknown_policy_fails_closed_before_insert(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "unknown-policy.sqlite3")
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "INSERT INTO oscore_metadata (key, value) VALUES ('endpoint_policy', ?)",
            ('{"ipv6_only":true,"link_local_scope":null,"scope_mode":"owning",'
             '"version":2}',),
        )

    with pytest.raises(ValueError, match="unsupported endpoint policy"):
        await store.pin_peer("fe80::1", b"peer-key")

    assert _stored_host_keys(store) == set()


@pytest.mark.asyncio
async def test_malformed_scope_migration_preserves_store_state(
    conforming_store: TransactionalOscoreContextStore,
) -> None:
    store = conforming_store
    await store.pin_peer("pinned-peer", b"pin-key")
    published = await store.put("context-peer", _context(), b"context-key")
    if isinstance(store, SqliteOscoreContextStore):
        assert await store.get("context-peer") is published
    original_hosts = _stored_host_keys(store)
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
        assert _stored_host_keys(store) == original_hosts
        assert await store.get("context-peer") is published
        assert await store.get_generation("context-peer") == 1
        assert await store.get_peer_pubkey("pinned-peer") == b"pin-key"
        assert await store.get_peer_pubkey("new-pin") is None

    if isinstance(store, SqliteOscoreContextStore):
        with sqlite3.connect(store._path) as connection:
            metadata = connection.execute(
                "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
            ).fetchone()
        assert metadata == (EndpointPolicy().serialize(),)


@pytest.mark.asyncio
async def test_sqlite_migration_write_failure_rolls_back(tmp_path: Path) -> None:
    hooks = _FailAfterWrite()
    store = SqliteOscoreContextStore(tmp_path / "migration-rollback.sqlite3", hooks=hooks)
    original = await store.put("fe80::1", _context(), b"peer-key")
    _mark_sqlite_as_legacy(store)
    hooks.enabled = True

    with pytest.raises(OSError, match="injected write failure"):
        store.migrate_endpoint_keys(_SCOPED_POLICY, {})

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


def test_channel_rejects_incomplete_context_store() -> None:
    with pytest.raises(TypeError, match="incomplete OSCORE context store"):
        SecureDatagramChannel(
            _RecordingChannel(),
            Identity.generate(),
            context_store=cast(Any, _IncompleteStore()),
        )


def test_public_oscore_context_store_is_concrete_memory_store() -> None:
    store = OscoreContextStore()

    assert isinstance(store, InMemoryOscoreContextStore)
    assert isinstance(store, TransactionalOscoreContextStore)


def test_endpoint_keys_are_canonical_authorities() -> None:
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
    store = OscoreContextStore()
    published = await store.put(
        "[FD00:0:0:0:0:0:0:1]:61616",
        _context(),
        b"peer-key",
    )

    loaded = await store.get("[fd00::1]:61616")

    assert loaded is published
    assert await store.get_generation("fd00::1") is None
    assert await store.get_generation("[fd00::1]:61616") == 1


@pytest.mark.asyncio
async def test_sqlite_reopen_reconstructs_context(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    original = _context()
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
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    await store.put("peer", _context(), b"peer-key")
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
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("Peer", _context(b"a" * 16), b"key-a")
    with pytest.raises(PeerKeyConflictError):
        await store.put("peer", _context(b"b" * 16), b"key-b")
    await store.put("peer:61616", _context(b"c" * 16), b"key-c")

    assert (await store.get_peer_pubkey("Peer")) == b"key-a"
    assert (await store.get_peer_pubkey("peer")) == b"key-a"
    assert (await store.get_peer_pubkey("peer:61616")) == b"key-c"


@pytest.mark.asyncio
async def test_partial_transaction_failure_preserves_old_record(tmp_path: Path) -> None:
    hooks = _FailAfterWrite()
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    await store.put("peer", _context(b"a" * 16), b"peer-key")

    hooks.enabled = True
    with pytest.raises(OSError, match="injected write failure"):
        await store.put(
            "peer",
            _context(b"b" * 16),
            b"peer-key",
            expected_generation=1,
        )

    loaded = await SqliteOscoreContextStore(path).get("peer")
    assert loaded is not None
    assert loaded.generation == 1
    assert loaded.oscore.export_parameters().master_secret == b"a" * 16


@pytest.mark.asyncio
async def test_cancellation_before_transaction_preserves_old_record(tmp_path: Path) -> None:
    hooks = _BlockBeforeTransaction()
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    await store.put("peer", _context(b"a" * 16), b"peer-key")

    hooks.enabled = True
    task = asyncio.create_task(
        store.put(
            "peer",
            _context(b"b" * 16),
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
    hooks = _BlockInTransaction()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", _context(), b"peer-key")

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
    hooks = _BlockMigrationInTransaction()
    path = tmp_path / f"cancel-{method}.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    original = await store.put("peer", _context(), b"peer-key")
    _mark_sqlite_as_legacy(store)
    _duplicate_legacy_context(store, "Peer")
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
    assert _stored_host_keys(store) == {"peer"}
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
    hooks = _BlockMigrationInTransaction()
    path = tmp_path / "cancel-rollback.sqlite3"
    store = SqliteOscoreContextStore(path, hooks=hooks)
    original = await store.put("peer", _context(), b"peer-key")
    _mark_sqlite_as_legacy(store)
    _duplicate_legacy_context(store, "Peer")
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
    assert _stored_host_keys(store) == {"Peer", "peer"}
    with sqlite3.connect(path) as connection:
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert metadata is None

    hooks.enabled = False
    store.migrate_endpoint_keys(EndpointPolicy(), {})
    assert _stored_host_keys(store) == {"peer"}
    with pytest.raises(EndpointPolicyConflictError):
        store.migrate_endpoint_keys(_SCOPED_POLICY, {})


@pytest.mark.asyncio
async def test_key_conflict_does_not_mutate_record(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("PEER", _context(b"a" * 16), b"key-a")

    with pytest.raises(PeerKeyConflictError):
        await store.put(
            "PEER",
            _context(b"b" * 16),
            b"key-b",
            expected_generation=1,
        )

    loaded = await store.get("PEER")
    assert loaded is not None
    assert loaded.peer_pubkey == b"key-a"
    assert loaded.oscore.export_parameters().master_secret == b"a" * 16


@pytest.mark.asyncio
async def test_context_replacement_rejects_stale_generation(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", _context(b"a" * 16), b"peer-key")
    replacement = await store.put("peer", _context(b"b" * 16), b"peer-key", expected_generation=1)
    assert replacement.generation == 2

    with pytest.raises(ContextGenerationError):
        await store.put(
            "peer",
            _context(b"c" * 16),
            b"peer-key",
            expected_generation=1,
        )

    loaded = await store.get("peer")
    assert loaded is not None
    assert loaded.generation == 2
    assert loaded.oscore.export_parameters().master_secret == b"b" * 16


@pytest.mark.asyncio
async def test_identical_material_replacement_preserves_high_water(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", _context(), b"peer-key")
    first = await store.reserve_sender_sequences("peer", 1, 4)
    assert (first.start, first.end) == (0, 4)

    replacement_context = _context()
    replacement = await store.put("peer", replacement_context, b"peer-key", expected_generation=1)
    assert replacement.generation == 2
    assert replacement_context.sender_sequence_number == 4
    second = await store.reserve_sender_sequences("peer", 2, 4)
    assert (second.start, second.end) == (4, 8)


@pytest.mark.asyncio
async def test_concurrent_reservations_are_disjoint(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    await store.put("peer", _context(), b"peer-key")

    reservations = await asyncio.gather(
        *(store.reserve_sender_sequences("peer", 1, 4) for _ in range(3))
    )
    ranges = sorted((reservation.start, reservation.end) for reservation in reservations)
    assert ranges == [(0, 4), (4, 8), (8, 12)]


@pytest.mark.asyncio
async def test_crash_with_unused_block_skips_values_on_reopen(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    await store.put("peer", _context(), b"peer-key")
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
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    context = _context(starting_sequence=MAX_OSCORE_SEQUENCE_NUMBER)
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
    inner = _RecordingChannel()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    channel = SecureDatagramChannel(
        inner,
        Identity.generate(),
        context_store=store,
        sequence_reservation_size=3,
    )
    await channel.add_context("peer", _context(), b"peer-key")

    await asyncio.gather(*(channel._send_protected(_request(mid), "peer") for mid in range(20)))

    assert len(inner.sent) == 20
    assert [_partial_iv(datagram) for datagram, _ in inner.sent] == list(range(20))


@pytest.mark.asyncio
async def test_independent_channels_send_unique_sequences(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    await SqliteOscoreContextStore(path).put("peer", _context(), b"peer-key")
    first_inner = _RecordingChannel()
    second_inner = _RecordingChannel()
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
        *(first._send_protected(_request(mid), "peer") for mid in range(10)),
        *(second._send_protected(_request(mid), "peer") for mid in range(10, 20)),
    )

    partial_ivs = [_partial_iv(datagram) for datagram, _ in first_inner.sent + second_inner.sent]
    assert len(partial_ivs) == 20
    assert len(set(partial_ivs)) == 20


@pytest.mark.asyncio
async def test_default_tofu_uses_context_store_binding() -> None:
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(_RecordingChannel(), Identity.generate(), context_store=store)
    await channel.add_context("PEER", _context(), b"peer-key")

    assert await channel._peer_resolver.get_peer_pubkey("PEER") == b"peer-key"
    assert await channel._peer_resolver.get_peer_pubkey("peer") == b"peer-key"


@pytest.mark.asyncio
async def test_sync_publication_rejects_after_async_store_use() -> None:
    store = InMemoryOscoreContextStore()
    assert await store.get("peer") is None

    with pytest.raises(RuntimeError, match="before async store use"):
        store.put_sync("peer", _context(), b"peer-key")


@pytest.mark.asyncio
async def test_failed_reservation_transmits_nothing() -> None:
    inner = _RecordingChannel()
    store = _FailingReservationStore()
    channel = SecureDatagramChannel(inner, Identity.generate(), context_store=store)
    await channel.add_context("peer", _context(), b"peer-key")

    await channel._send_protected(_request(1), "peer")

    assert inner.sent == []


def test_sender_identity_ignores_replay_window_configuration() -> None:
    first = _context(window_size=17)
    second = _context(window_size=64)

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
    original = _context()
    renamed = _context()
    equivalent_algorithm = type(
        "RenamedEquivalentAead",
        (),
        {"__module__": "replacement.crypto.backend", "value": 10},
    )()
    renamed.alg_aead = cast(Any, equivalent_algorithm)

    assert original.sender_cryptographic_identity() == renamed.sender_cryptographic_identity()
    assert original.recipient_cryptographic_identity() == renamed.recipient_cryptographic_identity()


@pytest.mark.asyncio
async def test_sqlite_rotation_aba_resumes_permanent_sender_ledger(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3")
    first_a = await store.put("peer", _context(b"a" * 16), b"peer-key")
    first_range = await store.reserve_sender_sequences("peer", first_a.generation, 4)
    assert (first_range.start, first_range.end) == (0, 4)

    context_b = await store.put("peer", _context(b"b" * 16), b"peer-key", expected_generation=1)
    b_range = await store.reserve_sender_sequences("peer", context_b.generation, 3)
    assert (b_range.start, b_range.end) == (0, 3)

    second_a_context = _context(b"a" * 16, window_size=64)
    second_a = await store.put("peer", second_a_context, b"peer-key", expected_generation=2)
    assert second_a.generation == 3
    assert second_a_context.sender_sequence_number == 4
    second_range = await store.reserve_sender_sequences("peer", 3, 4)
    assert (second_range.start, second_range.end) == (4, 8)


@pytest.mark.asyncio
async def test_in_memory_remove_preserves_pin_generation_and_ledgers() -> None:
    store = InMemoryOscoreContextStore()
    first = await store.put("peer", _context(b"a" * 16), b"peer-key")
    assert (await store.reserve_sender_sequences("peer", first.generation, 4)).end == 4

    await store.remove("peer")
    assert await store.get("peer") is None
    assert await store.get_peer_pubkey("peer") == b"peer-key"
    assert await store.get_generation("peer") == 2
    with pytest.raises(ContextGenerationError):
        await store.reserve_sender_sequences("peer", 1, 1)
    with pytest.raises(PeerKeyConflictError):
        await store.put("peer", _context(b"a" * 16), b"different-key", expected_generation=2)

    restored_context = _context(b"a" * 16)
    restored = await store.put("peer", restored_context, b"peer-key", expected_generation=2)
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 4


@pytest.mark.asyncio
async def test_sqlite_remove_tombstone_rejects_stale_handle_and_aba(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    first = await store.put("peer", _context(), b"peer-key")
    await store.reserve_sender_sequences("peer", first.generation, 4)
    await store.remove("peer")

    assert await store.get("peer") is None
    assert await store.get_peer_pubkey("peer") == b"peer-key"
    assert await store.get_generation("peer") == 2
    with pytest.raises(ContextGenerationError):
        await store.reserve_sender_sequences("peer", first.generation, 1)
    with pytest.raises(ContextGenerationError):
        await store.put("peer", _context(), b"peer-key", expected_generation=1)

    restored_context = _context()
    restored = await store.put("peer", restored_context, b"peer-key", expected_generation=2)
    assert restored.generation == 3
    assert restored_context.sender_sequence_number == 4
    reopened = SqliteOscoreContextStore(path)
    assert await reopened.get_peer_pubkey("peer") == b"peer-key"


@pytest.mark.asyncio
async def test_exhausted_context_reopens_loaded_and_exhausted(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    context = _context(starting_sequence=MAX_OSCORE_SEQUENCE_NUMBER)
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
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = _paired_contexts()
    protected, wire = _protected_request(sender)
    store = SqliteOscoreContextStore(path)
    await store.put("peer", recipient, b"peer-key")
    channel = SecureDatagramChannel(_RecordingChannel(), Identity.generate(), context_store=store)

    assert await channel._unprotect(protected, "peer") is not None

    replay = Message.decode(wire, LichenRemote("peer"))
    replay.direction = Direction.INCOMING
    reopened_channel = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened_channel._unprotect(replay, "peer") is None


@pytest.mark.asyncio
async def test_replay_persistence_failure_drops_plaintext(tmp_path: Path) -> None:
    hooks = _FailAfterWrite()
    sender, recipient = _paired_contexts()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", recipient, b"peer-key")
    channel = SecureDatagramChannel(_RecordingChannel(), Identity.generate(), context_store=store)
    hooks.enabled = True

    protected, wire = _protected_request(sender)
    assert await channel._unprotect(protected, "peer") is None
    hooks.enabled = False
    assert await channel._unprotect(_incoming_protected(wire), "peer") is not None


@pytest.mark.asyncio
async def test_same_replay_packet_is_linearizable_across_stores(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = _paired_contexts()
    _, wire = _protected_request(sender)
    await SqliteOscoreContextStore(path).put("peer", recipient, b"peer-key")
    barrier = _ReplayCasBarrier()
    first = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path, hooks=barrier),
    )
    second = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path, hooks=barrier),
    )

    results = await asyncio.gather(
        first._unprotect(_incoming_protected(wire), "peer"),
        second._unprotect(_incoming_protected(wire), "peer"),
    )

    assert sum(result is not None for result in results) == 1
    reopened = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened._unprotect(_incoming_protected(wire), "peer") is None


@pytest.mark.asyncio
async def test_different_replay_packets_conflict_without_erasure(tmp_path: Path) -> None:
    path = tmp_path / "contexts.sqlite3"
    sender, recipient = _paired_contexts()
    _, first_wire = _protected_request(sender, mid=80, token=b"first")
    _, second_wire = _protected_request(sender, mid=81, token=b"second")
    await SqliteOscoreContextStore(path).put("peer", recipient, b"peer-key")
    barrier = _ReplayCasBarrier()
    channels = [
        SecureDatagramChannel(
            _RecordingChannel(),
            Identity.generate(),
            context_store=SqliteOscoreContextStore(path, hooks=barrier),
        )
        for _ in range(2)
    ]

    results = await asyncio.gather(
        channels[0]._unprotect(_incoming_protected(first_wire), "peer"),
        channels[1]._unprotect(_incoming_protected(second_wire), "peer"),
    )
    assert sum(result is not None for result in results) == 1

    losing_index = 0 if results[0] is None else 1
    losing_wire = first_wire if losing_index == 0 else second_wire
    assert (
        await channels[losing_index]._unprotect(_incoming_protected(losing_wire), "peer")
        is not None
    )

    reopened = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=SqliteOscoreContextStore(path),
    )
    assert await reopened._unprotect(_incoming_protected(first_wire), "peer") is None
    assert await reopened._unprotect(_incoming_protected(second_wire), "peer") is None


def test_sqlite_file_mode_owner_and_journal_security(tmp_path: Path) -> None:
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
    insecure_parent = tmp_path / "shared"
    insecure_parent.mkdir(mode=0o700)
    os.chmod(insecure_parent, 0o777)

    with pytest.raises(PermissionError, match="group/other writable"):
        SqliteOscoreContextStore(insecure_parent / "contexts.sqlite3")


def test_sqlite_rejects_symlink_database_path(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = tmp_path / "contexts.sqlite3"
    symlink.symlink_to(target)

    with pytest.raises(ValueError, match="regular file"):
        SqliteOscoreContextStore(symlink)


def test_sqlite_accepts_secure_private_parent(tmp_path: Path) -> None:
    secure_parent = tmp_path / "private"
    secure_parent.mkdir(mode=0o700)

    store = SqliteOscoreContextStore(secure_parent / "contexts.sqlite3")

    assert store._path == str(secure_parent / "contexts.sqlite3")


@pytest.mark.asyncio
async def test_repeated_cancellation_returns_definitive_commit(tmp_path: Path) -> None:
    hooks = _BlockInTransaction()
    store = SqliteOscoreContextStore(tmp_path / "contexts.sqlite3", hooks=hooks)
    await store.put("peer", _context(), b"peer-key")
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
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork start method unavailable")
    fork = multiprocessing.get_context("fork")
    path = tmp_path / "contexts.sqlite3"
    store = SqliteOscoreContextStore(path)
    asyncio.run(store.put("Peer", _context(), b"peer-key"))
    context = asyncio.run(store.get("Peer"))
    assert context is not None
    reservation = asyncio.run(store.reserve_sender_sequences("Peer", 1, 4))
    context.oscore.set_sender_sequence_reservation(reservation.start, reservation.end)
    channel = SecureDatagramChannel(_RecordingChannel(), Identity.generate(), context_store=store)
    parent, child = fork.Pipe(duplex=False)
    process = fork.Process(target=_fork_sqlite_channel_send, args=(channel, child))
    process.start()
    child.close()
    assert parent.recv() == 4
    process.join(timeout=10)
    assert process.exitcode == 0


def test_fork_in_memory_store_fails_closed() -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork start method unavailable")
    fork = multiprocessing.get_context("fork")
    store = InMemoryOscoreContextStore()
    asyncio.run(store.put("peer", _context(), b"peer-key"))
    parent, child = fork.Pipe(duplex=False)
    process = fork.Process(target=_fork_memory_store_get, args=(store, child))
    process.start()
    child.close()
    assert parent.recv() == "fork-safe"
    process.join(timeout=10)
    assert process.exitcode == 0


@pytest.mark.asyncio
async def test_transport_canonicalizes_reg_name_destination(tmp_path: Path) -> None:
    inner = _RecordingChannel()
    context = _RemoteInspectingContext(
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
    await channel._send_protected(_request(1), "Peer")

    assert inner.sent[0][1] == "peer"
    assert context.protected_remote == "peer"


@pytest.mark.asyncio
async def test_send_datagram_rejects_invalid_host_synchronously() -> None:
    channel = SecureDatagramChannel(_RecordingChannel(), Identity.generate())

    with pytest.raises(ValueError, match="endpoint"):
        channel.send_datagram(_request(1), "bad\x00host")
    await asyncio.sleep(0)


def test_empty_standalone_tofu_binds_to_channel_store() -> None:
    store = InMemoryOscoreContextStore()
    resolver = TofuPeerResolver()
    channel = SecureDatagramChannel(
        _RecordingChannel(), Identity.generate(), context_store=store, peer_resolver=resolver
    )

    assert channel._peer_resolver is resolver
    assert resolver._context_store is store
    assert resolver._pinned == {}


@pytest.mark.asyncio
async def test_prepopulated_standalone_tofu_migrates_transactionally() -> None:
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Legacy", b"peer-key")
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )

    assert resolver._pinned == {}
    assert await channel._peer_resolver.get_peer_pubkey("Peer.Legacy") == b"peer-key"
    assert await store.get_peer_pubkey("Peer.Legacy") == b"peer-key"


@pytest.mark.asyncio
async def test_prepopulated_tofu_migrates_before_publication() -> None:
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Publish", b"peer-key")
    store = InMemoryOscoreContextStore()
    channel = SecureDatagramChannel(
        _RecordingChannel(),
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )

    await channel.add_context("Peer.Publish", _context(), b"peer-key")

    assert await store.get_peer_pubkey("Peer.Publish") == b"peer-key"
    assert await store.has_context("Peer.Publish")
    assert resolver._pinned == {}


@pytest.mark.asyncio
async def test_prepopulated_tofu_migration_conflict_fails_closed() -> None:
    resolver = TofuPeerResolver()
    await resolver.pin_peer("Peer.Legacy", b"legacy-key")
    store = InMemoryOscoreContextStore()
    await store.pin_peer("Peer.Legacy", b"authoritative-key")
    with pytest.raises(PeerKeyConflictError):
        SecureDatagramChannel(
            _RecordingChannel(),
            Identity.generate(),
            context_store=store,
            peer_resolver=resolver,
        )
    assert await store.get_peer_pubkey("Peer.Legacy") == b"authoritative-key"
    assert resolver._pinned == {"peer.legacy": b"legacy-key"}
    assert resolver._context_store is None
    assert resolver._endpoint_policy is None


def test_tofu_bound_to_different_store_is_incompatible() -> None:
    resolver = TofuPeerResolver(InMemoryOscoreContextStore())

    with pytest.raises(ValueError, match="different context store"):
        SecureDatagramChannel(
            _RecordingChannel(),
            Identity.generate(),
            context_store=InMemoryOscoreContextStore(),
            peer_resolver=resolver,
        )
