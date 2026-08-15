# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared fixtures and helpers for OSCORE context-store tests."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from aiocoap import GET, Message
from aiocoap.numbers import types
from aiocoap.oscore import Direction

from lichen.coap.secure import (
    InMemoryOscoreContextStore,
    SequenceReservation,
    SequenceReservationError,
    SqliteOscoreContextStore,
    SqliteStoreHooks,
    TransactionalOscoreContextStore,
)
from lichen.coap.transport import DatagramChannel, EndpointPolicy, LichenRemote, ReceiveCallback
from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


def make_context(
    secret: bytes = b"s" * 16,
    *,
    starting_sequence: int = 0,
    window_size: int = 17,
) -> MemorySecurityContext:
    """Create a test OSCORE context with common defaults."""
    return MemorySecurityContext(
        master_secret=secret,
        master_salt=b"salt1234",
        sender_id=b"\x01",
        recipient_id=b"\x02",
        window_size=window_size,
        id_context=b"lichen-test",
        starting_sequence_number=starting_sequence,
    )


SCOPED_POLICY = EndpointPolicy.owning_link_local("fe80::2%ble0")


class FailAfterWrite(SqliteStoreHooks):
    """Hook that fails after write operations."""

    def __init__(self) -> None:
        self.enabled = False

    def transaction_step(self, operation: str, step: str) -> None:
        if self.enabled and operation in {"put", "replay_cas", "migrate"} and step == "after_write":
            raise OSError("injected write failure")


class BlockBeforeTransaction(SqliteStoreHooks):
    """Hook that blocks before entering a transaction."""

    def __init__(self) -> None:
        self.enabled = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def before_transaction(self, operation: str, host: str) -> None:
        if self.enabled and operation == "put":
            self.entered.set()
            await self.release.wait()


class BlockBeforePin(SqliteStoreHooks):
    """Hook that blocks before pin_batch transactions."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def before_transaction(self, operation: str, host: str) -> None:
        if operation == "pin_batch":
            self.entered.set()
            await self.release.wait()


class BlockInTransaction(SqliteStoreHooks):
    """Hook that blocks inside a transaction after write."""

    def __init__(self) -> None:
        self.enabled = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def transaction_step(self, operation: str, step: str) -> None:
        if self.enabled and operation == "reserve" and step == "after_write":
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("transaction test release timed out")


class BlockMigrationInTransaction(SqliteStoreHooks):
    """Hook that blocks during migration after write."""

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


class ReplayCasBarrier(SqliteStoreHooks):
    """Hook that synchronizes concurrent replay CAS operations."""

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


class RecordingChannel(DatagramChannel):
    """Channel that records sent datagrams for testing."""

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str]] = []

    def send_datagram(
        self, data: bytes, dest: str, **kwargs: object  # type: ignore[override]
    ) -> None:
        self.sent.append((data, dest))

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self.receiver = receiver

    def close(self) -> None:
        pass


class RemoteInspectingContext(MemorySecurityContext):
    """Context that records the remote address during protect."""

    protected_remote: str | None = None

    def protect(self, message: Any, request_id: Any = None) -> Any:
        self.protected_remote = message.remote.hostinfo
        return super().protect(message, request_id)


class FailingReservationStore(InMemoryOscoreContextStore):
    """Store that always fails sequence reservation."""

    async def reserve_sender_sequences(
        self, host: str, generation: int, count: int
    ) -> SequenceReservation:
        raise SequenceReservationError("injected reservation failure")


class IncompleteStore:
    """Incomplete store implementation for testing type checks."""

    def check_process(self) -> None:
        pass


@pytest.fixture(params=("memory", "sqlite"))
def conforming_store(
    request: pytest.FixtureRequest, tmp_path: Path
) -> TransactionalOscoreContextStore:
    """Fixture that provides both store implementations for conformance testing."""
    if request.param == "memory":
        return InMemoryOscoreContextStore()
    return SqliteOscoreContextStore(tmp_path / "conformance.sqlite3")


def make_request(mid: int) -> bytes:
    """Create a simple CoAP GET request for testing."""
    message = Message(code=GET)
    message.token = mid.to_bytes(2, "big")
    message.mtype = types.NON
    message.mid = mid
    message.remote = LichenRemote("peer")
    message.direction = Direction.OUTGOING
    return cast(bytes, message.encode())


def stored_host_keys(store: TransactionalOscoreContextStore) -> set[str]:
    """Get the set of host keys stored in a store."""
    if isinstance(store, InMemoryOscoreContextStore):
        return set(store._records)
    sqlite_store = cast(SqliteOscoreContextStore, store)
    with sqlite3.connect(sqlite_store._path) as connection:
        return {str(row[0]) for row in connection.execute("SELECT host FROM oscore_hosts")}


def insert_legacy_pins(store: SqliteOscoreContextStore, rows: list[tuple[str, bytes]]) -> None:
    """Insert legacy pin rows directly into SQLite for testing migration."""
    with sqlite3.connect(store._path) as connection:
        connection.executemany("INSERT INTO oscore_hosts (host, peer_pubkey) VALUES (?, ?)", rows)


def mark_sqlite_as_legacy(*stores: SqliteOscoreContextStore) -> None:
    """Mark SQLite store(s) as lacking endpoint policy for legacy migration tests."""
    if not stores:
        return
    with sqlite3.connect(stores[0]._path) as connection:
        connection.execute("DELETE FROM oscore_metadata WHERE key = 'endpoint_policy'")
    for store in stores:
        store._endpoint_policy = None


def duplicate_legacy_context(
    store: SqliteOscoreContextStore, alias: str, *, generation: int | None = None
) -> None:
    """Duplicate the 'peer' context under a new alias for testing legacy coalescing."""
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


def extract_partial_iv(datagram: bytes) -> int:
    """Extract the partial IV from an OSCORE-protected message."""
    protected = Message.decode(datagram, LichenRemote("peer"))
    option: bytes | None = protected.opt.oscore
    assert option is not None
    length = option[0] & 0x07
    assert length > 0
    return int.from_bytes(option[1 : 1 + length], "big")


def paired_contexts() -> tuple[MemorySecurityContext, MemorySecurityContext]:
    """Create a paired initiator/responder context for testing replay detection."""
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


def protected_request(
    sender: MemorySecurityContext,
    *,
    mid: int = 77,
    token: bytes = b"replay",
) -> tuple[Message, bytes]:
    """Create a protected request message for replay testing."""
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


def incoming_protected(wire: bytes, endpoint: str = "peer") -> Message:
    """Decode wire bytes as an incoming protected message."""
    message = Message.decode(wire, LichenRemote(endpoint))
    message.direction = Direction.INCOMING
    return message
