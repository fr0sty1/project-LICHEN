# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fail-closed persistence tests for authenticated Announce state."""

from __future__ import annotations

import json
import os
import stat

import pytest

from lichen.announce.persistence import AnnouncePersistenceError, AnnounceStatePersistence
from lichen.crypto.identity import Identity


class MemoryAnchor:
    def __init__(self) -> None:
        self.revisions: dict[bytes, int] = {}

    def read(self, key: bytes) -> int | None:
        return self.revisions.get(key)

    def advance(self, key: bytes, expected: int | None, revision: int) -> None:
        if self.revisions.get(key) != expected or revision != (expected or 0) + 1:
            raise RuntimeError("compare-and-advance failed")
        self.revisions[key] = revision


LOCAL = Identity.from_seed(bytes(range(32)))
REMOTE = Identity.from_seed(bytes(range(32, 64)))


def test_bootstrap_authorization_requires_exact_boolean(tmp_path) -> None:
    with pytest.raises(AnnouncePersistenceError, match="exact boolean"):
        AnnounceStatePersistence(tmp_path / "node-state", LOCAL, MemoryAnchor(), allow_bootstrap=1)  # type: ignore[arg-type]


def test_bootstrap_commit_and_reboot_restore_exact_pin_and_floor(tmp_path) -> None:
    anchor = MemoryAnchor()
    path = tmp_path / "node-state"
    persistence = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    persistence.commit(REMOTE.iid, REMOTE.pubkey, 42)

    restored = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False)
    assert restored.pins == {REMOTE.iid: REMOTE.pubkey}
    assert restored.floors == {REMOTE.iid: 42}
    assert restored.local_sequence == 0
    assert stat.S_IMODE((tmp_path / "node-state.announce").stat().st_mode) == 0o600


def test_deleted_or_corrupt_state_fails_closed_against_anchor(tmp_path) -> None:
    anchor = MemoryAnchor()
    path = tmp_path / "node-state"
    AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    state_path = tmp_path / "node-state.announce"
    state_path.unlink()
    with pytest.raises(AnnouncePersistenceError, match="deleted"):
        AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)

    anchor = MemoryAnchor()
    AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    state_path.write_bytes(b"not-json")
    with pytest.raises(AnnouncePersistenceError, match="corrupt"):
        AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False)


def test_broken_symlink_state_is_corrupt_not_bootstrap(tmp_path) -> None:
    path = tmp_path / "node-state"
    os.symlink(tmp_path / "missing-state", tmp_path / "node-state.announce")

    with pytest.raises(AnnouncePersistenceError, match="unreadable"):
        AnnounceStatePersistence(path, LOCAL, MemoryAnchor(), allow_bootstrap=True)


def test_signature_and_key_binding_tampering_fail_closed(tmp_path) -> None:
    anchor = MemoryAnchor()
    path = tmp_path / "node-state"
    persistence = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    persistence.commit(REMOTE.iid, REMOTE.pubkey, 1)
    state_path = tmp_path / "node-state.announce"
    document = json.loads(state_path.read_text())
    document["floors"][0][1] = 2
    state_path.write_text(json.dumps(document))
    state_path.chmod(0o600)
    with pytest.raises(AnnouncePersistenceError, match="corrupt"):
        AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False)


def test_stale_concurrent_writer_cannot_overwrite_newer_revision(tmp_path) -> None:
    anchor = MemoryAnchor()
    path = tmp_path / "node-state"
    first = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    stale = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False)
    first.commit(REMOTE.iid, REMOTE.pubkey, 1)
    with pytest.raises(AnnouncePersistenceError, match="stale"):
        stale.commit(REMOTE.iid, REMOTE.pubkey, 2)
    assert AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False).floors == {
        REMOTE.iid: 1
    }


def test_commit_cannot_roll_back_durable_replay_floor(tmp_path) -> None:
    persistence = AnnounceStatePersistence(
        tmp_path / "node-state", LOCAL, MemoryAnchor(), allow_bootstrap=True
    )
    persistence.commit(REMOTE.iid, REMOTE.pubkey, 100)

    with pytest.raises(AnnouncePersistenceError, match="advance monotonically"):
        persistence.commit(REMOTE.iid, REMOTE.pubkey, 99)

    assert persistence.floors == {REMOTE.iid: 100}


def test_equal_exact_pin_and_floor_commit_is_idempotent(tmp_path) -> None:
    anchor = MemoryAnchor()
    persistence = AnnounceStatePersistence(
        tmp_path / "node-state", LOCAL, anchor, allow_bootstrap=True
    )
    persistence.commit(REMOTE.iid, REMOTE.pubkey, 100)
    revision = next(iter(anchor.revisions.values()))

    persistence.commit(REMOTE.iid, REMOTE.pubkey, 100)

    assert next(iter(anchor.revisions.values())) == revision
    assert persistence.floors == {REMOTE.iid: 100}


def test_lock_context_does_not_relabel_body_oserror(tmp_path, monkeypatch) -> None:
    persistence = AnnounceStatePersistence(
        tmp_path / "node-state", LOCAL, MemoryAnchor(), allow_bootstrap=True
    )
    failure = OSError("injected state read failure")

    def fail_read():
        raise failure

    monkeypatch.setattr(persistence, "_read_state", fail_read)
    with pytest.raises(OSError) as raised:
        persistence.reserve_local_sequence(1)
    assert raised.value is failure


def test_local_sequence_reservation_restores_and_wraps_exactly(tmp_path) -> None:
    anchor = MemoryAnchor()
    path = tmp_path / "node-state"
    persistence = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=True)
    persistence.reserve_local_sequence(1)
    assert AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False).local_sequence == 1

    # Seed the boundary through the signed transition helper; the final two
    # reservations exercise the normative fffe -> ffff -> 0000 wrap.
    with persistence._lock():
        revision, _local, pins, floors = persistence._read_state()
        persistence._publish_state(revision, 0xFFFE, pins, floors)
    persistence.reserve_local_sequence(0xFFFF)
    persistence.reserve_local_sequence(0)
    restored = AnnounceStatePersistence(path, LOCAL, anchor, allow_bootstrap=False)
    assert restored.local_sequence == 0


@pytest.mark.parametrize("sequence", [True, -1, 0x10000, 2])
def test_local_sequence_reservation_rejects_invalid_or_skipped_values(tmp_path, sequence) -> None:
    persistence = AnnounceStatePersistence(
        tmp_path / "node-state", LOCAL, MemoryAnchor(), allow_bootstrap=True
    )
    with pytest.raises(AnnouncePersistenceError):
        persistence.reserve_local_sequence(sequence)


@pytest.mark.parametrize(
    "iid,pubkey,sequence",
    [
        (bytearray(8), REMOTE.pubkey, 1),
        (REMOTE.iid, bytearray(32), 1),
        (REMOTE.iid, REMOTE.pubkey, True),
        (REMOTE.iid, REMOTE.pubkey, -1),
        (REMOTE.iid, REMOTE.pubkey, 0x10000),
        (bytes(8), REMOTE.pubkey, 1),
    ],
)
def test_commit_rejects_nonexact_or_unbound_security_inputs(
    tmp_path, iid, pubkey, sequence
) -> None:
    persistence = AnnounceStatePersistence(
        tmp_path / "node-state", LOCAL, MemoryAnchor(), allow_bootstrap=True
    )
    with pytest.raises(AnnouncePersistenceError):
        persistence.commit(iid, pubkey, sequence)
