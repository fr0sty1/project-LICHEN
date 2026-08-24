# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for secure key persistence (spec 15.2).

Tests file-based key storage, crash-safety, and TrustStore persistence.
"""

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

import pytest

import lichen.crypto.key_persistence as key_persistence_module
from lichen.crypto import (
    FileKeyStore,
    Identity,
    KeyPersistenceError,
    MemoryKeyStore,
    TrustEntry,
    TrustLevel,
    TrustStore,
    TrustStorePersistence,
)
from lichen.crypto.key_persistence import (
    TrustStorePersistenceError,
    TrustStorePersistenceIndeterminateError,
)
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.trust import compute_rotation_transcript
from lichen.rollback_anchor import AnchoredState

_RealFileKeyStore = FileKeyStore
_RealTrustStorePersistence = TrustStorePersistence
_AUTHENTICATION_KEY = bytes(range(32))
_ANCHOR_KEY = bytes(range(32, 64))
_TRUST_AUTH_DOMAIN = b"LICHEN-TRUST-STATE-v1\x00"


class MemoryStateAnchor:
    def __init__(self) -> None:
        self.states: dict[bytes, AnchoredState] = {}

    def read(self, key: bytes) -> AnchoredState | None:
        return self.states.get(key)

    def advance(
        self,
        key: bytes,
        expected: AnchoredState | None,
        state: AnchoredState,
    ) -> None:
        if self.states.get(key) != expected:
            raise RuntimeError("anchor compare-and-advance failed")
        if expected is not None and state.revision != expected.revision + 1:
            raise RuntimeError("anchor revision did not advance exactly")
        self.states[key] = state


class FailingTrustPersistence:
    is_crash_safe = True
    fails_closed = True

    def save(self, store: TrustStore) -> None:
        raise OSError("injected ordinary persistence failure")


_ANCHORS: dict[Path, MemoryStateAnchor] = {}


def _anchor(path: Path) -> MemoryStateAnchor:
    return _ANCHORS.setdefault(path, MemoryStateAnchor())


def FileKeyStore(  # noqa: N802
    base_dir,
    *,
    fail_closed: bool = True,  # type: ignore[no-untyped-def]
):
    path = Path(base_dir)
    return _RealFileKeyStore(
        path,
        revision_anchor=_anchor(path),
        anchor_key=_ANCHOR_KEY,
        allow_bootstrap=True,
        fail_closed=fail_closed,
    )


def TrustStorePersistence(  # noqa: N802
    base_dir,  # type: ignore[no-untyped-def]
):
    path = Path(base_dir)
    return _RealTrustStorePersistence(
        path,
        authentication_key=_AUTHENTICATION_KEY,
        revision_anchor=_anchor(path),
        anchor_key=_ANCHOR_KEY,
        allow_bootstrap=True,
    )


# Deterministic seeds for reproducible tests
SEED_ALICE = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
SEED_BOB = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")


def _entry_document(entry: TrustEntry, **overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "pubkey_hex": entry.pubkey.hex(),
        "iid_hex": entry.iid.hex(),
        "ygg_addr_hex": entry.ygg_addr.hex(),
        "trust_level": entry.trust_level.name,
        "first_seen": 0,
        "last_seen": 0,
        "revoked": False,
        "metadata": {},
        "rotation_sequence": 0,
    }
    data.update(overrides)
    return data


def _write_trust_document(path, entries, **overrides: object) -> None:
    body: dict[str, object] = {
        "format_version": 2,
        "revision": 1,
        "auto_pin": True,
        "entries": entries,
    }
    body.update(overrides)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    authentication = hmac.new(
        _AUTHENTICATION_KEY,
        _TRUST_AUTH_DOMAIN + canonical,
        hashlib.sha256,
    ).hexdigest()
    data = {**body, "authentication": authentication}
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


class TestMemoryKeyStore:
    """Tests for in-memory key store (testing only)."""

    def test_store_and_load_seed(self):
        """MemoryKeyStore stores and retrieves seed correctly."""
        store = MemoryKeyStore()
        store.store_seed(SEED_ALICE)
        assert store.load_seed() == SEED_ALICE

    def test_load_returns_none_initially(self):
        """MemoryKeyStore returns None when no seed stored."""
        store = MemoryKeyStore()
        assert store.load_seed() is None

    def test_is_not_crash_safe(self):
        """MemoryKeyStore is not crash-safe."""
        store = MemoryKeyStore()
        assert not store.is_crash_safe

    def test_store_rejects_invalid_length(self):
        """MemoryKeyStore rejects invalid seed length."""
        store = MemoryKeyStore()
        with pytest.raises(ValueError, match="32 bytes"):
            store.store_seed(b"\x00" * 16)

    def test_store_and_load_identity(self):
        """MemoryKeyStore stores and loads Identity via seed."""
        store = MemoryKeyStore()
        identity = Identity.from_seed(SEED_ALICE)
        store.store_identity(identity)

        loaded = store.load_identity()
        assert loaded is not None
        assert loaded.pubkey == identity.pubkey
        assert loaded.iid == identity.iid


class TestFileKeyStore:
    """Tests for file-based key storage."""

    def test_store_and_load_seed(self, tmp_path):
        """FileKeyStore stores and retrieves seed correctly."""
        store = FileKeyStore(tmp_path)
        store.store_seed(SEED_ALICE)
        assert store.load_seed() == SEED_ALICE

    def test_load_returns_none_when_empty(self, tmp_path):
        """FileKeyStore returns None when no seed exists."""
        store = FileKeyStore(tmp_path)
        assert store.load_seed() is None

    def test_is_crash_safe(self, tmp_path):
        """FileKeyStore is crash-safe."""
        store = FileKeyStore(tmp_path)
        assert store.is_crash_safe

    def test_store_rejects_invalid_length(self, tmp_path):
        """FileKeyStore rejects invalid seed length."""
        store = FileKeyStore(tmp_path)
        with pytest.raises(ValueError, match="32 bytes"):
            store.store_seed(b"\x00" * 16)

    def test_file_permissions_are_restricted(self, tmp_path):
        """FileKeyStore creates files with 0600 permissions (spec 15.2)."""
        store = FileKeyStore(tmp_path)
        store.store_seed(SEED_ALICE)

        # Check that slot files have restricted permissions
        slot0 = tmp_path / "node_seed_0.bin"
        slot1 = tmp_path / "node_seed_1.bin"

        # One of the slots should exist
        if slot0.exists():
            mode = stat.S_IMODE(os.stat(slot0).st_mode)
            assert mode == stat.S_IRUSR | stat.S_IWUSR, f"Expected 0600, got {oct(mode)}"
        elif slot1.exists():
            mode = stat.S_IMODE(os.stat(slot1).st_mode)
            assert mode == stat.S_IRUSR | stat.S_IWUSR, f"Expected 0600, got {oct(mode)}"
        else:
            pytest.fail("No slot file created")

    def test_two_slot_crash_safety(self, tmp_path):
        """FileKeyStore survives partial writes via two-slot mechanism."""
        store = FileKeyStore(tmp_path)

        # Write first seed
        store.store_seed(SEED_ALICE)
        assert store.load_seed() == SEED_ALICE

        # Write second seed (should go to other slot)
        store.store_seed(SEED_BOB)
        assert store.load_seed() == SEED_BOB

        # Both slots should exist
        slot0 = tmp_path / "node_seed_0.bin"
        slot1 = tmp_path / "node_seed_1.bin"
        assert slot0.exists() and slot1.exists()

    def test_generation_exhaustion_is_explicit_and_preserves_seed(self, tmp_path):
        store = FileKeyStore(tmp_path)
        store._write_slot(tmp_path / "node_seed_0.bin", 0xFFFFFFFF, SEED_ALICE)
        state = store._slot_anchor((0xFFFFFFFF, SEED_ALICE))
        store._revision_anchor.advance(store._anchor_key, None, state)
        with pytest.raises(KeyPersistenceError, match="generation exhausted"):
            store.store_seed(SEED_BOB)
        assert store.load_seed() == SEED_ALICE

    def test_symlink_slot_fails_closed_without_following_target(self, tmp_path):
        target = tmp_path / "target"
        target.write_bytes(SEED_ALICE)
        os.symlink(target, tmp_path / "node_seed_0.bin")
        store = FileKeyStore(tmp_path, fail_closed=True)
        with pytest.raises(KeyPersistenceError, match="corrupt"):
            store.load_seed()
        assert target.read_bytes() == SEED_ALICE

    def test_broken_symlink_slot_is_corrupt_not_fresh(self, tmp_path):
        os.symlink(tmp_path / "missing-target", tmp_path / "node_seed_0.bin")
        store = FileKeyStore(tmp_path, fail_closed=True)

        with pytest.raises(KeyPersistenceError, match="corrupt"):
            store.load_seed()

    def test_base_directory_and_lock_are_private(self, tmp_path):
        store = FileKeyStore(tmp_path)
        store.store_seed(SEED_ALICE)
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / ".node_seed.lock").stat().st_mode) == 0o600

    def test_deleting_only_initialized_slot_cannot_reset_identity(self, tmp_path):
        store = FileKeyStore(tmp_path, fail_closed=False)

        # Write seed
        store.store_seed(SEED_ALICE)

        # Corrupt one slot
        slot0 = tmp_path / "node_seed_0.bin"
        slot1 = tmp_path / "node_seed_1.bin"
        if slot0.exists():
            with open(slot0, "wb") as f:
                f.write(b"CORRUPT")
        elif slot1.exists():
            with open(slot1, "wb") as f:
                f.write(b"CORRUPT")

        with pytest.raises(KeyPersistenceError, match="deleted"):
            store.store_seed(SEED_BOB)

    def test_deleting_all_initialized_slots_is_detected_after_restart(self, tmp_path):
        store = FileKeyStore(tmp_path, fail_closed=False)
        store.store_seed(SEED_ALICE)
        for slot in (tmp_path / "node_seed_0.bin", tmp_path / "node_seed_1.bin"):
            slot.unlink(missing_ok=True)

        with pytest.raises(KeyPersistenceError, match="deleted"):
            FileKeyStore(tmp_path, fail_closed=False).load_seed()

    def test_restoring_older_slot_snapshot_is_detected_after_restart(self, tmp_path):
        store = FileKeyStore(tmp_path)
        store.store_seed(SEED_ALICE)
        old_slots = {
            slot.name: slot.read_bytes()
            for slot in (tmp_path / "node_seed_0.bin", tmp_path / "node_seed_1.bin")
            if slot.exists()
        }
        store.store_seed(SEED_BOB)
        for slot in (tmp_path / "node_seed_0.bin", tmp_path / "node_seed_1.bin"):
            slot.unlink(missing_ok=True)
        for name, contents in old_slots.items():
            (tmp_path / name).write_bytes(contents)
            (tmp_path / name).chmod(0o600)

        with pytest.raises(KeyPersistenceError, match="rollback|substitution"):
            FileKeyStore(tmp_path).load_seed()

    def test_equal_generation_divergence_is_detected(self, tmp_path):
        store = FileKeyStore(tmp_path)
        store._write_slot(tmp_path / "node_seed_0.bin", 1, SEED_ALICE)
        store._write_slot(tmp_path / "node_seed_1.bin", 1, SEED_BOB)

        with pytest.raises(KeyPersistenceError, match="conflicting generations"):
            store.load_seed()

    def test_unanchored_generation_ahead_seed_is_ignored_and_overwritten(self, tmp_path):
        store = FileKeyStore(tmp_path)
        store.store_seed(SEED_ALICE)
        store._write_slot(tmp_path / "node_seed_1.bin", 2, SEED_BOB)

        restarted = FileKeyStore(tmp_path)
        assert restarted.load_seed() == SEED_ALICE
        restarted.store_seed(SEED_ALICE)
        assert restarted.load_seed() == SEED_ALICE

    @pytest.mark.parametrize("value", [0, 1, None, "true"])
    def test_file_store_fail_closed_requires_exact_bool(self, tmp_path, value: object):
        with pytest.raises(ValueError, match="fail_closed"):
            _RealFileKeyStore(
                tmp_path,
                revision_anchor=MemoryStateAnchor(),
                anchor_key=_ANCHOR_KEY,
                allow_bootstrap=True,
                fail_closed=value,  # type: ignore[arg-type]
            )

    def test_lock_does_not_relabel_body_oserror(self, tmp_path, monkeypatch):
        store = FileKeyStore(tmp_path)

        def fail_body(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise OSError("body failure")

        monkeypatch.setattr(store, "_best_slot_locked", fail_body)
        with pytest.raises(OSError, match="body failure"):
            store.load_seed()

    @pytest.mark.parametrize("writer", ["seed", "trust"])
    def test_staging_cleanup_preserves_primary_error_and_closes_fd(
        self, tmp_path, monkeypatch, writer: str
    ):
        descriptors: list[int] = []

        def fail_fchmod(fd: int, _mode: int) -> None:
            descriptors.append(fd)
            raise OSError("primary staging failure")

        def fail_unlink(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise OSError("cleanup failure")

        monkeypatch.setattr(key_persistence_module.os, "fchmod", fail_fchmod)
        monkeypatch.setattr(Path, "unlink", fail_unlink)
        if writer == "seed":
            operation = lambda: FileKeyStore(tmp_path)._write_slot(  # noqa: E731
                tmp_path / "node_seed_0.bin", 1, SEED_ALICE
            )
        else:
            operation = lambda: TrustStorePersistence(  # noqa: E731
                tmp_path
            )._write_json_locked(b"{}")

        with pytest.raises(OSError, match="primary staging failure"):
            operation()
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])

    def test_fail_closed_raises_on_corrupt(self, tmp_path):
        """FileKeyStore raises when fail_closed and state is corrupt."""
        store = FileKeyStore(tmp_path, fail_closed=True)

        # Create corrupt slot files
        slot0 = tmp_path / "node_seed_0.bin"
        slot1 = tmp_path / "node_seed_1.bin"
        with open(slot0, "wb") as f:
            f.write(b"CORRUPT")
        with open(slot1, "wb") as f:
            f.write(b"CORRUPT")

        with pytest.raises(KeyPersistenceError, match="corrupt"):
            store.load_seed()

    def test_fail_closed_writer_preserves_wholly_corrupt_slots(self, tmp_path):
        store = FileKeyStore(tmp_path, fail_closed=True)
        store.store_seed(SEED_ALICE)
        store.store_seed(SEED_BOB)
        slots = [tmp_path / "node_seed_0.bin", tmp_path / "node_seed_1.bin"]
        for slot in slots:
            slot.write_bytes(b"CORRUPT")
        before = [slot.read_bytes() for slot in slots]

        with pytest.raises(KeyPersistenceError, match="deleted"):
            store.store_seed(SEED_ALICE)

        assert [slot.read_bytes() for slot in slots] == before

    def test_fail_closed_returns_none_when_missing(self, tmp_path):
        """FileKeyStore returns None when fail_closed and no files exist."""
        store = FileKeyStore(tmp_path, fail_closed=True)
        # No files exist yet - this is a fresh node, not corrupt
        assert store.load_seed() is None

    def test_store_and_load_identity(self, tmp_path):
        """FileKeyStore stores and loads Identity via seed."""
        store = FileKeyStore(tmp_path)
        identity = Identity.from_seed(SEED_ALICE)
        store.store_identity(identity)

        loaded = store.load_identity()
        assert loaded is not None
        assert loaded.pubkey == identity.pubkey
        assert loaded.iid == identity.iid
        assert loaded.ygg_addr == identity.ygg_addr

    def test_rejects_file_as_base_dir(self, tmp_path):
        """FileKeyStore rejects file path as base_dir."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("hello")

        with pytest.raises(KeyPersistenceError, match="not a real directory"):
            FileKeyStore(file_path)


class TestTrustStorePersistence:
    """Tests for TrustStore file persistence."""

    def test_save_and_load_empty_store(self, tmp_path):
        """TrustStorePersistence saves and loads empty store."""
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore()

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        assert len(loaded) == 0
        assert loaded.auto_pin == store.auto_pin

    def test_public_rotation_is_persisted_before_return(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        store = TrustStore(persistence=persistence)
        store.verify_or_pin(alice.pubkey, alice.iid)
        persistence.save(store)
        transcript = compute_rotation_transcript(alice.pubkey, bob.pubkey, 1)
        signature = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        rotated = store.rotate_key(alice.pubkey, bob.pubkey, 1, signature)

        assert rotated.rotation_sequence == 1
        restored = persistence.load()
        assert restored is not None
        assert alice.iid not in restored
        restored_bob = restored.get(bob.iid)
        assert restored_bob is not None
        assert restored_bob.rotation_sequence == 1

    @pytest.mark.parametrize("failure_point", ["chmod", "directory_fsync"])
    def test_post_replace_rotation_failure_is_indeterminate_and_recoverable(
        self, tmp_path, monkeypatch, failure_point: str
    ):
        persistence = TrustStorePersistence(tmp_path)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        store = TrustStore(persistence=persistence)
        store.verify_or_pin(alice.pubkey, alice.iid)
        transcript = compute_rotation_transcript(alice.pubkey, bob.pubkey, 1)
        signature = schnorr_sign(alice.privkey, alice.pubkey, transcript)

        if failure_point == "chmod":
            real_chmod = key_persistence_module.os.chmod

            def fail_chmod(path, mode):  # type: ignore[no-untyped-def]
                if Path(path) == tmp_path / "trust_store.json":
                    raise OSError("injected post-replace chmod failure")
                return real_chmod(path, mode)

            monkeypatch.setattr(key_persistence_module.os, "chmod", fail_chmod)
        else:
            real_fsync = key_persistence_module.os.fsync

            def fail_directory_fsync(fd: int) -> None:
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError("injected directory fsync failure")
                real_fsync(fd)

            monkeypatch.setattr(key_persistence_module.os, "fsync", fail_directory_fsync)

        with pytest.raises(TrustStorePersistenceIndeterminateError):
            store.rotate_key(alice.pubkey, bob.pubkey, 1, signature)

        assert store.get(alice.iid) is None
        assert store.get(bob.iid) is not None
        with pytest.raises(TrustStorePersistenceError, match="indeterminate"):
            persistence.load()
        restored = TrustStorePersistence(tmp_path).load()
        assert restored is not None
        assert restored.get(alice.iid) is None
        assert restored.get(bob.iid) is not None

    def test_deleting_initialized_trust_document_is_detected(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        persistence.save(TrustStore())
        (tmp_path / "trust_store.json").unlink()

        with pytest.raises(TrustStorePersistenceError, match="deleted"):
            TrustStorePersistence(tmp_path).load()

    def test_restoring_old_authenticated_document_is_detected(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore()
        persistence.save(store)
        old_document = (tmp_path / "trust_store.json").read_bytes()
        alice = Identity.from_seed(SEED_ALICE)
        store.verify_or_pin(alice.pubkey, alice.iid)
        persistence.save(store)
        (tmp_path / "trust_store.json").write_bytes(old_document)
        (tmp_path / "trust_store.json").chmod(0o600)

        with pytest.raises(TrustStorePersistenceError, match="rollback|substitution"):
            TrustStorePersistence(tmp_path).load()

    def test_byte_valid_forgery_fails_authentication(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        persistence.save(TrustStore())
        path = tmp_path / "trust_store.json"
        document = json.loads(path.read_bytes())
        document["auto_pin"] = False
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        path.chmod(0o600)

        with pytest.raises(TrustStorePersistenceError, match="authentication failed"):
            persistence.load()

    def test_trust_lock_does_not_relabel_body_oserror(self, tmp_path, monkeypatch):
        persistence = TrustStorePersistence(tmp_path)

        def fail_body(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise OSError("body failure")

        monkeypatch.setattr(persistence, "_read_json_locked", fail_body)
        with pytest.raises(OSError, match="body failure"):
            persistence.load()

    def test_save_and_load_with_entries(self, tmp_path):
        """TrustStorePersistence preserves trust entries."""
        persistence = TrustStorePersistence(tmp_path)

        # Create store with entries
        store = TrustStore()
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        store.verify_or_pin(alice.pubkey, alice.iid)
        store.verify_or_pin(bob.pubkey, bob.iid)

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        assert len(loaded) == 2
        assert alice.iid in loaded
        assert bob.iid in loaded

    def test_security_mutations_are_automatically_durable(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        store = TrustStore(persistence=persistence)

        store.verify_or_pin(alice.pubkey, alice.iid)
        assert persistence.load().get(alice.iid) is not None  # type: ignore[union-attr]
        store.add_trust_anchor(bob.pubkey, TrustLevel.BR_PROVISIONED)
        assert persistence.load().get(bob.iid) is not None  # type: ignore[union-attr]
        store.revoke(alice.iid)
        assert persistence.load().get(alice.iid).revoked  # type: ignore[union-attr]
        store.remove(bob.iid)
        assert persistence.load().get(bob.iid) is None  # type: ignore[union-attr]
        store.clear()
        restored = persistence.load()
        assert restored is not None
        assert len(restored) == 0

    def test_ordinary_persistence_failures_roll_back_every_security_mutation(self):
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)

        empty_mutations = [
            lambda store: store.verify_or_pin(alice.pubkey, alice.iid),
            lambda store: store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED),
        ]
        for mutate in empty_mutations:
            store = TrustStore(persistence=FailingTrustPersistence())
            with pytest.raises(OSError, match="ordinary persistence failure"):
                mutate(store)
            assert len(store) == 0
            assert store._persistence_revision == 0

        populated_mutations = [
            lambda store: store.verify_peer(alice.pubkey, alice.iid),
            lambda store: store.revoke(alice.iid),
            lambda store: store.remove(bob.iid),
            lambda store: store.clear(),
        ]
        for mutate in populated_mutations:
            store = TrustStore()
            store.verify_or_pin(alice.pubkey, alice.iid)
            store.verify_or_pin(bob.pubkey, bob.iid)
            before = store.list_entries(include_revoked=True)
            store._persistence = FailingTrustPersistence()
            with pytest.raises(OSError, match="ordinary persistence failure"):
                mutate(store)
            assert store.list_entries(include_revoked=True) == before
            assert store._persistence_revision == 0

    def test_preserves_trust_levels(self, tmp_path):
        """TrustStorePersistence preserves trust levels."""
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore()

        alice = Identity.from_seed(SEED_ALICE)
        store.add_trust_anchor(alice.pubkey, TrustLevel.BR_PROVISIONED)

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        entry = loaded.get(alice.iid)
        assert entry is not None
        assert entry.trust_level == TrustLevel.BR_PROVISIONED

    def test_preserves_revoked_status(self, tmp_path):
        """TrustStorePersistence preserves revoked status."""
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore()

        alice = Identity.from_seed(SEED_ALICE)
        store.verify_or_pin(alice.pubkey, alice.iid)
        store.revoke(alice.iid)

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        entry = loaded.get(alice.iid)
        assert entry is not None
        assert entry.revoked

    def test_preserves_metadata(self, tmp_path):
        """TrustStorePersistence preserves entry metadata."""
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore()

        alice = Identity.from_seed(SEED_ALICE)
        entry = TrustEntry.from_pubkey(
            alice.pubkey,
            metadata={"name": "alice", "role": "sensor"},
        )
        store._entries[entry.iid] = entry

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        loaded_entry = loaded.get(alice.iid)
        assert loaded_entry is not None
        assert loaded_entry.metadata["name"] == "alice"
        assert loaded_entry.metadata["role"] == "sensor"

    def test_load_returns_none_when_file_missing(self, tmp_path):
        """TrustStorePersistence returns None when file doesn't exist."""
        persistence = TrustStorePersistence(tmp_path)
        assert persistence.load() is None

    def test_load_raises_on_corrupt_json(self, tmp_path):
        """TrustStorePersistence raises on corrupt JSON (fail closed)."""
        persistence = TrustStorePersistence(tmp_path)
        file_path = tmp_path / "trust_store.json"
        file_path.write_text("{ not valid json }")
        file_path.chmod(0o600)

        with pytest.raises(TrustStorePersistenceError, match="corrupt JSON"):
            persistence.load()

    def test_load_wraps_json_integer_digit_limit(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        file_path = tmp_path / "trust_store.json"
        file_path.write_text('{"revision":' + "9" * 5000 + "}")
        file_path.chmod(0o600)

        with pytest.raises(TrustStorePersistenceError, match="corrupt JSON"):
            persistence.load()

    def test_load_raises_on_invalid_hex(self, tmp_path):
        """TrustStorePersistence raises on invalid hex in entry."""
        persistence = TrustStorePersistence(tmp_path)
        file_path = tmp_path / "trust_store.json"
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(file_path, [_entry_document(alice, pubkey_hex="not-hex")])

        with pytest.raises(TrustStorePersistenceError, match="invalid hex"):
            persistence.load()

    def test_load_raises_on_wrong_pubkey_length(self, tmp_path):
        """TrustStorePersistence raises on wrong pubkey length."""
        persistence = TrustStorePersistence(tmp_path)
        file_path = tmp_path / "trust_store.json"
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(file_path, [_entry_document(alice, pubkey_hex="0011")])

        with pytest.raises(TrustStorePersistenceError, match="must be 32 bytes"):
            persistence.load()

    def test_load_raises_on_pubkey_iid_mismatch(self, tmp_path):
        """TrustStorePersistence raises when pubkey doesn't derive to iid."""
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        bob = TrustEntry.from_pubkey(Identity.from_seed(SEED_BOB).pubkey)
        # Save Alice's entry
        store = TrustStore()
        store._entries[alice.iid] = alice
        persistence.save(store)
        # Tamper: replace Alice's iid with Bob's
        with open(tmp_path / "trust_store.json") as f:
            data = json.load(f)
        data["entries"][0]["iid_hex"] = bob.iid.hex()
        with open(tmp_path / "trust_store.json", "w") as f:
            json.dump(data, f)

        with pytest.raises(TrustStorePersistenceError, match="authentication failed"):
            persistence.load()

    def test_load_raises_on_duplicate_iid(self, tmp_path):
        """TrustStorePersistence raises on duplicate IIDs."""
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        # Manually create file with duplicate entries
        _write_trust_document(
            tmp_path / "trust_store.json",
            [_entry_document(alice), _entry_document(alice)],
        )

        with pytest.raises(TrustStorePersistenceError, match="duplicate iid"):
            persistence.load()

    def test_load_raises_on_invalid_trust_level(self, tmp_path):
        """TrustStorePersistence raises on invalid trust level."""
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(
            tmp_path / "trust_store.json",
            [_entry_document(alice, trust_level="INVALID_LEVEL")],
        )

        with pytest.raises(TrustStorePersistenceError, match="invalid trust_level"):
            persistence.load()

    def test_load_raises_on_negative_timestamp(self, tmp_path):
        """TrustStorePersistence raises on negative timestamps."""
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(
            tmp_path / "trust_store.json",
            [_entry_document(alice, first_seen=-1)],
        )

        with pytest.raises(TrustStorePersistenceError, match="non-negative"):
            persistence.load()

    def test_load_rejects_unrepresentable_integer_timestamp(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(
            tmp_path / "trust_store.json",
            [_entry_document(alice, first_seen=10**309, last_seen=10**309)],
        )

        with pytest.raises(TrustStorePersistenceError, match="timestamps must be finite"):
            persistence.load()

    def test_load_preserves_exact_large_integer_timestamp_order(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        alice = TrustEntry.from_pubkey(Identity.from_seed(SEED_ALICE).pubkey)
        _write_trust_document(
            tmp_path / "trust_store.json",
            [_entry_document(alice, first_seen=2**53, last_seen=2**53 + 1)],
        )

        loaded = persistence.load()
        assert loaded is not None
        entry = loaded.get(alice.iid)
        assert entry is not None
        assert entry.first_seen == 2**53
        assert entry.last_seen == 2**53 + 1

    def test_preserves_auto_pin_setting(self, tmp_path):
        """TrustStorePersistence preserves auto_pin setting."""
        persistence = TrustStorePersistence(tmp_path)
        store = TrustStore(auto_pin=False)

        persistence.save(store)
        loaded = persistence.load()

        assert loaded is not None
        assert loaded.auto_pin is False

    def test_stale_loaded_store_cannot_overwrite_newer_revision(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        initial = TrustStore()
        persistence.save(initial)
        first = persistence.load()
        stale = persistence.load()
        assert first is not None and stale is not None
        alice = Identity.from_seed(SEED_ALICE)
        bob = Identity.from_seed(SEED_BOB)
        first.verify_or_pin(alice.pubkey, alice.iid)
        with pytest.raises(TrustStorePersistenceError, match="stale"):
            stale.verify_or_pin(bob.pubkey, bob.iid)
        restored = persistence.load()
        assert restored is not None
        assert alice.iid in restored
        assert bob.iid not in restored

    def test_existing_revision_zero_is_rejected(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        _write_trust_document(tmp_path / "trust_store.json", [], revision=0)

        with pytest.raises(TrustStorePersistenceError, match="nonzero u64"):
            persistence.load()

    def test_revision_exhaustion_preserves_last_document(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        path = tmp_path / "trust_store.json"
        _write_trust_document(path, [], revision=(1 << 64) - 1)
        persistence._revision_anchor.advance(
            persistence._anchor_key,
            None,
            AnchoredState((1 << 64) - 1, hashlib.sha256(path.read_bytes()).digest()),
        )
        store = persistence.load()
        assert store is not None
        before = path.read_bytes()

        with pytest.raises(TrustStorePersistenceError, match="revision exhausted"):
            persistence.save(store)

        assert path.read_bytes() == before

    def test_trust_file_directory_and_lock_are_private(self, tmp_path):
        persistence = TrustStorePersistence(tmp_path)
        persistence.save(TrustStore())
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "trust_store.json").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / ".trust_store.lock").stat().st_mode) == 0o600

    def test_trust_store_symlink_fails_closed(self, tmp_path):
        target = tmp_path / "target.json"
        target.write_text("{}")
        os.symlink(target, tmp_path / "trust_store.json")
        persistence = TrustStorePersistence(tmp_path)
        with pytest.raises(TrustStorePersistenceError, match="unreadable"):
            persistence.load()
