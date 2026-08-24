# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Failure and durability tests for canonical vector JSON replacement."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

import atomic_json  # noqa: E402
import generate_dao_origin_signature as dao_generator  # noqa: E402
from atomic_json import atomic_write_json, atomic_write_json_batch  # noqa: E402


def _visible_files(path: Path) -> list[Path]:
    return sorted(item for item in path.iterdir() if not item.name.startswith("."))


def test_atomic_write_json_replaces_complete_document_and_preserves_mode(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_text('{"old": true}\n')
    destination.chmod(0o640)

    atomic_write_json(destination, {"vectors": [{"name": "complete"}]})

    assert json.loads(destination.read_text()) == {"vectors": [{"name": "complete"}]}
    assert stat.S_IMODE(destination.stat().st_mode) == 0o640
    assert _visible_files(tmp_path) == [destination]


def test_atomic_write_json_replace_failure_preserves_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "vectors.json"
    original = b'{"old": true}\n'
    destination.write_bytes(original)

    def fail_replace(
        _source: os.PathLike[str] | str,
        _destination: os.PathLike[str] | str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        raise OSError("injected replacement failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replacement failure"):
        atomic_write_json(destination, {"new": True})

    assert destination.read_bytes() == original
    assert _visible_files(tmp_path) == [destination]


def test_atomic_write_json_write_failure_preserves_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "dao_origin_signature.json"
    original = b'{"old": true}\n'
    destination.write_bytes(original)
    real_fdopen = os.fdopen

    class FailingStream:
        def __init__(self, stream: object) -> None:
            self._stream = stream

        def __enter__(self) -> FailingStream:
            self._stream.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, *args: object) -> object:
            return self._stream.__exit__(*args)  # type: ignore[attr-defined]

        def fileno(self) -> int:
            return self._stream.fileno()  # type: ignore[attr-defined,no-any-return]

        def write(self, _data: bytes) -> int:
            raise OSError("injected write failure")

    def fail_write(descriptor: int, mode: str) -> FailingStream:
        return FailingStream(real_fdopen(descriptor, mode))

    monkeypatch.setattr(os, "fdopen", fail_write)
    with pytest.raises(OSError, match="injected write failure"):
        atomic_write_json(destination, {"new": True})

    assert destination.read_bytes() == original
    assert _visible_files(tmp_path) == [destination]


@pytest.mark.parametrize("failure", ["write", "replace"])
def test_dao_generator_failure_preserves_canonical_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    destination = tmp_path / "dao_origin_signature.json"
    original = b'{"canonical": true}\n'
    destination.write_bytes(original)
    monkeypatch.setattr(dao_generator, "OUTPUT", destination)

    if failure == "replace":

        def fail_replace(
            _source: os.PathLike[str] | str,
            _destination: os.PathLike[str] | str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
        ) -> None:
            raise OSError("injected DAO replace failure")

        monkeypatch.setattr(os, "replace", fail_replace)
    else:
        real_fdopen = os.fdopen

        class FailingDaoStream:
            def __init__(self, stream: object) -> None:
                self._stream = stream

            def __enter__(self) -> FailingDaoStream:
                self._stream.__enter__()  # type: ignore[attr-defined]
                return self

            def __exit__(self, *args: object) -> object:
                return self._stream.__exit__(*args)  # type: ignore[attr-defined]

            def fileno(self) -> int:
                return self._stream.fileno()  # type: ignore[attr-defined,no-any-return]

            def write(self, _data: bytes) -> int:
                raise OSError("injected DAO write failure")

        def fail_write(descriptor: int, mode: str) -> FailingDaoStream:
            return FailingDaoStream(real_fdopen(descriptor, mode))

        monkeypatch.setattr(os, "fdopen", fail_write)

    with pytest.raises(OSError, match=rf"injected DAO {failure} failure"):
        dao_generator.write_output({"canonical": False})

    assert destination.read_bytes() == original
    assert _visible_files(tmp_path) == [destination]


@pytest.mark.parametrize("non_finite", [float("nan"), float("inf"), float("-inf")])
def test_atomic_write_json_rejects_non_finite_values_before_touching_destination(
    tmp_path: Path,
    non_finite: float,
) -> None:
    destination = tmp_path / "vectors.json"
    original = b'{"old": true}\n'
    destination.write_bytes(original)

    with pytest.raises(ValueError, match="Out of range float values"):
        atomic_write_json(destination, {"invalid": non_finite})

    assert destination.read_bytes() == original
    assert _visible_files(tmp_path) == [destination]


def test_atomic_write_json_batch_rolls_back_first_replace_when_second_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_original = b'{"generation": 1}\n'
    second_original = b'{"generation": 1}\n'
    first.write_bytes(first_original)
    second.write_bytes(second_original)
    real_replace = os.replace
    calls = 0

    def fail_second_replace(
        source: os.PathLike[str] | str,
        destination: os.PathLike[str] | str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected second replacement failure")
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "replace", fail_second_replace)
    with pytest.raises(OSError, match="injected second replacement failure"):
        atomic_write_json_batch(
            [
                (first, {"generation": 2}),
                (second, {"generation": 2}),
            ]
        )

    assert first.read_bytes() == first_original
    assert second.read_bytes() == second_original
    assert _visible_files(tmp_path) == [first, second]


@pytest.mark.parametrize(
    "reserved_name",
    [
        ".lichen-vector-batch.lock",
        ".lichen-vector-batch.transaction.json",
    ],
)
def test_atomic_batch_rejects_reserved_target_before_mutation(
    tmp_path: Path,
    reserved_name: str,
) -> None:
    reserved = tmp_path / reserved_name
    sentinel = b"reserved sentinel\n"
    reserved.write_bytes(sentinel)

    with pytest.raises(ValueError, match="reserved names"):
        atomic_write_json_batch([(reserved, {"generation": 2})])

    assert reserved.read_bytes() == sentinel
    assert list(tmp_path.iterdir()) == [reserved]


def test_atomic_write_json_directory_open_failure_is_not_silently_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "vectors.json"
    original = b'{"generation": 1}\n'
    destination.write_bytes(original)
    real_open = os.open
    calls = 0

    def fail_first_directory_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal calls
        if Path(path) == tmp_path and calls == 0:
            calls += 1
            raise OSError("injected directory open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_first_directory_open)
    with pytest.raises(OSError, match="injected directory open failure"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == original
    assert _visible_files(tmp_path) == [destination]


def test_next_writer_recovers_a_crash_after_partial_batch_replace(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b'{"generation": 1}\n')
    second.write_bytes(b'{"generation": 1}\n')
    first_backup = atomic_json._prepare(first, first.read_bytes(), 0o644)
    second_backup = atomic_json._prepare(second, second.read_bytes(), 0o644)
    first_new = atomic_json._prepare(first, b'{"generation": 2}\n', 0o644)
    second_new = atomic_json._prepare(second, b'{"generation": 2}\n', 0o644)
    entries = [
        {
            "target": first.name,
            "temporary": first_new.name,
            "backup": first_backup.name,
            "mode": 0o644,
            "existed": True,
        },
        {
            "target": second.name,
            "temporary": second_new.name,
            "backup": second_backup.name,
            "mode": 0o644,
            "existed": True,
        },
    ]
    atomic_json._write_journal(
        tmp_path / ".lichen-vector-batch.transaction.json",
        {"version": 1, "phase": "prepared", "entries": entries},
    )
    os.replace(first_new, first)

    atomic_write_json_batch([(first, {"generation": 3}), (second, {"generation": 3})])

    assert json.loads(first.read_text()) == {"generation": 3}
    assert json.loads(second.read_text()) == {"generation": 3}
    assert not (tmp_path / ".lichen-vector-batch.transaction.json").exists()


def test_rolled_back_checkpoint_makes_partial_cleanup_recoverable(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_original = b'{"generation": 1}\n'
    second_original = b'{"generation": 1}\n'
    first.write_bytes(first_original)
    second.write_bytes(second_original)
    first_backup = atomic_json._prepare(first, first_original, 0o644)
    second_backup = atomic_json._prepare(second, second_original, 0o644)
    first_new = atomic_json._prepare(first, b'{"generation": 2}\n', 0o644)
    second_new = atomic_json._prepare(second, b'{"generation": 2}\n', 0o644)
    entries = [
        {
            "target": first.name,
            "temporary": first_new.name,
            "backup": first_backup.name,
            "mode": 0o644,
            "existed": True,
        },
        {
            "target": second.name,
            "temporary": second_new.name,
            "backup": second_backup.name,
            "mode": 0o644,
            "existed": True,
        },
    ]
    os.replace(first_new, first)
    os.replace(second_new, second)
    first.write_bytes(first_original)
    second.write_bytes(second_original)
    atomic_json._write_journal(
        tmp_path / ".lichen-vector-batch.transaction.json",
        {"version": 1, "phase": "rolled_back", "entries": entries},
    )
    first_backup.unlink()

    atomic_write_json_batch([(first, {"generation": 3}), (second, {"generation": 3})])

    assert json.loads(first.read_text()) == {"generation": 3}
    assert json.loads(second.read_text()) == {"generation": 3}
    assert not (tmp_path / ".lichen-vector-batch.transaction.json").exists()


@pytest.mark.parametrize(
    "document",
    [
        {"version": True, "phase": "prepared", "entries": []},
        {"version": 1, "phase": "prepared", "entries": [], "extra": None},
        {
            "version": 1,
            "phase": "prepared",
            "entries": [
                {
                    "target": "first.json",
                    "temporary": ".first.tmp",
                    "backup": None,
                    "mode": 0o644,
                    "existed": False,
                    "extra": None,
                }
            ],
        },
    ],
)
def test_recovery_rejects_non_exact_journal_schema(
    tmp_path: Path,
    document: object,
) -> None:
    atomic_json._write_journal(
        tmp_path / ".lichen-vector-batch.transaction.json",
        document,
    )

    with pytest.raises(RuntimeError, match="journal is invalid"):
        atomic_write_json(tmp_path / "first.json", {"generation": 1})

    assert not (tmp_path / "first.json").exists()


def test_recovery_rejects_arbitrary_backup_name_without_overwriting_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "first.json"
    unrelated = tmp_path / "unrelated.json"
    original = b'{"generation": 1}\n'
    target.write_bytes(original)
    unrelated.write_bytes(b'{"secret": true}\n')
    atomic_json._write_journal(
        tmp_path / ".lichen-vector-batch.transaction.json",
        {
            "version": 1,
            "phase": "prepared",
            "entries": [
                {
                    "target": target.name,
                    "temporary": ".lichen-vector-prep-first.json.new.tmp",
                    "backup": unrelated.name,
                    "mode": 0o644,
                    "existed": True,
                }
            ],
        },
    )

    with pytest.raises(RuntimeError, match="unsafe path"):
        atomic_write_json(target, {"generation": 2})

    assert target.read_bytes() == original


def test_recovery_rejects_oversized_journal_before_json_decode(tmp_path: Path) -> None:
    journal = tmp_path / ".lichen-vector-batch.transaction.json"
    journal.write_bytes(b" " * (atomic_json._MAX_JOURNAL_BYTES + 1))
    journal.chmod(0o600)

    with pytest.raises(RuntimeError, match="journal is unsafe"):
        atomic_write_json(tmp_path / "first.json", {"generation": 1})


def test_prepare_failure_before_journal_cleans_every_staging_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "vectors.json"
    original = b'{"generation": 1}\n'
    destination.write_bytes(original)
    real_prepare = atomic_json._prepare_at
    calls = 0

    def fail_second_prepare(parent_fd: int, target: str, encoded: bytes, mode: int) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected new-content preparation failure")
        return real_prepare(parent_fd, target, encoded, mode)

    monkeypatch.setattr(atomic_json, "_prepare_at", fail_second_prepare)
    with pytest.raises(OSError, match="new-content preparation"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".lichen-vector-prep-*"))


def test_next_locked_writer_recovers_bounded_orphan_preparations(tmp_path: Path) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_bytes(b'{"generation": 1}\n')
    orphans = [atomic_json._prepare(destination, b"orphan", 0o600) for _ in range(3)]

    atomic_write_json(destination, {"generation": 2})

    assert json.loads(destination.read_text()) == {"generation": 2}
    assert all(not orphan.exists() for orphan in orphans)


def test_orphan_scan_is_bounded_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_bytes(b'{"generation": 1}\n')
    monkeypatch.setattr(atomic_json, "_MAX_ORPHAN_PREPARATIONS", 2)
    orphans = [atomic_json._prepare(destination, b"orphan", 0o600) for _ in range(3)]

    with pytest.raises(RuntimeError, match="too many orphaned"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == b'{"generation": 1}\n'
    assert all(orphan.exists() for orphan in orphans)


def test_concurrent_batch_writers_never_publish_mixed_generations(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    barrier = threading.Barrier(3)
    errors: list[BaseException] = []

    def writer(generation: int) -> None:
        try:
            barrier.wait()
            for _ in range(10):
                atomic_write_json_batch(
                    [
                        (first, {"generation": generation}),
                        (second, {"generation": generation}),
                    ]
                )
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(generation,)) for generation in (1, 2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert not errors, [(error, error.__cause__) for error in errors]
    assert json.loads(first.read_text()) == json.loads(second.read_text())


def test_batch_rejects_entry_count_above_recovery_limit_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(atomic_json, "_MAX_JOURNAL_ENTRIES", 1)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    with pytest.raises(ValueError, match="journal entry limit"):
        atomic_write_json_batch([(first, {}), (second, {})])

    assert list(tmp_path.iterdir()) == []


def test_batch_rejects_journal_too_large_for_recovery_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "destination-with-a-long-name.json"
    original = b"{}\n"
    destination.write_bytes(original)
    monkeypatch.setattr(atomic_json, "_MAX_JOURNAL_BYTES", 64)

    with pytest.raises(ValueError, match="journal byte limit"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == original
    assert not (tmp_path / ".lichen-vector-batch.transaction.json").exists()
    assert not list(tmp_path.glob(".lichen-vector-prep-*"))


def test_batch_rejects_backup_above_recovery_limit_before_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "vectors.json"
    original = b"12345"
    destination.write_bytes(original)
    monkeypatch.setattr(atomic_json, "_MAX_RECOVERY_ARTIFACT_BYTES", 4)

    with pytest.raises(RuntimeError, match="exceeds recovery bounds"):
        atomic_write_json(destination, {})

    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".lichen-vector-prep-*"))


def test_recovery_bounds_accept_exact_size_backup_and_all_journal_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_bytes(b"12345")
    monkeypatch.setattr(atomic_json, "_MAX_RECOVERY_ARTIFACT_BYTES", 5)
    published: list[object] = []
    write_journal = atomic_json._write_journal_at

    def record_journal(parent_fd: int, document: object) -> None:
        assert len(atomic_json.json_bytes(document)) <= atomic_json._MAX_JOURNAL_BYTES
        atomic_json._validated_journal(document)
        published.append(document)
        write_journal(parent_fd, document)

    monkeypatch.setattr(atomic_json, "_write_journal_at", record_journal)
    atomic_write_json(destination, {})

    assert json.loads(destination.read_text()) == {}
    assert published


def test_journal_read_rejects_post_stat_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = tmp_path / ".lichen-vector-batch.transaction.json"
    journal.write_bytes(b"{}")
    journal.chmod(0o600)
    monkeypatch.setattr(
        os,
        "read",
        lambda _descriptor, _count: b" " * (atomic_json._MAX_JOURNAL_BYTES + 1),
    )

    with pytest.raises(RuntimeError, match="journal is unsafe"):
        atomic_json._read_journal(journal)


def test_recovery_artifact_read_rejects_post_stat_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "backup"
    artifact.write_bytes(b"ok")
    monkeypatch.setattr(
        os,
        "read",
        lambda _descriptor, _count: b"x" * (atomic_json._MAX_RECOVERY_ARTIFACT_BYTES + 1),
    )

    with pytest.raises(RuntimeError, match="backup is unsafe"):
        atomic_json._read_recovery_artifact(artifact)


def test_batch_lock_rejects_symlink_without_touching_destination(tmp_path: Path) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_bytes(b"{}\n")
    lock_target = tmp_path / "unrelated"
    lock_target.write_bytes(b"sentinel")
    os.symlink(lock_target, tmp_path / ".lichen-vector-batch.lock")

    with pytest.raises(RuntimeError, match="lock is unavailable"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == b"{}\n"
    assert lock_target.read_bytes() == b"sentinel"


def test_batch_rejects_group_writable_parent_before_lock(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)
    try:
        with pytest.raises(RuntimeError, match="parent directory is unsafe"):
            atomic_write_json(unsafe / "vectors.json", {"generation": 1})
        assert not (unsafe / ".lichen-vector-batch.lock").exists()
    finally:
        unsafe.chmod(0o700)


def test_batch_rejects_symlinked_parent_before_lock(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    os.symlink(actual, linked)

    with pytest.raises(RuntimeError, match="parent directory is unsafe"):
        atomic_write_json(linked / "vectors.json", {"generation": 1})

    assert not (actual / ".lichen-vector-batch.lock").exists()


def test_batch_rejects_non_regular_destination_before_preparation(tmp_path: Path) -> None:
    destination = tmp_path / "vectors.json"
    destination.mkdir()

    with pytest.raises(RuntimeError, match="exceeds recovery bounds"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.is_dir()
    assert not list(tmp_path.glob(".lichen-vector-prep-*"))


def test_existing_target_short_read_cannot_publish_truncated_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "vectors.json"
    destination.write_bytes(b"12345")
    monkeypatch.setattr(os, "read", lambda _descriptor, _count: b"1")

    with pytest.raises(RuntimeError, match="changed while preparing"):
        atomic_write_json(destination, {"generation": 2})

    assert destination.read_bytes() == b"12345"
    assert not list(tmp_path.glob(".lichen-vector-prep-*"))


def test_batch_rejects_oversized_new_artifact_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "vectors.json"
    original = b'{"generation": 1}\n'
    destination.write_bytes(original)
    monkeypatch.setattr(atomic_json, "_MAX_OUTPUT_ARTIFACT_BYTES", 16)

    with pytest.raises(ValueError, match="artifact byte limit"):
        atomic_write_json(destination, {"payload": "x" * 32})

    assert destination.read_bytes() == original
    assert sorted(item.name for item in tmp_path.iterdir()) == [destination.name]


def test_bounded_encoder_matches_canonical_bytes_and_honors_exact_boundary() -> None:
    document = {"unicode": "lichen \U0001f344", "nested": [True, None, 42]}
    canonical = atomic_json.json_bytes(document)

    assert atomic_json._bounded_json_bytes(document, len(canonical)) == canonical
    with pytest.raises(ValueError, match="artifact byte limit"):
        atomic_json._bounded_json_bytes(document, len(canonical) - 1)


def test_batch_rejects_oversized_aggregate_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b"first sentinel")
    second.write_bytes(b"second sentinel")
    monkeypatch.setattr(atomic_json, "_MAX_OUTPUT_ARTIFACT_BYTES", 64)
    monkeypatch.setattr(atomic_json, "_MAX_BATCH_OUTPUT_BYTES", 32)

    with pytest.raises(ValueError, match="aggregate byte limit"):
        atomic_write_json_batch([(first, {"value": "a" * 8}), (second, {"value": "b" * 8})])

    assert first.read_bytes() == b"first sentinel"
    assert second.read_bytes() == b"second sentinel"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["first.json", "second.json"]


def test_batch_remains_bound_to_original_directory_inode_during_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = tmp_path / "active"
    active.mkdir(mode=0o700)
    destination = active / "vectors.json"
    destination.write_bytes(b'{"generation": 1}\n')
    displaced = tmp_path / "displaced"
    real_recover = atomic_json._recover_transaction
    swapped = False

    def swap_after_lock(parent_fd: int) -> None:
        nonlocal swapped
        real_recover(parent_fd)
        if not swapped:
            swapped = True
            active.rename(displaced)
            active.mkdir(mode=0o700)

    monkeypatch.setattr(atomic_json, "_recover_transaction", swap_after_lock)
    atomic_write_json(destination, {"generation": 2})

    assert not destination.exists()
    assert not list(active.iterdir())
    assert json.loads((displaced / destination.name).read_text()) == {"generation": 2}


def test_bounded_exact_reader_rejects_symlink_and_nonregular_file(
    tmp_path: Path,
) -> None:
    actual = tmp_path / "actual.json"
    actual.write_bytes(b"{}\n")
    linked = tmp_path / "linked.json"
    os.symlink(actual, linked)

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        atomic_json.read_bounded_exact(linked)
    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        atomic_json.read_bounded_exact(tmp_path)


def test_bounded_exact_reader_rejects_oversize_and_concurrent_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "vectors.json"
    artifact.write_bytes(b"stable")

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        atomic_json.read_bounded_exact(artifact, maximum=5)

    real_read = os.read
    changed = False

    def change_before_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        if not changed:
            changed = True
            artifact.write_bytes(b"change")
        return real_read(descriptor, count)

    monkeypatch.setattr(os, "read", change_before_read)
    with pytest.raises(RuntimeError, match="changed while being checked"):
        atomic_json.read_bounded_exact(artifact)
