#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Crash-safe JSON replacement shared by vector generators."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from collections.abc import Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator, TypedDict

_LOCK_NAME = ".lichen-vector-batch.lock"
_JOURNAL_NAME = ".lichen-vector-batch.transaction.json"
_JOURNAL_VERSION = 1
_PREPARATION_PREFIX = ".lichen-vector-prep-"
_MAX_ORPHAN_PREPARATIONS = 1024
_MAX_JOURNAL_ENTRIES = 1024
_MAX_JOURNAL_BYTES = 1024 * 1024
_MAX_RECOVERY_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_ARTIFACT_BYTES = _MAX_RECOVERY_ARTIFACT_BYTES
_MAX_BATCH_OUTPUT_BYTES = _MAX_RECOVERY_ARTIFACT_BYTES
_MAX_VECTOR_CHECK_BYTES = _MAX_RECOVERY_ARTIFACT_BYTES
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class _JournalEntry(TypedDict):
    target: str
    temporary: str
    backup: str | None
    mode: int
    existed: bool


def json_bytes(document: object) -> bytes:
    """Return the one canonical on-disk JSON representation."""
    return (json.dumps(document, indent=2, allow_nan=False) + "\n").encode()


def _bounded_json_bytes(document: object, maximum: int) -> bytes:
    """Serialize canonically and reject output beyond ``maximum`` bytes."""
    encoder = json.JSONEncoder(indent=2, allow_nan=False)
    chunks: list[bytes] = []
    total = 0
    for text_chunk in encoder.iterencode(document):
        # ensure_ascii=True is JSONEncoder's default, so character and UTF-8
        # byte lengths are identical. Check before allocating each byte chunk.
        total += len(text_chunk)
        if total >= maximum:  # Reserve the final canonical newline byte.
            raise ValueError("atomic JSON output exceeds artifact byte limit")
        chunks.append(text_chunk.encode("ascii"))
    chunks.append(b"\n")
    return b"".join(chunks)


def _read_exact_snapshot(
    descriptor: int,
    before: os.stat_result,
    maximum: int,
    unsafe_message: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    after = os.fstat(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if total > maximum or total != before.st_size or identity_after != identity_before:
        raise RuntimeError(unsafe_message)
    return b"".join(chunks)


def _open_owned_directory(path: Path) -> int:
    """Open and validate one directory; callers keep the descriptor pinned."""
    try:
        before = path.stat(follow_symlinks=False)
    except OSError:
        raise
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o022
    ):
        raise RuntimeError("atomic JSON parent directory is unsafe")
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError("atomic JSON parent directory is unsafe")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def read_bounded_exact(path: Path, maximum: int | None = None) -> bytes:
    """Read a stable, owned regular file without following either symlink."""
    if not isinstance(path, Path):
        raise TypeError("bounded vector reads require a pathlib.Path")
    if maximum is None:
        maximum = _MAX_VECTOR_CHECK_BYTES
    if type(maximum) is not int or maximum < 0:
        raise ValueError("bounded vector read limit must be a non-negative integer")
    parent_fd = _open_owned_directory(path.parent)
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise RuntimeError("vector artifact is unavailable or unsafe") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_size > maximum
            ):
                raise RuntimeError("vector artifact is unavailable or unsafe")
            return _read_exact_snapshot(
                descriptor,
                info,
                maximum,
                "vector artifact changed while being checked",
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _temporary_name(target: str) -> str:
    return f"{_PREPARATION_PREFIX}{target}.{secrets.token_hex(8)}.tmp"


def _prepare_at(parent_fd: int, target: str, encoded: bytes, mode: int) -> str:
    descriptor: int | None = None
    temporary = ""
    for _attempt in range(128):
        temporary = _temporary_name(target)
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                mode,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            continue
        break
    if descriptor is None:
        raise RuntimeError("unable to allocate atomic JSON preparation file")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            os.fchmod(stream.fileno(), mode)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent_fd)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return temporary


def _prepare(path: Path, encoded: bytes, mode: int) -> Path:
    """Test/recovery helper that prepares beneath a freshly pinned parent."""
    parent_fd = _open_owned_directory(path.parent)
    try:
        name = _prepare_at(parent_fd, path.name, encoded, mode)
    finally:
        os.close(parent_fd)
    return path.parent / name


def _fsync_directory(parent_fd: int) -> None:
    os.fsync(parent_fd)


@contextmanager
def _batch_lock(parent_fd: int) -> Iterator[None]:
    descriptor: int | None = None
    for _attempt in range(16):
        try:
            descriptor = os.open(
                _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | _NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            # APFS may transiently report ENOENT when two threads race the
            # first O_CREAT|O_NOFOLLOW open of the same directory entry.
            continue
        except OSError as exc:
            raise RuntimeError("atomic JSON batch lock is unavailable") from exc
        break
    if descriptor is None:
        raise RuntimeError("atomic JSON batch lock is unavailable")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("atomic JSON batch lock is unsafe")
        if info.st_mode & 0o077:
            os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError as exc:
        os.close(descriptor)
        raise RuntimeError("atomic JSON batch lock is unavailable") from exc
    except BaseException:
        os.close(descriptor)
        raise
    try:
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_journal_at(parent_fd: int, document: object) -> None:
    temporary = _prepare_at(
        parent_fd,
        _JOURNAL_NAME,
        _bounded_json_bytes(document, _MAX_JOURNAL_BYTES),
        0o600,
    )
    try:
        os.replace(
            temporary,
            _JOURNAL_NAME,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent_fd)


def _write_journal(path: Path, document: object) -> None:
    parent_fd = _open_owned_directory(path.parent)
    try:
        _write_journal_at(parent_fd, document)
    finally:
        os.close(parent_fd)


def _validated_journal(document: object) -> tuple[str, list[_JournalEntry]]:
    if (
        type(document) is not dict
        or set(document) != {"version", "phase", "entries"}
        or type(document.get("version")) is not int
        or document["version"] != _JOURNAL_VERSION
    ):
        raise RuntimeError("atomic JSON transaction journal is invalid")
    phase = document.get("phase")
    entries = document.get("entries")
    if (
        type(phase) is not str
        or phase not in ("prepared", "rolled_back", "committed")
        or type(entries) is not list
        or not entries
        or len(entries) > _MAX_JOURNAL_ENTRIES
    ):
        raise RuntimeError("atomic JSON transaction journal is invalid")
    validated: list[_JournalEntry] = []
    targets: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "target",
            "temporary",
            "backup",
            "mode",
            "existed",
        }:
            raise RuntimeError("atomic JSON transaction journal is invalid")
        target = entry.get("target")
        temporary = entry.get("temporary")
        backup = entry.get("backup")
        mode = entry.get("mode")
        existed = entry.get("existed")
        if (
            type(target) is not str
            or type(temporary) is not str
            or (backup is not None and type(backup) is not str)
        ):
            raise RuntimeError(
                "atomic JSON transaction journal contains an unsafe path"
            )
        names = (target, temporary) if backup is None else (target, temporary, backup)
        if any(
            not name or Path(name).name != name or name in (_LOCK_NAME, _JOURNAL_NAME)
            for name in names
        ):
            raise RuntimeError(
                "atomic JSON transaction journal contains an unsafe path"
            )
        preparation_prefix = f"{_PREPARATION_PREFIX}{target}."
        if (
            target.startswith(_PREPARATION_PREFIX)
            or not temporary.startswith(preparation_prefix)
            or not temporary.endswith(".tmp")
            or (
                backup is not None
                and (
                    not backup.startswith(preparation_prefix)
                    or not backup.endswith(".tmp")
                    or backup == temporary
                )
            )
        ):
            raise RuntimeError(
                "atomic JSON transaction journal contains an unsafe path"
            )
        if (
            type(mode) is not int
            or not 0 <= mode <= 0o7777
            or type(existed) is not bool
            or (existed and type(backup) is not str)
            or (not existed and backup is not None)
            or target in targets
        ):
            raise RuntimeError("atomic JSON transaction journal is invalid")
        targets.add(target)
        validated.append(
            {
                "target": target,
                "temporary": temporary,
                "backup": backup,
                "mode": mode,
                "existed": existed,
            }
        )
    return str(phase), validated


def _read_open_artifact_at(
    parent_fd: int,
    name: str,
    maximum: int,
    unavailable: str,
    unsafe: str,
    *,
    require_private: bool = False,
) -> bytes:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError(unavailable) from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or (require_private and info.st_mode & 0o077)
            or info.st_size > maximum
        ):
            raise RuntimeError(unsafe)
        return _read_exact_snapshot(descriptor, info, maximum, unsafe)
    finally:
        os.close(descriptor)


def _read_journal_at(parent_fd: int) -> object:
    raw = _read_open_artifact_at(
        parent_fd,
        _JOURNAL_NAME,
        _MAX_JOURNAL_BYTES,
        "atomic JSON transaction journal is unreadable",
        "atomic JSON transaction journal is unsafe",
        require_private=True,
    )
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("atomic JSON transaction journal is unreadable") from exc


def _read_journal(path: Path) -> object:
    parent_fd = _open_owned_directory(path.parent)
    try:
        return _read_journal_at(parent_fd)
    finally:
        os.close(parent_fd)


def _read_recovery_artifact_at(parent_fd: int, name: str) -> bytes:
    return _read_open_artifact_at(
        parent_fd,
        name,
        _MAX_RECOVERY_ARTIFACT_BYTES,
        "atomic JSON rollback backup is unavailable",
        "atomic JSON rollback backup is unsafe",
    )


def _read_recovery_artifact(path: Path) -> bytes:
    """Test helper that reads a recovery artifact beneath a pinned parent."""
    parent_fd = _open_owned_directory(path.parent)
    try:
        return _read_recovery_artifact_at(parent_fd, path.name)
    finally:
        os.close(parent_fd)


def _read_existing_target_at(parent_fd: int, name: str) -> tuple[bytes, int]:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError("atomic JSON destination is unreadable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_size > _MAX_RECOVERY_ARTIFACT_BYTES
        ):
            raise RuntimeError("atomic JSON destination exceeds recovery bounds")
        previous = _read_exact_snapshot(
            descriptor,
            info,
            _MAX_RECOVERY_ARTIFACT_BYTES,
            "atomic JSON destination changed while preparing recovery",
        )
        return previous, stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _validate_publishable_journal(entries: list[dict[str, object]]) -> None:
    """Ensure every phase this transaction may publish is recovery-readable."""
    if not entries or len(entries) > _MAX_JOURNAL_ENTRIES:
        raise ValueError("atomic JSON batch exceeds journal entry limit")
    for phase in ("prepared", "rolled_back", "committed"):
        document = {
            "version": _JOURNAL_VERSION,
            "phase": phase,
            "entries": entries,
        }
        _validated_journal(document)
        try:
            _bounded_json_bytes(document, _MAX_JOURNAL_BYTES)
        except ValueError as exc:
            raise ValueError("atomic JSON batch exceeds journal byte limit") from exc


def _recover_transaction(parent_fd: int) -> None:
    try:
        document = _read_journal_at(parent_fd)
    except FileNotFoundError:
        return
    phase, entries = _validated_journal(document)
    if phase == "prepared":
        for entry in entries:
            target = entry["target"]
            if entry["existed"]:
                backup = entry["backup"]
                assert backup is not None
                previous = _read_recovery_artifact_at(parent_fd, backup)
                rollback = _prepare_at(parent_fd, target, previous, entry["mode"])
                try:
                    os.replace(
                        rollback,
                        target,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                finally:
                    with suppress(FileNotFoundError):
                        os.unlink(rollback, dir_fd=parent_fd)
            else:
                with suppress(FileNotFoundError):
                    os.unlink(target, dir_fd=parent_fd)
        _fsync_directory(parent_fd)
        _write_journal_at(
            parent_fd,
            {
                "version": _JOURNAL_VERSION,
                "phase": "rolled_back",
                "entries": entries,
            },
        )
        _fsync_directory(parent_fd)
    for entry in entries:
        with suppress(FileNotFoundError):
            os.unlink(entry["temporary"], dir_fd=parent_fd)
        if entry["backup"] is not None:
            with suppress(FileNotFoundError):
                os.unlink(entry["backup"], dir_fd=parent_fd)
    with suppress(FileNotFoundError):
        os.unlink(_JOURNAL_NAME, dir_fd=parent_fd)
    _fsync_directory(parent_fd)


def _recover_orphan_preparations(parent_fd: int) -> None:
    """Remove bounded module-owned staging files while holding the batch lock."""
    orphans: list[str] = []
    with os.scandir(parent_fd) as entries:
        for item in entries:
            if not item.name.startswith(_PREPARATION_PREFIX):
                continue
            if len(orphans) >= _MAX_ORPHAN_PREPARATIONS:
                raise RuntimeError("too many orphaned atomic JSON preparation files")
            info = item.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("unsafe orphaned atomic JSON preparation path")
            orphans.append(item.name)
    for orphan in orphans:
        os.unlink(orphan, dir_fd=parent_fd)
    if orphans:
        _fsync_directory(parent_fd)


def atomic_write_json_batch(items: Sequence[tuple[Path, object]]) -> None:
    """Durably replace one locked, crash-recoverable same-directory batch."""
    if not items:
        raise ValueError("atomic JSON batch must not be empty")
    if len(items) > _MAX_JOURNAL_ENTRIES:
        raise ValueError("atomic JSON batch exceeds journal entry limit")
    paths = [path for path, _document in items]
    if any(not isinstance(path, Path) for path in paths):
        raise TypeError("atomic JSON destinations must be pathlib.Path values")
    if len(set(paths)) != len(paths):
        raise ValueError("atomic JSON batch destinations must be unique")
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        raise ValueError("atomic JSON batch destinations must share one directory")
    if any(
        not path.name
        or path.name in (_LOCK_NAME, _JOURNAL_NAME)
        or path.name.startswith(_PREPARATION_PREFIX)
        for path in paths
    ):
        raise ValueError("atomic JSON batch destinations must not use reserved names")
    encoded_items: list[tuple[str, bytes]] = []
    aggregate = 0
    artifact_limit = min(_MAX_OUTPUT_ARTIFACT_BYTES, _MAX_RECOVERY_ARTIFACT_BYTES)
    for path, document in items:
        encoded = _bounded_json_bytes(document, artifact_limit)
        aggregate += len(encoded)
        if aggregate > _MAX_BATCH_OUTPUT_BYTES:
            raise ValueError("atomic JSON batch exceeds aggregate byte limit")
        encoded_items.append((path.name, encoded))

    parent = parents.pop()
    parent_fd = _open_owned_directory(parent)
    try:
        with _batch_lock(parent_fd):
            _recover_transaction(parent_fd)
            _recover_orphan_preparations(parent_fd)
            entries: list[dict[str, object]] = []
            prepared_names: list[str] = []
            journal_published = False
            try:
                for target, encoded in encoded_items:
                    try:
                        previous, mode = _read_existing_target_at(parent_fd, target)
                        backup = _prepare_at(parent_fd, target, previous, mode)
                        prepared_names.append(backup)
                        existed = True
                    except FileNotFoundError:
                        mode = 0o644
                        backup = None
                        existed = False
                    temporary = _prepare_at(parent_fd, target, encoded, mode)
                    prepared_names.append(temporary)
                    entries.append(
                        {
                            "target": target,
                            "temporary": temporary,
                            "backup": backup,
                            "mode": mode,
                            "existed": existed,
                        }
                    )
                _validate_publishable_journal(entries)
                journal = {
                    "version": _JOURNAL_VERSION,
                    "phase": "prepared",
                    "entries": entries,
                }
                _write_journal_at(parent_fd, journal)
                journal_published = True
                _fsync_directory(parent_fd)
                for entry in entries:
                    os.replace(
                        str(entry["temporary"]),
                        str(entry["target"]),
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                _fsync_directory(parent_fd)
                journal["phase"] = "committed"
                _write_journal_at(parent_fd, journal)
                _fsync_directory(parent_fd)
            except BaseException as original_error:
                try:
                    if journal_published:
                        _recover_transaction(parent_fd)
                    else:
                        for prepared in prepared_names:
                            with suppress(FileNotFoundError):
                                os.unlink(prepared, dir_fd=parent_fd)
                        _fsync_directory(parent_fd)
                except BaseException:
                    raise RuntimeError(
                        "atomic JSON batch failed and durable recovery was incomplete"
                    ) from original_error
                raise
            _recover_transaction(parent_fd)
    finally:
        os.close(parent_fd)


def atomic_write_json(path: Path, document: object) -> None:
    """Serialize completely, then durably replace ``path`` from its directory."""
    atomic_write_json_batch([(path, document)])


__all__ = [
    "atomic_write_json",
    "atomic_write_json_batch",
    "json_bytes",
    "read_bounded_exact",
]
