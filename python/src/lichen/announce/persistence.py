# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Rollback-resistant persistence for origin-authenticated Announce state."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Protocol

from lichen.crypto.identity import Identity, _pubkey_to_iid
from lichen.crypto.schnorr48 import sign, verify
from lichen.gradient import MAX_ENTRIES

_STATE_DOMAIN = b"LICHEN-ANNOUNCE-STATE-v1\x00"
_FORMAT = 2
_MAX_STATE_BYTES = 256 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class AnnouncePersistenceError(RuntimeError):
    """Announce trust state is unavailable, corrupt, stale, or not durable."""


class RevisionAnchor(Protocol):
    """Independent monotonic storage used to detect file rollback/deletion."""

    def read(self, local_pubkey: bytes) -> int | None: ...

    def advance(self, local_pubkey: bytes, expected: int | None, revision: int) -> None: ...


class AnnounceStatePersistence:
    """Signed single-file journal with independent monotonic rollback anchor."""

    def __init__(
        self,
        path: str | Path,
        identity: Identity,
        revision_anchor: RevisionAnchor,
        *,
        allow_bootstrap: bool,
    ) -> None:
        if type(allow_bootstrap) is not bool:
            raise AnnouncePersistenceError("allow_bootstrap must be an exact boolean")
        self._path = Path(f"{path}.announce")
        self._lock_path = Path(f"{path}.announce.lock")
        self._identity = identity
        self._anchor = revision_anchor
        self._anchor_key = hashlib.sha256(_STATE_DOMAIN + identity.pubkey).digest()
        self._revision = 0
        self._local_sequence = 0
        self._pins: OrderedDict[bytes, bytes] = OrderedDict()
        self._floors: OrderedDict[bytes, int] = OrderedDict()
        self._prepare_directory()
        with self._lock():
            if not os.path.lexists(self._path):
                external = self._anchor.read(self._anchor_key)
                if external is not None:
                    raise AnnouncePersistenceError("announce persistence was deleted")
                if not allow_bootstrap:
                    raise AnnouncePersistenceError(
                        "announce persistence requires explicit bootstrap"
                    )
                self._write_state(1, self._local_sequence, self._pins, self._floors)
                self._anchor.advance(self._anchor_key, None, 1)
                self._revision = 1
            else:
                self._load_locked()

    @property
    def pins(self) -> OrderedDict[bytes, bytes]:
        return OrderedDict(self._pins)

    @property
    def floors(self) -> OrderedDict[bytes, int]:
        return OrderedDict(self._floors)

    @property
    def local_sequence(self) -> int:
        """Return the last crash-safely reserved local Announce sequence."""
        return self._local_sequence

    def reserve_local_sequence(self, sequence: int) -> None:
        """Durably reserve the exact next local sequence before transmission."""
        if type(sequence) is not int or not 0 <= sequence <= 0xFFFF:
            raise AnnouncePersistenceError("local announce sequence must fit in u16")
        with self._lock():
            disk_revision, local_sequence, disk_pins, disk_floors = self._read_state()
            if disk_revision != self._revision:
                raise AnnouncePersistenceError("stale announce persistence writer")
            expected = (local_sequence + 1) & 0xFFFF
            if sequence != expected:
                raise AnnouncePersistenceError(
                    f"local announce sequence must reserve exact successor {expected}"
                )
            self._publish_state(
                disk_revision,
                sequence,
                disk_pins,
                disk_floors,
            )

    def commit(self, iid: bytes, pubkey: bytes, sequence: int) -> None:
        """Atomically commit one already-verified pin and replay floor."""
        if type(iid) is not bytes or len(iid) != 8:
            raise AnnouncePersistenceError("announce IID must be exact 8-byte bytes")
        if type(pubkey) is not bytes or len(pubkey) != 32 or _pubkey_to_iid(pubkey) != iid:
            raise AnnouncePersistenceError("announce key does not derive to IID")
        if type(sequence) is not int or not 0 <= sequence <= 0xFFFF:
            raise AnnouncePersistenceError("announce sequence must fit in u16")
        with self._lock():
            disk_revision, local_sequence, disk_pins, disk_floors = self._read_state()
            if disk_revision != self._revision:
                raise AnnouncePersistenceError("stale announce persistence writer")
            incumbent = disk_pins.get(iid)
            if incumbent is not None and incumbent != pubkey:
                raise AnnouncePersistenceError("persisted announce key mismatch")
            previous_floor = disk_floors.get(iid)
            if previous_floor is not None:
                sequence_delta = (sequence - previous_floor) & 0xFFFF
                if sequence_delta == 0:
                    return
                if sequence_delta >= 0x8000:
                    raise AnnouncePersistenceError(
                        "announce replay floor must advance monotonically"
                    )
            disk_pins[iid] = pubkey
            disk_pins.move_to_end(iid)
            disk_floors[iid] = sequence
            disk_floors.move_to_end(iid)
            if len(disk_pins) > MAX_ENTRIES or len(disk_floors) > MAX_ENTRIES:
                raise AnnouncePersistenceError("announce persistence capacity exceeded")
            self._publish_state(
                disk_revision,
                local_sequence,
                disk_pins,
                disk_floors,
            )

    def _publish_state(
        self,
        disk_revision: int,
        local_sequence: int,
        pins: OrderedDict[bytes, bytes],
        floors: OrderedDict[bytes, int],
    ) -> None:
        new_revision = disk_revision + 1
        if new_revision > (1 << 64) - 1:
            raise AnnouncePersistenceError("announce persistence revision exhausted")
        self._write_state(new_revision, local_sequence, pins, floors)
        try:
            self._anchor.advance(self._anchor_key, disk_revision, new_revision)
        except BaseException as exc:
            raise AnnouncePersistenceError("announce rollback anchor update failed") from exc
        self._revision = new_revision
        self._local_sequence = local_sequence
        self._pins = pins
        self._floors = floors

    def _prepare_directory(self) -> None:
        parent = self._path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise AnnouncePersistenceError("announce persistence directory must be private")

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        try:
            descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise AnnouncePersistenceError("announce lock must be an owned private file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise AnnouncePersistenceError(f"announce persistence lock failed: {exc}") from exc
        except BaseException:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def _canonical(self, document: Mapping[str, object]) -> bytes:
        return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    def _write_state(
        self,
        revision: int,
        local_sequence: int,
        pins: Mapping[bytes, bytes],
        floors: Mapping[bytes, int],
    ) -> None:
        body: dict[str, object] = {
            "format": _FORMAT,
            "revision": revision,
            "local_pubkey": self._identity.pubkey.hex(),
            "local_sequence": local_sequence,
            "pins": [[iid.hex(), key.hex()] for iid, key in pins.items()],
            "floors": [[iid.hex(), floor] for iid, floor in floors.items()],
        }
        signature = sign(
            self._identity.privkey,
            self._identity.pubkey,
            _STATE_DOMAIN + self._canonical(body),
        )
        encoded = self._canonical({**body, "signature": signature.hex()}) + b"\n"
        if len(encoded) > _MAX_STATE_BYTES:
            raise AnnouncePersistenceError("announce state exceeds size limit")
        fd, tmp_name = tempfile.mkstemp(prefix=".announce.", suffix=".tmp", dir=self._path.parent)
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as file:
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, self._path)
            dir_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _load_locked(self) -> None:
        revision, local_sequence, pins, floors = self._read_state()
        external = self._anchor.read(self._anchor_key)
        if external is None or revision < external or revision > external + 1:
            raise AnnouncePersistenceError("announce persistence rollback detected")
        if revision == external + 1:
            self._anchor.advance(self._anchor_key, external, revision)
        self._revision = revision
        self._local_sequence = local_sequence
        self._pins = pins
        self._floors = floors

    def _read_state(
        self,
    ) -> tuple[int, int, OrderedDict[bytes, bytes], OrderedDict[bytes, int]]:
        try:
            descriptor = os.open(self._path, os.O_RDONLY | _NOFOLLOW)
        except OSError as exc:
            raise AnnouncePersistenceError(f"announce state unreadable: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > _MAX_STATE_BYTES
            ):
                raise AnnouncePersistenceError("announce state file is unsafe")
            raw = os.read(descriptor, _MAX_STATE_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            document = json.loads(raw)
            if type(document) is not dict or set(document) != {
                "format",
                "revision",
                "local_pubkey",
                "local_sequence",
                "pins",
                "floors",
                "signature",
            }:
                raise ValueError("invalid document schema")
            signature_hex = document.pop("signature")
            if type(signature_hex) is not str:
                raise ValueError("invalid signature")
            signature = bytes.fromhex(signature_hex)
            if not verify(
                self._identity.pubkey,
                _STATE_DOMAIN + self._canonical(document),
                signature,
            ):
                raise ValueError("invalid state signature")
            if (
                document["format"] != _FORMAT
                or document["local_pubkey"] != self._identity.pubkey.hex()
            ):
                raise ValueError("wrong format or local identity")
            revision = document["revision"]
            if type(revision) is not int or not 1 <= revision <= (1 << 64) - 1:
                raise ValueError("invalid revision")
            local_sequence = document["local_sequence"]
            if type(local_sequence) is not int or not 0 <= local_sequence <= 0xFFFF:
                raise ValueError("invalid local sequence")
            pins = self._parse_pins(document["pins"])
            floors = self._parse_floors(document["floors"], pins)
            return revision, local_sequence, pins, floors
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise AnnouncePersistenceError(f"announce state corrupt: {exc}") from exc

    @staticmethod
    def _parse_pins(raw: object) -> OrderedDict[bytes, bytes]:
        if type(raw) is not list or len(raw) > MAX_ENTRIES:
            raise ValueError("invalid pins")
        result: OrderedDict[bytes, bytes] = OrderedDict()
        for item in raw:
            if (
                type(item) is not list
                or len(item) != 2
                or any(type(value) is not str for value in item)
            ):
                raise ValueError("invalid pin entry")
            iid, pubkey = bytes.fromhex(item[0]), bytes.fromhex(item[1])
            if len(iid) != 8 or len(pubkey) != 32 or _pubkey_to_iid(pubkey) != iid or iid in result:
                raise ValueError("invalid pin binding")
            result[iid] = pubkey
        return result

    @staticmethod
    def _parse_floors(raw: object, pins: Mapping[bytes, bytes]) -> OrderedDict[bytes, int]:
        if type(raw) is not list or len(raw) > MAX_ENTRIES:
            raise ValueError("invalid floors")
        result: OrderedDict[bytes, int] = OrderedDict()
        for item in raw:
            if type(item) is not list or len(item) != 2 or type(item[0]) is not str:
                raise ValueError("invalid floor entry")
            iid, floor = bytes.fromhex(item[0]), item[1]
            if (
                iid not in pins
                or iid in result
                or type(floor) is not int
                or not 0 <= floor <= 0xFFFF
            ):
                raise ValueError("invalid replay floor")
            result[iid] = floor
        if set(result) != set(pins):
            raise ValueError("pins and floors differ")
        return result
