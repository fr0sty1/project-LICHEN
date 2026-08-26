# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link-layer epoch persistence across restarts (spec 4.4).

Cold boot with no stored epoch, or a stored value in 0..127, starts at 128.
Values 128..254 bump by one on boot. Epoch 255 is exhausted; the identity
must rotate. Storage failures fail closed (no silent rollback).
"""

from __future__ import annotations


class EpochStoreError(Exception):
    """Epoch could not be loaded or saved."""


class EpochExhaustedError(EpochStoreError):
    """Epoch 255; rotate the link identity before transmitting."""


class EpochStore:
    """In-memory epoch holder used by tests and higher-level NV adapters."""

    __slots__ = ("_epoch", "_failed")

    def __init__(self) -> None:
        self._epoch: int | None = None
        self._failed = False

    def load(self) -> int | None:
        if self._failed:
            raise EpochStoreError("epoch storage read failed")
        return self._epoch

    def save(self, epoch: int) -> None:
        if type(epoch) is not int:
            raise TypeError("epoch must be int")
        if epoch < 0 or epoch > 255:
            raise ValueError("epoch must be uint8")
        if self._failed:
            raise EpochStoreError("epoch persistence failed")
        self._epoch = epoch

    def fail_closed(self) -> None:
        """Simulate storage failure; subsequent load/save raise."""
        self._failed = True

    def boot_epoch(self) -> int:
        """Return the epoch to use after restart, persisting it first."""
        stored = self.load()
        if stored is None or stored <= 127:
            nxt = 128
        elif stored <= 254:
            nxt = stored + 1
        else:
            raise EpochExhaustedError("link epoch exhausted at 255")
        self.save(nxt)
        return nxt
