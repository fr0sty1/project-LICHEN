# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import pytest

from lichen.link.epoch_store import EpochExhaustedError, EpochStore, EpochStoreError


def test_cold_boot_starts_at_128() -> None:
    store = EpochStore()
    assert store.boot_epoch() == 128
    assert store.load() == 128


def test_boot_bumps_persisted_epoch() -> None:
    store = EpochStore()
    store.save(200)
    assert store.boot_epoch() == 201
    store.save(127)
    assert store.boot_epoch() == 128


def test_epoch_255_is_exhausted() -> None:
    store = EpochStore()
    store.save(255)
    with pytest.raises(EpochExhaustedError):
        store.boot_epoch()


def test_storage_failure_fails_closed() -> None:
    store = EpochStore()
    store.save(130)
    store.fail_closed()
    with pytest.raises(EpochStoreError):
        store.load()
    with pytest.raises(EpochStoreError):
        store.save(131)
