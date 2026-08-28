# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Atomic OSCORE active-context key-update tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from lichen.crypto.oscore import (
    MemorySecurityContext,
    OscoreContextParameters,
    OscoreContextSlot,
    OscoreKeyUpdateError,
    OscoreKeyUpdateState,
)

VECTORS = json.loads(
    (Path(__file__).parents[3] / "test/vectors/oscore_key_update.json").read_text()
)


def parameters(data: dict[str, Any]) -> OscoreContextParameters:
    """Decode one canonical vector context."""
    return OscoreContextParameters(
        master_secret=bytes.fromhex(data["master_secret"]),
        master_salt=bytes.fromhex(data["master_salt"]),
        sender_id=bytes.fromhex(data["sender_id"]),
        recipient_id=bytes.fromhex(data["recipient_id"]),
        algorithm=10,
        hashfun="sha256",
        window_size=32,
        id_context=bytes.fromhex(data["id_context"]) if data["id_context"] else None,
    )


def context(data: dict[str, Any]) -> MemorySecurityContext:
    return MemorySecurityContext.from_parameters(parameters(data), starting_sequence_number=0)


@dataclass
class AtomicStore:
    state: OscoreKeyUpdateState
    sender_high_water: int
    conflict: bool = False
    fail: bool = False

    def load(self) -> OscoreKeyUpdateState | None:
        if self.fail:
            raise OSError("simulated durable-store failure")
        return self.state

    def compare_exchange(
        self,
        expected: OscoreKeyUpdateState,
        replacement: OscoreKeyUpdateState,
        replacement_sender_high_water: int,
    ) -> bool:
        if self.fail:
            raise OSError("simulated durable-store failure")
        if self.conflict or self.state != expected:
            return False
        self.state = replacement
        self.sender_high_water = replacement_sender_high_water
        return True


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda item: item["name"])
def test_atomic_key_update_vectors(vector: dict[str, Any]) -> None:
    old = context(vector["initial"])
    assert old.durable_context_id().hex() == vector["initial"]["context_id"]
    slot = OscoreContextSlot(old, vector["initial_generation"])
    store = AtomicStore(slot.durable_state(), old.get_persisted_sequence_number())

    retired = slot.update(
        parameters(vector["replacement"]), vector["replacement_generation"], store
    )

    assert slot.generation == vector["replacement_generation"]
    assert slot.context.durable_context_id().hex() == vector["replacement"]["context_id"]
    assert store.state == slot.durable_state()
    assert store.sender_high_water == vector["replacement_sender_high_water"]
    assert retired is old and old.is_retired
    assert old.sender_key == bytes(16)
    assert old.recipient_key == bytes(16)
    assert old.common_iv == bytes(13)
    with pytest.raises(OscoreKeyUpdateError, match="retired"):
        old.new_sequence_number()
    assert not slot.context.has_reserved_sender_sequence
    slot.context.set_sender_sequence_reservation(0, 1)
    assert slot.context.new_sequence_number() == 0


@pytest.mark.parametrize("requested", [6, 7, 9, 0xFFFFFFFF])
def test_non_successor_generation_is_rejected_without_mutation(requested: int) -> None:
    vector = VECTORS["vectors"][0]
    old = context(vector["initial"])
    old.set_sender_sequence_reservation(0, 1)
    slot = OscoreContextSlot(old, 7)
    store = AtomicStore(slot.durable_state(), 0)

    with pytest.raises(OscoreKeyUpdateError, match="exactly one"):
        slot.update(parameters(vector["replacement"]), requested, store)

    assert slot.context is old and not old.is_retired
    assert store.state == slot.durable_state()


def test_generation_overflow_is_rejected_without_mutation() -> None:
    vector = VECTORS["vectors"][0]
    old = context(vector["initial"])
    slot = OscoreContextSlot(old, 0xFFFFFFFF)
    store = AtomicStore(slot.durable_state(), 0)
    with pytest.raises(OscoreKeyUpdateError, match="exactly one"):
        slot.update(parameters(vector["replacement"]), 0, store)
    assert slot.context is old and not old.is_retired


def test_reused_key_material_is_rejected_without_mutation() -> None:
    vector = VECTORS["vectors"][0]
    old = context(vector["initial"])
    slot = OscoreContextSlot(old, 7)
    store = AtomicStore(slot.durable_state(), 0)
    with pytest.raises(OscoreKeyUpdateError, match="reused"):
        slot.update(parameters(vector["initial"]), 8, store)
    assert slot.context is old and not old.is_retired


@pytest.mark.parametrize("failure", ["conflict", "error"])
def test_store_failure_preserves_old_context(failure: str) -> None:
    vector = VECTORS["vectors"][0]
    old = context(vector["initial"])
    old.set_sender_sequence_reservation(0, 1)
    slot = OscoreContextSlot(old, 7)
    store = AtomicStore(
        slot.durable_state(), 0, conflict=failure == "conflict", fail=failure == "error"
    )
    expected = OscoreKeyUpdateError if failure == "conflict" else OSError
    with pytest.raises(expected):
        slot.update(parameters(vector["replacement"]), 8, store)
    assert slot.context is old and not old.is_retired
    assert old.new_sequence_number() == 0


def test_invalid_replacement_is_derived_before_store_mutation() -> None:
    vector = VECTORS["vectors"][0]
    old = context(vector["initial"])
    slot = OscoreContextSlot(old, 7)
    store = AtomicStore(slot.durable_state(), 0)
    bad = parameters(vector["replacement"])
    bad = OscoreContextParameters(**{**bad.__dict__, "master_secret": b"short"})
    with pytest.raises(ValueError, match="16 bytes"):
        slot.update(bad, 8, store)
    assert slot.context is old and store.state == slot.durable_state()


def test_restore_rejects_rolled_back_generation() -> None:
    vector = VECTORS["vectors"][0]
    restored = context(vector["initial"])
    expected = OscoreContextSlot(restored, 7).durable_state()
    store = AtomicStore(
        OscoreKeyUpdateState(generation=8, context_id=expected.context_id), 0
    )
    with pytest.raises(OscoreKeyUpdateError, match="stale or missing"):
        OscoreContextSlot.restore_checked(restored, 7, store)
    assert not restored.is_retired
