# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the canonical cross-language TOFU edge-case corpus."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from lichen.crypto import DerivationMismatchError, TrustStore

VECTORS = Path(__file__).parents[3] / "test" / "vectors"


class _FailingPersistence:
    is_crash_safe = True
    fails_closed = True

    def save(self, store: TrustStore) -> None:
        del store
        raise OSError("injected durable write failure")


def _load() -> dict:
    return json.loads((VECTORS / "tofu_edge_cases.json").read_bytes())


def _case(document: dict, name: str) -> dict:
    return next(vector for vector in document["vectors"] if vector["name"] == name)


def test_tofu_edge_vectors_are_schema_valid_and_complete() -> None:
    document = _load()
    schema = json.loads((VECTORS / "schema.json").read_bytes())
    assert not list(Draft7Validator(schema).iter_errors(document))
    assert {vector["name"] for vector in document["vectors"]} == {
        "first_contact",
        "idempotent_repeat",
        "derivation_mismatch",
        "pinned_key_collision",
        "malformed_pubkey_short",
        "malformed_pubkey_long",
        "malformed_iid_short",
        "malformed_iid_long",
        "persistence_failure_rollback",
        "reboot_restore",
        "rollback_snapshot_rejected",
        "concurrent_first_contact",
        "replayed_collision",
        "independent_peer",
    }


def test_tofu_observation_vectors_drive_python_store() -> None:
    document = _load()
    alice = _case(document, "first_contact")
    alice_key = bytes.fromhex(alice["pubkey_hex"])
    alice_iid = bytes.fromhex(alice["iid_hex"])

    store = TrustStore(auto_pin=True)
    store.verify_or_pin(alice_key, alice_iid)
    assert len(store) == alice["expected"]["entry_count"]

    repeat = _case(document, "idempotent_repeat")
    for _ in range(repeat["repetitions"]):
        store.verify_or_pin(bytes.fromhex(repeat["pubkey_hex"]), bytes.fromhex(repeat["iid_hex"]))
    assert len(store) == repeat["expected"]["entry_count"]
    assert store.get(alice_iid).pubkey == alice_key  # type: ignore[union-attr]

    for name in ("pinned_key_collision", "replayed_collision"):
        vector = _case(document, name)
        before = store.list_entries(include_revoked=True)
        for _ in range(vector["repetitions"]):
            with pytest.raises(DerivationMismatchError):
                store.verify_or_pin(
                    bytes.fromhex(vector["pubkey_hex"]),
                    bytes.fromhex(vector["iid_hex"]),
                )
        assert store.list_entries(include_revoked=True) == before
        assert len(store) == vector["expected"]["entry_count"]

    independent = _case(document, "independent_peer")
    store.verify_or_pin(
        bytes.fromhex(independent["pubkey_hex"]), bytes.fromhex(independent["iid_hex"])
    )
    assert len(store) == independent["expected"]["entry_count"]


def test_tofu_rejection_and_rollback_vectors_drive_python_store() -> None:
    document = _load()
    mismatch = _case(document, "derivation_mismatch")
    store = TrustStore(auto_pin=True)
    with pytest.raises(DerivationMismatchError):
        store.verify_or_pin(
            bytes.fromhex(mismatch["pubkey_hex"]), bytes.fromhex(mismatch["iid_hex"])
        )
    assert len(store) == mismatch["expected"]["entry_count"]

    for name in (
        "malformed_pubkey_short",
        "malformed_pubkey_long",
        "malformed_iid_short",
        "malformed_iid_long",
    ):
        vector = _case(document, name)
        with pytest.raises(ValueError):
            store.verify_or_pin(
                bytes.fromhex(vector["pubkey_hex"]), bytes.fromhex(vector["iid_hex"])
            )
        assert len(store) == vector["expected"]["entry_count"]

    rollback = _case(document, "persistence_failure_rollback")
    store = TrustStore(auto_pin=True, persistence=_FailingPersistence())
    with pytest.raises(OSError, match="durable write failure"):
        store.verify_or_pin(
            bytes.fromhex(rollback["pubkey_hex"]), bytes.fromhex(rollback["iid_hex"])
        )
    assert len(store) == rollback["expected"]["entry_count"]

    reboot = _case(document, "reboot_restore")
    stale = _case(document, "rollback_snapshot_rejected")
    assert reboot["snapshot_generation"] >= reboot["minimum_generation"]
    assert stale["snapshot_generation"] < stale["minimum_generation"]


def test_tofu_concurrent_vector_has_serializable_single_pin_result() -> None:
    vector = _case(_load(), "concurrent_first_contact")
    store = TrustStore(auto_pin=True)
    results = []
    for _ in range(vector["concurrent_observers"]):
        before = len(store)
        store.verify_or_pin(bytes.fromhex(vector["pubkey_hex"]), bytes.fromhex(vector["iid_hex"]))
        results.append("pin_and_accept" if before == 0 else "accept_known")
    assert results == ["pin_and_accept", "accept_known"]
    assert len(store) == vector["expected"]["entry_count"]
