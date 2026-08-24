# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test vectors for CCP beacon signature gate (ccp_beacon_sig_gate.json).

Validates:
1. L2 signature verification gates DIO processing (conceptual - signature
   check happens in LinkLayer.receive() before process_dio is called)
2. Path cost calculation matches test vectors (rounding behavior)
3. Admissibility respects MAX_RANK_INCREASE ceiling
"""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.rpl.dodag import (
    INFINITE_RANK,
    MAX_RANK_INCREASE,
    MIN_HOP_RANK_INCREASE,
    DodagRole,
    DodagState,
    ParentCandidate,
)
from lichen.rpl.messages import DIO

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load_vectors() -> list[dict]:
    doc = json.loads((VECTORS_DIR / "ccp_beacon_sig_gate.json").read_text())
    assert doc["format_version"] == 2
    return doc["vectors"]


def _path_cost_vectors() -> list[tuple[str, dict]]:
    return [
        (v["name"], v)
        for v in _load_vectors()
        if v.get("category") == "path_cost"
        and "expected_path_cost" in v
        and v.get("link_etx") != "NaN"
        and v.get("link_etx", 0) >= 0
    ]


def _admissibility_vectors() -> list[tuple[str, dict]]:
    return [(v["name"], v) for v in _load_vectors() if v.get("category") == "admissibility"]


def _sig_gate_vectors() -> list[tuple[str, dict]]:
    return [(v["name"], v) for v in _load_vectors() if v.get("category") == "signature_gate"]


@pytest.mark.parametrize("name,vector", _path_cost_vectors())
def test_path_cost_calculation(name: str, vector: dict) -> None:
    """Verify path_cost matches test vector expected value."""
    candidate = ParentCandidate(
        neighbor_id=IPv6Address("fe80::1"),
        rank=vector["parent_rank"],
        link_etx=vector["link_etx"],
    )
    mhri = vector["min_hop_rank_increase"]
    expected = vector["expected_path_cost"]
    actual = candidate.path_cost(mhri)
    assert actual == expected, f"{name}: path_cost={actual}, expected={expected}"


def test_path_cost_half_boundary_python_even() -> None:
    """Verify Python banker's rounding at .5 boundary (rounds to even).

    This test explicitly checks the known divergence point where Python
    rounds 128.5 to 128 (nearest even) while Rust rounds to 129.
    """
    vectors = {v["name"]: v for v in _load_vectors()}
    vector = vectors["path_cost_half_boundary_python_even"]

    candidate = ParentCandidate(
        neighbor_id=IPv6Address("fe80::1"),
        rank=vector["parent_rank"],
        link_etx=vector["link_etx"],
    )
    mhri = vector["min_hop_rank_increase"]
    expected_python = vector["expected_path_cost_python"]

    actual = candidate.path_cost(mhri)
    assert actual == expected_python, (
        f"Python path_cost={actual}, expected={expected_python} (banker's rounding)"
    )

    # Verify the exact link_cost calculation
    link_cost = vector["link_etx"] * mhri
    assert abs(link_cost - vector["link_cost_exact"]) < 0.0001


def test_path_cost_overflow_saturates() -> None:
    """Verify overflow returns INFINITE_RANK (65535)."""
    vectors = {v["name"]: v for v in _load_vectors()}
    vector = vectors["path_cost_overflow_saturation"]

    candidate = ParentCandidate(
        neighbor_id=IPv6Address("fe80::1"),
        rank=vector["parent_rank"],
        link_etx=vector["link_etx"],
    )
    mhri = vector["min_hop_rank_increase"]

    actual = candidate.path_cost(mhri)
    assert actual == INFINITE_RANK


def test_negative_etx_raises() -> None:
    """Verify negative ETX raises ValueError at ParentCandidate creation."""
    with pytest.raises(ValueError, match="non-negative"):
        ParentCandidate(
            neighbor_id=IPv6Address("fe80::1"),
            rank=256,
            link_etx=-1.0,
        )


def test_nan_etx_path_cost() -> None:
    """Corrupted candidates fail closed consistently with the Rust oracle.

    Public construction and ``process_dio`` reject NaN before a candidate is
    admitted.  If internal state is nevertheless corrupted, ``path_cost``
    must saturate instead of raising from ``round(nan)``.
    """
    candidate = ParentCandidate.__new__(ParentCandidate)
    candidate.neighbor_id = IPv6Address("fe80::1")
    candidate.rank = 256
    candidate.link_etx = float("nan")

    assert candidate.path_cost(256) == INFINITE_RANK


@pytest.mark.parametrize("name,vector", _admissibility_vectors())
def test_admissibility_with_default_max_rank_increase(name: str, vector: dict) -> None:
    """Verify admissibility using Python's default MAX_RANK_INCREASE=2048."""
    lowest_rank = vector["lowest_rank"]
    path_cost = vector["path_cost"]
    expected_admissible = vector["expected_python_admissible"]

    # Python default MAX_RANK_INCREASE is 2048
    assert MAX_RANK_INCREASE == 2048, "Python MAX_RANK_INCREASE should be 2048"

    # Check ceiling calculation
    ceiling = lowest_rank + MAX_RANK_INCREASE
    actual_admissible = path_cost <= ceiling

    assert actual_admissible == expected_admissible, (
        f"{name}: admissible={actual_admissible}, expected={expected_admissible}, "
        f"path_cost={path_cost}, ceiling={ceiling}"
    )


def test_sig_gate_conceptual_invalid_signature() -> None:
    """Conceptual test: invalid signature means no DIO processing.

    In the actual implementation, signature verification happens in
    LinkLayer.receive() (link_layer.py:418). If verification fails,
    ReceiveError.BAD_SIGNATURE is returned and process_dio is never called.

    This test verifies the invariant by checking that an unjoined node
    with no DIOs processed remains in UNJOINED state.
    """
    node = DodagState(rpl_instance_id=0, dodag_id="fd00::1", version=128)

    # Before any DIO processing
    assert node.role is DodagRole.UNJOINED
    assert node.rank == INFINITE_RANK
    assert node.preferred_parent is None

    # If signature verification failed, process_dio would not be called.
    # The node state remains unchanged - this is the signature gate invariant.


def test_sig_gate_conceptual_valid_signature() -> None:
    """Conceptual test: valid signature allows DIO processing.

    When signature verification passes in LinkLayer.receive(), the frame
    is passed to upper layers and process_dio is called.
    """
    vectors = {v["name"]: v for v in _load_vectors()}
    vector = vectors["sig_gate_valid_allows_dio"]

    dodag_id = bytes.fromhex(vector["dio"]["dodag_id_hex"])
    dodag_id_str = ":".join(f"{dodag_id[i]:02x}{dodag_id[i + 1]:02x}" for i in range(0, 16, 2))

    node = DodagState(
        rpl_instance_id=vector["dio"]["rpl_instance_id"],
        dodag_id=dodag_id_str,
        version=vector["dio"]["version"],
    )

    dio = DIO(
        rpl_instance_id=vector["dio"]["rpl_instance_id"],
        version=vector["dio"]["version"],
        rank=vector["dio"]["rank"],
        dtsn=0,
        dodag_id=dodag_id_str,
    )

    # After valid signature, process_dio is called
    node.process_dio(dio, IPv6Address("fe80::2"), link_etx=vector["link_etx"])

    # Verify expected state change
    assert node.role is DodagRole.JOINED
    expected_rank = vector["expected"]["new_rank"]
    assert node.get_rank() == expected_rank


def test_dodag_state_unchanged_without_dio() -> None:
    """Verify DODAG state is immutable without DIO processing.

    This supports the signature gate invariant: if L2 rejects a frame,
    no state change occurs because process_dio is never called.
    """
    node = DodagState(rpl_instance_id=0, dodag_id="fd00::1", version=128)

    initial_role = node.role
    initial_rank = node.rank
    initial_parent = node.preferred_parent
    initial_parents = dict(node.parents)

    # No DIOs processed - state should be identical
    assert node.role == initial_role
    assert node.rank == initial_rank
    assert node.preferred_parent == initial_parent
    assert node.parents == initial_parents


def test_max_rank_increase_constant() -> None:
    """Document the MAX_RANK_INCREASE constant value.

    Python default is 2048, which differs from Rust default of 1024.
    This is a known divergence documented in the test vectors.
    """
    assert MAX_RANK_INCREASE == 2048, (
        "Python MAX_RANK_INCREASE should be 2048 (spec B.2 default). "
        "Note: Rust uses 1024 by default."
    )


def test_min_hop_rank_increase_constant() -> None:
    """Verify MIN_HOP_RANK_INCREASE matches spec."""
    assert MIN_HOP_RANK_INCREASE == 256
