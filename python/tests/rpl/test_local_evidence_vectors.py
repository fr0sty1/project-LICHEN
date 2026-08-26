# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: LOADng local-evidence gate vs shared vectors.

Drives ``lichen.rpl.evidence.EvidenceTable`` against every section of
``test/vectors/local_evidence.json`` (spec B2.5 / section 10.2).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.rpl.evidence import EvidenceTable, GradientEntry

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "local_evidence.json"


def _cases() -> list[tuple[str, dict]]:
    doc = json.loads(_VECTORS_PATH.read_text())["vectors"]
    return [(f"{section}:{case['name']}", case) for section, cases in doc.items() for case in cases]


def _table_with(case: dict) -> EvidenceTable:
    table = EvidenceTable()
    entry = case.get("gradient_entry")
    if entry is not None:
        table.add(GradientEntry(**entry))
    return table


@pytest.mark.parametrize(("case_id", "case"), _cases(), ids=lambda v: v)
def test_evidence_gate(case_id: str, case: dict) -> None:
    table = _table_with(case)
    exists = table.has_evidence(case["lookup_destination"], case["now"])
    assert exists is case["evidence_exists"], case["description"]


def test_expiry_boundary_is_inclusive_expired() -> None:
    # expires <= now means expired: 499999 fresh, exactly 500000 gone.
    table = EvidenceTable()
    table.add(
        GradientEntry(
            destination="fe80::b1",
            next_hop="fe80::b2",
            hop_count=1,
            seq_num=1,
            source="rrep",
            expires=500000,
        )
    )
    assert table.has_evidence("fe80::b1", 499999) is True
    assert table.has_evidence("fe80::b1", 500000) is False


def test_all_authenticated_sources_are_equal_for_the_gate() -> None:
    for source in ("announce", "rrep", "rpl", "data"):
        table = EvidenceTable()
        table.add(
            GradientEntry(
                destination="fe80::src",
                next_hop="fe80::nh",
                hop_count=2,
                seq_num=7,
                source=source,
                expires=1000,
            )
        )
        assert table.has_evidence("fe80::src", 999), source
