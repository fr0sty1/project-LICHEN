# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: CCP-15 interference score vs shared vectors.

Drives ``lichen.ccp.interference_score`` against the independent math
oracle in ``test/vectors/ccp-interference.json``
(score = busy_pct + PER*100, per vector descriptions).

The ``backoff_jitter_ms`` column in that file has no derivable oracle
(no spec text, generator, or closed form); it is intentionally not
asserted here. See bead project-LICHEN-worker6-a0gf.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.ccp import interference_score

_VECTORS_PATH = Path(__file__).parents[2] / "test" / "vectors" / "ccp-interference.json"


def _load_vectors() -> list[dict]:
    with open(_VECTORS_PATH) as f:
        return json.load(f)["vectors"]


@pytest.mark.parametrize(
    "case", json.loads(_VECTORS_PATH.read_text())["vectors"], ids=lambda v: v["name"]
)
def test_interference_score(case: dict) -> None:
    score = interference_score(case["busy_pct"], case["per"])
    assert score == pytest.approx(case["interference_score"]), case["description"]


@pytest.mark.parametrize(
    ("busy_pct", "per"),
    [(-1.0, 0.0), (101.0, 0.0), (0.0, -0.1), (50.0, 1.5)],
)
def test_rejects_out_of_range_inputs(busy_pct: float, per: float) -> None:
    with pytest.raises(ValueError):
        interference_score(busy_pct, per)
