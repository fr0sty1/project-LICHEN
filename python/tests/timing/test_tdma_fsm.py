# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from lichen.timing.tdma_fsm import TdmaState, on_event

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_tdma_ccp_fsm_vectors() -> None:
    document = _load("tdma_ccp_fsm.json")
    for case in document["vectors"]:
        nxt = on_event(
            TdmaState(case["from"]),
            case["event"],
            missed=case.get("missed"),
        )
        assert nxt is TdmaState(case["to"]), case["name"]
