# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Canonical RPL gateway-reachability advertisement vectors."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, cast

import pytest

from lichen.rpl.dodag import DodagState
from lichen.rpl.messages import DIO, RplOptionType

_VECTORS = Path(__file__).parents[3] / "test" / "vectors" / "gateway_reachability.json"


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS.read_text()))


@pytest.mark.parametrize("case", _document()["cases"], ids=lambda case: case["name"])
def test_gateway_reachability_vector(case: dict[str, Any]) -> None:
    document = _document()
    root = DodagState.as_root(
        rpl_instance_id=document["rpl_instance_id"],
        dodag_id=IPv6Address(document["dodag_id"]),
        version=document["version"],
    )

    changed = root.set_ygg_reachable(case["ygg_reachable"])
    wire = root.build_dio().to_bytes()
    parsed = DIO.from_bytes(wire)

    assert changed is case["ygg_reachable"]
    assert parsed.grounded is case["expected_grounded"]
    assert wire[4] == case["expected_g_mop_prf"]
    assert parsed.rank == document["rank"]
    assert all(option.type != RplOptionType.PREFIX_INFORMATION for option in parsed.options)


def test_non_root_cannot_claim_global_reachability() -> None:
    document = _document()
    node = DodagState(
        rpl_instance_id=document["rpl_instance_id"],
        dodag_id=IPv6Address(document["dodag_id"]),
        version=document["version"],
    )

    assert node.set_ygg_reachable(True) is False
    assert node.build_dio().grounded is False


def test_reachability_setter_rejects_truthy_non_bool() -> None:
    root = DodagState.as_root(1, "0200::1", 7)
    with pytest.raises(TypeError, match="bool"):
        root.set_ygg_reachable(1)  # type: ignore[arg-type]
