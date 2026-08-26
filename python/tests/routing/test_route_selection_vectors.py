# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-implementation vectors for local-first route selection."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, cast

import pytest

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.loadng.cache import RouteCache
from lichen.loadng.discovery import LoadngRouter
from lichen.routing.router import Router
from lichen.rpl.dodag import DodagRole, DodagState

_VECTORS = Path(__file__).parents[3] / "test" / "vectors" / "route_selection.json"


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS.read_text()))


def _packet(destination: IPv6Address) -> IPv6Packet:
    return IPv6Packet(
        header=IPv6Header(
            src_addr=IPv6Address("fe80::1"),
            dst_addr=destination,
            next_header=17,
            payload_length=0,
        ),
        payload=b"",
    )


@pytest.mark.parametrize("case", _document()["cases"], ids=lambda case: case["name"])
def test_route_selection_vector(case: dict[str, Any]) -> None:
    document = _document()
    gradient = GradientTable()
    router = Router(node_address=IPv6Address("0200::1"), gradient_table=gradient)
    destination = IPv6Address(case["destination"])

    if case["local_route"]:
        gradient.update(
            GradientEntry(
                destination=destination,
                next_hop=IPv6Address(document["next_hops"]["gradient"]),
                hop_count=1,
                seq_num=1,
                source=GradientSource.ANNOUNCE,
                expires=10_000,
            )
        )
    if case["local_discovery"]:
        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient,
            cache=RouteCache(),
        )
    if case["rpl_parent"]:
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id=IPv6Address("0200::1"),
            version=1,
            role=DodagRole.JOINED,
            preferred_parent=IPv6Address(document["next_hops"]["rpl_parent"]),
        )

    address_class = router.classify_address(destination)
    decision, next_hop = router.route(_packet(destination), now_ms=0)

    assert address_class.name.lower() == case["expected_class"]
    assert decision.name.lower() == case["expected_decision"]
    expected_next_hop = case["expected_next_hop"]
    assert next_hop == (IPv6Address(expected_next_hop) if expected_next_hop else None)
