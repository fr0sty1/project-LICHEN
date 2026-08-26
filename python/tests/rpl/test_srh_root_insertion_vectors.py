# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-implementation vectors for RFC 6554 root SRH insertion."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.ipv6.packet import IPv6Packet
from lichen.rpl.routing import RoutingError, insert_source_route

_VECTOR_PATH = Path(__file__).parents[3] / "test" / "vectors" / "srh_root_insertion.json"
_SCHEMA_PATH = _VECTOR_PATH.with_name("srh_root_insertion.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTOR_PATH.read_text()))


def test_srh_root_insertion_document_matches_schema() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    Draft7Validator.check_schema(schema)
    errors = sorted(
        Draft7Validator(schema).iter_errors(_document()), key=lambda error: error.path
    )
    assert not errors, [error.message for error in errors]


_ERROR_PATTERNS = {
    "empty_path": "must not be empty",
    "destination_mismatch": "does not end with packet destination",
    "duplicate_address": "duplicate",
    "source_in_path": "packet source",
    "multicast_address": "multicast",
    "hop_limit": "strictly less than hop_limit",
    "too_many_hops": "maximum hop count",
    "existing_routing_header": "already contains",
}


@pytest.mark.parametrize("case", _document()["cases"], ids=lambda case: case["name"])
def test_srh_root_insertion_vector(case: dict[str, Any]) -> None:
    packet = IPv6Packet.from_bytes(bytes.fromhex(case["packet"]), strict=True)
    route = [IPv6Address(bytes.fromhex(address)) for address in case["route"]]
    expected = case["expected"]
    if not expected["accepted"]:
        with pytest.raises(RoutingError, match=_ERROR_PATTERNS[expected["reason"]]):
            insert_source_route(packet, route)
        return

    routed, first_hop = insert_source_route(packet, route)
    assert first_hop.packed.hex() == expected["first_hop"]
    assert routed.to_bytes().hex() == expected["packet"]
