# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link-local assignment tests for LCI clients (spec 11 section 17.4)."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.ipv6.addr import (
    LINK_LOCAL_NETWORK,
    AddrError,
    link_local_from_pubkey,
    make_link_local,
)

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "ipv6-addresses.json"


def test_key_derived_assignment_matches_canonical_vectors_byte_for_byte() -> None:
    document = json.loads(VECTORS.read_text())
    vectors = [
        vector for vector in document["vectors"] if vector["profile"] == "key_derived_identity"
    ]

    assert vectors
    for vector in vectors:
        address = link_local_from_pubkey(bytes.fromhex(vector["pubkey"]))
        assert address in LINK_LOCAL_NETWORK
        assert address == IPv6Address(vector["link_local"])
        assert address.packed == bytes.fromhex(vector["link_local_packed"])
        assert address.packed[:8] == bytes.fromhex("fe80000000000000")
        assert address.packed[8:] == bytes.fromhex(vector["iid"])


@pytest.mark.parametrize("zone_id", ["lci0", "7", 7])
def test_zone_is_local_metadata_and_does_not_change_wire_bytes(zone_id: str | int) -> None:
    iid = bytes.fromhex("123456789abcdef0")
    unscoped = make_link_local(iid)
    scoped = make_link_local(iid, zone_id=zone_id)

    assert scoped.scope_id == str(zone_id)
    assert str(scoped) == f"fe80::1234:5678:9abc:def0%{zone_id}"
    assert scoped.packed == unscoped.packed
    assert scoped in LINK_LOCAL_NETWORK


def test_key_derived_assignment_preserves_zone() -> None:
    pubkey = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    address = link_local_from_pubkey(pubkey, zone_id="slip_lci")

    assert address.scope_id == "slip_lci"
    assert address.packed.hex() == "fe800000000000000c02a50225b4baaa"


@pytest.mark.parametrize(
    "iid",
    [b"", bytes(7), bytes(9), bytearray(8), memoryview(bytes(8)), "12345678"],
)
def test_assignment_rejects_noncanonical_iids(iid: object) -> None:
    with pytest.raises(AddrError):
        make_link_local(iid)  # type: ignore[arg-type]


@pytest.mark.parametrize("pubkey", [b"", bytes(31), bytes(33), bytearray(32)])
def test_assignment_rejects_noncanonical_public_keys(pubkey: object) -> None:
    with pytest.raises(AddrError):
        link_local_from_pubkey(pubkey)  # type: ignore[arg-type]


@pytest.mark.parametrize("zone_id", ["", "lci%0", "lci 0", 0, -1, True, object()])
def test_assignment_rejects_invalid_zones(zone_id: object) -> None:
    with pytest.raises(AddrError):
        make_link_local(bytes(8), zone_id=zone_id)  # type: ignore[arg-type]
