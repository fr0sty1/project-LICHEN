# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for IPv6 address handling and IID derivation (spec 6.1, 6.2, 12).

Oracles are hand-computed or taken from the spec's worked example addresses
(spec 12.2), not from the code under test.
"""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import Identity
from lichen.ipv6.addr import (
    AddrError,
    eui64_to_iid,
    is_unflagged_multicast,
    link_local_from_pubkey,
    mac48_to_eui64,
    make_link_local,
    multicast_scope,
    native_address_from_pubkey,
    routing_key,
    short_addr_to_iid,
    to_ipv6,
)

# Spec 12.2 example: link-local fe80::1234:5678:9abc:def0 has this IID.
# IID = EUI-64 XOR 0x0200_0000_0000_0000, so the source EUI-64 differs only in
# the U/L bit of the first octet: 0x12 XOR 0x02 = 0x10.
SPEC_EUI64 = bytes([0x10, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
SPEC_IID = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "ipv6-addresses.json"


def test_eui64_to_iid_flips_ul_bit() -> None:
    assert eui64_to_iid(SPEC_EUI64) == SPEC_IID


def test_eui64_to_iid_is_involutive_on_ul_bit() -> None:
    # Flipping twice returns the original EUI-64.
    assert eui64_to_iid(eui64_to_iid(SPEC_EUI64)) == SPEC_EUI64


def test_eui64_to_iid_rejects_wrong_length() -> None:
    with pytest.raises(AddrError):
        eui64_to_iid(b"\x00" * 7)


def test_mac48_to_eui64_inserts_fffe_without_flip() -> None:
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    assert mac48_to_eui64(mac) == bytes([0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_mac48_to_iid_full_chain() -> None:
    # Modified EUI-64 IID: insert ff:fe, then flip U/L bit (0x00 -> 0x02).
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    iid = eui64_to_iid(mac48_to_eui64(mac))
    assert iid == bytes([0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_mac48_to_eui64_rejects_wrong_length() -> None:
    with pytest.raises(AddrError):
        mac48_to_eui64(b"\x00" * 5)


def test_short_addr_to_iid() -> None:
    # RFC 4944 section 6: IID = 0000:00FF:FE00:XXXX (short addr in low bytes)
    # Independent oracle: 0x0000_00FF_FE00_0000 | XXXX, hand-computed bytes.
    assert short_addr_to_iid(0x0000) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00])
    assert short_addr_to_iid(0x0001) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x01])
    assert short_addr_to_iid(0xABCD) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0xAB, 0xCD])
    assert short_addr_to_iid(0xFFFF) == bytes([0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0xFF, 0xFF])


def test_short_addr_to_iid_rejects_out_of_range() -> None:
    with pytest.raises(AddrError):
        short_addr_to_iid(-1)
    with pytest.raises(AddrError):
        short_addr_to_iid(0x10000)


@pytest.mark.parametrize("value", [True, False, 1.0])
def test_short_addr_to_iid_rejects_non_int(value: object) -> None:
    # Independent oracle: bool subclasses int (True == 1, False == 0) so a
    # range check alone would accept them as RFC 4944 IIDs. float 1.0 is in
    # range then TypeError on bitwise OR; the public boundary is AddrError.
    assert isinstance(True, int) and True == 1 and False == 0
    assert 0 <= 1.0 <= 0xFFFF
    with pytest.raises(AddrError):
        short_addr_to_iid(value)  # type: ignore[arg-type]


def test_make_link_local_matches_spec_example() -> None:
    assert make_link_local(SPEC_IID) == IPv6Address("fe80::1234:5678:9abc:def0")


def test_make_link_local_rejects_bad_iid() -> None:
    with pytest.raises(AddrError):
        make_link_local(b"\x00" * 4)


def test_key_identity_exposes_only_bound_native_and_link_local_addresses() -> None:
    identity = Identity.from_seed(bytes(range(32)))
    assert native_address_from_pubkey(identity.pubkey) == IPv6Address(identity.ygg_addr)
    assert native_address_from_pubkey(identity.pubkey).packed[0] == 0x02
    assert link_local_from_pubkey(identity.pubkey) == make_link_local(identity.iid)


@pytest.mark.parametrize("pubkey", [b"", bytes(31), bytes(33), bytearray(32)])
def test_key_derived_address_helpers_reject_noncanonical_public_keys(pubkey) -> None:
    with pytest.raises(AddrError):
        native_address_from_pubkey(pubkey)
    with pytest.raises(AddrError):
        link_local_from_pubkey(pubkey)


def test_key_derived_ipv6_vectors_match_production_boundaries() -> None:
    document = json.loads(VECTORS.read_text())
    key_vectors = [
        vector for vector in document["vectors"]
        if vector["profile"] == "key_derived_identity"
    ]
    assert len(key_vectors) >= 5
    for vector in key_vectors:
        public_key = bytes.fromhex(vector["pubkey"])
        assert native_address_from_pubkey(public_key).packed.hex() == vector["native_packed"]
        assert str(native_address_from_pubkey(public_key)) == vector["native"]
        assert link_local_from_pubkey(public_key).packed.hex() == vector["link_local_packed"]


def test_eui64_and_short_addr_vectors_match_production_helpers() -> None:
    document = json.loads(VECTORS.read_text())
    eui_checked = 0
    short_checked = 0
    for vector in document["vectors"]:
        if "eui64" in vector:
            iid = eui64_to_iid(bytes.fromhex(vector["eui64"]))
            assert iid.hex() == vector["iid"], vector["name"]
            address = make_link_local(iid)
            assert address.packed.hex() == vector["link_local_packed"], vector["name"]
            assert str(address) == vector["link_local"], vector["name"]
            eui_checked += 1
        if "short_addr" in vector:
            assert short_addr_to_iid(vector["short_addr"]).hex() == vector["iid"], vector["name"]
            short_checked += 1
    assert eui_checked == 3
    assert short_checked == 3


@pytest.mark.parametrize(
    ("text", "scope"),
    [
        ("ff01::1", 1),
        ("ff02::1", 2),
        ("ff05::2", 5),
        ("ff08::1", 8),
        ("ff0e::1", 0xE),
    ],
)
def test_unflagged_multicast_scopes_ff01_to_ff0e(text: str, scope: int) -> None:
    addr = IPv6Address(text)
    assert multicast_scope(addr) == scope
    assert is_unflagged_multicast(addr)


def test_unicast_has_no_multicast_scope() -> None:
    assert multicast_scope(IPv6Address("fe80::1")) is None
    assert not is_unflagged_multicast(IPv6Address("fe80::1"))
    assert not is_unflagged_multicast(IPv6Address("ff00::1"))
    assert not is_unflagged_multicast(IPv6Address("ff11::1"))
    assert multicast_scope(IPv6Address("ff12::1")) == 2


def test_to_ipv6_accepts_documented_forms() -> None:
    # Independent oracle: stdlib IPv6Address from RFC 4291 link-local text.
    packed = bytes.fromhex("fe800000000000000000000000000001")
    text = "fe80::1"
    addr = IPv6Address(text)
    assert packed == addr.packed
    assert to_ipv6(addr) is addr
    assert to_ipv6(text) == addr
    assert to_ipv6(packed) == addr


@pytest.mark.parametrize("value", [True, False])
def test_to_ipv6_rejects_bool(value: bool) -> None:
    # Independent oracle: stdlib treats bool as int (True -> ::1, False -> ::).
    stdlib = IPv6Address(value)
    assert stdlib == IPv6Address("::1" if value else "::")
    with pytest.raises(AddrError):
        to_ipv6(value)


@pytest.mark.parametrize("value", [0, 1])
def test_to_ipv6_rejects_int(value: int) -> None:
    # Integers are not in the documented contract; 0/1 would be :: / ::1.
    with pytest.raises(AddrError):
        to_ipv6(value)


# RFC 4291: a zone identifier is local interface metadata, not part of the
# 128-bit address. Independent packed oracle for fe80::1.
_FE80_1_PACKED = bytes.fromhex("fe800000000000000000000000000001")


def test_to_ipv6_preserves_scope_id() -> None:
    # stdlib treats zoned and unzoned forms as unequal; to_ipv6 must not drop
    # the zone used for local send (make_link_local / LCI).
    zoned = IPv6Address("fe80::1%lci0")
    unzoned = IPv6Address("fe80::1")
    assert zoned.packed == unzoned.packed == _FE80_1_PACKED
    assert zoned != unzoned
    assert to_ipv6(zoned) is zoned
    parsed = to_ipv6("fe80::1%lci0")
    assert parsed.packed == _FE80_1_PACKED
    assert parsed.scope_id == "lci0"


def test_routing_key_unifies_zoned_and_unzoned_forms() -> None:
    # Independent oracle: stdlib packed bytes, not routing_key itself.
    zoned = IPv6Address("fe80::1%lci0")
    other_zone = IPv6Address("fe80::1%eth0")
    unzoned = IPv6Address("fe80::1")
    assert zoned != unzoned
    assert other_zone != zoned
    assert zoned.packed == other_zone.packed == unzoned.packed == _FE80_1_PACKED

    key_from_zoned = routing_key(zoned)
    key_from_text = routing_key("fe80::1%lci0")
    key_from_packed = routing_key(_FE80_1_PACKED)
    assert key_from_zoned == unzoned
    assert key_from_zoned == routing_key(other_zone) == routing_key(unzoned)
    assert key_from_text == unzoned
    assert key_from_packed == unzoned
    assert key_from_zoned.scope_id is None
    assert key_from_zoned.packed == _FE80_1_PACKED
    table = {key_from_zoned: "hit"}
    assert unzoned in table
    assert routing_key("fe80::1%eth0") in table
    split = {to_ipv6(zoned): "zoned"}
    assert unzoned not in split


def test_routing_key_round_trips_wire_packed_bytes() -> None:
    zoned = IPv6Address("fe80::1%lci0")
    assert routing_key(zoned).packed == zoned.packed == _FE80_1_PACKED
    assert routing_key(zoned.packed) == IPv6Address("fe80::1")
