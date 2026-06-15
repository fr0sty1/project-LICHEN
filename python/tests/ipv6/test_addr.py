"""Tests for IPv6 address handling and IID derivation (spec 6.1, 6.2, 12).

Oracles are hand-computed or taken from the spec's worked example addresses
(spec 12.2), not from the code under test.
"""

from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network

import pytest

from lichen.ipv6.addr import (
    AddrError,
    AddressManager,
    Identity,
    Scope,
    eui64_to_iid,
    mac48_to_eui64,
    make_gua,
    make_link_local,
    make_ula,
    short_addr_to_iid,
)

# Spec 12.2 example: link-local fe80::1234:5678:9abc:def0 has this IID.
# IID = EUI-64 XOR 0x0200_0000_0000_0000, so the source EUI-64 differs only in
# the U/L bit of the first octet: 0x12 XOR 0x02 = 0x10.
SPEC_EUI64 = bytes([0x10, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
SPEC_IID = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])


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
    assert mac48_to_eui64(mac) == bytes(
        [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55]
    )


def test_mac48_to_iid_full_chain() -> None:
    # Modified EUI-64 IID: insert ff:fe, then flip U/L bit (0x00 -> 0x02).
    mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    iid = eui64_to_iid(mac48_to_eui64(mac))
    assert iid == bytes([0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_mac48_to_eui64_rejects_wrong_length() -> None:
    with pytest.raises(AddrError):
        mac48_to_eui64(b"\x00" * 5)


def test_short_addr_to_iid() -> None:
    # 0x0000_00FF_FE00_0000 | (0x0001 << 48) = 0x0001_00FF_FE00_0000
    assert short_addr_to_iid(0x0001) == bytes(
        [0x00, 0x01, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00]
    )


def test_short_addr_to_iid_rejects_out_of_range() -> None:
    with pytest.raises(AddrError):
        short_addr_to_iid(0x10000)


def test_make_link_local_matches_spec_example() -> None:
    assert make_link_local(SPEC_IID) == IPv6Address("fe80::1234:5678:9abc:def0")


def test_make_link_local_rejects_bad_iid() -> None:
    with pytest.raises(AddrError):
        make_link_local(b"\x00" * 4)


def test_make_ula_matches_spec_example() -> None:
    prefix = IPv6Network("fd12:3456:789a:0001::/64")
    # The spec 12.2 example literal "fd12:...:0001::1234:..." is malformed (a
    # "::" alongside a full IID); the valid concatenation has no "::".
    assert make_ula(prefix, SPEC_IID) == IPv6Address(
        "fd12:3456:789a:1:1234:5678:9abc:def0"
    )


def test_make_ula_rejects_non_ula_prefix() -> None:
    with pytest.raises(AddrError):
        make_ula(IPv6Network("2001:db8::/64"), SPEC_IID)


def test_make_ula_rejects_non_64_prefix() -> None:
    with pytest.raises(AddrError):
        make_ula(IPv6Network("fd12:3456:789a::/48"), SPEC_IID)


def test_make_gua_matches_spec_example() -> None:
    prefix = IPv6Network("2001:db8:1234:1::/64")
    assert make_gua(prefix, SPEC_IID) == IPv6Address(
        "2001:db8:1234:1:1234:5678:9abc:def0"
    )


def test_make_gua_rejects_non_gua_prefix() -> None:
    with pytest.raises(AddrError):
        make_gua(IPv6Network("fd00::/64"), SPEC_IID)


def test_identity_iid_and_link_local() -> None:
    ident = Identity(SPEC_EUI64)
    assert ident.iid == SPEC_IID
    assert ident.link_local == IPv6Address("fe80::1234:5678:9abc:def0")


def test_identity_from_mac48() -> None:
    ident = Identity.from_mac48(bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    assert ident.iid == bytes([0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])


def test_identity_rejects_bad_eui64() -> None:
    with pytest.raises(AddrError):
        Identity(b"\x00" * 6)


def test_address_manager_has_link_local_from_start() -> None:
    mgr = AddressManager(Identity(SPEC_EUI64))
    assert mgr.get(Scope.LINK_LOCAL) == IPv6Address("fe80::1234:5678:9abc:def0")
    assert mgr.get(Scope.ULA) is None
    assert mgr.get(Scope.GUA) is None
    assert mgr.all() == [IPv6Address("fe80::1234:5678:9abc:def0")]


def test_address_manager_set_and_clear_prefixes() -> None:
    mgr = AddressManager(Identity(SPEC_EUI64))
    ula = mgr.set_ula_prefix(IPv6Network("fd12:3456:789a:0001::/64"))
    gua = mgr.set_gua_prefix(IPv6Network("2001:db8:1234:1::/64"))
    assert mgr.get(Scope.ULA) == ula
    assert mgr.get(Scope.GUA) == gua
    assert len(mgr.all()) == 3

    mgr.clear(Scope.ULA)
    assert mgr.get(Scope.ULA) is None
    assert len(mgr.all()) == 2


def test_address_manager_cannot_clear_link_local() -> None:
    mgr = AddressManager(Identity(SPEC_EUI64))
    with pytest.raises(AddrError):
        mgr.clear(Scope.LINK_LOCAL)
