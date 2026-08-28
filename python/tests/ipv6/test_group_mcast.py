# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group multicast derivation vs spec/12-apps.md 18.8.3 and RFC 3306.

Oracles are hand-built packed addresses and pinned SHA-256 digests.  This
file does not use lichen.ipv6.addr as its own expected-value generator.
"""

from __future__ import annotations

from hashlib import sha256
from ipaddress import IPv6Address, IPv6Network

import pytest

from lichen.ipv6.addr import (
    AddrError,
    group_multicast_from_id,
    unicast_prefix_based_mcast,
)

# echo -n team-alpha | shasum -a 256
TEAM_ALPHA_SHA256 = "29c4834a95b3703f05bda3e949d345d7bccec4e4f778b552003fd72b00f1fdef"
# echo -n a | shasum -a 256
SINGLE_A_SHA256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

# spec 18.8.1 / 18.8.3 template: Group 1 on 0200:1234:5678:9abc::/64
# ff35:0040:0200:1234:5678:9abc::0001
SPEC_GROUP1_PACKED = bytes.fromhex("ff3500400200123456789abc00000001")

# SHA-256("team-alpha") high 16 bits 0x29c4, default prefix 0200::/64
TEAM_ALPHA_DEFAULT_PACKED = bytes.fromhex("ff3500400200000000000000000029c4")

# Same id on the spec mesh /64
TEAM_ALPHA_MESH_PACKED = bytes.fromhex("ff3500400200123456789abc000029c4")


def _rfc3306_packed(prefix64: bytes, group_id: int) -> bytes:
    """Independent RFC 3306 assembler (not the production path)."""
    if len(prefix64) != 8:
        raise ValueError("prefix64 must be 8 bytes")
    if not 0 <= group_id <= 0xFFFF:
        raise ValueError("group id out of range")
    return b"\xff\x35\x00\x40" + prefix64 + b"\x00\x00" + group_id.to_bytes(2, "big")


def _gid16_from_pinned_digest(digest_hex: str) -> int:
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    return int.from_bytes(digest[:2], "big")


def test_pinned_sha256_literals_match_stdlib() -> None:
    assert sha256(b"team-alpha").hexdigest() == TEAM_ALPHA_SHA256
    assert sha256(b"a").hexdigest() == SINGLE_A_SHA256


def test_spec_example_group_1_on_mesh_prefix() -> None:
    got = unicast_prefix_based_mcast("0200:1234:5678:9abc::", 1)
    assert got.packed == SPEC_GROUP1_PACKED
    assert got.packed == _rfc3306_packed(bytes.fromhex("0200123456789abc"), 1)
    assert got == IPv6Address("ff35:40:200:1234:5678:9abc::1")


def test_spec_example_accepts_slash64_network() -> None:
    net = IPv6Network("0200:1234:5678:9abc::/64")
    got = unicast_prefix_based_mcast(net, 1)
    assert got.packed == SPEC_GROUP1_PACKED


def test_spec_example_masks_iid_from_full_unicast() -> None:
    got = unicast_prefix_based_mcast("0200:1234:5678:9abc::1111", 1)
    assert got.packed == SPEC_GROUP1_PACKED


def test_group_multicast_from_id_default_prefix_team_alpha() -> None:
    gid = _gid16_from_pinned_digest(TEAM_ALPHA_SHA256)
    assert gid == 0x29C4
    expected = _rfc3306_packed(bytes.fromhex("0200000000000000"), gid)
    assert expected == TEAM_ALPHA_DEFAULT_PACKED
    got = group_multicast_from_id("team-alpha")
    assert got.packed == expected
    assert got == IPv6Address(TEAM_ALPHA_DEFAULT_PACKED)


def test_group_multicast_from_id_uses_02xx_mesh_prefix() -> None:
    gid = _gid16_from_pinned_digest(TEAM_ALPHA_SHA256)
    expected = _rfc3306_packed(bytes.fromhex("0200123456789abc"), gid)
    assert expected == TEAM_ALPHA_MESH_PACKED
    got = group_multicast_from_id("team-alpha", prefix="0200:1234:5678:9abc::")
    assert got.packed == expected


def test_group_multicast_from_id_single_char() -> None:
    gid = _gid16_from_pinned_digest(SINGLE_A_SHA256)
    assert gid == 0xCA97
    expected = _rfc3306_packed(bytes.fromhex("0200000000000000"), gid)
    assert group_multicast_from_id("a").packed == expected


def test_rfc3306_header_fields() -> None:
    packed = unicast_prefix_based_mcast("0200:1234:5678:9abc::", 1).packed
    assert packed[0] == 0xFF
    assert packed[1] == 0x35  # P=1 T=1, scope 5
    assert packed[2] == 0x00
    assert packed[3] == 0x40  # plen 64
    assert packed[4:12] == bytes.fromhex("0200123456789abc")
    assert packed[12:14] == b"\x00\x00"
    assert packed[14:16] == b"\x00\x01"


def test_distinct_ids_yield_distinct_group_fields() -> None:
    a = group_multicast_from_id("team-alpha")
    b = group_multicast_from_id("team-bravo")
    assert a != b
    assert a.packed[:12] == b.packed[:12]
    assert a.packed[14:16] != b.packed[14:16]


def test_unicast_prefix_based_mcast_rejects_out_of_range() -> None:
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("0200::", -1)
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("0200::", 0x10000)
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("0200::", True)  # type: ignore[arg-type]


def test_unicast_prefix_based_mcast_rejects_non_native_prefix() -> None:
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("fe80::1", 1)
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("2001:db8::", 1)
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast(IPv6Network("0200:1234:5678::/48"), 1)


def test_group_multicast_from_id_rejects_empty_and_non_str() -> None:
    with pytest.raises(AddrError):
        group_multicast_from_id("")
    with pytest.raises(AddrError):
        group_multicast_from_id(b"team-alpha")  # type: ignore[arg-type]


def test_group_multicast_from_id_rejects_unpaired_surrogate() -> None:
    """Unpaired surrogates cannot be UTF-8 encoded and must raise AddrError."""
    with pytest.raises(AddrError, match="not valid UTF-8"):
        group_multicast_from_id("\ud800")


def test_spec_example_accepts_cidr_string() -> None:
    """CIDR string '/64' yields same result as IPv6Network or host string."""
    cidr_str = "0200:1234:5678:9abc::/64"
    got = unicast_prefix_based_mcast(cidr_str, 1)
    assert got.packed == SPEC_GROUP1_PACKED
    net = IPv6Network(cidr_str)
    assert got == unicast_prefix_based_mcast(net, 1)


def test_group_multicast_from_id_accepts_cidr_string() -> None:
    cidr_str = "0200:1234:5678:9abc::/64"
    gid = _gid16_from_pinned_digest(TEAM_ALPHA_SHA256)
    expected = _rfc3306_packed(bytes.fromhex("0200123456789abc"), gid)
    got = group_multicast_from_id("team-alpha", prefix=cidr_str)
    assert got.packed == expected
    assert got == group_multicast_from_id("team-alpha", prefix=IPv6Network(cidr_str))


def test_cidr_string_rejects_non_64_prefix() -> None:
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("0200:1234::/32", 1)
    with pytest.raises(AddrError):
        unicast_prefix_based_mcast("0200:1234:5678:9abc::/48", 1)
