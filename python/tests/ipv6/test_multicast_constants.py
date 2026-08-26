# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Byte-exact tests for the standard LICHEN multicast groups."""

from ipaddress import IPv6Address

from lichen.ipv6 import (
    ALL_LICHEN_NODES_MULTICAST,
    ALL_NODES_MULTICAST,
    ALL_RPL_NODES_MULTICAST,
    multicast_scope,
)


def test_standard_multicast_groups_are_typed_and_byte_exact() -> None:
    expected = (
        (ALL_NODES_MULTICAST, bytes.fromhex("ff020000000000000000000000000001")),
        (ALL_RPL_NODES_MULTICAST, bytes.fromhex("ff02000000000000000000000000001a")),
        (ALL_LICHEN_NODES_MULTICAST, bytes.fromhex("ff0300000000000000000000000000fc")),
    )

    for address, packed in expected:
        assert isinstance(address, IPv6Address)
        assert address.packed == packed


def test_standard_multicast_group_scopes_match_the_spec() -> None:
    assert multicast_scope(ALL_NODES_MULTICAST) == 2
    assert multicast_scope(ALL_RPL_NODES_MULTICAST) == 2
    assert multicast_scope(ALL_LICHEN_NODES_MULTICAST) == 3
