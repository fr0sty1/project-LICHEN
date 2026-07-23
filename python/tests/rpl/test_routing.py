# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RPL non-storing routing table and source-routed forwarding."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.rpl.dodag import DodagState
from lichen.rpl.routing import (
    RoutingError,
    RoutingTable,
    SourceRoutingHeader,
    advance_source_route,
    insert_source_route,
    next_hop_upward,
)

ROOT = IPv6Address("fd00::1")
A = IPv6Address("fd00::a")
B = IPv6Address("fd00::b")
DEST = IPv6Address("fd00::d")


def test_routing_table_add_lookup_remove() -> None:
    table = RoutingTable()
    table.add_route(DEST, [A, B, DEST])
    assert DEST in table
    assert table.lookup(DEST) == [A, B, DEST]
    assert table.build_source_route(DEST) == [A, B, DEST]
    assert len(table) == 1
    table.remove_route(DEST)
    assert DEST not in table
    assert table.lookup(DEST) is None


def test_routing_table_rejects_empty_path() -> None:
    with pytest.raises(RoutingError):
        RoutingTable().add_route(DEST, [])


def test_routing_table_rejects_path_not_ending_at_target() -> None:
    with pytest.raises(RoutingError, match="must end at target"):
        RoutingTable().add_route(DEST, [A, B])  # path does not end with DEST


def test_routing_table_accepts_string_addresses() -> None:
    table = RoutingTable()
    table.add_route("fd00::d", ["fd00::a", "fd00::d"])
    assert table.lookup(DEST) == [A, DEST]


def test_routing_table_accepts_eight_hops_and_rejects_nine() -> None:
    hops: list[IPv6Address | str] = [IPv6Address(f"fd00::{index}") for index in range(1, 10)]
    table = RoutingTable()
    table.add_route(hops[7], hops[:8])
    assert table.lookup(hops[7]) == hops[:8]
    with pytest.raises(RoutingError, match="maximum hop count"):
        table.add_route(hops[8], hops)


def test_srh_round_trip() -> None:
    srh = SourceRoutingHeader(segments_left=2, addresses=[B, DEST])
    ext = srh.to_extension_header()
    assert ext.header_type == NextHeader.ROUTING
    restored = SourceRoutingHeader.from_extension_header(ext)
    assert restored == srh


def test_srh_ext_data_layout() -> None:
    srh = SourceRoutingHeader(segments_left=1, addresses=[DEST])
    data = srh.to_ext_data()
    # routing_type=3, segments_left=1, 4 zero bytes, then a 16-byte address.
    assert data[:6] == bytes([3, 1, 0, 0, 0, 0])
    assert data[6:] == DEST.packed
    assert len(data) == 6 + 16


def test_srh_from_ext_data_rejects_wrong_type() -> None:
    with pytest.raises(RoutingError):
        SourceRoutingHeader.from_ext_data(bytes([4, 0, 0, 0, 0, 0]))


def test_srh_from_ext_data_rejects_segments_left_exceeds_addresses() -> None:
    # segments_left=2 but only 1 address (16 bytes) provided
    data = bytes([3, 2, 0, 0, 0, 0]) + DEST.packed
    with pytest.raises(RoutingError, match="segments_left exceeds"):
        SourceRoutingHeader.from_ext_data(data)


def test_srh_encode_rejects_segments_left_exceeds_addresses() -> None:
    with pytest.raises(RoutingError, match="segments_left exceeds"):
        SourceRoutingHeader(segments_left=2, addresses=[DEST]).to_ext_data()


def test_srh_accepts_eight_addresses_and_rejects_nine() -> None:
    addresses = [IPv6Address(f"fd00::{index}") for index in range(1, 10)]
    encoded = SourceRoutingHeader(8, addresses[:8]).to_ext_data()
    assert SourceRoutingHeader.from_ext_data(encoded).addresses == addresses[:8]

    with pytest.raises(RoutingError, match="maximum hop count"):
        SourceRoutingHeader(9, addresses).to_ext_data()
    wire = bytes([3, 8, 0, 0, 0, 0]) + b"".join(address.packed for address in addresses)
    with pytest.raises(RoutingError, match="maximum hop count"):
        SourceRoutingHeader.from_ext_data(wire)


def test_next_hop_upward_is_preferred_parent() -> None:
    dodag = DodagState(rpl_instance_id=0, dodag_id="fd00::1", version=1)
    assert next_hop_upward(dodag) is None
    dodag.preferred_parent = IPv6Address("fe80::1234")
    assert next_hop_upward(dodag) == IPv6Address("fe80::1234")


def test_insert_source_route_single_hop_no_srh() -> None:
    packet = IPv6Packet(header=IPv6Header(ROOT, ROOT, NextHeader.UDP), payload=b"hi")
    routed, first_hop = insert_source_route(packet, [DEST])
    assert first_hop == DEST
    assert routed.header.dst_addr == DEST
    assert routed.extension_headers == []  # direct neighbour, no SRH


def test_insert_source_route_accepts_eight_hops_and_rejects_nine() -> None:
    packet = IPv6Packet(header=IPv6Header(ROOT, ROOT, NextHeader.UDP), payload=b"hi")
    hops: list[IPv6Address | str] = [IPv6Address(f"fd00::{index}") for index in range(1, 10)]
    routed, first_hop = insert_source_route(packet, hops[:8])
    assert first_hop == hops[0]
    assert (
        SourceRoutingHeader.from_extension_header(routed.extension_headers[0]).addresses
        == hops[1:8]
    )
    with pytest.raises(RoutingError, match="maximum hop count"):
        insert_source_route(packet, hops)


def test_source_route_end_to_end_traversal() -> None:
    # Root sends to DEST via A then B. Path = [A, B, DEST].
    packet = IPv6Packet(header=IPv6Header(ROOT, ROOT, NextHeader.UDP), payload=b"payload")
    routed, first_hop = insert_source_route(packet, [A, B, DEST])
    assert first_hop == A
    assert routed.header.dst_addr == A

    # Wire round-trip to ensure the SRH survives serialization.
    routed = IPv6Packet.from_bytes(routed.to_bytes())

    visited = [first_hop]
    current = routed
    for _ in range(10):
        current, nxt = advance_source_route(current)
        if nxt is None:
            break
        visited.append(nxt)
    assert visited == [A, B, DEST]
    # At the final destination, segments_left is exhausted.
    _, nxt = advance_source_route(current)
    assert nxt is None
    assert current.header.dst_addr == DEST
    assert current.payload == b"payload"


def test_advance_without_srh_returns_none() -> None:
    packet = IPv6Packet(header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"x")
    _, nxt = advance_source_route(packet)
    assert nxt is None


def test_insert_source_route_validates_expected_destination() -> None:
    packet = IPv6Packet(
        header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"x"
    )
    # Path ends with DEST, matches expected_destination - should succeed
    routed, first_hop = insert_source_route(
        packet, [A, B, DEST], expected_destination=DEST
    )
    assert first_hop == A
    assert routed.header.dst_addr == A

    # Path does NOT end with expected_destination - should raise
    with pytest.raises(RoutingError, match="does not end with expected destination"):
        insert_source_route(packet, [A, B], expected_destination=DEST)
