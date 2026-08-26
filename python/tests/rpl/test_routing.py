# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RPL non-storing routing table and source-routed forwarding."""

from __future__ import annotations

from dataclasses import replace
from ipaddress import IPv6Address

import pytest

from lichen.ipv6.packet import ExtensionHeader, IPv6Header, IPv6Packet, NextHeader
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
    # The complete Routing header is 24 octets, so RFC 8200 Hdr Ext Len is 2
    # (length in 8-octet units, excluding the first 8 octets).
    assert srh.to_extension_header().to_bytes(NextHeader.UDP)[1] == 2


@pytest.mark.parametrize("length", range(6))
def test_srh_from_ext_data_rejects_truncated_fixed_fields(length: int) -> None:
    with pytest.raises(RoutingError, match="too short"):
        SourceRoutingHeader.from_ext_data(bytes(length))


def test_srh_from_ext_data_rejects_wrong_type() -> None:
    with pytest.raises(RoutingError):
        SourceRoutingHeader.from_ext_data(bytes([4, 0, 0, 0, 0, 0]))


@pytest.mark.parametrize("cmpr", [0x10, 0x01, 0xF0, 0x0F, 0xFF])
def test_srh_from_ext_data_rejects_compressed_addresses(cmpr: int) -> None:
    data = bytes([3, 1, cmpr, 0, 0, 0]) + DEST.packed
    with pytest.raises(RoutingError, match="compressed source routing headers"):
        SourceRoutingHeader.from_ext_data(data)


@pytest.mark.parametrize("pad", [1, 7, 15])
def test_srh_from_ext_data_rejects_nonzero_pad(pad: int) -> None:
    data = bytes([3, 1, 0, pad << 4, 0, 0]) + DEST.packed
    with pytest.raises(RoutingError, match="nonzero Pad"):
        SourceRoutingHeader.from_ext_data(data)


def test_srh_from_ext_data_ignores_reserved_bits() -> None:
    # RFC 6554 requires receivers to ignore the Reserved low nibble and
    # following two octets. Re-encoding emits their canonical zero values.
    data = bytes([3, 1, 0, 0x0F, 0xA5, 0x5A]) + DEST.packed
    restored = SourceRoutingHeader.from_ext_data(data)
    assert restored == SourceRoutingHeader(segments_left=1, addresses=[DEST])
    assert restored.to_ext_data()[:6] == bytes([3, 1, 0, 0, 0, 0])


@pytest.mark.parametrize("address_octets", [1, 15, 17, 31])
def test_srh_from_ext_data_rejects_misaligned_address_length(address_octets: int) -> None:
    data = bytes([3, 0, 0, 0, 0, 0]) + bytes(address_octets)
    with pytest.raises(RoutingError, match="not 16-byte aligned"):
        SourceRoutingHeader.from_ext_data(data)


def test_srh_zero_segments_and_empty_address_vector_round_trip() -> None:
    srh = SourceRoutingHeader(segments_left=0)
    assert srh.to_ext_data() == bytes([3, 0, 0, 0, 0, 0])
    assert SourceRoutingHeader.from_ext_data(srh.to_ext_data()) == srh


def test_srh_from_extension_header_rejects_wrong_extension_type() -> None:
    ext = SourceRoutingHeader(segments_left=1, addresses=[DEST]).to_extension_header()
    wrong_type = type(ext)(NextHeader.HOP_BY_HOP, ext.data)
    with pytest.raises(RoutingError, match="not a Routing extension header"):
        SourceRoutingHeader.from_extension_header(wrong_type)


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
    packet = IPv6Packet(header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"hi")
    routed, first_hop = insert_source_route(packet, [DEST])
    assert first_hop == DEST
    assert routed.header.dst_addr == DEST
    assert routed.extension_headers == []  # direct neighbour, no SRH


def test_insert_source_route_accepts_eight_hops_and_rejects_nine() -> None:
    hops: list[IPv6Address | str] = [IPv6Address(f"fd00::{index}") for index in range(10, 19)]
    packet = IPv6Packet(header=IPv6Header(ROOT, hops[7], NextHeader.UDP), payload=b"hi")
    routed, first_hop = insert_source_route(packet, hops[:8])
    assert first_hop == hops[0]
    assert (
        SourceRoutingHeader.from_extension_header(routed.extension_headers[0]).addresses
        == hops[1:8]
    )
    packet = replace(packet, header=replace(packet.header, dst_addr=hops[-1]))
    with pytest.raises(RoutingError, match="maximum hop count"):
        insert_source_route(packet, hops)


def test_source_route_end_to_end_traversal() -> None:
    # Root sends to DEST via A then B. Path = [A, B, DEST].
    packet = IPv6Packet(header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"payload")
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
    packet = IPv6Packet(header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"x")
    # Path ends with DEST, matches expected_destination - should succeed
    routed, first_hop = insert_source_route(packet, [A, B, DEST], expected_destination=DEST)
    assert first_hop == A
    assert routed.header.dst_addr == A

    # The packet's destination is always authoritative, even when the optional
    # compatibility argument is omitted.
    with pytest.raises(RoutingError, match="does not end with packet destination"):
        insert_source_route(packet, [A, B], expected_destination=DEST)

    with pytest.raises(RoutingError, match="does not match expected destination"):
        insert_source_route(packet, [A, B, DEST], expected_destination=B)


@pytest.mark.parametrize(
    ("path", "match"),
    [
        ([A, A, DEST], "duplicate"),
        ([ROOT, DEST], "packet source"),
        ([IPv6Address("ff02::1"), DEST], "multicast"),
    ],
)
def test_insert_source_route_rejects_non_strict_paths(
    path: list[IPv6Address], match: str
) -> None:
    packet = IPv6Packet(header=IPv6Header(ROOT, DEST, NextHeader.UDP), payload=b"x")
    with pytest.raises(RoutingError, match=match):
        insert_source_route(packet, path)


def test_insert_source_route_rejects_unusable_hop_limit() -> None:
    packet = IPv6Packet(
        header=IPv6Header(ROOT, DEST, NextHeader.UDP, hop_limit=2), payload=b"x"
    )
    with pytest.raises(RoutingError, match="strictly less than hop_limit"):
        insert_source_route(packet, [A, B, DEST])


def test_insert_source_route_rejects_existing_routing_header() -> None:
    packet = IPv6Packet(
        header=IPv6Header(ROOT, DEST, NextHeader.UDP),
        payload=b"x",
        extension_headers=[SourceRoutingHeader(0).to_extension_header()],
    )
    with pytest.raises(RoutingError, match="already contains"):
        insert_source_route(packet, [A, B, DEST])


def test_insert_source_route_preserves_hop_by_hop_first() -> None:
    hop_by_hop = ExtensionHeader(NextHeader.HOP_BY_HOP, bytes(6))
    packet = IPv6Packet(
        header=IPv6Header(ROOT, DEST, NextHeader.UDP),
        payload=b"x",
        extension_headers=[hop_by_hop],
    )
    routed, first_hop = insert_source_route(packet, [A, B, DEST])
    assert first_hop == A
    assert [ext.header_type for ext in routed.extension_headers] == [
        NextHeader.HOP_BY_HOP,
        NextHeader.ROUTING,
    ]
    assert IPv6Packet.from_bytes(routed.to_bytes(), strict=True) == routed


def test_advance_source_route_rejects_segments_left_gte_hop_limit() -> None:
    """RFC 6554 + LICHEN spec §5 line 418: Segments Left MUST be < Hop Limit."""
    srh = SourceRoutingHeader(segments_left=3, addresses=[A, B, DEST])
    ext = srh.to_extension_header()

    # segments_left=3, hop_limit=4: 3 < 4, should succeed
    # First hop from addresses with segments_left=3 is addresses[3-3]=addresses[0]=A
    packet_ok = IPv6Packet(
        header=IPv6Header(ROOT, A, NextHeader.UDP, hop_limit=4),
        payload=b"x",
        extension_headers=[ext],
    )
    _, nxt = advance_source_route(packet_ok)
    assert nxt == A

    # segments_left=3, hop_limit=3: 3 >= 3, should reject
    packet_eq = IPv6Packet(
        header=IPv6Header(ROOT, A, NextHeader.UDP, hop_limit=3),
        payload=b"x",
        extension_headers=[ext],
    )
    with pytest.raises(RoutingError, match="not strictly less than hop_limit"):
        advance_source_route(packet_eq)

    # segments_left=3, hop_limit=2: 3 >= 2, should reject
    packet_gt = IPv6Packet(
        header=IPv6Header(ROOT, A, NextHeader.UDP, hop_limit=2),
        payload=b"x",
        extension_headers=[ext],
    )
    with pytest.raises(RoutingError, match="not strictly less than hop_limit"):
        advance_source_route(packet_gt)


def test_advance_source_route_allows_zero_segments_left_with_any_hop_limit() -> None:
    """segments_left=0 is always valid (packet at final destination)."""
    srh = SourceRoutingHeader(segments_left=0, addresses=[DEST])
    ext = srh.to_extension_header()
    # hop_limit=0 is always rejected defensively (should have been dropped earlier)
    packet = IPv6Packet(
        header=IPv6Header(ROOT, DEST, NextHeader.UDP, hop_limit=0),
        payload=b"x",
        extension_headers=[ext],
    )
    with pytest.raises(RoutingError, match="hop_limit_exhausted"):
        advance_source_route(packet)
