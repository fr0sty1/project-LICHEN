# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LCI client IPv6 addressing oracle tests (spec 11 section 17.4).

Expected addresses are hand-derived from spec 17.4 and RFC 4291, not from
the production helpers under test.
"""

from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network

import pytest

from lichen.client.addressing import (
    DEFAULT_ROUTE_PREFIX,
    STATIC_CLIENT_ADDRESS,
    STATIC_CLIENT_IID,
    STATIC_NODE_ADDRESS,
    STATIC_NODE_IID,
    LciAddressAssignment,
    LciAddressError,
    LciAddressProfile,
    LciRoute,
    client_link_local,
    eui64_assignment,
    node_link_local,
    static_assignment,
)
from lichen.client.ip_coap import IpCoapConfig
from lichen.client.packet_coap import PacketCoapConfig
from lichen.ipv6.addr import LINK_LOCAL_NETWORK


def _rfc4291_link_local_from_eui64(eui64: bytes) -> IPv6Address:
    """Independent RFC 4291 modified-EUI-64 link-local constructor."""
    iid = bytes((eui64[0] ^ 0x02,)) + eui64[1:]
    return IPv6Address(bytes.fromhex("fe80000000000000") + iid)


def _rfc4291_link_local_from_mac48(mac: bytes) -> IPv6Address:
    """Independent RFC 4291 MAC-48 to link-local constructor."""
    return _rfc4291_link_local_from_eui64(mac[:3] + b"\xff\xfe" + mac[3:])


def test_static_constants_match_spec_17_4_packed_bytes() -> None:
    assert IPv6Address("fe80::2") == STATIC_CLIENT_ADDRESS
    assert IPv6Address("fe80::1") == STATIC_NODE_ADDRESS
    assert STATIC_CLIENT_ADDRESS.packed == bytes.fromhex("fe800000000000000000000000000002")
    assert STATIC_NODE_ADDRESS.packed == bytes.fromhex("fe800000000000000000000000000001")
    assert bytes.fromhex("0000000000000002") == STATIC_CLIENT_IID
    assert bytes.fromhex("0000000000000001") == STATIC_NODE_IID
    assert STATIC_CLIENT_ADDRESS in LINK_LOCAL_NETWORK
    assert STATIC_NODE_ADDRESS in LINK_LOCAL_NETWORK


def test_static_assignment_is_client_fe80_2_and_node_fe80_1() -> None:
    assignment = static_assignment()

    assert assignment.profile is LciAddressProfile.STATIC
    assert assignment.client == STATIC_CLIENT_ADDRESS
    assert assignment.node == STATIC_NODE_ADDRESS
    assert assignment.client.packed != assignment.node.packed


def test_static_assignment_routing_table_matches_spec() -> None:
    assignment = static_assignment()
    on_link, default = assignment.routing_table()

    assert on_link == LciRoute(prefix=IPv6Network("fe80::/10"), via=None)
    assert on_link.on_link is True
    assert default == LciRoute(prefix=IPv6Network("::/0"), via=IPv6Address("fe80::1"))
    assert default.on_link is False
    assert IPv6Network("::/0") == DEFAULT_ROUTE_PREFIX
    assert str(on_link.prefix) == "fe80::/10"
    assert str(default.prefix) == "::/0"


def test_static_assignment_zone_is_local_metadata() -> None:
    assignment = static_assignment(zone_id="sl0")

    assert assignment.client.scope_id == "sl0"
    assert assignment.node.scope_id == "sl0"
    assert str(assignment.client) == "fe80::2%sl0"
    assert str(assignment.node) == "fe80::1%sl0"
    assert assignment.client.packed == STATIC_CLIENT_ADDRESS.packed
    assert assignment.node.packed == STATIC_NODE_ADDRESS.packed
    assert assignment.routing_table()[1].via == assignment.node


def test_eui64_assignment_matches_independent_rfc4291_oracle() -> None:
    # Hand-chosen MAC/EUI-64 pair. MAC 00:11:22:33:44:55 expands to
    # 00:11:22:FF:FE:33:44:55, U/L flip yields IID 02:11:22:FF:FE:33:44:55.
    client_mac = bytes.fromhex("001122334455")
    node_eui64 = bytes.fromhex("103456789abcdef0")
    expected_client = IPv6Address("fe80::211:22ff:fe33:4455")
    expected_node = IPv6Address("fe80::1234:5678:9abc:def0")

    assignment = eui64_assignment(client_mac, node_eui64)

    assert assignment.profile is LciAddressProfile.EUI64
    assert assignment.client == expected_client
    assert assignment.node == expected_node
    assert assignment.client == _rfc4291_link_local_from_mac48(client_mac)
    assert assignment.node == _rfc4291_link_local_from_eui64(node_eui64)
    assert assignment.client.packed == bytes.fromhex("fe80000000000000021122fffe334455")
    assert assignment.node.packed == bytes.fromhex("fe80000000000000123456789abcdef0")
    on_link, default = assignment.routing_table()
    assert on_link.prefix == IPv6Network("fe80::/10")
    assert on_link.via is None
    assert default.via == expected_node


def test_client_link_local_accepts_eui64_hardware_address() -> None:
    eui64 = bytes.fromhex("001122fffe334455")
    address = client_link_local(eui64)

    assert address == _rfc4291_link_local_from_eui64(eui64)
    assert address == IPv6Address("fe80::211:22ff:fe33:4455")


def test_eui64_assignment_preserves_zone_without_changing_wire_bytes() -> None:
    client_mac = bytes.fromhex("001122334455")
    node_eui64 = bytes.fromhex("103456789abcdef0")
    assignment = eui64_assignment(client_mac, node_eui64, zone_id="lci0")

    assert assignment.client.scope_id == "lci0"
    assert assignment.node.scope_id == "lci0"
    assert assignment.client.packed == bytes.fromhex("fe80000000000000021122fffe334455")
    assert assignment.node.packed == bytes.fromhex("fe80000000000000123456789abcdef0")


def test_eui64_assignment_rejects_identical_client_and_node() -> None:
    # Same EUI-64 on both sides collapses to one link-local, which cannot
    # identify two LCI neighbors.
    eui64 = bytes.fromhex("001122fffe334455")
    with pytest.raises(LciAddressError, match="must differ"):
        eui64_assignment(eui64, eui64)


@pytest.mark.parametrize(
    "hwaddr",
    [b"", bytes(5), bytes(7), bytes(9), bytearray(6), memoryview(bytes(6)), "001122"],
)
def test_client_link_local_rejects_noncanonical_hardware_addresses(hwaddr: object) -> None:
    with pytest.raises(LciAddressError):
        client_link_local(hwaddr)  # type: ignore[arg-type]


@pytest.mark.parametrize("eui64", [b"", bytes(7), bytes(9), bytearray(8), None])
def test_node_link_local_rejects_noncanonical_eui64(eui64: object) -> None:
    with pytest.raises(LciAddressError):
        node_link_local(eui64)  # type: ignore[arg-type]


@pytest.mark.parametrize("zone_id", ["", "lci%0", "lci 0", 0, -1, True, object()])
def test_assignment_rejects_invalid_zones(zone_id: object) -> None:
    with pytest.raises(LciAddressError):
        static_assignment(zone_id=zone_id)  # type: ignore[arg-type]


def test_assignment_rejects_non_link_local_pair() -> None:
    with pytest.raises(LciAddressError, match="link-local"):
        LciAddressAssignment(
            client=IPv6Address("2001:db8::2"),
            node=STATIC_NODE_ADDRESS,
            profile=LciAddressProfile.STATIC,
        )


def test_assignment_rejects_string_profile() -> None:
    with pytest.raises(LciAddressError, match="profile"):
        LciAddressAssignment(
            client=STATIC_CLIENT_ADDRESS,
            node=STATIC_NODE_ADDRESS,
            profile="static",  # type: ignore[arg-type]
        )


def test_node_link_local_matches_spec_eui64_example() -> None:
    # Spec 12.2 / 6.2 worked example: EUI-64 10:34:56:78:9a:bc:de:f0.
    address = node_link_local(bytes.fromhex("103456789abcdef0"))
    assert address == IPv6Address("fe80::1234:5678:9abc:def0")
    assert address.packed == bytes.fromhex("fe80000000000000123456789abcdef0")


def test_static_assignment_accepts_numeric_zone_index() -> None:
    assignment = static_assignment(zone_id=7)
    assert assignment.client.scope_id == "7"
    assert assignment.node.scope_id == "7"
    assert assignment.client.packed == STATIC_CLIENT_ADDRESS.packed


def test_lci_config_defaults_are_the_static_neighbor_pair() -> None:
    packet = PacketCoapConfig()
    ip_coap = IpCoapConfig()

    assert packet.local_host == str(STATIC_CLIENT_ADDRESS)
    assert packet.peer_host == str(STATIC_NODE_ADDRESS)
    assert ip_coap.base_uri == f"coap://[{STATIC_NODE_ADDRESS}]"
