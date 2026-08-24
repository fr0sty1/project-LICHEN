# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN IPv6 network layer.

Key-derived native/link-local address handling and IPv6 packet construction.
"""

from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.ipv6.addr import (
    LINK_LOCAL_NETWORK,
    NATIVE_NETWORK,
    AddrError,
    address_from_prefix,
    eui64_to_iid,
    iid_to_eui64,
    link_local_from_pubkey,
    mac48_to_eui64,
    make_link_local,
    native_address_from_pubkey,
    short_addr_to_iid,
    to_ipv6,
)
from lichen.ipv6.icmpv6 import (
    DestUnreachableCode,
    EchoReply,
    EchoRequest,
    Icmpv6Error,
    Icmpv6ErrorMessage,
    Icmpv6Message,
    Icmpv6Type,
    TimeExceededCode,
    handle_icmpv6,
    icmpv6_checksum,
    make_dest_unreachable,
    make_packet_too_big,
    make_time_exceeded,
)
from lichen.ipv6.packet import (
    HEADER_LENGTH,
    ExtensionHeader,
    IPv6Header,
    IPv6Packet,
    NextHeader,
    PacketError,
)
from lichen.ipv6.udp import (
    UDP_HEADER_LENGTH,
    UDP_NEXT_HEADER,
    UdpDatagram,
    UdpError,
    udp_checksum,
)

__all__ = [
    "HEADER_LENGTH",
    "LINK_LOCAL_NETWORK",
    "NATIVE_NETWORK",
    "AddrError",
    "DestUnreachableCode",
    "EchoReply",
    "EchoRequest",
    "ExtensionHeader",
    "IPv6Header",
    "IPv6Packet",
    "Icmpv6Error",
    "Icmpv6ErrorMessage",
    "Icmpv6Message",
    "Icmpv6Type",
    "Identity",
    "PeerIdentity",
    "NextHeader",
    "PacketError",
    "TimeExceededCode",
    "UDP_HEADER_LENGTH",
    "UDP_NEXT_HEADER",
    "UdpDatagram",
    "UdpError",
    "udp_checksum",
    "address_from_prefix",
    "eui64_to_iid",
    "iid_to_eui64",
    "handle_icmpv6",
    "icmpv6_checksum",
    "mac48_to_eui64",
    "make_dest_unreachable",
    "make_link_local",
    "make_packet_too_big",
    "make_time_exceeded",
    "link_local_from_pubkey",
    "native_address_from_pubkey",
    "short_addr_to_iid",
    "to_ipv6",
    "yggdrasil_address",
]
