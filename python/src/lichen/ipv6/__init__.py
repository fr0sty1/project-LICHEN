"""LICHEN IPv6 network layer.

Address handling (IID derivation, link-local/ULA/GUA construction) and IPv6
packet construction/parsing.
"""

from lichen.ipv6.addr import (
    GUA_NETWORK,
    LINK_LOCAL_NETWORK,
    ULA_NETWORK,
    AddrError,
    AddressManager,
    Identity,
    Scope,
    address_from_prefix,
    eui64_to_iid,
    mac48_to_eui64,
    make_gua,
    make_link_local,
    make_ula,
    short_addr_to_iid,
)
from lichen.ipv6.packet import (
    HEADER_LENGTH,
    ExtensionHeader,
    IPv6Header,
    IPv6Packet,
    NextHeader,
    PacketError,
)

__all__ = [
    "GUA_NETWORK",
    "HEADER_LENGTH",
    "LINK_LOCAL_NETWORK",
    "ULA_NETWORK",
    "AddrError",
    "AddressManager",
    "ExtensionHeader",
    "IPv6Header",
    "IPv6Packet",
    "Identity",
    "NextHeader",
    "PacketError",
    "Scope",
    "address_from_prefix",
    "eui64_to_iid",
    "mac48_to_eui64",
    "make_gua",
    "make_link_local",
    "make_ula",
    "short_addr_to_iid",
]
