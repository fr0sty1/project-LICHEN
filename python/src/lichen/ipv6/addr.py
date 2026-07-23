# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IPv6 addressing for LICHEN (spec sections 6.1, 6.2, 12).

Interface-Identifier (IID) derivation and construction of the three LICHEN
address scopes (link-local, ULA, GUA). Addresses are represented with the
stdlib :mod:`ipaddress` module.

Per spec 6.2 the IID is derived directly from a node's 64-bit EUI-64 by
flipping the universal/local bit::

    IID = EUI-64 XOR 0x0200_0000_0000_0000

The ``ff:fe`` insertion familiar from 6LoWPAN applies only when converting a
48-bit MAC into an EUI-64 (:func:`mac48_to_eui64`); it is *not* part of IID
derivation from an already-64-bit EUI-64.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address, IPv6Network

# U/L bit (bit 1 of the first octet, big-endian) flipped per spec 6.2.
_UL_BIT = 0x0200_0000_0000_0000

LINK_LOCAL_NETWORK = IPv6Network("fe80::/10")
ULA_NETWORK = IPv6Network("fd00::/8")
GUA_NETWORK = IPv6Network("2000::/3")


def to_ipv6(value: IPv6Address | str | bytes) -> IPv6Address:
    """Coerce a value to IPv6Address.

    Accepts an existing IPv6Address (returned as-is), a string representation,
    or 16 bytes of packed address data.

    Raises:
        AddrError: for any invalid input (wrong-length bytes, malformed string,
        or other values that cannot be converted).
    """
    if isinstance(value, IPv6Address):
        return value
    if isinstance(value, bytes) and len(value) != 16:
        raise AddrError(f"packed IPv6 address must be 16 bytes, got {len(value)}")
    try:
        return IPv6Address(value)
    except ValueError as e:
        raise AddrError(str(e)) from e


class AddrError(Exception):
    """Raised when address material is malformed."""


class Scope(Enum):
    """LICHEN address scope (spec 6.1)."""

    LINK_LOCAL = "link_local"
    ULA = "ula"
    GUA = "gua"


def eui64_to_iid(eui64: bytes) -> bytes:
    """Derive a 64-bit IID from an EUI-64 by flipping the U/L bit (spec 6.2)."""
    if len(eui64) != 8:
        raise AddrError(f"EUI-64 must be 8 bytes, got {len(eui64)}")
    value = int.from_bytes(eui64, "big") ^ _UL_BIT
    return value.to_bytes(8, "big")


def mac48_to_eui64(mac: bytes) -> bytes:
    """Convert a 48-bit MAC to an EUI-64 by inserting ``FF FE`` (RFC 4291).

    This does *not* flip the U/L bit; pass the result to :func:`eui64_to_iid`
    to obtain a modified-EUI-64 interface identifier.
    """
    if len(mac) != 6:
        raise AddrError(f"MAC-48 must be 6 bytes, got {len(mac)}")
    return mac[:3] + b"\xff\xfe" + mac[3:]


def short_addr_to_iid(short_addr: int) -> bytes:
    """Derive an IID from a 16-bit short address (RFC 4944 section 6).

    Format: ``0000:00FF:FE00:XXXX`` where XXXX is the 16-bit short address
    in the low bytes of the IID.
    """
    if not 0 <= short_addr <= 0xFFFF:
        raise AddrError(f"short address out of range: {short_addr}")
    value = 0x0000_00FF_FE00_0000 | short_addr
    return value.to_bytes(8, "big")


def address_from_prefix(prefix: IPv6Network, iid: bytes) -> IPv6Address:
    """Combine a /64 prefix with an 8-byte IID into a full address."""
    if prefix.prefixlen != 64:
        raise AddrError(f"prefix must be /64, got /{prefix.prefixlen}")
    if len(iid) != 8:
        raise AddrError(f"IID must be 8 bytes, got {len(iid)}")
    return IPv6Address(prefix.network_address.packed[:8] + iid)


def make_link_local(iid: bytes) -> IPv6Address:
    """Build the link-local address ``fe80::<IID>`` (spec 6.1)."""
    if len(iid) != 8:
        raise AddrError(f"IID must be 8 bytes, got {len(iid)}")
    return IPv6Address(b"\xfe\x80" + b"\x00" * 6 + iid)


def make_ula(prefix: IPv6Network, iid: bytes) -> IPv6Address:
    """Build a ULA address from an ``fd00::/8`` /64 prefix and an IID."""
    if not prefix.subnet_of(ULA_NETWORK):
        raise AddrError(f"prefix {prefix} is not within {ULA_NETWORK}")
    return address_from_prefix(prefix, iid)


def make_gua(prefix: IPv6Network, iid: bytes) -> IPv6Address:
    """Build a GUA address from a ``2000::/3`` /64 prefix and an IID."""
    if not prefix.subnet_of(GUA_NETWORK):
        raise AddrError(f"prefix {prefix} is not within {GUA_NETWORK}")
    return address_from_prefix(prefix, iid)


@dataclass(frozen=True)
class Identity:
    """A node's stable identity: its EUI-64 and the addresses derived from it."""

    eui64: bytes

    def __post_init__(self) -> None:
        if len(self.eui64) != 8:
            raise AddrError(f"EUI-64 must be 8 bytes, got {len(self.eui64)}")

    @classmethod
    def from_mac48(cls, mac: bytes) -> Identity:
        """Build an identity from a 48-bit MAC (via modified EUI-64)."""
        return cls(mac48_to_eui64(mac))

    @property
    def iid(self) -> bytes:
        """The 8-byte interface identifier (spec 6.2)."""
        return eui64_to_iid(self.eui64)

    @property
    def link_local(self) -> IPv6Address:
        """The always-available link-local address."""
        return make_link_local(self.iid)

    def ula(self, prefix: IPv6Network) -> IPv6Address:
        """This node's ULA address under ``prefix``."""
        return make_ula(prefix, self.iid)

    def gua(self, prefix: IPv6Network) -> IPv6Address:
        """This node's GUA address under ``prefix``."""
        return make_gua(prefix, self.iid)


@dataclass
class AddressManager:
    """Tracks a node's current addresses by scope (spec 6.1).

    The link-local address is present from construction. ULA and GUA addresses
    appear once a prefix is learned (from a DODAG root or border router) and can
    be cleared when the prefix is withdrawn.
    """

    identity: Identity
    _by_scope: dict[Scope, IPv6Address] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._by_scope[Scope.LINK_LOCAL] = self.identity.link_local

    def set_ula_prefix(self, prefix: IPv6Network) -> IPv6Address:
        """Learn a ULA prefix and record the derived address."""
        addr = self.identity.ula(prefix)
        self._by_scope[Scope.ULA] = addr
        return addr

    def set_gua_prefix(self, prefix: IPv6Network) -> IPv6Address:
        """Learn a GUA prefix and record the derived address."""
        addr = self.identity.gua(prefix)
        self._by_scope[Scope.GUA] = addr
        return addr

    def clear(self, scope: Scope) -> None:
        """Withdraw the address for a scope (link-local cannot be cleared)."""
        if scope is Scope.LINK_LOCAL:
            raise AddrError("link-local address cannot be cleared")
        self._by_scope.pop(scope, None)

    def get(self, scope: Scope) -> IPv6Address | None:
        """The current address for a scope, or ``None`` if not configured."""
        return self._by_scope.get(scope)

    def all(self) -> list[IPv6Address]:
        """All currently configured addresses."""
        return list(self._by_scope.values())
