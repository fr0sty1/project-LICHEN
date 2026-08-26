# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IPv6 address construction for the LICHEN native-address profile.

Canonical node identities are cryptographic identities from
:mod:`lichen.crypto.identity`: an Ed25519 public key derives both the IID and
the primary address in exactly ``0200::/8``.  This module retains low-level
EUI-64 conversion helpers only for link-wire and standards interoperability;
they are not node-identity constructors.  LICHEN does not advertise ULA.
"""

from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network

# U/L bit (bit 1 of the first octet, big-endian) flipped per spec 6.2.
_UL_BIT = 0x0200_0000_0000_0000

LINK_LOCAL_NETWORK = IPv6Network("fe80::/10")
NATIVE_NETWORK = IPv6Network("0200::/8")

# Standard groups from spec/04-network.md section 6.3.1.  All-nodes is
# defined by ICMPv6 because Neighbor Discovery consumes it directly; the
# remaining LICHEN-wide groups live with the address profile.
ALL_RPL_NODES_MULTICAST: IPv6Address = IPv6Address("ff02::1a")
ALL_LICHEN_NODES_MULTICAST: IPv6Address = IPv6Address("ff03::fc")


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


def eui64_to_iid(eui64: bytes) -> bytes:
    """Derive a 64-bit IID from an EUI-64 by flipping the U/L bit (spec 6.2)."""
    if len(eui64) != 8:
        raise AddrError(f"EUI-64 must be 8 bytes, got {len(eui64)}")
    value = int.from_bytes(eui64, "big") ^ _UL_BIT
    return value.to_bytes(8, "big")


def iid_to_eui64(iid: bytes) -> bytes:
    """Recover the canonical wire EUI-64 by flipping the IID U/L bit."""
    if len(iid) != 8:
        raise AddrError(f"IID must be 8 bytes, got {len(iid)}")
    value = int.from_bytes(iid, "big") ^ _UL_BIT
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


def _normalize_zone_id(zone_id: str | int | None) -> str | None:
    """Return a zone identifier accepted by :class:`IPv6Address`.

    A zone is local interface metadata, not part of the 128-bit IPv6 address.
    Integer interface indexes are rendered in their canonical decimal form;
    interface names are preserved exactly.  Zero cannot identify an owning
    interface, and ``%`` is reserved as the address/zone delimiter.
    """
    if zone_id is None:
        return None
    if type(zone_id) is int:
        if zone_id <= 0:
            raise AddrError("IPv6 zone index must be positive")
        return str(zone_id)
    if type(zone_id) is not str:
        raise AddrError("IPv6 zone must be a string or positive interface index")
    if not zone_id:
        raise AddrError("IPv6 zone must not be empty")
    if "%" in zone_id or any(character.isspace() for character in zone_id):
        raise AddrError("IPv6 zone contains invalid characters")
    return zone_id


def make_link_local(iid: bytes, *, zone_id: str | int | None = None) -> IPv6Address:
    """Build the canonical ``fe80::/64`` address for an IID (spec 6.1).

    The canonical prefix is inside IPv6's ``fe80::/10`` link-local range.
    ``zone_id``, when supplied, records the owning local interface (for
    example ``"lci0"`` or interface index ``3``).  The zone is preserved by
    :class:`IPv6Address` but is not included in :attr:`IPv6Address.packed` and
    therefore is never transmitted as part of the address.
    """
    if type(iid) is not bytes:
        raise AddrError("IID must be immutable bytes")
    if len(iid) != 8:
        raise AddrError(f"IID must be 8 bytes, got {len(iid)}")
    address = IPv6Address(b"\xfe\x80" + b"\x00" * 6 + iid)
    zone = _normalize_zone_id(zone_id)
    if zone is None:
        return address
    try:
        return IPv6Address(f"{address}%{zone}")
    except ValueError as exc:  # Defensive boundary around stdlib validation.
        raise AddrError("invalid IPv6 zone") from exc


def native_address_from_pubkey(pubkey: bytes) -> IPv6Address:
    """Return the canonical key-derived primary address in ``0200::/8``."""
    if type(pubkey) is not bytes:
        raise AddrError("public key must be immutable bytes")
    try:
        from lichen.crypto.identity import yggdrasil_address

        address = yggdrasil_address(pubkey)
    except ValueError as exc:
        raise AddrError(str(exc)) from exc
    if address not in NATIVE_NETWORK:  # Defensive invariant at the public boundary.
        raise AddrError("derived address is outside the LICHEN native prefix")
    return address


def multicast_scope(addr: IPv6Address | str | bytes) -> int | None:
    """Return the 4-bit multicast scope, or None if the address is unicast.

    RFC 4291: the low nibble of the second octet is the scope. Unflagged
    well-known scopes used by LICHEN are ``ff01`` (interface) through
    ``ff0e`` (global).
    """
    packed = to_ipv6(addr).packed
    if packed[0] != 0xFF:
        return None
    return packed[1] & 0x0F


def is_unflagged_multicast(addr: IPv6Address | str | bytes) -> bool:
    """True for ``ff01::``-``ff0e::`` (flags nibble 0, scope 1..14)."""
    packed = to_ipv6(addr).packed
    if packed[0] != 0xFF:
        return False
    flags_and_scope = packed[1]
    return flags_and_scope & 0xF0 == 0 and 0x01 <= flags_and_scope <= 0x0E


def link_local_from_pubkey(pubkey: bytes, *, zone_id: str | int | None = None) -> IPv6Address:
    """Return the optionally zoned link-local address bound to a public key."""
    if type(pubkey) is not bytes:
        raise AddrError("public key must be immutable bytes")
    try:
        from lichen.crypto.identity import PeerIdentity

        return make_link_local(PeerIdentity.from_pubkey(pubkey).iid, zone_id=zone_id)
    except ValueError as exc:
        raise AddrError(str(exc)) from exc
