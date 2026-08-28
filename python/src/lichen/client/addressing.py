# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LCI client IPv6 addressing oracle (spec 11 section 17.4).

The local client is an IPv6 neighbor of the mesh node. Two assignment
profiles are defined:

- Static (simple): client ``fe80::2``, node ``fe80::1``
- EUI-64 derived: client from device MAC, node from node EUI-64

The node is the client's default router. The client's routing table is::

    fe80::/10  -> local interface (direct)
    ::/0       -> node link-local
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv6Address, IPv6Network

from lichen.ipv6.addr import (
    LINK_LOCAL_NETWORK,
    AddrError,
    eui64_to_iid,
    mac48_to_eui64,
    make_link_local,
)

# Spec 17.4 static (simple) IIDs: client fe80::2, node fe80::1.
STATIC_CLIENT_IID = bytes.fromhex("0000000000000002")
STATIC_NODE_IID = bytes.fromhex("0000000000000001")
STATIC_CLIENT_ADDRESS = IPv6Address("fe80::2")
STATIC_NODE_ADDRESS = IPv6Address("fe80::1")
DEFAULT_ROUTE_PREFIX = IPv6Network("::/0")


class LciAddressError(ValueError):
    """Raised when LCI client or node address material is invalid."""


class LciAddressProfile(StrEnum):
    """Spec 17.4 assignment profiles."""

    STATIC = "static"
    EUI64 = "eui64"


@dataclass(frozen=True)
class LciRoute:
    """One client routing-table entry (spec 17.4).

    ``via`` is ``None`` for on-link (local interface) destinations.
    ``zone_id`` binds the route to a specific interface (e.g., ``%eth0``).
    """

    prefix: IPv6Network
    via: IPv6Address | None
    zone_id: str | None = None

    @property
    def on_link(self) -> bool:
        """True when the prefix is reached on the local LCI interface."""
        return self.via is None


@dataclass(frozen=True)
class LciAddressAssignment:
    """Client and node link-local addresses plus the client's routes."""

    client: IPv6Address
    node: IPv6Address
    profile: LciAddressProfile

    def __post_init__(self) -> None:
        if not isinstance(self.profile, LciAddressProfile):
            raise LciAddressError("profile must be an LciAddressProfile")
        if type(self.client) is not IPv6Address or type(self.node) is not IPv6Address:
            raise LciAddressError("client and node must be IPv6Address values")
        if self.client not in LINK_LOCAL_NETWORK or self.node not in LINK_LOCAL_NETWORK:
            raise LciAddressError("LCI addresses must be link-local")
        if self.client.packed == self.node.packed:
            raise LciAddressError("client and node link-local addresses must differ")

    def routing_table(self) -> tuple[LciRoute, LciRoute]:
        """Return the spec 17.4 client routing table for this assignment.

        When the assignment has a zone_id, the on-link fe80::/10 route is
        bound to that zone so multi-interface consumers can install it on
        the LCI interface only.
        """
        return (
            LciRoute(prefix=LINK_LOCAL_NETWORK, via=None, zone_id=self.client.scope_id),
            LciRoute(prefix=DEFAULT_ROUTE_PREFIX, via=self.node),
        )


def _zoned_link_local(iid: bytes, zone_id: str | int | None) -> IPv6Address:
    try:
        return make_link_local(iid, zone_id=zone_id)
    except AddrError as exc:
        raise LciAddressError(str(exc)) from exc


def static_assignment(*, zone_id: str | int | None = None) -> LciAddressAssignment:
    """Return the spec 17.4 static pair: client ``fe80::2``, node ``fe80::1``."""
    return LciAddressAssignment(
        client=_zoned_link_local(STATIC_CLIENT_IID, zone_id),
        node=_zoned_link_local(STATIC_NODE_IID, zone_id),
        profile=LciAddressProfile.STATIC,
    )


def client_link_local(hwaddr: bytes, *, zone_id: str | int | None = None) -> IPv6Address:
    """Build the client link-local address from a device MAC or EUI-64.

    A 6-byte MAC-48 is expanded with ``FF FE`` (RFC 4291) before the U/L-bit
    flip. An 8-byte value is treated as a canonical EUI-64.
    """
    if type(hwaddr) is not bytes:
        raise LciAddressError("client hardware address must be immutable bytes")
    try:
        if len(hwaddr) == 6:
            iid = eui64_to_iid(mac48_to_eui64(hwaddr))
        elif len(hwaddr) == 8:
            iid = eui64_to_iid(hwaddr)
        else:
            raise LciAddressError(
                f"client hardware address must be 6-byte MAC-48 or 8-byte EUI-64, got {len(hwaddr)}"
            )
        return make_link_local(iid, zone_id=zone_id)
    except AddrError as exc:
        raise LciAddressError(str(exc)) from exc


def node_link_local(eui64: bytes, *, zone_id: str | int | None = None) -> IPv6Address:
    """Build the node link-local address from the node's EUI-64."""
    if type(eui64) is not bytes:
        raise LciAddressError("node EUI-64 must be immutable bytes")
    try:
        return make_link_local(eui64_to_iid(eui64), zone_id=zone_id)
    except AddrError as exc:
        raise LciAddressError(str(exc)) from exc


def eui64_assignment(
    client_mac: bytes,
    node_eui64: bytes,
    *,
    zone_id: str | int | None = None,
) -> LciAddressAssignment:
    """Return the spec 17.4 EUI-64 derived client/node pair."""
    return LciAddressAssignment(
        client=client_link_local(client_mac, zone_id=zone_id),
        node=node_link_local(node_eui64, zone_id=zone_id),
        profile=LciAddressProfile.EUI64,
    )
