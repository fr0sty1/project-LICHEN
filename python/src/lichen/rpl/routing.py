# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from ipaddress import IPv6Address

from lichen.ipv6 import to_ipv6
from lichen.ipv6.packet import ExtensionHeader, IPv6Packet, NextHeader
from lichen.rpl.dodag import DodagState

"""RPL non-storing routing table and source-routed forwarding (spec section 8.5).

In non-storing mode only the root holds a routing table; it learns each node's
parent from DAOs (assembled by the DAO handler) and stores the full path to each
target. Downward packets carry an RFC 6554 Source Routing Header (SRH, a Type 3
Routing extension header); intermediate nodes forward by advancing it per
RFC 8200 section 4.4. Upward packets simply go to the preferred parent.

The SRH here is uncompressed (CmprI = CmprE = 0); on-air 6LoRH compression is a
SCHC-layer concern.
"""

ROUTING_TYPE_SOURCE_ROUTE = 3
MAX_ROUTE_HOPS = 8
_SRH_FIELDS_LENGTH = 6  # routing_type, segments_left, CmprI/E, 3-byte pad/reserved


class RoutingError(Exception):
    """Raised on malformed routes or source-routing headers."""


@dataclass
class SourceRoutingHeader:
    """An RFC 6554 Source Routing Header (uncompressed).

    ``addresses`` are the hops still to be visited; ``segments_left`` counts how
    many remain. The next hop is ``addresses[len(addresses) - segments_left]``.
    """

    segments_left: int
    addresses: list[IPv6Address] = field(default_factory=list)

    def to_ext_data(self) -> bytes:
        """The extension-header body after the next-header/length prefix."""
        if len(self.addresses) > MAX_ROUTE_HOPS:
            raise RoutingError("source route exceeds maximum hop count")
        if not 0 <= self.segments_left <= len(self.addresses):
            raise RoutingError("segments_left exceeds address count")
        fields = bytes([ROUTING_TYPE_SOURCE_ROUTE, self.segments_left, 0, 0, 0, 0])
        return fields + b"".join(a.packed for a in self.addresses)

    @classmethod
    def from_ext_data(cls, data: bytes) -> SourceRoutingHeader:
        if len(data) < _SRH_FIELDS_LENGTH:
            raise RoutingError("source routing header too short")
        if data[0] != ROUTING_TYPE_SOURCE_ROUTE:
            raise RoutingError(f"not a source routing header: type {data[0]}")
        segments_left = data[1]
        cmpr = data[2]
        if cmpr != 0:
            raise RoutingError("compressed source routing headers not supported")
        addr_bytes = data[_SRH_FIELDS_LENGTH:]
        if len(addr_bytes) % 16 != 0:
            raise RoutingError("source-route address list is not 16-byte aligned")
        addresses = [IPv6Address(addr_bytes[i : i + 16]) for i in range(0, len(addr_bytes), 16)]
        if len(addresses) > MAX_ROUTE_HOPS:
            raise RoutingError("source route exceeds maximum hop count")
        if not 0 <= segments_left <= len(addresses):
            raise RoutingError("segments_left exceeds address count")
        return cls(segments_left=segments_left, addresses=addresses)

    def to_extension_header(self) -> ExtensionHeader:
        return ExtensionHeader(NextHeader.ROUTING, self.to_ext_data())

    @classmethod
    def from_extension_header(cls, ext: ExtensionHeader) -> SourceRoutingHeader:
        return cls.from_ext_data(ext.data)


@dataclass
class RoutingTable:
    """Root-side map of target address to the source-route path reaching it.

    A path is the ordered list of hops from the root to the target, the target
    itself being the final element.
    """

    _routes: dict[IPv6Address, list[IPv6Address]] = field(default_factory=dict)

    def add_route(
        self, target: IPv6Address | str, path: Sequence[IPv6Address | str]
    ) -> None:
        if not path:
            raise RoutingError("route path must not be empty")
        if len(path) > MAX_ROUTE_HOPS:
            raise RoutingError("route path exceeds maximum hop count")
        converted_target = to_ipv6(target)
        converted_path = [to_ipv6(a) for a in path]
        if converted_path[-1] != converted_target:
            raise RoutingError("route path must end at target")
        self._routes[converted_target] = converted_path

    def remove_route(self, target: IPv6Address | str) -> None:
        self._routes.pop(to_ipv6(target), None)

    def clear(self) -> None:
        self._routes.clear()

    def routes(self) -> dict[IPv6Address, list[IPv6Address]]:
        return dict(self._routes)

    def replace_routes(
        self, routes: dict[IPv6Address, list[IPv6Address]]
    ) -> None:
        self.clear()
        for target, path in routes.items():
            self.add_route(target, path)

    def lookup(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        path = self._routes.get(to_ipv6(target))
        return list(path) if path is not None else None

    def build_source_route(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        """The hop path to ``target``, or ``None`` if no route is known."""
        return self.lookup(target)

    def __len__(self) -> int:
        return len(self._routes)

    def __contains__(self, target: IPv6Address | str) -> bool:
        return to_ipv6(target) in self._routes


def next_hop_upward(dodag: DodagState) -> IPv6Address | None:
    """Next hop toward the root: the preferred parent (``None`` if unjoined)."""
    return dodag.preferred_parent


def insert_source_route(
    packet: IPv6Packet,
    path: Sequence[IPv6Address | str],
    *,
    expected_destination: IPv6Address | str | None = None,
) -> tuple[IPv6Packet, IPv6Address]:
    """At the root: prepend an SRH for ``path`` and return (packet, first hop).

    ``path`` is ``[h1, ..., hk, destination]`` (per RFC 6554 §3: final dst in
    IPv6 header, intermediates in SRH). Single-hop needs no SRH. Validates
    path ends with destination if ``expected_destination`` provided (project-LICHEN-dzgv).

    IMPORTANT: The final element of ``path`` must be the intended destination.
    This function replaces the packet's destination address with the first hop;
    if the path does not end with the actual final destination, that destination
    is lost and the packet will stop at the last hop in the path.

    When ``expected_destination`` is provided, the function validates that
    ``path[-1]`` matches it and raises :class:`RoutingError` if not. Use this
    when the intended destination is known to catch routing table bugs early.
    The :class:`RoutingTable` class guarantees this property for paths it
    returns via :meth:`~RoutingTable.build_source_route`.
    """
    hops = [to_ipv6(a) for a in path]
    if not hops:
        raise RoutingError("path must not be empty")
    if len(hops) > MAX_ROUTE_HOPS:
        raise RoutingError("source route exceeds maximum hop count")
    if expected_destination is not None:
        expected = to_ipv6(expected_destination)
        if hops[-1] != expected:
            raise RoutingError(
                f"path does not end with expected destination: "
                f"path ends with {hops[-1]}, expected {expected}"
            )
    first_hop = hops[0]
    new_header = replace(packet.header, dst_addr=first_hop)

    if len(hops) == 1:
        new_packet = replace(packet, header=new_header)
        return new_packet, first_hop

    remaining = hops[1:]
    srh = SourceRoutingHeader(segments_left=len(remaining), addresses=remaining)
    new_packet = IPv6Packet(
        header=new_header,
        payload=packet.payload,
        extension_headers=[srh.to_extension_header(), *packet.extension_headers],
    )
    return new_packet, first_hop


def _find_routing_header(packet: IPv6Packet) -> int | None:
    for i, ext in enumerate(packet.extension_headers):
        if ext.header_type == NextHeader.ROUTING:
            return i
    return None


def advance_source_route(
    packet: IPv6Packet,
) -> tuple[IPv6Packet, IPv6Address | None]:
    """At an intermediate node: consume one SRH hop (RFC 8200 4.4).

    Returns ``(updated_packet, next_hop)``. ``next_hop`` is ``None`` when this
    node is the final destination (no SRH, or segments_left already 0).
    """
    idx = _find_routing_header(packet)
    if idx is None:
        return packet, None

    srh = SourceRoutingHeader.from_extension_header(packet.extension_headers[idx])
    if srh.segments_left == 0:
        return packet, None

    i = len(srh.addresses) - srh.segments_left
    if not 0 <= i < len(srh.addresses):
        raise RoutingError("segments_left inconsistent with address list")
    next_hop = srh.addresses[i]
    new_srh = replace(srh, segments_left=srh.segments_left - 1)

    new_exts = list(packet.extension_headers)
    new_exts[idx] = new_srh.to_extension_header()
    new_header = replace(packet.header, dst_addr=next_hop)
    new_packet = replace(packet, header=new_header, extension_headers=new_exts)
    return new_packet, next_hop
