# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from functools import total_ordering
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
MAX_ROUTES = 256
_SRH_FIELDS_LENGTH = 6  # routing_type, segments_left, CmprI/E, 3-byte pad/reserved


class RoutingError(Exception):
    """Raised on malformed routes or source-routing headers."""


@total_ordering
@dataclass(frozen=True)
class RouteTarget:
    """Canonical IPv6 route prefix.

    ``prefix`` is always canonical: unused host bits are cleared.
    A /128 target behaves identically to a host address.
    """
    prefix: IPv6Address
    prefix_len: int

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_len <= 128):
            raise RoutingError(f"prefix_len must be between 0 and 128, got {self.prefix_len}")
        whole_bytes = self.prefix_len // 8
        remaining_bits = self.prefix_len % 8
        if remaining_bits:
            mask = 0xFF << (8 - remaining_bits)
            prefix = bytearray(self.prefix.packed)
            prefix[whole_bytes] &= mask
            prefix[whole_bytes + 1:] = b'\x00' * (15 - whole_bytes)
        else:
            prefix = bytearray(self.prefix.packed)
            prefix[whole_bytes:] = b'\x00' * (16 - whole_bytes)
        object.__setattr__(self, 'prefix', IPv6Address(bytes(prefix)))

    @classmethod
    def host(cls, address: IPv6Address | str) -> RouteTarget:
        return cls(to_ipv6(address), 128)

    def contains(self, address: IPv6Address | str) -> bool:
        addr = to_ipv6(address)
        if self.prefix_len == 128:
            return addr == self.prefix
        whole_bytes = self.prefix_len // 8
        if self.prefix.packed[:whole_bytes] != addr.packed[:whole_bytes]:
            return False
        remaining_bits = self.prefix_len % 8
        if remaining_bits == 0:
            return True
        mask = 0xFF << (8 - remaining_bits)
        return (self.prefix.packed[whole_bytes] ^ addr.packed[whole_bytes]) & mask == 0

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return (self.prefix_len, self.prefix) < (other.prefix_len, other.prefix)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return (self.prefix_len, self.prefix) <= (other.prefix_len, other.prefix)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return (self.prefix_len, self.prefix) > (other.prefix_len, other.prefix)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return (self.prefix_len, self.prefix) >= (other.prefix_len, other.prefix)

    def __hash__(self) -> int:
        return hash((self.prefix_len, self.prefix))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return self.prefix_len == other.prefix_len and self.prefix == other.prefix


class RouteEntryState:
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"


@dataclass
class RouteEntry:
    path: list[IPv6Address]
    state: str = RouteEntryState.FRESH

    @classmethod
    def fresh(cls, path: Sequence[IPv6Address | str]) -> RouteEntry:
        return cls(path=[to_ipv6(a) for a in path], state=RouteEntryState.FRESH)

    def is_usable(self) -> bool:
        return self.state != RouteEntryState.EXPIRED


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
        if segments_left == 0:
            addresses = []
        return cls(segments_left=segments_left, addresses=addresses)

    def to_extension_header(self) -> ExtensionHeader:
        return ExtensionHeader(NextHeader.ROUTING, self.to_ext_data())

    @classmethod
    def from_extension_header(cls, ext: ExtensionHeader) -> SourceRoutingHeader:
        return cls.from_ext_data(ext.data)


@dataclass
class RoutingTable:
    """Root-side map of route targets to source-route paths.

    Host routes use /128 targets and store the full path ending at the target.
    Prefix routes use shorter prefix lengths and store a path to the egress node.

    ``lookup`` uses longest-prefix-match when prefix routes are present,
    otherwise falls back to exact /128 host match for performance.
    """

    _routes: dict[RouteTarget, RouteEntry] = field(default_factory=dict)
    _prefix_route_count: int = 0

    def add_route(
        self, target: IPv6Address | str, path: Sequence[IPv6Address | str]
    ) -> None:
        converted_target = to_ipv6(target)
        converted_path = [to_ipv6(a) for a in path]
        if not path:
            raise RoutingError("route path must not be empty")
        if converted_path[-1] != converted_target:
            raise RoutingError("route path must end at target")
        if not self._add_target_route(RouteTarget.host(converted_target), converted_path):
            raise RoutingError("route capacity exceeded")

    def add_prefix_route(
        self,
        target: RouteTarget,
        egress: IPv6Address | str,
        path: Sequence[IPv6Address | str],
    ) -> None:
        if target.prefix_len == 128:
            raise RoutingError("use add_route for /128 targets")
        converted_path = [to_ipv6(a) for a in path]
        converted_egress = to_ipv6(egress)
        if converted_path[-1] != converted_egress:
            raise RoutingError("prefix route path must end at egress")
        if any(hop == target.prefix for hop in converted_path):
            raise RoutingError("prefix route path must not contain target prefix address")
        if not self._add_target_route(target, converted_path):
            raise RoutingError("route capacity exceeded")

    def _add_target_route(self, target: RouteTarget, path: list[IPv6Address]) -> bool:
        if not path:
            raise RoutingError("route path must not be empty")
        if len(path) > MAX_ROUTE_HOPS:
            raise RoutingError("route path exceeds maximum hop count")
        is_new = target not in self._routes
        if is_new and len(self._routes) >= MAX_ROUTES:
            return False
        self._routes[target] = RouteEntry.fresh(path)
        if is_new and target.prefix_len < 128:
            self._prefix_route_count += 1
        return True

    def remove_route(self, target: IPv6Address | str) -> None:
        self._routes.pop(RouteTarget.host(target), None)

    def remove_prefix_route(self, target: RouteTarget) -> None:
        if target.prefix_len < 128 and target in self._routes:
            del self._routes[target]
            self._prefix_route_count -= 1

    def clear(self) -> None:
        self._routes.clear()
        self._prefix_route_count = 0

    def routes(self) -> dict[IPv6Address, list[IPv6Address]]:
        result: dict[IPv6Address, list[IPv6Address]] = {}
        for rt, entry in self._routes.items():
            result[rt.prefix] = list(entry.path)
        return result

    def replace_routes(
        self, routes: dict[IPv6Address, list[IPv6Address]]
    ) -> None:
        self.clear()
        for target, path in routes.items():
            self._add_target_route(RouteTarget.host(target), path)

    def lookup(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        addr = to_ipv6(target)
        if self._prefix_route_count == 0:
            entry = self._routes.get(RouteTarget.host(addr))
            return list(entry.path) if entry is not None and entry.is_usable() else None
        best: RouteEntry | None = None
        best_len = -1
        for rt, entry in self._routes.items():
            if rt.contains(addr) and entry.is_usable() and rt.prefix_len > best_len:
                best = entry
                best_len = rt.prefix_len
        return list(best.path) if best is not None else None

    def build_source_route(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        return self.lookup(target)

    def entry_state(self, target: IPv6Address | str) -> str | None:
        entry = self._routes.get(RouteTarget.host(target))
        return entry.state if entry is not None else None

    def __len__(self) -> int:
        return len(self._routes)

    def __contains__(self, target: IPv6Address | str) -> bool:
        return RouteTarget.host(target) in self._routes


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
