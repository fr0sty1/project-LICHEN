# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from ipaddress import IPv6Address
from typing import Optional

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


class InvalidRouteEntryTransition(Exception):
    """Raised on invalid route entry state transitions."""


class RouteEntryState(Enum):
    Fresh = auto()
    Stale = auto()
    Expired = auto()

    def can_transition_to(self, next: RouteEntryState) -> bool:
        allowed = {
            RouteEntryState.Fresh: {RouteEntryState.Fresh, RouteEntryState.Stale, RouteEntryState.Expired},
            RouteEntryState.Stale: {RouteEntryState.Fresh, RouteEntryState.Stale, RouteEntryState.Expired},
            RouteEntryState.Expired: {RouteEntryState.Expired},
        }
        return next in allowed[self]


@dataclass
class RouteEntry:
    path: list[IPv6Address]
    state: RouteEntryState = RouteEntryState.Fresh

    @classmethod
    def fresh(cls, path: list[IPv6Address]) -> RouteEntry:
        return cls(path=path, state=RouteEntryState.Fresh)

    def is_usable(self) -> bool:
        return self.state != RouteEntryState.Expired

    def mark_stale(self) -> None:
        if not self.state.can_transition_to(RouteEntryState.Stale):
            raise InvalidRouteEntryTransition(
                f"cannot transition from {self.state.name} to Stale"
            )
        self.state = RouteEntryState.Stale

    def mark_expired(self) -> None:
        if not self.state.can_transition_to(RouteEntryState.Expired):
            raise InvalidRouteEntryTransition(
                f"cannot transition from {self.state.name} to Expired"
            )
        self.state = RouteEntryState.Expired

    def refresh(self, path: list[IPv6Address]) -> None:
        if self.state == RouteEntryState.Expired:
            raise InvalidRouteEntryTransition(
                "cannot refresh expired route entry"
            )
        self.path = path
        self.state = RouteEntryState.Fresh


@dataclass(frozen=True)
class RouteTarget:
    prefix: IPv6Address
    prefix_len: int

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_len <= 128):
            raise ValueError(f"prefix_len must be between 0 and 128, got {self.prefix_len}")

    @classmethod
    def new(cls, address: IPv6Address | str, prefix_len: int) -> RouteTarget:
        if not (0 <= prefix_len <= 128):
            raise ValueError(f"prefix_len must be between 0 and 128, got {prefix_len}")
        addr_bytes = bytearray(to_ipv6(address).packed)
        whole_bytes = prefix_len // 8
        remaining_bits = prefix_len % 8
        used_bytes = whole_bytes + (1 if remaining_bits else 0)
        if remaining_bits:
            addr_bytes[whole_bytes] &= 0xFF << (8 - remaining_bits)
        for i in range(used_bytes, 16):
            addr_bytes[i] = 0
        return cls(prefix=IPv6Address(bytes(addr_bytes)), prefix_len=prefix_len)

    @classmethod
    def host(cls, address: IPv6Address | str) -> RouteTarget:
        return cls(prefix=to_ipv6(address), prefix_len=128)

    def contains(self, address: IPv6Address | str) -> bool:
        addr = to_ipv6(address)
        whole_bytes = self.prefix_len // 8
        if self.prefix.packed[:whole_bytes] != addr.packed[:whole_bytes]:
            return False
        remaining_bits = self.prefix_len % 8
        if remaining_bits == 0:
            return True
        return (
            (self.prefix.packed[whole_bytes] ^ addr.packed[whole_bytes])
            & (0xFF << (8 - remaining_bits))
        ) == 0

    def __lt__(self, other: RouteTarget) -> bool:
        if not isinstance(other, RouteTarget):
            return NotImplemented
        return (self.prefix_len, self.prefix) < (other.prefix_len, other.prefix)


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


def _canonicalize_prefix(address: IPv6Address, prefix_len: int) -> IPv6Address:
    return RouteTarget.new(address, prefix_len).prefix


@dataclass
class RoutingTable:
    """Root-side map of target/prefix to source-route path reaching it.

    Supports both /128 host routes and shorter prefix routes with
    longest-prefix-match lookup.
    """

    _routes: dict[RouteTarget, RouteEntry] = field(default_factory=dict)
    _prefix_route_count: int = 0
    _rpl_managed_hosts: set[IPv6Address] = field(default_factory=set)
    _rpl_managed_prefixes: dict[RouteTarget, IPv6Address] = field(default_factory=dict)
    _unavailable_managed_prefixes: set[RouteTarget] = field(default_factory=set)

    def _add_target_route(self, target: RouteTarget, path: list[IPv6Address]) -> bool:
        if len(path) > MAX_ROUTE_HOPS:
            return False
        is_new = target not in self._routes
        if is_new and len(self._routes) == MAX_ROUTES:
            return False
        existing = self._routes.get(target)
        if existing is not None and existing.state != RouteEntryState.Expired:
            existing.refresh(path)
        else:
            self._routes[target] = RouteEntry.fresh(path)
        if is_new and target.prefix_len < 128:
            self._prefix_route_count += 1
        return True

    def add_route(
        self, target: IPv6Address | str, path: Sequence[IPv6Address | str]
    ) -> None:
        return self._legacy_add_route(target, path)

    def _legacy_add_route(
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
        if not self._add_target_route(RouteTarget.host(converted_target), converted_path):
            raise RoutingError("route capacity exceeded")

    def add_prefix_route(
        self,
        target: RouteTarget | IPv6Address | str,
        egress: IPv6Address | str,
        path: Sequence[IPv6Address | str],
    ) -> bool:
        if isinstance(target, RouteTarget):
            rt = target
        else:
            raise TypeError("add_prefix_route requires a RouteTarget")
        egress_addr = to_ipv6(egress)
        converted_path = [to_ipv6(a) for a in path]
        if rt.prefix_len == 128:
            return False
        if not converted_path or converted_path[-1] != egress_addr:
            return False
        if any(hop == rt.prefix for hop in converted_path):
            return False
        was_managed = self._rpl_managed_prefixes.get(rt) == egress_addr
        is_managed = was_managed or egress_addr in self._rpl_managed_hosts
        if not self._add_target_route(rt, converted_path):
            return False
        if is_managed:
            self._rpl_managed_prefixes[rt] = egress_addr
        else:
            self._rpl_managed_prefixes.pop(rt, None)
        self._unavailable_managed_prefixes.discard(rt)
        return True

    def add_host_route(
        self, target: IPv6Address | str, path: Sequence[IPv6Address | str]
    ) -> bool:
        converted_target = to_ipv6(target)
        converted_path = [to_ipv6(a) for a in path]
        if not converted_path:
            return False
        if len(converted_path) > MAX_ROUTE_HOPS:
            return False
        if converted_path[-1] != converted_target:
            return False
        return self._add_target_route(RouteTarget.host(converted_target), converted_path)

    def remove_route(self, target: IPv6Address | str) -> None:
        self._routes.pop(RouteTarget.host(to_ipv6(target)), None)

    def remove_prefix_route(self, target: RouteTarget) -> None:
        if target.prefix_len < 128 and target in self._routes:
            del self._routes[target]
            self._prefix_route_count -= 1
            self._rpl_managed_prefixes.pop(target, None)
            self._unavailable_managed_prefixes.discard(target)

    def clear(self) -> None:
        self._routes.clear()
        self._prefix_route_count = 0
        self._rpl_managed_prefixes.clear()
        self._rpl_managed_hosts.clear()
        self._unavailable_managed_prefixes.clear()

    def routes(self) -> dict[IPv6Address, list[IPv6Address]]:
        result: dict[IPv6Address, list[IPv6Address]] = {}
        for rt, entry in self._routes.items():
            if rt.prefix_len == 128 and entry.is_usable():
                result[rt.prefix] = entry.path
        return result

    def replace_routes(
        self, routes: dict[IPv6Address, list[IPv6Address]]
    ) -> None:
        self.clear()
        for target, path in routes.items():
            self._legacy_add_route(target, path)

    def lookup(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        addr = to_ipv6(target)
        if self._prefix_route_count == 0:
            entry = self._routes.get(RouteTarget.host(addr))
            if entry is not None and entry.is_usable():
                return list(entry.path)
            return None
        best: tuple[int, RouteEntry] | None = None
        for rt, entry in self._routes.items():
            if not entry.is_usable():
                continue
            if rt.contains(addr):
                if best is None or rt.prefix_len > best[0]:
                    best = (rt.prefix_len, entry)
        return list(best[1].path) if best is not None else None

    def build_source_route(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        """The hop path to ``target``, or ``None`` if no route is known."""
        return self.lookup(target)

    def __len__(self) -> int:
        return len(self._routes)

    def __contains__(self, target: IPv6Address | str) -> bool:
        return RouteTarget.host(to_ipv6(target)) in self._routes

    def mark_stale(self, target: IPv6Address | str) -> None:
        entry = self._routes.get(RouteTarget.host(to_ipv6(target)))
        if entry is not None:
            entry.mark_stale()

    def mark_expired(self, target: IPv6Address | str) -> None:
        entry = self._routes.get(RouteTarget.host(to_ipv6(target)))
        if entry is not None:
            entry.mark_expired()

    def mark_prefix_expired(self, target: RouteTarget) -> None:
        if target.prefix_len >= 128:
            return
        entry = self._routes.get(target)
        if entry is not None:
            entry.mark_expired()

    def entry_state(self, target: IPv6Address | str) -> Optional[RouteEntryState]:
        entry = self._routes.get(RouteTarget.host(to_ipv6(target)))
        return entry.state if entry is not None else None

    def entry_state_for_prefix(self, target: RouteTarget) -> Optional[RouteEntryState]:
        entry = self._routes.get(target)
        return entry.state if entry is not None else None


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
