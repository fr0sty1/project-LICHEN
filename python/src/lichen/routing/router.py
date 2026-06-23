"""Hybrid routing decision logic (spec section 7.2).

The Router decides how to forward each packet based on destination address:
1. Link-local (fe80::/10): Direct neighbor delivery
2. Mesh-local (ULA or mesh GUA): Gradient lookup → LOADng discovery
3. External: Forward to RPL parent toward border router

Why separate Router from LOADng/RPL: Each protocol has its own state machine.
The Router orchestrates them based on address classification and route availability.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address, IPv6Network

from lichen.gradient import GradientTable
from lichen.ipv6.packet import IPv6Packet
from lichen.loadng.discovery import LoadngRouter
from lichen.rpl.dodag import DodagState

logger = logging.getLogger(__name__)


class RoutingError(Exception):
    """Raised on routing failures that shouldn't happen."""


class AddressClass(Enum):
    """Classification of IPv6 destination address (spec 7.2).

    Why classify: Different address types require different routing strategies.
    Link-local goes directly to neighbor. Mesh-local uses gradient/LOADng.
    External routes through the border router via RPL.
    """

    LINK_LOCAL = auto()  # fe80::/10 - direct neighbor
    MESH_LOCAL = auto()  # ULA or mesh GUA - peer in mesh
    EXTERNAL = auto()    # Other GUA or unknown - route via border router


class RouteDecision(Enum):
    """What to do with a packet after routing decision.

    Why explicit enum: Callers need to know what action to take, and the
    decision may require additional state (queued packet, discovery request).
    """

    FORWARD = auto()      # Forward to next_hop now
    QUEUE = auto()        # Queue pending LOADng discovery
    DROP = auto()         # No route, cannot discover (unjoined, etc.)
    DELIVER_LOCAL = auto()  # Packet is for this node


@dataclass
class PendingPacket:
    """A packet queued pending route discovery.

    Why track: When LOADng discovery completes, we need to forward the
    original packet. Also for timeouts and queue management.

    Attributes:
        packet: The queued IPv6 packet.
        destination: The address we're discovering a route to.
        queued_at_ms: Timestamp when queued (for timeout).
    """

    packet: IPv6Packet
    destination: IPv6Address
    queued_at_ms: int


@dataclass
class DtnMessage:
    """A message buffered for DTN store-and-forward (spec 9.8).

    Attributes:
        packet: The IPv6 packet data.
        destination_iid: 8-byte IID of destination.
        expiry_unix: Unix timestamp when message expires.
        buffered_at_ms: When message was buffered (for eviction ordering).
    """

    packet: IPv6Packet
    destination_iid: bytes
    expiry_unix: int
    buffered_at_ms: int

    def size(self) -> int:
        """Approximate size in bytes for buffer accounting."""
        return len(self.packet.payload) + 100  # header overhead estimate


@dataclass
class Router:
    """Hybrid routing decision engine (spec 7.2).

    Why a class: Needs state across invocations:
    - gradient_table: Where to look up routes
    - dodag: RPL state for parent selection
    - loadng: LOADng router for discovery
    - pending_queue: Packets waiting for discovery
    - mesh_prefixes: Which prefixes are "in the mesh"

    Attributes:
        node_address: This node's IPv6 address.
        gradient_table: Unified routing table (spec section 11).
        dodag: RPL DODAG state for upward routing.
        loadng: LOADng router for reactive discovery.
        mesh_prefixes: Set of IPv6 prefixes that are "mesh-local".
            Why a set: Nodes may be part of multiple prefixes (ULA + GUA).
        pending_queue: Packets waiting for route discovery.
            Why dict by destination: Multiple packets may be queued for same dest.
        max_pending_per_dest: Max packets to queue per destination.
            Why limit: Prevent memory exhaustion during discovery.
    """

    node_address: IPv6Address
    gradient_table: GradientTable
    dodag: DodagState | None = None
    loadng: LoadngRouter | None = None
    mesh_prefixes: set[IPv6Network] = field(default_factory=set)
    pending_queue: dict[IPv6Address, list[PendingPacket]] = field(
        default_factory=dict, repr=False
    )
    max_pending_per_dest: int = 3
    node_coords: tuple[float, float] | None = None  # (lat, lon) for GPSR (spec 9.7)
    neighbor_coords: dict[IPv6Address, tuple[float, float]] = field(
        default_factory=dict, repr=False
    )  # link-local -> coords
    neighbor_queue_depth: dict[IPv6Address, int] = field(
        default_factory=dict, repr=False
    )  # link-local -> queue depth (spec 11.4)
    # DTN store-and-forward buffer (spec 9.8)
    dtn_buffer: list[DtnMessage] = field(default_factory=list, repr=False)
    dtn_buffer_max_bytes: int = 65536  # 64KB default

    # Why fe80::/10: RFC 4291 link-local prefix. All link-local addresses
    # start with fe80:: through febf::, which is fe80::/10.
    _LINK_LOCAL_PREFIX = IPv6Network("fe80::/10")

    # Why fd00::/8: RFC 4193 ULA prefix. LICHEN meshes typically use ULA.
    _ULA_PREFIX = IPv6Network("fd00::/8")

    def classify_address(self, addr: IPv6Address) -> AddressClass:
        """Classify an IPv6 destination address (spec 7.2 table).

        Why this order:
        1. Link-local check first: Most specific, cheap to check
        2. Mesh-local next: ULA or configured GUA prefixes
        3. External fallback: Everything else

        Args:
            addr: Destination IPv6 address.

        Returns:
            AddressClass indicating how to route.
        """
        # Why check link-local first: It's the most specific and common case
        # for neighbor discovery, etc.
        if addr in self._LINK_LOCAL_PREFIX:
            return AddressClass.LINK_LOCAL

        # Why check ULA: LICHEN meshes typically use fd00::/8 ULA prefixes
        # for mesh-internal addressing.
        if addr in self._ULA_PREFIX:
            return AddressClass.MESH_LOCAL

        # Why check mesh_prefixes: GUA prefixes from DIO/border router
        # should be routed as mesh-local.
        for prefix in self.mesh_prefixes:
            if addr in prefix:
                return AddressClass.MESH_LOCAL

        # Why external: Everything else goes to the border router.
        return AddressClass.EXTERNAL

    def route(
        self,
        packet: IPv6Packet,
        now_ms: int,
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Make a routing decision for a packet (spec 7.2 pseudocode).

        Why return tuple: Callers need both the decision (what to do) and
        the next hop (where to send it).

        Args:
            packet: IPv6 packet to route.
            now_ms: Current time in milliseconds.

        Returns:
            (decision, next_hop) tuple. next_hop is None for QUEUE/DROP/DELIVER_LOCAL.
        """
        dst = packet.header.dst_addr

        # Why check for local first: Don't route packets addressed to us.
        if dst == self.node_address:
            return RouteDecision.DELIVER_LOCAL, None

        addr_class = self.classify_address(dst)
        logger.debug("routing %s: class=%s", dst, addr_class.name)

        if addr_class == AddressClass.LINK_LOCAL:
            return self._route_link_local(dst)

        if addr_class == AddressClass.MESH_LOCAL:
            return self._route_mesh_local(packet, dst, now_ms)

        # External: route via RPL parent
        return self._route_external()

    def _route_link_local(
        self, dst: IPv6Address
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to a link-local address (direct neighbor).

        Why no lookup: Link-local addresses are by definition one hop away.
        The destination IS the next hop.
        """
        return RouteDecision.FORWARD, dst

    def _route_mesh_local(
        self,
        packet: IPv6Packet,
        dst: IPv6Address,
        now_ms: int,
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to a mesh-local address (ULA or mesh GUA).

        Strategy (spec 7.2):
        1. Check gradient table for existing route
        2. If found and not expired, forward
        3. If not found, initiate LOADng discovery and queue packet
        """
        # Why lookup with now: Expired entries should not be used.
        entry = self.gradient_table.lookup(dst, now=now_ms)

        if entry is not None:
            logger.debug("gradient found for %s: via %s, %d hops",
                        dst, entry.next_hop, entry.hop_count)
            return RouteDecision.FORWARD, entry.next_hop

        # Why check loadng: If LOADng isn't configured, try GPSR fallback.
        if self.loadng is None:
            # Try GPSR if we know destination coords (spec 9.7)
            dst_entry = self.gradient_table.lookup(dst)  # may be expired but has coords
            if dst_entry is not None and dst_entry.coords is not None:
                next_hop = self.gpsr_forward(dst_entry.coords)
                if next_hop is not None:
                    return RouteDecision.FORWARD, next_hop
            logger.warning("no gradient for %s, LOADng not configured, GPSR failed", dst)
            return RouteDecision.DROP, None

        # Initiate discovery and queue packet
        logger.debug("no gradient for %s, initiating LOADng discovery", dst)
        self._queue_pending(packet, dst, now_ms)

        return RouteDecision.QUEUE, None

    def _route_external(self) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to an external address (via RPL border router).

        Why RPL parent: External traffic goes "up" the DODAG tree to the
        border router, which has connectivity to the wider network.
        """
        if self.dodag is None:
            logger.warning("no DODAG state, cannot route external")
            return RouteDecision.DROP, None

        if not self.dodag.is_joined():
            logger.warning("not joined to DODAG, cannot route external")
            return RouteDecision.DROP, None

        parent = self.dodag.preferred_parent
        if parent is None:
            logger.warning("no preferred parent, cannot route external")
            return RouteDecision.DROP, None

        # Why parse as IPv6Address: preferred_parent is stored as string
        # in DodagState for flexibility, but we need an address here.
        try:
            next_hop = IPv6Address(parent)
        except ValueError:
            logger.error("invalid preferred_parent address: %s", parent)
            return RouteDecision.DROP, None

        return RouteDecision.FORWARD, next_hop

    def _queue_pending(
        self,
        packet: IPv6Packet,
        dst: IPv6Address,
        now_ms: int,
    ) -> None:
        """Queue a packet pending route discovery.

        Why queue: During LOADng discovery, packets should be held rather
        than dropped. When discovery succeeds, queued packets are forwarded.
        """
        pending = PendingPacket(
            packet=packet,
            destination=dst,
            queued_at_ms=now_ms,
        )

        queue = self.pending_queue.setdefault(dst, [])

        # Why limit: Prevent memory exhaustion during slow discovery.
        if len(queue) >= self.max_pending_per_dest:
            # Drop oldest packet
            queue.pop(0)
            logger.debug("pending queue full for %s, dropped oldest", dst)

        queue.append(pending)
        logger.debug("queued packet for %s, queue depth=%d", dst, len(queue))

    def get_pending(self, dst: IPv6Address) -> list[PendingPacket]:
        """Get all pending packets for a destination.

        Why separate method: Called when discovery succeeds to retrieve
        packets that can now be forwarded.

        Returns:
            List of pending packets (may be empty).
        """
        return list(self.pending_queue.get(dst, []))

    def clear_pending(self, dst: IPv6Address) -> int:
        """Clear pending packets for a destination.

        Why: Called after forwarding or after timeout to clean up.

        Returns:
            Number of packets cleared.
        """
        queue = self.pending_queue.pop(dst, [])
        return len(queue)

    def expire_pending(self, now_ms: int, timeout_ms: int) -> int:
        """Remove pending packets older than timeout.

        Why: Packets shouldn't be queued forever. If discovery fails or
        takes too long, drop the packets.

        Returns:
            Number of packets expired.
        """
        expired_count = 0
        cutoff = now_ms - timeout_ms

        # Why iterate copy: We're modifying the dict during iteration.
        for dst in list(self.pending_queue.keys()):
            queue = self.pending_queue[dst]
            original_len = len(queue)
            queue[:] = [p for p in queue if p.queued_at_ms > cutoff]
            expired_count += original_len - len(queue)

            if not queue:
                del self.pending_queue[dst]

        if expired_count > 0:
            logger.debug("expired %d pending packets", expired_count)

        return expired_count

    def add_mesh_prefix(self, prefix: IPv6Network | str) -> None:
        """Add a prefix to the set of mesh-local prefixes.

        Why: Prefixes learned from DIO or configuration should be added
        so addresses within them are classified as mesh-local.
        """
        if isinstance(prefix, str):
            prefix = IPv6Network(prefix)
        self.mesh_prefixes.add(prefix)

    def remove_mesh_prefix(self, prefix: IPv6Network | str) -> None:
        """Remove a prefix from mesh-local prefixes."""
        if isinstance(prefix, str):
            prefix = IPv6Network(prefix)
        self.mesh_prefixes.discard(prefix)

    def on_route_discovered(
        self, dst: IPv6Address, next_hop: IPv6Address, now_ms: int
    ) -> list[PendingPacket]:
        """Called when LOADng discovers a route.

        Why a callback: The Router owns the pending queue. When discovery
        succeeds, it needs to return the queued packets for forwarding.

        Returns:
            List of pending packets that can now be forwarded.
        """
        pending = self.get_pending(dst)
        self.clear_pending(dst)
        logger.debug("route discovered for %s, releasing %d pending packets",
                    dst, len(pending))
        return pending

    def update_neighbor_coords(
        self, neighbor: IPv6Address, coords: tuple[float, float]
    ) -> None:
        """Update coords for a neighbor (from their announce)."""
        self.neighbor_coords[neighbor] = coords

    def update_neighbor_queue_depth(
        self, neighbor: IPv6Address, depth: int
    ) -> None:
        """Update queue depth for a neighbor (from their announce, spec 11.4)."""
        self.neighbor_queue_depth[neighbor] = depth

    def get_neighbor_queue_depth(self, neighbor: IPv6Address) -> int:
        """Get queue depth for a neighbor (0 if unknown)."""
        return self.neighbor_queue_depth.get(neighbor, 0)

    # --- DTN store-and-forward (spec 9.8) ---

    def dtn_buffer_message(
        self,
        packet: IPv6Packet,
        destination_iid: bytes,
        expiry_unix: int,
        now_ms: int,
    ) -> bool:
        """Buffer a message for DTN store-and-forward.

        Returns True if buffered, False if rejected (e.g., already expired).
        """
        import time
        now_unix = int(time.time())
        if expiry_unix <= now_unix:
            logger.debug("dtn: rejecting expired message (expiry=%d, now=%d)",
                        expiry_unix, now_unix)
            return False

        msg = DtnMessage(
            packet=packet,
            destination_iid=destination_iid,
            expiry_unix=expiry_unix,
            buffered_at_ms=now_ms,
        )

        # Evict oldest messages until we have space
        self._dtn_evict_if_needed(msg.size())
        self.dtn_buffer.append(msg)
        logger.debug("dtn: buffered message for %s, expiry=%d, buffer_size=%d",
                    destination_iid.hex(), expiry_unix, len(self.dtn_buffer))
        return True

    def dtn_get_pending_iids(self) -> list[bytes]:
        """Get list of destination IIDs with buffered messages."""
        seen: set[bytes] = set()
        result: list[bytes] = []
        for msg in self.dtn_buffer:
            if msg.destination_iid not in seen:
                seen.add(msg.destination_iid)
                result.append(msg.destination_iid)
        return result

    def dtn_retrieve_for(self, destination_iid: bytes) -> list[DtnMessage]:
        """Retrieve and remove all messages for a destination IID."""
        matching = [m for m in self.dtn_buffer if m.destination_iid == destination_iid]
        self.dtn_buffer = [m for m in self.dtn_buffer if m.destination_iid != destination_iid]
        logger.debug("dtn: retrieved %d messages for %s",
                    len(matching), destination_iid.hex())
        return matching

    def dtn_expire_old(self) -> int:
        """Remove expired messages from buffer. Returns count removed."""
        import time
        now_unix = int(time.time())
        original_len = len(self.dtn_buffer)
        self.dtn_buffer = [m for m in self.dtn_buffer if m.expiry_unix > now_unix]
        expired = original_len - len(self.dtn_buffer)
        if expired > 0:
            logger.debug("dtn: expired %d messages", expired)
        return expired

    def _dtn_buffer_size(self) -> int:
        """Current buffer size in bytes."""
        return sum(m.size() for m in self.dtn_buffer)

    def _dtn_evict_if_needed(self, new_msg_size: int) -> int:
        """Evict oldest messages to make room. Returns count evicted."""
        evicted = 0
        while self._dtn_buffer_size() + new_msg_size > self.dtn_buffer_max_bytes:
            if not self.dtn_buffer:
                break
            oldest = self.dtn_buffer.pop(0)  # oldest-first eviction
            evicted += 1
            logger.debug("dtn: evicted message for %s to make room",
                        oldest.destination_iid.hex())
        return evicted

    def gpsr_forward(
        self, dst_coords: tuple[float, float]
    ) -> IPv6Address | None:
        """GPSR greedy forwarding: find neighbor closest to destination (spec 9.7).

        Returns next-hop address, or None if no progress possible (local minimum).
        """
        if self.node_coords is None:
            return None
        if not self.neighbor_coords:
            return None

        my_dist = _haversine(self.node_coords, dst_coords)
        best_neighbor: IPv6Address | None = None
        best_dist = my_dist  # must make progress

        for neighbor, coords in self.neighbor_coords.items():
            d = _haversine(coords, dst_coords)
            if d < best_dist:
                best_dist = d
                best_neighbor = neighbor

        if best_neighbor is not None:
            logger.debug("gpsr: forwarding to %s (%.1fm closer)",
                        best_neighbor, my_dist - best_dist)
        else:
            logger.debug("gpsr: local minimum, no progress possible")

        return best_neighbor


def _haversine(c1: tuple[float, float], c2: tuple[float, float]) -> float:
    """Haversine distance in meters between two (lat, lon) points."""
    lat1, lon1 = math.radians(c1[0]), math.radians(c1[1])
    lat2, lon2 = math.radians(c2[0]), math.radians(c2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    return 6_371_000 * c  # Earth radius in meters
