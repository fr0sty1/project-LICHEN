# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address, IPv6Network

from lichen.gradient import GradientTable
from lichen.ipv6.packet import IPv6Packet
from lichen.loadng.discovery import LoadngRouter
from lichen.rpl.dodag import DodagState

logger = logging.getLogger(__name__)

# Forwarding buffer limits (spec appendix-bufferbloat.md)
MAX_FORWARDING_SOURCES = 8
MAX_PACKETS_PER_SOURCE = 2

# GPSR null island detection threshold (~111 meters).
# GPS sensors often produce near-zero garbage, not exactly (0, 0).
NULL_ISLAND_EPSILON = 0.001
MAX_DTN_TTL_SECONDS = 604800
MAX_NEIGHBORS = 32
MAX_PENDING_DESTINATIONS = 8


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


class ForwardingResult(Enum):
    """Result of attempting to buffer a packet for forwarding.

    Why explicit enum: Callers need to distinguish between success and
    different failure modes (backpressure vs eviction).
    """

    ACCEPTED = auto()      # Packet buffered successfully
    BACKPRESSURE = auto()  # Source at per-source limit, send NACK upstream
    EVICTED = auto()       # Accepted, but evicted oldest from different source


@dataclass
class ForwardingEntry:
    """A packet buffered for forwarding on behalf of another source.

    Attributes:
        packet: The IPv6 packet data to forward.
        source_iid: 8-byte IID of the packet's originator.
        buffered_at_ms: Timestamp when buffered (for deadline expiry).
        deadline_ms: Absolute time after which packet should be dropped.
    """

    packet: IPv6Packet
    source_iid: bytes
    buffered_at_ms: int
    deadline_ms: int

    def __post_init__(self) -> None:
        if len(self.source_iid) != 8:
            raise ValueError(f"source_iid must be 8 bytes, got {len(self.source_iid)}")


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
    packet: IPv6Packet
    destination_iid: bytes
    expiry_unix: int
    buffered_at_ms: int
    _cached_size: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        if len(self.destination_iid) != 8:
            raise ValueError(f"destination_iid must be 8 bytes, got {len(self.destination_iid)}")
        self._cached_size = len(self.packet.to_bytes()) + len(self.destination_iid) + 32

    def size(self) -> int:
        return self._cached_size


@dataclass
class ForwardingBuffer:
    """Per-source forwarding buffer with backpressure (spec appendix-bufferbloat.md).

    Why per-source limits: Prevents one chatty node from monopolizing relay
    capacity. Each source gets MAX_PACKETS_PER_SOURCE slots; when full, the
    relay returns backpressure (NACK) rather than silently dropping.

    Why total source limit: Bounded memory. With MAX_FORWARDING_SOURCES sources
    and MAX_PACKETS_PER_SOURCE each, total capacity is 16 packets.

    **Thread safety (project-LICHEN-ccjp):** NOT thread-safe. All methods
    (try_buffer, expire_old, dequeue, etc.) mutate _buffer, _source_order,
    and stats counters without locks. Races possible in async/threaded use
    (e.g. concurrent expire + try_buffer). Use only from single thread
    (asyncio event loop). Add external lock or redesign if concurrent access
    needed.

    Attributes:
        max_sources: Maximum unique sources to track.
        max_per_source: Maximum packets buffered per source.
        _buffer: Dict mapping source IID to deque of ForwardingEntry.
        _source_order: OrderedDict[bytes, None] tracking LRU order (front=oldest).
        packets_accepted: Count of packets accepted.
        packets_backpressure: Count of packets rejected due to backpressure.
        packets_expired: Count of packets dropped due to deadline.
    """

    max_sources: int = MAX_FORWARDING_SOURCES
    max_per_source: int = MAX_PACKETS_PER_SOURCE
    _buffer: dict[bytes, deque[ForwardingEntry]] = field(
        default_factory=dict, repr=False
    )
    _source_order: OrderedDict[bytes, None] = field(
        default_factory=OrderedDict, repr=False
    )
    # Statistics
    packets_accepted: int = 0
    packets_backpressure: int = 0
    packets_expired: int = 0
    packets_evicted: int = 0

    def try_buffer(
        self,
        packet: IPv6Packet,
        source_iid: bytes,
        now_ms: int,
        deadline_ms: int,
    ) -> ForwardingResult:
        """Attempt to buffer a packet for forwarding.

        Args:
            packet: The IPv6 packet to forward.
            source_iid: 8-byte IID of the packet's originator.
            now_ms: Current time in milliseconds.
            deadline_ms: Absolute deadline (packet dropped if not forwarded by then).

        Returns:
            ForwardingResult indicating success or failure mode.
        """
        if len(source_iid) != 8:
            raise RoutingError(f"source_iid must be 8 bytes, got {len(source_iid)}")
        entry = ForwardingEntry(
            packet=packet,
            source_iid=source_iid,
            buffered_at_ms=now_ms,
            deadline_ms=deadline_ms,
        )

        # Check if source already has a queue
        if source_iid in self._buffer:
            queue = self._buffer[source_iid]
            if len(queue) >= self.max_per_source:
                # SECURITY: Per-source limit reached, return backpressure.
                # Caller should send NACK upstream.
                self.packets_backpressure += 1
                logger.debug(
                    "forwarding buffer full for source %s, backpressure",
                    source_iid.hex(),
                )
                return ForwardingResult.BACKPRESSURE

            queue.append(entry)
            self._touch_source(source_iid)
            self.packets_accepted += 1
            return ForwardingResult.ACCEPTED

        # New source - check if we need to evict
        result = ForwardingResult.ACCEPTED
        if len(self._buffer) >= self.max_sources:
            oldest_iid, _ = self._source_order.popitem(last=False)
            evicted_count = len(self._buffer.pop(oldest_iid, deque()))
            self.packets_evicted += evicted_count
            logger.debug(
                "forwarding buffer evicting source %s (%d packets)",
                oldest_iid.hex(),
                evicted_count,
            )
            result = ForwardingResult.EVICTED

        self._buffer[source_iid] = deque([entry])
        self._touch_source(source_iid)
        self.packets_accepted += 1
        return result

    def dequeue(self, source_iid: bytes) -> ForwardingEntry | None:
        """Remove and return the oldest packet for a source.

        Returns:
            ForwardingEntry if available, None if no packets for source.
        """
        if source_iid not in self._buffer:
            return None

        queue = self._buffer[source_iid]
        if not queue:
            return None

        entry = queue.popleft()

        # Clean up empty queues
        if not queue:
            del self._buffer[source_iid]
            self._source_order.pop(source_iid, None)

        return entry

    def peek(self, source_iid: bytes) -> ForwardingEntry | None:
        """Return the oldest packet for a source without removing it."""
        if source_iid not in self._buffer:
            return None
        queue = self._buffer[source_iid]
        return queue[0] if queue else None

    def expire_old(self, now_ms: int) -> int:
        """Remove packets past their deadline.

        Args:
            now_ms: Current time in milliseconds.

        Returns:
            Number of packets expired.
        """
        expired_count = 0
        empty_sources: list[bytes] = []

        for source_iid, queue in self._buffer.items():
            original_len = len(queue)
            # Keep only packets not past deadline
            self._buffer[source_iid] = deque(
                e for e in queue if e.deadline_ms > now_ms
            )
            expired = original_len - len(self._buffer[source_iid])
            expired_count += expired

            if not self._buffer[source_iid]:
                empty_sources.append(source_iid)

        # Clean up empty sources
        for source_iid in empty_sources:
            del self._buffer[source_iid]
            self._source_order.pop(source_iid, None)

        if expired_count > 0:
            self.packets_expired += expired_count
            logger.debug("forwarding buffer expired %d packets", expired_count)

        return expired_count

    def count_for_source(self, source_iid: bytes) -> int:
        """Return number of packets buffered for a source."""
        if source_iid not in self._buffer:
            return 0
        return len(self._buffer[source_iid])

    def total_count(self) -> int:
        """Return total number of packets in buffer."""
        return sum(len(q) for q in self._buffer.values())

    def source_count(self) -> int:
        """Return number of unique sources being tracked."""
        return len(self._buffer)

    def get_stats(self) -> dict[str, int]:
        return {
            "total_packets": self.total_count(),
            "sources": self.source_count(),
            "max_sources": self.max_sources,
            "max_per_source": self.max_per_source,
            "accepted": self.packets_accepted,
            "backpressure": self.packets_backpressure,
            "expired": self.packets_expired,
            "evicted": self.packets_evicted,
        }

    def _touch_source(self, source_iid: bytes) -> None:
        """Move source to MRU position using OrderedDict (matches GradientTable idiom)."""
        self._source_order[source_iid] = None
        self._source_order.move_to_end(source_iid)


@dataclass
class Router:
    """Hybrid routing decision engine (spec 7.2).

    Why a class: Needs state across invocations:
    - gradient_table: Where to look up routes
    - dodag: RPL state for parent selection
    - loadng: LOADng router for discovery
    - pending_queue: Packets waiting for discovery
    - mesh_prefixes: Which prefixes are "in the mesh"
    - forwarding_buffer, dtn_buffer: DTN and relay buffers

    **Thread safety (project-LICHEN-ccjp):** NOT thread-safe. Methods like
    expire_pending(), dtn_buffer_message(), dtn_retrieve_for(), and
    forwarding_buffer operations mutate shared state (pending_queue,
    dtn_buffer, _dtn_buffer_bytes, neighbor structures) without locks.
    Races can corrupt counters or lose packets in concurrent calls.
    Intended for single-threaded use (asyncio event loop). See
    ForwardingBuffer for details. External locking required for multi-thread.

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
        max_pending_destinations: Maximum unique destinations for pending discovery.
            Why: Prevents unbounded memory growth (see ForwardingBuffer.max_sources).
        max_neighbors: Maximum neighbors tracked before LRU eviction.
            Why: Prevents unbounded growth from transient neighbors.
        node_coords: This node's coordinates for GPSR.
        neighbor_coords: Link-local neighbor coordinates.
        neighbor_queue_depth: Link-local neighbor queue depths (spec 11.4).
    """

    node_address: IPv6Address
    gradient_table: GradientTable
    dodag: DodagState | None = None
    loadng: LoadngRouter | None = None
    mesh_prefixes: set[IPv6Network] = field(default_factory=set)
    pending_queue: dict[IPv6Address, deque[PendingPacket]] = field(
        default_factory=dict, repr=False
    )
    max_pending_per_dest: int = 3
    max_pending_destinations: int = MAX_PENDING_DESTINATIONS
    max_neighbors: int = MAX_NEIGHBORS
    _neighbor_order: list[IPv6Address] = field(default_factory=list, repr=False)
    _pending_order: list[IPv6Address] = field(default_factory=list, repr=False)
    node_coords: tuple[float, float] | None = None
    neighbor_coords: dict[IPv6Address, tuple[float, float]] = field(
        default_factory=dict, repr=False
    )
    neighbor_queue_depth: dict[IPv6Address, int] = field(
        default_factory=dict, repr=False
    )
    dtn_buffer: deque[DtnMessage] = field(default_factory=deque, repr=False)
    dtn_buffer_max_bytes: int = 65536
    _dtn_buffer_bytes: int = field(default=0, repr=False)
    forwarding_buffer: ForwardingBuffer = field(default_factory=ForwardingBuffer, repr=False)

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

        for prefix in list(self.mesh_prefixes):
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
            # Try GPSR if we know destination coords (spec 9.7, project-LICHEN-gom9)
            # SECURITY: Pass now_ms to reject expired entries (lookup uses
            # coord_expiry if present). Stale coords could misroute in mobile
            # meshes or enable coord-spoofing attacks after expiry.
            dst_entry = self.gradient_table.lookup(dst, now=now_ms)
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

        return RouteDecision.FORWARD, parent

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

        queue = self.pending_queue.setdefault(dst, deque(maxlen=self.max_pending_per_dest))

        # Why limit: Prevent memory exhaustion during slow discovery.
        if len(queue) >= self.max_pending_per_dest:
            # Drop oldest packet (O(1) with deque.popleft())
            queue.popleft()
            logger.debug("pending queue full for %s, dropped oldest", dst)

        queue.append(pending)
        logger.debug("queued packet for %s, queue depth=%d", dst, len(queue))
        self._touch_pending(dst)

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
        if dst in self._pending_order:
            self._pending_order.remove(dst)
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
        empty_dests: list[IPv6Address] = []

        for dst in list(self.pending_queue.keys()):
            queue = self.pending_queue[dst]
            original_len = len(queue)
            self.pending_queue[dst] = deque(
                p for p in queue if p.queued_at_ms > cutoff
            )
            queue = self.pending_queue[dst]
            expired_count += original_len - len(queue)

            if not queue:
                empty_dests.append(dst)

        for dst in empty_dests:
            if dst in self.pending_queue:
                del self.pending_queue[dst]
            if dst in self._pending_order:
                self._pending_order.remove(dst)

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

    def release_pending_for(self, dst: IPv6Address) -> list[PendingPacket]:
        """Release pending packets for a destination after route discovery.

        Call this after updating the gradient_table with a discovered route.
        The Router owns the pending queue; this method returns queued packets
        for forwarding once a route is available.

        Returns:
            List of pending packets that can now be forwarded.
        """
        pending = self.get_pending(dst)
        self.clear_pending(dst)
        logger.debug("releasing %d pending packets for %s", len(pending), dst)
        return pending

    def update_neighbor_coords(
        self, neighbor: IPv6Address, coords: tuple[float, float]
    ) -> bool:
        """Update coords for a neighbor (from their announce).

        Validates coordinates before storing. Invalid coordinates
        (NaN, inf, null island, out-of-range) are rejected.

        Returns:
            True if coords were stored, False if rejected as invalid.
        """
        lat, lon = coords
        if not _validate_coords(lat, lon):
            logger.warning("rejecting invalid coords for neighbor %s: (%s, %s)",
                          neighbor, lat, lon)
            return False
        self.neighbor_coords[neighbor] = coords
        self._touch_neighbor(neighbor)
        return True

    def update_neighbor_queue_depth(
        self, neighbor: IPv6Address, depth: int
    ) -> None:
        """Update queue depth for a neighbor (from their announce, spec 11.4)."""
        self.neighbor_queue_depth[neighbor] = depth
        self._touch_neighbor(neighbor)

    def get_neighbor_queue_depth(self, neighbor: IPv6Address) -> int:
        """Get queue depth for a neighbor (0 if unknown)."""
        return self.neighbor_queue_depth.get(neighbor, 0)

    def _touch_neighbor(self, neighbor: IPv6Address) -> None:
        """Maintain LRU order and evict oldest neighbor if over max."""
        if neighbor in self._neighbor_order:
            self._neighbor_order.remove(neighbor)
        self._neighbor_order.append(neighbor)
        if len(self._neighbor_order) > self.max_neighbors:
            oldest = self._neighbor_order.pop(0)
            self.neighbor_coords.pop(oldest, None)
            self.neighbor_queue_depth.pop(oldest, None)
            logger.debug("neighbor LRU eviction: removed %s", oldest)

    def _touch_pending(self, dst: IPv6Address) -> None:
        """Maintain LRU order and evict oldest destination if over max."""
        if dst in self._pending_order:
            self._pending_order.remove(dst)
        self._pending_order.append(dst)
        if len(self._pending_order) > self.max_pending_destinations:
            oldest = self._pending_order.pop(0)
            self.pending_queue.pop(oldest, None)
            logger.debug("pending queue evicting oldest destination %s", oldest)

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
        if len(destination_iid) != 8:
            raise RoutingError(f"destination_iid must be 8 bytes, got {len(destination_iid)}")
        now_unix = int(time.time())
        if expiry_unix <= now_unix:
            logger.debug("dtn: rejecting expired message (expiry=%d, now=%d)",
                        expiry_unix, now_unix)
            return False
        if expiry_unix > now_unix + MAX_DTN_TTL_SECONDS:
            logger.warning("dtn: rejecting message with excessive TTL")
            return False

        msg = DtnMessage(
            packet=packet,
            destination_iid=destination_iid,
            expiry_unix=expiry_unix,
            buffered_at_ms=now_ms,
        )

        # Reject messages that exceed the maximum buffer size
        if msg.size() > self.dtn_buffer_max_bytes:
            logger.debug("dtn: rejecting oversized message (size=%d, max=%d)",
                        msg.size(), self.dtn_buffer_max_bytes)
            return False

        # Evict oldest messages until we have space
        self._dtn_evict_if_needed(msg.size())
        self.dtn_buffer.append(msg)
        self._dtn_buffer_bytes += msg.size()
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
        """Retrieve and remove all messages for a destination IID.

        Uses single-pass partitioning to avoid O(2n) double iteration.
        """
        matching: list[DtnMessage] = []
        remaining: deque[DtnMessage] = deque()
        bytes_reduced: int = 0
        for msg in list(self.dtn_buffer):
            if msg.destination_iid == destination_iid:
                matching.append(msg)
                bytes_reduced += msg.size()
            else:
                remaining.append(msg)
        self.dtn_buffer = remaining
        self._dtn_buffer_bytes -= bytes_reduced
        logger.debug("dtn: retrieved %d messages for %s",
                    len(matching), destination_iid.hex())
        return matching

    def dtn_expire_old(self) -> int:
        """Remove expired messages from buffer. Returns count removed.

        Uses single-pass partitioning and updates running byte counter.
        """
        now_unix = int(time.time())
        expired = 0
        remaining: deque[DtnMessage] = deque()
        for msg in self.dtn_buffer:
            if msg.expiry_unix > now_unix:
                remaining.append(msg)
            else:
                expired += 1
                self._dtn_buffer_bytes -= msg.size()
        self.dtn_buffer = remaining
        if expired > 0:
            logger.debug("dtn: expired %d messages", expired)
        return expired

    def _dtn_buffer_size(self) -> int:
        """Current buffer size in bytes (O(1) via running counter)."""
        return self._dtn_buffer_bytes

    def _dtn_evict_if_needed(self, new_msg_size: int) -> int:
        """Evict oldest messages to make room. Returns count evicted.

        O(k) where k is evictions per insert, using running byte counter.
        """
        evicted = 0
        while self._dtn_buffer_bytes + new_msg_size > self.dtn_buffer_max_bytes:
            if not self.dtn_buffer:
                break
            oldest = self.dtn_buffer.popleft()  # oldest-first eviction (O(1))
            self._dtn_buffer_bytes -= oldest.size()
            evicted += 1
            logger.debug("dtn: evicted message for %s to make room",
                        oldest.destination_iid.hex())
        return evicted

    def gpsr_forward(
        self, dst_coords: tuple[float, float] | None
    ) -> IPv6Address | None:
        """GPSR greedy forwarding: find neighbor closest to destination (spec 9.7).

        Args:
            dst_coords: (lat, lon) of destination. Must be valid coordinates.

        Returns:
            Next-hop address, or None if no progress possible (local minimum)
            or if coords are invalid/missing.
        """
        if dst_coords is None:
            return None
        if self.node_coords is None:
            return None
        # Validate node_coords for NaN/inf (same rationale as dst_coords check below).
        my_lat, my_lon = self.node_coords
        if not _validate_coords(my_lat, my_lon):
            logger.warning("gpsr: node_coords invalid")
            return None
        if not self.neighbor_coords:
            return None
        # Validate coords are in valid ranges.
        # NaN/inf: checked first since NaN comparisons are always False,
        # making the range check unreliable for invalid floats.
        # (0,0): rejected as null island sentinel (almost always invalid GPS data).
        lat, lon = dst_coords
        if math.isnan(lat) or math.isnan(lon) or math.isinf(lat) or math.isinf(lon):
            logger.warning("gpsr: dst_coords contain NaN/inf")
            return None
        if abs(lat) < NULL_ISLAND_EPSILON and abs(lon) < NULL_ISLAND_EPSILON:
            logger.warning("gpsr: rejecting null island coords (%s, %s)", lat, lon)
            return None
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            logger.warning("gpsr: invalid dst_coords (%s, %s)", lat, lon)
            return None

        my_dist = _haversine(self.node_coords, dst_coords)
        best_neighbor: IPv6Address | None = None
        best_dist = my_dist  # must make progress

        for neighbor, coords in self.neighbor_coords.items():
            n_lat, n_lon = coords
            if not _validate_coords(n_lat, n_lon):
                logger.warning("gpsr: neighbor %s has invalid coords, skipping", neighbor)
                continue
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


def _validate_coords(lat: float, lon: float) -> bool:
    """Validate geographic coordinates.

    Rejects:
    - NaN or infinite values
    - Null island (0, 0) which is almost always invalid GPS data
    - Out-of-range values (lat must be -90..90, lon must be -180..180)

    Returns:
        True if coordinates are valid, False otherwise.
    """
    # NaN/inf: checked first since NaN comparisons are always False,
    # making the range check unreliable for invalid floats.
    if math.isnan(lat) or math.isnan(lon) or math.isinf(lat) or math.isinf(lon):
        return False
    # Near (0,0): rejected as null island sentinel (almost always invalid GPS data).
    if abs(lat) < NULL_ISLAND_EPSILON and abs(lon) < NULL_ISLAND_EPSILON:
        return False
    return -90 <= lat <= 90 and -180 <= lon <= 180


def _haversine(c1: tuple[float, float], c2: tuple[float, float]) -> float:
    """Haversine distance in meters between two (lat, lon) points."""
    lat1, lon1 = math.radians(c1[0]), math.radians(c1[1])
    lat2, lon2 = math.radians(c2[0]), math.radians(c2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    # Clamp a to [0, 1] before sqrt to handle floating-point errors
    c = 2 * math.asin(math.sqrt(max(0.0, min(1.0, a))))

    return 6_371_000 * c  # Earth radius in meters
