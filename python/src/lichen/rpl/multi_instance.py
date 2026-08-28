# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL Multi-Instance Coordination for Gateway Cooperation (GCP-5, RFC 6550 Section 5).

This module provides the Python oracle implementation for multi-gateway DODAG
coordination as specified in spec/08-gateway-coordination.md GCP-5:

- All cooperating gateways use the same RPLInstanceID
- Each gateway acts as DODAG root for that instance
- Nodes see a unified DODAG with multiple possible parents
- DAO messages propagate across backbone as needed for route aggregation

The coordination model uses a federated approach where each gateway maintains
its own DODAG root but shares routing information with peer gateways over the
backbone network. This enables:

1. Load balancing across gateways
2. Fault tolerance when a gateway fails
3. Optimal path selection for nodes
4. Seamless handoff between gateways

Cross-implementation contract: this module is kept semantically identical to
``rust/lichen-rpl/src/multi_instance.rs`` over the surface implemented HERE:
federation limits, ``MultiRootCoordinator`` membership/version/role APIs,
``DaoBackboneBridge`` accept/reject decisions and rejection reasons, and the
module-level helpers. These are validated against
``test/vectors/rpl_multi_instance.json`` with identical outcomes (repo rule:
all implementations MUST produce identical output).

Known gaps (present in the Rust file, deliberately NOT mirrored here): the
spec 02a.5 multi-root conflict surface -- ``MAX_CANDIDATES``-capped candidate
storage, ``RootCandidate`` ordering/``select_root``, the ``MultiRootState``
holdoff FSM, ``HOLDOFF_SUPERFRAMES``, and ``VersionChangeOutcome``. A partial
Python mirror of that surface lives in ``lichen.link.slot_coordination``
(link layer, not RPL) and is covered by its own tests; it is out of scope for
this module's parity claim until ported here with shared vectors.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from typing import Any, TypedDict, cast

from lichen.ipv6 import AddrError, routing_key
from lichen.rpl.dao_types import RplTarget, TransitInformation
from lichen.rpl.dodag import ROOT_RANK, DodagState
from lichen.rpl.messages import DAO, DIO, RplOptionType

# ─── Federation limits (mirror rust/lichen-rpl/src/multi_instance.rs) ───────

#: Default RPLInstanceID for LICHEN deployments.
DEFAULT_RPL_INSTANCE_ID = 0

#: Initial DODAG version (lollipop counter starts at 128).
INITIAL_DODAG_VERSION = 128

#: Maximum number of peer gateways (memory-exhaustion DoS guard).
#:
#: Design note (peer-cap refresh starvation): entries at this cap remain
#: refreshable forever -- there is deliberately no TTL/LRU eviction, matching
#: the Rust twin. Trade-off: 64 compromised-but-authenticated gateways can
#: permanently starve new legitimate peers. Idle-timeout eviction was
#: considered and DEFERRED pending cross-implementation coordination: any
#: eviction policy changes accept/reject outcomes and must land here, in
#: rust/lichen-rpl/src/multi_instance.rs, and in
#: test/vectors/rpl_multi_instance.json simultaneously. Do not change these
#: semantics unilaterally.
MAX_PEERS = 64

#: Maximum pending propagation messages queued for the backbone (DoS guard).
MAX_PENDING_PROPAGATIONS = 128

#: Maximum peers with stored received routes (DoS guard).
#: Subject to the same refresh-starvation trade-off as MAX_PEERS (see above).
MAX_RECEIVED_ROUTE_PEERS = 64

#: Maximum route targets or transits in a single DAO backbone message (DoS guard).
MAX_ROUTES_PER_MESSAGE = 256

#: Maximum age of a DAO backbone message timestamp before it is stale (replay guard).
DAO_TIMESTAMP_FRESHNESS_SECONDS = 300.0


class GatewayRole(Enum):
    """Role of a gateway in the federation."""

    PRIMARY = "primary"  # Elected time master (lowest IID)
    SECONDARY = "secondary"  # Non-primary gateway
    STANDALONE = "standalone"  # Not part of a federation


@dataclass(frozen=True)
class GatewayInfo:
    """Information about a cooperating gateway.

    Per GCP-4.1, gateway info includes IID, capabilities, slot map,
    superframe time, and supported federation modes. ``routes_learned``
    feeds federation-wide route totals (mirrors Rust ``GatewayInfo``).
    """

    iid: IPv6Address
    capabilities: dict[str, bool | int]
    slot_map: dict[str, list[int] | int | str]
    superframe_duration_s: int
    federation_modes: tuple[str, ...]
    routes_learned: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "iid", routing_key(self.iid))


class DaoBackboneMessage(TypedDict):
    """DAO message propagated over backbone between gateways.

    Per GCP-5, DAO messages propagate across backbone as needed for
    route aggregation. This carries the essential routing information.
    This is the canonical wire-dict shape shared with the test vectors
    (targets use ``target``/``prefix_length``; transit entries use
    ``path_sequence``/``path_lifetime``/``path_control``/``parent``,
    with ``""`` standing in for "no parent").
    """

    origin_gateway: str  # IID of originating gateway
    rpl_instance_id: int
    dao_sequence: int
    targets: list[dict[str, str | int]]  # RplTarget as dicts
    transit: list[dict[str, str | int]]  # TransitInformation as dicts
    timestamp: float


@dataclass
class MultiRootCoordinator:
    """Coordinates multiple DODAG roots in the same RPL instance.

    Per GCP-5, all cooperating gateways use the same RPLInstanceID and each
    acts as a DODAG root. This coordinator manages:

    1. Shared RPLInstanceID across all gateways
    2. DODAG version synchronization
    3. Gateway discovery and membership
    4. Time master election (lowest IID per GCP-6.1)
    """

    rpl_instance_id: int = DEFAULT_RPL_INSTANCE_ID
    local_gateway: GatewayInfo | None = None
    clock: Callable[[], float] = time.monotonic
    _peers: dict[IPv6Address, GatewayInfo] = field(default_factory=dict)
    _dodag_version: int = INITIAL_DODAG_VERSION
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not 0 <= self.rpl_instance_id <= 255:
            raise ValueError(f"RPLInstanceID must be 0-255, got {self.rpl_instance_id}")

    def add_peer(self, gateway: GatewayInfo) -> bool:
        """Add a discovered peer gateway to the federation.

        Per GCP-4.1, gateways discover each other via backbone multicast
        or LoRa fallback. This method registers a discovered peer.

        Enforces MAX_PEERS (memory-exhaustion DoS guard, mirroring Rust):
        returns True if the peer was added (or an existing peer updated),
        False if the limit was reached.
        """
        with self._lock:
            if len(self._peers) >= MAX_PEERS and gateway.iid not in self._peers:
                return False
            self._peers[gateway.iid] = gateway
            return True

    def remove_peer(self, iid: IPv6Address | str) -> bool:
        """Remove a peer gateway from the federation.

        Returns True if the peer was removed, False if not found.
        """
        iid = routing_key(iid)
        with self._lock:
            if iid in self._peers:
                del self._peers[iid]
                return True
            return False

    def get_peers(self) -> list[GatewayInfo]:
        """Return list of all known peer gateways."""
        with self._lock:
            return list(self._peers.values())

    def get_peer(self, iid: IPv6Address | str) -> GatewayInfo | None:
        """Get a specific peer gateway by IID."""
        iid = routing_key(iid)
        with self._lock:
            return self._peers.get(iid)

    def peer_count(self) -> int:
        """Return the number of known peer gateways."""
        with self._lock:
            return len(self._peers)

    def elect_time_master(self) -> GatewayInfo | None:
        """Elect time master by lowest IID (per GCP-6.1).

        Per GCP-6.1: Non-GPS gateways elect time master; lowest IID wins.
        GPS-equipped gateways use GPS epoch directly.

        Returns the elected time master, or None if no gateways known.
        """
        with self._lock:
            candidates = list(self._peers.values())
            if self.local_gateway is not None:
                candidates.append(self.local_gateway)
            if not candidates:
                return None

            # Lowest IID wins - compare by packed bytes for determinism
            return min(candidates, key=lambda g: g.iid.packed)

    def get_role(self) -> GatewayRole:
        """Determine this gateway's role in the federation.

        Holds the lock across the membership check and election so a
        concurrent peer update cannot produce an inconsistent role
        (TOCTOU guard, mirroring Rust ``get_role``).
        """
        with self._lock:
            if self.local_gateway is None:
                return GatewayRole.STANDALONE
            if not self._peers:
                return GatewayRole.STANDALONE

            candidates = list(self._peers.values()) + [self.local_gateway]
            master = min(candidates, key=lambda g: g.iid.packed)
            if master.iid == self.local_gateway.iid:
                return GatewayRole.PRIMARY
            return GatewayRole.SECONDARY

    def get_dodag_version(self) -> int:
        """Return current DODAG version (lollipop counter).

        Reads ``_dodag_version`` under the lock so a concurrent
        ``increment_dodag_version``/``set_dodag_version`` cannot be observed
        mid-write (torn-version guard, mirroring the Rust mutex).
        """
        with self._lock:
            return self._dodag_version

    def increment_dodag_version(self) -> int:
        """Increment DODAG version (lollipop semantics per RFC 6550 Section 7.2).

        The counter wraps from 255 to 0, entering the linear region.
        """
        with self._lock:
            self._dodag_version = (self._dodag_version + 1) % 256
            return self._dodag_version

    def set_dodag_version(self, new_version: int) -> None:
        """Set DODAG version explicitly (federation synchronization)."""
        if not 0 <= new_version <= 255:
            raise ValueError(f"DODAG version must be 0-255, got {new_version}")
        with self._lock:
            self._dodag_version = new_version

    def create_dodag_state(
        self,
        dodag_id: IPv6Address | str,
        node_address: IPv6Address | str | None = None,
    ) -> DodagState:
        """Create a DODAG state for a root gateway.

        Per GCP-5, each gateway acts as DODAG root for the shared instance.
        This creates the root state with the shared RPLInstanceID. The
        version snapshot is taken under the lock so a concurrent increment
        cannot tear the value stamped into the new DODAG state (zu44).
        """
        with self._lock:
            version = self._dodag_version
        return DodagState.as_root(
            rpl_instance_id=self.rpl_instance_id,
            dodag_id=dodag_id,
            version=version,
            node_address=node_address,
        )

    def total_aggregated_routes(self) -> int:
        """Total routes learned across all gateways in the federation.

        Mirrors Rust ``MultiRootCoordinator::total_aggregated_routes``:
        sums ``routes_learned`` over peers plus the local gateway.
        """
        with self._lock:
            total = sum(g.routes_learned for g in self._peers.values())
            if self.local_gateway is not None:
                total += self.local_gateway.routes_learned
            return total

    def validate_dio(self, dio: DIO) -> tuple[bool, str]:
        """Validate a DIO from a peer gateway.

        Per GCP-5, all cooperating gateways use the same RPLInstanceID.
        This validates that an incoming DIO conforms to federation rules:
        same instance ID (MUST), and peer gateways advertise root rank
        (each gateway acts as DODAG root for the shared instance).

        Returns (is_valid, reason); reasons match the Rust wording.
        """
        # MUST: Same RPLInstanceID
        if dio.rpl_instance_id != self.rpl_instance_id:
            msg = (
                f"RPLInstanceID mismatch: expected {self.rpl_instance_id}, "
                f"got {dio.rpl_instance_id}"
            )
            return (False, msg)

        # Root DIOs have rank = ROOT_RANK (256)
        if dio.rank != ROOT_RANK:
            return (False, f"Peer gateway DIO must have root rank {ROOT_RANK}, got {dio.rank}")

        return (True, "valid")


def _is_u8(value: object) -> bool:
    """True for a wire-decoded u8: an int in 0..=255 (bool excluded).

    Mirrors the Rust field types of ``DaoBackboneMessage`` (``u8``), where
    any other value fails decoding before ``receive_from_peer`` is reached.
    """
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255


def _is_number(value: object) -> bool:
    """True for a wire-decoded number: int or float (bool excluded).

    NaN/infinite floats are accepted here -- they are representable in the
    Rust ``f64`` timestamp field and are rejected later by the freshness
    guard (=> "stale_timestamp"), exactly as in Rust.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass
class DaoBackboneBridge:
    """Bridge for propagating DAO messages between gateways over backbone.

    Per GCP-5, DAO messages propagate across backbone as needed for route
    aggregation. This bridge handles:

    1. Converting local DAOs to backbone messages
    2. Receiving DAOs from peer gateways
    3. Merging routing information from multiple sources
    4. Maintaining consistency across the federation

    The backbone uses CoAP for transport (per GCP-6.4), with OSCORE protection
    in either PSK or Ed25519 mode (per GCP-3). Per GCP-9, received messages
    are authenticated (origin must match the OSCORE-authenticated sender) and
    replay-protected (timestamp freshness window).

    Validation outcomes mirror Rust ``DaoBackboneBridge::receive_from_peer``:

    ============================  ==========================================
    Outcome                       Rust counterpart
    ============================  ==========================================
    (True, "stored")              Ok(true)
    (False, "peer_limit_reached") Ok(false)
    (False, "instance_mismatch")  Err(InstanceIdMismatch)
    (False, "self_origin")        Err(SelfOrigin)
    (False, "stale_timestamp")    Err(StaleTimestamp)
    (False, "origin_auth_mismatch") Err(OriginAuthMismatch)
    (False, "too_many_routes")    Err(TooManyRoutes)
    (False, "malformed")          n/a -- Rust typed structs make malformed
                                  envelopes undecodable/unrepresentable
    ============================  ==========================================
    """

    coordinator: MultiRootCoordinator
    local_gateway_iid: IPv6Address | None = None
    clock: Callable[[], float] = time.monotonic
    _pending_propagation: list[DaoBackboneMessage] = field(default_factory=list)
    _received_routes: dict[IPv6Address, list[tuple[RplTarget, TransitInformation]]] = field(
        default_factory=dict
    )
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.local_gateway_iid is not None:
            self.local_gateway_iid = routing_key(self.local_gateway_iid)

    def dao_to_backbone_message(self, dao: DAO, targets: list[RplTarget]) -> DaoBackboneMessage:
        """Convert a DAO and its targets to a backbone propagation message.

        This serializes the essential routing information for transmission
        to peer gateways over the backbone network. Transit Information
        options are decoded with the vetted RFC 6550 6.7.8 codec.
        """
        if self.local_gateway_iid is None:
            raise ValueError("local_gateway_iid must be set to create backbone messages")

        transit_list: list[dict[str, str | int]] = []
        for opt in dao.options:
            if opt.type == RplOptionType.TRANSIT_INFORMATION:
                t = TransitInformation.from_option(opt)
                transit_list.append(
                    {
                        "path_control": t.path_control,
                        "path_sequence": t.path_sequence,
                        "path_lifetime": t.path_lifetime,
                        "parent": str(t.parent_address) if t.parent_address else "",
                    }
                )

        target_list: list[dict[str, str | int]] = [
            {"target": str(t.target), "prefix_length": t.prefix_length} for t in targets
        ]

        return DaoBackboneMessage(
            origin_gateway=str(self.local_gateway_iid),
            rpl_instance_id=dao.rpl_instance_id,
            dao_sequence=dao.dao_sequence,
            targets=target_list,
            transit=transit_list,
            timestamp=self.clock(),
        )

    def queue_for_propagation(self, message: DaoBackboneMessage) -> bool:
        """Queue a DAO backbone message for propagation to peers.

        Enforces MAX_PENDING_PROPAGATIONS (DoS guard, mirroring Rust):
        returns True if queued, False if the queue is full.
        """
        with self._lock:
            if len(self._pending_propagation) >= MAX_PENDING_PROPAGATIONS:
                return False
            self._pending_propagation.append(message)
            return True

    def get_pending_propagations(self) -> list[DaoBackboneMessage]:
        """Get and clear pending propagation messages."""
        with self._lock:
            messages = self._pending_propagation
            self._pending_propagation = []
            return messages

    def receive_from_peer(
        self,
        message: DaoBackboneMessage,
        authenticated_sender: IPv6Address | str,
        current_time: float,
    ) -> tuple[bool, str]:
        """Process a DAO backbone message received from a peer gateway.

        Per GCP-9, coordination messages are authenticated (OSCORE) and
        replay-protected (timestamps). Validation order and decisions
        mirror Rust ``DaoBackboneBridge::receive_from_peer``:

        0. Envelope shape/types (Python-only; see "malformed" below)
        1. RPL instance ID matches our federation (GCP-5 MUST)
        2. Origin gateway is not ourselves (self-loop prevention)
        3. Timestamp freshness in [0, DAO_TIMESTAMP_FRESHNESS_SECONDS];
           NaN ages are rejected (NaN comparisons bypass range guards)
        4. Claimed origin matches the OSCORE-authenticated sender
        5. At most MAX_ROUTES_PER_MESSAGE targets/transits per message
        6. At most MAX_RECEIVED_ROUTE_PEERS distinct origins stored

        Returns (accepted, reason); see the class docstring for the
        mapping onto the Rust Result<bool, MultiInstanceError> outcomes.

        Malformed envelopes (wrong types, missing keys, unparseable
        addresses, out-of-u8-range integers) yield (False, "malformed");
        the Rust type system makes those states unrepresentable, so no Rust
        reason exists to mirror. No exception escapes for any dict-shaped
        input.
        """
        # ── Envelope validation (fail-closed) ─────────────────────────────
        # Rust decodes backbone messages into typed structs ([u8; 16]
        # addresses, u8 counters, Vec targets/transits, f64 timestamp), so a
        # malformed message cannot reach its receive_from_peer. This oracle
        # accepts raw dicts and MUST validate that envelope up front instead
        # of raising TypeError/KeyError/ValueError mid-guard.
        malformed: tuple[bool, str] = (False, "malformed")
        if not isinstance(message, dict):
            return malformed

        origin_str = message.get("origin_gateway")
        instance_id = message.get("rpl_instance_id")
        dao_sequence = message.get("dao_sequence")
        target_list = message.get("targets")
        transit_list = message.get("transit")
        timestamp = message.get("timestamp")

        if (
            not isinstance(origin_str, str)
            or not _is_u8(instance_id)
            or not _is_u8(dao_sequence)
            or not _is_number(timestamp)
            or not isinstance(target_list, list)
            or not isinstance(transit_list, list)
        ):
            return malformed

        address_strings: list[str] = []
        for entry in target_list:
            if not isinstance(entry, dict):
                return malformed
            target = entry.get("target")
            prefix_length = entry.get("prefix_length")
            if not isinstance(target, str) or not _is_u8(prefix_length):
                return malformed
            address_strings.append(target)
        for entry in transit_list:
            if not isinstance(entry, dict):
                return malformed
            if not (
                _is_u8(entry.get("path_sequence"))
                and _is_u8(entry.get("path_lifetime"))
                and _is_u8(entry.get("path_control"))
            ):
                return malformed
            # "parent" mirrors Rust Option<[u8; 16]>: absent or "" means none.
            parent = entry.get("parent", "")
            if not isinstance(parent, str):
                return malformed
            if parent:
                address_strings.append(parent)

        try:
            for addr in address_strings:
                routing_key(addr)
            origin = routing_key(origin_str)
        except AddrError:
            return malformed
        sender = routing_key(authenticated_sender)

        # GCP-5 MUST: all cooperating gateways use the same RPLInstanceID
        if instance_id != self.coordinator.rpl_instance_id:
            return (False, "instance_mismatch")

        # A peer cannot claim our own IID as origin (self-loop prevention)
        if self.local_gateway_iid is not None and origin == self.local_gateway_iid:
            return (False, "self_origin")

        # Replay protection: reject stale, future, and NaN timestamps
        age = current_time - timestamp
        if math.isnan(age) or not 0.0 <= age <= DAO_TIMESTAMP_FRESHNESS_SECONDS:
            return (False, "stale_timestamp")

        # OSCORE-authenticated identity must match the claimed origin
        if origin != sender:
            return (False, "origin_auth_mismatch")

        # Route-count limit per message (memory-exhaustion prevention)
        if len(target_list) > MAX_ROUTES_PER_MESSAGE or len(transit_list) > MAX_ROUTES_PER_MESSAGE:
            return (False, "too_many_routes")

        # Pair each target with its transit by index; extra targets fall
        # back to a default transit per RFC 6550 (mirrors Rust pairing).
        # All coercions below are safe: the envelope was validated above.
        default_transit = {
            "path_sequence": dao_sequence,
            "path_lifetime": 60,
            "path_control": 0,
            "parent": "",
        }
        routes: list[tuple[RplTarget, TransitInformation]] = []
        for i, target_dict in enumerate(target_list):
            t = transit_list[i] if i < len(transit_list) else default_transit
            parent = str(t.get("parent", ""))
            transit = TransitInformation(
                path_sequence=cast(int, t["path_sequence"]),
                path_lifetime=cast(int, t["path_lifetime"]),
                path_control=cast(int, t["path_control"]),
                parent_address=routing_key(parent) if parent else None,
            )
            routes.append(
                (
                    RplTarget(
                        target=routing_key(str(target_dict["target"])),
                        prefix_length=int(target_dict["prefix_length"]),
                    ),
                    transit,
                )
            )

        with self._lock:
            if (
                len(self._received_routes) >= MAX_RECEIVED_ROUTE_PEERS
                and origin not in self._received_routes
            ):
                return (False, "peer_limit_reached")
            self._received_routes[origin] = routes

        return (True, "stored")

    def get_aggregated_routes(
        self,
    ) -> dict[IPv6Address, list[tuple[RplTarget, TransitInformation]]]:
        """Get all routes aggregated from peer gateways.

        Returns a dict mapping peer gateway IID to the routes learned from it.
        This enables the local gateway to build complete routing tables that
        include routes reachable via peer gateways.
        """
        with self._lock:
            return {origin: list(routes) for origin, routes in self._received_routes.items()}

    def total_received_routes(self) -> int:
        """Total number of routes received from all peers."""
        with self._lock:
            return sum(len(routes) for routes in self._received_routes.values())


def iid_compare(a: IPv6Address | str, b: IPv6Address | str) -> int:
    """Compare two gateway IIDs for conflict resolution.

    Per GCP-6.3, conflicts are resolved by lowest IID.
    Addresses are compared lexicographically over their packed 16-byte
    representation (identical to Rust ``iid_compare``); for fe80::/64
    link-locals this reduces to IID ordering.
    Returns: -1 if a < b, 0 if a == b, 1 if a > b.
    """
    a = routing_key(a)
    b = routing_key(b)
    if a.packed < b.packed:
        return -1
    elif a.packed > b.packed:
        return 1
    return 0


def resolve_slot_conflict(
    claimant_a: IPv6Address | str, claimant_b: IPv6Address | str
) -> IPv6Address:
    """Resolve slot conflict between two gateways.

    Per GCP-6.3: If two gateways claim overlapping slot: lowest IID MUST win.
    Returns the winning gateway's IID.
    """
    a = routing_key(claimant_a)
    b = routing_key(claimant_b)
    if a.packed <= b.packed:
        return a
    return b


def validate_rpl_instance_id(instance_id: int) -> tuple[bool, str]:
    """Validate that an RPLInstanceID is usable for the federation.

    Per GCP-5: All cooperating gateways MUST use the same RPLInstanceID;
    per RFC 6550 the ID is an 8-bit unsigned integer (0-255). Mirrors the
    Rust ``validate_rpl_instance_id`` range check. Returns (is_valid, reason).
    """
    if not 0 <= instance_id <= 255:
        return (False, f"Invalid RPLInstanceID: {instance_id} (must be 0-255)")
    return (True, f"All gateways configured for RPLInstanceID {instance_id}")


def generate_multi_instance_vectors() -> list[dict[str, Any]]:
    """Assemble the canonical RPL Multi-Instance Coordination test vectors.

    These vectors test the oracle implementation per the test/vectors/README.md
    format guidelines. Every expected value is a literal derived by hand from
    spec rules (spec/08-gateway-coordination.md GCP-5/GCP-6/GCP-9, RFC 6550);
    nothing here is computed by running the implementation under test.
    """
    vectors: list[dict[str, Any]] = []

    # Vector 1: Basic multi-root coordination.
    # fe80::1234:... < fe80::abcd:... byte-wise (0x12 < 0xab at octet 9),
    # so the lowest IID is elected time master (GCP-6.1).
    vectors.append(
        {
            "name": "multi_root_basic",
            "type": "coordination",
            "description": "Two gateways in same RPL instance, lowest IID elected as time master",
            "rpl_instance_id": 0,
            "gateways": [
                {"iid": "fe80::1234:5678:9abc:def0", "has_gps": False},
                {"iid": "fe80::abcd:ef01:2345:6789", "has_gps": False},
            ],
            "expected_time_master": "fe80::1234:5678:9abc:def0",
            "election_rule": "lowest_iid",
        }
    )

    # Vector 2: Slot conflict resolution. Lowest IID MUST win (GCP-6.3);
    # loser selects next available slot and re-claims.
    vectors.append(
        {
            "name": "slot_conflict_iid_resolution",
            "type": "conflict_resolution",
            "description": "Slot conflict resolved by lowest IID per GCP-6.3",
            "conflict_slot": 7,
            "claimant_a": "fe80::1234:5678:9abc:def0",
            "claimant_b": "fe80::abcd:ef01:2345:6789",
            "expected_winner": "fe80::1234:5678:9abc:def0",
            "loser_action": "select_next_available",
        }
    )

    # Vector 3: DAO backbone propagation shape (GCP-5).
    vectors.append(
        {
            "name": "dao_backbone_propagation",
            "type": "dao_propagation",
            "description": "DAO propagated from gateway A to gateway B over backbone",
            "origin_gateway": "fe80::1234:5678:9abc:def0",
            "rpl_instance_id": 0,
            "dao_sequence": 42,
            "targets": [
                {"target": "0200:1234:5678:9abc::", "prefix_length": 64},
            ],
            "transit": [
                {
                    "path_sequence": 42,
                    "path_lifetime": 60,
                    "path_control": 0,
                    "parent": "fe80::1111:2222:3333:4444",
                }
            ],
        }
    )

    # Vectors 4-5: DIO validation. Same instance accepted; different
    # instance rejected (GCP-5 MUST: all gateways share one RPLInstanceID).
    vectors.append(
        {
            "name": "dio_validation_same_instance",
            "type": "dio_validation",
            "description": "Peer gateway DIO with matching RPLInstanceID accepted",
            "rpl_instance_id": 0,
            "dio_instance_id": 0,
            "dio_rank": 256,
            "expected_valid": True,
        }
    )
    vectors.append(
        {
            "name": "dio_validation_different_instance",
            "type": "dio_validation",
            "description": "Peer gateway DIO with different RPLInstanceID rejected per GCP-5",
            "rpl_instance_id": 0,
            "dio_instance_id": 1,
            "dio_rank": 256,
            "expected_valid": False,
            "rejection_reason": "RPLInstanceID mismatch",
        }
    )

    # Vector 6: Lollipop counter wrap (RFC 6550 Section 7.2): 254 ->
    # 255 -> 0 (wrap past maximum into linear region) -> 1.
    vectors.append(
        {
            "name": "dodag_version_lollipop",
            "type": "version_management",
            "description": "DODAG version increments using lollipop semantics",
            "initial_version": 254,
            "increments": 3,
            "expected_versions": [255, 0, 1],  # Wraps at 256
        }
    )

    # Vector 7: Three-gateway federation. fe80::aaaa:... is lowest;
    # 5 + 3 + 7 = 15 routes learned federation-wide.
    vectors.append(
        {
            "name": "three_gateway_federation",
            "type": "coordination",
            "description": "Three gateways sharing RPL instance, route aggregation",
            "rpl_instance_id": 0,
            "gateways": [
                {"iid": "fe80::aaaa:1111:2222:3333", "routes_learned": 5},
                {"iid": "fe80::bbbb:4444:5555:6666", "routes_learned": 3},
                {"iid": "fe80::cccc:7777:8888:9999", "routes_learned": 7},
            ],
            "expected_time_master": "fe80::aaaa:1111:2222:3333",
            "total_aggregated_routes": 15,
        }
    )

    # Vector 8: Unified DODAG view (GCP-5): both roots advertise the same
    # instance at root rank, so a node may select either as parent.
    vectors.append(
        {
            "name": "unified_dodag_view",
            "type": "node_perspective",
            "description": "Node receives DIOs from multiple roots, sees unified DODAG",
            "rpl_instance_id": 0,
            "root_a": {"iid": "fe80::1234:5678:9abc:def0", "rank": 256, "version": 1},
            "root_b": {"iid": "fe80::abcd:ef01:2345:6789", "rank": 256, "version": 1},
            "node_can_select_either_parent": True,
            "parent_selection": "objective_function",
        }
    )

    # Vector 9: Version synchronization: after one increment both
    # federation members hold 128 + 1 = 129.
    vectors.append(
        {
            "name": "dodag_version_synchronization",
            "type": "version_management",
            "description": "All gateways in federation synchronize DODAG version on increment",
            "rpl_instance_id": 0,
            "initial_version": 128,
            "gateways": [
                {"iid": "fe80::1234:5678:9abc:def0", "role": "primary"},
                {"iid": "fe80::abcd:ef01:2345:6789", "role": "secondary"},
            ],
            "after_increment": {
                "primary_version": 129,
                "secondary_version": 129,
                "versions_match": True,
            },
        }
    )

    # Vector 10: Role determination. No local gateway or no peers means
    # standalone; otherwise primary iff local IID is the lowest.
    vectors.append(
        {
            "name": "gateway_role_determination",
            "type": "role_assignment",
            "description": "Gateway roles determined by IID comparison and federation membership",
            "test_cases": [
                {
                    "scenario": "standalone",
                    "local_gateway": "fe80::1234:5678:9abc:def0",
                    "peers": [],
                    "expected_role": "standalone",
                },
                {
                    "scenario": "primary_lowest_iid",
                    "local_gateway": "fe80::0001:0002:0003:0004",
                    "peers": ["fe80::ffff:ffff:ffff:ffff"],
                    "expected_role": "primary",
                },
                {
                    "scenario": "secondary_higher_iid",
                    "local_gateway": "fe80::ffff:ffff:ffff:ffff",
                    "peers": ["fe80::0001:0002:0003:0004"],
                    "expected_role": "secondary",
                },
            ],
        }
    )

    # Vector 11: RPLInstanceID range validation (RFC 6550: 8-bit field).
    vectors.append(
        {
            "name": "rpl_instance_id_validation",
            "type": "validation",
            "description": "RPLInstanceID must be 0-255 per RFC 6550",
            "valid_ids": [0, 1, 127, 128, 255],
            "invalid_ids": [-1, 256, 1000],
            "default_id": 0,
        }
    )

    # Vector 12: Multiple targets aggregate into one backbone message.
    vectors.append(
        {
            "name": "dao_target_aggregation",
            "type": "dao_propagation",
            "description": "Multiple targets from single DAO aggregated in backbone message",
            "origin_gateway": "fe80::1234:5678:9abc:def0",
            "rpl_instance_id": 0,
            "dao_sequence": 100,
            "targets": [
                {"target": "0200:aaaa::", "prefix_length": 64},
                {"target": "0200:bbbb::", "prefix_length": 64},
                {"target": "0200:cccc::", "prefix_length": 64},
            ],
            "target_count": 3,
        }
    )

    # Vector 13: IID comparison boundaries. Ordering is lexicographic over
    # packed bytes, so the first octet decides across scopes:
    # ::1 (loopback, 0x00) < fe80:: (link-local, 0xfe) < ff02:: (multicast, 0xff).
    # Within a scope later octets decide (0x1234... < 0xabcd...).
    vectors.append(
        {
            "name": "iid_comparison_bytes",
            "type": "comparison",
            "description": "IID comparison uses packed byte representation for ordering",
            "comparisons": [
                {
                    "a": "fe80::0001:0002:0003:0004",
                    "b": "fe80::ffff:ffff:ffff:ffff",
                    "result": -1,
                    "winner": "fe80::0001:0002:0003:0004",
                },
                {
                    "a": "fe80::1234:5678:9abc:def0",
                    "b": "fe80::abcd:ef01:2345:6789",
                    "result": -1,
                    "winner": "fe80::1234:5678:9abc:def0",
                },
                {
                    "a": "::1",
                    "b": "fe80::0001:0002:0003:0004",
                    "result": -1,
                    "winner": "::1",
                },
                {
                    "a": "fe80::ffff:ffff:ffff:ffff",
                    "b": "ff02::1",
                    "result": -1,
                    "winner": "fe80::ffff:ffff:ffff:ffff",
                },
                {
                    "a": "ff02::1",
                    "b": "ff02::2",
                    "result": -1,
                    "winner": "ff02::1",
                },
                {
                    "a": "fe80::1234:5678:9abc:def0",
                    "b": "fe80::1234:5678:9abc:def0",
                    "result": 0,
                    "winner": "either",
                },
            ],
        }
    )

    # Vectors 14-20: DaoBackboneBridge.receive_from_peer guard outcomes
    # (GCP-9). Each vector pins one reject path of the Rust guard taxonomy
    # (multi_instance.rs:672-755) to a hand-derived (accepted, reason)
    # tuple; none are computed from the implementation under test.
    #
    # Scenario conventions shared by all guard vectors:
    # - receiving gateway (local IID): fe80::abcd:ef01:2345:6789
    # - coordinator RPLInstanceID: 0; freshness window: 300 s
    # - current_time: 1000.0
    # - timestamp value "NaN" (string) denotes IEEE-754 NaN: JSON cannot
    #   carry a NaN literal, so consumers MUST decode the string to f64 NaN
    #   before evaluation (same convention as ccp_beacon_sig_gate.json).
    _guard_receiver = "fe80::abcd:ef01:2345:6789"
    _guard_origin = "fe80::1234:5678:9abc:def0"

    def _guard_message(timestamp: float | str) -> dict[str, Any]:
        return {
            "origin_gateway": _guard_origin,
            "rpl_instance_id": 0,
            "dao_sequence": 42,
            "targets": [{"target": "0200:5678::", "prefix_length": 64}],
            "transit": [
                {
                    "path_sequence": 42,
                    "path_lifetime": 60,
                    "path_control": 0,
                    "parent": "fe80::1111:2222:3333:4444",
                }
            ],
            "timestamp": timestamp,
        }

    # Vector 14: stale timestamp. age = 1000.0 - 600.0 = 400.0 > 300.0
    # window => replay rejected. (age == 300.0 exactly would be accepted.)
    vectors.append(
        {
            "name": "receive_guard_stale_timestamp",
            "type": "receive_from_peer_guard",
            "description": (
                "Timestamp aged 400s exceeds the 300s freshness window "
                "(GCP-9 replay guard); rejected as stale_timestamp"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": _guard_origin,
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": _guard_message(600.0),
            "expected_accepted": False,
            "expected_reason": "stale_timestamp",
        }
    )

    # Vector 15: future timestamp. age = 1000.0 - 1300.0 = -300.0 < 0 =>
    # outside [0, 300] => rejected as stale_timestamp (clock-skew/replay).
    vectors.append(
        {
            "name": "receive_guard_future_timestamp",
            "type": "receive_from_peer_guard",
            "description": (
                "Timestamp 300s in the future yields negative age outside "
                "[0, 300]; rejected as stale_timestamp"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": _guard_origin,
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": _guard_message(1300.0),
            "expected_accepted": False,
            "expected_reason": "stale_timestamp",
        }
    )

    # Vector 16: NaN timestamp. age = 1000.0 - NaN = NaN; every comparison
    # against NaN is false, so the range guard alone would pass it -- the
    # explicit isnan(age) check rejects it as stale_timestamp (Rust:
    # multi_instance.rs:696-704).
    vectors.append(
        {
            "name": "receive_guard_nan_timestamp",
            "type": "receive_from_peer_guard",
            "description": (
                "NaN timestamp makes age NaN, bypassing range comparisons; "
                "explicit NaN check rejects as stale_timestamp. Field "
                'timestamp "NaN" is the string sentinel for IEEE-754 NaN.'
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": _guard_origin,
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": _guard_message("NaN"),
            "expected_accepted": False,
            "expected_reason": "stale_timestamp",
        }
    )

    # Vector 17: self-origin loop. Claimed origin equals the receiving
    # gateway's own IID => self_origin (checked after instance match).
    vectors.append(
        {
            "name": "receive_guard_self_origin",
            "type": "receive_from_peer_guard",
            "description": (
                "Claimed origin equals the receiver's own IID "
                "(self-loop prevention, GCP-9); rejected as self_origin"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": _guard_receiver,
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": {
                "origin_gateway": _guard_receiver,
                "rpl_instance_id": 0,
                "dao_sequence": 42,
                "targets": [{"target": "0200:5678::", "prefix_length": 64}],
                "transit": [
                    {
                        "path_sequence": 42,
                        "path_lifetime": 60,
                        "path_control": 0,
                        "parent": "fe80::1111:2222:3333:4444",
                    }
                ],
                "timestamp": 990.0,
            },
            "expected_accepted": False,
            "expected_reason": "self_origin",
        }
    )

    # Vector 18: spoofed origin. Origin authenticates as neither itself nor
    # the receiver => origin does not match OSCORE-authenticated sender.
    # Guard order check: instance matches, origin != local, timestamp fresh,
    # so origin_auth_mismatch is the first firing guard.
    vectors.append(
        {
            "name": "receive_guard_origin_auth_mismatch",
            "type": "receive_from_peer_guard",
            "description": (
                "Claimed origin fe80::1234:... does not match the "
                "OSCORE-authenticated sender fe80::5555:... ; rejected as "
                "origin_auth_mismatch"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": "fe80::5555:6666:7777:8888",
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": _guard_message(990.0),
            "expected_accepted": False,
            "expected_reason": "origin_auth_mismatch",
        }
    )

    # Vector 19: route flood. 257 targets > MAX_ROUTES_PER_MESSAGE (256)
    # => too_many_routes (memory-exhaustion DoS guard). Entries generated
    # deterministically so regeneration stays byte-stable.
    vectors.append(
        {
            "name": "receive_guard_too_many_routes",
            "type": "receive_from_peer_guard",
            "description": (
                "257 route targets exceed MAX_ROUTES_PER_MESSAGE (256); rejected as too_many_routes"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": _guard_origin,
            "current_time": 1000.0,
            "prior_stored_origins": [],
            "message": {
                "origin_gateway": _guard_origin,
                "rpl_instance_id": 0,
                "dao_sequence": 42,
                "targets": [
                    {"target": f"0200::{i:x}", "prefix_length": 64}
                    for i in range(MAX_ROUTES_PER_MESSAGE + 1)
                ],
                "transit": [],
                "timestamp": 990.0,
            },
            "expected_accepted": False,
            "expected_reason": "too_many_routes",
        }
    )

    # Vector 20: peer-cap saturation. 64 distinct origins already hold
    # stored routes (= MAX_RECEIVED_ROUTE_PEERS); message 65 arrives from a
    # NEW origin => peer_limit_reached (Rust returns Ok(false)). Replay
    # procedure: store one minimal valid message per prior origin (empty
    # targets/transit, timestamp now-10, sender == origin, expecting
    # (True, "stored") each), then evaluate the main message.
    vectors.append(
        {
            "name": "receive_guard_peer_limit_reached",
            "type": "receive_from_peer_guard",
            "description": (
                "64 origins already stored (MAX_RECEIVED_ROUTE_PEERS); a "
                "65th distinct origin is refused as peer_limit_reached"
            ),
            "receiver_local_iid": _guard_receiver,
            "authenticated_sender": "fe80::900:ffff",
            "current_time": 1000.0,
            "prior_stored_origins": [f"fe80::900:{i:04x}" for i in range(MAX_RECEIVED_ROUTE_PEERS)],
            "message": {
                "origin_gateway": "fe80::900:ffff",
                "rpl_instance_id": 0,
                "dao_sequence": 7,
                "targets": [{"target": "0200:ffff::", "prefix_length": 64}],
                "transit": [],
                "timestamp": 990.0,
            },
            "expected_accepted": False,
            "expected_reason": "peer_limit_reached",
        }
    )

    return vectors
