# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN Node class - main integration point for protocol stack.

The Node class integrates all protocol layers:
- Radio: Physical layer (simulated or hardware)
- LinkLayer: Frame format, signing, replay protection
- Router: Hybrid routing (RPL + Announce + LOADng)
- AnnounceProcessor: Gradient building from announces

Why a single Node class: Provides clean lifecycle management (start/stop)
and coordinates the async receive loop, routing decisions, and packet flow.

Packet flow (RX):
    radio.receive() -> link.receive() -> router.route() -> deliver/forward

Packet flow (TX):
    node.send() -> router.route() -> link.send() -> radio.transmit()
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address, IPv6Network
from types import MappingProxyType
from typing import Literal, Protocol

from lichen._sync_callbacks import reject_awaitable_result, require_sync_callable
from lichen.announce.messages import AnnounceMessage
from lichen.announce.persistence import AnnounceStatePersistence
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import (
    MAX_SCHEDULER_DELAY_MS,
    AnnounceScheduler,
    SchedulerConfig,
)
from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.gradient import GRADIENT_TIMEOUT_MS, MAX_ENTRIES, GradientTable
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.packet import IPv6Packet, NextHeader
from lichen.l2_payload import (
    L2_ROUTING_TYPE_ANNOUNCE,
    L2PayloadKind,
    classify_l2_payload,
    l2_payload_body,
    wrap_routing_payload,
    wrap_schc_payload,
)
from lichen.link.frame import AddrMode
from lichen.link.link_layer import (
    MAX_SINGLE_FRAME_SCHC_PACKET,
    LinkLayer,
    LinkPersistenceError,
    LinkSecurityClockError,
    PersistenceRevisionAnchor,
    ReceiveError,
    RxFrame,
)
from lichen.link.tx_queue import Priority
from lichen.radio.base import Radio
from lichen.routing.router import RouteDecision, Router
from lichen.rpl.dodag import DodagState
from lichen.rpl.messages import RPL_ICMPV6_TYPE, RplCode
from lichen.schc.codec import SchcError
from lichen.schc.context import RuleVersionFailureTracker, RuleVersionFailureTrackerFull
from lichen.schc.fragment import (
    RULE_IDS,
    Ack,
    FragmentError,
    FragmentSender,
    ack_request,
    receiver_abort,
    sender_abort,
)
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.state_machine import StateMachine

logger = logging.getLogger(__name__)


def _is_fragment_control(data: bytes) -> bool:
    if len(data) < 2 or data[0] not in RULE_IDS:
        return False
    window = data[1] >> 7
    if data in (
        ack_request(data[0], window),
        sender_abort(data[0]),
        receiver_abort(data[0]),
    ):
        return True
    try:
        Ack.from_bytes(data)
    except FragmentError:
        return False
    return True


_NATIVE_MESH_PREFIX = IPv6Network("0200::/8")


def _relay_identity(packet: IPv6Packet) -> bytes:
    """Return a stable, collision-free identity for one forwarded datagram.

    Peer-specific SCHC encodings and the IPv6 Hop Limit can change at every
    relay. The remaining canonical IPv6 bytes are immutable in Node's
    forwarding path, so retaining them in full avoids hash-collision aliases.
    """
    canonical = bytearray(packet.to_bytes())
    canonical[7] = 0  # Hop Limit is the mutable IPv6 forwarding field.
    return bytes(canonical)


def _canonical_peer(peer: object) -> PeerIdentity:
    """Validate and detach one peer's key-derived identity."""
    if type(peer) is not PeerIdentity:
        raise TypeError("peer must be an exact PeerIdentity")
    if type(peer.pubkey) is not bytes or len(peer.pubkey) != 32:
        raise ValueError("peer must expose an exact 32-byte public key")
    canonical = PeerIdentity.from_pubkey(bytes(peer.pubkey))
    if type(peer.iid) is not bytes or peer.iid != canonical.iid:
        raise ValueError("peer IID does not match its public key")
    return canonical


class MeshtasticAdapterProtocol(Protocol):
    """Lifecycle surface Node needs from an optional Meshtastic adapter."""

    async def start(self) -> None:
        """Start adapter-owned async resources."""

    async def stop(self) -> None:
        """Stop adapter-owned async resources."""


class NodeState(Enum):
    """Lifecycle state of a Node."""

    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()


NODE_STATE_TRANSITIONS: dict[NodeState, frozenset[NodeState]] = {
    NodeState.STOPPED: frozenset({NodeState.STARTING}),
    NodeState.STARTING: frozenset({NodeState.RUNNING, NodeState.STOPPING}),
    NodeState.RUNNING: frozenset({NodeState.STOPPING}),
    NodeState.STOPPING: frozenset({NodeState.STOPPED}),
}

# Maximum relay-seen cache entries before LRU eviction
RELAY_SEEN_MAX_SIZE = 128
RELAY_SEEN_WINDOW_MS = 60_000
PEER_DB_MAX_SIZE = MAX_ENTRIES
RECEIVE_TIMEOUT_MAX_MS = 1_000
SCHC_RETRANSMISSION_TIMEOUT_SECONDS = 10.0


class PeerIdentityCollisionError(ValueError):
    """A peer IID is already bound to a different public key."""


class PeerDatabaseFullError(RuntimeError):
    """No peer database entry can be safely evicted."""


class PeerInUseError(RuntimeError):
    """A peer cannot be forgotten while dependent protocol state is live."""


def _validated_receive_timeout_ms(value: object) -> int:
    """Return one exact receive timeout that preserves expiry progress."""
    if type(value) is not int or not 1 <= value <= RECEIVE_TIMEOUT_MAX_MS:
        raise ValueError(f"receive_timeout_ms must be an integer in 1..{RECEIVE_TIMEOUT_MAX_MS}")
    return value


def _validated_timing_ms(name: str, value: object, *, minimum: int) -> int:
    """Return an exact bounded millisecond configuration value."""
    if type(value) is not int or not minimum <= value <= MAX_SCHEDULER_DELAY_MS:
        raise ValueError(f"{name} must be an integer in {minimum}..{MAX_SCHEDULER_DELAY_MS}")
    return value


@dataclass
class NodeConfig:
    """Configuration for a LICHEN node.

    Why a separate config: Makes construction clear and allows validation.

    Attributes:
        receive_timeout_ms: Timeout for each receive call.
            Why 1000: Balance between responsiveness and CPU usage.
        announce_interval_ms: How often to send announces.
            Why 300000: Spec section 9.4 (5 minutes).
        announce_jitter_ms: Random jitter for announces.
            Why 30000: Spec section 9.4 (0-30 seconds).
        pending_timeout_ms: How long to queue packets waiting for discovery.
            Why 5000: LOADng RREQ_WAIT_TIME is 5 seconds.
        rreq_jitter_min_ms: Minimum jitter before sending RREQ.
            Why 0: Allow immediate transmission when no contention.
        rreq_jitter_max_ms: Maximum jitter before sending RREQ.
            Why 100: LOADng spec recommends short jitter to reduce collisions.
        local_short_addr: Optional assigned 16-bit link address. The value must
            be non-reserved and have completed DAD before Node construction.
            A DAD collision requires constructing a new Node with the newly
            assigned address; mutating this configuration does not retarget a
            running link-layer security context.
        rpl_instance_id: Global RPL instance expected in authenticated DIOs.
        rpl_dodag_id: Exact DODAG identifier expected in authenticated DIOs.
        rpl_dodag_version: Initial local DODAG version before first admission.
        rpl_mop: Expected RPL mode of operation; only non-storing MOP 1 is
            implemented. The instance ID, DODAG ID, and expected role must be
            configured together; omitting all three disables DIO admission.
        rpl_dio_expected_role: Whether admitted DIO signers are roots or peers.
    """

    receive_timeout_ms: int = 1000
    announce_interval_ms: int = 300_000
    announce_jitter_ms: int = 30_000
    pending_timeout_ms: int = 5_000
    rreq_jitter_min_ms: int = 0
    rreq_jitter_max_ms: int = 100
    persist_path: str | None = None
    schc_failure_threshold: int = 3
    schc_failure_max_sources: int = 16
    local_short_addr: int | None = None
    rpl_instance_id: int | None = None
    rpl_dodag_id: IPv6Address | None = None
    rpl_dodag_version: int = 0
    rpl_mop: int = 1
    rpl_dio_expected_role: Literal["root", "peer"] | None = None


@dataclass
class _OutboundFragmentSession:
    """One Node-owned retransmission timer for a link-owned sender."""

    sender: FragmentSender
    peer: PeerIdentity
    timer_changed: asyncio.Event = field(default_factory=asyncio.Event)
    deadline: float | None = None
    task: asyncio.Task[None] | None = None


@dataclass(frozen=True)
class _PeerRxChannel:
    channel: int
    expires_ms: int


@dataclass
class Node:
    """A LICHEN mesh node integrating all protocol layers.

    Why a class: Owns all layer instances, manages lifecycle, coordinates
    async tasks for receiving, announcing, and routing.

    Attributes:
        identity: This node's cryptographic identity.
        radio: Physical layer (simulated or hardware).
        config: Node configuration.
        meshtastic: Enable Meshtastic BLE adapter (requires [meshtastic] extra).
        link: Link layer for frame signing/verification.
        gradient_table: Unified routing table.
        router: Hybrid routing decision engine.
        announce_processor: Processes incoming announces.
        peer_db: Known peers by IID (for signature verification).
        state: Current lifecycle state.
    """

    identity: Identity
    radio: Radio
    config: NodeConfig = field(default_factory=NodeConfig)
    meshtastic: bool = False
    persistence_revision_anchor: PersistenceRevisionAnchor | None = field(default=None, repr=False)
    allow_persistence_bootstrap: bool = False

    # Protocol layers - initialized in __post_init__
    link: LinkLayer = field(init=False, repr=False)
    gradient_table: GradientTable = field(default_factory=GradientTable)
    router: Router = field(init=False, repr=False)
    announce_processor: AnnounceProcessor = field(init=False, repr=False)
    _announce_persistence: AnnounceStatePersistence | None = field(
        default=None, init=False, repr=False
    )
    dodag: DodagState | None = field(default=None, init=False, repr=False)

    # Peer database - nodes we know about
    peer_db: Mapping[bytes, PeerIdentity] = field(default_factory=dict, repr=False)
    _peer_db: dict[bytes, PeerIdentity] = field(default_factory=dict, init=False, repr=False)
    # Per-peer RX channel from announces (CCP-9 rendezvous)
    _peer_rx_channel: dict[bytes, _PeerRxChannel] = field(default_factory=dict, repr=False)

    # Lifecycle state
    _state_machine: StateMachine[NodeState] = field(init=False, repr=False)
    _receive_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _supervisor_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _terminal_error: BaseException | None = field(default=None, init=False, repr=False)
    _lifecycle_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _fragment_operation_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock, init=False, repr=False
    )
    _fragment_shutdown_requested: bool = field(default=False, init=False, repr=False)
    _fragment_sessions: dict[bytes, _OutboundFragmentSession] = field(
        default_factory=dict, init=False, repr=False
    )

    # Announce scheduler - manages periodic announce transmission
    # Why separate: Single responsibility, persistence support, testability.
    _scheduler: AnnounceScheduler = field(init=False, repr=False)

    # Callbacks
    _on_receive: Callable[[bytes, PeerIdentity], None] | None = field(
        default=None, init=False, repr=False
    )
    _on_receive_owner: object | None = field(default=None, init=False, repr=False)
    _on_rule_version_failure: Callable[[bytes], None] | None = field(
        default=None, init=False, repr=False
    )
    _rule_version_failures: RuleVersionFailureTracker = field(init=False, repr=False)

    # Relay dedup: canonical IPv6 datagrams with mutable Hop Limit normalized.
    # This remains stable across peer-specific SCHC encodings and relay hops.
    _relay_seen: OrderedDict[bytes, int] = field(
        default_factory=OrderedDict, init=False, repr=False
    )

    # AnnounceProcessor's callback accepts only an IID, while the exact native
    # address also needs the authenticated public key. _process_announce binds
    # the candidate synchronously until the processor validates both.
    _announce_address_candidate: tuple[bytes, IPv6Address] | None = field(
        default=None, init=False, repr=False
    )

    # Meshtastic adapter (optional, created if meshtastic=True)
    _meshtastic_adapter: MeshtasticAdapterProtocol | None = field(
        default=None, init=False, repr=False
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name == "peer_db" and isinstance(self.__dict__.get("peer_db"), MappingProxyType):
            raise AttributeError("peer_db is a read-only Node-managed view")
        super().__setattr__(name, value)

    def __post_init__(self) -> None:
        self._validate_rpl_config()
        self.config.receive_timeout_ms = _validated_receive_timeout_ms(
            self.config.receive_timeout_ms
        )
        self.config.announce_interval_ms = _validated_timing_ms(
            "announce_interval_ms", self.config.announce_interval_ms, minimum=1
        )
        self.config.announce_jitter_ms = _validated_timing_ms(
            "announce_jitter_ms", self.config.announce_jitter_ms, minimum=0
        )
        self.config.pending_timeout_ms = _validated_timing_ms(
            "pending_timeout_ms", self.config.pending_timeout_ms, minimum=1
        )
        self.config.rreq_jitter_min_ms = _validated_timing_ms(
            "rreq_jitter_min_ms", self.config.rreq_jitter_min_ms, minimum=0
        )
        self.config.rreq_jitter_max_ms = _validated_timing_ms(
            "rreq_jitter_max_ms", self.config.rreq_jitter_max_ms, minimum=0
        )
        if self.config.rreq_jitter_min_ms > self.config.rreq_jitter_max_ms:
            raise ValueError("rreq_jitter_min_ms must not exceed rreq_jitter_max_ms")
        if len(self.peer_db) > PEER_DB_MAX_SIZE:
            raise ValueError(f"peer database cannot exceed {PEER_DB_MAX_SIZE} entries")
        canonical_peers: dict[bytes, PeerIdentity] = {}
        for iid, peer in self.peer_db.items():
            canonical = _canonical_peer(peer)
            if type(iid) is not bytes or iid != canonical.iid:
                raise ValueError("peer database key does not match its peer identity")
            incumbent = canonical_peers.get(canonical.iid)
            if incumbent is not None and incumbent.pubkey != canonical.pubkey:
                raise PeerIdentityCollisionError(f"peer IID collision for {canonical.iid.hex()}")
            canonical_peers[canonical.iid] = canonical
        self._peer_db = canonical_peers
        self.peer_db = MappingProxyType(self._peer_db)
        self._state_machine = StateMachine(
            initial=NodeState.STOPPED,
            transitions=NODE_STATE_TRANSITIONS,
            name=f"node[{self.identity.iid.hex()}]",
        )

        # Why initialize layers here: They depend on self.identity, self.radio.
        self.link = LinkLayer(
            radio=self.radio,
            identity=self.identity,
            peer_lookup=self._peer_lookup,
            peer_lookup_all=lambda: list(self._peer_db.values()),
            persist_path=self.config.persist_path,
            persistence_revision_anchor=self.persistence_revision_anchor,
            allow_persistence_bootstrap=self.allow_persistence_bootstrap,
            local_short_addr=self.config.local_short_addr,
        )
        self._rule_version_failures = RuleVersionFailureTracker(
            self.config.schc_failure_threshold,
            max_sources=self.config.schc_failure_max_sources,
        )

        if self.config.rpl_instance_id is not None:
            assert self.config.rpl_dodag_id is not None
            self.dodag = DodagState(
                rpl_instance_id=self.config.rpl_instance_id,
                dodag_id=self.config.rpl_dodag_id,
                version=self.config.rpl_dodag_version,
                node_address=yggdrasil_address(self.identity.pubkey),
            )

        self.router = Router(
            node_address=yggdrasil_address(self.identity.pubkey),
            gradient_table=self.gradient_table,
            dodag=self.dodag,
            mesh_prefixes={_NATIVE_MESH_PREFIX},
        )

        announce_seen: OrderedDict[bytes, int] = OrderedDict()
        announce_pins: OrderedDict[bytes, bytes] = OrderedDict()
        announce_reconciliation: set[bytes] = set()
        announce_committer: Callable[[bytes, bytes, int], None] | None = None
        if self.config.persist_path is not None:
            assert self.persistence_revision_anchor is not None
            self._announce_persistence = AnnounceStatePersistence(
                self.config.persist_path,
                self.identity,
                self.persistence_revision_anchor,
                allow_bootstrap=self.allow_persistence_bootstrap,
            )
            announce_seen = self._announce_persistence.floors
            announce_pins = self._announce_persistence.pins
            announce_reconciliation = set(announce_seen)
            announce_committer = self._announce_persistence.commit
            for iid, pubkey in announce_pins.items():
                incumbent = self._peer_db.get(iid)
                if incumbent is not None and incumbent.pubkey != pubkey:
                    raise PeerIdentityCollisionError(
                        f"persisted announce pin collides for {iid.hex()}"
                    )

        self.announce_processor = AnnounceProcessor(
            gradient_table=self.gradient_table,
            address_builder=self._address_for_announced_iid,
            _seen=announce_seen,
            _pinned_keys=announce_pins,
            _pending_reconciliation=announce_reconciliation,
            state_committer=announce_committer,
        )

        # Why scheduler: Encapsulates announce timing, signing, sequence numbers.
        # The transmitter lambda bridges scheduler to link layer.
        self._scheduler = AnnounceScheduler(
            identity=self.identity,
            transmitter=self,  # Node implements AnnounceTransmitter
            config=SchedulerConfig(
                interval_ms=self.config.announce_interval_ms,
                jitter_ms=self.config.announce_jitter_ms,
                initial_delay_ms=5_000,  # Why 5s: Let node discover peers first.
            ),
        )
        if self._announce_persistence is not None:
            self._scheduler.set_seq_num(self._announce_persistence.local_sequence)
            self._scheduler.set_on_seq_change(self._announce_persistence.reserve_local_sequence)

        # Meshtastic adapter: lazy import to avoid requiring bleak/betterproto
        if self.meshtastic:
            try:
                from lichen.interface.meshtastic.adapter import MeshtasticAdapter

                self._meshtastic_adapter = MeshtasticAdapter(self)
            except ImportError:
                logger.warning(
                    "meshtastic=True but adapter not available; "
                    "install with: pip install lichen[meshtastic]"
                )

    def _validate_rpl_config(self) -> None:
        """Require a complete, implemented authenticated-DIO admission scope."""
        configured = (
            self.config.rpl_instance_id,
            self.config.rpl_dodag_id,
            self.config.rpl_dio_expected_role,
        )
        if all(value is None for value in configured):
            return
        if any(value is None for value in configured):
            raise ValueError("RPL admission requires instance ID, DODAG ID, and expected DIO role")
        if (
            type(self.config.rpl_instance_id) is not int
            or not 0 <= self.config.rpl_instance_id < 0xC0
        ):
            raise ValueError("RPL instance ID must be a global 0..191 instance")
        if type(self.config.rpl_dodag_id) is not IPv6Address:
            raise TypeError("RPL DODAG ID must be an exact IPv6Address")
        if (
            type(self.config.rpl_dodag_version) is not int
            or not 0 <= self.config.rpl_dodag_version <= 0xFF
        ):
            raise ValueError("RPL DODAG version must be an integer in 0..255")
        if type(self.config.rpl_mop) is not int or self.config.rpl_mop != 1:
            raise ValueError("Node currently supports only RPL non-storing MOP 1")
        if self.config.rpl_dio_expected_role not in ("root", "peer"):
            raise ValueError("expected DIO role must be 'root' or 'peer'")

    @property
    def state(self) -> NodeState:
        """Return the node lifecycle state."""
        return self._state_machine.state

    @property
    def terminal_error(self) -> BaseException | None:
        """Return the last terminal background failure, if any."""
        return self._terminal_error

    def _peer_lookup(self, hint: bytes) -> PeerIdentity | None:
        if hint and len(hint) == 8 and hint in self._peer_db:
            return self._peer_db[hint]
        return None

    def _address_for_announced_iid(self, iid: bytes) -> IPv6Address:
        """Resolve an announce IID to its exact authenticated native address."""
        candidate = self._announce_address_candidate
        if candidate is not None and candidate[0] == iid:
            return candidate[1]
        peer = self._peer_db.get(iid)
        if peer is None:
            raise ValueError("announce IID has no authenticated public-key binding")
        return yggdrasil_address(peer.pubkey)

    def _relay_seen_recently(self, identity: bytes, now_ms: int) -> bool:
        """Return whether a relay identity is inside its fixed suppression window.

        Duplicate observations deliberately do not extend the deadline. This
        bounds suppression from an authenticated preplay or repeated spoof.
        """
        deadline = self._relay_seen.get(identity)
        if deadline is None:
            return False
        if deadline <= now_ms:
            self._relay_seen.pop(identity, None)
            return False
        return True

    def _remember_relay(self, identity: bytes, now_ms: int) -> None:
        """Record a relay identity without refreshing a live suppression window."""
        if self._relay_seen_recently(identity, now_ms):
            return
        self._relay_seen[identity] = now_ms + RELAY_SEEN_WINDOW_MS
        self._relay_seen.move_to_end(identity)
        if len(self._relay_seen) > RELAY_SEEN_MAX_SIZE:
            # Remove the oldest half to amortize eviction while preserving the
            # most recent loop-suppression history.
            for _ in range(RELAY_SEEN_MAX_SIZE // 2):
                self._relay_seen.popitem(last=False)

    def _peer_has_live_state(self, peer: PeerIdentity, now_ms: int) -> bool:
        """Return whether evicting ``peer`` would orphan security or routing state."""
        self._purge_expired_peer_rx_channels(now_ms)
        if self.link._pinned_keys.get(peer.iid) == peer.pubkey:
            return True
        if self.announce_processor.pinned_pubkey_for(peer.iid) == peer.pubkey:
            return True
        with self.link._security_lock:
            link_transaction_live = self.link._peer_has_eviction_blocker_unlocked(peer.pubkey)
        if (
            peer.pubkey in self._fragment_sessions
            or link_transaction_live
            or peer.iid in self._peer_rx_channel
        ):
            return True
        native = yggdrasil_address(peer.pubkey)
        for entry in self.gradient_table.entries():
            if entry.expires <= now_ms:
                continue
            if entry.destination == native:
                return True
            if entry.next_hop.packed[:8] == IPv6Address("fe80::").packed[:8] and (
                entry.next_hop.packed[8:] == peer.iid
            ):
                return True
        return False

    def _purge_expired_peer_rx_channels(self, now_ms: int) -> None:
        for iid, binding in tuple(self._peer_rx_channel.items()):
            if binding.expires_ms <= now_ms:
                self._peer_rx_channel.pop(iid, None)

    def _evictable_peer_iid(self, now_ms: int) -> bytes | None:
        """Select the oldest peer whose removal cannot orphan live state."""
        return next(
            (
                iid
                for iid, existing in self._peer_db.items()
                if not self._peer_has_live_state(existing, now_ms)
            ),
            None,
        )

    def add_peer(self, peer: PeerIdentity) -> None:
        """Add a peer to the database.

        Why exposed: Caller may have out-of-band knowledge of peers.
        Also called automatically when we receive a valid announce.
        """
        canonical = _canonical_peer(peer)
        incumbent = self._peer_db.get(canonical.iid)
        if incumbent is not None:
            if incumbent.pubkey != canonical.pubkey:
                logger.error(
                    "peer IID collision: iid=%s incumbent=%s candidate=%s",
                    canonical.iid.hex(),
                    incumbent.pubkey.hex(),
                    canonical.pubkey.hex(),
                )
                raise PeerIdentityCollisionError(f"peer IID collision for {canonical.iid.hex()}")
            return
        if len(self._peer_db) >= PEER_DB_MAX_SIZE:
            try:
                now_ms = int(asyncio.get_running_loop().time() * 1000)
            except RuntimeError:
                import time

                now_ms = int(time.monotonic() * 1000)
            evicted_iid = self._evictable_peer_iid(now_ms)
            if evicted_iid is None:
                raise PeerDatabaseFullError(
                    f"peer database is full ({PEER_DB_MAX_SIZE} protected entries)"
                )
            self._peer_db.pop(evicted_iid)
            self._peer_rx_channel.pop(evicted_iid, None)
        self._peer_db[canonical.iid] = canonical
        logger.debug("added peer: %s", canonical.iid.hex())

    def set_on_rule_version_failure(self, callback: Callable[[bytes], None] | None) -> None:
        """Install the operator notification for repeated authenticated SCHC failures."""
        if callback is not None:
            require_sync_callable(callback, "rule-version failure callback")
        self._on_rule_version_failure = callback

    def remove_peer(self, iid: bytes) -> bool:
        """Forget an idle peer, refusing to orphan live protocol state."""
        if type(iid) is not bytes or len(iid) != 8:
            raise ValueError("peer IID must be exact 8-byte bytes")
        peer = self._peer_db.get(iid)
        if peer is None:
            return False
        try:
            now_ms = int(asyncio.get_running_loop().time() * 1000)
        except RuntimeError:
            import time

            now_ms = int(time.monotonic() * 1000)
        if self._peer_has_live_state(peer, now_ms):
            raise PeerInUseError(f"peer {iid.hex()} has live protocol state")
        self._peer_db.pop(iid)
        self._peer_rx_channel.pop(iid, None)
        return True

    def _peer_for_next_hop(self, next_hop: IPv6Address | None) -> PeerIdentity | None:
        """Resolve a router-selected next hop to its signer identity."""
        if next_hop is None:
            return None
        packed = next_hop.packed
        if packed[:8] == IPv6Address("fe80::").packed[:8]:
            return self._peer_db.get(packed[8:])
        return next(
            (peer for peer in self._peer_db.values() if yggdrasil_address(peer.pubkey) == next_hop),
            None,
        )

    async def transmit_announce(self, data: bytes) -> bool:
        """Transmit announce data via link layer (AnnounceTransmitter protocol).

        Why a method on Node: Node owns the link layer. Scheduler calls this
        to actually send the announce bytes over the air.

        Announces are sent on the control channel (CH0) per CCP-9 so that
        unknown peers can discover this node.
        """
        return await self.link.send(wrap_routing_payload(data))

    def set_on_receive(self, callback: Callable[[bytes, PeerIdentity], None]) -> None:
        """Set callback for received application data.

        Why callback: Upper layers (CoAP, etc.) need to receive data.
        The callback is invoked with (payload, sender).
        """
        if self._on_receive_owner is not None and self._on_receive_owner is not self:
            raise RuntimeError("node receive callback already has an owner")
        self._on_receive = callback
        self._on_receive_owner = self

    def register_on_receive(
        self,
        owner: object,
        callback: Callable[[bytes, PeerIdentity], None],
    ) -> None:
        """Register one owner-controlled receive callback."""
        if owner is None:
            raise ValueError("node receive callback owner must not be None")
        if self._on_receive is not None:
            raise RuntimeError("node receive callback already has an owner")
        self._on_receive = callback
        self._on_receive_owner = owner

    def unregister_on_receive(self, owner: object) -> bool:
        """Clear the receive callback only when ``owner`` still controls it."""
        if owner is None:
            raise ValueError("node receive callback owner must not be None")
        if self._on_receive_owner is not owner:
            return False
        self._on_receive = None
        self._on_receive_owner = None
        return True

    async def start(self) -> None:
        """Start the node's async tasks.

        Why async: Creates background tasks that run until stop().
        """
        async with self._lifecycle_lock:
            self._state_machine.require(NodeState.STOPPED)
            self._terminal_error = None
            self._fragment_shutdown_requested = False
            self._state_machine.transition(NodeState.STARTING)
            logger.info("starting node %s", self.identity.iid.hex())
            scheduler_attempted = False
            adapter_attempted = False
            try:
                self._receive_task = asyncio.create_task(
                    self._receive_loop(),
                    name=f"node-rx-{self.identity.iid.hex()[:8]}",
                )
                await asyncio.sleep(0)
                self._raise_receive_failure()
                scheduler_attempted = True
                await self._scheduler.start()
                if self._meshtastic_adapter is not None:
                    adapter_attempted = True
                    await self._meshtastic_adapter.start()
                await asyncio.sleep(0)
                self._raise_receive_failure()
            except BaseException as primary:
                self._fragment_shutdown_requested = True
                self._state_machine.transition(NodeState.STOPPING)
                await self._cleanup_started(
                    adapter=adapter_attempted,
                    scheduler=scheduler_attempted,
                )
                self._state_machine.transition(NodeState.STOPPED)
                raise primary
            self._state_machine.transition(NodeState.RUNNING)
            receive_task = self._receive_task
            assert receive_task is not None
            self._supervisor_task = asyncio.create_task(
                self._supervise_receive_task(receive_task),
                name=f"node-rx-supervisor-{self.identity.iid.hex()[:8]}",
            )
            logger.info("node started")

    async def stop(self) -> None:
        """Stop the node's async tasks.

        Why graceful: Cancels tasks and waits for them to finish.
        """
        self._fragment_shutdown_requested = True
        async with self._lifecycle_lock:
            if self.state == NodeState.STOPPED:
                await self._cancel_fragment_sessions()
                return
            self._state_machine.require(NodeState.RUNNING)
            self._state_machine.transition(NodeState.STOPPING)
            logger.info("stopping node")
            error = await self._cleanup_started(
                adapter=self._meshtastic_adapter is not None,
                scheduler=True,
            )
            self._state_machine.transition(NodeState.STOPPED)
            logger.info("node stopped")
            if error is not None:
                raise error

    def _raise_receive_failure(self) -> None:
        task = self._receive_task
        if task is not None and task.done():
            task.result()

    async def _supervise_receive_task(self, receive_task: asyncio.Task[None]) -> None:
        """Stop sibling services if the receive task exits outside shutdown."""
        try:
            await receive_task
        except asyncio.CancelledError:
            return
        except BaseException as exc:
            terminal: BaseException = exc
        else:
            terminal = RuntimeError("receive task exited unexpectedly")
        self._terminal_error = terminal
        async with self._lifecycle_lock:
            if self.state is not NodeState.RUNNING or self._receive_task is not receive_task:
                return
            self._fragment_shutdown_requested = True
            self._state_machine.transition(NodeState.STOPPING)
            cleanup_error = await self._cleanup_started(
                adapter=self._meshtastic_adapter is not None,
                scheduler=True,
            )
            if cleanup_error is not None and cleanup_error is not terminal:
                logger.error("receive-failure cleanup also failed: %r", cleanup_error)
            self._state_machine.transition(NodeState.STOPPED)

    async def _cleanup_started(self, *, adapter: bool, scheduler: bool) -> BaseException | None:
        error: BaseException | None = None
        if adapter and self._meshtastic_adapter is not None:
            try:
                await self._meshtastic_adapter.stop()
            except BaseException as exc:
                error = exc
        if scheduler:
            try:
                await self._scheduler.stop()
            except BaseException as exc:
                if error is None:
                    error = exc
        try:
            await self._cancel_fragment_sessions()
        except BaseException as exc:
            if error is None:
                error = exc
        task = self._receive_task
        self._receive_task = None
        if task is not None:
            task.cancel()
            results = await asyncio.gather(task, return_exceptions=True)
            result = results[0]
            if (
                error is None
                and isinstance(result, BaseException)
                and not isinstance(result, asyncio.CancelledError)
            ):
                error = result
        return error

    async def _cancel_fragment_sessions(self) -> None:
        """Cancel every Node-owned SCHC timer and release its link session."""
        async with self._fragment_operation_lock:
            sessions = tuple(self._fragment_sessions.values())
            tasks = [session.task for session in sessions if session.task is not None]
            for session in sessions:
                await self._abort_fragment_session(session)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._fragment_sessions.clear()

    async def _receive_loop(self) -> None:
        """Continuously receive and process frames.

        Why infinite loop: Runs until cancelled by stop().
        """
        while True:
            try:
                await self._send_expired_reassembly_aborts()
                rx = await self.link.receive(self.config.receive_timeout_ms)
                if rx is not None and not isinstance(rx, ReceiveError):
                    await self._process_received(rx)
                elif isinstance(rx, ReceiveError):
                    if rx in (
                        ReceiveError.KEY_CHANGE,
                        ReceiveError.REPLAY,
                        ReceiveError.MIC_FAILED,
                    ):
                        logger.warning("link RX security event: %s", rx)
                    else:
                        logger.debug("link RX rejected: %s", rx)
            except asyncio.CancelledError:
                break
            except (LinkPersistenceError, LinkSecurityClockError):
                raise
            except Exception as e:
                logger.exception("error in receive loop: %s", e)
                # Continue receiving despite errors

    async def _send_expired_reassembly_aborts(self) -> None:
        """Drain link-owned inactivity transitions and transmit each abort once."""
        for peer_key, destination, wire in self.link.expire_authenticated_schc_reassembly():
            expected_destination = iid_to_eui64(PeerIdentity.from_pubkey(peer_key).iid)
            if destination != expected_destination:
                logger.error("link returned a mismatched SCHC expiry destination")
                continue
            try:
                sent = await self.link.send(
                    wire,
                    destination,
                    AddrMode.EXTENDED,
                    Priority.ACK,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("SCHC Receiver-Abort transmission failed")
                continue
            if not sent:
                logger.warning("SCHC Receiver-Abort was not transmitted")

    async def _process_received(self, rx: RxFrame) -> None:
        """Process a received and verified frame.

        Why separate method: Keeps receive loop simple, allows testing.
        """
        payload = rx.payload

        kind = classify_l2_payload(payload)
        body = l2_payload_body(payload)

        if kind == L2PayloadKind.ROUTING and len(body) > 0 and body[0] == L2_ROUTING_TYPE_ANNOUNCE:
            await self._process_announce(body, rx.sender, rx.rssi_dbm)
            return

        is_fragment = bool(payload) and payload[0] in (0x78, 0x79)

        # SCHC-compressed IPv6 data packet: decompress, route, relay or deliver.
        if kind != L2PayloadKind.SCHC and not is_fragment:
            if self._on_receive:
                self._on_receive(payload, rx.sender)
            return

        delivery_payload = payload
        if is_fragment:
            try:
                sender_output = self.link.accept_authenticated_schc_sender_control(rx)
                if sender_output is not None:
                    session = self._fragment_sessions.get(rx.sender_pubkey)
                    if session is not None:
                        # An authenticated ACK stops the preceding timer while
                        # its repair batch is prepared and transmitted.
                        session.deadline = None
                        session.timer_changed.set()
                    if not await self._send_fragment_outputs(sender_output, rx.sender):
                        await self._abort_fragment_session(session)
                    elif session is not None:
                        if session.sender.status == "active":
                            # Start the next full timeout only after every
                            # repair output (including its ACK request) is
                            # radio-accepted.
                            session.deadline = (
                                asyncio.get_running_loop().time()
                                + SCHC_RETRANSMISSION_TIMEOUT_SECONDS
                            )
                            session.timer_changed.set()
                        elif self._fragment_sessions.get(rx.sender_pubkey) is session:
                            self._fragment_sessions.pop(rx.sender_pubkey, None)
                    return
                authenticated_dio = None
                if self.dodag is None:
                    result, ipv6_bytes = self.link.accept_authenticated_schc_fragment(rx)
                else:
                    expected_role = self.config.rpl_dio_expected_role
                    assert expected_role is not None
                    result, ipv6_bytes, authenticated_dio = (
                        self.link.accept_authenticated_schc_fragment_dio(
                            rx,
                            expected_rpl_instance_id=self.dodag.rpl_instance_id,
                            expected_dodag_id=self.dodag.dodag_id,
                            expected_mop=1,
                            expected_role=expected_role,
                        )
                    )
            except (FragmentError, SchcError, TypeError, ValueError):
                self._record_schc_failure(rx)
                return
            if result.response is not None:
                await self.link.send(
                    result.response,
                    iid_to_eui64(rx.sender.iid),
                    AddrMode.EXTENDED,
                    Priority.ACK,
                )
            if ipv6_bytes is None:
                return
            assert result.reassembled is not None
            if authenticated_dio is not None:
                assert self.dodag is not None
                expected_role = self.config.rpl_dio_expected_role
                assert expected_role is not None
                try:
                    self.dodag.process_authenticated_dio_evidence(
                        self.link,
                        authenticated_dio,
                        expected_role=expected_role,
                    )
                except (FragmentError, SchcError, TypeError, ValueError):
                    self._record_schc_failure(rx)
                    return
                self._rule_version_failures.record_success(rx.sender_pubkey)
                return
            delivery_payload = wrap_schc_payload(result.reassembled)
        else:
            if self.dodag is not None and self._is_configured_rpl_dio(body):
                try:
                    expected_role = self.config.rpl_dio_expected_role
                    assert expected_role is not None
                    self.dodag.process_authenticated_dio(
                        self.link,
                        rx,
                        expected_role=expected_role,
                    )
                except (FragmentError, SchcError, TypeError, ValueError):
                    self._record_schc_failure(rx)
                    return
                self._rule_version_failures.record_success(rx.sender_pubkey)
                return
            try:
                ipv6_bytes = self.link.accept_authenticated_schc_packet(rx)
            except (SchcError, TypeError, ValueError):
                self._record_schc_failure(rx)
                return
        try:
            packet = IPv6Packet.from_bytes(ipv6_bytes, strict=True)
        except Exception:
            self._record_schc_failure(rx)
            return
        self._rule_version_failures.record_success(rx.sender_pubkey)
        relay_identity = _relay_identity(packet)

        now_ms = int(asyncio.get_running_loop().time() * 1000)
        decision, next_hop = self.router.route(packet, now_ms)

        if decision == RouteDecision.DELIVER_LOCAL:
            if self._on_receive:
                self._on_receive(delivery_payload, rx.sender)
        elif decision == RouteDecision.FORWARD:
            if self._relay_seen_recently(relay_identity, now_ms):
                return
            if packet.header.hop_limit <= 1:
                logger.debug("dropping IPv6 packet with exhausted Hop Limit")
                return
            packet.header.hop_limit -= 1
            forwarded_ipv6 = packet.to_bytes()
            # Link authentication proves only the immediate sender. Without
            # end-to-end source evidence, forwarded data MUST NOT modify the
            # routable gradient table for its asserted IPv6 source.
            peer = self._peer_for_next_hop(next_hop)
            if peer is None:
                logger.warning("forwarding next hop has no pinned peer identity")
                return
            try:
                forwarded = self.link.compress_schc_for_peer(
                    forwarded_ipv6,
                    peer.pubkey,
                    allow_fragmentation=True,
                )
            except (SchcError, TypeError, ValueError):
                logger.warning("forwarding next-hop SCHC policy rejected packet")
                return
            if not await self._transmit_peer_schc(forwarded, peer):
                return
            # Cache only a packet accepted for transmission; a transient
            # sender-capacity/radio failure must remain retryable.
            self._remember_relay(relay_identity, now_ms)

    def _is_configured_rpl_dio(self, schc: bytes) -> bool:
        """Classify a candidate DIO without consuming its authenticated receipt."""
        try:
            packet = IPv6Packet.from_bytes(decompress_packet(schc), strict=True)
        except (SchcError, TypeError, ValueError):
            return False
        return (
            packet.header.next_header == NextHeader.ICMPV6
            and len(packet.payload) >= 2
            and packet.payload[0] == RPL_ICMPV6_TYPE
            and packet.payload[1] == int(RplCode.DIO)
        )

    async def _transmit_peer_schc(
        self,
        schc: bytes,
        peer: PeerIdentity,
    ) -> bool:
        """Transmit one peer-policy encoding, fragmenting only through Link."""
        if len(schc) <= MAX_SINGLE_FRAME_SCHC_PACKET:
            return await self.link.send(
                wrap_schc_payload(schc),
                iid_to_eui64(peer.iid),
                AddrMode.EXTENDED,
                Priority.BULK,
            )
        if self._fragment_shutdown_requested:
            return False
        async with self._fragment_operation_lock:
            if self._fragment_shutdown_requested:
                return False
            sender: FragmentSender | None = None
            session: _OutboundFragmentSession | None = None
            try:
                sender = self.link.create_fragment_sender(schc, peer.pubkey)
                wires = sender.start()
                session = _OutboundFragmentSession(sender=sender, peer=peer)
                self._fragment_sessions[peer.pubkey] = session
                if not await self._send_initial_fragment_outputs(wires, peer):
                    await self._abort_fragment_session(session)
                    return False
                if sender.status != "active":
                    self._fragment_sessions.pop(peer.pubkey, None)
                    return not self._fragment_shutdown_requested
                session.deadline = (
                    asyncio.get_running_loop().time() + SCHC_RETRANSMISSION_TIMEOUT_SECONDS
                )
                task = asyncio.create_task(
                    self._drive_fragment_sender(session),
                    name=f"schc-fragment-{peer.iid.hex()}",
                )
                session.task = task

                def driver_done(completed: asyncio.Task[None]) -> None:
                    self._fragment_driver_done(peer.pubkey, session, completed)

                task.add_done_callback(driver_done)
            except asyncio.CancelledError:
                if session is not None:
                    await asyncio.shield(self._abort_fragment_session(session))
                elif sender is not None:
                    sender.cancel()
                raise
            except (FragmentError, SchcError, TypeError, ValueError):
                if session is not None:
                    await self._abort_fragment_session(session)
                elif sender is not None:
                    sender.cancel()
                logger.warning("authenticated SCHC fragmentation setup failed")
                return False
            except BaseException:
                if session is not None:
                    await asyncio.shield(self._abort_fragment_session(session))
                elif sender is not None:
                    sender.cancel()
                raise
        return True

    async def _send_initial_fragment_outputs(
        self,
        outputs: list[bytes],
        peer: PeerIdentity,
    ) -> bool:
        """Send initial fragments while observing concurrent shutdown requests."""
        for output in outputs:
            if self._fragment_shutdown_requested:
                return False
            try:
                sent = await self.link.send(
                    output,
                    iid_to_eui64(peer.iid),
                    AddrMode.EXTENDED,
                    Priority.ACK if _is_fragment_control(output) else Priority.BULK,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("SCHC fragmentation radio transmission failed")
                return False
            if not sent or self._fragment_shutdown_requested:
                return False
        return True

    async def _send_fragment_outputs(
        self,
        outputs: list[bytes],
        peer: PeerIdentity,
    ) -> bool:
        """Send one manager-issued output batch, stopping at the first failure."""
        for output in outputs:
            try:
                sent = await self.link.send(
                    output,
                    iid_to_eui64(peer.iid),
                    AddrMode.EXTENDED,
                    Priority.ACK if _is_fragment_control(output) else Priority.BULK,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("SCHC fragmentation radio transmission failed")
                return False
            if not sent:
                return False
        return True

    async def _abort_fragment_session(
        self,
        session: _OutboundFragmentSession | None,
    ) -> None:
        """Terminate one local sender and best-effort its protocol abort."""
        if session is None:
            return
        sender = session.sender
        abort = self.link.cancel_fragment_sender(sender)
        try:
            if abort is not None:
                try:
                    await self.link.send(
                        abort,
                        iid_to_eui64(session.peer.iid),
                        AddrMode.EXTENDED,
                        Priority.ACK,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("SCHC Sender-Abort transmission failed")
        finally:
            if self._fragment_sessions.get(session.peer.pubkey) is session:
                self._fragment_sessions.pop(session.peer.pubkey, None)

    async def _drive_fragment_sender(self, session: _OutboundFragmentSession) -> None:
        """Drive ACK waits and bounded retry exhaustion for one sender."""
        try:
            while session.sender.status == "active":
                deadline = session.deadline
                if deadline is None:
                    await session.timer_changed.wait()
                    session.timer_changed.clear()
                    continue
                remaining = max(0.0, deadline - asyncio.get_running_loop().time())
                try:
                    await asyncio.wait_for(
                        session.timer_changed.wait(),
                        timeout=remaining,
                    )
                except TimeoutError:
                    output = session.sender.timeout()
                    if output and not await self._send_fragment_outputs([output], session.peer):
                        await self._abort_fragment_session(session)
                        return
                    if session.sender.status == "active":
                        session.deadline = (
                            asyncio.get_running_loop().time() + SCHC_RETRANSMISSION_TIMEOUT_SECONDS
                        )
                else:
                    session.timer_changed.clear()
        except asyncio.CancelledError:
            await asyncio.shield(self._abort_fragment_session(session))
            raise

    def _fragment_driver_done(
        self,
        peer_key: bytes,
        session: _OutboundFragmentSession,
        task: asyncio.Task[None],
    ) -> None:
        """Drop only the exact completed session and retrieve task failures."""
        if self._fragment_sessions.get(peer_key) is session:
            self._fragment_sessions.pop(peer_key, None)
        if not task.cancelled():
            exception = task.exception()
            if exception is not None:
                logger.error(
                    "SCHC fragmentation driver failed",
                    exc_info=(type(exception), exception, exception.__traceback__),
                )

    def _record_schc_failure(self, rx: RxFrame) -> None:
        """Count one authenticated SCHC ingress failure without delivering it."""
        try:
            notify = self._rule_version_failures.record_failure(rx.sender_pubkey)
        except RuleVersionFailureTrackerFull:
            logger.error(
                "SCHC failure tracker full; source not admitted: %s",
                rx.sender_iid.hex(),
            )
            return
        if notify:
            logger.error(
                "repeated SCHC/IPv6 ingress failures from signer %s",
                rx.sender_pubkey.hex(),
            )
            if self._on_rule_version_failure is not None:
                try:
                    reject_awaitable_result(
                        self._on_rule_version_failure(rx.sender_pubkey),
                        "rule-version failure callback",
                    )
                except BaseException:
                    self._rule_version_failures._retry_notification(rx.sender_pubkey)
                    raise
            else:
                self._rule_version_failures._retry_notification(rx.sender_pubkey)

    async def _process_announce(self, payload: bytes, sender: PeerIdentity, rssi_dbm: int) -> None:
        """Process an announce message.

        Why async: May need to relay the announce.
        """
        try:
            announce = AnnounceMessage.from_bytes(payload)
        except Exception as e:
            logger.warning("failed to parse announce: %s", e)
            return

        # Preflight the derived identity before AnnounceProcessor mutates its
        # pin/sequence tables or the routable gradient table. Signature
        # validation still belongs to the processor; this check only prevents
        # a known collision or impossible-capacity admission from leaving
        # partially committed trust state.
        announced_peer = PeerIdentity.from_pubkey(announce.pubkey)
        if announced_peer.iid == announce.originator_iid:
            incumbent = self._peer_db.get(announced_peer.iid)
            if incumbent is not None and incumbent.pubkey != announced_peer.pubkey:
                logger.error(
                    "announce peer IID collision: iid=%s incumbent=%s candidate=%s",
                    announced_peer.iid.hex(),
                    incumbent.pubkey.hex(),
                    announced_peer.pubkey.hex(),
                )
                return
            if incumbent is None and len(self._peer_db) >= PEER_DB_MAX_SIZE:
                now_ms = int(asyncio.get_running_loop().time() * 1000)
                if self._evictable_peer_iid(now_ms) is None:
                    logger.warning("announce peer admission rejected: peer database is full")
                    return

        # Use sender's link-local address as from_neighbor
        # Why fe80:: prefix: Link-local is the "neighbor" address.
        from_neighbor = IPv6Address(
            bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + sender.iid
        )

        # Get current time in ms (in production, use monotonic clock)
        now_ms = int(asyncio.get_running_loop().time() * 1000)

        previous_candidate = self._announce_address_candidate
        self._announce_address_candidate = (
            announce.originator_iid,
            yggdrasil_address(announce.pubkey),
        )
        try:
            result = self.announce_processor.process(announce, from_neighbor, now_ms)
        finally:
            self._announce_address_candidate = previous_candidate

        if result.accepted:
            # Add peer to database if new
            if result.peer:
                try:
                    self.add_peer(result.peer)
                except (PeerDatabaseFullError, PeerIdentityCollisionError) as exc:
                    self.gradient_table.remove(yggdrasil_address(result.peer.pubkey))
                    self.announce_processor._restore_reconciliation_permit(
                        announce.originator_iid,
                        announce.pubkey,
                        announce.seq_num,
                    )
                    logger.warning("announce peer admission rejected: %s", exc)
                    return

            # Track peer's RX channel for CCP-9 rendezvous
            self._peer_rx_channel[announce.originator_iid] = _PeerRxChannel(
                channel=announce.rx_channel,
                expires_ms=now_ms + GRADIENT_TIMEOUT_MS,
            )

            # Relay if needed
            if result.should_relay:
                await self._relay_announce(announce)

    async def _relay_announce(self, announce: AnnounceMessage) -> None:
        """Relay an announce to neighbors.

        Why separate method: Relay involves incrementing hop count and resending.
        Relays are sent on control channel (CH0) so unknown neighbors can hear.
        """
        relay = self.announce_processor.get_relay_message(announce)
        if relay is None:
            return

        success = await self.link.send(wrap_routing_payload(relay.to_bytes()))
        if success:
            logger.debug("relayed announce from %s", announce.originator_iid.hex())

    async def _send_announce(self) -> None:
        """Send our own announce message.

        Why separate method: Allows testing and manual triggering.
        Delegates to scheduler for announce building (signing, seq_num).
        Announces sent on control channel (CH0) per CCP-9.
        """
        announce = self._scheduler.build_announce()
        data = wrap_routing_payload(announce.to_bytes())
        success = await self.link.send(data)
        if success:
            logger.info("sent announce seq=%d", announce.seq_num)

    @property
    def _announce_seq(self) -> int:
        """Current announce sequence number (for backwards compatibility).

        Why property: Tests expect node._announce_seq. Delegate to scheduler.
        """
        return self._scheduler.get_seq_num()

    async def send(self, ipv6_bytes: bytes) -> bool:
        """Send a raw IPv6 datagram through the SCHC + routing stack.

        Args:
            ipv6_bytes: A complete IPv6 datagram (e.g. IPv6 + UDP + CoAP).
                        Use coap.node_channel.NodeChannel to build this from CoAP.

        Returns:
            True if forwarded to the link layer, False if routed to drop.
        """
        try:
            packet = IPv6Packet.from_bytes(ipv6_bytes, strict=True)
        except Exception:
            logger.warning("send: failed to parse IPv6 packet")
            return False

        now_ms = int(asyncio.get_running_loop().time() * 1000)
        decision, next_hop = self.router.route(packet, now_ms)

        if decision == RouteDecision.FORWARD:
            peer = self._peer_for_next_hop(next_hop)
            if peer is None:
                logger.warning("send: resolved next hop has no pinned peer identity")
                return False
            try:
                schc = self.link.compress_schc_for_peer(
                    ipv6_bytes,
                    peer.pubkey,
                    allow_fragmentation=True,
                )
            except (SchcError, TypeError, ValueError) as exc:
                logger.warning("send: peer SCHC policy rejected packet: %s", exc)
                return False
            if not await self._transmit_peer_schc(schc, peer):
                return False
            self._remember_relay(_relay_identity(packet), now_ms)
            return True
        if decision == RouteDecision.DELIVER_LOCAL:
            try:
                wrapped = wrap_schc_payload(compress_packet(ipv6_bytes))
            except (SchcError, TypeError, ValueError) as exc:
                logger.warning("send: local SCHC policy rejected packet: %s", exc)
                return False
            if self._on_receive:
                self._on_receive(wrapped, PeerIdentity.from_pubkey(self.identity.pubkey))
            return True
        return False

    def scheduled_send(
        self,
        data: bytes,
        min_delay_ms: int | None = None,
        max_delay_ms: int | None = None,
    ) -> asyncio.Task[bool]:
        """Schedule a transmission after a random jitter delay.

        Why jitter: RREQ rebroadcast uses jitter to reduce collision probability
        when multiple nodes forward the same RREQ (LOADng spec).

        Args:
            data: Routing/control message body to transmit via link layer.
            min_delay_ms: Minimum delay in milliseconds. Defaults to config.rreq_jitter_min_ms.
            max_delay_ms: Maximum delay in milliseconds. Defaults to config.rreq_jitter_max_ms.

        Returns:
            The asyncio Task that will perform the delayed send.
        """
        if min_delay_ms is None:
            min_delay_ms = self.config.rreq_jitter_min_ms
        if max_delay_ms is None:
            max_delay_ms = self.config.rreq_jitter_max_ms

        min_delay_ms = _validated_timing_ms("min_delay_ms", min_delay_ms, minimum=0)
        max_delay_ms = _validated_timing_ms("max_delay_ms", max_delay_ms, minimum=0)
        if min_delay_ms > max_delay_ms:
            raise ValueError("min_delay_ms must not exceed max_delay_ms")

        delay_ms = random.randint(min_delay_ms, max_delay_ms)

        async def _delayed_send() -> bool:
            try:
                await asyncio.sleep(delay_ms / 1000)
                return await self.link.send(wrap_routing_payload(data))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("scheduled_send: link.send failed (delay=%dms)", delay_ms)
                raise

        return asyncio.create_task(
            _delayed_send(),
            name=f"scheduled-send-{delay_ms}ms",
        )

    def get_status(self) -> dict[str, object]:
        """Get node status for debugging/monitoring.

        Returns:
            Dict with node state, peer count, gradient count, etc.
            Includes `uptime` and `firmware` for Rust TUI compatibility.
        """
        # ponytail: uptime from event loop time, good enough for sim
        try:
            loop = asyncio.get_running_loop()
            uptime_secs = int(loop.time())
        except RuntimeError:
            uptime_secs = 0
        return {
            "iid": self.identity.iid.hex(),
            "pubkey": self.identity.pubkey.hex()[:16] + "...",
            "state": self.state.name,
            "peers": len(self.peer_db),
            "gradients": len(self.gradient_table),
            "announce_seq": self._scheduler.get_seq_num(),
            "uptime": uptime_secs,
            "firmware": "sim-0.1.0",
        }

    def get_queue_stats(self) -> dict[str, int]:
        """Get TX queue statistics for diagnostics.

        Returns:
            Dict with queue latency and drop counters per spec/appendix-bufferbloat.md.
            Fields:
                packets_queued: Total packets pushed to queue.
                packets_dropped_deadline: Packets expired before transmission.
                packets_dropped_full: Packets rejected due to full queue (backpressure).
                max_latency_ms: Worst-case time a packet spent in queue.
                avg_latency_ms: Smoothed average queue latency (EMA).
        """
        stats = self.link.tx_queue.stats
        return {
            "packets_queued": stats.packets_queued,
            "packets_dropped_deadline": stats.packets_dropped_deadline,
            "packets_dropped_full": stats.packets_dropped_full,
            "max_latency_ms": stats.max_latency_ms,
            "avg_latency_ms": stats.avg_latency_ms,
        }

    def get_neighbors(self) -> list[dict[str, object]]:
        """Get neighbor list for CoAP /neighbors resource.

        Returns:
            List of dicts with `addr` and `rssi` keys.
        """
        # ponytail: peer_db has IIDs, convert to link-local addresses
        neighbors = []
        for iid in self._peer_db:
            addr = IPv6Address(b"\xfe\x80\x00\x00\x00\x00\x00\x00" + iid)
            neighbors.append(
                {
                    "addr": str(addr),
                    "rssi": -100,  # ponytail: no per-peer RSSI tracking yet
                }
            )
        return neighbors

    def get_config(self) -> dict[str, int]:
        """Get node config for CoAP /config resource."""
        return {
            "receive_timeout_ms": self.config.receive_timeout_ms,
            "announce_interval_ms": self.config.announce_interval_ms,
        }

    _VALID_CONFIG_KEYS = frozenset({"receive_timeout_ms", "announce_interval_ms"})

    def set_config(self, updates: Mapping[str, object]) -> None:
        """Update node config from CoAP /config PUT.

        Raises:
            ValueError: If any key in updates is not a valid config key, or if
                receive_timeout_ms is not an exact bounded integer, or another
                numeric value is non-positive.
        """
        unknown = set(updates.keys()) - self._VALID_CONFIG_KEYS
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        receive_timeout_ms = self.config.receive_timeout_ms
        announce_interval_ms = self.config.announce_interval_ms
        if "receive_timeout_ms" in updates:
            raw = updates["receive_timeout_ms"]
            receive_timeout_ms = _validated_receive_timeout_ms(raw)
        if "announce_interval_ms" in updates:
            announce_interval_ms = _validated_timing_ms(
                "announce_interval_ms", updates["announce_interval_ms"], minimum=1
            )
        if "announce_interval_ms" in updates:
            self._scheduler.set_interval_ms(announce_interval_ms)
        self.config.receive_timeout_ms = receive_timeout_ms
        self.config.announce_interval_ms = announce_interval_ms
