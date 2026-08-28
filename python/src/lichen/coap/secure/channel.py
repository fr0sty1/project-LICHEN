# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""OSCORE-protected datagram channel implementation."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeGuard, cast

import aiocoap
from aiocoap import Message
from aiocoap.numbers.codes import EMPTY, POST
from aiocoap.numbers.types import ACK, CON, RST
from aiocoap.oscore import Direction

from lichen.crypto.edhoc import EdhocInitiator, OscoreContext
from lichen.crypto.oscore import MemorySecurityContext
from lichen.link.tx_queue import Priority

from ..transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    LichenRemote,
    LichenTransport,
    ReceiveCallback,
)
from .memory_store import OscoreContextStore
from .resolvers import EdhocPeerResolver, TofuPeerResolver
from .types import (
    PeerContext,
    ReplayWindowConflictError,
    TransactionalOscoreContextStore,
    _ProtectedCon,
    _RequestCorrelation,
    _SendOperation,
    _UnprotectedDatagram,
)

if TYPE_CHECKING:
    from lichen.crypto.identity import Identity

logger = logging.getLogger(__name__)


class _EdhocChannel(DatagramChannel):
    """A channel wrapper for EDHOC exchange that bypasses OSCORE.

    EDHOC messages are sent as raw CoAP over the inner channel. This
    wrapper ensures EDHOC traffic doesn't get OSCORE-protected (which
    would fail since we don't have a context yet).

    The SecureDatagramChannel holds a reference to this channel and
    dispatches EDHOC-related plaintext to it.
    """

    def __init__(self, inner: DatagramChannel) -> None:
        self._inner = inner
        self._receiver: ReceiveCallback | None = None
        # SECURITY: Lock for atomic check-and-set in set_receiver (defense-in-depth).
        # Uses threading.Lock (not asyncio.Lock) because:
        # 1. This class is designed for single-threaded async use only
        # 2. The lock guards synchronous set_receiver/clear_receiver mutations
        # 3. threading.Lock is simpler and avoids requiring an event loop at init
        self._receiver_lock = threading.Lock()

    def send_datagram(
        self,
        data: bytes,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        self._inner.send_datagram(data, dest, priority=priority, check_congestion=check_congestion)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        with self._receiver_lock:
            if self._receiver is not None:
                raise RuntimeError("channel already has a receiver")
            self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> bool:
        with self._receiver_lock:
            if self._receiver == receiver:
                self._receiver = None
                return True
            return False

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def dispatch(self, data: bytes, source: str) -> None:
        """Dispatch received data to the registered receiver.

        Called by SecureDatagramChannel when EDHOC-related plaintext arrives.

        Note: Reading self._receiver without _receiver_lock is safe because:
        1. This class is designed for single-threaded async use only
        2. The lock guards set_receiver/clear_receiver mutations, not reads
        3. In Python's async model, reads and writes to the same attribute
           within a single thread do not race; control yields only at await
        """
        receiver = self._receiver
        if receiver is not None:
            receiver(data, source)

    def close(self) -> None:
        pass  # Don't close the inner channel


class SecureDatagramChannel(DatagramChannel):
    """A DatagramChannel wrapper that applies OSCORE protection.

    Transparently encrypts outgoing datagrams and decrypts incoming ones
    using OSCORE security contexts. Contexts can be pre-provisioned or
    established via EDHOC on first contact.

    SECURITY: This channel requires OSCORE contexts to be established
    before messages can be exchanged. For lazy EDHOC establishment,
    the first send to an unknown peer will trigger handshake.

    Note on aiocoap integration:
        aiocoap's OSCORE machinery operates on Message objects with direction
        and request_id tracking. We handle this by:
        1. Decoding incoming bytes to Message with Direction.INCOMING
        2. On unprotect: getting a plaintext Message, re-encoding it
        3. On protect: decoding plaintext, setting Direction.OUTGOING, protecting

    Attributes:
        identity: Our cryptographic identity (for EDHOC signing).
        context_store: Storage for OSCORE contexts.
        peer_resolver: Resolver for peer public keys.
    """

    _MAX_PENDING_OUTBOUND = 4096
    _MAX_PROTECTED_CONS = 4096
    _MAX_ACTIVE_PEER_CONTEXTS = 2048
    _MAX_CONCURRENT_EDHOC = 64
    # SECURITY: RST rate-limiting to mitigate forged RST attacks
    _RST_RATE_LIMIT_WINDOW = 10.0  # seconds
    _RST_RATE_LIMIT_MAX = 20  # max RSTs per peer per window
    # SECURITY: Limit RST rate tracking entries to prevent memory exhaustion
    _MAX_RST_PEERS = 4096
    # SECURITY: Global RST rate limit to mitigate eviction-based rate bypass
    _GLOBAL_RST_RATE_LIMIT_MAX = 200  # max RSTs across all peers per window
    # SECURITY: Limit inbound requests per peer to prevent memory exhaustion
    _MAX_INBOUND_REQUESTS_PER_PEER = 256
    # Upper bound for exchange_lifetime to prevent unbounded resource retention
    _MAX_EXCHANGE_LIFETIME = 300.0  # seconds

    _STORE_METHODS = (
        "check_process",
        "get_sync",
        "get",
        "get_generation",
        "put",
        "put_sync",
        "reserve_sender_sequences",
        "compare_and_set_replay_window",
        "get_peer_pubkey",
        "pin_peer",
        "pin_peers",
        "migrate_endpoint_keys",
        "remove",
        "has_context_sync",
        "has_context",
    )

    def __init__(
        self,
        inner: DatagramChannel,
        identity: Identity,
        context_store: TransactionalOscoreContextStore | None = None,
        peer_resolver: EdhocPeerResolver | None = None,
        *,
        require_oscore: bool = True,
        local_host: str | None = None,
        edhoc_timeout: float = 30.0,
        sequence_reservation_size: int = 32,
    ) -> None:
        """Create a secure channel wrapping an inner channel.

        Args:
            inner: The underlying DatagramChannel.
            identity: Our Identity for signing EDHOC messages.
            context_store: Where to store OSCORE contexts. Created if None.
            peer_resolver: How to look up peer public keys. Uses TOFU if None.
            require_oscore: If True, reject plaintext messages. If False,
                allow passthrough for unprotected messages (useful for
                transitional deployments).
            local_host: Our host identifier for CoAP context (required for EDHOC).
            edhoc_timeout: Timeout in seconds for EDHOC message exchange.
        """
        if inner is None:
            raise TypeError("inner channel must not be None")
        if identity is None:
            raise TypeError("identity must not be None")
        self._inner = inner
        self._identity = identity
        if sequence_reservation_size <= 0:
            raise ValueError("sequence_reservation_size must be positive")
        if edhoc_timeout <= 0:
            raise ValueError("edhoc_timeout must be positive")
        candidate_store = context_store if context_store is not None else OscoreContextStore()
        missing = [
            method
            for method in self._STORE_METHODS
            if not callable(getattr(candidate_store, method, None))
        ]
        if missing or not isinstance(candidate_store, TransactionalOscoreContextStore):
            details = ", ".join(missing) if missing else "protocol-incompatible attributes"
            raise TypeError(f"incomplete OSCORE context store: {details}")
        candidate_resolver = peer_resolver if peer_resolver is not None else TofuPeerResolver()
        candidate_resolver.bind_authority(candidate_store, inner.endpoint_policy)
        self._context_store = candidate_store
        self._peer_resolver = candidate_resolver
        self._require_oscore = require_oscore
        self._local_host = local_host
        self._edhoc_timeout = edhoc_timeout
        self._receiver: ReceiveCallback | None = None
        self._inner_receiver_registered = False
        self._pending_edhoc: dict[str, asyncio.Future[None]] = {}
        # Temporary CoAP context and channel for EDHOC exchange (created lazily)
        self._edhoc_ctx: aiocoap.Context | None = None
        self._edhoc_channel: _EdhocChannel | None = None
        # Set of peers with active EDHOC exchange (allow plaintext from these)
        self._edhoc_active_peers: set[str] = set()
        self._sequence_reservation_size = sequence_reservation_size
        self._peer_locks: dict[str, asyncio.Lock] = {}
        self._active_peer_contexts: dict[str, PeerContext] = {}
        # LRU tracking via OrderedDict for O(1) move_to_end/popitem operations
        self._peer_context_lru: OrderedDict[str, None] = OrderedDict()
        self._pending_outbound: dict[tuple[str, bytes], _RequestCorrelation] = {}
        self._message_admissions: dict[int, tuple[str, _SendOperation]] = {}
        self._protected_cons: dict[tuple[str, int], _ProtectedCon] = {}
        # SECURITY: RST rate tracking per peer to mitigate forged RST attacks
        self._rst_rate_tracking: dict[str, list[float]] = {}
        # SECURITY: Global RST rate tracking to prevent eviction-based bypass
        self._global_rst_timestamps: list[float] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        # SECURITY: Lock for lazy EDHOC context initialization
        self._edhoc_ctx_lock = asyncio.Lock()
        self._closing = False
        self._inner_teardown_started = False
        self._shutdown_task: asyncio.Task[None] | None = None
        self._pid = os.getpid()
        # SECURITY: Fork generation counter to detect stale lock references
        self._fork_generation = 0

    # Maximum peer locks before cleanup is forced.
    # Bound: _MAX_ACTIVE_PEER_CONTEXTS (2048) + _MAX_CONCURRENT_EDHOC (64) = 2112
    _PEER_LOCKS_MAX = 2112

    def _check_process(self) -> None:
        self._context_store.check_process()
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            # SECURITY: Increment generation to invalidate any locks held by
            # coroutines that acquired them before the fork. Coroutines check
            # this generation after acquiring their lock; if it changed, they
            # know their lock is stale and must bail out.
            self._fork_generation += 1
            self._peer_locks = {}
            self._rst_rate_tracking = {}
            self._global_rst_timestamps = []
            self._tasks = set()
            self._clear_lifecycle_state()
            self._pending_edhoc = {}
            self._edhoc_active_peers = set()
            self._edhoc_ctx = None
            self._edhoc_channel = None
            self._edhoc_ctx_lock = asyncio.Lock()
        elif len(self._peer_locks) > self._PEER_LOCKS_MAX:
            self._cleanup_stale_peer_locks()

    def _cleanup_stale_peer_locks(self) -> None:
        """Remove locks for peers without active contexts or pending EDHOC.

        Only removes locks that are not currently held (locked() returns False).
        This prevents removing a lock while another coroutine is waiting for it.
        """
        stale_keys = [
            key
            for key, lock in self._peer_locks.items()
            if (
                key not in self._active_peer_contexts
                and key not in self._pending_edhoc
                and not lock.locked()
            )
        ]
        for key in stale_keys:
            self._peer_locks.pop(key, None)
            self._rst_rate_tracking.pop(key, None)

    def _check_rst_rate(self, peer_key: str) -> bool:
        """Check if RST from peer should be accepted under rate limiting.

        SECURITY: Mitigates forged RST attacks by limiting acceptance rate.
        Applies both per-peer and global rate limits. Global limit prevents
        attackers from evicting legitimate peers from tracking and then
        flooding them with RSTs.
        Returns True if the RST should be accepted, False if rate-limited.
        """
        now = asyncio.get_running_loop().time()
        window_start = now - self._RST_RATE_LIMIT_WINDOW

        # SECURITY: Check global RST rate limit first (prevents eviction bypass)
        self._global_rst_timestamps = [
            ts for ts in self._global_rst_timestamps if ts > window_start
        ]
        if len(self._global_rst_timestamps) >= self._GLOBAL_RST_RATE_LIMIT_MAX:
            logger.warning("Global RST rate limit exceeded, dropping RST from %s", peer_key)
            return False

        timestamps = self._rst_rate_tracking.get(peer_key, [])
        # Prune timestamps outside the window
        timestamps = [ts for ts in timestamps if ts > window_start]
        if len(timestamps) >= self._RST_RATE_LIMIT_MAX:
            logger.warning("RST rate limit exceeded for %s, dropping", peer_key)
            return False
        # SECURITY: Limit tracking entries to prevent memory exhaustion from
        # attackers forging RSTs from many source addresses. Eviction uses
        # staleness-based LRU to prevent attackers from evicting legitimate
        # peers by flooding with spoofed source addresses.
        if (
            peer_key not in self._rst_rate_tracking
            and len(self._rst_rate_tracking) >= self._MAX_RST_PEERS
        ):
            # First pass: look for fully stale entries (all timestamps expired)
            stale_key = None
            lru_key = None
            lru_max_ts = float("inf")
            for candidate_key, candidate_ts in self._rst_rate_tracking.items():
                if not candidate_ts:
                    # Empty list is fully stale
                    stale_key = candidate_key
                    break
                max_ts = max(candidate_ts)
                if max_ts <= window_start:
                    # All timestamps expired - fully stale
                    stale_key = candidate_key
                    break
                # Track LRU by most recent timestamp
                if max_ts < lru_max_ts:
                    lru_max_ts = max_ts
                    lru_key = candidate_key
            # Prefer stale entries; fall back to LRU if none are stale
            evict_key = stale_key if stale_key is not None else lru_key
            if evict_key is not None:
                self._rst_rate_tracking.pop(evict_key, None)
        timestamps.append(now)
        self._rst_rate_tracking[peer_key] = timestamps
        # Track global RST count
        self._global_rst_timestamps.append(now)
        return True

    async def _get_peer_context(self, host: str) -> PeerContext | None:
        self._check_process()
        key = self._endpoint_key(host)
        context = await self._context_store.get(key)
        self._publish_peer_context(key, context)
        return context

    def _publish_peer_context(self, key: str, context: PeerContext | None) -> None:
        previous = self._active_peer_contexts.get(key)
        if previous is context:
            # Update LRU position even for same context (access counts)
            self._touch_peer_lru(key)
            return
        if (
            previous is not None
            and context is not None
            and previous.generation == context.generation
        ):
            context.outbound_requests = previous.outbound_requests
            context.inbound_requests = previous.inbound_requests
            self._active_peer_contexts[key] = context
            self._touch_peer_lru(key)
            return
        if previous is not None:
            self._abandon_peer_admissions(key)
            self._clear_context_lifecycle(previous)
        self._active_peer_contexts.pop(key, None)
        self._remove_peer_lru(key)
        if previous is not None:
            self._pending_outbound = {
                pending_key: correlation
                for pending_key, correlation in self._pending_outbound.items()
                if pending_key[0] != key
            }
            for con_key in [con_key for con_key in self._protected_cons if con_key[0] == key]:
                self._protected_cons.pop(con_key, None)
        if context is not None:
            # SECURITY: Evict LRU peer context if limit reached
            self._evict_peer_contexts_if_needed()
            self._active_peer_contexts[key] = context
            self._touch_peer_lru(key)

    def _touch_peer_lru(self, key: str) -> None:
        """Move key to end of LRU (most recently used). O(1) via OrderedDict."""
        if key in self._peer_context_lru:
            self._peer_context_lru.move_to_end(key)
        else:
            self._peer_context_lru[key] = None

    def _remove_peer_lru(self, key: str) -> None:
        """Remove key from LRU. O(1) via OrderedDict."""
        self._peer_context_lru.pop(key, None)

    def _evict_peer_contexts_if_needed(self) -> None:
        """Evict least recently used peer contexts if limit exceeded."""
        while len(self._active_peer_contexts) >= self._MAX_ACTIVE_PEER_CONTEXTS:
            if not self._peer_context_lru:
                break
            # popitem(last=False) removes and returns the oldest (first) item
            evict_key, _ = self._peer_context_lru.popitem(last=False)
            # SECURITY: Defensive check for LRU/active context desynchronization.
            # If evict_key is not in _active_peer_contexts, log warning and continue
            # to avoid infinite loop from draining LRU without reducing active count.
            if evict_key not in self._active_peer_contexts:
                logger.warning("LRU desync: %s in LRU but not in active contexts", evict_key)
                continue
            evicted = self._active_peer_contexts.pop(evict_key, None)
            if evicted is not None:
                self._abandon_peer_admissions(evict_key)
                self._clear_context_lifecycle(evicted)
                # Clean up pending outbound requests for the evicted peer
                self._pending_outbound = {
                    key: correlation
                    for key, correlation in self._pending_outbound.items()
                    if key[0] != evict_key
                }
                # Clean up CON retransmit cache entries for the evicted peer
                for key in [key for key in self._protected_cons if key[0] == evict_key]:
                    self._protected_cons.pop(key, None)
                # Also clean up related state - only remove lock if not held
                lock = self._peer_locks.get(evict_key)
                if lock is not None and not lock.locked():
                    self._peer_locks.pop(evict_key, None)
                self._rst_rate_tracking.pop(evict_key, None)
                logger.debug("Evicted LRU peer context: %s", evict_key)

    def _clear_context_lifecycle(self, context: PeerContext) -> None:
        for correlation in context.outbound_requests.values():
            self._cancel_cancellation_timer(correlation)
        context.outbound_requests.clear()
        context.inbound_requests.clear()

    def _clear_peer_lifecycle(self, peer: str, context: PeerContext | None = None) -> None:
        self._abandon_peer_admissions(peer)
        active = self._active_peer_contexts.pop(peer, None)
        self._remove_peer_lru(peer)
        if context is not None:
            self._clear_context_lifecycle(context)
        if active is not None and active is not context:
            self._clear_context_lifecycle(active)
        self._pending_outbound = {
            key: correlation
            for key, correlation in self._pending_outbound.items()
            if key[0] != peer
        }
        for key in [key for key in self._protected_cons if key[0] == peer]:
            self._protected_cons.pop(key, None)

    def _clear_lifecycle_state(self) -> None:
        for peer in {peer for peer, _operation in self._message_admissions.values()}:
            self._abandon_peer_admissions(peer)
        for context in self._active_peer_contexts.values():
            self._clear_context_lifecycle(context)
        self._active_peer_contexts.clear()
        self._peer_context_lru.clear()
        self._pending_outbound.clear()
        self._message_admissions.clear()
        self._protected_cons.clear()

    def _abandon_peer_admissions(self, peer: str) -> None:
        context = self._active_peer_contexts.get(peer)
        for message_id, (admission_peer, operation) in tuple(self._message_admissions.items()):
            if admission_peer == peer:
                self._message_admissions.pop(message_id, None)
                self._finish_send_operation(peer, context, operation)

    def _track_task(self, coroutine: Any, on_done: Callable[[], None] | None = None) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)

        def done(completed: asyncio.Task[Any]) -> None:
            self._tasks.discard(completed)
            if on_done is not None:
                on_done()
            if not completed.cancelled() and (exc := completed.exception()):
                logger.debug("background task failed: %s", exc)

        task.add_done_callback(done)

    @staticmethod
    def _correlations(
        context: PeerContext, locally_originated: bool
    ) -> dict[bytes, _RequestCorrelation]:
        return context.outbound_requests if locally_originated else context.inbound_requests

    @staticmethod
    def _matches_lifecycle(
        correlation: _RequestCorrelation | None, lifecycle_id: object | None
    ) -> TypeGuard[_RequestCorrelation]:
        return correlation is not None and correlation.lifecycle_id is lifecycle_id

    @staticmethod
    def _cancel_cancellation_timer(correlation: _RequestCorrelation) -> None:
        if correlation.cancellation_timer is not None:
            correlation.cancellation_timer.cancel()
            correlation.cancellation_timer = None
        correlation.cancellation_deadline = None

    def _retire_outbound(
        self, context: PeerContext, token: bytes, correlation: _RequestCorrelation
    ) -> None:
        if context.outbound_requests.get(token) is correlation:
            context.outbound_requests.pop(token, None)
            self._cancel_cancellation_timer(correlation)

    def _schedule_cancellation_expiry(
        self, delay: float, callback: Callable[[], None]
    ) -> asyncio.TimerHandle:
        return asyncio.get_running_loop().call_later(delay, callback)

    def _expire_cancelled_observation(
        self,
        peer: str,
        generation: int,
        token: bytes,
        correlation: _RequestCorrelation,
    ) -> None:
        context = self._active_peer_contexts.get(peer)
        if (
            context is None
            or context.generation != generation
            or context.outbound_requests.get(token) is not correlation
        ):
            self._cancel_cancellation_timer(correlation)
            return
        correlation.cancellation_timer = None
        correlation.cancellation_deadline = None
        context.outbound_requests.pop(token, None)

    def _retire_inbound_if_done(
        self, context: PeerContext, token: bytes, correlation: _RequestCorrelation
    ) -> None:
        if context.inbound_requests.get(token) is not correlation:
            return
        ended_observation = correlation.observe and not correlation.interested
        if (
            correlation.pending_sends == 0
            and not correlation.con_mids
            and (correlation.terminal or ended_observation)
        ):
            context.inbound_requests.pop(token, None)

    def request_started(
        self, peer: str, token: bytes, *, locally_originated: bool
    ) -> object | None:
        key = self._endpoint_key(peer)
        if locally_originated:
            correlation = self._pending_outbound.get((key, token))
        else:
            context = self._active_peer_contexts.get(key)
            correlation = None if context is None else context.inbound_requests.get(token)
        return None if correlation is None else correlation.lifecycle_id

    def message_admitted(self, message: Message, peer: str) -> object | None:
        """Admit a message for lifecycle tracking.

        Raises:
            ValueError: If token is empty and there's already a pending request
                to the same peer with an empty token (collision prevention).
        """
        if self._closing:
            return None
        key = self._endpoint_key(peer)
        correlation = None
        locally_originated = message.code.is_request()
        if locally_originated:
            if len(self._pending_outbound) >= self._MAX_PENDING_OUTBOUND:
                raise RuntimeError("outbound request limit reached; apply backpressure")
            # SECURITY: Prevent empty token collision between concurrent requests
            # Check both _pending_outbound and context.outbound_requests
            context = self._active_peer_contexts.get(key)
            if message.token == b"" and (
                (key, b"") in self._pending_outbound
                or (context is not None and b"" in context.outbound_requests)
            ):
                raise ValueError("request rejected")
            correlation = _RequestCorrelation(None, observe=message.opt.observe == 0)
            self._pending_outbound[(key, message.token)] = correlation
        elif message.code.is_response():
            context = self._active_peer_contexts.get(key)
            if context is not None:
                correlation = context.inbound_requests.get(message.token)
        if correlation is None:
            return None
        # SECURITY: Assign to dict BEFORE incrementing pending_sends to avoid
        # orphaned state if the dict assignment fails (e.g., OOM)
        self._message_admissions[id(message)] = (
            key,
            _SendOperation(correlation, message.token, locally_originated),
        )
        correlation.pending_sends += 1
        return correlation.lifecycle_id

    def message_abandoned(self, message: Message) -> None:
        admission = self._message_admissions.pop(id(message), None)
        if admission is None:
            return
        key, operation = admission
        if (
            not operation.locally_originated
            and message.code.is_response()
            and message.opt.observe is None
        ):
            if not operation.finished:
                operation.finished = True
                operation.correlation.pending_sends -= 1
            return
        self._finish_send_operation(key, self._active_peer_contexts.get(key), operation)

    def request_interest_ended(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        *,
        locally_originated: bool,
    ) -> None:
        key = self._endpoint_key(peer)
        context = self._active_peer_contexts.get(key)
        if locally_originated:
            correlation = self._pending_outbound.get((key, token))
            if not self._matches_lifecycle(correlation, lifecycle_id) and context is not None:
                correlation = context.outbound_requests.get(token)
            if not self._matches_lifecycle(correlation, lifecycle_id):
                return
            correlation.interested = False
            if correlation.cancelled_observe:
                return
            if self._pending_outbound.get((key, token)) is correlation:
                self._pending_outbound.pop((key, token), None)
            if context is not None and context.outbound_requests.get(token) is correlation:
                self._retire_outbound(context, token, correlation)
            return

        if context is None:
            return
        correlation = context.inbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.interested = False
        self._retire_inbound_if_done(context, token, correlation)

    def observation_cancelled(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        exchange_lifetime: float,
    ) -> None:
        key = self._endpoint_key(peer)
        context = self._active_peer_contexts.get(key)
        correlation = self._pending_outbound.get((key, token))
        if not self._matches_lifecycle(correlation, lifecycle_id) and context is not None:
            correlation = context.outbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.interested = False
        correlation.cancelled_observe = True
        if context is None or correlation.cancellation_timer is not None:
            return
        delay = min(max(0.0, exchange_lifetime), self._MAX_EXCHANGE_LIFETIME)
        correlation.cancellation_deadline = asyncio.get_running_loop().time() + delay
        correlation.cancellation_timer = self._schedule_cancellation_expiry(
            delay,
            lambda: self._expire_cancelled_observation(key, context.generation, token, correlation),
        )

    def response_completed(self, peer: str, token: bytes, lifecycle_id: object | None) -> None:
        context = self._active_peer_contexts.get(self._endpoint_key(peer))
        if context is None:
            return
        correlation = context.inbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.terminal = True
        self._retire_inbound_if_done(context, token, correlation)

    def exchange_ended(self, peer: str, mid: int, *, reset: bool) -> None:
        key = (self._endpoint_key(peer), mid)
        cached = self._protected_cons.pop(key, None)
        if cached is None:
            return
        context = self._active_peer_contexts.get(key[0])
        if context is None:
            return
        correlations = self._correlations(context, cached.locally_originated)
        correlation = correlations.get(cached.token)
        if correlation is None or correlation is not cached.correlation:
            return
        correlation.con_mids.discard(mid)
        if reset:
            correlation.interested = False
        if (
            cached.locally_originated
            and not correlation.interested
            and not correlation.cancelled_observe
        ):
            self._retire_outbound(context, cached.token, correlation)
        elif not cached.locally_originated:
            self._retire_inbound_if_done(context, cached.token, correlation)

    def exchange_expired(self, peer: str, mid: int) -> None:
        self.exchange_ended(peer, mid, reset=True)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register a callback for received (unprotected) datagrams."""
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._inner.set_receiver(self._on_datagram)
        self._inner_receiver_registered = True
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> bool:
        if self._receiver == receiver:
            if self._inner_receiver_registered:
                self._inner.clear_receiver(self._on_datagram)
                self._inner_receiver_registered = False
            self._receiver = None
            return True
        return False

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def normalize_endpoint(self, endpoint: str | Endpoint) -> Endpoint:
        if not endpoint:
            raise ValueError("endpoint must not be empty")
        try:
            return self.endpoint_policy.normalize(endpoint)
        except ValueError as exc:
            raise ValueError(f"invalid endpoint: {exc}") from exc

    def _endpoint_key(self, endpoint: str | Endpoint) -> str:
        return self.normalize_endpoint(endpoint).authority

    @staticmethod
    def _has_oscore_option(data: bytes) -> bool:
        """Check if a CoAP datagram contains an OSCORE option without full decode.

        OSCORE is option number 9. In the CoAP option encoding, options are
        delta-encoded: the option delta is the cumulative sum of previous
        deltas. This method scans the option section (between the fixed header
        and payload marker 0xFF) for cumulative delta == 9, stopping early
        if the sum exceeds 9 or the payload marker is hit.

        Returns False for any datagram shorter than the 4-byte CoAP header.

        SECURITY: This check is not constant-time; processing latency varies
        based on message structure (option count and delta values). An attacker
        observing network timing could potentially infer whether messages
        contain an OSCORE option without decrypting. This is an acceptable
        trade-off for performance: the OSCORE option presence is visible in
        the unencrypted CoAP header anyway, and the performance benefit of
        avoiding full message decode for plaintext traffic outweighs the
        marginal information leakage.
        """
        if len(data) < 4:
            return False
        token_len = data[0] & 0x0F
        # SECURITY: RFC 7252 limits token length to 0-8 bytes; values 9-15 are reserved
        if token_len > 8:
            return False
        pos = 4 + token_len
        cum_delta = 0
        while pos < len(data):
            if data[pos] == 0xFF:
                break
            # Extended option delta if needed (13, 14)
            delta = data[pos] >> 4
            if delta == 13:
                if pos + 1 >= len(data):
                    return False
                delta = data[pos + 1] + 13
                skip = 1
            elif delta == 14:
                if pos + 2 >= len(data):
                    return False
                delta = int.from_bytes(data[pos + 1 : pos + 3], "big") + 269
                skip = 2
            elif delta == 15:
                return False
            else:
                skip = 0
            cum_delta += delta
            if cum_delta == 9:
                return True
            if cum_delta > 9:
                return False
            # Advance past option delta/len and option value
            option_len = data[pos] & 0x0F
            if option_len == 13:
                if pos + 1 + skip >= len(data):
                    return False
                slice_len = data[pos + 1 + skip] + 13
                skip_value = 1
            elif option_len == 14:
                if pos + 2 + skip >= len(data):
                    return False
                slice_len = int.from_bytes(data[pos + 1 + skip : pos + 3 + skip], "big") + 269
                skip_value = 2
            elif option_len == 15:
                return False
            else:
                slice_len = option_len
                skip_value = 0
            pos += 1 + skip + skip_value + slice_len
        return False

    def _on_datagram(self, data: bytes, source: str) -> None:
        """Handle an incoming datagram, unprotecting if OSCORE.

        This is synchronous since DatagramChannel callback is sync.
        We schedule async work for OSCORE processing.
        """
        if self._closing:
            return
        self._track_task(self._process_incoming(data, source))

    async def _process_incoming(self, data: bytes, source: str) -> None:
        """Process an incoming datagram asynchronously."""
        if self._closing:
            return
        try:
            remote = LichenRemote(source)

            # Fast-path: check for OSCORE marker before full decode
            # CoAP OSCORE option is Elective (0) at option number 9.
            # A minimal scan for option delta=9 before the payload marker
            # avoids a full Message decode for non-OSCORE traffic.
            has_oscore = self._has_oscore_option(data)

            if has_oscore:
                # Full decode needed for OSCORE unprotection
                msg = Message.decode(data, remote)
                msg.direction = Direction.INCOMING
                result = await self._unprotect_datagram(msg, source)
                if result is not None and self._receiver is not None:
                    peer_key = self._endpoint_key(source)
                    try:
                        self._receiver(result.data, source)
                    except Exception:
                        # Delivery failed: roll back the inbound mapping staged
                        # during unprotection so a peer retry starts fresh.
                        # Outbound correlations are kept so retransmitted
                        # responses still correlate after the retry.
                        added = result.added_correlation
                        if added is not None:
                            context = self._active_peer_contexts.get(peer_key)
                            if (
                                context is not None
                                and context.inbound_requests.get(msg.token) is added
                            ):
                                del context.inbound_requests[msg.token]
                        raise
                    # A terminal (non-observe) response successfully dispatched
                    # to the local client retires the outbound correlation now;
                    # on failure it is kept so peer retransmissions still match.
                    if result.message.code.is_response() and result.message.opt.observe is None:
                        context = self._active_peer_contexts.get(peer_key)
                        correlation = result.matched_correlation
                        if (
                            context is not None
                            and correlation is not None
                            and context.outbound_requests.get(msg.token) is correlation
                        ):
                            self._retire_outbound(context, msg.token, correlation)
            elif self._endpoint_key(source) in self._edhoc_active_peers:
                # EDHOC in progress with this peer - allow plaintext
                # (EDHOC responses are not OSCORE-protected).
                # Dispatch raw bytes to EDHOC channel where LichenTransport
                # will decode and route to the EDHOC CoAP context.
                logger.debug("Allowing plaintext from %s (EDHOC in progress)", source)
                if self._edhoc_channel is not None:
                    self._edhoc_channel.dispatch(data, source)
            else:
                # Non-OSCORE path: decode just enough to classify the message
                msg = Message.decode(data, remote)
                if msg.code is EMPTY and msg.mtype in (ACK, RST):
                    # SECURITY: Empty ACK/RST messages bypass OSCORE per RFC 7252/8613.
                    # An attacker can forge RST messages to cancel pending observations
                    # or disrupt request/response correlation. Mitigated with rate-limiting.
                    #
                    # ACKs are not rate-limited because:
                    # 1. ACKs cannot reset observations (less dangerous than RST)
                    # 2. Upper CoAP layer discards ACKs for unknown MIDs efficiently
                    # 3. The processing overhead is minimal (no state modification)
                    peer_key = self._endpoint_key(source)
                    if msg.mtype is RST and not self._check_rst_rate(peer_key):
                        return  # Rate-limited, drop the RST
                    if self._receiver is not None:
                        self._receiver(data, source)
                elif self._require_oscore:
                    logger.debug("Failed to process datagram from %s", source)
                elif self._receiver is not None:
                    self._receiver(data, source)

        except Exception:
            # SECURITY: Log generic message to avoid leaking internal state
            logger.debug("Failed to process datagram from %s", source)
            # Drop malformed datagrams

    async def _unprotect(self, msg: Message, source: str) -> bytes | None:
        """Unprotect an OSCORE-encrypted message.

        Returns the plaintext CoAP bytes, or None if unprotection fails.
        """
        result = await self._unprotect_datagram(msg, source)
        return None if result is None else result.data

    async def _unprotect_datagram(self, msg: Message, source: str) -> _UnprotectedDatagram | None:
        """Unprotect and stage correlation state for synchronous dispatch.

        Note: SecureDatagramChannel is designed for single-threaded async use
        only. The per-peer asyncio.Lock() is not thread-safe if accessed from
        multiple threads (e.g., via run_in_executor). Do not share instances
        across threads without external synchronization.
        """
        key = self._endpoint_key(source)
        # SECURITY: Capture fork generation before lock acquisition. If a fork
        # occurs while we hold the lock, the generation will change and our
        # lock reference becomes stale (points to the old _peer_locks dict).
        fork_gen = self._fork_generation
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # SECURITY: Check if fork happened during lock acquisition
            if self._fork_generation != fork_gen:
                return None  # Lock is stale, bail out
            if self._closing:
                return None
            peer_ctx = await self._get_peer_context(key)
            if peer_ctx is None:
                # SECURITY: Use generic message to avoid revealing context state
                logger.debug("Failed to process datagram from %s", source)
                return None

            try:
                request_id: object | None = None
                correlation: _RequestCorrelation | None = None
                if msg.code.is_response():
                    correlation = peer_ctx.outbound_requests.get(msg.token)
                    if correlation is not None:
                        request_id = correlation.request_id

                expected_replay_index, expected_replay_bitfield = (
                    peer_ctx.oscore.export_replay_window()
                )
                unprotected_msg, new_request_id = peer_ctx.oscore.unprotect(msg, request_id)
                replay_index, replay_bitfield = peer_ctx.oscore.export_replay_window()
                try:
                    await self._context_store.compare_and_set_replay_window(
                        key,
                        peer_ctx.generation,
                        peer_ctx.oscore.recipient_cryptographic_identity(),
                        expected_replay_index,
                        expected_replay_bitfield,
                        replay_index,
                        replay_bitfield,
                    )
                except ReplayWindowConflictError as error:
                    peer_ctx.oscore.restore_replay_window(*error.current_state)
                    raise
                except BaseException:
                    peer_ctx.oscore.restore_replay_window(
                        expected_replay_index, expected_replay_bitfield
                    )
                    raise
                if unprotected_msg.mtype is None:
                    unprotected_msg.mtype = msg.mtype
                if unprotected_msg.mid is None:
                    if msg.mid is None:
                        logger.warning("OSCORE-protected message has None mid from %s", source)
                    unprotected_msg.mid = msg.mid
                if unprotected_msg.remote is None:
                    unprotected_msg.remote = msg.remote
                unprotected_msg.token = msg.token
                # aiocoap encode() requires direction == OUTGOING for encoding.
                # We temporarily set it, encode, then restore the semantically
                # correct INCOMING direction since the message object is
                # returned in _UnprotectedDatagram for lifecycle checks.
                unprotected_msg.direction = Direction.OUTGOING
                encoded = cast(bytes, unprotected_msg.encode())
                unprotected_msg.direction = Direction.INCOMING
                added_correlation = None
                if not msg.code.is_response() and new_request_id is not None:
                    # SECURITY: Limit inbound requests per peer to prevent memory exhaustion
                    if len(peer_ctx.inbound_requests) >= self._MAX_INBOUND_REQUESTS_PER_PEER:
                        # SECURITY: Use generic message to avoid revealing rate-limit state
                        logger.debug("Failed to process datagram from %s", source)
                        return None
                    added_correlation = _RequestCorrelation(
                        new_request_id, observe=unprotected_msg.opt.observe == 0
                    )
                    peer_ctx.inbound_requests[msg.token] = added_correlation

                return _UnprotectedDatagram(
                    encoded,
                    unprotected_msg,
                    added_correlation,
                    correlation,
                )
            except Exception:
                # SECURITY: Use same generic message as other drop paths to prevent
                # attackers from distinguishing decryption failure vs missing context
                logger.debug("Failed to process datagram from %s", source)
                return None

    def send_datagram(
        self,
        data: bytes,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        """Send a datagram, protecting with OSCORE if context exists.

        If no OSCORE context exists for dest, this will trigger EDHOC
        handshake (if peer resolver can provide their public key).
        """
        if data is None or len(data) < 4:
            raise ValueError("data must be at least 4 bytes (CoAP header)")
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest)
        operation = self._prepare_send_operation(data, dest, key)
        self._schedule_send(data, dest, key, operation, priority, check_congestion)

    def send_message(
        self,
        message: Message,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        """Schedule an aiocoap message using its admission lifecycle identity."""
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest)
        try:
            data = cast(bytes, message.encode())
        except Exception:
            self.message_abandoned(message)
            raise
        operation: _SendOperation | None
        admission = self._message_admissions.pop(id(message), None)
        if admission is not None:
            admission_key, operation = admission
            if admission_key != key:
                self._finish_send_operation(
                    admission_key,
                    self._active_peer_contexts.get(admission_key),
                    operation,
                )
                logger.warning(
                    "message admitted for %s but sent to %s; dropping",
                    admission_key,
                    key,
                )
                return
        else:
            if hasattr(message, "_lichen_lifecycle_id"):
                return
            operation = self._prepare_send_operation(data, dest, key)
        if operation is not None and message.mtype is CON:
            try:
                self._stage_con(
                    key,
                    message,
                    data,
                    operation.correlation,
                    operation.locally_originated,
                )
            except Exception:
                self._finish_send_operation(key, self._active_peer_contexts.get(key), operation)
                raise
        if (
            operation is not None
            and operation.locally_originated
            and not operation.correlation.interested
        ):
            self._finish_send_operation(key, self._active_peer_contexts.get(key), operation)
            return
        self._schedule_send(data, dest, key, operation, priority, check_congestion)

    def _schedule_send(
        self,
        data: bytes,
        dest: str,
        key: str,
        operation: _SendOperation | None,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        self._track_task(
            self._send_protected(data, dest, key, operation, priority, check_congestion),
            lambda: self._finish_send_operation(
                key, self._active_peer_contexts.get(key), operation
            ),
        )

    def _prepare_send_operation(self, data: bytes, dest: str, key: str) -> _SendOperation | None:
        try:
            message = Message.decode(data, LichenRemote(dest))
        except Exception:
            return None
        if message.code.is_request():
            cached = self._protected_cons.get((key, message.mid)) if message.mtype is CON else None
            if (
                cached is not None
                and cached.locally_originated
                and cached.plaintext == data
                and cached.correlation is not None
            ):
                correlation = cached.correlation
            else:
                if len(self._pending_outbound) >= self._MAX_PENDING_OUTBOUND:
                    raise RuntimeError("outbound request limit reached; apply backpressure")
                # SECURITY: Prevent empty token collision between concurrent requests
                # Check both _pending_outbound and context.outbound_requests
                context = self._active_peer_contexts.get(key)
                if message.token == b"" and (
                    (key, b"") in self._pending_outbound
                    or (context is not None and b"" in context.outbound_requests)
                ):
                    raise ValueError(
                        "empty token collision: concurrent request to same peer with empty token"
                    )
                correlation = _RequestCorrelation(None, observe=message.opt.observe == 0)
            if message.mtype is CON:
                try:
                    self._stage_con(key, message, data, correlation, True)
                except Exception:
                    # Don't add to pending_outbound if staging failed
                    raise
            self._pending_outbound[(key, message.token)] = correlation
            correlation.pending_sends += 1
            return _SendOperation(correlation, message.token, True)
        if message.code.is_response():
            context = self._active_peer_contexts.get(key)
            response_correlation = (
                None if context is None else context.inbound_requests.get(message.token)
            )
            if response_correlation is not None:
                if message.mtype is CON:
                    self._stage_con(key, message, data, response_correlation, False)
                response_correlation.pending_sends += 1
                return _SendOperation(response_correlation, message.token, False)
        return None

    def _stage_con(
        self,
        key: str,
        message: Message,
        data: bytes,
        correlation: _RequestCorrelation,
        locally_originated: bool,
    ) -> None:
        # SECURITY: Reject malformed CON messages with None mid
        if message.mid is None:
            raise ValueError("CON message requires a valid mid")
        con_key = (key, message.mid)
        cached = self._protected_cons.get(con_key)
        if (
            cached is not None
            and cached.plaintext == data
            and cached.correlation is correlation
            and cached.locally_originated == locally_originated
        ):
            return
        if cached is not None and cached.correlation is not None:
            cached.correlation.con_mids.discard(message.mid)
            context = self._active_peer_contexts.get(key)
            if context is not None and not cached.locally_originated:
                self._retire_inbound_if_done(context, cached.token, cached.correlation)
        # SECURITY: Limit _protected_cons size to prevent memory exhaustion
        if (
            con_key not in self._protected_cons
            and len(self._protected_cons) >= self._MAX_PROTECTED_CONS
        ):
            # Evict oldest entry without active correlation state if possible
            evicted = False
            for candidate_key in list(self._protected_cons.keys()):
                candidate = self._protected_cons.get(candidate_key)
                if candidate is None:
                    continue
                # Skip entries with active correlation state
                if candidate.correlation is not None and (
                    candidate.correlation.pending_sends > 0 or candidate.correlation.con_mids
                ):
                    continue
                self._protected_cons.pop(candidate_key)
                # Note: con_mids is empty here (checked above), so no discard needed
                evicted = True
                break
            if not evicted:
                # All entries have active state; evict the one closest to
                # exchange timeout to minimize sequence-number waste.
                # Entries whose correlations will time out soonest are
                # least likely to need their cached protected bytes.
                best_key = None
                best_deadline: float | None = None
                for candidate_key in self._protected_cons:
                    candidate = self._protected_cons[candidate_key]
                    deadline = (
                        candidate.correlation.cancellation_deadline
                        if candidate.correlation is not None
                        else None
                    )
                    if best_key is None:
                        # First candidate
                        best_key = candidate_key
                        best_deadline = deadline
                    elif deadline is not None and (
                        best_deadline is None or deadline < best_deadline
                    ):
                        # Prefer entry with earlier deadline (will time out soonest)
                        best_key = candidate_key
                        best_deadline = deadline
                    # If both have no deadline, keep the first (oldest by insertion)
                if best_key is not None:
                    evicted_entry = self._protected_cons.pop(best_key)
                    if evicted_entry.correlation is not None:
                        evicted_entry.correlation.con_mids.discard(best_key[1])
        self._protected_cons[con_key] = _ProtectedCon(
            b"", message.token, locally_originated, correlation, data
        )
        correlation.con_mids.add(message.mid)

    def _finish_send_operation(
        self,
        key: str,
        context: PeerContext | None,
        operation: _SendOperation | None,
    ) -> None:
        if operation is None:
            return
        if operation.finished:
            return
        operation.finished = True
        correlation = operation.correlation
        correlation.pending_sends -= 1
        if operation.locally_originated:
            if not correlation.interested and not correlation.cancelled_observe:
                if self._pending_outbound.get((key, operation.token)) is correlation:
                    self._pending_outbound.pop((key, operation.token), None)
                if (
                    context is not None
                    and context.outbound_requests.get(operation.token) is correlation
                ):
                    self._retire_outbound(context, operation.token, correlation)
        elif context is not None:
            self._retire_inbound_if_done(context, operation.token, correlation)

    async def _send_protected(
        self,
        data: bytes,
        dest: str,
        key: str | None = None,
        operation: _SendOperation | None = None,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        """Send with OSCORE protection (async implementation)."""
        if self._closing:
            return
        self._check_process()
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest) if key is None else key
        if operation is None:
            operation = self._prepare_send_operation(data, dest, key)
        # SECURITY: Capture fork generation before lock acquisition. If a fork
        # occurs while we hold the lock, the generation will change and our
        # lock reference becomes stale (points to the old _peer_locks dict).
        fork_gen = self._fork_generation
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            peer_ctx: PeerContext | None = None
            try:
                # SECURITY: Check if fork happened during lock acquisition
                if self._fork_generation != fork_gen:
                    return  # Lock is stale, bail out
                if self._closing:
                    return
                remote = LichenRemote(dest)
                msg = Message.decode(data, remote)
                msg.direction = Direction.OUTGOING

                if msg.code is EMPTY and msg.mtype in (ACK, RST):
                    self._inner.send_datagram(
                        data, dest, priority=priority, check_congestion=check_congestion
                    )
                    return

                peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    await self._establish_context(dest, key)
                    peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    raise RuntimeError("context lost after establishment")

                if operation is not None:
                    correlations = self._correlations(peer_ctx, operation.locally_originated)
                    current = correlations.get(operation.token)
                    if operation.locally_originated:
                        pending = self._pending_outbound.get((key, operation.token))
                        if (
                            current is not operation.correlation
                            and pending is not operation.correlation
                        ):
                            return
                    elif current is not operation.correlation:
                        return

                con_key = (key, msg.mid)
                cached = self._protected_cons.get(con_key) if msg.mtype is CON else None
                if cached is not None and cached.plaintext == data and cached.data:
                    if operation is None or cached.correlation is not operation.correlation:
                        return
                    self._inner.send_datagram(
                        cached.data, dest, priority=priority, check_congestion=check_congestion
                    )
                    if (
                        cached.locally_originated
                        and cached.correlation is not None
                        and cached.correlation.interested
                        and self._pending_outbound.get((key, cached.token)) is cached.correlation
                    ):
                        peer_ctx.outbound_requests[cached.token] = cached.correlation
                        self._pending_outbound.pop((key, cached.token), None)
                    return
                if cached is not None and cached.plaintext != data:
                    if cached.correlation is not None:
                        cached.correlation.con_mids.discard(msg.mid)
                        if not cached.locally_originated:
                            self._retire_inbound_if_done(peer_ctx, cached.token, cached.correlation)
                    self._protected_cons.pop(con_key, None)

                if not peer_ctx.oscore.has_reserved_sender_sequence:
                    reservation = await self._context_store.reserve_sender_sequences(
                        key, peer_ctx.generation, self._sequence_reservation_size
                    )
                    if reservation.start >= reservation.end:
                        raise RuntimeError("invalid sequence reservation")
                    peer_ctx.oscore.set_sender_sequence_reservation(
                        reservation.start, reservation.end
                    )
                # Check for fork AFTER acquiring state but re-fetch peer_ctx
                # if state was cleared to avoid using orphaned references
                self._check_process()
                if peer_ctx is not None and key not in self._active_peer_contexts:
                    # Fork detected and state cleared; re-fetch context
                    peer_ctx = await self._get_peer_context(key)
                    if peer_ctx is None:
                        raise RuntimeError("context lost after fork detection")
                # Determine request_id for responses
                request_id = None
                inbound = peer_ctx.inbound_requests.get(msg.token)
                if msg.code.is_response() and inbound is not None:
                    request_id = inbound.request_id

                # Protect with OSCORE
                protected_msg, new_request_id = peer_ctx.oscore.protect(msg, request_id)

                # OSCORE creates a new message but doesn't preserve mtype/mid/remote.
                # Copy outer header fields from the original message for encoding.
                if protected_msg.mtype is None:
                    protected_msg.mtype = msg.mtype
                if protected_msg.mid is None:
                    protected_msg.mid = msg.mid
                if protected_msg.remote is None:
                    protected_msg.remote = msg.remote
                protected_msg.token = msg.token

                # Encode and send
                protected_data = cast(bytes, protected_msg.encode())
                correlation = None
                locally_originated = msg.code.is_request()
                if locally_originated and new_request_id is not None:
                    if operation is None:
                        raise RuntimeError("outgoing request has no lifecycle operation")
                    correlation = operation.correlation
                    correlation.request_id = new_request_id
                elif msg.code.is_response():
                    correlation = inbound
                if msg.mtype is CON:
                    staged = self._protected_cons.get(con_key)
                    if staged is None or staged.correlation is not correlation:
                        raise RuntimeError("CON lifecycle ownership changed during protection")
                    staged.data = protected_data
                self._inner.send_datagram(
                    protected_data, dest, priority=priority, check_congestion=check_congestion
                )

                if (
                    locally_originated
                    and correlation is not None
                    and correlation.interested
                    and self._pending_outbound.get((key, msg.token)) is correlation
                ):
                    peer_ctx.outbound_requests[msg.token] = correlation
                    self._pending_outbound.pop((key, msg.token), None)

            except Exception:
                # SECURITY: Log generic message to avoid leaking internal state
                logger.error("Failed to protect message for %s", key)
            finally:
                self._finish_send_operation(key, peer_ctx, operation)

    async def _establish_context(self, dest: str, key: str) -> None:
        """Establish an OSCORE context with a peer via EDHOC.

        This implements lazy EDHOC establishment per spec section 8.8.

        SECURITY: Register the pending future BEFORE any await to prevent
        race conditions where concurrent requests both pass the check and
        start parallel EDHOC handshakes with expired or conflicting state.

        Raises:
            RuntimeError: If concurrent EDHOC handshake limit is exceeded.
        """
        # Check if handshake already in progress
        if key in self._pending_edhoc:
            await self._pending_edhoc[key]
            return

        # SECURITY: Limit concurrent EDHOC handshakes to prevent memory exhaustion
        if len(self._pending_edhoc) >= self._MAX_CONCURRENT_EDHOC:
            raise RuntimeError(
                f"concurrent EDHOC handshake limit ({self._MAX_CONCURRENT_EDHOC}) exceeded"
            )

        # Create a future for others to wait on IMMEDIATELY before any await.
        # This prevents race conditions where concurrent requests both pass
        # the check above and start parallel EDHOC handshakes.
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending_edhoc[key] = future

        # Mark peer as having active EDHOC (allow plaintext responses)
        # Use key (normalized) for consistency with the membership check
        self._edhoc_active_peers.add(key)

        try:
            await self._peer_resolver.ensure_bound()

            # Get peer's public key
            peer_pubkey = await self._peer_resolver.get_peer_pubkey(key)
            if peer_pubkey is None:
                raise ValueError(f"Unknown peer: {dest}")

            # Run EDHOC as initiator
            initiator = EdhocInitiator.create(self._identity)

            # Message 1: Initiator -> Responder
            msg1 = initiator.create_message_1()

            # Send and wait for response
            msg2 = await self._edhoc_exchange(dest, msg1)

            # Process Message 2 and create Message 3
            msg3 = initiator.process_message_2(msg2, peer_pubkey)

            # Send Message 3
            await self._edhoc_send(dest, msg3)

            # Export OSCORE context
            edhoc_ctx = initiator.export_oscore()
            oscore_ctx = MemorySecurityContext.from_edhoc(edhoc_ctx)

            # Pin the peer key if using TOFU (do this BEFORE storing context
            # to avoid leaving invalid context if pin_peer raises on key mismatch)
            if isinstance(self._peer_resolver, TofuPeerResolver):
                await self._peer_resolver.pin_peer(dest, peer_pubkey)

            # Store the context (only after TOFU check passes)
            await self._context_store.put(dest, oscore_ctx, peer_pubkey)

            logger.info("Established OSCORE context with %s via EDHOC", dest)
            future.set_result(None)

        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            self._pending_edhoc.pop(key, None)
            self._edhoc_active_peers.discard(key)

    async def _get_edhoc_context(self) -> aiocoap.Context:
        """Get or create a temporary CoAP context for EDHOC exchange.

        EDHOC messages are sent as raw CoAP (not OSCORE-protected) over
        the inner channel. This context is separate from the main CoAP
        context that uses OSCORE.

        SECURITY: Uses lock to prevent race conditions where concurrent
        EDHOC handshakes could both create contexts before the async
        configuration completes.
        """
        async with self._edhoc_ctx_lock:
            if self._edhoc_ctx is None:
                if self._local_host is None:
                    raise ValueError(
                        "local_host required for EDHOC exchange; "
                        "pass local_host to SecureDatagramChannel"
                    )
                # Create a dedicated channel for EDHOC that bypasses OSCORE
                # We use a wrapper that just forwards to the inner channel
                # Use temporary variables to avoid leaving broken state if init fails
                edhoc_channel = _EdhocChannel(self._inner)
                edhoc_ctx = aiocoap.Context()
                await edhoc_ctx._append_tokenmanaged_messagemanaged_transport(
                    lambda mm: LichenTransport.create(
                        mm,
                        edhoc_channel,
                        self.normalize_endpoint(self._local_host).authority,
                    )
                )
                # Only assign to instance attributes after successful initialization
                self._edhoc_channel = edhoc_channel
                self._edhoc_ctx = edhoc_ctx
            return self._edhoc_ctx

    async def _edhoc_exchange(self, dest: str, msg: bytes) -> bytes:
        """Send EDHOC message and wait for response.

        Sends a CoAP POST to coap://[dest]/.well-known/edhoc with the
        EDHOC message as payload. Returns the response payload.

        Args:
            dest: Target host string.
            msg: EDHOC message bytes (Message 1 or Message 3).

        Returns:
            Response payload (Message 2 or empty for Message 3 response).

        Raises:
            ValueError: If EDHOC exchange fails.
        """
        dest = self.normalize_endpoint(dest).authority
        ctx = await self._get_edhoc_context()

        request = Message(
            code=POST,
            uri=f"{self.normalize_endpoint(dest).uri}/.well-known/edhoc",
            payload=msg,
        )

        try:
            response = await asyncio.wait_for(
                ctx.request(request).response,
                timeout=self._edhoc_timeout,
            )
        except TimeoutError:
            # SECURITY: Use generic error to avoid leaking timing information
            raise ValueError("EDHOC handshake failed") from None
        except Exception:
            # SECURITY: Use generic error to avoid exposing internal state
            raise ValueError("EDHOC handshake failed") from None

        if not response.code.is_successful():
            # SECURITY: Use generic error to avoid exposing response codes
            raise ValueError("EDHOC handshake failed")

        return response.payload or b""

    async def _edhoc_send(self, dest: str, msg: bytes) -> None:
        """Send EDHOC message without waiting for response.

        Used for the final Message 3 when we don't need to wait for
        a response (the context is already derived).
        """
        # For Message 3, we still do a full exchange to ensure delivery
        # The response is empty (2.04 Changed) but confirms receipt
        await self._edhoc_exchange(dest, msg)

    def close(self) -> None:
        """Close the channel."""
        for future in list(self._pending_edhoc.values()):
            if not future.done():
                future.cancel()
        self._pending_edhoc.clear()
        self._edhoc_active_peers.clear()
        edhoc_ctx = self._edhoc_ctx
        self._edhoc_ctx = None
        self._edhoc_channel = None
        if edhoc_ctx is not None:
            # Note: close() is fire-and-forget for EDHOC context shutdown.
            # The task is NOT added to self._tasks to avoid being cancelled by
            # _begin_teardown(). Call shutdown() for proper async cleanup.
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(edhoc_ctx.shutdown())

                def _edhoc_shutdown_done(completed: asyncio.Task[Any]) -> None:
                    # SECURITY: Retrieve exception to suppress "exception was never
                    # retrieved" warning and avoid hiding shutdown errors
                    if not completed.cancelled() and (exc := completed.exception()):
                        logger.debug("EDHOC context shutdown failed: %s", exc)

                task.add_done_callback(_edhoc_shutdown_done)
            except RuntimeError:
                # No running event loop - close() called from sync context.
                # EDHOC context shutdown is best-effort; skip if no loop.
                pass
        error: BaseException | None = None
        teardown_was_started = self._inner_teardown_started
        inner: DatagramChannel | None = None
        try:
            inner = self._begin_teardown()
        except BaseException as exc:
            error = exc
            if not teardown_was_started and self._inner_teardown_started:
                inner = self._inner
        if inner is not None:
            try:
                inner.close()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    async def shutdown(self) -> None:
        """Cancel and drain packet work before releasing the inner channel."""
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.create_task(self._shutdown_once())
        await asyncio.shield(self._shutdown_task)

    async def _shutdown_once(self) -> None:
        error: BaseException | None = None
        teardown_was_started = self._inner_teardown_started
        inner: DatagramChannel | None = None
        try:
            inner = self._begin_teardown()
        except BaseException as exc:
            error = exc
            if not teardown_was_started and self._inner_teardown_started:
                inner = self._inner

        tasks = tuple(self._tasks)
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except BaseException as exc:
                if error is None:
                    error = exc

        edhoc_ctx = self._edhoc_ctx
        self._edhoc_ctx = None
        self._edhoc_channel = None
        if edhoc_ctx is not None:
            try:
                await edhoc_ctx.shutdown()
            except BaseException as exc:
                if error is None:
                    error = exc

        try:
            self._clear_lifecycle_state()
        except BaseException as exc:
            if error is None:
                error = exc
        if inner is not None:
            try:
                await inner.shutdown()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    def _begin_teardown(self) -> DatagramChannel | None:
        if not self._closing:
            self._closing = True
            for task in tuple(self._tasks):
                task.cancel()
            self._clear_lifecycle_state()
            for future in list(self._pending_edhoc.values()):
                if not future.done():
                    future.cancel()
            self._pending_edhoc.clear()
            self._edhoc_active_peers.clear()
        if self._inner_teardown_started:
            return None
        self._inner_teardown_started = True
        if self._inner_receiver_registered:
            try:
                self._inner.clear_receiver(self._on_datagram)
            finally:
                self._inner_receiver_registered = False
                self._receiver = None
        else:
            self._receiver = None
        return self._inner

    # --- Context provisioning API ---

    def add_context_sync(
        self,
        host: str,
        oscore_ctx: OscoreContext | MemorySecurityContext,
        peer_pubkey: bytes,
    ) -> None:
        """Add a pre-provisioned OSCORE context (synchronous).

        Use this during setup before the event loop starts.
        """
        if not peer_pubkey:
            raise ValueError("peer_pubkey must not be empty")
        if isinstance(oscore_ctx, OscoreContext):
            oscore_ctx = MemorySecurityContext.from_edhoc(oscore_ctx)
        self._peer_resolver.ensure_bound_sync()
        key = self._endpoint_key(host)
        context = self._context_store.put_sync(key, oscore_ctx, peer_pubkey)
        self._publish_peer_context(key, context)

    async def add_context(
        self,
        host: str,
        oscore_ctx: OscoreContext | MemorySecurityContext,
        peer_pubkey: bytes,
    ) -> None:
        """Add a pre-provisioned OSCORE context for a peer.

        Use this when contexts are established out-of-band (e.g., via
        external key exchange or commissioning).

        Args:
            host: The peer's host string (IPv6 address).
            oscore_ctx: OSCORE context from EDHOC or pre-shared.
            peer_pubkey: Peer's Ed25519 public key.
        """
        if not peer_pubkey:
            raise ValueError("peer_pubkey must not be empty")
        if isinstance(oscore_ctx, OscoreContext):
            oscore_ctx = MemorySecurityContext.from_edhoc(oscore_ctx)
        await self._peer_resolver.ensure_bound()
        key = self._endpoint_key(host)
        # SECURITY: Capture fork generation before lock acquisition. If a fork
        # occurs while we hold the lock, the generation will change and our
        # lock reference becomes stale (points to the old _peer_locks dict).
        fork_gen = self._fork_generation
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # SECURITY: Check if fork happened during lock acquisition
            if self._fork_generation != fork_gen:
                raise RuntimeError("fork detected during lock acquisition")
            if self._closing:
                raise RuntimeError("secure datagram channel is closing")
            expected_generation = await self._context_store.get_generation(key)
            context = await self._context_store.put(
                key,
                oscore_ctx,
                peer_pubkey,
                expected_generation=expected_generation,
            )
            self._publish_peer_context(key, context)

    async def remove_context(self, host: str) -> None:
        """Remove a peer context after draining in-flight packet state."""
        key = self._endpoint_key(host)
        # SECURITY: Capture fork generation before lock acquisition. If a fork
        # occurs while we hold the lock, the generation will change and our
        # lock reference becomes stale (points to the old _peer_locks dict).
        fork_gen = self._fork_generation
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # SECURITY: Check if fork happened during lock acquisition
            if self._fork_generation != fork_gen:
                raise RuntimeError("fork detected during lock acquisition")
            if self._closing:
                raise RuntimeError("secure datagram channel is closing")
            await self._context_store.remove(key)
            self._publish_peer_context(key, None)
            # Note: Do not pop the lock here. Other coroutines may be waiting
            # on it, and popping would cause them to proceed with a new lock
            # while new callers get a different lock, causing unsynchronized
            # access. Let _cleanup_stale_peer_locks() handle cleanup.

    def has_context_sync(self, host: str) -> bool:
        """Check if we have an OSCORE context (synchronous)."""
        return self._context_store.has_context_sync(self._endpoint_key(host))

    async def has_context(self, host: str) -> bool:
        """Check if we have an OSCORE context for a peer."""
        return await self._context_store.has_context(self._endpoint_key(host))


def create_secure_channel(
    inner: DatagramChannel,
    identity: Identity,
    *,
    context_store: TransactionalOscoreContextStore | None = None,
    peer_resolver: EdhocPeerResolver | None = None,
    require_oscore: bool = True,
    local_host: str | None = None,
    edhoc_timeout: float = 30.0,
    sequence_reservation_size: int = 32,
) -> SecureDatagramChannel:
    """Create an OSCORE-protected DatagramChannel.

    This is the main entry point for adding security to a channel.

    Args:
        inner: The channel to wrap (InMemoryChannel, NodeChannel, etc.).
        identity: Our cryptographic identity.
        context_store: Optional custom context storage.
        peer_resolver: Optional custom peer resolution.
        require_oscore: Whether to reject plaintext messages.
        local_host: Our host identifier (required for EDHOC lazy establishment).
        edhoc_timeout: Timeout in seconds for EDHOC message exchange.
        sequence_reservation_size: Sender sequence numbers committed per block.

    Returns:
        A SecureDatagramChannel that encrypts/decrypts transparently.
    """
    return SecureDatagramChannel(
        inner,
        identity,
        context_store=context_store,
        peer_resolver=peer_resolver,
        require_oscore=require_oscore,
        local_host=local_host,
        edhoc_timeout=edhoc_timeout,
        sequence_reservation_size=sequence_reservation_size,
    )
