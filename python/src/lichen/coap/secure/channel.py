# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""OSCORE-protected datagram channel implementation."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Any, TypeGuard, cast

import aiocoap  # type: ignore[import-untyped]  # no official stubs
from aiocoap import Message
from aiocoap.numbers.codes import EMPTY, POST  # type: ignore[import-untyped]
from aiocoap.numbers.types import ACK, CON, RST  # type: ignore[import-untyped]
from aiocoap.oscore import Direction  # type: ignore[import-untyped]

from lichen.crypto.edhoc import EdhocInitiator, OscoreContext
from lichen.crypto.oscore import MemorySecurityContext

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

    def send_datagram(self, data: bytes, dest: str) -> None:
        self._inner.send_datagram(data, dest)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            self._receiver = None

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def dispatch(self, data: bytes, source: str) -> None:
        """Dispatch received data to the registered receiver.

        Called by SecureDatagramChannel when EDHOC-related plaintext arrives.
        """
        if self._receiver is not None:
            self._receiver(data, source)

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
        self._inner = inner
        self._identity = identity
        if sequence_reservation_size <= 0:
            raise ValueError("sequence_reservation_size must be positive")
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
        self._pending_outbound: dict[tuple[str, bytes], _RequestCorrelation] = {}
        self._message_admissions: dict[int, tuple[str, _SendOperation]] = {}
        self._protected_cons: dict[tuple[str, int], _ProtectedCon] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closing = False
        self._inner_teardown_started = False
        self._shutdown_task: asyncio.Task[None] | None = None
        self._pid = os.getpid()

    def _check_process(self) -> None:
        self._context_store.check_process()
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            self._peer_locks = {}
            self._clear_lifecycle_state()
            self._pending_edhoc = {}
            self._edhoc_active_peers = set()
            self._edhoc_ctx = None
            self._edhoc_channel = None

    async def _get_peer_context(self, host: str) -> PeerContext | None:
        self._check_process()
        key = self._endpoint_key(host)
        context = await self._context_store.get(key)
        self._publish_peer_context(key, context)
        return context

    def _publish_peer_context(self, key: str, context: PeerContext | None) -> None:
        previous = self._active_peer_contexts.get(key)
        if previous is context:
            return
        if (
            previous is not None
            and context is not None
            and previous.generation == context.generation
        ):
            context.outbound_requests = previous.outbound_requests
            context.inbound_requests = previous.inbound_requests
            self._active_peer_contexts[key] = context
            return
        if previous is not None:
            self._abandon_peer_admissions(key)
            self._clear_context_lifecycle(previous)
        self._active_peer_contexts.pop(key, None)
        if previous is not None:
            self._pending_outbound = {
                pending_key: correlation
                for pending_key, correlation in self._pending_outbound.items()
                if pending_key[0] != key
            }
            for con_key in [
                con_key for con_key in self._protected_cons if con_key[0] == key
            ]:
                self._protected_cons.pop(con_key, None)
        if context is not None:
            self._active_peer_contexts[key] = context

    def _clear_context_lifecycle(self, context: PeerContext) -> None:
        for correlation in context.outbound_requests.values():
            self._cancel_cancellation_timer(correlation)
        context.outbound_requests.clear()
        context.inbound_requests.clear()

    def _clear_peer_lifecycle(self, peer: str, context: PeerContext | None = None) -> None:
        self._abandon_peer_admissions(peer)
        active = self._active_peer_contexts.pop(peer, None)
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
        self._pending_outbound.clear()
        self._message_admissions.clear()
        self._protected_cons.clear()

    def _abandon_peer_admissions(self, peer: str) -> None:
        context = self._active_peer_contexts.get(peer)
        for message_id, (admission_peer, operation) in tuple(
            self._message_admissions.items()
        ):
            if admission_peer == peer:
                self._message_admissions.pop(message_id, None)
                self._finish_send_operation(peer, context, operation)

    def _track_task(
        self, coroutine: Any, on_done: ReceiveCallback | None = None
    ) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)

        def done(completed: asyncio.Task[Any]) -> None:
            self._tasks.discard(completed)
            if on_done is not None:
                on_done()
            if not completed.cancelled():
                completed.exception()

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
        self, delay: float, callback: ReceiveCallback
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
        if self._closing:
            return None
        key = self._endpoint_key(peer)
        correlation = None
        locally_originated = message.code.is_request()
        if locally_originated:
            if len(self._pending_outbound) >= self._MAX_PENDING_OUTBOUND:
                return None
            correlation = _RequestCorrelation(
                None, observe=message.opt.observe == 0
            )
            self._pending_outbound[(key, message.token)] = correlation
        elif message.code.is_response():
            context = self._active_peer_contexts.get(key)
            if context is not None:
                correlation = context.inbound_requests.get(message.token)
        if correlation is None:
            return None
        correlation.pending_sends += 1
        self._message_admissions[id(message)] = (
            key,
            _SendOperation(correlation, message.token, locally_originated),
        )
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
        self._finish_send_operation(
            key, self._active_peer_contexts.get(key), operation
        )

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
        delay = max(0.0, exchange_lifetime)
        correlation.cancellation_deadline = asyncio.get_running_loop().time() + delay
        correlation.cancellation_timer = self._schedule_cancellation_expiry(
            delay,
            lambda: self._expire_cancelled_observation(
                key, context.generation, token, correlation
            ),
        )

    def response_completed(
        self, peer: str, token: bytes, lifecycle_id: object | None
    ) -> None:
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

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            if self._inner_receiver_registered:
                self._inner.clear_receiver(self._on_datagram)
                self._inner_receiver_registered = False
            self._receiver = None

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def normalize_endpoint(self, endpoint: str | Endpoint) -> Endpoint:
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
        """
        if len(data) < 4:
            return False
        token_len = data[0] & 0x0F
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
                delta = int.from_bytes(data[pos + 1:pos + 3], "big") + 269
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
                slice_len = data[pos + 1 + skip] + 13
                skip_value = 1
            elif option_len == 14:
                slice_len = int.from_bytes(
                    data[pos + 1 + skip:pos + 3 + skip], "big"
                ) + 269
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
                plaintext = await self._unprotect(msg, source)
                if plaintext is not None and self._receiver is not None:
                    self._receiver(plaintext, source)
            elif source in self._edhoc_active_peers:
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
                    if self._receiver is not None:
                        self._receiver(data, source)
                elif self._require_oscore:
                    logger.warning("Rejected plaintext message from %s (OSCORE required)", source)
                elif self._receiver is not None:
                    self._receiver(data, source)

        except Exception as e:
            logger.debug("Failed to process datagram from %s: %s", source, e)
            # Drop malformed datagrams

    async def _unprotect(self, msg: Message, source: str) -> bytes | None:
        """Unprotect an OSCORE-encrypted message.

        Returns the plaintext CoAP bytes, or None if unprotection fails.
        """
        result = await self._unprotect_datagram(msg, source)
        return None if result is None else result.data

    async def _unprotect_datagram(
        self, msg: Message, source: str
    ) -> _UnprotectedDatagram | None:
        """Unprotect and stage correlation state for synchronous dispatch."""
        key = self._endpoint_key(source)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closing:
                return None
            peer_ctx = await self._get_peer_context(key)
            if peer_ctx is None:
                logger.warning("No OSCORE context for %s, dropping message", source)
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
                    unprotected_msg.mid = msg.mid
                if unprotected_msg.remote is None:
                    unprotected_msg.remote = msg.remote
                unprotected_msg.token = msg.token
                # aiocoap encode() requires direction == OUTGOING. This is
                # semantically INCOMING but the Message object with direction
                # is never returned to callers — we return bytes (encoded).
                # The direction leak is contained within this method.
                unprotected_msg.direction = Direction.OUTGOING

                encoded = cast(bytes, unprotected_msg.encode())
                added_correlation = None
                if not msg.code.is_response() and new_request_id is not None:
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
            except Exception as e:
                logger.warning("OSCORE unprotection failed for %s: %r", source, e)
                return None

    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send a datagram, protecting with OSCORE if context exists.

        If no OSCORE context exists for dest, this will trigger EDHOC
        handshake (if peer resolver can provide their public key).
        """
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest)
        operation = self._prepare_send_operation(data, dest, key)
        self._schedule_send(data, dest, key, operation)

    def send_message(self, message: Message, dest: str) -> None:
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
                return
        else:
            operation = None
            if hasattr(message, "_lichen_lifecycle_id"):
                return
            if operation is None:
                operation = self._prepare_send_operation(data, dest, key)
        if operation is not None and message.mtype is CON:
            self._stage_con(
                key,
                message,
                data,
                operation.correlation,
                operation.locally_originated,
            )
        if (
            operation is not None
            and operation.locally_originated
            and not operation.correlation.interested
        ):
            self._finish_send_operation(
                key, self._active_peer_contexts.get(key), operation
            )
            return
        self._schedule_send(data, dest, key, operation)

    def _schedule_send(
        self,
        data: bytes,
        dest: str,
        key: str,
        operation: _SendOperation | None,
    ) -> None:
        self._track_task(
            self._send_protected(data, dest, key, operation),
            lambda: self._finish_send_operation(
                key, self._active_peer_contexts.get(key), operation
            ),
        )

    def _prepare_send_operation(
        self, data: bytes, dest: str, key: str
    ) -> _SendOperation | None:
        try:
            message = Message.decode(data, LichenRemote(dest))
        except Exception:
            return None
        if message.code.is_request():
            cached = (
                self._protected_cons.get((key, message.mid))
                if message.mtype is CON
                else None
            )
            if (
                cached is not None
                and cached.locally_originated
                and cached.plaintext == data
                and cached.correlation is not None
            ):
                correlation = cached.correlation
            else:
                if len(self._pending_outbound) >= self._MAX_PENDING_OUTBOUND:
                    return None
                correlation = _RequestCorrelation(
                    None, observe=message.opt.observe == 0
                )
                self._pending_outbound[(key, message.token)] = correlation
            if message.mtype is CON:
                self._stage_con(key, message, data, correlation, True)
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
    ) -> None:
        """Send with OSCORE protection (async implementation)."""
        if self._closing:
            return
        self._check_process()
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest) if key is None else key
        if operation is None:
            operation = self._prepare_send_operation(data, dest, key)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            peer_ctx: PeerContext | None = None
            try:
                if self._closing:
                    return
                remote = LichenRemote(dest)
                msg = Message.decode(data, remote)
                msg.direction = Direction.OUTGOING

                if msg.code is EMPTY and msg.mtype in (ACK, RST):
                    self._inner.send_datagram(data, dest)
                    return

                peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    await self._establish_context(dest, key)
                    peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    raise RuntimeError("context lost after establishment")

                if operation is not None:
                    correlations = self._correlations(
                        peer_ctx, operation.locally_originated
                    )
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
                    self._inner.send_datagram(cached.data, dest)
                    if (
                        cached.locally_originated
                        and cached.correlation is not None
                        and cached.correlation.interested
                        and self._pending_outbound.get((key, cached.token))
                        is cached.correlation
                    ):
                        peer_ctx.outbound_requests[cached.token] = cached.correlation
                        self._pending_outbound.pop((key, cached.token), None)
                    return
                if cached is not None and cached.plaintext != data:
                    if cached.correlation is not None:
                        cached.correlation.con_mids.discard(msg.mid)
                        if not cached.locally_originated:
                            self._retire_inbound_if_done(
                                peer_ctx, cached.token, cached.correlation
                            )
                    self._protected_cons.pop(con_key, None)

                if not peer_ctx.oscore.has_reserved_sender_sequence:
                    reservation = await self._context_store.reserve_sender_sequences(
                        key, peer_ctx.generation, self._sequence_reservation_size
                    )
                    peer_ctx.oscore.set_sender_sequence_reservation(
                        reservation.start, reservation.end
                    )
                self._check_process()
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
                self._inner.send_datagram(protected_data, dest)

                if (
                    locally_originated
                    and correlation is not None
                    and correlation.interested
                    and self._pending_outbound.get((key, msg.token)) is correlation
                ):
                    peer_ctx.outbound_requests[msg.token] = correlation
                    self._pending_outbound.pop((key, msg.token), None)

            except Exception as e:
                logger.error("Failed to protect message for %s: %s", key, e)
            finally:
                self._finish_send_operation(key, peer_ctx, operation)

    async def _establish_context(self, dest: str, key: str) -> None:
        """Establish an OSCORE context with a peer via EDHOC.

        This implements lazy EDHOC establishment per spec section 8.8.
        """
        # Check if handshake already in progress
        if key in self._pending_edhoc:
            await self._pending_edhoc[key]
            return

        await self._peer_resolver.ensure_bound()

        # Get peer's public key
        peer_pubkey = await self._peer_resolver.get_peer_pubkey(key)
        if peer_pubkey is None:
            raise ValueError(f"Unknown peer: {dest}")

        # Create a future for others to wait on
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending_edhoc[key] = future

        # Mark peer as having active EDHOC (allow plaintext responses)
        self._edhoc_active_peers.add(dest)

        try:
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
            self._edhoc_active_peers.discard(dest)

    async def _get_edhoc_context(self) -> aiocoap.Context:
        """Get or create a temporary CoAP context for EDHOC exchange.

        EDHOC messages are sent as raw CoAP (not OSCORE-protected) over
        the inner channel. This context is separate from the main CoAP
        context that uses OSCORE.
        """
        if self._edhoc_ctx is None:
            if self._local_host is None:
                raise ValueError(
                    "local_host required for EDHOC exchange; "
                    "pass local_host to SecureDatagramChannel"
                )
            # Create a dedicated channel for EDHOC that bypasses OSCORE
            # We use a wrapper that just forwards to the inner channel
            self._edhoc_channel = _EdhocChannel(self._inner)
            self._edhoc_ctx = aiocoap.Context()
            await self._edhoc_ctx._append_tokenmanaged_messagemanaged_transport(
                lambda mm: LichenTransport.create(
                    mm,
                    self._edhoc_channel,
                    self.normalize_endpoint(self._local_host).authority,
                )
            )
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
            raise ValueError(f"EDHOC exchange with {dest} timed out") from None
        except Exception as e:
            raise ValueError(f"EDHOC exchange with {dest} failed: {e}") from e

        if not response.code.is_successful():
            raise ValueError(f"EDHOC exchange with {dest} returned error: {response.code}")

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
            asyncio.create_task(edhoc_ctx.shutdown())
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
        if isinstance(oscore_ctx, OscoreContext):
            oscore_ctx = MemorySecurityContext.from_edhoc(oscore_ctx)
        await self._peer_resolver.ensure_bound()
        key = self._endpoint_key(host)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
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
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closing:
                raise RuntimeError("secure datagram channel is closing")
            await self._context_store.remove(key)
            self._publish_peer_context(key, None)

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
