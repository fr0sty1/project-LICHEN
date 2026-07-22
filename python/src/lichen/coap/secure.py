# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""OSCORE-protected transport layer for LICHEN CoAP (spec section 8.7).

Provides transparent OSCORE encryption/decryption for CoAP datagrams.
Security contexts can be pre-provisioned or established via EDHOC.

Usage:
    # Wrap any DatagramChannel with OSCORE protection
    secure = SecureDatagramChannel(
        inner_channel,
        local_identity,
        context_store,
    )

    # Use with aiocoap as normal
    ctx = await create_lichen_context(secure, local_host)

Architecture:
    This module operates at the datagram layer, below aiocoap's message
    handling. When a datagram arrives, we:
    1. Parse enough to detect OSCORE option
    2. Unprotect using stored security context
    3. Pass plaintext to aiocoap

    On send, we:
    1. Receive plaintext from aiocoap
    2. Protect with OSCORE
    3. Send ciphertext via inner channel

    EDHOC key establishment (spec 8.8) runs as CoAP POSTs to
    /.well-known/edhoc before the first protected exchange.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import aiocoap
from aiocoap import Message
from aiocoap.numbers.codes import POST
from aiocoap.oscore import Direction

from lichen.crypto.edhoc import EdhocInitiator, OscoreContext
from lichen.crypto.oscore import MemorySecurityContext

from .transport import DatagramChannel, LichenRemote, LichenTransport, ReceiveCallback

if TYPE_CHECKING:
    from lichen.crypto.identity import Identity

logger = logging.getLogger(__name__)

# OSCORE option number (RFC 8613 Section 2)
OSCORE_OPTION_NUMBER = 9


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
        self._receiver = receiver

    def dispatch(self, data: bytes, source: str) -> None:
        """Dispatch received data to the registered receiver.

        Called by SecureDatagramChannel when EDHOC-related plaintext arrives.
        """
        if self._receiver is not None:
            self._receiver(data, source)

    def close(self) -> None:
        pass  # Don't close the inner channel


def _monotonic_time() -> float:
    """Get monotonic time, usable with or without event loop."""
    try:
        loop = asyncio.get_running_loop()
        return loop.time()
    except RuntimeError:
        # No running event loop, use time.monotonic()
        import time

        return time.monotonic()


<<<<<<< HEAD
=======
def _hash_32(sfn: int, key: int = 0) -> int:
    """FNV-1a 32-bit hash (matches C lichen_hash_32:502 and test/vectors/generate.py:1600).
    For OSCORE nonce check: _hash_32(seqno, int.from_bytes(nonce[0:8], 'big')) ^ LICHEN_SEED.
    See RFC8613 4.1, spec/06-security.md:15.3 for replay/nonce uniqueness.
    """
    lichen_seed = 0x4C494348454E  # "LICHEN" as u48 for seed (task requirement)
    h = 0x811C9DC5
    sfn = sfn ^ lichen_seed  # incorporate LICHEN per task
    for i in range(4):
        b = (sfn >> (i * 8)) & 0xFF
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    for i in range(8):
        b = (key >> (i * 8)) & 0xFF
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


>>>>>>> origin/integration/worker3-20260722
@dataclass
class PeerContext:
    """OSCORE context and metadata for a peer."""

    oscore: MemorySecurityContext
    peer_pubkey: bytes
    established_at: float = field(default_factory=_monotonic_time)
    # Track pending requests for response correlation
    pending_requests: dict[bytes, object] = field(default_factory=dict)


class OscoreContextStore:
    """Manages OSCORE security contexts keyed by peer host string.

    Thread-safe for concurrent access. Contexts are stored in memory;
    for persistent storage, subclass and override load/save hooks.

    Note: This class can be instantiated before the event loop starts.
    The internal lock is created lazily on first async access.
    """

    def __init__(self) -> None:
        self._contexts: dict[str, PeerContext] = {}
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (must be called from async context)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def get_sync(self, host: str) -> PeerContext | None:
        """Get OSCORE context for a peer (synchronous, for callbacks)."""
        return self._contexts.get(host)

    async def get(self, host: str) -> PeerContext | None:
        """Get OSCORE context for a peer, or None if not established."""
        async with self._get_lock():
            return self._contexts.get(host)

    async def put(self, host: str, oscore_ctx: MemorySecurityContext, peer_pubkey: bytes) -> None:
        """Store OSCORE context for a peer."""
        async with self._get_lock():
            self._contexts[host] = PeerContext(
                oscore=oscore_ctx,
                peer_pubkey=peer_pubkey,
            )

    def put_sync(self, host: str, oscore_ctx: MemorySecurityContext, peer_pubkey: bytes) -> None:
        """Store OSCORE context (synchronous)."""
        self._contexts[host] = PeerContext(
            oscore=oscore_ctx,
            peer_pubkey=peer_pubkey,
        )

    async def remove(self, host: str) -> None:
        """Remove OSCORE context for a peer."""
        async with self._get_lock():
            self._contexts.pop(host, None)

    def has_context_sync(self, host: str) -> bool:
        """Check if we have a context (synchronous)."""
        return host in self._contexts

    async def has_context(self, host: str) -> bool:
        """Check if we have a context for a peer."""
        async with self._get_lock():
            return host in self._contexts


class EdhocPeerResolver:
    """Resolves peer public keys for EDHOC authentication.

    Override this to implement custom peer discovery (TOFU, directory, etc.).
    """

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Get the Ed25519 public key for a peer host.

        Returns None if the peer is unknown. For TOFU, this would
        accept any peer on first contact and pin the key.
        """
        raise NotImplementedError("Subclass must implement peer resolution")


class TofuPeerResolver(EdhocPeerResolver):
    """Trust-On-First-Use peer resolution per spec section 8.6.

    Accepts any peer on first contact and pins their public key.

    Note: This class can be instantiated before the event loop starts.
    The internal lock is created lazily on first async access.
    """

    def __init__(self) -> None:
        self._pinned: dict[str, bytes] = {}
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (must be called from async context)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Get pinned public key for a peer."""
        async with self._get_lock():
            return self._pinned.get(host)

    async def pin_peer(self, host: str, pubkey: bytes) -> None:
        """Pin a peer's public key (TOFU)."""
        async with self._get_lock():
            if host in self._pinned:
                if self._pinned[host] != pubkey:
                    raise ValueError(
                        f"TOFU violation: peer {host} key changed (possible MITM or hardware swap)"
                    )
            else:
                self._pinned[host] = pubkey
                logger.info("TOFU: pinned key for %s", host)


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

    def __init__(
        self,
        inner: DatagramChannel,
        identity: Identity,
        context_store: OscoreContextStore | None = None,
        peer_resolver: EdhocPeerResolver | None = None,
        *,
        require_oscore: bool = True,
        local_host: str | None = None,
        edhoc_timeout: float = 30.0,
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
        self._context_store = context_store or OscoreContextStore()
        self._peer_resolver = peer_resolver or TofuPeerResolver()
        self._require_oscore = require_oscore
        self._local_host = local_host
        self._edhoc_timeout = edhoc_timeout
        self._receiver: ReceiveCallback | None = None
        self._pending_edhoc: dict[str, asyncio.Future[None]] = {}
        # Temporary CoAP context and channel for EDHOC exchange (created lazily)
        self._edhoc_ctx: aiocoap.Context | None = None
        self._edhoc_channel: _EdhocChannel | None = None
        # Set of peers with active EDHOC exchange (allow plaintext from these)
        self._edhoc_active_peers: set[str] = set()

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register a callback for received (unprotected) datagrams."""
        self._receiver = receiver
        self._inner.set_receiver(self._on_datagram)

    def _on_datagram(self, data: bytes, source: str) -> None:
        """Handle an incoming datagram, unprotecting if OSCORE.

        This is synchronous since DatagramChannel callback is sync.
        We schedule async work for OSCORE processing.
        """
        loop = asyncio.get_running_loop()
        loop.create_task(self._process_incoming(data, source))

    async def _process_incoming(self, data: bytes, source: str) -> None:
        """Process an incoming datagram asynchronously."""
        try:
            # Decode with a remote so aiocoap knows the source
            remote = LichenRemote(source)
            msg = Message.decode(data, remote)
            msg.direction = Direction.INCOMING
            has_oscore = msg.opt.oscore is not None

            if has_oscore:
                plaintext = await self._unprotect(msg, source)
                if plaintext is not None and self._receiver is not None:
                    self._receiver(plaintext, source)
            elif source in self._edhoc_active_peers:
                # EDHOC in progress with this peer - allow plaintext
                # (EDHOC responses are not OSCORE-protected)
                logger.debug("Allowing plaintext from %s (EDHOC in progress)", source)
                # Dispatch to EDHOC channel for response matching
                if self._edhoc_channel is not None:
                    self._edhoc_channel.dispatch(data, source)
            elif self._require_oscore:
                # Plaintext not allowed
                logger.warning("Rejected plaintext message from %s (OSCORE required)", source)
            elif self._receiver is not None:
                # Passthrough plaintext
                self._receiver(data, source)

        except Exception as e:
            logger.debug("Failed to process datagram from %s: %s", source, e)
            # Drop malformed datagrams

    async def _unprotect(self, msg: Message, source: str) -> bytes | None:
        """Unprotect an OSCORE-encrypted message.

        Returns the plaintext CoAP bytes, or None if unprotection fails.
        """
        peer_ctx = await self._context_store.get(source)
        if peer_ctx is None:
            logger.warning("No OSCORE context for %s, dropping message", source)
            return None

        try:
            # Determine if this is a request or response
            is_response = msg.code.is_response()

            # For responses, we need the request_id from when we sent the request.
            # Use atomic pop(key, None) to avoid race between concurrent tasks.
            request_id = None
            if is_response:
                request_id = peer_ctx.pending_requests.pop(msg.token, None)

            # Unprotect using aiocoap's OSCORE
            unprotected_msg, new_request_id = peer_ctx.oscore.unprotect(msg, request_id)

            # OSCORE creates a new message but doesn't preserve mtype/mid/remote.
            # Copy them from the outer message for proper encoding.
            # SECURITY: These are outer CoAP header fields, copied from the
            # protected message to allow re-encoding the plaintext.
            if unprotected_msg.mtype is None:
                unprotected_msg.mtype = msg.mtype
            if unprotected_msg.mid is None:
                unprotected_msg.mid = msg.mid
            if unprotected_msg.remote is None:
                unprotected_msg.remote = msg.remote
            # aiocoap's encode() asserts direction == OUTGOING. This message is
            # semantically INCOMING, but we must set OUTGOING to satisfy encode().
            # This is safe because we return bytes (not this Message object), so
            # the semantically-incorrect direction is never exposed to callers.
            # The Message object is discarded after encoding.
            unprotected_msg.direction = Direction.OUTGOING

            # If this is a request, store request_id for the response
            if not is_response and new_request_id is not None:
                peer_ctx.pending_requests[msg.token] = new_request_id

            return unprotected_msg.encode()

        except Exception as e:
            logger.warning("OSCORE unprotection failed for %s: %r", source, e)
            return None

    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send a datagram, protecting with OSCORE if context exists.

        If no OSCORE context exists for dest, this will trigger EDHOC
        handshake (if peer resolver can provide their public key).
        """
        loop = asyncio.get_running_loop()
        loop.create_task(self._send_protected(data, dest))

    async def _send_protected(self, data: bytes, dest: str) -> None:
        """Send with OSCORE protection (async implementation)."""
        # Ensure we have a context for this peer
        if not await self._context_store.has_context(dest):
            try:
                await self._establish_context(dest)
            except Exception as e:
                logger.error("Failed to establish OSCORE context with %s: %s", dest, e)
                return

        peer_ctx = await self._context_store.get(dest)
        if peer_ctx is None:
            logger.error("Context lost after establishment for %s", dest)
            return

        try:
            # Decode the plaintext CoAP message
            remote = LichenRemote(dest)
            msg = Message.decode(data, remote)
            msg.direction = Direction.OUTGOING

            # Determine request_id for responses (stored during _unprotect of the request)
            request_id = None
            if msg.code.is_response():
                request_id = peer_ctx.pending_requests.pop(msg.token, None)

            # Protect with OSCORE
            protected_msg, new_request_id = peer_ctx.oscore.protect(msg, request_id)

            # OSCORE creates a new message but doesn't preserve mtype/mid/remote.
            # Copy them from the original message for proper encoding.
            # SECURITY: These are outer CoAP header fields, not protected by OSCORE.
            if protected_msg.mtype is None:
                protected_msg.mtype = msg.mtype
            if protected_msg.mid is None:
                protected_msg.mid = msg.mid
            if protected_msg.remote is None:
                protected_msg.remote = msg.remote

            # Store request_id for requests (to correlate responses)
            if msg.code.is_request() and new_request_id is not None:
                peer_ctx.pending_requests[msg.token] = new_request_id

            # Encode and send
            protected_data = protected_msg.encode()
            self._inner.send_datagram(protected_data, dest)

        except Exception as e:
            logger.error("Failed to protect message for %s: %s", dest, e)

    async def _establish_context(self, dest: str) -> None:
        """Establish an OSCORE context with a peer via EDHOC.

        This implements lazy EDHOC establishment per spec section 8.8.
        """
        # Check if handshake already in progress
        if dest in self._pending_edhoc:
            await self._pending_edhoc[dest]
            return

        # Get peer's public key
        peer_pubkey = await self._peer_resolver.get_peer_pubkey(dest)
        if peer_pubkey is None:
            raise ValueError(f"Unknown peer: {dest}")

        # Create a future for others to wait on
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending_edhoc[dest] = future

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
            self._pending_edhoc.pop(dest, None)
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
                lambda mm: LichenTransport.create(mm, self._edhoc_channel, self._local_host)
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
        ctx = await self._get_edhoc_context()

        request = Message(
            code=POST,
            uri=f"coap://{dest}/.well-known/edhoc",
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
        self._inner.close()

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
        self._context_store.put_sync(host, oscore_ctx, peer_pubkey)

        if isinstance(self._peer_resolver, TofuPeerResolver):
            # Directly access the internal dict for sync operation
            self._peer_resolver._pinned[host] = peer_pubkey

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
        await self._context_store.put(host, oscore_ctx, peer_pubkey)

        # Pin the peer key
        if isinstance(self._peer_resolver, TofuPeerResolver):
            await self._peer_resolver.pin_peer(host, peer_pubkey)

    def has_context_sync(self, host: str) -> bool:
        """Check if we have an OSCORE context (synchronous)."""
        return self._context_store.has_context_sync(host)

    async def has_context(self, host: str) -> bool:
        """Check if we have an OSCORE context for a peer."""
        return await self._context_store.has_context(host)


def create_secure_channel(
    inner: DatagramChannel,
    identity: Identity,
    *,
    context_store: OscoreContextStore | None = None,
    peer_resolver: EdhocPeerResolver | None = None,
    require_oscore: bool = True,
    local_host: str | None = None,
    edhoc_timeout: float = 30.0,
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
    )
