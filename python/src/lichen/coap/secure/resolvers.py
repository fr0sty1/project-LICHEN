# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Peer resolvers for EDHOC authentication."""

from __future__ import annotations

import asyncio
import logging

from ..transport import EndpointPolicy
from .types import TransactionalOscoreContextStore
from .utils import validate_endpoint_key

logger = logging.getLogger(__name__)


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

    def bind_context_store(self, context_store: TransactionalOscoreContextStore) -> None:
        """Bind resolver authority to a context store when applicable."""

    def bind_authority(
        self,
        context_store: TransactionalOscoreContextStore,
        policy: EndpointPolicy,
    ) -> None:
        """Bind storage and channel endpoint identity when applicable."""
        self.bind_context_store(context_store)

    async def ensure_bound(self) -> None:
        """Complete any asynchronous authority migration before use."""

    def ensure_bound_sync(self) -> None:
        """Verify that synchronous use needs no asynchronous migration."""


class TofuPeerResolver(EdhocPeerResolver):
    """Trust-On-First-Use peer resolution per spec section 8.6.

    Accepts any peer on first contact and pins their public key.

    Note: This class can be instantiated before the event loop starts.
    The internal lock is created lazily on first async access.
    """

    def __init__(self, context_store: TransactionalOscoreContextStore | None = None) -> None:
        self._context_store = context_store
        self._pending_context_store: TransactionalOscoreContextStore | None = None
        self._pinned: dict[str, bytes] = {}
        self._endpoint_policy: EndpointPolicy | None = None
        self._lock: asyncio.Lock | None = None

    def bind_authority(
        self,
        context_store: TransactionalOscoreContextStore,
        policy: EndpointPolicy,
    ) -> None:
        if self._lock is not None and self._lock.locked():
            raise RuntimeError("TOFU resolver is busy")
        if self._context_store is not None and self._context_store is not context_store:
            raise ValueError("TOFU resolver is already bound to a different context store")
        if (
            self._pending_context_store is not None
            and self._pending_context_store is not context_store
        ):
            raise ValueError("TOFU resolver is pending migration to a different context store")
        if (
            self._endpoint_policy is not None
            and self._endpoint_policy != policy
        ):
            raise ValueError("TOFU resolver is already bound to a different endpoint policy")

        if (
            self._context_store is context_store
            and self._pending_context_store is None
            and self._endpoint_policy == policy
            and not self._pinned
        ):
            return
        context_store.migrate_endpoint_keys(policy, self._pinned)
        self._endpoint_policy = policy
        self._pinned = {}
        self._context_store = context_store
        self._pending_context_store = None

    def bind_context_store(self, context_store: TransactionalOscoreContextStore) -> None:
        if self._context_store is context_store:
            return
        if self._context_store is not None:
            raise ValueError("TOFU resolver is already bound to a different context store")
        if (
            self._pending_context_store is not None
            and self._pending_context_store is not context_store
        ):
            raise ValueError("TOFU resolver is pending migration to a different context store")
        if self._pinned:
            self._pending_context_store = context_store
        else:
            self._context_store = context_store

    async def ensure_bound(self) -> None:
        if self._pending_context_store is None:
            return
        async with self._get_lock():
            store = self._pending_context_store
            if store is None:
                return
            await store.pin_peers(self._pinned)
            self._pinned.clear()
            self._context_store = store
            self._pending_context_store = None

    def ensure_bound_sync(self) -> None:
        if self._pending_context_store is not None:
            raise RuntimeError("prepopulated TOFU migration requires asynchronous provisioning")

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (must be called from async context)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Get pinned public key for a peer."""
        await self.ensure_bound()
        key = self._normalize_key(host)
        if self._context_store is not None:
            return await self._context_store.get_peer_pubkey(key)
        async with self._get_lock():
            return self._pinned.get(key)

    async def pin_peer(self, host: str, pubkey: bytes) -> None:
        """Pin a peer's public key (TOFU)."""
        await self.ensure_bound()
        key = self._normalize_key(host)
        if self._context_store is not None:
            await self._context_store.pin_peer(key, pubkey)
            return
        async with self._get_lock():
            if key in self._pinned:
                if self._pinned[key] != pubkey:
                    raise ValueError(
                        f"TOFU violation: peer {host} key changed (possible MITM or hardware swap)"
                    )
            else:
                self._pinned[key] = bytes(pubkey)
                logger.info("TOFU: pinned key for %s", key)

    def _normalize_key(self, host: str) -> str:
        if self._endpoint_policy is None:
            return validate_endpoint_key(host)
        return self._endpoint_policy.normalize(host).authority
