# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""BR provisioning CoAP resource (spec 8.7).

SECURITY: Per spec section 8.7, BR provisioning channels MUST be encrypted and
authenticated. This resource implements the secure provisioning channel using
EDHOC for key establishment and AES-CCM for seed encryption.

The provisioning flow:
1. Node boots in commissioning mode and POSTs EDHOC Message 1
2. BR responds with Message 2 (signed with BR identity)
3. Node POSTs Message 3 to complete EDHOC
4. BR POSTs encrypted seed to /provision
5. Node decrypts, derives identity, POSTs encrypted ACK
6. BR verifies ACK matches provisioned pubkey
7. Both sides securely wipe session keys

Transport bindings: USB/BLE/LCI per spec. The encryption layer is
transport-agnostic; this CoAP resource handles framed bytes.

Usage::

    from lichen.coap.resources.provisioning import ProvisioningResource
    from lichen.crypto.identity import Identity

    # BR side
    br_identity = Identity.from_seed(br_seed)
    resource = ProvisioningResource.for_br(br_identity)
    site.add_resource(["provision"], resource)

    # Node side (commissioning mode)
    ephemeral = Identity.generate()
    resource = ProvisioningResource.for_node(ephemeral)
    site.add_resource(["provision"], resource)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Protocol

from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    CONTENT,
    CREATED,
    INTERNAL_SERVER_ERROR,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    Message,
    resource,
)
from aiocoap.numbers import ContentFormat

from lichen.crypto.provisioning import (
    BRProvisioningSession,
    DecryptionFailedError,
    NodeProvisioningSession,
    ProvisioningError,
    ProvisioningState,
)

if TYPE_CHECKING:
    from lichen.crypto.identity import Identity


CBOR_CONTENT_FORMAT = ContentFormat(60)

logger = logging.getLogger(__name__)


class ProvisioningRole(IntEnum):
    """Role in the provisioning protocol."""

    BR = 0  # Border router (provisioner)
    NODE = 1  # Node being provisioned (commissionee)


class SeedProvider(Protocol):
    """Protocol for generating or retrieving seeds to provision."""

    def generate_seed(self) -> bytes:
        """Generate a 32-byte seed for a new node.

        Returns:
            32 bytes of cryptographically secure randomness.
        """
        ...


class DefaultSeedProvider:
    """Default seed provider using os.urandom."""

    def generate_seed(self) -> bytes:
        """Generate a cryptographically secure 32-byte seed."""
        return os.urandom(32)


class ProvisionedIdentityCallback(Protocol):
    """Callback invoked when a node is successfully provisioned."""

    async def on_provisioned(
        self,
        node_pubkey: bytes,
        node_iid: bytes,
        node_ygg_addr: bytes,
    ) -> None:
        """Called when a node completes provisioning.

        Args:
            node_pubkey: 32-byte Ed25519 public key
            node_iid: 8-byte Interface Identifier
            node_ygg_addr: 16-byte Yggdrasil 02xx address
        """
        ...


class NewIdentityCallback(Protocol):
    """Callback invoked when the node receives a new identity."""

    async def on_new_identity(self, identity: Any) -> None:
        """Called when a node receives its new identity from BR.

        The node MUST store this identity securely and exit commissioning mode.

        Args:
            identity: The new Identity object derived from provisioned seed
        """
        ...


@dataclass
class ProvisioningSession:
    """Active provisioning session state."""

    peer_host: str
    session: BRProvisioningSession | NodeProvisioningSession
    created_at: float
    deadline: float
    state: ProvisioningState
    expiry_handle: Any = None
    provisioned_seed: bytes | None = None
    provisioned_identity: Any = None


class ProvisioningResource(resource.Resource):
    """POST /provision - BR provisioning channel (spec 8.7).

    SECURITY: This resource implements encrypted provisioning per spec 8.7.
    The channel uses EDHOC for key establishment and AES-CCM for seed transfer.
    Plaintext seed transfer is explicitly prohibited.

    Protocol flow (BR-initiated after EDHOC completes):
    1. EDHOC completes (via EdhocResource or inline)
    2. BR POSTs encrypted seed to /provision
    3. Node decrypts, derives identity, POSTs encrypted ACK
    4. BR verifies ACK, returns 2.04 Changed

    Usage depends on role:
    - BR: Use for_br() to create, call provision_node() to initiate
    - Node: Use for_node() to create, handle incoming provisioning requests
    """

    def __init__(
        self,
        identity: Identity,
        role: ProvisioningRole,
        *,
        seed_provider: SeedProvider | None = None,
        provisioned_callback: ProvisionedIdentityCallback | None = None,
        new_identity_callback: NewIdentityCallback | None = None,
        max_sessions: int = 10,
        session_lifetime: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a provisioning resource.

        Args:
            identity: Our cryptographic Identity for EDHOC signing.
            role: BR or NODE - determines which protocol side we implement.
            seed_provider: For BR role, provides seeds to provision.
            provisioned_callback: For BR role, called on successful provisioning.
            new_identity_callback: For NODE role, called when identity received.
            max_sessions: Maximum concurrent provisioning sessions.
            session_lifetime: Session timeout in seconds.
            monotonic: Clock source for timeouts.
        """
        super().__init__()
        self._identity = identity
        self._role = role
        self._seed_provider = seed_provider or DefaultSeedProvider()
        self._provisioned_callback = provisioned_callback
        self._new_identity_callback = new_identity_callback
        self._max_sessions = max_sessions
        self._session_lifetime = session_lifetime
        self._monotonic = monotonic

        # Active provisioning sessions keyed by peer_host
        self._sessions: dict[str, ProvisioningSession] = {}
        self._closed = False

    @classmethod
    def for_br(
        cls,
        identity: Identity,
        *,
        seed_provider: SeedProvider | None = None,
        provisioned_callback: ProvisionedIdentityCallback | None = None,
        **kwargs: Any,
    ) -> ProvisioningResource:
        """Create a provisioning resource for BR (provisioner) role.

        Args:
            identity: BR's cryptographic identity for EDHOC signing.
            seed_provider: Optional custom seed provider.
            provisioned_callback: Called when a node completes provisioning.
            **kwargs: Additional arguments passed to __init__.

        Returns:
            ProvisioningResource configured for BR role.
        """
        return cls(
            identity,
            ProvisioningRole.BR,
            seed_provider=seed_provider,
            provisioned_callback=provisioned_callback,
            **kwargs,
        )

    @classmethod
    def for_node(
        cls,
        ephemeral_identity: Identity,
        *,
        new_identity_callback: NewIdentityCallback | None = None,
        **kwargs: Any,
    ) -> ProvisioningResource:
        """Create a provisioning resource for NODE (commissionee) role.

        Args:
            ephemeral_identity: Node's ephemeral identity for commissioning.
            new_identity_callback: Called when node receives new identity.
            **kwargs: Additional arguments passed to __init__.

        Returns:
            ProvisioningResource configured for NODE role.
        """
        return cls(
            ephemeral_identity,
            ProvisioningRole.NODE,
            new_identity_callback=new_identity_callback,
            **kwargs,
        )

    @property
    def role(self) -> ProvisioningRole:
        """Return the provisioning role (BR or NODE)."""
        return self._role

    async def close(self) -> None:
        """Close all active sessions and prevent new ones."""
        self._closed = True
        for session in list(self._sessions.values()):
            self._remove_session(session, wipe=True)

    async def render_post(self, request: Message) -> Message:
        """Handle provisioning POST requests.

        The payload format depends on role and session state:
        - BR sending seed: CBOR-encoded ProvisioningPayload (encrypted)
        - Node sending ACK: CBOR-encoded ProvisioningPayload (encrypted)

        SECURITY: All payloads are encrypted with the EDHOC-derived session key.
        Plaintext transfer is never permitted.
        """
        if not request.payload:
            return Message(code=BAD_REQUEST)
        if self._closed:
            return Message(code=SERVICE_UNAVAILABLE)

        peer_host = request.remote.hostinfo if request.remote else None
        if not peer_host:
            return Message(code=BAD_REQUEST)

        self._expire_sessions()

        try:
            if self._role == ProvisioningRole.BR:
                return await self._handle_br_post(peer_host, request.payload)
            else:
                return await self._handle_node_post(peer_host, request.payload)
        except ProvisioningError:
            # SECURITY: Generic error to prevent oracle attacks
            return Message(code=BAD_REQUEST)
        except Exception:
            return Message(code=INTERNAL_SERVER_ERROR)

    async def render_get(self, request: Message) -> Message:
        """GET /provision returns provisioning status.

        For nodes in commissioning mode, returns whether provisioning is
        in progress or completed.
        """
        peer_host = request.remote.hostinfo if request.remote else None
        if not peer_host:
            return Message(code=BAD_REQUEST)

        session = self._sessions.get(peer_host)
        if session is None:
            status = {"state": "idle", "role": self._role.name.lower()}
        else:
            status = {
                "state": session.state.name.lower(),
                "role": self._role.name.lower(),
            }

        import cbor2

        response = Message(code=CONTENT, payload=cbor2.dumps(status))
        response.opt.content_format = CBOR_CONTENT_FORMAT
        return response

    async def _handle_br_post(self, peer_host: str, payload: bytes) -> Message:
        """Handle POST on BR side - expecting ACK from node."""
        session = self._sessions.get(peer_host)
        if session is None:
            # No active session - this shouldn't happen for BR
            return Message(code=BAD_REQUEST)

        br_session = session.session
        if not isinstance(br_session, BRProvisioningSession):
            return Message(code=INTERNAL_SERVER_ERROR)

        if br_session.state != ProvisioningState.ESTABLISHED:
            return Message(code=BAD_REQUEST)

        # Decrypt and verify ACK
        try:
            received_pubkey = br_session.decrypt_ack(payload)
        except DecryptionFailedError:
            self._remove_session(session, wipe=True)
            return Message(code=UNAUTHORIZED)
        except ProvisioningError:
            self._remove_session(session, wipe=True)
            return Message(code=BAD_REQUEST)

        # Provisioning complete - invoke callback
        # SECURITY: Callback failure MUST abort provisioning. If we proceed
        # after callback failure (e.g., database write fails), the BR marks
        # provisioning complete and wipes the session, but the node is never
        # registered. The node believes it is provisioned; the BR has no record.
        # This is an unrecoverable state - return error so node can retry.
        # SECURITY: decrypt_ack() already verified received_pubkey matches the
        # expected pubkey derived from provisioned_seed via hmac.compare_digest.
        # For defense-in-depth, pass the trusted derived pubkey to the callback,
        # not the verified-but-originally-untrusted received value.
        #
        # NOTE: Use the seed from the crypto layer if session.provisioned_seed
        # is not set. This handles create_br_session() used directly without
        # provision_node(). The crypto layer's seed is guaranteed to be set
        # if decrypt_ack() succeeded (it checks for empty seed and raises).
        seed_for_callback = session.provisioned_seed or br_session._provisioned_seed
        if self._provisioned_callback is not None and seed_for_callback:
            from lichen.crypto.identity import Identity

            provisioned_id = Identity.from_seed(seed_for_callback)
            try:
                await self._provisioned_callback.on_provisioned(
                    node_pubkey=provisioned_id.pubkey,
                    node_iid=provisioned_id.iid,
                    node_ygg_addr=provisioned_id.ygg_addr,
                )
            except Exception:
                # SECURITY: Log failure so operators can diagnose, but do NOT
                # leak details over the network (attacker could trigger failures
                # to probe callback behavior).
                logger.exception("on_provisioned callback failed")
                # Callback failed - do NOT wipe session (allows retry)
                return Message(code=SERVICE_UNAVAILABLE)

        # Wipe session only on success
        self._remove_session(session, wipe=True)

        return Message(code=CHANGED)

    async def _handle_node_post(self, peer_host: str, payload: bytes) -> Message:
        """Handle POST on NODE side - expecting encrypted seed from BR."""
        session = self._sessions.get(peer_host)
        if session is None:
            # No active session - this shouldn't happen
            return Message(code=BAD_REQUEST)

        node_session = session.session
        if not isinstance(node_session, NodeProvisioningSession):
            return Message(code=INTERNAL_SERVER_ERROR)

        if node_session.state != ProvisioningState.ESTABLISHED:
            return Message(code=BAD_REQUEST)

        # Decrypt seed and derive identity
        try:
            new_identity = node_session.decrypt_seed(payload)
        except DecryptionFailedError:
            self._remove_session(session, wipe=True)
            return Message(code=UNAUTHORIZED)
        except ProvisioningError:
            self._remove_session(session, wipe=True)
            return Message(code=BAD_REQUEST)

        session.provisioned_identity = new_identity

        # Create ACK
        try:
            ack = node_session.create_ack(new_identity.pubkey)
        except ProvisioningError:
            self._remove_session(session, wipe=True)
            return Message(code=INTERNAL_SERVER_ERROR)

        # Invoke callback with new identity
        # SECURITY: Callback failure MUST abort provisioning. If we proceed
        # after callback failure (e.g., identity storage fails), the node loses
        # its identity forever since the session is wiped. Return error so the
        # BR knows provisioning failed and the session can be retried.
        if self._new_identity_callback is not None:
            try:
                await self._new_identity_callback.on_new_identity(new_identity)
            except Exception:
                # SECURITY: Log failure so operators can diagnose, but do NOT
                # leak details over the network (attacker could trigger failures
                # to probe callback behavior).
                logger.exception("on_new_identity callback failed")
                # Callback failed - do NOT wipe session (allows retry)
                return Message(code=SERVICE_UNAVAILABLE)

        # SECURITY: Encode the ACK BEFORE wiping the session. If encode() fails
        # (e.g., cbor2 error), the exception propagates as INTERNAL_SERVER_ERROR
        # but the session remains intact, allowing the node to retry. Wiping
        # first would destroy provisioned_identity, making retry impossible.
        response = Message(code=CREATED, payload=ack.encode())
        response.opt.content_format = CBOR_CONTENT_FORMAT

        # Wipe session after response is fully constructed
        self._remove_session(session, wipe=True)

        return response

    def create_br_session(
        self,
        peer_host: str,
        node_pubkey: bytes,
    ) -> BRProvisioningSession:
        """Create a BR provisioning session for a node.

        SECURITY: The node's pubkey must be obtained out-of-band (QR code,
        pre-provisioned manifest, or TOFU with physical proximity verification).

        Args:
            peer_host: Node's network address for session tracking.
            node_pubkey: Node's ephemeral pubkey (32 bytes).

        Returns:
            BRProvisioningSession ready for EDHOC Message 1.

        Raises:
            RuntimeError: If closed or max sessions reached.
            ValueError: If node_pubkey is wrong length.
        """
        if self._closed:
            raise RuntimeError("Resource is closed")
        if self._role != ProvisioningRole.BR:
            raise RuntimeError("create_br_session requires BR role")

        # SECURITY: Expire sessions BEFORE checking max_sessions to prevent DoS.
        # Otherwise, an attacker could fill max_sessions slots, let them expire,
        # and permanently block new sessions until manual restart.
        self._expire_sessions()

        if len(self._sessions) >= self._max_sessions:
            raise RuntimeError("Max sessions reached")

        # SECURITY: Wipe any existing session for this peer_host before creating
        # a new one. Failing to wipe leaves cryptographic material (_prov_key,
        # _provisioned_seed) in memory, leaking secrets. This also prevents an
        # attacker from silently resetting a legitimate provisioning attempt.
        existing = self._sessions.get(peer_host)
        if existing is not None:
            self._remove_session(existing, wipe=True)

        br_session = BRProvisioningSession(self._identity, node_pubkey)
        now = self._monotonic()
        session = ProvisioningSession(
            peer_host=peer_host,
            session=br_session,
            created_at=now,
            deadline=now + self._session_lifetime,
            state=ProvisioningState.IDLE,
        )
        self._sessions[peer_host] = session

        return br_session

    def create_node_session(self, peer_host: str) -> NodeProvisioningSession:
        """Create a NODE provisioning session.

        Args:
            peer_host: BR's network address for session tracking.

        Returns:
            NodeProvisioningSession ready for EDHOC Message 1.

        Raises:
            RuntimeError: If closed or max sessions reached.
        """
        if self._closed:
            raise RuntimeError("Resource is closed")
        if self._role != ProvisioningRole.NODE:
            raise RuntimeError("create_node_session requires NODE role")

        # SECURITY: Expire sessions BEFORE checking max_sessions to prevent DoS.
        # Otherwise, an attacker could fill max_sessions slots, let them expire,
        # and permanently block new sessions until manual restart.
        self._expire_sessions()

        if len(self._sessions) >= self._max_sessions:
            raise RuntimeError("Max sessions reached")

        # SECURITY: Wipe existing session before overwriting. Without this,
        # the old session's cryptographic material would leak when overwritten.
        existing = self._sessions.get(peer_host)
        if existing is not None:
            self._remove_session(existing, wipe=True)

        node_session = NodeProvisioningSession(self._identity)
        now = self._monotonic()
        session = ProvisioningSession(
            peer_host=peer_host,
            session=node_session,
            created_at=now,
            deadline=now + self._session_lifetime,
            state=ProvisioningState.IDLE,
        )
        self._sessions[peer_host] = session

        return node_session

    async def provision_node(
        self,
        peer_host: str,
        node_pubkey: bytes,
        send_message: Callable[[bytes], Awaitable[Any]],
        receive_message: Callable[[], Awaitable[bytes]],
    ) -> bytes:
        """Provision a node with a new identity (BR side).

        This is the high-level BR API for provisioning. It:
        1. Creates a session with the node
        2. Performs EDHOC handshake (caller provides message transport)
        3. Encrypts and sends the seed
        4. Verifies the ACK

        Args:
            peer_host: Node's network address.
            node_pubkey: Node's ephemeral pubkey (32 bytes, from out-of-band).
            send_message: Async callable to send bytes to the node.
            receive_message: Async callable to receive bytes from the node.

        Returns:
            The provisioned seed (32 bytes).

        Raises:
            ProvisioningError: If provisioning fails.
        """
        br_session = self.create_br_session(peer_host, node_pubkey)

        try:
            # EDHOC handshake: wait for Message 1, send Message 2, wait for Message 3
            msg1 = await receive_message()
            msg2 = br_session.process_message_1(msg1)
            await send_message(msg2)
            msg3 = await receive_message()
            br_session.process_message_3(msg3)

            # Generate seed
            seed = self._seed_provider.generate_seed()

            # Store seed in session for later verification
            session = self._sessions.get(peer_host)
            if session is None:
                raise RuntimeError(
                    f"Session for {peer_host} not found after create_br_session"
                )
            session.provisioned_seed = seed

            # Encrypt and send seed (session now ESTABLISHED after EDHOC)
            encrypted = br_session.encrypt_seed(seed)
            await send_message(encrypted.encode())

            # Wait for and verify ACK from node
            # SECURITY: Per spec 8.7, the BR MUST verify the node derived the correct
            # pubkey from the provisioned seed. Without this, an attacker could intercept
            # the seed and substitute their own identity.
            ack_data = await receive_message()
            try:
                br_session.decrypt_ack(ack_data)
            except ProvisioningError:
                raise ProvisioningError("ACK verification failed") from None

            return seed
        finally:
            # SECURITY: Clean up session after provisioning (success or failure) to
            # prevent memory leak, resource exhaustion, and ensure cryptographic
            # material is wiped
            session = self._sessions.get(peer_host)
            if session is not None:
                self._remove_session(session, wipe=True)

    def _remove_session(self, session: ProvisioningSession, *, wipe: bool) -> None:
        """Remove a session from tracking."""
        if (
            session.peer_host in self._sessions
            and self._sessions[session.peer_host] is session
        ):
            del self._sessions[session.peer_host]

        if session.expiry_handle is not None:
            session.expiry_handle.cancel()
            session.expiry_handle = None

        if wipe:
            if hasattr(session.session, "wipe"):
                session.session.wipe()
            session.provisioned_seed = None
            session.provisioned_identity = None

    def _expire_sessions(self) -> None:
        """Remove expired sessions."""
        now = self._monotonic()
        expired = [s for s in self._sessions.values() if now >= s.deadline]
        for session in expired:
            self._remove_session(session, wipe=True)
