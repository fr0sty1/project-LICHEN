# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""EDHOC key establishment resource (RFC 9528)."""

from __future__ import annotations

import asyncio
import contextlib
import math
import time
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    INTERNAL_SERVER_ERROR,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    Message,
    resource,
)
from aiocoap.numbers import ContentFormat, constants

from lichen.coap.transport import EndpointPolicy

if TYPE_CHECKING:
    from lichen.coap.secure import (
        EdhocPeerResolver,
        TransactionalOscoreContextStore,
    )


class _EdhocTimerHandle(Protocol):
    def cancel(self) -> None: ...


class _EdhocTransientError(RuntimeError):
    """A resolver or store failure that may succeed when retried."""


class EdhocResource(resource.Resource):
    """POST /.well-known/edhoc — EDHOC key establishment (RFC 9528, spec 8.8).

    Handles the responder side of EDHOC key exchange. Messages are exchanged
    as raw bytes (not CBOR-wrapped) per RFC 9528 Section 5.3.

    Protocol flow:
        1. Client POSTs Message 1 -> Server returns Message 2
        2. Client POSTs Message 3 -> Server returns empty 2.04 Changed

    After step 2, both sides have derived the OSCORE master secret and salt.

    Usage::

        from lichen.coap.resources import EdhocResource
        from lichen.crypto.identity import Identity

        identity = Identity.generate()
        edhoc = EdhocResource(identity, context_store, peer_resolver)
        site.add_resource([".well-known", "edhoc"], edhoc)
    """

    def __init__(
        self,
        identity: Any,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: EdhocPeerResolver,
        endpoint_policy: EndpointPolicy | None = None,
        *,
        max_sessions: int = 100,
        session_lifetime: float = constants.TransportTuning().EXCHANGE_LIFETIME,
        monotonic: Callable[[], float] = time.monotonic,
        call_later: Callable[[float, Callable[[], None]], _EdhocTimerHandle] | None = None,
    ) -> None:
        """Create an EDHOC responder resource.

        Args:
            identity: Our cryptographic Identity for signing.
            context_store: Transactional store for derived contexts.
            peer_resolver: EdhocPeerResolver to look up/pin peer pubkeys.
        """
        super().__init__()
        if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions <= 0:
            raise ValueError("max_sessions must be a positive integer")
        try:
            lifetime = float(session_lifetime)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("session_lifetime must be finite and positive") from None
        if isinstance(session_lifetime, bool) or not math.isfinite(lifetime) or lifetime <= 0:
            raise ValueError("session_lifetime must be finite and positive")
        self._max_sessions = max_sessions
        self._session_lifetime = lifetime
        self._monotonic = monotonic
        self._call_later = call_later
        self._identity = identity
        self._context_store = context_store
        self._peer_resolver = peer_resolver
        self._endpoint_policy = endpoint_policy
        if endpoint_policy is None:
            self._peer_resolver.bind_context_store(self._context_store)
        else:
            self._peer_resolver.bind_authority(self._context_store, endpoint_policy)
        # Active EDHOC sessions keyed by (peer_host, C_I)
        self._sessions: dict[tuple[str, bytes], Any] = {}
        self._completing: dict[tuple[str, bytes], Any] = {}
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None

    async def close(self) -> None:
        """Close once and drain every in-progress publication."""
        if self._close_task is None:
            self._closed = True
            self._request_close()
            self._close_task = asyncio.create_task(self._drain_close())
        await asyncio.shield(self._close_task)

    def _request_close(self) -> None:
        self._closed = True
        for key, session in list(self._sessions.items()):
            self._remove_session(key, session, abort=True)
        for session in list(self._completing.values()):
            session["closed"] = True
            self._abort_record(session)
            publication = session.get("publication_task")
            if publication is not None and not publication.done():
                publication.cancel()

    async def _drain_close(self) -> None:
        completing = list(self._completing.values())
        publications = [
            session["publication_task"]
            for session in completing
            if session.get("publication_task") is not None
        ]
        if publications:
            await asyncio.gather(*publications, return_exceptions=True)
        if completing:
            await asyncio.gather(
                *(session["finalized_event"].wait() for session in completing)
            )

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self._request_close()

    def bind_endpoint_policy(self, policy: EndpointPolicy) -> None:
        """Bind authoritative channel endpoint identity before serving."""
        self._peer_resolver.bind_authority(self._context_store, policy)
        self._endpoint_policy = policy

    def _endpoint_key(self, endpoint: str) -> str:
        policy = self._endpoint_policy or EndpointPolicy()
        return policy.normalize(endpoint).authority

    @staticmethod
    def _message_1_connection_id(payload: bytes) -> bytes | None:
        """Return C_I for a structurally valid Message 1, otherwise None."""
        from lichen.crypto.edhoc import (
            SUITE_0,
            X25519_KEY_LEN,
            Method,
            _decode_cbor_sequence,
            _validate_connection_id,
        )

        try:
            items = _decode_cbor_sequence(payload)
            if len(items) not in (4, 5):
                return None
            if type(items[0]) is not int or items[0] != Method.SIGN_SIGN * 4 + 1:
                return None
            if type(items[1]) is not int or items[1] != SUITE_0:
                return None
            if not isinstance(items[2], bytes) or len(items[2]) != X25519_KEY_LEN:
                return None
            if len(items) == 5 and not isinstance(items[4], bytes):
                return None
            return _validate_connection_id(items[3], "C_I")
        except ValueError:
            return None

    def _peer_session(
        self, peer_host: str
    ) -> tuple[tuple[str, bytes], dict[str, Any]] | None:
        for key, session in self._sessions.items():
            if key[0] == peer_host:
                return key, session
        return None

    @staticmethod
    def _edhoc_response(payload: bytes) -> Message:
        response = Message(code=CHANGED, payload=payload)
        response.opt.content_format = ContentFormat(65535)
        return response

    async def render_post(self, request: Message) -> Message:
        """Handle EDHOC POST request.

        Expects Message 1 or Message 3 in the payload. Determines which
        based on whether we have an active session for the sender.
        """
        if not request.payload:
            return Message(code=BAD_REQUEST)
        if self._closed:
            return Message(code=SERVICE_UNAVAILABLE)

        # Get peer address from remote
        peer_host = request.remote.hostinfo if request.remote else None
        if not peer_host:
            return Message(code=BAD_REQUEST)
        try:
            peer_host = self._endpoint_key(peer_host)
        except ValueError:
            return Message(code=BAD_REQUEST)

        payload = request.payload
        self._expire_sessions()
        active = self._peer_session(peer_host)

        active_session = None
        for (host, _), session in reversed(list(self._sessions.items())):
            if host == peer_host:
                active_session = session
                break

        try:
            if active_session is None:
                # This is Message 1 - start new session
                return await self._handle_message_1(peer_host, payload)
            else:
                # Check for exact M1 retransmission before assuming M3
                if active_session["msg1"] == payload:
                    return self._edhoc_response(active_session["msg2"])
                # Check if this is a different M1 (restart attempt) - reject it
                if self._message_1_connection_id(payload) is not None:
                    return Message(code=BAD_REQUEST)
                # This is Message 3 - complete handshake
                return await self._handle_message_3(peer_host, payload, active_session)
        except _EdhocTransientError:
            return Message(code=SERVICE_UNAVAILABLE)
        except ValueError:
            if active is not None:
                self._remove_session(active[0], active[1], abort=True)
            return Message(code=BAD_REQUEST)
        except Exception:
            if active is not None:
                self._remove_session(active[0], active[1], abort=True)
            return Message(code=INTERNAL_SERVER_ERROR)

    async def _handle_message_1(self, peer_host: str, msg1: bytes) -> Message:
        """Process EDHOC Message 1 and return Message 2."""
        from lichen.crypto.edhoc import EdhocResponder

        # Get peer's public key for authentication
        # SECURITY: Reject unknown peers early rather than proceeding with a
        # dummy key. An all-zeros key is a valid Ed25519 point, so passing it
        # to crypto routines could allow attacks. TOFU would defer this check
        # to Message 3, but we currently require pre-known peers.
        try:
            await self._peer_resolver.ensure_bound()
        except Exception as exc:
            raise _EdhocTransientError from exc
        self._expire_sessions()
        try:
            peer_pubkey = await self._peer_resolver.get_peer_pubkey(peer_host)
        except Exception as exc:
            raise _EdhocTransientError from exc
        self._expire_sessions()
        if peer_pubkey is None:
            return Message(code=UNAUTHORIZED)
        try:
            expected_generation = await self._context_store.get_generation(peer_host)
        except Exception as exc:
            raise _EdhocTransientError from exc
        self._expire_sessions()

        existing = self._peer_session(peer_host)
        if existing is not None:
            if existing[1]["msg1"] == msg1:
                return self._edhoc_response(existing[1]["msg2"])
            return Message(code=BAD_REQUEST)
        if self._closed or len(self._sessions) + len(self._completing) >= self._max_sessions:
            return Message(code=SERVICE_UNAVAILABLE)
        if any(key[0] == peer_host for key in self._completing):
            return Message(code=SERVICE_UNAVAILABLE)

        self._cleanup_session(peer_host)
        responder = EdhocResponder.create(self._identity)
        msg2 = responder.process_message_1(msg1, peer_pubkey)
        c_i = responder._c_i
        deadline = self._monotonic() + self._session_lifetime
        session_key = (peer_host, c_i)
        session = {
            "responder": responder,
            "peer_pubkey": peer_pubkey,
            "expected_generation": expected_generation,
            "deadline": deadline,
            "expiry_handle": None,
            "msg1": msg1,
            "msg2": msg2,
            "state": "ACTIVE",
            "aborted": False,
            "closed": False,
            "key": session_key,
        }
        self._sessions[session_key] = session
        try:
            self._schedule_expiry(session_key, session)
        except Exception:
            self._remove_session(session_key, session, abort=True)
            raise

        return self._edhoc_response(msg2)

    def _cleanup_session(self, peer_host: str) -> None:
        """Remove any existing session for peer_host."""
        for key in list(self._sessions.keys()):
            if key[0] == peer_host:
                self._remove_session(key, self._sessions[key], abort=True)

    async def _handle_message_3(
        self, peer_host: str, msg3: bytes, session: dict[str, Any]
    ) -> Message:
        """Process EDHOC Message 3 and establish OSCORE context."""
        from lichen.crypto.oscore import MemorySecurityContext

        responder = session["responder"]
        peer_pubkey = session["peer_pubkey"]
        expected_generation = session["expected_generation"]
        session_key = session["key"]

        self._expire_sessions()
        if self._sessions.get(session_key) is not session:
            return Message(code=BAD_REQUEST)

        if peer_pubkey is None:
            # SECURITY: Defense-in-depth check. Message 1 handler now rejects
            # unknown peers early, but if a session somehow lacks a peer key,
            # fail here rather than proceeding with verification.
            self._remove_session(session_key, session, abort=True)
            return Message(code=UNAUTHORIZED)

        try:
            responder.process_message_3(msg3, peer_pubkey)
            edhoc_ctx = responder.export_oscore()
            oscore_ctx = MemorySecurityContext.from_edhoc(edhoc_ctx)

            # Message 3 completed synchronously before the deadline. Remove it
            # from active expiry before publication, which may legitimately block.
            if self._monotonic() >= session["deadline"]:
                self._remove_session(session_key, session, abort=True)
                return Message(code=BAD_REQUEST)
            if not self._transition_to_completing(session_key, session):
                return Message(code=BAD_REQUEST)
        except Exception:
            self._remove_session(session_key, session, abort=True)
            raise

        publication: asyncio.Task[None] | None = None
        try:
            async def publish() -> None:
                await self._peer_resolver.ensure_bound()
                await self._context_store.put(
                    peer_host,
                    oscore_ctx,
                    peer_pubkey,
                    expected_generation=expected_generation,
                )

            publication = asyncio.create_task(publish())
            session["publication_task"] = publication
            try:
                await asyncio.shield(publication)
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    publication.cancel()
                    await asyncio.gather(publication, return_exceptions=True)
                    raise
                raise _EdhocTransientError from None
            except Exception as exc:
                raise _EdhocTransientError from exc
            return Message(code=CHANGED)
        finally:
            pending_tasks: list[asyncio.Task[Any]] = []
            if publication is not None and not publication.done():
                publication.cancel()
                pending_tasks.append(publication)
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            self._finalize_completion(session_key, session)

    def _schedule_expiry(
        self, session_key: tuple[str, bytes], session: dict[str, Any]
    ) -> None:
        delay = max(0.0, session["deadline"] - self._monotonic())
        scheduler = self._call_later or asyncio.get_running_loop().call_later
        resource_ref = weakref.ref(self)

        def expire() -> None:
            resource = resource_ref()
            if resource is not None:
                resource._expire_session(session_key, session)

        handle = scheduler(delay, expire)
        if self._sessions.get(session_key) is session:
            session["expiry_handle"] = handle
        else:
            handle.cancel()

    def _expire_session(
        self, session_key: tuple[str, bytes], session: dict[str, Any]
    ) -> None:
        if self._sessions.get(session_key) is not session:
            return
        if self._monotonic() < session["deadline"]:
            self._schedule_expiry(session_key, session)
            return
        self._remove_session(session_key, session, abort=True)

    def _remove_session(
        self,
        session_key: tuple[str, bytes],
        session: dict[str, Any],
        *,
        abort: bool,
    ) -> bool:
        if self._sessions.get(session_key) is not session:
            return False
        handle = session.get("expiry_handle")
        if handle is not None:
            handle.cancel()
            session["expiry_handle"] = None
        if abort:
            self._abort_record(session)
            session["state"] = "ABORTED"
        del self._sessions[session_key]
        return True

    def _transition_to_completing(
        self, session_key: tuple[str, bytes], session: dict[str, Any]
    ) -> bool:
        if self._closed or self._sessions.get(session_key) is not session:
            return False
        handle = session.get("expiry_handle")
        if handle is not None:
            handle.cancel()
            session["expiry_handle"] = None
        del self._sessions[session_key]
        session["state"] = "COMPLETING"
        session["finalized_event"] = asyncio.Event()
        session["publication_task"] = None
        self._completing[session_key] = session
        return True

    def _finalize_completion(
        self, session_key: tuple[str, bytes], session: dict[str, Any]
    ) -> None:
        if self._completing.get(session_key) is session:
            del self._completing[session_key]
        session["publication_task"] = None
        self._abort_record(session)
        session["state"] = "CLOSED" if session["closed"] else "COMPLETE"
        session["finalized_event"].set()

    @staticmethod
    def _abort_record(session: dict[str, Any]) -> None:
        if not session["aborted"]:
            session["responder"].abort()
            session["aborted"] = True

    def _expire_sessions(self) -> None:
        """Synchronously catch deadlines before request processing."""
        now = self._monotonic()
        expired = [
            (key, session)
            for key, session in self._sessions.items()
            if now >= session["deadline"]
        ]
        for key, session in expired:
            self._remove_session(key, session, abort=True)
