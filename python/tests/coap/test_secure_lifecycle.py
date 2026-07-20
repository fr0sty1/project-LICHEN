# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Correlation lifecycle tests for the secure CoAP datagram transport."""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from aiocoap import CONTENT, GET, Message, error, resource
from aiocoap.numbers.codes import EMPTY
from aiocoap.numbers.types import ACK, CON, NON, RST
from aiocoap.oscore import Direction

from lichen.coap.secure import (
    PeerContext,
    SecureDatagramChannel,
    _ProtectedCon,
    _RequestCorrelation,
    _UnprotectedDatagram,
)
from lichen.coap.transport import (
    DatagramChannel,
    LichenRemote,
    _AiocoapLifecycleAdapter,
    create_lichen_context,
)
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


class _RecordingChannel(DatagramChannel):
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str]] = []
        self.receiver: Any = None
        self.fail_sends = 0
        self.closed = False
        self.clear_calls = 0
        self.close_calls = 0
        self.shutdown_calls = 0
        self.shutdown_error: BaseException | None = None
        self.clear_error: BaseException | None = None
        self.identities: dict[tuple[str, bytes, bool], object] = {}
        self.interest_ended: list[tuple[str, bytes, object | None, bool]] = []
        self.exchanges_ended: list[tuple[str, int, bool]] = []

    def send_datagram(self, data: bytes, dest: str) -> None:
        if self.fail_sends:
            self.fail_sends -= 1
            raise OSError("injected send failure")
        self.sent.append((data, dest))

    def set_receiver(self, receiver: Any) -> None:
        self.receiver = receiver

    def clear_receiver(self, receiver: Any) -> None:
        self.clear_calls += 1
        if self.clear_error is not None:
            raise self.clear_error
        if self.receiver == receiver:
            self.receiver = None

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.closed = True
        if self.shutdown_error is not None:
            raise self.shutdown_error

    def request_started(
        self, peer: str, token: bytes, *, locally_originated: bool
    ) -> object:
        return self.identities.setdefault((peer, token, locally_originated), object())

    def request_interest_ended(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        *,
        locally_originated: bool,
    ) -> None:
        self.interest_ended.append((peer, token, lifecycle_id, locally_originated))

    def exchange_ended(self, peer: str, mid: int, *, reset: bool) -> None:
        self.exchanges_ended.append((peer, mid, reset))


class _FakeOscore:
    has_reserved_sender_sequence = True

    def __init__(self, *, fail_protect: bool = False, fail_encode: bool = False) -> None:
        self.protect_calls = 0
        self.request_ids: list[object | None] = []
        self.fail_protect = fail_protect
        self.fail_encode = fail_encode

    def protect(self, message: Message, request_id: object = None) -> tuple[Message, object]:
        self.protect_calls += 1
        self.request_ids.append(request_id)
        if self.fail_protect:
            raise ValueError("injected protection failure")
        protected = Message(
            code=message.code, payload=f"protected-{self.protect_calls}".encode()
        )
        protected.opt.oscore = b"\x01"
        if self.fail_encode:
            protected.encode = cast(Any, self._fail_encode)
        return protected, object()

    @staticmethod
    def _fail_encode() -> bytes:
        raise ValueError("injected encode failure")


class _ManualTimer:
    def __init__(self, delay: float, callback: Any) -> None:
        self.delay = delay
        self.callback = callback
        self.cancelled = False
        self.elapsed = 0.0
        self.fired = False

    def cancel(self) -> None:
        self.cancelled = True

    def fire(self) -> None:
        self.advance(self.delay - self.elapsed)

    def advance(self, seconds: float) -> None:
        if self.cancelled or self.fired:
            return
        self.elapsed += seconds
        if self.elapsed >= self.delay:
            self.fired = True
            self.callback()


def _capture_timer(
    timers: list[_ManualTimer], delay: float, callback: Any
) -> _ManualTimer:
    timer = _ManualTimer(delay, callback)
    timers.append(timer)
    return timer


def _message(*, code: Any, mtype: Any, mid: int, token: bytes) -> bytes:
    message = Message(code=code, _mtype=mtype, _mid=mid, _token=token)
    message.remote = LichenRemote("peer")
    return cast(bytes, message.encode())


def _channel() -> tuple[SecureDatagramChannel, _RecordingChannel]:
    inner = _RecordingChannel()
    return SecureDatagramChannel(inner, Identity.generate()), inner


def _context(sender_id: bytes = b"\x01", recipient_id: bytes = b"\x02") -> MemorySecurityContext:
    return MemorySecurityContext(
        master_secret=b"s" * 16,
        master_salt=b"t" * 8,
        sender_id=sender_id,
        recipient_id=recipient_id,
    )


class _ContentResource(resource.Resource):
    async def render_get(self, _request: Message) -> Message:
        return Message(code=CONTENT, payload=b"value")


class _BlockingSite:
    async def render_to_pipe(self, _pipe: Any) -> None:
        await asyncio.Event().wait()


def _activate(
    channel: SecureDatagramChannel, oscore: Any
) -> PeerContext:
    peer = PeerContext(oscore, b"peer-key")
    channel._active_peer_contexts["peer"] = peer

    async def get_peer_context(host: str) -> PeerContext:
        assert host == "peer"
        return peer

    channel._get_peer_context = cast(Any, get_peer_context)
    return peer


def test_equal_tokens_are_isolated_by_direction() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"same"
    outbound = _RequestCorrelation(object(), observe=True)
    inbound = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = outbound
    peer.inbound_requests[token] = inbound

    channel.request_interest_ended(
        "peer", token, outbound.lifecycle_id, locally_originated=True
    )

    assert token not in peer.outbound_requests
    assert token in peer.inbound_requests


@pytest.mark.asyncio
async def test_real_oscore_equal_token_bidirectional_responses_decrypt() -> None:
    alice_inner = _RecordingChannel()
    bob_inner = _RecordingChannel()
    alice = SecureDatagramChannel(alice_inner, Identity.generate())
    bob = SecureDatagramChannel(bob_inner, Identity.generate())
    alice.add_context_sync("bob", _context(b"\x01", b"\x02"), b"bob-key")
    bob.add_context_sync("alice", _context(b"\x02", b"\x01"), b"alice-key")
    token = b"shared"
    alice_request = _message(code=GET, mtype=NON, mid=100, token=token)
    bob_request = _message(code=GET, mtype=NON, mid=101, token=token)

    await alice._send_protected(alice_request, "bob")
    await bob._send_protected(bob_request, "alice")
    alice_wire = alice_inner.sent[-1][0]
    bob_wire = bob_inner.sent[-1][0]
    alice_peer = alice._active_peer_contexts["bob"]
    bob_peer = bob._active_peer_contexts["alice"]

    alice_incoming = Message.decode(bob_wire, LichenRemote("bob"))
    alice_incoming.direction = Direction.INCOMING
    bob_incoming = Message.decode(alice_wire, LichenRemote("alice"))
    bob_incoming.direction = Direction.INCOMING
    assert await alice._unprotect_datagram(alice_incoming, "bob") is not None
    assert await bob._unprotect_datagram(bob_incoming, "alice") is not None

    assert alice_peer.outbound_requests[token].request_id is not (
        alice_peer.inbound_requests[token].request_id
    )
    assert bob_peer.outbound_requests[token].request_id is not (
        bob_peer.inbound_requests[token].request_id
    )

    alice_response = Message(
        code=CONTENT,
        _mtype=NON,
        _mid=102,
        _token=token,
        payload=b"alice-response",
    )
    alice_response.remote = LichenRemote("bob")
    bob_response = Message(
        code=CONTENT,
        _mtype=NON,
        _mid=103,
        _token=token,
        payload=b"bob-response",
    )
    bob_response.remote = LichenRemote("alice")
    await alice._send_protected(cast(bytes, alice_response.encode()), "bob")
    await bob._send_protected(cast(bytes, bob_response.encode()), "alice")

    protected_for_alice = Message.decode(
        bob_inner.sent[-1][0], LichenRemote("bob")
    )
    protected_for_alice.direction = Direction.INCOMING
    protected_for_bob = Message.decode(
        alice_inner.sent[-1][0], LichenRemote("alice")
    )
    protected_for_bob.direction = Direction.INCOMING
    alice_plaintext = await alice._unprotect_datagram(protected_for_alice, "bob")
    bob_plaintext = await bob._unprotect_datagram(protected_for_bob, "alice")

    assert alice_plaintext is not None
    assert bob_plaintext is not None
    assert Message.decode(
        alice_plaintext.data, LichenRemote("bob")
    ).payload == b"bob-response"
    assert Message.decode(
        bob_plaintext.data, LichenRemote("alice")
    ).payload == b"alice-response"


@pytest.mark.asyncio
async def test_terminal_response_retires_only_after_successful_dispatch() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"ordinary"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.outbound_requests[token] = correlation
    outer = Message(code=CONTENT, _mtype=NON, _mid=1, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")
    plaintext = Message(code=CONTENT, _mtype=NON, _mid=1, _token=token)
    plaintext.remote = LichenRemote("peer")

    async def unprotect(_message: Message, _source: str) -> _UnprotectedDatagram:
        return _UnprotectedDatagram(
            cast(bytes, plaintext.encode()), plaintext, matched_correlation=correlation
        )

    channel._unprotect_datagram = cast(Any, unprotect)

    def first_receiver(_data: bytes, _source: str) -> None:
        pass

    channel.set_receiver(first_receiver)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    assert token not in peer.outbound_requests

    correlation = _RequestCorrelation(object(), observe=False)
    peer.outbound_requests[token] = correlation

    def fail_delivery(_data: bytes, _source: str) -> None:
        raise RuntimeError("injected delivery failure")

    channel.clear_receiver(first_receiver)
    channel.set_receiver(fail_delivery)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    assert token in peer.outbound_requests


@pytest.mark.asyncio
async def test_observe_notifications_retain_id_until_cancel() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"observe"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = correlation
    outer = Message(code=CONTENT, _mtype=NON, _mid=2, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")

    async def unprotect(message: Message, _source: str) -> _UnprotectedDatagram:
        plaintext = Message(code=CONTENT, _mtype=NON, _mid=message.mid, _token=token)
        plaintext.opt.observe = message.mid
        plaintext.remote = LichenRemote("peer")
        return _UnprotectedDatagram(
            cast(bytes, plaintext.encode()),
            plaintext,
            matched_correlation=correlation,
        )

    channel._unprotect_datagram = cast(Any, unprotect)
    channel.set_receiver(lambda _data, _source: None)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    outer.mid = 3
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    assert peer.outbound_requests[token] is correlation

    channel.request_interest_ended(
        "peer", token, correlation.lifecycle_id, locally_originated=True
    )
    assert token not in peer.outbound_requests


@pytest.mark.asyncio
async def test_aiocoap_observe_cancel_immediately_ends_secure_interest() -> None:
    inner = _RecordingChannel()
    context = await create_lichen_context(inner, "local")
    try:
        message = Message(code=GET, uri="coap://peer/value", observe=0)
        request = context.request(message, handle_blockwise=False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert request.observation is not None

        request.observation.cancel()

        assert message.token
        identity = inner.identities[("peer", message.token, True)]
        assert inner.interest_ended[-1] == ("peer", message.token, identity, True)
        request.response.cancel()
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_established_observe_cancel_releases_exchange_and_rsts_next_notification() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    context = await create_lichen_context(channel, "local")
    observe_message = Message(code=GET, uri="coap://peer/observe", observe=0)
    observe = context.request(observe_message, handle_blockwise=False)
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))
        correlation = peer.outbound_requests[observe_message.token]
        token_manager = context.request_interfaces[0]
        message_manager = token_manager.token_interface
        exchange_key = (observe_message.remote, observe_message.mid)
        _monitor, retransmission = message_manager._active_exchanges[exchange_key]

        initial = Message(
            code=CONTENT,
            _mtype=CON,
            _mid=800,
            _token=observe_message.token,
            payload=b"initial",
        )
        initial.opt.observe = 0
        assert channel._receiver is not None
        channel._receiver(cast(bytes, initial.encode()), "peer")
        assert (await observe.response).payload == b"initial"
        await asyncio.gather(*tuple(channel._tasks))

        next_message = Message(code=GET, uri="coap://peer/next")
        next_request = context.request(next_message, handle_blockwise=False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        sent_before_cancel = len(inner.sent)

        assert observe.observation is not None
        observe.observation.cancel()
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))

        assert (observe_message.token, observe_message.remote) not in (
            token_manager.outgoing_requests
        )
        assert exchange_key not in message_manager._active_exchanges
        assert retransmission.cancelled()
        assert len(inner.sent) == sent_before_cancel + 1
        assert correlation.cancelled_observe
        assert peer.outbound_requests[observe_message.token] is correlation
        assert correlation.cancellation_deadline is not None
        assert observe_message.transport_tuning.EXCHANGE_LIFETIME == 247.0
        assert correlation.cancellation_deadline - asyncio.get_running_loop().time() == (
            pytest.approx(
                observe_message.transport_tuning.EXCHANGE_LIFETIME, abs=0.1
            )
        )

        notification = Message(
            code=CONTENT,
            _mtype=CON,
            _mid=801,
            _token=observe_message.token,
            payload=b"late",
        )
        notification.opt.observe = 1
        notification.remote = LichenRemote("peer")
        outer = Message(
            code=CONTENT,
            _mtype=CON,
            _mid=801,
            _token=observe_message.token,
        )
        outer.opt.oscore = b"\x01"
        outer.remote = LichenRemote("peer")

        async def unprotect(
            _message: Message, _source: str
        ) -> _UnprotectedDatagram:
            return _UnprotectedDatagram(
                cast(bytes, notification.encode()),
                notification,
                matched_correlation=correlation,
            )

        channel._unprotect_datagram = cast(Any, unprotect)
        await channel._process_incoming(cast(bytes, outer.encode()), "peer")
        await asyncio.gather(*tuple(channel._tasks))

        assert peer.outbound_requests[observe_message.token] is correlation
        rst = Message.decode(inner.sent[-1][0], LichenRemote("peer"))
        assert rst.code is EMPTY
        assert rst.mtype is RST
        assert rst.mid == 801

        release = Message(code=EMPTY, _mtype=ACK, _mid=next_message.mid)
        channel._receiver(cast(bytes, release.encode()), "peer")
        next_request.response.cancel()
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_cancel_tombstone_decrypts_two_real_con_retransmissions_then_expires() -> None:
    client_inner = _RecordingChannel()
    server_inner = _RecordingChannel()
    client = SecureDatagramChannel(client_inner, Identity.generate())
    server = SecureDatagramChannel(server_inner, Identity.generate())
    client.add_context_sync("server", _context(b"\x01", b"\x02"), b"server-key")
    server.add_context_sync("client", _context(b"\x02", b"\x01"), b"client-key")
    token = b"observe"
    request = Message(code=GET, _mtype=NON, _mid=810, _token=token)
    request.opt.observe = 0
    request.remote = LichenRemote("server")
    await client._send_protected(cast(bytes, request.encode()), "server")
    protected_request = Message.decode(
        client_inner.sent[-1][0], LichenRemote("client")
    )
    protected_request.direction = Direction.INCOMING
    assert await server._unprotect_datagram(protected_request, "client") is not None

    client_peer = client._active_peer_contexts["server"]
    correlation = client_peer.outbound_requests[token]
    timers: list[_ManualTimer] = []

    def schedule(delay: float, callback: Any) -> _ManualTimer:
        return _capture_timer(timers, delay, callback)

    client._schedule_cancellation_expiry = cast(Any, schedule)
    exchange_lifetime = request.transport_tuning.EXCHANGE_LIFETIME
    client.observation_cancelled(
        "server", token, correlation.lifecycle_id, exchange_lifetime
    )
    context = await create_lichen_context(client, "client")
    try:
        notification = Message(
            code=CONTENT,
            _mtype=CON,
            _mid=811,
            _token=token,
            payload=b"notification",
        )
        notification.opt.observe = 1
        notification.remote = LichenRemote("client")
        await server._send_protected(
            cast(bytes, notification.encode()), "client"
        )
        protected_notification = server_inner.sent[-1][0]

        for _ in range(2):
            sent_before = len(client_inner.sent)
            await client._process_incoming(protected_notification, "server")
            await asyncio.gather(*tuple(client._tasks))
            assert len(client_inner.sent) == sent_before + 1
            rst = Message.decode(
                client_inner.sent[sent_before][0], LichenRemote("server")
            )
            assert rst.code is EMPTY
            assert rst.mtype is RST
            assert rst.mid == 811
            assert client_peer.outbound_requests[token] is correlation

        assert len(timers) == 1
        assert timers[0].delay == exchange_lifetime
        timers[0].fire()
        assert token not in client_peer.outbound_requests
        assert correlation.cancellation_timer is None
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_silent_cancel_tombstone_expires_without_timer_leak() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"silent"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = correlation
    timers: list[_ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(timers, delay, callback),
    )

    exchange_lifetime = 13.0
    channel.observation_cancelled(
        "peer", token, correlation.lifecycle_id, exchange_lifetime
    )
    assert len(timers) == 1
    assert timers[0].delay == exchange_lifetime
    timers[0].advance(exchange_lifetime - 0.001)
    assert peer.outbound_requests[token] is correlation
    assert not timers[0].fired
    timers[0].advance(0.001)

    assert token not in peer.outbound_requests
    assert correlation.cancellation_timer is None
    assert correlation.cancellation_deadline is None


@pytest.mark.asyncio
async def test_non_cancel_notifications_do_not_refresh_tombstone_expiry() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"non-only"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = correlation
    timers: list[_ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(timers, delay, callback),
    )
    exchange_lifetime = 17.0
    channel.observation_cancelled(
        "peer", token, correlation.lifecycle_id, exchange_lifetime
    )
    original_deadline = correlation.cancellation_deadline
    timers[0].advance(5.0)
    notification = Message(code=CONTENT, _mtype=NON, _mid=812, _token=token)
    notification.opt.observe = 2
    notification.remote = LichenRemote("peer")
    outer = Message(code=CONTENT, _mtype=NON, _mid=812, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")

    async def unprotect(
        _message: Message, _source: str
    ) -> _UnprotectedDatagram:
        return _UnprotectedDatagram(
            cast(bytes, notification.encode()),
            notification,
            matched_correlation=correlation,
        )

    channel._unprotect_datagram = cast(Any, unprotect)
    channel.set_receiver(lambda _data, _source: None)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    channel.observation_cancelled(
        "peer", token, correlation.lifecycle_id, exchange_lifetime
    )

    assert peer.outbound_requests[token] is correlation
    assert len(timers) == 1
    assert timers[0].delay == exchange_lifetime
    assert timers[0].elapsed == 5.0
    assert correlation.cancellation_deadline == original_deadline
    timers[0].advance(exchange_lifetime - 5.001)
    assert peer.outbound_requests[token] is correlation
    timers[0].advance(0.001)
    assert token not in peer.outbound_requests


@pytest.mark.asyncio
async def test_cancel_tombstone_expiry_is_identity_safe_under_token_reuse() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"reuse"
    old = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = old
    timers: list[_ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(timers, delay, callback),
    )
    channel.observation_cancelled("peer", token, old.lifecycle_id, 247.0)
    replacement = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = replacement

    timers[0].fire()

    assert peer.outbound_requests[token] is replacement
    assert old.cancellation_timer is None


@pytest.mark.asyncio
async def test_cancel_timers_clear_on_close_and_context_replacement() -> None:
    first, _first_inner = _channel()
    first_peer = _activate(first, _FakeOscore())
    first_correlation = _RequestCorrelation(object(), observe=True)
    first_peer.outbound_requests[b"close"] = first_correlation
    first_timers: list[_ManualTimer] = []
    first._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(first_timers, delay, callback),
    )
    first.observation_cancelled(
        "peer", b"close", first_correlation.lifecycle_id, 247.0
    )
    first.close()
    assert first_timers[0].cancelled
    assert first_correlation.cancellation_timer is None

    second, _second_inner = _channel()
    second_peer = _activate(second, _FakeOscore())
    second_correlation = _RequestCorrelation(object(), observe=True)
    second_peer.outbound_requests[b"replace"] = second_correlation
    second_timers: list[_ManualTimer] = []
    second._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(second_timers, delay, callback),
    )
    second.observation_cancelled(
        "peer", b"replace", second_correlation.lifecycle_id, 247.0
    )
    second._publish_peer_context(
        "peer", PeerContext(_FakeOscore(), b"peer-key", generation=2)
    )
    assert second_timers[0].cancelled
    assert second_correlation.cancellation_timer is None


@pytest.mark.asyncio
async def test_piggybacked_ack_only_ends_exact_active_exchange() -> None:
    inner = _RecordingChannel()
    context = await create_lichen_context(inner, "local")
    try:
        request = context.request(
            Message(code=GET, uri="coap://peer/value"), handle_blockwise=False
        )
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        outgoing = Message.decode(inner.sent[-1][0], LichenRemote("peer"))
        response = Message(
            code=CONTENT,
            _mtype=ACK,
            _mid=outgoing.mid,
            _token=outgoing.token,
            payload=b"ok",
        )
        assert inner.receiver is not None
        inner.receiver(cast(bytes, response.encode()), "peer")

        assert (await request.response).payload == b"ok"
        assert inner.exchanges_ended == [("peer", outgoing.mid, False)]

        unmatched = Message(code=EMPTY, _mtype=ACK, _mid=outgoing.mid, _token=b"")
        inner.receiver(cast(bytes, unmatched.encode()), "peer")
        assert inner.exchanges_ended == [("peer", outgoing.mid, False)]
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_mid_reuse_replaces_stale_ciphertext_cache() -> None:
    channel, inner = _channel()
    oscore = _FakeOscore()
    _activate(channel, oscore)
    first = _message(code=GET, mtype=CON, mid=41, token=b"first")
    second = _message(code=GET, mtype=CON, mid=41, token=b"second")

    await channel._send_protected(first, "peer")
    first_ciphertext = inner.sent[-1][0]
    channel.exchange_ended("peer", 41, reset=False)
    await channel._send_protected(second, "peer")

    assert oscore.protect_calls == 2
    assert inner.sent[-1][0] != first_ciphertext
    assert channel._protected_cons[("peer", 41)].token == b"second"


@pytest.mark.asyncio
@pytest.mark.parametrize("mtype", [ACK, CON])
async def test_deferred_terminal_observe_response_survives_until_send(
    mtype: Any,
) -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"obs-term"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[token] = correlation
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    try:
        channel.send_datagram(
            _message(code=CONTENT, mtype=mtype, mid=42, token=token), "peer"
        )
        channel.response_completed("peer", token, correlation.lifecycle_id)
        channel.request_interest_ended(
            "peer", token, correlation.lifecycle_id, locally_originated=False
        )
        assert peer.inbound_requests[token] is correlation
        assert correlation.pending_sends == 1
    finally:
        lock.release()

    await asyncio.gather(*tuple(channel._tasks))
    assert inner.sent
    if mtype is CON:
        assert peer.inbound_requests[token] is correlation
        channel.exchange_ended("peer", 42, reset=False)
    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_same_token_pipe_replacement_cannot_end_new_correlation() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    context = await create_lichen_context(
        channel, "local", site=cast(Any, _BlockingSite())
    )
    token = b"refresh"
    try:
        first = _RequestCorrelation(object(), observe=True)
        peer.inbound_requests[token] = first
        request1 = Message(code=GET, _mtype=NON, _mid=50, _token=token)
        request1.opt.observe = 0
        request1.remote = LichenRemote("peer")
        assert channel._receiver is not None
        channel._receiver(cast(bytes, request1.encode()), "peer")
        await asyncio.sleep(0)

        replacement = _RequestCorrelation(object(), observe=True)
        peer.inbound_requests[token] = replacement
        request2 = Message(code=GET, _mtype=NON, _mid=51, _token=token)
        request2.opt.observe = 0
        request2.remote = LichenRemote("peer")
        channel._receiver(cast(bytes, request2.encode()), "peer")

        assert peer.inbound_requests[token] is replacement
        assert replacement.interested
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_idempotent_context_put_preserves_lifecycle_state() -> None:
    inner = _RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    oscore = _context()
    channel.add_context_sync("peer", oscore, b"peer-key")
    peer = channel._active_peer_contexts["peer"]
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[b"observe"] = correlation

    await channel.add_context("peer", oscore, b"peer-key")

    assert channel._active_peer_contexts["peer"] is peer
    assert peer.inbound_requests[b"observe"] is correlation


def test_same_generation_reload_transfers_lifecycle_state() -> None:
    channel, _inner = _channel()
    old_peer = _activate(channel, _FakeOscore())
    correlation = _RequestCorrelation(object(), observe=True)
    old_peer.inbound_requests[b"observe"] = correlation
    replacement = PeerContext(_FakeOscore(), b"peer-key", generation=old_peer.generation)

    channel._publish_peer_context("peer", replacement)

    assert channel._active_peer_contexts["peer"] is replacement
    assert replacement.inbound_requests[b"observe"] is correlation


@pytest.mark.asyncio
async def test_remove_context_serializes_and_clears_lifecycle() -> None:
    inner = _RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    channel.add_context_sync("peer", _context(), b"peer-key")
    peer = channel._active_peer_contexts["peer"]
    peer.inbound_requests[b"request"] = _RequestCorrelation(object(), observe=False)
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[b"observe"] = correlation
    timers: list[_ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: _capture_timer(timers, delay, callback),
    )
    channel.observation_cancelled(
        "peer", b"observe", correlation.lifecycle_id, 247.0
    )

    await channel.remove_context("peer")

    assert "peer" not in channel._active_peer_contexts
    assert peer.inbound_requests == {}
    assert timers[0].cancelled
    assert correlation.cancellation_timer is None
    assert not await channel.has_context("peer")


@pytest.mark.asyncio
async def test_context_replacement_retires_queued_old_response() -> None:
    inner = _RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    old_oscore = _context()
    channel.add_context_sync("peer", old_oscore, b"peer-key")
    old_peer = channel._active_peer_contexts["peer"]
    token = b"old"
    correlation = _RequestCorrelation(object(), observe=False)
    old_peer.inbound_requests[token] = correlation
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    try:
        replacement_task = asyncio.create_task(
            channel.add_context("peer", _context(b"\x03", b"\x04"), b"peer-key")
        )
        await asyncio.sleep(0)
        channel.send_datagram(
            _message(code=CONTENT, mtype=NON, mid=52, token=token), "peer"
        )
    finally:
        lock.release()

    await replacement_task
    await asyncio.gather(*tuple(channel._tasks))
    assert channel._active_peer_contexts["peer"] is not old_peer
    assert old_peer.inbound_requests == {}
    assert inner.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mtype", [NON, CON])
@pytest.mark.filterwarnings("ignore:Initializing messages with an MID is deprecated")
@pytest.mark.filterwarnings("ignore:Initializing messages with an mtype is deprecated")
async def test_no_response_final_retires_suppressed_and_empty_ack(mtype: Any) -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    site = resource.Site()
    site.add_resource(["value"], _ContentResource())
    context = await create_lichen_context(channel, "local", site=site)
    token = b"no-response"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.inbound_requests[token] = correlation
    request = Message(code=GET, _mtype=mtype, _mid=53, _token=token)
    request.opt.uri_path = ("value",)
    request.opt.no_response = 2
    request.remote = LichenRemote("peer")
    try:
        assert channel._receiver is not None
        channel._receiver(cast(bytes, request.encode()), "peer")
        for _ in range(10):
            await asyncio.sleep(0)
            if token not in peer.inbound_requests:
                break

        assert token not in peer.inbound_requests
        if mtype is CON:
            await asyncio.gather(*tuple(channel._tasks))
            control = Message.decode(inner.sent[-1][0], LichenRemote("peer"))
            assert control.code is EMPTY
            assert control.mtype is ACK
        else:
            assert inner.sent == []
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_failed_terminal_con_protection_retires_on_expiry() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore(fail_protect=True))
    token = b"failed"
    correlation = _RequestCorrelation(object(), observe=False, terminal=True)
    peer.inbound_requests[token] = correlation

    await channel._send_protected(
        _message(code=CONTENT, mtype=CON, mid=59, token=token), "peer"
    )

    assert peer.inbound_requests[token] is correlation
    assert correlation.con_mids == {59}
    assert channel._protected_cons[("peer", 59)].data == b""
    channel.exchange_expired("peer", 59)
    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_shutdown_cancels_queued_packet_tasks_and_rejects_new_send() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    peer.outbound_requests[b"receive"] = _RequestCorrelation(object(), observe=False)
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    channel.send_datagram(
        _message(code=GET, mtype=NON, mid=60, token=b"queued-send"), "peer"
    )
    incoming = Message(code=CONTENT, _mtype=NON, _mid=61, _token=b"receive")
    incoming.opt.oscore = b"\x01"
    incoming.remote = LichenRemote("peer")
    channel._on_datagram(cast(bytes, incoming.encode()), "peer")

    shutdown = asyncio.create_task(channel.shutdown())
    await asyncio.sleep(0)
    lock.release()
    await shutdown

    assert channel._tasks == set()
    assert channel._active_peer_contexts == {}
    assert channel._pending_outbound == {}
    assert inner.sent == []
    assert inner.closed
    with pytest.raises(RuntimeError, match="closing"):
        channel.send_datagram(
            _message(code=GET, mtype=NON, mid=62, token=b"late"), "peer"
        )


@pytest.mark.asyncio
async def test_shutdown_releases_receiver_and_inner_once() -> None:
    channel, inner = _channel()
    channel.set_receiver(lambda _data, _source: None)

    await asyncio.gather(channel.shutdown(), channel.shutdown())
    await channel.shutdown()
    channel.close()

    assert inner.receiver is None
    assert inner.clear_calls == 1
    assert inner.shutdown_calls == 1
    assert inner.close_calls == 0
    assert channel._receiver is None


@pytest.mark.asyncio
async def test_shutdown_cleans_up_and_shares_edhoc_failure() -> None:
    channel, inner = _channel()
    channel.set_receiver(lambda _data, _source: None)
    edhoc_error = RuntimeError("injected EDHOC shutdown failure")

    class _FailingEdhocContext:
        calls = 0

        async def shutdown(self) -> None:
            self.calls += 1
            raise edhoc_error

    edhoc = _FailingEdhocContext()
    channel._edhoc_ctx = cast(Any, edhoc)

    results = await asyncio.gather(
        channel.shutdown(), channel.shutdown(), return_exceptions=True
    )
    repeated = await asyncio.gather(channel.shutdown(), return_exceptions=True)

    assert results == [edhoc_error, edhoc_error]
    assert repeated == [edhoc_error]
    assert edhoc.calls == 1
    assert inner.shutdown_calls == 1
    assert inner.receiver is None
    assert channel._edhoc_ctx is None
    assert channel._edhoc_channel is None
    assert channel._active_peer_contexts == {}


@pytest.mark.asyncio
async def test_shutdown_continues_after_receiver_detach_failure() -> None:
    channel, inner = _channel()
    channel.set_receiver(lambda _data, _source: None)
    clear_error = RuntimeError("injected receiver detach failure")
    inner.clear_error = clear_error

    results = await asyncio.gather(
        channel.shutdown(), channel.shutdown(), return_exceptions=True
    )

    assert results == [clear_error, clear_error]
    assert inner.clear_calls == 1
    assert inner.shutdown_calls == 1
    assert channel._inner_receiver_registered is False
    assert channel._receiver is None


def test_close_continues_after_receiver_detach_failure() -> None:
    channel, inner = _channel()
    channel.set_receiver(lambda _data, _source: None)
    clear_error = RuntimeError("injected receiver detach failure")
    inner.clear_error = clear_error

    with pytest.raises(RuntimeError) as raised:
        channel.close()
    channel.close()

    assert raised.value is clear_error
    assert inner.clear_calls == 1
    assert inner.close_calls == 1
    assert channel._inner_receiver_registered is False
    assert channel._receiver is None


@pytest.mark.asyncio
async def test_close_then_shutdown_does_not_repeat_inner_teardown() -> None:
    channel, inner = _channel()
    channel.set_receiver(lambda _data, _source: None)

    channel.close()
    channel.close()
    await channel.shutdown()
    await channel.shutdown()

    assert inner.receiver is None
    assert inner.clear_calls == 1
    assert inner.close_calls == 1
    assert inner.shutdown_calls == 0


@pytest.mark.asyncio
async def test_nstart_cancelled_backlogged_observe_never_sends() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    context = await create_lichen_context(channel, "local")
    first_message = Message(code=GET, uri="coap://peer/first")
    second_message = Message(code=GET, uri="coap://peer/observe", observe=0)
    first = context.request(first_message, handle_blockwise=False)
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))
        assert len(inner.sent) == 1

        second = context.request(second_message, handle_blockwise=False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert second.observation is not None
        assert len(inner.sent) == 1
        second_identity = second_message._lichen_lifecycle_id
        assert channel.request_started(
            "peer", second_message.token, locally_originated=True
        ) is second_identity

        second.observation.cancel()
        second.response.cancel()
        assert channel.request_started(
            "peer", second_message.token, locally_originated=True
        ) is None

        response = Message(
            code=CONTENT,
            _mtype=ACK,
            _mid=first_message.mid,
            _token=first_message.token,
            payload=b"first",
        )
        assert channel._receiver is not None
        channel._receiver(cast(bytes, response.encode()), "peer")
        assert (await first.response).payload == b"first"
        await asyncio.sleep(0)

        assert len(inner.sent) == 1
        assert second_message.token not in peer.outbound_requests
        assert ("peer", second_message.token) not in channel._pending_outbound
        assert id(second_message) not in channel._message_admissions
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_nstart_backlogged_terminal_con_retains_until_ack() -> None:
    channel, inner = _channel()
    oscore = _FakeOscore()
    peer = _activate(channel, oscore)
    context = await create_lichen_context(channel, "local")
    blocker_message = Message(code=GET, uri="coap://peer/blocker")
    blocker = context.request(blocker_message, handle_blockwise=False)
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))
        assert len(inner.sent) == 1

        token_manager = context.request_interfaces[0]
        message_manager = token_manager.token_interface
        token = b"terminal"
        request_id = object()
        correlation = _RequestCorrelation(request_id, observe=True, interested=False)
        peer.inbound_requests[token] = correlation
        observe_request = Message(code=GET, _mtype=NON, _mid=70, _token=token)
        observe_request.opt.observe = 0
        observe_request.remote = LichenRemote("peer")
        observe_request._lichen_lifecycle_id = correlation.lifecycle_id
        terminal = Message(code=CONTENT, _mtype=CON, _token=token, payload=b"done")
        terminal.remote = blocker_message.remote
        terminal.request = observe_request

        message_manager.send_message(terminal, lambda: None)

        assert len(inner.sent) == 1
        assert correlation.terminal
        assert correlation.pending_sends == 1
        assert peer.inbound_requests[token] is correlation
        assert id(terminal) in channel._message_admissions

        release = Message(code=EMPTY, _mtype=ACK, _mid=blocker_message.mid)
        assert channel._receiver is not None
        channel._receiver(cast(bytes, release.encode()), "peer")
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))

        assert len(inner.sent) == 2
        assert correlation.pending_sends == 0
        assert correlation.con_mids == {terminal.mid}
        assert oscore.request_ids[-1] is request_id
        assert peer.inbound_requests[token] is correlation
        assert id(terminal) not in channel._message_admissions

        ack = Message(code=EMPTY, _mtype=ACK, _mid=terminal.mid)
        channel._receiver(cast(bytes, ack.encode()), "peer")
        assert token not in peer.inbound_requests
        blocker.response.cancel()
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_max_retransmit_abandons_all_backlog_lifecycle_state() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    context = await create_lichen_context(channel, "local")
    blocker_message = Message(code=GET, uri="coap://peer/blocker")
    blocker = context.request(blocker_message, handle_blockwise=False)
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.gather(*tuple(channel._tasks))
        assert len(inner.sent) == 1
        blocker_token = blocker_message.token
        assert ("peer", blocker_message.mid) in channel._protected_cons

        queued_message = Message(code=GET, uri="coap://peer/queued", observe=0)
        queued = context.request(queued_message, handle_blockwise=False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        queued_identity = queued_message._lichen_lifecycle_id
        assert channel.request_started(
            "peer", queued_message.token, locally_originated=True
        ) is queued_identity

        token_manager = context.request_interfaces[0]
        message_manager = token_manager.token_interface
        response_token = b"timeout"
        terminal_correlation = _RequestCorrelation(
            object(), observe=True, interested=False
        )
        peer.inbound_requests[response_token] = terminal_correlation
        incoming = Message(
            code=GET, _mtype=NON, _mid=72, _token=response_token
        )
        incoming.opt.observe = 0
        incoming.remote = LichenRemote("peer")
        incoming._lichen_lifecycle_id = terminal_correlation.lifecycle_id
        terminal = Message(
            code=CONTENT,
            _mtype=CON,
            _token=response_token,
            payload=b"timeout",
        )
        terminal.remote = blocker_message.remote
        terminal.request = incoming
        message_manager.send_message(terminal, lambda: None)
        assert terminal_correlation.pending_sends == 1
        assert id(terminal) in channel._message_admissions

        message_manager._retransmit(
            blocker_message,
            1.0,
            blocker_message.transport_tuning.MAX_RETRANSMIT,
        )

        with pytest.raises(error.NetworkError):
            await blocker.response
        with pytest.raises(error.NetworkError):
            await queued.response
        assert blocker_token not in peer.outbound_requests
        assert queued_message.token not in peer.outbound_requests
        assert ("peer", queued_message.token) not in channel._pending_outbound
        assert ("peer", blocker_message.mid) not in channel._protected_cons
        assert id(terminal) not in channel._message_admissions
        assert terminal_correlation.pending_sends == 0
        assert terminal_correlation.terminal
        assert response_token not in peer.inbound_requests
        assert blocker_message.remote not in message_manager._backlogs
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_terminal_response_encode_failure_completes_after_admission_rollback() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    context = await create_lichen_context(channel, "local")
    token = b"failure"
    correlation = _RequestCorrelation(object(), observe=True, interested=False)
    peer.inbound_requests[token] = correlation
    request = Message(code=GET, _mtype=NON, _mid=71, _token=token)
    request.opt.observe = 0
    request.remote = LichenRemote("peer")
    request._lichen_lifecycle_id = correlation.lifecycle_id
    response = Message(
        code=CONTENT,
        _mtype=NON,
        _token=token,
        payload=cast(Any, "not-bytes"),
    )
    response.remote = LichenRemote("peer")
    response.request = request
    token_manager = context.request_interfaces[0]
    message_manager = token_manager.token_interface
    remote = await message_manager.message_interface.determine_remote(
        Message(code=GET, uri="coap://peer")
    )
    request.remote = remote
    response.remote = remote
    try:
        with pytest.raises(TypeError):
            message_manager.send_message(response, lambda: None)

        assert correlation.pending_sends == 0
        assert correlation.terminal
        assert token not in peer.inbound_requests
        assert id(response) not in channel._message_admissions
    finally:
        await context.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("mtype", [ACK, NON])
async def test_ordinary_inbound_correlation_retires_after_response(mtype: Any) -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"inbound"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.inbound_requests[token] = correlation
    channel.response_completed("peer", token, correlation.lifecycle_id)

    await channel._send_protected(
        _message(code=CONTENT, mtype=mtype, mid=9, token=token), "peer"
    )

    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_inbound_observe_retained_across_notifications_and_rst() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"inbound-observe"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[token] = correlation
    notification = Message(code=CONTENT, _mtype=CON, _mid=10, _token=token)
    notification.opt.observe = 1
    notification.remote = LichenRemote("peer")

    await channel._send_protected(cast(bytes, notification.encode()), "peer")
    assert peer.inbound_requests[token] is correlation

    channel.exchange_ended("peer", 10, reset=True)
    assert token not in peer.inbound_requests


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["ack", "rst", "expiry"])
async def test_con_retransmission_reuses_bytes_and_retires(ending: str) -> None:
    channel, inner = _channel()
    oscore = _FakeOscore()
    peer = _activate(channel, oscore)
    token = b"response"
    correlation = _RequestCorrelation(
        object(), observe=False, interested=False, terminal=True
    )
    peer.inbound_requests[token] = correlation
    wire = _message(code=CONTENT, mtype=CON, mid=17, token=token)

    await channel._send_protected(wire, "peer")
    await channel._send_protected(wire, "peer")

    assert oscore.protect_calls == 1
    assert inner.sent[0][0] == inner.sent[1][0]
    assert correlation.con_mids == {17}

    if ending == "expiry":
        channel.exchange_expired("peer", 17)
    else:
        channel.exchange_ended("peer", 17, reset=ending == "rst")
    assert token not in peer.inbound_requests
    assert ("peer", 17) not in channel._protected_cons


@pytest.mark.asyncio
async def test_failed_send_retries_cached_con_without_reprotecting() -> None:
    channel, inner = _channel()
    inner.fail_sends = 1
    oscore = _FakeOscore()
    peer = _activate(channel, oscore)
    token = b"request"
    wire = _message(code=GET, mtype=CON, mid=21, token=token)

    await channel._send_protected(wire, "peer")
    assert token not in peer.outbound_requests
    cached = channel._protected_cons[("peer", 21)].data

    await channel._send_protected(wire, "peer")
    assert oscore.protect_calls == 1
    assert inner.sent == [(cached, "peer")]
    assert token in peer.outbound_requests


@pytest.mark.asyncio
async def test_encode_failure_does_not_publish_correlation() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore(fail_encode=True))

    await channel._send_protected(_message(code=GET, mtype=NON, mid=22, token=b"bad"), "peer")

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}


@pytest.mark.asyncio
async def test_protection_failure_does_not_publish_correlation() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore(fail_protect=True))

    await channel._send_protected(
        _message(code=GET, mtype=NON, mid=23, token=b"bad-protect"), "peer"
    )

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}


@pytest.mark.asyncio
async def test_failed_request_delivery_rolls_back_new_inbound_mapping() -> None:
    channel, _inner = _channel()
    peer = _activate(channel, _FakeOscore())
    token = b"delivery"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.inbound_requests[token] = correlation
    outer = Message(code=GET, _mtype=NON, _mid=24, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")
    plaintext = Message(code=GET, _mtype=NON, _mid=24, _token=token)
    plaintext.remote = LichenRemote("peer")

    async def unprotect(_message: Message, _source: str) -> _UnprotectedDatagram:
        return _UnprotectedDatagram(
            cast(bytes, plaintext.encode()), plaintext, correlation
        )

    channel._unprotect_datagram = cast(Any, unprotect)

    def fail_delivery(_data: bytes, _source: str) -> None:
        raise RuntimeError("delivery failed")

    channel.set_receiver(fail_delivery)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")

    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_empty_ack_and_rst_pass_unprotected_without_unmatched_mutation() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[b"kept"] = correlation
    received: list[bytes] = []
    channel.set_receiver(lambda data, _source: received.append(data))

    for mtype, mid in ((ACK, 30), (RST, 31)):
        wire = _message(code=EMPTY, mtype=mtype, mid=mid, token=b"")
        await channel._send_protected(wire, "peer")
        await channel._process_incoming(wire, "peer")

    assert [data for data, _dest in inner.sent] == received
    assert peer.inbound_requests[b"kept"] is correlation


def test_close_clears_bounded_lifecycle_state() -> None:
    channel, inner = _channel()
    peer = _activate(channel, _FakeOscore())
    peer.outbound_requests[b"request"] = _RequestCorrelation(object(), observe=True)
    channel._protected_cons[("peer", 1)] = _ProtectedCon(
        b"ciphertext", b"request", True
    )

    channel.close()

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}
    assert inner.closed


def test_lifecycle_adapter_rejects_unsupported_aiocoap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lichen.coap.transport.importlib.metadata.version", lambda _name: "0.4.18")
    with pytest.raises(RuntimeError, match="requires aiocoap 0.4.17"):
        _AiocoapLifecycleAdapter(cast(Any, object()), _RecordingChannel())
