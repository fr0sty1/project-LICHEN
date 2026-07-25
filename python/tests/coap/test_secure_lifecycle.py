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

from lichen.coap.secure import SecureDatagramChannel
from lichen.coap.secure.types import (
    _ProtectedCon,
    _RequestCorrelation,
    _UnprotectedDatagram,
)
from lichen.coap.transport import (
    LichenRemote,
    _AiocoapLifecycleAdapter,
    create_lichen_context,
)
from lichen.crypto.identity import Identity

from .conftest import (
    ContentResource,
    FakeOscore,
    ManualTimer,
    RecordingChannel,
    activate_peer,
    capture_timer,
    make_context,
    make_message,
)


class _BlockingSite:
    """Site that blocks forever for testing."""

    async def render_to_pipe(self, _pipe: Any) -> None:
        await asyncio.Event().wait()


@pytest.mark.asyncio
async def test_terminal_response_retires_only_after_successful_dispatch() -> None:
    """Terminal response retires correlation only after successful dispatch."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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
    """Observe notifications retain request ID until cancel."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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

    channel.request_interest_ended("peer", token, correlation.lifecycle_id, locally_originated=True)
    assert token not in peer.outbound_requests


@pytest.mark.asyncio
async def test_aiocoap_observe_cancel_immediately_ends_secure_interest() -> None:
    """aiocoap observe cancel immediately ends secure interest."""
    inner = RecordingChannel()
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
    """Established observe cancel releases exchange and RSTs next notification."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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
            pytest.approx(observe_message.transport_tuning.EXCHANGE_LIFETIME, abs=0.1)
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

        async def unprotect(_message: Message, _source: str) -> _UnprotectedDatagram:
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
    """Cancel tombstone decrypts CON retransmissions then expires."""
    from aiocoap.oscore import Direction

    client_inner = RecordingChannel()
    server_inner = RecordingChannel()
    client = SecureDatagramChannel(client_inner, Identity.generate())
    server = SecureDatagramChannel(server_inner, Identity.generate())
    client.add_context_sync("server", make_context(b"\x01", b"\x02"), b"server-key")
    server.add_context_sync("client", make_context(b"\x02", b"\x01"), b"client-key")
    token = b"observe"
    request = Message(code=GET, _mtype=NON, _mid=810, _token=token)
    request.opt.observe = 0
    request.remote = LichenRemote("server")
    await client._send_protected(cast(bytes, request.encode()), "server")
    protected_request = Message.decode(client_inner.sent[-1][0], LichenRemote("client"))
    protected_request.direction = Direction.INCOMING
    assert await server._unprotect_datagram(protected_request, "client") is not None

    client_peer = client._active_peer_contexts["server"]
    correlation = client_peer.outbound_requests[token]
    timers: list[ManualTimer] = []

    def schedule(delay: float, callback: Any) -> ManualTimer:
        return capture_timer(timers, delay, callback)

    client._schedule_cancellation_expiry = cast(Any, schedule)
    exchange_lifetime = request.transport_tuning.EXCHANGE_LIFETIME
    client.observation_cancelled("server", token, correlation.lifecycle_id, exchange_lifetime)
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
        await server._send_protected(cast(bytes, notification.encode()), "client")
        protected_notification = server_inner.sent[-1][0]

        for _ in range(2):
            sent_before = len(client_inner.sent)
            await client._process_incoming(protected_notification, "server")
            await asyncio.gather(*tuple(client._tasks))
            assert len(client_inner.sent) == sent_before + 1
            rst = Message.decode(client_inner.sent[sent_before][0], LichenRemote("server"))
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
    """Silent cancel tombstone expires without timer leak."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"silent"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = correlation
    timers: list[ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(timers, delay, callback),
    )

    exchange_lifetime = 13.0
    channel.observation_cancelled("peer", token, correlation.lifecycle_id, exchange_lifetime)
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
    """NON notifications do not refresh tombstone expiry."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"non-only"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = correlation
    timers: list[ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(timers, delay, callback),
    )
    exchange_lifetime = 17.0
    channel.observation_cancelled("peer", token, correlation.lifecycle_id, exchange_lifetime)
    original_deadline = correlation.cancellation_deadline
    timers[0].advance(5.0)
    notification = Message(code=CONTENT, _mtype=NON, _mid=812, _token=token)
    notification.opt.observe = 2
    notification.remote = LichenRemote("peer")
    outer = Message(code=CONTENT, _mtype=NON, _mid=812, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")

    async def unprotect(_message: Message, _source: str) -> _UnprotectedDatagram:
        return _UnprotectedDatagram(
            cast(bytes, notification.encode()),
            notification,
            matched_correlation=correlation,
        )

    channel._unprotect_datagram = cast(Any, unprotect)
    channel.set_receiver(lambda _data, _source: None)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")
    channel.observation_cancelled("peer", token, correlation.lifecycle_id, exchange_lifetime)

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
    """Cancel tombstone expiry is identity-safe under token reuse."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"reuse"
    old = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = old
    timers: list[ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(timers, delay, callback),
    )
    channel.observation_cancelled("peer", token, old.lifecycle_id, 247.0)
    replacement = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = replacement

    timers[0].fire()

    assert peer.outbound_requests[token] is replacement
    assert old.cancellation_timer is None


@pytest.mark.asyncio
async def test_piggybacked_ack_only_ends_exact_active_exchange() -> None:
    """Piggybacked ACK only ends exact active exchange."""
    inner = RecordingChannel()
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
@pytest.mark.parametrize("mtype", [ACK, CON])
async def test_deferred_terminal_observe_response_survives_until_send(
    mtype: Any,
) -> None:
    """Deferred terminal observe response survives until send."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"obs-term"
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[token] = correlation
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    try:
        channel.send_datagram(make_message(code=CONTENT, mtype=mtype, mid=42, token=token), "peer")
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
    """Same token pipe replacement cannot end new correlation."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    context = await create_lichen_context(channel, "local", site=cast(Any, _BlockingSite()))
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
@pytest.mark.parametrize("mtype", [NON, CON])
@pytest.mark.filterwarnings("ignore:Initializing messages with an MID is deprecated")
@pytest.mark.filterwarnings("ignore:Initializing messages with an mtype is deprecated")
async def test_no_response_final_retires_suppressed_and_empty_ack(mtype: Any) -> None:
    """No-response final retires suppressed and sends empty ACK."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    site = resource.Site()
    site.add_resource(["value"], ContentResource())
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
    """Failed terminal CON protection retires on expiry."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore(fail_protect=True))
    token = b"failed"
    correlation = _RequestCorrelation(object(), observe=False, terminal=True)
    peer.inbound_requests[token] = correlation

    await channel._send_protected(make_message(code=CONTENT, mtype=CON, mid=59, token=token), "peer")

    assert peer.inbound_requests[token] is correlation
    assert correlation.con_mids == {59}
    assert channel._protected_cons[("peer", 59)].data == b""
    channel.exchange_expired("peer", 59)
    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_shutdown_cancels_queued_packet_tasks_and_rejects_new_send() -> None:
    """Shutdown cancels queued packet tasks and rejects new send."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    peer.outbound_requests[b"receive"] = _RequestCorrelation(object(), observe=False)
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    channel.send_datagram(make_message(code=GET, mtype=NON, mid=60, token=b"queued-send"), "peer")
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
        channel.send_datagram(make_message(code=GET, mtype=NON, mid=62, token=b"late"), "peer")


@pytest.mark.asyncio
async def test_shutdown_releases_receiver_and_inner_once() -> None:
    """Shutdown releases receiver and inner exactly once."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
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
    """Shutdown cleans up and shares EDHOC failure across waiters."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    channel.set_receiver(lambda _data, _source: None)
    edhoc_error = RuntimeError("injected EDHOC shutdown failure")

    class _FailingEdhocContext:
        calls = 0

        async def shutdown(self) -> None:
            self.calls += 1
            raise edhoc_error

    edhoc = _FailingEdhocContext()
    channel._edhoc_ctx = cast(Any, edhoc)

    results = await asyncio.gather(channel.shutdown(), channel.shutdown(), return_exceptions=True)
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
    """Shutdown continues after receiver detach failure."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    channel.set_receiver(lambda _data, _source: None)
    clear_error = RuntimeError("injected receiver detach failure")
    inner.clear_error = clear_error

    results = await asyncio.gather(channel.shutdown(), channel.shutdown(), return_exceptions=True)

    assert results == [clear_error, clear_error]
    assert inner.clear_calls == 1
    assert inner.shutdown_calls == 1
    assert channel._inner_receiver_registered is False
    assert channel._receiver is None


def test_close_continues_after_receiver_detach_failure() -> None:
    """Close continues after receiver detach failure."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
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
    """Close then shutdown does not repeat inner teardown."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
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
    """NSTART-cancelled backlogged observe never sends."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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
        assert (
            channel.request_started("peer", second_message.token, locally_originated=True)
            is second_identity
        )

        second.observation.cancel()
        second.response.cancel()
        assert (
            channel.request_started("peer", second_message.token, locally_originated=True) is None
        )

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
    """NSTART-backlogged terminal CON retains until ACK."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    oscore = FakeOscore()
    peer = activate_peer(channel, oscore)
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
    """MAX_RETRANSMIT abandons all backlog lifecycle state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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
        assert (
            channel.request_started("peer", queued_message.token, locally_originated=True)
            is queued_identity
        )

        token_manager = context.request_interfaces[0]
        message_manager = token_manager.token_interface
        response_token = b"timeout"
        terminal_correlation = _RequestCorrelation(object(), observe=True, interested=False)
        peer.inbound_requests[response_token] = terminal_correlation
        incoming = Message(code=GET, _mtype=NON, _mid=72, _token=response_token)
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
    """Terminal response encode failure completes after admission rollback."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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
    """Ordinary inbound correlation retires after response."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"inbound"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.inbound_requests[token] = correlation
    channel.response_completed("peer", token, correlation.lifecycle_id)

    await channel._send_protected(make_message(code=CONTENT, mtype=mtype, mid=9, token=token), "peer")

    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_inbound_observe_retained_across_notifications_and_rst() -> None:
    """Inbound observe is retained across notifications until RST."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
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


def test_close_clears_bounded_lifecycle_state() -> None:
    """Close clears bounded lifecycle state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    peer.outbound_requests[b"request"] = _RequestCorrelation(object(), observe=True)
    channel._protected_cons[("peer", 1)] = _ProtectedCon(b"ciphertext", b"request", True)

    channel.close()

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}
    assert inner.closed


def test_lifecycle_adapter_rejects_unsupported_aiocoap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lifecycle adapter rejects unsupported aiocoap version."""
    monkeypatch.setattr("lichen.coap.transport.importlib.metadata.version", lambda _name: "0.4.18")
    with pytest.raises(RuntimeError, match="requires aiocoap 0.4.17"):
        _AiocoapLifecycleAdapter(cast(Any, object()), RecordingChannel())
