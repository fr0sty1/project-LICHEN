# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE message protection and unprotection in SecureDatagramChannel."""

from __future__ import annotations

from typing import Any, cast

import pytest
from aiocoap import GET, Message
from aiocoap.numbers.codes import CONTENT, EMPTY
from aiocoap.numbers.types import ACK, CON, NON, RST
from aiocoap.oscore import Direction

from lichen.coap.secure import SecureDatagramChannel
from lichen.coap.secure.types import _RequestCorrelation, _UnprotectedDatagram
from lichen.coap.transport import LichenRemote
from lichen.crypto.identity import Identity

from .conftest import (
    FakeOscore,
    RecordingChannel,
    activate_peer,
    make_context,
    make_message,
)


def test_equal_tokens_are_isolated_by_direction() -> None:
    """Equal tokens are isolated by request direction (outbound vs inbound)."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"same"
    outbound = _RequestCorrelation(object(), observe=True)
    inbound = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[token] = outbound
    peer.inbound_requests[token] = inbound

    channel.request_interest_ended("peer", token, outbound.lifecycle_id, locally_originated=True)

    assert token not in peer.outbound_requests
    assert token in peer.inbound_requests


@pytest.mark.asyncio
async def test_real_oscore_equal_token_bidirectional_responses_decrypt() -> None:
    """Bidirectional OSCORE with equal tokens decrypts correctly."""
    alice_inner = RecordingChannel()
    bob_inner = RecordingChannel()
    alice = SecureDatagramChannel(alice_inner, Identity.generate())
    bob = SecureDatagramChannel(bob_inner, Identity.generate())
    alice.add_context_sync("bob", make_context(b"\x01", b"\x02"), b"bob-key")
    bob.add_context_sync("alice", make_context(b"\x02", b"\x01"), b"alice-key")
    token = b"shared"
    alice_request = make_message(code=GET, mtype=NON, mid=100, token=token)
    bob_request = make_message(code=GET, mtype=NON, mid=101, token=token)

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

    protected_for_alice = Message.decode(bob_inner.sent[-1][0], LichenRemote("bob"))
    protected_for_alice.direction = Direction.INCOMING
    protected_for_bob = Message.decode(alice_inner.sent[-1][0], LichenRemote("alice"))
    protected_for_bob.direction = Direction.INCOMING
    alice_plaintext = await alice._unprotect_datagram(protected_for_alice, "bob")
    bob_plaintext = await bob._unprotect_datagram(protected_for_bob, "alice")

    assert alice_plaintext is not None
    assert bob_plaintext is not None
    assert Message.decode(alice_plaintext.data, LichenRemote("bob")).payload == b"bob-response"
    assert Message.decode(bob_plaintext.data, LichenRemote("alice")).payload == b"alice-response"


@pytest.mark.asyncio
async def test_mid_reuse_replaces_stale_ciphertext_cache() -> None:
    """MID reuse replaces stale ciphertext in the cache."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    oscore = FakeOscore()
    activate_peer(channel, oscore)
    first = make_message(code=GET, mtype=CON, mid=41, token=b"first")
    second = make_message(code=GET, mtype=CON, mid=41, token=b"second")

    await channel._send_protected(first, "peer")
    first_ciphertext = inner.sent[-1][0]
    channel.exchange_ended("peer", 41, reset=False)
    await channel._send_protected(second, "peer")

    assert oscore.protect_calls == 2
    assert inner.sent[-1][0] != first_ciphertext
    assert channel._protected_cons[("peer", 41)].token == b"second"


@pytest.mark.asyncio
@pytest.mark.parametrize("ending", ["ack", "rst", "expiry"])
async def test_con_retransmission_reuses_bytes_and_retires(ending: str) -> None:
    """CON retransmissions reuse cached bytes and retire on ACK/RST/expiry."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    oscore = FakeOscore()
    peer = activate_peer(channel, oscore)
    token = b"response"
    correlation = _RequestCorrelation(object(), observe=False, interested=False, terminal=True)
    peer.inbound_requests[token] = correlation
    wire = make_message(code=CONTENT, mtype=CON, mid=17, token=token)

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
    """Failed send retries use cached CON without re-protecting."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    inner.fail_sends = 1
    oscore = FakeOscore()
    peer = activate_peer(channel, oscore)
    token = b"request"
    wire = make_message(code=GET, mtype=CON, mid=21, token=token)

    await channel._send_protected(wire, "peer")
    assert token not in peer.outbound_requests
    cached = channel._protected_cons[("peer", 21)].data

    await channel._send_protected(wire, "peer")
    assert oscore.protect_calls == 1
    assert inner.sent == [(cached, "peer")]
    assert token in peer.outbound_requests


@pytest.mark.asyncio
async def test_encode_failure_does_not_publish_correlation() -> None:
    """Encode failure during protection does not publish correlation."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore(fail_encode=True))

    await channel._send_protected(make_message(code=GET, mtype=NON, mid=22, token=b"bad"), "peer")

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}


@pytest.mark.asyncio
async def test_protection_failure_does_not_publish_correlation() -> None:
    """Protection failure does not publish correlation."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore(fail_protect=True))

    await channel._send_protected(
        make_message(code=GET, mtype=NON, mid=23, token=b"bad-protect"), "peer"
    )

    assert peer.outbound_requests == {}
    assert channel._protected_cons == {}


@pytest.mark.asyncio
async def test_failed_request_delivery_rolls_back_new_inbound_mapping() -> None:
    """Failed request delivery rolls back newly created inbound mapping."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    token = b"delivery"
    correlation = _RequestCorrelation(object(), observe=False)
    peer.inbound_requests[token] = correlation
    outer = Message(code=GET, _mtype=NON, _mid=24, _token=token)
    outer.opt.oscore = b"\x01"
    outer.remote = LichenRemote("peer")
    plaintext = Message(code=GET, _mtype=NON, _mid=24, _token=token)
    plaintext.remote = LichenRemote("peer")

    async def unprotect(_message: Message, _source: str) -> _UnprotectedDatagram:
        return _UnprotectedDatagram(cast(bytes, plaintext.encode()), plaintext, correlation)

    channel._unprotect_datagram = cast(Any, unprotect)

    def fail_delivery(_data: bytes, _source: str) -> None:
        raise RuntimeError("delivery failed")

    channel.set_receiver(fail_delivery)
    await channel._process_incoming(cast(bytes, outer.encode()), "peer")

    assert token not in peer.inbound_requests


@pytest.mark.asyncio
async def test_empty_ack_and_rst_pass_unprotected_without_unmatched_mutation() -> None:
    """Empty ACK and RST pass through unprotected without mutating state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    peer = activate_peer(channel, FakeOscore())
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[b"kept"] = correlation
    received: list[bytes] = []
    channel.set_receiver(lambda data, _source: received.append(data))

    for mtype, mid in ((ACK, 30), (RST, 31)):
        wire = make_message(code=EMPTY, mtype=mtype, mid=mid, token=b"")
        await channel._send_protected(wire, "peer")
        await channel._process_incoming(wire, "peer")

    assert [data for data, _dest in inner.sent] == received
    assert peer.inbound_requests[b"kept"] is correlation
