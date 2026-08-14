# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE security context management in SecureDatagramChannel."""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from aiocoap.numbers.codes import CONTENT
from aiocoap.numbers.types import NON

from lichen.coap.secure import PeerContext, SecureDatagramChannel
from lichen.coap.secure.types import _RequestCorrelation
from lichen.crypto.identity import Identity

from .conftest import (
    FakeOscore,
    ManualTimer,
    RecordingChannel,
    activate_peer,
    capture_timer,
    make_context,
    make_message,
)


@pytest.mark.asyncio
async def test_idempotent_context_put_preserves_lifecycle_state() -> None:
    """Adding the same context twice is idempotent and preserves lifecycle state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    oscore = make_context()
    channel.add_context_sync("peer", oscore, b"peer-key")
    peer = channel._active_peer_contexts["peer"]
    correlation = _RequestCorrelation(object(), observe=True)
    peer.inbound_requests[b"observe"] = correlation

    await channel.add_context("peer", oscore, b"peer-key")

    assert channel._active_peer_contexts["peer"] is peer
    assert peer.inbound_requests[b"observe"] is correlation


def test_same_generation_reload_transfers_lifecycle_state() -> None:
    """Reloading a context with the same generation transfers lifecycle state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    old_peer = activate_peer(channel, FakeOscore())
    correlation = _RequestCorrelation(object(), observe=True)
    old_peer.inbound_requests[b"observe"] = correlation
    replacement = PeerContext(FakeOscore(), b"peer-key", generation=old_peer.generation)

    channel._publish_peer_context("peer", replacement)

    assert channel._active_peer_contexts["peer"] is replacement
    assert replacement.inbound_requests[b"observe"] is correlation


@pytest.mark.asyncio
async def test_remove_context_serializes_and_clears_lifecycle() -> None:
    """Removing a context serializes access and clears lifecycle state."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    channel.add_context_sync("peer", make_context(), b"peer-key")
    peer = channel._active_peer_contexts["peer"]
    peer.inbound_requests[b"request"] = _RequestCorrelation(object(), observe=False)
    correlation = _RequestCorrelation(object(), observe=True)
    peer.outbound_requests[b"observe"] = correlation
    timers: list[ManualTimer] = []
    channel._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(timers, delay, callback),
    )
    channel.observation_cancelled("peer", b"observe", correlation.lifecycle_id, 247.0)

    await channel.remove_context("peer")

    assert "peer" not in channel._active_peer_contexts
    assert peer.inbound_requests == {}
    assert timers[0].cancelled
    assert correlation.cancellation_timer is None
    assert not await channel.has_context("peer")


@pytest.mark.asyncio
async def test_context_replacement_retires_queued_old_response() -> None:
    """Replacing a context retires queued responses for the old context."""
    inner = RecordingChannel()
    channel = SecureDatagramChannel(inner, Identity.generate())
    old_oscore = make_context()
    channel.add_context_sync("peer", old_oscore, b"peer-key")
    old_peer = channel._active_peer_contexts["peer"]
    token = b"old"
    correlation = _RequestCorrelation(object(), observe=False)
    old_peer.inbound_requests[token] = correlation
    lock = channel._peer_locks.setdefault("peer", asyncio.Lock())
    await lock.acquire()
    try:
        replacement_task = asyncio.create_task(
            channel.add_context("peer", make_context(b"\x03", b"\x04"), b"peer-key")
        )
        await asyncio.sleep(0)
        channel.send_datagram(
            make_message(code=CONTENT, mtype=NON, mid=52, token=token), "peer"
        )
    finally:
        lock.release()

    await replacement_task
    await asyncio.gather(*tuple(channel._tasks))
    assert channel._active_peer_contexts["peer"] is not old_peer
    assert old_peer.inbound_requests == {}
    assert inner.sent == []


@pytest.mark.asyncio
async def test_cancel_timers_clear_on_close_and_context_replacement() -> None:
    """Cancellation timers are cleared on close and context replacement."""
    # Test close
    inner = RecordingChannel()
    first = SecureDatagramChannel(inner, Identity.generate())
    first_peer = activate_peer(first, FakeOscore())
    first_correlation = _RequestCorrelation(object(), observe=True)
    first_peer.outbound_requests[b"close"] = first_correlation
    first_timers: list[ManualTimer] = []
    first._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(first_timers, delay, callback),
    )
    first.observation_cancelled("peer", b"close", first_correlation.lifecycle_id, 247.0)
    first.close()
    assert first_timers[0].cancelled
    assert first_correlation.cancellation_timer is None

    # Test context replacement
    inner2 = RecordingChannel()
    second = SecureDatagramChannel(inner2, Identity.generate())
    second_peer = activate_peer(second, FakeOscore())
    second_correlation = _RequestCorrelation(object(), observe=True)
    second_peer.outbound_requests[b"replace"] = second_correlation
    second_timers: list[ManualTimer] = []
    second._schedule_cancellation_expiry = cast(
        Any,
        lambda delay, callback: capture_timer(second_timers, delay, callback),
    )
    second.observation_cancelled("peer", b"replace", second_correlation.lifecycle_id, 247.0)
    second._publish_peer_context("peer", PeerContext(FakeOscore(), b"peer-key", generation=2))
    assert second_timers[0].cancelled
    assert second_correlation.cancellation_timer is None
