# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared test fixtures for secure CoAP transport tests."""

from __future__ import annotations

from typing import Any, cast

import pytest
from aiocoap import Message, resource
from aiocoap.numbers.codes import CONTENT

from lichen.coap.secure import (
    PeerContext,
    SecureDatagramChannel,
)
from lichen.coap.transport import DatagramChannel, LichenRemote
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


class RecordingChannel(DatagramChannel):
    """Test double that records all sent datagrams."""

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

    def request_started(self, peer: str, token: bytes, *, locally_originated: bool) -> object:
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


class FakeOscore:
    """Test double for OSCORE context."""

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
        protected = Message(code=message.code, payload=f"protected-{self.protect_calls}".encode())
        protected.opt.oscore = b"\x01"
        if self.fail_encode:
            protected.encode = cast(Any, self._fail_encode)
        return protected, object()

    @staticmethod
    def _fail_encode() -> bytes:
        raise ValueError("injected encode failure")


class ManualTimer:
    """Test timer that can be manually advanced."""

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


def capture_timer(timers: list[ManualTimer], delay: float, callback: Any) -> ManualTimer:
    """Capture a timer into the list for manual control."""
    timer = ManualTimer(delay, callback)
    timers.append(timer)
    return timer


def make_message(*, code: Any, mtype: Any, mid: int, token: bytes) -> bytes:
    """Create an encoded CoAP message."""
    message = Message(code=code, _mtype=mtype, _mid=mid, _token=token)
    message.remote = LichenRemote("peer")
    return cast(bytes, message.encode())


def make_context(
    sender_id: bytes = b"\x01", recipient_id: bytes = b"\x02"
) -> MemorySecurityContext:
    """Create a test OSCORE context."""
    return MemorySecurityContext(
        master_secret=b"s" * 16,
        master_salt=b"t" * 8,
        sender_id=sender_id,
        recipient_id=recipient_id,
    )


class ContentResource(resource.Resource):
    """Simple CoAP resource that returns fixed content."""

    async def render_get(self, _request: Message) -> Message:
        return Message(code=CONTENT, payload=b"value")


def activate_peer(channel: SecureDatagramChannel, oscore: Any) -> PeerContext:
    """Activate a peer context on a channel."""
    peer = PeerContext(oscore, b"peer-key")
    channel._active_peer_contexts["peer"] = peer

    async def get_peer_context(host: str) -> PeerContext:
        assert host == "peer"
        return peer

    channel._get_peer_context = cast(Any, get_peer_context)
    return peer


@pytest.fixture
def channel_pair() -> tuple[SecureDatagramChannel, RecordingChannel]:
    """Create a SecureDatagramChannel with a RecordingChannel inner."""
    inner = RecordingChannel()
    return SecureDatagramChannel(inner, Identity.generate()), inner
