# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Oracle tests for /deaddrop (spec 18.9).

Drives ``DeadDropResource`` as the Python oracle for store-and-forward drops:
OSCORE write gate, rate/size/storage limits, TTL clamp and expiry, FIFO
eviction, query filters, private-drop 4.03, Observe, and deaddrop.json pins.
"""

from __future__ import annotations

import asyncio
import json
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import aiocoap
import cbor2
import pytest
from aiocoap import GET, POST, Message

from lichen.coap.resources import StaticNodeInfo
from lichen.coap.resources.base import CBOR, SENML_CBOR
from lichen.coap.resources.deaddrop import (
    DEADDROP_DEFAULT_TTL,
    DEADDROP_MAX_DROP_SIZE,
    DEADDROP_MAX_TTL,
    DEADDROP_POSTS_PER_HOUR,
    DEADDROP_STORAGE_BR,
    DEADDROP_STORAGE_LEAF,
    DeadDropDetailsResource,
    DeadDropResource,
)
from lichen.coap.resources.site import build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.oscore import MemorySecurityContext
from lichen.senml.codec import SenmlRecord, pack, unpack

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test" / "vectors" / "deaddrop.json").read_text()
)


def _vec(name: str) -> dict[str, Any]:
    matches = [item for item in VECTORS["vectors"] if item["name"] == name]
    assert len(matches) == 1, name
    return cast(dict[str, Any], matches[0])


class _Clock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _records(*items: dict[str, Any]) -> list[SenmlRecord]:
    return [SenmlRecord(**item) for item in items]


def _senml(*items: dict[str, Any]) -> list[SenmlRecord]:
    """Build a SenML pack as ``SenmlRecord`` list (RFC 8428 field names)."""
    return _records(*items)


def _protected(payload: list[SenmlRecord] | bytes, context: str = "ctx-a") -> Message:
    body = payload if isinstance(payload, bytes) else pack(payload)
    request = Message(code=POST, payload=body)
    request.oscore_context_id = context
    return request


class _PostUnprotectRemote:
    """Structural aiocoap OSCOREAddress used after successful unprotect."""

    def __init__(self, security_context: object) -> None:
        self.security_context = security_context


def _memory_context(*, recipient_id: bytes, sender_id: bytes = b"server") -> MemorySecurityContext:
    return MemorySecurityContext(
        master_secret=b"\x11" * 16,
        master_salt=b"\x22" * 8,
        sender_id=sender_id,
        recipient_id=recipient_id,
        id_context=b"deaddrop",
    )


def _live_oscore_request(
    payload: list[SenmlRecord] | bytes,
    *,
    recipient_id: bytes,
    code: Any = POST,
) -> tuple[Message, MemorySecurityContext]:
    body = payload if isinstance(payload, bytes) else pack(payload)
    context = _memory_context(recipient_id=recipient_id)
    request = Message(code=code, payload=body)
    request.remote = _PostUnprotectRemote(context)
    return request, context


def _spoofed_oscore(
    payload: list[SenmlRecord] | bytes,
    option: bytes | None = b"\x00",
) -> Message:
    """Plaintext POST with a client-attached OSCORE option (not unprotected)."""
    body = payload if isinstance(payload, bytes) else pack(payload)
    request = Message(code=POST, payload=body)
    request.opt.oscore = option
    return request


def _record_value(records: list[SenmlRecord], name: str) -> Any:
    for record in records:
        if record.n == name:
            if record.vs is not None:
                return record.vs
            return record.v
    return None


def _get(
    *,
    path: tuple[str, ...] = (),
    query: tuple[str, ...] = (),
    context: str | None = None,
) -> Message:
    request = Message(code=GET)
    if path:
        request.opt.uri_path = path
    if query:
        request.opt.uri_query = query
    if context is not None:
        request.oscore_context_id = context
    return request


# ---------------------------------------------------------------------------
# Spec constants
# ---------------------------------------------------------------------------


class TestSpecConstants:
    def test_rate_and_storage_match_spec_18_9(self) -> None:
        assert DEADDROP_POSTS_PER_HOUR == 6
        assert DEADDROP_MAX_DROP_SIZE == 1536
        assert DEADDROP_STORAGE_LEAF == 8 * 1024
        assert DEADDROP_STORAGE_BR == 32 * 1024
        assert DEADDROP_DEFAULT_TTL == 24 * 3600
        assert DEADDROP_MAX_TTL == 7 * 24 * 3600

    def test_rejects_non_positive_storage_limit(self) -> None:
        with pytest.raises(ValueError):
            DeadDropResource(storage_limit=0)
        with pytest.raises(ValueError):
            DeadDropResource(storage_limit=-1)
        with pytest.raises(ValueError):
            DeadDropResource(storage_limit=True)


# ---------------------------------------------------------------------------
# POST / GET oracle
# ---------------------------------------------------------------------------


class TestPostAndGet:
    async def test_unprotected_post_unauthorized(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(
            Message(code=POST, payload=pack(_senml({"n": "content", "vs": "x"})))
        )
        assert response.code == aiocoap.UNAUTHORIZED
        assert response.opt.content_format == CBOR
        assert cbor2.loads(response.payload) == {"error": "oscore_required"}
        assert dd.drops() == []

    async def test_protected_post_created_with_location_and_max_age(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml({"n": "type", "vs": "message"}, {"n": "content", "vs": "hi"})
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        assert response.opt.location_path[0] == "deaddrop"
        assert len(response.opt.location_path[1]) == 6
        assert response.opt.max_age == DEADDROP_DEFAULT_TTL
        assert len(dd.drops()) == 1

    async def test_get_wraps_each_drop_with_metadata(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "type", "vs": "message"}, {"n": "content", "vs": "bottle"})
        created = await dd.render_post(_protected(payload))
        drop_id = created.opt.location_path[1]
        clock.t += 12
        response = await dd.render_get(_get())
        assert response.code == aiocoap.CONTENT
        assert response.opt.content_format == SENML_CBOR
        records = unpack(response.payload)
        assert any(r.n == "id" and r.vs == drop_id for r in records)
        assert any(r.n == "age_s" and r.u == "s" and r.v == 12 for r in records)
        assert any(r.n == "content" and r.vs == "bottle" for r in records)

    async def test_empty_get_is_empty_senml_array(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_get(_get())
        assert response.code == aiocoap.CONTENT
        assert unpack(response.payload) == []

    async def test_empty_payload_is_bad_request(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(_protected(b""))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_non_array_cbor_is_bad_request(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(_protected(cbor2.dumps({"n": "content", "vs": "x"})))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_trailing_cbor_is_bad_request(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = pack(_senml({"n": "content", "vs": "x"})) + b"\x00"
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.BAD_REQUEST


class TestOscorePostGate:
    """Spec 18.9: POST requires a distinct post-unprotect OSCORE identity."""

    _PAYLOAD = _senml({"n": "content", "vs": "x"})

    async def _reject_unprotected(self, request: Message) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(request)
        assert response.code == aiocoap.UNAUTHORIZED
        assert response.opt.content_format == CBOR
        assert cbor2.loads(response.payload) == {"error": "oscore_required"}
        assert dd.drops() == []
        assert dd.storage_info()["drop_count"] == 0

    async def test_spoofed_oscore_option_is_unauthorized(self) -> None:
        await self._reject_unprotected(_spoofed_oscore(self._PAYLOAD, b"\x00"))

    async def test_empty_oscore_option_is_unauthorized(self) -> None:
        await self._reject_unprotected(_spoofed_oscore(self._PAYLOAD, b""))

    async def test_oscore_protected_flag_without_identity_is_unauthorized(self) -> None:
        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.oscore_protected = True
        await self._reject_unprotected(request)

    async def test_boolean_oscore_context_is_unauthorized(self) -> None:
        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.oscore_context = True
        await self._reject_unprotected(request)

    async def test_empty_bound_identity_is_unauthorized(self) -> None:
        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.oscore_context_id = ""
        request.oscore_context = ""
        await self._reject_unprotected(request)

    async def test_bound_context_id_still_creates(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(_protected(self._PAYLOAD, context="alice"))
        assert response.code == aiocoap.CREATED
        stored = dd.drops(context_id="alice")
        assert len(stored) == 1
        assert stored[0]["context"] == "alice"

    async def test_bound_identity_not_replaced_by_spoofed_option(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        request = _protected(self._PAYLOAD, context="alice")
        request.opt.oscore = b"\x00"
        response = await dd.render_post(request)
        assert response.code == aiocoap.CREATED
        assert dd.drops()[0]["context"] == "alice"

    async def test_bound_oscore_context_object_is_distinct(self) -> None:
        class _Ctx:
            def durable_context_id(self) -> bytes:
                return b"alice-ctx"

        dd = DeadDropResource(time_func=_Clock())
        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.oscore_context = _Ctx()
        request.opt.oscore = b"\x00"
        response = await dd.render_post(request)
        assert response.code == aiocoap.CREATED
        stored = dd.drops()[0]
        assert stored["context"] == b"alice-ctx".hex()

    async def test_identity_on_remote_counts_as_unprotect_binding(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.remote = type("R", (), {"oscore_context_id": "from-remote"})()
        response = await dd.render_post(request)
        assert response.code == aiocoap.CREATED
        assert dd.drops()[0]["context"] == "from-remote"

    async def test_live_unprotect_remote_uses_authenticated_peer_role(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        request, context = _live_oscore_request(self._PAYLOAD, recipient_id=b"alice")

        response = await dd.render_post(request)

        assert response.code == aiocoap.CREATED
        assert context.sender_id == b"server"
        assert context.recipient_id == b"alice"
        assert dd.drops()[0]["context"] == "oscore-peer:616c696365"

    async def test_reconstructed_live_context_cannot_replay_peer_quota(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        alice_contexts: list[MemorySecurityContext] = []
        for _ in range(DEADDROP_POSTS_PER_HOUR):
            clock.t += 1
            request, context = _live_oscore_request(self._PAYLOAD, recipient_id=b"alice")
            alice_contexts.append(context)
            assert (await dd.render_post(request)).code == aiocoap.CREATED

        # The legacy durable ID omits recipient_id; both peers deliberately
        # collide there. Authorization must still use each live peer's KID.
        bob_request, bob_context = _live_oscore_request(self._PAYLOAD, recipient_id=b"bob")
        assert alice_contexts[0].durable_context_id() == bob_context.durable_context_id()

        replayed_identity, _ = _live_oscore_request(self._PAYLOAD, recipient_id=b"alice")
        assert (await dd.render_post(replayed_identity)).code == aiocoap.TOO_MANY_REQUESTS
        assert (await dd.render_post(bob_request)).code == aiocoap.CREATED

    async def test_live_context_without_peer_identity_fails_closed(self) -> None:
        class _MissingPeer:
            def durable_context_id(self) -> bytes:
                return b"local-only-context"

        request = Message(code=POST, payload=pack(self._PAYLOAD))
        request.remote = _PostUnprotectRemote(_MissingPeer())
        request.oscore_context_id = "spoofed-fallback"
        request.opt.oscore = b"\x00"
        await self._reject_unprotected(request)

    async def test_live_peer_identity_controls_private_acl(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        details = DeadDropDetailsResource(dd)
        private = _senml(
            {"n": "privacy", "vs": "private"},
            {"n": "content", "vs": "alice-only"},
        )
        create_request, _ = _live_oscore_request(private, recipient_id=b"alice")
        created = await dd.render_post(create_request)
        drop_id = created.opt.location_path[1]

        bob_request, _ = _live_oscore_request(b"", recipient_id=b"bob", code=GET)
        bob_request.opt.uri_path = (drop_id,)
        # SECURITY: private drops return NOT_FOUND to hide existence
        assert (await details.render_get(bob_request)).code == aiocoap.NOT_FOUND

        alice_request, _ = _live_oscore_request(b"", recipient_id=b"alice", code=GET)
        alice_request.opt.uri_path = (drop_id,)
        allowed = await details.render_get(alice_request)
        assert allowed.code == aiocoap.CONTENT
        assert unpack(allowed.payload) == private

    async def test_spoofed_option_does_not_share_default_rate_bucket(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "content", "vs": "n"})
        for _ in range(DEADDROP_POSTS_PER_HOUR):
            clock.t += 1
            created = await dd.render_post(_protected(payload, context="default"))
            assert created.code == aiocoap.CREATED
        clock.t += 1
        spoofed = await dd.render_post(_spoofed_oscore(payload, b"\x00"))
        assert spoofed.code == aiocoap.UNAUTHORIZED
        assert cbor2.loads(spoofed.payload) == {"error": "oscore_required"}
        limited = await dd.render_post(_protected(payload, context="default"))
        assert limited.code == aiocoap.TOO_MANY_REQUESTS
        other = await dd.render_post(_protected(payload, context="ctx-b"))
        assert other.code == aiocoap.CREATED

    async def test_spoofed_option_does_not_unlock_private_drop(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml(
            {"n": "privacy", "vs": "private"},
            {"n": "content", "vs": "paired-only"},
        )
        created = await dd.render_post(_protected(payload, context="default"))
        drop_id = created.opt.location_path[1]
        spoof_list = Message(code=GET)
        spoof_list.opt.oscore = b"\x00"
        listing = await dd.render_get(spoof_list)
        assert listing.code == aiocoap.CONTENT
        assert unpack(listing.payload) == []
        details = DeadDropDetailsResource(dd)
        spoof_get = _get(path=(drop_id,))
        spoof_get.opt.oscore = b"\x00"
        spoof_get.oscore_protected = True
        # SECURITY: private drops return NOT_FOUND to hide existence
        forbidden = await details.render_get(spoof_get)
        assert forbidden.code == aiocoap.NOT_FOUND
        allowed = await details.render_get(_get(path=(drop_id,), context="default"))
        assert allowed.code == aiocoap.CONTENT
        assert unpack(allowed.payload) == payload


class TestDropById:
    async def test_get_single_drop_payload_and_max_age(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        details = DeadDropDetailsResource(dd)
        payload = _senml({"n": "content", "vs": "secret cache"})
        created = await dd.render_post(_protected(payload))
        drop_id = created.opt.location_path[1]
        clock.t += 100
        response = await details.render_get(_get(path=(drop_id,)))
        assert response.code == aiocoap.CONTENT
        assert response.opt.content_format == SENML_CBOR
        assert unpack(response.payload) == payload
        assert response.opt.max_age == DEADDROP_DEFAULT_TTL - 100

    async def test_missing_and_invalid_ids_are_not_found(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        details = DeadDropDetailsResource(dd)
        missing = await details.render_get(_get(path=("ffffff",)))
        assert missing.code == aiocoap.NOT_FOUND
        invalid = await details.render_get(_get(path=("7F3A9C",)))
        assert invalid.code == aiocoap.NOT_FOUND
        plus = await details.render_get(_get(path=("+fffff",)))
        assert plus.code == aiocoap.NOT_FOUND
        empty = await details.render_get(_get())
        assert empty.code == aiocoap.NOT_FOUND


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


class TestLimits:
    async def test_oversized_post_is_4_13(self) -> None:
        vec = _vec("request_entity_too_large")
        dd = DeadDropResource(time_func=_Clock())
        payload = b"\x00" * vec["payload_size"]
        response = await dd.render_post(_protected(payload))
        assert int(response.code) == vec["expected"]["response_code"]
        assert response.code == aiocoap.REQUEST_ENTITY_TOO_LARGE

    async def test_exact_max_size_accepted(self) -> None:
        dd = DeadDropResource(storage_limit=DEADDROP_MAX_DROP_SIZE + 16, time_func=_Clock())
        # CBOR array of one {n, vs} record; pad vs so encoded size == 1536.
        vs = "x" * 1500
        body = pack(_senml({"n": "content", "vs": vs}))
        assert len(body) <= DEADDROP_MAX_DROP_SIZE
        padded = body  # keep under the cap; the oversize case is the vector pin
        response = await dd.render_post(_protected(padded))
        assert response.code == aiocoap.CREATED

    async def test_seventh_post_in_hour_is_4_29(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "content", "vs": "n"})
        for _ in range(DEADDROP_POSTS_PER_HOUR):
            clock.t += 1
            response = await dd.render_post(_protected(payload))
            assert response.code == aiocoap.CREATED
        clock.t += 1
        limited = await dd.render_post(_protected(payload))
        assert limited.code == aiocoap.TOO_MANY_REQUESTS
        assert limited.opt.content_format == CBOR
        assert cbor2.loads(limited.payload) == {"retry_after": limited.opt.max_age}
        assert limited.opt.max_age >= 1
        # A different OSCORE context is not rate-limited by the first.
        other = await dd.render_post(_protected(payload, context="ctx-b"))
        assert other.code == aiocoap.CREATED

    async def test_rate_limit_clears_after_hour(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "content", "vs": "n"})
        for _ in range(DEADDROP_POSTS_PER_HOUR):
            clock.t += 1
            assert (await dd.render_post(_protected(payload))).code == aiocoap.CREATED
        clock.t += 3600
        retry = await dd.render_post(_protected(payload))
        assert retry.code == aiocoap.CREATED

    async def test_storage_full_returns_5_03_cbor(self) -> None:
        vec = _vec("storage_full_rejection")
        payload = _senml({"n": "content", "vs": "block"})
        size = len(pack(payload))
        dd = DeadDropResource(storage_limit=size, time_func=_Clock())
        first = await dd.render_post(_protected(payload, context="ctx-a"))
        assert first.code == aiocoap.CREATED
        # Same-size second drop from another context: cannot evict enough because
        # the in-flight drop still occupies the entire budget until eviction of
        # the oldest (which then leaves room). Fill with a larger encoded body.
        bigger = _senml({"n": "content", "vs": "block" + "!" * 16})
        assert len(pack(bigger)) > size
        full = await dd.render_post(_protected(bigger, context="ctx-b"))
        # Bigger than the limit: no eviction of the occupant, 5.03.
        assert int(full.code) == vec["expected"]["response_code"]
        assert full.code == aiocoap.SERVICE_UNAVAILABLE
        body = cbor2.loads(full.payload)
        assert body["reason"] == vec["expected"]["cbor_payload"]["reason"]
        assert body["retry_after"] == vec["expected"]["cbor_payload"]["retry_after"]
        assert "available_kb" in body
        assert dd.storage_info()["drop_count"] == 1

    async def test_drop_larger_than_budget_does_not_wipe_store(self) -> None:
        small = _senml({"n": "content", "vs": "keep"})
        size = len(pack(small))
        dd = DeadDropResource(storage_limit=size, time_func=_Clock())
        assert dd.add_drop(small, context_id="ctx-a", drop_id="aa0001") == "aa0001"
        huge = _senml({"n": "content", "vs": "x" * 200})
        assert len(pack(huge)) > size
        assert dd.add_drop(huge, context_id="ctx-b") is None
        assert [item["id"] for item in dd.drops()] == ["aa0001"]


class TestTtlAndEviction:
    async def test_ttl_clamped_to_seven_days(self) -> None:
        vec = _vec("ttl_clamped_to_max")
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml({"n": "ttl", "v": vec["ttl"]}, {"n": "content", "vs": "long"})
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        assert response.opt.max_age == vec["expected"]["effective_ttl"] == DEADDROP_MAX_TTL

    async def test_expired_drops_omitted_from_get(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "ttl", "v": 10}, {"n": "content", "vs": "soon"})
        created = await dd.render_post(_protected(payload))
        drop_id = created.opt.location_path[1]
        clock.t += 11
        listing = await dd.render_get(_get())
        assert unpack(listing.payload) == []
        details = DeadDropDetailsResource(dd)
        missing = await details.render_get(_get(path=(drop_id,)))
        assert missing.code == aiocoap.NOT_FOUND

    async def test_drop_expires_at_created_plus_ttl(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "ttl", "v": 10}, {"n": "content", "vs": "edge"})
        created = await dd.render_post(_protected(payload))
        drop_id = created.opt.location_path[1]
        clock.t += 10
        listing = await dd.render_get(_get())
        assert unpack(listing.payload) == []
        details = DeadDropDetailsResource(dd)
        missing = await details.render_get(_get(path=(drop_id,)))
        assert missing.code == aiocoap.NOT_FOUND

    async def test_fifo_evicts_oldest_after_expired(self) -> None:
        vec = _vec("eviction_fifo_order")
        clock = _Clock()
        payload = _senml({"n": "content", "vs": "x" * 20})
        size = len(pack(payload))
        # Three drops plus a new one of `size` must evict only the oldest.
        limit = size * 3 + 8
        dd = DeadDropResource(storage_limit=limit, time_func=clock)
        ids = ["aa0001", "aa0002", "aa0003"]
        for drop_id in ids:
            clock.t += 1
            assert dd.add_drop(payload, context_id="ctx-a", drop_id=drop_id) == drop_id
        clock.t += 1
        new_id = dd.add_drop(payload, context_id="ctx-a", drop_id="aa0004")
        assert new_id == "aa0004"
        remaining = [item["id"] for item in dd.drops()]
        assert remaining == ["aa0002", "aa0003", "aa0004"]
        assert vec["expected"]["evicted"] == "drop-001"
        assert remaining[0] != "aa0001"

    async def test_expired_evicted_before_oldest(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(storage_limit=200, time_func=clock)
        short = _senml({"n": "content", "vs": "old-short"})
        long_lived = _senml({"n": "content", "vs": "keep-me"})
        assert dd.add_drop(short, context_id="ctx-a", ttl=5, drop_id="aa0001")
        clock.t += 1
        assert dd.add_drop(long_lived, context_id="ctx-a", ttl=500, drop_id="aa0002")
        clock.t += 6
        filler = _senml({"n": "content", "vs": "new"})
        assert dd.add_drop(filler, context_id="ctx-a", drop_id="aa0003")
        assert [item["id"] for item in dd.drops()] == ["aa0002", "aa0003"]


class TestQueryFilters:
    async def test_type_and_after_and_node(self) -> None:
        clock = _Clock(1000)
        dd = DeadDropResource(time_func=clock)
        msg = _senml(
            {"n": "type", "vs": "message"},
            {"n": "content", "vs": "a"},
            {"n": "recipient", "vs": "abc123"},
        )
        waypoint = _senml({"n": "type", "vs": "waypoint"}, {"n": "content", "vs": "b"})
        clock.t = 1000
        await dd.render_post(_protected(msg))
        clock.t = 2000
        await dd.render_post(_protected(waypoint, context="ctx-b"))
        by_type = unpack((await dd.render_get(_get(query=("type=message",)))).payload)
        assert _record_value(by_type, "content") == "a"
        assert _record_value(by_type, "type") == "message"
        after = unpack((await dd.render_get(_get(query=("after=1500",)))).payload)
        assert _record_value(after, "content") == "b"
        by_node = unpack((await dd.render_get(_get(query=("node=abc123",)))).payload)
        assert _record_value(by_node, "content") == "a"

    async def test_invalid_after_is_bad_request(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_get(_get(query=("after=nope",)))
        assert response.code == aiocoap.BAD_REQUEST


class TestDefaultClockUnixEpoch:
    """Default construction must run drops on unix seconds (spec 18.9, LCI 17.5.8).

    No injected clock: expectations derive from RFC 8428 (SenML base times are
    unix seconds) and the spec's literal examples (?after=17216... and
    n="expires" v=1721736400), so wall-clock ``time.time()`` itself is the
    oracle, not the resource. A monotonic default would treat those unix
    instants as ~1.7e9 seconds of uptime and empty ?after or clamp TTL to 7d.
    """

    # spec/11-lci.md 17.5.8 POST example: bt=1721650000, expires=1721736400
    _LCI_AFTER = 1_721_650_000
    _LCI_EXPIRES = 1_721_736_400

    def test_default_clocks_split_unix_and_monotonic(self) -> None:
        dd = DeadDropResource()
        assert dd._time_func is time.time
        assert dd._rate_time_func is time.monotonic
        injected = _Clock()
        pinned = DeadDropResource(time_func=injected)
        assert pinned._time_func is injected
        assert pinned._rate_time_func is injected

    async def test_created_timestamps_are_unix_seconds(self) -> None:
        dd = DeadDropResource()
        payload = _senml({"n": "content", "vs": "now"})
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        created = dd.drops()[0]["created"]
        wall = time.time()
        assert created > 1_600_000_000
        assert abs(created - wall) < 5

    async def test_future_expires_max_age_is_remaining_wall_time(self) -> None:
        dd = DeadDropResource()
        expires = int(time.time()) + 3600
        payload = _senml(
            {"n": "content", "vs": "bottle"},
            {"n": "expires", "v": expires},
        )
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        remaining = expires - time.time()
        assert abs(response.opt.max_age - remaining) <= 2
        assert response.opt.max_age != DEADDROP_MAX_TTL
        assert response.opt.max_age != DEADDROP_DEFAULT_TTL

    async def test_past_expires_does_not_resurrect_default_ttl(self) -> None:
        dd = DeadDropResource()
        payload = _senml(
            {"n": "content", "vs": "stale"},
            {"n": "expires", "v": int(time.time()) - 60},
        )
        created = await dd.render_post(_protected(payload))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 0
        listing = await dd.render_get(_get())
        assert unpack(listing.payload) == []

    async def test_lci_example_expires_is_unix_and_already_past(self) -> None:
        dd = DeadDropResource()
        payload = _senml(
            {"n": "type", "vs": "message"},
            {"n": "content", "vs": "cache"},
            {"n": "expires", "v": self._LCI_EXPIRES},
        )
        created = await dd.render_post(_protected(payload))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 0
        listing = unpack((await dd.render_get(_get())).payload)
        assert listing == []

    async def test_decimal_future_expires_max_age_is_remaining_wall_time(self) -> None:
        dd = DeadDropResource()
        expires = Decimal(int(time.time()) + 3600)
        payload = _senml(
            {"n": "content", "vs": "bottle"},
            {"n": "expires", "v": expires},
        )
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        stored = dd.drops()[0]
        remaining = float(expires) - time.time()
        assert abs(stored["ttl"] - remaining) <= 2
        assert stored["ttl"] != DEADDROP_MAX_TTL
        assert stored["ttl"] != DEADDROP_DEFAULT_TTL

    async def test_decimal_past_expires_does_not_resurrect_default_ttl(self) -> None:
        dd = DeadDropResource()
        payload = _senml(
            {"n": "content", "vs": "stale"},
            {"n": "expires", "v": Decimal(int(time.time()) - 60)},
        )
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        listing = await dd.render_get(_get())
        assert unpack(listing.payload) == []
        assert dd.storage_info()["drop_count"] == 0

    async def test_after_query_matches_unix_created_times(self) -> None:
        dd = DeadDropResource()
        payload = _senml({"n": "type", "vs": "message"}, {"n": "content", "vs": "now"})
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        spec_after = unpack(
            (await dd.render_get(_get(query=(f"after={self._LCI_AFTER}",)))).payload
        )
        assert _record_value(spec_after, "content") == "now"
        ancient = unpack((await dd.render_get(_get(query=("after=1000000000",)))).payload)
        assert _record_value(ancient, "content") == "now"
        future = unpack(
            (await dd.render_get(_get(query=(f"after={int(time.time()) + 600}",)))).payload
        )
        assert future == []

    async def test_rate_limit_window_enforced_on_default_construction(self) -> None:
        dd = DeadDropResource()
        payload = _senml({"n": "content", "vs": "burst"})
        for _ in range(DEADDROP_POSTS_PER_HOUR):
            response = await dd.render_post(_protected(payload))
            assert response.code == aiocoap.CREATED
        limited = await dd.render_post(_protected(payload))
        assert limited.code == aiocoap.TOO_MANY_REQUESTS
        assert limited.opt.max_age >= 1


class TestHugeIntegerAndNonPositiveRetention:
    """Unvalidated direct-construction records must clamp or expire, never crash.

    The codec rejects beyond-float-range and non-finite numbers (4.00 on the
    wire), but ``SenmlRecord`` dataclass construction does not validate, so
    ``add_drop`` callers can hand the resource such values directly.
    """

    async def test_huge_integer_expires_clamps_to_max_ttl(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml(
            {"n": "content", "vs": "far-future"},
            {"n": "expires", "v": 10**400},
        )
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        stored = dd.drops()[0]
        assert stored["ttl"] == DEADDROP_MAX_TTL
        # Clamped retention, not the 24h default.
        assert stored["ttl"] != DEADDROP_DEFAULT_TTL

    async def test_negative_huge_integer_expires_expires_immediately(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml(
            {"n": "content", "vs": "ancient"},
            {"n": "expires", "v": -(10**400)},
        )
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        assert dd.drops() == []

    async def test_nonfinite_decimal_expires_is_rejected_to_default_ttl(self) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _records(
            {"n": "content", "vs": "garbage-expires"},
            {"n": "expires", "v": Decimal("NaN")},
        )
        created_id = dd.add_drop(payload, context_id="ctx-a")
        assert created_id is not None
        body = (await dd.render_get(_get())).payload
        wrapped = [item for item in cbor2.loads(body) if item.get(_SENML_N) == "ttl"]
        assert len(wrapped) == 1
        assert wrapped[0][_SENML_V] == DEADDROP_DEFAULT_TTL

    async def test_nonfinite_float_expires_keeps_legacy_fail_closed_semantics(self) -> None:
        nan_dd = DeadDropResource(time_func=_Clock())
        payload = _records({"n": "expires", "v": float("nan")}, {"n": "content", "vs": "x"})
        assert nan_dd.add_drop(payload, context_id="ctx-a") is not None
        assert nan_dd.drops() == []

        inf_dd = DeadDropResource(time_func=_Clock())
        payload = _records({"n": "expires", "v": float("inf")}, {"n": "content", "vs": "x"})
        assert inf_dd.add_drop(payload, context_id="ctx-a") is not None
        stored = inf_dd.drops()[0]
        assert stored["ttl"] == DEADDROP_MAX_TTL

    @pytest.mark.parametrize("ttl", [10**400, Decimal("1e999"), float("inf")])
    async def test_post_conversion_infinite_ttl_clamps_to_max_ttl(
        self, ttl: int | Decimal | float
    ) -> None:
        """Huge finite ints/Decimals arrive as +inf and clamp like huge expires."""
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml({"n": "ttl", "v": ttl}, {"n": "content", "vs": "vast"})
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        stored = dd.drops()[0]
        assert stored["ttl"] == DEADDROP_MAX_TTL
        # Clamped retention, not the 24h default.
        assert stored["ttl"] != DEADDROP_DEFAULT_TTL

    @pytest.mark.parametrize("ttl", [-(10**400), Decimal("-1e999"), float("-inf"), float("nan")])
    async def test_nonfinite_or_negative_infinite_ttl_expires_immediately(
        self, ttl: int | Decimal | float
    ) -> None:
        """-inf post-conversion means zero retention, mirroring finite ttl <= 0."""
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml({"n": "ttl", "v": ttl}, {"n": "content", "vs": "void"})
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        assert dd.drops() == []

    @pytest.mark.parametrize("ttl", [Decimal("sNaN"), Decimal("+Infinity")])
    async def test_nonfinite_decimal_ttl_gated_by_is_finite_reaches_default(
        self, ttl: Decimal
    ) -> None:
        """sNaN/infinite Decimals never reach conversion; record counts as absent."""
        dd = DeadDropResource(time_func=_Clock())
        payload = _records({"n": "ttl", "v": ttl}, {"n": "content", "vs": "gated"})
        assert dd.add_drop(payload, context_id="ctx-a") is not None
        stored = dd.drops()[0]
        assert stored["ttl"] == DEADDROP_DEFAULT_TTL

    @pytest.mark.parametrize("ttl", [0, -10])
    async def test_non_positive_ttl_record_expires_immediately_not_default(self, ttl: int) -> None:
        clock = _Clock()
        dd = DeadDropResource(time_func=clock)
        payload = _senml({"n": "ttl", "v": ttl}, {"n": "content", "vs": "zero"})
        created = await dd.render_post(_protected(payload))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 0
        assert created.opt.max_age != DEADDROP_DEFAULT_TTL
        assert unpack((await dd.render_get(_get())).payload) == []
        details = DeadDropDetailsResource(dd)
        drop_id = created.opt.location_path[1]
        assert (await details.render_get(_get(path=(drop_id,)))).code == aiocoap.NOT_FOUND

    async def test_add_drop_explicit_zero_or_negative_ttl_retains_zero(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml({"n": "content", "vs": "explicit"})
        assert dd.add_drop(payload, context_id="ctx-a", ttl=0, drop_id="aa0001")
        assert dd.add_drop(payload, context_id="ctx-a", ttl=-10, drop_id="aa0002")
        assert dd.drops() == []

    async def test_wire_rejects_huge_integer_expires_with_bad_request(self) -> None:
        body = cbor2.dumps([{_SENML_N: "expires", _SENML_V: 10**400}])
        dd = DeadDropResource(time_func=_Clock())
        response = await dd.render_post(_protected(body))
        assert response.code == aiocoap.BAD_REQUEST
        assert dd.drops() == []


class TestPrivacy:
    async def test_private_drop_hidden_and_forbidden(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        payload = _senml(
            {"n": "privacy", "vs": "private"},
            {"n": "content", "vs": "paired-only"},
        )
        created = await dd.render_post(_protected(payload, context="alice"))
        drop_id = created.opt.location_path[1]
        public_list = unpack((await dd.render_get(_get())).payload)
        assert public_list == []
        owner_list = unpack((await dd.render_get(_get(context="alice"))).payload)
        assert _record_value(owner_list, "content") == "paired-only"
        details = DeadDropDetailsResource(dd)
        # SECURITY: private drops return NOT_FOUND to hide existence
        forbidden = await details.render_get(_get(path=(drop_id,)))
        assert forbidden.code == aiocoap.NOT_FOUND
        allowed = await details.render_get(_get(path=(drop_id,), context="alice"))
        assert allowed.code == aiocoap.CONTENT
        stranger = await details.render_get(_get(path=(drop_id,), context="bob"))
        assert stranger.code == aiocoap.NOT_FOUND


class TestCanonicalPayload:
    async def test_spec_example_senml_creates_drop(self) -> None:
        vec = _vec("canonical_senml_payload")
        dd = DeadDropResource(time_func=_Clock())
        payload = _records(*vec["senml_payload_decoded"])
        response = await dd.render_post(_protected(payload))
        assert response.code == aiocoap.CREATED
        location = "/" + "/".join(response.opt.location_path)
        assert location.startswith(vec["expected"]["location_path_prefix"])
        listing = unpack((await dd.render_get(_get())).payload)
        assert _record_value(listing, "content") == (
            "Supply cache at these coords - do not broadcast"
        )


# ---------------------------------------------------------------------------
# RFC 8428 integer-label SenML+CBOR (independent of string-key dumps)
# ---------------------------------------------------------------------------

# RFC 8428 Table 4. Hand-built maps are the independent oracle: they do not
# go through DeadDropResource or through pack() of the code under test.
_SENML_N = 0
_SENML_U = 1
_SENML_V = 2
_SENML_VS = 3


def _assert_integer_label_pack(payload: bytes) -> list[dict[int, Any]]:
    """Decode ct=112 CBOR and require RFC 8428 integer labels on every map."""
    raw = cbor2.loads(payload)
    assert isinstance(raw, list)
    for item in raw:
        assert isinstance(item, dict)
        assert item, "SenML record must not be an empty map"
        assert all(type(key) is int for key in item)
    return raw


class TestRfc8428IntegerLabelSenml:
    """POST pack() honors ttl/type/recipient/privacy; GET unpacks with n/vs/v."""

    async def test_pack_post_honors_ttl_type_recipient_and_privacy(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        records = [
            SenmlRecord(n="type", vs="message"),
            SenmlRecord(n="content", vs="cache"),
            SenmlRecord(n="ttl", v=3600),
            SenmlRecord(n="recipient", vs="abc123"),
            SenmlRecord(n="privacy", vs="private"),
        ]
        packed = pack(records)
        _assert_integer_label_pack(packed)

        created = await dd.render_post(_protected(packed, context="alice"))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 3600
        drop_id = created.opt.location_path[1]

        public = await dd.render_get(_get())
        assert public.code == aiocoap.CONTENT
        assert public.opt.content_format == SENML_CBOR
        assert unpack(public.payload) == []

        owner = await dd.render_get(_get(context="alice"))
        owner_raw = _assert_integer_label_pack(owner.payload)
        owner_records = unpack(owner.payload)
        assert _record_value(owner_records, "id") == drop_id
        assert _record_value(owner_records, "type") == "message"
        assert _record_value(owner_records, "content") == "cache"
        assert _record_value(owner_records, "recipient") == "abc123"
        assert _record_value(owner_records, "privacy") == "private"
        assert any(rec.n is not None and rec.vs is not None for rec in owner_records)
        assert any(rec.n is not None and rec.v is not None for rec in owner_records)
        assert any(_SENML_N in item and _SENML_VS in item for item in owner_raw)

        by_type = unpack(
            (await dd.render_get(_get(query=("type=message",), context="alice"))).payload
        )
        assert _record_value(by_type, "content") == "cache"
        by_node = unpack(
            (await dd.render_get(_get(query=("node=abc123",), context="alice"))).payload
        )
        assert _record_value(by_node, "content") == "cache"

        details = DeadDropDetailsResource(dd)
        # SECURITY: private drops return NOT_FOUND to hide existence
        forbidden = await details.render_get(_get(path=(drop_id,)))
        assert forbidden.code == aiocoap.NOT_FOUND
        allowed = await details.render_get(_get(path=(drop_id,), context="alice"))
        assert allowed.code == aiocoap.CONTENT
        detail_raw = _assert_integer_label_pack(allowed.payload)
        got = unpack(allowed.payload)
        assert _record_value(got, "privacy") == "private"
        assert _record_value(got, "ttl") == 3600
        assert _record_value(got, "type") == "message"
        assert _record_value(got, "recipient") == "abc123"
        assert any(
            item.get(_SENML_N) == "privacy" and item.get(_SENML_VS) == "private"
            for item in detail_raw
        )

    async def test_hand_built_integer_labels_set_privacy_and_ttl(self) -> None:
        """Independent oracle: RFC 8428 Table 4 maps, not pack() and not the resource."""
        dd = DeadDropResource(time_func=_Clock())
        body = cbor2.dumps(
            [
                {_SENML_N: "privacy", _SENML_VS: "private"},
                {_SENML_N: "ttl", _SENML_V: 3600},
                {_SENML_N: "type", _SENML_VS: "message"},
                {_SENML_N: "content", _SENML_VS: "secret"},
                {_SENML_N: "recipient", _SENML_VS: "node-b"},
            ]
        )
        _assert_integer_label_pack(body)
        created = await dd.render_post(_protected(body, context="alice"))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 3600
        drop_id = created.opt.location_path[1]

        assert unpack((await dd.render_get(_get())).payload) == []
        owner = unpack((await dd.render_get(_get(context="alice"))).payload)
        assert _record_value(owner, "content") == "secret"
        assert _record_value(owner, "type") == "message"

        details = DeadDropDetailsResource(dd)
        # SECURITY: private drops return NOT_FOUND to hide existence
        assert (await details.render_get(_get(path=(drop_id,)))).code == aiocoap.NOT_FOUND
        allowed = await details.render_get(_get(path=(drop_id,), context="alice"))
        got = unpack(allowed.payload)
        assert _record_value(got, "privacy") == "private"
        assert _record_value(got, "ttl") == 3600
        assert _record_value(got, "recipient") == "node-b"

    async def test_string_key_dumps_are_not_rfc8428_cbor(self) -> None:
        """String-key CBOR is SenML+JSON shape; GET must still emit integer labels."""
        string_keyed = cbor2.dumps(
            [
                {"n": "privacy", "vs": "private"},
                {"n": "ttl", "v": 3600},
                {"n": "content", "vs": "x"},
            ]
        )
        raw = cbor2.loads(string_keyed)
        assert all(isinstance(k, str) for item in raw for k in item)
        ignored = unpack(string_keyed)
        assert all(rec.n is None and rec.vs is None and rec.v is None for rec in ignored)

        dd = DeadDropResource(time_func=_Clock())
        created = await dd.render_post(_protected(string_keyed, context="alice"))
        assert created.code == aiocoap.CREATED
        listing = await dd.render_get(_get(context="alice"))
        _assert_integer_label_pack(listing.payload)
        records = unpack(listing.payload)
        assert _record_value(records, "content") == "x"
        assert created.opt.max_age == 3600
        assert unpack((await dd.render_get(_get())).payload) == []

    async def test_mixed_integer_and_string_labels_honor_privacy(self) -> None:
        """A pack with both Table 4 labels and JSON-style names must not fail-open."""
        dd = DeadDropResource(time_func=_Clock())
        body = cbor2.dumps(
            [
                {_SENML_N: "type", _SENML_VS: "message"},
                {"n": "privacy", "vs": "private"},
                {_SENML_N: "ttl", _SENML_V: 3600},
                {"n": "content", "vs": "mix"},
            ]
        )
        created = await dd.render_post(_protected(body, context="alice"))
        assert created.code == aiocoap.CREATED
        assert created.opt.max_age == 3600
        drop_id = created.opt.location_path[1]
        assert unpack((await dd.render_get(_get())).payload) == []
        owner = unpack((await dd.render_get(_get(context="alice"))).payload)
        assert _record_value(owner, "content") == "mix"
        assert _record_value(owner, "type") == "message"
        details = DeadDropDetailsResource(dd)
        # SECURITY: private drops return NOT_FOUND to hide existence
        assert (await details.render_get(_get(path=(drop_id,)))).code == aiocoap.NOT_FOUND


# ---------------------------------------------------------------------------
# Site wiring and Observe
# ---------------------------------------------------------------------------


async def _setup(
    dd: DeadDropResource | None = None,
) -> tuple[aiocoap.Context, aiocoap.Context, DeadDropResource]:
    net = InMemoryNetwork()
    resource = dd if dd is not None else DeadDropResource(time_func=_Clock())
    site = build_site(StaticNodeInfo(status={"rank": 256}), deaddrop_resource=resource)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, resource


class TestSiteAndObserve:
    async def test_default_site_has_no_deaddrop(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv", site=build_site(StaticNodeInfo())
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            response = await client.request(
                Message(code=POST, uri="coap://srv/deaddrop", payload=cbor2.dumps([]))
            ).response
            assert response.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_wkc_omits_all_dynamic_drop_ids_for_anonymous_discovery(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        assert dd.add_drop(
            _senml({"n": "content", "vs": "public"}),
            context_id="alice",
            drop_id="aa0001",
        )
        assert dd.add_drop(
            _senml({"n": "privacy", "vs": "private"}),
            context_id="alice",
            drop_id="aa0002",
            privacy="private",
        )
        assert dd.add_drop(
            _senml({"n": "privacy", "vs": "group"}),
            context_id="group-a",
            drop_id="aa0003",
            privacy="group",
        )
        client, server, _ = await _setup(dd)
        try:
            response = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            body = response.payload.decode()
            assert response.code == aiocoap.CONTENT
            assert "</deaddrop>" in body
            assert "aa0001" not in body
            assert "aa0002" not in body
            assert "aa0003" not in body
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_dynamic_discovery_is_auth_independent_and_cache_stable(self) -> None:
        dd = DeadDropResource(time_func=_Clock())
        details = DeadDropDetailsResource(dd)
        before = list(details.get_resources_as_linkheader().links)
        private = _senml(
            {"n": "privacy", "vs": "private"},
            {"n": "content", "vs": "owner-only"},
        )
        assert dd.add_drop(
            private,
            context_id="alice",
            drop_id="7f3a9c",
            privacy="private",
        )
        after = list(details.get_resources_as_linkheader().links)

        # The link-header hook has no request context, so the safe result is
        # identical for anonymous and authenticated callers and cannot cache a
        # dynamic identifier across ACL/storage changes.
        assert before == after == []
        # SECURITY: private drops return NOT_FOUND to hide existence
        assert (await details.render_get(_get(path=("7f3a9c",)))).code == aiocoap.NOT_FOUND
        owner = await details.render_get(_get(path=("7f3a9c",), context="alice"))
        assert owner.code == aiocoap.CONTENT
        assert unpack(owner.payload) == private

    async def test_unprotected_post_over_stack_is_unauthorized(self) -> None:
        client, server, _dd = await _setup()
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/deaddrop",
                    payload=pack(_senml({"n": "content", "vs": "x"})),
                )
            ).response
            assert response.code == aiocoap.UNAUTHORIZED
            assert cbor2.loads(response.payload) == {"error": "oscore_required"}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_spoofed_oscore_option_over_stack_is_unauthorized(self) -> None:
        client, server, dd = await _setup()
        try:
            request = Message(
                code=POST,
                uri="coap://srv/deaddrop",
                payload=pack(_senml({"n": "content", "vs": "x"})),
            )
            request.opt.oscore = b"\x00"
            response = await client.request(request).response
            assert response.code == aiocoap.UNAUTHORIZED
            assert cbor2.loads(response.payload) == {"error": "oscore_required"}
            assert dd.drops() == []
            empty = Message(
                code=POST,
                uri="coap://srv/deaddrop",
                payload=pack(_senml({"n": "content", "vs": "y"})),
            )
            empty.opt.oscore = b""
            empty_response = await client.request(empty).response
            assert empty_response.code == aiocoap.UNAUTHORIZED
            assert dd.drops() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_by_id_over_stack(self) -> None:
        client, server, dd = await _setup()
        try:
            drop_id = dd.add_drop(
                _senml({"n": "content", "vs": "stack"}),
                context_id="ctx-a",
                drop_id="7f3a9c",
            )
            assert drop_id == "7f3a9c"
            response = await client.request(
                Message(code=GET, uri="coap://srv/deaddrop/7f3a9c")
            ).response
            assert response.code == aiocoap.CONTENT
            assert response.opt.content_format == 112
            assert unpack(response.payload) == _senml({"n": "content", "vs": "stack"})
            assert response.opt.max_age is not None
            missing = await client.request(
                Message(code=GET, uri="coap://srv/deaddrop/ffffff")
            ).response
            assert missing.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notifies_on_new_drop(self) -> None:
        client, server, dd = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/deaddrop"))
            first = await req.response
            assert first.code == aiocoap.CONTENT
            assert first.opt.observe is not None
            assert unpack(first.payload) == []
            obs_iter = req.observation.__aiter__()
            dd.add_drop(_senml({"n": "content", "vs": "arrived"}), context_id="ctx-a")
            notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            records = unpack(notification.payload)
            assert _record_value(records, "content") == "arrived"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_well_known_core_advertises_deaddrop(self) -> None:
        client, server, _dd = await _setup()
        try:
            response = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            body = response.payload.decode()
            assert "</deaddrop>" in body
            assert 'rt="deaddrop"' in body or "rt=deaddrop" in body
            assert "obs" in body
        finally:
            await client.shutdown()
            await server.shutdown()
