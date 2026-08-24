# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /sos, /rollcall, and /checkin CoAP resources."""

from __future__ import annotations

import asyncio
import time

import aiocoap
import cbor2
import pytest
from aiocoap import DELETE, GET, POST, Message

from lichen.coap.resources import (
    CheckInResource,
    RollcallResource,
    SosResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.resources.emergency import (
    MAX_ROLLCALL_TIMEOUT_S,
    MAX_ROLLCALLS,
    SOS_COOLDOWN_S,
    SOS_HOURLY_MAX,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_EUI = bytes.fromhex("0102030405060708")
_T0 = 1_700_000_000.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, SosResource]:
    net = InMemoryNetwork()
    sos = SosResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, sos_resource=sos)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, sos


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestSosGet:
    async def test_idle_state(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/sos")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            state = cbor2.loads(resp.payload)
            assert state["active"] is False
            assert state["from"] is None
            assert state["t"] is None
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_active_after_activate(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            resp = await client.request(Message(code=GET, uri="coap://srv/sos")).response
            state = cbor2.loads(resp.payload)
            assert state["active"] is True
            assert state["from"] == _EUI.hex()
            assert state["t"] == pytest.approx(_T0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_idle_after_cancel(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            sos.cancel()
            resp = await client.request(Message(code=GET, uri="coap://srv/sos")).response
            state = cbor2.loads(resp.payload)
            assert state["active"] is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/sos")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# POST / DELETE
# ---------------------------------------------------------------------------


class TestSosPutDelete:
    async def test_put_with_body_activates(self) -> None:
        client, server, sos = await _setup()
        try:
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.CREATED
            assert sos._active is True
            assert sos._from == _EUI.hex()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_no_body_is_rejected(self) -> None:
        client, server, sos = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=b"")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_invalid_cbor_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            # b"\xa5\x01" is a truncated CBOR map (declares 5 entries, body cut short)
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=b"\xa5\x01")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_nonstring_from_returns_bad_request(self) -> None:
        """Non-string 'from' field (e.g. integer) must be rejected."""
        client, server, sos = await _setup()
        try:
            # "from" as integer instead of hex string
            body = cbor2.dumps({"from": 12345, "t": _T0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False  # should not activate
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_nonnumeric_t_returns_bad_request(self) -> None:
        """Non-numeric 't' field (e.g. string) must be rejected."""
        client, server, sos = await _setup()
        try:
            # "t" as string instead of numeric
            body = cbor2.dumps({"from": _EUI.hex(), "t": "not-a-number"})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False  # should not activate
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_cbor_with_tag_returns_bad_request(self) -> None:
        """CBOR containing tags (e.g. bignums) must be rejected."""
        client, server, sos = await _setup()
        try:
            # CBOR bignum tag (tag 2) for a huge integer that would cause OverflowError
            # This tests that CBOR tags are properly rejected
            bignum_cbor = (
                bytes(
                    [
                        0xA2,  # map(2)
                        0x64,
                        0x66,
                        0x72,
                        0x6F,
                        0x6D,  # "from"
                        0x70,  # text(16)
                    ]
                )
                + _EUI.hex().encode()
                + bytes(
                    [
                        0x61,
                        0x74,  # "t"
                        0xC2,  # tag 2 (positive bignum)
                        0x50,  # bstr(16)
                    ]
                )
                + b"\xff" * 16
            )  # huge bignum value

            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=bignum_cbor, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_cancels_sos(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            resp = await client.request(Message(code=DELETE, uri="coap://srv/sos")).response
            assert resp.code == aiocoap.DELETED
            assert sos._active is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_when_idle_is_harmless(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=DELETE, uri="coap://srv/sos")).response
            assert resp.code == aiocoap.DELETED
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class TestSosRateLimiting:
    """Tests for SOS per-source rate limiting (10min cooldown, 3/hour max)."""

    def test_first_request_allowed(self) -> None:
        """First request from a source should always be allowed."""
        sos = SosResource()
        assert sos.check_rate_limit(_EUI.hex()) is True

    def test_request_within_cooldown_blocked(self) -> None:
        """Request within 10-minute cooldown should be blocked."""
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        # First request allowed
        assert sos.check_rate_limit(_EUI.hex()) is True
        sos._record_request(_EUI.hex())
        # Request 5 minutes later should be blocked (within 10min cooldown)
        current_time = _T0 + 300  # 5 minutes
        sos._time_func = lambda: current_time
        assert sos.check_rate_limit(_EUI.hex()) is False

    def test_request_after_cooldown_allowed(self) -> None:
        """Request after 10-minute cooldown should be allowed."""
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        # First request
        sos._record_request(_EUI.hex())
        # Request 11 minutes later should be allowed
        current_time = _T0 + 660  # 11 minutes
        sos._time_func = lambda: current_time
        assert sos.check_rate_limit(_EUI.hex()) is True

    def test_hourly_max_enforced(self) -> None:
        """4th request within an hour should be blocked."""
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        # Make 3 requests, each spaced > 10 min apart
        for i in range(SOS_HOURLY_MAX):
            assert sos.check_rate_limit(_EUI.hex()) is True
            sos._record_request(_EUI.hex())
            current_time = _T0 + (i + 1) * 620  # 10+ min apart
            sos._time_func = lambda ct=current_time: ct
        # 4th request should be blocked even though cooldown passed
        assert sos.check_rate_limit(_EUI.hex()) is False

    def test_hourly_window_slides(self) -> None:
        """After an hour, oldest request expires and new one is allowed."""
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        # Make 3 requests
        for i in range(SOS_HOURLY_MAX):
            sos._record_request(_EUI.hex())
            current_time = _T0 + (i + 1) * 620
            sos._time_func = lambda ct=current_time: ct
        # 4th blocked
        assert sos.check_rate_limit(_EUI.hex()) is False
        # Move past 1 hour from first request
        current_time = _T0 + 3601
        sos._time_func = lambda: current_time
        # Now allowed (first request expired)
        assert sos.check_rate_limit(_EUI.hex()) is True

    def test_different_sources_independent(self) -> None:
        """Rate limits are per-source; different sources don't interfere."""
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        source_a = "0102030405060708"
        source_b = "0807060504030201"
        # Source A makes a request
        sos._record_request(source_a)
        # Source B should still be allowed immediately
        assert sos.check_rate_limit(source_b) is True
        # Source A should be blocked (within cooldown)
        assert sos.check_rate_limit(source_a) is False

    async def test_post_rate_limited_returns_too_many_requests(self) -> None:
        """POST that violates rate limit returns TOO_MANY_REQUESTS."""
        net = InMemoryNetwork()
        current_time = _T0
        sos = SosResource(time_func=lambda: current_time)
        info = StaticNodeInfo(status={"rank": 256})
        site = build_site(info, sos_resource=sos)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            # First POST succeeds
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.CREATED
            # Second POST within cooldown should be rate limited
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.TOO_MANY_REQUESTS
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_succeeds_after_cooldown(self) -> None:
        """POST succeeds after cooldown period passes."""
        net = InMemoryNetwork()
        current_time = [_T0]  # Use list to allow mutation in closure
        sos = SosResource(time_func=lambda: current_time[0])
        info = StaticNodeInfo(status={"rank": 256})
        site = build_site(info, sos_resource=sos)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            # First POST succeeds
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.CREATED
            # Advance time past cooldown
            current_time[0] = _T0 + SOS_COOLDOWN_S + 1
            # Second POST should succeed
            resp = await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.CREATED
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------


class TestSosObserve:
    async def test_observe_notified_on_activate(self) -> None:
        client, server, sos = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/sos"))
            first = await req.response
            assert cbor2.loads(first.payload)["active"] is False

            obs_iter = req.observation.__aiter__()
            sos.activate(_EUI, _T0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_cancel(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/sos"))
            await req.response

            obs_iter = req.observation.__aiter__()
            sos.cancel()
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_retrigger(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/sos"))
            await req.response

            obs_iter = req.observation.__aiter__()
            sos.retrigger()
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_retrigger_noop_when_idle(self) -> None:
        _, server, sos = await _setup()
        try:
            # retrigger while idle should not call updated_state (no crash, no notification)
            sos.retrigger()
            assert sos._active is False
        finally:
            await server.shutdown()

    async def test_observe_notified_on_put(self) -> None:
        client, server, _ = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/sos"))
            await req.response

            obs_iter = req.observation.__aiter__()
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            await client.request(
                Message(code=POST, uri="coap://srv/sos", payload=body, content_format=60)
            ).response
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Rollcall POST validation
# ---------------------------------------------------------------------------


async def _setup_rollcall() -> tuple[aiocoap.Context, aiocoap.Context, RollcallResource]:
    net = InMemoryNetwork()
    rollcall = RollcallResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, rollcall_resource=rollcall)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, rollcall


def _rollcall_post_body(**overrides: object) -> bytes:
    body: dict[str, object] = {"id": "roll-001", "ts": 1_700_000_000, "timeout_s": 60}
    body.update(overrides)
    return cbor2.dumps(body)


class TestRollcallPostValidation:
    async def test_valid_post_creates_rollcall(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            got = await client.request(Message(code=GET, uri="coap://srv/rollcall")).response
            listing = cbor2.loads(got.payload)
            entry = listing["rollcalls"][0]
            assert entry["id"] == "roll-001"
            assert entry["started"] == 1_700_000_000
            assert entry["timeout_s"] == 60
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_string_ts_rejected(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(ts="bad"),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert "roll-001" not in rollcall._rollcalls
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_null_ts_rejected(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(ts=None),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert "roll-001" not in rollcall._rollcalls
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_bool_ts_rejected(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(ts=True),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert "roll-001" not in rollcall._rollcalls
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_negative_ts_rejected(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(ts=-1),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("bad_timeout", [2**63, float("inf"), float("nan")])
    async def test_post_out_of_range_timeout_rejected(self, bad_timeout: object) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(timeout_s=bad_timeout),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert "roll-001" not in rollcall._rollcalls
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("bad_timeout", [0, -5, True])
    async def test_post_degenerate_timeout_rejected(self, bad_timeout: object) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(timeout_s=bad_timeout),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_timeout_over_cap_rejected(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(timeout_s=MAX_ROLLCALL_TIMEOUT_S + 1),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert "roll-001" not in rollcall._rollcalls
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_timeout_at_cap_accepted(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(timeout_s=MAX_ROLLCALL_TIMEOUT_S),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_capacity_limit_returns_service_unavailable(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            for i in range(MAX_ROLLCALLS):
                resp = await client.request(
                    Message(
                        code=POST,
                        uri="coap://srv/rollcall",
                        payload=_rollcall_post_body(id=f"roll-{i}", ts=int(time.time())),
                        content_format=60,
                    )
                ).response
                assert resp.code == aiocoap.CREATED
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(id="overflow"),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.SERVICE_UNAVAILABLE
            assert "overflow" not in rollcall._rollcalls
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(id="roll-0", timeout_s=120),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert rollcall._rollcalls["roll-0"]["timeout_s"] == 120
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_expired_entries_pruned_on_post(self) -> None:
        client, server, rollcall = await _setup_rollcall()
        try:
            rollcall._rollcalls["stale"] = {
                "id": "stale",
                "started": int(time.time()) - 3600,
                "timeout_s": 60,
                "responded": [],
                "missing": [],
            }
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rollcall",
                    payload=_rollcall_post_body(id="fresh"),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert "stale" not in rollcall._rollcalls
            got = await client.request(Message(code=GET, uri="coap://srv/rollcall")).response
            listing = cbor2.loads(got.payload)
            assert [entry["id"] for entry in listing["rollcalls"]] == ["fresh"]
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_update_drops_new_rollcall_when_full(self) -> None:
        rollcall = RollcallResource()
        for i in range(MAX_ROLLCALLS):
            rollcall.update(f"roll-{i}")
        rollcall.update("overflow")
        assert "overflow" not in rollcall._rollcalls
        assert len(rollcall._rollcalls) == MAX_ROLLCALLS

    async def test_update_prunes_expired_before_capacity_check(self) -> None:
        rollcall = RollcallResource()
        for i in range(MAX_ROLLCALLS):
            rollcall.update(f"roll-{i}")
        rollcall._rollcalls["roll-0"]["started"] = int(time.time()) - 3600
        rollcall.update("fresh")
        assert "fresh" in rollcall._rollcalls
        assert len(rollcall._rollcalls) == MAX_ROLLCALLS


# ---------------------------------------------------------------------------
# CheckIn POST/GET validation
# ---------------------------------------------------------------------------


async def _setup_checkin() -> tuple[aiocoap.Context, aiocoap.Context, CheckInResource]:
    net = InMemoryNetwork()
    checkin = CheckInResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, checkin_resource=checkin)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, checkin


def _checkin_post_body(**overrides: object) -> bytes:
    body: dict[str, object] = {
        "node": "0200111122223333",
        "ts": 1_700_000_000,
        "status": "ok",
    }
    body.update(overrides)
    return cbor2.dumps(body)


class TestCheckInPostValidation:
    """Tests for /checkin POST validation per spec 18.6.1."""

    async def test_valid_post_returns_changed(self) -> None:
        """Valid check-in should return 2.04 Changed."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CHANGED
            assert "0200111122223333" in checkin._checkins
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_with_optional_fields(self) -> None:
        """Check-in with optional lat, lon, msg fields should succeed."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(lat=37.77, lon=-122.42, msg="At checkpoint"),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CHANGED
            entry = checkin._checkins["0200111122223333"]
            assert entry["lat"] == pytest.approx(37.77)
            assert entry["lon"] == pytest.approx(-122.42)
            assert entry["msg"] == "At checkpoint"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_missing_node_rejected(self) -> None:
        """Missing node field should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            body = cbor2.dumps({"ts": 1_700_000_000, "status": "ok"})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/checkin", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert len(checkin._checkins) == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_missing_ts_rejected(self) -> None:
        """Missing ts field should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            body = cbor2.dumps({"node": "0200111122223333", "status": "ok"})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/checkin", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_missing_status_rejected(self) -> None:
        """Missing status field should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            body = cbor2.dumps({"node": "0200111122223333", "ts": 1_700_000_000})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/checkin", payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("bad_status", ["unknown", "OK", "HELP", "foo", "", 123])
    async def test_post_invalid_status_rejected(self, bad_status: object) -> None:
        """Invalid status values should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(status=bad_status),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("valid_status", ["ok", "help", "delayed"])
    async def test_post_valid_status_values_accepted(self, valid_status: str) -> None:
        """Valid status values per spec should be accepted."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(status=valid_status),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CHANGED
            assert checkin._checkins["0200111122223333"]["status"] == valid_status
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_negative_ts_rejected(self) -> None:
        """Negative timestamp should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(ts=-1),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_bool_ts_rejected(self) -> None:
        """Boolean timestamp should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(ts=True),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_string_ts_rejected(self) -> None:
        """String timestamp should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(ts="not-a-number"),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("bad_lat", [float("inf"), float("nan"), "string", True])
    async def test_post_invalid_lat_rejected(self, bad_lat: object) -> None:
        """Invalid lat values should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(lat=bad_lat),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("bad_lon", [float("inf"), float("nan"), "string", True])
    async def test_post_invalid_lon_rejected(self, bad_lon: object) -> None:
        """Invalid lon values should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(lon=bad_lon),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_invalid_msg_rejected(self) -> None:
        """Non-string msg should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(msg=12345),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_empty_payload_rejected(self) -> None:
        """Empty payload should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/checkin", payload=b"")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_invalid_cbor_rejected(self) -> None:
        """Invalid CBOR should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/checkin", payload=b"\xa5\x01")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_empty_node_rejected(self) -> None:
        """Empty node string should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(node=""),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_nonstring_node_rejected(self) -> None:
        """Non-string node should be rejected."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(node=12345),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()


class TestCheckInGet:
    """Tests for /checkin GET."""

    async def test_get_empty_returns_empty_list(self) -> None:
        """GET with no check-ins returns empty list."""
        client, server, checkin = await _setup_checkin()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/checkin")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            data = cbor2.loads(resp.payload)
            assert data == {"checkins": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_returns_stored_checkins(self) -> None:
        """GET returns all stored check-ins."""
        client, server, checkin = await _setup_checkin()
        try:
            # Post two check-ins
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(node="0200111111111111", status="ok"),
                    content_format=60,
                )
            ).response
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(node="0200222222222222", status="help"),
                    content_format=60,
                )
            ).response
            # GET check-ins
            resp = await client.request(Message(code=GET, uri="coap://srv/checkin")).response
            assert resp.code == aiocoap.CONTENT
            data = cbor2.loads(resp.payload)
            assert len(data["checkins"]) == 2
            nodes = {c["node"] for c in data["checkins"]}
            assert nodes == {"0200111111111111", "0200222222222222"}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_updates_existing_checkin(self) -> None:
        """POST from same node updates the existing check-in."""
        client, server, checkin = await _setup_checkin()
        try:
            # First check-in
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(status="ok"),
                    content_format=60,
                )
            ).response
            assert checkin._checkins["0200111122223333"]["status"] == "ok"
            # Update check-in
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/checkin",
                    payload=_checkin_post_body(status="help", ts=1_700_000_100),
                    content_format=60,
                )
            ).response
            assert len(checkin._checkins) == 1  # Still one entry
            assert checkin._checkins["0200111122223333"]["status"] == "help"
            assert checkin._checkins["0200111122223333"]["ts"] == 1_700_000_100
        finally:
            await client.shutdown()
            await server.shutdown()


class TestCheckInCapacity:
    """Tests for /checkin storage capacity."""

    async def test_oldest_pruned_when_full(self) -> None:
        """Oldest check-in is pruned when capacity is reached."""
        from lichen.coap.resources.emergency import MAX_CHECKINS

        checkin = CheckInResource()
        # Fill up storage with check-ins
        for i in range(MAX_CHECKINS):
            checkin._checkins[f"node-{i:04d}"] = {
                "node": f"node-{i:04d}",
                "ts": 1_700_000_000 + i,  # Increasing timestamps
                "status": "ok",
            }
        assert len(checkin._checkins) == MAX_CHECKINS
        assert "node-0000" in checkin._checkins  # Oldest entry
        # Add one more - should prune the oldest (node-0000)
        checkin._prune_oldest()
        checkin._checkins["node-new"] = {
            "node": "node-new",
            "ts": 1_700_001_000,
            "status": "ok",
        }
        assert len(checkin._checkins) == MAX_CHECKINS
        assert "node-0000" not in checkin._checkins  # Pruned
        assert "node-new" in checkin._checkins  # Added
