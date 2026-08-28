# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Oracle tests for /confessions (spec 18.10).

Drives ``ConfessionsResource`` as the Python oracle for the anonymous
ephemeral board: SenML POST, CBOR query GET, rate/size/storage/TTL limits,
FIFO eviction, reboot-clear, Observe, and confessions.json pins.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from ipaddress import IPv6Address
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiocoap
import cbor2
import pytest
from aiocoap import GET, POST, Message

from lichen.coap.resources import StaticNodeInfo
from lichen.coap.resources.base import CBOR
from lichen.coap.resources.confessions import (
    CONFESSION_COOLDOWN_S,
    CONFESSION_DEFAULT_TTL,
    CONFESSION_HOURLY_MAX,
    CONFESSION_MAX_SIZE,
    CONFESSION_MAX_TTL,
    CONFESSION_STORAGE_BR,
    CONFESSION_STORAGE_LEAF,
    ConfessionsDetailsResource,
    ConfessionsResource,
    _generate_id,
    _is_confession_id,
)
from lichen.coap.resources.site import build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.ipv6.addr import make_link_local
from lichen.senml.codec import SenmlRecord, pack

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test" / "vectors" / "confessions.json").read_text()
)
RATE_VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test" / "vectors" / "confessions_rate.json").read_text()
)


def _vec(name: str, doc: dict[str, Any] = VECTORS) -> dict[str, Any]:
    matches = [item for item in doc["vectors"] if item["name"] == name]
    assert len(matches) == 1, name
    return matches[0]


class _Clock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _pack_senml_json(items: list[dict[str, Any]]) -> bytes:
    records: list[SenmlRecord] = []
    for item in items:
        records.append(
            SenmlRecord(
                bn=item.get("bn"),
                bt=item.get("bt"),
                n=item.get("n"),
                u=item.get("u"),
                v=item.get("v"),
                vs=item.get("vs"),
            )
        )
    return pack(records)


def _payload(
    iid: str = "0011223344556677",
    content: str = "it was me",
    *,
    anonymous: int | None = 1,
    ttl: int | None = None,
    extra: list[SenmlRecord] | None = None,
    bt: float | None = None,
) -> bytes:
    records = [
        SenmlRecord(bn=f"urn:dev:mac:{iid}:", bt=bt),
        SenmlRecord(n="type", vs="confession"),
        SenmlRecord(n="content", vs=content),
    ]
    if anonymous is not None:
        records.append(SenmlRecord(n="anonymous", v=anonymous))
    if ttl is not None:
        records.append(SenmlRecord(n="ttl", v=ttl))
    if extra:
        records.extend(extra)
    return pack(records)


def _bind_source(
    request: Message,
    iid: str | None = None,
    *,
    oscore: str | None = None,
    hostinfo: str | None = None,
) -> Message:
    """Attach an authenticated IPv6 and/or OSCORE identity to *request*."""
    if hostinfo is not None:
        request.remote = SimpleNamespace(hostinfo=hostinfo)
    elif iid is not None:
        addr = make_link_local(bytes.fromhex(iid))
        request.remote = SimpleNamespace(hostinfo=f"[{addr}]")
    if oscore is not None:
        request.oscore_context_id = oscore
    return request


def _post(
    payload: bytes,
    *,
    source_iid: str | None = None,
    oscore: str | None = None,
    hostinfo: str | None = None,
) -> Message:
    return _bind_source(
        Message(code=POST, payload=payload),
        source_iid,
        oscore=oscore,
        hostinfo=hostinfo,
    )


def _get(
    *,
    path: tuple[str, ...] = (),
    query: tuple[str, ...] = (),
    source_iid: str | None = None,
) -> Message:
    request = Message(code=GET)
    if path:
        request.opt.uri_path = path
    if query:
        request.opt.uri_query = query
    return _bind_source(request, source_iid)


# ---------------------------------------------------------------------------
# Spec constants
# ---------------------------------------------------------------------------


class TestSpecConstants:
    def test_rate_and_storage_match_spec_18_10_3(self) -> None:
        assert CONFESSION_COOLDOWN_S == 30
        assert CONFESSION_HOURLY_MAX == 12
        assert CONFESSION_MAX_SIZE == 768
        assert CONFESSION_STORAGE_LEAF == 2 * 1024
        assert CONFESSION_STORAGE_BR == 8 * 1024
        assert CONFESSION_DEFAULT_TTL == 12 * 3600
        assert CONFESSION_MAX_TTL == 48 * 3600
        assert RATE_VECTORS["limits"]["per_30s"] == 1
        assert RATE_VECTORS["limits"]["per_hour"] == 12
        assert RATE_VECTORS["limits"]["time_source"] == "monotonic_uptime"

    def test_time_func_defaults_to_monotonic(self) -> None:
        assert ConfessionsResource()._time_func is time.monotonic

    def test_rejects_non_positive_storage_limit(self) -> None:
        with pytest.raises(ValueError):
            ConfessionsResource(storage_limit=0)
        with pytest.raises(ValueError):
            ConfessionsResource(storage_limit=-1)
        with pytest.raises(ValueError):
            ConfessionsResource(storage_limit=True)

    def test_border_router_uses_8kb(self) -> None:
        leaf = ConfessionsResource()
        br = ConfessionsResource(is_border_router=True)
        assert leaf.storage_info()["storage_max_kb"] == 2.0
        assert br.storage_info()["storage_max_kb"] == 8.0


def _truncated_content_hash(content: str, timestamp: float, *, suffix: int | None = None) -> str:
    """Independent oracle for the old content+timestamp ID scheme."""
    body = f"{content}:{suffix}:{timestamp}" if suffix is not None else f"{content}:{timestamp}"
    return hashlib.sha256(body.encode()).hexdigest()[:6]


# ---------------------------------------------------------------------------
# Confession IDs (CSPRNG, not content hash)
# ---------------------------------------------------------------------------


class TestConfessionIds:
    def test_generate_id_is_six_lowercase_hex(self) -> None:
        conf_id = _generate_id()
        assert _is_confession_id(conf_id)
        assert len(conf_id) == 6

    def test_identical_content_and_timestamp_are_not_stable(self) -> None:
        content = "Left the forward operating base unlocked at 0200."
        ts = 1_721_654_321.0
        first = ConfessionsResource(time_func=_Clock(ts)).add_confession(content, ts=ts)
        second = ConfessionsResource(time_func=_Clock(ts)).add_confession(content, ts=ts)
        assert first != second
        assert _is_confession_id(first)
        assert _is_confession_id(second)

    def test_id_is_not_sha256_of_content_and_timestamp(self) -> None:
        content = "it was me"
        ts = 1_721_654_321.0
        hashed = _truncated_content_hash(content, ts)
        hashed_retry = _truncated_content_hash(content, ts, suffix=1)
        board = ConfessionsResource(time_func=_Clock(ts))
        conf_id = board.add_confession(content, ts=ts)
        assert conf_id != hashed
        assert conf_id != hashed_retry
        assert _is_confession_id(conf_id)

    def test_same_board_same_payload_gets_distinct_ids(self) -> None:
        clock = _Clock(1_721_654_321.0)
        board = ConfessionsResource(time_func=clock)
        content = "same text"
        first = board.add_confession(content, ts=clock.t)
        second = board.add_confession(content, ts=clock.t)
        assert first != second
        ids = {item["id"] for item in board.confessions()}
        assert ids == {first, second}

    def test_unique_id_retries_on_collision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from lichen.coap.resources import confessions as module

        board = ConfessionsResource(time_func=_Clock())
        board.add_confession("held", confession_id="aaaaaa")
        draws = iter(["aaaaaa", "aaaaaa", "bbbbbb"])
        monkeypatch.setattr(module, "_generate_id", lambda: next(draws))
        assert board.add_confession("fresh") == "bbbbbb"
        remaining = [item["id"] for item in board.confessions()]
        assert remaining == ["aaaaaa", "bbbbbb"]

    async def test_post_location_path_is_not_content_hash(self) -> None:
        content = "it was me"
        bt = 1_721_654_321.0
        hashed = _truncated_content_hash(content, bt)
        clock = _Clock(bt)
        board = ConfessionsResource(time_func=clock)
        first = await board.render_post(_post(_payload(content=content, bt=bt)))
        clock.t += CONFESSION_COOLDOWN_S
        second = await board.render_post(_post(_payload(content=content, bt=bt)))
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.CREATED
        id1 = first.opt.location_path[1]
        id2 = second.opt.location_path[1]
        assert _is_confession_id(id1)
        assert _is_confession_id(id2)
        assert id1 != id2
        assert id1 != hashed
        assert id2 != hashed
        assert first.opt.location_path == ("confessions", id1)
        assert second.opt.location_path == ("confessions", id2)


# ---------------------------------------------------------------------------
# POST / GET oracle
# ---------------------------------------------------------------------------


class TestPostAndGet:
    async def test_spec_example_creates_anonymous_confession(self) -> None:
        vec = _vec("anonymous_confession_default")
        clock = _Clock(1_721_654_321.0)
        board = ConfessionsResource(time_func=clock)
        response = await board.render_post(_post(_pack_senml_json(vec["senml_json"])))
        assert response.code == aiocoap.CREATED
        assert response.code.dotted == vec["expected"]["response_code"].split()[0]
        location = "/" + "/".join(response.opt.location_path)
        assert location.startswith(vec["expected"]["location_path_prefix"])
        assert len(response.opt.location_path[1]) == 6
        assert response.opt.max_age == 43200
        stored = board.confessions()
        assert len(stored) == 1
        assert stored[0]["anonymous"] is True
        assert stored[0]["source"] is None
        assert "oscore" not in stored[0]
        assert stored[0]["content"].startswith("Left the forward operating base")

    async def test_minimal_anonymous_defaults(self) -> None:
        vec = _vec("anonymous_confession_minimal")
        board = ConfessionsResource(time_func=_Clock())
        response = await board.render_post(_post(_pack_senml_json(vec["senml_json"])))
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["anonymous"] is vec["expected"]["anonymous_default"] is True
        assert stored["source"] is None
        assert response.opt.max_age == CONFESSION_DEFAULT_TTL

    async def test_non_anonymous_stores_sender(self) -> None:
        vec = _vec("non_anonymous_confession")
        board = ConfessionsResource(time_func=_Clock())
        iid = "0011223344556677"
        response = await board.render_post(
            _post(_pack_senml_json(vec["senml_json"]), source_iid=iid)
        )
        assert response.code.dotted in {
            opt.split()[0] for opt in vec["expected"]["response_code_options"]
        }
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["anonymous"] is False
        assert stored["source"] == iid
        detail = await ConfessionsDetailsResource(board).render_get(_get(path=(stored["id"],)))
        body = cbor2.loads(detail.payload)
        assert body["sender"] == iid
        assert body["anonymous"] is False

    async def test_get_collection_is_cbor_query_map(self) -> None:
        clock = _Clock(1_000.0)
        iid = "0011223344556677"
        board = ConfessionsResource(time_func=clock)
        created = await board.render_post(
            _post(_payload(iid=iid, content="hello", bt=1_000.0), source_iid=iid)
        )
        conf_id = created.opt.location_path[1]
        clock.t += 12
        # Authenticated GET from same IID shows requester's rate info
        response = await board.render_get(_get(source_iid=iid))
        assert response.code == aiocoap.CONTENT
        assert response.opt.content_format == CBOR
        body = cbor2.loads(response.payload)
        assert body["count"] == 1
        assert body["confessions"][0]["id"] == conf_id
        assert body["confessions"][0]["content"] == "hello"
        assert body["confessions"][0]["age_s"] == 12
        assert body["rate_remaining"] == CONFESSION_HOURLY_MAX - 1
        assert "storage_used_kb" in body
        assert body["storage_max_kb"] == 2.0
        assert "logging" not in body

    async def test_empty_get_is_zero_count(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        response = await board.render_get(_get())
        body = cbor2.loads(response.payload)
        assert body["count"] == 0
        assert body["confessions"] == []

    async def test_listing_is_newest_first(self) -> None:
        clock = _Clock(100.0)
        board = ConfessionsResource(time_func=clock)
        await board.render_post(_post(_payload(content="old", bt=100.0)))
        clock.t += 40
        await board.render_post(_post(_payload(content="new", bt=140.0)))
        body = cbor2.loads((await board.render_get(_get())).payload)
        assert [item["content"] for item in body["confessions"]] == ["new", "old"]

    async def test_empty_payload_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        response = await board.render_post(_post(b""))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_non_array_cbor_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        response = await board.render_post(_post(cbor2.dumps({"n": "content", "vs": "x"})))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_trailing_cbor_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        payload = _payload() + b"\x00"
        response = await board.render_post(_post(payload))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_missing_iid_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        payload = pack([SenmlRecord(n="type", vs="confession"), SenmlRecord(n="content", vs="x")])
        response = await board.render_post(_post(payload))
        assert response.code == aiocoap.BAD_REQUEST

    async def test_wrong_type_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        payload = pack(
            [
                SenmlRecord(bn="urn:dev:mac:0011223344556677:"),
                SenmlRecord(n="type", vs="message"),
                SenmlRecord(n="content", vs="nope"),
            ]
        )
        response = await board.render_post(_post(payload))
        assert response.code == aiocoap.BAD_REQUEST


class TestGetById:
    async def test_get_single_confession_and_max_age(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        details = ConfessionsDetailsResource(board)
        created = await board.render_post(_post(_payload(content="secret cache", ttl=100)))
        conf_id = created.opt.location_path[1]
        clock.t += 12
        response = await details.render_get(_get(path=(conf_id,)))
        assert response.code == aiocoap.CONTENT
        assert response.opt.content_format == CBOR
        body = cbor2.loads(response.payload)
        assert body["id"] == conf_id
        assert body["content"] == "secret cache"
        assert body["age_s"] == 12
        assert body["anonymous"] is True
        assert "sender" not in body
        assert response.opt.max_age == 88

    async def test_missing_and_invalid_ids_are_not_found(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        details = ConfessionsDetailsResource(board)
        missing = await details.render_get(_get(path=("ffffff",)))
        assert missing.code == aiocoap.NOT_FOUND
        invalid = await details.render_get(_get(path=("7F3A9C",)))
        assert invalid.code == aiocoap.NOT_FOUND
        empty = await details.render_get(_get())
        assert empty.code == aiocoap.NOT_FOUND


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


class TestLimits:
    async def test_oversized_post_is_4_13(self) -> None:
        vec = _vec("max_confession_size_exceeded")
        board = ConfessionsResource(time_func=_Clock())
        payload = _payload(content="x" * vec["payload_size_bytes"])
        assert len(payload) > CONFESSION_MAX_SIZE
        response = await board.render_post(_post(payload))
        assert response.code == aiocoap.REQUEST_ENTITY_TOO_LARGE
        assert response.code.dotted == vec["expected"]["response_code"].split()[0]
        assert board.confessions() == []

    async def test_payload_at_768_is_accepted(self) -> None:
        vec = _vec("max_confession_size_accepted")
        board = ConfessionsResource(time_func=_Clock())
        content_len = 1
        body = _payload(content="x")
        while len(_payload(content="x" * (content_len + 1))) <= CONFESSION_MAX_SIZE:
            content_len += 1
            body = _payload(content="x" * content_len)
        assert len(body) <= CONFESSION_MAX_SIZE == vec["payload_size_bytes"]
        response = await board.render_post(_post(body))
        assert response.code == aiocoap.CREATED
        assert vec["expected"]["accept"] is True

    async def test_thirteenth_post_in_hour_is_4_29(self) -> None:
        vec = _vec("rate_limit_13th_post_rejected")
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        iid = vec["sender_iid"]
        for i in range(vec["history_count_in_rolling_hour"]):
            clock.t += CONFESSION_COOLDOWN_S
            response = await board.render_post(
                _post(_payload(iid=iid, content=f"n{i}"), source_iid=iid)
            )
            assert response.code == aiocoap.CREATED
        clock.t += CONFESSION_COOLDOWN_S
        limited = await board.render_post(
            _post(_payload(iid=iid, content="rejected"), source_iid=iid)
        )
        assert limited.code == aiocoap.TOO_MANY_REQUESTS
        assert limited.code.dotted == vec["expected"]["response_code"].split()[0]
        assert limited.opt.content_format == CBOR
        assert cbor2.loads(limited.payload) == {"retry_after": limited.opt.max_age}
        assert limited.opt.max_age >= 1

    async def test_twelfth_post_at_hourly_limit_accepted(self) -> None:
        vec = _vec("rate_limit_12th_post_accepted")
        clock = _Clock()
        board = ConfessionsResource(time_func=clock, node_iid=vec["sender_iid"])
        iid = vec["sender_iid"]
        for i in range(vec["history_count_in_rolling_hour"]):
            clock.t += CONFESSION_COOLDOWN_S
            assert (
                await board.render_post(_post(_payload(iid=iid, content=f"n{i}"), source_iid=iid))
            ).code == (aiocoap.CREATED)
        clock.t += CONFESSION_COOLDOWN_S
        twelfth = await board.render_post(
            _post(_pack_senml_json(vec["senml_json"]), source_iid=iid)
        )
        assert twelfth.code == aiocoap.CREATED
        # Authenticated GET from same IID shows requester's rate info
        listing = cbor2.loads((await board.render_get(_get(source_iid=iid))).payload)
        assert listing["rate_remaining"] == vec["expected"]["rate_remaining"] == 0

    async def test_second_within_30s_is_4_29_with_retry_after(self) -> None:
        vec = _vec("rate_limit_30s_window")
        clock = _Clock(vec["last_post_uptime_ms"] / 1000)
        board = ConfessionsResource(time_func=clock)
        iid = vec["sender_iid"]
        assert (
            await board.render_post(_post(_payload(iid=iid, content="first"), source_iid=iid))
        ).code == (aiocoap.CREATED)
        clock.t = vec["current_uptime_ms"] / 1000
        limited = await board.render_post(
            _post(_payload(iid=iid, content="second"), source_iid=iid)
        )
        assert limited.code == aiocoap.TOO_MANY_REQUESTS
        assert cbor2.loads(limited.payload)["retry_after"] == vec["expected"]["retry_after_s"]
        assert limited.opt.max_age == vec["expected"]["retry_after_s"]

    async def test_different_nodes_independent(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        a_iid = "aa" * 8
        b_iid = "bb" * 8
        for i in range(CONFESSION_HOURLY_MAX):
            clock.t += CONFESSION_COOLDOWN_S
            assert (
                await board.render_post(
                    _post(_payload(iid=a_iid, content=f"a{i}"), source_iid=a_iid)
                )
            ).code == aiocoap.CREATED
        clock.t += CONFESSION_COOLDOWN_S
        other = await board.render_post(
            _post(_payload(iid=b_iid, content="fresh"), source_iid=b_iid)
        )
        assert other.code == aiocoap.CREATED


class TestAuthenticatedIdentity:
    """Rate limits and displayed sender bind to authenticated identity, not bn."""

    async def test_distinct_bn_does_not_mint_quota(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        source = "0011223344556677"
        first = await board.render_post(
            _post(_payload(iid="aa" * 8, content="one"), source_iid=source)
        )
        assert first.code == aiocoap.CREATED
        second = await board.render_post(
            _post(_payload(iid="bb" * 8, content="two"), source_iid=source)
        )
        assert second.code == aiocoap.TOO_MANY_REQUESTS
        assert list(board._request_times) == [source]

    async def test_twenty_spoofed_bn_share_one_bucket(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        source = "0011223344556677"
        created = 0
        limited = 0
        for i in range(20):
            response = await board.render_post(
                _post(_payload(iid=f"{i:016x}", content=f"spam{i}"), source_iid=source)
            )
            if response.code == aiocoap.CREATED:
                created += 1
            elif response.code == aiocoap.TOO_MANY_REQUESTS:
                limited += 1
            else:
                raise AssertionError(response.code)
        assert created == 1
        assert limited == 19
        assert list(board._request_times) == [source]

    async def test_senml_sender_field_is_not_trusted(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        victim = "aabbccddeeff0011"
        real = "0011223344556677"
        response = await board.render_post(
            _post(
                _payload(
                    iid=victim,
                    anonymous=0,
                    content="field",
                    extra=[SenmlRecord(n="sender", vs=victim)],
                ),
                source_iid=real,
            )
        )
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["source"] is None
        detail = await ConfessionsDetailsResource(board).render_get(_get(path=(stored["id"],)))
        assert "sender" not in cbor2.loads(detail.payload)
        assert list(board._request_times) == [real]

    async def test_spoofed_bn_is_not_displayed_sender(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        victim = "aabbccddeeff0011"
        real = "0011223344556677"
        response = await board.render_post(
            _post(_payload(iid=victim, anonymous=0, content="impersonate"), source_iid=real)
        )
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["anonymous"] is False
        assert stored["source"] is None
        detail = await ConfessionsDetailsResource(board).render_get(_get(path=(stored["id"],)))
        body = cbor2.loads(detail.payload)
        assert "sender" not in body
        assert body["anonymous"] is False

    async def test_matching_bn_and_ipv6_iid_displays_sender(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        iid = "0011223344556677"
        response = await board.render_post(
            _post(_payload(iid=iid, anonymous=0, content="signed"), source_iid=iid)
        )
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["source"] == iid
        detail = await ConfessionsDetailsResource(board).render_get(_get(path=(stored["id"],)))
        assert cbor2.loads(detail.payload)["sender"] == iid

    async def test_non_anonymous_without_authenticated_iid_omits_sender(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        response = await board.render_post(_post(_payload(anonymous=0, content="no remote")))
        assert response.code == aiocoap.CREATED
        stored = board.confessions()[0]
        assert stored["source"] is None
        detail = await ConfessionsDetailsResource(board).render_get(_get(path=(stored["id"],)))
        assert "sender" not in cbor2.loads(detail.payload)

    async def test_same_bn_different_ipv6_sources_are_independent(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        claimed = "ffffffffffff0000"
        a_iid = "aa" * 8
        b_iid = "bb" * 8
        first = await board.render_post(
            _post(_payload(iid=claimed, content="from-a"), source_iid=a_iid)
        )
        second = await board.render_post(
            _post(_payload(iid=claimed, content="from-b"), source_iid=b_iid)
        )
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.CREATED
        assert set(board._request_times) == {a_iid, b_iid}

    async def test_oscore_identity_keys_rate_when_no_ipv6(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        first = await board.render_post(
            _post(_payload(iid="aa" * 8, content="one"), oscore="kid-a")
        )
        second = await board.render_post(
            _post(_payload(iid="bb" * 8, content="two"), oscore="kid-a")
        )
        other = await board.render_post(
            _post(_payload(iid="aa" * 8, content="other"), oscore="kid-b")
        )
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.TOO_MANY_REQUESTS
        assert other.code == aiocoap.CREATED
        assert set(board._request_times) == {"oscore:kid-a", "oscore:kid-b"}

    async def test_ipv6_iid_preferred_over_oscore(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        iid = "0011223344556677"
        first = await board.render_post(
            _post(_payload(content="one"), source_iid=iid, oscore="kid-a")
        )
        second = await board.render_post(
            _post(_payload(content="two"), source_iid=iid, oscore="kid-b")
        )
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.TOO_MANY_REQUESTS
        assert list(board._request_times) == [iid]

    async def test_native_0200_source_iid_keys_rate(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        iid = "0011223344556677"
        packed = b"\x02" + b"\x00" * 7 + bytes.fromhex(iid)
        hostinfo = f"[{IPv6Address(packed)}]:61616"
        first = await board.render_post(
            _post(_payload(iid="aa" * 8, content="one"), hostinfo=hostinfo)
        )
        second = await board.render_post(
            _post(_payload(iid="bb" * 8, content="two"), hostinfo=hostinfo)
        )
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.TOO_MANY_REQUESTS
        assert list(board._request_times) == [iid]

    async def test_stale_rate_buckets_reaped_without_key_return(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        for i in range(20):
            board._record_request(f"{i:016x}")
        assert len(board._request_times) == 20
        clock.t += 3601
        live = "aa" * 8
        created = await board.render_post(
            _post(_payload(iid=live, content="fresh"), source_iid=live)
        )
        assert created.code == aiocoap.CREATED
        assert list(board._request_times) == [live]

    async def test_get_reaps_stale_buckets_without_that_key(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock, node_iid="0011223344556677")
        for i in range(8):
            board._record_request(f"{i:016x}")
        assert len(board._request_times) == 8
        clock.t += 3601
        await board.render_get(_get())
        assert board._request_times == {}

    async def test_unauthenticated_posts_share_one_bucket(self) -> None:
        clock = _Clock()
        board = ConfessionsResource(time_func=clock)
        first = await board.render_post(_post(_payload(iid="aa" * 8, content="one")))
        second = await board.render_post(_post(_payload(iid="bb" * 8, content="two")))
        assert first.code == aiocoap.CREATED
        assert second.code == aiocoap.TOO_MANY_REQUESTS
        assert list(board._request_times) == ["unauthenticated"]


class TestTtlAndEviction:
    async def test_ttl_clamped_to_48h(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        payload = _payload(content="long", ttl=CONFESSION_MAX_TTL * 2)
        response = await board.render_post(_post(payload))
        assert response.code == aiocoap.CREATED
        assert response.opt.max_age == CONFESSION_MAX_TTL

    async def test_expired_omitted_from_get(self) -> None:
        vec = _vec("ttl_expiry")
        clock = _Clock(vec["confession"]["ts"])
        board = ConfessionsResource(time_func=clock)
        conf_id = board.add_confession(
            "expired",
            confession_id="aabb01",
            ts=vec["confession"]["ts"],
            ttl=vec["confession"]["ttl"],
        )
        clock.t = vec["current_time"]
        listing = cbor2.loads((await board.render_get(_get())).payload)
        assert listing["confessions"] == []
        assert vec["expected"]["confession_returned"] is False
        missing = await ConfessionsDetailsResource(board).render_get(_get(path=(conf_id,)))
        assert missing.code == aiocoap.NOT_FOUND

    async def test_fifo_evicts_oldest_silently(self) -> None:
        vec = _vec("storage_full_fifo_eviction")
        clock = _Clock()
        limit = int(vec["storage_max_kb"] * 1024)
        board = ConfessionsResource(time_func=clock, storage_limit=limit)
        # Vector uses names like "oldest1"; seed equivalent 6-char hex ids in the
        # same FIFO order and sizes so eviction matches 18.10.3.
        seeds = [
            ("aa0001", vec["existing_confessions"][0]),
            ("aa0002", vec["existing_confessions"][1]),
            ("aa0003", vec["existing_confessions"][2]),
            ("aa0004", vec["existing_confessions"][3]),
        ]
        for conf_id, item in seeds:
            clock.t = float(item["ts"])
            board.add_confession("x", confession_id=conf_id, ts=item["ts"], size=item["size_bytes"])
        incoming = vec["incoming_confession_size_bytes"]
        clock.t += 1
        new_id = board.add_confession("incoming", confession_id="aa0005", size=incoming)
        remaining = [item["id"] for item in board.confessions()]
        assert new_id == "aa0005"
        assert remaining == ["aa0003", "aa0004", "aa0005"]
        assert vec["expected"]["eviction_policy"] == "FIFO"
        assert vec["expected"]["no_back_pressure"] is True

    async def test_br_budget_holds_more_than_leaf(self) -> None:
        vec = _vec("storage_full_br_larger_budget")
        size = 512
        leaf = ConfessionsResource(storage_limit=CONFESSION_STORAGE_LEAF, time_func=_Clock())
        br = ConfessionsResource(
            is_border_router=True, storage_limit=CONFESSION_STORAGE_BR, time_func=_Clock()
        )
        leaf_fit = CONFESSION_STORAGE_LEAF // size
        br_fit = CONFESSION_STORAGE_BR // size
        assert br_fit > leaf_fit
        assert vec["storage_max_kb"] == 8
        for i in range(leaf_fit):
            leaf.add_confession(f"l{i}", confession_id=f"{i:06x}", size=size)
        assert len(leaf.confessions()) == leaf_fit
        for i in range(br_fit):
            br.add_confession(f"b{i}", confession_id=f"{i:06x}", size=size)
        assert len(br.confessions()) == br_fit
        br.add_confession("overflow", confession_id="ffffff", size=size)
        assert vec["expected"]["eviction_needed"] is True
        assert len(br.confessions()) == br_fit


class TestQueryAndReboot:
    async def test_count_since_after_type(self) -> None:
        clock = _Clock(1000)
        board = ConfessionsResource(time_func=clock)
        clock.t = 1000
        await board.render_post(_post(_payload(content="a", bt=1000)))
        clock.t = 2000
        await board.render_post(_post(_payload(content="b", bt=2000)))
        limited = cbor2.loads((await board.render_get(_get(query=("count=1",)))).payload)
        assert limited["count"] == 1
        assert limited["confessions"][0]["content"] == "b"
        since = cbor2.loads((await board.render_get(_get(query=("since=1500",)))).payload)
        assert [item["content"] for item in since["confessions"]] == ["b"]
        after = cbor2.loads((await board.render_get(_get(query=("after=1000",)))).payload)
        assert [item["content"] for item in after["confessions"]] == ["b"]
        typed = cbor2.loads((await board.render_get(_get(query=("type=confession",)))).payload)
        assert typed["count"] == 2
        other = cbor2.loads((await board.render_get(_get(query=("type=waypoint",)))).payload)
        assert other["count"] == 0

    async def test_invalid_query_is_bad_request(self) -> None:
        board = ConfessionsResource(time_func=_Clock())
        assert (await board.render_get(_get(query=("count=nope",)))).code == aiocoap.BAD_REQUEST
        assert (await board.render_get(_get(query=("since=nope",)))).code == aiocoap.BAD_REQUEST
        assert (await board.render_get(_get(query=("after=nope",)))).code == aiocoap.BAD_REQUEST
        assert (await board.render_get(_get(query=("count=-1",)))).code == aiocoap.BAD_REQUEST

    async def test_reboot_clears_ram(self) -> None:
        for name in ("reboot_clear_empty_get", "reboot_clear_crash"):
            vec = _vec(name)
            board = ConfessionsResource(time_func=_Clock())
            for i in range(vec["pre_reboot_confession_count"]):
                board.add_confession(f"c{i}", confession_id=f"{i:06x}")
            assert len(board.confessions()) == vec["pre_reboot_confession_count"]
            board.clear()
            response = await board.render_get(_get())
            body = cbor2.loads(response.payload)
            assert response.code == aiocoap.CONTENT
            assert body["count"] == vec["expected"]["confession_count"] == 0
            assert body["confessions"] == []

    async def test_persist_flag_surfaces_logging(self) -> None:
        board = ConfessionsResource(time_func=_Clock(), persist=True)
        body = cbor2.loads((await board.render_get(_get())).payload)
        assert body["logging"] is True

    async def test_no_log_storage_is_ram_only(self) -> None:
        vec = _vec("no_log_guarantee_checks")
        board = ConfessionsResource(time_func=_Clock())
        await board.render_post(_post(_payload(content="do not persist")))
        assert vec["expected"]["storage_type"] == "ram_only"
        assert vec["expected"]["cleared_on_reboot"] is True
        assert board._confessions  # in-process list, not a file
        board.clear()
        assert board.confessions() == []


# ---------------------------------------------------------------------------
# Site wiring and Observe
# ---------------------------------------------------------------------------


async def _setup(
    board: ConfessionsResource | None = None,
) -> tuple[aiocoap.Context, aiocoap.Context, ConfessionsResource]:
    net = InMemoryNetwork()
    resource = board if board is not None else ConfessionsResource(time_func=_Clock())
    site = build_site(StaticNodeInfo(status={"rank": 256}), confessions_resource=resource)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, resource


class TestSiteAndObserve:
    async def test_default_site_has_no_confessions(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv", site=build_site(StaticNodeInfo())
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            response = await client.request(
                Message(code=POST, uri="coap://srv/confessions", payload=_payload())
            ).response
            assert response.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_by_id_over_stack(self) -> None:
        client, server, board = await _setup()
        try:
            conf_id = board.add_confession("stack", confession_id="7f3a9c")
            assert conf_id == "7f3a9c"
            response = await client.request(
                Message(code=GET, uri="coap://srv/confessions/7f3a9c")
            ).response
            assert response.code == aiocoap.CONTENT
            assert response.opt.content_format == 60
            assert cbor2.loads(response.payload)["content"] == "stack"
            missing = await client.request(
                Message(code=GET, uri="coap://srv/confessions/ffffff")
            ).response
            assert missing.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notifies_on_new_confession(self) -> None:
        client, server, board = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/confessions"))
            first = await req.response
            assert first.code == aiocoap.CONTENT
            assert first.opt.observe is not None
            assert cbor2.loads(first.payload)["confessions"] == []
            obs_iter = req.observation.__aiter__()
            board.add_confession("arrived", confession_id="aa00aa")
            notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            body = cbor2.loads(notification.payload)
            assert any(item.get("content") == "arrived" for item in body["confessions"])
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_well_known_core_advertises_confessions(self) -> None:
        client, server, _board = await _setup()
        try:
            response = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            body = response.payload.decode()
            assert "</confessions>" in body
            assert 'rt="confessions"' in body or "rt=confessions" in body
            assert "obs" in body
        finally:
            await client.shutdown()
            await server.shutdown()

    def test_link_description_matches_spec(self) -> None:
        desc = ConfessionsResource().get_link_description()
        assert desc["rt"] == "confessions"
        # GET body is 18.10.7 CBOR query map (ct=60), not SenML+CBOR (ct=112)
        assert desc["ct"] == str(int(CBOR))
        assert "obs" in desc
