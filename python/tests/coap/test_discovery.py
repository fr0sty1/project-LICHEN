# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Python discovery oracle for GET /.well-known/core (spec/11-lci.md 17.5.1).

Independent oracle: expected href/rt/obs/ct values are copied from the spec
example, not from ``get_link_description()``. Live emission is decoded by a
second link-format parser in this file and cross-checked against
``parse_link_format`` (the LCI client decoder).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from aiocoap import CONTENT, GET, Message

from lichen.client.lci import parse_link_format
from lichen.coap.resources import (
    DeadDropResource,
    MessageReceiptsResource,
    MessagesResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

# RFC 6690 application/link-format
WKC_CONTENT_FORMAT = 40
CBOR_CT = "60"
SENML_CT = "112"


@dataclass(frozen=True)
class SpecLink:
    """One spec/11-lci.md 17.5.1 discovery entry."""

    path: str
    rt: str
    obs: bool = False
    ct: str | None = None


# Copied from spec/11-lci.md section 17.5.1 (not from implementation).
SPEC_ALWAYS: tuple[SpecLink, ...] = (
    SpecLink("/config", "config"),
    SpecLink("/config/radio", "config"),
    SpecLink("/config/identity", "config"),
    SpecLink("/status", "status", obs=True),
    SpecLink("/status/neighbors", "status", obs=True),
    SpecLink("/status/routes", "status"),
)

# Spec 17.5.1 also lists /diag and /confessions. Those resources exist but are
# not mounted by build_site(); they are pinned on the spec example body below.
SPEC_OPTIONAL: tuple[SpecLink, ...] = (
    SpecLink("/keys", "keystore"),
    SpecLink("/msg/inbox", "msg.inbox", obs=True, ct=CBOR_CT),
    SpecLink("/msg/sent", "msg.sent", ct=CBOR_CT),
    SpecLink("/msg/ack", "msg.ack", ct=CBOR_CT),
    SpecLink("/deaddrop", "deaddrop", obs=True, ct=SENML_CT),
)


def _split_quoted(text: str, sep: str) -> list[str]:
    """Split *text* on *sep* ignoring separators inside double quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == sep and not in_quotes:
            piece = "".join(buf).strip()
            if piece:
                parts.append(piece)
            buf = []
        else:
            buf.append(ch)
    if in_quotes:
        raise ValueError("unclosed quote")
    piece = "".join(buf).strip()
    if piece:
        parts.append(piece)
    return parts


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_wkc_oracle(body: str) -> dict[str, dict[str, object]]:
    """Second CoRE Link Format decoder (href -> rt/obs/ct). Independent of LCI."""
    out: dict[str, dict[str, object]] = {}
    for entry in _split_quoted(body, ","):
        target, *params = [part.strip() for part in _split_quoted(entry, ";")]
        if not target.startswith("<") or not target.endswith(">"):
            continue
        href = target[1:-1]
        rt: tuple[str, ...] = ()
        obs = False
        ct: str | None = None
        for param in params:
            if param == "obs":
                obs = True
            elif param.startswith("rt="):
                rt = tuple(_unquote(param[3:]).split())
            elif param.startswith("ct="):
                ct = _unquote(param[3:])
        out[href] = {"rt": rt, "obs": obs, "ct": ct}
    return out


def _assert_spec_link(parsed: dict[str, dict[str, object]], spec: SpecLink) -> None:
    assert spec.path in parsed, f"{spec.path} missing from WKC"
    attrs = parsed[spec.path]
    assert attrs["rt"] == (spec.rt,), f"{spec.path} rt={attrs['rt']!r} want {(spec.rt,)!r}"
    assert attrs["obs"] is spec.obs, f"{spec.path} obs={attrs['obs']!r} want {spec.obs!r}"
    if spec.ct is not None:
        assert attrs["ct"] == spec.ct, f"{spec.path} ct={attrs['ct']!r} want {spec.ct!r}"


async def _stack(site: Any) -> tuple[Any, Any]:
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


async def _wkc(client: Any, query: str = "") -> tuple[Message, str]:
    uri = "coap://server/.well-known/core"
    if query:
        uri = f"{uri}?{query}"
    response = await client.request(Message(code=GET, uri=uri)).response
    return response, response.payload.decode("ascii")


@pytest.mark.asyncio
async def test_default_site_wkc_matches_spec_always_on_links() -> None:
    client, server = await _stack(build_site(StaticNodeInfo()))
    try:
        response, body = await _wkc(client)
        assert response.code == CONTENT
        assert int(response.opt.content_format) == WKC_CONTENT_FORMAT
        parsed = parse_wkc_oracle(body)
        caps = parse_link_format(body)
        for spec in SPEC_ALWAYS:
            _assert_spec_link(parsed, spec)
            assert spec.path in caps.resources
            assert caps.resource_types[spec.path] == (spec.rt,)
            assert (spec.path in caps.observable) is spec.obs
        for spec in SPEC_OPTIONAL:
            assert spec.path not in parsed
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_rt_query_filters_to_matching_resource_types() -> None:
    client, server = await _stack(build_site(StaticNodeInfo()))
    try:
        _response, body = await _wkc(client, "rt=config")
        parsed = parse_wkc_oracle(body)
        hrefs = {href for href in parsed if href.startswith("/")}
        assert hrefs == {"/config", "/config/radio", "/config/identity"}
        for href in hrefs:
            assert parsed[href]["rt"] == ("config",)

        _response, status_body = await _wkc(client, "rt=status")
        status_parsed = parse_wkc_oracle(status_body)
        status_hrefs = {href for href in status_parsed if href.startswith("/")}
        assert status_hrefs == {"/status", "/status/neighbors", "/status/routes"}
        assert status_parsed["/status"]["obs"] is True
        assert status_parsed["/status/neighbors"]["obs"] is True
        assert status_parsed["/status/routes"]["obs"] is False
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_unknown_rt_query_omits_lichen_resources() -> None:
    client, server = await _stack(build_site(StaticNodeInfo()))
    try:
        response, body = await _wkc(client, "rt=no-such-type")
        assert response.code == CONTENT
        parsed = parse_wkc_oracle(body)
        assert not any(href.startswith("/config") or href.startswith("/status") for href in parsed)
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_optional_spec_resources_advertise_when_mounted() -> None:
    site = build_site(
        StaticNodeInfo(),
        pubkey=bytes(range(32)),
        messages_resource=MessagesResource(),
        message_receipts_resource=MessageReceiptsResource(),
        deaddrop_resource=DeadDropResource(),
    )
    client, server = await _stack(site)
    try:
        response, body = await _wkc(client)
        assert int(response.opt.content_format) == WKC_CONTENT_FORMAT
        parsed = parse_wkc_oracle(body)
        caps = parse_link_format(body)
        for spec in (*SPEC_ALWAYS, *SPEC_OPTIONAL):
            _assert_spec_link(parsed, spec)
            assert spec.path in caps.resources
            assert caps.resource_types[spec.path] == (spec.rt,)
            assert (spec.path in caps.observable) is spec.obs

        _response, filtered = await _wkc(client, "rt=msg.*")
        filtered_parsed = parse_wkc_oracle(filtered)
        msg_hrefs = {href for href in filtered_parsed if href.startswith("/msg/")}
        assert {"/msg/inbox", "/msg/sent", "/msg/ack"} <= msg_hrefs
    finally:
        await client.shutdown()
        await server.shutdown()


def test_oracle_parser_agrees_with_lci_decoder_on_spec_example() -> None:
    """Cross-check the test-local parser against the real LCI decoder."""
    body = (
        '</config>;rt="config",'
        '</config/radio>;rt="config",'
        '</config/identity>;rt="config",'
        '</status>;rt="status";obs,'
        '</status/neighbors>;rt="status";obs,'
        '</status/routes>;rt="status",'
        '</keys>;rt="keystore",'
        '</diag>;rt="diagnostics",'
        '</msg/inbox>;rt="msg.inbox";ct=60;obs,'
        '</msg/sent>;rt="msg.sent";ct=60,'
        '</msg/ack>;rt="msg.ack";ct=60,'
        '</deaddrop>;rt="deaddrop";ct=112;obs,'
        '</confessions>;rt="confessions";ct=112;obs'
    )
    parsed = parse_wkc_oracle(body)
    caps = parse_link_format(body)
    extra = (
        SpecLink("/diag", "diagnostics"),
        SpecLink("/confessions", "confessions", obs=True, ct=SENML_CT),
    )
    for spec in (*SPEC_ALWAYS, *SPEC_OPTIONAL, *extra):
        _assert_spec_link(parsed, spec)
        assert spec.path in caps.resources
        assert caps.resource_types[spec.path] == (spec.rt,)
        assert (spec.path in caps.observable) is spec.obs
