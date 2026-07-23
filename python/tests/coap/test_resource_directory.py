# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the CoAP Resource Directory (/rd, RFC 9176)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import DELETE, GET, POST, Message, resource

from lichen.coap.resources import ResourceDirectoryResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LINKS = [
    {"href": "/sensors", "rt": "senml"},
    {"href": "/status",  "rt": "status"},
]


async def _setup(resource_directory: bool = True):
    net = InMemoryNetwork()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, resource_directory=resource_directory)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server


async def _register(client, ep: str = "node-01", lt: int = 3600, links=None):
    """POST /rd?ep=<ep>&lt=<lt> and return the response."""
    body = cbor2.dumps(links or _LINKS)
    return await client.request(
        Message(
            code=POST,
            uri=f"coap://srv/rd?ep={ep}&lt={lt}",
            payload=body,
            content_format=60,
        )
    ).response


# ---------------------------------------------------------------------------
# Registration (POST /rd)
# ---------------------------------------------------------------------------


class TestRdPost:
    async def test_register_returns_created(self) -> None:
        client, server = await _setup()
        try:
            resp = await _register(client)
            assert resp.code == aiocoap.CREATED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_register_returns_location_path(self) -> None:
        client, server = await _setup()
        try:
            resp = await _register(client, ep="node-01")
            loc = resp.opt.location_path
            assert loc is not None
            assert loc[0] == "rd"
            assert loc[1]  # non-empty reg ID
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_register_without_ep_returns_bad_request(self) -> None:
        client, server = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/rd",
                        payload=cbor2.dumps(_LINKS), content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_two_registrations_get_different_ids(self) -> None:
        client, server = await _setup()
        try:
            r1 = await _register(client, ep="node-01")
            r2 = await _register(client, ep="node-02")
            id1 = r1.opt.location_path[1]
            id2 = r2.opt.location_path[1]
            assert id1 != id2
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_lifetime_accepts_rfc9176_boundaries(self) -> None:
        client, server = await _setup()
        try:
            minimum = await _register(client, ep="minimum", lt=1)
            maximum = await _register(client, ep="maximum", lt=(1 << 32) - 1)
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            assert minimum.code == aiocoap.CREATED
            assert maximum.code == aiocoap.CREATED
            assert [entry["lt"] for entry in cbor2.loads(listing.payload)] == [
                1,
                (1 << 32) - 1,
            ]
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "lifetime",
        ["", "true", "false", "1.0", "+1", "-1", "0", str(1 << 32)],
    )
    async def test_lifetime_rejects_invalid_values_without_mutation(
        self, lifetime: str
    ) -> None:
        client, server = await _setup()
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri=f"coap://srv/rd?ep=node-01&lt={lifetime}",
                    payload=cbor2.dumps(_LINKS),
                )
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(listing.payload) == []
            links = discovery.payload.decode().split(",")
            assert all(not link.startswith("</rd/") for link in links)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_register_with_invalid_cbor_body_returns_bad_request(self) -> None:
        client, server = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/rd?ep=node-01",
                        payload=b"\xa5\x01", content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_register_with_no_body_succeeds(self) -> None:
        """Empty body is legal — the endpoint just has no declared links."""
        client, server = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/rd?ep=node-99")
            ).response
            assert resp.code == aiocoap.CREATED
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "links",
        [
            [1],
            [{}],
            [{"rt": "senml"}],
            [{"href": ""}],
            [{"href": "relative"}],
            [{"href": "/trailing/"}],
            [{"href": "/double//segment"}],
            [{"href": "/../status"}],
            [{"href": "/status", "unknown": "value"}],
            [{"href": "/status", "rt": 1}],
            [{"href": "/status", "rt": ""}],
        ],
    )
    async def test_register_rejects_invalid_link_descriptors_without_mutation(
        self, links: object
    ) -> None:
        client, server = await _setup()
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rd?ep=node-01",
                    payload=cbor2.dumps(links),
                )
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(listing.payload) == []
            links = discovery.payload.decode().split(",")
            assert all(not link.startswith("</rd/") for link in links)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_register_rejects_nested_duplicate_cbor_keys_without_mutation(
        self,
    ) -> None:
        client, server = await _setup()
        try:
            key = cbor2.dumps("href")
            payload = (
                b"\x81\xa2"
                + key
                + cbor2.dumps("/sensors")
                + key
                + cbor2.dumps("/status")
            )
            response = await client.request(
                Message(code=POST, uri="coap://srv/rd?ep=node-01", payload=payload)
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(listing.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "payload",
        [
            b"\xd8\x1c" + cbor2.dumps(_LINKS),
            b"\x81\xa1" + cbor2.dumps("href") + b"\xd8\x1d\x00",
        ],
    )
    async def test_register_rejects_tags_without_entry_or_route(
        self, payload: bytes
    ) -> None:
        client, server = await _setup()
        try:
            response = await client.request(
                Message(code=POST, uri="coap://srv/rd?ep=node-01", payload=payload)
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(listing.payload) == []
            links = discovery.payload.decode().split(",")
            assert all(not link.startswith("</rd/") for link in links)
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "trailing",
        [cbor2.dumps({"extra": True}), b"trailing-junk"],
    )
    async def test_register_rejects_trailing_cbor_without_mutation(
        self, trailing: bytes
    ) -> None:
        client, server = await _setup()
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/rd?ep=node-01",
                    payload=cbor2.dumps(_LINKS) + trailing,
                    content_format=60,
                )
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response

            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(listing.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Lookup (GET /rd)
# ---------------------------------------------------------------------------


class TestRdGet:
    async def test_empty_directory(self) -> None:
        client, server = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            assert resp.code == aiocoap.CONTENT
            assert cbor2.loads(resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_registered_endpoint_appears_in_get(self) -> None:
        client, server = await _setup()
        try:
            await _register(client, ep="node-01")
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["ep"] == "node-01"
            assert entries[0]["lt"] == 3600
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_links_stored_in_registration(self) -> None:
        client, server = await _setup()
        try:
            await _register(client, ep="node-01", links=_LINKS)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            entry = cbor2.loads(resp.payload)[0]
            hrefs = {lnk["href"] for lnk in entry["links"]}
            assert hrefs == {"/sensors", "/status"}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_filter_by_ep(self) -> None:
        client, server = await _setup()
        try:
            await _register(client, ep="node-01")
            await _register(client, ep="node-02")
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd?ep=node-01")
            ).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["ep"] == "node-01"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_two_registrations_both_returned(self) -> None:
        client, server = await _setup()
        try:
            await _register(client, ep="node-01")
            await _register(client, ep="node-02")
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            entries = cbor2.loads(resp.payload)
            eps = {e["ep"] for e in entries}
            assert eps == {"node-01", "node-02"}
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Delete (DELETE /rd/<id>)
# ---------------------------------------------------------------------------


class TestRdDelete:
    async def test_delete_removes_registration(self) -> None:
        client, server = await _setup()
        try:
            reg = await _register(client, ep="node-01")
            reg_id = reg.opt.location_path[1]

            del_resp = await client.request(
                Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
            ).response
            assert del_resp.code == aiocoap.DELETED

            second_delete = await client.request(
                Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response

            get_resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            assert second_delete.code == aiocoap.NOT_FOUND
            assert f"</rd/{reg_id}>" not in discovery.payload.decode()
            assert cbor2.loads(get_resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_unknown_id_returns_not_found(self) -> None:
        client, server = await _setup()
        try:
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/rd/99999")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_repeated_add_delete_keeps_dynamic_routes_bounded(self) -> None:
        client, server = await _setup()
        deleted_paths: list[str] = []
        try:
            for index in range(10):
                registration = await _register(client, ep=f"node-{index}")
                reg_id = registration.opt.location_path[1]
                deleted_paths.append(f"</rd/{reg_id}>")
                response = await client.request(
                    Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
                ).response
                assert response.code == aiocoap.DELETED

            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            body = discovery.payload.decode()
            assert all(path not in body for path in deleted_paths)
            assert cbor2.loads(listing.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_route_removal_failure_preserves_entry_and_route(self) -> None:
        net = InMemoryNetwork()
        site = resource.Site()
        fail_removal = [True]

        def remove_route(reg_id: str) -> None:
            if fail_removal[0]:
                raise RuntimeError("injected route removal failure")
            site.remove_resource(["rd", reg_id])

        rd = ResourceDirectoryResource(site, route_remover=remove_route)
        site.add_resource(["rd"], rd)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            registration = await _register(client)
            reg_id = registration.opt.location_path[1]
            failed = await client.request(
                Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
            ).response
            listing = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response

            assert failed.code == aiocoap.INTERNAL_SERVER_ERROR
            assert cbor2.loads(listing.payload)[0]["id"] == reg_id

            fail_removal[0] = False
            succeeded = await client.request(
                Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
            ).response
            absent = await client.request(
                Message(code=DELETE, uri=f"coap://srv/rd/{reg_id}")
            ).response
            assert succeeded.code == aiocoap.DELETED
            assert absent.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Not exposed without flag
# ---------------------------------------------------------------------------


class TestRdNotExposed:
    async def test_rd_not_exposed_by_default(self) -> None:
        client, server = await _setup(resource_directory=False)
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/rd")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()
