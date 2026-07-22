# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN web status dashboard."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from lichen.dashboard.app import create_app

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------


class TestIndex:
    async def test_index_returns_200(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert resp.status_code == 200

    async def test_index_is_html(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert "text/html" in resp.headers["content-type"]

    async def test_index_uses_offline_refresh_script(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert "https://unpkg.com" not in resp.text
        assert "htmx.org" not in resp.text
        assert "function refreshElement" in resp.text
        assert 'hx-get="/partial/status"' in resp.text

    async def test_index_has_no_external_script_or_link_urls(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        external_urls = re.findall(r"""(?:src|href)=["']https?://[^"']+["']""", resp.text)
        # Allow D3.js CDN for advanced mesh visualization (topology, spectrum, GPS)
        d3_urls = [u for u in external_urls if "d3js.org" in u]
        assert len(d3_urls) <= 1
        other_urls = [u for u in external_urls if "d3js.org" not in u]
        assert other_urls == []

    async def test_index_contains_partials(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert "/partial/status" in resp.text
        assert "/partial/neighbors" in resp.text
        assert "/partial/presence" in resp.text
        assert "/partial/messages" in resp.text


# ---------------------------------------------------------------------------
# Partial fragments — node reachable
# ---------------------------------------------------------------------------


def _mock_fetch(return_value):
    return patch("lichen.dashboard.app._fetch", new=AsyncMock(return_value=return_value))


class TestPartialStatus:
    async def test_status_dict_renders_table(self, client: AsyncClient) -> None:
        with _mock_fetch({"rank": 256, "role": "router"}):
            resp = await client.get("/partial/status")
        assert resp.status_code == 200
        assert "rank" in resp.text
        assert "256" in resp.text

    async def test_status_unreachable_shows_error(self, client: AsyncClient) -> None:
        with _mock_fetch(None):
            resp = await client.get("/partial/status")
        assert resp.status_code == 200
        assert "Unreachable" in resp.text


class TestPartialNeighbors:
    async def test_empty_list_shows_message(self, client: AsyncClient) -> None:
        with _mock_fetch([]):
            resp = await client.get("/partial/neighbors")
        assert "No neighbors" in resp.text

    async def test_list_with_entry_renders_items(self, client: AsyncClient) -> None:
        with _mock_fetch([{"eui64": "00:11:22:33:44:55:66:77", "rssi": -80}]):
            resp = await client.get("/partial/neighbors")
        assert "eui64" in resp.text

    async def test_unreachable(self, client: AsyncClient) -> None:
        with _mock_fetch(None):
            resp = await client.get("/partial/neighbors")
        assert "Unreachable" in resp.text


class TestPartialPresence:
    async def test_empty(self, client: AsyncClient) -> None:
        with _mock_fetch([]):
            resp = await client.get("/partial/presence")
        assert "No peers" in resp.text

    async def test_with_peers(self, client: AsyncClient) -> None:
        with _mock_fetch([{"ep": "node-01", "lt": 3600}]):
            resp = await client.get("/partial/presence")
        assert "node-01" in resp.text


class TestPartialMessages:
    async def test_empty_inbox(self, client: AsyncClient) -> None:
        with _mock_fetch({"messages": []}):
            resp = await client.get("/partial/messages")
        assert "Inbox empty" in resp.text

    async def test_with_message(self, client: AsyncClient) -> None:
        with _mock_fetch({"messages": [{"from": "alice", "body": "hello mesh"}]}) as fetch:
            resp = await client.get("/partial/messages")
        assert "hello mesh" in resp.text
        fetch.assert_awaited_once_with("/msg/inbox")


class TestPartialSensors:
    async def test_empty(self, client: AsyncClient) -> None:
        with _mock_fetch([]):
            resp = await client.get("/partial/sensors")
        assert "No data" in resp.text

    async def test_list_format_senml(self, client: AsyncClient) -> None:
        # SenML as list-of-lists [name, value, unit]
        with _mock_fetch([["temperature", 23.4, "Cel"], ["humidity", 61.0, "%RH"]]):
            resp = await client.get("/partial/sensors")
        assert "temperature" in resp.text
        assert "23.4" in resp.text

    async def test_dict_format_senml(self, client: AsyncClient) -> None:
        # SenML as list-of-maps {n, v, u}
        with _mock_fetch([{"n": "temp", "v": 22.5, "u": "Cel"}]):
            resp = await client.get("/partial/sensors")
        assert "temp" in resp.text

    async def test_unreachable(self, client: AsyncClient) -> None:
        with _mock_fetch(None):
            resp = await client.get("/partial/sensors")
        assert "Unreachable" in resp.text


class TestPartialLocation:
    async def test_location_renders(self, client: AsyncClient) -> None:
        with _mock_fetch([["lat", 37.7749], ["lon", -122.4194]]):
            resp = await client.get("/partial/location")
        assert "lat" in resp.text
        assert "37.7749" in resp.text

    async def test_unreachable(self, client: AsyncClient) -> None:
        with _mock_fetch(None):
            resp = await client.get("/partial/location")
        assert "Unreachable" in resp.text


# ---------------------------------------------------------------------------
# Index — new cards present
# ---------------------------------------------------------------------------


class TestIndexCards:
    async def test_sensors_card_in_page(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert "/partial/sensors" in resp.text

    async def test_location_card_in_page(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        assert "/partial/location" in resp.text

    async def test_polling_targets_are_served_locally(self, client: AsyncClient) -> None:
        resp = await client.get("/")
        targets = sorted(set(re.findall(r'hx-get="([^"]+)"', resp.text)))
        assert targets == [
            "/partial/location",
            "/partial/messages",
            "/partial/neighbors",
            "/partial/presence",
            "/partial/sensors",
            "/partial/status",
        ]

        for target in targets:
            with _mock_fetch([]):
                partial = await client.get(target)
            assert partial.status_code == 200


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


class TestApiStatus:
    async def test_ok_true_when_data(self, client: AsyncClient) -> None:
        with _mock_fetch({"rank": 128}):
            resp = await client.get("/api/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["data"]["rank"] == 128

    async def test_ok_false_when_unreachable(self, client: AsyncClient) -> None:
        with _mock_fetch(None):
            resp = await client.get("/api/status")
        body = resp.json()
        assert body["ok"] is False
        assert body["data"] is None
