# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN web status dashboard."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from lichen.dashboard.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------


class TestIndex:
    def test_index_returns_200(self, client: TestClient) -> None:
        resp = client.get("/")
        assert resp.status_code == 200

    def test_index_is_html(self, client: TestClient) -> None:
        resp = client.get("/")
        assert "text/html" in resp.headers["content-type"]

    def test_index_contains_htmx(self, client: TestClient) -> None:
        resp = client.get("/")
        assert "htmx.org" in resp.text

    def test_index_contains_partials(self, client: TestClient) -> None:
        resp = client.get("/")
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
    def test_status_dict_renders_table(self, client: TestClient) -> None:
        with _mock_fetch({"rank": 256, "role": "router"}):
            resp = client.get("/partial/status")
        assert resp.status_code == 200
        assert "rank" in resp.text
        assert "256" in resp.text

    def test_status_unreachable_shows_error(self, client: TestClient) -> None:
        with _mock_fetch(None):
            resp = client.get("/partial/status")
        assert resp.status_code == 200
        assert "Unreachable" in resp.text


class TestPartialNeighbors:
    def test_empty_list_shows_message(self, client: TestClient) -> None:
        with _mock_fetch([]):
            resp = client.get("/partial/neighbors")
        assert "No neighbors" in resp.text

    def test_list_with_entry_renders_items(self, client: TestClient) -> None:
        with _mock_fetch([{"eui64": "00:11:22:33:44:55:66:77", "rssi": -80}]):
            resp = client.get("/partial/neighbors")
        assert "eui64" in resp.text

    def test_unreachable(self, client: TestClient) -> None:
        with _mock_fetch(None):
            resp = client.get("/partial/neighbors")
        assert "Unreachable" in resp.text


class TestPartialPresence:
    def test_empty(self, client: TestClient) -> None:
        with _mock_fetch([]):
            resp = client.get("/partial/presence")
        assert "No peers" in resp.text

    def test_with_peers(self, client: TestClient) -> None:
        with _mock_fetch([{"ep": "node-01", "lt": 3600}]):
            resp = client.get("/partial/presence")
        assert "node-01" in resp.text


class TestPartialMessages:
    def test_empty_inbox(self, client: TestClient) -> None:
        with _mock_fetch([]):
            resp = client.get("/partial/messages")
        assert "Inbox empty" in resp.text

    def test_with_message(self, client: TestClient) -> None:
        with _mock_fetch([{"from": "alice", "text": "hello mesh"}]):
            resp = client.get("/partial/messages")
        assert "hello mesh" in resp.text


class TestPartialSensors:
    def test_empty(self, client: TestClient) -> None:
        with _mock_fetch([]):
            resp = client.get("/partial/sensors")
        assert "No data" in resp.text

    def test_list_format_senml(self, client: TestClient) -> None:
        # SenML as list-of-lists [name, value, unit]
        with _mock_fetch([["temperature", 23.4, "Cel"], ["humidity", 61.0, "%RH"]]):
            resp = client.get("/partial/sensors")
        assert "temperature" in resp.text
        assert "23.4" in resp.text

    def test_dict_format_senml(self, client: TestClient) -> None:
        # SenML as list-of-maps {n, v, u}
        with _mock_fetch([{"n": "temp", "v": 22.5, "u": "Cel"}]):
            resp = client.get("/partial/sensors")
        assert "temp" in resp.text

    def test_unreachable(self, client: TestClient) -> None:
        with _mock_fetch(None):
            resp = client.get("/partial/sensors")
        assert "Unreachable" in resp.text


class TestPartialLocation:
    def test_location_renders(self, client: TestClient) -> None:
        with _mock_fetch([["lat", 37.7749], ["lon", -122.4194]]):
            resp = client.get("/partial/location")
        assert "lat" in resp.text
        assert "37.7749" in resp.text

    def test_unreachable(self, client: TestClient) -> None:
        with _mock_fetch(None):
            resp = client.get("/partial/location")
        assert "Unreachable" in resp.text


# ---------------------------------------------------------------------------
# Index — new cards present
# ---------------------------------------------------------------------------


class TestIndexCards:
    def test_sensors_card_in_page(self, client: TestClient) -> None:
        resp = client.get("/")
        assert "/partial/sensors" in resp.text

    def test_location_card_in_page(self, client: TestClient) -> None:
        resp = client.get("/")
        assert "/partial/location" in resp.text


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


class TestApiStatus:
    def test_ok_true_when_data(self, client: TestClient) -> None:
        with _mock_fetch({"rank": 128}):
            resp = client.get("/api/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["data"]["rank"] == 128

    def test_ok_false_when_unreachable(self, client: TestClient) -> None:
        with _mock_fetch(None):
            resp = client.get("/api/status")
        body = resp.json()
        assert body["ok"] is False
        assert body["data"] is None
