# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for REST API authentication."""

import pytest
from httpx import ASGITransport, AsyncClient

from lichen.sim.api import SimulatorAPI
from lichen.sim.auth import generate_token


class TestGenerateToken:
    """Tests for token generation."""

    def test_generates_string(self) -> None:
        """generate_token returns a non-empty string."""
        token = generate_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generates_unique_tokens(self) -> None:
        """generate_token returns unique tokens each call."""
        tokens = [generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100


class TestBearerAuthMiddleware:
    """Tests for bearer token authentication middleware."""

    @pytest.fixture
    def token(self) -> str:
        """Generate a test token."""
        return generate_token()

    @pytest.fixture
    def api_with_auth(self, token: str) -> SimulatorAPI:
        """Create a SimulatorAPI with authentication enabled."""
        return SimulatorAPI(api_token=token)

    @pytest.fixture
    def app_with_auth(self, api_with_auth: SimulatorAPI):
        """Create a Starlette app with authentication."""
        return api_with_auth.create_app()

    @pytest.fixture
    async def client_with_auth(self, app_with_auth) -> AsyncClient:
        """Create an async test client for authenticated app."""
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_request_without_token_returns_401(
        self, client_with_auth: AsyncClient
    ) -> None:
        """Requests without Authorization header return 401."""
        response = await client_with_auth.post("/sim", json={"id": "sim1"})

        assert response.status_code == 401
        assert "Unauthorized" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_request_with_invalid_token_returns_401(
        self, client_with_auth: AsyncClient
    ) -> None:
        """Requests with invalid token return 401."""
        response = await client_with_auth.post(
            "/sim",
            json={"id": "sim1"},
            headers={"Authorization": "Bearer wrong-token"},
        )

        assert response.status_code == 401
        assert "Unauthorized" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_request_with_malformed_header_returns_401(
        self, client_with_auth: AsyncClient
    ) -> None:
        """Requests with malformed Authorization header return 401."""
        # Missing "Bearer " prefix
        response = await client_with_auth.post(
            "/sim",
            json={"id": "sim1"},
            headers={"Authorization": "token-without-bearer"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_request_with_valid_token_succeeds(
        self, client_with_auth: AsyncClient, token: str
    ) -> None:
        """Requests with valid token succeed."""
        response = await client_with_auth.post(
            "/sim",
            json={"id": "sim1"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json()["id"] == "sim1"

    @pytest.mark.asyncio
    async def test_all_endpoints_require_auth(
        self, client_with_auth: AsyncClient
    ) -> None:
        """All API endpoints require authentication."""
        # Test various endpoints without auth
        endpoints = [
            ("POST", "/sim", {"id": "sim1"}),
            ("GET", "/sim/sim1", None),
            ("DELETE", "/sim/sim1", None),
            ("POST", "/sim/sim1/tick", {"time_us": 1000}),
            ("POST", "/sim/sim1/node", {"id": "n1"}),
            ("GET", "/sim/sim1/topology", None),
            ("GET", "/sim/sim1/chaos", None),
        ]

        for method, path, body in endpoints:
            if method == "GET":
                response = await client_with_auth.get(path)
            elif method == "POST":
                response = await client_with_auth.post(path, json=body)
            elif method == "DELETE":
                response = await client_with_auth.delete(path)

            assert response.status_code == 401, f"{method} {path} should require auth"


class TestNoAuth:
    """Tests that API works without authentication when token not configured."""

    @pytest.fixture
    def api_no_auth(self) -> SimulatorAPI:
        """Create a SimulatorAPI without authentication."""
        return SimulatorAPI()

    @pytest.fixture
    def app_no_auth(self, api_no_auth: SimulatorAPI):
        """Create a Starlette app without authentication."""
        return api_no_auth.create_app()

    @pytest.fixture
    async def client_no_auth(self, app_no_auth) -> AsyncClient:
        """Create an async test client for unauthenticated app."""
        transport = ASGITransport(app=app_no_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_request_without_token_succeeds(
        self, client_no_auth: AsyncClient
    ) -> None:
        """When auth is disabled, requests without token succeed."""
        response = await client_no_auth.post("/sim", json={"id": "sim1"})

        assert response.status_code == 200
        assert response.json()["id"] == "sim1"
