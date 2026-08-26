# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for REST API authentication."""

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette

from lichen.sim.api import SimulatorAPI
from lichen.sim.auth import (
    MIN_TOKEN_LENGTH,
    WEBSOCKET_AUTH_SUBPROTOCOL,
    BearerAuthMiddleware,
    WeakTokenError,
    extract_websocket_token,
    generate_token,
    validate_token_strength,
)
from lichen.sim.simulation import Simulation


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


class TestTokenValidation:
    """Tests for token strength validation."""

    def test_accepts_generated_token(self) -> None:
        """validate_token_strength accepts generated tokens."""
        token = generate_token()
        # Should not raise
        validate_token_strength(token)

    def test_accepts_token_at_minimum_length(self) -> None:
        """validate_token_strength accepts token at exactly minimum length."""
        token = "a" * MIN_TOKEN_LENGTH
        # Should not raise
        validate_token_strength(token)

    def test_rejects_short_token(self) -> None:
        """validate_token_strength rejects tokens shorter than minimum."""
        token = "a" * (MIN_TOKEN_LENGTH - 1)
        with pytest.raises(WeakTokenError) as exc_info:
            validate_token_strength(token)
        assert str(MIN_TOKEN_LENGTH) in str(exc_info.value)
        assert "generate" in str(exc_info.value).lower()

    def test_rejects_very_short_token(self) -> None:
        """validate_token_strength rejects obviously weak tokens."""
        with pytest.raises(WeakTokenError):
            validate_token_strength("password")

    def test_rejects_empty_token(self) -> None:
        """validate_token_strength rejects empty string."""
        with pytest.raises(WeakTokenError):
            validate_token_strength("")

    def test_error_message_includes_helpful_hint(self) -> None:
        """WeakTokenError message includes suggestion to use generate."""
        with pytest.raises(WeakTokenError) as exc_info:
            validate_token_strength("weak")
        assert "generate" in str(exc_info.value).lower()


class TestBearerAuthMiddleware:
    """Tests for bearer token authentication middleware."""

    def test_rejects_empty_token_at_init(self) -> None:
        """BearerAuthMiddleware raises WeakTokenError for empty token."""
        from starlette.applications import Starlette

        app = Starlette()
        with pytest.raises(WeakTokenError):
            BearerAuthMiddleware(app, "")

    def test_rejects_short_token_at_init(self) -> None:
        """BearerAuthMiddleware raises WeakTokenError for short token."""
        from starlette.applications import Starlette

        app = Starlette()
        with pytest.raises(WeakTokenError):
            BearerAuthMiddleware(app, "short")

    @pytest.fixture
    def token(self) -> str:
        """Generate a test token."""
        return generate_token()

    @pytest.fixture
    def api_with_auth(self, token: str) -> SimulatorAPI:
        """Create a SimulatorAPI with authentication enabled."""
        return SimulatorAPI(api_token=token)

    @pytest.fixture
    def app_with_auth(self, api_with_auth: SimulatorAPI) -> Starlette:
        """Create a Starlette app with authentication."""
        return api_with_auth.create_app()

    @pytest.fixture
    async def client_with_auth(self, app_with_auth: Starlette) -> AsyncGenerator[AsyncClient, None]:
        """Create an async test client for authenticated app."""
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_request_without_token_returns_401(self, client_with_auth: AsyncClient) -> None:
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
    async def test_all_endpoints_require_auth(self, client_with_auth: AsyncClient) -> None:
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
    def app_no_auth(self, api_no_auth: SimulatorAPI) -> Starlette:
        """Create a Starlette app without authentication."""
        return api_no_auth.create_app()

    @pytest.fixture
    async def client_no_auth(self, app_no_auth: Starlette) -> AsyncGenerator[AsyncClient, None]:
        """Create an async test client for unauthenticated app."""
        transport = ASGITransport(app=app_no_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_request_without_token_succeeds(self, client_no_auth: AsyncClient) -> None:
        """When auth is disabled, requests without token succeed."""
        response = await client_no_auth.post("/sim", json={"id": "sim1"})

        assert response.status_code == 200
        assert response.json()["id"] == "sim1"


class TestConstantTimeComparison:
    """Tests verifying constant-time behavior of token validation.

    The middleware must always call secrets.compare_digest() regardless of
    whether a token was provided, to prevent timing attacks that could reveal
    whether authentication was attempted.
    """

    @pytest.fixture
    def token(self) -> str:
        """Generate a test token."""
        return generate_token()

    @pytest.fixture
    def api_with_auth(self, token: str) -> SimulatorAPI:
        """Create a SimulatorAPI with authentication enabled."""
        return SimulatorAPI(api_token=token)

    @pytest.fixture
    def app_with_auth(self, api_with_auth: SimulatorAPI) -> Starlette:
        """Create a Starlette app with authentication."""
        return api_with_auth.create_app()

    @pytest.fixture
    async def client_with_auth(self, app_with_auth: Starlette) -> AsyncGenerator[AsyncClient, None]:
        """Create an async test client for authenticated app."""
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_no_token_and_wrong_token_both_return_401(
        self, client_with_auth: AsyncClient
    ) -> None:
        """Both missing and invalid tokens return 401.

        This documents that both code paths result in the same behavior,
        supporting constant-time validation where compare_digest is always
        called (with empty string when no token is provided).
        """
        # No token at all
        response_no_token = await client_with_auth.post("/sim", json={"id": "sim1"})
        assert response_no_token.status_code == 401

        # Wrong token
        response_wrong = await client_with_auth.post(
            "/sim",
            json={"id": "sim1"},
            headers={"Authorization": "Bearer wrong-token-value"},
        )
        assert response_wrong.status_code == 401

        # Both should have the same error structure
        assert response_no_token.json() == response_wrong.json()


class TestWebSocketTokenExtraction:
    """Tests for WebSocket subprotocol token extraction."""

    def test_extracts_token_from_bearer_subprotocol(self) -> None:
        """Extracts token from bearer.<token> subprotocol."""
        token = extract_websocket_token([f"{WEBSOCKET_AUTH_SUBPROTOCOL}.my-secret-token"])
        assert token == "my-secret-token"

    def test_returns_none_when_no_bearer_subprotocol(self) -> None:
        """Returns None when no bearer subprotocol present."""
        token = extract_websocket_token(["graphql-ws", "json"])
        assert token is None

    def test_returns_none_for_empty_list(self) -> None:
        """Returns None for empty subprotocol list."""
        token = extract_websocket_token([])
        assert token is None

    def test_ignores_non_bearer_subprotocols(self) -> None:
        """Ignores subprotocols that don't match bearer format."""
        token = extract_websocket_token(
            ["graphql-ws", f"{WEBSOCKET_AUTH_SUBPROTOCOL}.secret", "json"]
        )
        assert token == "secret"

    def test_handles_bearer_prefix_only(self) -> None:
        """Handles edge case of just 'bearer' without dot."""
        token = extract_websocket_token([WEBSOCKET_AUTH_SUBPROTOCOL])
        assert token is None

    def test_extracts_empty_token_after_dot(self) -> None:
        """Extracts empty string if token is empty after dot."""
        token = extract_websocket_token([f"{WEBSOCKET_AUTH_SUBPROTOCOL}."])
        assert token == ""


class TestWebSocketAuthentication:
    """Tests that configured API credentials also protect WebSockets."""

    @staticmethod
    def _websocket(subprotocols: list[str]) -> AsyncMock:
        websocket = AsyncMock()
        websocket.path_params = {"sim_id": "sim1"}
        websocket.scope = {"subprotocols": subprotocols}
        return websocket

    @pytest.mark.asyncio
    async def test_missing_token_is_rejected_before_simulation_lookup(self) -> None:
        """An authenticated API rejects missing WebSocket credentials."""
        api = SimulatorAPI(api_token=generate_token())
        websocket = self._websocket([])

        with patch("lichen.sim.api.handle_websocket", new_callable=AsyncMock) as handler:
            await api.websocket_endpoint(websocket)

        websocket.close.assert_awaited_once_with(code=4401, reason="Unauthorized")
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_wrong_token_is_rejected(self) -> None:
        """An authenticated API rejects an incorrect WebSocket token."""
        api = SimulatorAPI(api_token=generate_token())
        websocket = self._websocket([f"{WEBSOCKET_AUTH_SUBPROTOCOL}.wrong-token"])

        with patch("lichen.sim.api.handle_websocket", new_callable=AsyncMock) as handler:
            await api.websocket_endpoint(websocket)

        websocket.close.assert_awaited_once_with(code=4401, reason="Unauthorized")
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_valid_token_reaches_websocket_handler(self) -> None:
        """A matching WebSocket bearer token authorizes the connection."""
        token = generate_token()
        api = SimulatorAPI(api_token=token)
        api._simulations["sim1"] = Simulation(sim_id="sim1")
        websocket = self._websocket([f"{WEBSOCKET_AUTH_SUBPROTOCOL}.{token}"])

        with patch("lichen.sim.api.handle_websocket", new_callable=AsyncMock) as handler:
            await api.websocket_endpoint(websocket)

        websocket.close.assert_not_awaited()
        handler.assert_awaited_once_with(websocket, api._ws_manager, "sim1")

    @pytest.mark.asyncio
    async def test_unconfigured_api_preserves_unauthenticated_websocket(self) -> None:
        """Loopback-compatible no-auth API behavior remains available."""
        api = SimulatorAPI()
        api._simulations["sim1"] = Simulation(sim_id="sim1")
        websocket = self._websocket([])

        with patch("lichen.sim.api.handle_websocket", new_callable=AsyncMock) as handler:
            await api.websocket_endpoint(websocket)

        websocket.close.assert_not_awaited()
        handler.assert_awaited_once_with(websocket, api._ws_manager, "sim1")
