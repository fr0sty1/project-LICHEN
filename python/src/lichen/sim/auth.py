# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Authentication middleware for the LICHEN simulator REST API.

This module provides bearer token authentication for the simulator API.
Authentication is optional but strongly recommended when binding to
non-localhost addresses.

SECURITY: WebSocket authentication uses the ``Sec-WebSocket-Protocol`` header
to pass the token. This keeps the token out of URLs, which would otherwise
appear in server access logs, proxy logs, and browser history. The client
sends ``Sec-WebSocket-Protocol: bearer, <token>`` and the server echoes back
``Sec-WebSocket-Protocol: bearer`` to complete the handshake.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

# SECURITY: Prefix for bearer token in WebSocket subprotocol header.
# Format: "bearer.<token>" in Sec-WebSocket-Protocol header
WEBSOCKET_AUTH_SUBPROTOCOL = "bearer"


# SECURITY: Minimum token length to prevent brute-force attacks.
# 16 characters of URL-safe base64 provides ~96 bits of entropy,
# which is well above the 80-bit minimum for short-term secrets.
MIN_TOKEN_LENGTH = 16


class WeakTokenError(ValueError):
    """Raised when a user-provided token does not meet minimum strength requirements."""

    pass


def validate_token_strength(token: str) -> None:
    """Validate that a token meets minimum strength requirements.

    Args:
        token: The token to validate.

    Raises:
        WeakTokenError: If the token is too short or otherwise weak.
    """
    if len(token) < MIN_TOKEN_LENGTH:
        raise WeakTokenError(
            f"API token must be at least {MIN_TOKEN_LENGTH} characters. "
            f"Provided token has {len(token)} characters. "
            "Use '--api-token generate' for a secure token."
        )


def generate_token() -> str:
    """Generate a cryptographically secure API token.

    Returns:
        A 32-character URL-safe token.
    """
    return secrets.token_urlsafe(24)


def extract_websocket_token(subprotocols: list[str]) -> str | None:
    """Extract bearer token from WebSocket subprotocols.

    The token is passed as a subprotocol in the format "bearer.<token>".
    This keeps the token out of the URL query string, avoiding exposure
    in server logs and browser history.

    Args:
        subprotocols: List of requested subprotocols from the client.

    Returns:
        The extracted token, or None if no valid bearer token found.
    """
    for proto in subprotocols:
        if proto.startswith(f"{WEBSOCKET_AUTH_SUBPROTOCOL}."):
            return proto[len(WEBSOCKET_AUTH_SUBPROTOCOL) + 1 :]
    return None


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that requires a valid Bearer token for all requests.

    Validates the Authorization header against a configured token.

    WebSocket connections pass the token via the ``Sec-WebSocket-Protocol``
    header as ``bearer.<token>``. This avoids exposing the token in URLs,
    which would appear in server logs and browser history.

    Usage:
        token = generate_token()
        app.add_middleware(BearerAuthMiddleware, token=token)

    Clients must include:
        - HTTP: Authorization: Bearer <token>
        - WebSocket: Sec-WebSocket-Protocol: bearer.<token>
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application to wrap.
            token: The bearer token to validate against.
        """
        super().__init__(app)
        self._token = token

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Validate the bearer token before passing to the handler.

        Args:
            request: The incoming request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response from the handler, or a 401 error if unauthorized.
        """
        # SECURITY: WebSocket connections use subprotocol header to avoid
        # exposing the token in URLs (which appear in logs/history).
        if request.scope.get("type") == "websocket":
            subprotocols = request.scope.get("subprotocols", [])
            token = extract_websocket_token(subprotocols)
        else:
            # HTTP requests use Authorization header
            auth_header = request.headers.get("Authorization", "")
            token = auth_header[7:] if auth_header.startswith("Bearer ") else None

        # SECURITY: Use constant-time comparison to prevent timing attacks
        if token is None or not secrets.compare_digest(token, self._token):
            return JSONResponse(
                {"error": "Unauthorized. Provide 'Authorization: Bearer <token>' header."},
                status_code=401,
            )

        return await call_next(request)
