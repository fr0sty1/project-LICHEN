# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Authentication middleware for the LICHEN simulator REST API.

This module provides bearer token authentication for the simulator API.
Authentication is optional but strongly recommended when binding to
non-localhost addresses.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp


def generate_token() -> str:
    """Generate a cryptographically secure API token.

    Returns:
        A 32-character URL-safe token.
    """
    return secrets.token_urlsafe(24)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that requires a valid Bearer token for all requests.

    Validates the Authorization header against a configured token.
    WebSocket connections must pass the token as a query parameter
    since browsers cannot set custom headers on WebSocket requests.

    Usage:
        token = generate_token()
        app.add_middleware(BearerAuthMiddleware, token=token)

    Clients must include:
        - HTTP: Authorization: Bearer <token>
        - WebSocket: ?token=<token> query parameter
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application to wrap.
            token: The bearer token to validate against.
        """
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        """Validate the bearer token before passing to the handler.

        Args:
            request: The incoming request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response from the handler, or a 401 error if unauthorized.
        """
        # WebSocket connections use query parameter
        if request.scope.get("type") == "websocket":
            token = request.query_params.get("token")
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
