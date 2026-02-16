"""Authentication middleware for Servagent.

Provides a pure ASGI middleware that authenticates requests before they
reach the MCP SDK's own auth stack.  When OAuth is active, the SDK's
``ServagentOAuthProvider.load_access_token()`` also recognises the raw
API_KEY, so Bearer-token requests on ``/mcp`` are validated by the SDK
itself — the outer middleware simply lets them through.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging

from starlette.types import ASGIApp, Receive, Scope, Send

from servagent.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def _extract_bearer(headers: list[tuple[bytes, bytes]]) -> str:
    """Return the Bearer token value from raw ASGI headers, or empty string."""
    for key, value in headers:
        if key.lower() == b"authorization":
            decoded = value.decode("latin-1")
            if decoded.startswith("Bearer "):
                return decoded[7:].strip()
    return ""


def _extract_basic(headers: list[tuple[bytes, bytes]]) -> tuple[str, str] | None:
    """Return (username, password) from HTTP Basic Auth header, or None."""
    for key, value in headers:
        if key.lower() == b"authorization":
            decoded = value.decode("latin-1")
            if decoded.startswith("Basic "):
                try:
                    payload = base64.b64decode(decoded[6:]).decode("utf-8")
                except Exception:
                    return None
                if ":" not in payload:
                    return None
                uid, _, secret = payload.partition(":")
                return uid, secret
    return None


def _is_valid_api_key(token: str) -> bool:
    """Timing-safe comparison of *token* against the configured API key."""
    if not settings.api_key:
        return False
    return hmac.compare_digest(token, settings.api_key)


def _is_valid_basic_auth(headers: list[tuple[bytes, bytes]]) -> bool:
    """Check HTTP Basic Auth against configured OAuth registration credentials."""
    creds = _extract_basic(headers)
    if creds is None:
        return False
    uid, secret = creds
    return (
        hmac.compare_digest(uid, settings.oauth_client_id)
        and hmac.compare_digest(secret, settings.oauth_client_secret)
    )


# ---------------------------------------------------------------------------
# JSON error helpers (raw ASGI — no Starlette dependency at send time)
# ---------------------------------------------------------------------------

async def _send_json_error(
    send: Send,
    *,
    status: int,
    body: dict,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    raw = json.dumps(body).encode()
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(raw)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": raw})


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

class AuthMiddleware:
    """Pure ASGI authentication middleware.

    Handles two auth zones:

    * ``/.well-known/`` — always public (OAuth discovery).
    * ``/mcp/*`` — when OAuth is active, **all** sub-paths (including
      ``/register``, ``/authorize``, ``/token``, ``/revoke``) are
      delegated entirely to the SDK.  The SDK's ``BearerAuthBackend``
      validates tokens via ``ServagentOAuthProvider.load_access_token()``,
      which also recognises a raw ``API_KEY``.  When OAuth is *not*
      active, the middleware validates the Bearer token itself.
    * Everything else (``/sse``, ``/upload``, …) — Bearer ``API_KEY``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])

        # ── .well-known — always public ──
        if "/.well-known/" in path:
            await self.app(scope, receive, send)
            return

        # ── /mcp/* — delegate to SDK when OAuth is active ──
        if path.startswith("/mcp"):
            if settings.oauth_issuer_url:
                # The SDK handles everything inside /mcp when OAuth is on:
                #   /mcp/register  — dynamic client registration (RFC 7591)
                #   /mcp/authorize — authorization code flow
                #   /mcp/token     — token exchange
                #   /mcp/revoke    — token revocation
                #   /mcp/          — MCP JSON-RPC (Bearer token validated via
                #                    ServagentOAuthProvider.load_access_token,
                #                    which accepts both OAuth tokens and API_KEY)
                await self.app(scope, receive, send)
                return

            # No OAuth — fall through to plain API key check below.

        # ── All other routes (SSE, upload, etc.) — Bearer API_KEY ──
        if not settings.api_key:
            await self.app(scope, receive, send)
            return

        token = _extract_bearer(headers)
        if not _is_valid_api_key(token):
            logger.warning("Rejected request: invalid or missing Bearer token for %s", path)
            await _send_json_error(
                send,
                status=401,
                body={"error": "Invalid or missing API key"},
            )
            return

        await self.app(scope, receive, send)
