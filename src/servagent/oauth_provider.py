"""OAuth 2.0 Authorization Server provider backed by SQLite.

Implements the MCP SDK's OAuthAuthorizationServerProvider protocol with
persistent storage for clients, authorization codes, and tokens.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import time
from pathlib import Path

import aiosqlite

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

# Token lifetimes
ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 86400 * 30  # 30 days
AUTHORIZATION_CODE_TTL = 300  # 5 minutes

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS clients (
    client_id        TEXT PRIMARY KEY,
    client_secret    TEXT,
    client_id_issued_at       INTEGER,
    client_secret_expires_at  INTEGER,
    redirect_uris    TEXT NOT NULL,
    token_endpoint_auth_method TEXT,
    grant_types      TEXT NOT NULL,
    response_types   TEXT NOT NULL,
    scope            TEXT,
    client_name      TEXT,
    client_uri       TEXT,
    logo_uri         TEXT,
    contacts         TEXT,
    tos_uri          TEXT,
    policy_uri       TEXT,
    jwks_uri         TEXT,
    jwks             TEXT,
    software_id      TEXT,
    software_version TEXT
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code             TEXT PRIMARY KEY,
    client_id        TEXT NOT NULL,
    scopes           TEXT NOT NULL,
    expires_at       REAL NOT NULL,
    code_challenge   TEXT NOT NULL,
    redirect_uri     TEXT NOT NULL,
    redirect_uri_provided_explicitly  INTEGER NOT NULL,
    resource         TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token       TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    expires_at  INTEGER,
    resource    TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token       TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    expires_at  INTEGER,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);
"""


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

class OAuthSQLiteStore:
    """Async SQLite store for OAuth clients, codes, and tokens."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.info("OAuth SQLite store initialised: %s", self._db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "Store not initialised — call initialize() first"
        return self._db

    # -- clients --

    async def save_client(self, c: OAuthClientInformationFull) -> None:
        await self.db.execute(
            """INSERT OR REPLACE INTO clients
               (client_id, client_secret, client_id_issued_at,
                client_secret_expires_at, redirect_uris,
                token_endpoint_auth_method, grant_types, response_types,
                scope, client_name, client_uri, logo_uri, contacts,
                tos_uri, policy_uri, jwks_uri, jwks, software_id,
                software_version)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                c.client_id,
                c.client_secret,
                c.client_id_issued_at,
                c.client_secret_expires_at,
                json.dumps([str(u) for u in c.redirect_uris]),
                c.token_endpoint_auth_method,
                json.dumps(c.grant_types),
                json.dumps(c.response_types),
                c.scope,
                c.client_name,
                str(c.client_uri) if c.client_uri else None,
                str(c.logo_uri) if c.logo_uri else None,
                json.dumps(c.contacts) if c.contacts else None,
                str(c.tos_uri) if c.tos_uri else None,
                str(c.policy_uri) if c.policy_uri else None,
                str(c.jwks_uri) if c.jwks_uri else None,
                json.dumps(c.jwks) if c.jwks else None,
                c.software_id,
                c.software_version,
            ),
        )
        await self.db.commit()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        async with self.db.execute(
            "SELECT * FROM clients WHERE client_id = ?", (client_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull(
            client_id=row["client_id"],
            client_secret=row["client_secret"],
            client_id_issued_at=row["client_id_issued_at"],
            client_secret_expires_at=row["client_secret_expires_at"],
            redirect_uris=json.loads(row["redirect_uris"]),
            token_endpoint_auth_method=row["token_endpoint_auth_method"],
            grant_types=json.loads(row["grant_types"]),
            response_types=json.loads(row["response_types"]),
            scope=row["scope"],
            client_name=row["client_name"],
            client_uri=row["client_uri"],
            logo_uri=row["logo_uri"],
            contacts=json.loads(row["contacts"]) if row["contacts"] else None,
            tos_uri=row["tos_uri"],
            policy_uri=row["policy_uri"],
            jwks_uri=row["jwks_uri"],
            jwks=json.loads(row["jwks"]) if row["jwks"] else None,
            software_id=row["software_id"],
            software_version=row["software_version"],
        )

    # -- static client (pre-registered at startup) --

    # Well-known redirect URIs for major MCP-compatible platforms.
    # Add new entries here when additional platforms adopt MCP + OAuth.
    KNOWN_REDIRECT_URIS: list[str] = [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
    ]

    async def ensure_static_client(
        self,
        client_id: str,
        client_secret: str,
        extra_redirect_uris: list[str] | None = None,
    ) -> None:
        """Insert or update a statically-configured OAuth client.

        This allows the operator to set a CLIENT_ID + CLIENT_SECRET in the
        server configuration.  The client is upserted at startup so that
        MCP clients (like Claude.ai, ChatGPT, etc.) can use these
        credentials directly in the OAuth flow without going through
        dynamic registration first.

        The ``redirect_uris`` list includes all known MCP platform
        callbacks (see ``KNOWN_REDIRECT_URIS``).  Pass
        *extra_redirect_uris* to append additional URIs (e.g. for
        a custom client).
        """
        redirect_uris = list(self.KNOWN_REDIRECT_URIS)
        if extra_redirect_uris:
            redirect_uris.extend(extra_redirect_uris)

        now = int(time.time())
        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=now,
            client_secret_expires_at=0,  # never expires
            redirect_uris=redirect_uris,
            token_endpoint_auth_method="client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="admin",
            client_name="static-operator-client",
        )
        await self.save_client(client_info)
        logger.info("Static OAuth client upserted: %s (redirect_uris=%d)", client_id, len(redirect_uris))

    # -- authorization codes --

    async def save_authorization_code(self, ac: AuthorizationCode) -> None:
        await self.db.execute(
            """INSERT INTO authorization_codes
               (code, client_id, scopes, expires_at, code_challenge,
                redirect_uri, redirect_uri_provided_explicitly, resource)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                ac.code,
                ac.client_id,
                json.dumps(ac.scopes),
                ac.expires_at,
                ac.code_challenge,
                str(ac.redirect_uri),
                int(ac.redirect_uri_provided_explicitly),
                ac.resource,
            ),
        )
        await self.db.commit()

    async def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        async with self.db.execute(
            "SELECT * FROM authorization_codes WHERE code = ?", (code,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return AuthorizationCode(
            code=row["code"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            resource=row["resource"],
        )

    async def delete_authorization_code(self, code: str) -> None:
        await self.db.execute("DELETE FROM authorization_codes WHERE code = ?", (code,))
        await self.db.commit()

    # -- access tokens --

    async def save_access_token(self, at: AccessToken) -> None:
        await self.db.execute(
            """INSERT INTO access_tokens (token, client_id, scopes, expires_at, resource)
               VALUES (?,?,?,?,?)""",
            (at.token, at.client_id, json.dumps(at.scopes), at.expires_at, at.resource),
        )
        await self.db.commit()

    async def get_access_token(self, token: str) -> AccessToken | None:
        async with self.db.execute(
            "SELECT * FROM access_tokens WHERE token = ?", (token,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return AccessToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
        )

    async def delete_access_token(self, token: str) -> None:
        await self.db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
        await self.db.commit()

    # -- refresh tokens --

    async def save_refresh_token(self, rt: RefreshToken) -> None:
        await self.db.execute(
            """INSERT INTO refresh_tokens (token, client_id, scopes, expires_at)
               VALUES (?,?,?,?)""",
            (rt.token, rt.client_id, json.dumps(rt.scopes), rt.expires_at),
        )
        await self.db.commit()

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        async with self.db.execute(
            "SELECT * FROM refresh_tokens WHERE token = ?", (token,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
        )

    async def delete_refresh_token(self, token: str) -> None:
        await self.db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        await self.db.commit()

    async def delete_tokens_for_client(self, client_id: str) -> None:
        await self.db.execute("DELETE FROM access_tokens WHERE client_id = ?", (client_id,))
        await self.db.execute("DELETE FROM refresh_tokens WHERE client_id = ?", (client_id,))
        await self.db.commit()


# ---------------------------------------------------------------------------
# OAuth Authorization Server Provider
# ---------------------------------------------------------------------------

class ServagentOAuthProvider:
    """OAuthAuthorizationServerProvider backed by SQLite.

    Uses an auto-approve model: any registered client is trusted.
    This is appropriate for a single-operator server administration tool
    protected by network-level security and/or TLS.
    """

    def __init__(self, store: OAuthSQLiteStore) -> None:
        self.store = store

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await self.store.save_client(client_info)
        logger.info("OAuth client registered: %s (%s)", client_info.client_id, client_info.client_name)

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        # Auto-approve: generate an authorization code immediately and redirect.
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            scopes=params.scopes or [],
            expires_at=time.time() + AUTHORIZATION_CODE_TTL,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        await self.store.save_authorization_code(auth_code)
        logger.info("OAuth authorization code issued for client %s", client.client_id)
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code,
            state=params.state,
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        ac = await self.store.get_authorization_code(authorization_code)
        if ac is None:
            return None
        if time.time() > ac.expires_at:
            await self.store.delete_authorization_code(authorization_code)
            return None
        return ac

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        # Single-use: delete the code
        await self.store.delete_authorization_code(authorization_code.code)

        now = int(time.time())
        access_token = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + ACCESS_TOKEN_TTL,
            resource=authorization_code.resource,
        )
        refresh_token = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + REFRESH_TOKEN_TTL,
        )
        await self.store.save_access_token(access_token)
        await self.store.save_refresh_token(refresh_token)

        logger.info("OAuth tokens issued for client %s", client.client_id)
        return OAuthToken(
            access_token=access_token.token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
            refresh_token=refresh_token.token,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        rt = await self.store.get_refresh_token(refresh_token)
        if rt is None:
            return None
        if rt.expires_at is not None and time.time() > rt.expires_at:
            await self.store.delete_refresh_token(refresh_token)
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotate: delete the old refresh token
        await self.store.delete_refresh_token(refresh_token.token)

        now = int(time.time())
        new_scopes = scopes if scopes else refresh_token.scopes

        access_token = AccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=new_scopes,
            expires_at=now + ACCESS_TOKEN_TTL,
        )
        new_refresh_token = RefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=new_scopes,
            expires_at=now + REFRESH_TOKEN_TTL,
        )
        await self.store.save_access_token(access_token)
        await self.store.save_refresh_token(new_refresh_token)

        logger.info("OAuth tokens refreshed for client %s", client.client_id)
        return OAuthToken(
            access_token=access_token.token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(new_scopes) if new_scopes else None,
            refresh_token=new_refresh_token.token,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Fast-path: accept a raw API_KEY as a valid access token.
        # This lets clients authenticate with a simple Bearer header
        # even when OAuth is active, without going through the OAuth flow.
        from servagent.config import settings

        if settings.api_key and hmac.compare_digest(token, settings.api_key):
            return AccessToken(
                token=token,
                client_id="api-key-client",
                scopes=["admin"],
                expires_at=int(time.time()) + 86400,
            )

        at = await self.store.get_access_token(token)
        if at is None:
            return None
        if at.expires_at is not None and time.time() > at.expires_at:
            await self.store.delete_access_token(token)
            return None
        return at

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        # Revoke all tokens for the client (both access and refresh)
        # as recommended by the spec.
        client_id = token.client_id
        await self.store.delete_tokens_for_client(client_id)
        logger.info("OAuth tokens revoked for client %s", client_id)
