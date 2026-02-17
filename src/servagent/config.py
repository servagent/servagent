"""Configuration for Servagent server."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings


def _find_dotenv() -> str:
    """Locate the .env file.

    Search order:
      1. /opt/servagent/.env  (production install)
      2. .env next to the package source tree (dev / git clone)
      3. .env in the current working directory (fallback)
    """
    prod = Path("/opt/servagent/.env")
    if prod.is_file():
        return str(prod)

    # Dev path — walk up from this file to the repo root
    here = Path(__file__).resolve().parent  # src/servagent/
    repo_root = here.parent.parent          # project root
    dev = repo_root / ".env"
    if dev.is_file():
        return str(dev)

    # Fallback: cwd
    return ".env"


class Settings(BaseSettings):
    """Server configuration loaded from environment variables or .env file."""

    host: str = "0.0.0.0"
    port: int = 8765
    transport: str = "streamable-http"

    # Public base URL (scheme + host + optional port, no trailing slash, no path).
    # Set automatically by install.sh when a domain is provided.
    # Used to derive the OAuth issuer URL. Example: https://mcp.example.com
    base_url: str = ""

    # API key for authenticating clients. MUST be set in production.
    api_key: str = ""

    # Working directory for command execution (empty = server cwd)
    work_dir: str = ""

    # Command execution timeout in seconds
    command_timeout: int = 300

    # Maximum output size in bytes returned from commands
    max_output_size: int = 1_000_000  # 1 MB

    # Maximum upload file size in bytes (default 100 MB)
    upload_max_size: int = 100_000_000

    # TLS — paths to Let's Encrypt (or other) certificate files.
    # When both are set the server starts in HTTPS mode.
    tls_certfile: str = ""
    tls_keyfile: str = ""

    # OAuth 2.0 — Set issuer URL to enable OAuth for the /mcp endpoint.
    # Must include the /mcp path, e.g. https://myserver.example.com/mcp
    # When set, dynamic client registration, authorization code flow with PKCE,
    # and token revocation are enabled. The simple Bearer token (api_key)
    # continues to work for /sse, /messages/, and /upload endpoints.
    oauth_issuer_url: str = ""

    # OAuth 2.0 — Registration credentials (HTTP Basic Auth).
    # CLIENT_ID and CLIENT_SECRET required to register new OAuth clients
    # via POST /mcp/register.  Both must be set together.
    oauth_client_id: str = ""
    oauth_client_secret: str = ""

    # Path to the SQLite database for OAuth client and token persistence.
    # Default: ~/.servagent/oauth.db
    oauth_db_path: str = ""

    # Tool selection — comma-separated list of tools to expose, or "all".
    # Default exposes the essential tools including file operations.
    # Use "all" to expose every tool (recommended for large models like Claude, GPT-4).
    tools: str = "execute_command,write_file,read_file,edit_file,upload_file"

    # Logging level
    log_level: str = "INFO"

    model_config = {
        "env_prefix": "SERVAGENT_",
        "env_file": _find_dotenv(),
        "env_file_encoding": "utf-8",
    }

    @property
    def working_directory(self) -> Path:
        if self.work_dir:
            return Path(self.work_dir).expanduser().resolve()
        return Path.cwd()

    @property
    def oauth_database_path(self) -> Path:
        if self.oauth_db_path:
            return Path(self.oauth_db_path).expanduser().resolve()
        return Path.home() / ".servagent" / "oauth.db"


class _LazySettings:
    """Proxy that defers ``Settings()`` instantiation until first attribute access.

    This avoids a top-level ``PermissionError`` when the ``.env`` file exists
    but is not readable by the current user (e.g. ``servagent status`` run
    without sudo while ``/opt/servagent/.env`` is root-only).
    """

    _instance: Settings | None = None

    def _get(self) -> Settings:
        if self._instance is None:
            self._instance = Settings()
        return self._instance

    def __getattr__(self, name: str):  # noqa: ANN001
        return getattr(self._get(), name)


settings: Settings = _LazySettings()  # type: ignore[assignment]
