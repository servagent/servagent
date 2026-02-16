"""Configuration for Servagent server."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Server configuration loaded from environment variables or .env file."""

    host: str = "0.0.0.0"
    port: int = 8765
    transport: str = "streamable-http"

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
    # Default exposes only the essential tools to save context window for small LLMs.
    # Use "all" to expose every tool (recommended for large models like Claude, GPT-4).
    tools: str = "execute_command,upload_file"

    # Logging level
    log_level: str = "INFO"

    model_config = {
        "env_prefix": "SERVAGENT_",
        "env_file": ".env",
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


settings = Settings()
