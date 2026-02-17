"""Servagent - Main server entry point."""

from __future__ import annotations

import contextlib
import getpass
import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from mcp.server.transport_security import TransportSecuritySettings

from servagent.auth import AuthMiddleware
from servagent.config import settings
from servagent.tools import ALL_TOOL_NAMES, register_tools

if TYPE_CHECKING:
    from servagent.oauth_provider import OAuthSQLiteStore, ServagentOAuthProvider

logger = logging.getLogger("servagent")


# ------------------------------------------------------------------
# Server context collection (runs once at startup)
# ------------------------------------------------------------------

def _run_quiet(cmd: str) -> str:
    """Run a shell command, return stdout stripped. Empty string on failure."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _detect_distro() -> str:
    """Return distro name + version from /etc/os-release, or platform fallback."""
    try:
        lines = Path("/etc/os-release").read_text().splitlines()
        info = {}
        for line in lines:
            if "=" in line:
                k, _, v = line.partition("=")
                info[k] = v.strip('"')
        name = info.get("PRETTY_NAME", "")
        if name:
            return name
    except Exception:
        pass
    return platform.platform()


def _detect_package_manager() -> str:
    """Detect the system package manager."""
    for mgr in ("apt", "dnf", "yum", "apk", "pacman", "zypper", "brew"):
        if _run_quiet(f"command -v {mgr}"):
            return mgr
    return "unknown"


def _detect_init_system() -> str:
    """Detect init system (systemd, openrc, etc.)."""
    if Path("/run/systemd/system").is_dir():
        return "systemd"
    if _run_quiet("command -v rc-service"):
        return "openrc"
    if Path("/sbin/init").exists():
        return "sysvinit"
    return "unknown"


def _detect_shell() -> str:
    """Return the default shell."""
    return os.environ.get("SHELL", _run_quiet("getent passwd $(whoami) | cut -d: -f7") or "unknown")


def _detect_sudo() -> str:
    """Check if sudo is available and passwordless."""
    if os.getuid() == 0:
        return "root"
    r = _run_quiet("sudo -n true 2>&1 && echo ok")
    if "ok" in r:
        return "passwordless"
    if _run_quiet("command -v sudo"):
        return "available (password required)"
    return "not available"


def _detect_ips() -> str:
    """Return a comma-separated list of non-loopback IPs."""
    # Try ip command first (Linux), then ifconfig fallback (macOS)
    raw = _run_quiet("ip -brief addr 2>/dev/null | awk '{print $3}' | cut -d/ -f1")
    if not raw:
        raw = _run_quiet("ifconfig 2>/dev/null | grep 'inet ' | awk '{print $2}'")
    if not raw:
        raw = _run_quiet("hostname -I 2>/dev/null")
    ips = [
        ip.strip() for ip in raw.split("\n")
        if ip.strip() and ip.strip() != "127.0.0.1" and ip.strip() != "::1"
    ]
    return ", ".join(ips) if ips else "unknown"


def _collect_server_context() -> str:
    """Collect system information and return a compact context block.

    Runs synchronously at startup (once). Each detection is fault-tolerant:
    if a command fails, the field shows "unknown".
    """
    distro = _detect_distro()
    kernel = platform.release()
    arch = platform.machine()
    hostname = platform.node()
    ips = _detect_ips()
    user = getpass.getuser()
    uid = os.getuid()
    sudo = _detect_sudo()
    shell = _detect_shell()
    pkg = _detect_package_manager()
    init = _detect_init_system()
    py = platform.python_version()
    cwd = str(settings.working_directory)

    lines = [
        "## Remote server",
        f"- OS: {distro} — {kernel} — {arch}",
        f"- Hostname: {hostname}",
        f"- IPs: {ips}",
        f"- User: {user} (uid={uid}, sudo: {sudo})",
        f"- Shell: {shell}",
        f"- Package manager: {pkg}",
        f"- Init: {init}",
        f"- Python: {py}",
        f"- Working directory: {cwd}",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------
# Skills collection (optional, from SKILL.md files)
# ------------------------------------------------------------------

def _collect_skills() -> str:
    """Scan the ``skills/`` directory and return assembled skill blocks.

    The skills directory lives at the root of the working directory
    (project root in dev, ``/opt/servagent/`` in production).
    Each subdirectory that contains a ``SKILL.md`` file has its content
    included.  If the file starts with a markdown heading (``#``), it is
    used as-is; otherwise a ``### dirname`` heading is prepended
    automatically.

    Returns an empty string when the directory is empty or missing.
    """
    skills_path = settings.working_directory / "skills"
    if not skills_path.is_dir():
        return ""

    sections: list[str] = []
    for entry in sorted(skills_path.iterdir()):
        if not entry.is_dir():
            continue
        skill_file = entry / "SKILL.md"
        if not skill_file.is_file():
            continue
        content = skill_file.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            continue
        # Use the file's own heading if present, otherwise add one
        if content.startswith("#"):
            sections.append(content)
        else:
            sections.append(f"### {entry.name}\n{content}")
        logger.info("Loaded skill: %s", entry.name)

    if not sections:
        return ""
    return "## Skills\n\n" + "\n\n".join(sections)


# ------------------------------------------------------------------
# Instructions (static rules — kept minimal)
# ------------------------------------------------------------------

_SERVER_RULES = """\
## Rules
- Every tool runs on the **remote server**, not on the client machine.
- `execute_command` returns exit_code, stdout, stderr. exit_code 0 = success. \
Read stderr on failure. If timed_out is true, the command was killed.
- Do not retry permission errors (exit_code 126/127) — they require user intervention.
- Destructive commands (rm, mkfs, dd, shutdown, reboot) — confirm with the user first.
- Large outputs are truncated.

## File writing best practices
- **ALWAYS use `write_file` to create or overwrite files** — it is faster, more \
reliable, and avoids shell escaping issues. NEVER use `execute_command` with \
heredocs (`cat <<EOF`), `echo`, or `printf` to write file content.
- **Use `edit_file` for targeted modifications** to existing files instead of \
rewriting them entirely.
- `execute_command` is for **running programs** (install packages, restart services, \
git, docker, etc.), not for writing file content.

## Multi-file projects (websites, configs, apps)
When building a project with multiple files (e.g. a website, an application):
1. **Create the directory structure first** with `execute_command` (`mkdir -p`).
2. **Write each file individually** with `write_file` — one file per tool call.
3. **Install dependencies / set permissions** with `execute_command`.
4. **Verify** the result (e.g. check syntax, restart service, test URL).
Keep each file focused and under 500 lines. Split large files when possible \
(e.g. separate CSS/JS from HTML)."""


def _build_instructions() -> str:
    """Build the full server instructions string (context + skills + rules)."""
    context = _collect_server_context()
    skills = _collect_skills()
    parts = [context]
    if skills:
        parts.append(skills)
    parts.append(_SERVER_RULES)
    return "\n\n".join(parts) + "\n"


# ------------------------------------------------------------------
# MCP + Starlette app
# ------------------------------------------------------------------

def create_mcp(
    oauth_provider: ServagentOAuthProvider | None = None,
) -> FastMCP:
    """Build and configure the FastMCP instance.

    Args:
        oauth_provider: When provided, enables OAuth 2.0 on the ``/mcp``
            endpoint (dynamic client registration, authorization code +
            PKCE, token revocation).
    """
    # When behind a reverse proxy (host=127.0.0.1), the MCP SDK's
    # TransportSecurityMiddleware rejects requests whose Host header
    # doesn't match 127.0.0.1/localhost.  Disable DNS-rebinding
    # protection in that case — Nginx already handles host validation.
    if settings.host == "127.0.0.1":
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )
    else:
        transport_security = None  # SDK defaults

    extra_kwargs: dict = {}
    if oauth_provider is not None and settings.oauth_issuer_url:
        from mcp.server.auth.settings import (
            AuthSettings,
            ClientRegistrationOptions,
            RevocationOptions,
        )

        extra_kwargs["auth_server_provider"] = oauth_provider
        extra_kwargs["auth"] = AuthSettings(
            issuer_url=settings.oauth_issuer_url,
            resource_server_url=settings.oauth_issuer_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["admin"],
                default_scopes=["admin"],
            ),
            revocation_options=RevocationOptions(enabled=True),
        )

    instructions = _build_instructions()

    mcp = FastMCP(
        "servagent: Remote Linux Server Administration",
        instructions=instructions,
        stateless_http=True,
        json_response=True,
        transport_security=transport_security,
        # The streamable-http endpoint path inside the sub-app.
        # When mounted at /mcp, the sub-app sees "/" so we set this to "/".
        streamable_http_path="/",
        **extra_kwargs,
    )

    # --- Tool selection ---
    enabled_tools: set[str] | None = None  # None = all tools
    tools_cfg = settings.tools.strip()
    if tools_cfg.lower() != "all":
        requested = {t.strip() for t in tools_cfg.split(",") if t.strip()}
        unknown = requested - ALL_TOOL_NAMES
        if unknown:
            logger.warning("Unknown tool(s) in SERVAGENT_TOOLS (ignored): %s", ", ".join(sorted(unknown)))
        enabled_tools = requested & ALL_TOOL_NAMES
        if not enabled_tools:
            logger.warning("No valid tools in SERVAGENT_TOOLS, falling back to all tools")
            enabled_tools = None

    count = register_tools(mcp, enabled_tools=enabled_tools)
    if enabled_tools is not None:
        logger.info("Registered %d/%d tools: %s", count, len(ALL_TOOL_NAMES), ", ".join(sorted(enabled_tools)))
    else:
        logger.info("Registered all %d tools", count)

    return mcp


def create_app() -> Starlette:
    """Create the Starlette ASGI app with both transports.

    Endpoints:
      - ``/mcp``       — Streamable HTTP (Claude Desktop, Claude Code, etc.)
      - ``/sse``       — SSE legacy transport (LM Studio, older clients)
      - ``/messages/`` — SSE message posting endpoint
      - ``/upload``    — File upload via multipart/form-data (POST)
    """
    # --- OAuth setup (optional) ---
    oauth_store: OAuthSQLiteStore | None = None
    oauth_provider: ServagentOAuthProvider | None = None

    if settings.oauth_issuer_url:
        from servagent.oauth_provider import OAuthSQLiteStore, ServagentOAuthProvider  # noqa: F811

        oauth_store = OAuthSQLiteStore(settings.oauth_database_path)
        oauth_provider = ServagentOAuthProvider(oauth_store)

    mcp = create_mcp(oauth_provider=oauth_provider)

    # --- Streamable HTTP transport (modern) ---
    # Mount the sub-app at /mcp.  The sub-app's internal route is "/"
    # (set via streamable_http_path="/"), so the full path becomes /mcp.
    streamable_app = mcp.streamable_http_app()

    # --- SSE transport (legacy, for LM Studio etc.) ---
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> Response:
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp._mcp_server.run(
                streams[0],
                streams[1],
                mcp._mcp_server.create_initialization_options(),
            )
        return Response()

    # --- Lifespan ---
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        if oauth_store:
            await oauth_store.initialize()
            # Pre-register the static operator client so that MCP clients
            # (like Claude.ai) can use the configured CLIENT_ID/SECRET
            # directly in the OAuth flow.
            if settings.oauth_client_id and settings.oauth_client_secret:
                await oauth_store.ensure_static_client(
                    client_id=settings.oauth_client_id,
                    client_secret=settings.oauth_client_secret,
                )
        logger.info(
            "Servagent starting on %s:%s (transports=streamable-http+sse, auth=%s, oauth=%s)",
            settings.host,
            settings.port,
            "enabled" if settings.api_key else "disabled",
            "enabled" if settings.oauth_issuer_url else "disabled",
        )
        async with mcp.session_manager.run():
            yield
        if oauth_store:
            await oauth_store.close()
        logger.info("Servagent stopped.")

    # --- File upload endpoint ---
    async def handle_upload(request: Request) -> Response:
        """Accept multipart file uploads to the remote server.

        Expects ``multipart/form-data`` with:
          - ``file``: the file to upload
          - ``path``: destination path on the remote server
          - ``create_dirs`` (optional): "true" to auto-create parent dirs (default true)
        """
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" not in content_type:
            return JSONResponse(
                {"error": "Content-Type must be multipart/form-data"},
                status_code=400,
            )

        form = await request.form()

        upload_file = form.get("file")
        dest_path = form.get("path")

        if upload_file is None or dest_path is None:
            return JSONResponse(
                {"error": "Both 'file' and 'path' fields are required"},
                status_code=400,
            )

        create_dirs = form.get("create_dirs", "true").lower() in ("true", "1", "yes")

        # Read file content with size limit enforcement
        max_size = settings.upload_max_size
        chunks: list[bytes] = []
        total = 0
        async for chunk in upload_file.stream():  # type: ignore[union-attr]
            total += len(chunk)
            if total > max_size:
                return JSONResponse(
                    {"error": f"File exceeds maximum upload size ({max_size} bytes)"},
                    status_code=413,
                )
            chunks.append(chunk)

        data = b"".join(chunks)

        p = Path(dest_path).expanduser().resolve()
        if create_dirs:
            p.parent.mkdir(parents=True, exist_ok=True)

        p.write_bytes(data)
        logger.info("Uploaded %d bytes -> %s", len(data), p)

        return JSONResponse({
            "path": str(p),
            "bytes_written": len(data),
            "filename": getattr(upload_file, "filename", None),
        })

    # --- OAuth well-known redirects (RFC 8414 / RFC 9728) ---
    # MCP clients discover OAuth endpoints via well-known URLs at the
    # domain root, e.g.:
    #   /.well-known/oauth-protected-resource/mcp       (RFC 9728)
    #   /.well-known/oauth-authorization-server/mcp      (RFC 8414)
    #   /.well-known/oauth-authorization-server           (legacy)
    # But the SDK mounts these inside the /mcp sub-app.  We add
    # root-level routes that forward to the sub-app equivalents.

    async def _well_known_proxy(request: Request) -> Response:
        """Forward root-level .well-known requests to the /mcp sub-app."""
        wk_path = request.url.path  # e.g. /.well-known/oauth-authorization-server/mcp
        # Map to sub-app path: /mcp/.well-known/oauth-authorization-server
        # Strip trailing resource path ("/mcp") if present
        parts = wk_path.split("/")
        # /.well-known/<type>/mcp → /.well-known/<type>
        if len(parts) >= 4 and parts[-1] == "mcp":
            inner_path = "/".join(parts[:-1])
        else:
            inner_path = wk_path
        from starlette.responses import RedirectResponse
        return RedirectResponse(url=f"/mcp{inner_path}", status_code=307)

    well_known_routes: list = []
    if settings.oauth_issuer_url:
        well_known_routes = [
            Route(
                "/.well-known/oauth-authorization-server/mcp",
                endpoint=_well_known_proxy,
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-authorization-server",
                endpoint=_well_known_proxy,
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                endpoint=_well_known_proxy,
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=_well_known_proxy,
                methods=["GET", "OPTIONS"],
            ),
        ]

    # SSE and messages routes are explicit, streamable-http is mounted
    # at /mcp (not "/" which would swallow /sse and /messages/).
    app = Starlette(
        routes=[
            *well_known_routes,
            Route("/sse", endpoint=handle_sse),
            Route("/upload", endpoint=handle_upload, methods=["POST"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
            Mount("/mcp", app=streamable_app),
        ],
        middleware=[
            Middleware(AuthMiddleware),
        ],
        lifespan=lifespan,
    )
    return app


def main() -> None:
    """CLI entry point."""
    import uvicorn

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not settings.api_key and not settings.oauth_issuer_url:
        logger.warning(
            "WARNING: No API key or OAuth configured. The server is open to anyone who can reach it. "
            "Set SERVAGENT_API_KEY or SERVAGENT_OAUTH_ISSUER_URL to require authentication."
        )

    # Validate OAuth registration credentials (must be both or neither)
    has_id = bool(settings.oauth_client_id)
    has_secret = bool(settings.oauth_client_secret)
    if has_id != has_secret:
        logger.error(
            "FATAL: SERVAGENT_OAUTH_CLIENT_ID and SERVAGENT_OAUTH_CLIENT_SECRET "
            "must both be set (or both empty). Exiting."
        )
        raise SystemExit(1)

    if has_id and not settings.oauth_issuer_url:
        logger.warning(
            "WARNING: OAuth registration credentials are configured but OAuth is disabled "
            "(SERVAGENT_OAUTH_ISSUER_URL is not set). The credentials will have no effect."
        )

    if settings.oauth_issuer_url:
        from urllib.parse import urlparse
        parsed = urlparse(settings.oauth_issuer_url)
        if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
            logger.error(
                "FATAL: SERVAGENT_OAUTH_ISSUER_URL must use HTTPS (got %s). "
                "If behind a reverse proxy with TLS, update the URL to use https://. "
                "Example: https://%s/mcp",
                settings.oauth_issuer_url,
                parsed.hostname or "your-domain.com",
            )
            raise SystemExit(1)

    if settings.oauth_issuer_url and not (settings.tls_certfile and settings.tls_keyfile):
        logger.warning(
            "WARNING: OAuth is enabled without TLS. "
            "Tokens will be transmitted in cleartext. Use TLS in production."
        )

    ssl_kwargs: dict = {}
    if settings.tls_certfile and settings.tls_keyfile:
        ssl_kwargs["ssl_certfile"] = settings.tls_certfile
        ssl_kwargs["ssl_keyfile"] = settings.tls_keyfile
        logger.info("TLS enabled: %s", settings.tls_certfile)

    uvicorn.run(
        "servagent.server:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
