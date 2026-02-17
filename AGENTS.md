# AGENTS.md

## Project Overview

**servagent** is a Python MCP (Model Context Protocol) server that enables remote AI-driven server administration. It exposes system tools (command execution, file management, process control, service management) over two transports simultaneously: Streamable HTTP and SSE (legacy).

## Commands

```bash
# Install in development mode
pip install -e .

# Run the server (all equivalent)
servagent                    # Default: starts the MCP server
servagent run                # Explicit subcommand

# Or directly
python -m servagent.server

# CLI subcommands
servagent status             # Show service status and configuration
servagent uninstall          # Uninstall (interactive)
servagent uninstall -y       # Uninstall (non-interactive)
servagent uninstall --keep-certs  # Keep Let's Encrypt certs
servagent update             # Update to latest version
servagent update develop     # Update from a specific branch
servagent update --force     # Force reinstall
servagent oauth setup        # Generate OAuth credentials and write to .env (interactive)
servagent oauth setup --issuer-url https://example.com/mcp  # Non-interactive
servagent oauth renew        # Regenerate credentials (invalidates sessions)
servagent oauth renew --yes  # Non-interactive
servagent oauth remove       # Disable OAuth and comment out credentials
servagent oauth remove --yes --keep-db  # Keep the OAuth database
servagent --version          # Show version
servagent --help             # Show help with all subcommands

# Remote one-liner install (no git clone needed)
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- votre-domaine.com
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --version v0.2.0

# Production install (from git clone)
sudo bash install.sh                                  # HTTP on port 8765
sudo bash install.sh votre-domaine.com                # HTTPS via Let's Encrypt
sudo bash install.sh --full-access                    # HTTP + sudo privileges
sudo bash install.sh --full-access votre-domaine.com  # HTTPS + sudo privileges

# Uninstall (via shell script directly)
sudo bash uninstall.sh              # Interactive (confirmation required)
sudo bash uninstall.sh -y           # Non-interactive
sudo bash uninstall.sh --keep-certs # Keep Let's Encrypt certificates
```

## Architecture

- `src/servagent/cli.py` — CLI entry point using click. `@click.group(invoke_without_command=True)` so `servagent` without arguments starts the server. Subcommands: `run` (start server), `status` (show systemd service status + config), `uninstall` (locate and run `uninstall.sh` via sudo), `update` (locate and run `update.sh` via sudo), `oauth` (group: `setup`, `renew`, `remove` — manage OAuth credentials in `.env`). Script discovery via `_find_script()` checks `/opt/servagent/` (production) then repo root (dev). `.env` discovery via `_find_env_file()` uses the same search order. `--version` flag from `__version__`
- `src/servagent/server.py` — Server module, Starlette ASGI app exposing both transports:
  - `/mcp` — Streamable HTTP (Claude Desktop, Claude Code, LM Studio)
  - `/sse` — SSE connection endpoint (legacy clients)
  - `/messages/` — SSE message posting endpoint
  - `/upload` — File upload via multipart/form-data (POST), secured by Bearer token
  - `/.well-known/oauth-*` — Root-level redirect routes (307) for OAuth discovery (RFC 8414 / RFC 9728), forwarding to `/mcp/.well-known/...`
  - `_build_instructions()` dynamically generates the MCP instructions string from `_collect_server_context()` (OS, IPs, shell, package manager, sudo, etc.) + `_collect_skills()` (optional SKILL.md files from `skills/` directory) + `_SERVER_RULES` (compact static rules). Sent once at connection time via `FastMCP(instructions=...)`
  - Lifespan: initializes OAuth SQLite store and pre-registers static OAuth client via `ensure_static_client()` when credentials are configured
- `src/servagent/tools.py` — All MCP tool definitions (execute_command, file ops, process mgmt, tail_file, upload_file, etc.). Each tool has `ToolAnnotations` (read-only/destructive/idempotent hints) and docstrings that explicitly state it operates on the **remote** server to help AI clients differentiate from local operations. Exports `ALL_TOOL_NAMES` (set of all 18 tool names) and `register_tools(mcp, enabled_tools)` which conditionally registers only the requested tools
- `src/servagent/config.py` — Configuration via pydantic-settings, loaded from env vars / `.env`
- `src/servagent/auth.py` — Authentication middleware with four auth paths: (1) `/.well-known/` routes always pass through (OAuth discovery, RFC 8414 / RFC 9728), (2) `/mcp/register` requires HTTP Basic Auth with `OAUTH_CLIENT_ID:OAUTH_CLIENT_SECRET`, (3) `/mcp/*` accepts Bearer `API_KEY` or SDK OAuth pass-through, (4) all other routes require Bearer `API_KEY`. Uses `hmac.compare_digest()` for timing-safe comparisons. CORS preflight (`OPTIONS`) on `/mcp/register` is always allowed through
- `src/servagent/oauth_provider.py` — OAuth 2.0 Authorization Server provider backed by SQLite. Implements the MCP SDK's `OAuthAuthorizationServerProvider` protocol with `OAuthSQLiteStore` (persistence) and `ServagentOAuthProvider` (auto-approve model). Tables: `clients`, `authorization_codes`, `access_tokens`, `refresh_tokens`. Includes `ensure_static_client()` to pre-register operator credentials as a valid OAuth client at startup (for Claude.ai, ChatGPT, and similar UIs that use CLIENT_ID/SECRET directly without calling `/mcp/register` first). `KNOWN_REDIRECT_URIS` class attribute lists all supported platform callbacks
- `generate-oauth-credentials.sh` — CLI script to generate `CLIENT_ID` / `CLIENT_SECRET` pairs. Supports `--write` to update `.env` directly

## Key Patterns

- The `FastMCP` instance is created with a descriptive `name`, `instructions`, `stateless_http=True` and `streamable_http_path="/"` so it maps cleanly when mounted at `/mcp` and AI clients receive contextual guidance at initialization
- **Dynamic instructions**: `_build_instructions()` assembles the MCP instructions at startup by combining `_collect_server_context()` (OS, hostname, IPs, user/sudo, shell, package manager, init system, Python version, working directory) + `_collect_skills()` (optional SKILL.md files from `skills/` directory) + `_SERVER_RULES` (compact static rules). Each detection helper (`_detect_distro`, `_detect_ips`, `_detect_sudo`, etc.) is fault-tolerant — returns "unknown" on failure. Uses synchronous `subprocess.run` (not async) since it runs once at startup
- **Skills**: `_collect_skills()` scans the `skills/` directory at the root of the working directory for subdirectories containing `SKILL.md` files. Their content is injected into the MCP instructions under a `## Skills` section. Each skill directory becomes a subsection. If the markdown starts with a `#` heading it is used as-is, otherwise `### dirname` is prepended. The `skills/` directory is always present at project root (with `.gitkeep`), but its content is git-ignored since it may contain server-specific credentials. No configuration variable needed — the path is always `{working_directory}/skills/`
- Every tool is annotated with `ToolAnnotations` from `mcp.types` to declare structured hints: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. These are sent per-tool in the `tools/list` response and complement the textual instructions
- When `host=127.0.0.1` (reverse proxy mode), DNS-rebinding protection is disabled via `TransportSecuritySettings`
- SSE transport uses `SseServerTransport` from the MCP SDK, wired manually to the same `FastMCP` server instance
- **Dual auth**: Two authentication mechanisms coexist. Bearer token (`API_KEY`) gives direct access to all endpoints. OAuth protects `/mcp` via access tokens from the SDK. Auth matrix: `/.well-known/` → always public (OAuth discovery); `/mcp/register` → HTTP Basic Auth with `OAUTH_CLIENT_ID:OAUTH_CLIENT_SECRET` (operator credentials); `/mcp/*` → Bearer `API_KEY` or SDK OAuth; `/sse`, `/messages/`, `/upload` → Bearer `API_KEY`
- Auth middleware runs on all routes via Starlette `BaseHTTPMiddleware`. `.well-known` paths always pass through without auth (OAuth/resource discovery). For `/mcp/register`: validates HTTP Basic Auth against configured `oauth_client_id`/`oauth_client_secret`; returns 403 if credentials not configured, 401 if invalid. For other `/mcp` routes when OAuth is active: accepts Bearer `API_KEY` as a fast-path, otherwise passes through to the SDK's OAuth middleware. CORS preflight (`OPTIONS`) on `/mcp/register` always passes through
- **Static OAuth client**: When `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are configured, `ensure_static_client()` pre-registers them as a valid OAuth client in the SQLite database at startup (via `INSERT OR REPLACE`). This allows MCP clients like Claude.ai and ChatGPT — which use the CLIENT_ID/SECRET directly in the OAuth authorize/token flow without calling `/mcp/register` first — to authenticate immediately. The static client is configured with `redirect_uris` from `KNOWN_REDIRECT_URIS` (Claude.ai + ChatGPT callbacks), `grant_types=["authorization_code", "refresh_token"]`, `scope="admin"`, and `token_endpoint_auth_method="client_secret_post"`. New platform redirect URIs should be added to the `KNOWN_REDIRECT_URIS` class attribute in `OAuthSQLiteStore`
- **Dynamic client registration**: Programmatic clients (scripts, SDKs) can still use `POST /mcp/register` with HTTP Basic Auth to obtain their own `client_id`/`client_secret`. Both paths (static client + dynamic registration) coexist
- **OAuth discovery redirects**: Root-level `.well-known` redirect routes (307) forward RFC 8414/9728 discovery URLs to the `/mcp` sub-app. The MCP SDK mounts OAuth routes inside the sub-app, but clients discover them at domain root level. Four routes are added when OAuth is active: `/.well-known/oauth-authorization-server/mcp`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-protected-resource` — all redirect to `/mcp/.well-known/...`
- **Startup validation**: `main()` validates that `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are either both set or both empty (fatal error otherwise). Warns if credentials are configured but `OAUTH_ISSUER_URL` is not set (credentials would have no effect)
- **Remote install**: `install-remote.sh` is a thin bootstrap script for `curl | bash` one-liner installs. It downloads a GitHub tarball (latest release or specific `--version`), extracts to a temp dir, and runs the bundled `install.sh`. Supports `curl` and `wget`. All arguments except `--version` are forwarded to `install.sh`. Falls back to `main` branch if no GitHub releases exist. Automatically injects `-y` before calling `install.sh` to skip interactive prompts (stdin is not a terminal in a pipe)
- `install.sh` supports `--full-access` flag to grant sudo NOPASSWD to the service user and disable `NoNewPrivileges` in systemd; without the flag, an interactive prompt asks during installation
- `uninstall.sh` reverses everything done by `install.sh`: stops/removes systemd services, Nginx config, sudoers file, app directory, system user, and optionally Let's Encrypt certificates. Requires confirmation unless `-y` is passed. `--keep-certs` preserves TLS certificates
- **Tool selection**: `SERVAGENT_TOOLS` controls which tools are exposed. Default is `execute_command,upload_file` (minimal, saves context window for small LLMs). Set to `all` to expose all 18 tools. Invalid tool names are logged as warnings and ignored. In `server.py`, the config string is parsed into a `set[str]` and passed to `register_tools(mcp, enabled_tools=...)`
- **CLI**: The `servagent` entry point is `servagent.cli:cli` (click group). Without subcommand, it calls `server.main()` to start the server (backward-compatible). `status` queries systemd via `systemctl show` and displays config from `settings`. `uninstall`/`update` delegate to shell scripts found via `_find_script()` (production: `/opt/servagent/`, dev: repo root), executed via `subprocess.run(["sudo", "bash", ...])`. CLI flags map directly to script flags. `oauth` is a click subgroup with three commands: `setup` (generates CLIENT_ID/CLIENT_SECRET, writes to `.env` with `OAUTH_ISSUER_URL`; prompts for issuer URL if `--issuer-url` not given; refuses if OAuth already configured), `renew` (regenerates credentials, deletes OAuth database to invalidate all sessions; requires `--yes` or interactive confirmation), `remove` (comments out all `SERVAGENT_OAUTH_*` vars in `.env`, deletes OAuth database unless `--keep-db`; requires `--yes` or interactive confirmation). All three commands use `_find_env_file()` to auto-detect `.env` or accept `--env-file`. Helper functions `_env_set`, `_env_comment_out`, `_env_get` manipulate `.env` via regex

## Key Dependencies

- `mcp[cli]>=1.26.0` — Official MCP Python SDK (FastMCP, SSE transport, Streamable HTTP, OAuth server support)
- `pydantic-settings>=2.0.0` — Configuration management
- `aiosqlite>=0.20.0` — Async SQLite for OAuth persistence
- `click>=8.0.0` — CLI framework (subcommands, options, help generation)
- `starlette` / `uvicorn` — ASGI server (bundled with mcp)

## Configuration

All settings use the `SERVAGENT_` prefix as environment variables. See `.env.example`.

## Documentation Maintenance

**CRITICAL**: Whenever you modify code, add features, or change behavior, you MUST update the relevant documentation files:

- **README.md** — User-facing documentation: installation, usage, features, configuration examples
- **AGENTS.md** — AI agent integration guide (if it exists)
- **CLAUDE.md** — This file: architecture, commands, key patterns
- **Other .md files** — Update any documentation that references the modified functionality

**Process**:
1. After making any code changes, check which documentation files are affected
2. Update those files to reflect the new behavior, features, or configuration
3. Ensure examples, command snippets, and descriptions remain accurate
4. If adding a new tool in `tools.py`, document it in README.md
5. If changing configuration options, update both `.env.example` and README.md
