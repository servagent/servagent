
<p align="center">
    <picture>
        <img src="/docs/assets/logo-label@600px.png" alt="OpenClaw">
    </picture>
</p>

# Servagent

Servagent is an MCP (Model Context Protocol) server that enables a remote AI to take full control of a Linux server: command execution, file management, service administration, and more.

## Transports

The server exposes two MCP transports simultaneously:

| Transport | Endpoint | Clients |
|---|---|---|
| **Streamable HTTP** | `/mcp` | Claude Code, LM Studio, Claude Desktop (via [mcp-remote](https://www.npmjs.com/package/mcp-remote)), modern clients |
| **SSE** (legacy) | `/sse` + `/messages/` | Older clients |
| **File Upload** | `POST /upload` | Any HTTP client (curl, scripts, etc.) |

## Features

| Tool | Description |
|---|---|
| `execute_command` | Execute any shell command (bash, python, etc.) |
| `read_file` / `write_file` / `edit_file` | Read, write, and edit files |
| `read_file_binary` / `write_file_binary` | Binary file transfer (base64) |
| `upload_file` | Copy a file from one path to another on the remote server |
| `list_directory` | List directory contents |
| `move_path` / `copy_path` / `delete_path` | Move, copy, and delete files/directories |
| `list_processes` / `kill_process` | Process management |
| `tail_file` | Tail/follow log files or journalctl (remote debugging) |
| `system_info` / `network_info` | System and network information |
| `service_action` | Systemd service management (start/stop/restart/status) |
| `get_environment` | Environment variables |

Each tool is annotated with MCP `ToolAnnotations` (read-only, destructive, idempotent) to guide AI clients. Server instructions include anti-loop rules, error handling, and workflow guidelines.

## Prerequisites

- Linux (Ubuntu/Debian, RHEL/CentOS, etc.)
- Python >= 3.10
- Root access for installation as a service

## One-liner Installation

Install directly on your server with a single command:

```bash
# Simple HTTP installation (by IP)
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash

# HTTPS installation with Let's Encrypt
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- your-domain.com

# Installation with full sudo privileges + HTTPS
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --full-access your-domain.com

# Install a specific version
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --version v0.2.0
```

The script automatically downloads the latest release (or the `main` branch if no releases exist), extracts the archive, and runs the installation. The `-y` flag is injected automatically so that interactive prompts are skipped (since stdin is not a terminal in a `curl | bash` pipeline).

## Installation from a Git Clone

If you prefer to clone the repository manually:

```bash
# 1. Clone the repository
git clone https://github.com/Servagent/servagent.git
cd servagent

# 2a. Simple HTTP installation (by IP)
sudo bash install.sh

# 2b. OR direct HTTPS installation with Let's Encrypt
sudo bash install.sh your-domain.com

# 2c. OR installation with full sudo privileges (no interactive prompt)
sudo bash install.sh --full-access your-domain.com
```

The script automatically:
- Creates a `servagent` system user
- Installs in `/opt/servagent` with a virtualenv
- Generates an API key (displayed once — **save it**)
- Creates and enables the systemd service
- **If a domain is provided**: Let's Encrypt certificate, HTTPS on port 443, auto-renewal
- **Interactive prompt** to grant full sudo privileges (or `--full-access` to automate)

```bash
# Check status
servagent status

# View logs
sudo journalctl -u servagent -f
```

The server starts automatically at the end of installation:
- Without domain: `http://<server-ip>:8765/mcp` (Streamable HTTP) or `/sse` (SSE)
- With domain: `https://your-domain.com/mcp` (Streamable HTTP) or `/sse` (SSE)

## Manual Installation (Development)

```bash
# Create a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install the project
pip install -e .

# Configure
cp .env.example .env
# Edit .env to set SERVAGENT_API_KEY

# Run
servagent

# Available commands
servagent --help
servagent --version
```

## Status

Check the service status and current configuration:

```bash
servagent status
```

Displays: systemd service state (active/inactive/failed), PID, uptime, and configuration summary (port, API key, OAuth, TLS, enabled tools). API keys and OAuth secrets are masked (only the last 6 characters are shown). If the `.env` file is not readable, the command automatically escalates with `sudo`.

## API Key Management

Generate and manage the API key via the CLI:

```bash
servagent apikey setup       # Generate an API key and write it to .env
servagent apikey renew       # Regenerate the API key (invalidates the current one)
servagent apikey remove      # Comment out the API key in .env
```

The key is displayed in full only at generation time (`setup` / `renew`). Use `servagent status` to verify it is configured (masked).

## Uninstallation

To completely remove Servagent from the server:

```bash
servagent uninstall              # Interactive (confirmation required)
servagent uninstall -y           # Non-interactive (no confirmation)
servagent uninstall --keep-certs # Keep Let's Encrypt certificates
```

The script automatically removes:
- The systemd service and certbot renewal timer
- The Nginx configuration (if applicable)
- The sudoers file (`/etc/sudoers.d/servagent`)
- The application directory (`/opt/servagent`: virtualenv, `.env`, sources)
- The `servagent` system user
- Let's Encrypt certificates (unless `--keep-certs` is used)

> **Note**: System packages (certbot, python3, nginx) are not removed as they may be used by other services.

## Update

Update to the latest version:

```bash
servagent update             # Update from the current branch
servagent update develop     # Update from a specific branch
servagent update --force     # Force reinstallation even if already up to date
```

The script automatically:
1. Runs `git pull` to fetch the latest changes
2. Copies sources to `/opt/servagent/`
3. Reinstalls the package in editable mode (`pip install -e`) in the virtualenv
4. Restarts the service
5. Verifies the service is running correctly

If no changes are detected, the script stops without restarting the service. In case of issues, a rollback command is displayed at the end of execution.

## Configuration

All options are configurable via environment variables or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `SERVAGENT_HOST` | `0.0.0.0` | Listen interface |
| `SERVAGENT_PORT` | `8765` | Listen port |
| `SERVAGENT_API_KEY` | _(empty)_ | API key (Bearer token). **Required in production.** |
| `SERVAGENT_WORK_DIR` | _(cwd)_ | Default working directory |
| `SERVAGENT_COMMAND_TIMEOUT` | `300` | Command timeout (seconds) |
| `SERVAGENT_MAX_OUTPUT_SIZE` | `1000000` | Maximum output size (bytes) |
| `SERVAGENT_UPLOAD_MAX_SIZE` | `100000000` | Maximum upload file size (bytes, 100 MB) |
| `SERVAGENT_TLS_CERTFILE` | _(empty)_ | Path to TLS certificate (fullchain.pem) |
| `SERVAGENT_TLS_KEYFILE` | _(empty)_ | Path to TLS private key (privkey.pem) |
| `SERVAGENT_TOOLS` | `execute_command,write_file,read_file,edit_file,upload_file` | Tools to expose (comma-separated list, or `all`) |
| `SERVAGENT_LOG_LEVEL` | `INFO` | Log level |
| `SERVAGENT_OAUTH_ISSUER_URL` | _(empty)_ | OAuth issuer URL (include `/mcp`). Enables OAuth when set. |
| `SERVAGENT_OAUTH_CLIENT_ID` | _(empty)_ | Operator Client ID: static OAuth client + `/mcp/register` protection |
| `SERVAGENT_OAUTH_CLIENT_SECRET` | _(empty)_ | Associated Client Secret (both must be set together) |
| `SERVAGENT_OAUTH_DB_PATH` | `~/.servagent/oauth.db` | OAuth SQLite database path |

## HTTPS with Let's Encrypt

TLS is built directly into `install.sh`. Simply pass the domain as an argument (see One-liner Installation).

**Prerequisites**: The domain must point to the server's IP and port 80 must be open for Let's Encrypt's HTTP-01 challenge.

To enable HTTPS on a server already installed with HTTP:

```bash
sudo bash setup-tls.sh your-domain.com
```

### Alternative: Nginx Reverse Proxy

If you prefer to use Nginx (useful when other web services run on the same server):

```bash
# 1. Install Nginx and Certbot
sudo apt install nginx certbot python3-certbot-nginx

# 2. Obtain a Let's Encrypt certificate
sudo certbot --nginx -d your-domain.com

# 3. Copy the Nginx configuration
sudo cp nginx.conf.example /etc/nginx/sites-available/servagent
# Edit the file to replace 'your-domain.com' with your domain

# 4. Enable and reload
sudo ln -s /etc/nginx/sites-available/servagent /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The MCP endpoint will then be accessible over HTTPS: `https://your-domain.com/mcp`

> **Note**: Behind a reverse proxy, set `SERVAGENT_HOST=127.0.0.1` so the server automatically disables the MCP SDK's DNS-rebinding protection (Nginx already handles Host header validation).

## Connecting from an MCP Client

### Claude Code

Claude Code supporte nativement les serveurs MCP distants via Streamable HTTP. Ajoutez cette configuration dans votre fichier de settings Claude Code (`.mcp.json`, project settings, ou via `claude mcp add`) :

```json
{
  "mcpServers": {
    "servagent": {
      "type": "streamable-http",
      "url": "https://your-domain.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### Claude Desktop

Claude Desktop ne supporte que les serveurs MCP locaux via `stdio`. Pour se connecter à un serveur distant, utilisez [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) comme pont. Ajoutez ceci dans votre `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "servagent": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-domain.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

> `mcp-remote` crée un serveur stdio local qui relaie les requêtes vers le serveur HTTP distant. Nécessite Node.js installé.

### Autres clients (LM Studio, etc.)

Les clients qui supportent nativement Streamable HTTP peuvent utiliser cette configuration :

```json
{
  "mcpServers": {
    "servagent": {
      "url": "https://your-domain.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### SSE (Legacy Clients)

```json
{
  "mcpServers": {
    "servagent": {
      "url": "https://your-domain.com/sse",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### Testing with curl

```bash
# Health check (the MCP endpoint responds to POST requests)
curl -X POST https://your-domain.com/mcp \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

### File Upload

The `POST /upload` endpoint allows sending files to the remote server via `multipart/form-data`. It is protected by the same Bearer token as the MCP endpoints.

```bash
# Send a file to the server
curl -X POST https://your-domain.com/upload \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@my-file.tar.gz" \
  -F "path=/opt/app/my-file.tar.gz" \
  -F "create_dirs=true"
```

Form fields:
- `file` (required): the file to send
- `path` (required): destination path on the remote server
- `create_dirs` (optional, default `true`): create parent directories if needed

The maximum size is configurable via `SERVAGENT_UPLOAD_MAX_SIZE` (default: 100 MB).

## Authentication

The server supports two authentication mechanisms that coexist:

| Mechanism | Protects | Configuration |
|---|---|---|
| **Bearer token** (`API_KEY`) | `/mcp`, `/sse`, `/messages/`, `/upload` | `SERVAGENT_API_KEY` |
| **OAuth 2.0** | `/mcp` (via access token), `/mcp/register` (via Basic Auth) | `SERVAGENT_OAUTH_*` |

Both mechanisms work in parallel. The Bearer token gives direct access to all endpoints. OAuth enables a standard registration and authorization flow.

The `/.well-known/` endpoints (OAuth discovery, RFC 8414 / RFC 9728) are always accessible without authentication.

## OAuth 2.0 (Streamable HTTP)

In addition to simple Bearer token authentication, the server supports OAuth 2.0 for the `/mcp` endpoint. This allows compatible MCP applications to connect via the standard OAuth protocol (authorization code + PKCE, RFC 7636).

### Enabling OAuth

```bash
# Auto-detects the issuer URL from TLS cert domain or server IP
servagent oauth setup

# Explicit issuer URL (if auto-detection fails)
servagent oauth setup --issuer-url https://your-domain.com/mcp
```

This generates `CLIENT_ID` and `CLIENT_SECRET`, and writes all three `SERVAGENT_OAUTH_*` variables to `.env`:

```bash
# In .env — the URL MUST include the /mcp path
SERVAGENT_OAUTH_ISSUER_URL=https://your-domain.com/mcp

# Operator credentials (dual purpose: static OAuth client + /mcp/register protection)
SERVAGENT_OAUTH_CLIENT_ID=servagent-xxxxxxxxxxxxxxxx
SERVAGENT_OAUTH_CLIENT_SECRET=a-strong-randomly-generated-secret
```

### Renewing / Removing OAuth

```bash
# Regenerate credentials (invalidates all existing sessions)
servagent oauth renew

# Disable OAuth entirely (comments out vars in .env, removes database)
servagent oauth remove

# Disable OAuth but keep the database file
servagent oauth remove --keep-db
```

When OAuth is enabled:
- **`/mcp`** is protected by OAuth (the MCP SDK handles tokens) **or** by the Bearer token (`API_KEY`)
- **`/mcp/register`** is protected by HTTP Basic Auth with `CLIENT_ID:CLIENT_SECRET`
- **`/sse`**, **`/messages/`**, **`/upload`** remain protected by the simple Bearer token (`API_KEY`)
- **`/.well-known/`** is always accessible without authentication (OAuth discovery)

### Authentication Matrix

| Endpoint | Bearer API_KEY | OAuth access_token | Basic CLIENT_ID:SECRET |
|---|---|---|---|
| `/.well-known/*` | - | - | - (public) |
| `/mcp` | yes | yes | - |
| `/mcp/register` | - | - | **required** |
| `/sse` | yes | - | - |
| `/messages/` | yes | - | - |
| `/upload` | yes | - | - |

### Dual Purpose of CLIENT_ID / CLIENT_SECRET

The operator credentials (`CLIENT_ID` / `CLIENT_SECRET`) serve two purposes:

1. **Static OAuth client**: At startup, the server pre-registers these credentials as a valid OAuth client in the SQLite database (via `ensure_static_client()`). This allows interfaces like Claude.ai and ChatGPT to use the CLIENT_ID/SECRET directly in the OAuth flow (authorize → token) **without calling `/mcp/register`**. Redirect URIs for known platforms (Claude.ai, ChatGPT) are pre-configured automatically.

2. **`/mcp/register` protection**: The same credentials protect the dynamic registration endpoint via HTTP Basic Auth. Programmatic clients (scripts, SDKs) can register to obtain their own `client_id`/`client_secret`.

Both modes coexist: the static client works for UIs (Claude.ai, ChatGPT, etc.), and dynamic registration works for scripts and SDKs.

### Connecting from Claude.ai

1. On Claude.ai, go to **Settings** → **Connectors** → **Add a custom connector**
2. Fill in the fields:
   - **Name**: `servagent` (or a name of your choice)
   - **Remote MCP server URL**: `https://your-domain.com/mcp`
   - **OAuth Client ID**: the value of `SERVAGENT_OAUTH_CLIENT_ID`
   - **OAuth Client Secret**: the value of `SERVAGENT_OAUTH_CLIENT_SECRET`
3. Confirm — Claude.ai automatically performs the OAuth flow (discovery → authorization → token)

### Connecting from ChatGPT

1. On ChatGPT, go to **Settings** → **Connectors** → **Add a custom connector**
2. Fill in the fields:
   - **Name**: `servagent`
   - **MCP server URL**: `https://your-domain.com/mcp`
   - **Client ID**: the value of `SERVAGENT_OAUTH_CLIENT_ID`
   - **Client Secret**: the value of `SERVAGENT_OAUTH_CLIENT_SECRET`
3. Confirm — ChatGPT performs the OAuth flow with its redirect URI (`https://chatgpt.com/connector_platform_oauth_redirect`)

### OAuth Endpoints (under `/mcp`)

| Endpoint | Description |
|---|---|
| `/.well-known/oauth-authorization-server` | OAuth metadata (RFC 8414) |
| `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `/authorize` | Authorization endpoint |
| `/token` | Code/refresh token exchange |
| `/register` | Dynamic client registration (RFC 7591) |
| `/revoke` | Token revocation (RFC 7009) |

> **Note**: The `/.well-known/` discovery URLs are accessible both at the domain root level and under `/mcp`. 307 redirects at the root level forward to the `/mcp` sub-app to ensure compatibility with all MCP clients.

### OAuth Flow (Dynamic Registration)

For programmatic clients using dynamic registration:

```bash
# 1. Register a client (HTTP Basic Auth with CLIENT_ID:CLIENT_SECRET)
curl -X POST https://your-domain.com/mcp/register \
  -u "MY_CLIENT_ID:MY_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "My App",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
# → returns dynamic client_id + client_secret
```

Then the standard OAuth flow proceeds normally:

1. The client discovers endpoints via `GET /.well-known/oauth-authorization-server/mcp` (or `/mcp/.well-known/oauth-authorization-server`)
2. The client obtains an authorization code via `/mcp/authorize` (with PKCE)
3. The client exchanges the code for an access token via `POST /mcp/token`
4. The client uses the access token to call `/mcp`

The server uses an auto-approve model: any registered client (static or dynamic) is considered authorized.

Access tokens expire after 1 hour. Refresh tokens last 30 days with automatic rotation.

### Storage

OAuth clients and tokens are persisted in a SQLite database (default: `~/.servagent/oauth.db`). Data survives server restarts. The static client is re-registered (upsert) on each startup.

## Skills

Skills allow you to enrich the context sent to the LLM with information specific to your server: hosted domains, SMTP credentials, available services, etc. Each skill is a directory containing a `SKILL.md` file whose content is injected into the MCP instructions.

The `skills/` directory is located at the project root (in dev) or in `/opt/servagent/skills/` (in production). Its content is git-ignored (`.gitignore`) as it may contain sensitive information specific to each server.

### Structure

```
skills/
├── .gitkeep
├── webserver/
│   └── SKILL.md
├── smtp/
│   └── SKILL.md
└── docker/
    └── SKILL.md
```

### Example: `skills/webserver/SKILL.md`

```markdown
# webserver
Domain: myserver.com (points to this server)
Web root: /var/www/myserver.com
Nginx config: /etc/nginx/sites-available/myserver.com
SSL: Let's Encrypt, auto-renew via certbot timer
```

### Example: `skills/smtp/SKILL.md`

```markdown
# smtp
This server can send emails via SMTP.
- Host: smtp.gmail.com
- Port: 587
- User: bot@myserver.com
- Password: xxxx-xxxx-xxxx
- Use: `msmtp` or `swaks` CLI (already installed)
```

The content of each `SKILL.md` is injected as-is into the MCP instructions under a `## Skills` section. If the file starts with a markdown heading (`#`), it is used as-is. Otherwise, a `### directory_name` heading is added automatically.

## Security

> **WARNING**: This server gives full control over the host machine. Secure it properly.

- **Always** set `SERVAGENT_API_KEY` in production
- **Always** use TLS (`setup-tls.sh` or Nginx) in production
- Restrict port access via firewall (`ufw`, `iptables`)
- The service runs under a dedicated user (`servagent`)
- By default, the user has **no** sudo privileges (`NoNewPrivileges=true`)
- The `--full-access` option (or the interactive prompt) grants `sudo NOPASSWD: ALL` via `/etc/sudoers.d/servagent` and disables `NoNewPrivileges`

## Project Structure

```
servagent/
  src/servagent/
    __init__.py        # Version
    cli.py             # CLI entry point (click subcommands: run, status, uninstall, update, apikey, oauth)
    config.py          # Configuration (pydantic-settings)
    auth.py            # Authentication middleware (Bearer + Basic Auth + OAuth)
    oauth_provider.py  # OAuth 2.0 provider with SQLite storage + static client
    tools.py           # All MCP tools
    server.py          # Server module, Starlette app + MCP (Streamable HTTP + SSE + .well-known)
  skills/              # Skills directory (content in .gitignore)
    .gitkeep
  pyproject.toml                  # Metadata and dependencies
  install.sh                      # Linux installation script (from git clone)
  install-remote.sh               # One-liner installation script (curl | bash)
  uninstall.sh                    # Complete uninstallation script
  setup-tls.sh                    # HTTPS setup with Let's Encrypt
  generate-oauth-credentials.sh   # CLIENT_ID / CLIENT_SECRET generator
  nginx.conf.example              # Nginx configuration (optional)
  .env.example                    # Configuration template
```

## Learn More

### MCP (Model Context Protocol)

- [modelcontextprotocol.io](https://modelcontextprotocol.io) — Official documentation, guides, and tutorials
- [GitHub repository](https://github.com/modelcontextprotocol/modelcontextprotocol) — Specification and links to documentation
- [Specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25) — Direct access to the dated specification

### Skills

- [agentskills.io](https://agentskills.io/) — Agent Skills documentation
- [GitHub repository](https://github.com/agentskills/agentskills) — Agent Skills specification and examples

## License

MIT
