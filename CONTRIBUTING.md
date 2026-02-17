# Contributing to Servagent

Thank you for your interest in contributing to Servagent! This document explains how to get involved and what to expect.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Commit Guidelines](#commit-guidelines)
- [Pull Requests](#pull-requests)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Style Guide](#style-guide)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

Be respectful, constructive, and inclusive. We want this project to be welcoming for everyone regardless of experience level, background, or identity. Harassment, trolling, or destructive behavior will not be tolerated.

## Getting Started

Servagent is a Python MCP (Model Context Protocol) server that enables remote AI-driven server administration. Before contributing, familiarize yourself with:

- The [README](README.md) for features and usage
- The [MCP specification](https://modelcontextprotocol.io/) for protocol context
- The project architecture in [AGENTS.md](AGENTS.md)

## Development Setup

### Prerequisites

- Python >= 3.10
- Git
- A Linux machine or VM (for testing tools that interact with the OS)

### Local Installation

```bash
# 1. Fork and clone the repository
git clone https://github.com/<your-username>/servagent.git
cd servagent

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in development mode
pip install -e .

# 4. Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set SERVAGENT_API_KEY for local testing

# 5. Run the server
servagent
```

The server starts on `http://localhost:8765` by default. The MCP endpoint is at `/mcp` and the legacy SSE endpoint at `/sse`.

### Verifying Your Setup

```bash
# Test the MCP endpoint
curl -X POST http://localhost:8765/mcp \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## Project Structure

```
src/servagent/
  __init__.py          # Package version
  config.py            # Configuration via pydantic-settings (SERVAGENT_* env vars)
  auth.py              # Authentication middleware (Bearer token + Basic Auth + OAuth)
  oauth_provider.py    # OAuth 2.0 server with SQLite persistence
  tools.py             # All MCP tool definitions (18 tools)
  server.py            # Entry point, Starlette ASGI app, transports, instructions
```

Key files at the root:

| File | Purpose |
|---|---|
| `pyproject.toml` | Project metadata and dependencies |
| `.env.example` | Configuration template |
| `install.sh` | Production installation script |
| `install-remote.sh` | One-liner remote install (`curl \| bash`) |
| `uninstall.sh` | Complete removal script |
| `setup-tls.sh` | Let's Encrypt TLS setup |
| `generate-oauth-credentials.sh` | OAuth credential generator |

## Making Changes

### Branching

1. Create a branch from `main` with a descriptive name:
   ```bash
   git checkout -b feat/new-tool-name    # New feature
   git checkout -b fix/auth-header-bug   # Bug fix
   git checkout -b docs/improve-readme   # Documentation
   ```

2. Keep your branch focused on a single change. Split unrelated changes into separate PRs.

### Branch Naming Convention

| Prefix | Purpose |
|---|---|
| `feat/` | New feature or tool |
| `fix/` | Bug fix |
| `docs/` | Documentation only |
| `refactor/` | Code restructuring without behavior change |
| `chore/` | Build, CI, dependencies, or maintenance |

### Adding a New MCP Tool

When adding a new tool to `tools.py`:

1. Define the tool function with a clear docstring that explicitly mentions it operates on the **remote** server
2. Add `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`)
3. Add the tool name to `ALL_TOOL_NAMES`
4. Register it in `register_tools()` with the conditional `enabled_tools` check
5. Document it in `README.md` (features table) and `.env.example` (available tools list)
6. Update `CLAUDE.md` if the change affects architecture or key patterns

### Modifying Configuration

When adding or changing a configuration option:

1. Add the field to the `Settings` class in `config.py` (with `SERVAGENT_` prefix)
2. Document it in `.env.example` with comments
3. Add it to the configuration table in `README.md`

## Commit Guidelines

We use **imperative mood** in commit messages (as if completing the sentence "This commit will..."):

```
Add tail_file tool for remote log monitoring
Fix Bearer token validation in auth middleware
Update README with OAuth configuration examples
```

### Format

```
<type>: <short description>

<optional body with more detail>
```

**Types:** `Add`, `Fix`, `Update`, `Refactor`, `Remove`, `Rename`

- First line: 72 characters max
- Body: wrap at 72 characters, explain *why* not *what*
- Reference issues when applicable: `Fixes #42`

## Pull Requests

### Before Submitting

- [ ] Your code runs without errors (`servagent` starts and responds to requests)
- [ ] You tested your changes locally with an MCP client or `curl`
- [ ] You updated relevant documentation (see [Documentation](#documentation))
- [ ] Your commits follow the [commit guidelines](#commit-guidelines)
- [ ] Shell scripts (if modified) work on both Debian/Ubuntu and RHEL/CentOS

### Submitting a PR

1. Push your branch and open a PR against `main`
2. Fill in the PR template:
   - **What** does this PR do?
   - **Why** is this change needed?
   - **How** was it tested?
3. Keep the PR focused — one logical change per PR
4. Be responsive to review feedback

### Review Process

- A maintainer will review your PR
- You may be asked to make changes — this is normal and collaborative
- Once approved, a maintainer will merge your PR

## Reporting Bugs

Open an issue with:

1. **Description**: What happened vs. what you expected
2. **Steps to reproduce**: Minimal set of steps to trigger the bug
3. **Environment**: OS/distro, Python version, Servagent version, MCP client used
4. **Logs**: Relevant output from `journalctl -u servagent` or the server console
5. **Configuration**: Relevant `.env` settings (redact secrets!)

## Suggesting Features

Open an issue with:

1. **Problem**: What limitation or need are you addressing?
2. **Proposal**: How would you solve it?
3. **Alternatives**: Other approaches you considered
4. **Context**: Your use case (which MCP client, what kind of server, etc.)

Feature discussions happen in issues before implementation starts. This avoids wasted effort on features that may not align with the project's direction.

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Instead, please report them privately by emailing the maintainer or using GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature.

Given that Servagent grants system-level access to remote machines, security is critical. We take all reports seriously and will respond promptly.

## Style Guide

### Python

- **Python >= 3.10** — use modern syntax (type unions `X | Y`, `match/case` where appropriate)
- **Type hints** on all public function signatures
- **Docstrings** on all public functions and classes
- Follow PEP 8 conventions
- Use `async`/`await` for I/O operations
- Use `pathlib.Path` over `os.path` for file operations
- Keep imports sorted: stdlib, third-party, local

### Shell Scripts

- Use `#!/usr/bin/env bash` shebang
- Use `set -euo pipefail` at the top
- Quote all variables: `"${var}"` not `$var`
- Support both Debian/Ubuntu (`apt`) and RHEL/CentOS (`dnf`/`yum`)
- Include usage/help text for scripts with arguments
- Use functions for reusable logic

### General

- Keep changes minimal and focused
- Avoid over-engineering — solve the problem at hand
- Prefer clarity over cleverness
- No dead code or commented-out blocks

## Documentation

**Every code change must include documentation updates.** This is not optional.

| What Changed | Update These Files |
|---|---|
| New tool in `tools.py` | `README.md` (features table), `.env.example` (tools list) |
| New config option | `README.md` (config table), `.env.example`, `config.py` docstring |
| Architecture change | `CLAUDE.md` |
| User-facing behavior | `README.md` |
| Shell scripts | `README.md` (relevant install/update/uninstall sections) |

## License

By contributing to Servagent, you agree that your contributions will be licensed under the [MIT License](https://opensource.org/licenses/MIT).
