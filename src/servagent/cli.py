"""Servagent CLI — command-line interface with subcommands."""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import click

from servagent import __version__


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _find_script(name: str) -> Path | None:
    """Locate a shell script (uninstall.sh, update.sh, etc.).

    Search order:
      1. /opt/servagent/<name>  (production install)
      2. Next to the Python package source tree (dev mode / git clone)
    """
    # Production path
    prod = Path(f"/opt/servagent/{name}")
    if prod.is_file():
        return prod

    # Dev path — walk up from this file to find the repo root
    here = Path(__file__).resolve().parent  # src/servagent/
    repo_root = here.parent.parent          # project root
    dev = repo_root / name
    if dev.is_file():
        return dev

    return None


def _find_env_file() -> Path | None:
    """Locate the .env file.

    Search order:
      1. /opt/servagent/.env  (production)
      2. Repo root .env       (dev)
    """
    prod = Path("/opt/servagent/.env")
    if prod.is_file():
        return prod

    here = Path(__file__).resolve().parent
    repo_root = here.parent.parent
    dev = repo_root / ".env"
    if dev.is_file():
        return dev

    return None


def _generate_credentials() -> tuple[str, str]:
    """Generate a CLIENT_ID and CLIENT_SECRET pair."""
    client_id = "servagent-" + secrets.token_hex(8)
    client_secret = secrets.token_urlsafe(48)
    return client_id, client_secret


def _env_set(env_path: Path, key: str, value: str) -> None:
    """Set a key=value in a .env file.

    If the key exists (commented or not), it is replaced.
    Otherwise it is appended.
    """
    content = env_path.read_text()
    # Match both "KEY=..." and "# KEY=..."
    pattern = re.compile(rf"^[#\s]*{re.escape(key)}\s*=.*$", re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key}={value}", content)
    else:
        content = content.rstrip("\n") + f"\n{key}={value}\n"
    env_path.write_text(content)


def _env_comment_out(env_path: Path, key: str) -> None:
    """Comment out a key in a .env file (prefix with '# ')."""
    content = env_path.read_text()
    pattern = re.compile(rf"^({re.escape(key)}\s*=.*)$", re.MULTILINE)
    content = pattern.sub(r"# \1", content)
    env_path.write_text(content)


def _env_get(env_path: Path, key: str) -> str:
    """Read a key from a .env file. Returns empty string if not found or commented."""
    content = env_path.read_text()
    pattern = re.compile(rf"^{re.escape(key)}\s*=\s*(.*)$", re.MULTILINE)
    m = pattern.search(content)
    return m.group(1).strip() if m else ""


# ------------------------------------------------------------------
# CLI group
# ------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="servagent")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """servagent — Remote server administration via MCP."""
    if ctx.invoked_subcommand is None:
        from servagent.server import main
        main()


# ------------------------------------------------------------------
# run
# ------------------------------------------------------------------

@cli.command()
def run() -> None:
    """Start the MCP server."""
    from servagent.server import main
    main()


# ------------------------------------------------------------------
# status
# ------------------------------------------------------------------

def _systemctl_query(prop: str) -> str:
    """Query a systemd property for servagent.service."""
    try:
        r = subprocess.run(
            ["systemctl", "show", "servagent.service", f"--property={prop}"],
            capture_output=True, text=True, timeout=5,
        )
        # Output is like "ActiveState=active\n"
        for line in r.stdout.strip().splitlines():
            if "=" in line:
                return line.split("=", 1)[1]
    except Exception:
        pass
    return ""


@cli.command()
def status() -> None:
    """Show service status and configuration."""
    click.echo(f"servagent v{__version__}")
    click.echo()

    # --- Systemd service status ---
    has_systemctl = shutil.which("systemctl") is not None

    if has_systemctl:
        active = _systemctl_query("ActiveState")
        sub = _systemctl_query("SubState")
        pid = _systemctl_query("MainPID")
        since = _systemctl_query("ActiveEnterTimestamp")

        if active:
            label = f"{active} ({sub})" if sub else active
            if active == "active":
                label = click.style(label, fg="green")
            elif active == "failed":
                label = click.style(label, fg="red")
            else:
                label = click.style(label, fg="yellow")
            click.echo(f"  Service:  {label}")
            if pid and pid != "0":
                click.echo(f"  PID:      {pid}")
            if since:
                click.echo(f"  Since:    {since}")
        else:
            click.echo("  Service:  " + click.style("not installed", fg="yellow"))
    else:
        click.echo("  Service:  " + click.style("systemd not available", dim=True))

    click.echo()

    # --- Configuration ---
    from servagent.config import settings

    click.echo("  Configuration:")
    click.echo(f"    Port:    {settings.port}")
    click.echo(f"    Host:    {settings.host}")

    api_status = click.style("configured", fg="green") if settings.api_key else click.style("not set", fg="yellow")
    click.echo(f"    API key: {api_status}")

    oauth_status = click.style("enabled", fg="green") if settings.oauth_issuer_url else click.style("disabled", dim=True)
    click.echo(f"    OAuth:   {oauth_status}")

    tls_status = click.style("enabled", fg="green") if (settings.tls_certfile and settings.tls_keyfile) else click.style("disabled", dim=True)
    click.echo(f"    TLS:     {tls_status}")

    tools_cfg = settings.tools.strip()
    if tools_cfg.lower() == "all":
        tools_display = "all"
    else:
        tools_display = tools_cfg
    click.echo(f"    Tools:   {tools_display}")


# ------------------------------------------------------------------
# uninstall
# ------------------------------------------------------------------

@cli.command()
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--keep-certs", is_flag=True, help="Keep Let's Encrypt certificates.")
def uninstall(yes: bool, keep_certs: bool) -> None:
    """Uninstall servagent from this system."""
    script = _find_script("uninstall.sh")
    if script is None:
        click.echo("Error: uninstall.sh not found.", err=True)
        raise SystemExit(1)

    cmd: list[str] = ["sudo", "bash", str(script)]
    if yes:
        cmd.append("-y")
    if keep_certs:
        cmd.append("--keep-certs")

    result = subprocess.run(cmd)
    raise SystemExit(result.returncode)


# ------------------------------------------------------------------
# update
# ------------------------------------------------------------------

@cli.command()
@click.argument("branch", required=False)
@click.option("--force", is_flag=True, help="Force reinstall even if already up to date.")
def update(branch: str | None, force: bool) -> None:
    """Update servagent to the latest version."""
    script = _find_script("update.sh")
    if script is None:
        click.echo("Error: update.sh not found.", err=True)
        raise SystemExit(1)

    cmd: list[str] = ["sudo", "bash", str(script)]
    if force:
        cmd.append("--force")
    if branch:
        cmd.append(branch)

    result = subprocess.run(cmd)
    raise SystemExit(result.returncode)


# ------------------------------------------------------------------
# oauth
# ------------------------------------------------------------------

@cli.group()
def oauth() -> None:
    """Manage OAuth 2.0 credentials."""


@oauth.command()
@click.option("--issuer-url", prompt="Issuer URL (e.g. https://your-domain.com/mcp)",
              help="OAuth issuer URL (must include /mcp).")
@click.option("--env-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to the .env file (auto-detected if omitted).")
def setup(issuer_url: str, env_file: str | None) -> None:
    """Generate OAuth credentials and write them to .env."""
    env_path = Path(env_file) if env_file else _find_env_file()
    if env_path is None:
        click.echo("Error: .env file not found. Create one first (cp .env.example .env).", err=True)
        raise SystemExit(1)

    # Check if OAuth is already configured
    existing_id = _env_get(env_path, "SERVAGENT_OAUTH_CLIENT_ID")
    if existing_id:
        click.echo(f"  OAuth is already configured (client_id={existing_id}).")
        click.echo("  Use 'servagent oauth renew' to regenerate credentials")
        click.echo("  or  'servagent oauth remove' to disable OAuth.")
        raise SystemExit(1)

    client_id, client_secret = _generate_credentials()

    _env_set(env_path, "SERVAGENT_OAUTH_ISSUER_URL", issuer_url)
    _env_set(env_path, "SERVAGENT_OAUTH_CLIENT_ID", client_id)
    _env_set(env_path, "SERVAGENT_OAUTH_CLIENT_SECRET", client_secret)

    click.echo()
    click.echo("  OAuth credentials generated and written to " + click.style(str(env_path), fg="cyan"))
    click.echo()
    click.echo(f"    Issuer URL:    {click.style(issuer_url, fg='green')}")
    click.echo(f"    Client ID:     {click.style(client_id, fg='green')}")
    click.echo(f"    Client Secret: {click.style(client_secret, fg='green')}")
    click.echo()
    click.echo("  Restart the server for changes to take effect:")
    if shutil.which("systemctl"):
        click.echo("    sudo systemctl restart servagent")
    else:
        click.echo("    servagent run")
    click.echo()


@oauth.command()
@click.option("--env-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to the .env file (auto-detected if omitted).")
@click.confirmation_option(prompt="This will invalidate all existing OAuth sessions. Continue?")
def renew(env_file: str | None) -> None:
    """Regenerate OAuth credentials (invalidates existing sessions)."""
    env_path = Path(env_file) if env_file else _find_env_file()
    if env_path is None:
        click.echo("Error: .env file not found.", err=True)
        raise SystemExit(1)

    existing_id = _env_get(env_path, "SERVAGENT_OAUTH_CLIENT_ID")
    if not existing_id:
        click.echo("  OAuth is not configured. Use 'servagent oauth setup' first.", err=True)
        raise SystemExit(1)

    client_id, client_secret = _generate_credentials()

    _env_set(env_path, "SERVAGENT_OAUTH_CLIENT_ID", client_id)
    _env_set(env_path, "SERVAGENT_OAUTH_CLIENT_SECRET", client_secret)

    click.echo()
    click.echo("  OAuth credentials renewed in " + click.style(str(env_path), fg="cyan"))
    click.echo()
    click.echo(f"    Client ID:     {click.style(client_id, fg='green')}")
    click.echo(f"    Client Secret: {click.style(client_secret, fg='green')}")
    click.echo()

    # Remove OAuth database to clear old tokens
    from servagent.config import settings
    db_path = settings.oauth_database_path
    if db_path.exists():
        db_path.unlink()
        click.echo(f"  OAuth database removed: {db_path}")

    click.echo()
    click.echo("  Restart the server for changes to take effect:")
    if shutil.which("systemctl"):
        click.echo("    sudo systemctl restart servagent")
    else:
        click.echo("    servagent run")
    click.echo()
    click.echo(click.style("  All existing OAuth sessions have been invalidated.", fg="yellow"))
    click.echo()


@oauth.command()
@click.option("--env-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to the .env file (auto-detected if omitted).")
@click.option("--keep-db", is_flag=True, help="Keep the OAuth database file.")
@click.confirmation_option(prompt="This will disable OAuth. Continue?")
def remove(env_file: str | None, keep_db: bool) -> None:
    """Disable OAuth and remove credentials from .env."""
    env_path = Path(env_file) if env_file else _find_env_file()
    if env_path is None:
        click.echo("Error: .env file not found.", err=True)
        raise SystemExit(1)

    existing_id = _env_get(env_path, "SERVAGENT_OAUTH_CLIENT_ID")
    if not existing_id:
        click.echo("  OAuth is not configured. Nothing to remove.")
        return

    _env_comment_out(env_path, "SERVAGENT_OAUTH_ISSUER_URL")
    _env_comment_out(env_path, "SERVAGENT_OAUTH_CLIENT_ID")
    _env_comment_out(env_path, "SERVAGENT_OAUTH_CLIENT_SECRET")

    click.echo()
    click.echo("  OAuth credentials commented out in " + click.style(str(env_path), fg="cyan"))

    if not keep_db:
        from servagent.config import settings
        db_path = settings.oauth_database_path
        if db_path.exists():
            db_path.unlink()
            click.echo(f"  OAuth database removed: {db_path}")

    click.echo()
    click.echo("  Restart the server for changes to take effect:")
    if shutil.which("systemctl"):
        click.echo("    sudo systemctl restart servagent")
    else:
        click.echo("    servagent run")
    click.echo()
    click.echo(click.style("  OAuth has been disabled.", fg="yellow"))
    click.echo()
