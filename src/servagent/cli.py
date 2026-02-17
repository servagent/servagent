"""Servagent CLI — command-line interface with subcommands."""

from __future__ import annotations

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
