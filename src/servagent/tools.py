"""MCP tools for remote server administration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from servagent.config import settings

logger = logging.getLogger(__name__)

# Complete list of all available tool names (used for validation).
ALL_TOOL_NAMES: set[str] = {
    "execute_command",
    "read_file",
    "write_file",
    "edit_file",
    "service_action",
    "tail_file",
}


def _enabled(name: str, enabled_tools: set[str] | None) -> bool:
    """Return True if *name* should be registered."""
    if enabled_tools is None:
        return True  # None means "all"
    return name in enabled_tools


def register_tools(mcp: FastMCP, enabled_tools: set[str] | None = None) -> int:
    """Register server-administration tools on the MCP instance.

    Args:
        mcp: The FastMCP server instance.
        enabled_tools: Set of tool names to register. ``None`` means all tools.

    Returns:
        Number of tools registered.
    """
    count = 0

    # ------------------------------------------------------------------
    # 1. Command execution
    # ------------------------------------------------------------------

    if _enabled("execute_command", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def execute_command(
            command: str,
            work_dir: str = "",
            timeout: int = 0,
            ctx: Context = None,
        ) -> dict:
            """Execute a shell command on the **remote** server and return its output.

            This is the general-purpose tool for remote administration. The command
            runs in a shell on the remote host and you receive stdout, stderr, and
            the exit code. Use it for anything that doesn't have a dedicated tool:
            installing packages, running scripts, managing users, docker, git, etc.

            Args:
                command: The shell command to execute (e.g. "ls -la /var/log").
                work_dir: Working directory for the command. Defaults to server work_dir.
                timeout: Timeout in seconds (0 = use server default).

            Note: exit_code 0 = success. Non-zero = failure — read stderr before retrying.
            If timed_out is true, the command was killed; retry once with a larger timeout
            or report to the user.
            """
            cwd = Path(work_dir).expanduser().resolve() if work_dir else settings.working_directory
            timeout = timeout or settings.command_timeout

            if ctx:
                await ctx.info(f"Executing: {command}")

            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd),
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout}s",
                    "timed_out": True,
                }

            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")

            # Truncate large outputs
            if len(stdout_text) > settings.max_output_size:
                stdout_text = stdout_text[: settings.max_output_size] + "\n... [truncated]"
            if len(stderr_text) > settings.max_output_size:
                stderr_text = stderr_text[: settings.max_output_size] + "\n... [truncated]"

            return {
                "exit_code": proc.returncode,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "timed_out": False,
            }

        count += 1

    # ------------------------------------------------------------------
    # 2. File operations
    # ------------------------------------------------------------------

    if _enabled("read_file", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def read_file(path: str, offset: int = 0, limit: int = 0) -> dict:
            """Read a text file on the **remote** server.

            Args:
                path: Absolute or relative file path on the remote server.
                offset: Line number to start reading from (0-based).
                limit: Maximum number of lines to return (0 = all).
            """
            p = Path(path).expanduser().resolve()
            if not p.is_file():
                return {"error": f"File not found: {p}"}

            text = p.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines(keepends=True)

            if offset:
                lines = lines[offset:]
            if limit:
                lines = lines[:limit]

            return {
                "path": str(p),
                "content": "".join(lines),
                "total_lines": len(text.splitlines()),
            }

        count += 1

    if _enabled("write_file", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )
        async def write_file(path: str, content: str, create_dirs: bool = True) -> dict:
            """Create or overwrite a text file on the **remote** server.

            Args:
                path: Absolute or relative file path on the remote server.
                content: Text content to write.
                create_dirs: Create parent directories if they don't exist.
            """
            p = Path(path).expanduser().resolve()
            if create_dirs:
                p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return {"path": str(p), "bytes_written": len(content.encode("utf-8"))}

        count += 1

    if _enabled("edit_file", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def edit_file(path: str, old_string: str, new_string: str) -> dict:
            """Find and replace a string in a file on the **remote** server.

            All occurrences of ``old_string`` are replaced.

            Args:
                path: File path on the remote server.
                old_string: The exact text to find.
                new_string: The replacement text.

            Note: If old_string is not found, re-read the file first — content
            may differ from expectations.
            """
            p = Path(path).expanduser().resolve()
            if not p.is_file():
                return {"error": f"File not found: {p}"}

            text = p.read_text(encoding="utf-8", errors="replace")
            count_ = text.count(old_string)
            if count_ == 0:
                return {"error": "old_string not found in file", "path": str(p)}

            new_text = text.replace(old_string, new_string)
            p.write_text(new_text, encoding="utf-8")
            return {"path": str(p), "replacements": count_}

        count += 1

    # ------------------------------------------------------------------
    # 3. Service management (systemd)
    # ------------------------------------------------------------------

    if _enabled("service_action", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def service_action(service: str, action: str) -> dict:
            """Manage a systemd service on the **remote** server.

            Args:
                service: Service name (e.g. "nginx", "postgresql").
                action: One of: status, start, stop, restart, enable, disable.
            """
            allowed_actions = {"status", "start", "stop", "restart", "enable", "disable"}
            if action not in allowed_actions:
                return {"error": f"Invalid action. Allowed: {', '.join(sorted(allowed_actions))}"}

            cmd = f"systemctl {action} {service}"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            return {
                "service": service,
                "action": action,
                "exit_code": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            }

        count += 1

    # ------------------------------------------------------------------
    # 4. Log tailing
    # ------------------------------------------------------------------

    if _enabled("tail_file", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def tail_file(
            path: str = "",
            lines: int = 50,
            follow: bool = False,
            follow_timeout: int = 10,
            journalctl_unit: str = "",
            journalctl_args: str = "",
            ctx: Context = None,
        ) -> dict:
            """Tail a log file or journalctl unit on the **remote** server.

            Use ``path`` for files or ``journalctl_unit`` for systemd journals (mutually exclusive).

            Args:
                path: File to tail (e.g. "/var/log/syslog").
                lines: Number of trailing lines (default 50).
                journalctl_unit: Systemd unit to tail (e.g. "nginx").
                journalctl_args: Extra journalctl flags (e.g. "--since '5 min ago'").
                follow: Keep reading new lines for follow_timeout seconds.
                follow_timeout: Seconds to follow (default 10, max 60).
            """
            if not path and not journalctl_unit:
                return {"error": "Provide either 'path' or 'journalctl_unit'."}
            if path and journalctl_unit:
                return {"error": "'path' and 'journalctl_unit' are mutually exclusive."}

            follow_timeout = min(max(follow_timeout, 1), 60)

            # Build the shell command
            if path:
                p = Path(path).expanduser().resolve()
                if not p.is_file():
                    return {"error": f"File not found: {p}"}
                if follow:
                    cmd = f"tail -n {lines} -f {p}"
                else:
                    cmd = f"tail -n {lines} {p}"
            else:
                # journalctl mode
                unit_flag = f"-u {journalctl_unit}"
                follow_flag = "-f" if follow else ""
                cmd = f"journalctl {unit_flag} -n {lines} --no-pager {follow_flag} {journalctl_args}".strip()

            if ctx:
                await ctx.info(f"Running: {cmd}")

            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                if follow:
                    # Read output until follow_timeout expires, then kill the process.
                    collected_out: list[bytes] = []
                    collected_err: list[bytes] = []

                    async def _read_stream(stream, buf):
                        try:
                            async for line in stream:
                                buf.append(line)
                        except asyncio.CancelledError:
                            pass

                    read_out = asyncio.create_task(_read_stream(proc.stdout, collected_out))
                    read_err = asyncio.create_task(_read_stream(proc.stderr, collected_err))

                    await asyncio.sleep(follow_timeout)

                    # Terminate the tailing process
                    proc.kill()
                    await proc.wait()
                    read_out.cancel()
                    read_err.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await read_out
                    with contextlib.suppress(asyncio.CancelledError):
                        await read_err

                    stdout_text = b"".join(collected_out).decode("utf-8", errors="replace")
                    stderr_text = b"".join(collected_err).decode("utf-8", errors="replace")
                else:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=settings.command_timeout,
                    )
                    stdout_text = stdout.decode("utf-8", errors="replace")
                    stderr_text = stderr.decode("utf-8", errors="replace")

            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "error": f"Command timed out after {settings.command_timeout}s",
                    "source": path or journalctl_unit,
                }

            # Truncate large outputs
            if len(stdout_text) > settings.max_output_size:
                stdout_text = stdout_text[: settings.max_output_size] + "\n... [truncated]"

            return {
                "source": path or f"journalctl:{journalctl_unit}",
                "lines_requested": lines,
                "follow": follow,
                "follow_timeout": follow_timeout if follow else None,
                "output": stdout_text,
                "stderr": stderr_text if stderr_text else None,
            }

        count += 1

    return count
