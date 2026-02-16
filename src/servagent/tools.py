"""MCP tools for remote server administration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import platform
import shutil
import signal
from base64 import b64decode, b64encode
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
    "list_directory",
    "move_path",
    "copy_path",
    "delete_path",
    "read_file_binary",
    "write_file_binary",
    "upload_file",
    "list_processes",
    "kill_process",
    "system_info",
    "network_info",
    "service_action",
    "tail_file",
    "get_environment",
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
            """Read the contents of a text file on the **remote** server's filesystem.

            Returns the file content along with total line count. For binary files,
            use ``read_file_binary`` instead.

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
            """Write text content to a file on the **remote** server (creates or overwrites).

            Parent directories are created automatically by default. For binary
            files, use ``write_file_binary`` instead.

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

            All occurrences of ``old_string`` are replaced. Returns the number of
            replacements made.

            Args:
                path: File path on the remote server.
                old_string: The exact text to find.
                new_string: The replacement text.

            Note: If old_string is not found, re-read the file to verify its current
            content before retrying. Do not retry with the same old_string — the file
            content may differ from expectations.
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

    if _enabled("list_directory", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def list_directory(path: str = ".", recursive: bool = False) -> dict:
            """List files and directories on the **remote** server at the given path.

            Returns each entry's name, type (file/directory) and size.

            Args:
                path: Directory path on the remote server (default: server working directory).
                recursive: If true, list recursively.
            """
            p = Path(path).expanduser().resolve()
            if not p.is_dir():
                return {"error": f"Not a directory: {p}"}

            entries = []
            try:
                items = p.rglob("*") if recursive else p.iterdir()
                for item in sorted(items):
                    try:
                        stat = item.stat()
                        entries.append({
                            "name": str(item.relative_to(p)),
                            "type": "directory" if item.is_dir() else "file",
                            "size": stat.st_size if item.is_file() else None,
                        })
                    except PermissionError:
                        entries.append({
                            "name": str(item.relative_to(p)),
                            "type": "unknown",
                            "error": "permission denied",
                        })
            except PermissionError:
                return {"error": f"Permission denied: {p}"}

            return {"path": str(p), "entries": entries}

        count += 1

    if _enabled("move_path", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def move_path(source: str, destination: str) -> dict:
            """Move or rename a file or directory on the **remote** server.

            Args:
                source: Source path on the remote server.
                destination: Destination path on the remote server.
            """
            src = Path(source).expanduser().resolve()
            dst = Path(destination).expanduser().resolve()
            if not src.exists():
                return {"error": f"Source not found: {src}"}
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            return {"source": str(src), "destination": str(dst)}

        count += 1

    if _enabled("copy_path", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )
        async def copy_path(source: str, destination: str) -> dict:
            """Copy a file or directory on the **remote** server.

            Directories are copied recursively. Parent directories of the
            destination are created automatically.

            Args:
                source: Source path on the remote server.
                destination: Destination path on the remote server.
            """
            src = Path(source).expanduser().resolve()
            dst = Path(destination).expanduser().resolve()
            if not src.exists():
                return {"error": f"Source not found: {src}"}
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(str(src), str(dst))
            else:
                shutil.copy2(str(src), str(dst))
            return {"source": str(src), "destination": str(dst)}

        count += 1

    if _enabled("delete_path", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def delete_path(path: str) -> dict:
            """Delete a file or directory on the **remote** server.

            Directories are removed recursively. IRREVERSIBLE. Confirm with the
            user before deleting directories or critical files.

            Args:
                path: Path to delete on the remote server.
            """
            p = Path(path).expanduser().resolve()
            if not p.exists():
                return {"error": f"Not found: {p}"}
            if p.is_dir():
                shutil.rmtree(str(p))
            else:
                p.unlink()
            return {"deleted": str(p)}

        count += 1

    if _enabled("read_file_binary", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def read_file_binary(path: str) -> dict:
            """Read a binary file on the **remote** server and return its content as base64.

            Use this for non-text files (images, archives, compiled binaries, etc.).
            For text files, prefer ``read_file``.

            Args:
                path: File path on the remote server.
            """
            p = Path(path).expanduser().resolve()
            if not p.is_file():
                return {"error": f"File not found: {p}"}
            data = p.read_bytes()
            return {
                "path": str(p),
                "size": len(data),
                "content_base64": b64encode(data).decode("ascii"),
            }

        count += 1

    if _enabled("write_file_binary", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )
        async def write_file_binary(path: str, content_base64: str, create_dirs: bool = True) -> dict:
            """Write binary content (base64-encoded) to a file on the **remote** server.

            Use this to upload non-text files (images, archives, etc.) to the remote
            host. For text files, prefer ``write_file``.

            Args:
                path: File path on the remote server.
                content_base64: Base64-encoded content.
                create_dirs: Create parent directories if they don't exist.
            """
            p = Path(path).expanduser().resolve()
            if create_dirs:
                p.parent.mkdir(parents=True, exist_ok=True)
            data = b64decode(content_base64)
            p.write_bytes(data)
            return {"path": str(p), "bytes_written": len(data)}

        count += 1

    # ------------------------------------------------------------------
    # 3. Process management
    # ------------------------------------------------------------------

    if _enabled("list_processes", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def list_processes(filter_name: str = "") -> dict:
            """List running processes on the **remote** server (``ps aux`` output).

            Use this to inspect what is running on the remote host. Combine with
            ``kill_process`` to manage processes.

            Returns the full process list in one call. Do not call again unless
            you expect the process state to have changed.

            Args:
                filter_name: Optional string to filter process names (case-insensitive grep).
            """
            cmd = "ps aux"
            if filter_name:
                cmd += f" | head -1; ps aux | grep -i '{filter_name}' | grep -v grep"

            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return {"processes": stdout.decode("utf-8", errors="replace")}

        count += 1

    if _enabled("kill_process", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
        async def kill_process(pid: int, sig: int = 15) -> dict:
            """Send a signal to a process on the **remote** server.

            Use SIGTERM (15) for a graceful stop or SIGKILL (9) to force-kill.
            Find the PID first with ``list_processes``.

            Args:
                pid: Process ID on the remote server.
                sig: Signal number (15=SIGTERM, 9=SIGKILL).

            Note: "Permission denied" = do not retry, requires elevated privileges.
            "Process not found" = process already exited, no further action needed.
            """
            try:
                os.kill(pid, sig)
                return {"pid": pid, "signal": sig, "status": "signal sent"}
            except ProcessLookupError:
                return {"error": f"Process {pid} not found"}
            except PermissionError:
                return {"error": f"Permission denied for PID {pid}"}

        count += 1

    # ------------------------------------------------------------------
    # 4. System information
    # ------------------------------------------------------------------

    if _enabled("system_info", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def system_info() -> dict:
            """Return system information about the **remote** server (OS, hostname, memory, disk, uptime).

            Returns static system information. Call once per session — values do
            not change between calls."""
            info: dict = {
                "platform": platform.platform(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "python_version": platform.python_version(),
            }

            # Memory info
            proc = await asyncio.create_subprocess_shell(
                "free -h 2>/dev/null || vm_stat 2>/dev/null",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            info["memory"] = stdout.decode("utf-8", errors="replace").strip()

            # Disk info
            proc = await asyncio.create_subprocess_shell(
                "df -h /",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            info["disk"] = stdout.decode("utf-8", errors="replace").strip()

            # Uptime
            proc = await asyncio.create_subprocess_shell(
                "uptime",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            info["uptime"] = stdout.decode("utf-8", errors="replace").strip()

            return info

        count += 1

    if _enabled("network_info", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def network_info() -> dict:
            """Return network configuration of the **remote** server (interfaces and listening ports).

            Shows IP addresses, network interfaces, and all TCP ports in LISTEN state.
            Call once per session unless you expect network changes."""
            result: dict = {}

            proc = await asyncio.create_subprocess_shell(
                "ip addr 2>/dev/null || ifconfig 2>/dev/null",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            result["interfaces"] = stdout.decode("utf-8", errors="replace").strip()

            proc = await asyncio.create_subprocess_shell(
                "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            result["listening_ports"] = stdout.decode("utf-8", errors="replace").strip()

            return result

        count += 1

    # ------------------------------------------------------------------
    # 5. Service management (systemd)
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

            Start, stop, restart or check the status of any systemd unit.
            Requires the server process to have sufficient privileges (see
            ``--full-access`` installation flag).

            Args:
                service: Service name (e.g. "nginx", "postgresql").
                action: One of: status, start, stop, restart, enable, disable.

            Note: "status" is read-only. Other actions modify service state.
            After start/restart, verify with "status" before assuming success.
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
    # 6. Log tailing
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

            Returns the last N lines, optionally following for new output in
            real time. Ideal for debugging services, watching deployment logs,
            or monitoring application output on the remote host.

            Use EITHER ``path`` to tail a file (e.g. /var/log/syslog) OR
            ``journalctl_unit`` to tail a systemd journal (e.g. "nginx").
            When ``follow`` is True the command runs for up to ``follow_timeout``
            seconds, capturing any new lines that appear during that window.

            Args:
                path: File to tail on the remote server (e.g. "/var/log/syslog"). Mutually exclusive with journalctl_unit.
                lines: Number of trailing lines to return (default 50).
                journalctl_unit: Systemd unit name to tail via journalctl (e.g. "nginx"). Mutually exclusive with path.
                journalctl_args: Extra flags passed to journalctl (e.g. "--since '5 min ago'" or "-p err").
                follow: If true, keep reading new lines for up to follow_timeout seconds.
                follow_timeout: Seconds to follow before stopping (default 10, max 60). Only used when follow=True.
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

    # ------------------------------------------------------------------
    # 7. File upload (via HTTP endpoint)
    # ------------------------------------------------------------------

    if _enabled("upload_file", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )
        async def upload_file(
            local_path: str,
            remote_path: str,
            create_dirs: bool = True,
        ) -> dict:
            """Upload a file to the **remote** server via the ``/upload`` HTTP endpoint.

            This tool is a convenience wrapper: it reads a local file and writes it
            to the specified remote path. For AI clients that need to push a file
            from another source, use the ``/upload`` endpoint directly with
            ``multipart/form-data`` (fields: ``file``, ``path``, ``create_dirs``).

            For text content you already have in memory, prefer ``write_file`` or
            ``write_file_binary`` instead.

            Args:
                local_path: Path to the file on the remote server's local filesystem to read from.
                remote_path: Destination path on the remote server to write to.
                create_dirs: Create parent directories if they don't exist.
            """
            src = Path(local_path).expanduser().resolve()
            if not src.is_file():
                return {"error": f"Source file not found: {src}"}

            dst = Path(remote_path).expanduser().resolve()
            if create_dirs:
                dst.parent.mkdir(parents=True, exist_ok=True)

            data = src.read_bytes()

            max_size = settings.upload_max_size
            if len(data) > max_size:
                return {"error": f"File size ({len(data)} bytes) exceeds maximum ({max_size} bytes)"}

            dst.write_bytes(data)
            return {
                "source": str(src),
                "destination": str(dst),
                "bytes_written": len(data),
            }

        count += 1

    # ------------------------------------------------------------------
    # 8. Environment
    # ------------------------------------------------------------------

    if _enabled("get_environment", enabled_tools):

        @mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=True,
                openWorldHint=False,
            ),
        )
        async def get_environment(filter_key: str = "") -> dict:
            """Return environment variables from the **remote** server's process.

            Useful for checking configuration, paths, or runtime settings on the
            remote host.

            Args:
                filter_key: Optional substring to filter variable names (case-insensitive).
            """
            env = dict(os.environ)
            if filter_key:
                env = {k: v for k, v in env.items() if filter_key.upper() in k.upper()}
            return {"variables": env}

        count += 1

    return count
