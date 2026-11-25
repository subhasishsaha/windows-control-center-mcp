"""Windows Control Center Local MCP Server (Strictly Stdio Transport).

Provides AGY CLI / Antigravity with full, authorized access to your Windows computer locally:
- PowerShell & CMD command execution (kernel-sandboxed)
- Python script runner (inside virtual environment, kernel-sandboxed)
- Process monitoring and management (CPU, RAM, safe termination)
- File system read/write/search/delete/copy
- System status (CPU, RAM, Disks, Battery, Uptime)
- Network configuration and connectivity inspection
- Desktop automation (Application launcher, Clipboard, Notifications, Screenshots)

STRICT HOST STDIO ONLY: Runs locally on the host machine using standard input/output (stdio).
Zero network ports, zero HTTP endpoints, zero remote surface.
"""

import argparse
from importlib.metadata import PackageNotFoundError, version as _pkg_version
import json
import logging
import sys
from typing import Annotated, Any, Dict, List, Literal, Optional
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

# Import underlying tool implementations
from tools.command_tools import (
    execute_cmd as _execute_cmd,
    execute_elevated_command as _execute_elevated_command,
    execute_powershell as _execute_powershell,
    execute_python as _execute_python,
    get_security_status as _get_security_status,
    kill_process as _kill_process,
    list_processes as _list_processes,
)
from tools.desktop_tools import (
    get_clipboard as _get_clipboard,
    launch_app as _launch_app,
    set_clipboard as _set_clipboard,
    show_notification as _show_notification,
    take_screenshot as _take_screenshot,
)
from tools.filesystem_tools import (
    copy_or_move as _copy_or_move,
    delete_file_or_dir as _delete_file_or_dir,
    get_file_info as _get_file_info,
    list_directory as _list_directory,
    read_file as _read_file,
    search_files as _search_files,
    write_file as _write_file,
)
from tools.system_tools import (
    get_environment as _get_environment,
    get_network_info as _get_network_info,
    get_system_info as _get_system_info,
)

# Configure logging to sys.stderr exclusively so stdout remains clean for MCP JSON-RPC
logger = logging.getLogger("WindowsMCP")
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)

def _get_server_version() -> str:
    try:
        return _pkg_version("windows-control-center-mcp")
    except PackageNotFoundError:
        return "1.0.1"


# Initialize FastMCP Server
mcp = FastMCP(
    name="Windows-Control-Center",
    version=_get_server_version(),
    instructions=(
        "Windows Control Center MCP Server. This server allows the AI assistant to interact "
        "with the user's Windows PC: executing shell commands (PowerShell/CMD), running Python scripts, "
        "reading/writing files, monitoring system health (CPU, RAM, Disks, Battery), inspecting "
        "and managing processes, reading/writing clipboard text, launching applications/URLs, "
        "taking desktop screenshots, and displaying desktop notifications."
    ),
)

_READ_ONLY_LOCAL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_READ_ONLY_NETWORK = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
_DESTRUCTIVE_EXEC = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)
_DESTRUCTIVE_LOCAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
_WRITE_IDEMPOTENT_LOCAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_ACTION_LOCAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
_ACTION_OPEN_WORLD = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)


# ==========================================
# Category 1: Command & Process Execution
# ==========================================


@mcp.tool(annotations=_DESTRUCTIVE_EXEC, tags={"command", "shell", "execution"})
def execute_powershell(
    command: Annotated[str, Field(min_length=1, description="The PowerShell command, cmdlet, or script block to run.")],
    working_dir: Optional[str] = None,
    timeout: Annotated[int, Field(ge=1, le=3600, description="Maximum execution time in seconds before terminating.")] = 120,
    elevate: bool = False,
) -> Dict[str, Any]:
    """Execute a PowerShell command or script on the Windows computer.

    Execution is strictly and immutably isolated within a Windows Job Object sandbox with kernel memory and process quotas.
    Protected by security guardrails against RCE, disk formatting, and malicious payloads.

    Args:
        command: The PowerShell command, cmdlet, or script block to run.
        working_dir: Working directory path (default: current directory).
        timeout: Maximum execution time in seconds before terminating (default: 120).
        elevate: Whether to request Windows administrative privilege elevation (default: False).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', 'execution_time_seconds', 'timed_out', and 'sandboxed'.
    """
    logger.info("Executing PowerShell command (elevate=%s): %s", elevate, command[:100])
    return _execute_powershell(command=command, working_dir=working_dir, timeout=timeout, elevate=elevate)


@mcp.tool(annotations=_DESTRUCTIVE_EXEC, tags={"command", "elevated", "execution"})
def execute_elevated_command(
    command: Annotated[str, Field(min_length=1, description="PowerShell command or script to execute with elevation.")],
    timeout: Annotated[int, Field(ge=1, le=3600, description="Maximum execution time in seconds.")] = 120,
    working_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a command with Administrator / Elevated privileges via Windows UAC.

    Validates against security guardrails before granting elevation.

    Args:
        command: PowerShell command or script to execute with elevation.
        timeout: Maximum execution time in seconds (default: 120).
        working_dir: Optional working directory for command execution.

    Returns:
        Dictionary with stdout, stderr, return_code, execution_time_seconds, and elevation status.
    """
    logger.warning("Executing ELEVATED command: %s", command[:100])
    return _execute_elevated_command(command=command, timeout=timeout, working_dir=working_dir)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"security", "read-only"})
def get_security_status() -> Dict[str, Any]:
    """Inspect active security guardrails, administrative status, and safeguards.

    Returns:
        Dictionary with is_admin, strict_mode, allow_elevation, and protection metrics.
    """
    return _get_security_status()


@mcp.tool(annotations=_DESTRUCTIVE_EXEC, tags={"command", "shell", "execution"})
def execute_cmd(
    command: Annotated[str, Field(min_length=1, description="The cmd.exe command to run.")],
    working_dir: Optional[str] = None,
    timeout: Annotated[int, Field(ge=1, le=3600, description="Maximum execution time in seconds.")] = 120,
) -> Dict[str, Any]:
    """Execute a Command Prompt (cmd.exe) command or batch line on Windows.

    Execution is strictly and immutably isolated within a Windows Job Object sandbox with kernel memory and process quotas.

    Args:
        command: The cmd.exe command to run.
        working_dir: Working directory path (default: current directory).
        timeout: Maximum execution time in seconds (default: 120).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', 'timed_out', and 'sandboxed'.
    """
    logger.info("Executing CMD command: %s", command[:100])
    return _execute_cmd(command=command, working_dir=working_dir, timeout=timeout)


@mcp.tool(annotations=_DESTRUCTIVE_EXEC, tags={"command", "python", "execution"})
def execute_python(
    code: Annotated[str, Field(min_length=1, description="Python source code snippet to execute.")],
    timeout: Annotated[int, Field(ge=1, le=3600, description="Maximum seconds to wait before terminating.")] = 60,
) -> Dict[str, Any]:
    """Execute Python code snippet directly inside this server's virtual environment.

    Execution is strictly and immutably isolated within a Windows Job Object sandbox with kernel memory and process quotas.

    Args:
        code: Python source code snippet to execute.
        timeout: Maximum seconds to wait before terminating (default: 60).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', 'timed_out', and 'sandboxed'.
    """
    logger.info("Executing Python snippet (%d characters)", len(code))
    return _execute_python(code=code, timeout=timeout)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"process", "monitoring", "read-only"})
def list_processes(
    filter_name: Optional[str] = None,
    sort_by: Literal["cpu", "memory"] = "cpu",
    limit: Annotated[int, Field(ge=1, le=500, description="Maximum number of processes to return.")] = 25,
) -> List[Dict[str, Any]]:
    """List running processes on the system with PID, CPU %, memory usage, and user info.

    Args:
        filter_name: Optional case-insensitive substring to filter processes (e.g., 'chrome', 'python', 'code').
        sort_by: Metric to sort by: 'cpu' or 'memory' (default: 'cpu').
        limit: Maximum number of processes to return (default: 25).

    Returns:
        List of process objects containing pid, name, cpu_percent, memory_mb, status, username.
    """
    return _list_processes(filter_name=filter_name, sort_by=sort_by, limit=limit)


@mcp.tool(annotations=_DESTRUCTIVE_LOCAL, tags={"process", "destructive"})
def kill_process(
    pid: Annotated[Optional[int], Field(ge=0, description="Numeric Process ID to terminate.")] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """Terminate a running process by Process ID (PID) or process executable name.

    Guards critical Windows system processes (csrss, lsass, etc.) and the MCP server itself.

    Args:
        pid: The numeric Process ID to kill.
        name: Name of the process image to terminate (e.g., 'notepad.exe').

    Returns:
        Dictionary confirming killed processes and any permission/not-found errors.
    """
    logger.info("Killing process pid=%s, name=%s", pid, name)
    return _kill_process(pid=pid, name=name)


# ==========================================
# Category 2: File System Operations
# ==========================================


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"filesystem", "read-only"})
def read_file(
    path: Annotated[str, Field(min_length=1, description="Path to the target file (relative or absolute).")],
    start_line: Annotated[int, Field(ge=1, description="1-indexed line number to start reading from.")] = 1,
    max_lines: Annotated[int, Field(ge=1, le=5000, description="Maximum number of lines to return.")] = 500,
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Read contents of a file on the local machine with line-range pagination.

    Args:
        path: Path to the target file (relative or absolute).
        start_line: 1-indexed line number to start reading from (default: 1).
        max_lines: Maximum number of lines to return (default: 500).
        encoding: File encoding (default: 'utf-8').

    Returns:
        Dictionary with file content, path, total_lines, and truncation status.
    """
    return _read_file(path=path, start_line=start_line, max_lines=max_lines, encoding=encoding)


@mcp.tool(annotations=_DESTRUCTIVE_LOCAL, tags={"filesystem", "write"})
def write_file(
    path: Annotated[str, Field(min_length=1, description="Path where the file should be written.")],
    content: str,
    mode: Literal["w", "a"] = "w",
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Write or append text content to a file. Automatically creates parent directories.

    Args:
        path: Path where the file should be written.
        content: Text content to write into the file.
        mode: 'w' to overwrite existing file, or 'a' to append (default: 'w').
        encoding: File encoding (default: 'utf-8').

    Returns:
        Dictionary with status, bytes written, and absolute path.
    """
    logger.info("Writing file %s (mode=%s, %d characters)", path, mode, len(content))
    return _write_file(path=path, content=content, mode=mode, encoding=encoding)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"filesystem", "read-only"})
def list_directory(
    path: str = ".",
    recursive: bool = False,
    max_depth: Annotated[int, Field(ge=1, le=20, description="Maximum recursion depth when recursive=True.")] = 2,
    max_items: Annotated[int, Field(ge=1, le=1000, description="Maximum items to return.")] = 100,
) -> Dict[str, Any]:
    """List files and folders in a directory with file sizes and modification timestamps.

    Args:
        path: Directory path to inspect (default: current directory).
        recursive: Whether to recursively scan child directories (default: False).
        max_depth: Maximum recursion depth when recursive=True (default: 2).
        max_items: Maximum items to return (default: 100).

    Returns:
        Dictionary with item metadata (name, path, is_dir, size_bytes, modified).
    """
    return _list_directory(path=path, recursive=recursive, max_depth=max_depth, max_items=max_items)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"filesystem", "search", "read-only"})
def search_files(
    pattern: Annotated[str, Field(min_length=1, description="Wildcard search pattern (e.g., '*.docx', 'config*.json').")],
    root_path: str = ".",
    max_results: Annotated[int, Field(ge=1, le=500, description="Maximum results to return.")] = 50,
) -> Dict[str, Any]:
    """Search for files and directories matching a wildcard pattern (e.g. '*.py', 'report*.*').

    Args:
        pattern: Wildcard search pattern (e.g., '*.docx', 'config*.json').
        root_path: Root folder where search begins (default: current directory).
        max_results: Maximum results to return (default: 50).

    Returns:
        Dictionary with count and list of matched files.
    """
    return _search_files(pattern=pattern, root_path=root_path, max_results=max_results)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"filesystem", "read-only"})
def get_file_info(
    path: Annotated[str, Field(min_length=1, description="Path to inspect.")],
) -> Dict[str, Any]:
    """Get detailed metadata for a file or directory (size, timestamps, permissions, extension).

    Args:
        path: Path to inspect.

    Returns:
        Dictionary with size, created, modified, accessed, and type information.
    """
    return _get_file_info(path=path)


@mcp.tool(annotations=_DESTRUCTIVE_LOCAL, tags={"filesystem", "destructive"})
def delete_file_or_dir(
    path: Annotated[str, Field(min_length=1, description="Path of the file or directory to delete.")],
    recursive: bool = False,
) -> Dict[str, Any]:
    """Delete a file or directory on the computer safely.

    Protected against accidental or malicious deletion of system directories or drive roots.

    Args:
        path: Path of the file or directory to delete.
        recursive: If True, delete non-empty directories recursively (default: False).

    Returns:
        Dictionary confirming deletion action or error details.
    """
    logger.warning("Deleting path: %s (recursive=%s)", path, recursive)
    return _delete_file_or_dir(path=path, recursive=recursive)


@mcp.tool(annotations=_DESTRUCTIVE_LOCAL, tags={"filesystem", "write"})
def copy_or_move(
    source: Annotated[str, Field(min_length=1, description="Source file or folder path.")],
    destination: Annotated[str, Field(min_length=1, description="Destination file or folder path.")],
    action: Literal["copy", "move"] = "copy",
) -> Dict[str, Any]:
    """Copy or move a file or directory from source to destination.

    Validates that destination (and source if moving) is not a protected system path.

    Args:
        source: Source file or folder path.
        destination: Destination file or folder path.
        action: 'copy' or 'move' (default: 'copy').

    Returns:
        Dictionary confirming operation status and paths.
    """
    logger.info("%s from %s to %s", action.capitalize(), source, destination)
    return _copy_or_move(source=source, destination=destination, action=action)


# ==========================================
# Category 3: System & Hardware Monitoring
# ==========================================


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"system", "monitoring", "read-only"})
def get_system_info() -> Dict[str, Any]:
    """Get full system health: OS version, CPU cores & usage, RAM usage, all disk drives, and battery.

    Returns:
        Dictionary with detailed OS, CPU, Memory, Disk drives (C:, D:, E: etc.), and Battery stats.
    """
    return _get_system_info()


@mcp.tool(annotations=_READ_ONLY_NETWORK, tags={"system", "network", "read-only"})
def get_network_info() -> Dict[str, Any]:
    """Get network adapters, local IPv4 addresses, and check active internet connectivity.

    Returns:
        Dictionary with hostname, active adapters, IPv4 addresses, and internet ping status.
    """
    return _get_network_info()


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"system", "read-only"})
def get_environment(var_name: Optional[str] = None) -> Dict[str, Any]:
    """Get a specific environment variable or view common system environment variables.

    Masks sensitive secrets (keys, passwords, tokens) when STRICT_MODE is active.

    Args:
        var_name: Specific variable name to retrieve. If None, lists standard system variables.

    Returns:
        Dictionary with variable names and values.
    """
    return _get_environment(var_name=var_name)


# ==========================================
# Category 4: Desktop & GUI Automation
# ==========================================


@mcp.tool(annotations=_ACTION_OPEN_WORLD, tags={"desktop", "automation"})
def launch_app(
    target: Annotated[str, Field(min_length=1, description="Application executable/shortcut name, document path, or website URL.")],
    args: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch an application (e.g. notepad, calc, code), open a file, or open a website URL.

    Guarded against shell command injection and dangerous system executables.

    Args:
        target: Application executable/shortcut name, document path, or website URL (e.g. 'https://...').
        args: Optional command line arguments.

    Returns:
        Dictionary with launch status and action taken.
    """
    logger.info("Launching: target=%s, args=%s", target, args)
    return _launch_app(target=target, args=args)


@mcp.tool(annotations=_READ_ONLY_LOCAL, tags={"desktop", "clipboard", "read-only"})
def get_clipboard() -> Dict[str, Any]:
    """Read the current text content from the Windows clipboard.

    Returns:
        Dictionary with clipboard text content, character count, and empty status.
    """
    return _get_clipboard()


@mcp.tool(annotations=_WRITE_IDEMPOTENT_LOCAL, tags={"desktop", "clipboard"})
def set_clipboard(text: str) -> Dict[str, Any]:
    """Copy text to the Windows clipboard so the user or an app can paste it.

    Args:
        text: Text string to place into clipboard.

    Returns:
        Dictionary indicating status and characters copied.
    """
    return _set_clipboard(text=text)


@mcp.tool(annotations=_ACTION_LOCAL, tags={"desktop", "screenshot"})
def take_screenshot(save_path: Optional[str] = None) -> Dict[str, Any]:
    """Take a screenshot of the primary Windows display and save it as a PNG file.

    Args:
        save_path: Optional file path for the screenshot. Defaults to a timestamped file in 'screenshots/'.

    Returns:
        Dictionary with image path, dimensions, and capture status.
    """
    logger.info("Taking screenshot (save_path=%s)", save_path)
    return _take_screenshot(save_path=save_path)


@mcp.tool(annotations=_ACTION_LOCAL, tags={"desktop", "notification"})
def show_notification(
    title: Annotated[str, Field(min_length=1, description="Notification header text.")],
    message: Annotated[str, Field(min_length=1, description="Notification message text.")],
) -> Dict[str, Any]:
    """Display a Windows toast or balloon notification on the user's desktop screen.

    Args:
        title: Notification header text.
        message: Notification message text.

    Returns:
        Dictionary confirming notification dispatch.
    """
    logger.info("Displaying desktop notification: '%s' - '%s'", title, message)
    return _show_notification(title=title, message=message)


# ==========================================
# Resources & Prompts
# ==========================================


@mcp.resource("system://specs", mime_type="application/json", tags={"system", "read-only"})
def system_specs_resource() -> str:
    """Read-only resource presenting system hardware, OS, and disk summary."""
    info = _get_system_info()
    return json.dumps(info, indent=2)


@mcp.resource("system://network", mime_type="application/json", tags={"system", "network", "read-only"})
def system_network_resource() -> str:
    """Read-only resource presenting active network interfaces and connectivity."""
    info = _get_network_info()
    return json.dumps(info, indent=2)


@mcp.prompt("system_health_check", tags={"system", "diagnostics"})
def system_health_check_prompt() -> str:
    """Prompt template to inspect Windows laptop performance, disk space, and running tasks."""
    return (
        "Please check the overall health of my Windows computer. "
        "1. Check CPU and memory usage using `get_system_info`.\n"
        "2. Check if any disk drive is running out of space.\n"
        "3. List top 5 processes consuming the most CPU or memory using `list_processes`.\n"
        "4. Summarize any recommendations or issues found."
    )


# ==========================================
# Main Entry Point (Strictly Local Stdio)
# ==========================================


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments for the stdio MCP server."""
    parser = argparse.ArgumentParser(
        description="Windows Control Center Local MCP Server (Strictly Host Stdio Transport)"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio"],
        default="stdio",
        help="MCP transport protocol (strictly 'stdio' for host machine execution).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO, routed strictly to sys.stderr).",
    )
    return parser.parse_args()


def main() -> None:
    """Run the Windows Control Center MCP server over host stdio."""
    args = parse_arguments()
    logger.setLevel(getattr(logging, args.log_level))

    logger.info("Starting Windows Control Center MCP Server (Host Stdio Transport)...")

    # FastMCP stdio transport: communicates strictly via stdin/stdout with client sub-process.
    # sys.stderr is reserved for logging to prevent corrupting JSON-RPC protocol frames.
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
