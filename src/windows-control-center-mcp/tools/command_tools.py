"""Command and process execution tools for Windows MCP Server."""

import os
import sys
import time
from typing import Any, Dict, List, Optional
import psutil
from sandbox import (
    JobSandboxConfig,
    is_job_sandbox_supported,
    run_in_job_sandbox,
)
from security import (
    PROTECTED_PROCESS_NAMES,
    execute_elevated,
    is_admin,
    validate_command,
    validate_python_code,
)


def _decode_output(raw_bytes: bytes) -> str:
    """Safely decode command line output using common Windows encodings."""
    if not raw_bytes:
        return ""
    for enc in ("utf-8", "cp1252", "oem", "latin-1"):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _execution_error_result(
    stderr: str,
    *,
    blocked_by_guardrail: bool = False,
    sandboxed: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build a uniform error payload for command and code execution failures."""
    result: Dict[str, Any] = {
        "stdout": "",
        "stderr": stderr,
        "return_code": -1,
        "timed_out": False,
        "execution_time_seconds": 0.0,
    }
    if blocked_by_guardrail:
        result["blocked_by_guardrail"] = True
    if sandboxed is not None:
        result["sandboxed"] = sandboxed
    return result


def _run_sandboxed_command(
    cmd: List[str],
    *,
    working_dir: Optional[str] = None,
    timeout: int = 120,
    timeout_label: str = "Command",
) -> Dict[str, Any]:
    """Validate working directory, enforce mandatory Job Object sandboxing, and execute cmd."""
    cwd: Optional[str] = None
    if working_dir is not None:
        cwd = os.path.abspath(working_dir)
        if not os.path.exists(cwd):
            return _execution_error_result(f"Working directory does not exist: {cwd}")

    # Strict enforcement: Job Object sandboxing is mandatory and non-bypassable
    if not is_job_sandbox_supported():
        return _execution_error_result(
            "Execution blocked: Windows Job Object sandbox is mandatory and unavailable in this environment.",
            blocked_by_guardrail=True,
            sandboxed=False,
        )

    bounded_timeout = max(1, min(timeout, 3600))
    start_time = time.perf_counter()
    raw_stdout, raw_stderr, return_code, timed_out, metrics = run_in_job_sandbox(
        cmd,
        cwd=cwd,
        timeout=bounded_timeout,
    )
    exec_time = round(time.perf_counter() - start_time, 2)
    stderr_str = _decode_output(raw_stderr)
    if timed_out and not stderr_str:
        stderr_str = f"{timeout_label} timed out after {bounded_timeout} seconds."

    return {
        "stdout": _decode_output(raw_stdout),
        "stderr": stderr_str,
        "return_code": return_code,
        "timed_out": timed_out,
        "execution_time_seconds": exec_time,
        "sandboxed": True,
        "sandbox_backend": "windows_job_object",
        "sandbox_metrics": metrics,
    }


def execute_powershell(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
    elevate: bool = False,
) -> Dict[str, Any]:
    """Execute a PowerShell command on the local Windows machine.

    Enforces security guardrails to block dangerous commands, disk destruction, and remote payloads.
    Execution is strictly and immutably isolated inside a Windows Job Object sandbox with kernel memory and process quotas.

    Args:
        command: The PowerShell command or script block to run.
        working_dir: Directory where the command should execute (default: current directory).
        timeout: Maximum seconds to wait before terminating (default: 120).
        elevate: Whether to request Windows administrative privilege elevation (default: False).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, timed_out status,
        and sandbox metrics.
    """
    # If elevation requested, route through UAC elevation executor directly
    # (execute_elevated validates the command internally; elevated procs cannot join unprivileged jobs)
    if elevate:
        return execute_elevated(command, timeout=timeout, working_dir=working_dir)

    is_safe, security_err = validate_command(command, working_dir=working_dir)
    if not is_safe:
        return _execution_error_result(
            security_err or "Command blocked by security guardrails.",
            blocked_by_guardrail=True,
        )

    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {command}",
    ]
    return _run_sandboxed_command(
        ps_cmd,
        working_dir=working_dir if working_dir is not None else os.getcwd(),
        timeout=timeout,
        timeout_label="Command",
    )


def execute_cmd(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Execute a Command Prompt (cmd.exe) command on Windows.

    Enforces security guardrails to block dangerous commands, disk destruction, and remote payloads.
    Execution is strictly and immutably isolated inside a Windows Job Object sandbox with kernel memory and process quotas.

    Args:
        command: The cmd.exe command to execute.
        working_dir: Working directory (default: current directory).
        timeout: Maximum seconds to wait before terminating (default: 120).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, timed_out status,
        and sandbox metrics.
    """
    is_safe, security_err = validate_command(command, working_dir=working_dir)
    if not is_safe:
        return _execution_error_result(
            security_err or "Command blocked by security guardrails.",
            blocked_by_guardrail=True,
        )

    return _run_sandboxed_command(
        ["cmd.exe", "/c", command],
        working_dir=working_dir if working_dir is not None else os.getcwd(),
        timeout=timeout,
        timeout_label="Command",
    )


def execute_python(
    code: str,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Execute Python code in the server's virtual environment.

    Enforces AST inspection to block dangerous system manipulation and remote payloads.
    Execution is strictly and immutably isolated inside a Windows Job Object sandbox with kernel memory and process quotas.

    Args:
        code: Python source code snippet to run.
        timeout: Maximum execution time in seconds (default: 60).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, timed_out status,
        and sandbox metrics.
    """
    is_safe, security_err = validate_python_code(code)
    if not is_safe:
        return _execution_error_result(
            security_err or "Python code blocked by security guardrails.",
            blocked_by_guardrail=True,
        )

    return _run_sandboxed_command(
        [sys.executable, "-c", code],
        working_dir=None,
        timeout=timeout,
        timeout_label="Python execution",
    )


def list_processes(
    filter_name: Optional[str] = None,
    sort_by: str = "cpu",
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """List running processes on the system with CPU, memory, and PID info.

    Args:
        filter_name: Optional substring to filter process names (case-insensitive, e.g., 'chrome').
        sort_by: Metric to sort by: 'cpu' or 'memory' (default: 'cpu').
        limit: Maximum number of processes to return (clamped between 1 and 500, default: 25).

    Returns:
        List of process information objects.
    """
    limit = max(1, min(limit, 500))
    filter_lower = filter_name.lower() if filter_name else None
    procs: List[Dict[str, Any]] = []

    if filter_lower:
        # Pre-filter on pid/name before querying expensive Win32 token/memory attributes
        for p in psutil.process_iter(["pid", "name"]):
            try:
                name = p.info.get("name") or ""
                if filter_lower not in name.lower():
                    continue
                with p.oneshot():
                    mem_info = p.memory_info()
                    try:
                        username = p.username()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        username = None
                    procs.append({
                        "pid": p.pid,
                        "name": name,
                        "cpu_percent": p.cpu_percent() or 0.0,
                        "memory_mb": round(mem_info.rss / (1024 * 1024), 1) if mem_info else 0.0,
                        "status": p.status(),
                        "username": username,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    else:
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status", "username"]):
            try:
                info = p.info
                mem_info = info.get("memory_info")
                procs.append({
                    "pid": info.get("pid"),
                    "name": info.get("name") or "",
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "memory_mb": round(mem_info.rss / (1024 * 1024), 1) if mem_info else 0.0,
                    "status": info.get("status"),
                    "username": info.get("username"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    sort_key = "memory_mb" if sort_by.lower() == "memory" else "cpu_percent"
    procs.sort(key=lambda x: x[sort_key], reverse=True)
    return procs[:limit]


def kill_process(
    pid: Optional[int] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """Terminate a process by PID or process name, protecting critical OS and server processes.

    Args:
        pid: The Process ID to terminate.
        name: Name of process(es) to terminate (e.g., 'notepad.exe').

    Returns:
        A dictionary summarizing terminated processes and any errors.
    """
    if pid is None and not name:
        return {"success": False, "message": "Must provide either pid or name."}

    my_pid = os.getpid()
    try:
        parent_pid = psutil.Process(my_pid).ppid()
    except Exception:
        parent_pid = None

    killed = []
    errors = []

    # 1. Kill by PID
    if pid is not None:
        if pid in (0, 4):
            return {
                "success": False,
                "message": f"REFUSED: Termination of core Windows kernel process (PID {pid}) is prohibited.",
                "killed_processes": [],
                "errors": ["Target process is protected."],
            }
        if pid in (my_pid, parent_pid):
            return {
                "success": False,
                "message": f"REFUSED: Termination of MCP server process or its direct parent (PID {pid}) is prohibited.",
                "killed_processes": [],
                "errors": ["Target process is protected."],
            }
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            if p_name.lower() in PROTECTED_PROCESS_NAMES:
                return {
                    "success": False,
                    "message": f"REFUSED: Termination of critical Windows system process '{p_name}' (PID {pid}) is prohibited.",
                    "killed_processes": [],
                    "errors": ["Target process is protected."],
                }
            p.terminate()
            p.wait(timeout=3)
            killed.append({"pid": pid, "name": p_name})
        except psutil.TimeoutExpired:
            try:
                p.kill()
                killed.append({"pid": pid, "name": p.name(), "forced": True})
            except Exception as e:
                errors.append(f"PID {pid}: {str(e)}")
        except Exception as e:
            errors.append(f"PID {pid}: {str(e)}")

    # 2. Kill by Name
    if name:
        target_name_lower = name.strip().lower()
        if target_name_lower in PROTECTED_PROCESS_NAMES:
            return {
                "success": False,
                "message": f"REFUSED: Termination of critical Windows system process '{name}' is prohibited.",
                "killed_processes": [],
                "errors": ["Target process is protected."],
            }

        for p in psutil.process_iter(["pid", "name"]):
            try:
                p_info = p.info
                p_pid = p_info["pid"]
                p_name = p_info["name"] or ""
                if p_name.lower() == target_name_lower:
                    if p_pid in (my_pid, parent_pid):
                        errors.append(f"Skipped PID {p_pid} (MCP server process protected)")
                        continue
                    p.terminate()
                    killed.append({"pid": p_pid, "name": p_name})
            except Exception as e:
                errors.append(f"Process {name}: {str(e)}")

    return {
        "success": len(killed) > 0,
        "killed_processes": killed,
        "errors": errors,
    }


def execute_elevated_command(
    command: str,
    timeout: int = 120,
    working_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a command with Administrator / Elevated privileges.

    Triggers Windows UAC elevation if not already running as Administrator.
    Strictly validates the command against security guardrails before permitting elevation.

    Args:
        command: PowerShell command to run with elevated permissions.
        timeout: Maximum seconds to wait before terminating (default: 120).
        working_dir: Optional directory where command should execute.

    Returns:
        Dictionary with command output, return code, and elevation status.
    """
    return execute_elevated(command=command, timeout=timeout, working_dir=working_dir)


def get_security_status() -> Dict[str, Any]:
    """Get the current security, guardrail, and privilege status of the MCP server.

    Returns:
        Dictionary detailing admin status, strict mode, elevation policy, sandbox status, and audit log file.
    """
    import security
    default_cfg = JobSandboxConfig()
    return {
        "is_admin": is_admin(),
        "strict_mode": security.STRICT_MODE,
        "allow_elevation": security.ALLOW_ELEVATION,
        "audit_log_path": security.AUDIT_LOG_FILE,
        "protected_system_roots": len(security.CRITICAL_PATHS) + len(security.SYSTEM_DRIVES),
        "dangerous_patterns_blocked": len(security.DANGEROUS_COMMAND_PATTERNS),
        "protected_system_processes": len(security.PROTECTED_PROCESS_NAMES),
        "host_os_write_protected": True,
        "host_os_read_only": True,
        "host_os_roots": security.HOST_OS_ROOTS,
        "sandbox_backend": "windows_job_object",
        "sandbox_supported": is_job_sandbox_supported(),
        "sandbox_mandatory": True,
        "sandbox_bypass_allowed": False,
        "sandbox_limits": {
            "max_memory_mb": default_cfg.max_memory_mb,
            "max_job_memory_mb": default_cfg.max_job_memory_mb,
            "max_processes": default_cfg.max_processes,
            "kill_on_close": default_cfg.kill_on_close,
            "ui_restrictions": default_cfg.ui_restrictions,
        },
    }
