# 🛠️ Windows Control Center MCP Server — Technical Deep Dive & Architecture

This document provides a comprehensive technical breakdown of the **Windows Control Center MCP Server** (`windows-control-center-mcp`). It covers the internal architecture, security invariants, Win32 Job Object kernel sandboxing, two-stage dropper defenses, AST analysis, tool implementations, and IPC protocol mechanics.

---

## 📑 Table of Contents

1. [High-Level Architecture & Process Model](#1-high-level-architecture--process-model)
2. [Strict Host Stdio IPC & Protocol Cleanliness](#2-strict-host-stdio-ipc--protocol-cleanliness)
3. [Multi-Layer Security Engine (`security.py`)](#3-multi-layer-security-engine-securitypy)
   - [Hardcoded Host OS Write Protection](#hardcoded-host-os-write-protection)
   - [Two-Stage Dropper & Script Execution Defense](#two-stage-dropper--script-execution-defense)
   - [Base64 PowerShell De-obfuscation Engine](#base64-powershell-de-obfuscation-engine)
   - [Python AST Static Code Analyzer](#python-ast-static-code-analyzer)
   - [Ransomware & Disk Destruction Defense](#ransomware--disk-destruction-defense)
   - [Sensitive Credential & Secret Protection](#sensitive-credential--secret-protection)
4. [Kernel-Level Win32 Job Object Sandboxing (`sandbox.py`)](#4-kernel-level-win32-job-object-sandboxing-sandboxpy)
   - [Process Quotas & Fork-Bomb Mitigation](#process-quotas--fork-bomb-mitigation)
   - [Memory Commit Caps](#memory-commit-caps)
   - [UI & Desktop Isolation](#ui--desktop-isolation)
   - [Atomic Process Hierarchy Termination](#atomic-process-hierarchy-termination)
5. [Modular Tool Subsystems (`tools/`)](#5-modular-tool-subsystems-tools)
   - [Command & Script Execution Subsystem](#command--script-execution-subsystem)
   - [Process Monitoring & BSOD Mitigation](#process-monitoring--bsod-mitigation)
   - [Filesystem Operations with Pagination & Encodings](#filesystem-operations-with-pagination--encodings)
   - [System Telemetry & Sensitive Variable Redaction](#system-telemetry--sensitive-variable-redaction)
   - [Desktop Automation & GUI Interaction](#desktop-automation--gui-interaction)
6. [MCP Resources, Prompts & Tool Annotations (`server.py`)](#6-mcp-resources-prompts--tool-annotations-serverpy)
7. [Structured Audit Logging & Telemetry](#7-structured-audit-logging--telemetry)
8. [Automated Verification & Test Harness](#8-automated-verification--test-harness)

---

## 1. High-Level Architecture & Process Model

The Windows Control Center MCP Server is built using **FastMCP v4** and runs as a local, on-demand child process managed directly by the AI client (Google Antigravity, Claude Desktop, Cursor, Cline, Roo Code).

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 AI Host Client (Parent)                                │
│                   (Antigravity / Claude Desktop / Cursor / Cline / Roo)                │
└───────────────────────────┬────────────────────────────────┬───────────────────────────┘
                            │ (sys.stdin pipe)               │ (sys.stdout pipe)
                            │ JSON-RPC Requests              │ JSON-RPC Responses
                            ▼                                │
┌────────────────────────────────────────────────────────────┴───────────────────────────┐
│                           Windows Control Center MCP (Child)                           │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                            Security Guardrail Engine                             │  │
│  │   • Host OS Hardcoded Write Lock        • Two-Stage Dropper Content Scanner      │  │
│  │   • PowerShell Base64 De-obfuscator     • Python Abstract Syntax Tree (AST)      │  │
│  │   • Command Canonicalizer               • Credential & Path Boundary Validator   │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ (Verified Clean)                         │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                          Execution & Kernel Sandbox                              │  │
│  │   • Win32 Job Object Container          • Hard Commit Memory Caps (512MB/1024MB) │  │
│  │   • Active Process Quota (Max 16)       • Win32 UI/Desktop Isolation Limits      │  │
│  │   • Atomic TerminateJobObject Tree Kill • High-Resolution Performance Counters   │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │                                          │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              Windows OS Subsystems                               │  │
│  │   • PowerShell 5.1/7+ Engine            • Command Prompt (cmd.exe)               │  │
│  │   • Python 3.10+ Virtual Environment    • Win32 Process / Desktop APIs           │  │
│  │   • NTFS Filesystem (Local Drives)      • Windows NT Security SRM (Kernel DACLs) │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Key Architectural Invariants:
1. **Zero Open Ports**: No HTTP, WebSocket, or TCP socket is opened. The server cannot be probed, port-scanned, or reached over the local network or internet.
2. **Deterministic Lifecycle**: The server lives and dies with the parent AI client session. When the client closes the pipe or terminates, the operating system cleans up all child processes automatically.
3. **No Daemon Overhead**: Uses zero CPU and zero memory when idle.

---

## 2. Strict Host Stdio IPC & Protocol Cleanliness

The Model Context Protocol (MCP) relies on bidirectional standard input/output streams (`stdio`) exchanging JSON-RPC 2.0 messages:
- **`sys.stdin`**: Dedicated exclusively to incoming JSON-RPC requests from the client.
- **`sys.stdout`**: Dedicated exclusively to outgoing JSON-RPC responses from the server.

### Stdout Pollution Prevention
A single rogue log message, print statement, or third-party warning emitted to `stdout` corrupts the JSON-RPC framing and causes the client harness to crash. 

Windows Control Center enforces protocol cleanliness through several design measures:
1. **Logging Redirection**: Python's logging subsystem is configured with a custom `StreamHandler(sys.stderr)` and strict formatting. No logger ever writes to `stdout`.
2. **Third-Party Noise Suppression**: Loggers from `fastmcp`, `mcp`, `urllib3`, and underlying libraries are silenced or redirected to `stderr`.
3. **Subprocess Isolation**: When spawning PowerShell, CMD, or Python child processes, their stdout is captured via OS pipes (`subprocess.PIPE`), processed internally, and serialized into the JSON-RPC response payload, preventing raw child output from bleeding into the parent MCP transport channel.

---

## 3. Multi-Layer Security Engine (`security.py`)

The security engine provides pre-execution analysis and invariant enforcement across all tools.

### Hardcoded Host OS Write Protection
The host operating system directory (`C:\Windows`, `%SystemRoot%`, `%WinDir%`, `System32`, `SysWOW64`, etc.) is declared **strictly read-only**:
- **Zero Bypass Under Any Privilege**: No permission level—including Windows Administrator elevation, UAC `RunAs`, or `ALLOW_ELEVATION=true`—can authorize a write or modification to this directory.
- **Canonical Path Resolution**: The engine intercepts short 8.3 names (`C:\WINDOW~1`), directory junctions, symlinks, extended UNC device paths (`\\?\C:\Windows`, `\\.\C:\Windows`), and localhost administrative network shares (`\\localhost\c$\Windows`, `\\127.0.0.1\c$\Windows`).
- **Operation Interception**:
  - Direct filesystem tools (`write_file`, `delete_file_or_dir`, `copy_or_move`) check `validate_path_safety(path, operation="write")`.
  - Shell commands check for redirection operators (`>`, `>>`, `| Out-File`), PowerShell cmdlets (`Set-Content`, `Add-Content`, `New-Item`, `Copy-Item`, `Move-Item`, `Remove-Item`, `Clear-Content`), legacy CMD commands (`del`, `erase`, `copy`, `move`, `ren`, `mkdir`, `rmdir`), and permission modification tools (`takeown`, `icacls`, `attrib`).
  - .NET file APIs: `[System.IO.File]::WriteAllText(...)`, `[System.IO.File]::Create(...)`, `[System.IO.File]::Delete(...)`.
  - Python write APIs: `open(..., 'w')`, `shutil.copy/move/rmtree`, `pathlib.Path.write_text`.

### Two-Stage Dropper & Script Execution Defense
To prevent an agent from bypassing write locks by dropping an executable script into a non-OS directory (e.g., `C:\temp\exploit.ps1`) and then running it, the security engine uses a 3-tier defense:

```
Stage 1 (Write Time):
  agent calls write_file("C:\\temp\\exploit.ps1", "Copy-Item malware.dll C:\\Windows\\")
       │
       ▼
  validate_script_content() scans script content
       │
       ├── Matches host OS write or ransomware pattern? ──► REJECT WRITE (File never created)
       └── Clean? ──► Permit write to C:\temp\

Stage 2 (Execution Time):
  agent calls execute_powershell("powershell -File C:\\temp\\exploit.ps1")
       │
       ▼
  _extract_referenced_scripts() parses command for script file paths
       │
       ├── File exists on disk? ──► Read file & run validate_script_content()
       │                                  │
       │                                  ├── Prohibited statement? ──► REJECT COMMAND
       │                                  └── Clean? ──► Proceed to Stage 3
       └── Direct command? ──► Proceed to Stage 3

Stage 3 (Runtime Kernel DACL):
  Script runs non-elevated in Win32 Job Object
       │
       ▼
  Windows NT Security Reference Monitor (SRM) checks file DACLs
       │
       └── Attempting write to C:\Windows? ──► STATUS_ACCESS_DENIED (0x80070005)
```

1. **`validate_script_content(content, filename_or_ext)`**:
   Pre-scans `.ps1`, `.bat`, `.cmd`, `.vbs`, `.py`, and `.reg` content before `write_file` commits bytes to disk.
2. **`_extract_referenced_scripts(command, working_dir)`**:
   Parses PowerShell call operators (`&`, `.`), `-File` arguments, `cmd /c` targets, and direct invocations. Reads referenced files from disk and validates them before process creation.
3. **Elevated Execution Restriction**:
   `execute_elevated` strictly requires that any custom script file referenced in an elevated command must be pre-scanned and validated, preventing malicious UAC elevation popups.

### Base64 PowerShell De-obfuscation Engine
PowerShell commands frequently use `-EncodedCommand` / `-enc` to obscure malicious payloads:
1. Detects base64 tokens preceded by encoding switches (`-EncodedCommand`, `-enc`, `-e`).
2. Decodes UTF-16LE bytes back into plaintext PowerShell script blocks.
3. Recursively feeds the decoded inner command back into `validate_command()` to detect nested and multi-stage obfuscated payloads.

### Python AST Static Code Analyzer
`execute_python` parses all code into an Abstract Syntax Tree (`ast.parse`) prior to execution:
- Walks all `ast.Call` nodes.
- Inspects calls to `subprocess.run`, `subprocess.Popen`, `os.system`, and `os.popen`, extracting arguments and verifying inner commands against `validate_command`.
- Inspects file write operations: `open(..., 'w'/'a'/'+'/'x')`, `pathlib.Path.write_text()`, `pathlib.Path.write_bytes()`.
- Inspects destructive filesystem methods: `os.remove()`, `os.unlink()`, `os.rmdir()`, `shutil.rmtree()`, `shutil.move()`.
- Fails closed on dynamic evasion: detects obfuscated execution constructs like `exec(base64.b64decode(...))` or `eval(...)`.

### Ransomware & Disk Destruction Defense
Pre-compiled regex engines check commands against known destructive patterns:
- **Disk Partitioning**: `format <drive>:`, `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `diskpart`.
- **Shadow Copy Wiping**: `vssadmin delete shadows`, `wmic shadowcopy delete`, WMI/CIM `Win32_ShadowCopy` deletion, `wbadmin delete catalog`.
- **Boot & Journal Sabotage**: `bcdedit /delete`, `fsutil usn deletejournal`.
- **Security Disabling**: `Set-MpPreference -DisableRealtimeMonitoring 1`, `netsh advfirewall set allprofiles state off`, stopping `WinDefend` or `MpsSvc` services.

### Sensitive Credential & Secret Protection
`validate_read_safety(path)` prevents reading sensitive Windows credential repositories:
- System hives: `SAM`, `SECURITY`, `SYSTEM` in `C:\Windows\System32\config`.
- User registry: `NTUSER.DAT`, `UsrClass.dat`.
- Cloud credentials: `%USERPROFILE%\.aws\credentials`, `%USERPROFILE%\.azure`, `.gcloud`.
- SSH & Certificates: `id_rsa`, `id_ed25519`, `.pfx`, `.p12`.
- Browser databases: Chrome, Edge, and Firefox `Login Data` and `Web Data` SQLite vaults.

---

## 4. Kernel-Level Win32 Job Object Sandboxing (`sandbox.py`)

All non-elevated commands (`execute_powershell`, `execute_cmd`, `execute_python`) run inside a dedicated **Win32 Job Object**. 

Job Objects are kernel-level containers provided by the Windows NT kernel (`ntdll.dll` / `kernel32.dll`) that impose mandatory resource and execution limits on processes and all of their descendants.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Windows NT Kernel Space                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Win32 Job Object Container                    │  │
│  │                                                                  │  │
│  │   [Process Quota]             [Memory Commit Caps]               │  │
│  │   MaxActiveProcesses = 16     PerProcessCommitCap = 512 MB       │  │
│  │   ActiveProcessLimitHit ──►   JobMemoryCommitCap = 1024 MB       │  │
│  │   (Kernel throws WinError 1816)  OOM ──► Terminated by NT Kernel │  │
│  │                                                                  │  │
│  │   [UI & Desktop Isolation]    [Atomic Process Tree Kill]         │  │
│  │   • UILIMIT_HANDLES           • TerminateJobObject()             │  │
│  │   • UILIMIT_GLOBALATOMS       • Zero surviving child processes   │  │
│  │   • UILIMIT_DESKTOP           • Kills background daemons         │  │
│  │   • UILIMIT_EXITWINDOWS                                          │  │
│  │                                                                  │  │
│  │   ┌───────────────────────┐      ┌───────────────────────────┐   │  │
│  │   │  Child Process (cmd)  │ ──►  │ Child Descendant (python) │   │  │
│  │   └───────────────────────┘      └───────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Win32 API Implementation Details:
The sandbox uses `ctypes.windll.kernel32` to interact directly with the Windows API:
1. **`CreateJobObjectW(None, None)`**: Spawns an anonymous kernel Job Object.
2. **`SetInformationJobObject`**: Configures `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` and `JOBOBJECT_BASIC_UI_RESTRICTIONS`.
3. **`AssignProcessToJobObject`**: Assigns the child process handle to the job container immediately upon process creation (using `CREATE_SUSPENDED` or post-creation binding).

### Process Quotas & Fork-Bomb Mitigation
- **Limit**: `ActiveProcessLimit = 16`.
- **Flag**: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`.
- If a script attempts a batch fork bomb (`%0|%0`) or recursively spawns sub-processes, the Windows kernel rejects the 17th `CreateProcess` call with `ERROR_NOT_ENOUGH_QUOTA` (WinError 1816), completely neutralizing the denial-of-service attempt.

### Memory Commit Caps
- **Per-Process Limit**: 512 MB (`ProcessMemoryLimit`).
- **Cumulative Job Limit**: 1024 MB (`JobMemoryLimit`).
- **Flags**: `JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY`.
- Protects the host machine against runaway memory allocation, infinite loops, and buffer-bloat denial-of-service. If an allocation exceeds these caps, the kernel terminates the violating process immediately.

### UI & Desktop Isolation
Imposes Win32 UI restrictions via `JobObjectBasicUIRestrictions`:
- `JOB_OBJECT_UILIMIT_HANDLES`: Child processes cannot access USER handles owned by processes outside the job.
- `JOB_OBJECT_UILIMIT_GLOBALATOMS`: Cannot manipulate global atom tables.
- `JOB_OBJECT_UILIMIT_DESKTOP`: Cannot create, switch, or modify Windows desktops.
- `JOB_OBJECT_UILIMIT_EXITWINDOWS`: Cannot invoke `ExitWindowsEx` to shut down or restart the machine.

### Atomic Process Hierarchy Termination
When a command completes or times out:
- Calling `TerminateJobObject(hJob, exit_code)` atomically terminates every process currently associated with the job object in ring 0.
- Guarantees **zero orphaned background processes**, **zero dangling reverse shells**, and **zero detached child tasks**.

### High-Resolution Telemetry
Queries `QueryInformationJobObject` with `JobObjectBasicAccountingInformation` and `JobObjectBasicAndIoAccountingInformation` to report:
- `user_time_seconds`: CPU user-mode processing time.
- `kernel_time_seconds`: CPU kernel-mode syscall time.
- `peak_process_memory_mb`: Highest RAM footprint of any single process in the job.
- `peak_job_memory_mb`: Highest combined RAM commit across the entire tree.
- `total_processes_spawned`: Count of all child and descendant processes initiated.

---

## 5. Modular Tool Subsystems (`tools/`)

All tools are implemented in modular libraries under `src/windows-control-center-mcp/tools/`:

### Command & Script Execution Subsystem (`command_tools.py`)
- **`execute_powershell`**: Runs PowerShell commands using `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <cmd>`. Non-elevated execution runs strictly within the Job Object sandbox.
- **`execute_cmd`**: Executes commands via `cmd.exe /c <cmd>` in the sandbox.
- **`execute_python`**: Runs code in the active Python runtime via `[sys.executable, "-c", code]`. Pre-validated with AST analysis.
- **`execute_elevated_command`**: Routes through Windows UAC elevation via `Start-Process powershell -Verb RunAs`. Fully verified against host OS write locks and script dropper rules prior to triggering UAC.

### Process Monitoring & BSOD Mitigation (`command_tools.py`)
- **`list_processes`**: Queries running processes via `psutil.process_iter()`. Supports filtering by name and sorting by CPU % or RSS memory.
- **`kill_process`**: Terminates processes by PID or image name. 
  - **Protected OS Services**: Hardcoded protection blocks killing critical kernel services (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `wininit.exe`, `winlogon.exe`, `dwm.exe`).
  - **Self-Protection**: Prevents the MCP server from terminating itself (`os.getpid()`) or its parent AI client harness (`psutil.Process(my_pid).ppid()`).

### Filesystem Operations with Pagination & Encodings (`filesystem_tools.py`)
- **`read_file`**: Reads text files safely. Features:
  - Line-based pagination (`start_line`, `max_lines` capped at 5000).
  - Multi-encoding fallback: sequentially attempts `utf-8`, `cp1252`, `latin-1` in strict mode before falling back to loss-tolerant replacement.
- **`write_file`**: Creates or appends to files. Pre-validates destination paths and runs `validate_script_content` on executable scripts.
- **`list_directory`**: Paginated directory browsing with file sizes, timestamps, and recursion depth control.
- **`search_files`**: Pattern-based file search using `fnmatch` with max results caps and depth boundaries.
- **`delete_file_or_dir`**: Safe deletion. Recursively deletes directories using a custom Win32 read-only attribute remover (`_remove_readonly`), while protecting drive roots, system directories, and the audit log.
- **`copy_or_move`**: Safe copy/move operations with destination collision checks and host OS folder isolation.

### System Telemetry & Sensitive Variable Redaction (`system_tools.py`)
- **`get_system_info`**: Real-time hardware telemetry:
  - CPU usage percentage, physical and logical core counts.
  - RAM total, used, available in GB.
  - Disk partition table with mount points, filesystem types, and percentage free.
  - Battery charge percentage and power line status.
  - System boot time and uptime formatting.
- **`get_network_info`**: Active network interface adapters, IP addresses, netmasks, broadcast addresses, MAC addresses, and default gateway connectivity check.
- **`get_environment`**: Dumps system environment variables while automatically redacting sensitive secrets matching pattern:
  `KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|CERT|PRIVATE|SIGNING|PAT|DATABASE_URL`
- **`get_security_status`**: Current server security posture, elevation policy, and audit log path.

### Desktop Automation & GUI Interaction (`desktop_tools.py`)
- **`launch_app`**: Spawns desktop applications (`notepad.exe`, `calc.exe`, etc.) via `subprocess.Popen` without shell string concatenation (`shell=False`), preventing command injection.
- **`get_clipboard` / `set_clipboard`**: Reads and writes text to the native Windows clipboard via `pyperclip`.
- **`take_screenshot`**: Captures multi-monitor screen geometry using Pillow's `ImageGrab.grab(all_screens=True)` and writes PNG output with randomized names in an isolated directory.
- **`show_notification`**: Dispatches native Windows toast notifications via PowerShell `Windows.UI.Notifications`.

---

## 6. MCP Resources, Prompts & Tool Annotations (`server.py`)

### MCP Tool Annotations
Every tool registered with `@mcp.tool` includes `ToolAnnotations` providing machine-readable safety hints to the AI client model:
- **`read_only_hint = True`**: Declared for tools that perform no state mutation (`read_file`, `list_directory`, `get_system_info`, `list_processes`, `get_clipboard`, etc.). Clients can safely auto-approve these tools.
- **`destructive_hint = True`**: Declared for state-mutating or execution tools (`execute_powershell`, `execute_cmd`, `execute_python`, `delete_file_or_dir`, `kill_process`). Clients can present confirmation dialogs before executing.

### Live MCP Resources
Resources provide streaming read-only context:
- **`system://specs`**: Live JSON stream providing instant hardware, memory, and disk telemetry.
- **`system://network`**: Live JSON stream providing network interfaces and connectivity status.

### Interactive Prompts
- **`system_health_check`**: Pre-defined prompt template instructing the model to diagnose system performance, evaluate disk exhaustion risks, and identify high-resource processes.

---

## 7. Structured Audit Logging & Telemetry

Every security decision and operational command is recorded to a structured JSON Lines log file:
- Default path: `security_audit.log` (configurable via `MCP_AUDIT_LOG_FILE`).
- Protected: The security engine forbids deleting or modifying this log file through MCP tools.

### Sample Audit Event Schema:
```json
{
  "timestamp": "2026-11-25T21:06:33.857Z",
  "event_type": "COMMAND_ALLOWED",
  "target": "Get-Process | Select-Object -First 5",
  "allowed": true,
  "reason": "",
  "strict_mode": true,
  "elevated": false
}
```
When an attack or violation occurs:
```json
{
  "timestamp": "2026-11-25T22:12:15.102Z",
  "event_type": "REFERENCED_SCRIPT_BLOCKED",
  "target": "powershell -File C:\\temp\\exploit.ps1",
  "allowed": false,
  "reason": "HARDCODED SECURITY RESTRICTION: Script line contains prohibited command: Write/modification attempt on host OS folder via PowerShell cmdlet or redirection is hardcoded blocked.",
  "strict_mode": true,
  "elevated": false
}
```

---

## 8. Automated Verification & Test Harness

The server features a **100-test automated suite** in `tests/`:

```
tests/
├── test_security.py          # 40 tests: Regex guardrails, AST validation, dropper blocks, host OS write locks
├── test_command_tools.py     # 12 tests: PowerShell, CMD, Python, Job Object sandbox execution, quotas
├── test_filesystem_tools.py  # 18 tests: Pagination, encodings, safe delete, directory recursion, path safety
├── test_server.py            # 12 tests: FastMCP registration, annotations, resources, prompts, stdio cleanliness
├── test_desktop_tools.py     # 8 tests: App launcher injection safety, clipboard, notification scripts
├── test_system_tools.py      # 6 tests: Hardware metrics, network inspection, sensitive variable redaction
└── test_sandbox.py           # 4 tests: Win32 Job Object memory caps, process limits, atomic tree kill
```

### Running the Test Suite
```powershell
uv run pytest -v
```

### Static Analysis Checks
- **Memory Leak Check**: Validates zero unbounded caches, proper file handle closing, and deterministic context management.
- **Stdio Verification**: Dedicated test (`test_stdio_cleanliness_stdout_untouched_by_logging`) intercepts `sys.stdout` and verifies that no logging statements or diagnostics ever leak onto the JSON-RPC pipe.
