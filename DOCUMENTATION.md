# 🛠️ Windows Control Center MCP Server — Technical Architecture & Subsystems

This document provides a technical overview of the **Windows Control Center MCP Server** (`windows-control-center-mcp`). It describes the server's internal architecture, process model, input validation mechanisms, Win32 Job Object sandboxing, tool implementations, IPC protocol handling, and known security boundaries.

---

## 📑 Table of Contents

1. [High-Level Architecture & Process Model](#1-high-level-architecture--process-model)
2. [Host Stdio IPC & Protocol Cleanliness](#2-host-stdio-ipc--protocol-cleanliness)
3. [Security & Validation Engine (`security.py`)](#3-security--validation-engine-securitypy)
   - [Host OS Path Write Protection](#host-os-path-write-protection)
   - [Script Content & Reference Scanning](#script-content--reference-scanning)
   - [Base64 Encoded Command Inspection](#base64-encoded-command-inspection)
   - [Python AST Static Code Analysis](#python-ast-static-code-analysis)
   - [Destructive Command Pattern Detection](#destructive-command-pattern-detection)
   - [Sensitive Credential Path Protection](#sensitive-credential-path-protection)
4. [Win32 Job Object Sandboxing (`sandbox.py`)](#4-win32-job-object-sandboxing-sandboxpy)
   - [API Implementation Details](#api-implementation-details)
   - [Process Quotas](#process-quotas)
   - [Memory Commit Limits](#memory-commit-limits)
   - [UI Restrictions](#ui-restrictions)
   - [Process Tree Termination](#process-tree-termination)
   - [Resource Accounting Telemetry](#resource-accounting-telemetry)
5. [Modular Tool Subsystems (`tools/`)](#5-modular-tool-subsystems-tools)
   - [Command & Script Execution Subsystem](#command--script-execution-subsystem)
   - [Process Monitoring & System Process Protection](#process-monitoring--system-process-protection)
   - [Filesystem Operations](#filesystem-operations)
   - [System Telemetry & Sensitive Variable Redaction](#system-telemetry--sensitive-variable-redaction)
   - [Desktop Automation & GUI Interaction](#desktop-automation--gui-interaction)
6. [MCP Resources, Prompts & Tool Annotations (`server.py`)](#6-mcp-resources-prompts--tool-annotations-serverpy)
7. [Structured Audit Logging](#7-structured-audit-logging)
8. [Automated Verification & Test Suite](#8-automated-verification--test-suite)
9. [Security Boundaries, Known Limitations & Threat Model](#9-security-boundaries-known-limitations--threat-model)
   - [Semantic Gap: Static Regex vs. Dynamic Shell Execution](#semantic-gap-static-regex-vs-dynamic-shell-execution)
   - [Filesystem Scope & User-Space Blast Radius](#filesystem-scope--user-space-blast-radius)
   - [Network Egress & Lack of Network Isolation](#network-egress--lack-of-network-isolation)
   - [Process Creation Timing (TOCTOU in Sandbox Binding)](#process-creation-timing-toctou-in-sandbox-binding)
   - [Python Dynamic Execution & Win32 API Access](#python-dynamic-execution--win32-api-access)
   - [Elevation Boundary (UAC)](#elevation-boundary-uac)
   - [Indirect Prompt Injection (Confused Deputy)](#indirect-prompt-injection-confused-deputy)

---

## 1. High-Level Architecture & Process Model

The Windows Control Center MCP Server is built using **FastMCP v4** and runs as a local child process spawned directly by the AI client (Google Antigravity, Claude Desktop, Cursor, Cline, Roo Code).

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
│  │                              Input Validation Engine                             │  │
│  │   • Host OS Path Validation             • Script Content Pre-Scanner             │  │
│  │   • Base64 Command Inspection           • Python Abstract Syntax Tree (AST)      │  │
│  │   • Path Normalization & Canonicalizer  • Credential Path Read Restrictions      │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │ (Validated Input)                        │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                         Win32 Job Object Process Sandbox                         │  │
│  │   • Win32 Job Object Container          • Memory Commit Limits (512MB / 1024MB)  │  │
│  │   • Active Process Quota (Max 16)       • Win32 UI Restrictions                  │  │
│  │   • TerminateJobObject Process Cleanup  • Resource Accounting Telemetry          │  │
│  └──────────────────────────────────────────┬───────────────────────────────────────┘  │
│                                             │                                          │
│                                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              Windows Subsystems                                  │  │
│  │   • PowerShell Engine                   • Command Prompt (cmd.exe)               │  │
│  │   • Python Virtual Environment          • Win32 Desktop & Notification APIs      │  │
│  │   • Local Filesystem (NTFS / ReFS)      • Windows NT File Permissions (DACLs)    │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Characteristics:
1. **Zero Open Network Ports**: No HTTP, WebSocket, or TCP socket is opened. The server operates locally via stdio streams.
2. **Lifecycle Bound to Client**: The server process runs as a child process of the client application. When the client closes the pipe or terminates, child processes managed in the Job Object are terminated.
3. **No Background Services**: Runs on demand as a child process without requiring background Windows services or persistent background daemons.

---

## 2. Host Stdio IPC & Protocol Cleanliness

The Model Context Protocol (MCP) relies on bidirectional standard input/output streams (`stdio`) exchanging JSON-RPC 2.0 messages:
- **`sys.stdin`**: Dedicated exclusively to incoming JSON-RPC requests from the client.
- **`sys.stdout`**: Dedicated exclusively to outgoing JSON-RPC responses from the server.

### Stdout Pollution Prevention
Any unexpected string emitted to `stdout` (such as a print statement, diagnostic message, or unhandled library logging) corrupts JSON-RPC framing and causes communication errors with the client.

Windows Control Center maintains protocol cleanliness through the following design measures:
1. **Logging Redirection**: Python's logging subsystem is configured with a `StreamHandler(sys.stderr)` and specific formatting. Log messages are directed to `stderr`.
2. **Third-Party Logger Configuration**: Loggers from dependencies (`fastmcp`, `mcp`, `urllib3`, etc.) are silenced or routed to `stderr`.
3. **Subprocess Isolation**: When running PowerShell, CMD, or Python child processes, their stdout is captured via OS pipes (`subprocess.PIPE`), processed internally, and serialized into the JSON-RPC response payload, preventing raw child process output from leaking into the parent MCP transport channel.

---

## 3. Security & Validation Engine (`security.py`)

The validation engine inspects commands, arguments, and paths prior to execution.

### Host OS Path Write Protection
The validation policy restricts write and modification operations targeting Windows system directories (`C:\Windows`, `%SystemRoot%`, `%WinDir%`, `System32`, `SysWOW64`, `C:\Program Files`, `C:\ProgramData`, etc.):
- **Enforced Regardless of Elevation**: Write restrictions against system directories apply across all tool calls, including elevated execution (`ALLOW_ELEVATION=true`).
- **Path Normalization**: The engine normalizes paths to detect alternative representations:
  - Bare drive letters (e.g., `C:` normalized to `C:\`).
  - Extended-length and device prefixes (`\\?\`, `\\.\`).
  - Localhost administrative network shares (`\\localhost\c$\Windows`, `\\127.0.0.1\c$\Windows`).
  - 8.3 short paths (e.g., `C:\WINDOW~1`) expanded using the Win32 `GetLongPathNameW` API.
- **Operation Interception**:
  - Filesystem tools (`write_file`, `delete_file_or_dir`, `copy_or_move`) validate paths via `validate_path_safety(path, operation="write")`.
  - Shell command strings are inspected for redirection operators (`>`, `>>`, `| Out-File`), PowerShell cmdlets (`Set-Content`, `Add-Content`, `New-Item`, `Copy-Item`, `Move-Item`, `Remove-Item`), legacy CMD commands (`del`, `erase`, `copy`, `move`, `ren`, `mkdir`, `rmdir`), and permission modification tools (`takeown`, `icacls`, `attrib`).
  - .NET file APIs targeting host OS paths (such as `[System.IO.File]::WriteAllText(...)`).

### Script Content & Reference Scanning
To prevent bypassing command validation by writing script files to non-system directories and subsequently running them, the validation engine applies a multi-step check:

```
Step 1 (Write Time):
  write_file("C:\\temp\\script.ps1", content)
       │
       ▼
  validate_script_content() scans script content
       │
       ├── Matches system write or destructive disk pattern? ──► Reject write
       └── Clean? ──► Permit write to C:\temp\

Step 2 (Execution Time):
  execute_powershell("powershell -File C:\\temp\\script.ps1")
       │
       ▼
  _extract_referenced_scripts() parses command for script file paths
       │
       ├── File exists? ──► Read file & run validate_script_content()
       │                         │
       │                         ├── Prohibited pattern? ──► Reject execution
       │                         └── Clean? ──► Proceed to run in Job Object
       └── Inline command? ──► Validate command string directly
```

1. **`validate_script_content(content, filename_or_ext)`**:
   Scans `.ps1`, `.bat`, `.cmd`, `.vbs`, `.py`, and `.reg` content before `write_file` writes data to disk.
2. **`_extract_referenced_scripts(command, working_dir)`**:
   Parses PowerShell call operators (`&`, `.`), `-File` arguments, and `cmd /c` targets. Reads referenced files from disk and validates their contents before process creation.
3. **Elevated Execution Restriction**:
   `execute_elevated_command` verifies referenced scripts and command strings against the same validation rules prior to requesting elevation.

### Base64 Encoded Command Inspection
PowerShell commands can accept Base64-encoded strings via switches like `-EncodedCommand`:
1. Identifies Base64 tokens preceded by encoding switches (`-EncodedCommand`, `-enc`, etc.) or `FromBase64String` calls.
2. Decodes bytes (checking UTF-16LE, UTF-8, and Latin-1 encodings).
3. Evaluates the decoded inner command text against `validate_command` to inspect nested or obfuscated commands.

### Python AST Static Code Analysis
`execute_python` parses code into an Abstract Syntax Tree using Python's built-in `ast` module prior to execution:
- Traverses `ast.Call` nodes.
- Inspects calls to process spawning functions (`subprocess.run`, `subprocess.Popen`, `os.system`, `os.popen`), extracting arguments and verifying inner commands against `validate_command`.
- Inspects file write operations: `open(..., 'w'/'a'/'+'/'x')`, `pathlib.Path.write_text()`, `pathlib.Path.write_bytes()`.
- Inspects filesystem modification methods: `os.remove()`, `os.unlink()`, `os.rmdir()`, `shutil.rmtree()`, `shutil.move()`.
- Rejects dynamic execution constructs such as `exec(base64.b64decode(...))` or `eval(...)` in strict mode.

### Destructive Command Pattern Detection
Regex patterns check command strings against common destructive patterns:
- **Disk Partitioning & Formatting**: `format <drive>:`, `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `diskpart`.
- **Shadow Copy Deletion**: `vssadmin delete shadows`, `wmic shadowcopy delete`, WMI/CIM `Win32_ShadowCopy` deletion, `wbadmin delete catalog`.
- **Boot Configuration Sabotage**: `bcdedit /delete`, `fsutil usn deletejournal`.
- **Security Service Tampering**: `Set-MpPreference -DisableRealtimeMonitoring 1`, `netsh advfirewall set allprofiles state off`, stopping `WinDefend` or `MpsSvc` services.

### Sensitive Credential Path Protection
`validate_read_safety(path)` restricts reading common credential stores:
- System registry hives: `SAM`, `SECURITY`, `SYSTEM` in `C:\Windows\System32\config`.
- User registry files: `NTUSER.DAT`, `UsrClass.dat`.
- Cloud provider credentials: `%USERPROFILE%\.aws\credentials`, `%USERPROFILE%\.azure`, `.gcloud`.
- SSH keys & certificates: `id_rsa`, `id_ed25519`, `.pfx`, `.p12`.
- Browser credential stores: Chrome, Edge, and Firefox `Login Data` and `Web Data` SQLite databases.

---

## 4. Win32 Job Object Sandboxing (`sandbox.py`)

Non-elevated commands (`execute_powershell`, `execute_cmd`, `execute_python`) run within a dedicated **Win32 Job Object**.

Job Objects are Windows kernel objects that allow groups of processes to be managed as a unit, enforcing resource quotas and operational restrictions across child processes and their descendants.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Windows NT Kernel Space                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Win32 Job Object Container                    │  │
│  │                                                                  │  │
│  │   [Process Quotas]             [Memory Commit Limits]            │  │
│  │   ActiveProcessLimit = 16      ProcessMemoryLimit = 512 MB       │  │
│  │   (Further spawns return       JobMemoryLimit = 1024 MB          │  │
│  │    ERROR_NOT_ENOUGH_QUOTA)     (OOM handled by OS)               │  │
│  │                                                                  │  │
│  │   [UI Restrictions]            [Process Tree Termination]        │  │
│  │   • UILIMIT_HANDLES            • TerminateJobObject()            │  │
│  │   • UILIMIT_GLOBALATOMS        • Terminates all assigned         │  │
│  │   • UILIMIT_DESKTOP              processes on timeout or exit    │  │
│  │   • UILIMIT_EXITWINDOWS                                          │  │
│  │                                                                  │  │
│  │   ┌───────────────────────┐      ┌───────────────────────────┐   │  │
│  │   │  Child Process (cmd)  │ ──►  │ Child Descendant (python) │   │  │
│  │   └───────────────────────┘      └───────────────────────────┘   │  │
│  │                                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### API Implementation Details
The sandbox uses the `pywin32` library (`win32job`, `win32api`, `win32con`):
1. **`win32job.CreateJobObject(None, "")`**: Creates an anonymous Job Object.
2. **`win32job.SetInformationJobObject`**: Configures `JobObjectExtendedLimitInformation` and `JobObjectBasicUIRestrictions`.
3. **`win32job.AssignProcessToJobObject(job_handle, int(proc._handle))`**: Assigns the child process handle to the Job Object immediately after spawning via `subprocess.Popen(..., creationflags=subprocess.CREATE_NO_WINDOW)`. If assignment fails and the process is still running, the server terminates the process and raises a `RuntimeError`.

### Process Quotas
- **Limit**: `ActiveProcessLimit = 16`.
- **Flag**: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`.
- If a script attempts to spawn processes beyond the configured limit, subsequent process creation calls fail with `ERROR_NOT_ENOUGH_QUOTA` (WinError 1816).

### Memory Commit Limits
- **Per-Process Limit**: 512 MB (`ProcessMemoryLimit`).
- **Cumulative Job Limit**: 1024 MB (`JobMemoryLimit`).
- **Flags**: `JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY`.
- Sets caps on committed memory for the process hierarchy, preventing runaway memory allocations from affecting the host system.

### UI Restrictions
Configured via `JobObjectBasicUIRestrictions`:
- `JOB_OBJECT_UILIMIT_HANDLES`: Restricts access to USER handles owned by processes outside the job.
- `JOB_OBJECT_UILIMIT_GLOBALATOMS`: Prevents adding atoms to the global atom table.
- `JOB_OBJECT_UILIMIT_DESKTOP`: Prevents creating or switching desktops.
- `JOB_OBJECT_UILIMIT_EXITWINDOWS`: Prevents calling `ExitWindowsEx` to restart or shut down the machine.
- `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`: Prevents altering system parameters via `SystemParametersInfo`.

### Process Tree Termination
When a command completes or reaches its timeout:
- `win32job.TerminateJobObject(self.job_handle, exit_code)` terminates all active processes currently associated with the Job Object.
- With `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` configured, closing the job handle automatically terminates associated processes.

### Resource Accounting Telemetry
Queries `QueryInformationJobObject` using `JobObjectExtendedLimitInformation` and `JobObjectBasicAccountingInformation` to report:
- `cpu_user_seconds`: CPU user-mode processing time.
- `cpu_kernel_seconds`: CPU kernel-mode processing time.
- `peak_process_memory_mb`: Highest committed memory observed in a single process.
- `peak_job_memory_mb`: Highest cumulative committed memory observed across all processes in the job.
- `total_processes_spawned`: Total count of processes created within the job.
- `active_processes`: Number of currently running processes in the job.

---

## 5. Modular Tool Subsystems (`tools/`)

Tools are implemented across modular modules in `src/windows-control-center-mcp/tools/`:

### Command & Script Execution Subsystem (`command_tools.py`)
- **`execute_powershell`**: Runs PowerShell commands using `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <cmd>` within the Job Object sandbox.
- **`execute_cmd`**: Runs commands via `cmd.exe /c <cmd>` within the Job Object sandbox.
- **`execute_python`**: Runs Python code via `[sys.executable, "-c", code]` within the Job Object sandbox following AST validation.
- **`execute_elevated_command`**: Runs administrative commands via `Start-Process powershell -Verb RunAs` (when enabled via `MCP_ALLOW_ELEVATION=true`), validating commands against path restrictions and script rules before requesting elevation.

### Process Monitoring & System Process Protection (`command_tools.py`)
- **`list_processes`**: Lists running processes using `psutil.process_iter()`, with options to filter by name and sort by CPU or memory usage.
- **`kill_process`**: Terminates a process by PID or name.
  - **Protected System Processes**: Rejects termination requests targeting core Windows processes (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `wininit.exe`, `winlogon.exe`, `dwm.exe`, `fontdrvhost.exe`, `svchost.exe`, `sihost.exe`, `explorer.exe`).
  - **Self & Parent Protection**: Rejects termination requests targeting the MCP server PID (`os.getpid()`) or its parent client PID.

### Filesystem Operations (`filesystem_tools.py`)
- **`read_file`**: Reads file contents with pagination parameters (`start_line`, `max_lines` up to 5000) and multi-encoding fallback (`utf-8`, `cp1252`, `latin-1`).
- **`write_file`**: Creates or appends to files. Validates target paths and scans script content before writing.
- **`list_directory`**: Paginated directory listing with file sizes, timestamps, and recursion control.
- **`search_files`**: Pattern-based file search using `fnmatch` with result count limits and depth boundaries.
- **`get_file_info`**: Retrieves file attributes, sizes, and timestamps.
- **`delete_file_or_dir`**: Deletes files or directories, with checks preventing deletion of drive roots, system directories, and the audit log.
- **`copy_or_move`**: Copies or moves files and folders with target path validation.

### System Telemetry & Sensitive Variable Redaction (`system_tools.py`)
- **`get_system_info`**: Retrieves hardware and operating system status:
  - CPU usage percentage, physical and logical core counts.
  - RAM total, used, and available in GB.
  - Disk partition table with mount points, filesystem types, and free space percentages.
  - Battery charge percentage and power line status.
  - System boot time and uptime formatting.
- **`get_network_info`**: Retrieves network adapters, IP addresses, netmasks, broadcast addresses, MAC addresses, and default gateway status.
- **`get_environment`**: Returns environment variables, redacting variables containing sensitive patterns (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `AUTH`, `CERT`, `PRIVATE`, `PAT`, `DATABASE_URL`).
- **`get_security_status`**: Reports current server configuration, administrative status, and audit log path.

### Desktop Automation & GUI Interaction (`desktop_tools.py`)
- **`launch_app`**: Spawns desktop applications via `subprocess.Popen` with `shell=False`, restricting direct invocation of command shells.
- **`get_clipboard` / `set_clipboard`**: Reads and writes text to the Windows system clipboard via `pyperclip`.
- **`take_screenshot`**: Captures screen geometry using Pillow (`ImageGrab.grab(all_screens=True)`) and saves PNG output to a temporary path.
- **`show_notification`**: Displays a Windows toast notification using PowerShell notifications API.

---

## 6. MCP Resources, Prompts & Tool Annotations (`server.py`)

### MCP Tool Annotations
Tools registered with FastMCP include annotations indicating their operation type:
- **`read_only_hint = True`**: Applied to query-only tools (`read_file`, `list_directory`, `get_system_info`, `list_processes`, `get_clipboard`, etc.). Clients can use this hint for automatic approval workflows.
- **`destructive_hint = True`**: Applied to modifying or execution tools (`execute_powershell`, `execute_cmd`, `execute_python`, `delete_file_or_dir`, `kill_process`). Clients can use this hint to display confirmation prompts.

### Live MCP Resources
- **`system://specs`**: Live JSON stream providing CPU, memory, OS, and disk information.
- **`system://network`**: Live JSON stream providing active network interface information.

### Interactive Prompts
- **`system_health_check`**: Predefined prompt template for diagnosing system resource usage and process status.

---

## 7. Structured Audit Logging

Security decisions and executions are recorded to a structured JSON Lines log file:
- Default location: `security_audit.log` (configurable via `MCP_AUDIT_LOG_FILE`).
- The audit log file is protected from deletion or modification through MCP filesystem tools.

### Log Entry Format:
```json
{
  "timestamp": "2026-11-25 21:06:33",
  "event": "COMMAND_ALLOWED",
  "command": "Get-Process | Select-Object -First 5",
  "allowed": true,
  "elevated": false,
  "is_admin": false,
  "reason": ""
}
```

When an operation is rejected by policy:
```json
{
  "timestamp": "2026-11-25 22:12:15",
  "event": "REFERENCED_SCRIPT_BLOCKED",
  "command": "powershell -File C:\\temp\\script.ps1",
  "allowed": false,
  "elevated": false,
  "is_admin": false,
  "reason": "HARDCODED SECURITY RESTRICTION: Script line contains prohibited command: Write/modification attempt on host OS folder via PowerShell cmdlet or redirection is hardcoded blocked."
}
```

---

## 8. Automated Verification & Test Suite

The test suite consists of **100 automated unit and integration tests** located in `tests/`:

```
tests/
├── test_security.py          # 40 tests: Validation rules, AST analysis, script scanning, path protections
├── test_command_tools.py     # 12 tests: PowerShell, CMD, Python execution, Job Object sandboxing, quotas
├── test_filesystem_tools.py  # 18 tests: File read pagination, encodings, directory operations, path safety
├── test_server.py            # 12 tests: FastMCP registrations, tool annotations, resources, stdio verification
├── test_desktop_tools.py     # 8 tests: App launcher arguments, clipboard operations, notification handling
├── test_system_tools.py      # 6 tests: System metrics, network reporting, environment variable redaction
└── test_sandbox.py           # 4 tests: Job Object memory limits, process quotas, process termination
```

### Running the Test Suite
```powershell
uv run pytest -v
```

### Stdio Verification
A dedicated test (`test_stdio_cleanliness_stdout_untouched_by_logging`) intercepts `sys.stdout` to verify that logging and diagnostic outputs are directed to `stderr` and do not interfere with JSON-RPC stdio transport.

---

## 9. Security Boundaries, Known Limitations & Threat Model

The server employs cooperative software-level validation and Win32 Job Object resource controls. It does not provide hypervisor-grade isolation or container virtualization. Operators and security teams should recognize the following architectural boundaries and threat vectors:

### Semantic Gap: Static Regex vs. Dynamic Shell Execution
- **Dynamic String Composition**: PowerShell and CMD are Turing-complete environments. Static regular expressions search for explicit string tokens. Commands can dynamically build prohibited paths or commands at runtime (e.g., using `[char]` conversions, string concatenation, or format operators like `"{0}{1}" -f "C:\Win","dows"`), which static regex cannot resolve before execution.
- **Alternative APIs & Invocation Methods**: PowerShell commands can invoke .NET reflection (`[type]::GetType(...)`), COM objects (`New-Object -ComObject Scripting.FileSystemObject`), or WMI/CIM methods that do not use standard cmdlet or redirection syntax.
- **Limitation**: Static analysis cannot substitute for full language interpretation or runtime behavioral sandboxing.

### Filesystem Scope & User-Space Blast Radius
- **Host User Privileges**: The server and its spawned child processes execute under the security context of the logged-in Windows user.
- **Targeted vs. Global Protection**: The hardcoded path protection protects Windows operating system roots (`C:\Windows`, `Program Files`, etc.). However, non-system directories accessible to the user (such as `Documents`, `Desktop`, code repositories, or user-level startup scripts in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) remain accessible to filesystem tools if commanded.
- **Limitation**: The server does not enforce working-directory jails or namespace filesystem virtualization (e.g., AppContainers or chroot-like constructs).

### Network Egress & Lack of Network Isolation
- **No Network Boundaries in Job Objects**: Win32 Job Objects provide CPU, memory, and process quota enforcement, but do not provide network namespace or firewall isolation.
- **Outbound Connections**: While specific remote payload download patterns (such as piped `curl | iex` or `certutil -urlcache`) are pattern-matched, arbitrary network calls initiated by Python (`urllib`, `requests`, `socket`), PowerShell (`Invoke-RestMethod`), or native binaries can establish outbound network connections.

### Process Creation Timing (TOCTOU in Sandbox Binding)
- **Attachment Window**: When launching subprocesses, `subprocess.Popen` creates the process before `win32job.AssignProcessToJobObject` assigns it to the Job Object container.
- **Limitation**: A narrow microsecond timing window exists where a process begins execution before Job Object resource quotas and UI restrictions are attached. A fully preemptive sandbox requires calling the Win32 `CreateProcessW` API with `CREATE_SUSPENDED`, binding the Job Object handle, and then resuming the initial thread via `ResumeThread`.

### Python Dynamic Execution & Win32 API Access
- **Dynamic Attribute Resolution**: While AST analysis checks static calls to `subprocess`, `os.system`, and `open()`, dynamic Python constructs (such as `getattr(__import__('os'), 'system')` or builtins manipulation) are not resolvable via static AST inspection.
- **Direct Win32 API Access**: Python scripts can import `ctypes` or `pywin32` to invoke Win32 APIs directly, bypassing high-level filesystem tool guardrails.

### Elevation Boundary (UAC)
- **Escape from Sandbox**: When `MCP_ALLOW_ELEVATION=true` is enabled, `execute_elevated_command` triggers a Windows UAC elevation prompt (`Start-Process -Verb RunAs`).
- **Limitation**: If the user grants UAC elevation, the elevated process runs outside the Job Object container with administrative privileges, bypassing memory caps, process quotas, and user-level DACL restrictions.

### Indirect Prompt Injection (Confused Deputy)
- **LLM-Driven Execution**: As an MCP server, tools are executed based on tool-call requests emitted by an AI model.
- **Limitation**: If an LLM processes untrusted third-party content (e.g., summarizing an external webpage, reading untrusted emails, or parsing an unvetted code repository) that contains prompt injection instructions, the server evaluates whether the requested tool calls violate syntactic guardrails, not the semantic intent or trustworthiness of the upstream prompt.
