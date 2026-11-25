# 🪟 Windows Control Center MCP Server

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg)](https://www.microsoft.com/windows)
[![Protocol: Model Context Protocol](https://img.shields.io/badge/protocol-MCP%202024--11--05-purple.svg)](https://modelcontextprotocol.io/)
[![Built with FastMCP](https://img.shields.io/badge/built%20with-FastMCP%20v4-brightgreen.svg)](https://github.com/jlowin/fastmcp)
[![Tests: 100 Passing](https://img.shields.io/badge/tests-100%20passed-success.svg)](tests/)

A local **Model Context Protocol (MCP)** server that connects AI assistants (**Google Antigravity, Claude Desktop, Cursor, Cline, Roo Code**) to your local Windows environment via standard input/output (**stdio**).

Built with **FastMCP**, it runs locally as a child process without opening network ports, providing tools for command execution, filesystem operations, process inspection, system telemetry, and desktop interactions.

---

## ⚡ What Does This Project Do?

Windows Control Center provides tools for interacting with Windows systems:

- **Command & Script Execution**: Run PowerShell, CMD, and Python scripts with execution timeouts, memory commit limits, and process count quotas via Win32 Job Objects.
- **Filesystem Management**: Inspect, read (with pagination), write, search, move, and delete files and directories, with path validation on system directories.
- **Process Inspection & Management**: List active processes with CPU and RAM metrics, and terminate processes by PID with protection for core system processes (`csrss.exe`, `lsass.exe`, `services.exe`, etc.).
- **Hardware & System Telemetry**: Retrieve system status (CPU usage, RAM allocation, disk partition usage, battery health, uptime, and active network interfaces).
- **Desktop & GUI Automation**: Launch applications directly without shell string concatenation, read and write system clipboard text, trigger Windows toast notifications, and capture multi-monitor screenshots.
- **Local Stdio IPC**: Spawned on demand as a child process by your AI client (Antigravity, Claude, Cursor, etc.), communicating via standard I/O pipes and terminating when the client session ends.

---

## 📁 Project Structure

```
windows-mcp/
├── .github/
│   └── workflows/
│       ├── test.yml                # CI test matrix across Windows 10/11 & Python 3.10-3.12
│       └── publish.yml             # Manual workflow: build wheel & publish to PyPI
├── src/
│   └── windows-control-center-mcp/ # Core server package
│       ├── server.py               # FastMCP stdio server entrypoint & schemas
│       ├── security.py             # Path validation, script scanning & command validation
│       ├── sandbox.py              # Win32 Job Object process limits & resource quotas
│       └── tools/                  # Tool implementations
│           ├── command_tools.py    # PowerShell, CMD, Python & process execution
│           ├── desktop_tools.py    # App launcher, clipboard, notifications & screenshots
│           ├── filesystem_tools.py # Paginated file read, write, search, move & delete
│           └── system_tools.py     # Hardware telemetry, network status & environment
├── tests/                          # Automated test suite (100 unit & integration tests)
│   ├── test_command_tools.py
│   ├── test_desktop_tools.py
│   ├── test_filesystem_tools.py
│   ├── test_sandbox.py
│   ├── test_security.py
│   ├── test_server.py
│   └── test_system_tools.py
├── pyproject.toml                  # PEP 621 package manifest, scripts & pytest options
├── requirements.txt                # Pinned runtime dependencies
├── CONTRIBUTING.md                 # Contribution guidelines
├── DOCUMENTATION.md                # Technical architecture & subsystem documentation
├── LICENSE                         # MIT License
└── README.md                       # Project overview and client setup
```

---

## 🚀 Installation & Client Setup (Windows)

### Prerequisites

Install `uv` (the fast Python package manager) on Windows via PowerShell:
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```
*(Or via winget: `winget install astral-sh.uv`)*

---

### Client Configuration Files

Add the server to your preferred AI client configuration using `uvx`:

#### 1. Google Antigravity / AGY CLI

File path: `%USERPROFILE%\.gemini\config\mcp_config.json`

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "uvx",
      "args": [
        "windows-control-center-mcp",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

#### 2. Claude Desktop

File path: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "uvx",
      "args": [
        "windows-control-center-mcp",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

#### 3. Cursor

File path: In Cursor Settings > Features > MCP, or in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "uvx",
      "args": [
        "windows-control-center-mcp",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

#### 4. Cline / Roo Code (VS Code Extension)

File path: `%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "uvx",
      "args": [
        "windows-control-center-mcp",
        "--transport",
        "stdio"
      ],
      "env": {
        "MCP_STRICT_MODE": "true",
        "MCP_ALLOW_ELEVATION": "true"
      },
      "disabled": false,
      "autoApprove": [
        "get_system_info",
        "get_network_info",
        "list_processes",
        "get_file_info",
        "read_file",
        "list_directory",
        "search_files"
      ]
    }
  }
}
```

---

## 🧰 Available Tools (22 Tools)

### 1. Command Execution & Process Management
| Tool | Description | Safety Hints |
|---|---|---|
| `execute_powershell` | Execute PowerShell commands inside Win32 Job Object sandbox. | `destructive: true` |
| `execute_cmd` | Execute Command Prompt (CMD.EXE) commands in Win32 Job Object sandbox. | `destructive: true` |
| `execute_python` | Run Python code with AST validation & Win32 Job Object limits. | `destructive: true` |
| `execute_elevated_command` | Trigger UAC prompt (`RunAs`) for administrative commands (when enabled). | `destructive: true` |
| `list_processes` | Inspect running processes with PID, CPU %, and memory usage. | `read_only: true` |
| `kill_process` | Terminate a process by PID (blocks attempts on core system processes). | `destructive: true` |

### 2. Filesystem Operations
| Tool | Description | Safety Hints |
|---|---|---|
| `read_file` | Read file contents with line offset and limit pagination. | `read_only: true` |
| `write_file` | Create or overwrite files (restricted on protected system directories). | `destructive: false` |
| `list_directory` | Paginated listing of directories with file size and timestamps. | `read_only: true` |
| `search_files` | Search for files by pattern, extension, and optional recursion depth. | `read_only: true` |
| `get_file_info` | Get file metadata, size, timestamps, and attributes. | `read_only: true` |
| `delete_file_or_dir` | Delete a file or directory (restricted on drive roots and system directories). | `destructive: true` |
| `copy_or_move` | Copy or move files/folders with destination overwrite checks. | `destructive: false` |

### 3. System Telemetry & Network
| Tool | Description | Safety Hints |
|---|---|---|
| `get_system_info` | OS version, CPU usage, RAM allocations, disk space, and battery status. | `read_only: true` |
| `get_network_info` | Active network adapters, IP addresses, MACs, and gateway status. | `read_only: true` |
| `get_environment` | Read environment variables (redacts sensitive tokens matching key/secret patterns). | `read_only: true` |
| `get_security_status`| Current server policy, admin status, and audit log path. | `read_only: true` |

### 4. Desktop Automation
| Tool | Description | Safety Hints |
|---|---|---|
| `launch_app` | Launch desktop applications directly without shell string concatenation. | `destructive: false` |
| `get_clipboard` | Read text currently on the Windows system clipboard. | `read_only: true` |
| `set_clipboard` | Place text onto the Windows system clipboard. | `destructive: false` |
| `take_screenshot` | Capture multi-monitor screenshot and save to a local PNG. | `destructive: false` |
| `show_notification` | Display a native Windows toast notification popup. | `destructive: false` |

### MCP Resources & Prompts
- **Resource `system://specs`**: Live JSON stream of CPU, memory, OS, and disk status.
- **Resource `system://network`**: Live JSON stream of active network interfaces.
- **Prompt `system_health_check`**: Diagnostic prompt template to evaluate system health.

---

## 🧪 Testing

Run the automated test suite using `uv`:

```powershell
uv run pytest -v
```

The test suite contains **100 automated unit and integration tests** verifying tool registrations, security policies, AST inspection, sandbox isolation, and stdio cleanliness across both Windows 10 and Windows 11.

---

## ⚠️ Security Boundaries & Known Limitations

Windows Control Center uses software guardrails (regex filtering, path normalization, and AST checks) alongside Win32 Job Object resource controls. Users should understand the following design boundaries:

- **Not an OS Container or Hypervisor**: Subprocesses execute directly on the host under your Windows user account, not inside a virtual machine, AppContainer, or isolated filesystem sandbox.
- **User-Space File Access**: Guardrails protect Windows system paths (`C:\Windows`, `System32`, `Program Files`, etc.). Any files, repositories, or documents that your logged-in user account has rights to read, modify, or delete remain accessible to tools if commanded.
- **No Network Egress Filtering**: Win32 Job Objects do not provide network isolation. Executed commands and scripts can establish outbound network connections unless restricted by external firewalls.
- **Static Analysis Limitations**: Pattern checks analyze static command text. Dynamic string concatenation, runtime variable interpolation, .NET reflection, or COM objects in PowerShell can bypass static regex inspection.
- **Client Approvals Recommended**: When configuring your AI client, consider using confirmation prompts rather than broad `autoApprove` for mutating tools (`execute_powershell`, `execute_cmd`, `execute_python`, `delete_file_or_dir`).

---

## 📄 License & Contributing

- **License**: Released under the [MIT License](LICENSE).
- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) for code conventions and testing requirements.
