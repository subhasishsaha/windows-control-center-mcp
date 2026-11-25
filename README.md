# 🪟 Windows Control Center MCP Server

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg)](https://www.microsoft.com/windows)
[![Protocol: Model Context Protocol](https://img.shields.io/badge/protocol-MCP%202024--11--05-purple.svg)](https://modelcontextprotocol.io/)
[![Built with FastMCP](https://img.shields.io/badge/built%20with-FastMCP%20v4-brightgreen.svg)](https://github.com/jlowin/fastmcp)
[![Tests: 100 Passing](https://img.shields.io/badge/tests-100%20passed-success.svg)](tests/)

A secure, high-performance, strictly local **Model Context Protocol (MCP)** server that connects AI assistants (**Google Antigravity, Claude Desktop, Cursor, Cline, Roo Code**) to your local Windows environment via native standard input/output (**stdio**).

Built on **FastMCP**, it operates with **zero network exposure** (no HTTP/TCP ports) and wraps system automation in defense-in-depth security: a hardcoded, non-bypassable host OS write lock and kernel-level Win32 Job Object process sandboxing.

---

## ⚡ What Does This Project Do?

Windows Control Center gives your AI agent authorized, monitored, and safe control over your Windows machine:

- **Command & Script Execution**: Run PowerShell, CMD, and isolated Python scripts with AST inspection and kernel sandboxing (CPU caps, memory limits, and fork-bomb quotas).
- **Filesystem Management**: Inspect, read (with pagination), write, search, move, and safely delete files and folders—with an unconditional write-block protecting Windows system directories.
- **Process Inspection & Safety**: List active processes with CPU and RAM metrics, and terminate runaway processes while protecting core Windows kernel services from BSODs.
- **Hardware & System Telemetry**: Stream real-time hardware status (CPU usage, RAM allocation, disk partition usage, battery health, uptime, and active network interfaces).
- **Desktop & GUI Automation**: Launch applications safely (without shell string concatenation), inspect and set the system clipboard, trigger Windows toast notifications, and capture multi-monitor screenshots.
- **Native Host Stdio IPC**: Spawned on demand as a child process by your AI client (Antigravity, Claude, Cursor, etc.), communicating strictly through standard I/O pipes and terminating cleanly when the session ends.

---

## 📁 Project Structure

```
windows-mcp/
├── .github/
│   └── workflows/
│       └── publish.yml             # Manual workflow: test, build wheel & publish to PyPI
├── src/
│   └── windows-control-center-mcp/ # Tier 1: Core engine & server package
│       ├── server.py               # FastMCP stdio server entrypoint & schemas
│       ├── security.py             # Security engine, AST analyzer & host OS write lock
│       ├── sandbox.py              # Win32 Job Object kernel sandbox & process quotas
│       └── tools/                  # Modular tool implementations
│           ├── command_tools.py    # PowerShell, CMD, Python & process execution
│           ├── desktop_tools.py    # App launcher, clipboard, notifications & screenshots
│           ├── filesystem_tools.py # Paginated file read, write, search, move & delete
│           └── system_tools.py     # Hardware telemetry, network status & environment
├── tests/                          # Tier 2: Automated test suite (100 unit & integration tests)
│   ├── test_command_tools.py
│   ├── test_desktop_tools.py
│   ├── test_filesystem_tools.py
│   ├── test_sandbox.py
│   ├── test_security.py
│   ├── test_server.py
│   └── test_system_tools.py
├── pyproject.toml                  # PEP 621 package manifest, scripts & pytest options
├── requirements.txt                # Pinned runtime dependencies
├── CONTRIBUTING.md                 # Contribution guidelines & security policy
├── DOCUMENTATION.md                # In-depth technical architecture & security documentation
├── LICENSE                         # MIT License
└── README.md                       # Project documentation
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

Add the server to your preferred AI client configuration using `uvx` (zero-install):

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
| `execute_cmd` | Execute legacy Command Prompt (CMD.EXE) commands in sandbox. | `destructive: true` |
| `execute_python` | Run Python code with AST validation & kernel sandbox quotas. | `destructive: true` |
| `execute_elevated_command` | Trigger UAC prompt (`RunAs`) for admin commands (if allowed). | `destructive: true` |
| `list_processes` | Inspect all running processes with PID, CPU %, and memory usage. | `read_only: true` |
| `kill_process` | Terminate a process by PID (blocks attempts on OS kernel processes). | `destructive: true` |

### 2. Filesystem Operations
| Tool | Description | Safety Hints |
|---|---|---|
| `read_file` | Read file contents with line offset and limit pagination. | `read_only: true` |
| `write_file` | Create or overwrite files (blocked against host OS directories). | `destructive: false` |
| `list_directory` | Paginated listing of directories with file size and timestamps. | `read_only: true` |
| `search_files` | Search for files by pattern, extension, and optional recursion depth. | `read_only: true` |
| `get_file_info` | Get file metadata, size, timestamps, and attributes. | `read_only: true` |
| `delete_file_or_dir` | Safely delete a file or directory (blocked on drive roots/OS paths). | `destructive: true` |
| `copy_or_move` | Copy or move files/folders with destination overwrite checks. | `destructive: false` |

### 3. System Telemetry & Network
| Tool | Description | Safety Hints |
|---|---|---|
| `get_system_info` | OS version, CPU usage, RAM allocations, disk space, and battery. | `read_only: true` |
| `get_network_info` | Active network adapters, IP addresses, MACs, and gateway status. | `read_only: true` |
| `get_environment` | Read environment variables (automatically redacts secrets and keys). | `read_only: true` |
| `get_security_status`| Current server policy, admin status, and audit log path. | `read_only: true` |

### 4. Desktop Automation
| Tool | Description | Safety Hints |
|---|---|---|
| `launch_app` | Launch desktop applications safely without shell concatenation. | `destructive: false` |
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

Run the full automated test suite using `uv`:

```powershell
uv run pytest -v
```

All **100 automated unit and integration tests** verify tool registrations, security policies, AST inspection, sandbox isolation, and stdio cleanliness across both Windows 10 and Windows 11.

---

## 📄 License & Contributing

- **License**: Released under the [MIT License](LICENSE).
- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) for code conventions, security disclosure guidelines, and testing requirements.
