# MCP HTTP Proxy + SSE Bridge

- Author: Jason Cheng (Jason Tools)
- License: MIT
- Version: 1.1.1 (2026-03-09)
- Languages: [English](README.md) · [繁體中文](README_zh-TW.md)

## Features

1. **HTTP/HTTPS Proxy** — works around macOS security software that blocks network connections from Claude Desktop's MCP child processes
2. **SSE Bridge** — exposes a stdio MCP server as an SSE endpoint for remote MCP clients (e.g. Chatbox, Open WebUI)

Both features share one port and have zero external dependencies (pure Python stdlib).

---

## The problem (Proxy)

On macOS with certain security software installed (e.g. Avast, Norton), MCP child processes started by Claude Desktop may be unable to reach internal network services, failing with `No route to host` (errno=65 `EHOSTUNREACH`) or `Connection failed`.

Running the same MCP program by hand in a terminal works fine:

| How it runs | Can reach the internal network |
|-------------|-------------------------------|
| Python run by hand in a terminal | Yes |
| Claude Desktop child process | Blocked |
| launchd background service | Blocked |

### Root cause

Security software (e.g. Avast) installs a macOS **Network Extension** that applies different network filtering policies depending on where a process comes from:

- **Interactive processes** (started from a terminal): internal connections allowed
- **Non-interactive processes** (Claude Desktop children, launchd services): internal connections blocked

Even with "File Shield" and "Web Shield" turned off in the security software, the Network Extension still runs at system level.

To check whether a Network Extension is present:

```bash
systemextensionsctl list
# An entry of type network_extension (e.g. Avast, Norton) means this is the cause
```

---

## Quick setup

### Files

```
/path/to/mcp_proxy/
├── mcp_proxy.py          # Proxy + SSE Bridge
├── start_proxy.command   # macOS launcher (double-click, runs in foreground)
├── start_proxy_bg.sh     # Background launcher
├── README.md             # This document
├── README_zh-TW.md       # Traditional Chinese version
└── CHANGELOG.md          # Version history

~/Applications/
└── MCP Proxy.app         # AppleScript app for Login Items (recommended)
```

### CLI arguments

```
python mcp_proxy.py [options]

Options:
  --port, -p PORT     Listen port (default 28080)
  --sse CMD [ARGS]    stdio MCP server command to bridge (must come last)
```

---

## Mode 1: Proxy only

For working around macOS security software that blocks MCP child-process connections.

### Start

```bash
# Default port 28080
python3 mcp_proxy.py

# Custom port
python3 mcp_proxy.py -p 9000
```

### Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` and add to each MCP server's `env`:

```json
{
  "mcpServers": {
    "your-mcp-server": {
      "command": "...",
      "args": ["..."],
      "env": {
        "HTTP_PROXY": "http://127.0.0.1:28080",
        "HTTPS_PROXY": "http://127.0.0.1:28080",
        "...other existing settings..."
      }
    }
  }
}
```

---

## Mode 2: Proxy + SSE Bridge

For exposing a stdio MCP server as an SSE endpoint so remote clients such as Chatbox or Open WebUI can connect.

### Start

```bash
# Bridge @modelcontextprotocol/server-everything
python3 mcp_proxy.py --sse npx -y @modelcontextprotocol/server-everything

# Bridge your own Python MCP server
python3 mcp_proxy.py --sse python3 my_mcp_server.py

# Custom port
python3 mcp_proxy.py -p 9000 --sse npx -y @modelcontextprotocol/server-everything
```

### SSE endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sse` | GET | Open the SSE connection; receives `endpoint` and `message` events |
| `/messages?session_id=<id>` | POST | Send a JSON-RPC message to the MCP server |
| `/messages` | OPTIONS | CORS preflight response |

The SSE transport follows MCP specification version 2024-11-05.

### Configure Chatbox

| Field | Value |
|-------|-------|
| Type | Remote (http/sse) |
| URL | `http://127.0.0.1:28080/sse` |

### Configure Claude Desktop (via mcp-remote)

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:28080/sse"]
    }
  }
}
```

### SSE test

```bash
# Test the SSE connection (should receive an endpoint event)
curl http://127.0.0.1:28080/sse

# Without --sse, /sse returns 400
python3 mcp_proxy.py &
curl http://127.0.0.1:28080/sse
# Expected: HTTP/1.1 400 Bad Request
```

---

## Start at login

### macOS

> **Important**: do not use launchd (LaunchAgents). The Avast Network Extension blocks outbound connections from processes started by launchd. The proxy must start in the user session context via Login Items.

**Option 1: MCP Proxy.app (recommended)**

A prebuilt AppleScript app wrapper that starts the proxy in a Terminal window:

```bash
# Build the app (creates ~/Applications/MCP Proxy.app)
osacompile -o ~/Applications/"MCP Proxy.app" -e '
tell application "Terminal"
	do script "pkill -f mcp_proxy.py 2>/dev/null; sleep 1; /usr/local/bin/python3 -u mcp_proxy.py"
end tell
'

# Add it to Login Items
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Users/<your-user>/Applications/MCP Proxy.app", hidden:true, name:"MCP Proxy"}'
```

**Option 2: add to Login Items by hand**

1. Open **System Settings** → **General** → **Login Items**
2. Click **+** and add `start_proxy.command`

### Linux (systemd)

Create `/etc/systemd/user/mcp-proxy.service`:

```ini
[Unit]
Description=MCP HTTP Proxy

[Service]
ExecStart=/usr/bin/python3 -u /path/to/mcp_proxy/mcp_proxy.py
Restart=always

[Install]
WantedBy=default.target
```

Enable it:
```bash
systemctl --user enable mcp-proxy
systemctl --user start mcp-proxy
```

---

## Management commands

```bash
# Check proxy status
lsof -i :28080

# Stop the proxy
pkill -f mcp_proxy.py

# Start by hand (foreground)
python3 -u /path/to/mcp_proxy/mcp_proxy.py

# Start by hand (background)
nohup python3 -u /path/to/mcp_proxy/mcp_proxy.py > /tmp/mcp_proxy.log 2>&1 &

# View the log
tail -f /tmp/mcp_proxy.log
```

---

## Testing

```bash
# Test the proxy (HTTP)
curl -x http://127.0.0.1:28080 http://httpbin.org/get

# Test the proxy (HTTPS)
curl -x http://127.0.0.1:28080 -k https://your-internal-host:port/

# Test the SSE Bridge
python3 mcp_proxy.py --sse npx -y @modelcontextprotocol/server-everything &
curl http://127.0.0.1:28080/sse
# Expected: event: endpoint and data: /messages?session_id=...

# Disconnect cleanup test
# Interrupt the curl above, then confirm the child process is gone:
ps aux | grep server-everything
```

---

## Troubleshooting

### Proxy will not start
```
Error: Port already in use
```
Fix: `pkill -f mcp_proxy.py`, then start it again

### MCP still cannot connect
1. Confirm the proxy is running: `lsof -i :28080`
2. Confirm the Claude Desktop configuration is correct
3. Restart Claude Desktop

### Proxy log shows connection errors
```
[ERROR] host:port - [Errno 65] No route to host
```
The proxy itself is being blocked. Make sure it was **started by hand from a terminal**, not as a launchd service.

---

## How it works

### Proxy mode

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Desktop │     │   MCP Proxy     │     │ Internal service│
│                 │     │  (Terminal)     │     │                 │
│  MCP Server ────┼────►│  127.0.0.1:28080├────►│  192.168.x.x    │
│  (restricted)   │     │ (unrestricted)  │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### SSE Bridge mode

```
┌─────────────────┐     ┌──────────────────────────┐
│  Chatbox /      │ SSE │   MCP Proxy              │
│  Open WebUI /   │◄───►│   127.0.0.1:28080        │
│  mcp-remote     │     │                          │
│                 │     │  GET /sse ──► spawn child │
│                 │     │  POST /messages ──► stdin │
│                 │     │  stdout ──► SSE events    │
└─────────────────┘     └──────────────────────────┘
```

---

## Notes

- The proxy must be started **from a terminal or the user session context**, **not launchd** (the Avast Network Extension blocks outbound connections from launchd processes)
- The proxy has to keep running; closing the Terminal window stops it
- Recommended: add `MCP Proxy.app` (~/Applications/) to Login Items for auto-start
- Each `GET /sse` connection on the SSE Bridge spawns its own child process, cleaned up automatically on disconnect

---

Last updated: 2026-03-09
