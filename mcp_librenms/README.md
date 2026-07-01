# LibreNMS MCP Server v4.2.1

FastMCP-based LibreNMS API integration, optimized for weak/small LLMs (gpt-oss:120b etc.).

## Features

- **22 tools** — streamlined from 32, merged overlapping, removed debug/niche tools
- **Weak-model friendly** — `[YES]/[NO]` intent markers, Chinese + English docstrings
- **Compact responses** — slim device/port objects, no indent JSON, `{"data":[], "count":N}` format
- **Triple transport** — `stdio` (default, for Claude Desktop / mcpo) + `streamable-http` + `sse`
- **Smart resolvers** — `_resolve_device()` accepts hostname, IP, or device_id

## Quick Start

### Prerequisites

```bash
pip install mcp requests uvicorn
```

### stdio mode (Claude Desktop / mcpo)

```bash
python3 mcp_librenms.py \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN" \
  --verify-ssl false \
  --cache-ttl 600
```

### streamable-http mode

```bash
python3 mcp_librenms.py \
  --transport streamable-http \
  --listen 0.0.0.0 \
  --port 8080 \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN"
```

### SSE mode (for Chatbox / Open WebUI)

```bash
python3 mcp_librenms.py \
  --transport sse \
  --listen 0.0.0.0 \
  --port 8080 \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN" \
  --api-key "YOUR_MCP_API_KEY"
```

Chatbox connection settings:

| Field | Value |
|-------|-------|
| Type | Remote (http/sse) |
| URL | `http://SERVER_IP:8080/sse` |
| HTTP Header | `Authorization=Bearer YOUR_MCP_API_KEY` |

### mcpo (OpenAPI proxy) deployment

```bash
uvx mcpo --port 8000 --api-key "YOUR_KEY" -- \
  python3 mcp_librenms.py \
    --url "https://librenms.example.com/api/v0" \
    --token "YOUR_API_TOKEN" \
    --verify-ssl false
```

systemd service example:

```ini
[Unit]
Description=MCP LibreNMS Server (via mcpo)
After=network.target

[Service]
Type=simple
User=mcpuser
EnvironmentFile=/etc/default/mcp_librenms
ExecStart=/bin/bash -c 'uvx mcpo --port ${MCPO_PORT} --api-key "${MCPO_API_KEY}" -- \
  env LIBRENMS_URL=${LIBRENMS_URL} LIBRENMS_TOKEN=${LIBRENMS_TOKEN} \
  uvx --with mcp --with requests --with urllib3 python /opt/mcp/mcp_librenms.py'
Restart=always

[Install]
WantedBy=multi-user.target
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "librenms": {
      "command": "uvx",
      "args": [
        "--with", "mcp", "--with", "requests",
        "python3", "/path/to/mcp_librenms.py",
        "--url", "https://librenms.example.com/api/v0",
        "--token", "YOUR_API_TOKEN",
        "--verify-ssl", "false"
      ]
    }
  }
}
```

## Tools (22)

### Device Management
| Tool | Description |
|------|-------------|
| `list_devices` | List/search devices (default limit 50, filter by status/OS/location) |
| `get_device_info` | Get single device details by hostname/IP/device_id |
| `get_device_ports` | Get all ports for a device |
| `get_devices_with_ports` | Get multiple devices with their ports |
| `diagnose_device` | Comprehensive device diagnosis with health score |

### Network Lookup
| Tool | Description |
|------|-------------|
| `search_ip_to_mac` | IP to MAC address lookup (ARP) |
| `search_mac_to_ip` | MAC to IP address lookup (ARP) |
| `search_fdb_by_mac` | MAC to switch/port lookup (FDB) |
| `troubleshoot_ip` | Full IP trace: ARP + FDB + device + VLAN (one-shot) |

### Network Tables
| Tool | Description |
|------|-------------|
| `list_fdb_entries` | List FDB entries (by device or VLAN) |
| `get_network_arp_table` | ARP table for a network/device |

### Monitoring
| Tool | Description |
|------|-------------|
| `list_all_services` | List monitored services |
| `get_recent_alerts` | Current active (firing) alerts |
| `get_alert_history` | Historical alerts including resolved |
| `network_health_overview` | Network dashboard: health score + problem devices |

### Performance Ranking
| Tool | Description |
|------|-------------|
| `get_top_cpu` | Devices ranked by CPU usage (requires helper, see below) |
| `get_top_memory` | Devices ranked by memory usage (requires helper, see below) |

### SLA
| Tool | Description |
|------|-------------|
| `get_device_sla` | Device availability SLA (uptime %, outage history) |
| `get_cisco_sla` | Cisco IP SLA probe results (RTT, jitter, status; requires helper) |

### Utility
| Tool | Description |
|------|-------------|
| `librenms_api` | Raw API call (any LibreNMS endpoint) |
| `health_check` | Verify API connectivity |
| `clear_cache` | Clear internal API cache |

## Server-side Helper Setup

LibreNMS REST API does **not** expose processor/mempool data
([GitHub #17737](https://github.com/librenms/librenms/issues/17737)),
nor Cisco IP SLA probe data.
The `get_top_cpu`, `get_top_memory`, and `get_cisco_sla` tools require a helper PHP script
deployed on the LibreNMS server.

### Install helper

```bash
# Copy to LibreNMS web root
cp custom_top_devices.php /opt/librenms/html/
chown librenms:librenms /opt/librenms/html/custom_top_devices.php
```

### Verify

```bash
curl -sk -H "X-Auth-Token: YOUR_TOKEN" \
  "https://librenms.example.com/custom_top_devices.php?type=processor&limit=5"
```

Expected response:
```json
{"status":"ok","data":[{"device_id":1,"hostname":"sw01","sysName":"sw01",
  "ip":"10.0.0.1","cpu_usage_pct":45.2,"processor_count":2}],"count":1}
```

The MCP tools auto-detect this helper. If not deployed, they fall back to
per-device API calls (which will likely return empty due to the API limitation).

## Configuration

| CLI Param | Env Var | Default | Description |
|-----------|---------|---------|-------------|
| `--url` | `LIBRENMS_URL` | *required* | LibreNMS API base URL (`/api/v0`) |
| `--token` | `LIBRENMS_TOKEN` | *required* | API token |
| `--verify-ssl` | `LIBRENMS_VERIFY_SSL` | `true` | Verify SSL certificates |
| `--cache-ttl` | `LIBRENMS_CACHE_TTL` | `300` | Cache TTL in seconds |
| `--timeout` | `LIBRENMS_TIMEOUT` | `30` | API request timeout |
| `--max-retries` | `LIBRENMS_MAX_RETRIES` | `3` | Retry count on failure |
| `--batch-size` | `LIBRENMS_BATCH_SIZE` | `200` | Pagination batch size |
| `--transport` | - | `stdio` | Transport: `stdio`, `streamable-http`, or `sse` |
| `--listen` | - | `0.0.0.0` | HTTP bind address (http/sse transport) |
| `--port` | - | `8000` | HTTP port (http/sse transport) |
| `--api-key` | `MCP_API_KEY` | *(none)* | Bearer token auth for SSE/HTTP clients |

Priority: CLI args > environment variables > defaults.

## Changelog

### v4.2.1 (2026-03-02) - Compatibility Fix
- Requires `mcp>=1.26.0` (`TransportSecuritySettings` added in newer SDK)
- Fixed Claude Desktop startup failure caused by outdated mcp package (1.9.4 → 1.26.0)
- `pip install mcp requests uvicorn` (`uvicorn` only needed for SSE/HTTP transport)

### v4.2.0 (2026-02-26) - SLA Tools + SSE/Streamable-HTTP Fix
- Added `get_device_sla`: device availability SLA (uptime %, outage history)
- Added `get_cisco_sla`: Cisco IP SLA probe results (RTT, jitter, status)
- SSE/Streamable-HTTP: use `uvicorn` + `sse_app()`/`streamable_http_app()` (fixes custom host/port)
- Disabled DNS rebinding protection (fixes 421 Misdirected Request from Chatbox/Open WebUI)
- Added `--api-key` Bearer token authentication for SSE/HTTP clients
- `custom_top_devices.php`: added `cisco_sla` query type
- `_extract_data` keys expanded: `availability`, `outages`

### v4.1.0 (2026-02-23) - CPU/Memory Ranking + Robustness
- Added `get_top_cpu`, `get_top_memory` tools with `custom_top_devices.php` helper
- `custom_top_devices.php`: server-side DB query bypassing API limitation
- sysName included in all device-referencing tool responses
- `list_devices` default limit changed from unlimited to 50
- Improved docstrings with Chinese trigger phrases for weak model matching
- Multi-strategy health data retrieval with diagnostic error messages
- `_extract_data` keys expanded: processors, mempools, graphs, sensors

### v4.0.0 (2026-02-10) - Complete Rewrite
- 32 to 18 tools (merged overlapping, removed debug/niche tools)
- Compact JSON via `_R()` (no indent, no `ensure_ascii`)
- Slim device/port objects (`_slim_device` ~11 fields, `_slim_port` ~7 fields)
- `_resolve_device()` accepts hostname/IP/device_id
- Human-readable params: `state="ok"/"warning"/"critical"`, `vlan_tag` not `vlan_id`
- Consistent `{"data": [...], "count": N}` response format
- `[YES]/[NO]` intent markers in docstrings
- Dual transport: stdio + streamable-http

### v3.11.0 - Dual transport support (stdio + streamable-http)
### v3.10.2 - VLAN mapping fix (vlan_id vs vlan_vlan)
### v3.x - Initial FastMCP implementation, 32 tools

## Author

**Jason Cheng** (Jason Tools) - Enhanced by Claude
License: MIT
