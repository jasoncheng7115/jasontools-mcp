# LibreNMS MCP Server v4.5.0

FastMCP-based LibreNMS API integration, optimized for weak/small LLMs (gpt-oss:120b etc.).

## Features

- **29 tools** — streamlined from 32, merged overlapping, removed debug/niche tools
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

## Tools (29)

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
| `get_event_log` | Device event log (state/config/hardware changes) |
| `get_monitoring_health` | Devices that stopped being polled (stale/disabled/ignored) |
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

### Sensors / Hardware
| Tool | Description |
|------|-------------|
| `get_sensor_health` | Temperature, voltage, fan, power sensor health + outliers |
| `get_optical_health` | SFP/GBIC DDM light-level margin + replacement risk ranking |

### Port Traffic
| Tool | Description |
|------|-------------|
| `get_port_traffic` | Bandwidth utilisation + error counters, ranked worst-first |

### Whole-network Performance
| Tool | Description |
|------|-------------|
| `get_all_device_performance` | CPU + memory for **every** device in one call, not just top N |

### Syslog
| Tool | Description |
|------|-------------|
| `get_syslog` | Syslog messages devices sent to LibreNMS (scope by device — see the quirks table) |

### Utility
| Tool | Description |
|------|-------------|
| `librenms_api` | Raw API call (any LibreNMS endpoint) |
| `health_check` | Verify API connectivity |
| `clear_cache` | Clear internal API cache |

## Optical Health Notes

`get_optical_health` is a **point-in-time snapshot** — nothing is stored between
calls. LibreNMS keeps sensor history in RRD and the REST API exposes it only as
graph images, so decay-rate prediction ("this GBIC will hit the alarm threshold
in N months") is **not** possible without either a server-side helper reading RRD
or a local datastore. Risk is instead ranked by:

- **Threshold margin** — `sensor_current` minus the low-light alarm limit
- **Peer outlier** — deviation from the median of same-device, same-direction
  modules (median/MAD, needs ≥4 peers). Substitutes cross-sectional comparison
  for the unavailable longitudinal one.
- **Bias current / temperature** — paired from the same transceiver when present

### Fallback thresholds

Devices that report no `sensor_limit_low` (MikroTik RouterOS returns NULL for
every optical limit) fall back to generic SFP/SFP+ values:

| Direction | Low alarm | Low warn |
|-----------|-----------|----------|
| RX | -20.0 dBm | -18.0 dBm |
| TX | -9.0 dBm | -8.0 dBm |

Rows resolved this way are marked `src=fb` in the output so a fallback verdict is
never mistaken for vendor data. Adjust `_OPT_FALLBACK_LIMITS` for your optics.

### Requirements

Transceivers must expose DDM/DOM and the LibreNMS `sensors` discovery module must
be enabled, otherwise no `dbm` sensors exist and the tool reports zero modules.
Readings older than `stale_days` (default 7) are reported as `stale` rather than
scored, so a device that stopped being polled does not surface as a false critical.

## API Quirks Worth Knowing

Observed on a LibreNMS instance while building v4.3/v4.4. Verify against your own
server before relying on any of it.

| Endpoint | Behaviour |
|----------|-----------|
| `/devices` | **Ignores `limit`, `hostname`, `ip`, and `columns`** — always returns every device with all 61 columns. Filtering must be done client-side, and a query filter's result must never be trusted without verifying it (see the v4.3.0 `_resolve_device` fix). |
| `/ports` | **Honours `columns`** — the default response has no traffic or error counters at all. `get_port_traffic` requests them explicitly. |
| `/logs/eventlog` | Returns **oldest-first** and can hold hundreds of thousands of rows. Use `?from=` to window it; paging to the end is not viable. |
| `/resources/sensors` | One call returns every sensor on every device. This is what keeps the sensor tools to a single request. |
| `/devices/{id}/availability` | One call per device, so whole-network SLA is fanned out over a thread pool. |
| `/resources/links`, `/resources/wireless` | Returned 404 — no LLDP topology or wireless data. Link-endpoint correlation for optical is therefore not possible. |
| `ifInDiscards` / `ifOutDiscards` | Not valid `columns` values; only `ifInErrors_delta` / `ifOutErrors_delta` are available. |
| `/devices/{id}/processors`, `/devices/{id}/mempools` | **HTTP 500 on 26.x master.** Use `/devices/{id}/health/processor` to list sensor ids, then `/devices/{id}/health/processor/{sensor_id}` for the reading. `get_all_device_performance` does exactly this, fanned out over a thread pool. |
| `/logs/syslog` | Extremely slow. Unscoped, two rows took **41.7s**; adding `from=` timed out entirely. Scoping by numeric `device_id` (17s) beats scoping by hostname (54s). `get_syslog` defaults to a 120s timeout and asks for a device. |
| `custom_top_devices.php` | The bundled helper bootstraps `includes/init.php`. On 26.x it emits its headers and then **zero bytes** — the fast path silently yields nothing, so the tools must have a working fallback. |

## Monitoring Health

`get_monitoring_health` exists because every other tool reports whatever LibreNMS
last stored. A device that silently stopped being polled still returns confident
readings — on the reference server, a disabled switch was serving sensor values
from 2023 with no indication they were three years old.

Categories: `never_polled`, `stale` (beyond `stale_hours`), `disabled` (retains
last known values indefinitely), `ignored`, `down`, `slow_poll` (>30s per poll).

Run it first when any other tool returns numbers that look implausible.

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

### v4.5.0 (2026-09-06) - Whole-network Performance / Syslog

Two tools, both driven by what the reference server could not answer:

- **`get_all_device_performance`** — CPU and memory for every device in one call.
  `get_top_cpu` / `get_top_memory` only ever returned a ranked slice, and on a
  server without the PHP helper they fell back to a serial per-device loop that
  did not finish inside 120s. The new tool fans out over a thread pool and
  returned all 72 up devices in **9.7s**.
- **`get_syslog`** — syslog messages, which had no tool at all. `get_event_log`
  covers LibreNMS's own event log, which is a different thing.

Supporting changes:

- `_api_request` accepts a per-call `timeout`; the 30s default cannot cover syslog.
- The performance fallback reads `health/{type}` then `health/{type}/{sensor_id}`
  because `/devices/{id}/processors` and `/mempools` return HTTP 500 on 26.x.

### v4.4.0 (2026-07-29) - Sensor / Port / Event / Monitoring Coverage
- Added `get_sensor_health`: temperature, voltage, fan, power sensor health with
  two-sided peer-outlier detection. On the reference server 369 of 377 sensors
  had no tool covering them before this.
- Added `get_port_traffic`: bandwidth utilisation and error counters ranked
  worst-first, sortable by `utilization` / `errors` / `traffic`. Requires
  `?columns=` on `/ports` — the default response omits both entirely.
- Added `get_event_log`: device event log windowed with `?from=`
- Added `get_monitoring_health`: surfaces devices that stopped being polled
- `get_device_sla` whole-network fetch parallelised via new `_parallel_map`:
  **11.6s → 5.3s** on 82 devices (previously one serial call per device)
- `SimpleCache` is now lock-protected — its expiry path could raise `KeyError`
  once reached from a thread pool
- `_peer_outliers` generalised from the optical-only version, with two-sided
  support so a sensor far *above* its peers is flagged too
- Fixed sensor class filter: an empty class set is now treated as "nothing
  qualifies" rather than "no filter", which had leaked `dbm` rows into
  `get_sensor_health` for devices holding only optical sensors

### v4.3.0 (2026-07-29) - Optical Transceiver Health
- Added `get_optical_health`: SFP/GBIC DDM light-level margin + risk ranking
- Whole-network scope via a single `resources/sensors` call; raw sensor rows are
  never returned to the caller, only summary counts plus capped detail rows
  (default 20, hard cap 100)
- Pairs `dbm` with the bias-current / temperature sensors of the same transceiver
  by reducing `sensor_descr` to a port key
- Built-in fallback thresholds when a device reports no `sensor_limit_low`
- Peer-outlier detection (median/MAD) replaces trend analysis, which is
  impossible without stored history
- Stale readings reported as `stale`, not scored as `critical`
- **Fixed `_resolve_device`**: LibreNMS versions that ignore the `?hostname=` /
  `?ip=` query filter return the full device list, and taking `devs[0]` resolved
  *every* hostname/IP to the same device. Results are now verified against the
  query. Affected every tool with a `device` parameter; only numeric device IDs
  had been resolving correctly.

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
