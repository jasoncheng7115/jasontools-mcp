# phpIPAM MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **phpIPAM**, built on FastMCP. It exposes **21 tools** for IP address management, subnets, VLANs, devices, racks and folders, with token-efficient plain-text output tuned for small/local LLMs (e.g. `gpt-oss:120b`).

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 2.5
- **Transports:** `stdio` (default), `sse`, `streamable-http`

---

## Features

- **Sections & subnets** — list/inspect sections and subnets, subnet usage stats (used/free/total), CIDR search.
- **IP addresses** — list used IPs in a subnet, **find the next free IP**, search by IP or hostname (partial match).
- **VLANs, devices, racks, folders, tags** — list/detail for each; rack view includes mounted devices and space utilization.
- **Utility** — `health_check` (API reachability) and `clear_cache`.
- **Token-efficient output** — pipe-table for lists, `key: value` for details, detail field allowlists to drop noise, long values truncated (30 chars), search results capped at 50 to avoid context overflow.
- Consistent `page`/`page_size` pagination on every list endpoint; response caching with TTL.
- Multi-transport, optional API-key (Bearer) auth for HTTP (pure-ASGI middleware so SSE streaming isn't broken).

---

## Requirements

- Python 3.10+
- A phpIPAM **API app** (App ID) with a token; the App must have API access enabled.
- Python packages:

```bash
pip install mcp requests urllib3
# uvicorn is required for the sse / streamable-http transports
pip install uvicorn
```

Or run directly with `uvx` (no venv needed):

```bash
uvx --with mcp --with requests --with urllib3 --with uvicorn \
    python mcp_phpipam.py
```

---

## Configuration

The **phpIPAM connection is configured via environment variables**; transport/auth options are CLI flags (or env where noted).

### phpIPAM connection (env vars)

| Env var | Default | Description |
|---|---|---|
| `PHPIPAM_URL` | — (required) | Base URL, e.g. `https://phpipam.example.com` (a trailing `/api` is stripped) |
| `PHPIPAM_TOKEN` | — (required) | API token |
| `PHPIPAM_APP_ID` | — (required) | API App ID (from phpIPAM → Administration → API) |
| `PHPIPAM_CACHE_TTL` | `300` | Response cache TTL (seconds) |
| `PHPIPAM_TIMEOUT` | `10` | Request timeout (seconds) |
| `PHPIPAM_VERIFY_SSL` | `false` | Verify TLS certificate (`true` to enable) |

### Transport / auth

| Env var | CLI arg | Default | Description |
|---|---|---|---|
| — | `--transport` / `-t` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--host` / `-H` | `127.0.0.1` | HTTP bind address |
| — | `--port` / `-p` | `8000` | HTTP port |
| `MCP_API_KEY` | `--api-key` / `-k` | — | Bearer token to protect the HTTP/SSE endpoint |

---

## Usage

### stdio (default)

```bash
PHPIPAM_URL=https://phpipam.example.com \
PHPIPAM_TOKEN=YOUR_TOKEN PHPIPAM_APP_ID=mcp \
python3 mcp_phpipam.py
```

### SSE

```bash
python3 mcp_phpipam.py --transport sse --host 0.0.0.0 --port 8012 --api-key YOUR_BEARER_TOKEN
# (PHPIPAM_* env vars must be set)
```

### Streamable HTTP

```bash
python3 mcp_phpipam.py --transport streamable-http --host 0.0.0.0 --port 8007
```

---

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "phpipam": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/scripts/mcp_phpipam/mcp_phpipam.py"],
      "env": {
        "PHPIPAM_URL": "https://your-phpipam-host",
        "PHPIPAM_TOKEN": "your_token",
        "PHPIPAM_APP_ID": "your_app_id",
        "PHPIPAM_CACHE_TTL": "300",
        "PHPIPAM_TIMEOUT": "10",
        "PHPIPAM_VERIFY_SSL": "false"
      }
    }
  }
}
```

Restart Claude Desktop after editing.

---

## Open WebUI (via mcpo)

Expose the stdio server as an OpenAPI endpoint with [`mcpo`](https://github.com/open-webui/mcpo):

```bash
uvx mcpo --port 8007 --api-key "YOUR_MCPO_KEY" -- \
  env PHPIPAM_URL=https://your-phpipam-host \
      PHPIPAM_TOKEN=TOKEN PHPIPAM_APP_ID=mcp \
      PHPIPAM_VERIFY_SSL=false \
  python /opt/mcp/mcp_phpipam.py
```

Each tool is then available at `POST http://host:8007/<tool_name>` with `Authorization: Bearer YOUR_MCPO_KEY`. Point Open WebUI's tool server at `http://host:8007`.

---

## Tools (21)

### Sections & subnets

| Tool | Description |
|---|---|
| `list_sections` | List all IPAM sections |
| `get_section` | Section details by ID |
| `list_subnets` | List subnets (all, or filtered by section) |
| `get_subnet` | Full subnet details by ID |
| `get_subnet_usage` | Subnet usage stats (used / free / total) |
| `search_subnet` | Search subnets by CIDR / network address |

### IP addresses

| Tool | Description |
|---|---|
| `find_free_ip` | Find the next available IP in a subnet |
| `list_subnet_addresses` | List used IPs in a subnet (who's using each) |
| `search_ip` | Search a specific IP across all subnets |
| `search_hostname` | Search IP records by hostname (partial match) |

### VLANs, devices, racks, folders, tags

| Tool | Description |
|---|---|
| `list_vlans` | List all VLANs |
| `get_vlan` | VLAN details by DB ID |
| `list_devices` | List network devices (switches/routers/firewalls/servers…) |
| `get_device` | Device details by ID |
| `list_racks` | List server/network racks |
| `get_rack` | Rack details incl. mounted devices + space utilization |
| `list_folders` | List organizational folders |
| `get_folder` | Folder details + contained sections |
| `list_tags` | List IP status tags (Used, Available, Reserved, DHCP…) |

### Utility

| Tool | Description |
|---|---|
| `health_check` | Check phpIPAM API reachability |
| `clear_cache` | Clear the API response cache |

---

## Notes

- **App ID + token.** Create an API app in phpIPAM (Administration → API), enable it, and use its App ID + token. `PHPIPAM_URL` should be the site root; a trailing `/api` is stripped automatically.
- **Token-efficient by design.** Lists render as compact pipe-tables with truncated values; detail views use field allowlists; search results are capped at 50 to protect the LLM context.
- All tools return plain-text/JSON payloads; connection errors are reported in the response.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies; the API-key middleware is pure-ASGI so it doesn't break SSE streaming.

---

## Changelog (recent)

- **v2.5** — Small-LLM optimization: clearer tool descriptions, consistent `page`/`page_size` pagination, token-efficient plain-text output, detail field allowlists, SSE/streamable-http via uvicorn with DNS-rebinding disabled, optional `--api-key` Bearer auth.
