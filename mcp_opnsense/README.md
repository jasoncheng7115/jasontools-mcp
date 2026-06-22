# OPNsense MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **OPNsense**, built on FastMCP and optimized for weak/small LLMs (e.g. `gpt-oss`, `gemma`). It exposes **20 read-only tools** with compact JSON output and camelCase tool names.

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Transports:** `stdio` (default), `sse`, `streamable-http`

> Tested against **OPNsense 26.1.x**. Firewall rule / alias retrieval uses the native API and requires **OPNsense 24.7+** (see [Notes](#notes)).

---

## Features

- Read firewall **filter rules** via the native API (`firewall/filter/search_rule` with `show_all=1`) — including GUI rules under *Firewall > Rules*, not just automation rules.
- **Alias-aware rules**: each rule resolves `src_alias` / `dst_alias` plus the alias description.
- **Aliases** with resolved entry list and live item counts.
- NAT (config.xml + API), services, DHCP leases/settings, interfaces, ARP/NDP, routes.
- Firmware status/info/config, packages and plugins (`os-*`).
- Config summary + raw `config.xml` download/parse.
- Multi-transport, optional API-key auth for HTTP, response caching with TTL, retry with backoff.

---

## Requirements

- Python 3.10+
- An OPNsense **API key + secret** (System → Access → Users → *API keys*)
- Python packages:

```bash
pip install mcp aiohttp requests defusedxml urllib3 uvicorn
```

`uvicorn` is only needed for the `sse` / `streamable-http` transports.

---

## Configuration

Settings are resolved in this order: **CLI args > environment variables > defaults**.

| Env var | CLI arg | Default | Description |
|---|---|---|---|
| `OPNSENSE_HOST` | `--host` | — (required) | Base URL, e.g. `https://192.168.1.1` |
| `OPNSENSE_API_KEY` | `--api-key` | — | OPNsense API key |
| `OPNSENSE_API_SECRET` | `--api-secret` | — | OPNsense API secret |
| `OPNSENSE_VERIFY_SSL` | `--verify-ssl` | `false` | Verify TLS certificate |
| `OPNSENSE_TIMEOUT` | `--timeout` | `30` | Request timeout (seconds) |
| `OPNSENSE_CACHE_TTL` | `--cache-ttl` | `300` | GET cache TTL (seconds) |
| `OPNSENSE_MAX_RETRIES` | `--max-retries` | `3` | Retry attempts (exponential backoff) |
| — | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--listen` | `0.0.0.0` | HTTP bind address |
| — | `--port` | `8000` | HTTP port |
| `MCP_API_KEY` | `--mcp-api-key` | — | Bearer token to protect the HTTP/SSE endpoint |

---

## Usage

### stdio (default)

```bash
python3 mcp_opnsense.py \
  --host "https://192.168.1.1" \
  --api-key KEY --api-secret SECRET
```

### SSE

```bash
python3 mcp_opnsense.py --transport sse --listen 0.0.0.0 --port 8017 \
  --host "https://192.168.1.1" --api-key KEY --api-secret SECRET \
  --mcp-api-key YOUR_BEARER_TOKEN
```

### Streamable HTTP

```bash
python3 mcp_opnsense.py --transport streamable-http --port 8000 \
  --host "https://192.168.1.1" --api-key KEY --api-secret SECRET
```

---

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/mcp_opnsense/mcp_opnsense.py"],
      "env": {
        "OPNSENSE_HOST": "https://your-opnsense-host",
        "OPNSENSE_API_KEY": "your-opnsense-api-key",
        "OPNSENSE_API_SECRET": "your-opnsense-api-secret",
        "OPNSENSE_VERIFY_SSL": "false",
        "OPNSENSE_TIMEOUT": "30"
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
uvx mcpo --port 8016 --api-key "YOUR_MCPO_KEY" -- \
  env OPNSENSE_HOST=https://192.168.1.1 \
      OPNSENSE_API_KEY=KEY \
      OPNSENSE_API_SECRET=SECRET \
      OPNSENSE_VERIFY_SSL=false \
  python /opt/mcp/mcp_opnsense.py
```

Each tool is then available at `POST http://host:8016/<toolName>` with `Authorization: Bearer YOUR_MCPO_KEY`. Point Open WebUI's tool server at `http://host:8016`.

---

## Tools (20)

| Tool | Description |
|---|---|
| `getConfigSummary` | System info + firewall/alias/NAT/interface counts (rule & alias counts via API) |
| `getFirewallRules` | Filter rules via API (`source="api"`, default) or config.xml; alias-aware |
| `getNatRulesConfig` | NAT rules from config.xml (forward / outbound / source / one_to_one) |
| `getAliases` | Aliases via API (default) or config.xml; content list + item counts |
| `getAliasContent` | Resolved entries of a specific alias |
| `getServices` | Service overview (running / stopped / locked) |
| `getServiceStatus` | Status of one service |
| `getFirmwareStatus` | Update availability + health check |
| `getFirmwareInfo` | Full package list + security audit |
| `getFirmwareConfig` | Firmware settings, mirror options, repo connectivity |
| `getPackageInfo` | Details / license / changelog for one package |
| `getDhcpLeases` | DHCPv4 leases (optional search) |
| `getDhcpSettings` | DHCP service status + settings |
| `getInterfaces` | Interfaces from config.xml + API (optional stats) |
| `getNetworkNeighbors` | ARP (IPv4) and/or NDP (IPv6) tables |
| `getRoutes` | Routing table |
| `getNatRules` | NAT rules via API (`source_nat` / `one_to_one`) |
| `downloadConfigXml` | Download + parse config.xml; system info + section counts |
| `getPlugins` | OPNsense plugins (`os-*`); filter by status/search |
| `getPackages` | System packages (non `os-*`); filter by status/search |

### `getFirewallRules` arguments

| Arg | Default | Description |
|---|---|---|
| `source` | `api` | `api` (native rule API) or `config` (config.xml) |
| `interface` | — | Filter by interface name or label (`wan`, `lan`, `opt1`, …) |
| `action` | — | `pass` / `block` / `reject` |
| `enabled_only` | — | `true` = enabled, `false` = disabled, omit = all |
| `aliases_only` | `false` | Only rules referencing an alias |
| `automatic` | — | `true` = auto rules, `false` = user rules (api only) |

---

## Notes

- **Firewall rules need the API.** Since OPNsense 24.7 the rule engine moved to the MVC model, so the legacy `config.xml` `<filter><rule>` section is empty. This server fetches rules from `firewall/filter/search_rule` with `show_all=1`, which is why `getFirewallRules`, `getConfigSummary` and `downloadConfigXml` default to the API for rule counts.
- **`source="config"`** (for `getFirewallRules` / `getAliases`) and `downloadConfigXml` require config.xml download, available on OPNsense ≥ 23.7.8 or with the `os-api-backup` plugin.
- All tools return JSON; errors come back as `{"error": "..."}` rather than raising.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies.

---

## Changelog (recent)

- **v2.3.0** — Fetch firewall rules + aliases via native API (`search_rule?show_all=1`, `alias/search_item`); alias matching via `alias_meta_*`; fixed `firewall_rules=0` in `getConfigSummary`/`downloadConfigXml` on 24.7+.
- **v2.2.x** — `getPlugins` / `getPackages`; OPNsense version in config summary.
- **v2.0.0** — FastMCP rewrite, 35 → 20 tools, camelCase names, multi-transport.
