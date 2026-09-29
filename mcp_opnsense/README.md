# OPNsense MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **OPNsense**, built on FastMCP and optimized for weak/small LLMs (e.g. `gpt-oss`, `gemma`). It exposes **21 read-only tools** with compact JSON output and camelCase tool names.

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 2.4.1
- **Transports:** `stdio` (default), `sse`, `streamable-http`

> Tested against **OPNsense 26.1.10**. Reads use the native API where one exists and fall back to `config.xml`, so older releases degrade instead of breaking — see [Minimum OPNsense version per data source](#minimum-opnsense-version-per-data-source). **Port forward needs 26.1+** for the API path; **firewall rules need 26.1+** to be complete (below that, see the cutover note).

---

## Features

- Read firewall **filter rules** via the native API (`firewall/filter/search_rule`), covering GUI rules, automation rules and legacy rules alike.
- **Alias-aware rules**: each rule resolves `src_alias` / `dst_alias` plus the alias description.
- **Aliases** with resolved entry list and live item counts.
- **All four NAT types** through one tool — port forward (26.1 `d_nat` API), outbound, one-to-one, NPTv6.
- **Gateways**: configuration *and* live dpinger status in one call — monitor IP, `monitor_disable`, priority, weight, loss/latency, including dynamic DHCP/PPPoE gateways.
- Services, DHCP leases/settings, interfaces, ARP/NDP, routes.
- Firmware status/info/config, packages and plugins (`os-*`).
- Config summary, plus raw XML export of any `config.xml` section.
- API-first with automatic `config.xml` fallback; every answer reports the `source` it came from.
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
  --host "https://opnsense.example.com" \
  --api-key KEY --api-secret SECRET
```

### SSE

```bash
python3 mcp_opnsense.py --transport sse --listen 0.0.0.0 --port 8017 \
  --host "https://opnsense.example.com" --api-key KEY --api-secret SECRET \
  --mcp-api-key YOUR_BEARER_TOKEN
```

SSE mode also serves **Streamable HTTP at `/mcp` on the same port** (since v2.4.1). Prefer `/mcp` for any
client that supports it (e.g. Claude Code `"type": "http"`): SSE clients that auto-reconnect after a dropped
connection (laptop sleep, network blip) get a fresh session without re-sending `initialize`, and every call then
fails with `-32602 Invalid request parameters`. `/mcp` is stateless, so there is no session to lose.

### Streamable HTTP

```bash
python3 mcp_opnsense.py --transport streamable-http --port 8000 \
  --host "https://opnsense.example.com" --api-key KEY --api-secret SECRET
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

## Tools (21)

| Tool | Description |
|---|---|
| `getConfigSummary` | System info + firewall/alias/NAT/interface counts (rules counted via API) |
| `getFirewallRules` | Filter rules via API, config.xml fallback; alias-aware |
| `getNatRules` | NAT rules of any type via API, config.xml fallback |
| `getNatRulesConfig` | NAT rules straight from config.xml (compatibility; prefer `getNatRules`) |
| `getGateways` | Gateway config **and** live status: monitor IP, priority, loss/delay |
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
| `downloadConfigXml` | config.xml: summary, or raw XML of a named section |
| `getPlugins` | OPNsense plugins (`os-*`); filter by status/search |
| `getPackages` | System packages (non `os-*`); filter by status/search |

Every tool that can read from either source reports which one it used in a `source` field (`"api"` or `"config"`).

### `getFirewallRules` arguments

| Arg | Default | Description |
|---|---|---|
| `interface` | — | Filter by interface key (`wan`, `lan`, `opt1`, …). Matches rules spanning several interfaces (`"wan,opt2"`) |
| `action` | — | `pass` / `block` / `reject` |
| `enabled_only` | — | `true` = enabled, `false` = disabled, omit = all |
| `aliases_only` | `false` | Only rules referencing an alias |
| `include_automatic` | `true` | `false` = only rules a human configured |

### `getNatRules` arguments

| Arg | Default | Description |
|---|---|---|
| `nat_type` | `port_forward` | `port_forward` / `outbound` / `one_to_one` / `npt`. Aliases: `forward` → `port_forward`, `source_nat` / `source` → `outbound` |
| `enabled_only` | — | `true` = enabled, `false` = disabled, omit = all |
| `search` | — | Filter by description (case-insensitive) |
| `include_automatic` | `false` | Include rules OPNsense synthesizes for display (anti-lockout, automatic outbound NAT) — these are not in the config |

### `downloadConfigXml` arguments

| Arg | Default | Description |
|---|---|---|
| `section` | — | Top-level section to dump as raw XML (`gateways`, `system`, `nat`, `interfaces`, `OPNsense/Gateways`, …). Omit for the summary |
| `max_chars` | `40000` | Truncation limit — the full config.xml is typically 300 KB+ |

### `getGateways` arguments

| Arg | Default | Description |
|---|---|---|
| `name` | — | Only this gateway (case-insensitive). Omit for all |

---

## Minimum OPNsense version per data source

Tools read the native MVC API first and fall back to `config.xml` when it is unavailable, so an older firewall degrades rather than breaking. What you lose depends on the release:

| Data | API endpoint | Min version | Below that |
|---|---|---|---|
| Firewall rules | `firewall/filter/search_rule` | **24.1** | config.xml `<filter><rule>` |
| Port forward | `firewall/d_nat/search_rule` | **26.1** | config.xml `<nat><rule>` |
| Outbound NAT | `firewall/source_nat/search_rule` | **24.1** | config.xml `<nat><outbound>` |
| One-to-one NAT | `firewall/one_to_one/search_rule` | **24.7** | config.xml `<nat><onetoone>` |
| NPTv6 | `firewall/npt/search_rule` | **24.1** | *no config.xml equivalent — API only* |
| Aliases | `firewall/alias/search_item` | **23.7** | config.xml `<alias>` |
| Alias contents | `firewall/alias_util/list/{name}` | **23.7** | — |
| Gateways | `routing/settings/search_gateway` | **24.1** | config.xml + `routes/gateway/status` |
| config.xml download | `core/backup/download/this` | **23.7.8** | requires the `os-api-backup` plugin |

### The 26.1 firewall-rule cutover (read this before trusting a rule count)

`firewall/filter/search_rule` exists from 24.1, **but on 24.1–25.7 it only returned Firewall → Automation rules** — the rules you see in the GUI lived in `config.xml` `<filter><rule>`. In **26.1** those rules were promoted into the MVC model, and `config.xml` `<filter><rule>` is now **empty**.

So neither source alone is right across versions:

- Reading config.xml on 26.1 returns **0 rules** on a firewall with hundreds.
- Reading the API on 25.x returns **only automation rules** unless `show_all=1` is sent.

This server sends `show_all=1` (on 25.x that is what merges the legacy config.xml rules into the response; on 26.1 they are always merged and the flag is harmless) and falls back to config.xml only if the API call fails. `getConfigSummary` reports both `firewall_rules` (effective, from the API) and `firewall_rules_in_xml`, so a `0` reads as "migrated" rather than "none".

Gateways moved the same way: 26.1 leaves an empty `<gateways><gateway_item/></gateways>` stub in config.xml and keeps the real config under `<OPNsense><Gateways>`. `downloadConfigXml(section="gateways")` detects the stub and points at the new path.

---

## Notes

- All tools return JSON; errors come back as `{"error": "..."}` rather than raising.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies.
- The HTTP client honours `HTTP_PROXY` / `HTTPS_PROXY`. Claude Desktop on macOS needs this to route through `mcp_proxy` when security software blocks its child processes.
- **Reading gateway status alone is misleading.** A gateway with `monitor_disable` set is never probed by dpinger, so it always reports `Online` and *cannot* be marked down. `getGateways` flags that case in a `note` field rather than letting it look healthy.
- Rules OPNsense generates itself (automatic filter rules, anti-lockout port forwards, automatic outbound NAT) are tagged `is_automatic`. They are display-only and not in the config.

---

## Changelog (recent)

- **v2.4.1** — SSE mode also serves Streamable HTTP at `/mcp` (stateless), so clients no longer get stuck on an uninitialized session after an SSE reconnect (all calls failing with `-32602`); API-key check moved to plain ASGI middleware (constant-time compare), ending the `AssertionError` logged on every SSE disconnect.
- **v2.4.0** — **Fixes `getFirewallRules` / `getConfigSummary` returning 0 rules on OPNsense 26.1** (they read config.xml, which 26.1 leaves empty). Reads are now API-first with a config.xml fallback and report their `source`. New `getGateways` (config + live status, incl. dynamic DHCP/PPPoE gateways). `getNatRules` becomes the single NAT entry point and gains port forward via the 26.1 `firewall/d_nat` API. `downloadConfigXml` gains `section` to return real XML instead of only counts. Backward compatible: all v2.3.0 tool names and arguments still work.
- **v2.3.0** — Claimed API-based rules + aliases, but the code still parsed config.xml; the `firewall_rules=0` bug it was meant to fix shipped instead. Superseded by v2.4.0.
- **v2.2.x** — `getPlugins` / `getPackages`; OPNsense version in config summary.
- **v2.0.0** — FastMCP rewrite, 35 → 20 tools, camelCase names, multi-transport.
