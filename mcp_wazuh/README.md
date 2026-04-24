# MCP Server for Wazuh SIEM

FastMCP-based Wazuh SIEM integration for LLM tools. Exposes 25 MCP tools covering
alerts, vulnerabilities, agents, rules, logs, cluster, and cache.

- Author: Jason Cheng (co-created with Claude Code)
- License: MIT
- Version: v1.3.8 (2026-04-24)
- Languages: [English](README.md) · [繁體中文](README_zh-TW.md)

---

## What it does

Talk to a Wazuh SIEM deployment from an LLM. The server speaks to two Wazuh APIs:

- Wazuh Manager API (port 55000, JWT) — agents, rules, cluster, stats
- Wazuh Indexer (port 9200, Basic auth) — raw alerts in `wazuh-alerts-*`

Responses are compacted (None stripped, minimal JSON separators) and include a
human-readable `severity` label on top of the raw `rule.level` number so small models
don't misinterpret the 0-15 scale.

---

## Requirements

- Python 3.10+
- Wazuh Manager & Indexer reachable over HTTPS (tested against Wazuh 4.x, including 4.12)
- Python packages: `mcp`, `requests`, `urllib3`, `uvicorn` (for SSE / streamable-http)

```bash
pip install mcp requests urllib3 uvicorn
```

---

## Quick start

### stdio transport (Claude Desktop / local CLI)

```bash
python3 mcp_wazuh.py \
  --manager-host 192.168.1.40 --manager-user wazuh  --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin  --indexer-pass CHANGE_ME
```

### SSE transport (Chatbox and similar legacy MCP clients)

```bash
python3 mcp_wazuh.py --transport sse --host 0.0.0.0 --port 8014 \
  --api-key YOUR_SECRET_KEY \
  --manager-host 192.168.1.40 --manager-user wazuh --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass CHANGE_ME
```

Endpoint: `http://<host>:8014/sse`

### Streamable HTTP transport (multi-client / network access)

```bash
python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \
  --api-key YOUR_SECRET_KEY \
  --manager-host 192.168.1.40 --manager-user wazuh --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass CHANGE_ME
```

Endpoint: `http://<host>:8000/mcp`

---

## Configuration

Precedence: **CLI args > environment variables > defaults**.

### CLI arguments

| Argument | Description | Default |
|---|---|---|
| `--manager-host` | Manager hostname / IP | (required) |
| `--manager-port` | Manager port | `55000` |
| `--manager-user` / `--manager-pass` | Manager credentials | (required) |
| `--indexer-host` | Indexer hostname / IP | (required) |
| `--indexer-port` | Indexer port | `9200` |
| `--indexer-user` / `--indexer-pass` | Indexer credentials | (required) |
| `--use-ssl` | Enable TLS verification | `false` |
| `--protocol` | `http` or `https` | `https` |
| `--cache-duration` | Cache TTL (seconds) | `300` |
| `--request-timeout` | Request timeout (seconds) | `30` |
| `--retry-attempts` | Retry attempts | `3` |
| `--transport` | `stdio`, `sse`, or `streamable-http` | `stdio` |
| `--host` | HTTP server bind | `0.0.0.0` |
| `--port` | HTTP server port | `8000` |
| `--api-key` | Bearer token for SSE / HTTP | (none) |
| `--severity-low-max` | Max rule level counted as Low | `6` |
| `--severity-medium-max` | Max rule level counted as Medium | `11` |
| `--severity-high-max` | Max rule level counted as High | `13` |

### Environment variables

```
WAZUH_API_HOST              WAZUH_INDEXER_HOST
WAZUH_API_PORT              WAZUH_INDEXER_PORT
WAZUH_API_USERNAME          WAZUH_INDEXER_USERNAME
WAZUH_API_PASSWORD          WAZUH_INDEXER_PASSWORD
WAZUH_VERIFY_SSL            WAZUH_TEST_PROTOCOL
WAZUH_CACHE_TTL             WAZUH_TIMEOUT
WAZUH_MAX_RETRIES
WAZUH_SEVERITY_LOW_MAX      WAZUH_SEVERITY_MEDIUM_MAX
WAZUH_SEVERITY_HIGH_MAX
MCP_API_KEY
```

### Severity thresholds

Wazuh rule levels run 0-15 and there is no single official Low/Medium/High/Critical split.
The defaults match common Wazuh Dashboard VIS buckets:

- Low: 0-6
- Medium: 7-11
- High: 12-13
- Critical: 14-15

If your Dashboard uses different thresholds, override them at startup, e.g.

```bash
--severity-low-max 3 --severity-medium-max 7 --severity-high-max 11
```

produces Low 0-3, Medium 4-7, High 8-11, Critical 12-15.

---

## Tools

### Alert monitoring
- `alertSummary` — full alerts with IoC extraction, paginated
- `alertStatistics` — counts + severity distribution + top rules / agents
- `agentsWithAlerts` — Top N agents by alert count

### Rules
- `rulesSummary` — detection rules with compliance mappings (GDPR, HIPAA, PCI-DSS, NIST)

### Vulnerabilities
- `vulnerabilitySummary` — CVE list per agent

### Agent management
- `listAgents` — agent inventory (paginated)
- `listGroups` — agent groups with counts
- `agentDetail` / `agentHardware` / `agentPackages` / `agentNetworks` / `agentSCA`
- `agentProcesses` / `agentPorts`
- `agentsOutdated` / `agentsSummary`

### Manager / logs / cluster
- `searchManagerLogs`, `logCollectorStats`, `remotedStats`, `weeklyStats`
- `clusterHealth`, `clusterNodes`

### Utility
- `healthCheck`, `clearCache`, `cacheStats`

---

## Pagination pattern

Tools that return lists (`alertSummary`, `listAgents`, `vulnerabilitySummary`,
`rulesSummary`, `clusterNodes`) include a `pagination` block:

```json
{
  "pagination": {
    "offset": 0,
    "page_size": 50,
    "returned_count": 50,
    "total_matches": 15234,
    "has_more": true,
    "next_offset": 50
  }
}
```

LLM clients should treat `has_more: true` as a cue to prompt the user for continuation
and reuse `next_offset` on the next call.

---

## Deployment with systemd

Example unit file for SSE transport, with orphan-process cleanup:

```ini
[Unit]
Description=MCP Wazuh SSE service
After=network.target

[Service]
Type=simple
User=mcpuser
Group=mcpuser
WorkingDirectory=/opt/mcp
# Kill any stale process bound to our port before we start.
ExecStartPre=/usr/bin/fuser -k 8014/tcp
ExecStart=/opt/mcp/venv/bin/python3 /opt/mcp/mcp_wazuh.py \
    --transport sse --host 0.0.0.0 --port 8014 \
    --api-key REDACTED \
    --manager-host 192.168.1.40 --manager-user wazuh --manager-pass REDACTED \
    --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass REDACTED
# Clean up after crash so next ExecStartPre does not see ghost children.
ExecStopPost=/usr/bin/fuser -k 8014/tcp
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now mcp_wazuh_sse.service
journalctl -u mcp_wazuh_sse.service -f
```

---

## Suggested LLM system prompt

For small-context models (e.g. gpt-oss:120b on GAIVIS) we recommend pinning
the behaviour with a short system prompt. Keep `alertSummary` pages small
and prefer statistics tools first.

```
You are a Wazuh SIEM analysis assistant. Query alerts, vulnerabilities and
agents via the MCP tools. Reply in the user's language.
Prefer the statistics tools first, then fetch detail pages.

Routing:
- counts / distribution / top-N  -> alertStatistics, agentsWithAlerts
- alert detail / IoC             -> alertSummary
- agent inventory                -> listAgents
- per-agent CVEs                 -> vulnerabilitySummary

alertSummary rules:
- max_results must stay <= 50 (hard cap 100)
- After each call, look at pagination.has_more:
  - true  -> tell the user "N alerts remain; say 'next' to continue"
  - false -> tell the user this was the last page
- On "next" / "continue", reissue alertSummary with offset = next_offset
  and the same filters. Do not auto-paginate if the user did not ask.

When total_alerts > 500, start with alertStatistics and surface top 5
rules / agents; ask the user to narrow the scope before fetching detail.

Output:
- Format alert lists as markdown tables (time, agent, level, rule, description),
  max 20 rows; summarise the rest.
- Always show a pagination line at the end.
- Use the `severity` field from the tool response. Do not re-map rule.level yourself.
```

---

## Troubleshooting

- **`Unable to retrieve cluster status`** — Only seen on unexpected API shape.
  v1.3.7 fixes the `/cluster/status` parsing for cluster deployments.
- **`Agent ID '1234' exceeds maximum (999)`** — pre-v1.3.7 bug, removed in v1.3.7.
- **Port already in use / SSE crash loop** — another process holds the port.
  Use the `ExecStartPre` / `ExecStopPost` `fuser -k` hooks shown above.
- **`421 Misdirected Request`** — MCP SDK DNS rebinding protection. v1.3.5+ disables it.
- **Open WebUI can't see tools** — refresh the page after restarting the MCP server;
  Open WebUI re-fetches the OpenAPI spec on reload.

---

## References

- Inspired by [mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh) (Rust)
  by Gianluca Brigandi
- Wazuh API reference: <https://documentation.wazuh.com/current/user-manual/api/reference.html>
