# Graylog MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **Graylog**, providing advanced log analysis, statistics and export through a single file. It exposes **23 tools** (21 analysis/management + 2 debug), with techniques to break through Graylog's standard API result limits (Export API, time slicing, smart pagination) so counts and distributions stay accurate on very large datasets.

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 1.9.43
- **Transports:** `stdio` (default), `sse`, `streamable-http`

---

## Features

- **Accurate statistics** — total counts, top sources, level breakdown and time patterns that survive Graylog's API paging/limit caps via multiple breakthrough strategies (Export API, time slicing, pagination) plus intelligent deduplication.
- **Analysis** — temporal patterns (peaks/spikes), source ranking, error-pattern extraction, log-level distribution (with error/warning rates), and arbitrary field value distribution.
- **Search & export** — paginated search, raw log sampling, and high-volume export/analysis.
- **Streams & system** — list streams, server version / cluster / node info.
- **Content packs & dashboards** — list/inspect content packs (incl. extracted dashboards/widgets from a revision) and dashboards.
- **Robust operations** — time-snapshot for batch queries (prevents time drift), adaptive timeouts, partial-result fallback, query-string normalization following Graylog escaping rules.
- **Token-efficient output** — compact JSON, flattened returns, trimmed metadata for smaller LLM context.
- Multi-transport, optional API-key (Bearer) auth for HTTP, and file logging to `~/.mcp_graylog.log`.

---

## Requirements

- Python 3.10+
- A Graylog **API token** (recommended) or username/password
- Python packages:

```bash
pip install httpx mcp
# uvicorn + starlette are required for the sse / streamable-http transports
pip install uvicorn starlette
```

Or run directly with `uvx` (no venv needed):

```bash
uvx --with httpx --with mcp --with uvicorn --with starlette \
    python mcp_graylog.py
```

---

## Configuration

Settings are resolved in this order: **CLI args > environment variables > defaults**.

| Env var | CLI arg | Default | Description |
|---|---|---|---|
| `GRAYLOG_HOST` | `--host` | — (required) | Base URL, e.g. `https://graylog.example.com:9000` |
| `GRAYLOG_API_TOKEN` | `--api-token` | — | API token (preferred; used as Basic-auth user with password `token`) |
| `GRAYLOG_USERNAME` | `--username` | — | Username (password auth) |
| `GRAYLOG_PASSWORD` | `--password` | — | Password (password auth) |
| `GRAYLOG_VERIFY_SSL` | `--verify-ssl` | `false` | Verify TLS certificate |
| `GRAYLOG_TIMEOUT` | — | `30` | Request timeout (seconds) |
| `MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `MCP_HTTP_HOST` | `--http-host` | `0.0.0.0` | HTTP bind address |
| `MCP_HTTP_PORT` | `--http-port` | `8000` | HTTP port |
| `MCP_API_KEY` | `--api-key` | — | Bearer token to protect the HTTP/SSE endpoint |

Diagnostics: `--test` runs a connectivity/self test, `--debug` raises log verbosity, `--help` prints usage.

---

## Usage

### stdio (default)

```bash
python3 mcp_graylog.py \
  --host "https://graylog.example.com:9000" \
  --api-token YOUR_GRAYLOG_TOKEN
```

### SSE

```bash
python3 mcp_graylog.py --transport sse --http-host 0.0.0.0 --http-port 8020 \
  --host "https://graylog.example.com:9000" --api-token YOUR_GRAYLOG_TOKEN \
  --api-key YOUR_BEARER_TOKEN
```

### Streamable HTTP

```bash
python3 mcp_graylog.py --transport streamable-http --http-port 8001 \
  --host "https://graylog.example.com:9000" --api-token YOUR_GRAYLOG_TOKEN
```

### Connectivity test

```bash
python3 mcp_graylog.py --test --debug \
  --host "https://graylog.example.com:9000" --api-token YOUR_GRAYLOG_TOKEN
```

---

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "graylog": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/mcp_graylog/mcp_graylog.py"],
      "env": {
        "GRAYLOG_HOST": "https://graylog.example.com:9000",
        "GRAYLOG_API_TOKEN": "your-graylog-api-token",
        "GRAYLOG_VERIFY_SSL": "false",
        "GRAYLOG_TIMEOUT": "30"
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
uvx mcpo --port 8001 --api-key "YOUR_MCPO_KEY" -- \
  env GRAYLOG_HOST=https://graylog.example.com:9000 \
      GRAYLOG_API_TOKEN=TOKEN \
      GRAYLOG_VERIFY_SSL=false \
  python /opt/mcp/mcp_graylog.py
```

Each tool is then available at `POST http://host:8001/<tool_name>` with `Authorization: Bearer YOUR_MCPO_KEY`. Point Open WebUI's tool server at `http://host:8001`.

---

## Tools (23)

### Log statistics & analysis

| Tool | Description |
|---|---|
| `get_log_statistics` | Aggregated stats: total count, top sources, level breakdown, time patterns |
| `analyze_time_patterns` | Temporal distribution: hourly/minute breakdown, peak times, traffic spikes |
| `analyze_source_distribution` | Rank log sources (hosts/devices) by volume |
| `analyze_error_patterns` | Error keyword frequency, error-producing sources, recent error samples |
| `get_log_level_analysis` | Level distribution (ERROR/WARN/INFO/DEBUG…) with counts, pct, error/warning rate |
| `analyze_field_distribution` | Value distribution for any log field |

### Search & sampling

| Tool | Description |
|---|---|
| `get_log_sample` | Retrieve sample raw log messages for inspection |
| `search_logs_paginated` | Search logs with true pagination |
| `search_messages_export` | Export and analyze logs (high-volume, breakthrough strategies) |

### Streams & system

| Tool | Description |
|---|---|
| `get_streams` | List all streams with ID, title, description, status |
| `get_system_info` | Server version, cluster status, node info |
| `get_current_time` | Server time in UTC and Asia/Taipei — anchor correct absolute (UTC) time ranges |
| `list_inputs` | Configured inputs (syslog/GELF/raw…) with type, bind/port and running state |
| `list_index_sets` | Index sets with rotation/retention policy, shards/replicas, writable/default flags |
| `list_indices` | Cluster health, total event count, active write target, per-index size/doc-count/time-range |
| `list_fields` | Available message field names for query building (optional `prefix` filter + `limit`) |

### Content packs & dashboards

| Tool | Description |
|---|---|
| `list_content_packs` | List installed content packs |
| `get_content_pack` | Details of a content pack by ID |
| `get_content_pack_revision` | Full revision config incl. extracted dashboards/widgets |
| `list_dashboards` | List dashboards with ID and title |
| `get_dashboard` | Dashboard metadata and widget configurations by ID |

### Debug / diagnostics

| Tool | Description |
|---|---|
| `test_accurate_counting` | Compare different message-counting strategies |
| `test_source_analysis_fix` | Compare standard vs enhanced source-analysis sampling |

---

## Notes

- **API-limit breakthrough.** Graylog's search API caps result sizes; for accurate counts/distributions this server combines the Export API, time slicing and smart pagination, then de-duplicates. A single time snapshot is taken per batch query to avoid time drift between sub-requests.
- **Query escaping.** Query strings are normalized to Graylog's escaping rules — e.g. `source:router\-004` vs `source:"router-004"` are treated equivalently; unescaped special characters are validated/auto-fixed.
- **Numeric/IP terms are auto-quoted.** Bare numeric or IPv4 tokens (e.g. `4624`, `192.168.1.100`) are wrapped in quotes before hitting Graylog (`AUTO_QUOTE_NUMERIC_TERMS`). This sidesteps OpenSearch `search_phase_execution`/`number_format` exceptions that fire when a field is mapped with conflicting types across a stream's indices, and is the semantically-correct match for an IP. Field-scoped (`port:443`), already-quoted, wildcard and range tokens are left untouched.
- **Time ranges are UTC.** Absolute ranges are interpreted as UTC. Offset-bearing input (e.g. `+08:00`) is now correctly converted to UTC before querying; prefer `...Z` or relative `now-Nh`. Call `get_current_time` to anchor boundaries.
- **Errors are explicit.** When all Graylog API attempts fail, tools return an explicit error (not an empty result) that **surfaces the underlying OpenSearch search/count error** plus a hint when it looks like a numeric field-mapping conflict. API errors are logged at WARNING and captured in `~/.mcp_graylog.log`.
- All tools return compact JSON with trimmed metadata to reduce LLM token usage.
- DNS-rebinding middleware is not attached to the HTTP transports, avoiding `421 Misdirected Request` behind reverse proxies.

---

## Changelog (recent)

- **v1.9.43** — Fixed bare numeric/IPv4 query terms failing with a generic error on streams with index field-mapping conflicts: auto-quote numeric/IP tokens, and surface the underlying OpenSearch error instead of swallowing it.
- **v1.9.42** — Added 5 read-only infrastructure tools (`get_current_time`, `list_inputs`, `list_index_sets`, `list_indices`, `list_fields`) for parity with the official Graylog MCP.
- **v1.9.41** — Fixed timezone offset (`+08:00`) in absolute time input being dropped instead of converted to UTC (caused up to an 8h window shift and inflated counts).
- **v1.9.40** — Fixed `TransportSecurityMiddleware` crash on SSE/streamable-http startup.
- **v1.9.39** — Added API-key auth middleware (`--api-key` / `MCP_API_KEY`); shared SSE/HTTP middleware setup.
- **v1.9.38** — Added SSE transport; fixed false-positive API-error detection on legitimately empty results.
- **v1.9.37** — Explicit error on total API failure; file logging to `~/.mcp_graylog.log`.
- **v1.9.36** — Token-efficiency pass on analyzer return structures (removed sample_messages, duplicate distributions, verbose metadata).
- **v1.9.35** — Added streamable-http transport; compact JSON output; flattened returns.
