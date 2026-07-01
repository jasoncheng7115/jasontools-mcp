# Odoo MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **Odoo**, built on FastMCP over Odoo's XML-RPC API. It exposes **13 tools** for sales quotations, purchase orders, deliveries, products, stock and partners — with token-saving output controls tuned for small/local LLMs.

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 1.8.3
- **Tested:** Odoo 13 Community Edition
- **Transports:** `stdio` (default), `sse`, `streamable-http`

---

## Features

- **Sales / quotations** — flexible search (partner, state, date & amount range, product names/keywords with AND/OR and exclude logic), quick stats, and full order details.
- **Purchasing & delivery** — search purchase orders and delivery orders (stock pickings) with state / date / product-keyword filters; detailed views by ID.
- **Products & stock** — keyword/multi-keyword product search, product details, and on-hand stock by warehouse/location.
- **Partners** — search partners (returns a Markdown link to the partner page) and create-or-get with VAT / 統一編號, customer/supplier flags and contacts.
- **Token-saving controls** on every search: `count_only` (count without data), `compact` (essential fields only), `include_lines` / `include_moves` to skip line-item detail, plus `offset` pagination — designed for `gpt-oss:120b` and similar.
- Multi-transport, optional API-key (Bearer) auth for HTTP, response caching with TTL, retry with backoff.

> **Keyword note:** product keywords are matched as-is — do **not** translate user keywords (e.g. `["proxmox", "訓練"]`).

---

## Requirements

- Python 3.10+
- Odoo credentials (URL, database, username, password) with XML-RPC access
- Python packages:

```bash
pip install mcp requests
# uvicorn + starlette are required for the sse / streamable-http transports
pip install uvicorn starlette
```

Or run directly with `uvx` (no venv needed):

```bash
uvx --with mcp --with requests --with uvicorn --with starlette \
    python mcp_odoo.py
```

---

## Configuration

The **Odoo connection is configured via environment variables**; transport/auth options are also available as CLI flags (CLI > env for those).

### Odoo connection (env vars)

| Env var | Default | Description |
|---|---|---|
| `ODOO_URL` | — (required) | Odoo base URL, e.g. `http://your-odoo-host:8069` |
| `ODOO_DATABASE` | — (required) | Database name |
| `ODOO_USERNAME` | — (required) | Login user |
| `ODOO_PASSWORD` | — (required) | Password (or API key as password on Odoo 14+) |
| `ODOO_DEFAULT_LANGUAGE` | `zh_TW` | Default language for records |
| `ODOO_CACHE_TTL` | `300` | Response cache TTL (seconds) |
| `ODOO_TIMEOUT` | `30` | Request timeout (seconds) |
| `ODOO_MAX_RETRIES` | `3` | Retry attempts (exponential backoff) |

### Transport / auth

| Env var | CLI arg | Default | Description |
|---|---|---|---|
| — | `--transport` / `-t` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--host` / `-H` | `127.0.0.1` | HTTP bind address |
| — | `--port` / `-p` | `8001` | HTTP port |
| `MCP_API_KEY` | `--api-key` / `-k` | — | Bearer token to protect the HTTP/SSE endpoint |

HTTP endpoints: streamable-http at `/mcp`, SSE at `/sse`.

---

## Usage

### stdio (default)

```bash
ODOO_URL=http://your-odoo-host:8069 ODOO_DATABASE=db \
ODOO_USERNAME=user ODOO_PASSWORD=pass \
python3 mcp_odoo.py
```

### SSE

```bash
python3 mcp_odoo.py --transport sse --host 0.0.0.0 --port 8009 --api-key YOUR_BEARER_TOKEN
# (ODOO_* env vars must be set)
```

### Streamable HTTP

```bash
python3 mcp_odoo.py --transport streamable-http --host 0.0.0.0 --port 8008
# endpoint: http://host:8008/mcp
```

---

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "odoo": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/scripts/mcp_odoo/mcp_odoo.py"],
      "env": {
        "ODOO_URL": "http://your-odoo-host:8069",
        "ODOO_DATABASE": "your_odoo_db",
        "ODOO_USERNAME": "your_username",
        "ODOO_PASSWORD": "your_password",
        "ODOO_DEFAULT_LANGUAGE": "zh_TW",
        "ODOO_CACHE_TTL": "300",
        "ODOO_TIMEOUT": "30",
        "ODOO_MAX_RETRIES": "3"
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
uvx mcpo --port 8008 --api-key "YOUR_MCPO_KEY" -- \
  env ODOO_URL=http://your-odoo-host:8069 \
      ODOO_DATABASE=db ODOO_USERNAME=user ODOO_PASSWORD=pass \
  python /opt/mcp/mcp_odoo.py
```

Each tool is then available at `POST http://host:8008/<tool_name>` with `Authorization: Bearer YOUR_MCPO_KEY`. Point Open WebUI's tool server at `http://host:8008`.

---

## Tools (13)

### System

| Tool | Description |
|---|---|
| `get_odoo_system_info` | Odoo version, connection status, server capabilities |

### Sales & quotations

| Tool | Description |
|---|---|
| `search_quotations` | Search quotations/sales orders (partner, state, date & amount range, `product_names`/`product_keywords` with `product_match_mode` any/all + exclude, pagination) |
| `get_quotation_stats` | Quick aggregated quotation statistics (counts/amounts) by partner/state |
| `get_quotation_details` | Full quotation / sales order detail by ID |

### Purchasing & delivery

| Tool | Description |
|---|---|
| `search_purchase_orders` | Search purchase orders (state, date range, product keywords, pagination) |
| `get_purchase_order_details` | Full purchase order detail by ID |
| `search_delivery_orders` | Search delivery orders / stock pickings (state, picking type, product keywords) |
| `get_delivery_order_details` | Full delivery order (stock picking) detail by ID |

### Products & stock

| Tool | Description |
|---|---|
| `search_products` | Search products by `keywords` (multi-keyword AND match) |
| `get_product_details` | Full product detail by ID |
| `get_product_stock` | On-hand stock/quantity by warehouse / location |

### Partners

| Tool | Description |
|---|---|
| `search_partners` | Search partners (customers/suppliers); returns a Markdown link to the partner page |
| `create_or_get_partner` | Create a partner or return an existing match; supports VAT (統一編號), customer/supplier flags |

---

## Notes

- **Token-saving output.** All search tools accept `count_only`, `compact`, `include_lines`/`include_moves`, and `offset` to keep responses small for local LLMs.
- **Do not translate keywords.** Product keyword matching is literal; pass the user's original terms.
- All tools return string payloads (JSON/Markdown); connection issues are reported in the response rather than crashing the server.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies.
- `MCP_API_KEY` protects the MCP HTTP/SSE endpoint; it is separate from Odoo credentials. Clients send `Authorization: Bearer <key>`.

---

## Changelog (recent)

- **v1.8.3** — API-key auth for HTTP transports (`--api-key` / `MCP_API_KEY`).
- **v1.8.2** — Disabled DNS-rebinding protection (fixes `421` for external clients).
- **v1.8.1** — Custom host/port for SSE/streamable-http via uvicorn.
- **v1.8.0** — SSE transport; Markdown partner link in `search_partners`.
- **v1.7.0** — Token-saving controls (`count_only`/`compact`/`include_*`); `product_keywords`; `get_quotation_stats`.
- **v1.5.6–1.6.0** — Pagination (`offset`) on all search tools; advanced quotation filtering (`product_names`, amount range, match modes, excludes).
