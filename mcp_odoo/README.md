# Odoo MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **Odoo**, built on FastMCP over Odoo's XML-RPC API. It exposes **18 read tools** for sales quotations, sales analysis, purchase orders, deliveries, products, stock, invoices, partners and chatter history — with token-saving output controls tuned for small/local LLMs — plus **13 opt-in write tools** for quotations and customers (`--enable-write`).

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 1.11.0
- **Tested:** Odoo 13 and 18 Community Edition (write tools: Odoo 18)
- **Transports:** `stdio` (default), `sse`, `streamable-http`

---

## Features

- **Sales / quotations** — flexible search (partner, state, date & amount range, product names/keywords with AND/OR and exclude logic), quick stats, and full order details.
- **Purchasing & delivery** — search purchase orders and delivery orders (stock pickings) with state / date / product-keyword filters; detailed views by ID.
- **Products & stock** — keyword/multi-keyword product search, product details, and on-hand stock by warehouse/location.
- **Quotation writing (opt-in)** — create quotations with note/section lines, edit header and lines, copy to another customer, confirm, set a customer's default pricelist / payment terms, add contacts, download the quotation or pro-forma PDF. Prices are protected from pricelist recomputation; every write is audited.
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
| `ODOO_ENABLE_WRITE` | `--enable-write` | off | Register the 13 write tools (see below) |

### Write tools

| Env var | Default | Description |
|---|---|---|
| `ODOO_AUDIT_LOG` | `~/.local/state/mcp_odoo/audit.jsonl` | One JSON line per write: time, Odoo user, client IP / user agent, action, record, changes |
| `ODOO_DEFAULT_COMPANY_ID` | — | Company for new quotations, partners and contacts (default: the Odoo user's current company) |
| `ODOO_DEFAULT_TEAM_ID` | — | Sales team for new quotations |
| `ODOO_DEFAULT_SALESPERSON_ID` | — | Salesperson (user ID) for new quotations |
| `ODOO_DEFAULT_PRICELIST_ID` | — | Pricelist for new quotations, partners and contacts (Odoo's own default may be a foreign-currency list) |
| `ODOO_DEFAULT_SALE_TAX_IDS` | — | Comma-separated tax IDs put on new product lines that name no tax (only for the default company) |

The IDs are specific to one database, so they are settings, not code. Unset means Odoo's own default.
| `ODOO_PDF_DIR` | `~/Downloads` | Where `download_quotation_pdf` saves files in stdio mode |

HTTP endpoints: streamable-http at `/mcp`, SSE at `/sse`. Since v1.9.1 the SSE mode serves `/mcp` as well.

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

SSE mode also serves **Streamable HTTP at `/mcp` on the same port** (since v1.9.1). Prefer `/mcp` for any
client that supports it (e.g. Claude Code `"type": "http"`): SSE clients that auto-reconnect after a dropped
connection (laptop sleep, network blip) get a fresh session without re-sending `initialize`, and every call then
fails with `-32602 Invalid request parameters`. `/mcp` is stateless, so there is no session to lose.

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

## Tools (18 + 13 write)

### System

| Tool | Description |
|---|---|
| `get_odoo_system_info` | Odoo version, connection status, server capabilities |

### Sales & quotations

| Tool | Description |
|---|---|
| `search_quotations` | Search quotations/sales orders (partner, state, `invoice_status` e.g. "to invoice", customer PO number `client_order_ref`, note text `description_contains` — end customers often appear only in the note — date & amount range, `product_names`/`product_keywords` with `product_match_mode` any/all + exclude, pagination) |
| `search_quotation_lines` | Search past quotation lines by description keywords (AND): order, customer, date, quantity, unit price, plus min/max/average price per currency — "what did we quote for X before" |
| `get_sales_report` | Revenue of confirmed orders grouped by month / quarter / year / customer / product / category / salesperson / team, with invoiced vs to-invoice amounts |
| `get_quotation_stats` | Quick aggregated quotation statistics (counts/amounts) by partner/state |
| `get_quotation_details` | Full quotation / sales order detail by ID |
| `get_record_messages` | Chatter of a quotation, partner, invoice, delivery or purchase order: notes, emails, and field changes (who changed what from which value), in local time |

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
| `search_products` | Search products by `keywords` (multi-keyword AND match); returns `company_id` and `quote_line_name` (the exact text the first line of a quotation line must start with) |
| `get_product_details` | Full product detail by ID |
| `get_product_stock` | On-hand stock/quantity by warehouse / location |

### Invoices

| Tool | Description |
|---|---|
| `search_invoices` | Search invoices by customer, number, state, payment state, date, due date, amount, or source document. `unpaid_only=True` for outstanding receivables |
| `get_invoice_details` | Full invoice detail by id or number, including line items and payment status |
| `get_invoice_stats` | Totals and outstanding balance, grouped by payment state, state, customer or month |

Odoo stores customer invoices, vendor bills and credit notes in one model
(`account.move`). These tools default to customer invoices; pass
`invoice_type="vendor"`, `"customer_credit"`, `"vendor_credit"` or `"all"`
for the rest.

Two behaviours worth knowing:

- **`unpaid_only` excludes drafts.** A draft invoice has not been issued to the
  customer, so counting it as receivable overstates what is owed. On the
  reference database that is the difference between 22 invoices / 648,730
  outstanding and 16 / 41,576. Pass `state="draft"` to see drafts explicitly.
- **Draft invoices have no number.** Odoo reports `name` as `/` until an invoice
  is posted; these are shown as `（草稿．尚未編號）` with an `is_draft` flag.

### Partners

| Tool | Description |
|---|---|
| `search_partners` | Search partners by name, email, phone/mobile, or VAT / 統一編號; returns a Markdown link to the partner page |

### Quotation writing (only with `--enable-write`)

| Tool | Description |
|---|---|
| `create_quotation` | Create a draft quotation: customer, lines, note, validity date, customer PO number, payment terms; company / team / salesperson / pricelist / tax from the site defaults unless given |
| `update_quotation` | Change header fields of a draft/sent quotation (customer, PO number, note, validity date, quotation date, payment terms, pricelist, team, salesperson, addresses); on a confirmed order only the PO number. Returns before → after per field |
| `update_quotation_lines` | Add / change / delete lines, including `line_note` and `line_section` lines and `sequence` |
| `preview_quotation_copy` | Show what a copy to another customer would look like; writes nothing |
| `copy_quotation` | Copy a quotation to another customer (`confirm=True` required) |
| `confirm_quotation` | Confirm a quotation into a sales order (`confirm=True` required; otherwise a preview) |
| `update_partner_terms` | Set a customer's default pricelist and/or payment terms for one company |
| `add_contact_to_partner` | Add a contact person under a company; the contact gets the company's pricelist |
| `create_or_get_partner` | Create a company/individual with the default pricelist, or return the existing one with the same exact name or tax ID |
| `update_partner` | Change a partner's name, tax ID, email, phone, mobile, address, country, job position, language, notes, reference, company flag, default pricelist |
| `post_note` | Internal note on a quotation, partner, invoice, delivery or purchase order (no email is sent) |
| `change_quotation_state` | Set a sent/cancelled quotation back to draft, or mark a draft as sent (no email). Cancelling is deliberately not offered |
| `download_quotation_pdf` | Quotation (`sale.report_saleorder`) or pro-forma PDF |

Line spec example — a product line with its quantity formula as a separate note line below it:

```json
[
  {"display_type": "line_section", "name": "Proxmox VE subscription"},
  {"product_id": 126, "qty": 6, "price_unit": 1180,
   "name": "<exact product name>\n<subscription period ...>",
   "note_after": "(3Nodes x 2CPUs x 1Year) = 6"}
]
```

What the write tools guard against:

- **Repricing.** Odoo recomputes `price_unit` from the pricelist when the quantity changes, so a quantity-only update keeps the line's current price, and explicit `price_unit` values are re-applied if Odoo overrode them. Changing the customer or copying an order puts the original pricelist (currency) and unit prices back. Everything undone is listed in `warnings`.
- **Products from another company.** A product must belong to the order's company or to no company; otherwise the order becomes unreadable for that company. Nothing is written if any product fails the check.
- **Wrong product names.** Writes run with `lang=zh_TW`; English product names may still carry stale `(copy)` suffixes. When a product line's `name` is given, its first line must be exactly the product's name (`quote_line_name` from `search_products`) — the quotation PDF prints only the description, so an abbreviated first line is what the customer sees. Anything else is refused.
- **Wrong currency.** Results carry a warning when the quotation's currency is not the company's.
- **Missing PO number.** `confirm_quotation` warns when `client_order_ref` is empty.
- **Trying it first.** Every write tool takes `dry_run=True` (or, for copy / confirm / state change, works as a preview until `confirm=True`) and reports exactly what it would change.
- **Nothing destructive.** There is no tool to delete or cancel a quotation or to delete a partner.
- **Mistyped customers.** `copy_quotation` takes `new_partner_id`, or a name that matches exactly one partner; it never creates a partner.

Every write returns the record as read back from Odoo (untaxed / tax / total, currency, first line of each description), is appended to `ODOO_AUDIT_LOG`, and is posted as an internal note in the record's chatter.

`download_quotation_pdf` renders through Odoo's web session (reports are not available over XML-RPC). Over HTTP it returns a link to `/files/<token>/<file>.pdf` that is valid for 15 minutes; the random token stands in for the API key, so the link can be fetched with plain `curl`. In stdio mode the file is saved to `ODOO_PDF_DIR`.

Enable them only for clients that should change data. A typical setup runs one read-only instance for chat front ends (e.g. via mcpo) and one `--enable-write` instance for an agent.

---

## Notes

- **Token-saving output.** All search tools accept `count_only`, `compact`, `include_lines`/`include_moves`, and `offset` to keep responses small for local LLMs.
- **Do not translate keywords.** Product keyword matching is literal; pass the user's original terms.
- All tools return string payloads (JSON/Markdown); connection issues are reported in the response rather than crashing the server.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies.
- `MCP_API_KEY` protects the MCP HTTP/SSE endpoint; it is separate from Odoo credentials. Clients send `Authorization: Bearer <key>`.

---

## Changelog (recent)

### v1.11.0 — Sales analysis, line search, partner editing, safer writes

- New read tools: `get_sales_report` (revenue by month / customer / product / salesperson …), `search_quotation_lines` (past prices by description keyword), `get_record_messages` (chatter: notes, emails, field changes). `search_quotations` gains `invoice_status` and `client_order_ref`; `search_partners` gains `vat`; product search returns `company_id` and `quote_line_name`.
- New write tools: `update_partner`, `post_note`, `change_quotation_state` (draft / mark sent only). `create_or_get_partner` moved behind `--enable-write` (it creates records) and matches existing partners by tax ID too.
- Site defaults (`ODOO_DEFAULT_*`) for company, team, salesperson, pricelist and sale tax; new partners and contacts get the default / company pricelist instead of Odoo's foreign-currency default.
- Product-name check on quotation lines, currency and missing-PO warnings, before/after diffs, `dry_run` on every write tool, `date_order` editable, PO number editable on confirmed orders.
- Fixes: `count_only` never exceeded `limit` (10 instead of 57); searching partners by phone always failed (malformed domain); actions returning `None` (e.g. mark as sent) were reported as errors although they had succeeded.

### v1.10.0 — Quotation writing

Adds nine write tools behind `--enable-write` / `ODOO_ENABLE_WRITE=1`: `create_quotation`, `update_quotation`, `update_quotation_lines`, `preview_quotation_copy`, `copy_quotation`, `confirm_quotation`, `update_partner_terms`, `add_contact_to_partner`, `download_quotation_pdf`. Note and section lines, price protection against pricelist recomputation, company check on products, `zh_TW` product names, read-back results, audit log plus chatter note. Older disabled copies of the copy/update tools were rewritten for Odoo 18; `copy_quotation` no longer creates a partner from an unmatched name.

### v1.9.1 — SSE reconnect fix

SSE mode also serves Streamable HTTP at `/mcp` (stateless), so clients no longer get stuck on an uninitialized session after an SSE reconnect (all calls failing with `-32602`); API-key check moved to plain ASGI middleware (constant-time compare), ending the `AssertionError` logged on every SSE disconnect.

### v1.9.0 — Invoice reading

Adds `search_invoices`, `get_invoice_details` and `get_invoice_stats` over
`account.move`. Customer invoices by default; vendor bills and credit notes via
`invoice_type`.

`unpaid_only` filters on `amount_residual > 0` rather than `payment_state`,
because `payment_state` can be unset on drafts — and it also restricts to posted
invoices, since a draft has not been issued yet.


- **v1.8.3** — API-key auth for HTTP transports (`--api-key` / `MCP_API_KEY`).
- **v1.8.2** — Disabled DNS-rebinding protection (fixes `421` for external clients).
- **v1.8.1** — Custom host/port for SSE/streamable-http via uvicorn.
- **v1.8.0** — SSE transport; Markdown partner link in `search_partners`.
- **v1.7.0** — Token-saving controls (`count_only`/`compact`/`include_*`); `product_keywords`; `get_quotation_stats`.
- **v1.5.6–1.6.0** — Pagination (`offset`) on all search tools; advanced quotation filtering (`product_names`, amount range, match modes, excludes).
