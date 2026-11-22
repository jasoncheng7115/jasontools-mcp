# SearXNG MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives local LLMs (OpenCode, Open WebUI, Claude Desktop …) web search through a **self-hosted [SearXNG](https://github.com/searxng/searxng)** instance. Queries go to your own SearXNG, not to a third-party search API (except in the optional paused mode, see below).

It is built to keep small models from hammering the search engines: answers are cached, calls are rate-limited, and when the upstream engines are blocked the tool says so plainly instead of returning "0 results" (which makes models retry with ever-changing keywords).

- **Author:** Jason Cheng (Jason Tools)
- **License:** MIT
- **Version:** 1.0.0
- **Transport:** `streamable-http` at `/mcp` (port 8021)
- **Languages:** [English](README.md) · [繁體中文](README_zh-TW.md)

---

## Features

- **Two tools**: `web_search` (default) and `code_search` (SearXNG `it` category: Stack Overflow, GitHub, MDN, npm, Packagist, Docker Hub …).
- **In-memory cache**: the same query within 24 hours is answered from cache (up to 2000 entries). Queries are case-insensitive and repeated spaces are collapsed.
- **Rate limit**: 10 searches per minute and 100 per hour by default. When exceeded the tool returns an error that tells the model *not* to retry.
- **Blocked engines are reported**: if SearXNG returns no results and lists `unresponsive_engines` (CAPTCHA, rate limit, timeout …), the tool returns an error saying the engines are unavailable and that retrying with other keywords will not help. When only some engines fail, a note is appended to the results.
- **Paused mode** (optional): set `WEB_SEARCH_PAUSED=<reason>` and `web_search` adds results from free, no-key, no-signup sources on top of what SearXNG still returns (e.g. Wikipedia):
  - DuckDuckGo Instant Answer API
  - Stack Exchange API (stackoverflow + serverfault; the keyless quota is 300 requests/IP/day — skipped when fewer than 30 remain or when the API asks for a backoff)
  - Hacker News (Algolia API)
  - Stack Exchange and HN are only queried when the query contains English keywords, and a result is kept only if its title contains at least one of them.
  - Without this variable, none of these extra sources are used.
  - In paused mode the query text is sent directly from this server to those three public APIs, not through SearXNG.
- Output is compact plain text (title, URL, snippet, source engine) to save model context.

---

## Requirements

- A SearXNG instance with the **JSON format enabled** in `settings.yml`:

  ```yaml
  search:
    formats:
      - html
      - json
  ```

- Python 3.12 (tested; the provided Dockerfile uses `python:3.12-slim`) with `mcp==2.0.0` and `httpx>=0.27`.

---

## Configuration (environment variables)

- `SEARXNG_URL` — SearXNG base URL. Default `http://searxng:8080`.
- `SEARCH_TIMEOUT` — SearXNG request timeout in seconds. Default `45`.
- `SEARCH_CACHE_TTL` — cache lifetime in seconds. Default `86400` (24 h).
- `SEARCH_CACHE_MAX` — maximum cached queries. Default `2000`.
- `SEARCH_LIMIT_PER_MIN` — searches allowed per minute. Default `10`.
- `SEARCH_LIMIT_PER_HOUR` — searches allowed per hour. Default `100`.
- `WEB_SEARCH_PAUSED` — unset by default. Any non-empty value turns on paused mode; the value is shown to the model as the reason, e.g. `WEB_SEARCH_PAUSED="upstream engines blocked"`.

Cache hits do not count against the rate limit. The cache and counters are per process and reset on restart.

---

## Usage

### Docker Compose (recommended)

Put `Dockerfile` and `mcp_searxng.py` in a directory next to your SearXNG compose project and add the service from [`docker-compose.example.yml`](docker-compose.example.yml):

```bash
docker compose up -d --build searxng-mcp
```

The MCP endpoint is then `http://<host>:8021/mcp`.

### Plain Python

```bash
pip install "mcp==2.0.0" "httpx>=0.27"
SEARXNG_URL=http://localhost:8080 python mcp_searxng.py
```

### OpenCode

```json
{
  "mcp": {
    "searxng": {
      "type": "remote",
      "url": "http://searxng.example.com:8021/mcp"
    }
  }
}
```

### Claude Desktop / other stdio-only clients

Use a streamable-HTTP bridge such as `mcp-remote`:

```json
{
  "mcpServers": {
    "searxng": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://searxng.example.com:8021/mcp"]
    }
  }
}
```

---

## Tools (2)

- `web_search(query, max_results=8, language="zh-TW")` — general web search; use this first.
- `code_search(query, max_results=8)` — technical sites only (SearXNG `it` category, `en-US`). Keyword matching, so use exact English terms such as function names or error messages.

---

## Notes

- The server has no authentication. Expose port 8021 only to trusted networks.
- Search results are untrusted web content and go straight into the model's context; treat them like any other external input (prompt injection is possible).
- Tool descriptions and messages are in Traditional Chinese; models handle them fine, but edit the strings if you need another language.
- Search engines block IPs that send too many automated queries. Keep the cache and rate limit on, and prefer few, good queries.

---

## Changelog

- **1.0.0** (2026-11-21)
  - First public release.
  - `web_search` and `code_search` over SearXNG, streamable HTTP on port 8021.
  - 24-hour query cache and per-minute/per-hour rate limit.
  - Clear error when the upstream engines are unresponsive, so models stop retrying.
  - Optional paused mode with DuckDuckGo Instant Answer, Stack Exchange and Hacker News as extra sources.
