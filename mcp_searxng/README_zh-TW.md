# SearXNG MCP Server

這是 [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器，透過**自行架設的 [SearXNG](https://github.com/searxng/searxng)** 執行個體，讓本機 LLM (OpenCode、Open WebUI、Claude Desktop …) 能夠搜尋網路。查詢會送到您自己的 SearXNG，而不是第三方搜尋 API (選用的暫停模式除外，詳見下文)。

設計目的是避免小模型猛打搜尋引擎：回答會快取、呼叫有速率限制，而當上游引擎被封鎖時，工具會直接說明狀況，而不是回傳「0 筆結果」(那會讓模型不斷換關鍵字重試)。

- 作者：Jason Cheng (Jason Tools)
- 授權：MIT
- 版本：1.0.0
- 傳輸方式：`streamable-http`，位於 `/mcp` (連接埠 8021)
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能特色

- **兩個工具**：`web_search` (預設) 與 `code_search` (SearXNG `it` 分類：Stack Overflow、GitHub、MDN、npm、Packagist、Docker Hub …)。
- **記憶體內快取**：24 小時內相同的查詢會直接由快取回答 (最多 2000 筆)。查詢不分大小寫，連續的空格會合併為一個。
- **速率限制**：預設每分鐘 10 次、每小時 100 次搜尋。超過時工具會回傳錯誤，告訴模型*不要*重試。
- **回報被封鎖的引擎**：如果 SearXNG 沒有回傳任何結果，並列出 `unresponsive_engines` (CAPTCHA、速率限制、逾時 …)，工具會回傳錯誤，說明引擎無法使用，換其他關鍵字重試也沒有幫助。若只有部分引擎失敗，則會在結果後附上一則說明。
- **暫停模式** (選用)：設定 `WEB_SEARCH_PAUSED=<reason>` 後，`web_search` 除了 SearXNG 仍能回傳的結果 (例如 Wikipedia) 之外，還會加上來自免費、免金鑰、免註冊來源的結果：
  - DuckDuckGo Instant Answer API
  - Stack Exchange API (stackoverflow + serverfault；免金鑰配額為每個 IP 每天 300 次請求，剩餘不到 30 次或 API 要求退避時會略過)
  - Hacker News (Algolia API)
  - 只有在查詢含有英文關鍵字時才會查詢 Stack Exchange 與 HN，且只保留標題至少包含其中一個關鍵字的結果。
  - 沒有設定這個變數時，不會使用上述任何額外來源。
  - 在暫停模式下，查詢文字會由本伺服器直接送到這三個公開 API，不經過 SearXNG。
- 輸出為精簡的純文字 (標題、URL、摘要、來源引擎)，以節省模型的上下文。

---

## 系統需求

- 在 `settings.yml` 中**啟用 JSON 格式**的 SearXNG 執行個體：

  ```yaml
  search:
    formats:
      - html
      - json
  ```

- Python 3.12 (已測試；隨附的 Dockerfile 使用 `python:3.12-slim`)，搭配 `mcp==2.0.0` 與 `httpx>=0.27`。

---

## 設定 (環境變數)

- `SEARXNG_URL`：SearXNG 基礎 URL。預設 `http://searxng:8080`。
- `SEARCH_TIMEOUT`：SearXNG 請求逾時秒數。預設 `45`。
- `SEARCH_CACHE_TTL`：快取存留時間 (秒)。預設 `86400` (24 h)。
- `SEARCH_CACHE_MAX`：快取查詢數上限。預設 `2000`。
- `SEARCH_LIMIT_PER_MIN`：每分鐘允許的搜尋次數。預設 `10`。
- `SEARCH_LIMIT_PER_HOUR`：每小時允許的搜尋次數。預設 `100`。
- `WEB_SEARCH_PAUSED`：預設未設定。任何非空值都會開啟暫停模式；這個值會當作原因顯示給模型，例如 `WEB_SEARCH_PAUSED="upstream engines blocked"`。

命中快取不計入速率限制。快取與計數器以處理程序為單位，重新啟動後就會重設。

---

## 使用方式

### Docker Compose (建議)

把 `Dockerfile` 與 `mcp_searxng.py` 放在 SearXNG compose 專案旁的目錄中，並加入 [`docker-compose.example.yml`](docker-compose.example.yml) 裡的服務：

```bash
docker compose up -d --build searxng-mcp
```

MCP 端點即為 `http://<host>:8021/mcp`。

### 直接用 Python

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

### Claude Desktop／其他只支援 stdio 的用戶端

使用 streamable-HTTP 橋接工具，例如 `mcp-remote`：

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

## 工具 (2)

- `web_search(query, max_results=8, language="zh-TW")`：一般網路搜尋；請優先使用這個。
- `code_search(query, max_results=8)`：僅限技術網站 (SearXNG `it` 分類，`en-US`)。採關鍵字比對，請使用精確的英文詞彙，例如函式名稱或錯誤訊息。

---

## 注意事項

- 本伺服器沒有認證機制。請只將連接埠 8021 開放給受信任的網路。
- 搜尋結果是不受信任的網頁內容，會直接進入模型的上下文；請比照其他外部輸入看待 (可能遭到提示詞注入)。
- 工具說明與訊息為繁體中文；模型可以正常處理，若需要其他語言，請自行修改這些字串。
- 搜尋引擎會封鎖送出過多自動化查詢的 IP。請保持快取與速率限制開啟，並盡量以少量、精準的查詢為主。

---

## 變更記錄

- **1.0.0** (2026-11-21)
  - 首次公開發布。
  - 透過 SearXNG 提供 `web_search` 與 `code_search`，在連接埠 8021 提供 streamable HTTP。
  - 24 小時查詢快取，以及每分鐘／每小時的速率限制。
  - 上游引擎無回應時回傳明確錯誤，讓模型停止重試。
  - 選用的暫停模式，以 DuckDuckGo Instant Answer、Stack Exchange 與 Hacker News 作為額外來源。
