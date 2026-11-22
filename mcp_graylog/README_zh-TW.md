# Graylog MCP Server

這是 **Graylog** 的 [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器，以單一檔案提供進階的記錄分析、統計與匯出功能。共提供 **28 個工具** (26 個分析／管理工具 + 2 個除錯工具)，並運用多種技巧突破 Graylog 標準 API 的結果數量限制 (Export API、時間切片、智慧分頁)，讓資料量非常大時的計數與分布依然準確。

- 作者：Jason Cheng (Jason Tools)
- 授權：MIT
- 版本：1.10.2
- 傳輸方式：`stdio` (預設)、`sse`、`streamable-http`
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能特色

- **準確的統計**：總筆數、主要來源、層級分布與時間模式，透過多種突破策略 (Export API、時間切片、分頁) 加上智慧去除重複，不受 Graylog API 分頁／數量上限影響。
- **分析**：時間模式 (尖峰／暴增)、來源排名、錯誤模式擷取、記錄層級分布 (含錯誤率／警告率)，以及任意欄位的值分布。
- **搜尋與匯出**：分頁搜尋、原始記錄取樣，以及大量匯出／分析。
- **串流與系統**：列出串流、伺服器版本／叢集／節點資訊。
- **內容套件與看板**：列出／檢視內容套件 (包含從修訂版本擷取出的看板／小工具) 與看板。
- **穩健的運作**：批次查詢使用時間快照 (避免時間漂移)、自動調整逾時、部分結果備援、依照 Graylog 跳脫規則正規化查詢字串。
- **節省 Token 的輸出**：精簡 JSON、扁平化回傳、精簡中繼資料，讓 LLM 的上下文更小。
- 支援多種傳輸方式、HTTP 可選用 API key (Bearer) 認證，並將記錄寫入檔案 `~/.mcp_graylog.log`。

---

## 系統需求

- Python 3.10+
- Graylog **API 權杖** (建議) 或使用者名稱／密碼
- Python 套件：

```bash
pip install httpx mcp
# uvicorn + starlette are required for the sse / streamable-http transports
pip install uvicorn starlette
```

或直接用 `uvx` 執行 (不需要 venv)：

```bash
uvx --with httpx --with mcp --with uvicorn --with starlette \
    python mcp_graylog.py
```

---

## 設定

設定值的優先順序：**CLI 參數 > 環境變數 > 預設值**。

| 環境變數 | CLI 參數 | 預設值 | 說明 |
|---|---|---|---|
| `GRAYLOG_HOST` | `--host` | — (必填) | 基礎 URL，例如 `https://graylog.example.com:9000` |
| `GRAYLOG_API_TOKEN` | `--api-token` | — | API 權杖 (建議使用；會當作 Basic 認證的使用者，密碼為 `token`) |
| `GRAYLOG_USERNAME` | `--username` | — | 使用者名稱 (密碼認證) |
| `GRAYLOG_PASSWORD` | `--password` | — | 密碼 (密碼認證) |
| `GRAYLOG_VERIFY_SSL` | `--verify-ssl` | `false` | 驗證 TLS 憑證 |
| `GRAYLOG_TIMEOUT` | — | `30` | 請求逾時 (秒) |
| `MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `MCP_HTTP_HOST` | `--http-host` | `0.0.0.0` | HTTP 繫結位址 |
| `MCP_HTTP_PORT` | `--http-port` | `8000` | HTTP 連接埠 |
| `MCP_API_KEY` | `--api-key` | — | 保護 HTTP/SSE 端點用的 Bearer 權杖 |

診斷：`--test` 執行連線／自我測試，`--debug` 提高記錄詳細程度，`--help` 顯示用法。

---

## 使用方式

### stdio (預設)

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

SSE 模式也會**在同一個連接埠的 `/mcp` 提供 Streamable HTTP** (自 v1.9.44 起)。只要用戶端支援 (例如 Claude Code 的
`"type": "http"`)，請優先使用 `/mcp`：SSE 用戶端在連線中斷 (筆電睡眠、網路短暫中斷) 後自動重新連線時，會拿到新的工作階段卻不會重送
`initialize`，之後每次呼叫都會失敗並回傳 `-32602 Invalid request parameters`。`/mcp` 是無狀態的，所以沒有工作階段會遺失。

### Streamable HTTP

```bash
python3 mcp_graylog.py --transport streamable-http --http-port 8001 \
  --host "https://graylog.example.com:9000" --api-token YOUR_GRAYLOG_TOKEN
```

### 連線測試

```bash
python3 mcp_graylog.py --test --debug \
  --host "https://graylog.example.com:9000" --api-token YOUR_GRAYLOG_TOKEN
```

---

## Claude Desktop

加到 `claude_desktop_config.json`：

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

編輯後請重新啟動 Claude Desktop。

---

## Open WebUI (透過 mcpo)

用 [`mcpo`](https://github.com/open-webui/mcpo) 把 stdio 伺服器公開為 OpenAPI 端點：

```bash
uvx mcpo --port 8001 --api-key "YOUR_MCPO_KEY" -- \
  env GRAYLOG_HOST=https://graylog.example.com:9000 \
      GRAYLOG_API_TOKEN=TOKEN \
      GRAYLOG_VERIFY_SSL=false \
  python /opt/mcp/mcp_graylog.py
```

之後每個工具都可透過 `POST http://host:8001/<tool_name>` 呼叫，並帶上 `Authorization: Bearer YOUR_MCPO_KEY`。將 Open WebUI 的工具伺服器指向 `http://host:8001` 即可。

---

## 工具 (28)

### 記錄統計與分析

| 工具 | 說明 |
|---|---|
| `get_log_statistics` | 彙總統計：總筆數、主要來源、層級分布、時間模式 |
| `analyze_time_patterns` | 時間分布：每小時／每分鐘分布、尖峰時段、流量暴增 |
| `analyze_source_distribution` | 依數量排名記錄來源 (主機／裝置) |
| `analyze_error_patterns` | 錯誤關鍵字頻率、產生錯誤的來源、最近的錯誤範例 |
| `get_log_level_analysis` | 層級分布 (ERROR/WARN/INFO/DEBUG…)，含筆數、百分比、錯誤率／警告率 |
| `analyze_field_distribution` | 任意記錄欄位的值分布 |

### 搜尋與取樣

| 工具 | 說明 |
|---|---|
| `get_log_sample` | 取得原始記錄訊息樣本以供檢視 |
| `search_logs_paginated` | 以真正的分頁搜尋記錄 |
| `search_messages_export` | 匯出並分析記錄 (大量資料，使用突破策略) |

### 串流與系統

| 工具 | 說明 |
|---|---|
| `get_streams` | 列出所有串流，含 ID、標題、說明、狀態 |
| `get_system_info` | 伺服器版本、叢集狀態、節點資訊 |
| `get_current_time` | 以 UTC 與 Asia/Taipei 顯示的伺服器時間，用來定出正確的絕對 (UTC) 時間範圍 |
| `list_inputs` | 已設定的輸入器 (syslog/GELF/raw…)，含類型、繫結／連接埠與執行狀態 |
| `list_index_sets` | 索引集，含輪替／保留原則、分片／副本、可寫入／預設旗標 |
| `list_indices` | 叢集健康狀態、事件總數、目前的寫入目標、各索引的大小／文件數／時間範圍 |
| `list_fields` | 可用於建立查詢的訊息欄位名稱 (可選用 `prefix` 篩選 + `limit`) |

### 健康狀態與效能 (唯讀)

| 工具 | 說明 |
|---|---|
| `get_cluster_health` | 一次呼叫就判斷整個叢集狀況：各節點的 heap %、journal 積壓量與時間長度、緩衝區使用率、處理量；OpenSearch 狀態、處理延遲、索引失敗 (24 h)、通知；附嚴重程度的 `findings` 與整體 `status` |
| `get_node_metrics` | 各節點的原始數值：journal (含其大小／時間上限)、JVM 記憶體、input/process/output 緩衝區、處理量 |
| `list_indexer_failures` | 過去 N 小時內 OpenSearch 拒絕建立索引的訊息，依錯誤類型與欄位分組，附範例值，日期對應錯誤另附修正提示 |
| `list_system_notifications` | Graylog 系統通知，依類型與標題分組，含次數、嚴重程度、最新時間與節點 |
| `find_silent_sources` | 在回溯時間範圍內有送出記錄、但已至少 N 分鐘沒有動靜的來源 (一次彙總查詢，不取樣訊息) |

### 內容套件與看板

| 工具 | 說明 |
|---|---|
| `list_content_packs` | 列出已安裝的內容套件 |
| `get_content_pack` | 依 ID 取得內容套件詳細資料 |
| `get_content_pack_revision` | 完整的修訂版本設定，包含擷取出的看板／小工具 |
| `list_dashboards` | 列出看板，含 ID 與標題 |
| `get_dashboard` | 依 ID 取得看板中繼資料與小工具設定 |

### 除錯／診斷

| 工具 | 說明 |
|---|---|
| `test_accurate_counting` | 比較不同的訊息計數策略 |
| `test_source_analysis_fix` | 比較標準與強化版的來源分析取樣 |

---

## 注意事項

- **突破 API 限制。** Graylog 的搜尋 API 會限制結果數量；為了取得準確的計數／分布，本伺服器結合 Export API、時間切片與智慧分頁，再去除重複。每次批次查詢只取一次時間快照，避免子請求之間發生時間漂移。
- **查詢跳脫。** 查詢字串會依 Graylog 的跳脫規則正規化，例如 `source:router\-004` 與 `source:"router-004"` 會視為相同；未跳脫的特殊字元會經過驗證／自動修正。
- **數字／IP 詞彙會自動加上引號。** 單獨的數字或 IPv4 詞彙 (例如 `4624`、`192.168.1.100`) 在送到 Graylog 前會先加上引號 (`AUTO_QUOTE_NUMERIC_TERMS`)。這樣可以避開欄位在串流的各個索引中對應到不同型別時所觸發的 OpenSearch `search_phase_execution`/`number_format` 例外，對 IP 來說也是語意上正確的比對方式。指定欄位的 (`port:443`)、已加引號的、萬用字元與範圍詞彙則不會更動。
- **時間範圍為 UTC。** 絕對時間範圍以 UTC 解讀。帶有時差的輸入 (例如 `+08:00`) 現在會在查詢前正確轉換為 UTC；建議使用 `...Z` 或相對時間 `now-Nh`。可呼叫 `get_current_time` 來定出時間邊界。
- **錯誤會明確回報。** 當所有 Graylog API 嘗試都失敗時，工具會回傳明確的錯誤 (而不是空結果)，並**揭露底層的 OpenSearch 搜尋／計數錯誤**；若看起來像數字欄位對應衝突，還會附上提示。API 錯誤會以 WARNING 層級記錄，並寫入 `~/.mcp_graylog.log`。
- 所有工具都回傳精簡 JSON 並精簡中繼資料，以減少 LLM 的 token 用量。
- HTTP 傳輸方式不掛載 DNS-rebinding 中介軟體，避免在反向代理後方出現 `421 Misdirected Request`。

---

## 變更記錄 (近期)

- **v1.10.2** — 又能在 Python 3.10 與 3.11 上載入 (1.9.44 到 1.10.1 因為 f-string 運算式內含反斜線而需要 3.12)。計數在取得第一個非零結果時就停止，而伺服器以 404/405/415 拒絕的端點 (在 Graylog 7.2 上，`POST /views/search/messages` 會回傳 415) 之後會直接略過，因此計數不會再送出注定失敗的請求。
- **v1.10.1** — `analyze_field_distribution` 與 `analyze_time_patterns` 現在改在 OpenSearch 中對整個範圍做彙總 (精確計數)，而不是只取樣幾千筆訊息，因此已剖析的欄位不會再回傳空值，每小時的計數加總也會等於總數；沒有該欄位的訊息會以 `missing_field_count` 回報。若彙總失敗則改回取樣。輸出大約縮小為 1/8。
- **v1.10.0** — 新增 5 個唯讀的健康狀態與效能工具 (`get_cluster_health`、`get_node_metrics`、`list_indexer_failures`、`list_system_notifications`、`find_silent_sources`)，讓 AI 代理程式能檢查 Graylog 是否健康、哪裡變慢，以及哪些來源停止傳送。各節點的資料透過 `/cluster/{nodeId}/…` 取得，因此一個 API 權杖即可涵蓋所有節點。
- **v1.9.45** — 在欄位超過 2048 個的索引上執行自由文字查詢時，會將單獨詞彙限定在 `message` 欄位後重試；計數路徑不再回報誤導性的 HTTP 405；匯出端點以 CSV 回傳的 OpenSearch 錯誤會當作錯誤拋出。
- **v1.9.44** — SSE 模式也在 `/mcp` 提供 Streamable HTTP (無狀態)，用戶端不會再於 SSE 重新連線後卡在未初始化的工作階段 (所有呼叫都以 `-32602` 失敗)；API key 檢查改用單純的 ASGI 中介軟體 (常數時間比對)，不再於每次 SSE 斷線時記錄 `AssertionError`。
- **v1.9.43** — 修正在索引欄位對應有衝突的串流上，單獨的數字／IPv4 查詢詞彙只回傳籠統錯誤的問題：數字／IP 詞彙會自動加上引號，並揭露底層的 OpenSearch 錯誤，而不是吞掉它。
- **v1.9.42** — 新增 5 個唯讀的基礎架構工具 (`get_current_time`、`list_inputs`、`list_index_sets`、`list_indices`、`list_fields`)，與官方 Graylog MCP 功能看齊。
- **v1.9.41** — 修正絕對時間輸入中的時區偏移 (`+08:00`) 被直接捨棄而不是轉換成 UTC 的問題 (會造成最多 8 小時的時間窗偏移與計數膨脹)。
- **v1.9.40** — 修正 SSE/streamable-http 啟動時 `TransportSecurityMiddleware` 當掉的問題。
- **v1.9.39** — 新增 API key 認證中介軟體 (`--api-key` / `MCP_API_KEY`)；SSE/HTTP 共用中介軟體設定。
- **v1.9.38** — 新增 SSE 傳輸方式；修正對確實為空的結果誤判為 API 錯誤的問題。
- **v1.9.37** — API 全部失敗時回傳明確錯誤；將記錄寫入檔案 `~/.mcp_graylog.log`。
- **v1.9.36** — 針對分析器回傳結構做節省 token 的調整 (移除 sample_messages、重複的分布、冗長的中繼資料)。
- **v1.9.35** — 新增 streamable-http 傳輸方式；精簡 JSON 輸出；扁平化回傳。
