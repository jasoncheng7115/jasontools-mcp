# phpIPAM MCP Server

以 FastMCP 打造的 **phpIPAM** [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器。提供 **21 個工具**，涵蓋 IP 位址管理、子網路、VLAN、裝置、機櫃與資料夾，並以節省 token 的純文字輸出，針對小型／本機 LLM (例如 `gpt-oss:120b`) 調校。

- **作者：** Jason Cheng (Jason Tools)
- **授權：** MIT
- **版本：** 2.5
- **傳輸方式：** `stdio` (預設)、`sse`、`streamable-http`
- **語言：** [English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能特色

- **區段與子網路**：列出／檢視區段與子網路、子網路使用統計 (已用／可用／總數)、CIDR 搜尋。
- **IP 位址**：列出子網路中已使用的 IP、**找出下一個可用 IP**、依 IP 或主機名稱搜尋 (部分比對)。
- **VLAN、裝置、機櫃、資料夾、標籤**：各有清單與詳細資料；機櫃檢視包含已安裝的裝置與空間使用率。
- **公用工具**：`health_check` (API 可達性) 與 `clear_cache`。
- **節省 token 的輸出**：清單用管線符號表格，詳細資料用 `key: value`，以詳細欄位允許清單濾除雜訊，過長的值會截斷 (30 個字元)，搜尋結果上限 50 筆以免超出上下文。
- 每個清單端點都使用一致的 `page`/`page_size` 分頁；回應快取具有 TTL。
- 多種傳輸方式，HTTP 可選用 API 金鑰 (Bearer) 認證 (採純 ASGI 中介軟體，不會破壞 SSE 串流)。

---

## 需求環境

- Python 3.10+
- 一個具有權杖的 phpIPAM **API 應用程式** (App ID)；該應用程式必須啟用 API 存取。
- Python 套件：

```bash
pip install mcp requests urllib3
# uvicorn is required for the sse / streamable-http transports
pip install uvicorn
```

或直接以 `uvx` 執行 (不需要 venv)：

```bash
uvx --with mcp --with requests --with urllib3 --with uvicorn \
    python mcp_phpipam.py
```

---

## 設定

**phpIPAM 連線透過環境變數設定**；傳輸方式／認證選項則是 CLI 旗標 (註明處亦可用環境變數)。

### phpIPAM 連線 (環境變數)

| 環境變數 | 預設值 | 說明 |
|---|---|---|
| `PHPIPAM_URL` | — (必填) | 基礎 URL，例如 `https://phpipam.example.com` (結尾的 `/api` 會被移除) |
| `PHPIPAM_TOKEN` | — (必填) | API 權杖 |
| `PHPIPAM_APP_ID` | — (必填) | API App ID (位於 phpIPAM → Administration → API) |
| `PHPIPAM_CACHE_TTL` | `300` | 回應快取 TTL (秒) |
| `PHPIPAM_TIMEOUT` | `10` | 請求逾時 (秒) |
| `PHPIPAM_VERIFY_SSL` | `false` | 驗證 TLS 憑證 (設為 `true` 啟用) |

### 傳輸方式／認證

| 環境變數 | CLI 參數 | 預設值 | 說明 |
|---|---|---|---|
| — | `--transport` / `-t` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--host` / `-H` | `127.0.0.1` | HTTP 繫結位址 |
| — | `--port` / `-p` | `8000` | HTTP 連接埠 |
| `MCP_API_KEY` | `--api-key` / `-k` | — | 保護 HTTP/SSE 端點的 Bearer 權杖 |

---

## 使用方式

### stdio (預設)

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

加入 `claude_desktop_config.json`：

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

編輯後請重新啟動 Claude Desktop。

---

## Open WebUI (透過 mcpo)

以 [`mcpo`](https://github.com/open-webui/mcpo) 將 stdio 伺服器公開為 OpenAPI 端點：

```bash
uvx mcpo --port 8007 --api-key "YOUR_MCPO_KEY" -- \
  env PHPIPAM_URL=https://your-phpipam-host \
      PHPIPAM_TOKEN=TOKEN PHPIPAM_APP_ID=mcp \
      PHPIPAM_VERIFY_SSL=false \
  python /opt/mcp/mcp_phpipam.py
```

之後每個工具都可透過 `POST http://host:8007/<tool_name>` 搭配 `Authorization: Bearer YOUR_MCPO_KEY` 呼叫。將 Open WebUI 的工具伺服器指向 `http://host:8007` 即可。

---

## 工具 (21)

### 區段與子網路

| 工具 | 說明 |
|---|---|
| `list_sections` | 列出所有 IPAM 區段 |
| `get_section` | 依 ID 取得區段詳細資料 |
| `list_subnets` | 列出子網路 (全部，或依區段篩選) |
| `get_subnet` | 依 ID 取得完整子網路詳細資料 |
| `get_subnet_usage` | 子網路使用統計 (已用／可用／總數) |
| `search_subnet` | 依 CIDR／網路位址搜尋子網路 |

### IP 位址

| 工具 | 說明 |
|---|---|
| `find_free_ip` | 找出子網路中下一個可用的 IP |
| `list_subnet_addresses` | 列出子網路中已使用的 IP (各由誰使用) |
| `search_ip` | 在所有子網路中搜尋特定 IP |
| `search_hostname` | 依主機名稱搜尋 IP 記錄 (部分比對) |

### VLAN、裝置、機櫃、資料夾、標籤

| 工具 | 說明 |
|---|---|
| `list_vlans` | 列出所有 VLAN |
| `get_vlan` | 依資料庫 ID 取得 VLAN 詳細資料 |
| `list_devices` | 列出網路裝置 (交換器／路由器／防火牆／伺服器…) |
| `get_device` | 依 ID 取得裝置詳細資料 |
| `list_racks` | 列出伺服器／網路機櫃 |
| `get_rack` | 機櫃詳細資料，含已安裝的裝置 + 空間使用率 |
| `list_folders` | 列出組織用資料夾 |
| `get_folder` | 資料夾詳細資料 + 所含區段 |
| `list_tags` | 列出 IP 狀態標籤 (Used、Available、Reserved、DHCP…) |

### 公用工具

| 工具 | 說明 |
|---|---|
| `health_check` | 檢查 phpIPAM API 是否可連線 |
| `clear_cache` | 清除 API 回應快取 |

---

## 注意事項

- **App ID + 權杖。** 在 phpIPAM 建立 API 應用程式 (Administration → API)，將其啟用，並使用它的 App ID + 權杖。`PHPIPAM_URL` 應為網站根目錄；結尾的 `/api` 會自動移除。
- **設計上即節省 token。** 清單以精簡的管線符號表格呈現並截斷過長的值；詳細資料檢視使用欄位允許清單；搜尋結果上限 50 筆，以保護 LLM 的上下文。
- 所有工具都回傳純文字／JSON 內容；連線錯誤會在回應中回報。
- HTTP 傳輸方式停用了 DNS rebinding 防護，以免在反向代理後方出現 `421 Misdirected Request`；API 金鑰中介軟體採純 ASGI，不會破壞 SSE 串流。

---

## 變更記錄 (近期)

- **v2.5**：小型 LLM 最佳化：更清楚的工具說明、一致的 `page`/`page_size` 分頁、節省 token 的純文字輸出、詳細欄位允許清單、透過 uvicorn 提供 SSE/streamable-http 並停用 DNS rebinding、可選用 `--api-key` Bearer 認證。
