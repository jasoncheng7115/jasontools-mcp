# LibreNMS MCP Server v4.5.2

以 FastMCP 為基礎的 LibreNMS API 整合工具，針對能力較弱、規模較小的 LLM (gpt-oss:120b 等) 最佳化。

- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

## 功能特色

- **29 個工具**：由 32 個精簡而來，合併功能重疊者，移除除錯用與冷門工具
- **對弱模型友善**：`[YES]/[NO]` 意圖標記，docstring 採中英雙語
- **精簡回應**：瘦身後的裝置／連接埠物件、不縮排的 JSON、`{"data":[], "count":N}` 格式
- **三種傳輸方式**：`stdio` (預設，供 Claude Desktop／mcpo 使用) + `streamable-http` + `sse`
- **智慧解析**：`_resolve_device()` 可接受主機名稱、IP 或 device_id

## 快速上手

### 需求環境

```bash
pip install mcp requests uvicorn
```

### stdio 模式 (Claude Desktop／mcpo)

```bash
python3 mcp_librenms.py \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN" \
  --verify-ssl false \
  --cache-ttl 600
```

### streamable-http 模式

```bash
python3 mcp_librenms.py \
  --transport streamable-http \
  --listen 0.0.0.0 \
  --port 8080 \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN"
```

### SSE 模式 (供 Chatbox／Open WebUI 使用)

```bash
python3 mcp_librenms.py \
  --transport sse \
  --listen 0.0.0.0 \
  --port 8080 \
  --url "https://librenms.example.com/api/v0" \
  --token "YOUR_API_TOKEN" \
  --api-key "YOUR_MCP_API_KEY"
```

Chatbox 連線設定：

| 欄位 | 值 |
|-------|-------|
| 類型 | Remote (http/sse) |
| URL | `http://SERVER_IP:8080/sse` |
| HTTP Header | `Authorization=Bearer YOUR_MCP_API_KEY` |

SSE 模式也會**在同一個連接埠的 `/mcp` 提供 Streamable HTTP** (自 v4.5.2 起)。只要用戶端支援 (例如 Claude Code 的 `"type": "http"`)，
請優先使用 `/mcp`：SSE 用戶端在連線中斷 (筆電睡眠、網路短暫斷線) 後自動重新連線時，會拿到新的工作階段卻不會重送
`initialize`，之後每次呼叫都會以 `-32602 Invalid request parameters` 失敗。`/mcp` 是無狀態的，所以沒有工作階段可以遺失。

### mcpo (OpenAPI proxy) 部署

```bash
uvx mcpo --port 8000 --api-key "YOUR_KEY" -- \
  python3 mcp_librenms.py \
    --url "https://librenms.example.com/api/v0" \
    --token "YOUR_API_TOKEN" \
    --verify-ssl false
```

systemd 服務範例：

```ini
[Unit]
Description=MCP LibreNMS Server (via mcpo)
After=network.target

[Service]
Type=simple
User=mcpuser
EnvironmentFile=/etc/default/mcp_librenms
ExecStart=/bin/bash -c 'uvx mcpo --port ${MCPO_PORT} --api-key "${MCPO_API_KEY}" -- \
  env LIBRENMS_URL=${LIBRENMS_URL} LIBRENMS_TOKEN=${LIBRENMS_TOKEN} \
  uvx --with mcp --with requests --with urllib3 python /opt/mcp/mcp_librenms.py'
Restart=always

[Install]
WantedBy=multi-user.target
```

### Claude Desktop 設定

```json
{
  "mcpServers": {
    "librenms": {
      "command": "uvx",
      "args": [
        "--with", "mcp", "--with", "requests",
        "python3", "/path/to/mcp_librenms.py",
        "--url", "https://librenms.example.com/api/v0",
        "--token", "YOUR_API_TOKEN",
        "--verify-ssl", "false"
      ]
    }
  }
}
```

## 工具 (29)

### 裝置管理
| 工具 | 說明 |
|------|-------------|
| `list_devices` | 列出／搜尋裝置 (預設上限 50 筆，可依狀態／OS／位置篩選) |
| `get_device_info` | 依主機名稱／IP／device_id 取得單一裝置詳細資料 |
| `get_device_ports` | 取得裝置的所有連接埠 |
| `get_devices_with_ports` | 取得多台裝置及其連接埠 |
| `diagnose_device` | 完整的裝置診斷，附健康分數 |

### 網路查詢
| 工具 | 說明 |
|------|-------------|
| `search_ip_to_mac` | 由 IP 查 MAC 位址 (ARP) |
| `search_mac_to_ip` | 由 MAC 查 IP 位址 (ARP) |
| `search_fdb_by_mac` | 由 MAC 查交換器／連接埠 (FDB) |
| `troubleshoot_ip` | 完整 IP 追查：ARP + FDB + 裝置 + VLAN (一次完成) |

### 網路表格
| 工具 | 說明 |
|------|-------------|
| `list_fdb_entries` | 列出 FDB 項目 (依裝置或 VLAN) |
| `get_network_arp_table` | 網路／裝置的 ARP 表 |

### 監控
| 工具 | 說明 |
|------|-------------|
| `list_all_services` | 列出受監控的服務 |
| `get_event_log` | 裝置事件記錄 (狀態／組態／硬體變更) |
| `get_monitoring_health` | 已停止輪詢的裝置 (過時／停用／忽略) |
| `get_recent_alerts` | 目前作用中 (觸發中) 的警報 |
| `get_alert_history` | 歷史警報，含已解除者 |
| `network_health_overview` | 網路資訊看板：健康分數 + 有問題的裝置 |

### 效能排行
| 工具 | 說明 |
|------|-------------|
| `get_top_cpu` | 依 CPU 使用率排序的裝置 (需要輔助程式，見下文) |
| `get_top_memory` | 依記憶體使用率排序的裝置 (需要輔助程式，見下文) |

### SLA
| 工具 | 說明 |
|------|-------------|
| `get_device_sla` | 裝置可用性 SLA (運作時間 %、中斷歷程) |
| `get_cisco_sla` | Cisco IP SLA 探測結果 (RTT、jitter、狀態；需要輔助程式) |

### 感測器／硬體
| 工具 | 說明 |
|------|-------------|
| `get_sensor_health` | 溫度、電壓、風扇、電源感測器健康狀態 + 離群值 |
| `get_optical_health` | SFP/GBIC DDM 光功率餘裕 + 更換風險排行 |

### 連接埠流量
| 工具 | 說明 |
|------|-------------|
| `get_port_traffic` | 頻寬使用率 + 錯誤計數器，由最差者開始排序 |

### 全網效能
| 工具 | 說明 |
|------|-------------|
| `get_all_device_performance` | 一次呼叫取得**每一台**裝置的 CPU + 記憶體，而非只有前 N 名 |

### Syslog
| 工具 | 說明 |
|------|-------------|
| `get_syslog` | 裝置送到 LibreNMS 的 Syslog 訊息 (依裝置限定範圍，見 API 特性表) |

### 公用工具
| 工具 | 說明 |
|------|-------------|
| `librenms_api` | 原始 API 呼叫 (任何 LibreNMS 端點) |
| `health_check` | 驗證 API 連線能力 |
| `clear_cache` | 清除內部 API 快取 |

## 光模組健康狀態說明

`get_optical_health` 是**某個時間點的快照**，兩次呼叫之間不會儲存任何資料。
LibreNMS 把感測器歷程存在 RRD，而 REST API 只以圖表影像的形式提供，因此若沒有
在伺服器端讀取 RRD 的輔助程式或本機資料儲存區，就**無法**做衰減速率預測 (「這顆 GBIC
會在 N 個月後達到警報閾值」)。改以下列方式排序風險：

- **閾值餘裕**：`sensor_current` 減去低光功率警報門檻
- **同儕離群值**：與同一裝置、同一方向模組中位數的偏差
  (median/MAD，需要 ≥4 個同儕)。以橫斷面比較取代無法取得的縱向比較。
- **偏壓電流／溫度**：若同一顆收發器有提供，則一併配對

### 備援閾值

未回報 `sensor_limit_low` 的裝置 (MikroTik RouterOS 對所有光模組門檻都回傳 NULL)
會改用通用的 SFP/SFP+ 數值：

| 方向 | 低警報 | 低警告 |
|-----------|-----------|----------|
| RX | -20.0 dBm | -18.0 dBm |
| TX | -9.0 dBm | -8.0 dBm |

以這種方式判定的資料列會在輸出中標示 `src=fb`，避免把備援判定誤認為廠商資料。
請依您的光模組調整 `_OPT_FALLBACK_LIMITS`。

### 需求

收發器必須提供 DDM/DOM，且必須啟用 LibreNMS 的 `sensors` 探索模組，
否則不會有任何 `dbm` 感測器，工具會回報 0 個模組。
早於 `stale_days` (預設 7) 的讀數會回報為 `stale` 而不計分，因此已停止輪詢的裝置
不會被誤判為嚴重 (critical)。

## 值得了解的 API 特性

以下是在開發 v4.3/v4.4 時於某台 LibreNMS 上觀察到的行為。依賴其中任何一項之前，
請先在您自己的伺服器上驗證。

| 端點 | 行為 |
|----------|-----------|
| `/devices` | **忽略 `limit`、`hostname`、`ip` 與 `columns`**：一律回傳所有裝置及全部 61 個欄位。篩選必須在用戶端進行，且查詢篩選的結果未經驗證絕不可採信 (見 v4.3.0 的 `_resolve_device` 修正)。 |
| `/ports` | **會套用 `columns`**：預設回應完全沒有流量與錯誤計數器。`get_port_traffic` 會明確要求這些欄位。 |
| `/logs/eventlog` | 以**由舊到新**的順序回傳，且可能有數十萬筆資料列。請用 `?from=` 限定時間範圍；翻頁到最後並不可行。 |
| `/resources/sensors` | 一次呼叫就回傳所有裝置上的所有感測器。感測器工具因此只需一次請求。 |
| `/devices/{id}/availability` | 每台裝置一次呼叫，因此全網 SLA 會透過執行緒集區平行展開。 |
| `/resources/links`、`/resources/wireless` | 回傳 404：沒有 LLDP 拓樸或無線資料。因此光模組無法進行鏈路端點關聯。 |
| `ifInDiscards` / `ifOutDiscards` | 不是有效的 `columns` 值；只有 `ifInErrors_delta` / `ifOutErrors_delta` 可用。 |
| `/devices/{id}/processors`、`/devices/{id}/mempools` | **在 26.x master 上回傳 HTTP 500。** 請用 `/devices/{id}/health/processor` 列出感測器 ID，再用 `/devices/{id}/health/processor/{sensor_id}` 取得讀數。`get_all_device_performance` 正是這樣做，並透過執行緒集區平行展開。 |
| `/logs/syslog` | 極慢。不限定範圍時，兩筆資料列花了 **41.7s**；加上 `from=` 則完全逾時。以數字 `device_id` 限定範圍 (17s) 比以主機名稱限定 (54s) 快。`get_syslog` 預設逾時 120s，並會要求指定裝置。 |
| `custom_top_devices.php` | 隨附的輔助程式會載入 `includes/init.php`。在 26.x 上它送出標頭後就只輸出 **0 位元組**：快速路徑會無聲無息地什麼都拿不到，因此工具必須有可正常運作的備援方式。 |

## 監控健康狀態

之所以有 `get_monitoring_health`，是因為其他所有工具回報的都是 LibreNMS 最後儲存的值。
無聲無息停止輪詢的裝置仍會回傳看似可信的讀數：在參考伺服器上，一台已停用的交換器
仍在提供 2023 年的感測器數值，完全看不出這些數值已經是三年前的資料。

類別：`never_polled`、`stale` (超過 `stale_hours`)、`disabled` (無限期保留
最後已知的數值)、`ignored`、`down`、`slow_poll` (每次輪詢 >30s)。

當其他工具回傳的數字看起來不合理時，請先執行它。

## 伺服器端輔助程式設定

LibreNMS REST API **不**提供處理器／記憶體集區資料
([GitHub #17737](https://github.com/librenms/librenms/issues/17737))，
也不提供 Cisco IP SLA 探測資料。
`get_top_cpu`、`get_top_memory` 與 `get_cisco_sla` 工具需要在 LibreNMS 伺服器上
部署一支輔助 PHP 指令碼。

### 安裝輔助程式

```bash
# Copy to LibreNMS web root
cp custom_top_devices.php /opt/librenms/html/
chown librenms:librenms /opt/librenms/html/custom_top_devices.php
```

### 驗證

```bash
curl -sk -H "X-Auth-Token: YOUR_TOKEN" \
  "https://librenms.example.com/custom_top_devices.php?type=processor&limit=5"
```

預期回應：
```json
{"status":"ok","data":[{"device_id":1,"hostname":"sw01","sysName":"sw01",
  "ip":"10.0.0.1","cpu_usage_pct":45.2,"processor_count":2}],"count":1}
```

MCP 工具會自動偵測這個輔助程式。若未部署，會退回逐台裝置呼叫 API
(由於 API 的限制，很可能回傳空值)。

## 設定

| CLI 參數 | 環境變數 | 預設值 | 說明 |
|-----------|---------|---------|-------------|
| `--url` | `LIBRENMS_URL` | *必填* | LibreNMS API 基礎 URL (`/api/v0`) |
| `--token` | `LIBRENMS_TOKEN` | *必填* | API 權杖 |
| `--verify-ssl` | `LIBRENMS_VERIFY_SSL` | `true` | 驗證 SSL 憑證 |
| `--cache-ttl` | `LIBRENMS_CACHE_TTL` | `300` | 快取 TTL (秒) |
| `--timeout` | `LIBRENMS_TIMEOUT` | `30` | API 請求逾時 |
| `--max-retries` | `LIBRENMS_MAX_RETRIES` | `3` | 失敗時的重試次數 |
| `--batch-size` | `LIBRENMS_BATCH_SIZE` | `200` | 分頁批次大小 |
| `--transport` | - | `stdio` | 傳輸方式：`stdio`、`streamable-http` 或 `sse` |
| `--listen` | - | `0.0.0.0` | HTTP 繫結位址 (http/sse 傳輸方式) |
| `--port` | - | `8000` | HTTP 連接埠 (http/sse 傳輸方式) |
| `--api-key` | `MCP_API_KEY` | *(無)* | SSE/HTTP 用戶端的 Bearer 權杖認證 |

優先順序：CLI 參數 > 環境變數 > 預設值。

## 變更記錄

### v4.5.2 (2026-09-29) - 修正：SSE 用戶端卡在未初始化的工作階段

SSE 模式也在 `/mcp` 提供 Streamable HTTP (無狀態)，因此用戶端在 SSE 重新連線後不會再卡在未初始化的工作階段 (所有呼叫都以 `-32602` 失敗)；API 金鑰檢查改為單純的 ASGI 中介軟體 (常數時間比對)，不再於每次 SSE 中斷連線時記錄 `AssertionError`。

### v4.5.1 (2026-09-06) - 修正：troubleshoot_ip 對每個 IP 都失效

`troubleshoot_ip` 會對 `search_fdb_by_mac` 的回傳值呼叫 `json.loads()`。
但該工具在某個時間點為了節省 token 改成以管線符號分隔的文字輸出，
因此每次查詢時解析都會拋出 `Expecting value: line 1 column 1`：自那次變更後，
這個工具沒有成功解析過任何一個 IP，而且失敗時的錯誤訊息完全看不出真正原因。

- 抽出 `_fdb_entries_for_mac()`，讓模組內的呼叫端取用結構化資料，
  而不是某個工具的呈現格式。
- 新增 `_tool_rows()`，可接受 JSON 或管線符號分隔的表格，供其餘仍需讀取
  其他工具輸出的地方使用。
- `switch_location` 已扁平化：在這台 LibreNMS 上，`/devices` 會以巢狀物件回傳位置，
  答案被埋在一團座標資料底下。

根本的錯誤值得直說：這個模組的工具刻意回傳兩種不同的格式，
因此模組內任何地方都不可假設自己拿到的是哪一種。

### v4.5.0 (2026-09-06) - 全網效能／Syslog

兩個工具，都是因應參考伺服器無法回答的問題而生：

- **`get_all_device_performance`**：一次呼叫取得每台裝置的 CPU 與記憶體。
  `get_top_cpu` / `get_top_memory` 只會回傳排序後的一部分，而在沒有 PHP 輔助程式的
  伺服器上，會退回逐台裝置的循序迴圈，120s 內跑不完。新工具透過執行緒集區平行展開，
  在 **9.7s** 內回傳全部 72 台運作中的裝置。
- **`get_syslog`**：Syslog 訊息，之前完全沒有工具可用。`get_event_log`
  涵蓋的是 LibreNMS 自己的事件記錄，那是另一回事。

配套變更：

- `_api_request` 可接受每次呼叫各自的 `timeout`；預設的 30s 不足以涵蓋 Syslog。
- 效能的備援方式改為先讀 `health/{type}` 再讀 `health/{type}/{sensor_id}`，
  因為 `/devices/{id}/processors` 與 `/mempools` 在 26.x 上回傳 HTTP 500。

### v4.4.0 (2026-07-29) - 感測器／連接埠／事件／監控涵蓋範圍
- 新增 `get_sensor_health`：溫度、電壓、風扇、電源感測器健康狀態，並提供
  雙向同儕離群值偵測。在參考伺服器上，377 個感測器中有 369 個在此之前沒有任何工具涵蓋。
- 新增 `get_port_traffic`：頻寬使用率與錯誤計數器，由最差者開始排序，
  可依 `utilization` / `errors` / `traffic` 排序。需要在 `/ports` 加上
  `?columns=`：預設回應完全省略這兩者。
- 新增 `get_event_log`：以 `?from=` 限定時間範圍的裝置事件記錄
- 新增 `get_monitoring_health`：找出已停止輪詢的裝置
- `get_device_sla` 的全網擷取透過新的 `_parallel_map` 平行化：
  82 台裝置 **11.6s → 5.3s** (先前每台裝置循序呼叫一次)
- `SimpleCache` 現在有鎖保護：從執行緒集區進入其到期路徑時，可能會拋出 `KeyError`
- `_peer_outliers` 由原本僅供光模組使用的版本通用化，並支援雙向，
  因此遠*高於*同儕的感測器也會被標示
- 修正感測器類別篩選：空的類別集合現在視為「沒有任何符合項」，而不是「不篩選」，
  先前會讓只有光模組感測器的裝置把 `dbm` 資料列漏進 `get_sensor_health`

### v4.3.0 (2026-07-29) - 光收發器健康狀態
- 新增 `get_optical_health`：SFP/GBIC DDM 光功率餘裕 + 風險排行
- 以單次 `resources/sensors` 呼叫涵蓋全網；原始感測器資料列絕不回傳給呼叫端，
  只回傳摘要計數與有上限的明細資料列 (預設 20，硬性上限 100)
- 將 `sensor_descr` 簡化為連接埠鍵值，讓 `dbm` 與同一顆收發器的偏壓電流／溫度感測器配對
- 裝置未回報 `sensor_limit_low` 時使用內建的備援閾值
- 以同儕離群值偵測 (median/MAD) 取代趨勢分析，因為沒有儲存的歷程就不可能做趨勢分析
- 過時的讀數回報為 `stale`，而不是計為 `critical`
- **修正 `_resolve_device`**：會忽略 `?hostname=` / `?ip=` 查詢篩選的 LibreNMS 版本
  會回傳完整裝置清單，而取 `devs[0]` 會讓*每一個*主機名稱／IP 都解析成同一台裝置。
  現在會將結果與查詢條件比對驗證。所有帶 `device` 參數的工具都受影響；先前只有
  數字裝置 ID 能正確解析。

### v4.2.1 (2026-03-02) - 相容性修正
- 需要 `mcp>=1.26.0` (較新的 SDK 才加入 `TransportSecuritySettings`)
- 修正 mcp 套件過舊 (1.9.4 → 1.26.0) 導致 Claude Desktop 無法啟動的問題
- `pip install mcp requests uvicorn` (只有 SSE/HTTP 傳輸方式才需要 `uvicorn`)

### v4.2.0 (2026-02-26) - SLA 工具 + SSE/Streamable-HTTP 修正
- 新增 `get_device_sla`：裝置可用性 SLA (運作時間 %、中斷歷程)
- 新增 `get_cisco_sla`：Cisco IP SLA 探測結果 (RTT、jitter、狀態)
- SSE/Streamable-HTTP：改用 `uvicorn` + `sse_app()`/`streamable_http_app()` (修正自訂主機／連接埠)
- 停用 DNS rebinding 防護 (修正 Chatbox/Open WebUI 出現的 421 Misdirected Request)
- 新增 `--api-key` Bearer 權杖認證，供 SSE/HTTP 用戶端使用
- `custom_top_devices.php`：新增 `cisco_sla` 查詢類型
- `_extract_data` 鍵值擴充：`availability`、`outages`

### v4.1.0 (2026-02-23) - CPU／記憶體排行 + 穩健性
- 新增 `get_top_cpu`、`get_top_memory` 工具，搭配 `custom_top_devices.php` 輔助程式
- `custom_top_devices.php`：在伺服器端查詢資料庫，繞過 API 的限制
- 所有涉及裝置的工具回應都包含 sysName
- `list_devices` 預設上限由不限改為 50
- 改善 docstring，加入中文觸發詞以利弱模型比對
- 多重策略擷取健康資料，並提供診斷用錯誤訊息
- `_extract_data` 鍵值擴充：processors、mempools、graphs、sensors

### v4.0.0 (2026-02-10) - 全面改寫
- 工具由 32 個減為 18 個 (合併功能重疊者，移除除錯用與冷門工具)
- 透過 `_R()` 輸出精簡 JSON (不縮排、不使用 `ensure_ascii`)
- 瘦身後的裝置／連接埠物件 (`_slim_device` 約 11 個欄位，`_slim_port` 約 7 個欄位)
- `_resolve_device()` 可接受主機名稱／IP／device_id
- 人類易讀的參數：`state="ok"/"warning"/"critical"`，使用 `vlan_tag` 而非 `vlan_id`
- 一致的 `{"data": [...], "count": N}` 回應格式
- docstring 中加入 `[YES]/[NO]` 意圖標記
- 雙傳輸方式：stdio + streamable-http

### v3.11.0 - 支援雙傳輸方式 (stdio + streamable-http)
### v3.10.2 - VLAN 對應修正 (vlan_id 與 vlan_vlan)
### v3.x - 最初的 FastMCP 實作，32 個工具

## 作者

**Jason Cheng** (Jason Tools) - 由 Claude 協助強化
授權：MIT
