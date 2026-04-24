# MCP Server for Wazuh SIEM

以 FastMCP 為基礎的 Wazuh SIEM 整合工具，讓 LLM 可透過自然語言操作 Wazuh。提供 25 個 MCP 工具，涵蓋告警、漏洞、Agent、規則、日誌、叢集、快取等功能。

- 作者：Jason Cheng (與 Claude Code 共同建置)
- 授權：MIT
- 版本：v1.3.8（2026-04-24）
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能簡介

讓 LLM 直接查詢 Wazuh SIEM，背後同時對接兩個 Wazuh API：

- Wazuh Manager API (port 55000，JWT 認證)：agents、rules、cluster、stats
- Wazuh Indexer (port 9200，Basic 認證)：`wazuh-alerts-*` 原始告警資料

回傳內容會做壓縮 (移除 None、最小化 JSON 分隔符)，並在原始 `rule.level` 數字之外附上人類易讀的 `severity` 標籤，避免小模型誤判 0-15 分級。

---

## 需求環境

- Python 3.10 以上
- 可連通的 Wazuh Manager 與 Indexer (已測試 Wazuh 4.x，含 4.12)
- Python 套件：`mcp`、`requests`、`urllib3`、`uvicorn` (SSE、streamable-http 時使用)

```bash
pip install mcp requests urllib3 uvicorn
```

---

## 快速上手

### stdio 模式 (Claude Desktop、本機 CLI)

```bash
python3 mcp_wazuh.py \
  --manager-host 192.168.1.40 --manager-user wazuh  --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin  --indexer-pass CHANGE_ME
```

### SSE 模式 (Chatbox 等舊版 MCP client)

```bash
python3 mcp_wazuh.py --transport sse --host 0.0.0.0 --port 8014 \
  --api-key YOUR_SECRET_KEY \
  --manager-host 192.168.1.40 --manager-user wazuh --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass CHANGE_ME
```

端點：`http://<host>:8014/sse`

### Streamable HTTP 模式 (多 client、網路存取)

```bash
python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \
  --api-key YOUR_SECRET_KEY \
  --manager-host 192.168.1.40 --manager-user wazuh --manager-pass CHANGE_ME \
  --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass CHANGE_ME
```

端點：`http://<host>:8000/mcp`

---

## 設定選項

優先順序：**CLI 參數 > 環境變數 > 預設值**。

### CLI 參數

| 參數 | 說明 | 預設 |
|---|---|---|
| `--manager-host` | Manager hostname、IP | (必填) |
| `--manager-port` | Manager port | `55000` |
| `--manager-user`、`--manager-pass` | Manager 帳密 | (必填) |
| `--indexer-host` | Indexer hostname、IP | (必填) |
| `--indexer-port` | Indexer port | `9200` |
| `--indexer-user`、`--indexer-pass` | Indexer 帳密 | (必填) |
| `--use-ssl` | 啟用 TLS 驗證 | `false` |
| `--protocol` | `http`、`https` | `https` |
| `--cache-duration` | 快取 TTL (秒) | `300` |
| `--request-timeout` | 請求逾時 (秒) | `30` |
| `--retry-attempts` | 失敗重試次數 | `3` |
| `--transport` | `stdio`、`sse`、`streamable-http` | `stdio` |
| `--host` | HTTP server 監聽位址 | `0.0.0.0` |
| `--port` | HTTP server port | `8000` |
| `--api-key` | SSE、HTTP 模式的 Bearer token | (無) |
| `--severity-low-max` | 最多到這個 rule level 算 Low | `6` |
| `--severity-medium-max` | 最多到這個 rule level 算 Medium | `11` |
| `--severity-high-max` | 最多到這個 rule level 算 High | `13` |

### 環境變數

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

### Severity 切點

Wazuh rule level 範圍 0-15，官方沒有單一的 Low、Medium、High、Critical 切點定義。本工具預設對齊 Wazuh Dashboard VIS 常見切點：

- Low：0-6
- Medium：7-11
- High：12-13
- Critical：14-15

若貴司 Dashboard 使用不同切點，在啟動時覆寫即可，例如：

```bash
--severity-low-max 3 --severity-medium-max 7 --severity-high-max 11
```

會變成 Low 0-3、Medium 4-7、High 8-11、Critical 12-15。

---

## 工具清單

### 告警監控
- `alertSummary`：完整告警內容 + IoC 抽取，支援分頁
- `alertStatistics`：告警數量與 severity 分布，top rules、top agents
- `agentsWithAlerts`：依告警數排序的 Top N 主機

### 規則
- `rulesSummary`：偵測規則，含 GDPR、HIPAA、PCI-DSS、NIST 合規對應

### 漏洞
- `vulnerabilitySummary`：每個 agent 的 CVE 清單

### Agent 管理
- `listAgents`：Agent 清單 (支援分頁)
- `listGroups`：群組清單與每組 agent 數
- `agentDetail`、`agentHardware`、`agentPackages`、`agentNetworks`、`agentSCA`
- `agentProcesses`、`agentPorts`
- `agentsOutdated`、`agentsSummary`

### Manager、日誌、叢集
- `searchManagerLogs`、`logCollectorStats`、`remotedStats`、`weeklyStats`
- `clusterHealth`、`clusterNodes`

### 工具類
- `healthCheck`、`clearCache`、`cacheStats`

---

## 分頁慣例

列表型工具 (`alertSummary`、`listAgents`、`vulnerabilitySummary`、`rulesSummary`、`clusterNodes`) 回傳中會包含 `pagination` 區塊：

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

LLM 端看到 `has_more: true` 時，應提示使用者回覆「下一頁」再發第二次查詢，且帶入 `next_offset`。

---

## 以 systemd 部署 (SSE 範例)

加上 orphan process 清理：

```ini
[Unit]
Description=MCP Wazuh SSE service
After=network.target

[Service]
Type=simple
User=mcpuser
Group=mcpuser
WorkingDirectory=/opt/mcp
# 啟動前清掉可能殘留在本 port 的舊 process
ExecStartPre=/usr/bin/fuser -k 8014/tcp
ExecStart=/opt/mcp/venv/bin/python3 /opt/mcp/mcp_wazuh.py \
    --transport sse --host 0.0.0.0 --port 8014 \
    --api-key REDACTED \
    --manager-host 192.168.1.40 --manager-user wazuh --manager-pass REDACTED \
    --indexer-host 192.168.1.40 --indexer-user admin --indexer-pass REDACTED
# 崩潰後再清一次，避免子 process 占 port
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

## 建議的 LLM system prompt

給小上下文模型 (例如 GAIVIS 上的 gpt-oss:120b)，建議用簡短 system prompt 固定行為，`alertSummary` 每批筆數要小，優先用統計類工具。

```
你是 Wazuh SIEM 分析助理，用 MCP 工具查詢告警、漏洞、Agent。繁體中文回答。
先用統計類工具確認範圍，再撈明細。

工具選擇：
- 統計、分布、Top N → alertStatistics、agentsWithAlerts
- 告警明細、IoC → alertSummary
- Agent 清單 → listAgents
- 某 agent 漏洞 → vulnerabilitySummary

alertSummary 分頁：
- max_results 上限 50 (超過 100 會爆 context)
- 呼叫後看 has_more：true 提示「還有 N 筆，回『下一頁』續查」；false 提示已結束
- 使用者說「下一頁」「繼續」→ 用 next_offset 續查，其他參數不變
- 沒要求不要自動翻頁

告警量大先用 alertStatistics 看總量：
- > 500 → 回 severity 分布 + top 5 rules、agents，請縮範圍
- 100~500 → alertSummary(max_results=30, min_level=8)

輸出：告警用 markdown 表格 (時間、Agent、Level、Rule、描述)，最多 20 列；
結尾「本批 X / 總 Y / 剩 Z」；severity 用工具回傳欄位，不自己換算。
```

---

## 常見問題排除

- **`Unable to retrieve cluster status`**：舊版 `/cluster/status` 解析錯誤，v1.3.7 已修正，cluster 部署可正常回傳。
- **`Agent ID '1234' exceeds maximum (999)`**：v1.3.7 之前的 bug，已移除 999 硬上限。
- **Port 已被占用、SSE crash loop**：其他 process 占了 port，用上面 systemd 範例中的 `ExecStartPre`、`ExecStopPost` 配合 `fuser -k` 清理。
- **`421 Misdirected Request`**：MCP SDK 的 DNS rebinding protection，v1.3.5 之後已關閉。
- **Open WebUI 看不到工具**：重啟 MCP server 後需在 Open WebUI 頁面重新整理，它會重新抓 OpenAPI spec。

---

## 參考

- 設計參考自 [mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh) (Rust)，作者 Gianluca Brigandi
- Wazuh API 文件：<https://documentation.wazuh.com/current/user-manual/api/reference.html>
