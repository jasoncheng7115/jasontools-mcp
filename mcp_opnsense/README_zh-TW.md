# OPNsense MCP Server

適用於 **OPNsense** 的 [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器，以 FastMCP 為基礎，並針對能力較弱／小型的 LLM (例如 `gpt-oss`、`gemma`) 最佳化。提供 **28 個唯讀工具**，輸出精簡的 JSON，工具名稱採 camelCase。

- 作者：Jason Cheng (Jason Tools)
- 授權：MIT
- 版本：2.5.0
- 傳輸方式：`stdio` (預設)、`sse`、`streamable-http`
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

> 已在 **OPNsense 26.1.2 與 26.1.10** 上測試。有原生 API 的資料一律走 API，沒有時改讀 `config.xml`，因此舊版本只會功能降級而不會壞掉，詳見[各資料來源所需的最低 OPNsense 版本](#各資料來源所需的最低-opnsense-版本)。**連接埠轉送的 API 路徑需要 26.1 以上**；**防火牆規則需要 26.1 以上才完整** (低於此版本請見切換說明)。

---

## 功能

- 透過原生 API (`firewall/filter/search_rule`) 讀取防火牆**篩選規則**，GUI 規則、自動化規則與舊式規則都涵蓋在內。
- **可解析別名的規則**：每條規則都會解析 `src_alias`／`dst_alias` 以及別名說明。
- **別名**：含解析後的項目清單與即時項目數。
- 一個工具涵蓋**全部四種 NAT 類型**：連接埠轉送 (26.1 `d_nat` API)、輸出 (outbound)、一對一、NPTv6。
- **閘道**：一次呼叫同時取得設定*與* dpinger 即時狀態：監控 IP、`monitor_disable`、優先順序、權重、遺失率／延遲，也包含動態 DHCP/PPPoE 閘道。
- **疑難排解**：防火牆記錄 (含符合的規則)、即時狀態表、系統／稽核／服務記錄、Suricata IDS 警報、各規則命中計數 (找出沒用到的規則)。
- **健康狀態**：運作時間、負載、記憶體、磁碟、溫度、狀態表使用率與系統通知；VPN 通道 (WireGuard 交握、OpenVPN 用戶端、IPsec SA)；憑證到期日。
- 服務、**Kea、Dnsmasq 與 ISC** 的 DHCP 租約／設定、含連線速度的介面、ARP/NDP、即時路由表。
- 韌體狀態／資訊／設定、套件與外掛程式 (`os-*`)。
- **嚴格唯讀**：沒有任何工具會在防火牆上啟動作業 (不做更新檢查、稽核、健康檢查或連線測試)，也絕不回傳私密金鑰。
- 設定摘要，以及匯出任一 `config.xml` 區段的原始 XML。
- 以 API 優先，並自動改用 `config.xml`；每個回答都會標明資料來源 `source`。
- 多種傳輸方式、HTTP 可選用 API 金鑰認證、具 TTL 的回應快取、含退避的重試。

---

## 需求環境

- Python 3.10 以上
- OPNsense **API 金鑰 + 密鑰** (System → Access → Users → *API keys*)
- Python 套件：

```bash
pip install mcp aiohttp requests defusedxml urllib3 uvicorn
```

只有 `sse`／`streamable-http` 傳輸才需要 `uvicorn`。

---

## 設定

設定值的解析順序：**CLI 參數 > 環境變數 > 預設值**。

| 環境變數 | CLI 參數 | 預設值 | 說明 |
|---|---|---|---|
| `OPNSENSE_HOST` | `--host` | — (必填) | 基礎 URL，例如 `https://opnsense.example.com` |
| `OPNSENSE_API_KEY` | `--api-key` | — | OPNsense API 金鑰 |
| `OPNSENSE_API_SECRET` | `--api-secret` | — | OPNsense API 密鑰 |
| `OPNSENSE_VERIFY_SSL` | `--verify-ssl` | `false` | 驗證 TLS 憑證 |
| `OPNSENSE_TIMEOUT` | `--timeout` | `30` | 請求逾時 (秒) |
| `OPNSENSE_CACHE_TTL` | `--cache-ttl` | `300` | GET 快取 TTL (秒) |
| `OPNSENSE_MAX_RETRIES` | `--max-retries` | `3` | 重試次數 (指數退避) |
| — | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--listen` | `0.0.0.0` | HTTP 綁定位址 |
| — | `--port` | `8000` | HTTP 連接埠 |
| `MCP_API_KEY` | `--mcp-api-key` | — | 保護 HTTP/SSE 端點用的 Bearer 權杖 |

---

## 使用方式

### stdio (預設)

```bash
python3 mcp_opnsense.py \
  --host "https://opnsense.example.com" \
  --api-key KEY --api-secret SECRET
```

### SSE

```bash
python3 mcp_opnsense.py --transport sse --listen 0.0.0.0 --port 8017 \
  --host "https://opnsense.example.com" --api-key KEY --api-secret SECRET \
  --mcp-api-key YOUR_BEARER_TOKEN
```

SSE 模式也會**在同一個連接埠的 `/mcp` 提供 Streamable HTTP** (自 v2.4.1 起)。只要用戶端支援，請優先使用 `/mcp`
(例如 Claude Code 的 `"type": "http"`)：SSE 用戶端在連線中斷 (筆電睡眠、網路短暫斷線) 後自動重新連線時，
會拿到一個新的工作階段卻沒有重送 `initialize`，之後每次呼叫都會以 `-32602 Invalid request parameters` 失敗。
`/mcp` 是無狀態的，因此沒有工作階段可遺失。

### Streamable HTTP

```bash
python3 mcp_opnsense.py --transport streamable-http --port 8000 \
  --host "https://opnsense.example.com" --api-key KEY --api-secret SECRET
```

---

## Claude Desktop

加入 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/mcp_opnsense/mcp_opnsense.py"],
      "env": {
        "OPNSENSE_HOST": "https://your-opnsense-host",
        "OPNSENSE_API_KEY": "your-opnsense-api-key",
        "OPNSENSE_API_SECRET": "your-opnsense-api-secret",
        "OPNSENSE_VERIFY_SSL": "false",
        "OPNSENSE_TIMEOUT": "30"
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
uvx mcpo --port 8016 --api-key "YOUR_MCPO_KEY" -- \
  env OPNSENSE_HOST=https://opnsense.example.com \
      OPNSENSE_API_KEY=KEY \
      OPNSENSE_API_SECRET=SECRET \
      OPNSENSE_VERIFY_SSL=false \
  python /opt/mcp/mcp_opnsense.py
```

之後每個工具都可透過 `POST http://host:8016/<toolName>` 並帶上 `Authorization: Bearer YOUR_MCPO_KEY` 使用。將 Open WebUI 的工具伺服器指向 `http://host:8016`。

---

## 工具 (28)

| 工具 | 說明 |
|---|---|
| `getConfigSummary` | 系統資訊 + 防火牆／別名／NAT／介面數量 (規則數經由 API 計算) |
| `getFirewallRules` | 經由 API 取得篩選規則，必要時改讀 config.xml；可解析別名 |
| `getNatRules` | 經由 API 取得任一類型的 NAT 規則，必要時改讀 config.xml |
| `getNatRulesConfig` | 直接從 config.xml 讀取 NAT 規則 (相容用途；建議改用 `getNatRules`) |
| `getGateways` | 閘道設定**與**即時狀態：監控 IP、優先順序、遺失率／延遲 |
| `getAliases` | 經由 API (預設) 或 config.xml 取得別名；內容清單 + 項目數 |
| `getAliasContent` | 指定別名解析後的項目 |
| `getServices` | 服務總覽 (執行中／已停止／已鎖定) |
| `getServiceStatus` | 單一服務的狀態 |
| `getFirmwareStatus` | 依路由器上次的更新檢查結果，列出待安裝的更新與是否需要重新開機 (不會啟動新的檢查) |
| `getFirmwareInfo` | 產品版本、系列、套件／外掛程式數量 (不會傾印 400 KB 的套件清單) |
| `getFirmwareConfig` | 韌體設定與鏡像站選項 |
| `getPackageInfo` | 單一套件的詳細資料／授權／變更記錄 |
| `getDhcpLeases` | 合併 Kea、Dnsmasq 與 ISC (v4/v6) 的租約；可依 IP/MAC/主機名稱/廠商搜尋 |
| `getDhcpSettings` | 使用中的 DHCP 伺服器、子網路、集區、發放的選項、靜態保留 |
| `getInterfaces` | 介面的狀態、IP、連線速度／雙工、閘道；可選擇附上計數器 |
| `getNetworkNeighbors` | ARP (IPv4) 及／或 NDP (IPv6) 表 |
| `getRoutes` | 使用中的核心路由表 + 已設定的靜態路由 |
| `downloadConfigXml` | config.xml：摘要，或指定區段的原始 XML |
| `getPlugins` | OPNsense 外掛程式 (`os-*`)；可依狀態／關鍵字篩選 |
| `getPackages` | 系統套件 (非 `os-*`)；可依狀態／關鍵字篩選 |
| `getSystemHealth` | 運作時間、負載、記憶體、swap、磁碟、溫度、狀態表、系統通知 |
| `getFirewallLog` | 防火牆記錄與符合的規則；可依動作／介面／IP／連接埠篩選 |
| `getFirewallStates` | 即時狀態表 (目前的連線)；可依 IP／連接埠／規則篩選 |
| `getSystemLog` | 系統、稽核、閘道、Kea、WireGuard、Suricata 與其他記錄；可依嚴重程度篩選 |
| `getVpnStatus` | WireGuard 對等端 (最後交握時間、流量)、OpenVPN 工作階段、IPsec SA |
| `getIdsAlerts` | Suricata IDS/IPS 警報 |
| `getCertificates` | 憑證與到期日、剩餘天數 (絕不回傳私密金鑰) |

凡是能從兩種來源讀取的工具，都會在 `source` 欄位標明實際使用的來源 (`"api"` 或 `"config"`)。

### `getFirewallRules` 參數

| 參數 | 預設值 | 說明 |
|---|---|---|
| `interface` | — | 依介面鍵值 (`wan`、`lan`、`opt1`…) 篩選。跨多個介面的規則 (`"wan,opt2"`) 也會符合 |
| `action` | — | `pass` / `block` / `reject` |
| `enabled_only` | — | `true` = 已啟用，`false` = 已停用，省略 = 全部 |
| `aliases_only` | `false` | 只列出引用別名的規則 |
| `include_automatic` | `true` | `false` = 只列出人工設定的規則 |

### `getNatRules` 參數

| 參數 | 預設值 | 說明 |
|---|---|---|
| `nat_type` | `port_forward` | `port_forward` / `outbound` / `one_to_one` / `npt`。別名：`forward` → `port_forward`，`source_nat` / `source` → `outbound` |
| `enabled_only` | — | `true` = 已啟用，`false` = 已停用，省略 = 全部 |
| `search` | — | 依說明篩選 (不分大小寫) |
| `include_automatic` | `false` | 包含 OPNsense 為了顯示而自動產生的規則 (防鎖定、自動輸出 NAT)，這些規則不在設定檔中 |

### `downloadConfigXml` 參數

| 參數 | 預設值 | 說明 |
|---|---|---|
| `section` | — | 要以原始 XML 傾印的最上層區段 (`gateways`、`system`、`nat`、`interfaces`、`OPNsense/Gateways`…)。省略則回傳摘要 |
| `max_chars` | `40000` | 截斷上限，完整的 config.xml 通常超過 300 KB |

### `getGateways` 參數

| 參數 | 預設值 | 說明 |
|---|---|---|
| `name` | — | 只查這個閘道 (不分大小寫)。省略則查全部 |

---

## 各資料來源所需的最低 OPNsense 版本

工具會先讀原生 MVC API，無法使用時再改讀 `config.xml`，因此較舊的防火牆只會功能降級而不會壞掉。會少掉哪些功能取決於版本：

| 資料 | API 端點 | 最低版本 | 低於此版本時 |
|---|---|---|---|
| 防火牆規則 | `firewall/filter/search_rule` | **24.1** | config.xml `<filter><rule>` |
| 連接埠轉送 | `firewall/d_nat/search_rule` | **26.1** | config.xml `<nat><rule>` |
| 輸出 NAT | `firewall/source_nat/search_rule` | **24.1** | config.xml `<nat><outbound>` |
| 一對一 NAT | `firewall/one_to_one/search_rule` | **24.7** | config.xml `<nat><onetoone>` |
| NPTv6 | `firewall/npt/search_rule` | **24.1** | *config.xml 沒有對應項目，僅能透過 API* |
| 別名 | `firewall/alias/search_item` | **23.7** | config.xml `<alias>` |
| 別名內容 | `firewall/alias_util/list/{name}` | **23.7** | — |
| 閘道 | `routing/settings/search_gateway` | **24.1** | config.xml + `routes/gateway/status` |
| 下載 config.xml | `core/backup/download/this` | **23.7.8** | 需要 `os-api-backup` 外掛程式 |
| DHCP 租約 | `kea/leases4/search`、`dnsmasq/leases/search`、`dhcpv4/leases/searchLease` | Kea 24.1、Dnsmasq 24.7；ISC 自 **26.1** 起為外掛程式 | 合併所有有回應的伺服器 |
| 介面 | `interfaces/overview/interfacesInfo` | **23.1** | — |
| 規則命中計數 | `firewall/filter_util/rule_stats` | **24.7** | `include_stats` 回傳錯誤 |
| 記錄 | `diagnostics/log/core/{scope}` | **23.7** | — |

### 26.1 防火牆規則切換 (相信規則數量之前請先讀這段)

`firewall/filter/search_rule` 從 24.1 起就有，**但在 24.1–25.7 只會回傳 Firewall → Automation 規則**，您在 GUI 看到的規則存放在 `config.xml` 的 `<filter><rule>`。到了 **26.1**，這些規則被移入 MVC 模型，`config.xml` 的 `<filter><rule>` 現在是**空的**。

所以沒有任何單一來源在各版本上都正確：

- 在 26.1 讀 config.xml，即使防火牆有數百條規則也會得到 **0 條**。
- 在 25.x 讀 API，除非送出 `show_all=1`，否則**只會得到自動化規則**。

這個伺服器會送出 `show_all=1` (在 25.x 上，這個旗標會把舊式 config.xml 規則合併進回應；在 26.1 上規則一律會合併，這個旗標無害)，只有 API 呼叫失敗時才改讀 config.xml。`getConfigSummary` 會同時回報 `firewall_rules` (實際生效，來自 API) 與 `firewall_rules_in_xml`，因此 `0` 代表的是「已遷移」而不是「沒有規則」。

閘道也以同樣方式搬移：26.1 在 config.xml 裡留下一個空的 `<gateways><gateway_item/></gateways>` 殘留結構，真正的設定放在 `<OPNsense><Gateways>` 底下。`downloadConfigXml(section="gateways")` 會偵測到這個殘留結構並指向新路徑。

---

## 附註

- 所有工具都回傳 JSON；錯誤會以 `{"error": "..."}` 回傳，而不是拋出例外。
- HTTP 傳輸停用了 DNS rebinding 防護，避免在反向代理後方出現 `421 Misdirected Request`。
- HTTP 用戶端會遵循 `HTTP_PROXY`／`HTTPS_PROXY`。當資安軟體封鎖 macOS 上 Claude Desktop 的子處理程序時，需要靠這個設定讓連線經由 `mcp_proxy` 轉送。
- **只看閘道狀態會被誤導。** 設定了 `monitor_disable` 的閘道永遠不會被 dpinger 探測，所以一律回報 `Online`，而且*不可能*被標記為離線。`getGateways` 會在 `note` 欄位標註這種情況，而不是讓它看起來正常。
- OPNsense 自行產生的規則 (自動篩選規則、防鎖定連接埠轉送、自動輸出 NAT) 會標上 `is_automatic`。這些規則僅供顯示，不在設定檔中。
- **唯讀就是唯讀。** 有幾個看似讀取的韌體端點，其實是會在防火牆上啟動作業的 POST：`core/firmware/check` (更新檢查)、`audit`、`health` (套件完整性檢查) 與 `connection`。v2.4.1 以前，`getFirmwareStatus`、`getFirmwareInfo` 與 `getFirmwareConfig` 每次請求都會呼叫它們。現在已不再呼叫；`getFirmwareStatus` 會回報路由器上次的檢查結果及其距今多久。
- **`trust/cert/search` 會回傳私密金鑰** (`prv`、`prv_payload`)。`getCertificates` 只複製允許清單中的欄位。
- `getSystemLog` 只接受固定清單中的記錄名稱：`diagnostics/log/core/<scope>/clear` 會清除記錄，因此路徑絕不由自由輸入的文字組成。
- 請使用具唯讀權限的專用 API 使用者，不要用 root 的金鑰：這個伺服器所做的一切都是讀取。
- HTTP 4xx (此版本沒有該端點、未安裝外掛程式、沒有權限) 不再重試；v2.4.1 每次都會以退避方式重試三次 (約 3.5 秒)。

---

## 變更記錄 (近期)

- **v2.5.0** — 以運作中的 26.1 防火牆與 26.1/26.7 API 進行檢視。
  - **修正：** 在使用 Kea/Dnsmasq 的防火牆上，DHCP 租約一律是空的 (只查詢 ISC API；ISC 自 26.1 起是外掛程式)，現在會合併 Kea、Dnsmasq 與 ISC，`getDhcpSettings` 也會顯示 Kea 的子網路、集區、選項與保留。`getRoutes` 只回傳靜態路由 (大多數防火牆上是空的)，現在改為核心路由表。`getInterfaces(interface=...)` 會回傳所有介面，現在只回傳一個，並附上來自 `interfaces/overview` 的連線速度與 IP。`getServiceStatus` 可比對 `kea-dhcp/v4` 這類服務 id 與說明。`getFirmwareStatus`／`getFirmwareInfo`／`getFirmwareConfig` 不再於防火牆上啟動更新檢查、稽核、健康檢查或連線測試，`getFirmwareInfo` 也從約 400 KB 降到 1 KB 以下。`getAliasContent` 新增 `search` (輸入 IP 可找出包含它的網段) 與 `limit` (一個 GeoIP 別名就有 140 KB)，並會回傳連接埠別名所設定的連接埠。`getAliases` 從 API 與 config.xml 回傳相同的欄位，並附上即時項目數。`getConfigSummary` 從 10 秒縮短為約 1 秒。4xx 不再重試。
  - **新增：** `getSystemHealth`、`getFirewallLog`、`getFirewallStates`、`getSystemLog`、`getVpnStatus`、`getIdsAlerts`、`getCertificates`；`getFirewallRules(include_stats, unused_only)` 提供各規則命中計數。

- **v2.4.1** — SSE 模式也在 `/mcp` 提供 Streamable HTTP (無狀態)，因此用戶端在 SSE 重新連線後不會再卡在未初始化的工作階段 (所有呼叫都以 `-32602` 失敗)；API 金鑰檢查改為單純的 ASGI 中介軟體 (常數時間比對)，不再於每次 SSE 中斷時記錄 `AssertionError`。
- **v2.4.0** — **修正 `getFirewallRules`／`getConfigSummary` 在 OPNsense 26.1 上回傳 0 條規則** (它們讀的是 config.xml，而 26.1 會把它清空)。現在讀取以 API 優先、必要時改讀 config.xml，並回報 `source`。新增 `getGateways` (設定 + 即時狀態，含動態 DHCP/PPPoE 閘道)。`getNatRules` 成為唯一的 NAT 入口，並透過 26.1 的 `firewall/d_nat` API 支援連接埠轉送。`downloadConfigXml` 新增 `section`，可回傳真正的 XML，而不只是數量。向下相容：v2.3.0 的所有工具名稱與參數仍可使用。
- **v2.3.0** — 宣稱改用 API 讀取規則與別名，但程式碼其實仍在解析 config.xml；原本要修正的 `firewall_rules=0` 錯誤反而照樣發布了。已由 v2.4.0 取代。
- **v2.2.x** — `getPlugins`／`getPackages`；設定摘要中顯示 OPNsense 版本。
- **v2.0.0** — 以 FastMCP 改寫，工具從 35 個精簡為 20 個，採 camelCase 名稱，支援多種傳輸方式。
