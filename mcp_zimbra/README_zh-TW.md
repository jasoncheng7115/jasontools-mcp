# Zimbra MCP Server

以 FastMCP 為基礎的 Zimbra Collaboration Suite 整合工具，讓 LLM 可透過自然語言查詢與管理 Zimbra 郵件系統。提供 52 個 MCP 工具，涵蓋帳號、網域、郵件佇列、權限稽核、信件內容、行事曆與工作項目。

- 作者：Jason Cheng（與 Claude Code 共同建置）
- 授權：MIT
- 版本：v1.10.0（2026-09-04）
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能簡介

透過 Zimbra 的 SOAP API 操作兩個命名空間：

- `urn:zimbraAdmin`（連接埠 7071）：帳號、網域、COS、伺服器、郵件佇列、權限
- `urn:zimbraMail`（管理員委派）：信件內容、通訊錄、行事曆、工作項目

回傳內容經過壓縮（移除空值、精簡 JSON 分隔符），並針對能力較弱的模型在每個工具附上一行使用提示，降低選錯工具的機率。

---

## 需求環境

- Python 3.10 以上
- 可連通的 Zimbra 8.8 / 9 / 10（管理連接埠 7071）
- Python 套件：`mcp`、`requests`、`urllib3`、`uvicorn`（SSE、streamable-http 時使用）

```bash
pip install mcp requests urllib3 uvicorn
```

---

## 認證模式

### 管理員模式（建議）

以管理員帳號登入，再透過 SOAP 標頭的 `<account>` 委派存取任一使用者信箱。**設定檔裡不會出現任何個人密碼**，使用者改自己的密碼也不會影響服務。

```bash
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin"
export ZIMBRA_ADMIN_PASS="CHANGE_ME"
```

可用工具：44 個基本工具 + 8 個信件讀取工具。

### 使用者模式

以一般帳號登入，只能存取自己的信箱。適合單一使用者的桌面情境。

```bash
export ZIMBRA_USER_EMAIL="user@example.com"
export ZIMBRA_USER_PASS="CHANGE_ME"
```

可用工具：13 個基本工具 + 8 個信件讀取工具。管理類工具不會註冊。

### 信件讀取開關

信件、行事曆、工作項目這 8 個工具**預設關閉**，要明確開啟：

```bash
export ZIMBRA_ENABLE_MAIL_READ="true"
```

關閉時這些工具不會出現在工具清單裡，模型不會知道有這些功能。

---

## 快速上手

### stdio 模式（Claude Desktop、本機 CLI）

```bash
python3 mcp_zimbra.py \
  --admin-url https://mail.example.com:7071/service/admin/soap \
  --admin-user admin --admin-pass CHANGE_ME
```

### SSE 模式（Chatbox、Jan.ai、OpenCode 等）

```bash
python3 mcp_zimbra.py --transport sse --http-port 8010 --api-key YOUR_KEY
```

### Streamable HTTP 模式（多用戶端、Open WebUI）

```bash
python3 mcp_zimbra.py --transport streamable-http --http-port 8000 --api-key YOUR_KEY
```

SSE 與 streamable-http 模式支援 `--api-key`，未帶正確的 `Authorization: Bearer` 標頭會回 401。

---

## 設定選項

設定順序為 **CLI 參數 > 環境變數 > 預設值**。

| 項目 | 環境變數 | 預設值 |
|------|----------|--------|
| 管理 API 網址 | `ZIMBRA_ADMIN_URL` | 無（必填） |
| 管理員帳號 | `ZIMBRA_ADMIN_USER` | 無 |
| 管理員密碼 | `ZIMBRA_ADMIN_PASS` | 無 |
| 郵件 API 網址 | `ZIMBRA_MAIL_URL` | 無 |
| 驗證 SSL 憑證 | `ZIMBRA_VERIFY_SSL` | `false` |
| 快取存續時間 | `ZIMBRA_CACHE_TTL` | `300`（秒） |
| 逾時 | `ZIMBRA_TIMEOUT` | `30`（秒） |
| 重試次數 | `ZIMBRA_MAX_RETRIES` | `3` |
| 啟用信件讀取 | `ZIMBRA_ENABLE_MAIL_READ` | `false` |

信件追蹤（選用，未設定時該 6 個工具不會註冊）：

| 項目 | 環境變數 | 預設值 |
|------|----------|--------|
| 服務網址 | `JT_ZMMSGTRACE_URL` | `http://localhost` |
| 連接埠 | `JT_ZMMSGTRACE_PORT` | `8989` |
| API 金鑰 | `JT_ZMMSGTRACE_API_KEY` | 無 |

---

## 工具清單

### 帳號管理（6 個）

| 工具 | 說明 |
|------|------|
| `getAccountInfo` | 查詢帳號資訊（配額、狀態、建立日期等） |
| `getAccountQuota` | 查詢帳號配額與使用量 |
| `getAccountAliases` | 查詢帳號的所有別名 |
| `unlockAccount` | 解鎖被鎖定的帳號 |
| `getAllAccounts` | 列出所有帳號，可篩選與分頁 |
| `getAccountCount` | 依網域或狀態統計帳號數 |

### 通訊群組（3 個）

| 工具 | 說明 |
|------|------|
| `getDLInfo` | 查詢通訊群組資訊 |
| `getDLMembers` | 查詢通訊群組成員，支援分頁 |
| `getAllDistributionLists` | 列出所有通訊群組 |

### 郵件佇列（3 個）

| 工具 | 說明 |
|------|------|
| `getQueueStat` | 依伺服器查詢郵件佇列統計 |
| `getQueueList` | 列出佇列中的郵件 |
| `searchMailQueue` | 依寄件者或收件者搜尋佇列 |

### 統計（2 個）

| 工具 | 說明 |
|------|------|
| `getMailboxStats` | 跨伺服器的信箱統計 |
| `getQuotaUsage` | 帳號配額使用量並排序（單次 API 呼叫，速度快） |

### 系統與網域（9 個）

| 工具 | 說明 |
|------|------|
| `getServerList` | 列出所有 Zimbra 伺服器 |
| `getServerStatus` | 即時服務狀態 |
| `getActiveSessions` | 目前登入中的使用者（SOAP／IMAP／管理介面） |
| `getDomainList` | 列出所有郵件網域 |
| `getDomainInfo` | 查詢網域詳細資訊 |
| `getCOSList` | 列出所有服務等級（COS） |
| `getCOSInfo` | 查詢 COS 詳細內容，支援正規表示式篩選與分頁 |
| `countAccountByCOS` | 依 COS 統計帳號數 |
| `getVersionInfo` | 查詢 Zimbra 版本 |

### 權限（3 個）

| 工具 | 說明 |
|------|------|
| `getGrants` | 查詢授予或被授予的權限 |
| `checkRight` | 檢查某個對象是否具有指定權限 |
| `getDelegates` | 查詢帳號的委派設定 |

### 批次稽核（5 個）

| 工具 | 說明 |
|------|------|
| `getAllDelegations` | 一次列出全站 sendAs／sendOnBehalfOf 委派權限 |
| `getAllForwardings` | 列出所有設定轉寄的帳號 |
| `getAllOutOfOffice` | 列出所有啟用外出自動回覆的帳號 |
| `getInactiveAccounts` | 列出閒置超過 N 天的帳號 |
| `searchByAttribute` | 以任意 LDAP 屬性搜尋 |

### 信件讀寫（7 個）†

| 工具 | 說明 |
|------|------|
| `searchMail` | 依主旨／寄件者／收件者／內文／日期搜尋信箱（資料夾支援模糊比對） |
| `getMailDetail` | 取單封信全文、標頭與附件清單 |
| `getConversation` | 取整串對話 |
| `getMailAttachment` | 下載附件到本機（`~/Downloads`） |
| `listFolders` | 列出信箱資料夾，可用關鍵字篩選 |
| `saveDraft` | 新信或回覆／轉寄存成草稿供人工確認後送出 |
| `searchContacts` | 搜尋個人通訊錄 |

### 行事曆與工作（3 個）†

| 工具 | 說明 |
|------|------|
| `searchCalendar` | 查詢期間內的約會，可指定單一行事曆；自動展開重複事件 |
| `getAppointment` | 取單一約會完整內容：描述、參與者與答覆狀態、重複規則、附件 |
| `searchTasks` | 查詢工作項目，可依資料夾、狀態、到期日篩選 |

約會與工作屬於行事曆項目而非郵件，`searchMail` 永遠找不到它們。這三個工具改用 `types="appointment"` 與 `types="task"`，走的是同一套管理員委派的郵件 API，同樣受 `ZIMBRA_ENABLE_MAIL_READ` 控制。

### 通訊錄查詢（1 個）

| 工具 | 說明 |
|------|------|
| `searchGal` | 搜尋全域通訊錄（GAL） |

### 進階通訊群組（1 個）

| 工具 | 說明 |
|------|------|
| `getDLMembership` | 查詢帳號或群組隸屬於哪些通訊群組（含巢狀關係） |

### 信件追蹤（6 個）

需設定 `JT_ZMMSGTRACE_API_KEY` 才會註冊。查詢的是獨立的 jt_zmmsgtrace 服務，不是 Zimbra 的 SOAP API。

| 工具 | 說明 |
|------|------|
| `jt_zmmsgtrace_search` | 於追蹤記錄中自由搜尋 |
| `jt_zmmsgtrace_search_by_sender` | 依寄件者追蹤 |
| `jt_zmmsgtrace_search_by_recipient` | 依收件者追蹤 |
| `jt_zmmsgtrace_search_by_message_id` | 依 Message-ID 追蹤單封信 |
| `jt_zmmsgtrace_search_by_host` | 依處理主機追蹤 |
| `jt_zmmsgtrace_search_by_time` | 依時間區間追蹤 |

### 工具類（3 個）

| 工具 | 說明 |
|------|------|
| `health_check` | 系統健康檢查 |
| `clear_cache` | 清除所有快取的 API 回應 |
| `cache_stats` | 查詢快取使用統計 |

**管理員模式合計 52 個**、**使用者模式合計 21 個**。

† 需要 `ZIMBRA_ENABLE_MAIL_READ=true`。

---

## 使用範例

管理類：

```
請查詢 user@example.com 的帳號資訊
請查看 mail.example.com 伺服器的健康狀況
請解鎖 locked_user@example.com 帳號
列出所有設定了轉寄的帳號
```

開啟信件讀取後，信件、行事曆與工作也可以問：

```
請找 user@example.com 信箱裡主旨含「報價」、2026-01-01 之後的信，列 20 筆
user@example.com 這週有哪些會議？
user@example.com 下週三下午有空嗎？
「Ceph 建置」那場會議有誰參加？他們回覆了嗎？
user@example.com 的待辦事項裡，還沒完成、且今年到期的有哪些？
```

**每個信件、行事曆、工作類工具都必須明確帶入 `account` 參數。** 管理員模式是靠管理員委派去讀信箱的，伺服器沒有「我的信箱」這個概念，也不會替你猜。

---

## 使用上要知道的幾件事

**`searchMail` 一旦傳入 `query`，`date_from` 與 `date_to` 會被忽略。** 日期必須寫進查詢字串裡，格式為 `after:MM/DD/YYYY`、`before:MM/DD/YYYY`。這是 Zimbra 查詢語法的限制。

**`searchCalendar` 沒有這個問題。** 它的 `date_from` 與 `date_to` 是以 SOAP 屬性（`calExpandInstStart` / `calExpandInstEnd`）送出，不會併進查詢字串，所以日期與 `query` 可以同時生效。

**`getMailDetail` 的參數是 `msg_id`，`getAppointment` 是 `appt_id`。** 不是 `message_id` 或 `appointment_id`，寫錯會被參數驗證擋下。

**查詢是當下的快照。** 這套工具不留歷史，要看趨勢得自己另外儲存。

**約會的參與者清單要取明細才有。** `searchCalendar` 的結果只帶 `has_other_attendees` 旗標，完整名單與答覆狀態要用 `getAppointment`，或在 `searchCalendar` 加上 `include_attendees=true`（每筆多一次請求，超過 20 筆會自動略過並在 `note` 說明）。

**答覆狀態有兩個來源。** `<at ptst>` 是邀請上記錄的狀態，`<replies>` 才是對方實際回覆的，後者優先。兩個工具共用同一套判定，同一場會議不會給出兩種答案。

---

## 以 systemd 部署（SSE 範例）

```ini
[Unit]
Description=MCP Zimbra (SSE)
After=network.target

[Service]
Type=simple
User=mcpuser
EnvironmentFile=/etc/mcp/zimbra.env
ExecStart=/usr/local/bin/uvx --with "mcp<2" --with requests --with urllib3 \
          --with uvicorn --with starlette --from /opt/mcp \
          python3 /opt/mcp/mcp_zimbra.py --transport sse --http-port 8010
Restart=always

[Install]
WantedBy=multi-user.target
```

`uvx` 每次啟動都會重新解析相依套件，**務必釘住 `mcp<2`**。`mcp` 2.0.0 移除了 `mcp.server.fastmcp`，沒釘版本的服務會在重新啟動時直接崩潰。

---

## 常見問題排除

**401 Unauthorized** — 管理員帳密錯誤，或 SSE／HTTP 模式的 `--api-key` 不符。

**421 Misdirected Request** — 走 SSE 或 streamable-http 且經過反向代理時出現。v1.9.1 起已停用 DNS rebinding 保護來避免這個問題。

**`Invalid request parameters`（SSE 斷線重連後）** — 伺服器端記錄的是 `Received request before initialization was complete`。SSE 重連後不會重跑 MCP `initialize` 握手，目前只能重開用戶端工作階段。這個錯誤訊息容易被誤判為金鑰失效或參數寫錯。

**行事曆或工作查不到資料** — 先確認 `ZIMBRA_ENABLE_MAIL_READ=true`，再用 `listFolders` 確認該帳號確實有 `view=appointment` 或 `view=task` 的資料夾。

**信件工具沒有出現在工具清單** — 同樣是 `ZIMBRA_ENABLE_MAIL_READ` 沒開；關閉時這些工具不會註冊，模型看不到。

---

## 相關連結

- 專案倉庫：[github.com/jasoncheng7115/jasontools-mcp](https://github.com/jasoncheng7115/jasontools-mcp)
- Zimbra SOAP API 文件：[files.zimbra.com/docs/soap_api](https://files.zimbra.com/docs/soap_api/)
- Model Context Protocol：[modelcontextprotocol.io](https://modelcontextprotocol.io)
