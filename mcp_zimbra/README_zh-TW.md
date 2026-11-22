# Zimbra MCP Server

**版本：** 1.12.0
**作者：** Jason Cheng (與 Claude Code 共同建置)
**授權：** MIT
**最後更新：** 2026-10-09
**儲存庫：** [github.com/jasoncheng7115/jasontools-mcp](https://github.com/jasoncheng7115/jasontools-mcp)
**語言：** [English](README.md) · [繁體中文](README_zh-TW.md)

以 FastMCP 為基礎的 Zimbra Collaboration Suite 整合工具，透過自然語言互動，提供完整的郵件系統監控與管理功能。

---

## 📋 目錄

- [功能特色](#-功能特色)
- [需求環境](#-需求環境)
- [安裝](#-安裝)
- [設定](#️-設定)
- [使用方式](#-使用方式)
- [可用工具](#️-可用工具)
- [測試](#-測試)
- [疑難排解](#-疑難排解)
- [版本紀錄](#-版本紀錄)
- [參與貢獻](#-參與貢獻)
- [授權](#-授權)

---

## ✨ 功能特色

### 核心功能

- **帳號管理**：查看資訊、配額、別名，解鎖帳號，列出／統計帳號
- **通訊群組**：查詢通訊群組 (DL) 資訊與成員清單
- **郵件佇列監控**：統計、列出郵件、搜尋
- **伺服器監控**：服務狀態、健康檢查、伺服器清冊
- **信箱統計**：儲存空間分析與使用量排名
- **系統健康**：完整的健康診斷與報告

### 主要特色

- 🔐 安全的 SOAP API 整合與認證
- ⚡ 智慧快取機制，TTL 可自訂
- 🔄 自動重試機制，採指數退避
- 📊 即時服務狀態監控
- 🛡️ 安全檢查 (例如 unlockAccount 只對已鎖定的帳號有作用)
- 🌐 支援多台伺服器
- 📝 詳細的記錄與除錯功能

---

## 🔐 認證模式

mcp_zimbra 支援兩種認證模式：

### 管理員模式 (44 個基本工具 + 8 個 mail_read 工具)

可完整使用所有 Zimbra 管理工具。信件讀取工具需要 `ZIMBRA_ENABLE_MAIL_READ=true`。

```bash
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="admin_password"
export ZIMBRA_ENABLE_MAIL_READ="true"   # Optional: enable mail read tools
```

### 使用者模式 (13 個基本工具 + 8 個 mail_read 工具)

只能存取個人信箱。透過網頁用戶端 API 以一般使用者身分認證。

```bash
export ZIMBRA_MAIL_URL="https://mail.example.com"
export ZIMBRA_USER_EMAIL="user@example.com"
export ZIMBRA_USER_PASS="user_password"
export ZIMBRA_ENABLE_MAIL_READ="true"   # Optional: enable mail read tools
```

### 功能開關：信件讀取

`ZIMBRA_ENABLE_MAIL_READ` 控制信箱類工具，包括信件、附件、行事曆與工作 (預設：`false`)。核心工具如下：

| 工具 | 說明 |
|------|-------------|
| `searchMail` | 依主旨／寄件者／收件者／日期／內容搜尋信箱 |
| `getMailDetail` | 取得完整郵件內容、標頭、附件清單 |
| `getConversation` | 取得對話串中的所有郵件 |
| `listFolders` | 列出信箱資料夾 |
| `getMailAttachment` | 以一次性下載連結 (HTTP)、base64 或存檔的方式取得附件；可依 part ID 或檔名樣式挑選 |

**使用者模式工具 (一律可用)：**
| 類別 | 工具 |
|----------|-------|
| 信件寫入 | saveDraft, searchContacts |
| 目錄 | searchGal |
| 追蹤 | 6 個 jt_zmmsgtrace 工具 (有設定時) |
| 系統 | health_check, clear_cache, cache_stats, getVersionInfo |

**Claude Desktop (使用者模式)：**
```json
{
  "mcpServers": {
    "zimbra_user": {
      "command": "python3",
      "args": ["/path/to/mcp_zimbra/mcp_zimbra.py"],
      "env": {
        "ZIMBRA_MAIL_URL": "https://mail.example.com",
        "ZIMBRA_USER_EMAIL": "user@example.com",
        "ZIMBRA_USER_PASS": "password"
      }
    }
  }
}
```

> **注意**：如果同時提供管理員與使用者的認證資訊，以管理員模式優先。

---

## 📦 需求環境

### 系統需求

- **Python**：3.8 以上
- **Zimbra**：8.x、9.x 或 10.x (已在 10.1.10 FOSS 測試)
- **網路**：可透過 HTTPS 存取 Zimbra Admin API (預設連接埠 7071)

### Python 相依套件

```bash
pip install mcp requests urllib3
```

或使用專案提供的 requirements 檔 (如果有的話)：
```bash
pip install -r requirements.txt
```

---

## 🚀 安裝

### 1. 複製或下載

```bash
cd /path/to/your/mcp/servers/
git clone <repository-url> mcp_zimbra
# or download and extract the files
```

### 2. 安裝相依套件

```bash
cd mcp_zimbra
pip install mcp requests urllib3
```

### 3. 設定環境變數

```bash
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="your_admin_password"
```

選用的環境變數：
```bash
export ZIMBRA_VERIFY_SSL=false          # Disable SSL verification (not recommended for production)
export ZIMBRA_CACHE_DURATION=300        # Cache TTL in seconds (default: 300)
export ZIMBRA_REQUEST_TIMEOUT=30        # API timeout in seconds (default: 30)
export ZIMBRA_RETRY_ATTEMPTS=3          # Retry attempts (default: 3)
```

選用的 jt_zmmsgtrace 整合 (用於信件追蹤)：
```bash
export JT_ZMMSGTRACE_URL="http://localhost"      # jt_zmmsgtrace base URL (default: http://localhost)
export JT_ZMMSGTRACE_PORT="8989"                 # jt_zmmsgtrace port (default: 8989)
export JT_ZMMSGTRACE_API_KEY="your-api-key"      # jt_zmmsgtrace API key (required for mail tracing)
```

**注意**：只有設定了 JT_ZMMSGTRACE_API_KEY，信件追蹤工具 (jt_zmmsgtrace_*) 才會出現。

### 4. 設定 Claude Desktop

加入 Claude Desktop 的 MCP 設定檔 (`claude_desktop_config.json`)：

```json
{
  "mcpServers": {
    "zimbra_mail1": {
      "command": "python3",
      "args": ["/path/to/mcp_zimbra/mcp_zimbra.py"],
      "env": {
        "ZIMBRA_ADMIN_URL": "https://mail.example.com:7071/service/admin/soap",
        "ZIMBRA_ADMIN_USER": "admin@example.com",
        "ZIMBRA_ADMIN_PASS": "your_admin_password",
        "ZIMBRA_VERIFY_SSL": "false",
        "JT_ZMMSGTRACE_URL": "http://localhost",
        "JT_ZMMSGTRACE_PORT": "8989",
        "JT_ZMMSGTRACE_API_KEY": "your-secure-api-key-here-change-me"
      }
    }
  }
}
```

**注意**：jt_zmmsgtrace 的設定是選用的。沒有設定時，信件追蹤工具不會出現，但其他 Zimbra 工具都能正常運作。

**重要**：修改設定後請重新啟動 Claude Desktop。

---

## ⚙️ 設定

### 設定優先順序

伺服器依下列優先順序套用設定：

1. **命令列參數** (優先順序最高)
2. **環境變數**
3. **預設值** (優先順序最低)

### 設定選項

#### Zimbra 設定 (必填)

| 參數 | 環境變數 | 預設值 | 說明 |
|-----------|---------------------|---------|-------------|
| 管理 URL | `ZIMBRA_ADMIN_URL` | 必填 | Zimbra Admin SOAP API 端點 |
| 管理員帳號 | `ZIMBRA_ADMIN_USER` | 必填 | 管理員帳號的使用者名稱 |
| 管理員密碼 | `ZIMBRA_ADMIN_PASS` | 必填 | 管理員帳號的密碼 |
| SSL 驗證 | `ZIMBRA_VERIFY_SSL` | `true` | 啟用／停用 SSL 憑證驗證 |
| 快取存續時間 | `ZIMBRA_CACHE_DURATION` | `300` | 快取 TTL，單位為秒 |
| 請求逾時 | `ZIMBRA_REQUEST_TIMEOUT` | `30` | API 請求逾時，單位為秒 |
| 重試次數 | `ZIMBRA_RETRY_ATTEMPTS` | `3` | 請求失敗時的重試次數 |

#### jt_zmmsgtrace 設定 (選用，用於信件追蹤)

| 參數 | 環境變數 | 預設值 | 說明 |
|-----------|---------------------|---------|-------------|
| 基礎 URL | `JT_ZMMSGTRACE_URL` | `http://localhost` | jt_zmmsgtrace 服務的基礎 URL |
| 連接埠 | `JT_ZMMSGTRACE_PORT` | `8989` | jt_zmmsgtrace 服務的連接埠 |
| API 金鑰 | `JT_ZMMSGTRACE_API_KEY` | (無) | 認證用的 API 金鑰 (信件追蹤必填) |

**注意**：如果沒有設定 `JT_ZMMSGTRACE_API_KEY`，6 個信件追蹤工具不會出現，但其他 Zimbra 工具都能正常運作。

---

## 💻 使用方式

### 透過 Claude Desktop

設定完成後，就可以用自然語言操作 Zimbra：

```
請查詢 user@example.com 的帳號資訊
請查看 mail.example.com 伺服器的健康狀況
請解鎖 locked_user@example.com 帳號
請列出所有郵件佇列中的訊息
```

設定 `ZIMBRA_ENABLE_MAIL_READ=true` 後，信件、行事曆與工作也能使用：

```
請找 user@example.com 信箱裡主旨含「報價」、2026-01-01 之後的信，列 20 筆
user@example.com 這週有哪些會議？
user@example.com 下週三下午有空嗎？
「Ceph 建置」那場會議有誰參加？他們回覆了嗎？
user@example.com 的待辦事項裡，還沒完成、且今年到期的有哪些？
```

每個信件、行事曆與工作類工具都要明確帶入 `account` 參數。在管理員模式下，伺服器是透過管理員委派存取信箱，因此沒有「我的信箱」這個概念，也不會自行猜測。

### 直接從命令列執行 (測試用)

```bash
cd /path/to/mcp_zimbra
python3 mcp_zimbra.py
```

### SSE 模式

以 SSE 伺服器執行，供 Chatbox 或舊版 MCP 用戶端使用：

```bash
python3 mcp_zimbra.py --transport sse --host 0.0.0.0 --port 8010 --api-key "your-api-key"
```

端點 (同一個連接埠)：
- `http://<host>:<port>/sse`：傳統 SSE，給只支援 SSE 的用戶端
- `http://<host>:<port>/mcp`：Streamable HTTP (v1.10.1 起)。用戶端有支援的話**優先使用這個**
  (Claude Code：`"type": "http"`)。SSE 用戶端在連線中斷 (筆電睡眠、網路短暫中斷) 後自動重新連線時，
  會拿到新的工作階段卻沒有重送 `initialize`，之後每個呼叫都會失敗並回傳 `-32602 Invalid request
  parameters`。這裡的 Streamable HTTP 是無狀態的，所以沒有工作階段會遺失。

### Streamable HTTP 模式

以 HTTP 伺服器執行，供新版 MCP 用戶端使用：

```bash
python3 mcp_zimbra.py --transport streamable-http --host 0.0.0.0 --port 8000 --api-key "your-api-key"
```

端點：`http://<host>:<port>/mcp` (無狀態，請求之間不保留工作階段)

| 參數 | 預設值 | 說明 |
|-----------|---------|-------------|
| `--transport` | `stdio` | `stdio`、`sse` 或 `streamable-http` |
| `--host` | `127.0.0.1` | HTTP 監聽位址 (sse／streamable-http) |
| `--port` | `8000` | HTTP 監聽連接埠 (sse／streamable-http) |
| `--api-key`, `-k` | *(無)* | SSE／HTTP 認證用的 API 金鑰 (或使用 `MCP_API_KEY` 環境變數) |

---

## 🛠️ 可用工具

### 帳號管理 (6 個工具)

| 工具 | 說明 |
|------|-------------|
| `getAccountInfo` | 取得帳號資訊 (配額、狀態、建立日期等)，並附 `login_state`：帳號能否登入，以及不能登入的原因 |
| `getAccountQuota` | 取得帳號配額與使用量統計 |
| `getAccountAliases` | 取得帳號的所有別名 |
| `unlockAccount` | 解鎖被鎖定的帳號 (只對已鎖定的帳號有作用) |
| `getAllAccounts` | 列出所有帳號，支援篩選與分頁 |
| `getAccountCount` | 依網域或狀態統計帳號數 |

### 通訊群組 (3 個工具)

| 工具 | 說明 |
|------|-------------|
| `getDLInfo` | 取得通訊群組資訊 |
| `getDLMembers` | 取得通訊群組成員，支援分頁 |
| `getAllDistributionLists` | 列出所有通訊群組，支援網域篩選與分頁 |

### 郵件佇列 (3 個工具)

| 工具 | 說明 |
|------|-------------|
| `getQueueStat` | 依伺服器取得郵件佇列統計 |
| `getQueueList` | 列出郵件佇列中的郵件 |
| `searchMailQueue` | 依寄件者或收件者搜尋郵件佇列 |

### 統計 (2 個工具)

| 工具 | 說明 |
|------|-------------|
| `getMailboxStats` | 取得所有伺服器的信箱統計 |
| `getQuotaUsage` | **⚡ 快速**：取得帳號配額使用量並排序 (單次 API 呼叫) |

### 系統與網域 (9 個工具)

| 工具 | 說明 |
|------|-------------|
| `getServerList` | 取得所有 Zimbra 伺服器清單 |
| `getServerStatus` | 取得伺服器的即時服務狀態 |
| `getActiveSessions` | **⚡ 新增**：取得目前登入中的使用者 (SOAP／IMAP／管理工作階段) |
| `getDomainList` | 取得所有郵件網域清單 |
| `getDomainInfo` | 取得網域詳細資訊 |
| `getCOSList` | 取得服務等級 (Class of Service) 定義清單 |
| `getCOSInfo` | 取得 COS 詳細資訊，支援以正規表示式篩選屬性與分頁 |
| `countAccountByCOS` | **⚡ 新增**：依 COS 統計帳號數 |
| `getVersionInfo` | **⚡ 新增**：查詢 Zimbra 版本資訊 |

### 權限 (3 個工具)

| 工具 | 說明 |
|------|-------------|
| `getGrants` | **⚡ 新增**：查詢授予某個實體或由某個實體授予的權限 |
| `checkRight` | **⚡ 新增**：檢查受權者對某個目標是否具有指定權限 |
| `getDelegates` | **⚡ 新增**：查詢帳號的委派設定 |

### 批次稽核 (5 個工具)

| 工具 | 說明 |
|------|-------------|
| `getAllDelegations` | 一次列出所有 sendAs／sendOnBehalfOf 委派權限 |
| `getAllForwardings` | 列出所有設定郵件轉寄規則的帳號 |
| `getAllOutOfOffice` | 列出所有啟用外出自動回覆的帳號 |
| `getInactiveAccounts` | 列出閒置 N 天以上的帳號 |
| `searchByAttribute` | 以通用 LDAP 篩選條件搜尋任意屬性 |

### 信件搜尋 (10 個工具)

| 工具 | 說明 |
|------|-------------|
| `searchMail` | 依主旨 (單一字詞也能比對到較長字串的中間)／寄件者／收件者／內文／日期／`since` (精確到秒)／附件檔名搜尋；可指定資料夾並選擇是否包含子資料夾；每筆結果附 folder_path 與 snippet |
| `getMailDetail` | 完整郵件：標頭、純文字內文 (HTML 會轉換)、去除引用歷史的 `body_latest`、選用的 HTML、附件清單 |
| `getMailDetails` | **⚡ 新增**：一次最多讀取 50 封郵件 |
| `getConversation` | 對話串中的所有郵件，並附 `reply_state`：誰最後回覆，以及是否在等我回覆 (別名也算我) |
| `getMailAttachment` | **⚡ 更新**：以一次性下載連結 (HTTP 傳輸模式，10 分鐘內有效，用 curl 下載)、base64 (≤10 MB) 或存檔的方式取得附件；可用 `filename_pattern` (例如 `*-A4.pdf`) 取代 part ID；可用 `filename` 重新命名 |
| `getAttachmentText` | **⚡ 新增**：擷取 PDF (文字層，掃描檔則以 `chi_tra+eng` 進行 OCR)、圖片 (OCR) 或文字附件的文字 |
| `waitForMail` | **⚡ 新增**：等待指定寄件者／主旨的郵件送達 (輪詢，最長 10 分鐘) |
| `listFolders` | 列出信箱資料夾，可用關鍵字篩選 |
| `saveDraft` | 將新郵件或回覆／轉寄存成草稿供檢查 (不會寄出任何郵件)；附件可用 base64 提供，或取自其他郵件 |
| `searchContacts` | 搜尋使用者的個人通訊錄／聯絡人 |

### 行事曆與工作 (6 個工具)

| 工具 | 說明 |
|------|-------------|
| `searchCalendar` | **⚡ 新增**：查詢日期範圍內的約會，可查所有行事曆或單一資料夾；會展開週期性事件 |
| `getAppointment` | **⚡ 新增**：取得單一約會的完整內容：描述、參與者與回覆狀態、週期規則、附件 |
| `searchTasks` | **⚡ 新增**：依資料夾、狀態與到期日篩選 Zimbra 工作 (Tasks) |
| `createAppointment` | **⚡ 新增**：建立個人約會：主旨、開始／結束時間、地點、備註、行事曆、全天、提醒 |
| `updateAppointment` | **⚡ 新增**：修改個人約會的主旨、時間、地點、備註或提醒；支援 `dry_run` |
| `deleteAppointment` | **⚡ 新增**：刪除個人約會 (需 `confirm=true`，否則只會預覽) |

行事曆寫入預設只動主要的 `Calendar`。要修改或刪除其他行事曆 (共用或家人的行事曆) 中的約會，
需要 `allow_other_calendar=true`；有參與者的約會一律拒絕，因為修改會寄信通知參與者。
行事曆與草稿的寫入都會記錄在 `ZIMBRA_AUDIT_LOG`
(預設為 `~/.local/state/mcp_zimbra/audit.jsonl`)。

`getAttachmentText` 需要伺服器上有 `pdftotext`／`pdfinfo` (poppler-utils)，OCR 則需要
`tesseract` 與 `chi_tra` 語言資料 (`apt install poppler-utils tesseract-ocr
tesseract-ocr-chi-tra`)。

約會與工作屬於行事曆項目而非郵件，所以 `searchMail` 永遠找不到它們。行事曆與工作類工具
對同一套管理員委派的郵件 API 使用 `types="appointment"`／`types="task"`，並同樣受
`ZIMBRA_ENABLE_MAIL_READ` 旗標控制。

`searchCalendar` 的 `date_from`／`date_to` 是以 SOAP 屬性送出，因此會與 `query` 一起
生效。自 v1.11.0 起，`searchMail` 也會將 `query` 與其他所有篩選條件 (寄件者、日期、資料夾等)
合併，而不是讓 `query` 取代它們。

`createAppointment` 建立的約會沒有參與者，因此不會寄出任何邀請。時間以 `timezone`
(預設 `Asia/Taipei`) 的當地時間解讀。如果同一個行事曆已經有相同主旨、相同開始時間的約會，
會回傳該筆約會並附 `status: "exists"`，而不是再建立一筆，所以重試呼叫是安全的；
確定要建立時請帶 `allow_duplicate=true`。建立結果會用 `getAppointment` 讀回。

### 目錄與搜尋 (1 個工具)

| 工具 | 說明 |
|------|-------------|
| `searchGal` | 搜尋全域通訊錄 (GAL) |

### 進階通訊群組功能 (1 個工具)

| 工具 | 說明 |
|------|-------------|
| `getDLMembership` | **⚡ 新增**：查詢帳號或通訊群組隸屬於哪些通訊群組 (含巢狀關係) |

### 信件追蹤 (6 個工具)

只有設定了 `JT_ZMMSGTRACE_API_KEY` 才會註冊。這些工具查詢的是獨立的
jt_zmmsgtrace 服務，而不是 Zimbra 的 SOAP API。

| 工具 | 說明 |
|------|-------------|
| `jt_zmmsgtrace_search` | 在郵件追蹤記錄中自由搜尋 |
| `jt_zmmsgtrace_search_by_sender` | 追蹤某寄件者寄出的郵件 |
| `jt_zmmsgtrace_search_by_recipient` | 追蹤寄給某收件者的郵件 |
| `jt_zmmsgtrace_search_by_message_id` | 依 Message-ID 追蹤單封郵件 |
| `jt_zmmsgtrace_search_by_host` | 追蹤經由指定主機處理的郵件 |
| `jt_zmmsgtrace_search_by_time` | 追蹤某個時間區間內的郵件 |

### 公用工具 (3 個工具)

| 工具 | 說明 |
|------|-------------|
| `health_check` | 完整的系統健康診斷 |
| `clear_cache` | 清除所有快取的 API 回應 |
| `cache_stats` | 取得快取使用統計 |

**合計：管理員模式 52 個工具** (44 個基本 + 8 個 mail_read)：6 個帳號 + 3 個通訊群組 + 3 個郵件佇列 + 2 個統計 + 9 個系統 + 3 個權限 + 5 個批次稽核 + 5 個信件讀取† + 3 個行事曆與工作† + 2 個信件寫入 + 1 個目錄 + 1 個進階通訊群組 + 3 個公用工具 + 6 個 jt_zmmsgtrace
**合計：使用者模式 21 個工具** (13 個基本 + 8 個 mail_read)：5 個信件讀取† + 3 個行事曆與工作† + 2 個信件寫入 + 1 個目錄 + 3 個公用工具 + 1 個版本 + 6 個 jt_zmmsgtrace

†信件讀取工具需要 `ZIMBRA_ENABLE_MAIL_READ=true`

---

## 🧪 測試

### 快速健康檢查

```bash
cd /path/to/mcp_zimbra

# Set environment variables
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="your_password"

# Run status test
python3 quick_test_status.py
```

**預期輸出：**
```
✅ mailbox        : running
✅ mta            : running
✅ ldap           : running
❌ imapd          : stopped
...
Summary: X running, Y stopped, 0 unknown
✅ Status looks correct!
```

### 測試 unlockAccount 功能

```bash
python3 test_unlock_account.py user@example.com
```

### 用範例測試

```bash
python3 examples_unlock_account.py
```

---

## 🔧 疑難排解

### 常見問題

#### 帳號明明正常，卻被回報為已鎖定

`zimbraPasswordLocked: TRUE` **不會**鎖定帳號，只代表使用者不能自行變更密碼 (必須由
管理員變更)。帳號是否鎖定，只由 `zimbraAccountStatus` 決定：

| zimbraAccountStatus | 意義 |
|---|---|
| `active` | 正常，可以登入 |
| `locked` | 由管理員鎖定 |
| `lockout` | 密碼錯誤次數過多而被自動鎖定；`zimbraPasswordLockoutLockedTime` 記錄鎖定時間 |
| `maintenance` / `pending` / `closed` | 無法登入 |

自 v1.11.1 起，`getAccountInfo` 會回傳已經判讀好的 `login_state` 區塊
(`can_login`、`locked_reason`、`auto_unlock_at`、`user_can_change_password`)，
模型不必再自行解讀原始屬性。

#### 1. 認證失敗

**錯誤：** `No authToken in response`

**解決方式：**
- 確認 `ZIMBRA_ADMIN_USER` 與 `ZIMBRA_ADMIN_PASS` 正確
- 確認管理員帳號具有 API 存取權限
- 檢查管理 URL 是否正確 (應包含連接埠 7071)

#### 2. SSL 憑證錯誤

**錯誤：** `SSLError: certificate verify failed`

**解決方式：**
```bash
export ZIMBRA_VERIFY_SSL=false
```

**注意：** 只在測試環境停用 SSL 驗證。

#### 3. 伺服器狀態為空

**錯誤：** `total_servers: 0` 或 services 陣列為空

**解決方式：**
- 先執行 `getServerList()` 確認伺服器可以存取
- 檢查管理員帳號是否有查詢服務狀態的權限
- 確認 Zimbra 版本相容 (支援 8.x、9.x、10.x)

#### 4. 連線逾時

**錯誤：** `Request timeout`

**解決方式：**
- 加長逾時時間：`export ZIMBRA_REQUEST_TIMEOUT=60`
- 檢查到 Zimbra 伺服器的網路連線
- 確認防火牆規則允許存取連接埠 7071

### 除錯模式

啟用除錯記錄：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

或設定環境變數：
```bash
export ZIMBRA_LOG_LEVEL=DEBUG
```

---

## 📜 版本紀錄

### v1.12.0 (2026-10-09) - 目前版本

**新功能：附件、文字擷取、搜尋、讀信、行事曆編輯**

- 附件：HTTP 傳輸模式改提供一次性下載連結 (之前存在伺服器上的檔案會落在服務私有的 /tmp，
  用戶端拿不到)，另支援 base64、重新命名，以及依檔名樣式挑選。`getAttachmentText` 可讀取 PDF 文字，或對掃描檔進行 OCR。
- `searchMail`：新增 `include_subfolders`、`attachment_name`、`since`、`include_attachment_names`，
  每筆結果附 `folder_path` 與 `snippet`；單一字詞的主旨可比對到較長字串的中間
  (之前 `DC2026167` 找不到 `採購單-DC2026167-02`)。
- `getMailDetail` 會讀取 HTML 內文：之前只有 HTML 的郵件會回傳空白內文。
  新增 `body_text`、`body_latest` (去除引用歷史)、`include_html`；`msg_id` 也接受
  `message_id`。新增 `getMailDetails` (批次) 與 `waitForMail`。
- `getConversation` 會回報誰最後回覆 (`reply_state`)。
- 新增 `updateAppointment`、`deleteAppointment`，並套用上述的行事曆防護。
- `saveDraft` 支援附件。修正：回覆時引用的原信是空的，因為引用內容是從
  `getMailDetail` 沒有回傳的欄位組出來的。
- 工具結果改為純 JSON 文字，不再是 `{"result": "<json string>"}`。

### v1.11.1 (2026-10-06)

**修正：正常帳號被回報為已鎖定**

模型讀取 `getAccountInfo` 時看到 `zimbraPasswordLocked: TRUE`，就判定帳號已鎖定，
但 `zimbraAccountStatus` 其實是 `active`。這個屬性只會阻止使用者自行變更密碼。
`getAccountInfo` 現在會回傳只依 `zimbraAccountStatus` 推導的 `login_state`：`can_login`、`meaning`、
`locked_reason` (管理員鎖定或密碼錯誤自動鎖定)、自動鎖定時的 `locked_since` 與
`auto_unlock_at`、`user_can_change_password`、
`must_change_password_at_next_login`，以及如何解讀這些屬性的說明。

### v1.11.0 (2026-10-02)

**新功能：createAppointment；修正：searchMail 的 `query` 會使其他篩選條件失效**

- `createAppointment`：建立個人約會，可設定主旨、開始／結束時間、地點、備註、
  行事曆 (模糊比對名稱，須恰好符合一個)、全天與提醒。沒有參與者，所以不會寄任何東西
  給任何人。同一行事曆中以主旨＋開始時間防止重複建立。與其他行事曆工具一樣受
  `ZIMBRA_ENABLE_MAIL_READ` 控制。
- `searchMail`：之前傳入 `query` 會取代其他所有篩選條件，因此 `query` 加上
  `sender`／`date_from`／`folder` 時，會在沒有提示的情況下忽略後者，結果看起來
  像沒有篩選。現在 `query` 會以 AND 與其他篩選條件合併。

### v1.10.1 (2026-09-29)

**修正：SSE 用戶端卡在未初始化的工作階段**

每個工具呼叫 (連 `health_check` 也是) 都回傳 `-32602 Invalid request parameters`，
伺服器記錄則顯示 `Received request before initialization was complete`。用戶端的
SSE 連線在筆電睡眠時中斷；喚醒後 EventSource 重新連線並拿到新的 `session_id`，
卻沒有重送 `initialize`。

- `--transport sse` 現在也會在同一個連接埠的 `/mcp` 提供 Streamable HTTP。既有的
  `/sse` 用戶端照常運作；支援 Streamable HTTP 的用戶端應改用 `/mcp`。
- Streamable HTTP 以無狀態模式執行 (`stateless_http=True`)：伺服器端沒有工作階段
  會遺失，所以睡眠／喚醒與伺服器重新啟動都不會再讓用戶端失效。
- API 金鑰檢查改寫為單純的 ASGI 中介軟體，並使用固定時間比對。
  之前的 `BaseHTTPMiddleware` 每次 SSE 連線關閉時都會記錄一段 `AssertionError` 追蹤資訊。

### v1.10.0 (2026-09-04)

**新功能：行事曆與工作讀取**

約會與工作存放在郵件儲存區之外，所以即使 `listFolders` 列得出這些資料夾，
`searchMail` 也永遠找不到它們。三個新工具補上這個缺口：

- **`searchCalendar`**：查詢日期範圍內的約會，可查所有行事曆或單一資料夾。
  週期性事件會透過 `calExpandInstStart`／`calExpandInstEnd` 展開，
  因此每筆結果回報的都是確實落在查詢區間內的發生時間。
  選用的 `include_attendees` 會取得完整參與者清單，但上限為 20 筆結果，
  因為每個約會都要多發一次請求。
- **`getAppointment`**：取得單一約會的完整內容：描述內文、每位參與者及其
  回覆狀態、週期規則、附件。
- **`searchTasks`**：Zimbra 工作 (Tasks)，可依資料夾、狀態與到期日篩選。

注意事項：

- `date_from`／`date_to` 是以 SOAP 屬性送出，不會併入查詢字串，
  因此可以和呼叫端提供的 `query` 並存。這刻意與 `searchMail` 不同；在 `searchMail` 中，
  傳入 `query` 會使日期參數被忽略。
- 以空白查詢搜尋約會或工作時，Zimbra 什麼都不會回傳，並不代表「所有項目」。
  因此「所有行事曆」會展開為依帳號資料夾建立的明確 `inid:` 清單。
- 工作的狀態與到期日篩選在用戶端進行；Zimbra 的工作搜尋對這兩者都沒有
  可靠的伺服器端運算子，而工作資料夾通常夠小，先取回再篩選的成本仍然很低。
- 參與者的回覆狀態優先取自 `<replies>`，沒有時退回使用
  `<at ptst>`。兩個工具共用這套邏輯，所以同一場會議不會回報兩種
  不同的答案。
- 參數命名沿用 `getMailDetail` 的 `msg_id` 風格：`appt_id`。

### v1.9.3 (2026-08-31)
**修正**：`searchMail` 的日期篩選會在沒有提示的情況下回傳零筆結果
- `date_from`／`date_to` 只會解析 `YYYY/MM/DD`；其他格式 (特別是 ISO
  `2026-01-01`) 會原封不動傳給 Zimbra，產生什麼都比對不到的查詢，
  而且**不會引發任何錯誤**，看起來就像「沒有這封信」
- 新的 `_parse_search_date()` 接受 `YYYY-MM-DD`、`YYYY/MM/DD`、`MM/DD/YYYY`、`YYYYMMDD`
- 無法解析的日期現在會回傳明確的錯誤，而不是空的結果
- 注意：`sender`／`from:` **只比對電子郵件位址**，不比對顯示名稱；
  搜尋中文人名或公司名請用 `query` 做全文搜尋

### v1.9.2 (2026-03-02)
**最佳化**：相容能力較弱的 LLM
- **新輔助函式**：`tool_response()`，輸出精簡的 JSON 並注入 `usage_hint`
- 所有 `json.dumps` 呼叫改用 `tool_response()` (移除 `indent=2`，約省下 30% token)
- `USAGE_HINTS` 字典：為能力較弱的模型提供每個工具一行的使用指引 (50 個以上工具)
- `getServerStatus`：**新參數** `summary` (預設：true)，精簡輸出，只列出有問題的服務
- `getConversation`：**新參數** `limit` (預設：25)，截斷過長的對話串，保留最新的郵件
- `health_check`：以 `stopped_service_names` 清單取代完整的 services 陣列

### v1.9.1 (2026-02-26)
**修正**：SSE／streamable-http 傳輸修正
- 停用 DNS rebinding 保護 (修正外部用戶端遇到的 421 Misdirected Request)
- 直接使用 uvicorn 綁定 host／port (FastMCP.run() 的限制)
- 為 SSE／HTTP 傳輸加入 API 金鑰認證 (`--api-key`／`MCP_API_KEY`)

### v1.9.0 (2026-02-26)
**強化**：`searchByAttribute` 新增 extra_attrs 參數
- 新參數 `extra_attrs`：以逗號分隔的屬性名稱，會在預設欄位之外一併回傳
- 節省 token：只回傳要求的額外屬性 (例如 `zimbraNotes,description`)

### v1.8.9 (2026-02-13)
**錯誤修正**：透過分頁正確統計帳號數
- `getAccountCount`：修正未定義變數造成的當機與錯誤的統計數字 (Zimbra 不會回傳 `searchTotal`；現在改用分頁逐筆計數)
- `countAccountByCOS`：同樣的修正，改用分頁計數而不是 `limit=1` (之前所有 COS 都回傳 0)

### v1.8.8 (2026-02-13)
**最佳化**：伺服器端篩選全面檢查
- `countAccountByCOS`：改寫為每個 COS 各用一次 LDAP 查詢 (之前會取回所有帳號，浪費 5-50MB)
- `getAllAccounts`：`status_filter` 改為伺服器端 LDAP 查詢 (之前在用戶端篩選，分頁不準確)

### v1.8.7 (2026-02-13)
**強化**：`getAccountCount` 改為伺服器端篩選
- 改寫為使用 `SearchDirectoryRequest` 搭配 LDAP 篩選條件 (之前在用戶端逐筆處理)
- **新參數**：`query`，任意 LDAP 篩選條件 (例如 `(zimbraMailHost=mail1.example.com)`)
- `status_filter` 與 `query` 會自動以 AND 合併
- 只回傳數量，大幅減少 token 用量

### v1.8.6 (2026-02-13)
**新功能**：新增 SSE 傳輸支援
- `--transport` 現在接受 `stdio`、`sse`、`streamable-http`
- SSE 傳輸供舊版 MCP 用戶端使用，底層是 mcp SDK 1.22.0 原生的 `run_sse_async()`

### v1.8.5 (2026-02-13)
**新功能**：信件讀取工具改由 `ZIMBRA_ENABLE_MAIL_READ` 開關控制
- `searchMail`、`getMailDetail`、`getConversation`、`listFolders`、`getMailAttachment` 只在 `ZIMBRA_ENABLE_MAIL_READ=true` 時註冊 (預設：`false`)
- 可在重視安全性的環境中部署不具讀信能力的版本
- 工具數：管理員 44+8／使用者 13+8 (基本 + mail_read)

### v1.8.4 (2026-02-13)
**穩健性**：加入輸入驗證防護，提升與能力較弱 LLM 的相容性
- 所有 `msg_id`／`conversation_id` 參數在呼叫 SOAP 前先驗證；空值會回傳附使用範例的明確錯誤
- `searchMail` 回應包含 `usage_hint` 欄位，說明如何使用結果中的 ID
- Docstring 中的 ID 範例改為實際的格式 (原為 `"12345"`，現為 `"894727"`)
- 避免能力較弱的模型 (例如 gpt-oss:120b) 送出空參數

### v1.8.3 (2026-02-12)
**強化**：saveDraft 在回覆／轉寄時自動引用原信
- 回覆草稿會自動附上「On {date}, {from} wrote:」與 `> ` 引用的原信內文
- 轉寄草稿會自動附上「Forwarded message」標頭與原信內文
- LLM 只需提供回覆內容，原信引用會自動處理
- 回應包含 `note` 欄位，告知 LLM 已完成引用

### v1.8.2 (2026-02-12)
**修正**：JSON 輸出的中日韓 (CJK) 字元改為可讀文字
- **修正**：全域設定 `ensure_ascii=False`，CJK 字元以可讀文字輸出，而不是 `\uXXXX` 跳脫序列
- 避免 LLM 誤讀字形相近的中文字 (例如 諾→誠、殷→般)

### v1.8.1 (2026-02-12)
**錯誤修正**：searchMail 的日期範圍不含邊界 (差一天)
- **修正**：`date_from`／`date_to` 現在確實包含邊界；Zimbra 的 `after:`／`before:` 邊界會自動調整
- 查詢「今天的信」現在會回傳正確結果

### v1.8.0 (2026-02-11)
**雙認證模式**：支援管理員＋使用者模式
- **新增**：透過 `urn:zimbraAccount` 進行使用者模式認證 (一般使用者帳密)
- **新設定**：使用者模式用的 `ZIMBRA_USER_EMAIL`、`ZIMBRA_USER_PASS`
- **新增**：條件式工具註冊，使用者模式下隱藏僅限管理員的工具
- **新增**：使用者模式最多提供 18 個存取個人信箱的工具
- **不變**：管理員模式維持最多 49 個工具，程式路徑完全沒有變動
- 使用者模式工具：searchMail、getMailDetail、getConversation、getMailAttachment、listFolders、saveDraft、searchContacts、searchGal、health_check、clear_cache、cache_stats、getVersionInfo，以及 6 個 jt_zmmsgtrace 工具

### v1.7.0 (2026-02-11)
**信件、聯絡人、草稿與資料夾**：完整的信箱搜尋、聯絡人、草稿撰寫與資料夾管理
- **新類別**：信件與聯絡人 (7 個工具)
  - `searchMail()`：依主旨／寄件者／收件者／內文／日期搜尋信箱 (資料夾模糊比對)
  - `getMailDetail()`：取得含內文、標頭、附件的完整郵件
  - `getConversation()`：取得對話串中的所有郵件
  - `getMailAttachment()`：透過 REST 將附件下載為本機檔案
  - `listFolders()`：列出信箱資料夾，可用關鍵字篩選
  - `saveDraft()`：將新郵件或回覆／轉寄存成草稿供檢查
  - `searchContacts()`：搜尋使用者的個人通訊錄／聯絡人
- **新輔助函式**：`query_zimbra_mail_api()`，以管理員委派方式發送 mail 命名空間的 SOAP 請求
- **新設定**：`ZIMBRA_MAIL_URL`，供 REST 操作 (附件下載) 使用的網頁用戶端 URL
- 工具總數：49

### v1.6.0 (2026-02-09)
**批次稽核工具**：以 LDAP 為基礎、單次呼叫的稽核查詢
- **新類別**：批次稽核 (5 個工具)
  - `getAllDelegations()`：列出所有 sendAs／sendOnBehalfOf 權限
  - `getAllForwardings()`：列出所有郵件轉寄規則
  - `getAllOutOfOffice()`：列出所有啟用自動回覆的帳號
  - `getInactiveAccounts()`：列出閒置 N 天以上的帳號
  - `searchByAttribute()`：通用 LDAP 篩選條件搜尋
- **修正**：`getGrants()` 未指定 target_name 時，不再送出無效的 `<target>` 元素
- 工具總數：42

### v1.5.0 (2026-02-09)
**相容性與傳輸**：相容 gpt-oss:120b＋支援 Streamable HTTP
- **新增**：Streamable HTTP 傳輸模式 (`--transport streamable-http`)
- **移除**：`getTopMailboxesBySize()` (已淘汰，請改用 `getQuotaUsage()`)
- **修正**：`getAccountQuota()` 現在以 UUID 呼叫 GetMailboxRequest (之前會出現 500 錯誤)
- **修正**：`unlockAccount()` 會重新查詢，並同時處理「locked」與「lockout」兩種狀態
- **修正**：`getQueueList()`／`searchMailQueue()` 的寄件者欄位改用完整位址 (之前只有網域)
- **修正**：未指定 queue_name 時，`searchMailQueue()` 會搜尋全部 5 個佇列
- **修正**：`getGrants()` 的預設 target_type 改為「account」
- **更名**：5 個工具的 `max_results` → `limit`，統一參數命名
- **改寫**：全部 37 個工具的 docstring 改用正確的 `Args: param_name:` 格式，提升與 LLM 的相容性
- 工具總數：37

### v1.4.0 (2025-11-28)
**重大版本**：新增 12 個進階查詢與監控工具
- **新類別**：權限 (3 個工具)
  - `getGrants()`：查詢授予某個實體或由某個實體授予的權限
  - `checkRight()`：檢查受權者對某個目標是否具有指定權限
  - `getDelegates()`：查詢帳號的委派設定
- **新類別**：目錄與搜尋 (1 個工具)
  - `searchGal()`：透過 SearchDirectory API 搜尋全域通訊錄
- **新類別**：COS 統計 (1 個工具)
  - `countAccountByCOS()`：依 COS 統計帳號數
- **新類別**：進階通訊群組 (1 個工具)
  - `getDLMembership()`：查詢帳號或通訊群組隸屬於哪些通訊群組 (含巢狀關係)
- **新類別**：系統資訊 (1 個工具)
  - `getVersionInfo()`：查詢 Zimbra 版本資訊
- **錯誤修正**：
  - 修正 `searchGal()` 改用 SearchDirectory API (更可靠)
  - 修正 `getGrants()` 的解析，支援多種 XML 格式與屬性名稱
  - `searchGal()` 加入分頁資訊
- **移除**：`getAllLocales()`、`getAllTimezones()`、`searchAutoProvDirectory()`、`getLicenseInfo()`、`verifyCertKey()`、`getCert()`、`getCSR()` (不常用，或僅限 Network Edition)
- **工具總數從 31 個增加到 38 個** (增加 23%！)
- 適用情境：安全稽核、權限管理、GAL 搜尋、系統清查

### v1.3.1 (2025-11-28)
**強化**：getCOSInfo() 加入分頁支援
- **新參數**：屬性分頁用的 `limit` 與 `offset`
- 避免查詢所有 COS 屬性時超出上下文長度
- 範例：`getCOSInfo("default", attr_filter=".*", limit=50)` 會回傳前 50 個屬性
- 回傳 `matched_attributes` (篩選後) 與 `returned_attributes` (分頁後)
- 加入顯示分頁狀態的 `display_message` (例如「顯示前 50 筆（共 498 筆，還有 448 筆未顯示）」)
- 屬性依字母排序，確保分頁結果一致
- 適合瀏覽大量屬性，又不會塞爆上下文

### v1.3.0 (2025-11-27)
**新功能**：新增 getActiveSessions()，即時監控工作階段
- **新工具**：`getActiveSessions()`，查詢目前登入中的使用者
- 顯示 SOAP (網頁用戶端)、IMAP、POP3 與管理工作階段
- **快速模式**：只取得工作階段數量 (摘要)
- **詳細模式**：列出所有使用中的使用者及其工作階段詳細資訊
- 即時資料 (不使用快取)，監控更準確
- 適用情境：「誰現在正在登入？」、「有多少人正在使用？」
- 工具總數從 31 個增加到 32 個

### v1.2.6 (2025-11-27)
**使用體驗改善**：所有分頁函式加入 display_message
- **新增**：`create_pagination_message()` 輔助函式
- 所有分頁函式現在會顯示清楚的訊息，例如：
  - 「顯示 10 筆（共 10 筆，已全部顯示）」
  - 「顯示前 100 筆（共 250 筆，還有 150 筆未顯示）」
- **更新的函式**：getAllAccounts、getAllDistributionLists、getDLMembers、getQuotaUsage
- **額外修正**：getAllDistributionLists 也有同樣的「more」錯誤，現已修正！
- 使用者不再搞不清楚是否已看到全部結果

### v1.2.5 (2025-11-27)
**錯誤修正**：修正 getAccountCount() 回傳錯誤數量 (嚴重)
- **錯誤**：實際有 10 個帳號，`getAccountCount()` 卻顯示 1 個
- **根本原因**：`getAllAccounts()` 把「more」(布林值) 當成數量使用！
- **修正**：getAllAccounts 現在會正確解析 searchTotal 屬性
- **強化**：getAccountCount 現在以完整逐筆處理作為備援，確保準確

### v1.2.4 (2025-11-27)
**安全性**：getCOSInfo() 強化為預設安全的行為
- **不帶篩選條件**：只回傳約 30 個常用屬性 (避免超出上下文長度)
- **帶篩選條件**：回傳篩選後的屬性 (針對性查詢)
- 使用 `attr_filter=".*"` 取得所有屬性 (會附警告)
- 回應中附上常用篩選規則的建議
- 預設安全，不會再意外超出上下文長度！

### v1.2.3 (2025-11-27)
**新工具**：新增具屬性篩選功能的 getCOSInfo()
- 依名稱查詢特定 COS，並以正規表示式篩選屬性
- 解決查詢 COS 設定時超出上下文長度的問題
- 使用 `attr_filter="password"` 只取得密碼相關設定
- 範例：`getCOSInfo("default", attr_filter="password|quota|limit")`
- 工具總數從 30 個增加到 31 個

### v1.2.2 (2025-11-27)
**效能**：新增 getQuotaUsage()，快速排名帳號儲存用量
- **新工具**：`getQuotaUsage()`，單次 API 呼叫，最多快 1000 倍！
- 使用 Zimbra 的 `GetQuotaUsageRequest` API (針對大量查詢最佳化)
- 支援依 totalUsed、percentUsed、quotaLimit 排序
- 支援分頁 (limit、offset)，適用大型系統
- `getTopMailboxesBySize()` 內部改用 `getQuotaUsage()` (向下相容)
- 工具總數從 29 個增加到 30 個

### v1.2.1 (2025-11-27)
**錯誤修正**：修正動態通訊群組支援
- `getAllDistributionLists()` 現在會同時查詢靜態通訊群組與動態群組
- 修正查詢，加入 `types="distributionlists,dynamicgroups"`
- 加入 `memberURL` 屬性偵測，準確識別動態群組
- 同樣的修正也套用到 `getDLInfo()` 與 `getDLMembers()`

### v1.2.0 (2025-11-27)
**新功能**：新增 jt_zmmsgtrace 整合
- 6 個透過 jt_zmmsgtrace API 追蹤郵件的新工具
- 可依寄件者、收件者、Message-ID、主機、時間搜尋
- 完整追蹤郵件傳遞路徑
- 搜尋支援正規表示式
- 工具總數從 23 個增加到 29 個

### v1.1.7 (2025-11-27)
**錯誤修正**：修正 getAllDistributionLists() 的 memberCount 問題
- 新增 `include_member_count` 參數 (預設：False)
- 為 False (預設) 時：memberCount 回傳 null (速度快)
- 為 True 時：逐一查詢每個通訊群組的實際成員數 (較慢但準確)
- 修正誤用 Zimbra 屬性導致一律回傳 0 的問題

### v1.1.6 (2025-11-27)
**新功能**：新增 getAllDistributionLists() 函式
- 列出系統中的所有通訊群組
- 支援網域篩選 (單一或多個網域)
- 支援以 offset 與 limit 分頁
- 回傳通訊群組詳細資料：name、displayName、dynamic、description、memberCount
- 工具總數從 22 個增加到 23 個

### v1.1.5 (2025-11-27)
**重大修正**：完全改寫服務狀態解析
- 修正錯誤的 XML 解析 (之前找的是錯誤的元素結構)
- 查明 Zimbra 實際格式：`<status service="X">1</status>`
- 確認狀態碼：「1」= running、「0」= stopped
- 加入時間戳記轉換為 ISO 格式
- 服務現在會顯示正確的 running／stopped 狀態

### v1.1.3 (2025-11-27)
**強化 unlockAccount 並加入安全檢查**
- 只解鎖狀態為「locked」的帳號
- 未鎖定的帳號回傳「skipped」狀態
- 避免意外修改帳號狀態

### v1.1.1 (2025-11-27)
**修正 getServerStatus 並改善 XML 解析**
- 加入多種 SOAP 請求格式的備援策略
- 強化 XML 解析，提供 3 種不同的解析策略
- 提升與 Zimbra 10.x FOSS 版的相容性

### v1.1.0 (2025-01-27)
- 新增帳號解鎖功能
- 新增郵件佇列搜尋功能
- 新增信箱統計與儲存用量排名
- 強化佇列監控功能

### v1.0.0 (2025-01-27)
首次發布，提供基本功能

---

## 🤝 參與貢獻

### 回報問題

如果遇到任何問題：

1. 先查看[疑難排解](#-疑難排解)章節
2. 啟用除錯記錄並擷取輸出內容
3. 附上您的 Zimbra 版本 (`zmprov -v`)
4. 建立 issue 並提供詳細資訊

### 開發

參與貢獻的方式：

1. Fork 這個儲存庫
2. 建立功能分支
3. 進行修改
4. 完整測試
5. 送出 pull request

---

## 📄 授權

MIT 授權條款 (MIT License)

Copyright (c) 2025 Jason Cheng

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 📚 其他資源

### 說明文件檔案

- `FIX_v1.1.5_SUMMARY.md`：v1.1.5 修正的詳細摘要
- `QUICK_TEST_v1.1.5.md`：快速測試指南
- `UNLOCK_ACCOUNT_FIX.md`：unlockAccount 功能說明文件
- `TESTING_GUIDE.md`：完整測試指南

### 測試腳本

- `quick_test_status.py`：快速服務狀態測試
- `test_unlock_account.py`：unlockAccount 函式測試
- `examples_unlock_account.py`：使用範例

### 相關連結

- [Zimbra SOAP API 說明文件](https://wiki.zimbra.com/wiki/SOAP_API_Reference_Material)
- [FastMCP 說明文件](https://github.com/jlowin/fastmcp)
- [Claude Desktop MCP 設定](https://docs.claude.com/en/docs/claude-code/mcp)

---

## 📞 支援

如有問題或需要支援：

- 參閱本儲存庫中的說明文件
- 查看疑難排解章節
- 建立 issue 並提供詳細資訊

---

**祝監控愉快！** 🚀

_這個 MCP 伺服器讓您透過與 Claude 的自然語言互動，更輕鬆地管理 Zimbra。_
