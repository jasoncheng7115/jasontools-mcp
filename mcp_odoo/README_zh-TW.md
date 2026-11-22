# Odoo MCP Server

適用於 **Odoo** 的 [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器，以 FastMCP 為基礎，透過 Odoo 的 XML-RPC API 運作。提供 **18 個讀取工具**，涵蓋報價單、銷售分析、採購單、出貨、產品、庫存、發票、聯絡人與訊息紀錄 (chatter)，並針對小型／本機 LLM 調校了節省 token 的輸出控制；另有 **25 個需手動開啟的寫入工具**，用於報價單、客戶、產品、發票與出貨單 (`--enable-write`)。

- 作者：Jason Cheng (Jason Tools)
- 授權：MIT
- 版本：1.16.0
- 測試環境：Odoo 13 與 18 Community Edition (寫入工具：Odoo 18)
- 傳輸方式：`stdio` (預設)、`sse`、`streamable-http`
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能

- **銷售／報價單**：彈性搜尋 (聯絡人、狀態、日期與金額範圍、產品名稱／關鍵字，支援 AND／OR 與排除邏輯)、快速統計，以及完整的訂單明細。
- **採購與出貨**：搜尋採購單與出貨單 (stock picking)，可依狀態／日期／產品關鍵字篩選；依 ID 檢視明細。開啟寫入工具後，可建立出貨單 (手動建立或從銷售訂單建立，含服務類產品)、編輯、驗證，並下載送貨單／揀貨單 PDF。
- **產品與庫存**：以關鍵字／多關鍵字搜尋產品、產品明細，以及各倉庫／儲位的現有庫存。
- **報價單寫入 (需手動開啟)**：建立含備註／區段行的報價單、編輯表頭與明細行、複製給另一個客戶、確認、設定客戶的預設價目表／付款條件、新增聯絡人、下載報價單或形式發票 PDF。單價受到保護，不會被價目表重新計算；每次寫入都會留下稽核記錄。
- **聯絡人**：搜尋聯絡人 (回傳指向聯絡人頁面的 Markdown 連結)，以及依 VAT／統一編號、客戶／供應商旗標與聯絡人建立或取得聯絡人。
- 每個搜尋工具都有**節省 token 的控制項**：`count_only` (只計數不回傳資料)、`compact` (只回傳必要欄位)、`include_lines`／`include_moves` 可略過明細行，以及 `offset` 分頁，專為 `gpt-oss:120b` 等模型設計。
- 多種傳輸方式、HTTP 可選用 API 金鑰 (Bearer) 認證、具 TTL 的回應快取、含退避的重試。

> **關於關鍵字：** 產品關鍵字會原樣比對，**不要**翻譯使用者的關鍵字 (例如 `["proxmox", "訓練"]`)。

---

## 需求環境

- Python 3.10 以上
- 具 XML-RPC 存取權限的 Odoo 認證資訊 (URL、資料庫、使用者名稱、密碼)
- Python 套件：

```bash
pip install mcp requests
# uvicorn + starlette are required for the sse / streamable-http transports
pip install uvicorn starlette
```

或直接以 `uvx` 執行 (不需要 venv)：

```bash
uvx --with mcp --with requests --with uvicorn --with starlette \
    python mcp_odoo.py
```

---

## 設定

**Odoo 連線透過環境變數設定**；傳輸／認證選項也可用 CLI 參數指定 (這些選項的優先順序為 CLI > 環境變數)。

### Odoo 連線 (環境變數)

| 環境變數 | 預設值 | 說明 |
|---|---|---|
| `ODOO_URL` | — (必填) | Odoo 基礎 URL，例如 `http://your-odoo-host:8069` |
| `ODOO_DATABASE` | — (必填) | 資料庫名稱 |
| `ODOO_USERNAME` | — (必填) | 登入使用者 |
| `ODOO_PASSWORD` | — (必填) | 密碼 (Odoo 14 以上也可用 API 金鑰當密碼) |
| `ODOO_DEFAULT_LANGUAGE` | `zh_TW` | 記錄的預設語言 |
| `ODOO_CACHE_TTL` | `300` | 回應快取 TTL (秒) |
| `ODOO_TIMEOUT` | `30` | 請求逾時 (秒) |
| `ODOO_MAX_RETRIES` | `3` | 重試次數 (指數退避) |

### 傳輸／認證

| 環境變數 | CLI 參數 | 預設值 | 說明 |
|---|---|---|---|
| — | `--transport` / `-t` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| — | `--host` / `-H` | `127.0.0.1` | HTTP 綁定位址 |
| — | `--port` / `-p` | `8001` | HTTP 連接埠 |
| `MCP_API_KEY` | `--api-key` / `-k` | — | 保護 HTTP/SSE 端點用的 Bearer 權杖 |
| `ODOO_ENABLE_WRITE` | `--enable-write` | 關閉 | 註冊寫入工具 (見下方) |

### 寫入工具

| 環境變數 | 預設值 | 說明 |
|---|---|---|
| `ODOO_AUDIT_LOG` | `~/.local/state/mcp_odoo/audit.jsonl` | 每次寫入記一行 JSON：時間、Odoo 使用者、用戶端 IP／User-Agent、動作、記錄、變更內容 |
| `ODOO_DEFAULT_COMPANY_ID` | — | 新報價單、聯絡人與聯絡人員所屬的公司 (預設：Odoo 使用者目前的公司) |
| `ODOO_DEFAULT_TEAM_ID` | — | 新報價單的銷售團隊 |
| `ODOO_DEFAULT_SALESPERSON_ID` | — | 新報價單的業務員 (使用者 ID) |
| `ODOO_DEFAULT_PRICELIST_ID` | — | 新報價單、聯絡人與聯絡人員的價目表 (Odoo 本身的預設可能是外幣價目表) |
| `ODOO_DEFAULT_SALE_TAX_IDS` | — | 以逗號分隔的稅別 ID，套用在未指定稅別的新產品行 (僅限預設公司) |

這些 ID 只對應單一資料庫，因此屬於設定而非程式碼。未設定時採用 Odoo 本身的預設值。
| `ODOO_PDF_DIR` | `~/Downloads` | stdio 模式下 `download_quotation_pdf`／`download_delivery_pdf` 存檔的位置 |

HTTP 端點：streamable-http 在 `/mcp`，SSE 在 `/sse`。自 v1.9.1 起，SSE 模式也同時提供 `/mcp`。

---

## 使用方式

### stdio (預設)

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

SSE 模式也會**在同一個連接埠的 `/mcp` 提供 Streamable HTTP** (自 v1.9.1 起)。只要用戶端支援，請優先使用 `/mcp`
(例如 Claude Code 的 `"type": "http"`)：SSE 用戶端在連線中斷 (筆電睡眠、網路短暫斷線) 後自動重新連線時，
會拿到一個新的工作階段卻沒有重送 `initialize`，之後每次呼叫都會以 `-32602 Invalid request parameters` 失敗。
`/mcp` 是無狀態的，因此沒有工作階段可遺失。

### Streamable HTTP

```bash
python3 mcp_odoo.py --transport streamable-http --host 0.0.0.0 --port 8008
# endpoint: http://host:8008/mcp
```

---

## Claude Desktop

加入 `claude_desktop_config.json`：

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

編輯後請重新啟動 Claude Desktop。

---

## Open WebUI (透過 mcpo)

用 [`mcpo`](https://github.com/open-webui/mcpo) 把 stdio 伺服器公開為 OpenAPI 端點：

```bash
uvx mcpo --port 8008 --api-key "YOUR_MCPO_KEY" -- \
  env ODOO_URL=http://your-odoo-host:8069 \
      ODOO_DATABASE=db ODOO_USERNAME=user ODOO_PASSWORD=pass \
  python /opt/mcp/mcp_odoo.py
```

之後每個工具都可透過 `POST http://host:8008/<tool_name>` 並帶上 `Authorization: Bearer YOUR_MCPO_KEY` 使用。將 Open WebUI 的工具伺服器指向 `http://host:8008`。

---

## 工具 (18 + 25 個寫入)

### 系統

| 工具 | 說明 |
|---|---|
| `get_odoo_system_info` | Odoo 版本、連線狀態、伺服器功能 |

### 銷售與報價單

| 工具 | 說明 |
|---|---|
| `search_quotations` | 搜尋報價單／銷售訂單 (聯絡人、狀態、`invoice_status` 例如 "to invoice"、客戶採購單號 `client_order_ref`、備註文字 `description_contains` (最終客戶常常只出現在備註裡)、日期與金額範圍、`product_names`／`product_keywords` 搭配 `product_match_mode` any/all 與排除條件、分頁) |
| `search_quotation_lines` | 依描述關鍵字 (AND) 搜尋過去的報價明細行：訂單、客戶、日期、數量、單價，以及各幣別的最低／最高／平均價格，用來回答「之前 X 報價多少」 |
| `get_sales_report` | 已確認訂單的營收，可依月／季／年／客戶／產品／類別／業務員／團隊分組，並列出已開發票與待開發票金額 |
| `get_quotation_stats` | 依聯絡人／狀態快速彙總報價單統計 (筆數／金額) |
| `get_quotation_details` | 依 ID 取得完整的報價單／銷售訂單明細 |
| `get_record_messages` | 報價單、聯絡人、發票、出貨單或採購單的訊息紀錄 (chatter)：備註、電子郵件與欄位變更 (誰把什麼從哪個值改成什麼)，以當地時間顯示 |

### 採購與出貨

| 工具 | 說明 |
|---|---|
| `search_purchase_orders` | 搜尋採購單 (狀態、日期範圍、產品關鍵字、分頁) |
| `get_purchase_order_details` | 依 ID 取得完整的採購單明細 |
| `search_delivery_orders` | 搜尋出貨單／stock picking (狀態、作業類型、產品關鍵字) |
| `get_delivery_order_details` | 依 ID 取得完整的出貨單 (stock picking) 明細 |

### 產品與庫存

| 工具 | 說明 |
|---|---|
| `search_products` | 以 `keywords` 搜尋產品 (多關鍵字 AND 比對)；回傳 `company_id` 與 `quote_line_name` (報價明細行第一行必須以這段文字開頭) |
| `get_product_details` | 依 ID 取得完整的產品明細 |
| `get_product_stock` | 各倉庫／儲位的現有庫存／數量 |

### 發票

| 工具 | 說明 |
|---|---|
| `search_invoices` | 依客戶、號碼、狀態、付款狀態、日期、到期日、金額或來源文件搜尋發票。`unpaid_only=True` 可列出未收應收帳款 |
| `get_invoice_details` | 依 id 或號碼取得完整的發票明細，包含明細行與付款狀態 |
| `get_invoice_stats` | 合計與未收餘額，可依付款狀態、狀態、客戶或月份分組 |

Odoo 把客戶發票、供應商帳單與折讓單存放在同一個模型
(`account.move`)。這些工具預設查詢客戶發票；其他類型請傳入
`invoice_type="vendor"`、`"customer_credit"`、`"vendor_credit"` 或 `"all"`。

有兩個行為值得注意：

- **`unpaid_only` 會排除草稿。** 草稿發票尚未開給客戶，若算進應收帳款會高估欠款金額。
  在參考資料庫上，兩者的差別是 22 張發票／未收 648,730 與 16 張／41,576。
  要查看草稿請明確傳入 `state="draft"`。
- **草稿發票沒有號碼。** 發票過帳前，Odoo 回報的 `name` 是 `/`；
  這類發票會顯示為 `（草稿．尚未編號）`，並帶有 `is_draft` 旗標。

### 聯絡人

| 工具 | 說明 |
|---|---|
| `search_partners` | 依名稱、電子郵件、電話／手機或 VAT／統一編號搜尋聯絡人；回傳指向聯絡人頁面的 Markdown 連結 |

### 報價單寫入 (僅限 `--enable-write`)

| 工具 | 說明 |
|---|---|
| `create_quotation` | 建立草稿報價單：客戶、明細行、備註、有效日期、客戶採購單號、付款條件；公司／團隊／業務員／價目表／稅別未指定時採用站台預設值 |
| `update_quotation` | 變更草稿／已傳送報價單的表頭欄位 (客戶、採購單號、備註、有效日期、報價日期、付款條件、價目表、團隊、業務員、地址)；已確認的訂單只能改採購單號。逐欄回傳變更前 → 變更後 |
| `update_quotation_lines` | 新增／變更／刪除明細行，包含 `line_note` 與 `line_section` 行、`sequence`，以及新增或更新時的 `note_after` |
| `preview_quotation_copy` | 預覽複製給另一個客戶後的樣子；不寫入任何資料 |
| `copy_quotation` | 將報價單複製給另一個客戶 (需要 `confirm=True`) |
| `confirm_quotation` | 將報價單確認為銷售訂單 (需要 `confirm=True`；否則只預覽) |
| `update_partner_terms` | 設定客戶在某家公司的預設價目表及／或付款條件 |
| `add_contact_to_partner` | 在公司底下新增聯絡人員；聯絡人員會套用該公司的價目表 |
| `create_or_get_partner` | 以預設價目表建立公司／個人，或回傳名稱或統一編號完全相同的既有聯絡人 |
| `update_partner` | 變更聯絡人的名稱、統一編號、電子郵件、電話、手機、地址、國家、職位、語言、備註、參考、公司旗標、預設價目表 |
| `post_note` | 在報價單、聯絡人、發票、出貨單或採購單上記錄內部備註 (不會寄出電子郵件) |
| `change_quotation_state` | 把已傳送／已取消的報價單改回草稿，或把草稿標記為已傳送 (不寄電子郵件)。刻意不提供取消功能 |
| `download_quotation_pdf` | 報價單 (`sale.report_saleorder`) 或形式發票 PDF |
| `create_product` | 以站台預設的銷項／進項稅別建立產品 (範本 + 變體)；名稱或內部參考重複時拒絕建立 |
| `update_product` | 變更產品的名稱、銷售描述、價格、稅別、內部參考、類別、可銷售／可採購旗標、類型 (服務／商品)、庫存追蹤、內部備註、送貨單描述；封存或還原 |
| `duplicate_invoice` | 將客戶發票複製成新日期的新草稿 (每月固定費用) |
| `create_invoice` | 建立草稿客戶發票 |
| `post_invoice` | 將草稿發票過帳 (需要 `confirm=True`；否則只預覽) |
| `draft_invoice` | 將已過帳的發票重設為草稿 (需要 `confirm=True`；否則只預覽) |
| `update_delivery_order` | 變更出貨單的預定日期、送貨地址、來源文件、備註、負責人、優先順序。已完成的出貨單只能改備註與負責人；已取消的會被拒絕 |
| `update_delivery_lines` | 新增／變更／刪除出貨明細行：`qty` (需求量)、`quantity` (完成量)、`description_picking`、`sequence`。只有草稿明細行可以刪除；其他明細行請把 `qty` 設為 0。不適用於已完成或已取消的出貨單 |
| `create_delivery_order` | 手動建立新的草稿出貨單：聯絡人、明細行 (`product_id`、`qty`、`description`)、來源文件、預定日期、備註、作業類型。允許服務類產品。不會連結到銷售訂單 |
| `create_delivery_from_order` | 針對已確認銷售訂單尚未出貨的部分建立新的草稿出貨單，含服務類產品；連結到該訂單及其送貨地址與倉庫。已在其他出貨單上的明細行會略過 |
| `validate_delivery_order` | Odoo 的 *驗證* 按鈕：除非 `confirm=True`，否則只預覽；可逐行指定完成量 (預設 = 需求量)；數量不足時，必須用 `backorder` 指定剩餘部分是否轉入欠交單。庫存將變成負數前會先警告 |
| `download_delivery_pdf` | 出貨單的送貨單 (`stock.report_deliveryslip`，送貨單) 或揀貨作業 (`stock.report_picking`) PDF，任何狀態皆可 |

明細行規格範例：一個產品行，並在其下方以獨立的備註行列出數量公式：

```json
[
  {"display_type": "line_section", "name": "Proxmox VE subscription"},
  {"product_id": 126, "qty": 6, "price_unit": 1180,
   "name": "<exact product name>\n<subscription period ...>",
   "note_after": "(3Nodes x 2CPUs x 1Year) = 6"}
]
```

寫入工具會防範的情況：

- **重新計價。** 數量變更時，Odoo 會依價目表重新計算 `price_unit`，因此只改數量的更新會保留該行目前的單價；若 Odoo 覆寫了明確指定的 `price_unit`，會再重新套用。變更客戶或複製訂單時，會把原本的價目表 (幣別) 與單價改回來。所有被還原的項目都會列在 `warnings` 中。
- **其他公司的產品。** 產品必須屬於訂單所屬的公司或不屬於任何公司；否則該公司將無法讀取這張訂單。只要有任何一個產品沒通過檢查，就不會寫入任何資料。
- **錯誤的產品名稱。** 寫入時使用 `lang=zh_TW`；英文產品名稱仍可能帶有過時的 `(copy)` 後置字串。指定產品行的 `name` 時，第一行必須與產品名稱完全相同 (即 `search_products` 回傳的 `quote_line_name`)。報價單 PDF 只印出描述，所以縮寫過的第一行就是客戶看到的內容。其他寫法一律拒絕。
- **錯誤的幣別。** 報價單幣別與公司幣別不同時，結果會帶有警告。
- **缺少採購單號。** `client_order_ref` 為空時，`confirm_quotation` 會發出警告。
- **未知的明細行鍵值。** 明細行規格只接受 `product_id`、`name`、`qty` (`quantity` / `product_qty` / `product_uom_qty`)、`price_unit`、`discount`、`tax_id` (`taxes_id` / `tax_ids`)、`sequence`、`display_type`、`note_after` (在 `update_quotation_lines` 中另有 `line_id` / `action`)。其他鍵值 (例如 `"line_note": "..."`) 會被拒絕並附上提示 (`display_type: "line_note"` 或 `note_after`)，且不寫入任何資料，`dry_run` 時也一樣。
- **看似備註其實不是備註。** 既沒有 `product_id` 也沒有 `display_type` 的明細行，會變成沒有產品的產品行 (只是看起來像備註)；兩個工具都會對此發出警告。
- **出貨單就是出貨單。** 出貨工具會拒絕處理收貨單與內部調撥。建立或編輯出貨單都不會異動庫存；只有帶 `confirm=True` 的 `validate_delivery_order` 才會。編輯時會警告這些變更不會回寫到銷售訂單。
- **先試再做。** 每個寫入工具都接受 `dry_run=True` (複製／確認／狀態變更則在 `confirm=True` 之前都只是預覽)，並精確回報會變更哪些內容。
- **沒有破壞性操作。** 沒有任何工具可以刪除或取消報價單，或刪除聯絡人。
- **打錯客戶。** `copy_quotation` 接受 `new_partner_id`，或恰好只符合一個聯絡人的名稱；它絕不會建立聯絡人。

每次寫入都會回傳從 Odoo 讀回的記錄 (未稅金額／稅額／總計、幣別，以及每一行描述與備註的完整文字)，附加寫入 `ODOO_AUDIT_LOG`，並以內部備註的形式張貼到該記錄的訊息紀錄 (chatter)。

`download_quotation_pdf` 與 `download_delivery_pdf` 透過 Odoo 的網頁工作階段產生 (XML-RPC 無法取得報表)。透過 HTTP 時，會回傳一個指向 `/files/<token>/<file>.pdf` 的連結，有效期 15 分鐘；隨機權杖取代了 API 金鑰，因此可以直接用一般的 `curl` 抓取。stdio 模式下檔案會存到 `ODOO_PDF_DIR`。

只對應該能變更資料的用戶端開啟這些工具。常見的配置是：一個唯讀執行個體給聊天前端使用 (例如透過 mcpo)，另一個 `--enable-write` 執行個體給代理程式使用。

---

## 附註

- **節省 token 的輸出。** 所有搜尋工具都接受 `count_only`、`compact`、`include_lines`／`include_moves` 與 `offset`，讓回應對本機 LLM 保持精簡。
- **不要翻譯關鍵字。** 產品關鍵字是逐字比對；請傳入使用者原本的用詞。
- 所有工具都回傳字串內容 (JSON／Markdown)；連線問題會在回應中回報，而不會讓伺服器當掉。
- HTTP 傳輸停用了 DNS rebinding 防護，避免在反向代理後方出現 `421 Misdirected Request`。
- `MCP_API_KEY` 保護的是 MCP HTTP/SSE 端點，與 Odoo 認證資訊無關。用戶端需送出 `Authorization: Bearer <key>`。

---

## 變更記錄 (近期)

### v1.16.0 — 建立與驗證出貨單

- 新寫入工具：`create_delivery_order` (手動建立) 與 `create_delivery_from_order` (從已確認的銷售訂單建立，針對尚未出貨的數量)。兩者都接受服務類產品 (Odoo 在確認訂單時從不把服務放進出貨單)，並建立草稿。
- 新寫入工具：`validate_delivery_order`，即 *驗證* 按鈕。除非 `confirm=True`，否則只預覽；可逐行指定完成量，數量不足時拒絕自行猜測：`backorder=True` 把剩餘部分保留在欠交單，`False` 則捨棄。
- `update_product` 可變更 `type` (服務／商品)、`is_storable`、`description` (內部備註) 與 `description_picking` (送貨單上的文字)。

### v1.15.1 — 伺服器重新啟動後仍可使用

- `/mcp` 對 `GET` 回應 `405 Method Not Allowed`，讓用戶端不會開啟獨立的 SSE 串流 (這個伺服器從不主動送出訊息)。Claude Code 會把該串流中斷 (伺服器重新啟動、主機重新開機) 視為連線失效，重試約 15 秒後便放棄，直到手動重新連線。現在工具呼叫都是單純的 POST，重新啟動後仍可繼續運作。

### v1.15.0 — 送貨單 PDF

- 新的寫入群組工具：`download_delivery_pdf`，將出貨單輸出為 PDF，可選 `delivery_slip` (送貨單，`stock.report_deliveryslip`，包含站台的範本覆寫) 或 `picking` (揀貨作業，`stock.report_picking`)。回傳模式與 `download_quotation_pdf` 相同：一次性連結、`base64` 或 `text`。
- 修正：檔名含非 ASCII 字元時 (中文名稱公司的每張出貨單都是)，一次性 PDF 連結會回傳 HTTP 500。現在下載會送出 ASCII 的 `filename` 加上 `filename*=UTF-8''…`，連結也經過 URL 編碼。
- 修正：`update_delivery_lines` 在**草稿**出貨單新增明細行時，會把整張出貨單確認掉 (異動被以 `additional` 送出，導致 Odoo 確認該調撥單)。現在草稿出貨單會維持草稿。

### v1.14.0 — 出貨單編輯

- 新寫入工具：`update_delivery_order` (預定日期、送貨地址、來源文件、備註、負責人、優先順序) 與 `update_delivery_lines` (新增／變更／刪除明細行)。兩者都不會驗證出貨單或異動庫存。
- 對出貨單的寫入會張貼到其訊息紀錄 (chatter)，與報價單和聯絡人相同。

### v1.13.0 — 更嚴格的報價明細行

- `create_quotation` 與 `update_quotation_lines` 遇到未知的明細行鍵值會拒絕，而不是默默丟掉 (以前 `line_note` 鍵值會消失，結果卻顯示 `created` 且沒有任何警告)。錯誤訊息會指出該鍵值、可能想用的欄位以及允許的鍵值。
- `update_quotation_lines`：`note_after` 在 `update` 時也能使用，會在產品行正下方新增備註行。
- 明細行既沒有 `product_id` 也沒有 `display_type` 時會發出警告 (它會變成沒有產品的產品行，而不是備註)，`dry_run` 時也一樣。
- 結果會回傳每一行完整的描述與備註文字，而不是只有第一行。

### v1.12.0 — 產品、發票、更安全的寫入

- 新寫入工具：`create_product`、`update_product`、`duplicate_invoice`、`create_invoice`、`post_invoice`、`draft_invoice`。
- `update_quotation_lines` 可寫入稅別 (`tax_id` 23 / [23] / [])；數量也接受 `quantity` / `product_qty`；`line_id` 也接受 `id`。
- `search_quotations` 全域搜尋在沒有符合結果時不再列出不相關的訂單，並會搜尋明細行描述。

### v1.11.1 — 明細行修正

- 只要明細行帶有稅別，`get_quotation_details` 搭配 `include_lines` (預設) 以及 `get_purchase_order_details` 都會以 `'int' object is not subscriptable` 失敗，因為 Odoo 回傳的稅別欄位只是單純的 id。現在會從 `account.tax` 查出稅別名稱。
- `download_quotation_pdf` 新增 `return_mode`：`url` (預設)、`base64` 或 `text` (PDF 的文字內容，給無法讀取 PDF 的用戶端)。

### v1.11.0 — 銷售分析、明細行搜尋、聯絡人編輯、更安全的寫入

- 新讀取工具：`get_sales_report` (依月份／客戶／產品／業務員…統計營收)、`search_quotation_lines` (依描述關鍵字查過去的價格)、`get_record_messages` (訊息紀錄：備註、電子郵件、欄位變更)。`search_quotations` 新增 `invoice_status` 與 `client_order_ref`；`search_partners` 新增 `vat`；產品搜尋會回傳 `company_id` 與 `quote_line_name`。
- 新寫入工具：`update_partner`、`post_note`、`change_quotation_state` (僅限改回草稿／標記為已傳送)。`create_or_get_partner` 移到 `--enable-write` 之後 (因為它會建立記錄)，並且也會依統一編號比對既有聯絡人。
- 公司、團隊、業務員、價目表與銷項稅別的站台預設值 (`ODOO_DEFAULT_*`)；新聯絡人與聯絡人員會套用預設價目表／公司價目表，而不是 Odoo 的外幣預設價目表。
- 報價明細行的產品名稱檢查、幣別與缺少採購單號的警告、變更前／後差異、每個寫入工具都有 `dry_run`、`date_order` 可編輯、已確認訂單的採購單號可編輯。
- 修正：`count_only` 從不超過 `limit` (顯示 10 而不是 57)；依電話搜尋聯絡人總是失敗 (domain 格式錯誤)；回傳 `None` 的動作 (例如標記為已傳送) 明明成功卻被回報為錯誤。

### v1.10.0 — 報價單寫入

在 `--enable-write` / `ODOO_ENABLE_WRITE=1` 之後新增九個寫入工具：`create_quotation`、`update_quotation`、`update_quotation_lines`、`preview_quotation_copy`、`copy_quotation`、`confirm_quotation`、`update_partner_terms`、`add_contact_to_partner`、`download_quotation_pdf`。支援備註與區段行、防止價目表重新計算單價、產品的公司檢查、`zh_TW` 產品名稱、讀回結果、稽核記錄加上訊息紀錄備註。舊版已停用的複製／更新工具已針對 Odoo 18 重寫；`copy_quotation` 不再因名稱比對不到而建立聯絡人。

### v1.9.1 — SSE 重新連線修正

SSE 模式也在 `/mcp` 提供 Streamable HTTP (無狀態)，因此用戶端在 SSE 重新連線後不會再卡在未初始化的工作階段 (所有呼叫都以 `-32602` 失敗)；API 金鑰檢查改為單純的 ASGI 中介軟體 (常數時間比對)，不再於每次 SSE 中斷時記錄 `AssertionError`。

### v1.9.0 — 發票讀取

新增 `search_invoices`、`get_invoice_details` 與 `get_invoice_stats`，以
`account.move` 為基礎。預設查詢客戶發票；供應商帳單與折讓單透過
`invoice_type` 指定。

`unpaid_only` 以 `amount_residual > 0` 篩選，而不是 `payment_state`，
因為草稿的 `payment_state` 可能未設定；它也只限已過帳的發票，
因為草稿還沒開出。


- **v1.8.3** — HTTP 傳輸的 API 金鑰認證 (`--api-key` / `MCP_API_KEY`)。
- **v1.8.2** — 停用 DNS rebinding 防護 (修正外部用戶端的 `421`)。
- **v1.8.1** — 透過 uvicorn 讓 SSE/streamable-http 可自訂主機／連接埠。
- **v1.8.0** — SSE 傳輸；`search_partners` 回傳 Markdown 聯絡人連結。
- **v1.7.0** — 節省 token 的控制項 (`count_only`/`compact`/`include_*`)；`product_keywords`；`get_quotation_stats`。
- **v1.5.6–1.6.0** — 所有搜尋工具支援分頁 (`offset`)；進階報價單篩選 (`product_names`、金額範圍、比對模式、排除條件)。
