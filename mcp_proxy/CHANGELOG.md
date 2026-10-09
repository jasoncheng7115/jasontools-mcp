# Changelog

All notable changes to MCP HTTP Proxy will be documented in this file.

## [1.1.1] - 2026-03-09

### Added

- `start_proxy_bg.sh`：背景啟動腳本，搭配 Login Items 使用
- `MCP Proxy.app`（~/Applications/）：AppleScript app 包裝，透過 Terminal 啟動 proxy

### Fixed

- **開機自動啟動**：改用 Login Items + AppleScript app 取代 launchd
  - 發現 Avast Network Extension 會阻擋 launchd 啟動的 process 對外連線（`[Errno 65] No route to host`）
  - 只有從 user terminal session 啟動的 process 才能正常連線
  - launchd (LaunchAgents) 和 AppleScript `do shell script` 都無法繞過此限制
  - 必須透過 Terminal.app 執行才算 "互動式" process

### Changed

- README.md 更新開機自動啟動章節，標註 launchd 不可用的原因

## [1.1.0] - 2026-02-26

### Added

- **SSE Bridge 功能**：透過 `--sse` 參數將 stdio MCP 伺服器暴露為 SSE 端點
  - `GET /sse`：建立 SSE 連線，自動產生 session 並啟動子程序
  - `POST /messages?session_id=<id>`：轉發 JSON-RPC 訊息至子程序 stdin
  - `OPTIONS /messages`：CORS preflight 支援
  - 自動 keepalive（每 15 秒）
  - 斷線自動清理子程序（terminate → 5 秒後 kill）
- 使用 `argparse` 取代 `sys.argv[1]` 解析 CLI 參數
  - `--port` / `-p`：自訂 port（預設 28080）
  - `--sse`：指定要橋接的 stdio MCP 伺服器指令
- CORS headers 支援（`Access-Control-Allow-Origin: *`）
- Session 管理（`Session` 類別 + 模組層級 `sessions` 字典）
- 啟動 banner 顯示 SSE endpoint URL

### Changed

- `handle_client()` 新增 `sse_command` 參數，使用 `functools.partial` 傳入
- `main()` 改用 `argparse` 取得參數
- 無 `--sse` 時行為與 v1.0.x 完全相同

## [1.0.1] - 2026-02-09

### Changed

- 將 `Claude_Desktop_MCP_Network_Fix.md` 的根因分析內容整併至 `README.md`
- 移除文件中的真實內網 IP，改用通用範例
- 刪除 `Claude_Desktop_MCP_Network_Fix.md`（內容已整併，不再需要）

## [1.0.0] - 2026-01-13

### Added

- 初始版本發布
- `mcp_proxy.py`：基於 Python asyncio 的 HTTP/HTTPS 代理程式
  - 支援 HTTPS CONNECT tunnel（雙向透明隧道）
  - 支援 HTTP 正向代理（GET/POST/PUT/DELETE/HEAD/OPTIONS）
  - 自動過濾 `Proxy-` 開頭的 header
  - 連線逾時 30 秒保護
  - Port 佔用偵測（macOS errno 48 / Linux errno 98）
  - 預設監聽 `127.0.0.1:28080`，可透過命令列參數自訂
- `start_proxy.command`：macOS 點兩下啟動腳本，自動清除舊程序後啟動
- `README.md`：操作手冊（快速設置、開機自啟、管理命令、故障排除）
- `Claude_Desktop_MCP_Network_Fix.md`：完整問題分析文件（診斷過程、根因分析、解決方案）
