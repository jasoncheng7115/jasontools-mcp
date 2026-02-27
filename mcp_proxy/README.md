# MCP HTTP Proxy + SSE Bridge

## 功能

1. **HTTP/HTTPS Proxy** — 解決 macOS 安全軟體阻擋 Claude Desktop MCP 子程序的網路連線問題
2. **SSE Bridge** — 將 stdio MCP 伺服器透過 SSE 端點暴露給遠端 MCP 客戶端（如 Chatbox、Open WebUI）

兩個功能共用同一個 port，零外部依賴（純 Python stdlib）。

---

## 問題描述（Proxy）

在 macOS 上，當安裝了某些安全軟體（如 Avast、Norton 等）時，Claude Desktop 啟動的 MCP 子程序可能無法連線到內網服務，出現 `No route to host`（errno=65 `EHOSTUNREACH`）或 `Connection failed` 錯誤。

用終端機手動執行同一支 MCP 程式卻完全正常：

| 執行方式 | 能否連線內網 |
|---------|-------------|
| 終端機手動執行 Python | 可以 |
| Claude Desktop 子程序 | 被阻擋 |
| launchd 背景服務 | 被阻擋 |

### 根因分析

安全軟體（如 Avast）會安裝 macOS **Network Extension**，對不同來源的程序套用不同的網路過濾策略：

- **互動式程序**（從終端機啟動）：允許內網連線
- **非互動式程序**（Claude Desktop 子程序、launchd 服務）：阻擋內網連線

即使在安全軟體中關閉「檔案防護」和「網頁守衛」，Network Extension 仍然在系統層級執行。

可用以下命令確認是否有 Network Extension：

```bash
systemextensionsctl list
# 若看到 network_extension 類型的項目（如 Avast、Norton），即為此問題的原因
```

---

## 快速設置

### 檔案位置

```
/path/to/mcp_proxy/
├── mcp_proxy.py          # 代理程式 + SSE Bridge
├── start_proxy.command   # macOS 啟動腳本（點兩下執行）
├── README.md             # 本文件
└── CHANGELOG.md          # 版本記錄
```

### CLI 參數

```
python mcp_proxy.py [選項]

選項:
  --port, -p PORT     監聽 port（預設 28080）
  --sse CMD [ARGS]    要橋接的 stdio MCP 伺服器指令（放在最後面）
```

---

## 模式一：純 Proxy 模式

適用於解決 macOS 安全軟體阻擋 MCP 子程序的連線問題。

### 啟動

```bash
# 預設 port 28080
python3 mcp_proxy.py

# 自訂 port
python3 mcp_proxy.py -p 9000
```

### 設定 Claude Desktop

編輯 `~/Library/Application Support/Claude/claude_desktop_config.json`，為每個 MCP 服務的 `env` 加入：

```json
{
  "mcpServers": {
    "your-mcp-server": {
      "command": "...",
      "args": ["..."],
      "env": {
        "HTTP_PROXY": "http://127.0.0.1:28080",
        "HTTPS_PROXY": "http://127.0.0.1:28080",
        "...其他原有設定..."
      }
    }
  }
}
```

---

## 模式二：Proxy + SSE Bridge

適用於將 stdio MCP 伺服器暴露為 SSE 端點，讓 Chatbox、Open WebUI 等遠端客戶端連線。

### 啟動

```bash
# 橋接 @modelcontextprotocol/server-everything
python3 mcp_proxy.py --sse npx -y @modelcontextprotocol/server-everything

# 橋接自訂 Python MCP 伺服器
python3 mcp_proxy.py --sse python3 my_mcp_server.py

# 指定 port
python3 mcp_proxy.py -p 9000 --sse npx -y @modelcontextprotocol/server-everything
```

### SSE 端點

| 端點 | 方法 | 說明 |
|------|------|------|
| `/sse` | GET | 建立 SSE 連線，接收 `endpoint` 和 `message` 事件 |
| `/messages?session_id=<id>` | POST | 送出 JSON-RPC 訊息給 MCP 伺服器 |
| `/messages` | OPTIONS | CORS preflight 回應 |

SSE 傳輸協定遵循 MCP 規格版本 2024-11-05。

### 設定 Chatbox

| 欄位 | 值 |
|------|-----|
| 類型 | 遠端 (http/sse) |
| URL | `http://127.0.0.1:28080/sse` |

### 設定 Claude Desktop（使用 mcp-remote）

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:28080/sse"]
    }
  }
}
```

### SSE 測試

```bash
# 測試 SSE 連線（應收到 endpoint 事件）
curl http://127.0.0.1:28080/sse

# 無 --sse 時，/sse 回 400
python3 mcp_proxy.py &
curl http://127.0.0.1:28080/sse
# 預期: HTTP/1.1 400 Bad Request
```

---

## 開機自動啟動

### macOS

1. 打開 **系統設定** → **一般** → **登入項目**
2. 點選 **+** 加入 `start_proxy.command`

### Linux (systemd)

建立 `/etc/systemd/user/mcp-proxy.service`：

```ini
[Unit]
Description=MCP HTTP Proxy

[Service]
ExecStart=/usr/bin/python3 -u /path/to/mcp_proxy/mcp_proxy.py
Restart=always

[Install]
WantedBy=default.target
```

啟用：
```bash
systemctl --user enable mcp-proxy
systemctl --user start mcp-proxy
```

---

## 管理命令

```bash
# 查看代理狀態
lsof -i :28080

# 停止代理
pkill -f mcp_proxy.py

# 手動啟動（前台）
python3 -u /path/to/mcp_proxy/mcp_proxy.py

# 手動啟動（背景）
nohup python3 -u /path/to/mcp_proxy/mcp_proxy.py > /tmp/mcp_proxy.log 2>&1 &

# 查看記錄
tail -f /tmp/mcp_proxy.log
```

---

## 測試

```bash
# 測試 Proxy（HTTP）
curl -x http://127.0.0.1:28080 http://httpbin.org/get

# 測試 Proxy（HTTPS）
curl -x http://127.0.0.1:28080 -k https://your-internal-host:port/

# 測試 SSE Bridge
python3 mcp_proxy.py --sse npx -y @modelcontextprotocol/server-everything &
curl http://127.0.0.1:28080/sse
# 預期: 收到 event: endpoint 和 data: /messages?session_id=...

# 斷線清理測試
# 中斷上方 curl，確認子程序被清除：
ps aux | grep server-everything
```

---

## 故障排除

### 代理無法啟動
```
Error: Port already in use
```
解決：`pkill -f mcp_proxy.py` 然後重新啟動

### MCP 仍然無法連線
1. 確認代理正在執行：`lsof -i :28080`
2. 確認 Claude Desktop 設定正確
3. 重啟 Claude Desktop

### 代理記錄顯示連線錯誤
```
[ERROR] host:port - [Errno 65] No route to host
```
這表示代理本身也被阻擋，確認代理是從**終端機手動啟動**而非 launchd 服務。

---

## 工作原理

### Proxy 模式

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Desktop │     │   MCP Proxy     │     │  內網服務        │
│                 │     │  (Terminal)     │     │                 │
│  MCP Server ────┼────►│  127.0.0.1:28080├────►│  192.168.x.x    │
│  (受限程序)      │     │  (不受限)        │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### SSE Bridge 模式

```
┌─────────────────┐     ┌──────────────────────────┐
│  Chatbox /      │ SSE │   MCP Proxy              │
│  Open WebUI /   │◄───►│   127.0.0.1:28080        │
│  mcp-remote     │     │                          │
│                 │     │  GET /sse ──► spawn child │
│                 │     │  POST /messages ──► stdin │
│                 │     │  stdout ──► SSE events    │
└─────────────────┘     └──────────────────────────┘
```

---

## 注意事項

- 代理必須從**終端機手動啟動**，不能用 launchd
- 代理需要保持執行，關閉終端機視窗會停止代理
- 建議使用 `start_proxy.command` 並加入登入項目
- SSE Bridge 的每個 `GET /sse` 連線會產生一個獨立的子程序，斷線時自動清理

---

**作者**: Jason Cheng (jason@jason.tools)
**最後更新**: 2026-02-26
