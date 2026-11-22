# Proxmox VE MCP Server

適用於 **Proxmox VE** 的 [Model Context Protocol](https://modelcontextprotocol.io) (MCP) 伺服器，以單一檔案提供完整的叢集、節點、VM/CT、儲存、Ceph、HA 與防火牆管理功能。共提供 **81 個工具**：唯讀查詢一律可用，寫入／生命週期操作則須透過明確的功能開關啟用 (預設為唯讀)。

- 作者：Jason Cheng (jason@jason.tools)
- 授權：MIT
- 版本：1.8.0
- 傳輸方式：`stdio` (預設)、`sse`、`streamable-http`
- 語言：[English](README.md) · [繁體中文](README_zh-TW.md)

---

## 功能特色

- **叢集與節點**：總覽、狀態、節點資源、作業、系統／叢集記錄。
- **VM 與容器**：統一的清單／狀態／設定／快照／效能查詢，支援篩選與分頁；自動偵測類型 (QEMU 或 LXC)。
- **生命週期**：啟動／關機／停止／重新啟動／重設／遷移／備份／快照／複製／更新／刪除／建立 (皆受功能開關控管)。
- **儲存**：儲存狀態／內容、ZFS 儲存集區、備份與備份作業。
- **Ceph**：叢集健康狀態、OSD (含個別 OSD 詳細資訊)、集區。
- **網路與防火牆**：介面、橋接、防火牆規則 (叢集／節點／客體範圍)。
- **硬體與健康狀態**：PCI 裝置、CPU 資訊、磁碟 SMART／耗損程度、效能統計。
- **高可用性 (HA)**：HA 狀態與資源設定。
- **批次收集工具**：一次呼叫 `get_all_*` 即可取得整個叢集的資料 (設定、快照、防火牆規則、備份、效能、狀態歷程、操作記錄)。
- 支援多種傳輸方式、HTTP 可選用 API 金鑰 (Bearer) 認證、透過 Guest Agent 解析 IP、透過 virtio-balloon 取得準確的客體內部記憶體用量。

---

## 需求環境

- Python 3.10 以上
- Proxmox VE **API 權杖** (建議) 或使用者名稱／密碼
- Python 套件：

```bash
pip install httpx websockets pillow pydantic mcp
# uvicorn + starlette are pulled in transitively for the sse / streamable-http transports
```

或直接用 `uvx` 執行 (不需要 venv)：

```bash
uvx --with httpx --with websockets --with pillow --with pydantic --with mcp \
    python mcp_pve.py
```

---

## 設定

設定值的優先順序：**CLI 參數 > 環境變數 > 預設值**。

| 環境變數 | CLI 參數 | 預設值 | 說明 |
|---|---|---|---|
| `PVE_HOST` | `--host` | — (必填) | 基礎 URL，例如 `https://pve.example.com:8006`。可用逗號分隔列出多個叢集節點以進行容錯移轉：`https://pve1.example.com:8006,https://pve2.example.com:8006` |
| `PVE_USERNAME` | `--username` | — | 例如 `root@pam` (密碼認證) |
| `PVE_PASSWORD` | `--password` | — | 密碼 (密碼認證) |
| `PVE_API_TOKEN_ID` | `--api-token-id` | — | 例如 `root@pam!mytoken` (權杖認證，建議使用) |
| `PVE_API_TOKEN_SECRET` | `--api-token-secret` | — | API 權杖密鑰 |
| `PVE_VERIFY_SSL` | `--verify-ssl` | `false` | 驗證 TLS 憑證 |
| `PVE_TIMEOUT` | — | `30` | 要求逾時 (秒) |
| `MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `MCP_HTTP_HOST` | `--http-host` | `0.0.0.0` | HTTP 繫結位址 |
| `MCP_HTTP_PORT` | `--http-port` | `8000` | HTTP 連接埠 |
| `MCP_API_KEY` | `--api-key` | — | 用來保護 HTTP/SSE 端點的 Bearer 權杖 |
| `MCP_PVE_COMPACT` | — | 關閉 | 設為 `1` 會縮短工具與參數說明，適合小上下文模型 |

盡量使用 **API 權杖**認證；若只提供使用者名稱／密碼，伺服器會改用 ticket + CSRF 認證。

---

## 使用方式

### stdio (預設)

```bash
python3 mcp_pve.py \
  --host "https://pve.example.com:8006" \
  --api-token-id 'root@pam!mytoken' --api-token-secret SECRET
```

### SSE

```bash
python3 mcp_pve.py --transport sse --http-host 0.0.0.0 --http-port 8015 \
  --host "https://pve.example.com:8006" \
  --api-token-id 'root@pam!mytoken' --api-token-secret SECRET \
  --api-key YOUR_BEARER_TOKEN
```

SSE 模式也會**在同一個連接埠的 `/mcp` 提供 Streamable HTTP** (自 v1.5.7 起)。只要用戶端支援
(例如 Claude Code 的 `"type": "http"`)，請優先使用 `/mcp`：SSE 用戶端在連線中斷後 (筆電睡眠、網路短暫斷線) 自動重新連線時，
會拿到新的工作階段卻沒有重新送出 `initialize`，之後每次呼叫都會以
`-32602 Invalid request parameters` 失敗。`/mcp` 是無狀態的，因此沒有工作階段會遺失。

### Streamable HTTP

```bash
python3 mcp_pve.py --transport streamable-http --http-port 8004 \
  --host "https://pve.example.com:8006" \
  --api-token-id 'root@pam!mytoken' --api-token-secret SECRET
```

---

## Claude Desktop

加入 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "proxmox": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/mcp_pve/mcp_pve.py"],
      "env": {
        "PVE_HOST": "https://your-pve-host:8006",
        "PVE_API_TOKEN_ID": "root@pam!mytoken",
        "PVE_API_TOKEN_SECRET": "your-token-secret",
        "PVE_VERIFY_SSL": "false",
        "PVE_TIMEOUT": "30"
      }
    }
  }
}
```

編輯後請重新啟動 Claude Desktop。

---

## Open WebUI (透過 mcpo)

用 [`mcpo`](https://github.com/open-webui/mcpo) 將 stdio 伺服器公開為 OpenAPI 端點：

```bash
uvx mcpo --port 8004 --api-key "YOUR_MCPO_KEY" -- \
  env PVE_HOST=https://pve.example.com:8006 \
      PVE_API_TOKEN_ID='root@pam!mytoken' \
      PVE_API_TOKEN_SECRET=SECRET \
      PVE_VERIFY_SSL=false \
  python /opt/mcp/mcp_pve.py
```

之後每個工具都可透過 `POST http://host:8004/<tool_name>` 呼叫，並帶上 `Authorization: Bearer YOUR_MCPO_KEY`。將 Open WebUI 的工具伺服器指向 `http://host:8004` 即可。

---

## 功能開關 (寫入操作)

寫入／生命週期操作**預設為停用**，由 `mcp_pve.py` 開頭附近的 `ENABLE_*` 旗標控制。管控分為兩層：停用的工具不會出現在 `list_tools` 中，**而且**執行時也會被擋下。

預設狀態：

- 預設**啟用**：`ENABLE_VM_BACKUP`、`ENABLE_CT_BACKUP`、`ENABLE_VM_SNAPSHOT`、`ENABLE_CT_SNAPSHOT`。
- 預設**停用**：其他所有項目 (建立／複製／更新／刪除／啟動／停止／關機／重新啟動／重設／遷移／備份作業)，以及 `ENABLE_HA_CONFIG` (HA 規則、HA 資源設定、HA 移動、CRS 選項) 與 `ENABLE_NODE_MAINTENANCE` (Ceph 旗標、節點重新啟動)。

建議：正式環境中請將 `ENABLE_VM_DELETE` 與 `ENABLE_CT_DELETE` 維持為 `False`，只啟用實際會用到的操作。

---

## 工具 (81)

### 叢集與節點

| 工具 | 說明 |
|---|---|
| `get_cluster_overview` | 完整的叢集總覽：資源、狀態、健康指標 |
| `get_cluster_status` | 整體叢集狀態與節點健康狀態 |
| `get_cluster_nodes` | 所有節點的詳細資訊 |
| `get_node_status` | 節點的 CPU／記憶體／系統狀態 |
| `get_node_resources` | 從叢集資源取得節點資源用量 (VM、CT、儲存) |
| `get_node_tasks` | 節點作業執行狀態與歷程 |
| `get_task_log` | 依 UPID 取得單一作業的狀態與輸出記錄；`errors_only` 只保留說明失敗原因的行 |
| `get_backup_failures` | 各節點最近失敗的備份 (vzdump) 作業：哪台 VM/CT 失敗、從記錄擷取的一行原因，以及每個客體的失敗次數 |

### 維運檢查 (唯讀)

這些工具回答的是「這樣做安全嗎？」與「哪裡出問題？」，而不是回傳原始 API 資料。

| 工具 | 說明 |
|---|---|
| `migration_preflight` | 遷移前檢查：兩個節點的 CPU 廠牌／型號、客體 CPU 類型、本機磁碟、掛載的 ISO、直通裝置、目標節點的記憶體餘裕、HA。判定結果為 `ok`／`warning`／`blocked`，並提供建議模式 (`online`／`offline`／`restart`) |
| `verify_guest` | 遷移、重新啟動或還原之後：取樣狀態，檢查運作時間、CPU 與網路計數器是否有在變動、Guest Agent 是否回應，以及從 MCP 伺服器連線 TCP 連接埠是否有回應。結果為 `healthy`／`suspect`／`down` 並附上原因 |
| `get_capacity_report` | 每個節點：已用 RAM 與分配給執行中 VM 的記憶體對照、容器限制與實際用量對照、CPU 廠牌。建議哪些 VM 該移到哪裡，優先選擇同廠牌的目標節點 |
| `find_guest` | 找出哪台 VM／容器擁有某個 IP、MAC、名稱片段或 VMID (設定、Guest Agent、容器介面) |
| `check_ip_conflicts` | 被多個客體使用的 IP (目前衝突，或潛在衝突：已停止的客體啟動後就會衝突) 以及重複的 MAC；客體內部的 Docker／橋接位址會被忽略 |
| `get_backup_coverage` | 沒有備份的執行中客體、不在任何備份作業中的客體、最後一次備份過舊的客體，並附上儲存與驗證狀態 |
| `get_notification_health` | 已設定的通知端點與比對器、沒有被任何比對器使用的端點，以及在備份作業記錄中找到的傳送失敗 |
| `get_node_updates` | 各節點待安裝的更新 (依來源分類)、執行中與最新已安裝核心的比較 (是否需要重新啟動)、pve-manager 版本 |
| `get_stale_snapshots` | 整個叢集中超過 N 天的快照 |
| `audit_container_features` | 特權容器、nesting／keyctl 與 OS 類型的對照、開機時不會自動啟動的執行中容器 |
| `find_oom_events` | 從節點核心記錄找出 OOM kill，並對應到客體與服務；可區分是客體碰到自己的記憶體上限，還是主機本身記憶體不足 |
| `audit_ha_rules` | 可能被放到不同 CPU 廠牌節點上的 HA VM (跨廠牌線上移動會讓客體凍結)、這些 VM 是否開啟自動重新平衡、非嚴格、已停用或懸空的規則 |
| `plan_node_evacuation` | 重新啟動前清空節點的規劃：每個執行中客體標示為線上遷移／重新啟動遷移／離線遷移／no_capacity，遵守嚴格的 HA 節點規則與可用 RAM 保留量 (`min_free_gib`，預設 16)。VM 以設定的 RAM 計算 |
| `check_node_after_reboot` | 節點已恢復且具備仲裁、執行的是最新已安裝核心、Ceph OSD 為 up 且 PG 為 clean、`noout` 仍有設定 → ready／not_ready |

### 節點維護與 HA 設定 *(受功能開關控管，需 confirm=true)*

| 工具 | 開關 | 說明 |
|---|---|---|
| `ha_rule_set` | `ENABLE_HA_CONFIG` | 建立／更新／刪除 HA 節點親和性或資源親和性規則；除非指定 `allow_mixed_vendor`，否則拒絕跨 CPU 廠牌的 VM 規則 |
| `ha_resource_set` | `ENABLE_HA_CONFIG` | 要求的狀態、個別資源的自動重新平衡、failback、max_relocate／max_restart |
| `ha_move` | `ENABLE_HA_CONFIG` | 移動 HA 客體：`migrate` (線上遷移，經 `migration_preflight` 檢查) 或 `relocate` (停止、移動、啟動) |
| `set_ha_crs` | `ENABLE_HA_CONFIG` | 排程器模式與自動重新平衡：在進行計畫性節點作業前先關閉重新平衡 |
| `set_ceph_flag` | `ENABLE_NODE_MAINTENANCE` | 設定／清除 `noout`、`norebalance`、`nobackfill`、`norecover`、`noscrub`、`nodeep-scrub`、`noin`、`nodown` |
| `reboot_node` | `ENABLE_NODE_MAINTENANCE` | 只有在節點已清空、仲裁不受影響且 Ceph 為 clean 時才重新啟動節點；會先設定 `noout` |

HA 節點維護模式 (`ha-manager crm-command node-maintenance`) 沒有 API，因此流程為：`plan_node_evacuation` → 移動或停止客體 → `reboot_node` → `check_node_after_reboot` → `set_ceph_flag noout false` → 將客體移回。

`migrate` 現在會先執行 `migration_preflight`，並拒絕被判定為不安全的線上遷移 (例如跨 CPU 廠牌，這種遷移可能「成功」完成卻讓客體凍結)；`force=true` 可強制執行。容器一律以重新啟動模式移動。

### VM 與容器：查詢

| 工具 | 說明 |
|---|---|
| `list_vms` | 列出 VM，支援篩選與分頁 (id／名稱／狀態；IP 與準確的記憶體用量) |
| `list_containers` | 列出 LXC 容器，支援篩選與分頁 |
| `get_status` | VM 或容器的狀態 (自動偵測類型) |
| `get_config` | VM 或容器的設定 |
| `get_snapshots` | VM 或容器的快照 |
| `get_performance` | VM 或容器的效能統計 |

### VM 與容器：生命週期 *(受功能開關控管)*

| 工具 | 說明 |
|---|---|
| `start` | 啟動 VM 或容器 |
| `shutdown` | 正常關機 |
| `stop` | 強制停止 (可能造成資料遺失) |
| `reboot` | 正常重新啟動 |
| `reset` | 硬體重設 (僅限 VM) |
| `migrate` | 遷移到其他節點 |
| `backup` | 備份 VM 或容器 |
| `snapshot` | 建立快照 |
| `clone` | 複製 VM 或容器 |
| `update_config` | 更新 VM/CT 設定 |
| `delete` | 永久刪除 VM 或容器 |
| `create_vm` | 以完整硬體設定建立新 VM |
| `create_container` | 建立新的 LXC 容器 |

### 佈建輔助工具

| 工具 | 說明 |
|---|---|
| `list_iso_images` | 可用於安裝的 ISO 映像 |
| `list_templates` | 可用的容器範本 |
| `get_next_vmid` | 下一個可用的 VM/CT ID |
| `get_vm_config_options` | 可用的 VM 建立選項 (CPU 類型、NIC 類型等) |
| `get_network_bridges` | 可用的網路橋接及其設定 |

### Proxmox Backup Server (透過 PVE 儲存 API 讀取，不需要 PBS 認證資訊)

| 工具 | 說明 |
|---|---|
| `get_pbs_status` | 掛在 PVE 上的 PBS 儲存：伺服器、資料儲存區、命名空間、是否啟用、已用／總量、過去一個月的每日成長量、預估幾天後會滿 |
| `get_pbs_backups` | 每個客體：快照數量、最新／最舊、大小、最新快照是否已驗證、失敗與從未驗證的快照、受保護、已加密；PBS 備份過舊或沒有 PBS 備份的執行中客體 |

垃圾回收、驗證／修剪／同步作業的結果與 PBS 作業只能在 PBS 本身查看。

### 儲存與備份

| 工具 | 說明 |
|---|---|
| `get_storage_status` | 儲存狀態與用量 |
| `get_storage_content` | 儲存內容清單 (images/iso/vztmpl/backup/…) |
| `get_zfs_pools` | ZFS 儲存集區狀態 |
| `list_backups` | 儲存中的備份檔案 |
| `get_backup_jobs` | 備份作業排程與狀態 |
| `create_backup_job` | 立即執行備份作業 *(受功能開關控管)* |

### Ceph

| 工具 | 說明 |
|---|---|
| `get_ceph_status` | 叢集健康狀態、監視器、OSD、PG、用量 |
| `get_ceph_osds` | 所有節點的 OSD 狀態 |
| `get_ceph_osd_details` | 指定 OSD 的詳細資訊 |
| `get_ceph_pools` | 集區資訊與統計 |

### 網路、防火牆與硬體

| 工具 | 說明 |
|---|---|
| `get_network_interfaces` | 介面狀態與設定 |
| `get_firewall_rules` | 叢集／節點／客體的防火牆規則 |
| `get_hardware_info` | 硬體資訊，包含 PCI 裝置 |
| `get_cpu_info` | CPU 資訊與功能 |
| `get_disk_info` | 磁碟資訊，包含 SMART 健康狀態／耗損程度 |
| `get_performance_stats` | 節點效能統計 |

### 記錄

| 工具 | 說明 |
|---|---|
| `get_system_logs` | 節點的系統記錄 |
| `get_cluster_logs` | 全叢集記錄與作業歷程 |

### 高可用性

| 工具 | 說明 |
|---|---|
| `get_ha_status` | HA 叢集狀態 |
| `get_ha_resources` | HA 資源狀態與設定 |

### 批次收集工具 (全叢集、支援分頁)

| 工具 | 說明 |
|---|---|
| `get_all_vm_configs` | 所有 VM 與容器的設定 |
| `get_all_snapshots` | 所有 VM 與容器的快照 |
| `get_all_backup_status` | 所有客體的備份狀態／歷程 |
| `get_all_performance_stats` | 所有節點／客體的效能統計 |
| `get_all_vm_status_history` | 所有客體的電源狀態變更歷程 |
| `get_all_vm_firewall_rules` | 所有客體的防火牆規則 |
| `get_all_operation_logs` | 所有節點／客體的操作記錄 |

---

## 注意事項

- **VM 記憶體準確度 (v1.5.6)。** Proxmox 對執行中 QEMU VM 回報的 `mem` 是主機端 KVM 處理程序的 RSS (包含模擬額外負擔)，可能超過設定的 RAM。`list_vms` 現在會在客體回報 virtio-balloon 統計時，從 `status/current` 的 `ballooninfo` 推算真正的客體內部用量，並限制 `memory_used_mb` 使其不會超過 `memory_mb`。若要取得準確的 Windows 客體用量，請安裝 **virtio-balloon 驅動程式與服務**。
- **分頁。** 批次 `get_all_*` 與清單類工具支援 `limit`/`offset`，避免塞爆 LLM 的上下文；上限在內部限制 (schema 中沒有 `maximum`，因此 mcpo 之類的 OpenAPI 代理不會拒絕較大的值)。
- **多個節點容錯移轉 (v1.7.0)。** 任何一個節點的 API 都能服務整個叢集，因此 `PVE_HOST` 可以列出多個節點。目前的節點無法連線時，伺服器會改用下一個，並持續使用有回應的那一個。讀取 (GET) 在任何網路錯誤後都會改由其他節點重試；動作 (POST/PUT/DELETE) 只有在要求不可能已送達伺服器時 (連線被拒／連線逾時) 才會重試，因此遷移或關機絕不會被送出兩次。連線逾時上限為 5 秒，所以一個掛掉的節點只會多花幾秒。`get_cluster_status` 會在 `api_host` 中顯示回應的節點。
- 所有工具都回傳結構化 JSON；錯誤會放在回傳內容中，而不是拋出例外。
- HTTP 傳輸方式已停用 DNS rebinding 防護，以避免在反向代理後面出現 `421 Misdirected Request`。

---

## 變更記錄 (近期)

- **v1.8.0**：節點維護與 HA：`plan_node_evacuation`、`check_node_after_reboot`、`audit_ha_rules` (唯讀)；`ha_rule_set`、`ha_resource_set`、`ha_move`、`set_ha_crs` (`ENABLE_HA_CONFIG`)；`set_ceph_flag`、`reboot_node` (`ENABLE_NODE_MAINTENANCE`)。透過 PVE API 讀取 Proxmox Backup Server：`get_pbs_status`、`get_pbs_backups`。`migration_preflight` 新增 `min_free_gib` 參數，會擋下記憶體不足的目標節點，並以目前用量計算容器。
- **v1.7.0**：`PVE_HOST` 接受以逗號分隔的叢集節點清單，並自動容錯移轉；非冪等的要求在可能已送達伺服器後絕不重送；連線逾時 5 秒；`get_cluster_status` 回報 `api_host`。
- **v1.6.0**：十一個唯讀維運檢查：`migration_preflight`、`verify_guest`、`get_capacity_report`、`find_guest`、`check_ip_conflicts`、`get_backup_coverage`、`get_notification_health`、`get_node_updates`、`get_stale_snapshots`、`audit_container_features`、`find_oom_events`。`migrate` 會執行預檢並拒絕不安全的線上遷移。`get_all_operation_logs` 從 UPID 填入 `vmid`；`get_all_snapshots` 新增 `age_days`；`MCP_PVE_COMPACT=1` 可使用簡短說明。
- **v1.5.8**：新增 `get_task_log` 與 `get_backup_failures`。備份作業原本只回報 `job errors`；失敗的客體與原因都在作業記錄裡，但沒有任何工具能讀取。
- **v1.5.7**：SSE 模式也在 `/mcp` 提供 Streamable HTTP (無狀態)，用戶端在 SSE 重新連線後不會再卡在未初始化的工作階段 (所有呼叫都以 `-32602` 失敗)；API 金鑰檢查改為單純的 ASGI 中介軟體 (常數時間比較)，解決每次 SSE 斷線都記錄 `AssertionError` 的問題。
- **v1.5.6**：修正 VM 記憶體用量不準確 (`memory_used_mb` 可能超過總量)；改用 balloon 推算的客體內部用量並加上限制；將 IP／記憶體查詢合併為一輪並行處理。
- **v1.5.5**：從 `get_ceph_status` 移除 `include_details`，避免 token 用量超出上限。
- **v1.5.4**：SSE/streamable-HTTP 改用 FastMCP 包裝 (修正 `421`)；可選用 `--api-key` Bearer 認證。
- **v1.5.3**：SSE 傳輸方式；`list_vms`／`list_containers` 加入用量指標 (CPU/記憶體/網路)。
- **v1.5.1–1.5.2**：清單類工具加入 Guest Agent IP；移除分頁參數 schema 中的 `maximum`。
- **v1.5.0**：將 28 個 VM/CT 工具整合為 15 個統一工具 (自動偵測類型)。
