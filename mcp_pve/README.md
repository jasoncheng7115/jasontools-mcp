# Proxmox VE MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for **Proxmox VE**, providing comprehensive cluster, node, VM/CT, storage, Ceph, HA and firewall management through a single file. It exposes **81 tools**: read-only queries are always available, while write/lifecycle operations are gated behind explicit feature toggles (read-only by default).

- **Author:** Jason Cheng (jason@jason.tools)
- **License:** MIT
- **Version:** 1.8.0
- **Transports:** `stdio` (default), `sse`, `streamable-http`

---

## Features

- **Cluster & nodes** — overview, status, node resources, tasks, system/cluster logs.
- **VMs & containers** — unified list/status/config/snapshot/performance queries with filtering and pagination; type (QEMU vs LXC) auto-detected.
- **Lifecycle** — start / shutdown / stop / reboot / reset / migrate / backup / snapshot / clone / update / delete / create (all behind feature toggles).
- **Storage** — storage status/content, ZFS pools, backups and backup jobs.
- **Ceph** — cluster health, OSDs (with per-OSD details), pools.
- **Network & firewall** — interfaces, bridges, firewall rules (cluster/node/guest scope).
- **Hardware & health** — PCI devices, CPU info, disk SMART/wearout, performance stats.
- **High Availability** — HA status and resource configuration.
- **Batch collectors** — one-call `get_all_*` across the whole cluster (configs, snapshots, firewall rules, backups, performance, status history, operation logs).
- Multi-transport, optional API-key (Bearer) auth for HTTP, IP resolution via guest agent, accurate in-guest memory via virtio-balloon.

---

## Requirements

- Python 3.10+
- Proxmox VE **API token** (recommended) or username/password
- Python packages:

```bash
pip install httpx websockets pillow pydantic mcp
# uvicorn + starlette are pulled in transitively for the sse / streamable-http transports
```

Or run directly with `uvx` (no venv needed):

```bash
uvx --with httpx --with websockets --with pillow --with pydantic --with mcp \
    python mcp_pve.py
```

---

## Configuration

Settings are resolved in this order: **CLI args > environment variables > defaults**.

| Env var | CLI arg | Default | Description |
|---|---|---|---|
| `PVE_HOST` | `--host` | — (required) | Base URL, e.g. `https://pve.example.com:8006`. List several cluster nodes comma-separated for failover: `https://pve1.example.com:8006,https://pve2.example.com:8006` |
| `PVE_USERNAME` | `--username` | — | e.g. `root@pam` (password auth) |
| `PVE_PASSWORD` | `--password` | — | Password (password auth) |
| `PVE_API_TOKEN_ID` | `--api-token-id` | — | e.g. `root@pam!mytoken` (token auth, preferred) |
| `PVE_API_TOKEN_SECRET` | `--api-token-secret` | — | API token secret |
| `PVE_VERIFY_SSL` | `--verify-ssl` | `false` | Verify TLS certificate |
| `PVE_TIMEOUT` | — | `30` | Request timeout (seconds) |
| `MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` \| `sse` \| `streamable-http` |
| `MCP_HTTP_HOST` | `--http-host` | `0.0.0.0` | HTTP bind address |
| `MCP_HTTP_PORT` | `--http-port` | `8000` | HTTP port |
| `MCP_API_KEY` | `--api-key` | — | Bearer token to protect the HTTP/SSE endpoint |
| `MCP_PVE_COMPACT` | — | off | `1` shortens tool and parameter descriptions for small-context models |

Use **API token** auth where possible; the server falls back to ticket + CSRF when only username/password are supplied.

---

## Usage

### stdio (default)

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

SSE mode also serves **Streamable HTTP at `/mcp` on the same port** (since v1.5.7). Prefer `/mcp` for any
client that supports it (e.g. Claude Code `"type": "http"`): SSE clients that auto-reconnect after a dropped
connection (laptop sleep, network blip) get a fresh session without re-sending `initialize`, and every call then
fails with `-32602 Invalid request parameters`. `/mcp` is stateless, so there is no session to lose.

### Streamable HTTP

```bash
python3 mcp_pve.py --transport streamable-http --http-port 8004 \
  --host "https://pve.example.com:8006" \
  --api-token-id 'root@pam!mytoken' --api-token-secret SECRET
```

---

## Claude Desktop

Add to `claude_desktop_config.json`:

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

Restart Claude Desktop after editing.

---

## Open WebUI (via mcpo)

Expose the stdio server as an OpenAPI endpoint with [`mcpo`](https://github.com/open-webui/mcpo):

```bash
uvx mcpo --port 8004 --api-key "YOUR_MCPO_KEY" -- \
  env PVE_HOST=https://pve.example.com:8006 \
      PVE_API_TOKEN_ID='root@pam!mytoken' \
      PVE_API_TOKEN_SECRET=SECRET \
      PVE_VERIFY_SSL=false \
  python /opt/mcp/mcp_pve.py
```

Each tool is then available at `POST http://host:8004/<tool_name>` with `Authorization: Bearer YOUR_MCPO_KEY`. Point Open WebUI's tool server at `http://host:8004`.

---

## Feature toggles (write operations)

Write/lifecycle operations are **disabled by default** and controlled by `ENABLE_*` flags near the top of `mcp_pve.py`. Enforcement is two-layered: disabled tools are hidden from `list_tools` **and** blocked at execution.

Default state:

- **Enabled** by default: `ENABLE_VM_BACKUP`, `ENABLE_CT_BACKUP`, `ENABLE_VM_SNAPSHOT`, `ENABLE_CT_SNAPSHOT`.
- **Disabled** by default: everything else (create / clone / update / delete / start / stop / shutdown / reboot / reset / migrate / backup-job), plus `ENABLE_HA_CONFIG` (HA rules, HA resource settings, HA moves, CRS options) and `ENABLE_NODE_MAINTENANCE` (Ceph flags, node reboot).

Recommendation: keep `ENABLE_VM_DELETE` and `ENABLE_CT_DELETE` = `False` in production, and enable only the operations you actively use.

---

## Tools (81)

### Cluster & nodes

| Tool | Description |
|---|---|
| `get_cluster_overview` | Comprehensive cluster overview: resources, status, health metrics |
| `get_cluster_status` | Overall cluster status and node health |
| `get_cluster_nodes` | Detailed info for all nodes |
| `get_node_status` | CPU / memory / system status of a node |
| `get_node_resources` | Node resource usage (VMs, CTs, storage) from cluster resources |
| `get_node_tasks` | Node task execution status and history |
| `get_task_log` | Status and output log of one task by UPID; `errors_only` keeps just the lines that explain a failure |
| `get_backup_failures` | Recent failed backup (vzdump) jobs across nodes: which VM/CT failed, a one-line reason from the log, and a per-guest count |

### Operations checks (read-only)

These answer "is this safe?" and "what is wrong?" instead of returning raw API data.

| Tool | Description |
|---|---|
| `migration_preflight` | Before a migration: CPU vendor/model of both nodes, guest CPU type, local disks, mounted ISO, passthrough devices, target memory headroom, HA. Verdict `ok` / `warning` / `blocked` and the recommended mode (`online` / `offline` / `restart`) |
| `verify_guest` | After a migration, reboot or restore: samples status and checks that uptime, CPU and network counters move, the guest agent answers and TCP ports answer from the MCP server. `healthy` / `suspect` / `down` with reasons |
| `get_capacity_report` | Per node: RAM used vs memory allocated to running VMs, container limits vs real use, CPU vendor. Suggests which VMs to move where, preferring same-vendor targets |
| `find_guest` | Which VM/container owns an IP, MAC, name fragment or VMID (config, guest agent, container interfaces) |
| `check_ip_conflicts` | IPs used by more than one guest (active, or latent: a stopped guest would clash when started) and duplicate MACs; Docker/bridge addresses inside guests are ignored |
| `get_backup_coverage` | Running guests without a backup, guests in no backup job, guests whose last backup is too old, with storage and verify state |
| `get_notification_health` | Configured notification endpoints and matchers, endpoints no matcher uses, and delivery failures found in backup task logs |
| `get_node_updates` | Pending updates per node (by origin), running vs newest installed kernel (reboot needed), pve-manager version |
| `get_stale_snapshots` | Snapshots older than N days across the cluster |
| `audit_container_features` | Privileged containers, nesting/keyctl against the OS type, running containers that will not start on boot |
| `find_oom_events` | OOM kills from the nodes' kernel logs mapped to the guest and service; tells a guest hitting its own memory limit apart from the host running out of memory |
| `audit_ha_rules` | HA VMs that may be placed on nodes with a different CPU vendor (a live move across vendors freezes the guest), whether automatic rebalancing is on for them, non-strict, disabled or dangling rules |
| `plan_node_evacuation` | Plan for emptying a node before a reboot: per running guest live migrate / restart-migrate / offline migrate / no_capacity, honouring strict HA node rules and a free-RAM margin (`min_free_gib`, default 16). VMs count at their configured RAM |
| `check_node_after_reboot` | Node back and quorate, newest installed kernel running, Ceph OSDs up and PGs clean, `noout` still set → ready / not_ready |

### Node maintenance & HA configuration *(feature-toggled, confirm=true)*

| Tool | Toggle | Description |
|---|---|---|
| `ha_rule_set` | `ENABLE_HA_CONFIG` | Create / update / delete an HA node- or resource-affinity rule; refuses a VM rule spanning CPU vendors unless `allow_mixed_vendor` |
| `ha_resource_set` | `ENABLE_HA_CONFIG` | Requested state, per-resource auto-rebalance, failback, max_relocate / max_restart |
| `ha_move` | `ENABLE_HA_CONFIG` | Move an HA guest: `migrate` (live, checked by `migration_preflight`) or `relocate` (stop, move, start) |
| `set_ha_crs` | `ENABLE_HA_CONFIG` | Scheduler mode and automatic rebalancing — turn rebalancing off before planned node work |
| `set_ceph_flag` | `ENABLE_NODE_MAINTENANCE` | Set / clear `noout`, `norebalance`, `nobackfill`, `norecover`, `noscrub`, `nodeep-scrub`, `noin`, `nodown` |
| `reboot_node` | `ENABLE_NODE_MAINTENANCE` | Reboot a node only if it is empty, quorum survives and Ceph is clean; sets `noout` first |

HA node maintenance mode (`ha-manager crm-command node-maintenance`) has no API, so the workflow is: `plan_node_evacuation` → move or stop guests → `reboot_node` → `check_node_after_reboot` → `set_ceph_flag noout false` → move guests back.

`migrate` now runs `migration_preflight` first and refuses a live migration it rates unsafe (for example across CPU vendors, where the migration can finish "successfully" and leave the guest frozen); `force=true` overrides. Containers are moved in restart mode.

### VMs & containers — query

| Tool | Description |
|---|---|
| `list_vms` | List VMs with filtering + pagination (id/name/status; IP + accurate memory) |
| `list_containers` | List LXC containers with filtering + pagination |
| `get_status` | Status of a VM or container (auto-detects type) |
| `get_config` | Configuration of a VM or container |
| `get_snapshots` | Snapshots of a VM or container |
| `get_performance` | Performance statistics of a VM or container |

### VMs & containers — lifecycle *(feature-toggled)*

| Tool | Description |
|---|---|
| `start` | Start a VM or container |
| `shutdown` | Graceful shutdown |
| `stop` | Force stop (may cause data loss) |
| `reboot` | Graceful reboot |
| `reset` | Hardware reset (VMs only) |
| `migrate` | Migrate to another node |
| `backup` | Back up a VM or container |
| `snapshot` | Create a snapshot |
| `clone` | Clone a VM or container |
| `update_config` | Update VM/CT configuration |
| `delete` | Delete a VM or container permanently |
| `create_vm` | Create a new VM with full hardware config |
| `create_container` | Create a new LXC container |

### Provisioning helpers

| Tool | Description |
|---|---|
| `list_iso_images` | Available ISO images for installation |
| `list_templates` | Available container templates |
| `get_next_vmid` | Next available VM/CT ID |
| `get_vm_config_options` | Available VM creation options (CPU types, NIC types, …) |
| `get_network_bridges` | Available network bridges and their config |

### Proxmox Backup Server (read through the PVE storage API — no PBS credentials)

| Tool | Description |
|---|---|
| `get_pbs_status` | PBS storages attached to PVE: server, datastore, namespace, enabled, used/total, growth per day over the last month, estimated days until full |
| `get_pbs_backups` | Per guest: snapshot count, newest/oldest, size, newest verified or not, failed and never-verified snapshots, protected, encrypted; running guests with stale or no PBS backups |

Garbage collection, verify / prune / sync job results and PBS tasks are only visible on the PBS itself.

### Storage & backups

| Tool | Description |
|---|---|
| `get_storage_status` | Storage status and usage |
| `get_storage_content` | Storage content list (images/iso/vztmpl/backup/…) |
| `get_zfs_pools` | ZFS pool status |
| `list_backups` | Backup files in a storage |
| `get_backup_jobs` | Backup job schedules and status |
| `create_backup_job` | Run an immediate backup job *(feature-toggled)* |

### Ceph

| Tool | Description |
|---|---|
| `get_ceph_status` | Cluster health, monitors, OSDs, PGs, usage |
| `get_ceph_osds` | OSD status across all nodes |
| `get_ceph_osd_details` | Detailed info for specific OSD(s) |
| `get_ceph_pools` | Pool information and statistics |

### Network, firewall & hardware

| Tool | Description |
|---|---|
| `get_network_interfaces` | Interface status and configuration |
| `get_firewall_rules` | Firewall rules for cluster / node / guest |
| `get_hardware_info` | Hardware info including PCI devices |
| `get_cpu_info` | CPU information and capabilities |
| `get_disk_info` | Disk info including SMART health / wearout |
| `get_performance_stats` | Node performance statistics |

### Logs

| Tool | Description |
|---|---|
| `get_system_logs` | System logs from a node |
| `get_cluster_logs` | Cluster-wide logs and task history |

### High Availability

| Tool | Description |
|---|---|
| `get_ha_status` | HA cluster status |
| `get_ha_resources` | HA resource status and configuration |

### Batch collectors (whole-cluster, paginated)

| Tool | Description |
|---|---|
| `get_all_vm_configs` | Configs for all VMs and containers |
| `get_all_snapshots` | Snapshots for all VMs and containers |
| `get_all_backup_status` | Backup status/history for all guests |
| `get_all_performance_stats` | Performance stats for all nodes/guests |
| `get_all_vm_status_history` | Power-state change history for all guests |
| `get_all_vm_firewall_rules` | Firewall rules for all guests |
| `get_all_operation_logs` | Operation logs from all nodes/guests |

---

## Notes

- **VM memory accuracy (v1.5.6).** Proxmox's `mem` for a running QEMU VM is the host-side KVM process RSS (includes emulation overhead) and can exceed the configured RAM. `list_vms` now derives true in-guest usage from `status/current` `ballooninfo` when the guest reports virtio-balloon stats, and clamps `memory_used_mb` so it never exceeds `memory_mb`. For accurate Windows guest usage, install the **virtio-balloon driver + service**.
- **Pagination.** Batch `get_all_*` and list tools support `limit`/`offset` to avoid overflowing the LLM context; limits are clamped internally (no `maximum` in the schema, so OpenAPI proxies like mcpo don't reject large values).
- **Several nodes for failover (v1.7.0).** Any node's API serves the whole cluster, so `PVE_HOST` can list several nodes. When the current one is unreachable the server moves to the next and keeps using whichever answered. Reads (GET) are retried on another node after any network error; actions (POST/PUT/DELETE) only when the request cannot have reached the server (connection refused / connect timeout), so a migration or shutdown is never sent twice. The connect timeout is capped at 5 s, so a dead node costs a few seconds. `get_cluster_status` shows the answering node in `api_host`.
- All tools return structured JSON; errors come back in the payload rather than raising.
- DNS-rebinding protection is disabled on the HTTP transports to avoid `421 Misdirected Request` behind reverse proxies.

---

## Changelog (recent)

- **v1.8.0** — Node maintenance and HA: `plan_node_evacuation`, `check_node_after_reboot`, `audit_ha_rules` (read-only); `ha_rule_set`, `ha_resource_set`, `ha_move`, `set_ha_crs` (`ENABLE_HA_CONFIG`); `set_ceph_flag`, `reboot_node` (`ENABLE_NODE_MAINTENANCE`). Proxmox Backup Server through the PVE API: `get_pbs_status`, `get_pbs_backups`. `migration_preflight` takes `min_free_gib`, blocks a target without the memory and counts containers at current use.
- **v1.7.0** — `PVE_HOST` accepts a comma-separated list of cluster nodes with automatic failover; non-idempotent requests are never resent after they may have reached the server; 5 s connect timeout; `get_cluster_status` reports `api_host`.
- **v1.6.0** — Eleven read-only operations checks: `migration_preflight`, `verify_guest`, `get_capacity_report`, `find_guest`, `check_ip_conflicts`, `get_backup_coverage`, `get_notification_health`, `get_node_updates`, `get_stale_snapshots`, `audit_container_features`, `find_oom_events`. `migrate` runs the preflight and refuses unsafe live migrations. `get_all_operation_logs` fills `vmid` from the UPID; `get_all_snapshots` adds `age_days`; `MCP_PVE_COMPACT=1` for short descriptions.
- **v1.5.8** — New `get_task_log` and `get_backup_failures`. A backup job only reported `job errors`; the guest that failed and the reason were in the task log, which no tool could read.
- **v1.5.7** — SSE mode also serves Streamable HTTP at `/mcp` (stateless), so clients no longer get stuck on an uninitialized session after an SSE reconnect (all calls failing with `-32602`); API-key check moved to plain ASGI middleware (constant-time compare), ending the `AssertionError` logged on every SSE disconnect.
- **v1.5.6** — Fix inaccurate VM memory usage (`memory_used_mb` could exceed total); balloon-derived in-guest usage + clamp; merged IP/memory lookups into one concurrent wave.
- **v1.5.5** — Removed `include_details` from `get_ceph_status` to prevent token overflow.
- **v1.5.4** — FastMCP wrapper for SSE/streamable-HTTP (fixes `421`); optional `--api-key` Bearer auth.
- **v1.5.3** — SSE transport; usage metrics (CPU/mem/net) in `list_vms` / `list_containers`.
- **v1.5.1–1.5.2** — Guest-agent IP in list tools; removed schema `maximum` on pagination params.
- **v1.5.0** — Consolidated 28 VM/CT tools into 15 unified tools (auto type detection).
