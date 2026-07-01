# Zimbra MCP Server

**Version:** 1.9.2
**Author:** Jason Cheng (co-created with Claude Code)
**License:** MIT
**Last Updated:** 2026-03-02
**Repository:** [github.com/jasoncheng7115/jasontools-mcp](https://github.com/jasoncheng7115/jasontools-mcp)

FastMCP-based integration for Zimbra Collaboration Suite, providing comprehensive email system monitoring and administration capabilities through natural language interactions.

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Available Tools](#available-tools)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Version History](#version-history)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Core Capabilities

- **Account Management** - View info, quota, aliases, unlock accounts, list/count accounts
- **Distribution Lists** - Query DL information and member lists
- **Mail Queue Monitoring** - Statistics, message listing, search capabilities
- **Server Monitoring** - Service status, health checks, server inventory
- **Mailbox Statistics** - Storage analysis and usage rankings
- **System Health** - Comprehensive health diagnostics and reporting

### Key Features

- 🔐 Secure SOAP API integration with authentication
- ⚡ Smart caching system with configurable TTL
- 🔄 Automatic retry mechanism with exponential backoff
- 📊 Real-time service status monitoring
- 🛡️ Safety checks (e.g., unlockAccount only works on locked accounts)
- 🌐 Multi-server support
- 📝 Detailed logging and debugging capabilities

---

## 🔐 Authentication Modes

mcp_zimbra supports two authentication modes:

### Admin Mode (44 base + 5 mail_read)

Full access to all Zimbra administration tools. Mail read tools require `ZIMBRA_ENABLE_MAIL_READ=true`.

```bash
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="admin_password"
export ZIMBRA_ENABLE_MAIL_READ="true"   # Optional: enable mail read tools
```

### User Mode (13 base + 5 mail_read)

Personal mailbox access only. Authenticates as a regular user via the web client API.

```bash
export ZIMBRA_MAIL_URL="https://mail.example.com"
export ZIMBRA_USER_EMAIL="user@example.com"
export ZIMBRA_USER_PASS="user_password"
export ZIMBRA_ENABLE_MAIL_READ="true"   # Optional: enable mail read tools
```

### Feature Toggle: Mail Read

`ZIMBRA_ENABLE_MAIL_READ` controls 5 mail reading tools (default: `false`):

| Tool | Description |
|------|-------------|
| `searchMail` | Search mailbox by subject/sender/recipient/date/content |
| `getMailDetail` | Get full message content, headers, attachment list |
| `getConversation` | Get all messages in a conversation thread |
| `listFolders` | List mailbox folders |
| `getMailAttachment` | Download email attachment to local file |

**User Mode Tools (always available):**
| Category | Tools |
|----------|-------|
| Mail Write | saveDraft, searchContacts |
| Directory | searchGal |
| Trace | 6 jt_zmmsgtrace tools (if configured) |
| System | health_check, clear_cache, cache_stats, getVersionInfo |

**Claude Desktop (User Mode):**
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

> **Note**: If both admin and user credentials are provided, admin mode takes priority.

---

## 📦 Requirements

### System Requirements

- **Python**: 3.8 or higher
- **Zimbra**: 8.x, 9.x, or 10.x (tested on 10.1.10 FOSS)
- **Network**: HTTPS access to Zimbra Admin API (default port 7071)

### Python Dependencies

```bash
pip install mcp requests urllib3
```

Or use the provided requirements (if available):
```bash
pip install -r requirements.txt
```

---

## 🚀 Installation

### 1. Clone or Download

```bash
cd /path/to/your/mcp/servers/
git clone <repository-url> mcp_zimbra
# or download and extract the files
```

### 2. Install Dependencies

```bash
cd mcp_zimbra
pip install mcp requests urllib3
```

### 3. Configure Environment Variables

```bash
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="your_admin_password"
```

Optional environment variables:
```bash
export ZIMBRA_VERIFY_SSL=false          # Disable SSL verification (not recommended for production)
export ZIMBRA_CACHE_DURATION=300        # Cache TTL in seconds (default: 300)
export ZIMBRA_REQUEST_TIMEOUT=30        # API timeout in seconds (default: 30)
export ZIMBRA_RETRY_ATTEMPTS=3          # Retry attempts (default: 3)
```

Optional jt_zmmsgtrace integration (for mail tracing):
```bash
export JT_ZMMSGTRACE_URL="http://localhost"      # jt_zmmsgtrace base URL (default: http://localhost)
export JT_ZMMSGTRACE_PORT="8989"                 # jt_zmmsgtrace port (default: 8989)
export JT_ZMMSGTRACE_API_KEY="your-api-key"      # jt_zmmsgtrace API key (required for mail tracing)
```

**Note**: Mail tracing tools (jt_zmmsgtrace_*) will only be available if JT_ZMMSGTRACE_API_KEY is configured.

### 4. Configure Claude Desktop

Add to your Claude Desktop MCP configuration file (`claude_desktop_config.json`):

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

**Note**: The jt_zmmsgtrace settings are optional. If not configured, mail tracing tools will not be available, but all other Zimbra tools will work normally.

**Important**: Restart Claude Desktop after modifying the configuration.

---

## ⚙️ Configuration

### Configuration Priority

The server uses the following priority for configuration:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Default values** (lowest priority)

### Configuration Options

#### Zimbra Configuration (Required)

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Admin URL | `ZIMBRA_ADMIN_URL` | Required | Zimbra Admin SOAP API endpoint |
| Admin User | `ZIMBRA_ADMIN_USER` | Required | Admin account username |
| Admin Password | `ZIMBRA_ADMIN_PASS` | Required | Admin account password |
| SSL Verification | `ZIMBRA_VERIFY_SSL` | `true` | Enable/disable SSL certificate verification |
| Cache Duration | `ZIMBRA_CACHE_DURATION` | `300` | Cache TTL in seconds |
| Request Timeout | `ZIMBRA_REQUEST_TIMEOUT` | `30` | API request timeout in seconds |
| Retry Attempts | `ZIMBRA_RETRY_ATTEMPTS` | `3` | Number of retry attempts for failed requests |

#### jt_zmmsgtrace Configuration (Optional - for Mail Tracing)

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Base URL | `JT_ZMMSGTRACE_URL` | `http://localhost` | jt_zmmsgtrace service base URL |
| Port | `JT_ZMMSGTRACE_PORT` | `8989` | jt_zmmsgtrace service port |
| API Key | `JT_ZMMSGTRACE_API_KEY` | (none) | API key for authentication (required for mail tracing) |

**Note**: If `JT_ZMMSGTRACE_API_KEY` is not set, the 6 mail tracing tools will not be available, but all other Zimbra tools will function normally.

---

## 💻 Usage

### Through Claude Desktop

Once configured, you can interact with Zimbra through natural language:

```
請查詢 user@example.com 的帳號資訊
請查看 mail.example.com 伺服器的健康狀況
請解鎖 locked_user@example.com 帳號
請列出所有郵件佇列中的訊息
```

### Direct Command Line (for testing)

```bash
cd /path/to/mcp_zimbra
python3 mcp_zimbra.py
```

### SSE Mode

Run as an SSE server for Chatbox / legacy MCP clients:

```bash
python3 mcp_zimbra.py --transport sse --host 0.0.0.0 --port 8010 --api-key "your-api-key"
```

Endpoint: `http://<host>:<port>/sse`

### Streamable HTTP Mode

Run as an HTTP server for modern MCP clients:

```bash
python3 mcp_zimbra.py --transport streamable-http --host 0.0.0.0 --port 8000 --api-key "your-api-key"
```

Endpoint: `http://<host>:<port>/mcp`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--transport` | `stdio` | `stdio`, `sse`, or `streamable-http` |
| `--host` | `127.0.0.1` | HTTP listen address (sse / streamable-http) |
| `--port` | `8000` | HTTP listen port (sse / streamable-http) |
| `--api-key`, `-k` | *(none)* | API key for SSE/HTTP auth (or `MCP_API_KEY` env var) |

---

## 🛠️ Available Tools

### Account Management (6 tools)

| Tool | Description |
|------|-------------|
| `getAccountInfo` | Get account information (quota, status, creation date, etc.) |
| `getAccountQuota` | Get account quota and usage statistics |
| `getAccountAliases` | Get all aliases for an account |
| `unlockAccount` | Unlock a locked account (only works on locked accounts) |
| `getAllAccounts` | List all accounts with filtering and pagination |
| `getAccountCount` | Count accounts by domain or status |

### Distribution Lists (3 tools)

| Tool | Description |
|------|-------------|
| `getDLInfo` | Get distribution list information |
| `getDLMembers` | Get distribution list members with pagination |
| `getAllDistributionLists` | List all distribution lists with domain filtering and pagination |

### Mail Queue (3 tools)

| Tool | Description |
|------|-------------|
| `getQueueStat` | Get mail queue statistics by server |
| `getQueueList` | List messages in mail queue |
| `searchMailQueue` | Search mail queue by sender or recipient |

### Statistics (2 tools)

| Tool | Description |
|------|-------------|
| `getMailboxStats` | Get mailbox statistics across all servers |
| `getQuotaUsage` | **⚡ FAST** - Get account quota usage with sorting (single API call) |

### System & Domain (9 tools)

| Tool | Description |
|------|-------------|
| `getServerList` | Get list of all Zimbra servers |
| `getServerStatus` | Get real-time service status for servers |
| `getActiveSessions` | **⚡ NEW** - Get currently logged-in users (SOAP/IMAP/Admin sessions) |
| `getDomainList` | Get list of all email domains |
| `getDomainInfo` | Get detailed domain information |
| `getCOSList` | Get list of Class of Service definitions |
| `getCOSInfo` | Get detailed COS info with regex attribute filtering and pagination |
| `countAccountByCOS` | **⚡ NEW** - Count accounts by COS with statistics |
| `getVersionInfo` | **⚡ NEW** - Query Zimbra version information |

### Rights & Permissions (3 tools)

| Tool | Description |
|------|-------------|
| `getGrants` | **⚡ NEW** - Query rights/permissions granted to or by an entity |
| `checkRight` | **⚡ NEW** - Check if a grantee has a specific right on a target |
| `getDelegates` | **⚡ NEW** - Query delegate settings for an account |

### Bulk Audit (5 tools)

| Tool | Description |
|------|-------------|
| `getAllDelegations` | List all sendAs/sendOnBehalfOf delegation rights in one call |
| `getAllForwardings` | List all accounts with mail forwarding rules |
| `getAllOutOfOffice` | List all accounts with out-of-office auto-reply enabled |
| `getInactiveAccounts` | List accounts inactive for N+ days |
| `searchByAttribute` | Generic LDAP filter search for any attribute |

### Mail Search (4 tools)

| Tool | Description |
|------|-------------|
| `searchMail` | Search mailbox by subject/sender/recipient/body/date (fuzzy folder match) |
| `getMailDetail` | Get full message with body, headers, attachment list |
| `getConversation` | Get all messages in a conversation thread |
| `getMailAttachment` | Download attachment to local file (~/Downloads) |
| `listFolders` | List mailbox folders with optional keyword filter |
| `saveDraft` | Save new email or reply/forward as draft for review |
| `searchContacts` | Search user's personal address book / contacts |

### Directory & Search (1 tool)

| Tool | Description |
|------|-------------|
| `searchGal` | Search Global Address List (GAL) |

### Advanced DL Features (1 tool)

| Tool | Description |
|------|-------------|
| `getDLMembership` | **⚡ NEW** - Query which DLs an account/DL belongs to (nested relations) |

### Utilities (3 tools)

| Tool | Description |
|------|-------------|
| `health_check` | Comprehensive system health diagnostics |
| `clear_cache` | Clear all cached API responses |
| `cache_stats` | Get cache usage statistics |

**Total: 49 tools in admin mode** (44 base + 5 mail_read) — 6 Account + 3 Distribution Lists + 3 Mail Queue + 2 Statistics + 9 System + 3 Rights + 5 Bulk Audit + 5 Mail Read† + 2 Mail Write + 1 Directory + 1 Advanced DL + 3 Utilities + 6 jt_zmmsgtrace
**Total: 18 tools in user mode** (13 base + 5 mail_read) — 5 Mail Read† + 2 Mail Write + 1 Directory + 3 Utilities + 1 Version + 6 jt_zmmsgtrace

†Mail Read tools require `ZIMBRA_ENABLE_MAIL_READ=true`

---

## 🧪 Testing

### Quick Health Check

```bash
cd /path/to/mcp_zimbra

# Set environment variables
export ZIMBRA_ADMIN_URL="https://mail.example.com:7071/service/admin/soap"
export ZIMBRA_ADMIN_USER="admin@example.com"
export ZIMBRA_ADMIN_PASS="your_password"

# Run status test
python3 quick_test_status.py
```

**Expected output:**
```
✅ mailbox        : running
✅ mta            : running
✅ ldap           : running
❌ imapd          : stopped
...
Summary: X running, Y stopped, 0 unknown
✅ Status looks correct!
```

### Test unlockAccount Function

```bash
python3 test_unlock_account.py user@example.com
```

### Test with Examples

```bash
python3 examples_unlock_account.py
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Authentication Failed

**Error:** `No authToken in response`

**Solution:**
- Verify `ZIMBRA_ADMIN_USER` and `ZIMBRA_ADMIN_PASS` are correct
- Ensure admin user has API access permissions
- Check if admin URL is correct (should include port 7071)

#### 2. SSL Certificate Error

**Error:** `SSLError: certificate verify failed`

**Solution:**
```bash
export ZIMBRA_VERIFY_SSL=false
```

**Note:** Only disable SSL verification in test environments.

#### 3. Empty Server Status

**Error:** `total_servers: 0` or empty services array

**Solution:**
- Run `getServerList()` first to verify servers are accessible
- Check if admin user has permissions to query service status
- Verify Zimbra version compatibility (8.x, 9.x, 10.x supported)

#### 4. Connection Timeout

**Error:** `Request timeout`

**Solution:**
- Increase timeout: `export ZIMBRA_REQUEST_TIMEOUT=60`
- Check network connectivity to Zimbra server
- Verify firewall rules allow access to port 7071

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Or set environment variable:
```bash
export ZIMBRA_LOG_LEVEL=DEBUG
```

---

## 📜 Version History

### v1.9.2 (2026-03-02) - Current
**OPTIMIZATION**: Weak LLM compatibility
- **NEW HELPER**: `tool_response()` — compact JSON output with `usage_hint` injection
- All `json.dumps` calls migrated to `tool_response()` (removes `indent=2`, saves ~30% tokens)
- `USAGE_HINTS` dict: per-tool one-line guidance for weaker models (50+ tools)
- `getServerStatus`: NEW PARAM `summary` (default: true) — compact output, problem services only
- `getConversation`: NEW PARAM `limit` (default: 25) — truncates long threads, keeps newest
- `health_check`: replaced full services array with `stopped_service_names` list

### v1.9.1 (2026-02-26)
**FIX**: SSE/streamable-http transport fixes
- Disable DNS rebinding protection (fixes 421 Misdirected Request from external clients)
- Use uvicorn directly for host/port binding (FastMCP.run() limitation)
- Add API key authentication for SSE/HTTP transports (`--api-key` / `MCP_API_KEY`)

### v1.9.0 (2026-02-26)
**ENHANCEMENT**: `searchByAttribute` extra_attrs parameter
- New param `extra_attrs`: comma-separated attribute names to include beyond default fields
- Saves tokens — only returns requested extra attributes (e.g. `zimbraNotes,description`)

### v1.8.9 (2026-02-13)
**BUG FIX**: Accurate account counting via pagination
- `getAccountCount`: fixed undefined variable crash + wrong counts (Zimbra doesn't return `searchTotal`; now uses paginated element counting)
- `countAccountByCOS`: same fix — paginated counting instead of `limit=1` (was returning 0 for all COS)

### v1.8.8 (2026-02-13)
**OPTIMIZATION**: Server-side filtering audit
- `countAccountByCOS`: rewritten to use LDAP per-COS query (was fetching ALL accounts — 5-50MB waste)
- `getAllAccounts`: `status_filter` now server-side LDAP query (was client-side, pagination was inaccurate)

### v1.8.7 (2026-02-13)
**ENHANCEMENT**: `getAccountCount` server-side filtering
- Rewritten to use `SearchDirectoryRequest` with LDAP filter (was client-side iteration)
- **NEW PARAM**: `query` — arbitrary LDAP filter (e.g. `(zimbraMailHost=mail1.example.com)`)
- `status_filter` + `query` auto-combined with AND
- Returns only count, drastically reduces token usage

### v1.8.6 (2026-02-13)
**FEATURE**: Added SSE transport support
- `--transport` now accepts `stdio`, `sse`, `streamable-http`
- SSE transport for legacy MCP clients, backed by mcp SDK 1.22.0 native `run_sse_async()`

### v1.8.5 (2026-02-13)
**FEATURE**: Mail read tools gated by `ZIMBRA_ENABLE_MAIL_READ` toggle
- `searchMail`, `getMailDetail`, `getConversation`, `listFolders`, `getMailAttachment` only registered when `ZIMBRA_ENABLE_MAIL_READ=true` (default: `false`)
- Allows deployment without mail reading capability for security-sensitive environments
- Tool counts: admin 44+5 / user 13+5 (base + mail_read)

### v1.8.4 (2026-02-13)
**ROBUSTNESS**: Input validation guards for weaker LLM compatibility
- All `msg_id`/`conversation_id` params validated before SOAP calls — empty values return clear error with usage example
- `searchMail` response includes `usage_hint` field guiding how to use result IDs
- Docstring ID examples updated to realistic format (was `"12345"`, now `"894727"`)
- Prevents weaker models (e.g. gpt-oss:120b) from sending empty params

### v1.8.3 (2026-02-12)
**ENHANCEMENT**: saveDraft auto-quotes original message on reply/forward
- Reply drafts auto-append "On {date}, {from} wrote:" + `> ` quoted original body
- Forward drafts auto-append "Forwarded message" header + original body
- LLM only needs to provide reply text; original quoting is handled automatically
- Response includes `note` field telling LLM that quoting was already done

### v1.8.2 (2026-02-12)
**FIX**: JSON output CJK characters as readable text
- **FIX**: Global `ensure_ascii=False` — CJK characters output as readable text instead of `\uXXXX` escapes
- Prevents LLM misreading similar-looking Chinese characters (e.g. 諾→誠, 殷→般)

### v1.8.1 (2026-02-12)
**BUG FIX**: searchMail date range was exclusive (off-by-one)
- **FIX**: `date_from`/`date_to` now truly inclusive — Zimbra `after:`/`before:` boundaries auto-adjusted
- Querying "today's mail" now returns correct results

### v1.8.0 (2026-02-11)
**DUAL AUTHENTICATION MODE**: Admin + User mode support
- **NEW**: User mode authentication via `urn:zimbraAccount` (regular user credentials)
- **NEW CONFIG**: `ZIMBRA_USER_EMAIL`, `ZIMBRA_USER_PASS` for user mode
- **NEW**: Conditional tool registration — admin-only tools hidden in user mode
- **NEW**: User mode provides up to 18 tools for personal mailbox access
- **UNCHANGED**: Admin mode retains up to 49 tools with zero code path changes
- User mode tools: searchMail, getMailDetail, getConversation, getMailAttachment, listFolders, saveDraft, searchContacts, searchGal, health_check, clear_cache, cache_stats, getVersionInfo, + 6 jt_zmmsgtrace tools

### v1.7.0 (2026-02-11)
**MAIL, CONTACTS, DRAFTS & FOLDERS**: Full mailbox search, contacts, draft composition, folder management
- **NEW CATEGORY**: Mail & Contacts (7 tools)
  - `searchMail()` - Search mailbox by subject/sender/recipient/body/date (fuzzy folder match)
  - `getMailDetail()` - Get full message with body, headers, attachments
  - `getConversation()` - Get all messages in a conversation thread
  - `getMailAttachment()` - Download attachment to local file via REST
  - `listFolders()` - List mailbox folders with optional keyword filter
  - `saveDraft()` - Save new email or reply/forward as draft for review
  - `searchContacts()` - Search user's personal address book / contacts
- **NEW HELPER**: `query_zimbra_mail_api()` - Admin-delegated mail namespace SOAP requests
- **NEW CONFIG**: `ZIMBRA_MAIL_URL` - Web client URL for REST operations (attachment download)
- Total tools: 49

### v1.6.0 (2026-02-09)
**BULK AUDIT TOOLS**: LDAP-based single-call audit queries
- **NEW CATEGORY**: Bulk Audit (5 tools)
  - `getAllDelegations()` - List all sendAs/sendOnBehalfOf rights
  - `getAllForwardings()` - List all mail forwarding rules
  - `getAllOutOfOffice()` - List all auto-reply enabled accounts
  - `getInactiveAccounts()` - List accounts inactive for N+ days
  - `searchByAttribute()` - Generic LDAP filter search
- **FIX**: `getGrants()` without target_name no longer sends invalid `<target>` element
- Total tools: 42

### v1.5.0 (2026-02-09)
**COMPATIBILITY & TRANSPORT**: gpt-oss:120b compatibility + Streamable HTTP support
- **NEW**: Streamable HTTP transport mode (`--transport streamable-http`)
- **REMOVED**: `getTopMailboxesBySize()` (deprecated, use `getQuotaUsage()`)
- **FIX**: `getAccountQuota()` now uses UUID for GetMailboxRequest (was 500 error)
- **FIX**: `unlockAccount()` handles both "locked" and "lockout" states with fresh query
- **FIX**: `getQueueList()`/`searchMailQueue()` sender field uses full address (was domain-only)
- **FIX**: `searchMailQueue()` searches all 5 queues when queue_name not specified
- **FIX**: `getGrants()` default target_type changed to "account"
- **RENAME**: `max_results` → `limit` in 5 tools for consistent parameter naming
- **REWRITE**: All 37 tool docstrings with proper `Args: param_name:` format for LLM compatibility
- Total tools: 37

### v1.4.0 (2025-11-28)
**MAJOR RELEASE**: Added 12 new advanced query and monitoring tools
- **NEW CATEGORY**: Rights & Permissions (3 tools)
  - `getGrants()` - Query rights/permissions granted to or by an entity
  - `checkRight()` - Check if a grantee has a specific right on a target
  - `getDelegates()` - Query delegate settings for an account
- **NEW CATEGORY**: Directory & Search (1 tool)
  - `searchGal()` - Search Global Address List via SearchDirectory API
- **NEW CATEGORY**: COS Statistics (1 tool)
  - `countAccountByCOS()` - Count accounts by COS with statistics
- **NEW CATEGORY**: Advanced DL (1 tool)
  - `getDLMembership()` - Query which DLs an account/DL belongs to (nested relations)
- **NEW CATEGORY**: System Information (1 tool)
  - `getVersionInfo()` - Query Zimbra version information
- **BUG FIXES**:
  - Fixed `searchGal()` to use SearchDirectory API (more reliable)
  - Fixed `getGrants()` parsing to support multiple XML formats and attribute names
  - Added pagination info to `searchGal()`
- **REMOVED**: `getAllLocales()`, `getAllTimezones()`, `searchAutoProvDirectory()`, `getLicenseInfo()`, `verifyCertKey()`, `getCert()`, `getCSR()` (not commonly needed or Network Edition only)
- **Total tools increased from 31 to 38** (23% increase!)
- Perfect for: Security audits, permission management, GAL searches, system inventory

### v1.3.1 (2025-11-28)
**ENHANCEMENT**: Added pagination support to getCOSInfo()
- **NEW PARAMETERS**: `limit` and `offset` for attribute pagination
- Prevents context overflow when querying all COS attributes
- Example: `getCOSInfo("default", attr_filter=".*", limit=50)` returns first 50 attributes
- Returns `matched_attributes` (after filtering) and `returned_attributes` (after pagination)
- Adds `display_message` showing pagination status (e.g., "顯示前 50 筆（共 498 筆，還有 448 筆未顯示）")
- Attributes are sorted alphabetically for consistent pagination
- Perfect for browsing large attribute sets without overwhelming context

### v1.3.0 (2025-11-27)
**NEW FEATURE**: Added getActiveSessions() for real-time session monitoring
- **NEW TOOL**: `getActiveSessions()` - Query currently logged-in users
- Shows SOAP (web client), IMAP, POP3, and admin sessions
- **Fast mode**: Get session counts only (summary)
- **Detailed mode**: List all active users with session details
- Real-time data (no caching) for accurate monitoring
- Perfect for: "誰現在正在登入？", "有多少人正在使用？"
- Total tools increased from 31 to 32

### v1.2.6 (2025-11-27)
**UX IMPROVEMENT**: Added display_message to all pagination functions
- **NEW**: `create_pagination_message()` helper function
- All pagination functions now show clear messages like:
  - "顯示 10 筆（共 10 筆，已全部顯示）"
  - "顯示前 100 筆（共 250 筆，還有 150 筆未顯示）"
- **Updated functions**: getAllAccounts, getAllDistributionLists, getDLMembers, getQuotaUsage
- **Bonus fix**: getAllDistributionLists had same 'more' bug - now fixed!
- Users no longer confused about whether they're seeing all results

### v1.2.5 (2025-11-27)
**BUG FIX**: Fixed getAccountCount() returning incorrect count (CRITICAL)
- **Bug**: `getAccountCount()` showed 1 account when actually 10 exist
- **Root cause**: `getAllAccounts()` was using 'more' (boolean) as count!
- **Fixed**: getAllAccounts now correctly parses searchTotal attribute
- **Enhanced**: getAccountCount now uses full iteration fallback for accuracy

### v1.2.4 (2025-11-27)
**SAFETY**: Enhanced getCOSInfo() with safe-by-default behavior
- **Without filter**: Returns only ~30 common attributes (prevents context overflow)
- **With filter**: Returns filtered attributes (targeted queries)
- Use `attr_filter=".*"` to get all attributes (with warning)
- Response includes helpful suggestions for common filter patterns
- Safe by default - no more accidental context overflow!

### v1.2.3 (2025-11-27)
**NEW TOOL**: Added getCOSInfo() with attribute filtering
- Query specific COS by name with regex attribute filtering
- Solves context overflow issue when querying COS settings
- Use `attr_filter="password"` to get only password-related settings
- Examples: `getCOSInfo("default", attr_filter="password|quota|limit")`
- Total tools increased from 30 to 31

### v1.2.2 (2025-11-27)
**PERFORMANCE**: Added getQuotaUsage() for fast account storage ranking
- **NEW TOOL**: `getQuotaUsage()` - Single API call, up to 1000x faster!
- Uses Zimbra's `GetQuotaUsageRequest` API (optimized for bulk queries)
- Supports sorting by totalUsed, percentUsed, quotaLimit
- Supports pagination (limit, offset) for large systems
- `getTopMailboxesBySize()` now uses `getQuotaUsage()` internally (backward compatible)
- Total tools increased from 29 to 30

### v1.2.1 (2025-11-27)
**BUG FIX**: Fixed dynamic distribution list support
- `getAllDistributionLists()` now queries both static DLs and dynamic groups
- Fixed query to include `types="distributionlists,dynamicgroups"`
- Added `memberURL` attribute detection for accurate dynamic group identification
- Applied fix to `getDLInfo()` and `getDLMembers()` as well

### v1.2.0 (2025-11-27)
**NEW FEATURE**: Added jt_zmmsgtrace integration
- 6 new tools for mail tracing via jt_zmmsgtrace API
- Search by sender, recipient, message ID, host, time
- Comprehensive mail delivery path tracking
- Support for regex patterns in searches
- Total tools increased from 23 to 29

### v1.1.7 (2025-11-27)
**BUG FIX**: Fixed getAllDistributionLists() memberCount issue
- Added `include_member_count` parameter (default: False)
- When False (default): Returns null for memberCount (fast)
- When True: Queries actual member count per DL (slower but accurate)
- Fixed incorrect Zimbra attribute usage that always returned 0

### v1.1.6 (2025-11-27)
**NEW FEATURE**: Added getAllDistributionLists() function
- List all distribution lists in the system
- Domain filtering support (single or multiple domains)
- Pagination support with offset and limit
- Returns DL details: name, displayName, dynamic, description, memberCount
- Total tools increased from 22 to 23

### v1.1.5 (2025-11-27)
**MAJOR FIX**: Completely rewrote service status parsing
- Fixed incorrect XML parsing (was looking for wrong element structure)
- Discovered actual Zimbra format: `<status service="X">1</status>`
- Confirmed status codes: "1"=running, "0"=stopped
- Added timestamp conversion to ISO format
- Services now show correct running/stopped status

### v1.1.3 (2025-11-27)
**Enhanced unlockAccount with safety checks**
- Only unlocks accounts in 'locked' status
- Returns 'skipped' status for non-locked accounts
- Prevents accidental status modification

### v1.1.1 (2025-11-27)
**Fixed getServerStatus with improved XML parsing**
- Added multiple SOAP request format fallback strategies
- Enhanced XML parsing with 3 different parsing strategies
- Improved compatibility with Zimbra 10.x FOSS edition

### v1.1.0 (2025-01-27)
- Added account unlock functionality
- Added mail queue search capabilities
- Added mailbox statistics and storage rankings
- Enhanced queue monitoring features

### v1.0.0 (2025-01-27)
Initial release with basic functionality

---

## 🤝 Contributing

### Reporting Issues

If you encounter any issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Enable debug logging and capture the output
3. Include your Zimbra version (`zmprov -v`)
4. Create an issue with detailed information

### Development

To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

MIT License

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

## 📚 Additional Resources

### Documentation Files

- `FIX_v1.1.5_SUMMARY.md` - Detailed v1.1.5 fix summary
- `QUICK_TEST_v1.1.5.md` - Quick testing guide
- `UNLOCK_ACCOUNT_FIX.md` - unlockAccount feature documentation
- `TESTING_GUIDE.md` - Comprehensive testing guide

### Test Scripts

- `quick_test_status.py` - Quick service status test
- `test_unlock_account.py` - unlockAccount function test
- `examples_unlock_account.py` - Usage examples

### Related Links

- [Zimbra SOAP API Documentation](https://wiki.zimbra.com/wiki/SOAP_API_Reference_Material)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [Claude Desktop MCP Configuration](https://docs.claude.com/en/docs/claude-code/mcp)

---

## 📞 Support

For questions or support:

- Review the documentation in this repository
- Check the troubleshooting section
- Create an issue with detailed information

---

**Happy Monitoring!** 🚀

_This MCP server makes Zimbra administration easier through natural language interactions with Claude._
