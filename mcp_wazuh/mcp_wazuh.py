#!/usr/bin/env python3
"""
MCP server for Wazuh SIEM API - v1.3.8
===============================================================================
Author: Jason Cheng (co-created with Claude Code)
Created: 2025-11-23
Last Modified: 2026-04-24
License: MIT
Repository: https://github.com/jasoncheng7115/jasontools-mcp

Reference:
This implementation is inspired by and references the design patterns from:
- mcp-server-wazuh (Rust implementation) by Gianluca Brigandi
  Repository: https://github.com/gbrigandi/mcp-server-wazuh
- mcp_librenms_sample.py architecture by Jason Cheng

FastMCP-based Wazuh SIEM integration providing comprehensive security monitoring
and analysis capabilities through natural language interactions.

Features:
- Real-time security alert monitoring and analysis
- Comprehensive vulnerability assessment across all agents
- Agent lifecycle management and health monitoring
- Security rule configuration and compliance tracking
- Detailed system statistics and performance insights
- Advanced log analysis and forensic capabilities
- Cluster health monitoring and node management
- Multi-framework compliance support (GDPR, HIPAA, PCI DSS, NIST)

Installation:
pip install mcp requests urllib3

Configuration Methods (Priority: CLI Args > Environment Variables > Defaults):

1. Command Line Arguments (Recommended):
   python3 mcp_wazuh.py \\
     --manager-host "192.168.1.100" \\
     --manager-user "wazuh" \\
     --manager-pass "wazuh" \\
     --indexer-host "192.168.1.100" \\
     --indexer-user "admin" \\
     --indexer-pass "admin"

   Available arguments:
   --manager-host          Wazuh Manager API hostname/IP
   --manager-port          Wazuh Manager API port (default: 55000)
   --manager-user          Wazuh Manager API username
   --manager-pass          Wazuh Manager API password
   --indexer-host          Wazuh Indexer hostname/IP
   --indexer-port          Wazuh Indexer port (default: 9200)
   --indexer-user          Wazuh Indexer username
   --indexer-pass          Wazuh Indexer password
   --use-ssl               Enable SSL/TLS (true/false, default: false)
   --protocol              Connection protocol (http/https, default: https)
   --cache-duration        Cache duration in seconds (default: 300)
   --request-timeout       Request timeout in seconds (default: 30)
   --retry-attempts        Retry attempts for failed requests (default: 3)
   --transport             MCP transport: stdio, sse, or streamable-http (default: stdio)
   --host                  HTTP server host for sse/streamable-http (default: 0.0.0.0)
   --port                  HTTP server port for sse/streamable-http (default: 8000)
   --api-key               API key for authentication (or set MCP_API_KEY env var)
   --severity-low-max      Max rule level for Low severity label (default: 6)
   --severity-medium-max   Max rule level for Medium severity label (default: 11)
   --severity-high-max     Max rule level for High severity label (default: 13)

2. Environment Variables:
   WAZUH_API_HOST          Manager hostname
   WAZUH_API_PORT          Manager port
   WAZUH_API_USERNAME      Manager username
   WAZUH_API_PASSWORD      Manager password
   WAZUH_INDEXER_HOST      Indexer hostname
   WAZUH_INDEXER_PORT      Indexer port
   WAZUH_INDEXER_USERNAME  Indexer username
   WAZUH_INDEXER_PASSWORD  Indexer password
   WAZUH_VERIFY_SSL        Enable SSL verification
   WAZUH_TEST_PROTOCOL     Connection protocol
   WAZUH_CACHE_TTL         Cache TTL
   WAZUH_TIMEOUT           Request timeout
   WAZUH_MAX_RETRIES       Retry attempts
   WAZUH_SEVERITY_LOW_MAX     Max rule level for Low severity (default: 6)
   WAZUH_SEVERITY_MEDIUM_MAX  Max rule level for Medium severity (default: 11)
   WAZUH_SEVERITY_HIGH_MAX    Max rule level for High severity (default: 13)

Usage:
chmod +x mcp_wazuh.py

# stdio mode (default, for Claude Desktop / CLI integration):
python3 mcp_wazuh.py --manager-host ... --indexer-host ...

# SSE mode (for Chatbox / legacy MCP clients):
python3 mcp_wazuh.py --transport sse --host 0.0.0.0 --port 8000 \
  --api-key YOUR_SECRET_KEY --manager-host ... --indexer-host ...

# streamable-http mode (for network-based / multi-client access):
python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \
  --api-key YOUR_SECRET_KEY --manager-host ... --indexer-host ...

python3 mcp_wazuh.py --help

Changelog:
  (dates in YYYY-MM-DD. Pre-v1.3.5 dates without exact records are estimated
   from release cadence and feature scope; they may drift by a few days from
   actual shipping dates.)

  v1.3.8 (2026-04-24) - Post-v1.3.7 refinements + multi-digit agent ID verified
    - vulnerabilitySummary cve_filter: now uses wildcard (case-insensitive) so partial
      matches like "CVE-2022" work against the 4.8+ states index (keyword field)
    - vulnerabilitySummary fallback semantics tightened: only fall back to wazuh-alerts-*
      when the states query FAILS (legacy Wazuh pre-4.8). An empty states result is
      authoritative ("agent has no active CVEs"); no more source=alerts confusion
    - normalize_agent_identifier: explicitly verified 5/6/7-digit agent IDs against
      live Wazuh API (e.g. "12345", "123456", "9999999"); f-string minimum-width
      format pads to 3 digits but does not truncate longer IDs
    - Docstring updated to document multi-digit support
  v1.3.7 (2026-04-24) - Wazuh 4.8+ vulnerability source + listAgents status=all fix
    - vulnerabilitySummary: now queries wazuh-states-vulnerabilities-* (4.8+ authoritative
      current-state index) first, with automatic fallback to wazuh-alerts-* data.vulnerability
      for legacy deployments. Output schema preserved.
    - listAgents: when status_filter="all" or "", no longer send status=all to Wazuh API
      (which rejects it with 400); just omits the status query param.
  v1.3.6 (2026-04-24) - Bug fixes, pagination, severity config, performance
    - alertSummary: default max_results lowered 300 -> 50 (context-friendly for gpt-oss:120b / GAIVIS)
    - normalize_agent_identifier: removed hard 999 cap; now supports agent IDs up to Wazuh max (15k+)
      (fixes vulnerabilitySummary, agentProcesses, agentPorts, agentDetail, agentHardware,
       agentPackages, agentNetworks, agentSCA, logCollectorStats for agent ID >= 1000)
    - listAgents: added offset parameter and pagination block (has_more, next_offset)
    - clusterHealth: fixed /cluster/status parsing (enabled/running are directly under data,
      not in affected_items), fixed /cluster/healthcheck (n_connected_nodes field does not
      exist in Wazuh 4.x API; use total_affected_items), added per-node info to output
    - agentsWithAlerts: removed expensive top_hits sub-aggregation, replaced with max_timestamp;
      raised max_agents cap 100 -> 500; docstring now hints min_level for > 3d time ranges
    - severity labels: thresholds are now configurable via CLI / env var
      (--severity-low-max / --severity-medium-max / --severity-high-max,
       WAZUH_SEVERITY_LOW_MAX / _MEDIUM_MAX / _HIGH_MAX)
      defaults aligned with Wazuh Dashboard VIS common thresholds:
      Low 0-6, Medium 7-11, High 12-13, Critical 14-15
  v1.3.5 (2026-04-23) - Fix SSE/Streamable-HTTP for external clients (Chatbox)
    - Disabled DNS rebinding protection (fixes 421 Misdirected Request)
    - Replaced FastMCP.run() with uvicorn for SSE/streamable-http (proper host/port)
    - Added --api-key / MCP_API_KEY for Bearer token authentication
  v1.3.4 (2026-04-10) - Add listGroups tool & SSE transport
    - New listGroups tool: list all agent groups with agent count per group
    - Added SSE transport support (--transport sse) for legacy MCP clients
  v1.3.3 (2026-02-20) - Severity labels & custom field queries
    - Added _severity_label() helper: converts Wazuh level 0-15 to Low/Medium/High/Critical
    - alertSummary: each alert now includes "severity" label (e.g. "High") alongside severity_level number
    - alertStatistics: severity_distribution keys now include level ranges (e.g. "Critical (level 12-15)")
    - alertStatistics: added severity_scale field explaining Wazuh 0-15 mapping
    - agentsWithAlerts: added max_severity label and severity in most_recent_alert
    - alertSummary: new custom_fields param for arbitrary field queries (= exact, ~ wildcard)
      Example: custom_fields="data.win.system.eventID=3,data.win.eventdata.image~mstsc.exe"
  v1.3.2 (2026-01-25) - Schema simplification for gpt-oss:120b tool calling compatibility
    - Replaced all Optional[type] = None with simple types + defaults (e.g. str = "", int = 0)
    - Eliminates anyOf/null union schemas in OpenAPI spec that gpt-oss:120b cannot parse
    - Matches Zimbra MCP's clean schema pattern that works correctly with 120B models
  v1.3.1 (2026-01-15) - camelCase tool naming for gpt-oss:120b compatibility
    - Renamed all tools from snake_case to camelCase (e.g. alert_summary → alertSummary)
    - gpt-oss:120b only recognizes camelCase tool names (matching Zimbra convention)
  v1.3.0 (2026-01-10) - Tool naming & docstring optimization for 120B model compatibility
    - Renamed all tools: removed get_wazuh_/search_wazuh_ prefixes for shorter, clearer names
    - Rewrote all docstrings: natural language descriptions, clear Args/Returns, one Example per tool
  v1.2.0 (2025-12-15) - Token optimization
    - Added _compact_json() helper: compact JSON output + strip None values (~30-40% token saving)
    - Trimmed all tool docstrings for 120B model compatibility
    - Removed redundant tools: get_wazuh_critical_vulnerabilities
      (use vulnerability_summary with severity_filter="Critical")
      and get_wazuh_manager_error_logs
      (use search_manager_logs with level_filter="error")
    - Deduplicated aggregation query in agents_with_alerts
    - 19 tools → 17 tools
  v1.1.0 (2025-12-01) - Transport support
    - Added --transport flag: stdio (default) and streamable-http
    - Added --host / --port flags for streamable-http mode
  v1.0.0 (2025-11-23) - Initial release
    - 19 MCP tools covering alerts, vulnerabilities, agents, rules, logs, cluster, cache
    - Dual API architecture: Manager (JWT) + Indexer (Basic Auth)
    - In-memory TTL cache, exponential backoff retry, module-level arg parsing
"""

import json
import os
import sys
import time
import argparse
import base64
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps
import logging
import hashlib
import urllib3

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wazuh-mcp-server')

# ═══════════════════════ Configuration Management ═══════════════════════

class WazuhConfig:
    """Configuration manager for Wazuh MCP Server with CLI and environment variable support"""

    def __init__(self, cli_args=None):
        """Initialize configuration with priority: CLI > ENV > Defaults"""
        # Manager configuration
        self.manager_host = self._get_value(cli_args, 'manager_host', 'WAZUH_API_HOST')
        self.manager_port = self._get_int_value(cli_args, 'manager_port', 'WAZUH_API_PORT', 55000)
        self.manager_user = self._get_value(cli_args, 'manager_user', 'WAZUH_API_USERNAME')
        self.manager_pass = self._get_value(cli_args, 'manager_pass', 'WAZUH_API_PASSWORD')

        # Indexer configuration
        self.indexer_host = self._get_value(cli_args, 'indexer_host', 'WAZUH_INDEXER_HOST')
        self.indexer_port = self._get_int_value(cli_args, 'indexer_port', 'WAZUH_INDEXER_PORT', 9200)
        self.indexer_user = self._get_value(cli_args, 'indexer_user', 'WAZUH_INDEXER_USERNAME')
        self.indexer_pass = self._get_value(cli_args, 'indexer_pass', 'WAZUH_INDEXER_PASSWORD')

        # Connection settings
        self.use_ssl = self._get_bool_value(cli_args, 'use_ssl', 'WAZUH_VERIFY_SSL', False)
        self.protocol = self._get_value(cli_args, 'protocol', 'WAZUH_TEST_PROTOCOL', 'https')

        # Performance settings
        self.cache_duration = self._get_int_value(cli_args, 'cache_duration', 'WAZUH_CACHE_TTL', 300)
        self.request_timeout = self._get_int_value(cli_args, 'request_timeout', 'WAZUH_TIMEOUT', 30)
        self.retry_attempts = self._get_int_value(cli_args, 'retry_attempts', 'WAZUH_MAX_RETRIES', 3)

        # Severity thresholds (Wazuh Dashboard VIS common defaults)
        # Low: 0..low_max, Medium: low_max+1..medium_max, High: medium_max+1..high_max, Critical: high_max+1..15
        self.severity_low_max = self._get_int_value(cli_args, 'severity_low_max', 'WAZUH_SEVERITY_LOW_MAX', 6)
        self.severity_medium_max = self._get_int_value(cli_args, 'severity_medium_max', 'WAZUH_SEVERITY_MEDIUM_MAX', 11)
        self.severity_high_max = self._get_int_value(cli_args, 'severity_high_max', 'WAZUH_SEVERITY_HIGH_MAX', 13)

        self._validate_config()

    def _get_value(self, cli_args, cli_attr, env_var, default=None):
        """Get configuration value with priority: CLI > ENV > Default"""
        if cli_args and hasattr(cli_args, cli_attr):
            value = getattr(cli_args, cli_attr)
            if value is not None:
                return value
        return os.getenv(env_var, default)

    def _get_int_value(self, cli_args, cli_attr, env_var, default):
        """Get integer configuration value"""
        value = self._get_value(cli_args, cli_attr, env_var)
        return int(value) if value is not None else default

    def _get_bool_value(self, cli_args, cli_attr, env_var, default):
        """Get boolean configuration value"""
        value = self._get_value(cli_args, cli_attr, env_var)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).lower() in ('true', '1', 'yes', 'on')

    def _validate_config(self):
        """Validate required configuration parameters"""
        errors = []

        if not all([self.manager_host, self.manager_user, self.manager_pass]):
            errors.append("Manager configuration incomplete (host, username, password required)")

        if not all([self.indexer_host, self.indexer_user, self.indexer_pass]):
            errors.append("Indexer configuration incomplete (host, username, password required)")

        if errors:
            logger.error("Configuration validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            logger.error("\nProvide configuration via:")
            logger.error("  CLI: --manager-host <HOST> --manager-user <USER> --manager-pass <PASS>")
            logger.error("  ENV: WAZUH_API_HOST=<HOST> WAZUH_API_USERNAME=<USER> WAZUH_API_PASSWORD=<PASS> ...")
            sys.exit(1)

        logger.info(f"Manager: {self.protocol}://{self.manager_host}:{self.manager_port}")
        logger.info(f"Indexer: {self.protocol}://{self.indexer_host}:{self.indexer_port}")
        logger.info(f"Cache: {self.cache_duration}s | Timeout: {self.request_timeout}s | SSL: {self.use_ssl}")
        logger.info(f"Severity: Low 0-{self.severity_low_max} / Medium {self.severity_low_max+1}-{self.severity_medium_max} / "
                    f"High {self.severity_medium_max+1}-{self.severity_high_max} / Critical {self.severity_high_max+1}-15")

# Global configuration instance
# Parse CLI arguments at module level (for uvx/mcpo compatibility)
_cli_args = None
if len(sys.argv) > 1:  # If arguments provided, parse them
    def _parse_args():
        parser = argparse.ArgumentParser(add_help=False)  # Disable default help to avoid conflicts
        parser.add_argument('--manager-host', help='Manager hostname or IP')
        parser.add_argument('--manager-port', type=int, help='Manager port')
        parser.add_argument('--manager-user', help='Manager username')
        parser.add_argument('--manager-pass', help='Manager password')
        parser.add_argument('--indexer-host', help='Indexer hostname or IP')
        parser.add_argument('--indexer-port', type=int, help='Indexer port')
        parser.add_argument('--indexer-user', help='Indexer username')
        parser.add_argument('--indexer-pass', help='Indexer password')
        parser.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'), help='Enable SSL verification')
        parser.add_argument('--protocol', choices=['http', 'https'], help='Connection protocol')
        parser.add_argument('--cache-duration', type=int, help='Cache duration in seconds')
        parser.add_argument('--request-timeout', type=int, help='Request timeout in seconds')
        parser.add_argument('--retry-attempts', type=int, help='Retry attempts')
        parser.add_argument('--transport', choices=['stdio', 'sse', 'streamable-http'], default='stdio', help='MCP transport type')
        parser.add_argument('--host', default='0.0.0.0', help='HTTP server host for sse/streamable-http')
        parser.add_argument('--port', type=int, default=8000, help='HTTP server port for sse/streamable-http')
        parser.add_argument('--api-key', default=os.environ.get('MCP_API_KEY', ''), help='API key for authentication')
        parser.add_argument('--severity-low-max', type=int, help='Max rule level for Low severity (default: 6)')
        parser.add_argument('--severity-medium-max', type=int, help='Max rule level for Medium severity (default: 11)')
        parser.add_argument('--severity-high-max', type=int, help='Max rule level for High severity (default: 13)')
        args, _ = parser.parse_known_args()  # Use parse_known_args to ignore unknown arguments
        return args
    _cli_args = _parse_args()

wazuh_config = WazuhConfig(cli_args=_cli_args)

# ═══════════════════════ JSON Serialization ═══════════════════════

class DateTimeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def _strip_none(obj):
    """Recursively remove keys with None values from dicts"""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(i) for i in obj]
    return obj

def _severity_label(level: int) -> str:
    """Convert Wazuh alert level (0-15) to severity label using configured thresholds."""
    if level > wazuh_config.severity_high_max:
        return "Critical"
    if level > wazuh_config.severity_medium_max:
        return "High"
    if level > wazuh_config.severity_low_max:
        return "Medium"
    return "Low"

def _compact_json(data: dict) -> str:
    """Serialize to compact JSON, stripping None values"""
    return json.dumps(_strip_none(data), ensure_ascii=False, cls=DateTimeJSONEncoder, separators=(',',':'))

# ═══════════════════════ Caching System ═══════════════════════

class MemoryCache:
    """Simple in-memory cache with TTL support"""

    def __init__(self, ttl_seconds: int = 300):
        self._storage = {}
        self._ttl = ttl_seconds

    def _compute_key(self, key_string: str) -> str:
        """Generate MD5 hash for cache key"""
        return hashlib.md5(key_string.encode('utf-8')).hexdigest()

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve value from cache if not expired"""
        hashed_key = self._compute_key(key)
        if hashed_key in self._storage:
            cached_value, cached_time = self._storage[hashed_key]
            if time.time() - cached_time < self._ttl:
                return cached_value
            del self._storage[hashed_key]
        return None

    def store(self, key: str, value: Any):
        """Store value in cache with current timestamp"""
        hashed_key = self._compute_key(key)
        self._storage[hashed_key] = (value, time.time())

    def invalidate_all(self):
        """Clear all cached entries"""
        self._storage.clear()

    def get_statistics(self) -> Dict[str, int]:
        """Get cache statistics"""
        current_ts = time.time()
        valid_entries = sum(
            1 for _, ts in self._storage.values()
            if current_ts - ts < self._ttl
        )
        return {
            "total_entries": len(self._storage),
            "valid_entries": valid_entries,
            "ttl_seconds": self._ttl
        }

# Global cache instance (will be initialized after config)
memory_cache = None

# ═══════════════════════ HTTP Session Management ═══════════════════════

# Global session instances (will be initialized after config)
manager_http_session = None
indexer_http_session = None
manager_jwt_token = None
manager_token_expiry = None

def get_manager_jwt_token() -> str:
    """Obtain JWT token from Wazuh Manager API"""
    global manager_jwt_token, manager_token_expiry

    # Check if we have a valid token
    if manager_jwt_token and manager_token_expiry:
        if datetime.now() < manager_token_expiry:
            return manager_jwt_token

    # Get new token
    auth_url = f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}/security/user/authenticate"
    auth_string = f"{wazuh_config.manager_user}:{wazuh_config.manager_pass}"
    encoded_auth = base64.b64encode(auth_string.encode()).decode()

    try:
        response = requests.get(
            auth_url,
            headers={
                "Authorization": f"Basic {encoded_auth}",
                "Content-Type": "application/json"
            },
            verify=wazuh_config.use_ssl,
            timeout=wazuh_config.request_timeout
        )
        response.raise_for_status()

        token_data = response.json()
        manager_jwt_token = token_data.get("data", {}).get("token")

        if not manager_jwt_token:
            raise Exception("No token in authentication response")

        # Token expires in 15 minutes, refresh 1 minute before
        manager_token_expiry = datetime.now() + timedelta(minutes=14)

        logger.debug("Successfully obtained JWT token")
        return manager_jwt_token

    except Exception as e:
        logger.error(f"Failed to obtain JWT token: {e}")
        raise Exception(f"Authentication failed: {str(e)}")

def setup_http_sessions():
    """Initialize HTTP sessions for Manager and Indexer"""
    global manager_http_session, indexer_http_session

    # Manager session (JWT token will be added on each request)
    manager_http_session = requests.Session()
    manager_http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "wazuh-mcp-server/1.3.8"
    })
    manager_http_session.verify = wazuh_config.use_ssl

    # Indexer session with Basic Authentication
    indexer_http_session = requests.Session()
    indexer_http_session.auth = (wazuh_config.indexer_user, wazuh_config.indexer_pass)
    indexer_http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "wazuh-mcp-server/1.3.8"
    })
    indexer_http_session.verify = wazuh_config.use_ssl

# Create FastMCP server instance (disable DNS rebinding protection for external clients)
mcp_server = FastMCP(
    "Wazuh",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
)

# Initialize cache and HTTP sessions (for module import)
memory_cache = MemoryCache(wazuh_config.cache_duration)
setup_http_sessions()

# ═══════════════════════ Utility Functions ═══════════════════════

def exponential_backoff_retry(max_attempts: int = 3, initial_delay: float = 1.0):
    """Decorator implementing exponential backoff retry logic"""
    def decorator_func(func):
        @wraps(func)
        def wrapper_func(*args, **kwargs):
            last_error = None
            for attempt_num in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as error:
                    last_error = error
                    if attempt_num < max_attempts - 1:
                        delay = initial_delay * (2 ** attempt_num)
                        logger.warning(f"Attempt {attempt_num + 1}/{max_attempts} failed: {error}")
                        logger.warning(f"Retrying in {delay}s...")
                        time.sleep(delay)
            logger.error(f"All {max_attempts} attempts exhausted")
            raise last_error
        return wrapper_func
    return decorator_func

def query_manager_api(endpoint: str, query_params: Optional[Dict] = None,
                     http_method: str = "GET", request_body: Optional[Dict] = None,
                     enable_cache: bool = True) -> Dict[str, Any]:
    """Execute API request to Wazuh Manager with caching and JWT authentication"""

    # Generate cache key
    cache_identifier = f"mgr:{http_method}:{endpoint}:{json.dumps(query_params, sort_keys=True)}:{json.dumps(request_body, sort_keys=True)}"

    # Check cache for GET requests
    if enable_cache and http_method.upper() == 'GET':
        cached_response = memory_cache.retrieve(cache_identifier)
        if cached_response:
            logger.debug(f"Cache hit: {endpoint}")
            return cached_response

    # Build full URL
    full_url = f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}{endpoint}"
    logger.debug(f"Manager API: {http_method} {full_url}")

    # Retry logic
    for attempt in range(wazuh_config.retry_attempts):
        try:
            # Get JWT token
            jwt_token = get_manager_jwt_token()

            # Make request with JWT token
            http_response = manager_http_session.request(
                http_method.upper(),
                full_url,
                params=query_params,
                json=request_body,
                headers={"Authorization": f"Bearer {jwt_token}"},
                timeout=wazuh_config.request_timeout
            )
            http_response.raise_for_status()

            response_data = http_response.json()

            # Cache successful GET requests
            if enable_cache and http_method.upper() == 'GET':
                memory_cache.store(cache_identifier, response_data)

            return response_data

        except requests.exceptions.RequestException as req_error:
            # If 401, invalidate token and retry
            if hasattr(req_error, 'response') and req_error.response and req_error.response.status_code == 401:
                global manager_jwt_token, manager_token_expiry
                manager_jwt_token = None
                manager_token_expiry = None
                logger.warning("Token expired or invalid, will get new token on retry")

            if attempt < wazuh_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Manager API request failed after {wazuh_config.retry_attempts} attempts")
                raise Exception(f"Wazuh Manager API error: {str(req_error)}")

def query_indexer_api(endpoint: str, query_params: Optional[Dict] = None,
                     http_method: str = "GET", request_body: Optional[Dict] = None,
                     enable_cache: bool = True) -> Dict[str, Any]:
    """Execute API request to Wazuh Indexer with caching"""

    # Generate cache key
    cache_identifier = f"idx:{http_method}:{endpoint}:{json.dumps(query_params, sort_keys=True)}:{json.dumps(request_body, sort_keys=True)}"

    # Check cache for GET requests
    if enable_cache and http_method.upper() == 'GET':
        cached_response = memory_cache.retrieve(cache_identifier)
        if cached_response:
            logger.debug(f"Cache hit: {endpoint}")
            return cached_response

    # Build full URL
    full_url = f"{wazuh_config.protocol}://{wazuh_config.indexer_host}:{wazuh_config.indexer_port}{endpoint}"
    logger.debug(f"Indexer API: {http_method} {full_url}")

    # Retry logic
    for attempt in range(wazuh_config.retry_attempts):
        try:
            http_response = indexer_http_session.request(
                http_method.upper(),
                full_url,
                params=query_params,
                json=request_body,
                timeout=wazuh_config.request_timeout
            )
            http_response.raise_for_status()

            response_data = http_response.json()

            # Cache successful GET/POST requests
            if enable_cache and http_method.upper() in ['GET', 'POST']:
                memory_cache.store(cache_identifier, response_data)

            return response_data

        except requests.exceptions.RequestException as req_error:
            if attempt < wazuh_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Indexer API request failed after {wazuh_config.retry_attempts} attempts")
                raise Exception(f"Wazuh Indexer API error: {str(req_error)}")

def normalize_agent_identifier(agent_id_input: str) -> str:
    """Convert agent ID to canonical form.

    Supports any numeric agent ID. IDs below 1000 are zero-padded to 3 digits
    (e.g. 1 -> "001"); IDs >= 1000 are passed through as plain numeric strings
    (e.g. 1234 -> "1234", 123456 -> "123456"). There is no upper cap -- 5/6/7-digit
    agent IDs work (verified against live Wazuh 4.x API).
    """
    try:
        agent_number = int(agent_id_input)
    except (ValueError, TypeError):
        raise ValueError(
            f"Invalid agent ID format: '{agent_id_input}'. Expected a numeric value."
        )

    if agent_number < 0:
        raise ValueError(f"Agent ID must be non-negative: '{agent_id_input}'")

    # f"{n:03d}" uses minimum-width formatting:
    #   1    -> "001"
    #   999  -> "999"
    #   1234 -> "1234"  (length is not truncated)
    return f"{agent_number:03d}"

# ═══════════════════════ MCP Tool Implementations ═══════════════════════

# ─────────────────── Alert Monitoring Tools ───────────────────

@mcp_server.tool()
def alertSummary(max_results: int = 50,
                  offset: int = 0,
                  min_level: int = 0,
                  max_level: int = 15,
                  time_range_hours: int = 24,
                  agent_name: str = "",
                  agent_id: str = "",
                  agent_ip: str = "",
                  rule_id: str = "",
                  rule_group: str = "",
                  rule_description: str = "",
                  mitre_technique: str = "",
                  mitre_tactic: str = "",
                  min_cvss_score: float = 0.0,
                  cve_id: str = "",
                  source_ip: str = "",
                  destination_ip: str = "",
                  user: str = "",
                  process_name: str = "",
                  file_path: str = "",
                  custom_fields: str = "") -> str:
    """[Wazuh SIEM] Retrieve security alerts with full details and IoC extraction.

    This is a Wazuh SIEM tool, NOT Graylog. Use this to view complete alert content (timestamp, rule, agent, IoC, etc.).
    If you only need counts and distribution, use alertStatistics instead.
    Supports pagination: when has_more=true, use offset=next_offset for the next page.

    IMPORTANT: Keep max_results small (<=50 recommended, hard-cap 100). Each alert includes
    full IoC detail, so larger pages often overflow small-context models. When the user wants
    "all alerts", prefer alertStatistics first, then fetch detail pages on demand.

    Args:
        max_results: Alerts per page, default 50, recommended <=50, do not exceed 100.
        offset: Pagination offset, default 0. Use response pagination.next_offset for next page.
        min_level: Min alert level 0-15. Levels: 0-3=Low, 4-7=Medium, 8-11=High, 12-15=Critical.
        max_level: Max alert level 0-15.
        time_range_hours: Hours to look back, default 24. Example: 72=3 days, 168=1 week.
        agent_name: Filter by agent hostname. Empty string means no filter.
        agent_id: Filter by agent ID (e.g. "001"), auto-padded to 3 digits. Empty string means no filter.
        agent_ip: Filter by agent IP. Empty string means no filter.
        rule_id: Exact match rule ID (e.g. "5710"). Empty string means no filter.
        rule_group: Partial match, case-insensitive (e.g. "authentication", "jason" finds "jason_tools_ioc"). Empty string means no filter.
        rule_description: Partial match, case-insensitive (e.g. "IoC", "brute force"). Empty string means no filter.
        mitre_technique: MITRE ATT&CK technique ID (e.g. "T1078"). Empty string means no filter.
        mitre_tactic: MITRE ATT&CK tactic (e.g. "Initial Access"). Empty string means no filter.
        min_cvss_score: Minimum CVSS score (e.g. 7.0), default 0.0 means no filter.
        cve_id: CVE ID (e.g. "CVE-2021-44228"). Empty string means no filter.
        source_ip: Filter by source IP. Empty string means no filter.
        destination_ip: Filter by destination IP. Empty string means no filter.
        user: Filter by username. Empty string means no filter.
        process_name: Filter by process name. Empty string means no filter.
        file_path: Filter by file path. Empty string means no filter.
        custom_fields: Custom field filters as comma-separated "field=value" pairs. Supports any Wazuh/Elasticsearch field. Use "~" for partial match (wildcard), "=" for exact match. Example: "data.win.system.eventID=3,data.win.eventdata.image~mstsc.exe" will match eventID exactly 3 AND image containing mstsc.exe.

    Returns:
        JSON object containing:
        - status: request status
        - pagination: paging info (offset, page_size, returned_count, total_matches, has_more, next_offset)
        - alerts: list of alerts, each with alert_id, timestamp, agent_name, agent_id, severity_level,
          rule_id, rule_groups, description, and ioc (source_ip, hash, URL, domain, MITRE mapping, etc.)

    Example:
        alertSummary(time_range_hours=24, min_level=8)
    """
    logger.info(f"Fetching alert summary (max={max_results}, offset={offset}, filters={{level:{min_level}-{max_level}, "
                f"time:{time_range_hours}h, agent:{agent_name or agent_id}, rule:{rule_id or rule_group}, cvss:{min_cvss_score}}})")

    try:
        # Build Elasticsearch query with filters
        must_clauses = []

        # Time range filter
        if time_range_hours:
            time_filter = {
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            }
            must_clauses.append(time_filter)

        # Alert level filter (range)
        if min_level > 0 or max_level < 15:
            level_range = {}
            if min_level > 0:
                level_range["gte"] = min_level
            if max_level < 15:
                level_range["lte"] = max_level
            level_filter = {
                "range": {
                    "rule.level": level_range
                }
            }
            must_clauses.append(level_filter)

        # Agent filters
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})
        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})
        if agent_ip:
            must_clauses.append({"match": {"agent.ip": agent_ip}})

        # Rule filters
        if rule_id:
            must_clauses.append({"term": {"rule.id": rule_id}})
        if rule_group:
            # Use wildcard query for partial matching in rule groups
            # This allows searching "jason" to find "jason_tools_ioc" or "ioc" to find any group with "ioc"
            must_clauses.append({
                "wildcard": {
                    "rule.groups": {
                        "value": f"*{rule_group}*",
                        "case_insensitive": True
                    }
                }
            })
        if rule_description:
            # Use wildcard query for true partial matching (works with both text and keyword fields)
            # This ensures we can find "IOC" in "Jason Tools IOC: Malicious..." regardless of field mapping
            must_clauses.append({
                "wildcard": {
                    "rule.description": {
                        "value": f"*{rule_description}*",
                        "case_insensitive": True
                    }
                }
            })

        # MITRE ATT&CK filters
        if mitre_technique:
            must_clauses.append({"match": {"rule.mitre.technique": mitre_technique}})
        if mitre_tactic:
            must_clauses.append({"match": {"rule.mitre.tactic": mitre_tactic}})

        # Network/System event filters
        if source_ip:
            must_clauses.append({"match": {"data.srcip": source_ip}})
        if destination_ip:
            must_clauses.append({"match": {"data.dstip": destination_ip}})
        if user:
            must_clauses.append({"match": {"data.dstuser": user}})
        if process_name:
            must_clauses.append({"match": {"data.process.name": process_name}})
        if file_path:
            must_clauses.append({"match_phrase": {"syscheck.path": file_path}})

        # Vulnerability filters
        if cve_id:
            must_clauses.append({"match": {"data.vulnerability.cve": cve_id}})

        # Custom field filters (supports any Wazuh/Elasticsearch field)
        if custom_fields:
            for pair in custom_fields.split(","):
                pair = pair.strip()
                if not pair:
                    continue
                if "~" in pair:
                    # Wildcard/partial match: field~value
                    field, value = pair.split("~", 1)
                    must_clauses.append({
                        "wildcard": {
                            field.strip(): {
                                "value": f"*{value.strip()}*",
                                "case_insensitive": True
                            }
                        }
                    })
                elif "=" in pair:
                    # Exact match: field=value
                    field, value = pair.split("=", 1)
                    field = field.strip()
                    value = value.strip()
                    # Try numeric match for integer values
                    try:
                        numeric_val = int(value)
                        must_clauses.append({"term": {field: numeric_val}})
                    except ValueError:
                        must_clauses.append({"term": {field: value}})

        # CVSS score filter (for vulnerability-related alerts)
        if min_cvss_score > 0:
            # Try to match CVSS3 or CVSS2 scores
            # Wazuh vulnerability alerts store CVSS in data.vulnerability.cvss
            cvss_filter = {
                "bool": {
                    "should": [
                        {
                            "range": {
                                "data.vulnerability.cvss.cvss3.base_score": {
                                    "gte": min_cvss_score
                                }
                            }
                        },
                        {
                            "range": {
                                "data.vulnerability.cvss.cvss2.base_score": {
                                    "gte": min_cvss_score
                                }
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
            must_clauses.append(cvss_filter)

        # Build final query with pagination
        if must_clauses:
            search_query = {
                "size": max_results,
                "from": offset,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                }
            }
        else:
            search_query = {
                "size": max_results,
                "from": offset,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_all": {}}
            }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=search_query
        )

        hits_data = api_response.get("hits", {})
        alert_hits = hits_data.get("hits", [])
        total_hits = hits_data.get("total", {})

        # Extract total count (Elasticsearch 7.x format)
        if isinstance(total_hits, dict):
            total_count = total_hits.get("value", 0)
        else:
            total_count = total_hits

        if not alert_hits:
            return _compact_json({
                "status": "success",
                "message": "No security alerts found matching the criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_count
                },
                "alerts": []
            })

        processed_alerts = []
        for hit_entry in alert_hits:
            alert_source = hit_entry.get("_source", {})

            # Extract alert details
            alert_identifier = alert_source.get("id") or hit_entry.get("_id", "N/A")
            event_timestamp = alert_source.get("timestamp", "N/A")

            rule_details = alert_source.get("rule", {})
            event_description = rule_details.get("description", "No description")
            severity_level = rule_details.get("level", 0)

            agent_details = alert_source.get("agent", {})
            agent_identifier = agent_details.get("name", "N/A")

            # Extract IoC (Indicators of Compromise) information
            alert_data = alert_source.get("data", {})
            ioc_info = {}

            # IP addresses (malicious IPs)
            if "srcip" in alert_data:
                ioc_info["source_ip"] = alert_data["srcip"]
            if "dstip" in alert_data:
                ioc_info["destination_ip"] = alert_data["dstip"]

            # File hashes (malware indicators)
            if "md5" in alert_data:
                ioc_info["md5_hash"] = alert_data["md5"]
            if "sha1" in alert_data:
                ioc_info["sha1_hash"] = alert_data["sha1"]
            if "sha256" in alert_data:
                ioc_info["sha256_hash"] = alert_data["sha256"]

            # URLs (malicious links)
            if "url" in alert_data:
                ioc_info["url"] = alert_data["url"]

            # Domain names
            if "domain" in alert_data:
                ioc_info["domain"] = alert_data["domain"]

            # Process information (suspicious processes)
            if "process" in alert_data:
                process_data = alert_data["process"]
                if isinstance(process_data, dict):
                    ioc_info["process_name"] = process_data.get("name")
                    ioc_info["process_path"] = process_data.get("path")
                    ioc_info["process_cmdline"] = process_data.get("cmdline")
                else:
                    ioc_info["process_name"] = process_data

            # File paths
            if "file" in alert_data:
                ioc_info["file_path"] = alert_data["file"]

            # Username (suspicious account activity)
            if "dstuser" in alert_data:
                ioc_info["username"] = alert_data["dstuser"]
            elif "srcuser" in alert_data:
                ioc_info["username"] = alert_data["srcuser"]

            # Port information
            if "dstport" in alert_data:
                ioc_info["destination_port"] = alert_data["dstport"]
            if "srcport" in alert_data:
                ioc_info["source_port"] = alert_data["srcport"]

            # MITRE ATT&CK mapping
            mitre_data = rule_details.get("mitre", {})
            if mitre_data:
                mitre_info = {}
                if "technique" in mitre_data and mitre_data["technique"]:
                    mitre_info["techniques"] = mitre_data["technique"]
                if "tactic" in mitre_data and mitre_data["tactic"]:
                    mitre_info["tactics"] = mitre_data["tactic"]
                if mitre_info:
                    ioc_info["mitre_attack"] = mitre_info

            # Threat intelligence (VirusTotal, etc.)
            if "virustotal" in alert_data:
                vt_data = alert_data["virustotal"]
                ioc_info["virustotal"] = {
                    "positives": vt_data.get("positives"),
                    "total": vt_data.get("total"),
                    "permalink": vt_data.get("permalink")
                }

            # Build alert entry
            alert_entry = {
                "alert_id": alert_identifier,
                "timestamp": event_timestamp,
                "agent_name": agent_identifier,
                "agent_id": agent_details.get("id", "N/A"),
                "severity_level": severity_level,
                "severity": _severity_label(severity_level),
                "rule_id": rule_details.get("id", "N/A"),
                "rule_groups": rule_details.get("groups", []),
                "description": event_description
            }

            # Only include IoC section if we found IoC data
            if ioc_info:
                alert_entry["ioc"] = ioc_info

            processed_alerts.append(alert_entry)

        # Calculate pagination info
        returned_count = len(processed_alerts)
        has_more = (offset + returned_count) < total_count

        return _compact_json({
            "status": "success",
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_count,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "alerts": processed_alerts
        })

    except Exception as error:
        logger.error(f"Alert retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve alerts: {str(error)}"
        })

@mcp_server.tool()
def alertStatistics(time_range_hours: int = 24,
                     agent_name: str = "",
                     agent_id: str = "",
                     rule_group: str = "",
                     rule_id: str = "",
                     rule_description: str = "") -> str:
    """[Wazuh SIEM] Get alert statistics summary (counts and distribution only, no alert details).

    This is a Wazuh SIEM tool, NOT Graylog. Use this to quickly check alert volume and severity breakdown before using alertSummary for details.

    Args:
        time_range_hours: Hours to look back, default 24. Example: 72=3 days, 168=1 week.
        agent_name: Filter by agent hostname.
        agent_id: Filter by agent ID (e.g. "031"), auto-padded to 3 digits.
        rule_group: Partial match, case-insensitive (e.g. "authentication").
        rule_id: Exact match rule ID (e.g. "5715").
        rule_description: Partial match, case-insensitive (e.g. "brute force").

    Returns:
        JSON object containing:
        - total_alerts: total alert count
        - severity_distribution: count and percentage for each severity level
        - top_agents: top 10 agents by alert count
        - top_rules: top 10 rules by trigger count

    Example:
        alertStatistics(time_range_hours=24)
    """
    logger.info(f"Fetching alert statistics (time={time_range_hours}h, agent_name={agent_name}, agent_id={agent_id}, "
                f"rule_group={rule_group}, rule_id={rule_id}, rule_description={rule_description})")

    try:
        # Build Elasticsearch aggregation query
        must_clauses = []

        # Time range filter
        if time_range_hours:
            must_clauses.append({
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            })

        # Agent filters
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})
        if agent_id:
            normalized_agent = normalize_agent_identifier(agent_id)
            must_clauses.append({"term": {"agent.id": normalized_agent}})

        # Rule filters
        if rule_id:
            must_clauses.append({"term": {"rule.id": rule_id}})
        if rule_group:
            # Use wildcard query for partial matching in rule groups
            # This allows searching "jason" to find "jason_tools_ioc" or "ioc" to find any group with "ioc"
            must_clauses.append({
                "wildcard": {
                    "rule.groups": {
                        "value": f"*{rule_group}*",
                        "case_insensitive": True
                    }
                }
            })
        if rule_description:
            # Use wildcard query for true partial matching (works with both text and keyword fields)
            # This ensures we can find "IOC" in "Jason Tools IOC: Malicious..." regardless of field mapping
            must_clauses.append({
                "wildcard": {
                    "rule.description": {
                        "value": f"*{rule_description}*",
                        "case_insensitive": True
                    }
                }
            })

        # Build aggregation query for statistics
        agg_query = {
            "size": 0,  # Don't return actual documents, only aggregations
            "track_total_hits": True,  # Get accurate total count (not limited to 10,000)
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}]
                }
            },
            "aggs": {
                # Severity level distribution
                "severity_stats": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "from": 0, "to": 4},
                            {"key": "medium", "from": 4, "to": 8},
                            {"key": "high", "from": 8, "to": 12},
                            {"key": "critical_emergency", "from": 12, "to": 16}
                        ]
                    }
                },
                # Top agents by alert count
                "top_agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                # Top rules
                "top_rules": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_description": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description"]
                            }
                        }
                    }
                }
            }
        }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=agg_query
        )

        # Extract total count from hits
        total_hits = api_response.get("hits", {}).get("total", {})
        total_count = total_hits.get("value", 0) if isinstance(total_hits, dict) else total_hits

        # Extract severity distribution
        severity_buckets = api_response.get("aggregations", {}).get("severity_stats", {}).get("buckets", [])

        # Calculate actual total from aggregations (more accurate than hits.total)
        agg_total = sum(bucket.get("doc_count", 0) for bucket in severity_buckets)

        # Use aggregation total if it's more accurate (handles cases where total_count was capped at 10,000)
        accurate_total = agg_total if agg_total > total_count else total_count

        severity_dist = {}
        for bucket in severity_buckets:
            key = bucket.get("key", "unknown")
            count = bucket.get("doc_count", 0)
            percentage = round((count / accurate_total * 100), 2) if accurate_total > 0 else 0
            severity_dist[key] = {
                "count": count,
                "percentage": percentage
            }

        # Extract top agents
        agent_buckets = api_response.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
        top_agents = [
            {
                "agent_name": bucket.get("key", "Unknown"),
                "alert_count": bucket.get("doc_count", 0)
            }
            for bucket in agent_buckets
        ]

        # Extract top rules
        rule_buckets = api_response.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        top_rules = []
        for bucket in rule_buckets:
            rule_hits = bucket.get("rule_description", {}).get("hits", {}).get("hits", [])
            description = "N/A"
            if rule_hits:
                description = rule_hits[0].get("_source", {}).get("rule", {}).get("description", "N/A")

            top_rules.append({
                "rule_id": bucket.get("key", "N/A"),
                "description": description,
                "trigger_count": bucket.get("doc_count", 0)
            })

        return _compact_json({
            "status": "success",
            "time_range_hours": time_range_hours,
            "filters": {
                "agent_name": agent_name,
                "agent_id": agent_id,
                "rule_group": rule_group,
                "rule_id": rule_id,
                "rule_description": rule_description
            },
            "total_alerts": accurate_total,
            "severity_scale": "Wazuh levels 0-15: Low(0-3), Medium(4-7), High(8-11), Critical(12-15)",
            "severity_distribution": {
                "Critical (level 12-15)": severity_dist.get("critical_emergency", {"count": 0, "percentage": 0}),
                "High (level 8-11)": severity_dist.get("high", {"count": 0, "percentage": 0}),
                "Medium (level 4-7)": severity_dist.get("medium", {"count": 0, "percentage": 0}),
                "Low (level 0-3)": severity_dist.get("low", {"count": 0, "percentage": 0})
            },
            "top_agents": top_agents if not (agent_name or agent_id) else [],
            "top_rules": top_rules
        })

    except Exception as error:
        logger.error(f"Alert statistics retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve alert statistics: {str(error)}"
        })

@mcp_server.tool()
def agentsWithAlerts(min_level: int = 0,
                       time_range_hours: int = 24,
                       max_agents: int = 100) -> str:
    """[Wazuh SIEM] List agents ranked by alert count, with max severity and latest alert timestamp.

    This is a Wazuh SIEM tool, NOT Graylog. Use this to quickly find which hosts have the most alerts.
    Returns a Top N ranking (not paginated). Default max_agents=100 is usually enough.

    Performance tip: for time ranges > 3 days, set min_level (e.g. min_level=8) to reduce
    the volume of data aggregated. Without a level filter, long ranges on noisy environments
    may time out at the Elasticsearch layer.

    Args:
        min_level: Min alert level 0-15, default 0 (no level filter).
        time_range_hours: Hours to look back, default 24. Example: 72=3 days, 168=1 week.
        max_agents: Max agents to return, default 100, upper bound 500.

    Returns:
        JSON object containing:
        - total_agents: number of agents found
        - agents: each with agent_name, agent_id, alert_count, max_severity_level,
          max_severity label, last_alert_timestamp

    Example:
        agentsWithAlerts(time_range_hours=24, min_level=8)
    """
    # Cap max_agents to safe upper bound
    if max_agents > 500:
        max_agents = 500

    logger.info(f"Analyzing agents with alerts (min_level={min_level}, "
                f"time_range={time_range_hours}h, max_agents={max_agents})")

    try:
        # Build Elasticsearch aggregation query
        must_clauses = []

        # Time range filter
        if time_range_hours:
            time_filter = {
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            }
            must_clauses.append(time_filter)

        # Alert level filter
        if min_level > 0:
            level_filter = {
                "range": {
                    "rule.level": {
                        "gte": min_level
                    }
                }
            }
            must_clauses.append(level_filter)

        # Build aggregation query.
        # Replaced expensive `top_hits` sub-aggregation with lightweight `max` on @timestamp,
        # which avoids loading a document per bucket and lets us cover longer time ranges.
        agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "aggs": {
                "agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": max_agents,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "agent_id": {
                            "terms": {"field": "agent.id", "size": 1}
                        },
                        "max_level": {
                            "max": {"field": "rule.level"}
                        },
                        "latest_ts": {
                            "max": {"field": "timestamp"}
                        }
                    }
                }
            }
        }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=agg_query
        )

        agent_buckets = api_response.get("aggregations", {}).get("agents", {}).get("buckets", [])

        if not agent_buckets:
            return _compact_json({
                "status": "success",
                "message": "No agents found with alerts matching the criteria",
                "total_agents": 0,
                "agents": []
            })

        processed_agents = []
        for bucket in agent_buckets:
            agent_name = bucket.get("key", "Unknown")
            alert_count = bucket.get("doc_count", 0)
            max_severity = int(bucket.get("max_level", {}).get("value", 0))

            # Extract agent ID
            agent_id_buckets = bucket.get("agent_id", {}).get("buckets", [])
            agent_id = agent_id_buckets[0].get("key", "N/A") if agent_id_buckets else "N/A"

            # Use the max aggregation's string value (ISO timestamp) when available
            latest_ts = bucket.get("latest_ts", {}).get("value_as_string") \
                        or bucket.get("latest_ts", {}).get("value")

            processed_agents.append({
                "agent_name": agent_name,
                "agent_id": agent_id,
                "alert_count": alert_count,
                "max_severity_level": max_severity,
                "max_severity": _severity_label(max_severity),
                "last_alert_timestamp": latest_ts
            })

        return _compact_json({
            "status": "success",
            "total_agents": len(processed_agents),
            "filter_criteria": {
                "min_level": min_level,
                "time_range_hours": time_range_hours,
                "max_agents": max_agents
            },
            "agents": processed_agents
        })

    except Exception as error:
        logger.error(f"Agent alert analysis failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to analyze agents: {str(error)}"
        })

# ─────────────────── Security Rules Tools ───────────────────

@mcp_server.tool()
def rulesSummary(max_results: int = 300,
                  offset: int = 0,
                  min_level: int = 0,
                  rule_group: str = "",
                  rule_file: str = "") -> str:
    """[Wazuh SIEM] Search Wazuh detection rules with compliance mappings (GDPR, HIPAA, PCI-DSS, NIST).

    This is a Wazuh SIEM tool, NOT Graylog. Supports pagination and multiple filters.

    Args:
        max_results: Rules per page, default 300.
        offset: Pagination offset, default 0.
        min_level: Min severity level 0-15. Levels: 0-3=low, 4-7=medium, 8-11=high, 12-15=critical.
        rule_group: Exact group name (e.g. "authentication", "web", "syscheck", "vulnerability-detector", "firewall").
        rule_file: Filter by rule filename (e.g. "0095-sshd_rules.xml").

    Returns:
        JSON object containing:
        - pagination: paging info
        - rules: list of rules, each with rule_id, severity_level, severity_category, description, groups, filename, status, compliance

    Example:
        rulesSummary(min_level=8, rule_group="authentication")
    """
    logger.info(f"Fetching rules (max={max_results}, offset={offset}, level={min_level}, group={rule_group})")

    try:
        # Build query parameters
        api_params = {"limit": max_results, "offset": offset}
        if min_level > 0:
            api_params["level"] = min_level
        if rule_group:
            api_params["group"] = rule_group
        if rule_file:
            api_params["filename"] = rule_file

        api_response = query_manager_api("/rules", query_params=api_params)

        data_section = api_response.get("data", {})
        rule_items = data_section.get("affected_items", [])
        total_items = data_section.get("total_affected_items", 0)

        if not rule_items:
            return _compact_json({
                "status": "success",
                "message": "No rules match the specified criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "rules": []
            })

        processed_rules = []
        for rule_entry in rule_items:
            rule_identifier = rule_entry.get("id", "N/A")
            severity_level = rule_entry.get("level", 0)
            rule_description = rule_entry.get("description", "No description")
            rule_groups = rule_entry.get("groups", [])
            source_file = rule_entry.get("filename", "N/A")
            rule_status = rule_entry.get("status", "unknown")

            # Calculate severity category using configured thresholds
            severity_category = _severity_label(severity_level)

            # Extract compliance mappings
            compliance_mappings = {}
            for compliance_type in ["gdpr", "hipaa", "pci_dss", "nist_800_53"]:
                if compliance_type in rule_entry and rule_entry[compliance_type]:
                    compliance_mappings[compliance_type.upper().replace("_", " ")] = rule_entry[compliance_type]

            processed_rules.append({
                "rule_id": rule_identifier,
                "severity_level": severity_level,
                "severity_category": severity_category,
                "description": rule_description,
                "groups": rule_groups,
                "filename": source_file,
                "status": rule_status,
                "compliance": compliance_mappings or None
            })

        # Calculate pagination info
        returned_count = len(processed_rules)
        has_more = (offset + returned_count) < total_items

        return _compact_json({
            "status": "success",
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_items,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "rules": processed_rules
        })

    except Exception as error:
        logger.error(f"Rule retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve rules: {str(error)}"
        })

# ─────────────────── Vulnerability Assessment Tools ───────────────────

def _process_vuln_states_doc(src: Dict[str, Any]) -> Dict[str, Any]:
    """Map a wazuh-states-vulnerabilities-* document to the output schema (4.8+ source)."""
    vuln = src.get("vulnerability", {}) or {}
    pkg = src.get("package", {}) or {}

    # states uses a single `score` block ({"base": 5.5, "version": "3.0"}) instead of
    # separate cvss2/cvss3 — map it into cvss_scores keyed by version so downstream
    # clients keep a familiar shape.
    cvss_scores: Dict[str, float] = {}
    score = vuln.get("score") or {}
    if isinstance(score, dict) and score.get("base") is not None:
        version = str(score.get("version", ""))
        label = "CVSS3_Score" if version.startswith("3") else \
                "CVSS2_Score" if version.startswith("2") else \
                f"CVSS_Score_v{version}" if version else "CVSS_Score"
        cvss_scores[label] = float(score["base"])

    severity = vuln.get("severity", "Unknown")
    pkg_name = pkg.get("name", "N/A")
    pkg_version = pkg.get("version", "N/A")
    scanner = (vuln.get("scanner") or {}) if isinstance(vuln.get("scanner"), dict) else {}

    return {
        "cve_id": vuln.get("id", "N/A"),
        "severity": severity.upper() if isinstance(severity, str) else severity,
        "title": f"{vuln.get('id', 'CVE')} affects {pkg_name}",
        "description": vuln.get("description") or f"Vulnerability in {pkg_name} {pkg_version}",
        "published_date": vuln.get("published_at"),
        "detected_at": vuln.get("detected_at"),
        "cvss_scores": cvss_scores or None,
        "reference_url": vuln.get("reference"),
        "package_name": pkg_name,
        "package_version": pkg_version,
        "package_architecture": pkg.get("architecture"),
        "under_evaluation": vuln.get("under_evaluation"),
        "scanner_source": scanner.get("source"),
    }


def _process_vuln_alert_doc(data_vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Map a wazuh-alerts-* data.vulnerability document to the output schema (legacy source)."""
    severity = data_vuln.get("severity", "Unknown")
    cvss_data = {}
    if "cvss" in data_vuln and isinstance(data_vuln["cvss"], dict):
        cvss_info = data_vuln["cvss"]
        if cvss_info.get("cvss2", {}).get("base_score"):
            cvss_data["CVSS2_Score"] = float(cvss_info["cvss2"]["base_score"])
        if cvss_info.get("cvss3", {}).get("base_score"):
            cvss_data["CVSS3_Score"] = float(cvss_info["cvss3"]["base_score"])

    pkg = data_vuln.get("package", {}) or {}
    pkg_name = pkg.get("name", "N/A")
    pkg_version = pkg.get("version", "N/A")

    return {
        "cve_id": data_vuln.get("cve", "N/A"),
        "severity": severity.upper() if isinstance(severity, str) else severity,
        "title": data_vuln.get("title", pkg_name),
        "description": f"Vulnerability in {pkg_name} {pkg_version}" if pkg_name != "N/A" else "No description",
        "published_date": data_vuln.get("published"),
        "updated_date": data_vuln.get("updated"),
        "detected_at": data_vuln.get("detection_time"),
        "cvss_scores": cvss_data or None,
        "reference_url": data_vuln.get("reference"),
        "package_name": pkg_name,
        "package_version": pkg_version,
    }


@mcp_server.tool()
def vulnerabilitySummary(agent_identifier: str,
                          max_results: int = 500,
                          offset: int = 0,
                          severity_filter: str = "",
                          cve_filter: str = "") -> str:
    """[Wazuh SIEM] Get current active CVEs for a specific agent.

    This is a Wazuh SIEM tool, NOT Graylog. Use listAgents first to get agent_id.
    Queries the modern wazuh-states-vulnerabilities-* index (Wazuh 4.8+) which holds
    the authoritative current state of vulnerabilities per agent. Falls back to the
    legacy wazuh-alerts-* data.vulnerability index for older deployments that do not
    populate the states index yet.

    Use severity_filter="Critical" to see critical CVEs only.

    Args:
        agent_identifier: Agent ID (required). Format: "0"=Manager, "1" or "001", auto-padded.
        max_results: CVEs per page, default 500.
        offset: Pagination offset, default 0.
        severity_filter: Exact match: "Low", "Medium", "High", or "Critical" (case-sensitive).
        cve_filter: CVE ID search (e.g. "CVE-2021-44228"), partial match.

    Returns:
        JSON object containing:
        - agent_id: queried agent ID
        - source: "states" (4.8+) or "alerts" (legacy fallback)
        - pagination: paging info
        - vulnerabilities: list of CVEs with cve_id, severity, title, description,
          cvss_scores, package_name, package_version

    Example:
        vulnerabilitySummary(agent_identifier="001", severity_filter="Critical")
    """
    logger.info(f"Fetching vulnerabilities for agent {agent_identifier} (max={max_results}, offset={offset})")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        # ── Try modern states index first (Wazuh 4.8+) ──────────────────────
        states_must: List[Dict[str, Any]] = [{"term": {"agent.id": normalized_id}}]
        if severity_filter:
            states_must.append({"term": {"vulnerability.severity": severity_filter}})
        if cve_filter:
            # vulnerability.id is a keyword field, so we need wildcard for partial match
            states_must.append({
                "wildcard": {
                    "vulnerability.id": {
                        "value": f"*{cve_filter}*",
                        "case_insensitive": True,
                    }
                }
            })

        states_query = {
            "size": max_results,
            "from": offset,
            "query": {"bool": {"must": states_must}},
            "sort": [{"vulnerability.detected_at": {"order": "desc"}}],
            # Only fetch the fields we need
            "_source": ["agent", "package", "vulnerability"],
            "track_total_hits": True,
        }

        source_used = "states"
        total_items = 0
        processed_vulns: List[Dict[str, Any]] = []
        states_query_succeeded = False

        try:
            states_resp = query_indexer_api(
                "/wazuh-states-vulnerabilities-*/_search",
                http_method="POST",
                request_body=states_query,
            )
            states_query_succeeded = True
            states_hits = states_resp.get("hits", {})
            total = states_hits.get("total", 0)
            total_items = total.get("value", 0) if isinstance(total, dict) else total
            state_docs = states_hits.get("hits", []) or []
            for hit in state_docs:
                processed_vulns.append(_process_vuln_states_doc(hit.get("_source", {})))
        except Exception as se:
            # States index likely does not exist (legacy Wazuh pre-4.8); fall back.
            logger.warning(f"states-vulnerabilities query failed, falling back to alerts: {se}")

        # ── Fallback: legacy alerts index (only when states query FAILED) ──
        # If states query succeeded (even with 0 hits), that's the authoritative
        # answer in 4.8+ -- do NOT fall back, an empty result means "no active CVEs".
        if not states_query_succeeded:
            source_used = "alerts"
            alert_must: List[Dict[str, Any]] = [
                {"exists": {"field": "data.vulnerability"}},
                {"term": {"agent.id": normalized_id}},
            ]
            if severity_filter:
                alert_must.append({"term": {"data.vulnerability.severity": severity_filter}})
            if cve_filter:
                alert_must.append({"match": {"data.vulnerability.cve": cve_filter}})

            alerts_query = {
                "size": max_results,
                "from": offset,
                "query": {"bool": {"must": alert_must}},
                "collapse": {"field": "data.vulnerability.cve"},
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": ["data.vulnerability", "timestamp", "agent.name"],
            }
            alerts_resp = query_indexer_api(
                "/wazuh-alerts-*/_search",
                http_method="POST",
                request_body=alerts_query,
            )
            alert_hits = alerts_resp.get("hits", {})
            total = alert_hits.get("total", 0)
            total_items = total.get("value", 0) if isinstance(total, dict) else total
            for hit in alert_hits.get("hits", []) or []:
                dv = (hit.get("_source", {}) or {}).get("data", {}).get("vulnerability")
                if dv:
                    processed_vulns.append(_process_vuln_alert_doc(dv))

        if not processed_vulns:
            return _compact_json({
                "status": "success",
                "message": f"No vulnerabilities found for agent {normalized_id}",
                "agent_id": normalized_id,
                "source": source_used,
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items,
                },
                "vulnerabilities": [],
            })

        returned_count = len(processed_vulns)
        has_more = (offset + returned_count) < total_items

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "source": source_used,
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_items,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None,
            },
            "vulnerabilities": processed_vulns,
        })

    except Exception as error:
        logger.error(f"Vulnerability retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve vulnerabilities: {str(error)}"
        })

# ─────────────────── Agent Management Tools ───────────────────

@mcp_server.tool()
def listGroups(search: str = "") -> str:
    """[Wazuh SIEM] List all agent groups with agent count per group.

    Use this to see which groups exist and how many agents belong to each.
    Much more efficient than listing all agents when you only need group statistics.

    Args:
        search: Partial group name to filter (e.g. "proxmox").

    Returns:
        JSON object containing:
        - total_groups: number of groups
        - groups: list of groups, each with name and agent_count

    Example:
        listGroups()
    """
    logger.info(f"Fetching agent groups (search={search!r})")

    try:
        api_params = {}
        if search:
            api_params["search"] = search

        api_response = query_manager_api("/groups", query_params=api_params)

        group_items = api_response.get("data", {}).get("affected_items", [])

        if not group_items:
            return _compact_json({
                "status": "success",
                "message": "No groups found",
                "total_groups": 0,
                "groups": []
            })

        processed_groups = []
        for g in group_items:
            processed_groups.append({
                "name": g.get("name", "N/A"),
                "agent_count": g.get("count", 0)
            })

        return _compact_json({
            "status": "success",
            "total_groups": len(processed_groups),
            "groups": processed_groups
        })

    except Exception as error:
        logger.error(f"Group listing failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to list groups: {str(error)}"
        })

@mcp_server.tool()
def listAgents(max_results: int = 300, offset: int = 0,
                status_filter: str = "active",
                name_filter: str = "", ip_filter: str = "",
                group_filter: str = "", os_filter: str = "",
                version_filter: str = "") -> str:
    """[Wazuh SIEM] List Wazuh monitored agents with full details, filtered by status.

    This is a Wazuh SIEM tool, NOT Graylog. Use this to list agents by status (active, disconnected, etc.),
    find specific hosts, or get agent_id for other tools. Agent "000" is always the Manager itself.
    To find disconnected/offline agents, use status_filter="disconnected".
    To see all agents regardless of status, use status_filter="all".
    Supports pagination: when has_more=true, use offset=next_offset for the next page.

    Args:
        max_results: Max agents per page, default 300.
        offset: Pagination offset, default 0. Use response pagination.next_offset for next page.
        status_filter: Agent connection status. Default "active". Options: "active", "disconnected", "pending", "never_connected", "all". Use "disconnected" to find offline agents.
        name_filter: Partial hostname match (e.g. "web" finds "web-server-01").
        ip_filter: Exact IP match (e.g. "192.168.1.100").
        group_filter: Exact group name match (e.g. "production").
        os_filter: OS platform partial match (e.g. "ubuntu", "windows", "centos").
        version_filter: Wazuh agent version filter (e.g. "4.7.0").

    Returns:
        JSON object containing:
        - pagination: paging info (offset, page_size, returned_count, total_matches, has_more, next_offset)
        - agents: list of agents, each with agent_id, agent_name, status, ip_address, os_info, agent_version, groups, last_keepalive

    Example:
        listAgents(status_filter="disconnected")
    """
    logger.info(f"Fetching agents (max={max_results}, offset={offset}, status={status_filter})")

    try:
        # Build query parameters.
        # Wazuh /agents accepts status in {active, pending, disconnected, never_connected}.
        # "all" / "" means "no status filter" -- omit the query param entirely,
        # otherwise Wazuh returns 400 Bad Request.
        api_params = {"limit": max_results, "offset": offset}
        if status_filter and status_filter.lower() != "all":
            api_params["status"] = status_filter
        if name_filter:
            api_params["name"] = name_filter
        if ip_filter:
            api_params["ip"] = ip_filter
        if group_filter:
            api_params["group"] = group_filter
        if os_filter:
            api_params["os.platform"] = os_filter
        if version_filter:
            api_params["version"] = version_filter

        api_response = query_manager_api("/agents", query_params=api_params)

        data_section = api_response.get("data", {})
        agent_items = data_section.get("affected_items", [])
        total_items = data_section.get("total_affected_items", 0)

        if not agent_items:
            return _compact_json({
                "status": "success",
                "message": f"No agents found (status filter: {status_filter})",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "agents": []
            })

        processed_agents = []
        for agent_entry in agent_items:
            agent_id = agent_entry.get("id", "N/A")
            agent_status = agent_entry.get("status", "unknown")

            # Map status to display format
            status_map = {
                "active": "ACTIVE",
                "disconnected": "DISCONNECTED",
                "pending": "PENDING",
                "never_connected": "NEVER_CONNECTED"
            }
            display_status = status_map.get(agent_status.lower(), agent_status.upper())

            # Extract OS information
            os_details = {}
            if "os" in agent_entry:
                os_data = agent_entry["os"]
                os_details = {
                    "name": os_data.get("name"),
                    "version": os_data.get("version"),
                    "architecture": os_data.get("arch")
                }

            # Format agent ID display
            agent_id_display = f"{agent_id} (Manager)" if agent_id == "000" else agent_id

            processed_agents.append({
                "agent_id": agent_id_display,
                "agent_name": agent_entry.get("name", "N/A"),
                "status": display_status,
                "ip_address": agent_entry.get("ip"),
                "registration_ip": agent_entry.get("registerIP"),
                "os_info": os_details or None,
                "agent_version": agent_entry.get("version"),
                "groups": agent_entry.get("group"),
                "last_keepalive": agent_entry.get("lastKeepAlive"),
                "registration_date": agent_entry.get("dateAdd"),
                "node": agent_entry.get("node_name"),
                "config_status": agent_entry.get("group_config_status")
            })

        # Calculate pagination info
        returned_count = len(processed_agents)
        has_more = (offset + returned_count) < total_items

        return _compact_json({
            "status": "success",
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_items,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "agents": processed_agents
        })

    except Exception as error:
        logger.error(f"Agent retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve agents: {str(error)}"
        })

@mcp_server.tool()
def agentProcesses(agent_identifier: str, max_results: int = 300,
                    search_filter: str = "") -> str:
    """[Wazuh SIEM] Get running processes on an agent via Syscollector.

    This is a Wazuh SIEM tool, NOT Graylog.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.
        max_results: Max processes to return, default 300.
        search_filter: Filter by process name or command.

    Returns:
        JSON object containing:
        - agent_id: queried agent ID
        - total_count: number of processes
        - processes: list of processes, each with process_id, process_name, state, username, command_line, memory_resident_kb

    Example:
        agentProcesses(agent_identifier="001", search_filter="nginx")
    """
    logger.info(f"Fetching processes for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_params = {"limit": max_results, "offset": 0}
        if search_filter:
            api_params["search"] = search_filter

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/processes",
            query_params=api_params
        )

        process_items = api_response.get("data", {}).get("affected_items", [])

        if not process_items:
            return _compact_json({
                "status": "success",
                "message": f"No process data available for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "processes": []
            })

        processed_procs = []
        for proc_entry in process_items:
            # Convert memory values from bytes to KB
            resident_mem = proc_entry.get("resident")
            vm_mem = proc_entry.get("vm_size")

            processed_procs.append({
                "process_id": proc_entry.get("pid", "N/A"),
                "process_name": proc_entry.get("name", "N/A"),
                "state": proc_entry.get("state"),
                "parent_pid": proc_entry.get("ppid"),
                "username": proc_entry.get("euser"),
                "command_line": proc_entry.get("cmd"),
                "start_time": proc_entry.get("start_time"),
                "memory_resident_kb": resident_mem // 1024 if resident_mem else None,
                "memory_virtual_kb": vm_mem // 1024 if vm_mem else None
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_procs),
            "processes": processed_procs
        })

    except Exception as error:
        logger.error(f"Process retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve processes: {str(error)}"
        })

@mcp_server.tool()
def agentPorts(agent_identifier: str, max_results: int = 300,
                protocol_filter: str = "", state_filter: str = "") -> str:
    """[Wazuh SIEM] Get network ports on an agent via Syscollector.

    This is a Wazuh SIEM tool, NOT Graylog.

    Args:
        agent_identifier: Agent ID (e.g. "001"), auto-padded to 3 digits.
        max_results: Max ports to return, default 300.
        protocol_filter: Protocol filter: "tcp" or "udp".
        state_filter: State filter: "LISTENING" or "ESTABLISHED".

    Returns:
        JSON object containing:
        - agent_id: queried agent ID
        - total_count: number of ports
        - ports: list of ports, each with protocol, local_address, remote_address, state, process_name, process_id

    Example:
        agentPorts(agent_identifier="001", state_filter="LISTENING")
    """
    logger.info(f"Fetching network ports for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        # Fetch extra results for client-side filtering
        api_params = {"limit": max_results * 2, "offset": 0}
        if protocol_filter:
            api_params["protocol"] = protocol_filter

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/ports",
            query_params=api_params
        )

        port_items = api_response.get("data", {}).get("affected_items", [])

        # Apply client-side state filtering (matching Rust logic)
        if state_filter:
            is_listening_filter = state_filter.strip().lower() == "listening"
            filtered_ports = []

            for port_entry in port_items:
                port_state = port_entry.get("state", "").strip()

                if not port_state:
                    # Include entries without state only for non-listening filter
                    if not is_listening_filter:
                        filtered_ports.append(port_entry)
                elif is_listening_filter:
                    # For LISTENING filter: only include LISTENING state
                    if port_state.lower() == "listening":
                        filtered_ports.append(port_entry)
                else:
                    # For non-LISTENING filter: exclude LISTENING state
                    if port_state.lower() != "listening":
                        filtered_ports.append(port_entry)

            port_items = filtered_ports[:max_results]
        else:
            port_items = port_items[:max_results]

        if not port_items:
            return _compact_json({
                "status": "success",
                "message": f"No network port data for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "ports": []
            })

        processed_ports = []
        for port_entry in port_items:
            local_info = port_entry.get("local", {})
            local_addr = f"{local_info.get('ip', 'N/A')}:{local_info.get('port', 'N/A')}"

            remote_info = port_entry.get("remote", {})
            remote_addr = None
            if remote_info:
                remote_addr = f"{remote_info.get('ip', 'N/A')}:{remote_info.get('port', 'N/A')}"

            processed_ports.append({
                "protocol": port_entry.get("protocol", "N/A"),
                "local_address": local_addr,
                "remote_address": remote_addr,
                "state": port_entry.get("state"),
                "process_name": port_entry.get("process"),
                "process_id": port_entry.get("pid"),
                "inode": port_entry.get("inode"),
                "tx_queue": port_entry.get("tx_queue"),
                "rx_queue": port_entry.get("rx_queue")
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_ports),
            "ports": processed_ports
        })

    except Exception as error:
        logger.error(f"Port retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve ports: {str(error)}"
        })

@mcp_server.tool()
def agentDetail(agent_identifier: str) -> str:
    """[Wazuh SIEM] Get comprehensive detail for a single agent.

    Returns all available fields: OS, version, groups, config status, registration date,
    last keepalive, node, manager, IP, and more. Use listAgents first to get agent_id.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.

    Returns:
        JSON object with full agent detail including id, name, ip, status, os, version,
        groups, manager, node, last_keepalive, registration_date, config_status, etc.

    Example:
        agentDetail(agent_identifier="001")
    """
    logger.info(f"Fetching detail for agent {agent_identifier}")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_response = query_manager_api(
            "/agents",
            query_params={"agents_list": normalized_id}
        )

        agent_items = api_response.get("data", {}).get("affected_items", [])

        if not agent_items:
            return _compact_json({
                "status": "error",
                "message": f"Agent {normalized_id} not found"
            })

        a = agent_items[0]
        os_data = a.get("os", {})

        result = {
            "agent_id": a.get("id"),
            "agent_name": a.get("name"),
            "status": a.get("status"),
            "ip_address": a.get("ip"),
            "registration_ip": a.get("registerIP"),
            "os": {
                "name": os_data.get("name"),
                "version": os_data.get("version"),
                "codename": os_data.get("codename"),
                "platform": os_data.get("platform"),
                "architecture": os_data.get("arch"),
                "kernel": os_data.get("uname"),
            } if os_data else None,
            "agent_version": a.get("version"),
            "groups": a.get("group"),
            "manager": a.get("manager"),
            "node_name": a.get("node_name"),
            "last_keepalive": a.get("lastKeepAlive"),
            "registration_date": a.get("dateAdd"),
            "config_status": a.get("group_config_status"),
            "status_code": a.get("status_code"),
            "merged_sum": a.get("mergedSum"),
            "config_sum": a.get("configSum"),
        }

        return _compact_json({"status": "success", "agent": result})

    except Exception as error:
        logger.error(f"Agent detail failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve agent detail: {str(error)}"
        })

@mcp_server.tool()
def agentHardware(agent_identifier: str) -> str:
    """[Wazuh SIEM] Get hardware info for an agent via Syscollector.

    Returns CPU model, cores, MHz, RAM total, board serial, etc.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.

    Returns:
        JSON object with cpu (name, cores, mhz), ram (total_mb, free_mb, usage_pct),
        board_serial, scan_time.

    Example:
        agentHardware(agent_identifier="001")
    """
    logger.info(f"Fetching hardware info for agent {agent_identifier}")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/hardware"
        )

        hw_items = api_response.get("data", {}).get("affected_items", [])

        if not hw_items:
            return _compact_json({
                "status": "success",
                "message": f"No hardware data available for agent {normalized_id}",
                "agent_id": normalized_id
            })

        hw = hw_items[0]
        cpu_data = hw.get("cpu", {})
        ram_data = hw.get("ram", {})

        ram_total = ram_data.get("total")
        ram_free = ram_data.get("free")
        ram_usage = ram_data.get("usage")

        result = {
            "agent_id": normalized_id,
            "cpu": {
                "name": cpu_data.get("name"),
                "cores": cpu_data.get("cores"),
                "mhz": cpu_data.get("mhz"),
            },
            "ram": {
                "total_mb": ram_total // 1024 if ram_total else None,
                "free_mb": ram_free // 1024 if ram_free else None,
                "usage_pct": ram_usage,
            },
            "board_serial": hw.get("board_serial"),
            "scan_time": hw.get("scan", {}).get("time"),
        }

        return _compact_json({"status": "success", "hardware": result})

    except Exception as error:
        logger.error(f"Hardware retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve hardware info: {str(error)}"
        })

@mcp_server.tool()
def agentPackages(agent_identifier: str, max_results: int = 500,
                   search_filter: str = "") -> str:
    """[Wazuh SIEM] Get installed software packages on an agent via Syscollector.

    Use this to check for outdated or vulnerable software versions.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.
        max_results: Max packages to return, default 500.
        search_filter: Filter by package name (e.g. "openssl", "nginx").

    Returns:
        JSON object with agent_id, total_count, and packages list (name, version,
        architecture, format, vendor, description, install_time).

    Example:
        agentPackages(agent_identifier="001", search_filter="openssl")
    """
    logger.info(f"Fetching packages for agent {agent_identifier}")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_params = {"limit": max_results, "offset": 0}
        if search_filter:
            api_params["search"] = search_filter

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/packages",
            query_params=api_params
        )

        pkg_items = api_response.get("data", {}).get("affected_items", [])

        if not pkg_items:
            return _compact_json({
                "status": "success",
                "message": f"No package data available for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "packages": []
            })

        processed_pkgs = []
        for pkg in pkg_items:
            processed_pkgs.append({
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "architecture": pkg.get("architecture"),
                "format": pkg.get("format"),
                "vendor": pkg.get("vendor"),
                "description": pkg.get("description"),
                "install_time": pkg.get("install_time"),
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_pkgs),
            "packages": processed_pkgs
        })

    except Exception as error:
        logger.error(f"Package retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve packages: {str(error)}"
        })

@mcp_server.tool()
def agentNetworks(agent_identifier: str) -> str:
    """[Wazuh SIEM] Get network interfaces and IP addresses for an agent via Syscollector.

    Returns interface name, MAC, MTU, state, and all associated IPv4/IPv6 addresses.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.

    Returns:
        JSON object with agent_id, interfaces list (name, mac, mtu, state, type,
        tx/rx stats) and addresses list (iface, address, netmask, broadcast, protocol).

    Example:
        agentNetworks(agent_identifier="001")
    """
    logger.info(f"Fetching network info for agent {agent_identifier}")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        # Fetch network interfaces
        iface_response = query_manager_api(
            f"/syscollector/{normalized_id}/netiface"
        )
        iface_items = iface_response.get("data", {}).get("affected_items", [])

        # Fetch network addresses
        addr_response = query_manager_api(
            f"/syscollector/{normalized_id}/netaddr"
        )
        addr_items = addr_response.get("data", {}).get("affected_items", [])

        processed_ifaces = []
        for iface in iface_items:
            tx = iface.get("tx", {})
            rx = iface.get("rx", {})
            processed_ifaces.append({
                "name": iface.get("name"),
                "mac": iface.get("mac"),
                "mtu": iface.get("mtu"),
                "state": iface.get("state"),
                "type": iface.get("type"),
                "tx_packets": tx.get("packets"),
                "tx_bytes": tx.get("bytes"),
                "tx_errors": tx.get("errors"),
                "rx_packets": rx.get("packets"),
                "rx_bytes": rx.get("bytes"),
                "rx_errors": rx.get("errors"),
            })

        processed_addrs = []
        for addr in addr_items:
            processed_addrs.append({
                "iface": addr.get("iface"),
                "address": addr.get("address"),
                "netmask": addr.get("netmask"),
                "broadcast": addr.get("broadcast"),
                "protocol": addr.get("proto"),
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "interfaces": processed_ifaces,
            "addresses": processed_addrs
        })

    except Exception as error:
        logger.error(f"Network info retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve network info: {str(error)}"
        })

@mcp_server.tool()
def agentSCA(agent_identifier: str) -> str:
    """[Wazuh SIEM] Get Security Configuration Assessment (SCA) results for an agent.

    Returns CIS benchmark / compliance scan results: pass/fail counts, score, and policy details.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.

    Returns:
        JSON object with agent_id and policies list (policy_id, name, description,
        pass, fail, invalid, total_checks, score, references, end_scan, hash_file).

    Example:
        agentSCA(agent_identifier="001")
    """
    logger.info(f"Fetching SCA results for agent {agent_identifier}")

    try:
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_response = query_manager_api(f"/sca/{normalized_id}")

        sca_items = api_response.get("data", {}).get("affected_items", [])

        if not sca_items:
            return _compact_json({
                "status": "success",
                "message": f"No SCA data available for agent {normalized_id}",
                "agent_id": normalized_id,
                "policies": []
            })

        processed_policies = []
        for policy in sca_items:
            processed_policies.append({
                "policy_id": policy.get("policy_id"),
                "name": policy.get("name"),
                "description": policy.get("description"),
                "pass": policy.get("pass"),
                "fail": policy.get("fail"),
                "invalid": policy.get("invalid"),
                "total_checks": policy.get("total_checks"),
                "score": policy.get("score"),
                "references": policy.get("references"),
                "end_scan": policy.get("end_scan"),
                "hash_file": policy.get("hash_file"),
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "policies": processed_policies
        })

    except Exception as error:
        logger.error(f"SCA retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve SCA results: {str(error)}"
        })

@mcp_server.tool()
def agentsOutdated() -> str:
    """[Wazuh SIEM] List agents with outdated Wazuh agent versions.

    Use this to identify hosts that need agent upgrades.

    Returns:
        JSON object with total_count and agents list (id, name, version).

    Example:
        agentsOutdated()
    """
    logger.info("Fetching outdated agents")

    try:
        api_response = query_manager_api("/agents/outdated")

        agent_items = api_response.get("data", {}).get("affected_items", [])

        if not agent_items:
            return _compact_json({
                "status": "success",
                "message": "All agents are up to date",
                "total_count": 0,
                "agents": []
            })

        processed = []
        for a in agent_items:
            processed.append({
                "agent_id": a.get("id"),
                "agent_name": a.get("name"),
                "version": a.get("version"),
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed),
            "agents": processed
        })

    except Exception as error:
        logger.error(f"Outdated agents retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve outdated agents: {str(error)}"
        })

@mcp_server.tool()
def agentsSummary() -> str:
    """[Wazuh SIEM] Get agent status summary (total count per status category).

    Returns how many agents are active, disconnected, pending, and never_connected.
    This only returns counts. For detailed agent list, use listAgents with status_filter.

    Returns:
        JSON object with connection (active, disconnected, pending, never_connected, total)
        and configuration (synced, not_synced, total) counts.

    Example:
        agentsSummary()
    """
    logger.info("Fetching agents summary")

    try:
        api_response = query_manager_api("/agents/summary/status")

        summary = api_response.get("data", {})

        if not summary:
            return _compact_json({
                "status": "error",
                "message": "No summary data returned"
            })

        connection = summary.get("connection", {})
        configuration = summary.get("configuration", {})

        return _compact_json({
            "status": "success",
            "connection": {
                "active": connection.get("active", 0),
                "disconnected": connection.get("disconnected", 0),
                "pending": connection.get("pending", 0),
                "never_connected": connection.get("never_connected", 0),
                "total": connection.get("total", 0),
            },
            "configuration": {
                "synced": configuration.get("synced", 0),
                "not_synced": configuration.get("not_synced", 0),
                "total": configuration.get("total", 0),
            }
        })

    except Exception as error:
        logger.error(f"Agents summary failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve agents summary: {str(error)}"
        })

# ─────────────────── Statistics & Monitoring Tools ───────────────────

@mcp_server.tool()
def searchManagerLogs(max_results: int = 300, skip_count: int = 0,
                        level_filter: str = "", tag_filter: str = "",
                        keyword_search: str = "") -> str:
    """[Wazuh SIEM] Search Wazuh Manager system logs.

    This is a Wazuh SIEM tool, NOT Graylog. Use level_filter="error" to see error logs only.

    Args:
        max_results: Max log entries to return, default 300.
        skip_count: Skip first N entries, default 0.
        level_filter: Log level filter: "error", "warning", or "info".
        tag_filter: Filter by log tag.
        keyword_search: Search keyword in log description.

    Returns:
        JSON object containing:
        - total_count: number of log entries
        - logs: list of logs, each with timestamp, tag, level, description

    Example:
        searchManagerLogs(level_filter="error", keyword_search="connection")
    """
    logger.info(f"Searching manager logs (max={max_results}, level={level_filter})")

    try:
        api_params = {"limit": max_results, "offset": skip_count}
        if level_filter:
            api_params["level"] = level_filter
        if tag_filter:
            api_params["tag"] = tag_filter
        if keyword_search:
            api_params["search"] = keyword_search

        api_response = query_manager_api("/manager/logs", query_params=api_params)

        log_items = api_response.get("data", {}).get("affected_items", [])

        if not log_items:
            return _compact_json({
                "status": "success",
                "message": "No log entries match the search criteria",
                "total_count": 0,
                "logs": []
            })

        processed_logs = []
        for log_entry in log_items:
            processed_logs.append({
                "timestamp": log_entry.get("timestamp", "N/A"),
                "tag": log_entry.get("tag", "N/A"),
                "level": log_entry.get("level", "N/A"),
                "description": log_entry.get("description", "No description")
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed_logs),
            "logs": processed_logs
        })

    except Exception as error:
        logger.error(f"Log search failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to search logs: {str(error)}"
        })

@mcp_server.tool()
def logCollectorStats(agent_identifier: str) -> str:
    """[Wazuh SIEM] Get log collector statistics (events, bytes, per-file metrics) for an agent.

    This is a Wazuh SIEM tool, NOT Graylog.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"), auto-padded to 3 digits.

    Returns:
        JSON object containing:
        - statistics: with agent_id, global_period (overall stats), interval_period (interval stats), each with per-file metrics

    Example:
        logCollectorStats(agent_identifier="001")
    """
    logger.info(f"Fetching log collector stats for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_response = query_manager_api(
            f"/agents/{normalized_id}/stats/logcollector"
        )

        stats_items = api_response.get("data", {}).get("affected_items", [])

        if not stats_items:
            return _compact_json({
                "status": "success",
                "message": f"No log collector stats for agent {normalized_id}",
                "agent_id": normalized_id
            })

        stats_data = stats_items[0]

        def extract_period_stats(period_info):
            """Extract statistics for a time period"""
            if not period_info:
                return None

            file_stats = []
            for file_data in period_info.get("files", []):
                target_stats = []
                for target_data in file_data.get("targets", []):
                    target_stats.append({
                        "name": target_data.get("name"),
                        "drops": target_data.get("drops")
                    })

                file_stats.append({
                    "file_path": file_data.get("location"),
                    "events_count": file_data.get("events"),
                    "bytes_count": file_data.get("bytes"),
                    "targets": target_stats
                })

            return {
                "period_start": period_info.get("start"),
                "period_end": period_info.get("end"),
                "files": file_stats
            }

        collector_stats = {
            "agent_id": normalized_id,
            "global_period": extract_period_stats(stats_data.get("global")),
            "interval_period": extract_period_stats(stats_data.get("interval"))
        }

        return _compact_json({
            "status": "success",
            "statistics": collector_stats
        })

    except Exception as error:
        logger.error(f"Log collector stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve log collector stats: {str(error)}"
        })

@mcp_server.tool()
def remotedStats() -> str:
    """[Wazuh SIEM] Get remoted daemon statistics (queue sizes, TCP sessions, message counts, traffic).

    This is a Wazuh SIEM tool, NOT Graylog.

    Returns:
        JSON object containing:
        - statistics: with queue_size, total_queue_size, tcp_sessions, sent_bytes, recv_bytes

    Example:
        remotedStats()
    """
    logger.info("Fetching remoted daemon statistics")

    try:
        api_response = query_manager_api("/manager/stats/remoted")

        stats_items = api_response.get("data", {}).get("affected_items", [])

        if not stats_items:
            return _compact_json({
                "status": "error",
                "message": "Remoted statistics unavailable"
            })

        stats_data = stats_items[0]

        remoted_metrics = {
            "queue_size": stats_data.get("queue_size"),
            "total_queue_size": stats_data.get("total_queue_size"),
            "tcp_sessions": stats_data.get("tcp_sessions"),
            "ctrl_msg_count": stats_data.get("ctrl_msg_count"),
            "discarded_count": stats_data.get("discarded_count"),
            "sent_bytes": stats_data.get("sent_bytes"),
            "recv_bytes": stats_data.get("recv_bytes"),
            "dequeued_after_close": stats_data.get("dequeued_after_close")
        }

        return _compact_json({
            "status": "success",
            "statistics": remoted_metrics
        })

    except Exception as error:
        logger.error(f"Remoted stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve remoted stats: {str(error)}"
        })

@mcp_server.tool()
def weeklyStats() -> str:
    """[Wazuh SIEM] Get weekly aggregated performance statistics from the Wazuh Manager.

    This is a Wazuh SIEM tool, NOT Graylog.

    Returns:
        JSON object containing:
        - statistics: weekly performance metrics

    Example:
        weeklyStats()
    """
    logger.info("Fetching weekly statistics")

    try:
        api_response = query_manager_api("/manager/stats/weekly")

        return _compact_json({
            "status": "success",
            "statistics": api_response.get("data", {})
        })

    except Exception as error:
        logger.error(f"Weekly stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve weekly stats: {str(error)}"
        })

@mcp_server.tool()
def clusterHealth() -> str:
    """[Wazuh SIEM] Check Wazuh cluster health (enabled, running, per-node status).

    This is a Wazuh SIEM tool, NOT Graylog.
    Works in both cluster and standalone deployments. In standalone mode,
    enabled/running will be false and there are no node details.

    Returns:
        JSON object containing:
        - cluster_health: with is_healthy, enabled, running, connected_nodes, nodes
          (nodes array includes name, type master/worker, status)

    Example:
        clusterHealth()
    """
    logger.info("Checking cluster health")

    try:
        # Retrieve cluster status.
        # Note: /cluster/status returns enabled/running directly under `data`,
        # NOT inside affected_items (which is used by list-type endpoints).
        status_response = query_manager_api("/cluster/status")
        status_info = status_response.get("data", {}) or {}

        if not status_info:
            return _compact_json({
                "status": "error",
                "message": "Unable to retrieve cluster status"
            })

        cluster_enabled = str(status_info.get("enabled", "no")).lower() == "yes"
        cluster_running = str(status_info.get("running", "no")).lower() == "yes"

        health_assessment = {
            "is_healthy": cluster_enabled and cluster_running,
            "enabled": cluster_enabled,
            "running": cluster_running
        }

        # Check node connectivity if cluster is operational
        if cluster_enabled and cluster_running:
            try:
                health_response = query_manager_api("/cluster/healthcheck")
                health_data = health_response.get("data", {}) or {}
                node_items = health_data.get("affected_items", []) or []
                # Count from affected_items length (or total_affected_items if present).
                # Note: Wazuh 4.x /cluster/healthcheck has no `n_connected_nodes` field.
                connected_count = health_data.get("total_affected_items") or len(node_items)
                health_assessment["connected_nodes"] = connected_count

                # Surface per-node detail so operators can see which workers are up
                nodes = []
                for node_entry in node_items:
                    info = node_entry.get("info", {}) or {}
                    nodes.append({
                        "name": info.get("name") or node_entry.get("name"),
                        "type": info.get("type"),
                        "version": info.get("version"),
                        "ip": info.get("ip"),
                        "active_agents": info.get("n_active_agents"),
                    })
                if nodes:
                    health_assessment["nodes"] = nodes

                if connected_count == 0:
                    health_assessment["is_healthy"] = False
                    health_assessment["health_issue"] = "No nodes connected"
            except Exception as hc_error:
                logger.warning(f"Healthcheck call failed (continuing): {hc_error}")
        elif not cluster_enabled:
            health_assessment["health_issue"] = "Cluster not enabled (standalone mode)"
        elif not cluster_running:
            health_assessment["health_issue"] = "Cluster not running"

        return _compact_json({
            "status": "success",
            "cluster_health": health_assessment
        })

    except Exception as error:
        logger.error(f"Cluster health check failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to check cluster health: {str(error)}"
        })

@mcp_server.tool()
def clusterNodes(max_results: int = 500, skip_count: int = 0,
                  node_type_filter: str = "") -> str:
    """[Wazuh SIEM] List Wazuh cluster nodes with type, version, IP, and status.

    This is a Wazuh SIEM tool, NOT Graylog.

    Args:
        max_results: Max nodes to return, default 500.
        skip_count: Skip first N nodes, default 0.
        node_type_filter: Node type filter: "master" or "worker".

    Returns:
        JSON object containing:
        - total_count: number of nodes
        - nodes: list of nodes, each with node_name, node_type, version, ip_address, status

    Example:
        clusterNodes(node_type_filter="worker")
    """
    logger.info(f"Fetching cluster nodes (max={max_results}, type={node_type_filter})")

    try:
        api_params = {"offset": skip_count, "limit": max_results}
        if node_type_filter:
            api_params["type"] = node_type_filter

        api_response = query_manager_api("/cluster/nodes", query_params=api_params)

        node_items = api_response.get("data", {}).get("affected_items", [])

        if not node_items:
            return _compact_json({
                "status": "success",
                "message": "No cluster nodes found",
                "total_count": 0,
                "nodes": []
            })

        processed_nodes = []
        for node_entry in node_items:
            node_status = node_entry.get("status", "unknown")

            # Map status to display format
            status_map = {
                "connected": "CONNECTED",
                "active": "CONNECTED",
                "disconnected": "DISCONNECTED"
            }
            display_status = status_map.get(node_status.lower(), node_status.upper())

            processed_nodes.append({
                "node_name": node_entry.get("name", "N/A"),
                "node_type": node_entry.get("type", "N/A"),
                "version": node_entry.get("version", "N/A"),
                "ip_address": node_entry.get("ip", "N/A"),
                "status": display_status
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed_nodes),
            "nodes": processed_nodes
        })

    except Exception as error:
        logger.error(f"Cluster node retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve cluster nodes: {str(error)}"
        })

# ─────────────────── Utility Tools ───────────────────

@mcp_server.tool()
def healthCheck() -> str:
    """[Wazuh SIEM] Test connectivity to Wazuh Manager and Indexer, returns response times, cache stats, and config.

    This is a Wazuh SIEM tool, NOT Graylog.

    Returns:
        JSON object containing:
        - overall_status: health status (healthy/unhealthy)
        - manager_api: Manager API status and response time in ms
        - indexer_api: Indexer API status and response time in ms
        - cache: cache statistics
        - configuration: current settings

    Example:
        healthCheck()
    """
    logger.info("Executing health check")

    try:
        # Test Manager API
        manager_start = time.time()
        query_manager_api("/", enable_cache=False)
        manager_latency = time.time() - manager_start

        # Test Indexer API
        indexer_start = time.time()
        query_indexer_api("/", enable_cache=False)
        indexer_latency = time.time() - indexer_start

        # Get cache metrics
        cache_metrics = memory_cache.get_statistics()

        health_report = {
            "overall_status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "manager_api": {
                "status": "operational",
                "response_time_ms": round(manager_latency * 1000, 2),
                "endpoint": f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}"
            },
            "indexer_api": {
                "status": "operational",
                "response_time_ms": round(indexer_latency * 1000, 2),
                "endpoint": f"{wazuh_config.protocol}://{wazuh_config.indexer_host}:{wazuh_config.indexer_port}"
            },
            "cache": cache_metrics,
            "configuration": {
                "request_timeout": wazuh_config.request_timeout,
                "retry_attempts": wazuh_config.retry_attempts,
                "ssl_verification": wazuh_config.use_ssl
            }
        }

        return _compact_json(health_report)

    except Exception as error:
        return _compact_json({
            "overall_status": "unhealthy",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        })

@mcp_server.tool()
def clearCache() -> str:
    """[Wazuh SIEM] Clear all cached Wazuh API responses. Forces fresh data on next request.

    This is a Wazuh SIEM tool, NOT Graylog.

    Returns:
        JSON object containing:
        - status: request status
        - message: result message

    Example:
        clearCache()
    """
    logger.info("Clearing cache")
    memory_cache.invalidate_all()
    return _compact_json({
        "status": "success",
        "message": "Cache cleared successfully"
    })

@mcp_server.tool()
def cacheStats() -> str:
    """[Wazuh SIEM] Get Wazuh cache usage info (total entries, valid entries, TTL).

    This is a Wazuh SIEM tool, NOT Graylog.

    Returns:
        JSON object containing:
        - cache_statistics: with total_entries, valid_entries, ttl_seconds

    Example:
        cacheStats()
    """
    logger.info("Retrieving cache statistics")
    cache_metrics = memory_cache.get_statistics()
    return _compact_json({
        "status": "success",
        "cache_statistics": cache_metrics
    })

# ═══════════════════════ CLI Argument Parser ═══════════════════════

def parse_cli_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Wazuh SIEM MCP Server - FastMCP Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

  Command Line Configuration:
    python3 mcp_wazuh.py \\
      --manager-host 192.168.1.100 --manager-user wazuh --manager-pass wazuh \\
      --indexer-host 192.168.1.100 --indexer-user admin --indexer-pass admin

  Environment Variables:
    export WAZUH_MANAGER_HOST=192.168.1.100
    export WAZUH_MANAGER_USER=wazuh
    export WAZUH_MANAGER_PASS=wazuh
    python3 mcp_wazuh.py

  Mixed Configuration:
    WAZUH_MANAGER_HOST=192.168.1.100 python3 mcp_wazuh.py \\
      --manager-user wazuh --manager-pass wazuh

  SSE Transport (legacy MCP clients, e.g. Chatbox):
    python3 mcp_wazuh.py --transport sse --host 0.0.0.0 --port 8000 \\
      --api-key YOUR_SECRET_KEY \\
      --manager-host 192.168.1.100 --manager-user wazuh --manager-pass wazuh \\
      --indexer-host 192.168.1.100 --indexer-user admin --indexer-pass admin

  Streamable HTTP Transport (network-based / multi-client):
    python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \\
      --api-key YOUR_SECRET_KEY \\
      --manager-host 192.168.1.100 --manager-user wazuh --manager-pass wazuh \\
      --indexer-host 192.168.1.100 --indexer-user admin --indexer-pass admin
        """
    )

    # Manager configuration
    mgr_group = parser.add_argument_group('Wazuh Manager API Configuration')
    mgr_group.add_argument('--manager-host', help='Manager hostname or IP')
    mgr_group.add_argument('--manager-port', type=int, help='Manager port (default: 55000)')
    mgr_group.add_argument('--manager-user', help='Manager username')
    mgr_group.add_argument('--manager-pass', help='Manager password')

    # Indexer configuration
    idx_group = parser.add_argument_group('Wazuh Indexer Configuration')
    idx_group.add_argument('--indexer-host', help='Indexer hostname or IP')
    idx_group.add_argument('--indexer-port', type=int, help='Indexer port (default: 9200)')
    idx_group.add_argument('--indexer-user', help='Indexer username')
    idx_group.add_argument('--indexer-pass', help='Indexer password')

    # Connection settings
    conn_group = parser.add_argument_group('Connection Settings')
    conn_group.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                           help='Enable SSL verification (default: false)')
    conn_group.add_argument('--protocol', choices=['http', 'https'],
                           help='Connection protocol (default: https)')

    # Performance settings
    perf_group = parser.add_argument_group('Performance Settings')
    perf_group.add_argument('--cache-duration', type=int,
                           help='Cache duration in seconds (default: 300)')
    perf_group.add_argument('--request-timeout', type=int,
                           help='Request timeout in seconds (default: 30)')
    perf_group.add_argument('--retry-attempts', type=int,
                           help='Retry attempts for failed requests (default: 3)')

    # Transport settings
    transport_group = parser.add_argument_group('MCP Transport Settings')
    transport_group.add_argument('--transport', choices=['stdio', 'sse', 'streamable-http'],
                                default='stdio',
                                help='MCP transport type (default: stdio)')
    transport_group.add_argument('--host', default='0.0.0.0',
                                help='HTTP server host for sse/streamable-http (default: 0.0.0.0)')
    transport_group.add_argument('--port', type=int, default=8000,
                                help='HTTP server port for sse/streamable-http (default: 8000)')
    transport_group.add_argument('--api-key',
                                default=os.environ.get('MCP_API_KEY', ''),
                                help='API key for authentication (or set MCP_API_KEY env var)')

    # Severity threshold settings
    sev_group = parser.add_argument_group('Severity Threshold Settings')
    sev_group.add_argument('--severity-low-max', type=int,
                          help='Max rule level for Low severity label (default: 6)')
    sev_group.add_argument('--severity-medium-max', type=int,
                          help='Max rule level for Medium severity label (default: 11)')
    sev_group.add_argument('--severity-high-max', type=int,
                          help='Max rule level for High severity label (default: 13)')

    return parser.parse_args()

# ═══════════════════════ Main Entry Point ═══════════════════════

if __name__ == "__main__":
    # Parse CLI arguments
    cli_args = parse_cli_arguments()

    # Initialize configuration
    wazuh_config = WazuhConfig(cli_args)

    # Initialize cache and HTTP sessions
    memory_cache = MemoryCache(wazuh_config.cache_duration)
    setup_http_sessions()

    # Display startup banner
    logger.info("=" * 80)
    logger.info("Wazuh SIEM MCP Server v1.3.8")
    logger.info("=" * 80)
    logger.info("Reference: Inspired by mcp-server-wazuh (Rust) by Gianluca Brigandi")
    logger.info("=" * 80)
    logger.info("Available Tools (25 total, camelCase):")
    logger.info("  • healthCheck() - Connectivity diagnostics")
    logger.info("  • alertSummary() - Security alerts with IoC")
    logger.info("  • alertStatistics() - Alert counts & distribution")
    logger.info("  • agentsWithAlerts() - Agents ranked by alert count")
    logger.info("  • rulesSummary() - Detection rules & compliance")
    logger.info("  • vulnerabilitySummary() - CVE scan results per agent")
    logger.info("  • listGroups() - Group inventory with agent counts")
    logger.info("  • listAgents() - Agent inventory")
    logger.info("  • agentDetail() - Single agent full detail")
    logger.info("  • agentHardware() - CPU, RAM, board serial")
    logger.info("  • agentPackages() - Installed software packages")
    logger.info("  • agentNetworks() - Network interfaces & IP addresses")
    logger.info("  • agentSCA() - Security Configuration Assessment")
    logger.info("  • agentsOutdated() - Agents needing version upgrade")
    logger.info("  • agentsSummary() - Agent status overview")
    logger.info("  • agentProcesses() - Process monitoring")
    logger.info("  • agentPorts() - Network port analysis")
    logger.info("  • searchManagerLogs() - Manager log search")
    logger.info("  • logCollectorStats() - Collection metrics")
    logger.info("  • remotedStats() - Daemon statistics")
    logger.info("  • weeklyStats() - Weekly aggregates")
    logger.info("  • clusterHealth() - Cluster status")
    logger.info("  • clusterNodes() - Node inventory")
    logger.info("  • clearCache() / cacheStats() - Cache management")
    logger.info("=" * 80)
    logger.info(f"Configuration:")
    logger.info(f"  Cache: {wazuh_config.cache_duration}s | Timeout: {wazuh_config.request_timeout}s")
    logger.info(f"  Retries: {wazuh_config.retry_attempts} | SSL: {wazuh_config.use_ssl}")
    logger.info(f"  Transport: {cli_args.transport}")
    if cli_args.transport == "sse":
        logger.info(f"  SSE endpoint: http://{cli_args.host}:{cli_args.port}/sse")
    elif cli_args.transport == "streamable-http":
        logger.info(f"  HTTP endpoint: http://{cli_args.host}:{cli_args.port}/mcp")
    logger.info("=" * 80)

    # Start MCP server with selected transport
    if cli_args.transport in ("sse", "streamable-http"):
        import uvicorn
        from starlette.responses import JSONResponse

        # Build Starlette app from FastMCP
        if cli_args.transport == "sse":
            app = mcp_server.sse_app()
        else:
            app = mcp_server.streamable_http_app()

        # Add API key authentication middleware if configured
        # NOTE: Use pure ASGI middleware — BaseHTTPMiddleware buffers
        #       streaming responses, which breaks SSE event delivery.
        if cli_args.api_key:
            _api_key = cli_args.api_key

            class APIKeyAuthMiddleware:
                def __init__(self, app):
                    self.app = app

                async def __call__(self, scope, receive, send):
                    if scope["type"] == "http":
                        headers = dict(scope.get("headers", []))
                        auth = headers.get(b"authorization", b"").decode()
                        token = auth[7:] if auth.startswith("Bearer ") else auth
                        if token != _api_key:
                            resp = JSONResponse(
                                {"error": "Unauthorized", "message": "Invalid or missing API key"},
                                status_code=401
                            )
                            await resp(scope, receive, send)
                            return
                    await self.app(scope, receive, send)

            app.add_middleware(APIKeyAuthMiddleware)
            logger.info(f"  API key authentication: enabled")

        uvicorn.run(app, host=cli_args.host, port=cli_args.port)
    else:
        mcp_server.run(transport="stdio")
