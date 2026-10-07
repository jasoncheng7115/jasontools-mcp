#!/usr/bin/env python3
"""
OPNsense MCP Server - v2.5.0 (FastMCP Rewrite)
================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
License: MIT
Created: 2025-06-25
Updated: 2026-10-07

FastMCP-based OPNsense integration optimized for weak/small LLMs.
28 tools, compact responses, camelCase tool names. Strictly read-only.
Supports stdio, streamable-http, and sse transport.

pip install mcp aiohttp requests defusedxml uvicorn

API vs config.xml
-----------------
Rules/aliases/NAT/gateways are read from the native MVC API first and fall back to
config.xml only when the API is unavailable (older OPNsense, missing plugin, error).
Every affected tool reports which source it used via a "source" field.

Minimum OPNsense version per data source (see README for the full matrix):
  - firewall/filter/search_rule   : 24.1+  (see the 26.1 cutover note below)
  - firewall/{source_nat,npt}/search_rule : 24.1+
  - firewall/one_to_one/search_rule       : 24.7+ (safe floor)
  - firewall/d_nat/search_rule    : 26.1+  (port forward; config.xml-only before that)
  - firewall/alias/search_item, alias_util/list : 23.7+
  - routing/settings/search_gateway : 24.1+
  - routes/gateway/status           : 23.7+
  - core/backup/download/this       : 23.7.8+ or os-api-backup plugin (fallback path)

IMPORTANT (the 26.1 cutover): filter/search_rule exists from 24.1, but on 24.1-25.7 it
only exposed Firewall > Automation rules — the real GUI rules lived in config.xml
<filter><rule>. In 26.1 the rules were promoted into the MVC model, and config.xml
<filter><rule> is now EMPTY. So neither source alone is correct across versions:
reading config.xml returns 0 rules on 26.1, reading the API returns only automation
rules on 25.x. We read the API first (with show_all=1, which on 25.x is what merges
the legacy config.xml rules into the response) and fall back to config.xml.

Changelog:
  v2.5.0 (2026-10-07) - Fixes from a live 26.1 review; 7 new read-only tools
    - FIX getDhcpLeases: always empty on Kea/Dnsmasq firewalls (only the ISC API was
      read, and ISC DHCP is a plugin since 26.1). Kea v4/v6, Dnsmasq and ISC v4/v6 are
      queried in parallel and merged; each lease says which server it came from.
    - FIX getDhcpSettings: 404 on 26.1. Now reports the active server and, for Kea,
      subnets, pools, routers/DNS/NTP handed out and static reservations.
    - FIX getRoutes: returned only System > Routes (static), empty on most firewalls.
      Now the kernel routing table (diagnostics/interface/getRoutes) + static routes.
    - FIX getInterfaces(interface=x): getInterfaceConfig ignores its argument and
      returned every interface. Rewritten on interfaces/overview/interfacesInfo: name,
      device, status, IPv4/IPv6, gateway, media (link speed), MTU, MAC.
    - FIX getServiceStatus: core/service/status/<x> does not exist; ids such as
      kea-dhcp/v4 could not be looked up. Now matches id/name/description.
    - FIX read-only: getFirmwareStatus/getFirmwareInfo/getFirmwareConfig POSTed
      core/firmware/{check,audit,health,connection}, which START jobs on the firewall
      (every LLM question triggered an update check). Removed; status now reports the
      router's last check and its age.
    - FIX size: getFirmwareInfo ~400 KB -> <1 KB; getFirmwareStatus 46 KB -> <1 KB;
      getAliasContent gets search (IP -> containing networks) + limit (GeoIP 140 KB).
    - getAliasContent: port aliases are not pf tables (returned 0); falls back to the
      configured content.
    - getAliases: API is the default source, same fields as config.xml, plus live
      current_items / last_updated.
    - getConfigSummary/downloadConfigXml: version from system_information instead of
      the 400 KB firmware/info (10 s -> ~1 s).
    - _request: HTTP 4xx is not retried (each missing endpoint cost ~3.5 s).
    - NEW getSystemHealth, getFirewallLog (rule name resolved from rid; wan/WAN2 mapped
      to devices), getFirewallStates, getSystemLog (fixed scope list - the same path
      family has a "clear" action), getVpnStatus, getIdsAlerts, getCertificates
      (allowlisted fields: trust/cert/search also returns private keys).
    - getFirewallRules: include_stats / unused_only via firewall/filter_util/rule_stats.
  v2.4.1 (2026-09-29) - SSE clients stuck on an uninitialized session
    - SSE mode now also serves Streamable HTTP at /mcp on the same port.
      SSE clients that auto-reconnect after a dropped connection (laptop sleep) get a
      fresh session without re-sending `initialize`; every call then fails with -32602
      "Invalid request parameters" (server log: "Received request before initialization
      was complete").
    - Streamable HTTP runs stateless: no server-side session to lose, so sleep/wake
      and server restarts no longer break clients. Clients should move to /mcp.
    - API key check is now plain ASGI middleware with a constant-time compare;
      BaseHTTPMiddleware logged an AssertionError on every SSE disconnect.
  v2.4.0 (2026-07-12) - API-first reads, gateways, real config.xml export
    - FIX: getFirewallRules/getConfigSummary returned 0 rules on OPNsense 26.1.
      They read config.xml <filter><rule>, which 26.1 leaves empty (rules moved to
      the MVC model). Now read firewall/filter/search_rule, config.xml as fallback.
    - NEW getGateways: gateway config + live status (monitor IP, monitor_disable,
      priority, weight, loss/delay) via routing/settings/search_gateway, which also
      surfaces dynamic (DHCP/PPPoE) gateways that have no config entry.
    - getNatRules: single entry point for all NAT types. nat_type now accepts
      port_forward | outbound | source_nat | one_to_one | npt. Port forward uses the
      26.1 firewall/d_nat API (note: the endpoint is "d_nat", not "forward"/"dnat"),
      falling back to config.xml <nat><rule> on older releases.
    - downloadConfigXml: new `section` arg returns the raw XML of a config.xml
      section (e.g. "gateways", "system", "nat"). No arg = previous summary output.
    - Synthetic rows (anti-lockout in d_nat, automatic outbound in source_nat) are
      tagged is_automatic and excluded by default; pass include_automatic=True.
    - Backward compatible: all v2.3.0 tool names and arguments still work.
      getNatRulesConfig is kept as a config.xml-only compatibility wrapper.
  v2.3.0 - Native-API firewall rules + aliases (INCOMPLETE - see v2.4.0)
    - Changelog claimed API-based rules but the code still parsed config.xml;
      the firewall_rules=0 bug it was meant to fix was actually shipped. Fixed in v2.4.0.
  v2.2.1 (2026-03-02) - Fix Claude Desktop launch: upgrade mcp 1.9.4 → 1.26.0
    - Local venv mcp package too old, missing mcp.server.transport_security module
    - Upgraded /Users/jasoncheng/venvs/mcp-opnsense/ mcp dependency
  v2.2.0 (2026-03-01) - Add getPlugins and getPackages tools
    - getPlugins: list/search OPNsense plugins (os-* packages) with status filter
    - getPackages: list/search system packages (non os-*) with status filter
    - Updated getFirmwareInfo docstring to reference new tools
    - 20 tools → 20 tools
  v2.1.1 (2026-03-01) - Fix version retrieval in getConfigSummary/downloadConfigXml
    - Switched from get_firmware_status() to get_firmware_info() for version retrieval
      (firmware/status returns empty when no firmware check has been run;
       firmware/info always returns product version reliably)
    - Added product_nickname and os_version to getConfigSummary system info
    - Added fallback: product sub-object → top-level fields
  v2.1.0 (2026-03-01) - Add OPNsense version to config summary
    - getConfigSummary and downloadConfigXml now include product_version/product_name
      from firmware API (config.xml doesn't contain OPNsense version)
    - Deployed mcp_opnsense_sse.service (SSE direct, port 8017)
  v2.0.0 (2026-02-28) - Complete FastMCP rewrite
    - Migrated from mcp.server.Server to FastMCP with @mcp.tool() decorators
    - 35 tools consolidated to 18 (49% reduction)
    - camelCase tool names optimized for gpt-oss:120b
    - [YES]/[NO] intent markers in docstrings
    - Compact JSON output via _R() (no indent, no ensure_ascii)
    - Config class: CLI args > env vars > defaults
    - SimpleCache with TTL for GET requests
    - Retry with exponential backoff
    - Multi-transport: stdio (default), streamable-http, sse
    - API key auth for HTTP transports (--mcp-api-key / MCP_API_KEY)
    - DNS rebinding protection disabled (fixes 421 Misdirected Request)
    - Removed _format_table_output (table format wastes tokens)
    - Removed get_firmware_comprehensive_overview, get_network_overview (split across tools)
  v1.6.0 (2025-06-25) - Added firmware and package version information functionality
  v1.5.0 (2025-06-25) - Added service management, DHCP, NAT, interface tools
"""

import json

# Override json.dumps default: output CJK characters as-is (not \uXXXX escapes)
# so LLMs can read them directly without decoding errors
_json_dumps_original = json.dumps
json.dumps = lambda *args, **kwargs: _json_dumps_original(*args, **{**{'ensure_ascii': False}, **kwargs})

import asyncio
import hashlib
import ipaddress
import logging
import os
import ssl
import sys
import time
import argparse
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import Element  # For type hints only
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mcp-opnsense")

__version__ = "2.5.0"


# ───────────────────────── Configuration ─────────────────────────

class Config:
    def __init__(self, args=None):
        if args:
            self.HOST = args.host or os.getenv("OPNSENSE_HOST")
            self.API_KEY = args.api_key or os.getenv("OPNSENSE_API_KEY", "")
            self.API_SECRET = args.api_secret or os.getenv("OPNSENSE_API_SECRET", "")
            self.VERIFY_SSL = args.verify_ssl if args.verify_ssl is not None else os.getenv("OPNSENSE_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
            self.TIMEOUT = args.timeout if args.timeout is not None else int(os.getenv("OPNSENSE_TIMEOUT", "30"))
            self.CACHE_TTL = args.cache_ttl if args.cache_ttl is not None else int(os.getenv("OPNSENSE_CACHE_TTL", "300"))
            self.MAX_RETRIES = args.max_retries if args.max_retries is not None else int(os.getenv("OPNSENSE_MAX_RETRIES", "3"))
        else:
            self.HOST = os.getenv("OPNSENSE_HOST", "https://192.168.1.1")
            self.API_KEY = os.getenv("OPNSENSE_API_KEY", "")
            self.API_SECRET = os.getenv("OPNSENSE_API_SECRET", "")
            self.VERIFY_SSL = os.getenv("OPNSENSE_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
            self.TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "30"))
            self.CACHE_TTL = int(os.getenv("OPNSENSE_CACHE_TTL", "300"))
            self.MAX_RETRIES = int(os.getenv("OPNSENSE_MAX_RETRIES", "3"))
        self.validate()

    def validate(self):
        if not self.HOST:
            logger.error("OPNsense HOST is required!")
            logger.error("  Command line: --host <URL>")
            logger.error("  Environment:  OPNSENSE_HOST=<URL>")
            sys.exit(1)
        if not self.HOST.startswith(('http://', 'https://')):
            self.HOST = f"https://{self.HOST}"
        self.HOST = self.HOST.rstrip('/')
        if not self.VERIFY_SSL:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.info(f"OPNsense Host: {self.HOST}")


# ───────────────────────── SimpleCache + Helpers ─────────────────────────

class SimpleCache:
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl

    def _key(self, key_data: str) -> str:
        return hashlib.md5(key_data.encode('utf-8')).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        safe_key = self._key(key)
        if safe_key in self.cache:
            data, ts = self.cache[safe_key]
            if time.time() - ts < self.ttl:
                return data
            del self.cache[safe_key]
        return None

    def set(self, key: str, value: Any):
        self.cache[self._key(key)] = (value, time.time())

    def clear(self):
        self.cache.clear()

    def stats(self) -> Dict[str, int]:
        now = time.time()
        active = sum(1 for _, (_, ts) in self.cache.items() if now - ts < self.ttl)
        return {"total_keys": len(self.cache), "active_keys": active, "ttl_seconds": self.ttl}


def _R(obj) -> str:
    """Compact JSON serialization (no indent, no ASCII escape)."""
    return json.dumps(obj, ensure_ascii=False)


def _truthy(v: Any) -> bool:
    """OPNsense encodes booleans as "1"/"0", "yes"/"no", true/false depending on endpoint."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "yes", "true", "on")


def _sel(v: Any) -> str:
    """Collapse an OPNsense dropdown field to its selected key.

    Model reads (routing/settings/get, firewall/*/get) return option fields as
    {"opt1": {"value": "Label", "selected": 0}, ...}; search_* endpoints return the
    plain key instead. Accept both.
    """
    if isinstance(v, dict):
        for key, opt in v.items():
            if isinstance(opt, dict) and _truthy(opt.get("selected")):
                return key
        return ""
    return "" if v is None else str(v)


def _alias_meta(meta: Any) -> Dict[str, str]:
    """Pull alias names + descriptions out of an alias_meta_<field> list.

    Each entry is {"value", "%value", "isAlias", "description"}; only isAlias entries
    are real aliases (plain networks like 192.0.2.0/24 appear here too).
    """
    if not isinstance(meta, list):
        return {}
    names, descs = [], []
    for entry in meta:
        if isinstance(entry, dict) and _truthy(entry.get("isAlias")):
            if entry.get("value"):
                names.append(str(entry["value"]))
            if entry.get("description"):
                descs.append(str(entry["description"]))
    out = {}
    if names:
        out["alias"] = ",".join(names)
    if descs:
        out["alias_desc"] = "; ".join(descs)
    return out


def _iface_match(rule_iface: str, wanted: str) -> bool:
    """A rule's interface field can list several interfaces ("wan,opt2")."""
    if not wanted:
        return True
    parts = [p.strip().lower() for p in str(rule_iface).split(",") if p.strip()]
    return wanted.strip().lower() in parts


def _normalize_api_rule(row: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a firewall/filter/search_rule row into a compact, LLM-friendly rule.

    Automatic/legacy rows and MVC rows have different shapes: MVC rows carry the raw
    key plus a "%"-prefixed label ("action": "block" / "%action": "Block") and an
    interface, while automatic rows carry only the already-human value and no
    interface at all. Prefer the raw key, fall back to the label.
    """
    def pick(key: str) -> str:
        return str(row.get(key) or row.get(f"%{key}") or "")

    is_auto = _truthy(row.get("is_automatic")) or _truthy(row.get("legacy"))
    rule = {
        "uuid": row.get("uuid", ""),
        "description": row.get("description") or row.get("descr") or "",
        "enabled": _truthy(row.get("enabled")),
        "action": pick("action").lower(),
        "interface": row.get("interface", ""),
        "direction": pick("direction").lower(),
        "ipprotocol": pick("ipprotocol"),
        "protocol": pick("protocol"),
        "source": row.get("source_net", ""),
        "source_port": row.get("source_port", ""),
        "destination": row.get("destination_net", ""),
        "destination_port": row.get("destination_port", ""),
        "sequence": row.get("sequence", ""),
        "is_automatic": is_auto,
    }
    if row.get("%interface"):
        rule["interface_label"] = row["%interface"]
    for field, prefix in (("source_net", "src"), ("destination_net", "dst")):
        for key, val in _alias_meta(row.get(f"alias_meta_{field}")).items():
            rule[f"{prefix}_{key}"] = val
    if _truthy(row.get("log")):
        rule["log"] = True
    if row.get("gateway"):
        rule["gateway"] = row["gateway"]
    return {k: v for k, v in rule.items() if v not in ("", None, False) or k == "enabled"}


def _normalize_dnat_rule(row: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a firewall/d_nat/search_rule row (port forward, OPNsense 26.1+).

    d_nat differs from the other rule controllers: keys are dotted
    ("destination.network"), state is "disabled" rather than "enabled", and the
    anti-lockout rows it synthesizes carry a "lockout_N" uuid instead of the
    is_automatic flag the other controllers use.
    """
    uuid = str(row.get("uuid", ""))
    is_auto = _truthy(row.get("is_automatic")) or uuid.startswith("lockout_")

    def pick(key: str) -> str:
        return str(row.get(key) or row.get(f"%{key}") or "")

    rule = {
        "uuid": uuid,
        "description": row.get("descr") or row.get("description") or "",
        "enabled": not _truthy(row.get("disabled")),
        "interface": row.get("interface", ""),
        "ipprotocol": pick("ipprotocol"),
        "protocol": pick("protocol"),
        "source": row.get("source.network", ""),
        "source_port": row.get("source.port", ""),
        "destination": row.get("destination.network", ""),
        "destination_port": row.get("destination.port", ""),
        "nat_ip": row.get("target", ""),
        "nat_port": row.get("local-port", ""),
        "is_automatic": is_auto,
    }
    if row.get("%interface"):
        rule["interface_label"] = row["%interface"]
    for field, prefix in (("source.network", "src"), ("destination.network", "dst")):
        for key, val in _alias_meta(row.get(f"alias_meta_{field}")).items():
            rule[f"{prefix}_{key}"] = val
    return {k: v for k, v in rule.items() if v not in ("", None, False) or k == "enabled"}


def _normalize_gateway(row: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a routing/settings/search_gateway row (config + live status merged).

    monitor_disable=1 with an empty monitor means dpinger never probes this gateway,
    so status stays "Online" and it can never be marked down — worth surfacing
    explicitly, because a gateway that "can't go down" looks identical to a healthy one.
    """
    monitor = str(row.get("monitor") or "")
    monitor_disabled = _truthy(row.get("monitor_disable"))
    gw = {
        "name": row.get("name", ""),
        "description": row.get("descr", ""),
        "interface": _sel(row.get("interface")),
        "interface_label": row.get("interface_descr", ""),
        "gateway": row.get("gateway", ""),
        "ipprotocol": _sel(row.get("ipprotocol")),
        "enabled": not _truthy(row.get("disabled")),
        "is_default": _truthy(row.get("defaultgw")),
        "dynamic": _truthy(row.get("dynamic")),
        "priority": str(row.get("priority", "")),
        "weight": str(row.get("weight", "")),
        # Config: what dpinger is told to probe.
        "monitor_ip": monitor or (row.get("gateway", "") if not monitor_disabled else ""),
        "monitor_explicit": bool(monitor),
        "monitor_disabled": monitor_disabled,
        # Live: dpinger's verdict.
        "status": row.get("status", ""),
        "loss": row.get("loss", ""),
        "delay": row.get("delay", ""),
        "stddev": row.get("stddev", ""),
    }
    if monitor_disabled:
        gw["note"] = "monitoring disabled - status is always Online, gateway cannot be marked down"
    if _truthy(row.get("force_down")):
        gw["note"] = "force_down is set - gateway is administratively marked down"
    return gw


# ───────────────────────── Global State + FastMCP ─────────────────────────

config: Optional[Config] = None
cache: Optional[SimpleCache] = None
client: Optional['OPNsenseClient'] = None

mcp = FastMCP(
    "OPNsense",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    # Streamable HTTP without server-side sessions: a client that lost its connection
    # (laptop sleep, network drop) never ends up on an uninitialized session.
    stateless_http=True,
)


DHCP_LEASE_ENDPOINTS = [
    ("kea_v4", "/api/kea/leases4/search"),
    ("kea_v6", "/api/kea/leases6/search"),
    ("dnsmasq", "/api/dnsmasq/leases/search"),
    ("isc_v4", "/api/dhcpv4/leases/searchLease"),
    ("isc_v6", "/api/dhcpv6/leases/searchLease"),
]


def _epoch_iso(v: Any) -> Optional[str]:
    try:
        n = int(float(v))
        return datetime.fromtimestamp(n).astimezone().isoformat(timespec="seconds") if n > 0 else None
    except (TypeError, ValueError):
        return str(v) if v not in (None, "") else None


def _normalize_lease(server: str, r: Dict[str, Any]) -> Dict[str, Any]:
    """Kea, Dnsmasq and ISC lease rows use different field names; map them to one shape."""
    if server.startswith("kea"):
        lease = {"ip": r.get("address"), "mac": r.get("hwaddr"), "hostname": r.get("hostname"),
                 "interface": r.get("if_descr"), "interface_name": r.get("if_name"), "device": r.get("if"),
                 "expires": _epoch_iso(r.get("expire")), "vendor": r.get("mac_info"),
                 "state": {"0": "active", "1": "declined", "2": "expired-reclaimed"}.get(str(r.get("state")), r.get("state"))}
    elif server == "dnsmasq":
        lease = {"ip": r.get("address"), "mac": r.get("hwaddr"), "hostname": r.get("hostname"),
                 "interface": r.get("if_descr"), "interface_name": r.get("if_name"), "device": r.get("if"),
                 "expires": _epoch_iso(r.get("expire")), "vendor": r.get("mac_info"),
                 "static": _truthy(r.get("is_reserved"))}
    else:
        lease = {"ip": r.get("address"), "mac": r.get("mac"), "hostname": r.get("hostname"),
                 "interface": r.get("if_descr"), "interface_name": r.get("if"),
                 "expires": r.get("ends"), "vendor": r.get("man"),
                 "state": r.get("state"), "static": r.get("type") == "static",
                 "online": r.get("status")}
    lease["server"] = server
    return {k: v for k, v in lease.items() if v not in (None, "")}


def _normalize_interface(r: Dict[str, Any]) -> Dict[str, Any]:
    cfg = r.get("config") or {}
    out = {
        "name": r.get("identifier") or "",
        "description": r.get("description"),
        "device": r.get("device"),
        "status": r.get("status"),
        "enabled": r.get("enabled"),
        "ipv4": r.get("addr4") or None,
        "ipv6": r.get("addr6") or None,
        "type": r.get("link_type"),
        "gateways": r.get("gateways") or None,
        "media": r.get("media"),
        "mtu": r.get("mtu"),
        "mac": r.get("macaddr"),
        "vlan_tag": r.get("vlan_tag"),
        "physical": r.get("is_physical"),
    }
    if isinstance(cfg, dict) and cfg.get("if") and cfg.get("if") != r.get("device"):
        out["parent"] = cfg.get("if")
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _normalize_api_alias(r: Dict[str, Any]) -> Dict[str, Any]:
    content = [x for x in str(r.get("content") or "").replace(",", "\n").split("\n") if x.strip()]
    out = {
        "name": r.get("name"),
        "type": r.get("type"),
        "description": r.get("description") or "",
        "enabled": _truthy(r.get("enabled")),
        "content_list": content,
        "content_count": len(content),
        "current_items": int(r["current_items"]) if str(r.get("current_items", "")).isdigit() else None,
        "last_updated": r.get("last_updated") or None,
        "category": r.get("%categories") or None,
        "update_freq_days": r.get("updatefreq") or None,
    }
    return {k: v for k, v in out.items() if v is not None}


def _alias_entries_matching(entries: List[Any], search: str) -> List[Any]:
    """IP search -> entries whose host/network contains it; otherwise substring match."""
    try:
        addr = ipaddress.ip_address(search)
    except ValueError:
        return [e for e in entries if search.lower() in str(e).lower()]
    hits = []
    for e in entries:
        try:
            if addr in ipaddress.ip_network(str(e).strip(), strict=False):
                hits.append(e)
        except ValueError:
            continue
    return hits


def _check_age_days(last_check: Optional[str]) -> Optional[int]:
    """'Wed Oct  7 08:38:10 CST 2026' -> whole days since then."""
    if not last_check:
        return None
    parts = str(last_check).split()
    try:
        # drop the time zone word (CST, UTC, ...), which strptime cannot parse reliably
        dt = datetime.strptime(" ".join(parts[:4] + parts[5:6]), "%a %b %d %H:%M:%S %Y")
        return max(0, (datetime.now() - dt).days)
    except (ValueError, IndexError):
        return None


def _sse_and_http_app(server):
    """Legacy SSE (/sse + /messages/) plus Streamable HTTP (/mcp) on one port.

    SSE clients that auto-reconnect after a dropped connection (laptop sleep, network
    blip) get a fresh session without re-sending `initialize`, and every call then fails
    with -32602 "Invalid request parameters". /mcp runs stateless, so there is no
    session to lose; clients that support Streamable HTTP should use it.
    """
    from starlette.applications import Starlette
    sse = server.sse_app()
    http = server.streamable_http_app()
    return Starlette(routes=list(sse.routes) + list(http.routes),
                     lifespan=http.router.lifespan_context)


class _APIKeyAuth:
    """API key check as plain ASGI middleware.

    Starlette's BaseHTTPMiddleware breaks on streaming responses and logged an
    AssertionError every time an SSE connection closed.
    """
    def __init__(self, app, api_key):
        self.app = app
        self.api_key = api_key.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            import hmac
            from starlette.responses import JSONResponse
            auth = dict(scope["headers"]).get(b"authorization", b"").decode("latin-1")
            token = auth[7:] if auth.startswith("Bearer ") else auth
            if not hmac.compare_digest(token.encode(), self.api_key):
                response = JSONResponse(
                    {"error": "Unauthorized", "message": "Invalid or missing API key"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


# ───────────────────────── OPNsenseClient ─────────────────────────

class _ClientError(Exception):
    """HTTP 4xx from OPNsense: not retried."""


class OPNsenseClient:
    """OPNsense API client for config.xml reading, service management, and firmware/package info"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        if self.cfg.VERIFY_SSL:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def ensure_session(self):
        """Lazy session creation - creates session on first use.

        trust_env=True makes aiohttp honour HTTP_PROXY/HTTPS_PROXY, which the `requests`
        path already did implicitly. Claude Desktop on macOS routes MCP traffic through
        mcp_proxy to get around security software blocking its child processes; without
        this, every API call from there fails and silently falls back to config.xml.
        """
        if self.session is None or self.session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context)
            auth = aiohttp.BasicAuth(self.cfg.API_KEY, self.cfg.API_SECRET)
            timeout = aiohttp.ClientTimeout(total=self.cfg.TIMEOUT)
            self.session = aiohttp.ClientSession(
                connector=connector, auth=auth, timeout=timeout, trust_env=True
            )

    async def _request(self, method: str, endpoint: str, data: Dict = None,
                       params: Dict = None, use_cache: bool = True) -> Dict:
        """Send API request with retry and caching."""
        await self.ensure_session()
        url = urljoin(self.cfg.HOST + "/", endpoint.lstrip("/"))

        # Cache check for GET
        cache_key = None
        if use_cache and method.upper() == "GET" and cache is not None:
            cache_key = f"{method}:{endpoint}:{json.dumps(params, sort_keys=True)}"
            cached = cache.get(cache_key)
            if cached is not None:
                return cached

        last_exc = None
        for attempt in range(self.cfg.MAX_RETRIES):
            try:
                kwargs = {}
                if data:
                    kwargs['json'] = data
                if params:
                    kwargs['params'] = params

                async with self.session.request(method, url, **kwargs) as response:
                    response_text = await response.text()
                    if response.status == 200:
                        try:
                            result = json.loads(response_text)
                        except json.JSONDecodeError:
                            result = {"raw_response": response_text}
                        if cache_key and cache is not None:
                            cache.set(cache_key, result)
                        return result
                    elif 400 <= response.status < 500:
                        # Missing endpoint (older release / plugin not installed) or no
                        # privilege: retrying cannot help and cost ~3 s per probe.
                        raise _ClientError(f"API error {response.status}: {response_text[:200]}")
                    else:
                        raise Exception(f"API error {response.status}: {response_text[:200]}")
            except _ClientError:
                raise
            except Exception as e:
                last_exc = e
                if attempt < self.cfg.MAX_RETRIES - 1:
                    await asyncio.sleep(1.0 * (2 ** attempt))

        raise Exception(f"OPNsense API error after {self.cfg.MAX_RETRIES} retries: {last_exc}")

    async def download_config_xml(self) -> Element:
        """Download config.xml using synchronous request wrapped in to_thread."""
        def _sync_download():
            url = f"{self.cfg.HOST}/api/core/backup/download/this"
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.cfg.API_KEY, self.cfg.API_SECRET),
                verify=self.cfg.VERIFY_SSL,
                timeout=self.cfg.TIMEOUT
            )
            if response.status_code == 404:
                raise RuntimeError(
                    "Could not find /api/core/backup/download/this endpoint. "
                    "Requires OPNsense >= 23.7.8 or os-api-backup plugin"
                )
            response.raise_for_status()
            if response.headers.get("content-type", "").startswith("application/json"):
                raise RuntimeError(f"API returned error: {response.text}")
            try:
                return ET.fromstring(response.content)
            except ET.ParseError as exc:
                raise RuntimeError(f"config.xml parsing failed: {exc}") from exc

        return await asyncio.to_thread(_sync_download)

    # ── XML Parsers (unchanged, they work well) ──

    def _is_disabled(self, elem: Optional[Element]) -> bool:
        if elem is None:
            return False
        disabled_elem = elem.find("disabled")
        if disabled_elem is None:
            return False
        disabled_value = disabled_elem.text
        if disabled_value is None:
            return False
        return disabled_value.strip().lower() in ("1", "yes", "true")

    def _parse_firewall_rules_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        alias_names = {txt(a.find("name")) for a in root.findall("./aliases/alias")}
        rules: List[Dict[str, Any]] = []
        for node in root.findall("./filter/rule"):
            src_addr = txt(node.find("source/address"))
            dst_addr = txt(node.find("destination/address"))
            rule_data = {
                "tracker": txt(node.find("tracker")),
                "description": txt(node.find("descr")),
                "interface": txt(node.find("interface")),
                "action": txt(node.find("type")),
                "protocol": txt(node.find("protocol")),
                "src_addr": src_addr,
                "src_port": txt(node.find("source/port")),
                "dst_addr": dst_addr,
                "dst_port": txt(node.find("destination/port")),
                "src_alias": src_addr if src_addr in alias_names else "",
                "dst_alias": dst_addr if dst_addr in alias_names else "",
                "enabled": not self._is_disabled(node),
                "direction": txt(node.find("direction"), "in"),
                "ipprotocol": txt(node.find("ipprotocol"), "inet"),
                "gateway": txt(node.find("gateway")),
                "log": node.find("log") is not None,
                "quick": node.find("quick") is not None,
            }
            rules.append(rule_data)
        return rules

    def _parse_aliases_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        aliases: List[Dict[str, Any]] = []
        for node in root.findall(".//alias"):
            name = txt(node.find("name"))
            if not name:
                continue
            content = txt(node.find("content")) or txt(node.find("address")) or txt(node.find("url"))
            content = content.replace("\n", ", ").strip()
            description = txt(node.find("description")) or txt(node.find("descr"))
            content_list = []
            if content:
                if ", " in content:
                    content_list = [item.strip() for item in content.split(", ") if item.strip()]
                else:
                    content_list = [content.strip()] if content.strip() else []
            aliases.append({
                "name": name,
                "type": txt(node.find("type")),
                "content": content,
                "description": description,
                "enabled": not self._is_disabled(node),
                "content_list": content_list,
                "content_count": len(content_list),
            })
        return aliases

    def _parse_nat_rules_from_xml(self, root: Element, rule_type: str) -> List[Dict[str, Any]]:
        def txt(elem: Optional[Element], default: str = "") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        rules: List[Dict[str, Any]] = []
        if rule_type == "forward":
            for node in root.findall("./nat/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")), "description": txt(node.find("descr")),
                    "interface": txt(node.find("interface")), "protocol": txt(node.find("protocol")),
                    "source": txt(node.find("source/address")), "src_port": txt(node.find("source/port")),
                    "destination": txt(node.find("destination/address")), "dst_port": txt(node.find("destination/port")),
                    "nat_ip": txt(node.find("target")), "nat_port": txt(node.find("local-port")),
                    "enabled": not self._is_disabled(node),
                })
        elif rule_type == "outbound":
            for node in root.findall("./nat/outbound/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")), "description": txt(node.find("descr")),
                    "source": txt(node.find("source/network")), "src_port": txt(node.find("source/port")),
                    "destination": txt(node.find("destination/network")), "dst_port": txt(node.find("destination/port")),
                    "translation": txt(node.find("translation/address")),
                    "interface": txt(node.find("interface")), "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),
                })
        elif rule_type == "source":
            for node in root.findall("./nat/advancedoutbound/rule") + root.findall("./nat/source/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")), "description": txt(node.find("descr")),
                    "source": txt(node.find("source/network")),
                    "translation": txt(node.find("translation/address")),
                    "interface": txt(node.find("interface")), "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),
                })
        elif rule_type == "one_to_one":
            for node in root.findall("./nat/onetoone/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")), "description": txt(node.find("descr")),
                    "external": txt(node.find("external")), "internal": txt(node.find("internal")),
                    "interface": txt(node.find("interface")), "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),
                })
        return rules

    def _parse_interfaces_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        interfaces: List[Dict[str, Any]] = []
        for node in root.findall("./interfaces/*"):
            interfaces.append({
                "name": node.tag, "if": txt(node.find("if")),
                "descr": txt(node.find("descr")), "enable": txt(node.find("enable")) == "1",
                "ipaddr": txt(node.find("ipaddr")), "subnet": txt(node.find("subnet")),
                "gateway": txt(node.find("gateway")), "mtu": txt(node.find("mtu")),
            })
        return interfaces

    def _parse_gateways_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        """Fallback gateway config reader.

        Gateways live in <gateways><gateway_item> on older releases and moved to
        <OPNsense><Gateways><gateway_item> with the MVC model; check both. Dynamic
        (DHCP/PPPoE) gateways have no config entry at all and only appear via the API.
        """
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        gateways: List[Dict[str, Any]] = []
        nodes = root.findall("./gateways/gateway_item") + \
            root.findall("./OPNsense/Gateways/gateway_item")
        for node in nodes:
            # 26.1 leaves a childless <gateway_item/> stub behind in the legacy
            # <gateways> block; parsing it would yield a gateway with every field blank.
            if len(node) == 0:
                continue
            gateways.append({
                "name": txt(node.find("name")),
                "interface": txt(node.find("interface")),
                "gateway": txt(node.find("gateway")),
                "monitor": txt(node.find("monitor")),
                "monitor_disable": _truthy(txt(node.find("monitor_disable"))),
                "priority": txt(node.find("priority")),
                "weight": txt(node.find("weight")),
                "defaultgw": _truthy(txt(node.find("defaultgw"))),
                "ipprotocol": txt(node.find("ipprotocol")),
                "description": txt(node.find("descr")),
                "enabled": not _truthy(txt(node.find("disabled"))),
                "dynamic": False,
            })
        return gateways

    # ── Service API Methods ──

    async def fetch_all_rows(self, endpoint: str, page_size: int = 500, max_rows: int = 20000) -> List[Dict]:
        """GET a search_* endpoint page by page and return every row."""
        rows, current = [], 1
        while len(rows) < max_rows:
            result = await self._request("GET", endpoint,
                                         params={"current": current, "rowCount": page_size, "searchPhrase": ""})
            page = result.get("rows", []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
            rows.extend(page)
            total = int(result.get("total", 0) or 0) if isinstance(result, dict) else 0
            if not page or len(page) < page_size or (total and len(rows) >= total):
                break
            current += 1
        return rows

    async def search_services(self, search_phrase: str = "", current: int = 1,
                              row_count: int = 100) -> Dict:
        data = {"current": current, "rowCount": row_count, "searchPhrase": search_phrase, "sort": {}}
        return await self._request("POST", "/api/core/service/search", data=data)

    async def get_all_services(self) -> List[Dict]:
        all_services = []
        current_page = 1
        while True:
            result = await self.search_services(current=current_page, row_count=100)
            if 'rows' in result and result['rows']:
                all_services.extend(result['rows'])
                total = result.get('total', 0)
                if (total > 0 and len(all_services) >= total) or len(result['rows']) < 100:
                    break
                current_page += 1
            else:
                break
        return all_services

    async def get_service_status(self, service_name: str) -> Dict:
        endpoints = [
            f"/api/core/service/status/{service_name}",
            f"/api/{service_name}/service/status",
        ]
        for endpoint in endpoints:
            try:
                result = await self._request("GET", endpoint)
                if result:
                    return {"service": service_name, "status": result}
            except Exception:
                continue
        # Fallback: search
        services = await self.search_services(search_phrase=service_name)
        if 'rows' in services:
            matching = [s for s in services['rows'] if s.get('name') == service_name or s.get('id') == service_name]
            if matching:
                return {"service": service_name, "status": matching[0]}
        return {"service": service_name, "error": "Service not found"}

    # ── Firmware API Methods ──
    # Read-only on purpose: core/firmware/{check,audit,health,connection} are POSTs that
    # start a job on the firewall (update check, security audit, pkg integrity check).

    async def get_firmware_status(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/status")

    async def get_product_version(self) -> Dict[str, str]:
        """Product and OS version from the small dashboard endpoint.

        core/firmware/info has the same data but is ~400 KB (every package) and took
        ~7 s, which made getConfigSummary slow; use it only as a fallback.
        """
        try:
            info = await self._request("GET", "/api/diagnostics/system/system_information")
            out = {}
            for v in info.get("versions", []):
                if v.startswith("OPNsense"):
                    out["product_name"] = "OPNsense"
                    out["product_version"] = v.split()[1].rsplit("-", 1)[0] if len(v.split()) > 1 else ""
                elif v.startswith(("FreeBSD", "HardenedBSD")):
                    out["os_version"] = v
            if out.get("product_version"):
                return out
        except Exception:
            pass
        try:
            fw = await self.get_firmware_info()
            return {"product_name": "OPNsense", "product_version": fw.get("product_version", "")}
        except Exception:
            return {}

    async def get_firmware_info(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/info")

    async def get_firmware_changelog(self, version: str = None) -> Dict:
        ep = f"/api/core/firmware/changelog/{version}" if version else "/api/core/firmware/changelog"
        return await self._request("POST", ep, data={})

    async def get_firmware_options(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/getOptions")

    async def get_firmware_settings(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/get")

    # ── Package API Methods ──

    async def get_package_details(self, package_name: str) -> Dict:
        return await self._request("POST", f"/api/core/firmware/details/{package_name}", data={})

    async def get_package_license(self, package_name: str) -> Dict:
        return await self._request("POST", f"/api/core/firmware/license/{package_name}", data={})

    # ── DHCP API Methods ──

    async def search_dhcp_leases(self, search_phrase: str = "", current: int = 1,
                                 row_count: int = 100) -> Dict:
        params = {"current": current, "rowCount": row_count, "searchPhrase": search_phrase}
        return await self._request("GET", "/api/dhcpv4/leases/searchlease", params=params)

    async def get_dhcp_service_status(self) -> Dict:
        return await self._request("GET", "/api/dhcpv4/service/status")

    async def get_dhcp_settings(self) -> Dict:
        return await self._request("GET", "/api/dhcpv4/settings/get")

    async def get_dhcp_interface_settings(self, interface: str) -> Dict:
        return await self._request("GET", f"/api/dhcpv4/settings/getdhcp/{interface}")

    # ── Interface API Methods ──

    async def get_interface_overview(self) -> Dict:
        endpoints = [
            "/api/diagnostics/interface/getInterfaceNames",
            "/api/core/interface/search",
            "/api/interfaces/overview/export",
            "/api/diagnostics/interface/getInterface",
        ]
        for endpoint in endpoints:
            try:
                result = await self._request("GET", endpoint)
                if result:
                    return {"endpoint_used": endpoint, "data": result}
            except Exception:
                continue
        raise Exception("No working interface endpoint found")

    async def get_interface_config(self, interface: str) -> Dict:
        endpoints = [
            f"/api/diagnostics/interface/getInterfaceConfig/{interface}",
            f"/api/interfaces/{interface}/get",
        ]
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint)
            except Exception:
                continue
        raise Exception(f"No working interface config endpoint for {interface}")

    async def get_interface_statistics(self) -> Dict:
        endpoints = [
            "/api/diagnostics/interface/getInterfaceStatistics",
            "/api/diagnostics/interface/getStats",
        ]
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint)
            except Exception:
                continue
        raise Exception("No working interface statistics endpoint found")

    async def get_arp_table(self) -> Dict:
        return await self._request("GET", "/api/diagnostics/interface/getArp")

    async def get_ndp_table(self) -> Dict:
        return await self._request("GET", "/api/diagnostics/interface/getNdp")

    async def get_routes(self) -> Dict:
        endpoints = [
            "/api/routes/routes/searchRoute",
            "/api/diagnostics/interface/getRoutes",
        ]
        for endpoint in endpoints:
            try:
                result = await self._request("GET", endpoint)
                if result:
                    return result
            except Exception:
                continue
        raise Exception("No working routes endpoint found")

    # ── Firewall / NAT / Alias API Methods ──

    async def search_filter_rules(self) -> Dict:
        """Firewall rules via the MVC API.

        show_all=1 is required on 25.x, where it is what pulls the legacy (config.xml)
        and internal rules into the result at all. On 26.1 those are always merged and
        show_all only adds pf counters, so sending it is harmless there. Send it either
        way rather than version-sniffing.

        Paging params are ignored on GET (OPNsense reads them with getPost()); a GET
        returns the whole set up to its 9999-row default, which is what we want.
        """
        return await self._request("GET", "/api/firewall/filter/search_rule",
                                   params={"show_all": "1"})

    async def search_nat_rules(self, nat_type: str = "source_nat", search_phrase: str = "",
                               row_count: int = 5000) -> Dict:
        """NAT rules via the MVC API.

        nat_type is the API controller name: d_nat (port forward, 26.1+),
        source_nat (outbound), one_to_one, npt.
        """
        params = {"current": 1, "rowCount": row_count, "searchPhrase": search_phrase}
        return await self._request("GET", f"/api/firewall/{nat_type}/search_rule", params=params)

    async def search_aliases_api(self, search_phrase: str = "", row_count: int = 5000) -> Dict:
        params = {"current": 1, "rowCount": row_count, "searchPhrase": search_phrase}
        return await self._request("GET", "/api/firewall/alias/search_item", params=params)

    async def list_alias_content(self, alias_name: str) -> Dict:
        return await self._request("GET", f"/api/firewall/alias_util/list/{alias_name}")

    # ── Gateway API Methods ──

    async def search_gateways(self) -> Dict:
        """Gateway config merged with live status (OPNsense 24.7+).

        Richer than routes/gateway/status: includes monitor/priority/weight config and
        dynamic (DHCP/PPPoE) gateways, whose uuid is the gateway name.
        """
        return await self._request("GET", "/api/routing/settings/search_gateway")

    async def get_gateway_status(self) -> Dict:
        return await self._request("GET", "/api/routes/gateway/status")


# ───────────────────────── Helper: ensure client ─────────────────────────

async def _ensure_client() -> OPNsenseClient:
    global client
    if client is None:
        client = OPNsenseClient(config)
    await client.ensure_session()
    return client


# ───────────────────────── MCP Tools (20) ─────────────────────────

# Tool 1: getConfigSummary
@mcp.tool()
async def getConfigSummary() -> str:
    """Get comprehensive OPNsense configuration summary from config.xml.
    [YES] Use for overall system info, firewall rule counts, alias counts, NAT stats.
    [NO] Don't use for specific rules -> use getFirewallRules()."""
    try:
        c = await _ensure_client()
        root = await c.download_config_xml()

        # Rules must come from the API: config.xml <filter><rule> is empty on 26.1,
        # so counting it there reports 0 firewall rules on a box that has hundreds.
        fw_rules, fw_source = await _fetch_firewall_rules()

        aliases = c._parse_aliases_from_xml(root)
        interfaces = c._parse_interfaces_from_xml(root)
        nat_fwd = c._parse_nat_rules_from_xml(root, "forward")
        nat_out = c._parse_nat_rules_from_xml(root, "outbound")
        nat_src = c._parse_nat_rules_from_xml(root, "source")
        nat_1to1 = c._parse_nat_rules_from_xml(root, "one_to_one")

        def txt(elem, default=""):
            return elem.text.strip() if elem is not None and elem.text else default

        sys_info = {}
        sys_node = root.find("./system")
        if sys_node is not None:
            sys_info = {
                "hostname": txt(sys_node.find("hostname")),
                "domain": txt(sys_node.find("domain")),
                "timezone": txt(sys_node.find("timezone")),
            }

        # OPNsense version (config.xml doesn't have it)
        sys_info.update(await c.get_product_version())

        user_rules = [r for r in fw_rules if not r.get("is_automatic")]

        return _R({
            "system": sys_info,
            "stats": {
                "firewall_rules": len(fw_rules),
                "firewall_rules_user": len(user_rules),
                "firewall_rules_source": fw_source,
                "enabled_rules": sum(1 for r in fw_rules if r.get("enabled")),
                "aliases": len(aliases),
                "interfaces": len(interfaces),
                "nat_forward": len(nat_fwd),
                "nat_outbound": len(nat_out),
                "nat_source": len(nat_src),
                "nat_1to1": len(nat_1to1),
            },
            "interfaces": interfaces,
        })
    except Exception as e:
        return _R({"error": str(e)})


# Tool 2: getFirewallRules
async def _fetch_firewall_rules() -> tuple:
    """Firewall rules, API first, config.xml as fallback. Returns (rules, source)."""
    c = await _ensure_client()
    try:
        result = await c.search_filter_rules()
        rows = result.get("rows", [])
        if rows:
            return [_normalize_api_rule(r) for r in rows], "api"
    except Exception as api_exc:
        logger.warning(f"filter/search_rule failed, falling back to config.xml: {api_exc}")
    root = await c.download_config_xml()
    return c._parse_firewall_rules_from_xml(root), "config"


@mcp.tool()
async def getFirewallRules(interface: Optional[str] = None, action: Optional[str] = None,
                           enabled_only: Optional[bool] = None,
                           aliases_only: bool = False,
                           include_automatic: bool = True,
                           include_stats: bool = False,
                           unused_only: bool = False) -> str:
    """Get firewall rules (native API, config.xml fallback).
    [YES] "防火牆規則", "show firewall rules", "rules on LAN", "pass rules",
          "沒用到的規則", "unused rules", "rule hit count", "規則命中數".
    [NO] "NAT rules" -> use getNatRules().
    [NO] "Why was X blocked / firewall log" -> use getFirewallLog().

    Args:
        interface: Filter by interface (e.g., wan, lan, opt1). A rule may span
            several interfaces ("wan,opt2"); it matches if any of them match.
        action: Filter by action (pass, block, reject).
        enabled_only: True=enabled only, False=disabled only, None=all.
        aliases_only: Only show rules that reference aliases.
        include_automatic: Include OPNsense's own automatic/internal rules.
            False = only rules a human configured.
        include_stats: Add pf counters per rule (evaluations, packets, bytes, states)
            since the last rule reload / reboot.
        unused_only: Only enabled rules that have matched no packets (implies
            include_stats). Candidates for cleanup - counters reset on reload."""
    try:
        rules, source = await _fetch_firewall_rules()
        if include_stats or unused_only:
            c = await _ensure_client()
            try:
                stats = (await c._request("GET", "/api/firewall/filter_util/rule_stats")).get("stats", {})
                for r in rules:
                    st = stats.get(r.get("uuid", ""))
                    if st:
                        r["stats"] = {k: st.get(k) for k in ("evaluations", "packets", "bytes", "states")}
            except Exception as exc:
                return _R({"error": f"rule statistics unavailable (needs OPNsense 24.7+): {exc}"})
        if unused_only:
            rules = [r for r in rules if r.get("enabled") and r.get("stats") is not None
                     and not r["stats"].get("packets")]

        if not include_automatic:
            rules = [r for r in rules if not r.get("is_automatic")]
        if interface:
            rules = [r for r in rules if _iface_match(r.get("interface", ""), interface)]
        if action:
            rules = [r for r in rules if r.get("action", "").lower() == action.lower()]
        if enabled_only is not None:
            rules = [r for r in rules if r.get("enabled") == enabled_only]
        if aliases_only:
            rules = [r for r in rules if r.get("src_alias") or r.get("dst_alias")]

        return _R({"source": source, "data": rules, "count": len(rules)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 3: getNatRules
# Maps a caller-facing NAT type to (API controller, config.xml rule_type).
# Legacy aliases keep pre-v2.4.0 callers working: "forward" was the old name for port
# forward, "source" the old name for outbound.
_NAT_TYPES = {
    "port_forward": ("d_nat", "forward"),        # d_nat needs 26.1+, config.xml before
    "forward": ("d_nat", "forward"),             # legacy alias
    "outbound": ("source_nat", "outbound"),
    "source_nat": ("source_nat", "outbound"),
    "source": ("source_nat", "source"),          # legacy alias
    "one_to_one": ("one_to_one", "one_to_one"),
    "npt": ("npt", None),                        # API only, no config.xml equivalent
}


@mcp.tool()
async def getNatRules(nat_type: str = "port_forward", enabled_only: Optional[bool] = None,
                      search: Optional[str] = None,
                      include_automatic: bool = False) -> str:
    """Get NAT rules of any type (native API, config.xml fallback).
    [YES] "NAT規則", "port forwarding rules", "轉port", "outbound NAT", "1:1 NAT", "NPTv6".
    [NO] "Firewall rules" -> use getFirewallRules().

    Args:
        nat_type: port_forward (port forward / destination NAT), outbound (source NAT),
            one_to_one, or npt. Aliases: "forward"=port_forward, "source_nat"/"source"=outbound.
        enabled_only: True=enabled only, False=disabled only, None=all.
        search: Filter by description (case-insensitive).
        include_automatic: Include rules OPNsense synthesizes for display
            (anti-lockout, automatic outbound NAT). These are not in the config."""
    try:
        key = (nat_type or "").lower()
        if key not in _NAT_TYPES:
            return _R({"error": f"Invalid nat_type. Must be one of: {sorted(_NAT_TYPES)}"})
        api_ctrl, xml_type = _NAT_TYPES[key]

        c = await _ensure_client()
        rules, source = [], None

        try:
            result = await c.search_nat_rules(api_ctrl, search_phrase=search or "")
            rows = result.get("rows", [])
            normalize = _normalize_dnat_rule if api_ctrl == "d_nat" else _normalize_api_rule
            rules, source = [normalize(r) for r in rows], "api"
        except Exception as api_exc:
            # d_nat is 26.1+; source_nat/one_to_one/npt are 24.x+. On older releases the
            # endpoint 404s and config.xml is the only source (npt has none).
            logger.warning(f"firewall/{api_ctrl}/search_rule failed, "
                           f"falling back to config.xml: {api_exc}")
            if xml_type is None:
                return _R({"error": f"{key} requires the API (no config.xml equivalent): {api_exc}"})
            root = await c.download_config_xml()
            rules, source = c._parse_nat_rules_from_xml(root, xml_type), "config"

        if not include_automatic:
            rules = [r for r in rules if not r.get("is_automatic")]
        if enabled_only is not None:
            rules = [r for r in rules if r.get("enabled") == enabled_only]
        if search:
            rules = [r for r in rules if search.lower() in r.get("description", "").lower()]

        return _R({"nat_type": key, "source": source, "data": rules, "count": len(rules)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 3b: getNatRulesConfig - kept for backward compatibility with pre-v2.4.0 callers.
@mcp.tool()
async def getNatRulesConfig(rule_type: str = "forward", enabled_only: Optional[bool] = None,
                            search: Optional[str] = None) -> str:
    """Get NAT rules straight from config.xml, skipping the API.
    [NO] Prefer getNatRules() - it reads the live API and falls back here automatically.
    [YES] Only when you specifically need the on-disk config.xml view.

    Args:
        rule_type: forward, outbound, source, or one_to_one.
        enabled_only: True=enabled only, False=disabled only, None=all.
        search: Filter by description (case-insensitive)."""
    try:
        valid = ["forward", "outbound", "source", "one_to_one"]
        if rule_type not in valid:
            return _R({"error": f"Invalid rule_type. Must be one of: {valid}"})

        c = await _ensure_client()
        root = await c.download_config_xml()
        rules = c._parse_nat_rules_from_xml(root, rule_type)

        if enabled_only is not None:
            rules = [r for r in rules if r["enabled"] == enabled_only]
        if search:
            rules = [r for r in rules if search.lower() in r.get("description", "").lower()]

        return _R({"rule_type": rule_type, "source": "config", "data": rules, "count": len(rules)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 4: getAliases
@mcp.tool()
async def getAliases(source: str = "api", alias_type: Optional[str] = None,
                     enabled_only: Optional[bool] = None,
                     search: Optional[str] = None) -> str:
    """Get aliases (name, type, content, description, enabled).
    [YES] "別名清單", "list aliases", "show host aliases", "alias search".
    [NO] "Alias content/entries" -> use getAliasContent().

    Both sources return the same fields. The API also reports how many entries the
    alias currently resolves to (current_items) and when it was last updated, which
    matters for URL/GeoIP aliases whose content is fetched, not typed in.

    Args:
        source: "api" (default; falls back to config.xml on error) or "config".
        alias_type: Filter by type (host, network, port, url, urltable, geoip, ...).
        enabled_only: True=enabled only, None=all.
        search: Filter by name or description (case-insensitive partial match)."""
    try:
        c = await _ensure_client()
        aliases, used = None, "config"
        if source != "config":
            try:
                result = await c.search_aliases_api(row_count=5000)
                aliases = [_normalize_api_alias(r) for r in result.get("rows", [])]
                used = "api"
            except Exception as api_exc:
                logger.warning(f"firewall/alias/search_item failed, falling back to config.xml: {api_exc}")
        if aliases is None:
            root = await c.download_config_xml()
            aliases = c._parse_aliases_from_xml(root)
        if alias_type:
            aliases = [a for a in aliases if str(a.get("type", "")).lower() == alias_type.lower()]
        if enabled_only is not None:
            aliases = [a for a in aliases if bool(a.get("enabled")) == enabled_only]
        if search:
            s = search.lower()
            aliases = [a for a in aliases
                       if s in str(a.get("name", "")).lower() or s in str(a.get("description", "")).lower()]
        return _R({"source": used, "data": aliases, "count": len(aliases)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 5: getAliasContent
@mcp.tool()
async def getAliasContent(alias_name: str, search: Optional[str] = None, limit: int = 200) -> str:
    """Get the entries an alias currently resolves to (IPs, networks, ports).
    [YES] "Show entries in alias X", "alias content", "別名內容", "is 1.2.3.4 in alias X".
    [NO] "List all aliases" -> use getAliases().

    GeoIP and URL aliases can hold thousands of networks; only the first `limit`
    entries are returned, with the full count in `total`. Use `search` to check
    whether a specific address or prefix is in the alias.

    Args:
        alias_name: The alias name.
        search: An IP address returns the entries (hosts or networks) that contain it,
                e.g. "203.0.113.5" matches "203.0.113.0/24". Anything else is a text match.
        limit: Max entries returned (default 200)."""
    try:
        c = await _ensure_client()
        result = await c.list_alias_content(alias_name)
        rows = result.get("rows", []) if isinstance(result, dict) else []
        entries = [r.get("ip", r) if isinstance(r, dict) else r for r in rows]
        source = "pf_table"
        if not entries:
            # Port aliases (and disabled ones) are not loaded as pf tables; show what is configured.
            try:
                found = await c.search_aliases_api(search_phrase=alias_name, row_count=50)
                for r in found.get("rows", []):
                    if r.get("name") == alias_name:
                        entries = _normalize_api_alias(r).get("content_list", [])
                        source = "configured"
                        break
            except Exception:
                pass
        total = len(entries)
        if search:
            entries = _alias_entries_matching(entries, search.strip())
        matched = len(entries)
        out = {"alias": alias_name, "source": source, "total": total, "entries": entries[:max(1, limit)]}
        if search:
            out["matched"] = matched
        if matched > limit:
            out["truncated"] = True
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 6: getServices
@mcp.tool()
async def getServices(search: Optional[str] = None) -> str:
    """Get OPNsense services overview with status (running/stopped/locked).
    [YES] "服務狀態", "show services", "which services are running?", "service list".
    [NO] "Specific service status" -> use getServiceStatus().

    Args:
        search: Search phrase to filter services by name."""
    try:
        c = await _ensure_client()
        if search:
            result = await c.search_services(search_phrase=search)
            services = result.get('rows', [])
        else:
            services = await c.get_all_services()

        running = [s for s in services if s.get('running', 0)]
        stopped = [s for s in services if not s.get('running', 0) and not s.get('locked', 0)]
        locked = [s for s in services if s.get('locked', 0)]

        return _R({
            "total": len(services),
            "stats": {"running": len(running), "stopped": len(stopped), "locked": len(locked)},
            "data": services,
        })
    except Exception as e:
        return _R({"error": str(e)})


# Tool 7: getServiceStatus
@mcp.tool()
async def getServiceStatus(service_name: str) -> str:
    """Status of one service: running or stopped.
    [YES] "Is unbound running?", "kea 有沒有在跑", "suricata status", "某服務狀態".
    [NO] "All services" -> use getServices().

    Matches the service id, name or description (case-insensitive, partial), so
    "kea", "dhcp", "suricata" or "wireguard" all work. Several matches are all returned.

    Args:
        service_name: Service id, name or part of its description."""
    try:
        c = await _ensure_client()
        wanted = service_name.strip().lower()
        services = await c.get_all_services()
        exact = [s for s in services if wanted in (str(s.get("id", "")).lower(), str(s.get("name", "")).lower())]
        matches = exact or [s for s in services
                            if wanted in str(s.get("id", "")).lower()
                            or wanted in str(s.get("name", "")).lower()
                            or wanted in str(s.get("description", "")).lower()]
        if matches:
            return _R({"query": service_name, "data": [{
                "id": s.get("id"), "name": s.get("name"), "description": s.get("description"),
                "running": bool(s.get("running")), "locked": bool(s.get("locked")),
            } for s in matches], "count": len(matches)})
        # Not in the service list: it may be installed but disabled
        try:
            st = await c._request("GET", f"/api/{wanted}/service/status")
            return _R({"query": service_name, "data": [{"id": wanted, "status": st.get("status")}],
                       "note": "Not in the running service list; status from the module itself."})
        except Exception:
            return _R({"query": service_name, "data": [], "count": 0,
                       "note": "No such service. Use getServices() for the list."})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 8: getFirmwareStatus
@mcp.tool()
async def getFirmwareStatus(include_packages: bool = False) -> str:
    """Firmware version and pending updates, from the router's last update check.
    [YES] "韌體狀態", "firmware update?", "is OPNsense up to date?", "需要更新嗎", "needs reboot".
    [NO] "Package list" -> use getPackages() / getPlugins().
    [NO] "Firmware settings" -> use getFirmwareConfig().

    Read-only: shows the result of the last check the router ran (see last_check and
    last_check_age_days); it does not start a new check. If the check is old, run
    "Check for updates" in the GUI first.

    Args:
        include_packages: Also list the names of packages that would be upgraded/added."""
    try:
        c = await _ensure_client()
        st = await c.get_firmware_status()
        out = {k: st.get(k) for k in (
            "product_version", "os_version", "status", "status_msg",
            "needs_reboot", "upgrade_major_version", "upgrade_major_message", "last_check",
            "connection", "repository") if st.get(k) not in (None, "")}
        out["needs_reboot"] = _truthy(st.get("needs_reboot") or st.get("status_reboot"))
        age = _check_age_days(st.get("last_check"))
        if age is not None:
            out["last_check_age_days"] = age
            if age > 7:
                out["note"] = f"Last update check was {age} days ago; the pending list may be out of date."
        counts = {k: len(st.get(k) or []) for k in (
            "upgrade_packages", "new_packages", "reinstall_packages", "remove_packages", "downgrade_packages")}
        out["counts"] = {k: v for k, v in counts.items() if v}
        if include_packages:
            out["upgrade_packages"] = [
                f"{p.get('name')} {p.get('current_version', '')}->{p.get('new_version', '')}".strip()
                for p in st.get("upgrade_packages") or []]
            out["new_packages"] = [f"{p.get('name')} {p.get('version', '')}".strip() for p in st.get("new_packages") or []]
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 9: getFirmwareInfo
@mcp.tool()
async def getFirmwareInfo() -> str:
    """Installed OPNsense product and package counts.
    [YES] "firmware info", "OPNsense 版本", "how many packages/plugins installed".
    [NO] "Firmware update status" -> use getFirmwareStatus().
    [NO] "Specific package" -> use getPackageInfo().
    [NO] "已安裝 plugin", "plugin list" -> use getPlugins().
    [NO] "已安裝套件", "installed packages" -> use getPackages().

    The full package list is several hundred KB; search it with getPackages() /
    getPlugins() instead."""
    try:
        c = await _ensure_client()
        info = await c.get_firmware_info()
        pkgs = info.get("package") or []
        plugins = info.get("plugin") or []
        product = info.get("product") or {}
        out = {k: info.get(k) for k in ("product_id", "product_version") if info.get(k)}
        for key, label in (("CORE_PRODUCT", "product_name"), ("CORE_NICKNAME", "nickname"),
                           ("CORE_SERIES", "series"), ("CORE_NEXT", "next_major"), ("CORE_ARCH", "arch"),
                           ("CORE_REPOSITORY", "repository"), ("CORE_HASH", "commit")):
            if isinstance(product, dict) and product.get(key):
                out[label] = str(product.get(key)).strip()
        out["packages_installed"] = sum(1 for p in pkgs if _truthy(p.get("installed")))
        out["plugins_installed"] = sorted(p.get("name") for p in plugins if _truthy(p.get("installed")))
        missing = sorted(p.get("name") for p in plugins if _truthy(p.get("configured")) and not _truthy(p.get("installed")))
        if missing:
            # Listed in the firmware config but not installed - usually a third-party
            # repository that is no longer configured, so these never get updates.
            out["plugins_configured_not_installed"] = missing
        out["plugins_available"] = len(plugins)
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 10: getFirmwareConfig
@mcp.tool()
async def getFirmwareConfig() -> str:
    """Get firmware configuration: settings, mirror options, repository connectivity.
    [YES] "韌體設定", "firmware mirror", "repo connectivity", "firmware options".
    [NO] "Update status" -> use getFirmwareStatus()."""
    try:
        c = await _ensure_client()
        result = {}
        try:
            result["settings"] = await c.get_firmware_settings()
        except Exception as e:
            result["settings_error"] = str(e)
        try:
            result["options"] = await c.get_firmware_options()
        except Exception as e:
            result["options_error"] = str(e)
        # core/firmware/connection is left out on purpose: it is a POST that runs a
        # connectivity test against the mirror. getFirmwareStatus() reports the result
        # of the last check ("connection", "repository").
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 11: getPackageInfo
@mcp.tool()
async def getPackageInfo(package_name: str, include_license: bool = False,
                         changelog_version: Optional[str] = None) -> str:
    """Get details for a specific package, optionally with license and changelog.
    [YES] "Package os-theme-rebellion info", "package license", "changelog for 24.7".
    [NO] "All packages" -> use getPackages() / getPlugins().

    Args:
        package_name: Package name (e.g., os-theme-rebellion, os-haproxy).
        include_license: Also fetch license text.
        changelog_version: Fetch changelog for this version (e.g., "24.7")."""
    try:
        c = await _ensure_client()
        result = {"package": package_name}
        result["details"] = await c.get_package_details(package_name)
        if include_license:
            try:
                result["license"] = await c.get_package_license(package_name)
            except Exception as e:
                result["license_error"] = str(e)
        if changelog_version:
            try:
                result["changelog"] = await c.get_firmware_changelog(changelog_version)
            except Exception as e:
                result["changelog_error"] = str(e)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 12: getDhcpLeases
@mcp.tool()
async def getDhcpLeases(search: Optional[str] = None, interface: Optional[str] = None) -> str:
    """DHCP leases from whichever DHCP server the firewall runs (Kea, Dnsmasq or ISC).
    [YES] "DHCP租約", "show leases", "find lease for 192.168.1.100", "MAC lease", "誰拿了這個 IP".
    [NO] "DHCP settings / pool / reservations" -> use getDhcpSettings().

    OPNsense 24.x+ ships Kea and Dnsmasq; ISC DHCP is a plugin from 26.1. All three
    are queried and merged; `server` says where each lease came from.

    Args:
        search: Filter by IP, MAC, hostname or vendor (partial match).
        interface: Only this interface (e.g. lan, LAN, igb0)."""
    try:
        c = await _ensure_client()
        leases, servers, errors = [], {}, {}
        results = await asyncio.gather(*(c.fetch_all_rows(path) for _, path in DHCP_LEASE_ENDPOINTS),
                                       return_exceptions=True)
        for (server, _), rows in zip(DHCP_LEASE_ENDPOINTS, results):
            if isinstance(rows, Exception):
                if "404" not in str(rows):
                    errors[server] = str(rows)[:200]
                continue
            servers[server] = len(rows)
            leases.extend(_normalize_lease(server, r) for r in rows)
        if interface:
            w = interface.lower()
            leases = [l for l in leases if w in (str(l.get("interface", "")).lower(), str(l.get("interface_name", "")).lower(),
                                                 str(l.get("device", "")).lower())]
        if search:
            s = search.lower()
            leases = [l for l in leases if any(s in str(v).lower() for v in
                                               (l.get("ip"), l.get("mac"), l.get("hostname"), l.get("vendor")))]
        leases.sort(key=lambda l: tuple(int(x) if x.isdigit() else 0 for x in str(l.get("ip", "")).split(".")))
        out = {"servers": servers, "data": leases, "count": len(leases)}
        if errors:
            out["errors"] = errors
        if not servers:
            out["note"] = "No DHCP lease endpoint answered; check that the API user has DHCP privileges."
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 13: getDhcpSettings
@mcp.tool()
async def getDhcpSettings(interface: Optional[str] = None) -> str:
    """Which DHCP server is active and how it is set up: interfaces, subnets, pools,
    DNS/router options handed out, and static reservations.
    [YES] "DHCP設定", "DHCP pool", "DHCP 範圍", "static mapping", "固定 IP 保留", "DHCP 發的 DNS".
    [NO] "Current leases" -> use getDhcpLeases().

    Args:
        interface: Only subnets/reservations on this interface (e.g. lan). None = all."""
    try:
        c = await _ensure_client()
        out: Dict[str, Any] = {}
        services = await c.get_all_services()
        out["services"] = [{"id": s.get("id"), "description": s.get("description"), "running": bool(s.get("running"))}
                           for s in services if any(k in str(s.get("id", "")).lower() for k in ("kea", "dhcpd", "dnsmasq"))]

        # Kea
        try:
            kea = (await c._request("GET", "/api/kea/dhcpv4/get")).get("dhcpv4", {})
            gen = kea.get("general", {})
            if _truthy(gen.get("enabled")):
                subnets = (await c._request("GET", "/api/kea/dhcpv4/search_subnet")).get("rows", [])
                res = await c.fetch_all_rows("/api/kea/dhcpv4/search_reservation")
                kea_out = {
                    "enabled": True,
                    "interfaces": [k for k, v in (gen.get("interfaces") or {}).items()
                                   if isinstance(v, dict) and _truthy(v.get("selected"))],
                    "valid_lifetime": gen.get("valid_lifetime"),
                    "subnets": [{
                        "subnet": s.get("subnet"), "pools": s.get("pools"),
                        "routers": s.get("option_data.routers"),
                        "dns_servers": s.get("option_data.domain_name_servers"),
                        "domain_name": s.get("option_data.domain_name"),
                        "ntp_servers": s.get("option_data.ntp_servers"),
                        "description": s.get("description"),
                    } for s in subnets],
                    "reservations": [{
                        "ip": r.get("ip_address"), "mac": r.get("hw_address"), "hostname": r.get("hostname"),
                        "subnet": r.get("%subnet") or r.get("subnet"), "description": r.get("description"),
                    } for r in res],
                }
                out["kea_dhcpv4"] = kea_out
        except Exception as exc:
            if "404" not in str(exc):
                out["kea_error"] = str(exc)[:200]

        # Dnsmasq
        try:
            dm = (await c._request("GET", "/api/dnsmasq/settings/get")).get("dnsmasq", {})
            if _truthy(dm.get("enable")):
                ranges = await c.fetch_all_rows("/api/dnsmasq/settings/search_range")
                hosts = await c.fetch_all_rows("/api/dnsmasq/settings/search_host")
                out["dnsmasq"] = {
                    "enabled": True,
                    "interfaces": [k for k, v in (dm.get("interface") or {}).items()
                                   if isinstance(v, dict) and _truthy(v.get("selected"))],
                    "ranges": [{k: r.get(k) for k in ("interface", "start_addr", "end_addr", "lease_time", "domain", "description")
                                if r.get(k)} for r in ranges],
                    "hosts": [{k: h.get(k) for k in ("host", "domain", "ip", "hwaddr", "description") if h.get(k)}
                              for h in hosts],
                }
        except Exception as exc:
            if "404" not in str(exc):
                out["dnsmasq_error"] = str(exc)[:200]

        # ISC (plugin from 26.1; core before)
        try:
            isc = await c._request("GET", "/api/dhcpv4/service/status")
            if isc.get("status") not in (None, "disabled", "unknown"):
                out["isc_dhcpv4"] = {"status": isc.get("status"),
                                     "note": "ISC DHCP settings are not exposed by the API; see downloadConfigXml(section=\"dhcpd\")."}
        except Exception:
            pass

        if interface:
            w = interface.lower()
            if "kea_dhcpv4" in out and w not in out["kea_dhcpv4"]["interfaces"]:
                out["kea_dhcpv4"]["note"] = f"Kea is not serving {interface}."
            if "dnsmasq" in out:
                out["dnsmasq"]["ranges"] = [r for r in out["dnsmasq"]["ranges"] if str(r.get("interface", "")).lower() == w]

        active = [k for k in ("kea_dhcpv4", "dnsmasq", "isc_dhcpv4") if k in out]
        out["active_servers"] = active
        if not active:
            out["note"] = "No DHCP server is enabled on this firewall (addresses may be handed out elsewhere)."
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 14: getInterfaces
@mcp.tool()
async def getInterfaces(interface: Optional[str] = None, include_unassigned: bool = False,
                        include_stats: bool = False) -> str:
    """Network interfaces: name, device, link status, speed/duplex, IPv4/IPv6, gateway, MTU, MAC.
    [YES] "網路介面", "show interfaces", "WAN IP", "WAN interface", "link speed", "介面是不是 up",
          "網卡速度", "interface stats", "errors/drops".
    [NO] "ARP/NDP table" -> use getNetworkNeighbors().
    [NO] "Gateway up/down, latency" -> use getGateways().

    `media` shows the negotiated speed: a gigabit port that reports 100baseTX usually
    means a bad cable or a 100M switch port.

    Args:
        interface: One interface by name (wan, lan, opt1), description (WAN2) or device (igb0, pppoe0).
        include_unassigned: Also list NIC ports not assigned to any interface.
        include_stats: Add packet/byte/error counters."""
    try:
        c = await _ensure_client()
        rows = await c.fetch_all_rows("/api/interfaces/overview/interfacesInfo")
        ifaces = [_normalize_interface(r) for r in rows]
        if interface:
            w = interface.lower()
            ifaces = [i for i in ifaces if w in (str(i.get("name", "")).lower(), str(i.get("description", "")).lower(),
                                                 str(i.get("device", "")).lower())]
        elif not include_unassigned:
            ifaces = [i for i in ifaces if i.get("name")]
        if include_stats and ifaces:
            try:
                stats = await c.get_interface_statistics()
                stats = stats.get("statistics", stats) if isinstance(stats, dict) else {}
                for i in ifaces:
                    for key, val in stats.items():
                        if isinstance(val, dict) and (val.get("name") == i.get("device") or key.endswith(f"({i.get('device')})")
                                                      or key == i.get("device")):
                            i["stats"] = {k: val.get(k) for k in (
                                "received-packets", "sent-packets", "received-bytes", "sent-bytes",
                                "received-errors", "send-errors", "dropped-packets", "collisions") if k in val}
                            break
            except Exception as exc:
                return _R({"data": ifaces, "count": len(ifaces), "stats_error": str(exc)})
        return _R({"data": ifaces, "count": len(ifaces)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 15: getNetworkNeighbors
@mcp.tool()
async def getNetworkNeighbors(protocol: str = "all") -> str:
    """Get ARP (IPv4) and/or NDP (IPv6) neighbor tables.
    [YES] "ARP表", "neighbor table", "MAC address table", "NDP table", "IPv6 neighbors".
    [NO] "Routing table" -> use getRoutes().

    Args:
        protocol: "ipv4" (ARP only), "ipv6" (NDP only), or "all" (both)."""
    try:
        c = await _ensure_client()
        result = {}
        if protocol in ("ipv4", "all"):
            try:
                result["arp"] = await c.get_arp_table()
            except Exception as e:
                result["arp_error"] = str(e)
        if protocol in ("ipv6", "all"):
            try:
                result["ndp"] = await c.get_ndp_table()
            except Exception as e:
                result["ndp_error"] = str(e)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 16: getRoutes
@mcp.tool()
async def getRoutes(search: Optional[str] = None, proto: str = "all", include_static_config: bool = True) -> str:
    """Routing table actually in use (kernel routes), plus configured static routes.
    [YES] "路由表", "routing table", "show routes", "default route", "how is 10.0.0.0/8 routed".
    [NO] "ARP table" -> use getNetworkNeighbors().
    [NO] "Gateway status/latency" -> use getGateways().

    Args:
        search: Filter by destination, gateway or interface (partial match).
        proto: "ipv4", "ipv6" or "all".
        include_static_config: Also return the static routes configured under System > Routes."""
    try:
        c = await _ensure_client()
        out: Dict[str, Any] = {}
        table = await c._request("GET", "/api/diagnostics/interface/getRoutes")
        rows = table if isinstance(table, list) else table.get("rows", [])
        routes = [{
            "proto": r.get("proto"), "destination": r.get("destination"), "gateway": r.get("gateway"),
            "flags": r.get("flags"), "interface": r.get("netif"), "interface_label": r.get("intf_description"),
            "mtu": r.get("mtu"),
        } for r in rows]
        if proto in ("ipv4", "ipv6"):
            routes = [r for r in routes if r["proto"] == proto]
        if search:
            s = search.lower()
            routes = [r for r in routes if any(s in str(r.get(k, "")).lower()
                                               for k in ("destination", "gateway", "interface", "interface_label"))]
        out["routes"] = routes
        out["count"] = len(routes)
        if include_static_config:
            try:
                static = await c.get_routes()
                out["static_routes"] = [{k: r.get(k) for k in ("network", "gateway", "descr", "disabled") if k in r}
                                        for r in static.get("rows", [])]
            except Exception as exc:
                out["static_routes_error"] = str(exc)[:200]
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 17: getGateways
@mcp.tool()
async def getGateways(name: Optional[str] = None) -> str:
    """Get gateways: configuration AND live status in one call.
    [YES] "閘道", "gateway status", "is the gateway down", "Monitor IP", "WAN down",
          "gateway loss/latency", "default gateway", "多 WAN".
    [NO] "Routing table" -> use getRoutes().

    Returns per gateway: interface, gateway IP, monitor_ip, monitor_disabled, priority,
    weight, is_default, plus live status/loss/delay from dpinger.

    Reading status alone is misleading: a gateway with monitor_disabled=true is never
    probed, so it always reports "Online" and can never be marked down. That case is
    flagged in the "note" field.

    Args:
        name: Only this gateway (case-insensitive). None = all."""
    try:
        c = await _ensure_client()
        gateways, source = [], None

        try:
            result = await c.search_gateways()
            gateways = [_normalize_gateway(r) for r in result.get("rows", [])]
            source = "api"
        except Exception as api_exc:
            logger.warning(f"routing/settings/search_gateway failed, "
                           f"falling back to config.xml: {api_exc}")
            root = await c.download_config_xml()
            gateways = c._parse_gateways_from_xml(root)
            source = "config"
            # config.xml has no live state; merge in what the status endpoint knows.
            # It also reports dynamic (DHCP/PPPoE) gateways, which have no config entry.
            try:
                status = await c.get_gateway_status()
                by_name = {g["name"]: g for g in gateways}
                for item in status.get("items", []):
                    gw = by_name.get(item.get("name"))
                    if gw is None:
                        gw = {"name": item.get("name", ""), "dynamic": True, "enabled": True}
                        gateways.append(gw)
                    gw.update({
                        "status": item.get("status_translated", ""),
                        "loss": item.get("loss", ""),
                        "delay": item.get("delay", ""),
                        "stddev": item.get("stddev", ""),
                    })
            except Exception as status_exc:
                logger.warning(f"routes/gateway/status failed: {status_exc}")

        if name:
            gateways = [g for g in gateways if g.get("name", "").lower() == name.lower()]

        return _R({"source": source, "data": gateways, "count": len(gateways)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 18: downloadConfigXml
@mcp.tool()
async def downloadConfigXml(section: Optional[str] = None,
                            max_chars: int = 40000) -> str:
    """Download OPNsense config.xml. With `section`, returns that section's raw XML.
    [YES] "下載設定檔", "download config", "config.xml backup", "撈設定檔".
    [YES] "show me the <gateways> section", "raw config for interfaces".
    [NO] "Firewall rules" -> use getFirewallRules() (26.1 keeps them out of config.xml).
    [NO] "Gateway monitor IP / status" -> use getGateways().

    Args:
        section: Top-level config.xml section to dump as raw XML, e.g. "gateways",
            "system", "nat", "interfaces", "OPNsense". Also accepts a path like
            "OPNsense/Gateways". None = system info + section counts (the summary).
        max_chars: Truncate the XML at this many characters. The full config.xml is
            typically 300KB+, which would blow the context window.

    Requires OPNsense >= 23.7.8 or os-api-backup plugin."""
    try:
        c = await _ensure_client()
        root = await c.download_config_xml()

        if section:
            path = section.strip().strip("/")
            nodes = root.findall(f"./{path}")
            if not nodes:
                available = sorted({child.tag for child in root})
                return _R({"error": f"Section '{section}' not found in config.xml",
                           "available_sections": available})

            out = {"section": path, "count": len(nodes)}

            # Sections that migrated to an MVC model leave a stub at the legacy path
            # (e.g. 26.1 keeps <gateways><gateway_item/></gateways> while the real data
            # sits under <OPNsense><Gateways>). The stub is not childless - it holds an
            # empty element - so test for actual content, not for children. Returning it
            # silently reads as "this section is empty", which is wrong.
            def _has_content(node: Element) -> bool:
                return any((e.text or "").strip() for e in node.iter())

            if not any(_has_content(n) for n in nodes):
                leaf = path.split("/")[-1].lower()
                mvc_root = root.find("./OPNsense")
                elsewhere = [f"OPNsense/{child.tag}" for child in (mvc_root if mvc_root is not None else [])
                             if child.tag.lower() == leaf and _has_content(child)]
                if elsewhere:
                    out["note"] = (f"'{path}' is an empty legacy stub; this data moved to "
                                   f"{elsewhere[0]}. Retry with section='{elsewhere[0]}'.")
                    out["see_also"] = elsewhere

            xml = "\n".join(ET.tostring(n, encoding="unicode") for n in nodes)
            if len(xml) > max_chars:
                out["xml"] = xml[:max_chars]
                out["truncated"] = True
                out["total_chars"] = len(xml)
            else:
                out["xml"] = xml
            return _R(out)

        def txt(elem, default=""):
            return elem.text.strip() if elem is not None and elem.text else default

        sys_info = {}
        sys_node = root.find("./system")
        if sys_node is not None:
            sys_info = {
                "hostname": txt(sys_node.find("hostname")),
                "domain": txt(sys_node.find("domain")),
                "timezone": txt(sys_node.find("timezone")),
            }

        # OPNsense version (config.xml doesn't have it)
        sys_info.update(await c.get_product_version())

        counts = {
            # config.xml-only counts. On 26.1 filter/rule is empty (rules live in the
            # MVC model), so this is the on-disk view, not the effective ruleset.
            "firewall_rules_in_xml": len(root.findall("./filter/rule")),
            "aliases": len(root.findall(".//alias")),
            "interfaces": len(root.findall("./interfaces/*")),
            "gateways": len(root.findall("./gateways/gateway_item")) +
                        len(root.findall("./OPNsense/Gateways/gateway_item")),
            "nat_forward": len(root.findall("./nat/rule")),
            "nat_outbound": len(root.findall("./nat/outbound/rule")),
            "nat_source": len(root.findall("./nat/advancedoutbound/rule")) + len(root.findall("./nat/source/rule")),
            "nat_1to1": len(root.findall("./nat/onetoone/rule")),
        }

        # The effective rule count comes from the API; report both so a 0 in the XML
        # reads as "migrated to the MVC model", not "this firewall has no rules".
        try:
            fw_rules, fw_source = await _fetch_firewall_rules()
            counts["firewall_rules"] = len(fw_rules)
            counts["firewall_rules_source"] = fw_source
        except Exception as exc:
            counts["firewall_rules_error"] = str(exc)

        return _R({"system": sys_info, "counts": counts,
                   "sections": sorted({child.tag for child in root}), "status": "ok"})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 19: getPlugins
@mcp.tool()
async def getPlugins(status: str = "all", search: Optional[str] = None) -> str:
    """Get OPNsense plugins (os-* packages) with optional filtering.
    [YES] "已安裝 plugin", "可安裝插件", "plugin list", "os-haproxy", "available plugins".
    [NO] "System packages" -> use getPackages().
    [NO] "Specific package detail" -> use getPackageInfo().

    Args:
        status: "all" (default), "installed", or "available".
        search: Filter by name or description (case-insensitive partial match)."""
    try:
        c = await _ensure_client()
        info = await c.get_firmware_info()
        packages = info.get("package", [])

        plugins = [p for p in packages if p.get("name", "").startswith("os-")]

        installed = [p for p in plugins if p.get("installed") == "1"]
        available = [p for p in plugins if p.get("installed") != "1"]

        if status == "installed":
            plugins = installed
        elif status == "available":
            plugins = available

        if search:
            kw = search.lower()
            plugins = [p for p in plugins
                       if kw in p.get("name", "").lower()
                       or kw in p.get("comment", "").lower()]

        slim = [{
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "comment": p.get("comment", ""),
            "installed": p.get("installed", "0"),
            "repository": p.get("repository", ""),
            "flatsize": p.get("flatsize", ""),
        } for p in plugins]

        return _R({
            "plugins": slim,
            "count": len(slim),
            "installed_count": len(installed),
            "available_count": len(available),
        })
    except Exception as e:
        return _R({"error": str(e)})


# Tool 20: getPackages
@mcp.tool()
async def getPackages(status: str = "installed", search: Optional[str] = None) -> str:
    """Get system packages (non-plugin, non os-* packages) with optional filtering.
    [YES] "已安裝套件", "系統套件", "installed packages", "patches", "FreeBSD packages".
    [NO] "Plugin list" -> use getPlugins().
    [NO] "Specific package detail" -> use getPackageInfo().

    Args:
        status: "installed" (default), "all", or "available".
        search: Filter by name or description (case-insensitive partial match)."""
    try:
        c = await _ensure_client()
        info = await c.get_firmware_info()
        packages = info.get("package", [])

        sys_pkgs = [p for p in packages if not p.get("name", "").startswith("os-")]

        installed = [p for p in sys_pkgs if p.get("installed") == "1"]
        available = [p for p in sys_pkgs if p.get("installed") != "1"]

        if status == "installed":
            sys_pkgs = installed
        elif status == "available":
            sys_pkgs = available

        if search:
            kw = search.lower()
            sys_pkgs = [p for p in sys_pkgs
                        if kw in p.get("name", "").lower()
                        or kw in p.get("comment", "").lower()]

        slim = [{
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "comment": p.get("comment", ""),
            "installed": p.get("installed", "0"),
            "repository": p.get("repository", ""),
            "flatsize": p.get("flatsize", ""),
        } for p in sys_pkgs]

        return _R({
            "packages": slim,
            "count": len(slim),
            "installed_count": len(installed),
            "available_count": len(available),
        })
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────────── Main Entry Point ─────────────────────────

# Tool 22: getSystemHealth
@mcp.tool()
async def getSystemHealth() -> str:
    """Firewall health at a glance: version, uptime, load, memory, swap, disk, CPU
    temperature, state table usage, and system notices (crash reports, pending reboot...).
    [YES] "系統狀態", "健康狀態", "uptime", "開機多久", "CPU 溫度", "記憶體", "磁碟空間",
          "load", "state table full?", "系統告警", "crash report".
    [NO] "Firmware updates" -> use getFirmwareStatus().
    [NO] "Interface errors / link speed" -> use getInterfaces(include_stats=True)."""
    try:
        c = await _ensure_client()
        endpoints = {
            "info": "/api/diagnostics/system/system_information",
            "time": "/api/diagnostics/system/system_time",
            "resources": "/api/diagnostics/system/systemResources",
            "swap": "/api/diagnostics/system/system_swap",
            "disk": "/api/diagnostics/system/systemDisk",
            "temperature": "/api/diagnostics/system/system_temperature",
            "states": "/api/diagnostics/firewall/pf_states",
            "notices": "/api/core/system/status",
        }
        got = dict(zip(endpoints, await asyncio.gather(
            *(c._request("GET", ep, use_cache=False) for ep in endpoints.values()), return_exceptions=True)))
        out: Dict[str, Any] = {}
        errors = {k: str(v)[:150] for k, v in got.items() if isinstance(v, Exception)}
        ok = {k: v for k, v in got.items() if not isinstance(v, Exception)}

        if "info" in ok:
            out["hostname"] = ok["info"].get("name")
            out["versions"] = ok["info"].get("versions")
        if "time" in ok:
            t = ok["time"]
            out.update({"uptime": t.get("uptime"), "boot_time": t.get("boottime"),
                        "load_average": t.get("loadavg"), "last_config_change": t.get("config")})
        if "resources" in ok:
            mem = ok["resources"].get("memory", {})
            try:
                total, used = int(mem.get("total", 0)), int(mem.get("used", 0))
                out["memory"] = {"total_mb": total // 1048576, "used_mb": used // 1048576,
                                 "used_pct": round(used * 100 / total, 1) if total else None,
                                 "zfs_arc_mb": int(mem.get("arc", 0)) // 1048576 if mem.get("arc") else None}
            except (TypeError, ValueError):
                out["memory"] = mem
        if "swap" in ok:
            out["swap"] = [{"device": s_.get("device"), "total_mb": int(s_.get("total", 0)) // 1024,
                            "used_mb": int(s_.get("used", 0)) // 1024} for s_ in ok["swap"].get("swap", [])]
        if "disk" in ok:
            out["disk"] = [{k: d.get(k) for k in ("mountpoint", "type", "blocks", "used", "available", "used_pct")}
                           for d in ok["disk"].get("devices", [])
                           if d.get("mountpoint") in ("/", "/var/log", "/tmp", "/var") or (d.get("used_pct") or 0) >= 80]
        if "temperature" in ok:
            temps = [float(x["temperature"]) for x in ok["temperature"] if str(x.get("temperature", "")).replace(".", "", 1).isdigit()]
            if temps:
                out["temperature_c"] = {"max": max(temps), "avg": round(sum(temps) / len(temps), 1), "sensors": len(temps)}
        if "states" in ok:
            try:
                cur, lim = int(ok["states"].get("current", 0)), int(ok["states"].get("limit", 0))
                out["state_table"] = {"current": cur, "limit": lim, "used_pct": round(cur * 100 / lim, 2) if lim else None}
            except (TypeError, ValueError):
                out["state_table"] = ok["states"]
        if "notices" in ok:
            subs = ok["notices"].get("subsystems", {})
            out["notices"] = [{"subsystem": k, "status": v.get("status"), "message": v.get("message"), "age": v.get("age")}
                              for k, v in (subs.items() if isinstance(subs, dict) else [])
                              if isinstance(v, dict) and v.get("status") not in ("OK", None)]
        if errors:
            out["errors"] = errors
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 23: getFirewallLog
@mcp.tool()
async def getFirewallLog(action: Optional[str] = None, interface: Optional[str] = None,
                         ip: Optional[str] = None, port: Optional[str] = None,
                         search: Optional[str] = None, limit: int = 50) -> str:
    """Recent firewall log entries (newest first): which packets were blocked or passed, and by which rule.
    [YES] "防火牆日誌", "firewall log", "為什麼被擋", "why is X blocked", "blocked traffic from IP",
          "誰在掃我的 port", "live log".
    [NO] "Rule list" -> use getFirewallRules().
    [NO] "Current connections" -> use getFirewallStates().

    Only rules with logging enabled (and the default deny rule) appear in the log.

    Args:
        action: pass, block or rdr. None = all.
        interface: Interface name or label (wan, LAN, WAN2, pppoe0 ...).
        ip: Source or destination IP.
        port: Source or destination port.
        search: Text in the rule label/description.
        limit: Max entries returned (default 50, max 500). Up to 2000 recent lines are scanned."""
    try:
        c = await _ensure_client()
        scan = 2000 if any((action, interface, ip, port, search)) else max(1, min(limit, 500))
        rows = await c._request("GET", "/api/diagnostics/firewall/log", params={"limit": scan}, use_cache=False)
        rows = rows if isinstance(rows, list) else rows.get("rows", [])
        # The log records the device (pppoe0, igb2); accept wan / WAN2 / opt1 as well.
        devices, labels = set(), {}
        try:
            for i in await c.fetch_all_rows("/api/interfaces/overview/interfacesInfo"):
                if i.get("device"):
                    labels[i["device"]] = i.get("description") or i.get("identifier")
                    if interface and interface.lower() in (str(i.get("identifier", "")).lower(),
                                                           str(i.get("description", "")).lower(),
                                                           str(i.get("device", "")).lower()):
                        devices.add(i["device"])
        except Exception:
            pass
        if interface and not devices:
            devices.add(interface)
        out = []
        for r in rows:
            if action and r.get("action") != action.lower():
                continue
            if interface and r.get("interface") not in devices:
                continue
            if ip and ip not in (r.get("src"), r.get("dst")):
                continue
            if port and str(port) not in (str(r.get("srcport")), str(r.get("dstport"))):
                continue
            if search and search.lower() not in str(r.get("label", "")).lower():
                continue
            out.append({k: r.get(k) for k in ("__timestamp__", "action", "interface_name", "interface", "dir",
                                              "protoname", "src", "srcport", "dst", "dstport", "label", "rid", "tcpflags")
                        if r.get(k) not in (None, "")})
            if len(out) >= min(limit, 500):
                break
        rule_names = {}
        if out:
            try:
                rules, _ = await _fetch_firewall_rules()
                rule_names = {r.get("uuid"): r.get("description") or r.get("source") for r in rules}
            except Exception:
                pass
        for e in out:
            e["time"] = e.pop("__timestamp__", None)
            if not e.get("label") and rule_names.get(e.get("rid")):
                e["rule"] = rule_names[e["rid"]]
            if e.get("interface") in labels:
                e["interface_label"] = labels[e["interface"]]
        return _R({"scanned": len(rows), "data": out, "count": len(out)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 24: getFirewallStates
@mcp.tool()
async def getFirewallStates(search: Optional[str] = None, limit: int = 50) -> str:
    """Current connections in the firewall state table (who talks to whom, via which rule, how much traffic).
    [YES] "目前連線", "state table", "active connections", "誰連到外面", "192.168.1.50 有哪些連線",
          "連線數", "top connections".
    [NO] "Past blocked traffic" -> use getFirewallLog().
    [NO] "State table size only" -> use getSystemHealth().

    Args:
        search: IP, port or rule description to filter by (strongly recommended - a busy
            firewall has thousands of states).
        limit: Max states returned (default 50, max 500)."""
    try:
        c = await _ensure_client()
        limit = max(1, min(limit, 500))
        res = await c._request("POST", "/api/diagnostics/firewall/query_states", use_cache=False,
                               data={"current": 1, "rowCount": limit, "searchPhrase": search or "", "sort": {}})
        rows = res.get("rows", []) if isinstance(res, dict) else []
        data = [{
            "proto": r.get("proto"), "src": f"{r.get('src_addr')}:{r.get('src_port')}",
            "dst": f"{r.get('dst_addr')}:{r.get('dst_port')}",
            "nat": f"{r.get('nat_addr')}:{r.get('nat_port')}" if r.get("nat_addr") else None,
            "state": r.get("state"), "direction": r.get("direction"), "age": r.get("age"),
            "packets": sum(r.get("pkts") or []) if isinstance(r.get("pkts"), list) else r.get("pkts"),
            "bytes": sum(r.get("bytes") or []) if isinstance(r.get("bytes"), list) else r.get("bytes"),
            "rule": r.get("descr"), "gateway": r.get("gateway"),
        } for r in rows]
        data = [{k: v for k, v in d.items() if v not in (None, "")} for d in data]
        return _R({"total_matching": res.get("total", len(rows)), "data": data, "count": len(data)})
    except Exception as e:
        return _R({"error": str(e)})


# Log scopes that may be read. Exactly two path segments: diagnostics/log/<module>/<scope>
# also has a "clear" action that wipes the log, so the path is never built from free text.
_LOG_SCOPES = ("system", "audit", "filter", "gateways", "routing", "resolver", "kea", "dnsmasq",
               "dhcpd", "wireguard", "openvpn", "ipsec", "suricata", "ntpd", "pkg", "configd",
               "lighttpd", "portalauth", "monit", "boot", "dhcrelay", "hostwatch")
_SEVERITIES = ("Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug")


# Tool 25: getSystemLog
@mcp.tool()
async def getSystemLog(log: str = "system", search: Optional[str] = None,
                       min_severity: Optional[str] = None, limit: int = 50) -> str:
    """Read an OPNsense log (newest first).
    [YES] "系統日誌", "system log", "audit log", "誰登入過", "login failures", "設定變更紀錄",
          "DHCP log", "WireGuard log", "Suricata log", "gateway log", "DNS log".
    [NO] "Firewall packet log" -> use getFirewallLog().
    [NO] "IDS alerts" -> use getIdsAlerts().

    Args:
        log: One of system, audit (logins, API calls, config changes), gateways, routing,
            resolver, kea, dnsmasq, dhcpd, wireguard, openvpn, ipsec, suricata, ntpd, pkg,
            configd, lighttpd, portalauth, monit, boot, dhcrelay, hostwatch.
        search: Text to search for.
        min_severity: Only this severity and worse: Emergency, Alert, Critical, Error,
            Warning, Notice, Informational, Debug.
        limit: Max lines (default 50, max 500)."""
    try:
        scope = (log or "").strip().lower()
        if scope not in _LOG_SCOPES:
            return _R({"error": f"Unknown log '{log}'.", "available": list(_LOG_SCOPES)})
        body: Dict[str, Any] = {"current": 1, "rowCount": max(1, min(limit, 500)), "searchPhrase": search or ""}
        if min_severity:
            sev = min_severity.strip().capitalize()
            if sev not in _SEVERITIES:
                return _R({"error": f"Unknown severity '{min_severity}'.", "available": list(_SEVERITIES)})
            body["severity"] = ",".join(_SEVERITIES[:_SEVERITIES.index(sev) + 1])
        c = await _ensure_client()
        res = await c._request("POST", f"/api/diagnostics/log/core/{scope}", data=body, use_cache=False)
        rows = [{"time": r.get("timestamp"), "severity": r.get("severity"), "process": r.get("process_name"),
                 "message": (r.get("line") or "").strip()} for r in res.get("rows", [])]
        return _R({"log": scope, "total_matching": res.get("total_rows", res.get("total")), "data": rows, "count": len(rows)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 26: getVpnStatus
@mcp.tool()
async def getVpnStatus(vpn_type: str = "all") -> str:
    """VPN tunnel status: WireGuard peers (last handshake, traffic), OpenVPN connected
    clients, IPsec phase 1/2 SAs.
    [YES] "VPN 狀態", "tunnel up?", "WireGuard 有沒有連上", "last handshake", "誰連上 VPN",
          "OpenVPN clients", "IPsec SA", "site-to-site".
    [NO] "VPN logs" -> use getSystemLog(log="wireguard"/"openvpn"/"ipsec").

    Args:
        vpn_type: wireguard, openvpn, ipsec or all."""
    try:
        c = await _ensure_client()
        want = vpn_type.lower()
        out: Dict[str, Any] = {}

        async def fetch(path):
            try:
                return await c._request("GET", path, use_cache=False)
            except Exception as exc:
                return exc

        if want in ("all", "wireguard"):
            wg = await fetch("/api/wireguard/service/show")
            if isinstance(wg, Exception):
                if "404" not in str(wg):
                    out["wireguard_error"] = str(wg)[:150]
            else:
                rows = wg.get("rows", [])
                ifaces = {r.get("if"): r for r in rows if r.get("type") == "interface"}
                peers = []
                for r in rows:
                    if r.get("type") != "peer":
                        continue
                    peers.append({k: v for k, v in {
                        "interface": r.get("if"), "instance": ifaces.get(r.get("if"), {}).get("name"),
                        "peer": r.get("name"), "endpoint": r.get("endpoint"), "allowed_ips": r.get("allowed-ips"),
                        "status": r.get("peer-status"), "latest_handshake_age_s": r.get("latest-handshake-age"),
                        "latest_handshake": _epoch_iso(r.get("latest-handshake-epoch")),
                        "rx_bytes": r.get("transfer-rx"), "tx_bytes": r.get("transfer-tx"),
                    }.items() if v not in (None, "")})
                out["wireguard"] = {"instances": [{"interface": k, "name": v.get("name"), "status": v.get("status"),
                                                   "listen_port": v.get("listen-port")} for k, v in ifaces.items()],
                                    "peers": peers}
        if want in ("all", "openvpn"):
            ov = await fetch("/api/openvpn/service/search_sessions")
            if isinstance(ov, Exception):
                if "404" not in str(ov):
                    out["openvpn_error"] = str(ov)[:150]
            else:
                out["openvpn_sessions"] = [{k: r.get(k) for k in (
                    "description", "type", "common_name", "real_address", "virtual_address", "connected_since",
                    "bytes_received", "bytes_sent", "status") if r.get(k) not in (None, "")} for r in ov.get("rows", [])]
        if want in ("all", "ipsec"):
            p1 = await fetch("/api/ipsec/sessions/search_phase1")
            if isinstance(p1, Exception):
                if "404" not in str(p1):
                    out["ipsec_error"] = str(p1)[:150]
            else:
                p2 = await fetch("/api/ipsec/sessions/search_phase2")
                out["ipsec"] = {"phase1": [{k: r.get(k) for k in (
                    "name", "phase1desc", "local-addrs", "remote-addrs", "connected", "install-time", "state")
                    if r.get(k) not in (None, "")} for r in p1.get("rows", [])],
                    "phase2_count": len(p2.get("rows", [])) if isinstance(p2, dict) else None}
        return _R(out)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 27: getIdsAlerts
@mcp.tool()
async def getIdsAlerts(search: Optional[str] = None, limit: int = 50) -> str:
    """Suricata IDS/IPS alerts (newest first): signature, source/destination, action taken.
    [YES] "IDS 告警", "Suricata alerts", "入侵偵測", "intrusion alerts", "was this IP flagged",
          "被 IPS 擋下的".
    [NO] "Firewall rule blocks" -> use getFirewallLog().

    Args:
        search: IP, signature text or SID to filter by.
        limit: Max alerts (default 50, max 500)."""
    try:
        c = await _ensure_client()
        status = None
        try:
            status = (await c._request("GET", "/api/ids/service/status", use_cache=False)).get("status")
        except Exception:
            pass
        res = await c._request("POST", "/api/ids/service/query_alerts", use_cache=False,
                               data={"current": 1, "rowCount": max(1, min(limit, 500)),
                                     "searchPhrase": search or "", "fileid": ""})
        data = [{k: v for k, v in {
            "time": r.get("timestamp"), "signature": r.get("alert"), "sid": r.get("alert_sid"),
            "action": r.get("alert_action"), "src": f"{r.get('src_ip')}:{r.get('src_port')}",
            "dst": f"{r.get('dest_ip')}:{r.get('dest_port')}", "proto": r.get("proto"),
            "app_proto": r.get("app_proto"), "interface": r.get("in_iface"),
        }.items() if v not in (None, "")} for r in res.get("rows", [])]
        return _R({"ids_status": status, "total_matching": res.get("total"), "data": data, "count": len(data)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 28: getCertificates
@mcp.tool()
async def getCertificates(expiring_within_days: Optional[int] = None, in_use_only: bool = False) -> str:
    """Certificates in System > Trust with expiry dates and days left.
    [YES] "憑證", "certificate expiry", "憑證到期", "SSL cert expired?", "Web GUI certificate",
          "which certs expire soon".
    [NO] "ACME / Let's Encrypt renewal log" -> use getSystemLog().

    Private keys are never returned.

    Args:
        expiring_within_days: Only certificates that expire within this many days
            (already expired ones included). None = all.
        in_use_only: Only certificates OPNsense is using."""
    try:
        c = await _ensure_client()
        rows = await c.fetch_all_rows("/api/trust/cert/search")
        now = time.time()
        certs = []
        for r in rows:
            # Copy only these fields: the search rows also carry prv / prv_payload (private keys).
            try:
                valid_to = int(r.get("valid_to") or 0)
            except ValueError:
                valid_to = 0
            days_left = int((valid_to - now) // 86400) if valid_to else None
            cert = {
                "description": r.get("descr"), "common_name": r.get("commonname"), "subject": r.get("name"),
                "type": r.get("%cert_type") or r.get("cert_type"), "in_use": _truthy(r.get("in_use")),
                "valid_from": _epoch_iso(r.get("valid_from")), "valid_to": _epoch_iso(r.get("valid_to")),
                "days_left": days_left, "expired": days_left is not None and days_left < 0,
                "san_dns": r.get("altnames_dns") or None, "key": r.get("%key_type") or None,
            }
            certs.append({k: v for k, v in cert.items() if v is not None})
        if in_use_only:
            certs = [x for x in certs if x.get("in_use")]
        if expiring_within_days is not None:
            certs = [x for x in certs if x.get("days_left") is not None and x["days_left"] <= expiring_within_days]
        certs.sort(key=lambda x: x.get("days_left", 1 << 30))
        return _R({"data": certs, "count": len(certs)})
    except Exception as e:
        return _R({"error": str(e)})


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f"OPNsense FastMCP Server v{__version__} (20 tools)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # stdio mode (default):
  python3 mcp_opnsense.py --host "https://192.168.1.1" --api-key KEY --api-secret SECRET

  # Streamable HTTP mode:
  python3 mcp_opnsense.py --transport streamable-http --port 8000 --host "https://192.168.1.1" --api-key KEY --api-secret SECRET

  # SSE mode:
  python3 mcp_opnsense.py --transport sse --port 8000 --host "https://192.168.1.1" --api-key KEY --api-secret SECRET
        """
    )
    parser.add_argument('--host', help='OPNsense base URL (e.g., https://192.168.1.1)')
    parser.add_argument('--api-key', dest='api_key', help='OPNsense API key')
    parser.add_argument('--api-secret', dest='api_secret', help='OPNsense API secret')
    parser.add_argument('--verify-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                        default=None, help='Verify SSL (true/false)')
    parser.add_argument('--cache-ttl', type=int, default=None, help='Cache TTL seconds (default: 300)')
    parser.add_argument('--timeout', type=int, default=None, help='API timeout seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=None, help='Max retries (default: 3)')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http', 'sse'], default='stdio',
                        help='Transport: stdio (default), streamable-http, or sse')
    parser.add_argument('--listen', default='0.0.0.0', help='HTTP bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='HTTP port (default: 8000)')
    parser.add_argument('--mcp-api-key', default=os.environ.get('MCP_API_KEY', ''),
                        help='API key for SSE/HTTP auth (or set MCP_API_KEY env var)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    config = Config(args)
    cache = SimpleCache(config.CACHE_TTL)

    logger.info("=" * 60)
    logger.info(f"OPNsense FastMCP Server v{__version__} (20 tools)")
    logger.info("=" * 60)
    logger.info(f"Transport: {args.transport}")
    if args.transport in ('streamable-http', 'sse'):
        logger.info(f"HTTP Listen: {args.listen}:{args.port}")
        if args.mcp_api_key:
            logger.info("API Key auth: enabled")
    logger.info(f"Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s, Retries={config.MAX_RETRIES}")
    logger.info("=" * 60)

    if args.transport in ('sse', 'streamable-http'):
        import uvicorn
        from starlette.responses import JSONResponse

        if args.transport == 'sse':
            app = _sse_and_http_app(mcp)
        else:
            app = mcp.streamable_http_app()

        if args.mcp_api_key:
            _api_key = args.mcp_api_key
            app = _APIKeyAuth(app, _api_key)

        uvicorn.run(app, host=args.listen, port=args.port)
    else:
        mcp.run(transport='stdio')
