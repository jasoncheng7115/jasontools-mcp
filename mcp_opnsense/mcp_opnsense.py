#!/usr/bin/env python3
"""
OPNsense MCP Server - v2.1.1 (FastMCP Rewrite)
================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
License: MIT
Created: 2025-06-25
Updated: 2026-03-01

FastMCP-based OPNsense integration optimized for weak/small LLMs.
18 tools, compact responses, camelCase tool names.
Supports stdio, streamable-http, and sse transport.

pip install mcp aiohttp requests defusedxml uvicorn

Changelog:
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

__version__ = "2.0.0"


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


# ───────────────────────── Global State + FastMCP ─────────────────────────

config: Optional[Config] = None
cache: Optional[SimpleCache] = None
client: Optional['OPNsenseClient'] = None

mcp = FastMCP(
    "OPNsense",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
)


# ───────────────────────── OPNsenseClient ─────────────────────────

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
        """Lazy session creation - creates session on first use."""
        if self.session is None or self.session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context)
            auth = aiohttp.BasicAuth(self.cfg.API_KEY, self.cfg.API_SECRET)
            timeout = aiohttp.ClientTimeout(total=self.cfg.TIMEOUT)
            self.session = aiohttp.ClientSession(
                connector=connector, auth=auth, timeout=timeout
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
                    else:
                        raise Exception(f"API error {response.status}: {response_text[:200]}")
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

    # ── Service API Methods ──

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

    async def get_firmware_status(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/status")

    async def get_firmware_info(self) -> Dict:
        return await self._request("GET", "/api/core/firmware/info")

    async def get_firmware_check(self) -> Dict:
        return await self._request("POST", "/api/core/firmware/check", data={})

    async def get_firmware_changelog(self, version: str = None) -> Dict:
        ep = f"/api/core/firmware/changelog/{version}" if version else "/api/core/firmware/changelog"
        return await self._request("POST", ep, data={})

    async def get_firmware_audit(self) -> Dict:
        return await self._request("POST", "/api/core/firmware/audit", data={})

    async def get_firmware_health(self) -> Dict:
        return await self._request("POST", "/api/core/firmware/health", data={})

    async def get_firmware_connection(self) -> Dict:
        return await self._request("POST", "/api/core/firmware/connection", data={})

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

    # ── NAT / Alias API Methods ──

    async def search_nat_rules(self, nat_type: str = "source_nat", search_phrase: str = "",
                               row_count: int = 100) -> Dict:
        params = {"current": 1, "rowCount": row_count, "searchPhrase": search_phrase}
        return await self._request("GET", f"/api/firewall/{nat_type}/searchRule", params=params)

    async def search_aliases_api(self, search_phrase: str = "", row_count: int = 100) -> Dict:
        params = {"current": 1, "rowCount": row_count, "searchPhrase": search_phrase}
        return await self._request("GET", "/api/firewall/alias/searchItem", params=params)

    async def list_alias_content(self, alias_name: str) -> Dict:
        return await self._request("GET", f"/api/firewall/alias_util/list/{alias_name}")


# ───────────────────────── Helper: ensure client ─────────────────────────

async def _ensure_client() -> OPNsenseClient:
    global client
    if client is None:
        client = OPNsenseClient(config)
    await client.ensure_session()
    return client


# ───────────────────────── MCP Tools (18) ─────────────────────────

# Tool 1: getConfigSummary
@mcp.tool()
async def getConfigSummary() -> str:
    """Get comprehensive OPNsense configuration summary from config.xml.
    [YES] Use for overall system info, firewall rule counts, alias counts, NAT stats.
    [NO] Don't use for specific rules -> use getFirewallRules()."""
    try:
        c = await _ensure_client()
        root = await c.download_config_xml()

        fw_rules = c._parse_firewall_rules_from_xml(root)
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

        # Get OPNsense version from firmware API (config.xml doesn't have it)
        try:
            fw_info = await c.get_firmware_info()
            sys_info["product_version"] = fw_info.get("product_version", "")
            sys_info["product_name"] = fw_info.get("product_id", "OPNsense")
            # Enrich from product sub-object if available
            product = fw_info.get("product", {})
            if not sys_info["product_version"] and product:
                sys_info["product_version"] = product.get("product_version", "")
            if product.get("product_name"):
                sys_info["product_name"] = product["product_name"]
            if product.get("product_nickname"):
                sys_info["product_nickname"] = product["product_nickname"]
            if fw_info.get("os_version"):
                sys_info["os_version"] = fw_info["os_version"]
        except Exception:
            pass

        return _R({
            "system": sys_info,
            "stats": {
                "firewall_rules": len(fw_rules),
                "enabled_rules": sum(1 for r in fw_rules if r["enabled"]),
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
@mcp.tool()
async def getFirewallRules(interface: Optional[str] = None, action: Optional[str] = None,
                           enabled_only: Optional[bool] = None,
                           aliases_only: bool = False) -> str:
    """Get firewall rules from config.xml with filtering.
    [YES] "防火牆規則", "show firewall rules", "rules on LAN", "pass rules".
    [NO] "NAT rules" -> use getNatRulesConfig().

    Args:
        interface: Filter by interface (e.g., wan, lan, opt1).
        action: Filter by action (pass, block, reject).
        enabled_only: True=enabled only, False=disabled only, None=all.
        aliases_only: Only show rules that reference aliases."""
    try:
        c = await _ensure_client()
        root = await c.download_config_xml()
        rules = c._parse_firewall_rules_from_xml(root)

        if interface:
            rules = [r for r in rules if r["interface"].lower() == interface.lower()]
        if action:
            rules = [r for r in rules if r["action"].lower() == action.lower()]
        if enabled_only is not None:
            rules = [r for r in rules if r["enabled"] == enabled_only]
        if aliases_only:
            rules = [r for r in rules if r["src_alias"] or r["dst_alias"]]

        return _R({"data": rules, "count": len(rules)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 3: getNatRulesConfig
@mcp.tool()
async def getNatRulesConfig(rule_type: str = "forward", enabled_only: Optional[bool] = None,
                            search: Optional[str] = None) -> str:
    """Get NAT rules from config.xml (forward, outbound, source, one_to_one).
    [YES] "NAT規則", "port forwarding rules", "outbound NAT".
    [NO] "API NAT rules" -> use getNatRules().

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

        return _R({"rule_type": rule_type, "data": rules, "count": len(rules)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 4: getAliases
@mcp.tool()
async def getAliases(source: str = "config", alias_type: Optional[str] = None,
                     enabled_only: Optional[bool] = None,
                     search: Optional[str] = None) -> str:
    """Get aliases from config.xml or API.
    [YES] "別名清單", "list aliases", "show host aliases", "alias search".
    [NO] "Alias content/entries" -> use getAliasContent().

    Args:
        source: "config" (config.xml) or "api" (REST API).
        alias_type: Filter by type (host, network, port, url, etc.).
        enabled_only: True=enabled only, None=all.
        search: Filter by name (case-insensitive partial match)."""
    try:
        c = await _ensure_client()
        if source == "api":
            result = await c.search_aliases_api(search_phrase=search or "", row_count=500)
            aliases = result.get("rows", [])
            return _R({"source": "api", "data": aliases, "count": len(aliases)})
        else:
            root = await c.download_config_xml()
            aliases = c._parse_aliases_from_xml(root)
            if alias_type:
                aliases = [a for a in aliases if a["type"].lower() == alias_type.lower()]
            if enabled_only is not None:
                aliases = [a for a in aliases if a["enabled"] == enabled_only]
            if search:
                aliases = [a for a in aliases if search.lower() in a["name"].lower()]
            return _R({"source": "config", "data": aliases, "count": len(aliases)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 5: getAliasContent
@mcp.tool()
async def getAliasContent(alias_name: str) -> str:
    """Get resolved content entries for a specific alias.
    [YES] "Show entries in alias X", "alias content", "別名內容".
    [NO] "List all aliases" -> use getAliases().

    Args:
        alias_name: The alias name to get content for."""
    try:
        c = await _ensure_client()
        result = await c.list_alias_content(alias_name)
        return _R({"alias": alias_name, "data": result})
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
    """Get detailed status for a specific service.
    [YES] "Check unbound status", "is dhcpd running?", "service X status".
    [NO] "All services" -> use getServices().

    Args:
        service_name: Name or ID of the service (e.g., unbound, dhcpd, openvpn)."""
    try:
        c = await _ensure_client()
        result = await c.get_service_status(service_name)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 8: getFirmwareStatus
@mcp.tool()
async def getFirmwareStatus() -> str:
    """Get firmware status, update availability, and health check.
    [YES] "韌體狀態", "firmware update?", "is OPNsense up to date?", "firmware health".
    [NO] "Package list" -> use getFirmwareInfo().
    [NO] "Firmware settings" -> use getFirmwareConfig()."""
    try:
        c = await _ensure_client()
        result = {}
        try:
            result["status"] = await c.get_firmware_status()
        except Exception as e:
            result["status_error"] = str(e)
        try:
            result["check"] = await c.get_firmware_check()
        except Exception as e:
            result["check_error"] = str(e)
        try:
            result["health"] = await c.get_firmware_health()
        except Exception as e:
            result["health_error"] = str(e)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 9: getFirmwareInfo
@mcp.tool()
async def getFirmwareInfo() -> str:
    """Get firmware info including package list and security audit.
    [YES] "套件清單", "installed packages", "firmware audit", "plugin list".
    [NO] "Firmware update status" -> use getFirmwareStatus().
    [NO] "Specific package" -> use getPackageInfo().

    Returns packages, plugins, and security audit results."""
    try:
        c = await _ensure_client()
        result = {}
        try:
            result["info"] = await c.get_firmware_info()
        except Exception as e:
            result["info_error"] = str(e)
        try:
            result["audit"] = await c.get_firmware_audit()
        except Exception as e:
            result["audit_error"] = str(e)
        return _R(result)
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
        try:
            result["connection"] = await c.get_firmware_connection()
        except Exception as e:
            result["connection_error"] = str(e)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 11: getPackageInfo
@mcp.tool()
async def getPackageInfo(package_name: str, include_license: bool = False,
                         changelog_version: Optional[str] = None) -> str:
    """Get details for a specific package, optionally with license and changelog.
    [YES] "Package os-theme-rebellion info", "package license", "changelog for 24.7".
    [NO] "All packages" -> use getFirmwareInfo().

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
async def getDhcpLeases(search: Optional[str] = None) -> str:
    """Get DHCP leases, optionally filtered by search phrase.
    [YES] "DHCP租約", "show leases", "find lease for 192.168.1.100", "MAC lease".
    [NO] "DHCP settings" -> use getDhcpSettings().

    Args:
        search: Filter by IP, MAC, or hostname (partial match)."""
    try:
        c = await _ensure_client()
        all_leases = []
        current_page = 1
        while True:
            result = await c.search_dhcp_leases(
                search_phrase=search or "", current=current_page, row_count=100
            )
            if 'rows' in result and result['rows']:
                all_leases.extend(result['rows'])
                total = result.get('total', 0)
                if (total > 0 and len(all_leases) >= total) or len(result['rows']) < 100:
                    break
                current_page += 1
            else:
                break
        return _R({"data": all_leases, "count": len(all_leases)})
    except Exception as e:
        return _R({"error": str(e)})


# Tool 13: getDhcpSettings
@mcp.tool()
async def getDhcpSettings(interface: Optional[str] = None) -> str:
    """Get DHCP service status and settings, optionally for a specific interface.
    [YES] "DHCP設定", "DHCP service status", "DHCP config for lan".
    [NO] "DHCP leases" -> use getDhcpLeases().

    Args:
        interface: Specific interface (e.g., lan, opt1). None=global settings."""
    try:
        c = await _ensure_client()
        result = {}
        try:
            result["service_status"] = await c.get_dhcp_service_status()
        except Exception as e:
            result["service_status_error"] = str(e)
        try:
            result["settings"] = await c.get_dhcp_settings()
        except Exception as e:
            result["settings_error"] = str(e)
        if interface:
            try:
                result["interface_settings"] = await c.get_dhcp_interface_settings(interface)
                result["interface"] = interface
            except Exception as e:
                result["interface_settings_error"] = str(e)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 14: getInterfaces
@mcp.tool()
async def getInterfaces(interface: Optional[str] = None,
                        include_stats: bool = False) -> str:
    """Get network interfaces from config.xml and API, optionally with statistics.
    [YES] "網路介面", "show interfaces", "WAN interface config", "interface stats".
    [NO] "ARP/NDP table" -> use getNetworkNeighbors().

    Args:
        interface: Specific interface name (e.g., wan, lan). None=all interfaces.
        include_stats: Include interface traffic statistics."""
    try:
        c = await _ensure_client()
        result = {}

        if interface:
            try:
                result["config"] = await c.get_interface_config(interface)
            except Exception as e:
                result["config_error"] = str(e)
        else:
            # API interfaces
            try:
                overview = await c.get_interface_overview()
                if 'data' in overview and isinstance(overview['data'], dict):
                    ifaces = []
                    for key, value in overview['data'].items():
                        if isinstance(value, dict):
                            iface = value.copy()
                            iface['name'] = key
                            ifaces.append(iface)
                        else:
                            ifaces.append({"name": key, "data": value})
                    result["api_interfaces"] = ifaces
                else:
                    result["api_interfaces"] = overview.get('data', [])
            except Exception as e:
                result["api_error"] = str(e)

            # Config.xml interfaces
            try:
                root = await c.download_config_xml()
                result["config_interfaces"] = c._parse_interfaces_from_xml(root)
            except Exception as e:
                result["config_error"] = str(e)

        if include_stats:
            try:
                result["statistics"] = await c.get_interface_statistics()
            except Exception as e:
                result["statistics_error"] = str(e)

        return _R(result)
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
async def getRoutes() -> str:
    """Get routing table.
    [YES] "路由表", "routing table", "show routes", "default gateway".
    [NO] "ARP table" -> use getNetworkNeighbors()."""
    try:
        c = await _ensure_client()
        result = await c.get_routes()
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 17: getNatRules
@mcp.tool()
async def getNatRules(nat_type: str = "source_nat",
                      search: Optional[str] = None) -> str:
    """Get NAT rules via API (source_nat or one_to_one).
    [YES] "API NAT rules", "source NAT", "1:1 NAT rules".
    [NO] "Config.xml NAT rules" -> use getNatRulesConfig().

    Args:
        nat_type: "source_nat" or "one_to_one".
        search: Filter by description."""
    try:
        c = await _ensure_client()
        result = await c.search_nat_rules(nat_type, search_phrase=search or "", row_count=500)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


# Tool 18: downloadConfigXml
@mcp.tool()
async def downloadConfigXml() -> str:
    """Download and parse OPNsense config.xml, returning system info and section counts.
    [YES] "下載設定檔", "download config", "config.xml backup".
    [NO] "Firewall rules" -> use getFirewallRules().
    [NO] "Full summary" -> use getConfigSummary().

    Requires OPNsense >= 23.7.8 or os-api-backup plugin."""
    try:
        c = await _ensure_client()
        root = await c.download_config_xml()

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

        try:
            fw_info = await c.get_firmware_info()
            sys_info["product_version"] = fw_info.get("product_version", "")
            sys_info["product_name"] = fw_info.get("product_id", "OPNsense")
            product = fw_info.get("product", {})
            if not sys_info["product_version"] and product:
                sys_info["product_version"] = product.get("product_version", "")
            if product.get("product_name"):
                sys_info["product_name"] = product["product_name"]
        except Exception:
            pass

        counts = {
            "firewall_rules": len(root.findall("./filter/rule")),
            "aliases": len(root.findall(".//alias")),
            "interfaces": len(root.findall("./interfaces/*")),
            "nat_forward": len(root.findall("./nat/rule")),
            "nat_outbound": len(root.findall("./nat/outbound/rule")),
            "nat_source": len(root.findall("./nat/advancedoutbound/rule")) + len(root.findall("./nat/source/rule")),
            "nat_1to1": len(root.findall("./nat/onetoone/rule")),
        }

        return _R({"system": sys_info, "counts": counts, "status": "ok"})
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────────── Main Entry Point ─────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f"OPNsense FastMCP Server v{__version__} (18 tools)",
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
    logger.info(f"OPNsense FastMCP Server v{__version__} (18 tools)")
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
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        if args.transport == 'sse':
            app = mcp.sse_app()
        else:
            app = mcp.streamable_http_app()

        if args.mcp_api_key:
            _api_key = args.mcp_api_key

            class APIKeyAuthMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request, call_next):
                    auth_header = request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer '):
                        token = auth_header[7:]
                    else:
                        token = auth_header
                    if token != _api_key:
                        return JSONResponse(
                            {"error": "Unauthorized", "message": "Invalid or missing API key"},
                            status_code=401
                        )
                    return await call_next(request)

            app.add_middleware(APIKeyAuthMiddleware)

        uvicorn.run(app, host=args.listen, port=args.port)
    else:
        mcp.run(transport='stdio')
