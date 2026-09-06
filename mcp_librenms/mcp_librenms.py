#!/usr/bin/env python3
"""
MCP server for LibreNMS API – v4.4.0 Slim (Weak-Model Optimized)
=================================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
License: MIT
Repository: https://github.com/jasoncheng7115/jasontools-mcp

FastMCP-based LibreNMS integration optimized for weak/small LLMs.
27 tools, compact responses, human-readable parameters.
Supports stdio, streamable-http, and sse transport.

pip install mcp requests uvicorn

Changelog:
  v4.4.0 - Sensor / port / event / monitoring coverage
    - Added get_sensor_health: temperature, voltage, fan, power sensors.
      369 of 377 sensors on the reference server had no tool before this.
    - Added get_port_traffic: bandwidth utilisation + error counters, ranked.
      Needs ?columns= on /ports; the default response omits both entirely.
    - Added get_event_log: device event log, date-filtered via ?from=
      (the log is oldest-first and can hold >300k rows - never page to the end)
    - Added get_monitoring_health: devices that stopped being polled, so that
      long-stale readings are not mistaken for current data by other tools
    - get_device_sla whole-network fetch parallelised: 11.6s -> 5.3s on 82
      devices (was one serial /availability call per device)
    - Added _parallel_map; SimpleCache is now lock-protected because its
      expiry path could raise KeyError once accessed from a thread pool
    - Peer-outlier detection generalised (_peer_outliers) with two-sided
      support, so a sensor far ABOVE its peers is flagged too
  v4.3.0 - Optical transceiver (SFP/GBIC DDM) health
    - Added get_optical_health: light-level margin + peer-outlier risk ranking
    - Single resources/sensors call for whole-network scope; raw sensors never
      returned to the caller, only summary counts + capped detail rows
    - Pairs dbm with bias-current / temperature sensors of the same transceiver
      via sensor_descr port-key matching
    - Built-in fallback thresholds for devices reporting no sensor_limit_low
      (MikroTik RouterOS reports NULL for every optical limit)
    - Stale readings reported as stale instead of being scored as critical
    - Point-in-time only: no history is stored, so no decay-rate prediction
  v4.2.1 - Compatibility fix
    - Requires mcp>=1.26.0 (TransportSecuritySettings added in newer SDK)
    - Fixed Claude Desktop startup failure caused by outdated mcp package
    - pip install: mcp requests uvicorn (uvicorn only needed for SSE/HTTP)
  v4.2.0 - SLA tools + SSE/Streamable-HTTP fix
    - Added get_device_sla: device availability SLA (uptime/outage history)
    - Added get_cisco_sla: Cisco IP SLA probe results (RTT, jitter, status)
    - SSE/Streamable-HTTP: use uvicorn + sse_app()/streamable_http_app()
      (FastMCP.run() does not support custom host/port for SSE)
    - Disabled DNS rebinding protection (fixes 421 Misdirected Request)
    - Added --api-key for SSE/HTTP Bearer token auth
    - custom_top_devices.php: added cisco_sla query type
    - _extract_data keys expanded: availability, outages
  v4.1.0 - CPU/Memory ranking + robustness improvements
    - Added get_top_cpu, get_top_memory tools with custom_top_devices.php helper
    - custom_top_devices.php: server-side DB query (bypasses API limitation)
    - sysName included in all device-referencing tool responses
    - list_devices default limit 50 (was unlimited, caused LLM output truncation)
    - Improved docstrings with Chinese trigger phrases for weak model matching
    - Multi-strategy health data retrieval with diagnostic error messages
    - _extract_data keys expanded: processors, mempools, graphs, sensors
  v4.0.0 - Complete rewrite for weak/small LLM optimization
    - 32 → 18 tools (merged overlapping, removed debug/niche tools)
    - Compact JSON via _R() (no indent, no ensure_ascii)
    - Slim device/port objects (_slim_device ~11 fields, _slim_port ~7 fields)
    - _resolve_device() accepts hostname/IP/device_id
    - Human-readable params: state="ok"/"warning"/"critical", vlan_tag not vlan_id
    - Consistent response format: {"data": [...], "count": N}
    - [YES]/[NO] intent markers in docstrings (Chinese + English)
    - Dual transport: stdio (default) + streamable-http (--transport http)
  v3.11.0 - Added dual transport support (stdio + streamable-http)
  v3.10.2 - VLAN mapping fix (vlan_id vs vlan_vlan)
  v3.x    - Initial FastMCP implementation, 32 tools
"""

import os
import sys
import re
import json
import time
import hashlib
import logging
import argparse
import ipaddress
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mcp-librenms")


# ───────────────────────── Configuration ─────────────────────────

class Config:
    def __init__(self, args=None):
        if args:
            self.BASE_URL = args.url or os.getenv("LIBRENMS_URL")
            self.TOKEN = args.token or os.getenv("LIBRENMS_TOKEN")
            self.CACHE_TTL = args.cache_ttl if args.cache_ttl is not None else int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
            self.TIMEOUT = args.timeout if args.timeout is not None else int(os.getenv("LIBRENMS_TIMEOUT", "30"))
            self.MAX_RETRIES = args.max_retries if args.max_retries is not None else int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
            self.BATCH_SIZE = args.batch_size if args.batch_size is not None else int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))
            self.VERIFY_SSL = args.verify_ssl if args.verify_ssl is not None else True
        else:
            self.BASE_URL = os.getenv("LIBRENMS_URL")
            self.TOKEN = os.getenv("LIBRENMS_TOKEN")
            self.CACHE_TTL = int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
            self.TIMEOUT = int(os.getenv("LIBRENMS_TIMEOUT", "30"))
            self.MAX_RETRIES = int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
            self.BATCH_SIZE = int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))
            self.VERIFY_SSL = os.getenv("LIBRENMS_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        self.validate()

    def validate(self):
        if not self.BASE_URL or not self.TOKEN:
            logger.error("LibreNMS URL and API Token are required!")
            logger.error("  Command line: --url <URL> --token <TOKEN>")
            logger.error("  Environment:  LIBRENMS_URL=<URL> LIBRENMS_TOKEN=<TOKEN>")
            sys.exit(1)
        self.BASE_URL = self.BASE_URL.rstrip('/')
        if not self.BASE_URL.endswith('/api/v0'):
            self.BASE_URL += '/api/v0'
        logger.info(f"LibreNMS URL: {self.BASE_URL}")


config = None


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class SimpleCache:
    """TTL cache. Locked because whole-network tools fan out over a thread pool
    (see _parallel_map) and two threads expiring the same key would collide."""

    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl
        self._lock = threading.Lock()

    def _key(self, key_data: str) -> str:
        return hashlib.md5(key_data.encode('utf-8')).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        safe_key = self._key(key)
        with self._lock:
            entry = self.cache.get(safe_key)
            if entry is None:
                return None
            data, ts = entry
            if time.time() - ts < self.ttl:
                return data
            self.cache.pop(safe_key, None)
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self.cache[self._key(key)] = (value, time.time())

    def clear(self):
        with self._lock:
            self.cache.clear()

    def stats(self) -> Dict[str, int]:
        now = time.time()
        with self._lock:
            items = list(self.cache.values())
        active = sum(1 for _, ts in items if now - ts < self.ttl)
        return {"total_keys": len(items), "active_keys": active, "ttl_seconds": self.ttl}


cache = None
session = None
mcp = FastMCP(
    "LibreNMS",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
)


def initialize_session():
    global session
    session = requests.Session()
    session.headers.update({
        "X-Auth-Token": config.TOKEN,
        "User-Agent": "mcp-librenms/4.4.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    session.verify = config.VERIFY_SSL


# ───────────────────────── Core Helpers ─────────────────────────

def _api_request(method: str, endpoint: str, params: Optional[Dict] = None,
                 json_body: Optional[Dict] = None, use_cache: bool = True,
                 timeout: Optional[int] = None) -> Dict:
    """Send API request to LibreNMS with caching and retry logic.

    timeout: per-call override. The syslog endpoint routinely needs 40-60s on a
    busy install even for a handful of rows, which the 30s default cannot cover.
    """
    cache_key = f"{method}:{endpoint}:{json.dumps(params, sort_keys=True)}:{json.dumps(json_body, sort_keys=True)}" if use_cache else None

    if cache_key and method.upper() == 'GET':
        cached = cache.get(cache_key)
        if cached:
            return cached

    url = f"{config.BASE_URL}/{endpoint.lstrip('/')}"
    last_exc = None

    for attempt in range(config.MAX_RETRIES):
        try:
            resp = session.request(method.upper(), url, params=params, json=json_body,
                                   timeout=timeout or config.TIMEOUT)
            resp.raise_for_status()
            result = resp.json()
            if cache_key and method.upper() == 'GET' and resp.status_code == 200:
                cache.set(cache_key, result)
            return result
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < config.MAX_RETRIES - 1:
                time.sleep(1.0 * (2 ** attempt))

    raise Exception(f"LibreNMS API error: {last_exc}")


def _extract_data(result: Any, keys: List[str] = None) -> List[Dict]:
    """Extract data array from API response."""
    if keys is None:
        keys = ['devices', 'services', 'alerts', 'data', 'results', 'eventlog',
                'alertlog', 'ports_fdb', 'fdb', 'ports', 'arp', 'ip_arp', 'vlans',
                'processors', 'mempools', 'graphs', 'sensors',
                'availability', 'outages']

    if isinstance(result, list):
        return result

    if isinstance(result, dict):
        for key in keys:
            if key in result:
                val = result[key]
                if isinstance(val, list):
                    return val
        # Fallback: find any list with dict items
        for key, val in result.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return val
        # Single-item result
        if result and not any(isinstance(v, list) for v in result.values()):
            return [result]

    return []


def _paginate(endpoint: str, params: Optional[Dict] = None,
              max_items: Optional[int] = None) -> List[Dict]:
    """Paginated API requests."""
    all_items = []
    offset = 0
    limit = min(config.BATCH_SIZE, 200)
    consecutive_empty = 0
    if params is None:
        params = {}

    for _ in range(50):  # Safety limit
        p = {**params, "limit": limit, "offset": offset}
        try:
            result = _api_request("GET", endpoint, params=p)
            items = _extract_data(result)

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 2 or offset == 0:
                    break
                offset += limit
                continue

            consecutive_empty = 0
            all_items.extend(items)

            if max_items and len(all_items) >= max_items:
                return all_items[:max_items]
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                break
            offset += limit

    # Fallback: large request if pagination got nothing
    if not all_items:
        try:
            result = _api_request("GET", endpoint, params={**params, "limit": 10000})
            all_items = _extract_data(result)
        except Exception:
            pass

    return all_items[:max_items] if max_items else all_items


# ───────────────────────── Utility Helpers ─────────────────────────

def _safe_parse_datetime(ts: Any) -> Optional[datetime]:
    if not ts or ts == '0000-00-00 00:00:00':
        return None
    ts = str(ts)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S.%f'):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts.replace('Z', '').split('+')[0])
    except Exception:
        return None


def _format_timestamp(ts: str) -> str:
    dt = _safe_parse_datetime(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else (str(ts) if ts else "N/A")


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    clean = re.sub(r'[:\-.]', '', mac.lower())
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC: {mac}")
    return clean


def _format_mac(mac: str) -> str:
    if not mac:
        return ""
    clean = re.sub(r'[:\-.]', '', mac.lower())
    if len(clean) != 12:
        return mac
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _validate_cidr(net: str) -> bool:
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False


def _normalize_port_status(val) -> str:
    if val is None:
        return 'unknown'
    if isinstance(val, str):
        return val.lower().strip()
    if isinstance(val, int):
        return {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown',
                5: 'dormant', 6: 'notpresent', 7: 'lowerlayerdown'}.get(val, 'unknown')
    return str(val).lower().strip()


def _evaluate_port_quality(ports: list, device_os: str = None) -> dict:
    if not ports:
        return {"confidence": "none", "has_ifOperStatus": False}
    total = len(ports)
    has_oper = sum(1 for p in ports if p.get('ifOperStatus') is not None)
    if has_oper == total:
        conf = "high"
    elif has_oper > total * 0.5:
        conf = "medium"
    else:
        conf = "low"
    return {"confidence": conf, "has_ifOperStatus": has_oper > 0,
            "ports_with_status": has_oper, "total_ports": total}


# ───────────────────────── v4.0 Slim Helpers ─────────────────────────

def _R(obj) -> str:
    """Compact JSON serialization (no indent, no ASCII escape)."""
    return json.dumps(obj, ensure_ascii=False, cls=DateTimeEncoder)


def _device_status_str(val) -> str:
    if val == 1 or val == "1":
        return "up"
    if val == 0 or val == "0":
        return "down"
    if val == 2 or val == "2":
        return "disabled"
    return "unknown"


def _slim_device(d: dict) -> dict:
    """Keep only essential device fields."""
    if not isinstance(d, dict):
        return d
    return {
        "device_id": d.get("device_id"),
        "hostname": d.get("hostname"),
        "sysName": d.get("sysName"),
        "ip": d.get("ip"),
        "os": d.get("os"),
        "version": d.get("version"),
        "hardware": d.get("hardware"),
        "type": d.get("type"),
        "location": d.get("location"),
        "status": _device_status_str(d.get("status")),
    }


def _slim_port(p: dict) -> dict:
    """Keep only essential port fields."""
    if not isinstance(p, dict):
        return p
    return {
        "port_id": p.get("port_id"),
        "ifName": p.get("ifName"),
        "ifDescr": p.get("ifDescr"),
        "ifAlias": p.get("ifAlias"),
        "ifOperStatus": p.get("ifOperStatus"),
        "ifSpeed": p.get("ifSpeed"),
        "ifType": p.get("ifType"),
    }


def _device_matches(d: Dict, query: str) -> bool:
    """Exact match of a device record against a hostname / sysName / IP query."""
    if not isinstance(d, dict):
        return False
    q = str(query).strip().lower()
    return q in {str(d.get(f, "") or "").lower() for f in ("hostname", "sysName", "ip")}


def _resolve_device(device: str) -> Optional[Dict]:
    """Resolve device by hostname, IP, or numeric ID. Returns slim device dict or None."""
    if not device:
        return None

    # Try numeric ID first
    try:
        device_id = int(device)
        result = _api_request("GET", f"devices/{device_id}")
        devs = _extract_data(result, ['devices'])
        if devs:
            return _slim_device(devs[0])
    except (ValueError, Exception):
        pass

    # Try hostname / IP search. Some LibreNMS versions ignore these query filters
    # and return the whole device list, so the response is verified rather than
    # trusted - taking devs[0] blindly resolves every name to the same device.
    for field in ['hostname', 'ip']:
        try:
            result = _api_request("GET", "devices", params={field: device})
            devs = _extract_data(result, ['devices'])
            match = next((d for d in devs if _device_matches(d, device)), None)
            if match:
                return _slim_device(match)
        except Exception:
            pass

    # Fallback: search all devices
    try:
        all_devs = _paginate("devices", max_items=500)
        dev_lower = device.lower()
        for d in all_devs:
            if not isinstance(d, dict):
                continue
            if (dev_lower == str(d.get("hostname", "")).lower() or
                dev_lower == str(d.get("sysName", "")).lower() or
                dev_lower == str(d.get("ip", "")).lower()):
                return _slim_device(d)
    except Exception:
        pass

    return None


def _build_vlan_cache() -> Dict:
    """Build vlan_id (DB ID) -> {vlan_tag, vlan_name} mapping."""
    mapping = {}
    try:
        result = _api_request("GET", "resources/vlans")
        for v in _extract_data(result, ['vlans']):
            db_id = str(v.get("vlan_id", ""))
            tag = v.get("vlan_vlan")
            if db_id and tag is not None:
                mapping[db_id] = {"vlan_tag": tag, "vlan_name": v.get("vlan_name", "")}
    except Exception as e:
        logger.warning(f"VLAN cache build failed: {e}")
    return mapping


def _enrich_vlan(entry: dict, vcache: dict) -> dict:
    """Add flat vlan_tag and vlan_name fields to entry."""
    vid = entry.get("vlan_id")
    if vid:
        m = vcache.get(str(vid))
        if m:
            entry["vlan_tag"] = m["vlan_tag"]
            entry["vlan_name"] = m["vlan_name"]
        else:
            entry["vlan_tag"] = None
            entry["vlan_name"] = None
    return entry


def _get_device_info_dict(device_id) -> Optional[dict]:
    """Fetch single device, return slim dict."""
    try:
        result = _api_request("GET", f"devices/{device_id}")
        devs = _extract_data(result, ['devices'])
        return _slim_device(devs[0]) if devs else None
    except Exception:
        return None


def _get_port_info_dict(port_id) -> Optional[dict]:
    """Fetch single port, return slim dict."""
    try:
        result = _api_request("GET", f"ports/{port_id}")
        ports = _extract_data(result, ['ports'])
        return _slim_port(ports[0]) if ports else None
    except Exception:
        return None


# ───────────────────────── MCP Tools (27) ─────────────────────────

@mcp.tool()
def librenms_api(method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> str:
    """Execute raw request to any LibreNMS REST API endpoint.
    [YES] Use for any API call not covered by other tools.
    [NO] Don't use if a specific tool exists for your task."""
    try:
        result = _api_request(method, endpoint, params, json_body, use_cache=False)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def health_check() -> str:
    """Check LibreNMS API connectivity, response time, and cache status.
    [YES] Use to verify API is working.
    [NO] Don't use for device-specific checks."""
    try:
        t0 = time.time()
        _api_request("GET", "devices", params={"limit": 1}, use_cache=False)
        ms = round((time.time() - t0) * 1000, 2)
        return _R({
            "status": "healthy",
            "api_response_ms": ms,
            "endpoint": config.BASE_URL,
            "cache": cache.stats(),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return _R({"status": "unhealthy", "error": str(e)})


@mcp.tool()
def get_device_info(device: str) -> str:
    """Get information for a single device.
    [YES] Use when user asks about a specific device by hostname, IP, or ID.
    [NO] Don't use to list multiple devices -> use list_devices().

    Args:
        device: Hostname, IP address, or numeric device ID."""
    try:
        d = _resolve_device(device)
        if not d:
            return _R({"error": f"Device not found: {device}"})
        return _R({"data": d})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def list_devices(limit: int = 0, status: Optional[str] = None,
                 os_filter: Optional[str] = None, location: Optional[str] = None,
                 search: Optional[str] = None) -> str:
    """List/search LibreNMS devices (default: ALL devices).
    [YES] "裝置清單", "show all devices", "list down devices", "find proxmox devices".
    [NO] "Show device 123 details" -> use get_device_info().
    [NO] "Show devices WITH ports" -> use get_devices_with_ports().

    Args:
        limit: Max devices returned (default 0=all).
        status: Filter: "up", "down", "disabled".
        os_filter: Filter by OS: "proxmox", "linux", "ios", etc.
        location: Filter by location string.
        search: Search hostname/sysName/IP (partial match)."""
    try:
        params = {}
        if status:
            params["status"] = {"up": "1", "down": "0", "disabled": "2"}.get(status.lower(), status)
        if location:
            params["location"] = location

        max_items = None if limit == 0 else limit
        devices = _paginate("devices", params, max_items=max_items)

        # Post-filter by OS
        if os_filter:
            os_lower = os_filter.lower()
            devices = [d for d in devices if isinstance(d, dict) and os_lower in d.get('os', '').lower()]

        # Post-filter by search
        if search:
            s = search.lower()
            devices = [d for d in devices if isinstance(d, dict) and (
                s in str(d.get('hostname', '')).lower() or
                s in str(d.get('sysName', '')).lower() or
                s in str(d.get('ip', '')).lower()
            )]

        slim = [_slim_device(d) for d in devices if isinstance(d, dict)]

        # Stats
        stats = {"up": 0, "down": 0, "disabled": 0, "unknown": 0}
        for d in slim:
            st = d.get("status", "unknown")
            stats[st] = stats.get(st, 0) + 1

        # Compact text table to save tokens for weak models
        header = "id|hostname|sysName|ip|os|hardware|type|location|status"
        rows = [header]
        for d in slim:
            rows.append("|".join([
                str(d.get("device_id", "")),
                d.get("hostname", "") or "",
                d.get("sysName", "") or "",
                d.get("ip", "") or "",
                d.get("os", "") or "",
                d.get("hardware", "") or "",
                d.get("type", "") or "",
                d.get("location", "") or "",
                d.get("status", ""),
            ]))
        table = "\n".join(rows)

        return f"COMPLETE device list: {len(slim)} devices (up:{stats['up']} down:{stats['down']} disabled:{stats['disabled']}). Display ALL rows.\n{table}"
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_device_ports(device: str, status_filter: Optional[str] = None) -> str:
    """Get ports/interfaces for a specific device.
    [YES] "Show ports for device X", "Which ports are up on switch01?".
    [NO] "Show ports for ALL proxmox devices" -> use get_devices_with_ports().

    Args:
        device: Hostname, IP, or device ID.
        status_filter: "up", "down", "admin_down", or None for all."""
    try:
        dev = _resolve_device(device)
        if not dev:
            return _R({"error": f"Device not found: {device}"})
        device_id = dev["device_id"]

        result = _api_request("GET", f"devices/{device_id}/ports")
        all_ports = _extract_data(result, ['ports'])

        quality = _evaluate_port_quality(all_ports, dev.get("os"))

        if status_filter and quality["has_ifOperStatus"]:
            sf = status_filter.lower()
            filtered = [p for p in all_ports if _normalize_port_status(p.get('ifOperStatus')) == sf.replace('admin_down', 'admindown')]
        else:
            filtered = all_ports

        slim = [_slim_port(p) for p in filtered]
        stats = {}
        for p in slim:
            s = _normalize_port_status(p.get('ifOperStatus'))
            stats[s] = stats.get(s, 0) + 1

        # Compact text output
        dev_info = f"Device: {dev.get('hostname')} (id:{device_id}, os:{dev.get('os')})"
        stat_str = ", ".join(f"{k}:{v}" for k, v in stats.items() if v > 0)
        header = "port_id|ifName|ifDescr|ifAlias|ifOperStatus|ifSpeed"
        rows = [f"{dev_info} | Ports: {len(slim)} ({stat_str})", header]
        for p in slim:
            rows.append("|".join([
                str(p.get("port_id", "")),
                p.get("ifName", "") or "",
                p.get("ifDescr", "") or "",
                p.get("ifAlias", "") or "",
                p.get("ifOperStatus", "") or "",
                str(p.get("ifSpeed", "") or ""),
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_devices_with_ports(os_filter: Optional[str] = None,
                           device_status: Optional[str] = None,
                           port_status: Optional[str] = None,
                           limit: int = 10) -> str:
    """Get devices AND their ports in one batch call.
    [YES] "Show proxmox devices with their ports", "Devices + ports in one query".
    [NO] "Show ports for one device" -> use get_device_ports().

    Args:
        os_filter: Filter by OS ("proxmox", "linux", "ios").
        device_status: Filter devices by "up" or "down".
        port_status: Filter ports by "up", "down", or None for all.
        limit: Max devices (default 10)."""
    try:
        params = {}
        if device_status:
            params["status"] = {"up": "1", "down": "0"}.get(device_status.lower(), device_status)

        devices = _extract_data(_api_request("GET", "devices", params={**params, "limit": limit * 2}), ['devices'])
        if os_filter:
            devices = [d for d in devices if os_filter.lower() in d.get('os', '').lower()]
        devices = devices[:limit]

        result_devices = []
        for d in devices:
            did = d.get('device_id')
            if not did:
                continue
            try:
                ports_result = _api_request("GET", f"devices/{did}/ports")
                ports = _extract_data(ports_result, ['ports'])
                quality = _evaluate_port_quality(ports, d.get('os'))

                if port_status and quality["has_ifOperStatus"]:
                    ps = port_status.lower()
                    ports = [p for p in ports if _normalize_port_status(p.get('ifOperStatus')) == ps]
                elif port_status and not quality["has_ifOperStatus"]:
                    ports = [p for p in ports if not p.get('disabled', 0)]

                result_devices.append({
                    "device_id": did,
                    "hostname": d.get("hostname"),
                    "sysName": d.get("sysName"),
                    "os": d.get("os"),
                    "status": _device_status_str(d.get("status")),
                    "ip": d.get("ip"),
                    "ports": [_slim_port(p) for p in ports],
                    "port_count": len(ports),
                    "data_quality": quality
                })
            except Exception as e:
                result_devices.append({"device_id": did, "hostname": d.get("hostname"), "error": str(e), "ports": []})

        # Compact text output
        lines = [f"Devices with ports: {len(result_devices)}"]
        for rd in result_devices:
            lines.append(f"--- {rd.get('hostname','')} (id:{rd.get('device_id','')}, os:{rd.get('os','')}, status:{rd.get('status','')}) ports:{rd.get('port_count',0)} ---")
            if rd.get("error"):
                lines.append(f"  ERROR: {rd['error']}")
                continue
            for p in rd.get("ports", []):
                lines.append(f"  {p.get('port_id','')}|{p.get('ifName','') or ''}|{p.get('ifDescr','') or ''}|{p.get('ifOperStatus','') or ''}|{p.get('ifSpeed','') or ''}")
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def search_ip_to_mac(ip_address: str) -> str:
    """Find MAC address for an IP address via ARP table.
    [YES] "What MAC is at IP 192.168.1.100?", "IP to MAC lookup".
    [NO] "Find IP for this MAC" -> use search_mac_to_ip().
    [NO] "Full IP investigation" -> use troubleshoot_ip().

    Args:
        ip_address: IP address to look up."""
    try:
        if not _validate_ip(ip_address):
            return _R({"error": f"Invalid IP: {ip_address}"})

        vcache = _build_vlan_cache()
        entries = []

        # Direct ARP lookup
        try:
            result = _api_request("GET", f"resources/ip/arp/{ip_address}")
            entries.extend(_extract_data(result, ['arp', 'ip_arp']))
        except Exception:
            pass

        # Device-specific fallback
        if not entries:
            try:
                devs = _extract_data(_api_request("GET", "devices", params={"limit": 5}), ['devices'])
                for d in devs:
                    did = d.get('device_id')
                    if not did:
                        continue
                    try:
                        arp = _extract_data(_api_request("GET", f"devices/{did}/arp"), ['arp', 'ip_arp'])
                        for e in arp:
                            if (e.get("ipv4_address") or e.get("ip_address")) == ip_address:
                                entries.append(e)
                                break
                        if entries:
                            break
                    except Exception:
                        pass
            except Exception:
                pass

        # Deduplicate
        seen = set()
        unique = []
        for e in entries:
            key = f"{e.get('mac_address', '')}_{e.get('device_id', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(e)

        # Enrich
        enriched = []
        for e in unique:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
                "port_id": e.get("port_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")

            # Add device/port context
            dev = _get_device_info_dict(e.get("device_id"))
            if dev:
                entry["device_hostname"] = dev.get("hostname")
                entry["device_sysName"] = dev.get("sysName")
            port = _get_port_info_dict(e.get("port_id"))
            if port:
                entry["port_name"] = port.get("ifName")

            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def search_mac_to_ip(mac_address: str) -> str:
    """Find IP addresses for a MAC address via ARP table.
    [YES] "What IP does this MAC have?", "MAC to IP lookup".
    [NO] "Find MAC for IP" -> use search_ip_to_mac().
    [NO] "Find switch port for MAC" -> use search_fdb_by_mac().

    Args:
        mac_address: MAC address (any format: aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, etc.)."""
    try:
        vcache = _build_vlan_cache()
        try:
            normalized = _normalize_mac(mac_address)
        except Exception:
            normalized = mac_address

        entries = []
        try:
            all_arp = _paginate("resources/ip/arp", max_items=5000)
            for e in all_arp:
                emac = e.get("mac_address", "")
                if (emac.lower() == mac_address.lower() or
                    emac.lower() == normalized.lower() or
                    mac_address.lower() in emac.lower()):
                    entries.append(e)
        except Exception:
            pass

        enriched = []
        for e in entries:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


def _tool_rows(payload: str) -> List[Dict]:
    """Normalise a tool's return value into a list of dicts.

    Tools in this module emit either JSON (via _R) or a pipe-delimited table with
    a header line, chosen per tool to save tokens. Anything calling a tool from
    inside this module must not assume which - that assumption is what broke
    troubleshoot_ip().
    """
    if not payload:
        return []
    text = payload.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            return []
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            for key in ("data", "results", "entries", "rows"):
                if isinstance(data.get(key), list):
                    return [d for d in data[key] if isinstance(d, dict)]
            return [] if "error" in data else [data]
        return []

    lines = [l for l in text.split("\n") if l.strip()]
    header_idx = next((i for i, l in enumerate(lines) if "|" in l), None)
    if header_idx is None:
        return []
    cols = lines[header_idx].split("|")
    rows = []
    for line in lines[header_idx + 1:]:
        if "|" not in line:
            continue
        vals = line.split("|")
        rows.append({c: (vals[i] if i < len(vals) else "") for i, c in enumerate(cols)})
    return rows


def _fdb_entries_for_mac(mac_address: str) -> List[Dict]:
    """FDB rows for a MAC, enriched with device and port names.

    Kept separate from search_fdb_by_mac() so that callers inside this module
    consume structured data. troubleshoot_ip() used to json.loads() the tool's
    return value, which broke silently the moment that tool switched to
    pipe-delimited text output.
    """
    vcache = _build_vlan_cache()
    try:
        normalized = _normalize_mac(mac_address)
    except Exception:
        normalized = mac_address

    fdb = []
    try:
        result = _api_request("GET", f"resources/fdb/{normalized}")
        fdb.extend(_extract_data(result, ['ports_fdb']))
    except Exception:
        pass

    if not fdb:
        try:
            all_fdb = _paginate("resources/fdb", max_items=5000)
            for e in all_fdb:
                emac = e.get("mac_address", "")
                if normalized in emac.lower() or mac_address.lower() in emac.lower():
                    fdb.append(e)
        except Exception:
            pass

    seen = set()
    unique = []
    for e in fdb:
        eid = e.get("ports_fdb_id") or str(e)
        if eid not in seen:
            seen.add(eid)
            unique.append(e)

    device_cache = {}
    port_cache = {}
    enriched = []

    for e in unique:
        entry = {
            "mac_address": _format_mac(e.get("mac_address", "")),
            "device_id": e.get("device_id"),
            "port_id": e.get("port_id"),
        }
        _enrich_vlan(e, vcache)
        entry["vlan_tag"] = e.get("vlan_tag")
        entry["vlan_name"] = e.get("vlan_name")

        did = e.get("device_id")
        if did:
            if did not in device_cache:
                device_cache[did] = _get_device_info_dict(did)
            dev = device_cache[did]
            if dev:
                entry["device_hostname"] = dev.get("hostname")
                entry["device_sysName"] = dev.get("sysName")
                entry["device_ip"] = dev.get("ip")
                entry["device_location"] = dev.get("location")

        pid = e.get("port_id")
        if pid:
            if pid not in port_cache:
                port_cache[pid] = _get_port_info_dict(pid)
            port = port_cache[pid]
            if port:
                entry["port_name"] = port.get("ifName")
                entry["port_descr"] = port.get("ifDescr")

        enriched.append(entry)

    return enriched


@mcp.tool()
def search_fdb_by_mac(mac_address: str) -> str:
    """Find which switch port a MAC address is on via FDB table.
    [YES] "Which switch is this MAC on?", "Find port for MAC aa:bb:cc:dd:ee:ff".
    [NO] "Find MAC for IP" -> use search_ip_to_mac().

    Args:
        mac_address: MAC address (any format)."""
    try:
        enriched = _fdb_entries_for_mac(mac_address)
        rows = [f"FDB search results: {len(enriched)}",
                "mac_address|device_id|device_hostname|device_sysName|port_id|port_name|vlan_tag|vlan_name"]
        for e in enriched:
            rows.append("|".join([
                e.get("mac_address", ""),
                str(e.get("device_id", "")),
                e.get("device_hostname", "") or "",
                e.get("device_sysName", "") or "",
                str(e.get("port_id", "")),
                e.get("port_name", "") or "",
                str(e.get("vlan_tag", "") or ""),
                e.get("vlan_name", "") or "",
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def troubleshoot_ip(ip_address: str) -> str:
    """One-stop IP investigation: ARP -> MAC -> FDB -> switch port.
    [YES] "Where is IP 192.168.1.100 connected?", "Trace IP to switch port".
    [NO] "Just find MAC for IP" -> use search_ip_to_mac().

    Args:
        ip_address: IP address to investigate."""
    try:
        result = {"ip_address": ip_address, "status": "investigating"}

        # Step 1: ARP -> MAC
        # search_ip_to_mac() currently returns JSON, but consume it defensively:
        # search_fdb_by_mac() used to return JSON too, and when it switched to
        # pipe-delimited text this function broke for every IP with no warning.
        arp_entries = _tool_rows(search_ip_to_mac(ip_address))

        if not arp_entries:
            result["status"] = "not_found"
            result["message"] = "IP not found in ARP table. Device may be offline or outside monitored network."
            return _R(result)

        arp = arp_entries[0]
        mac = arp.get("mac_address", "")
        result["mac_address"] = mac
        result["arp_device"] = arp.get("device_hostname")
        result["arp_device_sysName"] = arp.get("device_sysName")
        result["arp_vlan_tag"] = arp.get("vlan_tag")
        result["arp_vlan_name"] = arp.get("vlan_name")

        if not mac:
            result["status"] = "partial"
            result["message"] = "Found ARP entry but no MAC address."
            return _R(result)

        # Step 2: FDB -> switch port (structured helper, not the tool's text output)
        fdb_entries = _fdb_entries_for_mac(mac)

        if not fdb_entries:
            result["status"] = "partial"
            result["message"] = f"Found MAC {mac} but not in FDB table. Device may be on router not switch."
            return _R(result)

        fdb = fdb_entries[0]
        result["switch_hostname"] = fdb.get("device_hostname")
        result["switch_sysName"] = fdb.get("device_sysName")
        result["switch_ip"] = fdb.get("device_ip")
        result["switch_port"] = fdb.get("port_name")
        result["switch_port_descr"] = fdb.get("port_descr")
        result["fdb_vlan_tag"] = fdb.get("vlan_tag")
        result["fdb_vlan_name"] = fdb.get("vlan_name")

        # Step 3: Switch details
        did = fdb.get("device_id")
        if did:
            dev = _get_device_info_dict(did)
            if dev:
                result["switch_os"] = dev.get("os")
                # /devices returns location as a nested object on this LibreNMS;
                # emitting it raw buried the answer under a coordinate blob.
                loc = dev.get("location")
                result["switch_location"] = loc.get("location") if isinstance(loc, dict) else loc
                result["switch_status"] = dev.get("status")

        result["status"] = "success"
        result["summary"] = (
            f"IP {ip_address} -> MAC {mac} -> "
            f"{fdb.get('device_hostname', '?')} port {fdb.get('port_name', '?')} "
            f"(VLAN {fdb.get('vlan_tag', '?')})"
        )

        if len(fdb_entries) > 1:
            result["other_locations"] = [
                {"device": e.get("device_hostname"), "port": e.get("port_name")}
                for e in fdb_entries[1:5]
            ]

        return _R(result)
    except Exception as e:
        return _R({"error": str(e), "ip_address": ip_address})


@mcp.tool()
def list_fdb_entries(limit: int = 100, vlan_tag: Optional[int] = None,
                     device_id: Optional[int] = None, mac_filter: Optional[str] = None) -> str:
    """List FDB (forwarding database) entries.
    [YES] "Show FDB table", "List MAC addresses on VLAN 100".
    [NO] "Find specific MAC location" -> use search_fdb_by_mac().

    Args:
        limit: Max entries (default 100).
        vlan_tag: Filter by VLAN tag number (e.g., 100), NOT database ID.
        device_id: Filter by device ID.
        mac_filter: Filter by partial MAC address."""
    try:
        vcache = _build_vlan_cache()

        # Build reverse mapping: vlan_tag -> list of vlan_db_ids
        tag_to_dbids = {}
        for db_id, info in vcache.items():
            t = info.get("vlan_tag")
            if t is not None:
                tag_to_dbids.setdefault(str(t), []).append(db_id)

        params = {}
        if device_id is not None:
            params["device_id"] = device_id

        # If vlan_tag specified, find matching DB IDs
        target_dbids = None
        if vlan_tag is not None:
            target_dbids = set(tag_to_dbids.get(str(vlan_tag), []))

        entries = _paginate("resources/fdb", params, max_items=limit * 2 if vlan_tag else limit)

        # Filter by vlan_tag
        if target_dbids is not None:
            entries = [e for e in entries if str(e.get("vlan_id", "")) in target_dbids]

        # Filter by MAC
        if mac_filter:
            try:
                nf = _normalize_mac(mac_filter)
                entries = [e for e in entries if nf in e.get("mac_address", "")]
            except Exception:
                entries = [e for e in entries if mac_filter.lower() in e.get("mac_address", "").lower()]

        entries = entries[:limit]

        enriched = []
        for e in entries:
            entry = {
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
                "port_id": e.get("port_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        # Compact text output
        header = "mac_address|device_id|port_id|vlan_tag|vlan_name"
        rows = [f"FDB entries: {len(enriched)}", header]
        for e in enriched:
            rows.append("|".join([
                e.get("mac_address", ""),
                str(e.get("device_id", "")),
                str(e.get("port_id", "")),
                str(e.get("vlan_tag", "") or ""),
                e.get("vlan_name", "") or "",
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_network_arp_table(network_cidr: str, limit: int = 500) -> str:
    """Get ARP table entries for a network segment.
    [YES] "Show ARP table for 192.168.1.0/24".
    [NO] "Find MAC for single IP" -> use search_ip_to_mac().

    Args:
        network_cidr: Network in CIDR format (e.g., "192.168.1.0/24").
        limit: Max entries (default 500)."""
    try:
        if not _validate_cidr(network_cidr):
            return _R({"error": f"Invalid CIDR: {network_cidr}"})

        vcache = _build_vlan_cache()
        network = ipaddress.ip_network(network_cidr, strict=False)

        all_arp = _paginate("resources/ip/arp", max_items=limit * 2)
        filtered = []
        for e in all_arp:
            ip_str = e.get("ipv4_address") or e.get("ip_address")
            if ip_str:
                try:
                    if ipaddress.ip_address(ip_str) in network:
                        filtered.append(e)
                except ValueError:
                    continue
            if len(filtered) >= limit:
                break

        enriched = []
        for e in filtered:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        ip_count = len(set(e["ip_address"] for e in enriched if e.get("ip_address")))
        total_addr = network.num_addresses
        usable = max(total_addr - 2, 1) if network.prefixlen >= 24 else total_addr
        util_pct = round((ip_count / usable) * 100, 1)

        # Compact text output
        header = "ip_address|mac_address|device_id|vlan_tag|vlan_name"
        rows = [f"ARP table for {network_cidr}: {len(enriched)} entries, {ip_count} unique IPs, utilization {util_pct}%", header]
        for e in enriched:
            rows.append("|".join([
                e.get("ip_address", ""),
                e.get("mac_address", ""),
                str(e.get("device_id", "")),
                str(e.get("vlan_tag", "") or ""),
                e.get("vlan_name", "") or "",
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def list_all_services(state: Optional[str] = None, limit: int = 100,
                      service_type: Optional[str] = None) -> str:
    """List monitored services with filtering.
    [YES] "Show all services", "List critical services", "Which services are warning?".
    [NO] "Check specific device health" -> use diagnose_device().

    Args:
        state: Filter by state: "ok", "warning", "critical" (or "0", "1", "2").
        limit: Max services (default 100).
        service_type: Filter by type (e.g., "http", "ping")."""
    try:
        params = {}
        if state is not None:
            state_map = {"ok": "0", "warning": "1", "critical": "2", "0": "0", "1": "1", "2": "2"}
            params["state"] = state_map.get(state.lower(), state)
        if service_type:
            params["type"] = service_type

        services = _paginate("services", params, max_items=limit)

        stats = {"ok": 0, "warning": 0, "critical": 0, "unknown": 0}
        for svc in services:
            if not isinstance(svc, dict):
                continue
            s = str(svc.get("service_status", ""))
            if s == "0":
                stats["ok"] += 1
            elif s == "1":
                stats["warning"] += 1
            elif s == "2":
                stats["critical"] += 1
            else:
                stats["unknown"] += 1

        # Compact text output
        stat_str = ", ".join(f"{k}:{v}" for k, v in stats.items() if v > 0)
        rows = [f"Services: {len(services)} ({stat_str})",
                "service_id|device_id|service_type|service_desc|service_status|service_message"]
        for s in services:
            if not isinstance(s, dict):
                continue
            rows.append("|".join([
                str(s.get("service_id", "")),
                str(s.get("device_id", "")),
                s.get("service_type", "") or "",
                s.get("service_desc", "") or "",
                str(s.get("service_status", "")),
                (s.get("service_message", "") or "")[:80],
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_recent_alerts(limit: int = 10, severity: Optional[str] = None) -> str:
    """Get current ACTIVE alerts (firing right now).
    [YES] "現在有哪些告警?", "今天告警", "active alerts", "當前警報", "裝置狀況告警".
    [NO] "過去一週的告警歷史" -> use get_alert_history().

    Args:
        limit: Max alerts (default 10).
        severity: Filter by severity (e.g., "critical", "warning")."""
    try:
        params = {"limit": limit}
        if severity:
            params["severity"] = severity

        alerts = _extract_data(_api_request("GET", "alerts", params=params), ['alerts'])

        # Enrich with device info
        dev_cache = {}
        for alert in alerts:
            did = alert.get('device_id')
            if did and did not in dev_cache:
                dev_cache[did] = _get_device_info_dict(did)
            if did and dev_cache.get(did):
                d = dev_cache[did]
                alert['device_hostname'] = d.get('hostname')
                alert['device_sysName'] = d.get('sysName')
                alert['device_ip'] = d.get('ip')

        # Compact text output
        rows = [f"Active alerts: {len(alerts)}",
                "id|device_id|hostname|severity|rule|timestamp|state"]
        for a in alerts:
            rows.append("|".join([
                str(a.get("id", "")),
                str(a.get("device_id", "")),
                a.get("device_hostname", "") or a.get("hostname", "") or "",
                str(a.get("severity", "")),
                (a.get("rule", {}).get("name", "") if isinstance(a.get("rule"), dict) else str(a.get("rule", "")))[:60],
                _format_timestamp(a.get("timestamp", "") or a.get("datetime", "") or ""),
                str(a.get("state", "")),
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_alert_history(days: int = 30, limit: int = 100,
                      severity: Optional[str] = None) -> str:
    """Get historical alerts (including resolved) from multiple sources.
    [YES] "告警歷史", "今天的告警記錄", "過去7天告警", "alert history", "past alerts", "resolved alerts".
    [NO] "現在有哪些告警?" -> use get_recent_alerts().

    Args:
        days: Look back period (default 30).
        limit: Max alerts (default 100).
        severity: Filter by severity."""
    try:
        end = datetime.now()
        start = end - timedelta(days=days)
        all_alerts = []

        # Active alerts
        try:
            params = {"limit": min(limit, 500)}
            if severity:
                params["severity"] = severity
            active = _extract_data(_api_request("GET", "alerts", params=params), ['alerts'])
            for a in active:
                a["source"] = "active"
            all_alerts.extend(active)
        except Exception:
            pass

        # Alert log
        try:
            log = _extract_data(_api_request("GET", "alertlog", params={"limit": min(300, limit)}), ['alertlog'])
            for e in log:
                all_alerts.append({
                    "id": f"log_{e.get('id', '')}",
                    "timestamp": e.get("datetime") or e.get("time_logged"),
                    "device_id": e.get("device_id"),
                    "message": e.get("details", ""),
                    "severity": e.get("severity", "info"),
                    "rule": e.get("rule", ""),
                    "state": e.get("state", 0),
                    "source": "alertlog"
                })
        except Exception:
            pass

        # Filter by date
        filtered = []
        for a in all_alerts:
            ts = a.get("timestamp") or a.get("datetime")
            if ts:
                dt = _safe_parse_datetime(ts)
                if dt and not (start <= dt <= end):
                    continue
            if severity:
                a_sev = str(a.get("severity", "")).lower()
                if severity.lower() not in a_sev:
                    continue
            filtered.append(a)

        filtered = filtered[:limit]

        # Compact text output
        rows = [f"Alert history: {len(filtered)} entries (past {days} days)",
                "id|device_id|severity|rule|timestamp|state|source"]
        for a in filtered:
            rows.append("|".join([
                str(a.get("id", "")),
                str(a.get("device_id", "")),
                str(a.get("severity", "")),
                str(a.get("rule", ""))[:60],
                _format_timestamp(a.get("timestamp", "") or a.get("datetime", "") or ""),
                str(a.get("state", "")),
                a.get("source", ""),
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def diagnose_device(device: str) -> str:
    """Comprehensive device diagnostics with health score.
    [YES] "Diagnose device X", "Check health of switch01", "Why is device X down?".
    [NO] "Just show device info" -> use get_device_info().
    [NO] "Network overview" -> use network_health_overview().

    Args:
        device: Hostname, IP, or device ID."""
    try:
        dev = _resolve_device(device)
        if not dev:
            return _R({"error": f"Device not found: {device}"})

        device_id = dev["device_id"]
        diag = {
            "device": dev,
            "health_score": 0,
            "status": "analyzing"
        }

        # Port analysis
        port_score = 50
        try:
            ports_result = _api_request("GET", f"devices/{device_id}/ports")
            all_ports = _extract_data(ports_result, ['ports'])
            active_ports = [p for p in all_ports if not p.get('ignore') and not p.get('disabled')]
            quality = _evaluate_port_quality(active_ports, dev.get("os"))

            port_stats = {"up": 0, "down": 0, "unknown": 0}
            for p in active_ports:
                s = _normalize_port_status(p.get('ifOperStatus'))
                if s == 'up':
                    port_stats["up"] += 1
                elif s == 'down':
                    port_stats["down"] += 1
                else:
                    port_stats["unknown"] += 1

            diag["ports"] = {
                "total": len(all_ports),
                "active": len(active_ports),
                "status_breakdown": port_stats,
                "data_quality": quality
            }
            if active_ports:
                port_score = round((port_stats["up"] / len(active_ports)) * 100, 1)
        except Exception as e:
            diag["ports"] = {"error": str(e)}

        # Alert analysis
        alert_score = 100
        try:
            alerts = _extract_data(_api_request("GET", "alerts", params={"device_id": device_id}), ['alerts'])
            sev = {"critical": 0, "warning": 0, "info": 0}
            for a in alerts:
                s = str(a.get("severity", "")).lower()
                if "crit" in s or s == "5":
                    sev["critical"] += 1
                elif "warn" in s or s == "4":
                    sev["warning"] += 1
                else:
                    sev["info"] += 1

            diag["alerts"] = {"total": len(alerts), "severity": sev}
            alert_score = max(0, 100 - sev["critical"] * 30 - sev["warning"] * 10 - sev["info"] * 2)
        except Exception as e:
            diag["alerts"] = {"error": str(e)}

        # Health score: device_status 40%, ports 30%, alerts 30%
        dev_score = 100 if dev.get("status") == "up" else 0
        health = round(dev_score * 0.4 + port_score * 0.3 + alert_score * 0.3, 1)
        diag["health_score"] = health

        if health >= 90:
            diag["status"] = "excellent"
        elif health >= 75:
            diag["status"] = "good"
        elif health >= 50:
            diag["status"] = "fair"
        else:
            diag["status"] = "poor"

        # Recommendations
        recs = []
        if dev.get("status") != "up":
            recs.append(f"Device is {dev.get('status', 'unknown').upper()} - check connectivity and power")
        if diag.get("alerts", {}).get("severity", {}).get("critical", 0) > 0:
            recs.append(f"{diag['alerts']['severity']['critical']} critical alert(s) need attention")
        if diag.get("ports", {}).get("status_breakdown", {}).get("down", 0) > 0:
            recs.append(f"{diag['ports']['status_breakdown']['down']} port(s) are down")
        if not recs:
            recs.append("No issues detected")
        # Compact text output
        port_info = diag.get("ports", {})
        alert_info = diag.get("alerts", {})
        lines = [
            f"Diagnosis: {dev.get('hostname','')} (id:{device_id}, os:{dev.get('os','')}, status:{dev.get('status','')})",
            f"Health: {diag['status'].upper()} (score: {health})",
            f"Ports: {port_info.get('active','?')} active ({port_info.get('status_breakdown',{})})",
            f"Alerts: {alert_info.get('total','?')} ({alert_info.get('severity',{})})",
            f"Recommendations: {'; '.join(recs)}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def network_health_overview(location: Optional[str] = None, device_type: Optional[str] = None) -> str:
    """Network health dashboard with scores and problem devices.
    [YES] "How is the network?", "Network health overview", "Any problems?".
    [NO] "Show specific device" -> use get_device_info().
    [NO] "List all devices" -> use list_devices().

    Args:
        location: Filter by location.
        device_type: Filter by device type/OS."""
    try:
        report = {"health_score": 0, "status": "analyzing"}

        # Device stats (call API directly, not the tool which returns text)
        params = {}
        if location:
            params["location"] = location
        all_devs = _paginate("devices", params, max_items=None)
        if device_type:
            dt = device_type.lower()
            all_devs = [d for d in all_devs if isinstance(d, dict) and dt in d.get('os', '').lower()]
        devices = [_slim_device(d) for d in all_devs if isinstance(d, dict)]
        total = len(devices)

        stats = {"total": total, "up": 0, "down": 0, "disabled": 0}
        problems = []
        os_dist = {}

        for d in devices:
            s = d.get("status", "unknown")
            if s == "up":
                stats["up"] += 1
            elif s == "down":
                stats["down"] += 1
                problems.append({"device_id": d.get("device_id"), "hostname": d.get("hostname"),
                                 "sysName": d.get("sysName"), "ip": d.get("ip"),
                                 "reason": "Device DOWN", "severity": "critical"})
            elif s == "disabled":
                stats["disabled"] += 1
            os_name = d.get("os", "unknown")
            os_dist[os_name] = os_dist.get(os_name, 0) + 1

        report["device_stats"] = stats
        report["os_distribution"] = dict(sorted(os_dist.items(), key=lambda x: x[1], reverse=True)[:10])

        # Alert stats (call API directly)
        alerts = _extract_data(_api_request("GET", "alerts", params={"limit": 100}), ['alerts'])
        alert_stats = {"total": len(alerts), "critical": 0, "warning": 0}

        for a in alerts:
            sev = str(a.get("severity", "")).lower()
            if "crit" in sev or sev == "5":
                alert_stats["critical"] += 1
            elif "warn" in sev or sev == "4":
                alert_stats["warning"] += 1

        report["alert_stats"] = alert_stats

        # Health score
        dev_health = (stats["up"] / max(total, 1)) * 60
        alert_penalty = (alert_stats["critical"] * 5 + alert_stats["warning"] * 2) / max(total, 1)
        alert_health = max(0, 40 - alert_penalty)
        score = round(dev_health + alert_health, 1)

        report["health_score"] = score
        report["status"] = "excellent" if score >= 90 else "good" if score >= 75 else "fair" if score >= 50 else "poor"
        report["problem_devices"] = problems[:10]
        report["problem_count"] = len(problems)

        # Recommendations
        recs = []
        if stats["down"] > 0:
            recs.append(f"{stats['down']} device(s) DOWN - investigate immediately")
        if alert_stats["critical"] > 0:
            recs.append(f"{alert_stats['critical']} critical alert(s) need attention")
        if total > 0:
            recs.append(f"Network uptime: {round(stats['up']/total*100, 1)}% ({stats['up']}/{total})")

        # Compact text output
        lines = [
            f"Network Health: {report['status'].upper()} (score: {report['health_score']})",
            f"Devices: {stats['up']} up, {stats['down']} down, {stats['disabled']} disabled (total {total})",
            f"Alerts: {alert_stats['total']} active ({alert_stats['critical']} critical, {alert_stats['warning']} warning)",
            f"OS distribution: {', '.join(f'{k}:{v}' for k,v in report['os_distribution'].items())}",
        ]
        if recs:
            lines.append("Recommendations: " + "; ".join(recs))
        if problems:
            lines.append("Problem devices:")
            lines.append("id|hostname|sysName|ip|reason")
            for p in problems[:10]:
                lines.append(f"{p.get('device_id','')}|{p.get('hostname','')}|{p.get('sysName','')}|{p.get('ip','')}|{p.get('reason','')}")

        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


def _get_base_url() -> str:
    """Extract base domain URL from API URL (strip /api/v0)."""
    url = config.BASE_URL
    for suffix in ['/api/v0/', '/api/v0']:
        if url.endswith(suffix):
            return url[:-len(suffix)]
    return url


def _try_custom_top_devices(metric_type: str, limit: int) -> Optional[List[Dict]]:
    """Try calling custom_top_devices.php helper on LibreNMS server.
    Returns list of ranked device dicts, or None if helper not deployed."""
    base = _get_base_url()
    url = f"{base}/custom_top_devices.php"
    try:
        resp = session.request("GET", url,
                               params={"type": metric_type, "limit": limit},
                               timeout=config.TIMEOUT)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("status") == "ok" and isinstance(result.get("data"), list):
                return result["data"]
    except Exception:
        pass
    return None


def _build_health_ranking(metric_type: str, usage_field: str,
                          pct_key: str, count_key: str, limit: int) -> str:
    """Build device ranking by processor or mempool usage.
    Strategy 1: custom_top_devices.php helper (single SQL query, fast).
    Strategy 2: Per-device API calls (fallback, slow)."""
    try:
        # ── Strategy 1: Custom helper endpoint (recommended) ──
        custom_data = _try_custom_top_devices(metric_type, limit)
        if custom_data:
            data = custom_data[:limit]
            # Compact text output
            if data:
                keys = list(data[0].keys())
                rows = [f"Top {metric_type}: {len(data)} devices", "|".join(keys)]
                for d in data:
                    rows.append("|".join(str(d.get(k, "")) for k in keys))
                return "\n".join(rows)
            return f"Top {metric_type}: 0 devices"

        # ── Strategy 2: Per-device API calls (fallback) ──
        devices = _paginate("devices", max_items=500)
        rankings = []
        up_count = 0
        api_ok = 0

        for d in devices:
            if not isinstance(d, dict):
                continue
            did = d.get("device_id")
            if not did or _device_status_str(d.get("status")) != "up":
                continue
            up_count += 1

            # Try multiple endpoint patterns
            items = []
            for ep in [f"devices/{did}/{metric_type}s",
                       f"devices/{did}/health/device_{metric_type}",
                       f"devices/{did}/health/{metric_type}"]:
                try:
                    result = _api_request("GET", ep, use_cache=True)
                    items = _extract_data(result)
                    if items:
                        break
                except Exception:
                    continue
            if not items:
                continue

            usages = []
            for item in items:
                val = item.get(usage_field) or item.get("sensor_current")
                if val is not None:
                    try:
                        usages.append(float(val))
                    except (ValueError, TypeError):
                        pass
            if not usages:
                continue

            api_ok += 1
            avg = round(sum(usages) / len(usages), 1)
            rankings.append({
                "device_id": did,
                "hostname": d.get("hostname"),
                "sysName": d.get("sysName"),
                "ip": d.get("ip"),
                pct_key: avg,
                count_key: len(usages)
            })

        rankings.sort(key=lambda x: x[pct_key], reverse=True)
        top = rankings[:limit]

        if not rankings and up_count > 0:
            return (
                f"No {metric_type} data via API ({up_count} up devices checked). "
                f"Deploy custom_top_devices.php to LibreNMS server: "
                f"cp custom_top_devices.php /opt/librenms/html/ && "
                f"chown librenms:librenms /opt/librenms/html/custom_top_devices.php"
            )
        # Compact text output
        rows = [f"Top {metric_type} (API fallback): {len(top)} devices",
                f"id|hostname|sysName|ip|{pct_key}|{count_key}"]
        for r in top:
            rows.append("|".join([
                str(r.get("device_id", "")),
                r.get("hostname", "") or "",
                r.get("sysName", "") or "",
                r.get("ip", "") or "",
                str(r.get(pct_key, "")),
                str(r.get(count_key, "")),
            ]))
        return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_top_cpu(limit: int = 10) -> str:
    """Get devices ranked by CPU usage (highest first).
    [YES] "CPU排行", "CPU usage top 10", "哪些設備CPU最高?", "cpu使用率排行榜".
    [NO] "Memory排行" -> use get_top_memory().

    Args:
        limit: Top N devices (default 10)."""
    return _build_health_ranking("processor", "processor_usage",
                                 "cpu_usage_pct", "processor_count", limit)


@mcp.tool()
def get_top_memory(limit: int = 10) -> str:
    """Get devices ranked by memory usage (highest first).
    [YES] "Memory排行", "memory usage top 10", "記憶體使用率排行", "哪些設備記憶體最高?".
    [NO] "CPU排行" -> use get_top_cpu().

    Args:
        limit: Top N devices (default 10)."""
    return _build_health_ranking("mempool", "mempool_perc",
                                 "memory_usage_pct", "mempool_count", limit)


@mcp.tool()
def get_device_sla(device: Optional[str] = None, days: int = 30, limit: int = 10) -> str:
    """Get device availability SLA (uptime percentage and outage history).
    [YES] "SLA可用性", "device uptime SLA", "設備可用率", "outage history", "哪些設備可用率最低?".
    [NO] "Cisco IP SLA probes" -> use get_cisco_sla().

    Args:
        device: Hostname, IP, or device ID. None = worst-SLA devices across network.
        days: Look-back period for outages (default 30).
        limit: Max devices when device=None (default 10)."""
    try:
        if device:
            # Single device mode
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            device_id = dev["device_id"]

            # Get availability (pre-computed 1d/7d/30d/365d SLA%)
            avail = []
            try:
                result = _api_request("GET", f"devices/{device_id}/availability")
                avail = _extract_data(result, ['availability'])
            except Exception:
                pass

            # Get outages
            outages = []
            try:
                result = _api_request("GET", f"devices/{device_id}/outages")
                outages = _extract_data(result, ['outages'])
            except Exception:
                pass

            # Filter outages by days
            if days and outages:
                cutoff = datetime.now() - timedelta(days=days)
                filtered = []
                for o in outages:
                    ts = _safe_parse_datetime(o.get("going_down"))
                    if ts and ts >= cutoff:
                        filtered.append(o)
                outages = filtered

            # Compact text output for single device
            lines = [
                f"SLA for {dev.get('hostname','')} (id:{device_id}, status:{dev.get('status','')})",
                f"Outages in past {days} days: {len(outages)}",
            ]
            if avail:
                lines.append("Availability:")
                for a in avail:
                    dur = a.get("duration", 0)
                    try:
                        dur_days = int(dur) // 86400
                    except (ValueError, TypeError):
                        dur_days = "?"
                    lines.append(f"  {dur_days}d: {a.get('availability_perc', '?')}%")
            if outages:
                lines.append("Recent outages:")
                for o in outages[:10]:
                    lines.append(f"  {o.get('going_down','')} -> {o.get('up_again','still down')}")
            return "\n".join(lines)
        else:
            # All devices mode: collect availability, sort worst-first.
            # One API call per device, so the fetch is fanned out - serially this
            # is ~12s for 82 devices and over a minute at the 500-device cap.
            devices = [d for d in _paginate("devices", max_items=500)
                       if isinstance(d, dict) and d.get("device_id")]

            def _fetch_avail(d):
                result = _api_request("GET", f"devices/{d['device_id']}/availability")
                return _extract_data(result, ['availability'])

            avail_all = _parallel_map(_fetch_avail, devices)
            rankings = []

            for d, avail in zip(devices, avail_all):
                did = d.get("device_id")
                if not avail:
                    continue

                # Find the availability entry closest to requested days
                best = None
                for a in avail:
                    dur = a.get("duration")
                    if dur:
                        try:
                            dur_days = int(dur) // 86400
                        except (ValueError, TypeError):
                            continue
                        if best is None or abs(dur_days - days) < abs(best.get("_dur_days", 0) - days):
                            best = dict(a)
                            best["_dur_days"] = dur_days

                if best:
                    best.pop("_dur_days", None)
                    pct = best.get("availability_perc")
                    if pct is not None:
                        try:
                            pct = float(pct)
                        except (ValueError, TypeError):
                            pct = 100.0
                    else:
                        pct = 100.0
                    rankings.append({
                        "device_id": did,
                        "hostname": d.get("hostname"),
                        "sysName": d.get("sysName"),
                        "ip": d.get("ip"),
                        "status": _device_status_str(d.get("status")),
                        "availability_pct": pct,
                        "duration": best.get("duration"),
                    })

            # Sort worst-first (lowest availability)
            rankings.sort(key=lambda x: x["availability_pct"])
            top = rankings[:limit]
            # Compact text output
            rows = [f"Device SLA ranking (worst first, {days}d): {len(top)} devices",
                    "id|hostname|sysName|ip|status|availability_pct"]
            for r in top:
                rows.append("|".join([
                    str(r.get("device_id", "")),
                    r.get("hostname", "") or "",
                    r.get("sysName", "") or "",
                    r.get("ip", "") or "",
                    r.get("status", ""),
                    str(r.get("availability_pct", "")),
                ]))
            return "\n".join(rows)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_cisco_sla(device: Optional[str] = None, limit: int = 50) -> str:
    """Get Cisco IP SLA probe results (RTT, jitter, status).
    [YES] "Cisco SLA", "IP SLA探測", "SLA probe status", "RTT監控", "SLA探針結果".
    [NO] "Device uptime/availability SLA" -> use get_device_sla().

    Requires custom_top_devices.php deployed on LibreNMS server.

    Args:
        device: Hostname, IP, or device ID. None = all devices.
        limit: Max entries (default 50)."""
    try:
        _OPSTATUS = {0: "ok", 1: "unknown", 2: "down", 4: "over-threshold", 5: "timeout"}

        # Resolve device_id if specified
        device_id = None
        dev_info = None
        if device:
            dev_info = _resolve_device(device)
            if not dev_info:
                return _R({"error": f"Device not found: {device}"})
            device_id = dev_info["device_id"]

        # Call custom helper
        base = _get_base_url()
        url = f"{base}/custom_top_devices.php"
        params = {"type": "cisco_sla", "limit": limit}
        if device_id:
            params["device_id"] = device_id

        try:
            resp = session.request("GET", url, params=params, timeout=config.TIMEOUT)
            if resp.status_code != 200:
                return _R({"error": f"Helper returned HTTP {resp.status_code}. "
                           "Deploy custom_top_devices.php with cisco_sla support."})
            result = resp.json()
            if result.get("status") != "ok":
                return _R({"error": result.get("message", "Unknown error from helper")})
            data = result.get("data", [])
        except requests.exceptions.ConnectionError:
            return _R({"error": "Cannot reach custom_top_devices.php. "
                       "Deploy it to /opt/librenms/html/ on the LibreNMS server."})

        # Enrich with human-readable opstatus
        for entry in data:
            ops = entry.get("opstatus")
            if ops is not None:
                try:
                    entry["opstatus_str"] = _OPSTATUS.get(int(ops), f"unknown({ops})")
                except (ValueError, TypeError):
                    entry["opstatus_str"] = str(ops)

        # Compact text output
        if data:
            keys = list(data[0].keys())
            rows = [f"Cisco SLA: {len(data)} entries", "|".join(keys)]
            for d in data:
                rows.append("|".join(str(d.get(k, "")) for k in keys))
            return "\n".join(rows)
        return "Cisco SLA: 0 entries"
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────── Optical / DDM Helpers (v4.3.0) ─────────────────────

# Fallback light-level thresholds (dBm), used only when a device exposes no
# sensor_limit_low. MikroTik RouterOS reports NULL for every optical limit, so
# without these the margin check silently does nothing. Rows resolved this way
# are marked src="fb" so a fallback verdict is never read as vendor data.
_OPT_FALLBACK_LIMITS = {
    "rx": (-20.0, -18.0),   # (low_alarm, low_warn)
    "tx": (-9.0, -8.0),
}

_OPT_MARGIN_WARN = 2.0     # dB above low alarm -> warning
_OPT_MARGIN_WATCH = 3.0    # dB above low alarm -> watch
_PEER_MIN = 4              # min peers in a group before outlier stats mean anything
_PEER_MAD_K = 3.0          # flag readings more than K*MAD from the group median
_SEVERITY_ORDER = {"critical": 0, "warning": 1, "watch": 2,
                   "ok": 3, "no_data": 4, "stale": 5}
_OPT_SEVERITY_ORDER = _SEVERITY_ORDER  # kept for readability at optical call sites

# Measurement words stripped from sensor_descr to leave a bare port identifier,
# so the dbm / bias-current / temperature sensors of one transceiver can be paired.
_OPT_NOISE_RE = re.compile(
    r'\b(tx|rx|transmit|receive|optical|power|bias|current|laser|'
    r'temperature|temp|voltage|volt|level|signal|dom|ddm)\b', re.I)


def _optical_port_key(descr: str) -> str:
    """Reduce a sensor description to a port identifier for pairing.
    'sfp-sfpplus1 Tx' -> 'sfp-sfpplus1'; 'Gi1/0/1 Transmit Power' -> 'gi1/0/1'.
    Returns '' when nothing port-like remains, which is what keeps unrelated
    sensors (a UPS 'Current', an ambient 'Temperature') out of the pairing."""
    s = _OPT_NOISE_RE.sub(' ', descr or '')
    s = re.sub(r'\s+', ' ', s).strip(' _:,-')
    return s.lower()


def _optical_direction(descr: str) -> Optional[str]:
    """Infer tx/rx from a sensor description."""
    d = (descr or "").lower()
    if re.search(r'\b(tx|transmit|output|out)\b', d):
        return "tx"
    if re.search(r'\b(rx|receive|input|in)\b', d):
        return "rx"
    return None


def _to_float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _parallel_map(fn, items: List, workers: int = 8) -> List:
    """Run fn over items concurrently, preserving order.

    Whole-network tools that must call a per-device endpoint are otherwise
    serialised on network latency: 82 devices at ~140ms each is ~12s, and the
    500-device cap those tools use would be well past most client timeouts.
    Failures resolve to None rather than aborting the batch."""
    if not items:
        return []
    if len(items) == 1:
        try:
            return [fn(items[0])]
        except Exception:
            return [None]

    from concurrent.futures import ThreadPoolExecutor
    results = [None] * len(items)

    def _run(idx_item):
        idx, item = idx_item
        try:
            return idx, fn(item)
        except Exception:
            return idx, None

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        for idx, val in pool.map(_run, enumerate(items)):
            results[idx] = val
    return results


def _median(vals: List[float]) -> float:
    s = sorted(vals)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def _mad(vals: List[float], med: float) -> float:
    """Median absolute deviation - a spread measure that is not dragged around
    by the very outliers being looked for (mean/stddev would be)."""
    return _median([abs(v - med) for v in vals])


def _build_optical_records(sensors: List[Dict]) -> List[Dict]:
    """Pair each dbm sensor with the bias-current / temperature / voltage sensors
    of the same transceiver, flattened to one record per port+direction."""
    dbm_sensors = []
    extra = {}
    for s in sensors:
        if not isinstance(s, dict) or s.get("sensor_deleted"):
            continue
        cls = str(s.get("sensor_class") or "").lower()
        key = _optical_port_key(s.get("sensor_descr"))
        if not key:
            continue
        if cls == "dbm":
            dbm_sensors.append((key, s))
        elif cls in ("current", "temperature", "voltage"):
            extra.setdefault((s.get("device_id"), key, cls), s)

    now = datetime.now()
    records = []
    for key, s in dbm_sensors:
        did = s.get("device_id")
        direction = _optical_direction(s.get("sensor_descr")) or "?"

        low = _to_float(s.get("sensor_limit_low"))
        low_warn = _to_float(s.get("sensor_limit_low_warn"))
        src = "dev"
        if low is None:
            fb = _OPT_FALLBACK_LIMITS.get(direction)
            if fb:
                low = fb[0]
                low_warn = fb[1] if low_warn is None else low_warn
                src = "fb"
            else:
                src = "none"

        bias_s = extra.get((did, key, "current"))
        temp_s = extra.get((did, key, "temperature"))
        last = _safe_parse_datetime(s.get("lastupdate"))

        records.append({
            "device_id": did,
            "port": key,
            "dir": direction,
            "dbm": _to_float(s.get("sensor_current")),
            "low": low,
            "low_warn": low_warn,
            "src": src,
            "margin": None,
            "bias": _to_float(bias_s.get("sensor_current")) if bias_s else None,
            "temp": _to_float(temp_s.get("sensor_current")) if temp_s else None,
            "age_d": (now - last).days if last else None,
            "lastupdate": s.get("lastupdate"),
        })
    return records


def _peer_outliers(records: List[Dict], group_fn, value_key: str = "value",
                   two_sided: bool = False) -> Dict[int, Dict]:
    """Flag records sitting far from their peer group's median (median/MAD).

    Without stored history a reading cannot be compared against its own past, so
    it is compared against the population it should match right now: 40 identical
    SFPs at -5 dBm and one at -9 dBm makes that one suspect.

    two_sided=False flags only low readings (light levels only degrade downward).
    True also flags high ones, which is what temperature and voltage need."""
    groups = {}
    for r in records:
        if r.get(value_key) is None:
            continue
        groups.setdefault(group_fn(r), []).append(r)

    flags = {}
    for rs in groups.values():
        vals = [r[value_key] for r in rs]
        if len(vals) < _PEER_MIN:
            continue
        med = _median(vals)
        spread = _mad(vals, med)
        if spread < 0.05:          # readings effectively identical, no signal
            continue
        lo = med - _PEER_MAD_K * spread
        hi = med + _PEER_MAD_K * spread
        for r in rs:
            v = r[value_key]
            if v < lo or (two_sided and v > hi):
                flags[id(r)] = {"median": round(med, 2), "n": len(vals),
                                "side": "low" if v < lo else "high"}
    return flags


def _optical_peer_flags(records: List[Dict]) -> Dict[int, Dict]:
    """Same-device, same-direction peer comparison for transceivers."""
    return _peer_outliers(records, lambda r: (r["device_id"], r["dir"]),
                          value_key="dbm", two_sided=False)


def _classify_optical(rec: Dict, peer: Optional[Dict], stale_days: int) -> tuple:
    """Return (severity, reason) for one optical record."""
    age = rec.get("age_d")
    if age is not None and age > stale_days:
        return "stale", f"not polled for {age}d (last {rec.get('lastupdate')})"

    v = rec.get("dbm")
    if v is None:
        return "no_data", "no reading"
    # 0 dBm is 1 mW - a live laser cannot emit that with 0 mA of bias current,
    # so the pair reads as "module absent / not reporting", not as a real level.
    if v == 0 and rec.get("bias") == 0:
        return "no_data", "0 dBm with 0 mA bias - module absent or not reporting"

    low, low_warn = rec.get("low"), rec.get("low_warn")
    if low is None:
        return "ok", "no threshold available"

    margin = round(v - low, 2)
    rec["margin"] = margin

    if v <= low:
        return "critical", f"{v} dBm at/below low alarm {low}"
    if low_warn is not None and v <= low_warn:
        return "warning", f"{v} dBm at/below low warn {low_warn}"
    if margin < _OPT_MARGIN_WARN:
        return "warning", f"only {margin} dB margin above {low}"
    if peer:
        return "watch", (f"{v} dBm vs peer median {peer['median']} "
                         f"of {peer['n']} modules on same device")
    if margin < _OPT_MARGIN_WATCH:
        return "watch", f"{margin} dB margin above {low}"
    return "ok", ""


@mcp.tool()
def get_optical_health(device: Optional[str] = None, limit: int = 20,
                       severity: Optional[str] = None,
                       location: Optional[str] = None,
                       stale_days: int = 7) -> str:
    """Get optical transceiver (SFP/GBIC/DDM) health and replacement risk ranking.
    [YES] "光模組健康", "GBIC dBm", "光衰檢查", "SFP光功率", "哪些光模組該換?",
          "optical power margin", "transceiver health".
    [NO] "port traffic or up/down status" -> use get_device_ports().

    Point-in-time snapshot, nothing is stored. Risk is ranked by margin above the
    low-light alarm threshold and by deviation from same-device peers - NOT by
    decay rate, which would require history this server does not keep.

    Args:
        device: Hostname, IP, or device ID. None = whole network.
        limit: Max detail rows (default 20, hard cap 100).
        severity: Filter to one of critical/warning/watch/ok/stale/no_data.
        location: Filter devices by location substring (whole-network mode).
        stale_days: Readings older than this are flagged stale (default 7)."""
    try:
        limit = max(1, min(100, limit))

        # Resolve scope first so a single-device query never scans the network.
        target_id = None
        if device:
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            target_id = dev["device_id"]

        # One network-wide call returns every sensor on every device; filtering
        # happens here so the raw sensor list never reaches the caller.
        try:
            sensors = _extract_data(_api_request("GET", "resources/sensors"), ['sensors'])
        except Exception as e:
            return _R({"error": f"Cannot read resources/sensors: {e}"})

        if target_id is not None:
            sensors = [s for s in sensors
                       if isinstance(s, dict) and str(s.get("device_id")) == str(target_id)]

        records = _build_optical_records(sensors)

        # Device list is only needed for hostname/location columns, and it is the
        # slowest call in this tool - so it is fetched after the cheap exits.
        dev_map = {}
        if records:
            if target_id is not None:
                dev_map = {str(target_id): dev}
            else:
                for d in _paginate("devices", max_items=1000):
                    if isinstance(d, dict) and d.get("device_id") is not None:
                        dev_map[str(d["device_id"])] = d

        if location:
            loc = location.lower()
            records = [r for r in records
                       if loc in str(dev_map.get(str(r["device_id"]), {})
                                     .get("location", "")).lower()]

        if not records:
            scope = f"device {device}" if device else (f"location '{location}'" if location else "network")
            return (f"No optical (dbm) sensors found for {scope}.\n"
                    "Check that devices carrying SFP/GBIC modules are monitored and that "
                    "their transceivers expose DDM/DOM; sensors also need the LibreNMS "
                    "'sensors' discovery module enabled.")

        peer_flags = _optical_peer_flags(records)
        counts = {k: 0 for k in _OPT_SEVERITY_ORDER}
        for r in records:
            sev, why = _classify_optical(r, peer_flags.get(id(r)), stale_days)
            r["sev"], r["why"] = sev, why
            counts[sev] += 1

        shown = [r for r in records if r["sev"] == severity] if severity else list(records)
        if severity and not shown:
            return (f"Optical health: 0 modules with severity '{severity}' "
                    f"(of {len(records)} total). Counts: " +
                    " ".join(f"{k}:{counts[k]}" for k in _OPT_SEVERITY_ORDER))

        # Worst first; within a severity the thinnest margin leads.
        shown.sort(key=lambda r: (_OPT_SEVERITY_ORDER.get(r["sev"], 9),
                                  r["margin"] if r["margin"] is not None else 999))
        total_shown = len(shown)
        shown = shown[:limit]

        devices_n = len({r["device_id"] for r in records})
        lines = [f"Optical health: {len(records)} modules on {devices_n} devices | " +
                 " ".join(f"{k}:{counts[k]}" for k in _OPT_SEVERITY_ORDER)]

        if counts["stale"]:
            lines.append(f"WARN: {counts['stale']} reading(s) older than {stale_days}d - not trustworthy")
        if any(r["src"] == "fb" for r in shown):
            lines.append("NOTE: src=fb rows use built-in fallback thresholds (device reported none)")
        if total_shown > limit:
            lines.append(f"NOTE: showing worst {limit} of {total_shown} - raise limit or filter by device/severity")

        lines.append("id|hostname|port|dir|dBm|margin|low|src|bias_mA|temp_C|sev|reason")
        for r in shown:
            d = dev_map.get(str(r["device_id"]), {})
            lines.append("|".join([
                str(r["device_id"]),
                str(d.get("hostname", "") or ""),
                r["port"],
                r["dir"],
                "" if r["dbm"] is None else str(r["dbm"]),
                "" if r["margin"] is None else str(r["margin"]),
                "" if r["low"] is None else str(r["low"]),
                r["src"],
                "" if r["bias"] is None else str(r["bias"]),
                "" if r["temp"] is None else str(r["temp"]),
                r["sev"],
                r["why"],
            ]))
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────── Generic Sensor / Environmental Helpers ─────────────────

def _build_sensor_records(sensors: List[Dict], classes: Optional[set] = None) -> List[Dict]:
    """Flatten sensors into scoring records. Generic counterpart to
    _build_optical_records: no transceiver pairing, no fallback thresholds
    (a sane default exists for light levels, not for 'count' or 'state')."""
    now = datetime.now()
    out = []
    for s in sensors:
        if not isinstance(s, dict) or s.get("sensor_deleted"):
            continue
        cls = str(s.get("sensor_class") or "").lower()
        # `is not None` not truthiness: an empty set means "nothing qualifies",
        # which is what a device holding only dbm sensors reduces to.
        if classes is not None and cls not in classes:
            continue
        last = _safe_parse_datetime(s.get("lastupdate"))
        out.append({
            "device_id": s.get("device_id"),
            "cls": cls,
            "descr": str(s.get("sensor_descr") or "")[:40],
            "value": _to_float(s.get("sensor_current")),
            "hi": _to_float(s.get("sensor_limit")),
            "hi_warn": _to_float(s.get("sensor_limit_warn")),
            "lo": _to_float(s.get("sensor_limit_low")),
            "lo_warn": _to_float(s.get("sensor_limit_low_warn")),
            "age_d": (now - last).days if last else None,
            "lastupdate": s.get("lastupdate"),
        })
    return out


def _classify_sensor(rec: Dict, peer: Optional[Dict], stale_days: int) -> tuple:
    """Return (severity, reason) for a non-optical sensor reading."""
    age = rec.get("age_d")
    if age is not None and age > stale_days:
        return "stale", f"not polled for {age}d (last {rec.get('lastupdate')})"

    v = rec.get("value")
    if v is None:
        return "no_data", "no reading"

    hi, hi_w = rec.get("hi"), rec.get("hi_warn")
    lo, lo_w = rec.get("lo"), rec.get("lo_warn")

    if hi is not None and v >= hi:
        return "critical", f"{v} at/above high alarm {hi}"
    if lo is not None and v <= lo:
        return "critical", f"{v} at/below low alarm {lo}"
    if hi_w is not None and v >= hi_w:
        return "warning", f"{v} at/above high warn {hi_w}"
    if lo_w is not None and v <= lo_w:
        return "warning", f"{v} at/below low warn {lo_w}"
    if peer:
        return "watch", (f"{v} vs peer median {peer['median']} of "
                         f"{peer['n']} same-class sensors ({peer['side']} outlier)")
    if hi is None and lo is None:
        return "ok", "no threshold"
    return "ok", ""


def _severity_summary(counts: Dict[str, int]) -> str:
    return " ".join(f"{k}:{counts[k]}" for k in _SEVERITY_ORDER)


@mcp.tool()
def get_sensor_health(sensor_class: Optional[str] = None, device: Optional[str] = None,
                      limit: int = 20, severity: Optional[str] = None,
                      stale_days: int = 7) -> str:
    """Get hardware/environmental sensor health: temperature, voltage, fan, power.
    [YES] "溫度過高", "感測器健康", "風扇轉速", "電壓異常", "硬體健康檢查",
          "sensor health", "which devices are overheating?", "UPS battery".
    [NO] "SFP/GBIC light levels" -> use get_optical_health().
    [NO] "CPU or memory usage" -> use get_top_cpu() / get_top_memory().

    Ranked by threshold breach first, then by deviation from same-class peers on
    the same device. Point-in-time only; no history is stored.

    Args:
        sensor_class: temperature/voltage/fanspeed/power/current/state/charge/
                      load/runtime/frequency/count. None = all except dbm.
        device: Hostname, IP, or device ID. None = whole network.
        limit: Max detail rows (default 20, hard cap 100).
        severity: Filter to critical/warning/watch/ok/stale/no_data.
        stale_days: Readings older than this are flagged stale (default 7)."""
    try:
        limit = max(1, min(100, limit))

        target_id = None
        dev = None
        if device:
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            target_id = dev["device_id"]

        try:
            sensors = _extract_data(_api_request("GET", "resources/sensors"), ['sensors'])
        except Exception as e:
            return _R({"error": f"Cannot read resources/sensors: {e}"})

        if target_id is not None:
            sensors = [s for s in sensors
                       if isinstance(s, dict) and str(s.get("device_id")) == str(target_id)]

        if sensor_class:
            classes = {sensor_class.strip().lower()}
        else:
            # dbm has its own tool with transceiver-specific logic
            classes = {str(s.get("sensor_class") or "").lower() for s in sensors
                       if isinstance(s, dict)} - {"dbm"}

        records = _build_sensor_records(sensors, classes)
        if not records:
            avail = sorted({str(s.get("sensor_class") or "").lower()
                            for s in sensors if isinstance(s, dict)} - {""})
            return (f"No sensors matched (class={sensor_class or 'all'}"
                    f"{', device=' + device if device else ''}).\n"
                    f"Classes present: {', '.join(avail) if avail else 'none'}")

        dev_map = {}
        if target_id is not None:
            dev_map = {str(target_id): dev}
        else:
            for d in _paginate("devices", max_items=1000):
                if isinstance(d, dict) and d.get("device_id") is not None:
                    dev_map[str(d["device_id"])] = d

        # Temperature/voltage matter in both directions - a sensor far above its
        # peers is the interesting case, unlike light levels.
        peer_flags = _peer_outliers(records, lambda r: (r["device_id"], r["cls"]),
                                    value_key="value", two_sided=True)

        counts = {k: 0 for k in _SEVERITY_ORDER}
        for r in records:
            sev, why = _classify_sensor(r, peer_flags.get(id(r)), stale_days)
            r["sev"], r["why"] = sev, why
            counts[sev] += 1

        shown = [r for r in records if r["sev"] == severity] if severity else list(records)
        if severity and not shown:
            return (f"Sensor health: 0 sensors with severity '{severity}' "
                    f"(of {len(records)}). Counts: {_severity_summary(counts)}")

        shown.sort(key=lambda r: (_SEVERITY_ORDER.get(r["sev"], 9), r["cls"], -(r["value"] or 0)))
        total_shown = len(shown)
        shown = shown[:limit]

        devices_n = len({r["device_id"] for r in records})
        lines = [f"Sensor health: {len(records)} sensors on {devices_n} devices | "
                 f"{_severity_summary(counts)}"]
        if counts["stale"]:
            lines.append(f"WARN: {counts['stale']} reading(s) older than {stale_days}d - not trustworthy")
        if total_shown > limit:
            lines.append(f"NOTE: showing worst {limit} of {total_shown} - raise limit or filter by class/severity")

        lines.append("id|hostname|class|sensor|value|low|high|sev|reason")
        for r in shown:
            d = dev_map.get(str(r["device_id"]), {})
            lines.append("|".join([
                str(r["device_id"]),
                str(d.get("hostname", "") or ""),
                r["cls"],
                r["descr"],
                "" if r["value"] is None else str(r["value"]),
                "" if r["lo"] is None else str(r["lo"]),
                "" if r["hi"] is None else str(r["hi"]),
                r["sev"],
                r["why"],
            ]))
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────────── Port Traffic Helpers ─────────────────────────

# Requested explicitly: the default /ports response omits traffic and error
# counters entirely, and fetching every column for every port is far larger.
_PORT_TRAFFIC_COLUMNS = ("port_id,device_id,ifName,ifAlias,ifOperStatus,ifAdminStatus,"
                         "ifSpeed,ifInOctets_rate,ifOutOctets_rate,"
                         "ifInErrors_delta,ifOutErrors_delta")


@mcp.tool()
def get_port_traffic(device: Optional[str] = None, sort_by: str = "utilization",
                     limit: int = 20, min_utilization: Optional[float] = None,
                     up_only: bool = True) -> str:
    """Get port bandwidth utilization and error counters, ranked worst-first.
    [YES] "流量最高的埠", "頻寬使用率", "哪個介面塞爆了", "CRC錯誤", "介面錯誤",
          "port utilization", "top talkers", "interface errors".
    [NO] "port up/down status only" -> use get_device_ports().

    Args:
        device: Hostname, IP, or device ID. None = whole network.
        sort_by: "utilization" (default), "errors", or "traffic" (absolute bps).
        limit: Max detail rows (default 20, hard cap 100).
        min_utilization: Only show ports at/above this percent.
        up_only: Skip ports that are not operationally up (default True)."""
    try:
        limit = max(1, min(100, limit))
        sort_by = (sort_by or "utilization").strip().lower()
        if sort_by not in ("utilization", "errors", "traffic"):
            return _R({"error": f"Invalid sort_by '{sort_by}'. Use utilization, errors, or traffic."})

        target_id = None
        dev = None
        if device:
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            target_id = dev["device_id"]

        try:
            result = _api_request("GET", "ports", params={"columns": _PORT_TRAFFIC_COLUMNS})
            ports = _extract_data(result, ['ports'])
        except Exception as e:
            return _R({"error": f"Cannot read ports: {e}"})

        rows = []
        for p in ports:
            if not isinstance(p, dict):
                continue
            if target_id is not None and str(p.get("device_id")) != str(target_id):
                continue
            oper = _normalize_port_status(p.get("ifOperStatus"))
            if up_only and oper != "up":
                continue

            speed = _to_float(p.get("ifSpeed")) or 0.0
            in_bps = (_to_float(p.get("ifInOctets_rate")) or 0.0) * 8
            out_bps = (_to_float(p.get("ifOutOctets_rate")) or 0.0) * 8
            err_in = int(_to_float(p.get("ifInErrors_delta")) or 0)
            err_out = int(_to_float(p.get("ifOutErrors_delta")) or 0)

            # Utilisation follows the busier direction; links are rarely symmetric.
            util = round(max(in_bps, out_bps) / speed * 100, 1) if speed > 0 else None
            if min_utilization is not None and (util is None or util < min_utilization):
                continue

            rows.append({
                "device_id": p.get("device_id"),
                "port": p.get("ifName") or "",
                "alias": str(p.get("ifAlias") or "")[:24],
                "speed_mbps": round(speed / 1e6, 1) if speed else None,
                "in_mbps": round(in_bps / 1e6, 2),
                "out_mbps": round(out_bps / 1e6, 2),
                "util": util,
                "err_in": err_in,
                "err_out": err_out,
                "oper": oper,
            })

        if not rows:
            scope = f"device {device}" if device else "network"
            return (f"No matching ports for {scope} "
                    f"(up_only={up_only}, min_utilization={min_utilization}).")

        if sort_by == "errors":
            rows.sort(key=lambda r: -(r["err_in"] + r["err_out"]))
        elif sort_by == "traffic":
            rows.sort(key=lambda r: -(r["in_mbps"] + r["out_mbps"]))
        else:
            rows.sort(key=lambda r: -(r["util"] if r["util"] is not None else -1))

        total = len(rows)
        rows = rows[:limit]

        dev_map = {}
        if target_id is not None:
            dev_map = {str(target_id): dev}
        else:
            for d in _paginate("devices", max_items=1000):
                if isinstance(d, dict) and d.get("device_id") is not None:
                    dev_map[str(d["device_id"])] = d

        err_ports = sum(1 for r in rows if r["err_in"] or r["err_out"])
        lines = [f"Port traffic: {total} ports (sort={sort_by}, up_only={up_only})"
                 f"{f', {err_ports} shown with errors' if err_ports else ''}"]
        if total > limit:
            lines.append(f"NOTE: showing top {limit} of {total} - raise limit or filter by device")
        lines.append("id|hostname|port|alias|speed_mbps|in_mbps|out_mbps|util%|err_in|err_out")
        for r in rows:
            d = dev_map.get(str(r["device_id"]), {})
            lines.append("|".join([
                str(r["device_id"]),
                str(d.get("hostname", "") or ""),
                r["port"], r["alias"],
                "" if r["speed_mbps"] is None else str(r["speed_mbps"]),
                str(r["in_mbps"]), str(r["out_mbps"]),
                "" if r["util"] is None else str(r["util"]),
                str(r["err_in"]), str(r["err_out"]),
            ]))
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_event_log(device: Optional[str] = None, days: int = 7,
                  event_type: Optional[str] = None, limit: int = 20) -> str:
    """Get device event log entries (state changes, config/hardware changes).
    [YES] "事件記錄", "設備發生什麼事", "event log", "狀態變更記錄", "最近的事件".
    [NO] "firing alerts" -> use get_recent_alerts().
    [NO] "resolved alert history" -> use get_alert_history().

    Args:
        device: Hostname, IP, or device ID. None = all devices.
        days: Look-back window (default 7).
        event_type: Filter by type, e.g. "system", "interface", "sensor".
        limit: Max rows (default 20, hard cap 100)."""
    try:
        limit = max(1, min(100, limit))
        days = max(1, days)

        endpoint = "logs/eventlog"
        dev = None
        if device:
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            endpoint = f"logs/eventlog/{dev['device_id']}"

        # The log is returned oldest-first and can hold hundreds of thousands of
        # rows, so the date filter is what keeps this cheap - never page to the end.
        since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        try:
            result = _api_request("GET", endpoint,
                                  params={"from": since, "limit": min(limit * 5, 200)})
            logs = _extract_data(result, ['logs'])
        except Exception as e:
            return _R({"error": f"Cannot read {endpoint}: {e}"})

        if event_type:
            et = event_type.strip().lower()
            logs = [l for l in logs if str(l.get("type") or "").lower() == et]

        if not logs:
            scope = f"device {device}" if device else "network"
            return (f"No events for {scope} in the past {days} days"
                    f"{f' of type {event_type}' if event_type else ''}.")

        logs.sort(key=lambda l: str(l.get("datetime") or ""), reverse=True)
        total = len(logs)
        logs = logs[:limit]

        lines = [f"Events: {total} in past {days}d"
                 f"{f' (type={event_type})' if event_type else ''}"]
        if total > limit:
            lines.append(f"NOTE: showing newest {limit} of {total} retrieved")
        lines.append("datetime|id|hostname|type|message")
        for l in logs:
            lines.append("|".join([
                _format_timestamp(l.get("datetime")),
                str(l.get("device_id", "") or ""),
                str(l.get("hostname", "") or ""),
                str(l.get("type", "") or ""),
                str(l.get("message", "") or "").replace("|", "/")[:110],
            ]))
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_monitoring_health(stale_hours: int = 24, limit: int = 20) -> str:
    """Check monitoring coverage itself: devices that stopped being polled.
    [YES] "監控健康度", "哪些設備沒在輪詢", "資料是不是過期", "監控涵蓋率",
          "stale devices", "is monitoring working?", "devices not polled".
    [NO] "device up/down health score" -> use network_health_overview().

    Every other tool reports whatever LibreNMS last stored, so a device that
    silently stopped being polled yields confident-looking but years-old data.
    This surfaces those before they are mistaken for current readings.

    Args:
        stale_hours: Flag devices not polled within this many hours (default 24).
        limit: Max detail rows (default 20, hard cap 100)."""
    try:
        limit = max(1, min(100, limit))
        devices = [d for d in _paginate("devices", max_items=1000) if isinstance(d, dict)]
        if not devices:
            return _R({"error": "No devices returned by API"})

        now = datetime.now()
        cutoff = now - timedelta(hours=max(1, stale_hours))
        buckets = {"never_polled": [], "stale": [], "disabled": [],
                   "ignored": [], "down": [], "slow_poll": []}

        for d in devices:
            did = d.get("device_id")
            if not did:
                continue
            last = _safe_parse_datetime(d.get("last_polled"))
            age_h = round((now - last).total_seconds() / 3600, 1) if last else None
            row = {
                "device_id": did,
                "hostname": d.get("hostname") or "",
                "sysName": d.get("sysName") or "",
                "last_polled": d.get("last_polled") or "never",
                "age_h": age_h,
                "took_s": round(_to_float(d.get("last_polled_timetaken")) or 0, 1),
            }
            if str(d.get("disabled")) == "1":
                row["why"] = "disabled - retains last known values indefinitely"
                buckets["disabled"].append(row)
            elif str(d.get("ignore")) == "1":
                row["why"] = "ignored - polled but excluded from alerting"
                buckets["ignored"].append(row)
            elif last is None:
                row["why"] = "never polled"
                buckets["never_polled"].append(row)
            elif last < cutoff:
                row["why"] = f"not polled for {age_h}h"
                buckets["stale"].append(row)
            elif _device_status_str(d.get("status")) == "down":
                row["why"] = "device down"
                buckets["down"].append(row)
            elif row["took_s"] > 30:
                row["why"] = f"poll took {row['took_s']}s"
                buckets["slow_poll"].append(row)

        problems = (buckets["never_polled"] + buckets["stale"] + buckets["disabled"] +
                    buckets["ignored"] + buckets["down"] + buckets["slow_poll"])
        healthy = len(devices) - len(problems)

        lines = [f"Monitoring health: {len(devices)} devices | ok:{healthy} " +
                 " ".join(f"{k}:{len(v)}" for k, v in buckets.items())]
        if buckets["disabled"] or buckets["stale"] or buckets["never_polled"]:
            n = len(buckets["disabled"]) + len(buckets["stale"]) + len(buckets["never_polled"])
            lines.append(f"WARN: {n} device(s) are not producing current data - "
                         "readings reported for them by other tools may be long out of date")
        if not problems:
            lines.append("All devices polled within the window.")
            return "\n".join(lines)

        total = len(problems)
        problems = problems[:limit]
        if total > limit:
            lines.append(f"NOTE: showing {limit} of {total} - raise limit for the rest")
        lines.append("id|hostname|sysName|last_polled|age_h|issue")
        for r in problems:
            lines.append("|".join([
                str(r["device_id"]), r["hostname"], r["sysName"],
                str(r["last_polled"]),
                "" if r["age_h"] is None else str(r["age_h"]),
                r["why"],
            ]))
        return "\n".join(lines)
    except Exception as e:
        return _R({"error": str(e)})



@mcp.tool()
def get_all_device_performance(status: str = "up", sort_by: str = "cpu",
                               limit: int = 0, min_pct: int = 0) -> str:
    """Get CPU and memory usage for EVERY device in one call (not just top N).
    [YES] "所有設備的效能", "全部裝置 cpu 記憶體", "all device performance", "整體效能盤點", "有哪些機器負載偏高".
    [NO] "只要前 10 名" -> use get_top_cpu() / get_top_memory().

    Args:
        status: Filter by device state - "up" (default), "down", or "all".
        sort_by: Sort field - "cpu" (default), "memory", or "name".
        limit: Max rows returned. 0 = no limit (default).
        min_pct: Only include devices where CPU or memory is at or above this percentage (default 0)."""
    try:
        # The custom_top_devices.php helper is the fast path, but it is not
        # deployed everywhere (and returns an empty body on LibreNMS 26.x), so
        # fall back to querying each device concurrently rather than serially.
        cpu_rows = _try_custom_top_devices("processor", 1000) or []
        mem_rows = _try_custom_top_devices("mempool", 1000) or []
        used_helper = bool(cpu_rows or mem_rows)

        merged = {}

        def absorb(rows, key):
            for r in rows:
                if not isinstance(r, dict):
                    continue
                did = r.get("device_id")
                if did is None:
                    continue
                entry = merged.setdefault(did, {"device_id": did})
                entry.setdefault("hostname", r.get("hostname") or r.get("sysName") or "")
                for candidate in ("processor_usage", "mempool_perc", "usage", "usage_pct"):
                    if r.get(candidate) is not None:
                        try:
                            entry[key] = round(float(r[candidate]), 1)
                        except (TypeError, ValueError):
                            pass
                        break

        absorb(cpu_rows, "cpu_pct")
        absorb(mem_rows, "mem_pct")

        # The helper only knows devices that report the metric; fold in the full
        # inventory so devices with neither processor nor mempool still appear.
        devices = _paginate("devices", max_items=1000)
        for d in devices:
            if not isinstance(d, dict):
                continue
            did = d.get("device_id")
            if did is None:
                continue
            entry = merged.setdefault(did, {"device_id": did})
            entry["hostname"] = d.get("hostname") or entry.get("hostname") or ""
            entry["sysName"] = d.get("sysName") or ""
            entry["os"] = d.get("os") or ""
            entry["type"] = d.get("type") or ""
            entry["status"] = _device_status_str(d.get("status"))
            entry["uptime_days"] = round((d.get("uptime") or 0) / 86400, 1) if d.get("uptime") else None
            entry["location"] = d.get("location") or ""

        if not used_helper:
            targets = [r for r in merged.values() if r.get("status") == "up"]

            def _probe(entry):
                # /devices/{id}/processors and /mempools return HTTP 500 on
                # LibreNMS 26.x master; health/{type} lists the sensors and
                # health/{type}/{sensor_id} carries the actual reading.
                did = entry["device_id"]
                out = {}
                for kind, id_field, val_field, key in (
                    ("processor", "processor_id", "processor_usage", "cpu_pct"),
                    ("mempool", "mempool_id", "mempool_perc", "mem_pct"),
                ):
                    try:
                        listing = _extract_data(
                            _api_request("GET", f"devices/{did}/health/{kind}", use_cache=True),
                            ['graphs'])
                        ids = [g.get("sensor_id") or g.get(id_field)
                               for g in listing if isinstance(g, dict)]
                        ids = [i for i in ids if i is not None][:6]
                        vals = []
                        for sid in ids:
                            detail = _extract_data(
                                _api_request("GET", f"devices/{did}/health/{kind}/{sid}",
                                             use_cache=True), ['graphs'])
                            for item in detail:
                                if isinstance(item, dict) and item.get(val_field) is not None:
                                    try:
                                        vals.append(float(item[val_field]))
                                    except (TypeError, ValueError):
                                        pass
                        if vals:
                            out[key] = round(sum(vals) / len(vals), 1)
                    except Exception:
                        pass
                return (did, out)

            for did, vals in _parallel_map(_probe, targets, workers=12):
                if vals:
                    merged[did].update(vals)

        rows = list(merged.values())

        want = (status or "up").lower()
        if want != "all":
            rows = [r for r in rows if r.get("status") == want]

        if min_pct:
            rows = [r for r in rows
                    if (r.get("cpu_pct") or 0) >= min_pct or (r.get("mem_pct") or 0) >= min_pct]

        key = (sort_by or "cpu").lower()
        if key == "memory":
            rows.sort(key=lambda r: r.get("mem_pct") or -1, reverse=True)
        elif key == "name":
            rows.sort(key=lambda r: (r.get("hostname") or "").lower())
        else:
            rows.sort(key=lambda r: r.get("cpu_pct") or -1, reverse=True)

        total = len(rows)
        if limit and limit > 0:
            rows = rows[:limit]

        if not rows:
            return _R({"count": 0, "message": f"No devices matched (status={status}, min_pct={min_pct})"})

        cols = ["device_id", "hostname", "os", "type", "status",
                "cpu_pct", "mem_pct", "uptime_days", "location"]
        source = "helper" if used_helper else "per-device API (parallel)"
        out = [f"All device performance: {len(rows)} of {total} (status={status}, sort={key}, source={source})",
               "|".join(cols)]
        for r in rows:
            out.append("|".join("" if r.get(c) is None else str(r.get(c, "")) for c in cols))
        return "\n".join(out)

    except Exception as e:
        logger.error(f"get_all_device_performance failed: {e}")
        return _R({"error": str(e)})


@mcp.tool()
def get_syslog(device: Optional[str] = None, limit: int = 50,
               contains: Optional[str] = None, timeout: int = 120) -> str:
    """Get syslog messages collected by LibreNMS (messages sent by devices over syslog).
    [YES] "syslog", "系統記錄", "設備送來的 log", "看 syslog 有什麼", "這台機器的 syslog".
    [NO] "狀態變化/告警事件" -> use get_event_log(). [NO] "current alerts" -> use get_recent_alerts().

    WARNING: this endpoint is slow. On a busy install even 2 rows can take 40-60
    seconds because the syslog table is large. Always pass `device` when you can -
    scoping by device_id is several times faster than an unscoped query.

    Args:
        device: Hostname, IP or device ID to scope the query. None = all devices (slowest).
        limit: Max entries (default 50).
        contains: Case-insensitive substring filter applied to the message after retrieval.
        timeout: Seconds to wait before giving up (default 120)."""
    try:
        endpoint = "logs/syslog"
        scoped = None
        if device:
            dev = _resolve_device(device)
            if not dev:
                return _R({"error": f"Device not found: {device}"})
            # device_id is markedly faster than hostname on this endpoint
            scoped = dev.get("device_id")
            endpoint = f"logs/syslog/{scoped}"

        result = _api_request("GET", endpoint, params={"limit": max(1, int(limit))},
                              use_cache=True, timeout=max(30, int(timeout)))
        logs = _extract_data(result, ['logs', 'syslog'])

        if contains:
            needle = contains.lower()
            logs = [l for l in logs
                    if isinstance(l, dict) and needle in str(l.get("msg") or l.get("message") or "").lower()]

        if not logs:
            hint = "" if device else " (try scoping with device= — unscoped syslog often times out)"
            return _R({"count": 0, "message": f"No syslog entries found{hint}"})

        cols = ["timestamp", "hostname", "facility", "priority", "program", "msg"]
        out = [f"Syslog: {len(logs)} entries" + (f" for {device}" if device else " (all devices)"),
               "|".join(cols)]
        for l in logs:
            if not isinstance(l, dict):
                continue
            row = {
                "timestamp": l.get("timestamp", ""),
                "hostname": l.get("hostname") or l.get("sysName") or "",
                "facility": l.get("facility", ""),
                "priority": l.get("priority") or l.get("level") or "",
                "program": l.get("program") or l.get("tag") or "",
                "msg": str(l.get("msg") or l.get("message") or "").replace("|", "/")[:200],
            }
            out.append("|".join(str(row[c]) for c in cols))
        return "\n".join(out)

    except Exception as e:
        logger.error(f"get_syslog failed: {e}")
        msg = str(e)
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            msg = (f"Syslog query timed out after {timeout}s. This endpoint is slow on large "
                   f"installs — scope it with device= and/or lower limit, or raise timeout=.")
        return _R({"error": msg})

@mcp.tool()
def clear_cache() -> str:
    """Clear the internal API cache.
    [YES] Use when data seems stale or after making changes."""
    try:
        before = cache.stats()
        cache.clear()
        return _R({"status": "cleared", "keys_cleared": before["total_keys"]})
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────────── Main Entry Point ─────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="LibreNMS FastMCP Server v4.4.0 - Slim (Weak-Model Optimized)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # stdio mode (default):
  python3 mcp_librenms.py --url "http://192.168.1.68" --token "your_token"

  # Streamable HTTP mode:
  python3 mcp_librenms.py --transport streamable-http --port 8000 --url "http://192.168.1.68" --token "your_token"

  # SSE mode:
  python3 mcp_librenms.py --transport sse --port 8000 --url "http://192.168.1.68" --token "your_token"
        """
    )
    parser.add_argument('--url', '--host', dest='url',
                        help='LibreNMS base URL')
    parser.add_argument('--token', '--api-token', dest='token',
                        help='LibreNMS API token')
    parser.add_argument('--verify-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                        default=None, help='Verify SSL (true/false)')
    parser.add_argument('--cache-ttl', type=int, default=None, help='Cache TTL seconds (default: 300)')
    parser.add_argument('--timeout', type=int, default=None, help='API timeout seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=None, help='Max retries (default: 3)')
    parser.add_argument('--batch-size', type=int, default=None, help='Batch size (default: 200)')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http', 'sse'], default='stdio',
                        help='Transport: stdio (default), streamable-http, or sse')
    parser.add_argument('--listen', default='0.0.0.0', help='HTTP bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='HTTP port (default: 8000)')
    parser.add_argument('--api-key', default=os.environ.get('MCP_API_KEY', ''),
                        help='API key for SSE/HTTP auth (or set MCP_API_KEY env var)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    config = Config(args)
    cache = SimpleCache(config.CACHE_TTL)
    initialize_session()

    logger.info("=" * 60)
    logger.info("LibreNMS FastMCP Server v4.5.1 - Slim (29 tools)")
    logger.info("=" * 60)
    logger.info(f"Transport: {args.transport}")
    if args.transport in ('streamable-http', 'sse'):
        logger.info(f"HTTP Listen: {args.listen}:{args.port}")
        if args.api_key:
            logger.info("API Key auth: enabled")
    logger.info(f"Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s")
    logger.info("=" * 60)

    if args.transport in ('sse', 'streamable-http'):
        import uvicorn
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        if args.transport == 'sse':
            app = mcp.sse_app()
        else:
            app = mcp.streamable_http_app()

        if args.api_key:
            _api_key = args.api_key
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

