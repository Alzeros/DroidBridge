#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DroidBridge - per-app network launcher over an ADB bridge.

Only child processes launched from here inherit the proxy environment.
No TUN, no system proxy, no setx, no registry. Stdlib only.

Layers:
  Node / generic apps  -> HTTP_PROXY, HTTPS_PROXY, ALL_PROXY
  Electron / Chromium -> --proxy-server (they ignore *_PROXY env vars on Windows)
  Firefox / Gecko     -> isolated -no-remote -profile + user.js prefs
  All proxied traffic -> local router on 127.0.0.1:10086 -> rules.yaml
"""
from __future__ import annotations

import configparser
import ctypes
import csv
import io
import ipaddress
import json
import os
import re
import select
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit

import conn_tracker
import scrcpy_bridge

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
RULES_EXAMPLE_PATH = ROOT / "rules.example.yaml"
HTML_PATH = ROOT / "index.html"
ICO_PATH = ROOT / "droidbridge.ico"
PNG_PATH = ROOT / "droidbridge.png"
SVG_PATH = ROOT / "droidbridge.svg"
PROFILES_DIR = ROOT / "profiles"
BUNDLED_ADB_PATH = ROOT / "vendor" / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
RUNTIME_PATH = Path(tempfile.gettempdir()) / "droidbridge_runtime.json"

API_TOKEN = secrets.token_urlsafe(24)
MAX_BODY_BYTES = 1_048_576
MAX_PHONE_UPLOAD_BYTES = 512 * 1024 * 1024

DEFAULT_CONFIG = {
    "adb_path": "",
    "adb_serial": "",
    "proxy": {
        "host": "127.0.0.1",
        "port": 5038,
        "listen_host": "127.0.0.1",
        "listen_port": 10086,
        "rules_file": "rules.yaml",
        "enabled": True,
    },
    "apps": [
        {
            "id": "antigravity",
            "name": "Antigravity",
            "exe": "%LOCALAPPDATA%\\Programs\\antigravity\\Antigravity.exe",
            "args": "",
            "kind": "auto",
            "note": "Google AI IDE (Electron + Node sidecar)",
        }
    ],
    "phone_apps": [],
}

# Files that only exist next to an Electron / Chromium based binary.
ELECTRON_MARKERS = [
    "LICENSE.electron.txt",
    "resources.pak",
    "chrome_100_percent.pak",
    "vk_swiftshader_icd.json",
    "icudtl.dat",
    "v8_context_snapshot.bin",
    "chrome.dll",
    "LICENSES.chromium.html",
]

# Files that only exist next to a Firefox / Gecko based binary.
FIREFOX_MARKERS = [
    "xul.dll",
    "omni.ja",
    "mozglue.dll",
    "nss3.dll",
    "lgpllibs.dll",
    "application.ini",
    "platform.ini",
    "softokn3.dll",
]

FIREFOX_STEMS = {
    "firefox",
    "librewolf",
    "waterfox",
    "floorp",
    "zen",
    "thunderbird",
    "seamonkey",
}

NATIVE_BROWSER_STEMS = {"chrome", "msedge", "chromium", "brave", "vivaldi"}

BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
]

_server = None
_last_request = time.time()
_config_lock = threading.RLock()
_procs_lock = threading.Lock()
_quit_lock = threading.Lock()
_quit_timer: threading.Timer | None = None
_picker_lock = threading.Lock()
_icon_lock = threading.Lock()
_icon_cache: dict[tuple[str, int], bytes | None] = {}
_ui_browser_pids: set[int] = set()
_proxy_server = None
_proxy_thread = None
MAX_PROXY_EVENTS = 300
_proxy_events: list[dict] = []
_proxy_events_lock = threading.Lock()
_proxy_error = ""
_last_proxy_activity = 0.0
_tray = None
_ui_url = ""


# ---------------------------------------------------------------- config ----

def load_config():
    with _config_lock:
        if not CONFIG_PATH.exists():
            save_config(DEFAULT_CONFIG)
            cfg = json.loads(json.dumps(DEFAULT_CONFIG))
            ensure_rules_file(cfg)
            return cfg
        with CONFIG_PATH.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
        removed_legacy = False
        for legacy_key in ("router_enabled", "bypass"):
            if legacy_key in cfg.get("proxy", {}):
                cfg["proxy"].pop(legacy_key, None)
                removed_legacy = True
        for app in cfg.get("apps", []):
            if "bypass" in app:
                app.pop("bypass", None)
                removed_legacy = True
        for key, val in DEFAULT_CONFIG.items():
            cfg.setdefault(key, json.loads(json.dumps(val)))
        for key, val in DEFAULT_CONFIG["proxy"].items():
            cfg["proxy"].setdefault(key, val)
        if removed_legacy:
            save_config(cfg)
        ensure_rules_file(cfg)
        return cfg


def save_config(cfg):
    with _config_lock:
        tmp = CONFIG_PATH.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        tmp.replace(CONFIG_PATH)
    _invalidate_proxy_route_cache()


def rules_path(cfg):
    value = str(cfg.get("proxy", {}).get("rules_file") or "rules.yaml")
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def ensure_rules_file(cfg):
    path = rules_path(cfg)
    if path.exists() or path != ROOT / "rules.yaml" or not RULES_EXAMPLE_PATH.is_file():
        return
    try:
        path.write_text(RULES_EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError:
        pass


def _strip_yaml_comment(text):
    quoted = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted == '"':
            escaped = True
            continue
        if char in "'\"":
            quoted = None if quoted == char else (char if quoted is None else quoted)
        elif char == "#" and quoted is None and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    return text.rstrip()


def _yaml_scalar(text):
    value = _strip_yaml_comment(text.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        if value[0] == '"':
            try:
                return json.loads(value)
            except ValueError:
                pass
        return value[1:-1].replace("''", "'")
    return value


def _split_rule_fields(text):
    whole = _yaml_scalar(text)
    if whole != text and "," in whole:
        text = whole
    reader = csv.reader(io.StringIO(text), skipinitialspace=True, strict=True)
    fields = next(reader, [])
    return [_yaml_scalar(field) for field in fields]


def _normalize_target_host(host):
    value = str(host or "").strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


class RouteRule:
    def __init__(self, kind, value, action):
        self.kind = kind.upper()
        self.value = _normalize_target_host(value)
        self.action = action.upper()
        self.label = ",".join((self.kind, self.value, self.action))
        self.network = None
        if self.kind == "IP-CIDR":
            try:
                self.network = ipaddress.ip_network(self.value, strict=False)
            except ValueError as exc:
                raise ValueError("无效的 IP-CIDR：%s" % self.value) from exc

    def matches(self, host):
        target = _normalize_target_host(host)
        if self.kind == "MATCH":
            return True
        if self.kind == "IP-CIDR":
            try:
                return ipaddress.ip_address(target) in self.network
            except ValueError:
                return False
        if self.kind == "DOMAIN":
            return target == self.value
        if self.kind == "DOMAIN-SUFFIX":
            return target == self.value or target.endswith("." + self.value)
        if self.kind == "DOMAIN-KEYWORD":
            return self.value in target
        return False


class RouteTable:
    SUPPORTED_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "MATCH"}
    SUPPORTED_ACTIONS = {"DIRECT", "PROXY"}

    def __init__(self, upstream, rules, source, error=""):
        self.upstream = upstream
        self.rules = rules
        self.source = source
        self.error = error

    @property
    def upstream_url(self):
        return "http://%s:%s" % self.upstream

    @classmethod
    def _default_upstream(cls, cfg):
        proxy = cfg.get("proxy", {})
        try:
            upstream_port = int(proxy.get("port") or 5038)
        except (TypeError, ValueError, OverflowError):
            upstream_port = 5038
        return (str(proxy.get("host") or "127.0.0.1"), upstream_port)

    @classmethod
    def load_from_text(cls, text, cfg, source=""):
        proxy = cfg.get("proxy", {})
        upstream = cls._default_upstream(cfg)
        try:
            yaml_upstream = None
            rules = []
            in_rules = False
            seen_keys = set()
            seen_rules = set()
            for line_number, raw_line in enumerate(text.splitlines(), 1):
                line = _strip_yaml_comment(raw_line).strip()
                if not line:
                    continue
                if line == "rules:":
                    if "rules" in seen_keys:
                        raise ValueError("第 %d 行重复定义 rules" % line_number)
                    seen_keys.add("rules")
                    in_rules = True
                    continue
                if not in_rules and line.lower().startswith("upstream:"):
                    if "upstream" in seen_keys:
                        raise ValueError("第 %d 行重复定义 upstream" % line_number)
                    seen_keys.add("upstream")
                    yaml_upstream = _yaml_scalar(line.split(":", 1)[1])
                    if not yaml_upstream:
                        raise ValueError("第 %d 行 upstream 不能为空" % line_number)
                    continue
                if in_rules and line.startswith("-"):
                    raw_rule = line[1:].strip()
                    if not raw_rule:
                        raise ValueError("第 %d 行规则不能为空" % line_number)
                    fields = _split_rule_fields(raw_rule)
                    if len(fields) == 1:
                        fields = _split_rule_fields(fields[0])
                    if len(fields) == 2:
                        fields = [fields[0], "", fields[1]]
                    if len(fields) != 3:
                        raise ValueError("第 %d 行规则必须是 TYPE,TARGET,ACTION 或 MATCH,ACTION" % line_number)
                    kind, value, action = (field.strip() for field in fields)
                    kind = kind.upper()
                    action = action.upper()
                    if kind not in cls.SUPPORTED_KINDS:
                        raise ValueError("第 %d 行不支持规则类型 %s" % (line_number, kind))
                    if action not in cls.SUPPORTED_ACTIONS:
                        raise ValueError("第 %d 行不支持动作 %s" % (line_number, action))
                    if kind != "MATCH" and not value:
                        raise ValueError("第 %d 行规则目标不能为空" % line_number)
                    rule = RouteRule(kind, value, action)
                    if rule.label in seen_rules:
                        raise ValueError("第 %d 行重复定义规则 %s" % (line_number, rule.label))
                    seen_rules.add(rule.label)
                    rules.append(rule)
                    continue
                if in_rules:
                    raise ValueError("第 %d 行不是有效的 rules 条目" % line_number)
                raise ValueError("第 %d 行包含不支持的 YAML 字段或格式" % line_number)

            if yaml_upstream:
                parsed = urlsplit(yaml_upstream)
                try:
                    parsed_port = parsed.port
                except ValueError:
                    raise ValueError("upstream 端口无效")
                if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or not parsed_port:
                    raise ValueError("upstream 必须是带端口的 http:// 地址")
                if parsed.scheme.lower() != "http":
                    raise ValueError("当前版本只支持 HTTP 上游代理")
                if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                    raise ValueError("upstream 只支持 http://主机:端口，不支持凭据、路径或查询参数")
                upstream_host = _normalize_target_host(parsed.hostname)
                if upstream_host in {"localhost", "127.0.0.1", "::1"} and parsed_port == int(proxy.get("listen_port") or 10086):
                    raise ValueError("upstream 不能指向 DroidBridge 自身的分流入口")
                upstream = (parsed.hostname, parsed_port)
            effective_upstream_host = _normalize_target_host(upstream[0])
            effective_upstream_port = int(upstream[1])
            if (not effective_upstream_host or effective_upstream_port < 1 or effective_upstream_port > 65535):
                raise ValueError("upstream 主机或端口无效")
            if effective_upstream_host in {"localhost", "127.0.0.1", "::1"} and effective_upstream_port == int(proxy.get("listen_port") or 10086):
                raise ValueError("upstream 不能指向 DroidBridge 自身的分流入口")
            if not rules:
                raise ValueError("rules 不能为空")
            if rules[-1].kind != "MATCH":
                raise ValueError("rules 最后一条必须是 MATCH")
            if any(rule.kind == "MATCH" for rule in rules[:-1]):
                raise ValueError("MATCH 必须是最后一条规则")
            return cls(upstream, rules, source)
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            return cls(upstream, [], source, "规则加载失败：%s" % exc)

    @classmethod
    def load(cls, cfg):
        upstream = cls._default_upstream(cfg)
        path = rules_path(cfg)
        if not path.is_file():
            return cls(upstream, [], str(path), "规则文件不存在")
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            return cls(upstream, [], str(path), "规则加载失败：%s" % exc)
        return cls.load_from_text(text, cfg, str(path))

    def match_detail(self, host):
        for idx, rule in enumerate(self.rules, 1):
            if rule.matches(host):
                return rule, idx
        if self.error:
            raise ValueError(self.error)
        raise ValueError("没有匹配的分流规则")

    def rule_for(self, host):
        return self.match_detail(host)[0]

    def action_for(self, host):
        return self.rule_for(host).action


def extract_test_host(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.hostname:
            return _normalize_target_host(parsed.hostname)
    try:
        host, _ = _host_port(text, 80)
        return _normalize_target_host(host)
    except ValueError:
        return _normalize_target_host(text)


def save_rules_text(cfg: dict, content: str) -> RouteTable:
    path = rules_path(cfg)
    table = RouteTable.load_from_text(content, cfg, str(path))
    if table.error:
        return table
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(normalized, encoding="utf-8")
    tmp.replace(path)
    _invalidate_proxy_route_cache()
    return table


def quick_add_rule(cfg: dict, host: str, action: str, kind: str = "") -> dict:
    target_action = str(action or "").strip().upper()
    if target_action not in RouteTable.SUPPORTED_ACTIONS:
        raise ValueError("不支持的规则动作：%s" % target_action)
    target = extract_test_host(host)
    if not target:
        raise ValueError("目标主机不能为空")

    req_kind = str(kind or "").strip().upper()
    if req_kind:
        if req_kind not in (RouteTable.SUPPORTED_KINDS - {"MATCH"}):
            raise ValueError("不支持的规则类型：%s" % req_kind)
        if req_kind == "IP-CIDR":
            target = str(ipaddress.ip_network(target, strict=False))
        rule_kind, rule_value = req_kind, target
    else:
        try:
            ip = ipaddress.ip_address(target)
            rule_kind = "IP-CIDR"
            rule_value = f"{ip}/32" if ip.version == 4 else f"{ip}/128"
        except ValueError:
            rule_kind, rule_value = "DOMAIN", target

    candidate = RouteRule(rule_kind, rule_value, target_action)
    ensure_rules_file(cfg)
    path = rules_path(cfg)
    if not path.is_file():
        return {"ok": False, "error": "规则文件不存在"}

    raw_text = path.read_text(encoding="utf-8-sig")
    lines = raw_text.splitlines()
    rules_header_idx = None
    in_rules = False
    first_match_idx = None
    first_match_action = None
    first_match_indent = "  "
    duplicate_indices = set()
    rule_indent = "  "

    for idx, raw_line in enumerate(lines):
        stripped = _strip_yaml_comment(raw_line).strip()
        if not stripped:
            continue
        if stripped == "rules:":
            rules_header_idx = idx
            in_rules = True
            continue
        if in_rules and stripped.startswith("-"):
            leading = raw_line[: len(raw_line) - len(raw_line.lstrip())]
            if leading:
                rule_indent = leading
            fields = _split_rule_fields(stripped[1:].strip())
            if len(fields) == 1:
                fields = _split_rule_fields(fields[0])
            if len(fields) == 2:
                fields = [fields[0], "", fields[1]]
            if len(fields) == 3:
                rk, rv, ra = (f.strip() for f in fields)
                rk, ra = rk.upper(), ra.upper()
                try:
                    existing = (
                        RouteRule(rk, rv, ra)
                        if rk in RouteTable.SUPPORTED_KINDS and ra in RouteTable.SUPPORTED_ACTIONS
                        else None
                    )
                except ValueError:
                    existing = None
                if existing and existing.kind == candidate.kind and existing.value == candidate.value:
                    if first_match_idx is None:
                        first_match_idx = idx
                        first_match_action = existing.action
                        first_match_indent = leading or rule_indent
                    else:
                        duplicate_indices.add(idx)

    if rules_header_idx is None:
        return {"ok": False, "error": "规则文件缺少 rules: 段落"}

    if first_match_idx is not None:
        if first_match_action == candidate.action and not duplicate_indices:
            return {
                "ok": True,
                "rule": candidate.label,
                "changed": False,
                "updated": False,
                "message": "规则已存在：%s" % candidate.label,
            }
        lines[first_match_idx] = f"{first_match_indent}- {candidate.label}"
        new_lines = [ln for i, ln in enumerate(lines) if i not in duplicate_indices]
        updated = True
    else:
        new_lines = list(lines)
        new_lines.insert(rules_header_idx + 1, f"{rule_indent}- {candidate.label}")
        updated = False

    new_text = "\n".join(new_lines) + "\n"
    table = save_rules_text(cfg, new_text)
    if table.error:
        return {"ok": False, "error": table.error}
    return {
        "ok": True,
        "rule": candidate.label,
        "changed": True,
        "updated": updated,
        "rule_count": len(table.rules),
        "message": ("已更新规则：%s" if updated else "已添加规则：%s") % candidate.label,
    }


def _record_proxy_event(host, action, ok=True, error="", rule=""):
    event = {
        "time": time.strftime("%H:%M:%S"),
        "host": _normalize_target_host(host),
        "action": action,
        "ok": bool(ok),
    }
    if error:
        event["error"] = str(error)
    if rule:
        event["rule"] = str(rule)
    with _proxy_events_lock:
        _proxy_events.insert(0, event)
        del _proxy_events[MAX_PROXY_EVENTS:]


def clear_proxy_events() -> int:
    with _proxy_events_lock:
        cleared = len(_proxy_events)
        _proxy_events.clear()
        return cleared


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser((path or "").strip().strip('"')))


# ---------------------------------------------------------------- probing ----

def probe_proxy(host, port, timeout=0.35):
    host_str = str(host or "").strip()
    if not host_str or isinstance(port, bool):
        return False, 0
    try:
        port_num = int(port)
    except (ValueError, TypeError, OverflowError):
        return False, 0
    if not (1 <= port_num <= 65535):
        return False, 0

    started = time.time()
    try:
        with socket.create_connection((host_str, port_num), timeout=timeout):
            return True, round((time.time() - started) * 1000)
    except (OSError, ValueError, TypeError, OverflowError):
        return False, round((time.time() - started) * 1000)


EXIT_IP_URL = "https://api.ip.sb/geoip"
EXIT_IP_FALLBACK_URL = "https://api.ip.sb/ip"


def _format_exit_location(country: str, region: str, city: str) -> str:
    parts = []
    seen = set()
    for item in (country, region, city):
        text = str(item or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            parts.append(text)
    return ", ".join(parts)


def _parse_exit_ip_response(raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty response")
    if text.startswith("{"):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("unexpected json")
        ip_raw = str(data.get("ip") or "").strip()
        parsed_ip = ipaddress.ip_address(ip_raw)
        country_code = str(data.get("country_code") or "").strip().upper()
        country = str(data.get("country") or "").strip()
        region = str(data.get("region") or "").strip()
        city = str(data.get("city") or "").strip()
        isp = ""
        for key in ("isp", "asn_organization", "organization"):
            val = str(data.get(key) or "").strip()
            if val:
                isp = val
                break
        asn_val = data.get("asn")
        asn = None
        if isinstance(asn_val, int) and not isinstance(asn_val, bool) and asn_val > 0:
            asn = asn_val
        elif isinstance(asn_val, str) and asn_val.strip().isdigit():
            asn = int(asn_val.strip())
        timezone = str(data.get("timezone") or "").strip()
        return {
            "ip": str(parsed_ip),
            "country_code": country_code,
            "country": country,
            "region": region,
            "city": city,
            "location": _format_exit_location(country, region, city),
            "isp": isp,
            "asn": asn,
            "timezone": timezone,
        }
    parsed_ip = ipaddress.ip_address(text)
    return {
        "ip": str(parsed_ip),
        "country_code": "",
        "country": "",
        "region": "",
        "city": "",
        "location": "",
        "isp": "",
        "asn": None,
        "timezone": "",
    }


def query_exit_ip(cfg, url: str = EXIT_IP_URL, timeout: float = 6.0) -> dict:
    p = cfg["proxy"]
    route_table = RouteTable.load(cfg)
    upstream_target = route_table.upstream if not route_table.error else (p["host"], p["port"])
    via = "http://%s:%s" % upstream_target
    checked_at = time.strftime("%H:%M:%S")
    empty_geo = {
        "country_code": "",
        "country": "",
        "region": "",
        "city": "",
        "location": "",
        "isp": "",
        "asn": None,
        "timezone": "",
    }

    upstream_online, _ = probe_proxy(*upstream_target)
    if not upstream_online:
        return {
            "ok": False,
            "ip": "",
            **empty_geo,
            "error": "手机 Clash 上游离线，无法查询出口 IP",
            "source": url,
            "via": via,
            "latency_ms": 0,
            "checked_at": checked_at,
        }

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": via, "https": via})
    )
    candidates = [url]
    if url == EXIT_IP_URL and EXIT_IP_FALLBACK_URL not in candidates:
        candidates.append(EXIT_IP_FALLBACK_URL)

    started = time.time()
    last_err = "查询出口 IP 失败"
    for idx, target_url in enumerate(candidates):
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "curl/8.7.1",
                "Accept": "application/json, text/plain;q=0.9",
                "Cache-Control": "no-cache",
            },
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(8192).decode("utf-8", errors="replace").strip()
            latency_ms = round((time.time() - started) * 1000)
            info = _parse_exit_ip_response(raw)
            return {
                "ok": True,
                **info,
                "error": "",
                "source": target_url,
                "via": via,
                "latency_ms": latency_ms,
                "checked_at": time.strftime("%H:%M:%S"),
            }
        except ValueError:
            last_err = "出口 IP 接口返回内容异常"
            if idx + 1 < len(candidates):
                continue
        except urllib.error.HTTPError as exc:
            last_err = "查询失败（HTTP %s）" % exc.code
            if idx + 1 < len(candidates):
                continue
        except (TimeoutError, socket.timeout):
            last_err = "查询出口 IP 超时"
            break
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (TimeoutError, socket.timeout)):
                last_err = "查询出口 IP 超时"
            else:
                last_err = "查询出口 IP 失败：%s" % reason
            break
        except OSError as exc:
            last_err = "查询出口 IP 失败：%s" % exc
            break
    return {
        "ok": False,
        "ip": "",
        **empty_geo,
        "error": last_err,
        "source": url,
        "via": via,
        "latency_ms": round((time.time() - started) * 1000),
        "checked_at": time.strftime("%H:%M:%S"),
    }


def detect_kind(exe: str):
    """Return ('electron' | 'firefox' | 'generic', evidence list)."""
    folder = Path(exe).parent
    elec_found = [m for m in ELECTRON_MARKERS if (folder / m).exists()]
    stem = Path(exe).stem.lower()
    if stem in NATIVE_BROWSER_STEMS:
        return "electron", ["browser binary"] + elec_found
    if len(elec_found) >= 2:
        return "electron", elec_found

    ff_found = [m for m in FIREFOX_MARKERS if (folder / m).exists()]
    if stem in FIREFOX_STEMS:
        return "firefox", ["gecko binary"] + ff_found
    if len(ff_found) >= 2 and ("xul.dll" in ff_found or "omni.ja" in ff_found):
        return "firefox", ff_found

    return "generic", elec_found


def is_native_browser(exe: str) -> bool:
    """True for a standalone Chromium browser binary, not an Electron app."""
    return Path(exe).stem.lower() in NATIVE_BROWSER_STEMS


def effective_kind(app):
    if app.get("kind") in ("electron", "firefox", "generic"):
        return app["kind"]
    return detect_kind(expand(app["exe"]))[0]


TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
else:
    _kernel32 = None


_procs_cache = {"t": 0.0, "v": {}, "parents": {}}


def invalidate_process_cache():
    with _procs_lock:
        _procs_cache["t"] = 0.0
        _procs_cache["v"] = {}
        _procs_cache["parents"] = {}


def process_map():
    """Enumerate running process names -> PIDs in-process.

    A pythonw.exe (GUI, no console) parent spawning tasklist.exe makes
    Windows allocate a temporary console window -> the flashing black box.
    Toolhelp32 snapshot avoids spawning any child process at all.
    """
    if _kernel32 is None:
        return {}
    with _procs_lock:
        started = time.time()
        if started - _procs_cache["t"] < 1.5 and _procs_cache["v"]:
            return _procs_cache["v"]

        snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        procs = {}
        parents = {}
        if snap and snap != INVALID_HANDLE_VALUE:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            try:
                more = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
                while more:
                    exe_name = entry.szExeFile.lower()
                    procs.setdefault(exe_name, []).append(entry.th32ProcessID)
                    parents[entry.th32ProcessID] = entry.th32ParentProcessID
                    more = _kernel32.Process32NextW(snap, ctypes.byref(entry))
            finally:
                _kernel32.CloseHandle(snap)
        if procs:
            _procs_cache["t"] = started
            _procs_cache["v"] = procs
            _procs_cache["parents"] = parents
        return procs


def _ui_browser_process_ids():
    """Return the DroidBridge browser process tree to exclude from app checks."""
    if not _ui_browser_pids:
        return set()
    parents = _procs_cache.get("parents", {})
    ignored = set(_ui_browser_pids)
    changed = True
    while changed:
        changed = False
        for pid, parent_pid in parents.items():
            if pid not in ignored and parent_pid in ignored:
                ignored.add(pid)
                changed = True
    return ignored


def _query_process_path(pid: int) -> tuple[str | None, int]:
    if _kernel32 is None:
        return None, 0
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None, ctypes.get_last_error()
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value, 0
        return None, ctypes.get_last_error()
    finally:
        _kernel32.CloseHandle(handle)


def running_lines(exe: str):
    """Return matching running processes by full path; never spawns a visible console."""
    name = Path(exe).name
    if not name:
        return []
    pmap = process_map()
    if pmap:
        pids = pmap.get(name.lower(), [])
        if not pids:
            return []
        target_norms = {
            os.path.normcase(os.path.abspath(exe)),
            os.path.normcase(os.path.realpath(exe)),
        }
        matches = []
        ignored_pids = _ui_browser_process_ids()
        for pid in pids:
            if pid in ignored_pids:
                continue
            proc_path, err = _query_process_path(pid)
            if proc_path:
                proc_norms = {
                    os.path.normcase(os.path.abspath(proc_path)),
                    os.path.normcase(os.path.realpath(proc_path)),
                }
                if target_norms & proc_norms:
                    matches.append(proc_path)
            elif err == ERROR_ACCESS_DENIED:
                # Elevated process with matching exe name: keep conservative warning.
                matches.append(name)
        return matches

    # Fallback only if in-process enumeration failed; still fully hidden.
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        res = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq " + name, "/FO", "CSV", "/NH"],
            capture_output=True, timeout=6, startupinfo=si,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )
        text = res.stdout.decode("gbk", errors="ignore")
        return [ln for ln in text.splitlines() if name.lower() in ln.lower()]
    except Exception:
        return []


def split_args(text: str):
    """Split a Windows-ish argument string without eating backslashes."""
    if not (text or "").strip():
        return []
    out, cur, quoted = [], "", False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        elif ch.isspace() and not quoted:
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


# ------------------------------------------------------------- injection ----

def proxy_url(cfg):
    p = cfg["proxy"]
    return "http://%s:%s" % (p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086))


def upstream_url(cfg):
    p = cfg["proxy"]
    return "http://%s:%s" % (p["host"], p["port"])


def build_env(cfg):
    env = os.environ.copy()
    if not cfg["proxy"].get("enabled", True):
        return env, {}
    url = proxy_url(cfg)
    delta = {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "ALL_PROXY": url,
        # Clear inherited exceptions so every request reaches rules.yaml.
        "NO_PROXY": "",
    }
    env.update(delta)
    return env, delta


def proxy_probe_target(cfg):
    p = cfg["proxy"]
    return p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086)


def firefox_profile_dir(app) -> Path:
    raw = str(app.get("id") or app.get("name") or "firefox")
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", raw).strip("._") or "firefox"
    return PROFILES_DIR / safe_id


def _has_firefox_profile_arg(tokens: list[str]) -> bool:
    for tok in tokens:
        low = tok.lower()
        if low in ("-profile", "--profile", "-p") or low.startswith("--profile="):
            return True
    return False


def is_firefox_profile_locked(profile_dir: Path) -> bool:
    lock_file = profile_dir / "parent.lock"
    if os.name != "nt" or _kernel32 is None or not lock_file.is_file():
        return False
    ctypes.set_last_error(0)
    handle = _kernel32.CreateFileW(
        str(lock_file),
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle and handle != INVALID_HANDLE_VALUE:
        _kernel32.CloseHandle(handle)
        return False
    err = ctypes.get_last_error()
    return err in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_ACCESS_DENIED)


def build_firefox_user_js(cfg) -> tuple[str, str]:
    p = cfg["proxy"]
    if not p.get("enabled", True):
        text = (
            "// Generated by DroidBridge - proxy injection disabled\n"
            'user_pref("network.proxy.type", 0);\n'
        )
        return text, "type=0 (直连，代理注入已关闭)"

    host = str(p.get("listen_host", "127.0.0.1")).strip()
    port = int(p.get("listen_port", 10086))
    lines = [
        "// Generated by DroidBridge - updated on each launch",
        'user_pref("network.proxy.type", 1);',
        f'user_pref("network.proxy.http", {json.dumps(host)});',
        f'user_pref("network.proxy.http_port", {port});',
        f'user_pref("network.proxy.ssl", {json.dumps(host)});',
        f'user_pref("network.proxy.ssl_port", {port});',
        'user_pref("network.proxy.share_proxy_settings", true);',
        'user_pref("network.proxy.socks", "");',
        'user_pref("network.proxy.socks_port", 0);',
        'user_pref("network.proxy.no_proxies_on", "");',
        'user_pref("network.proxy.allow_hijacking_localhost", false);',
    ]
    summary = f"type=1 (manual) | http/ssl={host}:{port}"
    return "\n".join(lines) + "\n", summary


def write_firefox_user_js(profile_dir: Path, content: str):
    profile_dir.mkdir(parents=True, exist_ok=True)
    tmp = profile_dir / "user.js.tmp"
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(profile_dir / "user.js")


def _firefox_appdata_root(exe_path: str = "", appdata_dir: str = "") -> Path | None:
    base = appdata_dir or os.environ.get("APPDATA", "")
    if not base:
        return None
    stem = Path(exe_path).stem.lower() if exe_path else ""
    rel_map = {
        "librewolf": ("LibreWolf",),
        "waterfox": ("Waterfox",),
        "floorp": ("Floorp",),
        "zen": ("zen",),
        "thunderbird": ("Thunderbird",),
        "seamonkey": ("Mozilla", "SeaMonkey"),
    }
    return Path(base).joinpath(*rel_map.get(stem, ("Mozilla", "Firefox")))


def discover_firefox_default_profile(exe_path: str = "", appdata_dir: str = "") -> Path | None:
    root = _firefox_appdata_root(exe_path, appdata_dir=appdata_dir)
    if root is None or not root.is_dir():
        return None

    candidates: list[Path] = []
    profiles_ini = root / "profiles.ini"
    installs_ini = root / "installs.ini"

    def _resolve_entry(raw_path: str, is_relative: str = "1") -> Path | None:
        raw = str(raw_path or "").strip()
        if not raw:
            return None
        p = Path(raw)
        if str(is_relative or "1").strip() == "0" or p.is_absolute():
            return p
        return root / raw

    def _read_ini(path: Path):
        parser = configparser.RawConfigParser()
        parser.optionxform = str
        if path.is_file():
            try:
                parser.read(path, encoding="utf-8-sig")
            except (OSError, configparser.Error):
                pass
        return parser

    p_ini = _read_ini(profiles_ini)
    i_ini = _read_ini(installs_ini)

    for sec in p_ini.sections():
        if sec.startswith("Install") and p_ini.has_option(sec, "Default"):
            cand = _resolve_entry(p_ini.get(sec, "Default"), "1")
            if cand is not None:
                candidates.append(cand)

    for sec in i_ini.sections():
        if i_ini.has_option(sec, "Default"):
            cand = _resolve_entry(i_ini.get(sec, "Default"), "1")
            if cand is not None:
                candidates.append(cand)

    for sec in p_ini.sections():
        if sec.startswith("Profile") and p_ini.get(sec, "Default", fallback="").strip() == "1":
            cand = _resolve_entry(
                p_ini.get(sec, "Path", fallback=""),
                p_ini.get(sec, "IsRelative", fallback="1"),
            )
            if cand is not None:
                candidates.append(cand)

    profiles_sub = root / "Profiles"
    if profiles_sub.is_dir():
        globbed = [
            p for p in profiles_sub.iterdir()
            if p.is_dir() and (p.name.endswith(".default-release") or p.name.endswith(".default"))
        ]
        def _profile_mtime(p: Path) -> float:
            for marker in ("places.sqlite", "prefs.js"):
                f = p / marker
                if f.is_file():
                    try:
                        return f.stat().st_mtime
                    except OSError:
                        pass
            try:
                return p.stat().st_mtime
            except OSError:
                return 0.0
        globbed.sort(key=_profile_mtime, reverse=True)
        candidates.extend(globbed)

    for cand in candidates:
        if cand.is_dir():
            return cand
    return None


def sync_firefox_profile(app: dict, cfg: dict, source_dir: Path | None = None) -> dict:
    if effective_kind(app) != "firefox":
        return {"ok": False, "error": "该应用不是 Firefox / Gecko 类型"}
    if _has_firefox_profile_arg(split_args(app.get("args", ""))):
        return {"ok": False, "error": "已通过启动参数自定义 -profile，无法自动同步"}

    src = source_dir if source_dir is not None else discover_firefox_default_profile(expand(app.get("exe", "")))
    if src is None or not src.is_dir():
        return {"ok": False, "error": "未找到本机默认 Firefox 配置目录"}

    dst = firefox_profile_dir(app)
    try:
        if src.resolve() == dst.resolve():
            return {"ok": False, "error": "源配置目录与目标配置目录相同"}
    except OSError:
        pass

    if is_firefox_profile_locked(dst):
        return {"ok": False, "error": "代理版 Firefox 正在运行，请先关闭通过 DroidBridge 打开的窗口后再同步"}
    if is_firefox_profile_locked(src):
        return {"ok": False, "error": "常规 Firefox 正在运行，请先关闭日常 Firefox 窗口后再同步，避免数据损坏"}

    dst.parent.mkdir(parents=True, exist_ok=True)
    staging = dst.parent / f"{dst.name}.sync_tmp"
    backup = dst.parent / f"{dst.name}.sync_bak"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    if backup.exists():
        shutil.rmtree(backup, ignore_errors=True)

    ignore_names = {
        "parent.lock",
        "lock",
        ".parentlock",
        "crashes",
        "minidumps",
        "saved-telemetry-pings",
        "shader-cache",
        "addonStartup.json.lz4",
        "compatibility.ini",
    }

    def _ignore(dirpath, names):
        if Path(dirpath) == src:
            return [n for n in names if n in ignore_names]
        return []

    try:
        shutil.copytree(src, staging, ignore=_ignore)
        src_str = str(src)
        dst_str = str(dst)
        src_escaped = src_str.replace("\\", "\\\\")
        dst_escaped = dst_str.replace("\\", "\\\\")
        src_uri = src.as_uri()
        dst_uri = dst.as_uri()

        for fname in ("pkcs11.txt", "extensions.json"):
            fpath = staging / fname
            if fpath.is_file():
                text = fpath.read_text(encoding="utf-8", errors="replace")
                updated_text = (
                    text.replace(src_escaped, dst_escaped)
                    .replace(src_str, dst_str)
                    .replace(src_uri, dst_uri)
                )
                if updated_text != text:
                    fpath.write_text(updated_text, encoding="utf-8")

        user_js, prefs_summary = build_firefox_user_js(cfg)
        write_firefox_user_js(staging, user_js)

        if dst.exists():
            dst.replace(backup)
        staging.replace(dst)
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
    except Exception as exc:
        if backup.exists() and not dst.exists():
            try:
                backup.replace(dst)
            except OSError:
                pass
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        return {"ok": False, "error": "同步配置失败：%s" % exc}

    ext_dir = dst / "extensions"
    ext_count = len(list(ext_dir.iterdir())) if ext_dir.is_dir() else 0
    return {
        "ok": True,
        "source": str(src),
        "target": str(dst),
        "extensions": ext_count,
        "prefs": prefs_summary,
        "message": f"已同步本机配置（含 {ext_count} 个扩展）",
    }


def open_firefox_profile_dir(app: dict) -> dict:
    if effective_kind(app) != "firefox":
        return {"ok": False, "error": "该应用不是 Firefox / Gecko 类型"}
    profile_dir = firefox_profile_dir(app)
    profile_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        os.startfile(str(profile_dir))
    return {"ok": True, "path": str(profile_dir)}


def build_cmd(app, cfg):
    exe = expand(app["exe"])
    cmd = [exe] + split_args(app.get("args", ""))
    kind = effective_kind(app)
    injected = []
    if cfg["proxy"].get("enabled", True) and kind == "electron":
        url = proxy_url(cfg)
        flags = " ".join(cmd[1:])
        if "--proxy-server" not in flags:
            cmd.append("--proxy-server=" + url)
            injected.append("--proxy-server")
    elif kind == "firefox":
        user_args = cmd[1:]
        lower_args = [a.lower() for a in user_args]
        if not _has_firefox_profile_arg(user_args):
            profile_dir = firefox_profile_dir(app)
            if "-no-remote" not in lower_args and "--no-remote" not in lower_args:
                cmd.append("-no-remote")
                injected.append("-no-remote")
            cmd.extend(["-profile", str(profile_dir)])
            injected.append("-profile")
            injected.append("user.js" if cfg["proxy"].get("enabled", True) else "user.js(直连)")
    return cmd, kind, injected


def launch_app(app, cfg, dry_run=False, force=False):
    exe = expand(app["exe"])
    result = {"app": app.get("name", ""), "kind": None}
    if not Path(exe).is_file():
        result.update(ok=False, error="找不到可执行文件: " + exe)
        return result

    p = cfg["proxy"]
    online, latency = probe_proxy(*proxy_probe_target(cfg))
    if p.get("enabled", True) and not online:
        target_host, target_port = proxy_probe_target(cfg)
        reason = "本地分流入口 %s:%s 未启动" % (target_host, target_port)
        result.update(
            ok=False,
            error=reason,
        )
        return result

    cmd, kind, injected = build_cmd(app, cfg)
    env, delta = build_env(cfg)
    running = running_lines(exe)
    result.update(kind=kind, cmd=cmd, env=delta, injected=injected,
                  already_running=len(running), proxy_latency_ms=latency)

    managed_ff_profile = None
    ff_user_js_text = None
    if kind == "firefox":
        user_args = split_args(app.get("args", ""))
        if not _has_firefox_profile_arg(user_args):
            managed_ff_profile = firefox_profile_dir(app)
            profile_locked = is_firefox_profile_locked(managed_ff_profile)
            ff_user_js_text, prefs_summary = build_firefox_user_js(cfg)
            result.update(
                firefox_profile=str(managed_ff_profile),
                firefox_prefs=prefs_summary,
                profile_running=profile_locked,
            )
        else:
            profile_locked = False
            result.update(profile_running=False)
    else:
        profile_locked = False

    # Preview must always work, even when the app is already running.
    if dry_run:
        result.update(ok=True, dry_run=True, message="预览（未真正启动）")
        return result

    if kind == "electron" and running and not force:
        result.update(
            ok=False, code="already_running",
            error="%s 已在运行：Electron / Chromium 单实例锁会让新启动转发给旧进程，本次代理配置不会生效。请先完全退出。" % app["name"],
        )
        return result

    if kind == "firefox" and managed_ff_profile is not None and profile_locked and not force:
        result.update(
            ok=False, code="already_running",
            error="%s 的独立代理配置正在运行中：请先关闭通过 DroidBridge 打开的该窗口，否则新的代理设置不会生效。" % app["name"],
        )
        return result

    if kind == "firefox" and managed_ff_profile is not None and ff_user_js_text is not None:
        try:
            write_firefox_user_js(managed_ff_profile, ff_user_js_text)
        except OSError as exc:
            result.update(ok=False, error="写入 Firefox 代理配置失败: %s" % exc)
            return result

    try:
        subprocess.Popen(
            cmd,
            env=env,
            cwd=str(Path(exe).parent),
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    except Exception as exc:
        result.update(ok=False, error="启动失败: %s" % exc)
        return result

    invalidate_process_cache()
    result.update(ok=True, message="已启动 %s（%s）" % (app["name"], kind))
    return result


def make_state():
    cfg = load_config()
    p = cfg["proxy"]
    online, latency = probe_proxy(*proxy_probe_target(cfg))
    route_table = RouteTable.load(cfg)
    upstream_target = route_table.upstream if not route_table.error else (p["host"], p["port"])
    upstream_online, upstream_latency = probe_proxy(*upstream_target)
    apps = []
    for app in cfg["apps"]:
        exe = expand(app["exe"])
        kind, evidence = detect_kind(exe)
        eff_kind = effective_kind(app)
        has_custom_profile = _has_firefox_profile_arg(split_args(app.get("args", "")))
        ff_dir = firefox_profile_dir(app) if (eff_kind == "firefox" and not has_custom_profile) else None
        profile_running = is_firefox_profile_locked(ff_dir) if ff_dir is not None else False
        apps.append({
            **app,
            "resolved_exe": exe,
            "exists": Path(exe).is_file(),
            "detected_kind": kind,
            "effective_kind": eff_kind,
            "native_browser": is_native_browser(exe),
            "evidence": evidence,
            "running": bool(running_lines(exe)),
            "profile_running": profile_running,
            "firefox_profile_dir": str(ff_dir) if ff_dir is not None else "",
            "firefox_profile_exists": bool(ff_dir and ff_dir.is_dir()),
        })
    return {
        "proxy": p,
        "adb_path": str(cfg.get("adb_path") or ""),
        "adb_serial": str(cfg.get("adb_serial") or ""),
        "tray_active": is_tray_active(),
        "proxy_url": proxy_url(cfg),
        "proxy_upstream_url": "http://%s:%s" % upstream_target,
        "router_listen": "%s:%s" % (p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086)),
        "routing_rules_file": str(route_table.source) if route_table else "",
        "routing_rules_error": "; ".join(x for x in [route_table.error if route_table else "", _proxy_error] if x),
        "proxy_events": list(_proxy_events),
        "active_connections": _conn_registry.count(),
        "proxy_online": online,
        "proxy_latency_ms": latency,
        "proxy_upstream_online": upstream_online,
        "proxy_upstream_latency_ms": upstream_latency,
        "apps": apps,
        "phone_apps": list(cfg.get("phone_apps") or []),
        "phone_sessions": _phone_mirror.list_sessions(),
    }


def find_app(cfg, app_id):
    for app in cfg["apps"]:
        if app["id"] == app_id:
            return app
    return None


# ----------------------------------------------------------- native picker ----

OFN_FILEMUSTEXIST = 0x00001000
OFN_PATHMUSTEXIST = 0x00000800
OFN_NOCHANGEDIR = 0x00000008
OFN_EXPLORER = 0x00080000
OFN_DONTADDTORECENT = 0x02000000


class OPENFILENAMEW(ctypes.Structure):
    _fields_ = [
        ("lStructSize", wintypes.DWORD),
        ("hwndOwner", wintypes.HWND),
        ("hInstance", wintypes.HINSTANCE),
        ("lpstrFilter", ctypes.c_void_p),
        ("lpstrCustomFilter", ctypes.c_void_p),
        ("nMaxCustFilter", wintypes.DWORD),
        ("nFilterIndex", wintypes.DWORD),
        ("lpstrFile", ctypes.c_void_p),
        ("nMaxFile", wintypes.DWORD),
        ("lpstrFileTitle", wintypes.LPWSTR),
        ("nMaxFileTitle", wintypes.DWORD),
        ("lpstrInitialDir", wintypes.LPCWSTR),
        ("lpstrTitle", wintypes.LPCWSTR),
        ("Flags", wintypes.DWORD),
        ("nFileOffset", wintypes.WORD),
        ("nFileExtension", wintypes.WORD),
        ("lpstrDefExt", wintypes.LPCWSTR),
        ("lCustData", wintypes.LPARAM),
        ("lpfnHook", ctypes.c_void_p),
        ("lpTemplateName", wintypes.LPCWSTR),
        ("pvReserved", ctypes.c_void_p),
        ("dwReserved", wintypes.DWORD),
        ("FlagsEx", wintypes.DWORD),
    ]


def pick_exe_file(initial_path: str = ""):
    if os.name != "nt":
        return {"ok": False, "error": "仅支持 Windows 原生文件选择器"}
    if not _picker_lock.acquire(blocking=False):
        return {"ok": False, "busy": True, "error": "文件选择窗口已打开"}

    hr = -1
    ole32 = ctypes.WinDLL("ole32")
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None

    comdlg32 = ctypes.WinDLL("comdlg32")
    comdlg32.GetOpenFileNameW.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
    comdlg32.GetOpenFileNameW.restype = wintypes.BOOL
    comdlg32.CommDlgExtendedError.argtypes = []
    comdlg32.CommDlgExtendedError.restype = wintypes.DWORD

    try:
        hr = ole32.CoInitializeEx(None, 0x2)  # COINIT_APARTMENTTHREADED

        filter_buf = ctypes.create_unicode_buffer("可执行文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0\0")
        file_buf = ctypes.create_unicode_buffer(4096)

        initial_dir = None
        expanded = expand(initial_path)
        if expanded:
            p = Path(expanded)
            if p.is_dir():
                initial_dir = str(p)
            elif p.parent.is_dir():
                initial_dir = str(p.parent)

        ofn = OPENFILENAMEW()
        ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
        ofn.lpstrFilter = ctypes.addressof(filter_buf)
        ofn.nFilterIndex = 1
        ofn.lpstrFile = ctypes.addressof(file_buf)
        ofn.nMaxFile = len(file_buf)
        ofn.lpstrInitialDir = initial_dir
        ofn.lpstrTitle = "选择应用可执行文件"
        ofn.Flags = (
            OFN_FILEMUSTEXIST
            | OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR
            | OFN_EXPLORER
            | OFN_DONTADDTORECENT
        )

        if comdlg32.GetOpenFileNameW(ctypes.byref(ofn)):
            return {"ok": True, "path": file_buf.value}

        err = comdlg32.CommDlgExtendedError()
        if err:
            return {"ok": False, "error": "文件选择器出错 (0x%x)" % err}
        return {"ok": True, "cancelled": True, "path": ""}
    finally:
        if hr in (0, 1):
            ole32.CoUninitialize()
        _picker_lock.release()


# ----------------------------------------------------------- exe icon png ----

class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


class BITMAP(ctypes.Structure):
    _fields_ = [
        ("bmType", ctypes.c_long),
        ("bmWidth", ctypes.c_long),
        ("bmHeight", ctypes.c_long),
        ("bmWidthBytes", ctypes.c_long),
        ("bmPlanes", wintypes.WORD),
        ("bmBitsPixel", wintypes.WORD),
        ("bmBits", ctypes.c_void_p),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


if os.name == "nt":
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _user32.PrivateExtractIconsW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HICON),
        ctypes.POINTER(wintypes.UINT),
        wintypes.UINT,
        wintypes.UINT,
    ]
    _user32.PrivateExtractIconsW.restype = wintypes.UINT
    _user32.GetIconInfo.argtypes = [wintypes.HICON, ctypes.POINTER(ICONINFO)]
    _user32.GetIconInfo.restype = wintypes.BOOL
    _user32.DestroyIcon.argtypes = [wintypes.HICON]
    _user32.DestroyIcon.restype = wintypes.BOOL
    _user32.GetDC.argtypes = [wintypes.HWND]
    _user32.GetDC.restype = wintypes.HDC
    _user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _user32.ReleaseDC.restype = ctypes.c_int

    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _shell32.ExtractIconExW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HICON),
        ctypes.POINTER(wintypes.HICON),
        wintypes.UINT,
    ]
    _shell32.ExtractIconExW.restype = wintypes.UINT

    _gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    _gdi32.GetObjectW.argtypes = [wintypes.HGDIOBJ, ctypes.c_int, ctypes.c_void_p]
    _gdi32.GetObjectW.restype = ctypes.c_int
    _gdi32.GetDIBits.argtypes = [
        wintypes.HDC,
        wintypes.HBITMAP,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.UINT,
    ]
    _gdi32.GetDIBits.restype = ctypes.c_int
    _gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    _gdi32.DeleteObject.restype = wintypes.BOOL
else:
    _user32 = None
    _shell32 = None
    _gdi32 = None


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def _encode_png_rgba(width: int, height: int, rgba: bytearray) -> bytes:
    stride = width * 4
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)
        start = y * stride
        raw_rows.extend(rgba[start:start + stride])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw_rows), 6))
        + _png_chunk(b"IEND", b"")
    )


def _hicon_to_png(hicon) -> bytes | None:
    info = ICONINFO()
    if not _user32.GetIconInfo(hicon, ctypes.byref(info)):
        return None
    try:
        if not info.hbmColor:
            return None
        bm = BITMAP()
        if not _gdi32.GetObjectW(info.hbmColor, ctypes.sizeof(BITMAP), ctypes.byref(bm)):
            return None
        w, h = int(bm.bmWidth), abs(int(bm.bmHeight))
        if w <= 0 or h <= 0 or w > 512 or h > 512:
            return None

        hdc = _user32.GetDC(None)
        if not hdc:
            return None
        try:
            bmi = BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.biWidth = w
            bmi.biHeight = -h  # top-down DIB
            bmi.biPlanes = 1
            bmi.biBitCount = 32
            bmi.biCompression = 0  # BI_RGB

            buf_size = w * h * 4
            raw = (ctypes.c_ubyte * buf_size)()
            if not _gdi32.GetDIBits(hdc, info.hbmColor, 0, h, raw, ctypes.byref(bmi), 0):
                return None
            bgra = bytearray(raw)

            if not any(bgra[3::4]) and info.hbmMask:
                mask_raw = (ctypes.c_ubyte * buf_size)()
                m_bmi = BITMAPINFOHEADER()
                m_bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                m_bmi.biWidth = w
                m_bmi.biHeight = -h
                m_bmi.biPlanes = 1
                m_bmi.biBitCount = 32
                m_bmi.biCompression = 0
                if _gdi32.GetDIBits(hdc, info.hbmMask, 0, h, mask_raw, ctypes.byref(m_bmi), 0):
                    for i in range(0, buf_size, 4):
                        bgra[i + 3] = 255 if mask_raw[i] == 0 else 0
                else:
                    for i in range(0, buf_size, 4):
                        bgra[i + 3] = 255

            rgba = bytearray(buf_size)
            rgba[0::4] = bgra[2::4]
            rgba[1::4] = bgra[1::4]
            rgba[2::4] = bgra[0::4]
            rgba[3::4] = bgra[3::4]
            return _encode_png_rgba(w, h, rgba)
        finally:
            _user32.ReleaseDC(None, hdc)
    finally:
        if info.hbmColor:
            _gdi32.DeleteObject(info.hbmColor)
        if info.hbmMask:
            _gdi32.DeleteObject(info.hbmMask)


def extract_exe_icon_png(exe_path: str, size: int = 64) -> bytes | None:
    if os.name != "nt" or _user32 is None or _shell32 is None or _gdi32 is None:
        return None
    p = Path(exe_path)
    try:
        if not p.is_file():
            return None
        st = p.stat()
    except OSError:
        return None

    norm = os.path.normcase(os.path.abspath(str(p)))
    cache_key = (norm, st.st_mtime_ns)
    with _icon_lock:
        if cache_key in _icon_cache:
            return _icon_cache[cache_key]

    png_bytes = None
    hicon = wintypes.HICON()
    icon_id = wintypes.UINT()
    count = _user32.PrivateExtractIconsW(
        str(p), 0, size, size, ctypes.byref(hicon), ctypes.byref(icon_id), 1, 0
    )
    if count in (0, 0xFFFFFFFF) or not hicon.value:
        hicon = wintypes.HICON()
        count = _shell32.ExtractIconExW(str(p), 0, ctypes.byref(hicon), None, 1)
    if count not in (0, 0xFFFFFFFF) and hicon.value:
        try:
            png_bytes = _hicon_to_png(hicon)
        finally:
            _user32.DestroyIcon(hicon)

    with _icon_lock:
        if len(_icon_cache) > 64:
            _icon_cache.clear()
        _icon_cache[cache_key] = png_bytes
    return png_bytes


# ------------------------------------------------------------ quit control ----

_shutdown_lock = threading.Lock()


def _do_shutdown():
    with _shutdown_lock:
        _phone_mirror.shutdown()
        if _server:
            _server.shutdown()
        stop_proxy_server()


def _force_shutdown():
    close_ui_windows()
    _do_shutdown()


def cancel_pending_quit():
    global _quit_timer
    with _quit_lock:
        if _quit_timer is not None:
            _quit_timer.cancel()
            _quit_timer = None


def schedule_quit(delay=3.0):
    global _quit_timer
    with _quit_lock:
        if _quit_timer is not None:
            _quit_timer.cancel()
        timer = threading.Timer(delay, _do_shutdown)
        timer.daemon = True
        timer.start()
        _quit_timer = timer


# --------------------------------------------------------- local proxy ----

PROXY_BUFFER = 64 * 1024
PROXY_CONNECT_TIMEOUT = 12
PROXY_IDLE_TIMEOUT = 300
PROXY_MAX_BODY_BYTES = 64 * 1024 * 1024
PROXY_MAX_HEADER_BYTES = 256 * 1024


def _host_port(value, default_port, require_port=False):
    text = str(value or "").strip()
    if not text or any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError("无效的代理目标")
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            raise ValueError("无效的 IPv6 主机地址")
        host = text[1:closing]
        suffix = text[closing + 1:]
        if suffix and not suffix.startswith(":"):
            raise ValueError("无效的主机端口")
        port_text = suffix[1:] if suffix else ""
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
        if not port_text:
            raise ValueError("无效的主机端口")
    else:
        host, port_text = text, ""
    host = host.strip()
    if not host or any(char in host for char in "/\\@"):
        raise ValueError("无效的代理目标主机")
    if require_port and not port_text:
        raise ValueError("CONNECT 目标必须包含端口")
    try:
        port = int(port_text or default_port)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("无效的代理目标端口")
    if not 1 <= port <= 65535:
        raise ValueError("无效的代理目标端口")
    return host, port


def _proxy_target(handler):
    target = handler.path
    parsed = urlsplit(target)
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("仅支持 HTTP 和 HTTPS 代理目标")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("无效的 HTTP 代理目标")
        if parsed.fragment:
            raise ValueError("HTTP 代理目标不能包含 fragment")
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            raise ValueError("无效的 HTTP 代理目标端口")
        host = parsed.hostname
        return host, port, parsed
    if target.startswith("//"):
        raise ValueError("无效的 HTTP 请求目标")
    host_header = handler.headers.get("Host", "")
    host, port = _host_port(host_header, 80)
    return host, port, None


def _recv_headers(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(PROXY_BUFFER)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > PROXY_MAX_HEADER_BYTES:
            raise ValueError("代理响应头过大")
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        raise OSError("代理响应缺少完整响应头")
    end = marker + 4
    return bytes(data[:end]), bytes(data[end:])


def _read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _touch_proxy_activity():
    global _last_proxy_activity
    _last_proxy_activity = time.time()


def _format_proxy_error(exc, action="PROXY", default_msg="代理请求失败"):
    if isinstance(exc, ValueError):
        return str(exc) or default_msg
    if isinstance(exc, TimeoutError):
        return "连接上游超时（请检查手机 Clash / ADB）" if action == "PROXY" else "直连目标超时"
    if isinstance(exc, ConnectionRefusedError):
        return "上游代理拒绝连接（请检查手机 Clash 或 ADB 转发）" if action == "PROXY" else "目标服务器拒绝连接"
    if isinstance(exc, socket.gaierror):
        return "域名解析失败"
    if isinstance(exc, ConnectionResetError):
        return "连接被对端重置"
    if isinstance(exc, OSError):
        text = str(exc)
        if any(ord(ch) > 127 for ch in text):
            return text
        return f"{default_msg}：{text}" if text else default_msg
    return default_msg


def _read_chunked_body(stream, max_bytes=PROXY_MAX_BODY_BYTES) -> bytes:
    body = bytearray()
    while True:
        line = stream.readline(65536)
        if not line.endswith(b"\r\n"):
            raise ValueError("分块请求体格式无效")
        size_part = line[:-2].split(b";", 1)[0].strip()
        if not size_part:
            raise ValueError("分块请求体大小无效")
        try:
            chunk_size = int(size_part, 16)
        except ValueError:
            raise ValueError("分块请求体大小无效")
        if chunk_size < 0 or len(body) + chunk_size > max_bytes:
            raise ValueError("请求体超过代理限制")
        if chunk_size == 0:
            trailer_bytes = 0
            while True:
                trailer = stream.readline(65536)
                if not trailer:
                    raise ValueError("分块请求体未正常结束")
                trailer_bytes += len(trailer)
                if trailer_bytes > PROXY_MAX_HEADER_BYTES:
                    raise ValueError("分块请求尾部过大")
                if trailer == b"\r\n":
                    break
            break
        chunk = _read_exact(stream, chunk_size)
        if len(chunk) != chunk_size:
            raise ValueError("分块请求体未完整到达")
        crlf = _read_exact(stream, 2)
        if crlf != b"\r\n":
            raise ValueError("分块请求体缺少结束换行")
        body.extend(chunk)
    return bytes(body)


_conn_registry = conn_tracker.ConnectionRegistry()


def _relay_sockets(left, right, initial_right_to_left=b"", conn=None):
    if initial_right_to_left:
        left.sendall(initial_right_to_left)
        if conn is not None:
            conn.add_rx(len(initial_right_to_left))
        _touch_proxy_activity()
    sockets = [left, right]
    last_activity = time.monotonic()
    while sockets and time.monotonic() - last_activity < PROXY_IDLE_TIMEOUT:
        readable, _, _ = select.select(sockets, [], [], 5)
        if not readable:
            continue
        for source in readable:
            data = source.recv(PROXY_BUFFER)
            if not data:
                destination = right if source is left else left
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sockets.remove(source)
                continue
            destination = right if source is left else left
            destination.sendall(data)
            if conn is not None:
                if source is left:
                    conn.add_tx(len(data))
                else:
                    conn.add_rx(len(data))
            last_activity = time.monotonic()
            _touch_proxy_activity()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    rbufsize = 0

    def log_message(self, fmt, *args):
        pass

    def _route(self, route_table, host):
        rule_for = getattr(route_table, "rule_for", None)
        if callable(rule_for):
            rule = rule_for(host)
            return rule.action, getattr(rule, "label", "")
        return route_table.action_for(host), ""

    def _error(self, code, message):
        body = ("DroidBridge: " + message + "\n").encode("utf-8", errors="replace")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def _fail(self, code, host="", action="ERROR", rule="", message="代理请求失败"):
        _record_proxy_event(host or "unknown", action, False, message, rule=rule)
        self._error(code, message)

    def _table(self):
        table = self.server.route_table()
        if getattr(table, "error", ""):
            self._fail(503, action="ERROR", message="分流规则不可用")
            return None
        return table

    def _is_self_target(self, host, port):
        local_host, local_port = self.server.server_address[:2]
        normalized = _normalize_target_host(host)
        local_names = {_normalize_target_host(local_host), "localhost", "127.0.0.1", "::1"}
        return normalized in local_names and port == local_port

    def _connect(self, host, port):
        if self._is_self_target(host, port):
            raise ValueError("代理目标不能指向自身")
        return socket.create_connection((host, port), timeout=PROXY_CONNECT_TIMEOUT)

    def _upstream_connect(self, host, port, upstream):
        sock = self._connect(*upstream)
        request = (
            "CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
            % (self._connect_target(host, port), self._connect_target(host, port))
        ).encode("ascii")
        sock.sendall(request)
        response, initial = _recv_headers(sock)
        status_line = response.split(b"\r\n", 1)[0]
        try:
            status = int(status_line.split()[1])
        except (IndexError, ValueError):
            sock.close()
            raise OSError("手机代理返回了无效的 CONNECT 响应")
        if not 200 <= status < 300:
            sock.close()
            raise OSError("手机代理拒绝 CONNECT: %s" % status_line.decode("latin-1", errors="replace"))
        return sock, initial

    @staticmethod
    def _connect_target(host, port):
        return "[%s]:%s" % (host, port) if ":" in host else "%s:%s" % (host, port)

    def do_CONNECT(self):
        _touch_proxy_activity()
        host = ""
        action = "ERROR"
        rule = ""
        response_started = False
        upstream = None
        initial = b""
        try:
            table = self._table()
            if table is None:
                return
            host, port = _host_port(self.path, 443, require_port=True)
            action, rule = self._route(table, host)
            if action == "DIRECT":
                upstream = self._connect(host, port)
            else:
                if self._is_self_target(*table.upstream):
                    raise ValueError("上游代理不能指向自身")
                upstream, initial = self._upstream_connect(host, port, table.upstream)
            upstream.settimeout(PROXY_IDLE_TIMEOUT)
            try:
                self.connection.settimeout(PROXY_IDLE_TIMEOUT)
            except OSError:
                pass
            self.send_response(200, "Connection Established")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.close_connection = True
            response_started = True
            _record_proxy_event(host, action, rule=rule)
            conn = _conn_registry.register(
                host=host,
                port=port,
                protocol="HTTPS",
                action=action,
                rule=rule,
                client_addr=self.client_address,
                server_port=self.server.server_address[1],
                left_sock=self.connection,
                right_sock=upstream,
            )
            try:
                _relay_sockets(self.connection, upstream, initial, conn=conn)
            finally:
                _conn_registry.unregister(conn.id)
                upstream.close()
        except (OSError, ValueError, TimeoutError) as exc:
            if not response_started:
                msg = _format_proxy_error(exc, action, "无法建立代理隧道")
                self._fail(502, host, action, rule, msg)

    def _request_body(self):
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        encodings = [part.strip() for part in transfer_encoding.split(",") if part.strip()]
        if encodings == ["chunked"] or (encodings and encodings[-1] == "chunked" and all(e == "identity" for e in encodings[:-1])):
            return _read_chunked_body(self.rfile), True
        if encodings and encodings != ["identity"]:
            raise ValueError("不支持的 Transfer-Encoding：%s" % transfer_encoding)
        if self.headers.get("Expect"):
            raise ValueError("暂不支持 Expect 请求")
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return b"", False
        try:
            length = int(raw_length)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("无效的 Content-Length")
        if length < 0 or length > PROXY_MAX_BODY_BYTES:
            raise ValueError("请求体超过代理限制")
        body = _read_exact(self.rfile, length)
        if len(body) != length:
            raise ValueError("请求体未完整到达")
        return body, False

    def _request_bytes(self, target, host, port, parsed, body, absolute, from_chunked=False):
        if parsed is not None and parsed.scheme.lower() == "https":
            raise ValueError("HTTPS 请求必须使用 CONNECT")
        if absolute:
            request_target = target if parsed is not None else (
                "http://%s%s" % (self._connect_target(host, port), target or "/")
            )
        elif parsed is not None:
            request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        else:
            request_target = target or "/"
        lines = ["%s %s %s\r\n" % (self.command, request_target, self.request_version)]
        seen_host = False
        seen_content_length = False
        connection_tokens = set()
        for value in self.headers.get_all("Connection", []):
            connection_tokens.update(item.strip().lower() for item in value.split(",") if item.strip())
        hop_by_hop = {
            "connection", "keep-alive", "proxy-connection", "proxy-authorization",
            "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
        } | connection_tokens
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in hop_by_hop:
                continue
            if lower == "host":
                seen_host = True
            elif lower == "content-length":
                seen_content_length = True
            lines.append("%s: %s\r\n" % (key, value))
        if not seen_host:
            lines.append("Host: %s\r\n" % self._connect_target(host, port))
        if from_chunked and not seen_content_length:
            lines.append("Content-Length: %d\r\n" % len(body))
        lines.append("Connection: close\r\n\r\n")
        return "".join(lines).encode("latin-1", errors="replace") + body

    def do_GET(self):
        self._forward_http()

    def do_POST(self):
        self._forward_http()

    def do_PUT(self):
        self._forward_http()

    def do_PATCH(self):
        self._forward_http()

    def do_DELETE(self):
        self._forward_http()

    def do_HEAD(self):
        self._forward_http()

    def do_OPTIONS(self):
        self._forward_http()

    def do_TRACE(self):
        self._forward_http()

    def do_MKCOL(self):
        self._forward_http()

    def do_COPY(self):
        self._forward_http()

    def do_MOVE(self):
        self._forward_http()

    def do_LOCK(self):
        self._forward_http()

    def do_UNLOCK(self):
        self._forward_http()

    def do_PROPFIND(self):
        self._forward_http()

    def do_PROPPATCH(self):
        self._forward_http()

    def do_REPORT(self):
        self._forward_http()

    def do_MERGE(self):
        self._forward_http()

    def _forward_http(self):
        _touch_proxy_activity()
        upstream = None
        host = ""
        action = "ERROR"
        rule = ""
        response_started = False
        conn = None
        try:
            table = self._table()
            if table is None:
                return
            host, port, parsed = _proxy_target(self)
            action, rule = self._route(table, host)
            if action == "PROXY" and self._is_self_target(*table.upstream):
                raise ValueError("上游代理不能指向自身")
            body, from_chunked = self._request_body()
            request = self._request_bytes(
                self.path, host, port, parsed, body, absolute=(action == "PROXY"), from_chunked=from_chunked
            )
            upstream = self._connect(host, port) if action == "DIRECT" else self._connect(*table.upstream)
            upstream.settimeout(PROXY_IDLE_TIMEOUT)
            conn = _conn_registry.register(
                host=host,
                port=port,
                protocol="HTTP",
                action=action,
                rule=rule,
                client_addr=self.client_address,
                server_port=self.server.server_address[1],
                left_sock=self.connection,
                right_sock=upstream,
            )
            try:
                upstream.sendall(request)
                conn.add_tx(len(request))
                self.close_connection = True
                while True:
                    chunk = upstream.recv(PROXY_BUFFER)
                    if not chunk:
                        break
                    response_started = True
                    self.connection.sendall(chunk)
                    conn.add_rx(len(chunk))
                    _touch_proxy_activity()
                _record_proxy_event(host, action, rule=rule)
            finally:
                _conn_registry.unregister(conn.id)
        except (OSError, ValueError, TimeoutError) as exc:
            if not response_started and not (conn is not None and conn.closed_by_user):
                code = 400 if isinstance(exc, ValueError) else 502
                msg = _format_proxy_error(exc, action, "无法转发代理请求")
                self._fail(code, host, action, rule, msg)
        finally:
            if upstream is not None:
                upstream.close()


def _file_sig(path: Path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _invalidate_proxy_route_cache():
    server = _proxy_server
    if server is not None and hasattr(server, "invalidate_route_cache"):
        server.invalidate_route_cache()


class ProxyServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self._route_lock = threading.Lock()
        self._cfg_cache_key = None
        self._cfg_cache = None
        self._route_cache_key = None
        self._route_cache_table = None
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def invalidate_route_cache(self):
        with self._route_lock:
            self._cfg_cache_key = None
            self._cfg_cache = None
            self._route_cache_key = None
            self._route_cache_table = None

    def route_table(self):
        cfg_path = CONFIG_PATH
        cfg_key = (str(cfg_path), _file_sig(cfg_path))
        with self._route_lock:
            if cfg_key == self._cfg_cache_key and self._cfg_cache is not None:
                cfg = self._cfg_cache
            else:
                cfg = load_config()
                self._cfg_cache_key = (str(cfg_path), _file_sig(cfg_path))
                self._cfg_cache = cfg

            r_path = rules_path(cfg)
            p = cfg.get("proxy", {})
            rt_key = (
                str(r_path),
                _file_sig(r_path),
                str(p.get("host") or ""),
                str(p.get("port") or ""),
                str(p.get("listen_port") or ""),
            )
            if rt_key == self._route_cache_key and self._route_cache_table is not None:
                return self._route_cache_table

            table = RouteTable.load(cfg)
            self._route_cache_key = (
                str(r_path),
                _file_sig(r_path),
                str(p.get("host") or ""),
                str(p.get("port") or ""),
                str(p.get("listen_port") or ""),
            )
            self._route_cache_table = table
            return table


def start_proxy_server(cfg):
    global _proxy_server, _proxy_thread, _proxy_error
    p = cfg.get("proxy", {})
    host = str(p.get("listen_host") or "127.0.0.1").strip()
    if host not in {"127.0.0.1", "localhost"}:
        _proxy_error = "分流服务只能监听本机地址"
        return
    try:
        port = int(p.get("listen_port") or 10086)
    except (TypeError, ValueError, OverflowError):
        _proxy_error = "分流入口端口无效"
        return
    if not (1 <= port <= 65535):
        _proxy_error = "分流入口端口必须是 1-65535 之间的整数"
        return
    try:
        _proxy_server = ProxyServer((host, port), ProxyHandler)
    except OSError as exc:
        _proxy_server = None
        _proxy_thread = None
        _proxy_error = "分流入口启动失败：%s" % exc
        return
    _proxy_error = ""
    _proxy_thread = threading.Thread(target=_proxy_server.serve_forever, daemon=True)
    _proxy_thread.start()


def stop_proxy_server():
    global _proxy_server, _proxy_thread
    _conn_registry.close_all()
    server = _proxy_server
    if server is None:
        return
    server.shutdown()
    server.server_close()
    _proxy_server = None
    _proxy_thread = None


def restart_proxy_server(cfg):
    stop_proxy_server()
    start_proxy_server(cfg)


# ---------------------------------------------------------------------- adb ----

ADB_TIMEOUT = 8
ADB_OUTPUT_LIMIT = 64 * 1024


class AdbError(Exception):
    """Raised when an adb invocation cannot complete."""


class AdbTool:
    """Manual ADB helper: inspect devices and forwards, never run automatically."""

    def __init__(self, cfg, timeout=ADB_TIMEOUT):
        self.cfg = cfg or {}
        self.timeout = timeout
        self._lock = threading.Lock()

    def resolve(self):
        """Return the argv prefix used to invoke adb, or None when unavailable.

        Precedence: configured adb_path -> system PATH -> bundled vendor/platform-tools/adb.
        """
        configured = str(self.cfg.get("adb_path") or "").strip()
        if configured:
            candidate = expand(configured)
            return [candidate] if os.path.isfile(candidate) else None
        found = shutil.which("adb")
        if found:
            return [found]
        bundled = str(BUNDLED_ADB_PATH)
        return [bundled] if os.path.isfile(bundled) else None

    def _source_for(self, argv):
        if not argv:
            return ""
        if str(self.cfg.get("adb_path") or "").strip():
            return "configured"
        try:
            if os.path.normcase(os.path.abspath(argv[0])) == os.path.normcase(os.path.abspath(str(BUNDLED_ADB_PATH))):
                return "bundled"
        except OSError:
            pass
        return "path"

    def run(self, args, timeout=None):
        argv = self.resolve()
        if argv is None:
            raise AdbError("未找到 adb 可执行文件，请在 ADB 设置里填写路径")
        eff_timeout = self.timeout if timeout is None else timeout
        with self._lock:
            try:
                proc = subprocess.run(
                    argv + list(args),
                    capture_output=True,
                    timeout=eff_timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired:
                raise AdbError("adb 命令超时（%s 秒）" % eff_timeout)
            except OSError as exc:
                raise AdbError("无法执行 adb：%s" % exc)
        out = proc.stdout.decode("utf-8", errors="replace")[:ADB_OUTPUT_LIMIT]
        err = proc.stderr.decode("utf-8", errors="replace")[:ADB_OUTPUT_LIMIT]
        return proc.returncode, out, err

    def devices(self):
        code, out, err = self.run(["devices", "-l"])
        if code != 0:
            raise AdbError(err.strip() or "adb devices 执行失败")
        devices = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            entry = {"serial": parts[0], "state": parts[1], "model": "", "product": "", "device": ""}
            for token in parts[2:]:
                key, sep, value = token.partition(":")
                if sep and key in entry:
                    entry[key] = value
            devices.append(entry)
        return devices

    def forwards(self):
        code, out, err = self.run(["forward", "--list"])
        if code != 0:
            raise AdbError(err.strip() or "adb forward --list 执行失败")
        rows = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            rows.append({"serial": parts[0], "local": parts[1], "remote": parts[2]})
        return rows

    def online_device(self, serial: str = ""):
        explicit = str(serial or "").strip()
        preferred = explicit or str(self.cfg.get("adb_serial") or "").strip()
        online = [device for device in self.devices() if device["state"] == "device"]
        if explicit:
            for device in online:
                if device["serial"] == explicit:
                    return device
            raise AdbError("指定设备 %s 未在线" % explicit)
        if preferred:
            for device in online:
                if device["serial"] == preferred:
                    return device
        return online[0] if online else None

    def upstream_port(self):
        try:
            return int(self.cfg.get("proxy", {}).get("port") or 5038)
        except (TypeError, ValueError, OverflowError):
            return 5038

    def state(self):
        preferred = str(self.cfg.get("adb_serial") or "").strip()
        result = {
            "ok": True,
            "adb_path": "",
            "adb_source": "",
            "adb_found": False,
            "devices": [],
            "forwards": [],
            "upstream_port": self.upstream_port(),
            "selected_serial": preferred,
            "error": "",
        }
        argv = self.resolve()
        if argv is None:
            result["error"] = "未找到 adb 可执行文件，请在 ADB 设置里填写路径"
            return result
        result["adb_found"] = True
        result["adb_path"] = argv[0]
        result["adb_source"] = self._source_for(argv)
        try:
            result["devices"] = self.devices()
            result["forwards"] = self.forwards()
            online_serials = [d["serial"] for d in result["devices"] if d["state"] == "device"]
            if preferred and preferred in online_serials:
                result["selected_serial"] = preferred
            elif online_serials:
                result["selected_serial"] = online_serials[0]
        except AdbError as exc:
            result["error"] = str(exc)
        return result

    def forward(self, serial: str = ""):
        device = self.online_device(serial=serial)
        if device is None:
            raise AdbError("未检测到在线设备")
        port = self.upstream_port()
        code, _out, err = self.run(
            ["-s", device["serial"], "forward", "tcp:%d" % port, "tcp:%d" % port]
        )
        if code != 0:
            raise AdbError(err.strip() or "adb forward 执行失败")
        return {"serial": device["serial"], "local": "tcp:%d" % port, "remote": "tcp:%d" % port}

    def unforward(self, serial: str = ""):
        device = self.online_device(serial=serial)
        if device is None:
            raise AdbError("未检测到在线设备")
        port = self.upstream_port()
        code, _out, err = self.run(
            ["-s", device["serial"], "forward", "--remove", "tcp:%d" % port]
        )
        if code != 0:
            raise AdbError(err.strip() or "adb forward --remove 执行失败")
        return {"serial": device["serial"], "local": "tcp:%d" % port}


_phone_mirror = scrcpy_bridge.PhoneMirrorManager(adb_factory=AdbTool)


# ------------------------------------------------------------------ http ----

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._write(data, "application/json; charset=utf-8", code)

    def _write(self, data, ctype, code=200, cache_control="no-store"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _check_host(self):
        port = self.server.server_address[1]
        host = (self.headers.get("Host") or "").strip().lower()
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _check_origin(self):
        origin = (self.headers.get("Origin") or "").strip().rstrip("/").lower()
        if not origin:
            return True
        port = self.server.server_address[1]
        return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def _check_token(self, query):
        token = (self.headers.get("X-DroidBridge-Token") or "").strip()
        if not token:
            token = (query.get("token", [""])[0] or "").strip()
        return bool(token) and secrets.compare_digest(token, API_TOKEN)

    def _read_json_body(self):
        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len == "":
            length = 0
        else:
            try:
                length = int(raw_len)
            except ValueError:
                return None, (400, "Invalid Content-Length")
            if length < 0:
                return None, (400, "Invalid Content-Length")
            if length > MAX_BODY_BYTES:
                return None, (413, "Payload too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}, None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None, (400, "Invalid JSON")
        if not isinstance(data, dict):
            return None, (400, "JSON body must be an object")
        return data, None

    def do_GET(self):
        global _last_request
        if not self._check_host():
            self.send_json({"ok": False, "error": "forbidden host"}, 403)
            return

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/api/ping":
            cancel_pending_quit()
            _last_request = time.time()
            self.send_json({"ok": True, "app": "DroidBridge"})
            return

        static_icons = {
            "/favicon.ico": (ICO_PATH, "image/x-icon"),
            "/icon.png": (PNG_PATH, "image/png"),
            "/icon.svg": (SVG_PATH, "image/svg+xml; charset=utf-8"),
        }
        if parsed.path in static_icons:
            cancel_pending_quit()
            _last_request = time.time()
            asset_path, mime = static_icons[parsed.path]
            try:
                self._write(asset_path.read_bytes(), mime, cache_control="no-cache")
            except OSError:
                self.send_json({"error": "icon missing"}, 404)
            return

        if parsed.path in ("/", "/index.html"):
            cancel_pending_quit()
            _last_request = time.time()
            try:
                html = HTML_PATH.read_text(encoding="utf-8")
                html = html.replace("__DROIDBRIDGE_TOKEN__", API_TOKEN)
                self._write(html.encode("utf-8"), "text/html; charset=utf-8")
            except OSError:
                self.send_json({"error": "index.html missing"}, 500)
            return

        if parsed.path.startswith("/api/"):
            if not self._check_token(query):
                self.send_json({"ok": False, "error": "unauthorized"}, 403)
                return
            cancel_pending_quit()
            _last_request = time.time()

            if parsed.path == "/api/state":
                self.send_json(make_state())
                return

            if parsed.path == "/api/app/icon":
                app_id = query.get("id", [""])[0]
                app = find_app(load_config(), app_id)
                if not app:
                    self.send_json({"ok": False, "error": "not found"}, 404)
                    return
                png = extract_exe_icon_png(expand(app["exe"]))
                if not png:
                    self.send_json({"ok": False, "error": "no icon"}, 404)
                    return
                self._write(png, "image/png", cache_control="private, max-age=300")
                return

            if parsed.path == "/api/adb/state":
                self.send_json(AdbTool(load_config()).state())
                return

            if parsed.path == "/api/phone/status":
                session_id = query.get("session", ["main"])[0]
                self.send_json(_phone_mirror.status(session_id))
                return

            if parsed.path == "/api/phone/info":
                serial = query.get("serial", [""])[0]
                try:
                    info = scrcpy_bridge.get_device_info(AdbTool(load_config()), serial=serial)
                except scrcpy_bridge.ScrcpyError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 400)
                    return
                self.send_json(info)
                return

            if parsed.path == "/api/phone/apps":
                serial = query.get("serial", [""])[0]
                refresh_flag = query.get("refresh", ["0"])[0] in ("1", "true", "yes")
                try:
                    res = scrcpy_bridge.list_device_apps(AdbTool(load_config()), serial=serial, force_refresh=refresh_flag)
                except scrcpy_bridge.ScrcpyError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 400)
                    return
                res["sessions"] = _phone_mirror.list_sessions()
                self.send_json(res)
                return

            if parsed.path == "/api/phone/ws":
                if not self._check_origin():
                    self.send_json({"ok": False, "error": "forbidden origin"}, 403)
                    return
                session_id = query.get("session", ["main"])[0]
                upgrade = (self.headers.get("Upgrade") or "").strip().lower()
                conn_hdr = (self.headers.get("Connection") or "").lower()
                ws_ver = (self.headers.get("Sec-WebSocket-Version") or "").strip()
                ws_key = (self.headers.get("Sec-WebSocket-Key") or "").strip()
                if upgrade != "websocket" or "upgrade" not in conn_hdr or ws_ver != "13" or not ws_key:
                    self.send_json({"ok": False, "error": "invalid websocket handshake"}, 400)
                    return
                accept = scrcpy_bridge.ws_accept_key(ws_key)
                handshake = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n"
                    "\r\n"
                ).encode("ascii")
                self.wfile.write(handshake)
                self.wfile.flush()
                self.close_connection = True
                _phone_mirror.handle_websocket(scrcpy_bridge.WebSocketConn(self.connection), session_id=session_id)
                return

            if parsed.path == "/api/exit-ip":
                self.send_json(query_exit_ip(load_config()))
                return

            if parsed.path == "/api/connections":
                self.send_json(_conn_registry.snapshot())
                return
            
            if parsed.path == "/api/inspect":
                exe = expand(query.get("path", [""])[0])
                if not exe:
                    self.send_json({"exists": False, "kind": "generic", "evidence": [], "path": ""})
                    return
                kind, evidence = detect_kind(exe)
                self.send_json({
                    "path": exe,
                    "exists": Path(exe).is_file(),
                    "kind": kind,
                    "native_browser": is_native_browser(exe),
                    "evidence": evidence,
                })
                return

            if parsed.path == "/api/rules":
                cfg = load_config()
                ensure_rules_file(cfg)
                path = rules_path(cfg)
                content = ""
                read_err = ""
                if path.is_file():
                    try:
                        content = path.read_text(encoding="utf-8-sig")
                    except OSError as exc:
                        read_err = "读取规则文件失败：%s" % exc
                table = RouteTable.load(cfg)
                self.send_json({
                    "ok": not bool(read_err),
                    "path": str(path),
                    "content": content,
                    "error": read_err or table.error,
                    "rule_count": len(table.rules),
                    "upstream": table.upstream_url,
                })
                return

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        global _last_request
        if not self._check_host() or not self._check_origin():
            self.send_json({"ok": False, "error": "forbidden origin or host"}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not path.startswith("/api/") or not self._check_token(query):
            self.send_json({"ok": False, "error": "unauthorized"}, 403)
            return

        if path == "/api/phone/upload":
            cancel_pending_quit()
            _last_request = time.time()
            raw_len = self.headers.get("Content-Length")
            try:
                length = int(raw_len or 0)
            except ValueError:
                self.send_json({"ok": False, "error": "Invalid Content-Length"}, 400)
                return
            if length <= 0:
                self.send_json({"ok": False, "error": "上传文件内容为空"}, 400)
                return
            if length > MAX_PHONE_UPLOAD_BYTES:
                self.send_json({"ok": False, "error": "文件超过 512 MB 限制"}, 413)
                return
            filename = query.get("name", [""])[0]
            serial = query.get("serial", [""])[0]
            action = query.get("action", ["auto"])[0]
            safe_name = scrcpy_bridge.sanitize_upload_filename(filename)
            try:
                with tempfile.TemporaryDirectory(prefix="droidbridge-up-") as td:
                    tmp_path = Path(td) / safe_name
                    remaining = length
                    with tmp_path.open("wb") as fh:
                        while remaining > 0:
                            chunk = self.rfile.read(min(65536, remaining))
                            if not chunk:
                                raise EOFError("上传连接提前中断")
                            fh.write(chunk)
                            remaining -= len(chunk)
                    result = scrcpy_bridge.push_or_install_file(
                        AdbTool(load_config()),
                        tmp_path,
                        filename=safe_name,
                        serial=serial,
                        action=action,
                    )
            except (EOFError, OSError) as exc:
                self.send_json({"ok": False, "error": f"接收上传文件失败：{exc}"}, 400)
                return
            except scrcpy_bridge.ScrcpyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json(result)
            return

        body, err = self._read_json_body()
        if err:
            self.send_json({"ok": False, "error": err[1]}, err[0])
            return

        if path == "/api/quit":
            force = bool(body.get("force"))
            if force:
                cancel_pending_quit()
                stop_tray()
                timer = threading.Timer(0.15, _force_shutdown)
                timer.daemon = True
                timer.start()
                self.send_json({"ok": True, "quitting": True})
                return
            if is_tray_active():
                self.send_json({"ok": True, "kept_in_tray": True})
                return
            if time.time() - _last_proxy_activity < 60:
                self.send_json({"ok": True, "kept_in_tray": False, "active_proxy": True})
                return
            schedule_quit(3.0)
            self.send_json({"ok": True, "quitting": True})
            return

        cancel_pending_quit()
        _last_request = time.time()

        if path == "/api/ui/show":
            show_ui_window()
            self.send_json({"ok": True})
            return

        if path == "/api/probe":
            cfg = load_config()
            online, latency = probe_proxy(*proxy_probe_target(cfg))
            self.send_json({"ok": True, "online": online, "latency_ms": latency})
            return

        if path == "/api/pick-exe":
            res = pick_exe_file(str(body.get("initial") or ""))
            _last_request = time.time()
            self.send_json(res)
            return

        if path == "/api/adb/forward":
            serial = str(body.get("serial") or "").strip()
            try:
                result = AdbTool(load_config()).forward(serial=serial)
            except AdbError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({"ok": True, **result})
            return

        if path == "/api/adb/unforward":
            serial = str(body.get("serial") or "").strip()
            try:
                result = AdbTool(load_config()).unforward(serial=serial)
            except AdbError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({"ok": True, **result})
            return

        if path == "/api/phone/start":
            serial = str(body.get("serial") or "").strip()
            quality = body.get("quality")
            max_fps = body.get("max_fps")
            screen_off = bool(body.get("screen_off", False))
            try:
                st = _phone_mirror.start(
                    load_config(),
                    serial=serial,
                    quality=quality,
                    max_fps=max_fps,
                    screen_off=screen_off,
                )
            except scrcpy_bridge.ScrcpyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({"ok": True, "status": st})
            return

        if path == "/api/phone/stop":
            session_id = str(body.get("session") or query.get("session", ["main"])[0] or "main").strip()
            st = _phone_mirror.stop(session_id)
            self.send_json({"ok": True, "status": st})
            return

        if path == "/api/phone/launch-app":
            serial = str(body.get("serial") or "").strip()
            package = str(body.get("package") or "").strip()
            try:
                result = scrcpy_bridge.launch_device_app(AdbTool(load_config()), package=package, serial=serial)
            except scrcpy_bridge.ScrcpyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json(result)
            return

        if path == "/api/phone/app/open":
            serial = str(body.get("serial") or "").strip()
            package = str(body.get("package") or "").strip()
            name = str(body.get("name") or "").strip() or package
            preset = body.get("preset")
            custom_display = str(body.get("custom_display") or "").strip()
            ime_policy = body.get("ime_policy")
            max_fps = body.get("max_fps", 60)
            popout = bool(body.get("popout", True))
            try:
                pol = scrcpy_bridge.normalize_ime_policy(ime_policy, default="local")
                if custom_display:
                    vd_spec = scrcpy_bridge.validate_new_display(custom_display)
                    preset_key = "custom"
                    win_w, win_h = 0, 0
                else:
                    preset_key = scrcpy_bridge.normalize_vd_preset(preset)
                    preset_cfg = scrcpy_bridge.VD_PRESETS[preset_key]
                    vd_spec = preset_cfg["new_display"]
                    win_w, win_h = preset_cfg["win_w"], preset_cfg["win_h"]
                session_id = scrcpy_bridge.session_id_for_package(package)
                st = _phone_mirror.start(
                    load_config(),
                    serial=serial,
                    max_fps=max_fps,
                    session_id=session_id,
                    new_display=vd_spec,
                    start_app=package,
                    app_name=name,
                    preset=preset_key,
                    ime_policy=pol,
                )
            except scrcpy_bridge.ScrcpyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            base_url = f"http://127.0.0.1:{self.server.server_address[1]}/"
            win_url = f"{base_url}?phone_window={session_id}"
            focused = False
            if popout:
                win_title = f"{name} · DroidBridge 手机应用"
                focused = focus_window_by_title(win_title)
                if not focused:
                    open_w = win_w or 510
                    open_h = win_h or 947
                    open_window(win_url, width=open_w, height=open_h)
                    _schedule_resize_window(win_title, open_w, open_h)
            self.send_json({
                "ok": True,
                "session_id": session_id,
                "status": st,
                "window_url": win_url,
                "focused_existing": focused,
                "win_w": win_w,
                "win_h": win_h,
            })
            return

        if path == "/api/phone/window/resize":
            session_id = str(body.get("session") or "").strip()
            try:
                req_w = int(body.get("width") or 0)
                req_h = int(body.get("height") or 0)
            except (TypeError, ValueError):
                self.send_json({"ok": False, "error": "窗口尺寸格式错误"}, 400)
                return
            if not session_id or req_w < 260 or req_h < 260:
                self.send_json({"ok": False, "error": "缺少有效的窗口会话或尺寸"}, 400)
                return
            req_w = min(req_w, 3840)
            req_h = min(req_h, 2400)
            st = _phone_mirror.status(session_id)
            label = str(st.get("app_name") or st.get("package") or body.get("name") or "").strip()
            resized = False
            if label:
                win_title = f"{label} · DroidBridge 手机应用"
                resized = resize_window_by_title(win_title, req_w, req_h, restore_maximized=True)
            self.send_json({"ok": True, "resized": resized, "width": req_w, "height": req_h})
            return

        if path == "/api/phone/app/pin":
            package = str(body.get("package") or "").strip()
            name = str(body.get("name") or "").strip() or package
            try:
                scrcpy_bridge.session_id_for_package(package)
                preset_key = scrcpy_bridge.normalize_vd_preset(body.get("preset"))
                fps = scrcpy_bridge.normalize_max_fps(body.get("max_fps", 60))
            except scrcpy_bridge.ScrcpyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            cfg = load_config()
            pinned = list(cfg.get("phone_apps") or [])
            item = {
                "id": "papp_" + re.sub(r"[^A-Za-z0-9_]", "_", package),
                "name": name,
                "package": package,
                "preset": preset_key,
                "max_fps": fps,
            }
            replaced = False
            for idx, existing in enumerate(pinned):
                if existing.get("package") == package:
                    pinned[idx] = item
                    replaced = True
                    break
            if not replaced:
                pinned.append(item)
            cfg["phone_apps"] = pinned
            save_config(cfg)
            self.send_json({"ok": True, "item": item, "state": make_state()})
            return

        if path == "/api/phone/app/unpin":
            package = str(body.get("package") or "").strip()
            cfg = load_config()
            cfg["phone_apps"] = [x for x in (cfg.get("phone_apps") or []) if x.get("package") != package]
            save_config(cfg)
            self.send_json({"ok": True, "state": make_state()})
            return

        if path == "/api/settings":
            incoming = body.get("proxy", {})
            if not isinstance(incoming, dict):
                self.send_json({"ok": False, "error": "proxy 配置格式错误"}, 400)
                return

            new_adb_path = None
            if "adb_path" in body:
                raw_adb_path = body["adb_path"]
                if not isinstance(raw_adb_path, str):
                    self.send_json({"ok": False, "error": "adb 路径格式错误"}, 400)
                    return
                new_adb_path = raw_adb_path.strip()

            new_adb_serial = None
            if "adb_serial" in body:
                raw_adb_serial = body["adb_serial"]
                if not isinstance(raw_adb_serial, str):
                    self.send_json({"ok": False, "error": "adb 设备序列号格式错误"}, 400)
                    return
                new_adb_serial = raw_adb_serial.strip()

            new_host = None
            if "host" in incoming:
                if not isinstance(incoming["host"], str) or not incoming["host"].strip():
                    self.send_json({"ok": False, "error": "代理主机不能为空"}, 400)
                    return
                new_host = incoming["host"].strip()

            new_port = None
            if "port" in incoming:
                raw_port = incoming["port"]
                if isinstance(raw_port, (bool, float)):
                    self.send_json({"ok": False, "error": "代理端口必须是 1-65535 之间的整数"}, 400)
                    return
                try:
                    port_num = int(raw_port)
                except (ValueError, TypeError, OverflowError):
                    self.send_json({"ok": False, "error": "代理端口必须是 1-65535 之间的整数"}, 400)
                    return
                if not (1 <= port_num <= 65535):
                    self.send_json({"ok": False, "error": "代理端口必须是 1-65535 之间的整数"}, 400)
                    return
                new_port = port_num

            new_listen_port = None
            if "listen_port" in incoming:
                raw_listen_port = incoming["listen_port"]
                if isinstance(raw_listen_port, (bool, float)):
                    self.send_json({"ok": False, "error": "分流入口端口必须是 1-65535 之间的整数"}, 400)
                    return
                try:
                    listen_port_num = int(raw_listen_port)
                except (ValueError, TypeError, OverflowError):
                    self.send_json({"ok": False, "error": "分流入口端口必须是 1-65535 之间的整数"}, 400)
                    return
                if not (1 <= listen_port_num <= 65535):
                    self.send_json({"ok": False, "error": "分流入口端口必须是 1-65535 之间的整数"}, 400)
                    return
                new_listen_port = listen_port_num

            new_rules_file = None
            if "rules_file" in incoming:
                if not isinstance(incoming["rules_file"], str) or not incoming["rules_file"].strip():
                    self.send_json({"ok": False, "error": "规则文件不能为空"}, 400)
                    return
                new_rules_file = incoming["rules_file"].strip()

            restart_router = False
            with _config_lock:
                cfg = load_config()
                previous_proxy = dict(cfg["proxy"])
                if new_host is not None:
                    cfg["proxy"]["host"] = new_host
                if new_port is not None:
                    cfg["proxy"]["port"] = new_port
                if new_listen_port is not None:
                    cfg["proxy"]["listen_port"] = new_listen_port
                if new_rules_file is not None:
                    cfg["proxy"]["rules_file"] = new_rules_file
                if "enabled" in incoming:
                    cfg["proxy"]["enabled"] = bool(incoming["enabled"])
                if new_adb_path is not None:
                    cfg["adb_path"] = new_adb_path
                if new_adb_serial is not None:
                    cfg["adb_serial"] = new_adb_serial
                save_config(cfg)
                restart_keys = ("listen_host", "listen_port", "rules_file", "host", "port")
                restart_router = any(previous_proxy.get(key) != cfg["proxy"].get(key) for key in restart_keys)
            if restart_router:
                restart_proxy_server(load_config())
            _update_tray_tooltip()
            self.send_json({"ok": True, "state": make_state()})
            return

        if path == "/api/rules":
            content = body.get("content")
            if not isinstance(content, str):
                self.send_json({"ok": False, "error": "规则内容格式错误"}, 400)
                return
            cfg = load_config()
            table = save_rules_text(cfg, content)
            if table.error:
                self.send_json({"ok": False, "error": table.error}, 400)
                return
            self.send_json({
                "ok": True,
                "path": str(table.source),
                "rule_count": len(table.rules),
                "state": make_state(),
            })
            return

        if path == "/api/rules/test":
            raw_host = str(body.get("host") or "").strip()
            host = extract_test_host(raw_host)
            if not host:
                self.send_json({"ok": False, "error": "请输入域名或 URL"}, 400)
                return
            cfg = load_config()
            table = RouteTable.load(cfg)
            if table.error:
                self.send_json({"ok": False, "error": table.error}, 400)
                return
            try:
                rule, idx = table.match_detail(host)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({
                "ok": True,
                "host": host,
                "action": rule.action,
                "rule": rule.label,
                "rule_index": idx,
            })
            return

        if path == "/api/rules/quick-add":
            host = str(body.get("host") or "").strip()
            action = str(body.get("action") or "").strip()
            kind = str(body.get("kind") or "").strip()
            try:
                res = quick_add_rule(load_config(), host, action, kind=kind)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            if not res.get("ok"):
                self.send_json(res, 400)
                return
            res["state"] = make_state()
            self.send_json(res)
            return

        if path == "/api/events/clear":
            cleared = clear_proxy_events()
            self.send_json({"ok": True, "cleared": cleared, "state": make_state()})
            return

        if path == "/api/connections/close":
            if body.get("all"):
                closed = _conn_registry.close_all()
            else:
                conn_id = str(body.get("id") or "").strip()
                if not conn_id:
                    self.send_json({"ok": False, "error": "请指定要断开的连接 ID"}, 400)
                    return
                closed = _conn_registry.close_one(conn_id)
            self.send_json({"ok": True, "closed": closed, **_conn_registry.snapshot()})
            return

        if path == "/api/connections/reset-stats":
            _conn_registry.reset_stats()
            self.send_json(_conn_registry.snapshot())
            return

        if path in ("/api/app/add", "/api/app/update"):
            kind_val = body.get("kind") or "auto"
            if kind_val not in ("auto", "electron", "firefox", "generic"):
                kind_val = "auto"
            item = {
                "id": body.get("id") or ("app_%d" % int(time.time() * 1000)),
                "name": str(body.get("name") or "").strip() or "未命名应用",
                "exe": str(body.get("exe") or "").strip(),
                "args": str(body.get("args") or "").strip(),
                "kind": kind_val,
                "note": str(body.get("note") or "").strip(),
            }
            if not item["exe"]:
                self.send_json({"ok": False, "error": "可执行文件路径不能为空"}, 400)
                return
            with _config_lock:
                cfg = load_config()
                if path == "/api/app/update":
                    target = find_app(cfg, item["id"])
                    if not target:
                        self.send_json({"ok": False, "error": "找不到该应用"}, 404)
                        return
                    target.update(item)
                else:
                    cfg["apps"].append(item)
                save_config(cfg)
            self.send_json({"ok": True, "state": make_state()})
            return

        if path == "/api/app/delete":
            with _config_lock:
                cfg = load_config()
                before = len(cfg["apps"])
                cfg["apps"] = [a for a in cfg["apps"] if a["id"] != body.get("id")]
                save_config(cfg)
                removed = before - len(cfg["apps"])
            self.send_json({"ok": True, "removed": removed, "state": make_state()})
            return

        if path == "/api/app/firefox/sync":
            cfg = load_config()
            app = find_app(cfg, body.get("id"))
            if not app:
                self.send_json({"ok": False, "error": "找不到该应用"}, 404)
                return
            res = sync_firefox_profile(app, cfg)
            if not res.get("ok"):
                self.send_json(res, 400)
                return
            res["state"] = make_state()
            self.send_json(res)
            return

        if path == "/api/app/firefox/open-profile":
            cfg = load_config()
            app = find_app(cfg, body.get("id"))
            if not app:
                self.send_json({"ok": False, "error": "找不到该应用"}, 404)
                return
            res = open_firefox_profile_dir(app)
            self.send_json(res, 200 if res.get("ok") else 400)
            return

        if path == "/api/launch":
            cfg = load_config()
            app = find_app(cfg, body.get("id"))
            if not app:
                self.send_json({"ok": False, "error": "找不到该应用"}, 404)
                return
            result = launch_app(app, cfg, dry_run=bool(body.get("dry_run")),
                                force=bool(body.get("force")))
            self.send_json(result)
            return

        self.send_json({"error": "not found"}, 404)


# ------------------------------------------------------------------ main ----

def open_window(url, width=1120, height=780):
    profile = Path(tempfile.gettempdir()) / "droidbridge_profile"
    w = max(320, int(width or 1120))
    h = max(400, int(height or 780))
    for browser in BROWSERS:
        if not Path(browser).is_file():
            continue
        args = [
            browser,
            "--app=" + url,
            f"--window-size={w},{h}",
            "--user-data-dir=" + str(profile),
            "--no-first-run",
            "--no-default-browser-check",
            "--no-proxy-server",
        ]
        try:
            browser_process = subprocess.Popen(
                args,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
            pid = getattr(browser_process, "pid", None)
            if isinstance(pid, int) and pid > 0:
                _ui_browser_pids.add(pid)
                invalidate_process_cache()
            return browser
        except OSError:
            continue
    import webbrowser
    webbrowser.open(url)
    return "default browser"


UI_WINDOW_TITLE = "DroidBridge · 进程级网络应用台"
PROCESS_TERMINATE = 0x0001


def _find_ui_windows(user32=None) -> list[tuple[int, int]]:
    """Return [(hwnd, pid), ...] for visible/minimized DroidBridge --app windows."""
    if os.name != "nt":
        return []
    u32 = user32 or ctypes.WinDLL("user32", use_last_error=True)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    u32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    u32.EnumWindows.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    u32.GetWindowTextLengthW.restype = ctypes.c_int
    u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u32.GetWindowTextW.restype = ctypes.c_int
    u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u32.GetClassNameW.restype = ctypes.c_int
    u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u32.GetWindowThreadProcessId.restype = wintypes.DWORD

    invalidate_process_cache()
    try:
        process_map()
    except Exception:
        pass
    ui_pids = _ui_browser_process_ids()
    matched: list[tuple[int, int]] = []

    def _enum_cb(hwnd, _lparam):
        if not u32.IsWindowVisible(hwnd):
            return True
        cls_buf = ctypes.create_unicode_buffer(128)
        u32.GetClassNameW(hwnd, cls_buf, 128)
        cls_name = cls_buf.value
        if not cls_name.startswith("Chrome_WidgetWin_"):
            return True

        pid_val = wintypes.DWORD(0)
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_val))
        pid = int(pid_val.value)

        length = u32.GetWindowTextLengthW(hwnd)
        title = ""
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            u32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value

        # Only match our isolated --app window:
        # 1) Exact --app title (regular tabbed Chrome/Edge appends " - Google Chrome" / " - Microsoft Edge")
        # 2) Any titled Chrome_WidgetWin_* owned by our dedicated --user-data-dir=droidbridge_profile process tree
        if title == UI_WINDOW_TITLE or (pid in ui_pids and bool(title)):
            matched.append((int(hwnd), pid))
        return True

    cb = WNDENUMPROC(_enum_cb)
    u32.EnumWindows(cb, 0)
    return matched


def _terminate_pid(pid: int) -> bool:
    if os.name != "nt" or _kernel32 is None or pid <= 0:
        return False
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    handle = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        return False
    try:
        return bool(_kernel32.TerminateProcess(handle, 0))
    finally:
        _kernel32.CloseHandle(handle)


def close_ui_windows(wait_timeout: float = 1.0, user32=None) -> int:
    """Close DroidBridge's dedicated --app UI window(s) and remove their taskbar button."""
    if os.name != "nt":
        _ui_browser_pids.clear()
        return 0
    u32 = user32 or ctypes.WinDLL("user32", use_last_error=True)
    u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.PostMessageW.restype = wintypes.BOOL
    u32.IsWindow.argtypes = [wintypes.HWND]
    u32.IsWindow.restype = wintypes.BOOL

    windows = _find_ui_windows(user32=u32)
    tracked_pids = _ui_browser_process_ids()
    for hwnd, _pid in windows:
        u32.PostMessageW(hwnd, TrayController.WM_CLOSE, 0, 0)

    if windows and wait_timeout > 0:
        deadline = time.time() + wait_timeout
        while time.time() < deadline:
            if not any(u32.IsWindow(hwnd) for hwnd, _pid in windows):
                break
            time.sleep(0.05)

        still_open_pids = {
            pid for hwnd, pid in windows
            if u32.IsWindow(hwnd) and pid in tracked_pids
        }
        for pid in still_open_pids:
            _terminate_pid(pid)

    _ui_browser_pids.clear()
    invalidate_process_cache()
    return len(windows)


def focus_window_by_title(target_title: str, user32=None) -> bool:
    if os.name != "nt" or not target_title:
        return False
    u32 = user32 or ctypes.WinDLL("user32", use_last_error=True)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    u32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    u32.EnumWindows.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    u32.GetWindowTextLengthW.restype = ctypes.c_int
    u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u32.GetWindowTextW.restype = ctypes.c_int
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow.restype = wintypes.BOOL
    u32.SetForegroundWindow.argtypes = [wintypes.HWND]
    u32.SetForegroundWindow.restype = wintypes.BOOL

    found_hwnd = 0

    def _cb(hwnd, _lp):
        nonlocal found_hwnd
        if not u32.IsWindowVisible(hwnd):
            return True
        ln = u32.GetWindowTextLengthW(hwnd)
        if ln <= 0:
            return True
        buf = ctypes.create_unicode_buffer(ln + 1)
        u32.GetWindowTextW(hwnd, buf, ln + 1)
        if buf.value == target_title:
            found_hwnd = int(hwnd)
            return False
        return True

    cb = WNDENUMPROC(_cb)
    u32.EnumWindows(cb, 0)
    if not found_hwnd:
        return False
    if u32.IsIconic(found_hwnd):
        u32.ShowWindow(found_hwnd, 9)
    u32.SetForegroundWindow(found_hwnd)
    return True


class _WinRECT(ctypes.Structure):
    _fields_ = [
        ("left", wintypes.LONG),
        ("top", wintypes.LONG),
        ("right", wintypes.LONG),
        ("bottom", wintypes.LONG),
    ]


class _WinMONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", _WinRECT),
        ("rcWork", _WinRECT),
        ("dwFlags", wintypes.DWORD),
    ]


def resize_window_by_title(
    target_title: str,
    width: int,
    height: int,
    *,
    restore_maximized: bool = False,
    user32=None,
) -> bool:
    """Resize a visible top-level window matching target_title in logical DIPs."""
    if os.name != "nt" or not target_title:
        return False
    try:
        req_w = int(width)
        req_h = int(height)
    except (TypeError, ValueError):
        return False
    if req_w < 260 or req_h < 260:
        return False

    u32 = user32 or ctypes.WinDLL("user32", use_last_error=True)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    u32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    u32.EnumWindows.restype = wintypes.BOOL
    u32.IsWindowVisible.argtypes = [wintypes.HWND]
    u32.IsWindowVisible.restype = wintypes.BOOL
    u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    u32.GetWindowTextLengthW.restype = ctypes.c_int
    u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u32.GetWindowTextW.restype = ctypes.c_int

    found_hwnd = 0

    def _cb(hwnd, _lp):
        nonlocal found_hwnd
        if not u32.IsWindowVisible(hwnd):
            return True
        ln = u32.GetWindowTextLengthW(hwnd)
        if ln <= 0:
            return True
        buf = ctypes.create_unicode_buffer(ln + 1)
        u32.GetWindowTextW(hwnd, buf, ln + 1)
        if buf.value == target_title:
            found_hwnd = int(hwnd)
            return False
        return True

    cb = WNDENUMPROC(_cb)
    u32.EnumWindows(cb, 0)
    if not found_hwnd:
        return False

    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    u32.IsZoomed.argtypes = [wintypes.HWND]
    u32.IsZoomed.restype = wintypes.BOOL
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow.restype = wintypes.BOOL
    u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(_WinRECT)]
    u32.GetWindowRect.restype = wintypes.BOOL
    u32.SetWindowPos.argtypes = [
        wintypes.HWND, wintypes.HWND,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    u32.SetWindowPos.restype = wintypes.BOOL

    if u32.IsIconic(found_hwnd):
        return False
    if u32.IsZoomed(found_hwnd):
        if not restore_maximized:
            return False
        u32.ShowWindow(found_hwnd, 9)  # SW_RESTORE

    scale = 1.0
    get_sys_dpi = getattr(u32, "GetDpiForSystem", None)
    if get_sys_dpi is not None:
        try:
            get_sys_dpi.argtypes = []
            get_sys_dpi.restype = wintypes.UINT
            sys_dpi = int(get_sys_dpi() or 96)
            if 72 <= sys_dpi <= 480:
                scale = sys_dpi / 96.0
        except Exception:
            scale = 1.0

    target_w = max(300, int(round(req_w * scale)))
    target_h = max(320, int(round(req_h * scale)))

    work_left, work_top, work_right, work_bottom = 0, 0, 1920, 1040
    mon_from_win = getattr(u32, "MonitorFromWindow", None)
    get_mon_info = getattr(u32, "GetMonitorInfoW", None)
    if mon_from_win is not None and get_mon_info is not None:
        try:
            mon_from_win.argtypes = [wintypes.HWND, wintypes.DWORD]
            mon_from_win.restype = wintypes.HMONITOR
            get_mon_info.argtypes = [wintypes.HMONITOR, ctypes.POINTER(_WinMONITORINFO)]
            get_mon_info.restype = wintypes.BOOL
            hmon = mon_from_win(found_hwnd, 2)  # MONITOR_DEFAULTTONEAREST
            if hmon:
                mi = _WinMONITORINFO()
                mi.cbSize = ctypes.sizeof(_WinMONITORINFO)
                if get_mon_info(hmon, ctypes.byref(mi)):
                    work_left = int(mi.rcWork.left)
                    work_top = int(mi.rcWork.top)
                    work_right = int(mi.rcWork.right)
                    work_bottom = int(mi.rcWork.bottom)
        except Exception:
            pass

    work_w = max(400, work_right - work_left)
    work_h = max(400, work_bottom - work_top)
    max_w = max(320, int(work_w * 0.94))
    max_h = max(340, int(work_h * 0.94))
    if target_w > max_w or target_h > max_h:
        fit = min(max_w / target_w, max_h / target_h)
        target_w = max(300, int(round(target_w * fit)))
        target_h = max(320, int(round(target_h * fit)))

    rect = _WinRECT()
    if u32.GetWindowRect(found_hwnd, ctypes.byref(rect)):
        x = int(rect.left)
        y = int(rect.top)
    else:
        x = work_left + max(0, (work_w - target_w) // 2)
        y = work_top + max(0, (work_h - target_h) // 2)

    if x + target_w > work_right:
        x = max(work_left, work_right - target_w)
    if y + target_h > work_bottom:
        y = max(work_top, work_bottom - target_h)
    if x < work_left:
        x = work_left
    if y < work_top:
        y = work_top

    SWP_NOZORDER = 0x0004
    SWP_NOACTIVATE = 0x0010
    return bool(u32.SetWindowPos(found_hwnd, 0, x, y, target_w, target_h, SWP_NOZORDER | SWP_NOACTIVATE))


def _schedule_resize_window(target_title: str, width: int, height: int, timeout: float = 8.0):
    if os.name != "nt" or not target_title:
        return

    def _worker():
        deadline = time.monotonic() + max(0.5, float(timeout))
        while time.monotonic() < deadline:
            if resize_window_by_title(target_title, width, height):
                return
            time.sleep(0.12)

    threading.Thread(target=_worker, daemon=True).start()


def focus_existing_window(user32=None) -> bool:
    if focus_window_by_title(UI_WINDOW_TITLE, user32=user32):
        return True
    if os.name != "nt":
        return False
    u32 = user32 or ctypes.WinDLL("user32", use_last_error=True)
    u32.IsIconic.argtypes = [wintypes.HWND]
    u32.IsIconic.restype = wintypes.BOOL
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow.restype = wintypes.BOOL
    u32.SetForegroundWindow.argtypes = [wintypes.HWND]
    u32.SetForegroundWindow.restype = wintypes.BOOL

    windows = _find_ui_windows(user32=u32)
    if not windows:
        return False
    hwnd, _pid = windows[0]
    if u32.IsIconic(hwnd):
        u32.ShowWindow(hwnd, 9)  # SW_RESTORE
    u32.SetForegroundWindow(hwnd)
    return True


def _tray_tooltip_text(cfg=None) -> str:
    c = cfg or load_config()
    p = c.get("proxy", {})
    enabled = bool(p.get("enabled", True))
    listen = "%s:%s" % (p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086))
    status = "代理已开启" if enabled else "代理已关闭"
    return f"DroidBridge · {status} ({listen})"[:127]


def is_tray_active() -> bool:
    return bool(_tray is not None and _tray.active)


def _update_tray_tooltip(cfg=None):
    if _tray is not None and _tray.active:
        _tray.update_tooltip(_tray_tooltip_text(cfg))


def show_ui_window():
    if not focus_existing_window() and _ui_url:
        open_window(_ui_url)


def _toggle_tray_proxy():
    with _config_lock:
        cfg = load_config()
        cfg["proxy"]["enabled"] = not bool(cfg["proxy"].get("enabled", True))
        save_config(cfg)
    _update_tray_tooltip(cfg)


def _quit_from_tray():
    cancel_pending_quit()
    close_ui_windows()
    stop_tray()
    _do_shutdown()


class _TrayGUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _TrayTimeoutVersion(ctypes.Union):
    _fields_ = [
        ("uTimeout", wintypes.UINT),
        ("uVersion", wintypes.UINT),
    ]


class _NOTIFYICONDATAW(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("u", _TrayTimeoutVersion),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", _TrayGUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


_TrayLRESULT = ctypes.c_ssize_t
_TrayWNDPROC = (
    ctypes.WINFUNCTYPE(_TrayLRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    if os.name == "nt" else None
)


class _TrayWNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", _TrayWNDPROC if _TrayWNDPROC is not None else ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HICON),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


_tray_api_lock = threading.Lock()
_tray_api_ready = False


def _ensure_tray_win32_api():
    global _tray_api_ready
    if os.name != "nt" or _user32 is None or _shell32 is None or _kernel32 is None:
        return False
    with _tray_api_lock:
        if _tray_api_ready:
            return True
        _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        _kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
        _user32.RegisterClassW.argtypes = [ctypes.POINTER(_TrayWNDCLASSW)]
        _user32.RegisterClassW.restype = wintypes.ATOM
        _user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        _user32.UnregisterClassW.restype = wintypes.BOOL
        _user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p,
        ]
        _user32.CreateWindowExW.restype = wintypes.HWND
        _user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        _user32.DefWindowProcW.restype = _TrayLRESULT
        _user32.DestroyWindow.argtypes = [wintypes.HWND]
        _user32.DestroyWindow.restype = wintypes.BOOL
        _user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        _user32.GetMessageW.restype = ctypes.c_int
        _user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        _user32.TranslateMessage.restype = wintypes.BOOL
        _user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        _user32.DispatchMessageW.restype = _TrayLRESULT
        _user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        _user32.PostMessageW.restype = wintypes.BOOL
        _user32.PostQuitMessage.argtypes = [ctypes.c_int]
        _user32.PostQuitMessage.restype = None
        _user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        _user32.RegisterWindowMessageW.restype = wintypes.UINT
        _user32.CreatePopupMenu.argtypes = []
        _user32.CreatePopupMenu.restype = wintypes.HMENU
        _user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        _user32.AppendMenuW.restype = wintypes.BOOL
        _user32.SetMenuDefaultItem.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
        _user32.SetMenuDefaultItem.restype = wintypes.BOOL
        _user32.TrackPopupMenuEx.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.HWND, ctypes.c_void_p,
        ]
        _user32.TrackPopupMenuEx.restype = wintypes.BOOL
        _user32.DestroyMenu.argtypes = [wintypes.HMENU]
        _user32.DestroyMenu.restype = wintypes.BOOL
        _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        _user32.SetForegroundWindow.restype = wintypes.BOOL
        _user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        _user32.GetCursorPos.restype = wintypes.BOOL
        _user32.LoadImageW.argtypes = [
            wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT,
        ]
        _user32.LoadImageW.restype = wintypes.HICON
        _user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        _user32.LoadIconW.restype = wintypes.HICON
        _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
        _user32.GetSystemMetrics.restype = ctypes.c_int
        _shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW)]
        _shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        _tray_api_ready = True
        return True


class TrayController:
    """Minimal Windows system tray icon implemented purely with ctypes."""

    WM_CLOSE = 0x0010
    WM_DESTROY = 0x0002
    WM_COMMAND = 0x0111
    WM_CONTEXTMENU = 0x007B
    WM_LBUTTONUP = 0x0202
    WM_LBUTTONDBLCLK = 0x0203
    WM_RBUTTONUP = 0x0205
    WM_TRAYICON = 0x8001

    NIM_ADD = 0x00000000
    NIM_MODIFY = 0x00000001
    NIM_DELETE = 0x00000002
    NIF_MESSAGE = 0x00000001
    NIF_ICON = 0x00000002
    NIF_TIP = 0x00000004

    IMAGE_ICON = 1
    LR_LOADFROMFILE = 0x0010
    LR_DEFAULTSIZE = 0x0040
    MF_STRING = 0x0000
    MF_CHECKED = 0x0008
    MF_UNCHECKED = 0x0000
    MF_SEPARATOR = 0x0800
    TPM_LEFTALIGN = 0x0000
    TPM_BOTTOMALIGN = 0x0020
    TPM_RIGHTBUTTON = 0x0002

    CMD_OPEN = 1001
    CMD_TOGGLE_PROXY = 1002
    CMD_QUIT = 1003

    def __init__(self, on_open, on_toggle_proxy, on_quit, is_proxy_enabled, tooltip="DroidBridge"):
        self.on_open = on_open
        self.on_toggle_proxy = on_toggle_proxy
        self.on_quit = on_quit
        self.is_proxy_enabled = is_proxy_enabled
        self._tooltip = str(tooltip or "DroidBridge")[:127]
        self.active = False
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._hicon = None
        self._owns_icon = False
        self._nid = None
        self._wndproc_ref = None
        self._class_name = f"DroidBridgeTray_{id(self)}"
        self._hinst = None
        self._wm_taskbar_created = 0

    def start(self, timeout=2.0) -> bool:
        if os.name != "nt":
            return False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=timeout)
        return self.active

    def update_tooltip(self, text: str):
        if not _ensure_tray_win32_api():
            return
        with self._lock:
            self._tooltip = str(text or "DroidBridge")[:127]
            if not self.active or not self._hwnd or not self._nid:
                return
            self._nid.uFlags = self.NIF_TIP
            self._nid.szTip = self._tooltip
            _shell32.Shell_NotifyIconW(self.NIM_MODIFY, ctypes.byref(self._nid))

    def stop(self):
        if not _ensure_tray_win32_api():
            return
        with self._lock:
            hwnd = self._hwnd
        if hwnd:
            _user32.PostMessageW(hwnd, self.WM_CLOSE, 0, 0)
        if self._thread and self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2.0)

    def _run(self):
        if not _ensure_tray_win32_api():
            self._ready.set()
            return

        u32 = _user32
        s32 = _shell32
        k32 = _kernel32

        self._wm_taskbar_created = u32.RegisterWindowMessageW("TaskbarCreated")
        self._hinst = k32.GetModuleHandleW(None)

        def _show_menu(hwnd):
            hmenu = u32.CreatePopupMenu()
            if not hmenu:
                return
            try:
                u32.AppendMenuW(hmenu, self.MF_STRING, self.CMD_OPEN, "打开 DroidBridge 界面")
                u32.SetMenuDefaultItem(hmenu, self.CMD_OPEN, 0)
                u32.AppendMenuW(hmenu, self.MF_SEPARATOR, 0, None)
                enabled = bool(self.is_proxy_enabled())
                flag = self.MF_STRING | (self.MF_CHECKED if enabled else self.MF_UNCHECKED)
                u32.AppendMenuW(hmenu, flag, self.CMD_TOGGLE_PROXY, "代理注入")
                u32.AppendMenuW(hmenu, self.MF_SEPARATOR, 0, None)
                u32.AppendMenuW(hmenu, self.MF_STRING, self.CMD_QUIT, "彻底退出 DroidBridge")

                pt = wintypes.POINT()
                u32.GetCursorPos(ctypes.byref(pt))
                u32.SetForegroundWindow(hwnd)
                u32.TrackPopupMenuEx(
                    hmenu,
                    self.TPM_LEFTALIGN | self.TPM_BOTTOMALIGN | self.TPM_RIGHTBUTTON,
                    pt.x,
                    pt.y,
                    hwnd,
                    None,
                )
                u32.PostMessageW(hwnd, 0, 0, 0)
            finally:
                u32.DestroyMenu(hmenu)

        def _wndproc(hwnd, msg, wparam, lparam):
            if msg == self.WM_TRAYICON:
                event = lparam & 0xFFFF
                if event in (self.WM_LBUTTONUP, self.WM_LBUTTONDBLCLK):
                    threading.Thread(target=self.on_open, daemon=True).start()
                    return 0
                if event in (self.WM_RBUTTONUP, self.WM_CONTEXTMENU):
                    _show_menu(hwnd)
                    return 0
            elif self._wm_taskbar_created and msg == self._wm_taskbar_created:
                with self._lock:
                    if self._nid is not None:
                        self._nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
                        s32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(self._nid))
                return 0
            elif msg == self.WM_COMMAND:
                cmd_id = wparam & 0xFFFF
                if cmd_id == self.CMD_OPEN:
                    threading.Thread(target=self.on_open, daemon=True).start()
                elif cmd_id == self.CMD_TOGGLE_PROXY:
                    threading.Thread(target=self.on_toggle_proxy, daemon=True).start()
                elif cmd_id == self.CMD_QUIT:
                    threading.Thread(target=self.on_quit, daemon=True).start()
                return 0
            elif msg == self.WM_CLOSE:
                with self._lock:
                    self.active = False
                    if self._nid is not None:
                        s32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(self._nid))
                u32.DestroyWindow(hwnd)
                return 0
            elif msg == self.WM_DESTROY:
                with self._lock:
                    self.active = False
                    self._hwnd = None
                u32.PostQuitMessage(0)
                return 0
            return u32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = _TrayWNDPROC(_wndproc)
        wc = _TrayWNDCLASSW()
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = self._hinst
        wc.lpszClassName = self._class_name

        if not u32.RegisterClassW(ctypes.byref(wc)):
            self._ready.set()
            return

        hwnd = None
        try:
            hwnd = u32.CreateWindowExW(
                0, self._class_name, "DroidBridgeTray", 0,
                0, 0, 0, 0, None, None, self._hinst, None,
            )
            if not hwnd:
                self._ready.set()
                return

            cx = max(16, u32.GetSystemMetrics(49))
            cy = max(16, u32.GetSystemMetrics(50))
            if ICO_PATH.is_file():
                loaded = u32.LoadImageW(
                    None, str(ICO_PATH), self.IMAGE_ICON, cx, cy, self.LR_LOADFROMFILE,
                )
                if loaded:
                    self._hicon = loaded
                    self._owns_icon = True
            if not self._hicon:
                self._hicon = u32.LoadIconW(None, ctypes.cast(32512, wintypes.LPCWSTR))
                self._owns_icon = False

            nid = _NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
            nid.uCallbackMessage = self.WM_TRAYICON
            nid.hIcon = self._hicon
            nid.szTip = self._tooltip

            if not s32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid)):
                u32.DestroyWindow(hwnd)
                self._ready.set()
                return

            with self._lock:
                self._hwnd = hwnd
                self._nid = nid
                self.active = True
            self._ready.set()

            msg = wintypes.MSG()
            while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
        finally:
            with self._lock:
                self.active = False
                if self._nid is not None and self._hwnd:
                    s32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(self._nid))
                self._nid = None
                self._hwnd = None
                if self._owns_icon and self._hicon:
                    u32.DestroyIcon(self._hicon)
                self._hicon = None
                self._owns_icon = False
            u32.UnregisterClassW(self._class_name, self._hinst)
            self._ready.set()


def start_tray(cfg=None) -> bool:
    global _tray
    if os.name != "nt":
        return False
    if _tray is not None and _tray.active:
        return True
    tray = TrayController(
        on_open=show_ui_window,
        on_toggle_proxy=_toggle_tray_proxy,
        on_quit=_quit_from_tray,
        is_proxy_enabled=lambda: bool(load_config().get("proxy", {}).get("enabled", True)),
        tooltip=_tray_tooltip_text(cfg),
    )
    if tray.start():
        _tray = tray
        return True
    return False


def stop_tray():
    global _tray
    tray = _tray
    _tray = None
    if tray is not None:
        tray.stop()


def try_reuse_existing() -> bool:
    if not RUNTIME_PATH.is_file():
        return False
    try:
        data = json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))
        url = str(data.get("url") or "")
        token = str(data.get("token") or "")
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
            return False
        if not (1 <= parsed.port <= 65535):
            return False

        ping_url = f"http://127.0.0.1:{parsed.port}/api/ping"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(ping_url, timeout=0.5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if payload.get("ok") is True and payload.get("app") == "DroidBridge":
            if "--no-browser" not in sys.argv:
                shown = False
                if token:
                    try:
                        req = urllib.request.Request(
                            f"http://127.0.0.1:{parsed.port}/api/ui/show",
                            data=b"{}",
                            method="POST",
                            headers={
                                "Content-Type": "application/json",
                                "X-DroidBridge-Token": token,
                            },
                        )
                        with opener.open(req, timeout=1.0) as show_resp:
                            shown = show_resp.status == 200
                    except Exception:
                        shown = False
                if not shown and not focus_existing_window():
                    open_window(url)
            return True
    except Exception:
        return False
    return False


def idle_watchdog(timeout=180):
    """Shut down when no tray is active and no UI/proxy/app activity remains."""
    while True:
        time.sleep(15)
        if is_tray_active():
            continue
        if _phone_mirror.status().get("running"):
            continue
        now_ts = time.time()
        if now_ts - _last_request <= timeout or now_ts - _last_proxy_activity <= timeout:
            continue
        try:
            apps = load_config().get("apps", [])
            if any(running_lines(expand(a["exe"])) for a in apps):
                continue
        except Exception:
            pass
        if _server:
            threading.Thread(target=_server.shutdown, daemon=True).start()
            return


def main():
    global _server, _ui_url
    if try_reuse_existing():
        return

    cfg = load_config()
    start_proxy_server(cfg)
    _server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    _server.daemon_threads = True
    url = "http://127.0.0.1:%d/" % _server.server_address[1]
    _ui_url = url
    RUNTIME_PATH.write_text(
        json.dumps({"url": url, "pid": os.getpid(), "token": API_TOKEN}),
        encoding="utf-8",
    )
    print("DroidBridge:", url, flush=True)
    if os.name == "nt" and "--no-tray" not in sys.argv:
        start_tray(cfg)
    if "--no-browser" not in sys.argv:
        threading.Timer(0.4, lambda: open_window(url)).start()
    threading.Thread(target=idle_watchdog, daemon=True).start()
    try:
        _server.serve_forever(poll_interval=0.3)
    finally:
        _phone_mirror.shutdown()
        stop_tray()
        _server.server_close()
        stop_proxy_server()
        try:
            if RUNTIME_PATH.is_file():
                data = json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))
                if data.get("pid") == os.getpid():
                    RUNTIME_PATH.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # pythonw.exe has no console: make startup failures visible on disk.
        import traceback
        try:
            (ROOT / "droidbridge_error.log").write_text(
                time.strftime("%Y-%m-%d %H:%M:%S") + "\n" + traceback.format_exc(),
                encoding="utf-8",
            )
        except Exception:
            pass
        raise
