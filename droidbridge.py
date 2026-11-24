#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DroidBridge - per-app network launcher over an ADB bridge.

Only child processes launched from here inherit the proxy environment.
No TUN, no system proxy, no setx, no registry. Stdlib only.

Layers:
  Node / generic apps  -> HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY
  Electron / Chromium -> --proxy-server, --proxy-bypass-list (they ignore
                         *_PROXY env vars on Windows)
  Firefox / Gecko     -> isolated -no-remote -profile + user.js prefs
"""
from __future__ import annotations

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
import urllib.request
import zlib
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
RULES_EXAMPLE_PATH = ROOT / "rules.example.yaml"
HTML_PATH = ROOT / "index.html"
ICO_PATH = ROOT / "droidbridge.ico"
PNG_PATH = ROOT / "droidbridge.png"
SVG_PATH = ROOT / "droidbridge.svg"
PROFILES_DIR = ROOT / "profiles"
RUNTIME_PATH = Path(tempfile.gettempdir()) / "droidbridge_runtime.json"

API_TOKEN = secrets.token_urlsafe(24)
MAX_BODY_BYTES = 1_048_576

DEFAULT_CONFIG = {
    "adb_path": "",
    "proxy": {
        "host": "127.0.0.1",
        "port": 5038,
        "listen_host": "127.0.0.1",
        "listen_port": 10086,
        "router_enabled": True,
        "rules_file": "rules.yaml",
        "enabled": True,
        "bypass": ["localhost", "127.0.0.1", "::1"],
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
_proxy_events: list[dict] = []
_proxy_events_lock = threading.Lock()
_proxy_error = ""


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
        for key, val in DEFAULT_CONFIG.items():
            cfg.setdefault(key, json.loads(json.dumps(val)))
        for key, val in DEFAULT_CONFIG["proxy"].items():
            cfg["proxy"].setdefault(key, val)
        ensure_rules_file(cfg)
        return cfg


def save_config(cfg):
    with _config_lock:
        tmp = CONFIG_PATH.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        tmp.replace(CONFIG_PATH)


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


def parse_bypass(value):
    if isinstance(value, str):
        value = value.replace("\n", ",").split(",")
    if not isinstance(value, list):
        raise ValueError("直连例外格式错误")
    entries = [str(entry).strip() for entry in value]
    return [entry for entry in entries if entry]


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
    def load(cls, cfg):
        proxy = cfg.get("proxy", {})
        try:
            upstream_port = int(proxy.get("port") or 5038)
        except (TypeError, ValueError, OverflowError):
            upstream_port = 5038
        upstream = (str(proxy.get("host") or "127.0.0.1"), upstream_port)
        path = rules_path(cfg)
        if not path.is_file():
            return cls(upstream, [], str(path), "规则文件不存在")

        try:
            text = path.read_text(encoding="utf-8-sig")
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
            return cls(upstream, rules, str(path))
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            return cls(upstream, [], str(path), "规则加载失败：%s" % exc)

    def rule_for(self, host):
        for rule in self.rules:
            if rule.matches(host):
                return rule
        if self.error:
            raise ValueError(self.error)
        raise ValueError("没有匹配的分流规则")

    def action_for(self, host):
        return self.rule_for(host).action


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
        del _proxy_events[80:]


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


def detect_kind(exe: str):
    """Return ('electron' | 'firefox' | 'generic', evidence list)."""
    folder = Path(exe).parent
    elec_found = [m for m in ELECTRON_MARKERS if (folder / m).exists()]
    stem = Path(exe).stem.lower()
    if stem in ("chrome", "msedge", "chromium", "brave", "vivaldi"):
        return "electron", ["browser binary"] + elec_found
    if len(elec_found) >= 2:
        return "electron", elec_found

    ff_found = [m for m in FIREFOX_MARKERS if (folder / m).exists()]
    if stem in FIREFOX_STEMS:
        return "firefox", ["gecko binary"] + ff_found
    if len(ff_found) >= 2 and ("xul.dll" in ff_found or "omni.ja" in ff_found):
        return "firefox", ff_found

    return "generic", elec_found


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
    if p.get("router_enabled", False):
        return "http://%s:%s" % (p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086))
    return "http://%s:%s" % (p["host"], p["port"])


def upstream_url(cfg):
    p = cfg["proxy"]
    return "http://%s:%s" % (p["host"], p["port"])


def effective_bypass(cfg):
    # When the local router is active, its YAML rules must see every request.
    return [] if cfg["proxy"].get("router_enabled", False) else cfg["proxy"].get("bypass", [])


def build_env(cfg):
    env = os.environ.copy()
    if not cfg["proxy"].get("enabled", True):
        return env, {}
    url = proxy_url(cfg)
    delta = {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "ALL_PROXY": url,
        "NO_PROXY": ",".join(effective_bypass(cfg)),
    }
    env.update(delta)
    return env, delta


def proxy_probe_target(cfg):
    p = cfg["proxy"]
    if p.get("router_enabled", False):
        return p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086)
    return p["host"], p["port"]


# Chromium bypasses loopback implicitly; listing "::1" there needs bracket
# syntax and can break rule parsing. Keep "<local>" so intranet short names pass through.
CHROMIUM_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


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


def _firefox_bypass_list(bypass) -> str:
    seen = set()
    out = []
    for raw in (bypass or []):
        item = str(raw).strip()
        if not item or item.lower() == "<local>":
            continue
        if item.startswith("*.") and len(item) > 2:
            item = "." + item[2:]
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return ", ".join(out)


def build_firefox_user_js(cfg) -> tuple[str, str]:
    p = cfg["proxy"]
    if not p.get("enabled", True):
        text = (
            "// Generated by DroidBridge - proxy injection disabled\n"
            'user_pref("network.proxy.type", 0);\n'
        )
        return text, "type=0 (直连，代理注入已关闭)"

    proxy_host, proxy_port = p["host"], p["port"]
    if p.get("router_enabled", False):
        proxy_host, proxy_port = p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086)
    host = str(proxy_host).strip()
    port = int(proxy_port)
    no_proxy = _firefox_bypass_list(effective_bypass(cfg))
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
        f'user_pref("network.proxy.no_proxies_on", {json.dumps(no_proxy)});',
        'user_pref("network.proxy.allow_hijacking_localhost", false);',
    ]
    summary = f"type=1 (manual) | http/ssl={host}:{port} | no_proxies_on={no_proxy or '(none)'}"
    return "\n".join(lines) + "\n", summary


def write_firefox_user_js(profile_dir: Path, content: str):
    profile_dir.mkdir(parents=True, exist_ok=True)
    tmp = profile_dir / "user.js.tmp"
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(profile_dir / "user.js")


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
        if "--proxy-bypass-list" not in flags:
            rules = [x.strip() for x in effective_bypass(cfg)
                     if x.strip().lower() not in CHROMIUM_LOOPBACK]
            if rules:
                cmd.append("--proxy-bypass-list=" + ";".join(rules))
                injected.append("--proxy-bypass-list")
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
        reason = (
            "本地分流入口 %s:%s 未启动"
            if p.get("router_enabled", False)
            else "代理 %s:%s 未监听，请先启动手机 Clash"
        ) % (target_host, target_port)
        result.update(
            ok=False,
            error=reason,
        )
        return result

    if app.get("bypass"):
        bypass = list(dict.fromkeys([*p.get("bypass", []), *app["bypass"]]))
        cfg = {**cfg, "proxy": {**p, "bypass": bypass}}

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
    route_table = RouteTable.load(cfg) if p.get("router_enabled", False) else None
    upstream_target = route_table.upstream if route_table and not route_table.error else (p["host"], p["port"])
    upstream_online, upstream_latency = probe_proxy(*upstream_target)
    apps = []
    for app in cfg["apps"]:
        exe = expand(app["exe"])
        kind, evidence = detect_kind(exe)
        eff_kind = effective_kind(app)
        profile_running = (
            is_firefox_profile_locked(firefox_profile_dir(app))
            if (eff_kind == "firefox" and not _has_firefox_profile_arg(split_args(app.get("args", ""))))
            else False
        )
        apps.append({
            **app,
            "resolved_exe": exe,
            "exists": Path(exe).is_file(),
            "detected_kind": kind,
            "effective_kind": eff_kind,
            "evidence": evidence,
            "running": bool(running_lines(exe)),
            "profile_running": profile_running,
        })
    return {
        "proxy": p,
        "adb_path": str(cfg.get("adb_path") or ""),
        "proxy_url": proxy_url(cfg),
        "proxy_upstream_url": "http://%s:%s" % upstream_target,
        "router_enabled": bool(p.get("router_enabled", False)),
        "router_listen": "%s:%s" % (p.get("listen_host", "127.0.0.1"), p.get("listen_port", 10086)),
        "routing_rules_file": str(route_table.source) if route_table else "",
        "routing_rules_error": "; ".join(x for x in [route_table.error if route_table else "", _proxy_error] if x),
        "proxy_events": list(_proxy_events),
        "proxy_online": online,
        "proxy_latency_ms": latency,
        "proxy_upstream_online": upstream_online,
        "proxy_upstream_latency_ms": upstream_latency,
        "apps": apps,
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

def _do_shutdown():
    if _server:
        _server.shutdown()
    if _proxy_server:
        _proxy_server.shutdown()


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


def _relay_sockets(left, right, initial_right_to_left=b""):
    if initial_right_to_left:
        left.sendall(initial_right_to_left)
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
            last_activity = time.monotonic()


def _proxy_event(host, action, ok=True, error="", rule=""):
    """Call both the current and the rule-aware event logger during migration."""
    try:
        _record_proxy_event(host, action, ok, error, rule=rule)
    except TypeError:
        _record_proxy_event(host, action, ok, error)


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
        _proxy_event(host or "unknown", action, False, message, rule)
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
            self.send_response(200, "Connection Established")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            response_started = True
            _proxy_event(host, action, rule=rule)
            try:
                _relay_sockets(self.connection, upstream, initial)
            finally:
                upstream.close()
        except (OSError, ValueError, TimeoutError) as exc:
            if not response_started:
                self._fail(502, host, action, rule, "无法建立代理隧道")

    def _request_body(self):
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            raise ValueError("暂不支持分块请求体，请使用 Content-Length")
        if self.headers.get("Expect"):
            raise ValueError("暂不支持 Expect 请求")
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return b""
        try:
            length = int(raw_length)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("无效的 Content-Length")
        if length < 0 or length > PROXY_MAX_BODY_BYTES:
            raise ValueError("请求体超过代理限制")
        body = _read_exact(self.rfile, length)
        if len(body) != length:
            raise ValueError("请求体未完整到达")
        return body

    def _request_bytes(self, target, host, port, parsed, body, absolute):
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
            lines.append("%s: %s\r\n" % (key, value))
        if not seen_host:
            lines.append("Host: %s\r\n" % self._connect_target(host, port))
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
        upstream = None
        host = ""
        action = "ERROR"
        rule = ""
        response_started = False
        try:
            table = self._table()
            if table is None:
                return
            host, port, parsed = _proxy_target(self)
            action, rule = self._route(table, host)
            if action == "PROXY" and self._is_self_target(*table.upstream):
                raise ValueError("上游代理不能指向自身")
            body = self._request_body()
            request = self._request_bytes(
                self.path, host, port, parsed, body, absolute=action == "PROXY"
            )
            upstream = self._connect(host, port) if action == "DIRECT" else self._connect(*table.upstream)
            upstream.settimeout(PROXY_IDLE_TIMEOUT)
            upstream.sendall(request)
            self.close_connection = True
            while True:
                chunk = upstream.recv(PROXY_BUFFER)
                if not chunk:
                    break
                response_started = True
                self.connection.sendall(chunk)
            _proxy_event(host, action, rule=rule)
        except (OSError, ValueError, TimeoutError) as exc:
            if not response_started:
                code = 400 if isinstance(exc, ValueError) else 502
                self._fail(code, host, action, rule, "无法转发代理请求")
        finally:
            if upstream is not None:
                upstream.close()


class ProxyServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def route_table(self):
        cfg = load_config()
        return RouteTable.load(cfg)


def start_proxy_server(cfg):
    global _proxy_server, _proxy_thread, _proxy_error
    p = cfg.get("proxy", {})
    if not p.get("router_enabled", False):
        _proxy_error = ""
        return
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
        """Return the argv prefix used to invoke adb, or None when unavailable."""
        configured = str(self.cfg.get("adb_path") or "").strip()
        if configured:
            candidate = expand(configured)
            return [candidate] if os.path.isfile(candidate) else None
        found = shutil.which("adb")
        return [found] if found else None

    def run(self, args):
        argv = self.resolve()
        if argv is None:
            raise AdbError("未找到 adb 可执行文件，请在 ADB 设置里填写路径")
        with self._lock:
            try:
                proc = subprocess.run(
                    argv + list(args),
                    capture_output=True,
                    timeout=self.timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired:
                raise AdbError("adb 命令超时（%s 秒）" % self.timeout)
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

    def online_device(self):
        for device in self.devices():
            if device["state"] == "device":
                return device
        return None

    def upstream_port(self):
        try:
            return int(self.cfg.get("proxy", {}).get("port") or 5038)
        except (TypeError, ValueError, OverflowError):
            return 5038

    def state(self):
        result = {
            "ok": True,
            "adb_path": "",
            "adb_found": False,
            "devices": [],
            "forwards": [],
            "upstream_port": self.upstream_port(),
            "error": "",
        }
        argv = self.resolve()
        if argv is None:
            result["error"] = "未找到 adb 可执行文件，请在 ADB 设置里填写路径"
            return result
        result["adb_found"] = True
        result["adb_path"] = argv[0]
        try:
            result["devices"] = self.devices()
            result["forwards"] = self.forwards()
        except AdbError as exc:
            result["error"] = str(exc)
        return result

    def forward(self):
        device = self.online_device()
        if device is None:
            raise AdbError("未检测到在线设备")
        port = self.upstream_port()
        code, _out, err = self.run(
            ["-s", device["serial"], "forward", "tcp:%d" % port, "tcp:%d" % port]
        )
        if code != 0:
            raise AdbError(err.strip() or "adb forward 执行失败")
        return {"serial": device["serial"], "local": "tcp:%d" % port, "remote": "tcp:%d" % port}

    def unforward(self):
        device = self.online_device()
        if device is None:
            raise AdbError("未检测到在线设备")
        port = self.upstream_port()
        code, _out, err = self.run(
            ["-s", device["serial"], "forward", "--remove", "tcp:%d" % port]
        )
        if code != 0:
            raise AdbError(err.strip() or "adb forward --remove 执行失败")
        return {"serial": device["serial"], "local": "tcp:%d" % port}


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
                    "evidence": evidence,
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

        body, err = self._read_json_body()
        if err:
            self.send_json({"ok": False, "error": err[1]}, err[0])
            return

        if path == "/api/quit":
            schedule_quit(3.0)
            self.send_json({"ok": True})
            return

        cancel_pending_quit()
        _last_request = time.time()

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
            try:
                result = AdbTool(load_config()).forward()
            except AdbError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({"ok": True, **result})
            return

        if path == "/api/adb/unforward":
            try:
                result = AdbTool(load_config()).unforward()
            except AdbError as exc:
                self.send_json({"ok": False, "error": str(exc)}, 400)
                return
            self.send_json({"ok": True, **result})
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

            new_bypass = None
            if "bypass" in incoming:
                try:
                    new_bypass = parse_bypass(incoming["bypass"])
                except ValueError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 400)
                    return

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
                if "router_enabled" in incoming:
                    cfg["proxy"]["router_enabled"] = bool(incoming["router_enabled"])
                if new_bypass is not None:
                    cfg["proxy"]["bypass"] = new_bypass
                if new_adb_path is not None:
                    cfg["adb_path"] = new_adb_path
                save_config(cfg)
                router_keys = ("router_enabled", "listen_host", "listen_port", "rules_file", "host", "port")
                restart_router = any(previous_proxy.get(key) != cfg["proxy"].get(key) for key in router_keys)
            if restart_router:
                restart_proxy_server(load_config())
            self.send_json({"ok": True, "state": make_state()})
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
            if "bypass" in body:
                try:
                    item["bypass"] = parse_bypass(body["bypass"])
                except ValueError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, 400)
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

def open_window(url):
    profile = Path(tempfile.gettempdir()) / "droidbridge_profile"
    for browser in BROWSERS:
        if not Path(browser).is_file():
            continue
        args = [
            browser,
            "--app=" + url,
            "--window-size=1120,780",
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


def focus_existing_window() -> bool:
    if os.name != "nt":
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.IsIconic.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL

    found = [False]

    def _enum_cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        if buf.value.startswith("DroidBridge"):
            if user32.IsIconic(hwnd):
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            user32.SetForegroundWindow(hwnd)
            found[0] = True
            return False
        return True

    cb = WNDENUMPROC(_enum_cb)
    user32.EnumWindows(cb, 0)
    return found[0]


def try_reuse_existing() -> bool:
    if not RUNTIME_PATH.is_file():
        return False
    try:
        data = json.loads(RUNTIME_PATH.read_text(encoding="utf-8"))
        url = str(data.get("url") or "")
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
                if not focus_existing_window():
                    open_window(url)
            return True
    except Exception:
        return False
    return False


def idle_watchdog(timeout=180):
    """Shut down if the UI window is gone (no polling for `timeout` seconds)."""
    while True:
        time.sleep(15)
        if time.time() - _last_request > timeout and _server:
            threading.Thread(target=_server.shutdown, daemon=True).start()
            return


def main():
    global _server
    if try_reuse_existing():
        return

    cfg = load_config()
    start_proxy_server(cfg)
    _server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    _server.daemon_threads = True
    url = "http://127.0.0.1:%d/" % _server.server_address[1]
    RUNTIME_PATH.write_text(json.dumps({"url": url, "pid": os.getpid()}), encoding="utf-8")
    print("DroidBridge:", url, flush=True)
    if "--no-browser" not in sys.argv:
        threading.Timer(0.4, lambda: open_window(url)).start()
    threading.Thread(target=idle_watchdog, daemon=True).start()
    try:
        _server.serve_forever(poll_interval=0.3)
    finally:
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
