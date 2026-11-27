#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stdlib-only active proxy connection tracker and Windows TCP process resolver."""
from __future__ import annotations

import ctypes
import os
import socket
import struct
import threading
import time
from collections import deque
from ctypes import wintypes
from pathlib import Path
from typing import Callable

AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
ERROR_INSUFFICIENT_BUFFER = 122
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ACTIVE_WINDOW_SECONDS = 3.0
RATE_WINDOW_SECONDS = 2.0
_RATE_BUCKETS_PER_SEC = 4
_RATE_WINDOW_BUCKETS = int(RATE_WINDOW_SECONDS * _RATE_BUCKETS_PER_SEC)
_PROC_STATS_MAX = 256
_PID_CACHE_TTL = 10.0
_PID_CACHE_MAX = 256
_TREE_CACHE_TTL = 2.0
_ANCESTOR_MAX_DEPTH = 12


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _PROCESSENTRY32W(ctypes.Structure):
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
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    _iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
else:
    _iphlpapi = None
    _kernel32 = None


_pid_cache_lock = threading.Lock()
_pid_cache: dict[int, tuple[float, str, str, int]] = {}
_tree_cache_lock = threading.Lock()
_tree_cache: tuple[float, dict[int, tuple[int, str]]] = (0.0, {})
_ancestor_cache_lock = threading.Lock()
_ancestor_cache: dict[tuple[int, int], tuple[float, list[dict]]] = {}


def _snapshot_process_tree(force: bool = False) -> dict[int, tuple[int, str]]:
    """Return {pid: (parent_pid, exe_name)} for running Windows processes."""
    if os.name != "nt" or _kernel32 is None:
        return {}
    now = time.monotonic()
    if not force:
        with _tree_cache_lock:
            ts, cached = _tree_cache
            if cached and now - ts < _TREE_CACHE_TTL:
                return cached

    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return {}
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    tree: dict[int, tuple[int, str]] = {}
    try:
        more = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while more:
            tree[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), str(entry.szExeFile or ""))
            more = _kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snap)

    with _tree_cache_lock:
        globals()["_tree_cache"] = (now, tree)
    return tree


def _lookup_pid_name_toolhelp(target_pid: int) -> str:
    if _kernel32 is None or target_pid <= 0:
        return ""
    tree = _snapshot_process_tree(force=False)
    info = tree.get(target_pid)
    if info is None:
        tree = _snapshot_process_tree(force=True)
        info = tree.get(target_pid)
    return info[1] if info else ""


def _resolve_pid_meta(pid: int) -> tuple[str, str, int]:
    """Return (process_name, full_path, creation_time_100ns) for a Windows PID."""
    if os.name != "nt" or _kernel32 is None or pid <= 0:
        return "", "", 0
    now = time.monotonic()
    with _pid_cache_lock:
        cached = _pid_cache.get(pid)
        if cached and now - cached[0] < _PID_CACHE_TTL:
            return cached[1], cached[2], cached[3]

    full_path = ""
    proc_name = ""
    creation_time = 0
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        try:
            size = wintypes.DWORD(1024)
            buf = ctypes.create_unicode_buffer(1024)
            if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                full_path = buf.value
                proc_name = Path(full_path).name
            ct, et, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
            if _kernel32.GetProcessTimes(handle, ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)):
                creation_time = (int(ct.dwHighDateTime) << 32) | int(ct.dwLowDateTime)
        finally:
            _kernel32.CloseHandle(handle)
    if not proc_name:
        proc_name = _lookup_pid_name_toolhelp(pid)

    with _pid_cache_lock:
        if len(_pid_cache) >= _PID_CACHE_MAX:
            _pid_cache.clear()
        _pid_cache[pid] = (now, proc_name, full_path, creation_time)
    return proc_name, full_path, creation_time


def _resolve_pid_info(pid: int) -> tuple[str, str]:
    """Return (process_name, full_path) for a Windows PID, with short TTL caching."""
    proc_name, full_path, _ctime = _resolve_pid_meta(pid)
    return proc_name, full_path


def resolve_process_ancestors(
    pid: int,
    max_depth: int = _ANCESTOR_MAX_DEPTH,
    *,
    _tree_provider: Callable[[bool], dict[int, tuple[int, str]]] | None = None,
    _meta_provider: Callable[[int], tuple[str, str, int]] | None = None,
) -> list[dict]:
    """Walk parent PIDs upward (nearest parent first), guarding cycles and PID reuse."""
    if pid <= 0 or max_depth <= 0:
        return []
    use_cache = _tree_provider is None and _meta_provider is None
    if use_cache and (os.name != "nt" or _kernel32 is None):
        return []

    get_tree = _tree_provider or _snapshot_process_tree
    get_meta = _meta_provider or _resolve_pid_meta

    _, _, self_ctime = get_meta(pid)
    now = time.monotonic()
    cache_key = (pid, self_ctime)
    if use_cache:
        with _ancestor_cache_lock:
            cached = _ancestor_cache.get(cache_key)
            if cached and now - cached[0] < _PID_CACHE_TTL:
                return [dict(item) for item in cached[1]]

    tree = get_tree(False)
    if pid not in tree:
        tree = get_tree(True)

    ancestors: list[dict] = []
    visited = {pid}
    cur_pid = pid
    child_ctime = self_ctime
    for _ in range(max_depth):
        node = tree.get(cur_pid)
        if not node:
            break
        ppid = int(node[0] or 0)
        if ppid <= 0 or ppid in visited:
            break
        visited.add(ppid)
        p_name, p_path, p_ctime = get_meta(ppid)
        if not p_name:
            parent_node = tree.get(ppid)
            if parent_node:
                p_name = parent_node[1]
        # Guard against Windows PID reuse: a real parent cannot be created after its child.
        if child_ctime > 0 and p_ctime > 0 and p_ctime > child_ctime:
            break
        if p_name or p_path:
            ancestors.append({
                "pid": ppid,
                "process": p_name,
                "process_path": p_path,
            })
        cur_pid = ppid
        if p_ctime > 0:
            child_ctime = p_ctime

    if use_cache:
        with _ancestor_cache_lock:
            if len(_ancestor_cache) >= _PID_CACHE_MAX:
                _ancestor_cache.clear()
            _ancestor_cache[cache_key] = (now, [dict(item) for item in ancestors])
    return ancestors


def _query_tcp_table_bytes(af: int) -> bytes | None:
    if _iphlpapi is None:
        return None
    size = wintypes.DWORD(0)
    res = _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0)
    if res != ERROR_INSUFFICIENT_BUFFER and res != 0:
        return None
    for _ in range(3):
        alloc = max(int(size.value) + 4096, 4096)
        buf = ctypes.create_string_buffer(alloc)
        size = wintypes.DWORD(alloc)
        res = _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0)
        if res == 0:
            return buf.raw[: int(size.value)]
        if res != ERROR_INSUFFICIENT_BUFFER:
            return None
    return None


def resolve_local_tcp_owner(
    client_addr: tuple | None,
    server_port: int,
    exclude_pid: int | None = None,
) -> tuple[int, str, str]:
    """Identify the local process owning a TCP client socket connected to server_port.

    Returns (pid, process_name, exe_path); returns (0, '', '') when unavailable.
    """
    if os.name != "nt" or _iphlpapi is None or not client_addr or len(client_addr) < 2:
        return 0, "", ""
    client_ip = str(client_addr[0] or "")
    try:
        client_port = int(client_addr[1])
        srv_port = int(server_port)
    except (TypeError, ValueError):
        return 0, "", ""

    pid = 0
    if ":" in client_ip:
        try:
            target_ip = socket.inet_pton(socket.AF_INET6, client_ip.split("%", 1)[0])
        except OSError:
            return 0, "", ""
        raw = _query_tcp_table_bytes(AF_INET6)
        if not raw or len(raw) < 4:
            return 0, "", ""
        count = struct.unpack_from("<I", raw, 0)[0]
        row_size = 56
        offset = 4
        for _ in range(count):
            if offset + row_size > len(raw):
                break
            loc_addr, _loc_scope, loc_port_raw, _rem_addr, _rem_scope, rem_port_raw, _state, owning_pid = (
                struct.unpack_from("<16sII16sIIII", raw, offset)
            )
            offset += row_size
            loc_port = socket.ntohs(loc_port_raw & 0xFFFF)
            rem_port = socket.ntohs(rem_port_raw & 0xFFFF)
            if loc_port == client_port and rem_port == srv_port and loc_addr == target_ip:
                if exclude_pid and owning_pid == exclude_pid:
                    continue
                pid = int(owning_pid)
                break
    else:
        try:
            target_ip_int = struct.unpack("<I", socket.inet_aton(client_ip))[0]
        except OSError:
            return 0, "", ""
        raw = _query_tcp_table_bytes(AF_INET)
        if not raw or len(raw) < 4:
            return 0, "", ""
        count = struct.unpack_from("<I", raw, 0)[0]
        row_size = 24
        offset = 4
        for _ in range(count):
            if offset + row_size > len(raw):
                break
            _state, loc_addr, loc_port_raw, _rem_addr, rem_port_raw, owning_pid = (
                struct.unpack_from("<IIIIII", raw, offset)
            )
            offset += row_size
            loc_port = socket.ntohs(loc_port_raw & 0xFFFF)
            rem_port = socket.ntohs(rem_port_raw & 0xFFFF)
            if loc_port == client_port and rem_port == srv_port and loc_addr == target_ip_int:
                if exclude_pid and owning_pid == exclude_pid:
                    continue
                pid = int(owning_pid)
                break

    if pid <= 0:
        return 0, "", ""
    proc_name, exe_path = _resolve_pid_info(pid)
    return pid, proc_name, exe_path


def _format_target(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _close_socket_quiet(sock: socket.socket | None):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _SlidingRateMeter:
    """O(1) sliding-window byte rate meter (0.25s buckets over 2.0s window)."""

    __slots__ = ("_buckets",)

    def __init__(self):
        self._buckets: deque[list[int]] = deque()

    def add(self, tx: int, rx: int, now_mono: float):
        if tx <= 0 and rx <= 0:
            return
        b = int(now_mono * _RATE_BUCKETS_PER_SEC)
        if self._buckets and self._buckets[-1][0] == b:
            self._buckets[-1][1] += tx
            self._buckets[-1][2] += rx
        else:
            self._buckets.append([b, tx, rx])
        cutoff = b - _RATE_WINDOW_BUCKETS
        while self._buckets and self._buckets[0][0] <= cutoff:
            self._buckets.popleft()

    def rate(self, now_mono: float, window_s: float = RATE_WINDOW_SECONDS) -> tuple[int, int]:
        b = int(now_mono * _RATE_BUCKETS_PER_SEC)
        cutoff = b - _RATE_WINDOW_BUCKETS
        while self._buckets and self._buckets[0][0] <= cutoff:
            self._buckets.popleft()
        if not self._buckets:
            return 0, 0
        tx = sum(item[1] for item in self._buckets)
        rx = sum(item[2] for item in self._buckets)
        span = max(0.5, min(RATE_WINDOW_SECONDS, float(window_s)))
        return int(round(tx / span)), int(round(rx / span))


class _ProcessTrafficStats:
    """Cumulative session traffic and live speed for one process attribution chain."""

    __slots__ = (
        "process",
        "process_path",
        "ancestors",
        "tx_bytes",
        "rx_bytes",
        "conn_count",
        "last_seen_at",
        "last_seen_time",
        "rate",
    )

    def __init__(self, process: str, process_path: str, ancestors: list[dict], now_wall: float):
        self.process = process
        self.process_path = process_path
        self.ancestors = [
            {
                "process": str(a.get("process") or ""),
                "process_path": str(a.get("process_path") or ""),
            }
            for a in (ancestors or ())
        ]
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.conn_count = 0
        self.last_seen_at = now_wall
        self.last_seen_time = time.strftime("%H:%M:%S", time.localtime(now_wall))
        self.rate = _SlidingRateMeter()

    def to_dict(self, now_mono: float) -> dict:
        tx_bps, rx_bps = self.rate.rate(now_mono)
        return {
            "process": self.process,
            "process_path": self.process_path,
            "ancestors": [dict(a) for a in self.ancestors],
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "tx_bps": tx_bps,
            "rx_bps": rx_bps,
            "conn_count": self.conn_count,
            "last_seen_time": self.last_seen_time,
        }


def _make_proc_key(process: str, process_path: str, ancestors: list[dict]) -> tuple:
    anc_sig = tuple(
        (str(a.get("process") or "").lower(), str(a.get("process_path") or "").lower())
        for a in (ancestors or ())
    )
    return (str(process or "").lower(), str(process_path or "").lower(), anc_sig)


class ActiveConnection:
    """Represents one live proxied or direct connection currently passing through DroidBridge."""

    __slots__ = (
        "id",
        "host",
        "port",
        "target",
        "protocol",
        "action",
        "rule",
        "client_addr",
        "pid",
        "process",
        "process_path",
        "ancestors",
        "started_at",
        "started_time",
        "started_mono",
        "last_active_mono",
        "tx_bytes",
        "rx_bytes",
        "closed_by_user",
        "_rate",
        "_on_bytes",
        "_left",
        "_right",
        "_lock",
    )

    def __init__(
        self,
        conn_id: str,
        host: str,
        port: int,
        protocol: str,
        action: str,
        rule: str,
        client_addr: str,
        pid: int,
        process: str,
        process_path: str,
        left_sock: socket.socket | None,
        right_sock: socket.socket | None,
        ancestors: list[dict] | tuple[dict, ...] = (),
        on_bytes: Callable[[int, int, float], None] | None = None,
    ):
        now_wall = time.time()
        now_mono = time.monotonic()
        self.id = conn_id
        self.host = host
        self.port = int(port)
        self.target = _format_target(host, self.port)
        self.protocol = protocol
        self.action = action
        self.rule = rule
        self.client_addr = client_addr
        self.pid = int(pid or 0)
        self.process = process
        self.process_path = process_path
        self.ancestors = tuple(dict(item) for item in (ancestors or ()))
        self.started_at = now_wall
        self.started_time = time.strftime("%H:%M:%S", time.localtime(now_wall))
        self.started_mono = now_mono
        self.last_active_mono = now_mono
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.closed_by_user = False
        self._rate = _SlidingRateMeter()
        self._on_bytes = on_bytes
        self._left = left_sock
        self._right = right_sock
        self._lock = threading.Lock()

    def add_tx(self, count: int):
        if count <= 0:
            return
        now = time.monotonic()
        with self._lock:
            self.tx_bytes += count
            self.last_active_mono = now
            self._rate.add(count, 0, now)
        if self._on_bytes is not None:
            self._on_bytes(count, 0, now)

    def add_rx(self, count: int):
        if count <= 0:
            return
        now = time.monotonic()
        with self._lock:
            self.rx_bytes += count
            self.last_active_mono = now
            self._rate.add(0, count, now)
        if self._on_bytes is not None:
            self._on_bytes(0, count, now)

    def force_close(self):
        with self._lock:
            self.closed_by_user = True
            left, right = self._left, self._right
            self._left = None
            self._right = None
        _close_socket_quiet(left)
        _close_socket_quiet(right)

    def to_dict(self, now_mono: float) -> dict:
        with self._lock:
            elapsed = max(0.0, now_mono - self.started_mono)
            duration_s = int(elapsed)
            idle_s = max(0.0, now_mono - self.last_active_mono)
            tx_bps, rx_bps = self._rate.rate(now_mono, window_s=elapsed)
            return {
                "id": self.id,
                "host": self.host,
                "port": self.port,
                "target": self.target,
                "protocol": self.protocol,
                "action": self.action,
                "rule": self.rule,
                "client": self.client_addr,
                "pid": self.pid,
                "process": self.process,
                "process_path": self.process_path,
                "ancestors": [dict(item) for item in self.ancestors],
                "started_time": self.started_time,
                "duration_s": duration_s,
                "tx_bytes": self.tx_bytes,
                "rx_bytes": self.rx_bytes,
                "tx_bps": tx_bps,
                "rx_bps": rx_bps,
                "active": idle_s <= ACTIVE_WINDOW_SECONDS,
            }


class ConnectionRegistry:
    """Thread-safe registry of live proxy tunnels, real-time rates, and cumulative stats."""

    def __init__(
        self,
        owner_resolver: Callable[[tuple | None, int], tuple[int, str, str]] | None = None,
        ancestor_resolver: Callable[[int], list[dict]] | None = None,
    ):
        self._owner_resolver = owner_resolver or resolve_local_tcp_owner
        if ancestor_resolver is not None:
            self._ancestor_resolver: Callable[[int], list[dict]] | None = ancestor_resolver
        elif owner_resolver is None:
            self._ancestor_resolver = resolve_process_ancestors
        else:
            self._ancestor_resolver = None
        self._lock = threading.Lock()
        self._seq = 0
        self._conns: dict[str, ActiveConnection] = {}
        self._conn_proc_key: dict[str, tuple] = {}
        self._global_rate = _SlidingRateMeter()
        self._cum_tx = 0
        self._cum_rx = 0
        self._stats_since = time.strftime("%H:%M:%S", time.localtime(time.time()))
        self._proc_stats: dict[tuple, _ProcessTrafficStats] = {}

    def _record_bytes(self, proc_key: tuple, tx: int, rx: int, now_mono: float):
        now_wall = time.time()
        with self._lock:
            self._cum_tx += tx
            self._cum_rx += rx
            self._global_rate.add(tx, rx, now_mono)
            stat = self._proc_stats.get(proc_key)
            if stat is not None:
                stat.tx_bytes += tx
                stat.rx_bytes += rx
                stat.rate.add(tx, rx, now_mono)
                stat.last_seen_at = now_wall
                stat.last_seen_time = time.strftime("%H:%M:%S", time.localtime(now_wall))

    def resolve_owner(
        self,
        client_addr: tuple | None,
        server_port: int,
    ) -> tuple[int, str, str, list[dict]]:
        """Resolve (pid, process_name, process_path, ancestors) while client socket is still open."""
        try:
            pid, proc_name, proc_path = self._owner_resolver(client_addr, server_port)
        except Exception:
            pid, proc_name, proc_path = 0, "", ""
        ancestors: list[dict] = []
        if pid > 0 and self._ancestor_resolver is not None:
            try:
                ancestors = list(self._ancestor_resolver(pid) or [])
            except Exception:
                ancestors = []
        return int(pid or 0), str(proc_name or ""), str(proc_path or ""), ancestors

    def register(
        self,
        *,
        host: str,
        port: int,
        protocol: str,
        action: str,
        rule: str,
        client_addr: tuple | None,
        server_port: int,
        left_sock: socket.socket | None,
        right_sock: socket.socket | None,
        owner_info: tuple[int, str, str, list[dict]] | None = None,
    ) -> ActiveConnection:
        if owner_info is not None:
            pid, proc_name, proc_path, ancestors = owner_info
        else:
            pid, proc_name, proc_path, ancestors = self.resolve_owner(client_addr, server_port)
        client_str = (
            f"{client_addr[0]}:{client_addr[1]}"
            if client_addr and len(client_addr) >= 2
            else ""
        )
        proc_key = _make_proc_key(proc_name, proc_path, ancestors)
        now_wall = time.time()
        with self._lock:
            self._seq += 1
            conn_id = f"c{self._seq}"
            stat = self._proc_stats.get(proc_key)
            if stat is None:
                if len(self._proc_stats) >= _PROC_STATS_MAX:
                    active_keys = set(self._conn_proc_key.values())
                    idle_keys = [k for k in self._proc_stats if k not in active_keys]
                    if idle_keys:
                        oldest = min(idle_keys, key=lambda k: self._proc_stats[k].last_seen_at)
                        self._proc_stats.pop(oldest, None)
                stat = _ProcessTrafficStats(proc_name, proc_path, ancestors, now_wall)
                self._proc_stats[proc_key] = stat
            stat.conn_count += 1
            stat.last_seen_at = now_wall
            stat.last_seen_time = time.strftime("%H:%M:%S", time.localtime(now_wall))
            conn = ActiveConnection(
                conn_id=conn_id,
                host=host,
                port=port,
                protocol=protocol,
                action=action,
                rule=rule,
                client_addr=client_str,
                pid=pid,
                process=proc_name,
                process_path=proc_path,
                ancestors=ancestors,
                on_bytes=lambda tx, rx, now, pk=proc_key: self._record_bytes(pk, tx, rx, now),
                left_sock=left_sock,
                right_sock=right_sock,
            )
            self._conns[conn_id] = conn
            self._conn_proc_key[conn_id] = proc_key
            return conn

    def unregister(self, conn_id: str):
        with self._lock:
            conn = self._conns.pop(conn_id, None)
            pk = self._conn_proc_key.pop(conn_id, None)
            if (
                conn is not None
                and pk is not None
                and conn.pid <= 0
                and not conn.process
                and not conn.process_path
                and conn.tx_bytes == 0
                and conn.rx_bytes == 0
            ):
                stat = self._proc_stats.get(pk)
                if stat is not None:
                    stat.conn_count = max(0, stat.conn_count - 1)
                    if (
                        stat.conn_count == 0
                        and stat.tx_bytes == 0
                        and stat.rx_bytes == 0
                        and pk not in self._conn_proc_key.values()
                    ):
                        self._proc_stats.pop(pk, None)

    def count(self) -> int:
        with self._lock:
            return len(self._conns)

    def close_one(self, conn_id: str) -> int:
        with self._lock:
            conn = self._conns.pop(conn_id, None)
            self._conn_proc_key.pop(conn_id, None)
        if conn is None:
            return 0
        conn.force_close()
        return 1

    def close_all(self) -> int:
        with self._lock:
            items = list(self._conns.values())
            self._conns.clear()
            self._conn_proc_key.clear()
        for conn in items:
            conn.force_close()
        return len(items)

    def reset_stats(self):
        """Reset session cumulative byte counters and clear disconnected process history."""
        now_wall = time.time()
        with self._lock:
            self._cum_tx = 0
            self._cum_rx = 0
            self._stats_since = time.strftime("%H:%M:%S", time.localtime(now_wall))
            active_counts: dict[tuple, int] = {}
            for pk in self._conn_proc_key.values():
                active_counts[pk] = active_counts.get(pk, 0) + 1
            for pk in list(self._proc_stats.keys()):
                if pk not in active_counts:
                    self._proc_stats.pop(pk, None)
                else:
                    stat = self._proc_stats[pk]
                    stat.tx_bytes = 0
                    stat.rx_bytes = 0
                    stat.conn_count = active_counts[pk]
                    stat.last_seen_at = now_wall
                    stat.last_seen_time = self._stats_since

    def snapshot(self) -> dict:
        now_mono = time.monotonic()
        with self._lock:
            items = list(reversed(self._conns.values()))
            tx_bps, rx_bps = self._global_rate.rate(now_mono)
            cum_tx = self._cum_tx
            cum_rx = self._cum_rx
            stats_since = self._stats_since
            proc_rows = [stat.to_dict(now_mono) for stat in self._proc_stats.values()]
        rows = [conn.to_dict(now_mono) for conn in items]
        total_tx = sum(r["tx_bytes"] for r in rows)
        total_rx = sum(r["rx_bytes"] for r in rows)
        return {
            "ok": True,
            "connections": rows,
            "total": len(rows),
            "total_tx": total_tx,
            "total_rx": total_rx,
            "tx_bps": tx_bps,
            "rx_bps": rx_bps,
            "cumulative_tx": cum_tx,
            "cumulative_rx": cum_rx,
            "stats_since": stats_since,
            "process_stats": proc_rows,
        }
