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
_PID_CACHE_TTL = 10.0
_PID_CACHE_MAX = 256


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
_pid_cache: dict[int, tuple[float, str, str]] = {}


def _lookup_pid_name_toolhelp(target_pid: int) -> str:
    if _kernel32 is None or target_pid <= 0:
        return ""
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return ""
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    try:
        more = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while more:
            if int(entry.th32ProcessID) == target_pid:
                return str(entry.szExeFile or "")
            more = _kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snap)
    return ""


def _resolve_pid_info(pid: int) -> tuple[str, str]:
    """Return (process_name, full_path) for a Windows PID, with short TTL caching."""
    if os.name != "nt" or _kernel32 is None or pid <= 0:
        return "", ""
    now = time.monotonic()
    with _pid_cache_lock:
        cached = _pid_cache.get(pid)
        if cached and now - cached[0] < _PID_CACHE_TTL:
            return cached[1], cached[2]

    full_path = ""
    proc_name = ""
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        try:
            size = wintypes.DWORD(1024)
            buf = ctypes.create_unicode_buffer(1024)
            if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                full_path = buf.value
                proc_name = Path(full_path).name
        finally:
            _kernel32.CloseHandle(handle)
    if not proc_name:
        proc_name = _lookup_pid_name_toolhelp(pid)

    with _pid_cache_lock:
        if len(_pid_cache) >= _PID_CACHE_MAX:
            _pid_cache.clear()
        _pid_cache[pid] = (now, proc_name, full_path)
    return proc_name, full_path


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
        "started_at",
        "started_time",
        "started_mono",
        "last_active_mono",
        "tx_bytes",
        "rx_bytes",
        "closed_by_user",
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
        self.started_at = now_wall
        self.started_time = time.strftime("%H:%M:%S", time.localtime(now_wall))
        self.started_mono = now_mono
        self.last_active_mono = now_mono
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.closed_by_user = False
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

    def add_rx(self, count: int):
        if count <= 0:
            return
        now = time.monotonic()
        with self._lock:
            self.rx_bytes += count
            self.last_active_mono = now

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
            duration_s = max(0, int(now_mono - self.started_mono))
            idle_s = max(0.0, now_mono - self.last_active_mono)
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
                "started_time": self.started_time,
                "duration_s": duration_s,
                "tx_bytes": self.tx_bytes,
                "rx_bytes": self.rx_bytes,
                "active": idle_s <= ACTIVE_WINDOW_SECONDS,
            }


class ConnectionRegistry:
    """Thread-safe registry of live proxy tunnels and HTTP transfers."""

    def __init__(
        self,
        owner_resolver: Callable[[tuple | None, int], tuple[int, str, str]] | None = None,
    ):
        self._owner_resolver = owner_resolver or resolve_local_tcp_owner
        self._lock = threading.Lock()
        self._seq = 0
        self._conns: dict[str, ActiveConnection] = {}

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
    ) -> ActiveConnection:
        try:
            pid, proc_name, proc_path = self._owner_resolver(client_addr, server_port)
        except Exception:
            pid, proc_name, proc_path = 0, "", ""
        client_str = (
            f"{client_addr[0]}:{client_addr[1]}"
            if client_addr and len(client_addr) >= 2
            else ""
        )
        with self._lock:
            self._seq += 1
            conn_id = f"c{self._seq}"
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
                left_sock=left_sock,
                right_sock=right_sock,
            )
            self._conns[conn_id] = conn
            return conn

    def unregister(self, conn_id: str):
        with self._lock:
            self._conns.pop(conn_id, None)

    def count(self) -> int:
        with self._lock:
            return len(self._conns)

    def close_one(self, conn_id: str) -> int:
        with self._lock:
            conn = self._conns.pop(conn_id, None)
        if conn is None:
            return 0
        conn.force_close()
        return 1

    def close_all(self) -> int:
        with self._lock:
            items = list(self._conns.values())
            self._conns.clear()
        for conn in items:
            conn.force_close()
        return len(items)

    def snapshot(self) -> dict:
        now_mono = time.monotonic()
        with self._lock:
            items = list(reversed(self._conns.values()))
        rows = [conn.to_dict(now_mono) for conn in items]
        total_tx = sum(r["tx_bytes"] for r in rows)
        total_rx = sum(r["rx_bytes"] for r in rows)
        return {
            "ok": True,
            "connections": rows,
            "total": len(rows),
            "total_tx": total_tx,
            "total_rx": total_rx,
        }
